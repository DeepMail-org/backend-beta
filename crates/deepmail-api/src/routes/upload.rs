//! Secure file upload endpoint with deduplication.
//!
//! # Data Flow
//! 1. Receive multipart form data
//! 2. Extract file bytes and filename
//! 3. Run multi-layer validation (extension, size, magic bytes, MIME, zip bomb)
//! 4. Compute SHA-256 hash
//! 5. **Deduplication check**: if hash already analyzed, return cached result
//! 6. Write to quarantine (UUID renamed, 0o400 permissions)
//! 7. Insert email record into SQLite
//! 8. Enqueue analysis job to Redis
//! 9. Log audit event
//! 10. Return 202 Accepted with job ID
//!
//! # Security
//! - All validation runs BEFORE any disk write
//! - Dedup check prevents re-processing known files
//! - Errors are logged with full detail server-side but return safe messages

use axum::extract::{Multipart, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};

use deepmail_common::audit;
use deepmail_common::errors::DeepMailError;
use deepmail_common::models::{new_id, now_utc, UploadResponse};
use deepmail_common::queue::{Job, QUEUE_EMAIL_ANALYSIS};
use deepmail_common::upload::{quarantine, validation};
use deepmail_common::utils;

use crate::state::AppState;

/// Register upload routes.
pub fn routes() -> Router<AppState> {
    Router::new().route("/upload", post(upload_handler))
}

/// `POST /api/v1/upload`
///
/// Accepts a multipart form with a single file field named `file`.
/// Returns `202 Accepted` with the email ID and job ID on success.
async fn upload_handler(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<UploadResponse>), DeepMailError> {
    // ── Step 1: Extract file from multipart ──────────────────────────────────
    let (filename, data) = extract_file_field(&mut multipart).await?;

    tracing::info!(
        filename = %filename,
        size = data.len(),
        "File upload received"
    );

    // ── Step 2: Validate file (all checks run before disk write) ─────────────
    let validated = validation::validate_upload(
        &filename,
        &data,
        &state.config().upload,
    )?;

    tracing::info!(
        sanitized_name = %validated.sanitized_name,
        extension = %validated.extension,
        size = validated.size,
        "File validation passed"
    );

    // ── Step 3: Compute SHA-256 hash early for dedup ─────────────────────────
    let sha256 = utils::sha256_hash(&validated.data);

    // ── Step 4: Deduplication check ──────────────────────────────────────────
    {
        let conn = state.db_pool().get()?;
        let mut stmt = conn.prepare(
            "SELECT id, status FROM emails WHERE sha256_hash = ?1 AND status = 'completed' LIMIT 1"
        )?;

        let existing: Option<(String, String)> = stmt
            .query_row(rusqlite::params![sha256], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .ok();

        if let Some((existing_id, _status)) = existing {
            tracing::info!(
                existing_id = %existing_id,
                sha256 = %sha256,
                "Deduplication hit — returning cached result"
            );

            // Log the dedup event
            let _ = audit::log_dedup(state.db_pool(), &sha256, &existing_id);

            return Ok((
                StatusCode::OK,
                Json(UploadResponse {
                    email_id: existing_id,
                    job_id: String::new(),
                    status: "completed".to_string(),
                    message: "File already analyzed (deduplicated)".to_string(),
                    deduplicated: true,
                }),
            ));
        }
    }

    // ── Step 5: Quarantine the file ──────────────────────────────────────────
    let quarantined = quarantine::quarantine_file(
        state.quarantine_dir(),
        &validated.data,
    )?;

    tracing::info!(
        quarantine_name = %quarantined.quarantine_name,
        sha256 = %sha256,
        "File quarantined"
    );

    // ── Step 6: Insert email record into SQLite ──────────────────────────────
    let email_id = new_id();
    let quarantine_path_str = quarantined.path.to_string_lossy().to_string();
    let file_size = validated.size as i64;
    let original_name = validated.sanitized_name.clone();
    let submitted_at = now_utc();

    {
        let email_id = email_id.clone();
        let sha256 = sha256.clone();
        let conn = state.db_pool().get()?;

        conn.execute(
            "INSERT INTO emails (id, original_name, quarantine_path, sha256_hash, file_size, submitted_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                email_id,
                original_name,
                quarantine_path_str,
                sha256,
                file_size,
                submitted_at,
                "queued",
            ],
        )?;
    }

    tracing::info!(email_id = %email_id, "Email record inserted");

    // ── Step 7: Log audit event ──────────────────────────────────────────────
    let _ = audit::log_upload(state.db_pool(), &email_id, &original_name, &sha256, None);

    // ── Step 8: Enqueue analysis job to email_analysis queue ──────────────────
    let job = Job {
        id: email_id.clone(),
        job_type: "email_analysis".to_string(),
        payload: serde_json::to_string(&serde_json::json!({
            "email_id": email_id,
            "quarantine_path": quarantine_path_str,
            "sha256": sha256,
            "original_name": original_name,
        }))?,
        created_at: now_utc(),
    };

    let job_entry_id = {
        let mut queue = state.redis_queue().await;
        queue.enqueue_to(QUEUE_EMAIL_ANALYSIS, &job).await?
    };

    tracing::info!(
        email_id = %email_id,
        job_entry = %job_entry_id,
        "Analysis job enqueued to email_analysis queue"
    );

    // ── Step 9: Return success response ──────────────────────────────────────
    let response = UploadResponse {
        email_id: email_id.clone(),
        job_id: job_entry_id,
        status: "queued".to_string(),
        message: "Email submitted for analysis".to_string(),
        deduplicated: false,
    };

    Ok((StatusCode::ACCEPTED, Json(response)))
}

/// Extract the file field from multipart form data.
async fn extract_file_field(
    multipart: &mut Multipart,
) -> Result<(String, Vec<u8>), DeepMailError> {
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| DeepMailError::Upload(format!("Failed to read multipart field: {e}")))?
    {
        let name = field.name().unwrap_or("").to_string();

        if name != "file" {
            tracing::debug!(field_name = %name, "Skipping non-file field");
            continue;
        }

        let filename = field
            .file_name()
            .map(|s| s.to_string())
            .ok_or_else(|| {
                DeepMailError::Upload("File field has no filename".to_string())
            })?;

        let data = field
            .bytes()
            .await
            .map_err(|e| {
                DeepMailError::Upload(format!("Failed to read file bytes: {e}"))
            })?
            .to_vec();

        return Ok((filename, data));
    }

    Err(DeepMailError::Upload(
        "No 'file' field found in multipart form data".to_string(),
    ))
}
