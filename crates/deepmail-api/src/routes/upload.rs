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

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Multipart, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use rusqlite::Connection;

use deepmail_common::abuse;
use deepmail_common::audit;
use deepmail_common::errors::DeepMailError;
use deepmail_common::models::{new_id, now_utc, UploadResponse};
use deepmail_common::queue::{Job, QUEUE_EMAIL_ANALYSIS};
use deepmail_common::quota;
use deepmail_common::reuse;
use deepmail_common::upload::{quarantine, validation};
use deepmail_common::utils;

use crate::auth::AuthUser;
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    auth: AuthUser,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<UploadResponse>), DeepMailError> {
    let user_id = auth.user_id;
    {
        let conn = state.db_pool().get()?;
        ensure_user_exists(&conn, &user_id)?;
    }

    enforce_rate_limits(&state, &user_id, addr.ip().to_string(), "upload").await?;

    {
        let mut queue = state.redis_queue().await;
        let flagged = abuse::is_user_flagged(state.db_pool(), queue.conn_mut(), &user_id).await?;
        if flagged {
            return Err(DeepMailError::Forbidden(
                "Account flagged for abuse".to_string(),
            ));
        }
    }

    let quota_decision = quota::enforce_daily_quota(
        state.db_pool(),
        &user_id,
        "uploads",
        state.config().tenant.uploads_per_day as i64,
    )?;
    if !quota_decision.allowed {
        return Err(DeepMailError::RateLimited);
    }

    // ── Step 1: Extract file from multipart ──────────────────────────────────
    let (filename, data) = extract_file_field(&mut multipart).await?;

    tracing::info!(
        filename = %filename,
        size = data.len(),
        "File upload received"
    );

    // ── Step 2: Validate file (all checks run before disk write) ─────────────
    let validated = validation::validate_upload(&filename, &data, &state.config().upload)?;

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
            "SELECT id, status FROM emails
             WHERE sha256_hash = ?1 AND status = 'completed' AND is_deleted = 0 LIMIT 1",
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

            let new_email_id = new_id();
            conn.execute(
                "INSERT INTO emails (
                    id, original_name, quarantine_path, sha256_hash, file_size,
                    submitted_by, submitted_at, status, reused_from_email_id, completed_at
                )
                SELECT
                    ?1, original_name, quarantine_path, sha256_hash, file_size,
                    ?2, ?3, 'completed', id, ?3
                FROM emails WHERE id = ?4",
                rusqlite::params![new_email_id, user_id, now_utc(), existing_id],
            )?;

            conn.execute(
                "INSERT INTO analysis_results (id, email_id, result_type, data, threat_score, confidence, created_at)
                 SELECT lower(hex(randomblob(16))), ?1, result_type, data, threat_score, confidence, ?2
                 FROM analysis_results WHERE email_id = ?3",
                rusqlite::params![new_email_id, now_utc(), existing_id],
            )?;

            // Log the dedup event
            let _ = audit::log_dedup(state.db_pool(), &sha256, &existing_id);

            return Ok((
                StatusCode::OK,
                Json(UploadResponse {
                    email_id: new_email_id,
                    job_id: String::new(),
                    status: "completed".to_string(),
                    message: "File already analyzed (deduplicated)".to_string(),
                    deduplicated: true,
                }),
            ));
        }

        if let Some(hit) = reuse::lookup_reuse_entry(state.db_pool(), "file_sha256", &sha256)? {
            if let Some(reused_email_id) = hit.result_email_id {
                return Ok((
                    StatusCode::OK,
                    Json(UploadResponse {
                        email_id: reused_email_id,
                        job_id: String::new(),
                        status: "completed".to_string(),
                        message: "Reused existing result cache".to_string(),
                        deduplicated: true,
                    }),
                ));
            }
        }
    }

    // ── Step 5: Quarantine the file ──────────────────────────────────────────
    let quarantined = quarantine::quarantine_file(state.quarantine_dir(), &validated.data)?;

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
            "INSERT INTO emails (id, original_name, quarantine_path, sha256_hash, file_size, submitted_at, status, submitted_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                email_id,
                original_name,
                quarantine_path_str,
                sha256,
                file_size,
                submitted_at,
                "queued",
                user_id,
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
            "submitted_by": user_id,
            "trace_id": headers.get("x-request-id").and_then(|v| v.to_str().ok()).map(|s| s.to_string()).unwrap_or_else(new_id),
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

    if state.config().abuse.enabled {
        let mut queue = state.redis_queue().await;
        let exceeded = abuse::check_velocity(
            queue.conn_mut(),
            &user_id,
            "uploads",
            state.config().abuse.upload_velocity_per_min,
            60_000,
        )
        .await?;
        if exceeded {
            let details = "Upload velocity threshold exceeded".to_string();
            let _ = abuse::flag_user(state.db_pool(), &user_id, &details);
            let _ = abuse::record_abuse_event(
                state.db_pool(),
                &user_id,
                "velocity_upload",
                "critical",
                Some(&details),
                true,
            );
        }
    }

    Ok((StatusCode::ACCEPTED, Json(response)))
}

async fn enforce_rate_limits(
    state: &AppState,
    user_id: &str,
    ip: String,
    endpoint: &str,
) -> Result<(), DeepMailError> {
    let mut queue = state.redis_queue().await;
    let (user_allowed, _, _) = queue
        .check_rate_limit_token_bucket(
            "user",
            &format!("{user_id}:{endpoint}"),
            state.config().reliability.rate_limit_capacity,
            state.config().reliability.rate_limit_refill_per_sec,
            1,
        )
        .await?;
    if !user_allowed {
        return Err(DeepMailError::RateLimited);
    }

    let (ip_allowed, _, _) = queue
        .check_rate_limit_token_bucket(
            "ip",
            &format!("{ip}:{endpoint}"),
            state.config().reliability.rate_limit_capacity,
            state.config().reliability.rate_limit_refill_per_sec,
            1,
        )
        .await?;
    if !ip_allowed {
        return Err(DeepMailError::RateLimited);
    }
    Ok(())
}

fn ensure_user_exists(conn: &Connection, user_id: &str) -> Result<(), DeepMailError> {
    let exists = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1)",
            rusqlite::params![user_id],
            |row| row.get::<_, i64>(0),
        )
        .map(|value| value == 1)?;

    if exists {
        return Ok(());
    }

    let username = if user_id.trim().is_empty() {
        "analyst".to_string()
    } else {
        user_id.to_string()
    };
    let email = format!("{}@local.invalid", username.replace('@', "_"));

    conn.execute(
        "INSERT INTO users (id, username, email, password_hash, role, is_active)
         VALUES (?1, ?2, ?3, ?4, ?5, 1)",
        rusqlite::params![user_id, username, email, "external-auth", "analyst"],
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ensure_user_exists;
    use rusqlite::Connection;

    #[test]
    fn inserts_user_if_missing() {
        let conn = Connection::open_in_memory().expect("open sqlite");
        conn.execute_batch(
            "CREATE TABLE users (
                id TEXT PRIMARY KEY NOT NULL,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'analyst',
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )
        .expect("create users table");

        ensure_user_exists(&conn, "token-subject").expect("insert user");

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM users WHERE id = ?1",
                ["token-subject"],
                |row| row.get(0),
            )
            .expect("query user count");

        assert_eq!(count, 1);
    }
}

/// Extract the file field from multipart form data.
async fn extract_file_field(multipart: &mut Multipart) -> Result<(String, Vec<u8>), DeepMailError> {
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
            .ok_or_else(|| DeepMailError::Upload("File field has no filename".to_string()))?;

        let data = field
            .bytes()
            .await
            .map_err(|e| DeepMailError::Upload(format!("Failed to read file bytes: {e}")))?
            .to_vec();

        return Ok((filename, data));
    }

    Err(DeepMailError::Upload(
        "No 'file' field found in multipart form data".to_string(),
    ))
}
