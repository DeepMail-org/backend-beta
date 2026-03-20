//! Results query endpoint — retrieve the full analysis report for an email.
//!
//! # Endpoint
//! `GET /api/v1/results/:email_id`
//!
//! # Data Flow
//! 1. Validate `email_id` format
//! 2. Query `emails` table for the record
//! 3. Query `analysis_results` for all stage outputs
//! 4. Query `job_progress` for stage timing data
//! 5. Query `ioc_nodes` linked to this email via `ioc_relations`
//! 6. Assemble and return a structured `EmailAnalysisReport`
//!
//! # Security
//! - Database queries use prepared statements only
//! - No raw user input is interpolated into SQL
//! - Missing records return 404, not 500

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use deepmail_common::errors::DeepMailError;

use crate::auth::extract_user_id;
use crate::state::AppState;

// ─── Response types ───────────────────────────────────────────────────────────

/// Full analysis report for a single email submission.
#[derive(Debug, Serialize, Deserialize)]
pub struct EmailAnalysisReport {
    /// Core email metadata.
    pub email: EmailSummary,
    /// Per-stage analysis outputs (JSON blobs with scores).
    pub analysis_results: Vec<AnalysisResultEntry>,
    /// Stage-by-stage pipeline timing.
    pub job_progress: Vec<JobProgressEntry>,
    /// IOC nodes linked to this email.
    pub iocs: Vec<IocEntry>,
}

/// Core email record.
#[derive(Debug, Serialize, Deserialize)]
pub struct EmailSummary {
    pub id: String,
    pub original_name: String,
    pub sha256_hash: String,
    pub file_size: i64,
    pub submitted_at: String,
    pub status: String,
    pub current_stage: Option<String>,
    pub completed_at: Option<String>,
    pub error_message: Option<String>,
}

/// A single analysis result entry (one per stage that produces output).
#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisResultEntry {
    pub id: String,
    pub result_type: String,
    /// JSON-serialised stage output (headers, IOC list, score, etc.).
    pub data: serde_json::Value,
    pub threat_score: Option<f64>,
    pub confidence: Option<f64>,
    pub created_at: String,
}

/// Pipeline stage timing record.
#[derive(Debug, Serialize, Deserialize)]
pub struct JobProgressEntry {
    pub id: String,
    pub stage: String,
    pub status: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub details: Option<String>,
}

/// An IOC node linked to this email.
#[derive(Debug, Serialize, Deserialize)]
pub struct IocEntry {
    pub id: String,
    pub ioc_type: String,
    pub value: String,
    pub first_seen: String,
    pub last_seen: String,
    pub metadata: Option<String>,
}

// ─── Route registration ───────────────────────────────────────────────────────

/// Register results routes under the shared router.
pub fn routes() -> Router<AppState> {
    Router::new().route("/results/{email_id}", get(results_handler))
}

// ─── Handler ─────────────────────────────────────────────────────────────────

/// `GET /api/v1/results/:email_id`
///
/// Returns the full analysis report for the given email ID.
/// Responds with 404 if the email does not exist.
async fn results_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(email_id): Path<String>,
) -> Result<(StatusCode, Json<EmailAnalysisReport>), DeepMailError> {
    let user_id = extract_user_id(&headers, state.config())?;
    enforce_rate_limits(&state, &user_id, addr.ip().to_string(), "results").await?;

    let conn = state.db_pool().get()?;

    // ── 1. Fetch email record ──────────────────────────────────────────────────
    let email: Option<EmailSummary> = {
        let mut stmt = conn.prepare(
            "SELECT id, original_name, sha256_hash, file_size, submitted_at, \
                    status, current_stage, completed_at, error_message \
             FROM emails WHERE id = ?1 AND submitted_by = ?2",
        )?;

        stmt.query_row(rusqlite::params![email_id, user_id], |row| {
            Ok(EmailSummary {
                id: row.get(0)?,
                original_name: row.get(1)?,
                sha256_hash: row.get(2)?,
                file_size: row.get(3)?,
                submitted_at: row.get(4)?,
                status: row.get(5)?,
                current_stage: row.get(6)?,
                completed_at: row.get(7)?,
                error_message: row.get(8)?,
            })
        })
        .ok()
    };

    let email =
        email.ok_or_else(|| DeepMailError::NotFound(format!("Email '{email_id}' not found")))?;

    // ── 2. Fetch analysis results ──────────────────────────────────────────────
    let analysis_results: Vec<AnalysisResultEntry> = {
        let mut stmt = conn.prepare(
            "SELECT id, result_type, data, threat_score, confidence, created_at \
             FROM analysis_results \
             WHERE email_id = ?1 \
             ORDER BY created_at ASC",
        )?;

        let rows = stmt.query_map(rusqlite::params![email_id], |row| {
            let data_str: String = row.get(2)?;
            Ok(AnalysisResultEntry {
                id: row.get(0)?,
                result_type: row.get(1)?,
                data: serde_json::from_str(&data_str).unwrap_or(serde_json::Value::Null),
                threat_score: row.get(3)?,
                confidence: row.get(4)?,
                created_at: row.get(5)?,
            })
        })?;

        rows.filter_map(|r| r.ok()).collect()
    };

    // ── 3. Fetch job progress ─────────────────────────────────────────────────
    let job_progress: Vec<JobProgressEntry> = {
        let mut stmt = conn.prepare(
            "SELECT id, stage, status, started_at, completed_at, details \
             FROM job_progress \
             WHERE email_id = ?1 \
             ORDER BY started_at ASC",
        )?;

        let rows = stmt.query_map(rusqlite::params![email_id], |row| {
            Ok(JobProgressEntry {
                id: row.get(0)?,
                stage: row.get(1)?,
                status: row.get(2)?,
                started_at: row.get(3)?,
                completed_at: row.get(4)?,
                details: row.get(5)?,
            })
        })?;

        rows.filter_map(|r| r.ok()).collect()
    };

    // ── 4. Fetch linked IOC nodes ─────────────────────────────────────────────
    let iocs: Vec<IocEntry> = {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT n.id, n.ioc_type, n.value, n.first_seen, n.last_seen, n.metadata \
             FROM ioc_nodes n \
             INNER JOIN ioc_relations r ON r.source_id = n.id OR r.target_id = n.id \
             WHERE r.email_id = ?1 \
             ORDER BY n.ioc_type, n.value",
        )?;

        let rows = stmt.query_map(rusqlite::params![email_id], |row| {
            Ok(IocEntry {
                id: row.get(0)?,
                ioc_type: row.get(1)?,
                value: row.get(2)?,
                first_seen: row.get(3)?,
                last_seen: row.get(4)?,
                metadata: row.get(5)?,
            })
        })?;

        rows.filter_map(|r| r.ok()).collect()
    };

    let report = EmailAnalysisReport {
        email,
        analysis_results,
        job_progress,
        iocs,
    };

    tracing::info!(email_id = %email_id, "Results fetched");
    Ok((StatusCode::OK, Json(report)))
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
