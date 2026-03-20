//! Audit logging service for security-critical operations.
//!
//! All significant actions (uploads, analysis completions, auth events,
//! config changes) are recorded in the `audit_logs` table for compliance
//! and forensic review.
//!
//! # Security
//! - Uses prepared statements only
//! - Timestamps are server-generated (not client-supplied)
//! - Logs are append-only (no UPDATE or DELETE)

use crate::db::DbPool;
use crate::errors::DeepMailError;
use crate::models::new_id;

/// Record an audit log entry.
///
/// This is intentionally synchronous (uses a pooled connection) because
/// audit logging must not be skipped due to async cancellation.
pub fn log_audit(
    pool: &DbPool,
    action: &str,
    resource: &str,
    details: Option<&str>,
    user_id: Option<&str>,
    ip_address: Option<&str>,
) -> Result<(), DeepMailError> {
    let conn = pool.get()?;
    let id = new_id();

    conn.execute(
        "INSERT INTO audit_logs (id, action, resource, details, user_id, ip_address)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![id, action, resource, details, user_id, ip_address],
    )?;

    tracing::info!(
        action = action,
        resource = resource,
        user_id = user_id.unwrap_or("system"),
        "Audit log recorded"
    );

    Ok(())
}

/// Convenience: log an upload event.
pub fn log_upload(
    pool: &DbPool,
    email_id: &str,
    filename: &str,
    sha256: &str,
    ip_address: Option<&str>,
) -> Result<(), DeepMailError> {
    let details = format!(
        "filename={}, sha256={}, email_id={}",
        filename, sha256, email_id
    );
    log_audit(pool, "upload", "emails", Some(&details), None, ip_address)
}

/// Convenience: log an analysis completion event.
pub fn log_analysis_complete(
    pool: &DbPool,
    email_id: &str,
    threat_score: f64,
) -> Result<(), DeepMailError> {
    let details = format!("email_id={}, threat_score={:.1}", email_id, threat_score);
    log_audit(
        pool,
        "analysis_complete",
        "analysis_results",
        Some(&details),
        None,
        None,
    )
}

/// Convenience: log a deduplication event.
pub fn log_dedup(
    pool: &DbPool,
    sha256: &str,
    existing_email_id: &str,
) -> Result<(), DeepMailError> {
    let details = format!("sha256={}, existing_email_id={}", sha256, existing_email_id);
    log_audit(
        pool,
        "upload_deduplicated",
        "emails",
        Some(&details),
        None,
        None,
    )
}

/// Convenience: log a pipeline stage transition.
///
/// Called by the worker when each stage starts or completes.
pub fn log_pipeline_stage(
    pool: &DbPool,
    email_id: &str,
    stage: &str,
    status: &str,
) -> Result<(), DeepMailError> {
    let details = format!("email_id={email_id}, stage={stage}, status={status}");
    log_audit(
        pool,
        "pipeline_stage",
        "job_progress",
        Some(&details),
        None,
        None,
    )
}

/// Convenience: log a pipeline error event.
///
/// Records the full error in the audit table for forensic review.
pub fn log_error(pool: &DbPool, email_id: &str, error_msg: &str) -> Result<(), DeepMailError> {
    let details = format!("email_id={email_id}, error={error_msg}");
    log_audit(pool, "pipeline_error", "emails", Some(&details), None, None)
}
