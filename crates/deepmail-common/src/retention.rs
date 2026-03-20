use chrono::{Duration, Utc};

use crate::config::RetentionConfig;
use crate::db::DbPool;
use crate::errors::DeepMailError;

pub fn run_retention_cleanup(pool: &DbPool, cfg: &RetentionConfig) -> Result<(), DeepMailError> {
    let conn = pool.get()?;

    let archived = archive_phase(&conn, cfg)?;
    let soft_deleted = soft_delete_phase(&conn, cfg)?;
    let purged = purge_phase(&conn, cfg)?;
    let purged_logs = purge_logs(&conn, cfg)?;

    tracing::info!(
        archived,
        soft_deleted,
        purged,
        purged_logs,
        "Retention cleanup completed"
    );

    Ok(())
}

fn archive_phase(
    conn: &rusqlite::Connection,
    cfg: &RetentionConfig,
) -> Result<usize, DeepMailError> {
    let cutoff = (Utc::now() - Duration::days(cfg.archive_after_days as i64)).to_rfc3339();
    let now = Utc::now().to_rfc3339();

    let archived = conn.execute(
        "UPDATE emails
         SET archived_at = ?1
         WHERE submitted_at < ?2 AND archived_at IS NULL AND is_deleted = 0",
        rusqlite::params![now, cutoff],
    )?;

    conn.execute(
        "UPDATE attachments
         SET archived_at = ?1
         WHERE email_id IN (SELECT id FROM emails WHERE archived_at = ?1)
         AND archived_at IS NULL",
        rusqlite::params![now],
    )?;
    conn.execute(
        "UPDATE analysis_results
         SET archived_at = ?1
         WHERE email_id IN (SELECT id FROM emails WHERE archived_at = ?1)
         AND archived_at IS NULL",
        rusqlite::params![now],
    )?;
    conn.execute(
        "UPDATE sandbox_reports
         SET archived_at = ?1
         WHERE email_id IN (SELECT id FROM emails WHERE archived_at = ?1)
         AND archived_at IS NULL",
        rusqlite::params![now],
    )?;

    Ok(archived)
}

fn soft_delete_phase(
    conn: &rusqlite::Connection,
    cfg: &RetentionConfig,
) -> Result<usize, DeepMailError> {
    let cutoff = (Utc::now() - Duration::days(cfg.soft_delete_after_days as i64)).to_rfc3339();
    let now = Utc::now().to_rfc3339();

    let soft_deleted = conn.execute(
        "UPDATE emails
         SET deleted_at = ?1, is_deleted = 1
         WHERE archived_at IS NOT NULL AND archived_at < ?2 AND deleted_at IS NULL",
        rusqlite::params![now, cutoff],
    )?;

    conn.execute(
        "UPDATE attachments
         SET deleted_at = ?1, is_deleted = 1
         WHERE email_id IN (SELECT id FROM emails WHERE deleted_at = ?1)
         AND deleted_at IS NULL",
        rusqlite::params![now],
    )?;
    conn.execute(
        "UPDATE analysis_results
         SET deleted_at = ?1, is_deleted = 1
         WHERE email_id IN (SELECT id FROM emails WHERE deleted_at = ?1)
         AND deleted_at IS NULL",
        rusqlite::params![now],
    )?;
    conn.execute(
        "UPDATE sandbox_reports
         SET deleted_at = ?1, is_deleted = 1
         WHERE email_id IN (SELECT id FROM emails WHERE deleted_at = ?1)
         AND deleted_at IS NULL",
        rusqlite::params![now],
    )?;

    Ok(soft_deleted)
}

fn purge_phase(conn: &rusqlite::Connection, cfg: &RetentionConfig) -> Result<usize, DeepMailError> {
    let cutoff = (Utc::now() - Duration::days(cfg.purge_after_days as i64)).to_rfc3339();

    conn.execute(
        "DELETE FROM sandbox_reports WHERE is_deleted = 1 AND deleted_at < ?1",
        rusqlite::params![cutoff],
    )?;
    conn.execute(
        "DELETE FROM analysis_results WHERE is_deleted = 1 AND deleted_at < ?1",
        rusqlite::params![cutoff],
    )?;
    conn.execute(
        "DELETE FROM attachments WHERE is_deleted = 1 AND deleted_at < ?1",
        rusqlite::params![cutoff],
    )?;

    conn.execute(
        "DELETE FROM job_progress WHERE email_id IN (
            SELECT id FROM emails WHERE is_deleted = 1 AND deleted_at < ?1
        )",
        rusqlite::params![cutoff],
    )?;
    conn.execute(
        "DELETE FROM ioc_relations WHERE email_id IN (
            SELECT id FROM emails WHERE is_deleted = 1 AND deleted_at < ?1
        )",
        rusqlite::params![cutoff],
    )?;

    let purged = conn.execute(
        "DELETE FROM emails WHERE is_deleted = 1 AND deleted_at < ?1",
        rusqlite::params![cutoff],
    )?;

    Ok(purged)
}

fn purge_logs(conn: &rusqlite::Connection, cfg: &RetentionConfig) -> Result<usize, DeepMailError> {
    let cutoff = (Utc::now() - Duration::days(cfg.logs_ttl_days as i64)).to_rfc3339();
    conn.execute(
        "DELETE FROM audit_logs WHERE timestamp < ?1",
        rusqlite::params![cutoff],
    )
    .map_err(Into::into)
}
