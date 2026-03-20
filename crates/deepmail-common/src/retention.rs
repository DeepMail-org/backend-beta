use crate::config::RetentionConfig;
use crate::db::DbPool;
use crate::errors::DeepMailError;

pub fn run_retention_cleanup(_pool: &DbPool, _cfg: &RetentionConfig) -> Result<(), DeepMailError> {
    // TODO: retention cleanup: no-op (pending rewrite)
    // The full rewrite happens in Task 7 with archive/soft-delete/purge lifecycle.
    tracing::info!("retention cleanup: no-op (pending rewrite)");
    Ok(())
}
