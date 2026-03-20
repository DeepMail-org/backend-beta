use rusqlite::Connection;

use crate::db::migrations::MIGRATION_COUNT;
use crate::errors::DeepMailError;

pub fn validate_schema(conn: &Connection) -> Result<(), DeepMailError> {
    let applied: u32 = conn
        .query_row("SELECT COUNT(*) FROM _migrations", [], |row| row.get(0))
        .map_err(|e| DeepMailError::Database(format!("Failed to count applied migrations: {e}")))?;

    if applied > MIGRATION_COUNT {
        return Err(DeepMailError::Database(format!(
            "Database has {applied} migrations but this binary expects {MIGRATION_COUNT}; refusing to start"
        )));
    }

    if applied < MIGRATION_COUNT {
        return Err(DeepMailError::Database(format!(
            "Database has {applied} migrations after startup, expected {MIGRATION_COUNT}"
        )));
    }

    Ok(())
}
