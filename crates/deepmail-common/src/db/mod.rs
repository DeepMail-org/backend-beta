//! SQLite database module with connection pooling and WAL mode.
//!
//! # Security
//! - All queries MUST use prepared statements (no string interpolation)
//! - WAL mode enables concurrent reads with a single writer
//! - Foreign keys are enforced at the database level
//! - Busy timeout prevents lock contention failures

pub mod migrations;
pub mod schema_validation;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::OpenFlags;
use std::path::Path;
use std::time::Duration;

use crate::config::DatabaseConfig;
use crate::errors::DeepMailError;

/// Type alias for the SQLite connection pool.
pub type DbPool = Pool<SqliteConnectionManager>;

/// Initialize the SQLite connection pool with security hardening.
///
/// This function:
/// 1. Creates the parent directory if it doesn't exist
/// 2. Opens the database with restricted flags
/// 3. Enables WAL mode for concurrent access
/// 4. Enables foreign key enforcement
/// 5. Sets busy timeout to handle lock contention
/// 6. Runs all pending migrations
pub fn init_pool(config: &DatabaseConfig) -> Result<DbPool, DeepMailError> {
    // Ensure the database directory exists
    let db_path = Path::new(&config.path);
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            DeepMailError::Database(format!(
                "Failed to create database directory '{}': {e}",
                parent.display()
            ))
        })?;
    }

    let manager = SqliteConnectionManager::file(&config.path)
        .with_flags(
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_init(move |conn| {
            // Enable WAL mode for concurrent read access
            conn.execute_batch("PRAGMA journal_mode = WAL;")?;
            // Enforce foreign key constraints
            conn.execute_batch("PRAGMA foreign_keys = ON;")?;
            // Set busy timeout (milliseconds)
            conn.execute_batch(&format!(
                "PRAGMA busy_timeout = {};",
                5000 // Default, overridden below if needed
            ))?;
            // Secure defaults
            conn.execute_batch("PRAGMA secure_delete = ON;")?;
            conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL;")?;
            Ok(())
        });

    let pool = Pool::builder()
        .max_size(config.pool_size)
        .connection_timeout(Duration::from_secs(10))
        .build(manager)
        .map_err(|e| DeepMailError::Database(format!("Failed to create connection pool: {e}")))?;

    // Run migrations on startup
    {
        let conn = pool.get()?;
        migrations::run_migrations(&conn)?;
        schema_validation::validate_schema(&conn)?;
    }

    tracing::info!(
        path = %config.path,
        pool_size = config.pool_size,
        "SQLite connection pool initialized (WAL mode)"
    );

    Ok(pool)
}
