//! Application state shared across all handlers via Axum's `State` extractor.
//!
//! All fields are behind `Arc` so cloning is cheap. The state is immutable
//! after construction — mutable access (e.g. Redis) uses interior mutability
//! via `tokio::sync::Mutex`.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::Mutex;

use deepmail_common::config::AppConfig;
use deepmail_common::db::DbPool;
use deepmail_common::queue::RedisQueue;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    /// SQLite connection pool.
    db_pool: DbPool,
    /// Redis queue connection (behind Mutex for mutable access).
    redis_queue: Mutex<RedisQueue>,
    /// Application configuration.
    config: AppConfig,
    /// Canonical path to the quarantine directory.
    quarantine_dir: PathBuf,
}

impl AppState {
    /// Create a new application state.
    pub fn new(
        db_pool: DbPool,
        redis_queue: RedisQueue,
        config: AppConfig,
        quarantine_dir: PathBuf,
    ) -> Self {
        Self {
            inner: Arc::new(AppStateInner {
                db_pool,
                redis_queue: Mutex::new(redis_queue),
                config,
                quarantine_dir,
            }),
        }
    }

    /// Get a reference to the database connection pool.
    pub fn db_pool(&self) -> &DbPool {
        &self.inner.db_pool
    }

    /// Get the Redis queue (locked for mutable access).
    pub async fn redis_queue(&self) -> tokio::sync::MutexGuard<'_, RedisQueue> {
        self.inner.redis_queue.lock().await
    }

    /// Get a reference to the application configuration.
    pub fn config(&self) -> &AppConfig {
        &self.inner.config
    }

    /// Get a reference to the quarantine directory path.
    pub fn quarantine_dir(&self) -> &PathBuf {
        &self.inner.quarantine_dir
    }
}
