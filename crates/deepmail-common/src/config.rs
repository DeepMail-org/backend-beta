//! Typed configuration loaded from `config.toml` + environment overrides.
//!
//! Environment variables use the prefix `DEEPMAIL_` and double underscores
//! for nesting, e.g. `DEEPMAIL_SERVER__PORT=8080`.

use serde::Deserialize;
use std::path::PathBuf;

use crate::errors::DeepMailError;

/// Top-level application configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub upload: UploadConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    /// Maximum request body size in bytes.
    pub max_body_size: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    /// Path to the SQLite database file.
    pub path: String,
    /// Number of connections in the pool.
    pub pool_size: u32,
    /// Busy timeout in milliseconds.
    pub busy_timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    /// Redis stream name for the job queue.
    pub stream_name: String,
    /// Consumer group name.
    pub consumer_group: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UploadConfig {
    /// Maximum allowed file size in bytes.
    pub max_file_size: usize,
    /// Allowed file extensions (lowercase, no dot).
    pub allowed_extensions: Vec<String>,
    /// Directory for quarantined uploads.
    pub quarantine_path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    /// Requests per second per IP.
    pub rate_limit_rps: u32,
    /// Token bucket burst capacity.
    pub rate_limit_burst: u32,
    /// JWT signing secret.
    pub jwt_secret: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    /// Log level: trace, debug, info, warn, error.
    pub level: String,
    /// Output format: "json" or "pretty".
    pub format: String,
}

impl AppConfig {
    /// Load configuration from `config.toml` in the current directory,
    /// then overlay with environment variables prefixed `DEEPMAIL_`.
    pub fn load() -> Result<Self, DeepMailError> {
        Self::load_from("config.toml")
    }

    /// Load configuration from a specific file path.
    pub fn load_from(path: &str) -> Result<Self, DeepMailError> {
        let config_path = PathBuf::from(path);

        let settings = config::Config::builder()
            .add_source(config::File::from(config_path).required(true))
            .add_source(
                config::Environment::with_prefix("DEEPMAIL")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()
            .map_err(|e| DeepMailError::Config(format!("Failed to build config: {e}")))?;

        settings
            .try_deserialize::<AppConfig>()
            .map_err(|e| DeepMailError::Config(format!("Failed to deserialize config: {e}")))
    }
}
