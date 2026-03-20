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
    pub cache: CacheConfig,
    pub pipeline: PipelineConfig,
    pub worker: WorkerConfig,
    pub sandbox: SandboxConfig,
    pub features: FeatureFlags,
    pub tenant: TenantConfig,
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

/// Redis cache TTL configuration.
///
/// Controls how long threat intelligence results are cached per IOC type.
/// Shorter TTLs ensure freshness; longer TTLs reduce external API pressure.
#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    /// TTL for IP reputation cache entries (seconds). Default: 3600 (1 hour).
    #[serde(default = "default_ip_ttl")]
    pub ip_ttl_secs: u64,
    /// TTL for domain reputation cache entries (seconds). Default: 3600 (1 hour).
    #[serde(default = "default_domain_ttl")]
    pub domain_ttl_secs: u64,
    /// TTL for file hash cache entries (seconds). Default: 86400 (24 hours).
    /// Hash-based verdicts are stable (same bytes = same result), so longer TTL is safe.
    #[serde(default = "default_hash_ttl")]
    pub hash_ttl_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PipelineConfig {
    #[serde(default = "default_url_analysis_timeout_ms")]
    pub url_analysis_timeout_ms: u64,
    #[serde(default = "default_attachment_analysis_timeout_ms")]
    pub attachment_analysis_timeout_ms: u64,
    #[serde(default = "default_stage_retry_attempts")]
    pub stage_retry_attempts: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkerConfig {
    #[serde(default = "default_max_concurrent_jobs")]
    pub max_concurrent_jobs: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SandboxConfig {
    #[serde(default = "default_sandbox_enabled")]
    pub enabled: bool,
    #[serde(default = "default_sandbox_backend")]
    pub backend: String,
    #[serde(default = "default_sandbox_queue")]
    pub queue_stream: String,
    #[serde(default = "default_sandbox_image")]
    pub docker_image: String,
    #[serde(default = "default_sandbox_network")]
    pub docker_network: String,
    #[serde(default = "default_sandbox_seccomp")]
    pub seccomp_profile: String,
    #[serde(default = "default_sandbox_execution_timeout_ms")]
    pub execution_timeout_ms: u64,
    #[serde(default = "default_sandbox_cpu_limit")]
    pub cpu_limit: String,
    #[serde(default = "default_sandbox_memory_limit")]
    pub memory_limit: String,
    #[serde(default = "default_sandbox_pids_limit")]
    pub pids_limit: u32,
    #[serde(default = "default_progress_channel")]
    pub progress_channel: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FeatureFlags {
    #[serde(default = "default_feature_enable_sandbox")]
    pub enable_sandbox: bool,
    #[serde(default = "default_feature_enable_similarity")]
    pub enable_similarity: bool,
    #[serde(default = "default_feature_enable_intel_providers")]
    pub enable_intel_providers: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TenantConfig {
    #[serde(default = "default_uploads_per_day")]
    pub uploads_per_day: u32,
    #[serde(default = "default_sandbox_per_day")]
    pub sandbox_executions_per_day: u32,
    #[serde(default = "default_url_reuse_ttl_secs")]
    pub url_reuse_ttl_secs: u64,
    #[serde(default = "default_domain_reuse_ttl_secs")]
    pub domain_reuse_ttl_secs: u64,
    #[serde(default = "default_sandbox_reuse_ttl_secs")]
    pub sandbox_reuse_ttl_secs: u64,
}

fn default_ip_ttl() -> u64 {
    3600
}
fn default_domain_ttl() -> u64 {
    3600
}
fn default_hash_ttl() -> u64 {
    86400
}
fn default_url_analysis_timeout_ms() -> u64 {
    3000
}
fn default_attachment_analysis_timeout_ms() -> u64 {
    5000
}
fn default_stage_retry_attempts() -> u32 {
    2
}
fn default_max_concurrent_jobs() -> usize {
    4
}
fn default_sandbox_enabled() -> bool {
    true
}
fn default_sandbox_backend() -> String {
    "docker".to_string()
}
fn default_sandbox_queue() -> String {
    "deepmail:queue:sandbox".to_string()
}
fn default_sandbox_image() -> String {
    "deepmail/sandbox-playwright:latest".to_string()
}
fn default_sandbox_network() -> String {
    "deepmail_sandbox_net".to_string()
}
fn default_sandbox_seccomp() -> String {
    "./crates/deepmail-sandbox/assets/seccomp/chromium-minimal.json".to_string()
}
fn default_sandbox_execution_timeout_ms() -> u64 {
    15000
}
fn default_sandbox_cpu_limit() -> String {
    "1.0".to_string()
}
fn default_sandbox_memory_limit() -> String {
    "512m".to_string()
}
fn default_sandbox_pids_limit() -> u32 {
    128
}
fn default_progress_channel() -> String {
    "deepmail:events:progress".to_string()
}
fn default_feature_enable_sandbox() -> bool {
    true
}
fn default_feature_enable_similarity() -> bool {
    false
}
fn default_feature_enable_intel_providers() -> bool {
    true
}
fn default_uploads_per_day() -> u32 {
    100
}
fn default_sandbox_per_day() -> u32 {
    100
}
fn default_url_reuse_ttl_secs() -> u64 {
    3600
}
fn default_domain_reuse_ttl_secs() -> u64 {
    1800
}
fn default_sandbox_reuse_ttl_secs() -> u64 {
    86400
}

/// Type alias so callers can use `DeepMailConfig` for the top-level config.
pub type DeepMailConfig = AppConfig;

impl AppConfig {
    /// Load configuration from `config.toml` in the current directory,
    /// then overlay with environment variables prefixed `DEEPMAIL_`.
    pub fn load() -> Result<Self, DeepMailError> {
        if std::path::Path::new("config/base.toml").exists() {
            let env = std::env::var("DEEPMAIL_ENV").unwrap_or_else(|_| "development".to_string());
            Self::load_layered(&format!("config/{env}.toml"))
        } else {
            Self::load_from("config.toml")
        }
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

    pub fn load_layered(env_path: &str) -> Result<Self, DeepMailError> {
        let settings = config::Config::builder()
            .add_source(config::File::from(PathBuf::from("config/base.toml")).required(true))
            .add_source(config::File::from(PathBuf::from(env_path)).required(false))
            .add_source(
                config::Environment::with_prefix("DEEPMAIL")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()
            .map_err(|e| DeepMailError::Config(format!("Failed to build layered config: {e}")))?;

        settings.try_deserialize::<AppConfig>().map_err(|e| {
            DeepMailError::Config(format!("Failed to deserialize layered config: {e}"))
        })
    }
}
