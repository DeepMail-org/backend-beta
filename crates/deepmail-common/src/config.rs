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
    pub observability: ObservabilityConfig,
    pub reliability: ReliabilityConfig,
    pub retention: RetentionConfig,
    pub circuit_breaker: CircuitBreakerConfig,
    pub backup: BackupConfig,
    pub abuse: AbuseConfig,
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
    #[serde(default = "default_jwt_issuer")]
    pub jwt_issuer: String,
    #[serde(default = "default_jwt_audience")]
    pub jwt_audience: String,
    #[serde(default = "default_token_ttl_days")]
    pub token_ttl_days: u32,
    #[serde(default = "default_otp_ttl_minutes")]
    pub otp_ttl_minutes: u32,
    #[serde(default = "default_otp_max_attempts")]
    pub otp_max_attempts: u32,
    #[serde(default = "default_otp_lockout_secs")]
    pub otp_lockout_secs: u64,
    #[serde(default = "default_mtls_required_for_auth_admin")]
    pub mtls_required_for_auth_admin: bool,
    #[serde(default)]
    pub trusted_client_cert_fingerprints: Vec<String>,
    #[serde(default)]
    pub admin_ip_allowlist: Vec<String>,
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

#[derive(Debug, Clone, Deserialize)]
pub struct ObservabilityConfig {
    #[serde(default = "default_otlp_endpoint")]
    pub otlp_endpoint: String,
    #[serde(default = "default_otlp_enabled")]
    pub otlp_enabled: bool,
    #[serde(default = "default_otlp_batch_size")]
    pub otlp_batch_size: u32,
    #[serde(default = "default_otlp_batch_timeout_secs")]
    pub otlp_batch_timeout_secs: u64,
    #[serde(default = "default_service_namespace")]
    pub service_namespace: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReliabilityConfig {
    #[serde(default = "default_max_retry_attempts")]
    pub max_retry_attempts: u32,
    #[serde(default = "default_retry_base_backoff_ms")]
    pub retry_base_backoff_ms: u64,
    #[serde(default = "default_retry_max_backoff_ms")]
    pub retry_max_backoff_ms: u64,
    #[serde(default = "default_rate_limit_capacity")]
    pub rate_limit_capacity: u32,
    #[serde(default = "default_rate_limit_refill_per_sec")]
    pub rate_limit_refill_per_sec: f64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RetentionConfig {
    #[serde(default = "default_retention_archive_after_days")]
    pub archive_after_days: u32,
    #[serde(default = "default_retention_soft_delete_after_days")]
    pub soft_delete_after_days: u32,
    #[serde(default = "default_retention_purge_after_days")]
    pub purge_after_days: u32,
    #[serde(default = "default_retention_interval_secs")]
    pub cleanup_interval_secs: u64,
    #[serde(default = "default_retention_logs_ttl_days")]
    pub logs_ttl_days: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CircuitBreakerConfig {
    #[serde(default = "default_cb_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_cb_cooldown_secs")]
    pub cooldown_secs: u64,
    #[serde(default = "default_cb_half_open_max_probes")]
    pub half_open_max_probes: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackupConfig {
    #[serde(default = "default_backup_dir")]
    pub backup_dir: String,
    #[serde(default = "default_backup_passphrase_env_var")]
    pub passphrase_env_var: String,
    #[serde(default = "default_argon2_memory_kib")]
    pub argon2_memory_kib: u32,
    #[serde(default = "default_argon2_iterations")]
    pub argon2_iterations: u32,
    #[serde(default = "default_argon2_parallelism")]
    pub argon2_parallelism: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AbuseConfig {
    #[serde(default = "default_abuse_enabled")]
    pub enabled: bool,
    #[serde(default = "default_abuse_upload_velocity")]
    pub upload_velocity_per_min: u32,
    #[serde(default = "default_abuse_sandbox_velocity")]
    pub sandbox_velocity_per_min: u32,
    #[serde(default = "default_abuse_failed_threshold")]
    pub failed_upload_threshold_5min: u32,
    #[serde(default = "default_abuse_pattern_scan_interval")]
    pub pattern_scan_interval_secs: u64,
    #[serde(default = "default_abuse_repeated_hash_threshold")]
    pub repeated_malicious_hash_threshold: u32,
    #[serde(default = "default_abuse_sandbox_harvest_threshold")]
    pub sandbox_harvest_threshold: u32,
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
fn default_otlp_endpoint() -> String {
    "http://127.0.0.1:4317".to_string()
}
fn default_otlp_enabled() -> bool {
    false
}
fn default_otlp_batch_size() -> u32 {
    512
}
fn default_otlp_batch_timeout_secs() -> u64 {
    5
}
fn default_service_namespace() -> String {
    "deepmail".to_string()
}
fn default_max_retry_attempts() -> u32 {
    3
}
fn default_retry_base_backoff_ms() -> u64 {
    500
}
fn default_retry_max_backoff_ms() -> u64 {
    10000
}
fn default_rate_limit_capacity() -> u32 {
    60
}
fn default_rate_limit_refill_per_sec() -> f64 {
    10.0
}
fn default_retention_archive_after_days() -> u32 {
    30
}
fn default_retention_soft_delete_after_days() -> u32 {
    30
}
fn default_retention_purge_after_days() -> u32 {
    30
}
fn default_retention_logs_ttl_days() -> u32 {
    14
}
fn default_retention_interval_secs() -> u64 {
    3600
}
fn default_cb_failure_threshold() -> u32 {
    5
}
fn default_cb_cooldown_secs() -> u64 {
    30
}
fn default_cb_half_open_max_probes() -> u32 {
    2
}
fn default_backup_dir() -> String {
    "data/backups".to_string()
}
fn default_backup_passphrase_env_var() -> String {
    "DEEPMAIL_BACKUP_PASSPHRASE".to_string()
}
fn default_argon2_memory_kib() -> u32 {
    65536
}
fn default_argon2_iterations() -> u32 {
    3
}
fn default_argon2_parallelism() -> u32 {
    4
}
fn default_abuse_enabled() -> bool {
    true
}
fn default_abuse_upload_velocity() -> u32 {
    20
}
fn default_abuse_sandbox_velocity() -> u32 {
    15
}
fn default_abuse_failed_threshold() -> u32 {
    10
}
fn default_abuse_pattern_scan_interval() -> u64 {
    300
}
fn default_abuse_repeated_hash_threshold() -> u32 {
    5
}
fn default_abuse_sandbox_harvest_threshold() -> u32 {
    50
}
fn default_jwt_issuer() -> String {
    "deepmail-inhouse".to_string()
}
fn default_jwt_audience() -> String {
    "deepmail-clients".to_string()
}
fn default_token_ttl_days() -> u32 {
    7
}
fn default_otp_ttl_minutes() -> u32 {
    10
}
fn default_otp_max_attempts() -> u32 {
    5
}
fn default_otp_lockout_secs() -> u64 {
    900
}
fn default_mtls_required_for_auth_admin() -> bool {
    true
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
            .map_err(|e| DeepMailError::Config(format!("Failed to deserialize config: {e}")))?
            .apply_secret_providers()
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

        settings
            .try_deserialize::<AppConfig>()
            .map_err(|e| {
                DeepMailError::Config(format!("Failed to deserialize layered config: {e}"))
            })?
            .apply_secret_providers()
    }

    fn apply_secret_providers(mut self) -> Result<Self, DeepMailError> {
        if let Ok(secret_file) = std::env::var("DEEPMAIL_JWT_SECRET_FILE") {
            let secret = std::fs::read_to_string(&secret_file).map_err(|e| {
                DeepMailError::Config(format!(
                    "Failed to read JWT secret file '{secret_file}': {e}"
                ))
            })?;
            self.security.jwt_secret = secret.trim().to_string();
        }

        if let Ok(secret_cmd) = std::env::var("DEEPMAIL_JWT_SECRET_CMD") {
            let output = std::process::Command::new("sh")
                .arg("-c")
                .arg(&secret_cmd)
                .output()
                .map_err(|e| {
                    DeepMailError::Config(format!(
                        "Failed to execute JWT secret command '{secret_cmd}': {e}"
                    ))
                })?;
            if !output.status.success() {
                return Err(DeepMailError::Config(format!(
                    "JWT secret command failed with status: {}",
                    output.status
                )));
            }
            let secret = String::from_utf8(output.stdout).map_err(|e| {
                DeepMailError::Config(format!("JWT secret command output was not UTF-8: {e}"))
            })?;
            self.security.jwt_secret = secret.trim().to_string();
        }

        if self.security.jwt_secret.trim().is_empty() {
            return Err(DeepMailError::Config(
                "JWT secret cannot be empty after secret provider resolution".to_string(),
            ));
        }

        Ok(self)
    }
}
