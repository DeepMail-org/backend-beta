use serde::Deserialize;
use std::net::SocketAddr;

/// Configuration for the deepmail-dkim service.
///
/// Loaded from config.toml (if present) and overridden by environment variables
/// prefixed with `DEEPMAIL_DKIM_` (e.g., `DEEPMAIL_DKIM_GRPC_ADDR`).
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Address to bind the gRPC server to.
    /// Default: 0.0.0.0:50060
    #[serde(default = "default_grpc_addr")]
    pub grpc_addr: SocketAddr,

    /// PostgreSQL connection string.
    /// Example: postgres://deepmail:secret@localhost:5432/deepmail_dkim
    pub database_url: String,

    /// Timeout for DNS TXT lookups (DKIM key resolution), in milliseconds.
    /// Default: 5000
    #[serde(default = "default_dns_timeout_ms")]
    pub dns_timeout_ms: u64,

    /// TTL for cached DKIM public keys from DNS, in seconds.
    /// Default: 3600 (1 hour)
    #[serde(default = "default_key_cache_ttl_seconds")]
    pub key_cache_ttl_seconds: u64,

    /// NATS server URL for publishing DKIM analysis events.
    /// Default: nats://localhost:4222
    #[serde(default = "default_nats_url")]
    pub nats_url: String,
}

fn default_grpc_addr() -> SocketAddr {
    "0.0.0.0:50060".parse().unwrap()
}

fn default_dns_timeout_ms() -> u64 {
    5000
}

fn default_key_cache_ttl_seconds() -> u64 {
    3600
}

fn default_nats_url() -> String {
    "nats://localhost:4222".to_string()
}

impl Config {
    /// Load configuration from config.toml and DEEPMAIL_DKIM_* environment variables.
    ///
    /// Precedence (highest → lowest):
    /// 1. Environment variables: `DEEPMAIL_DKIM_GRPC_ADDR`, etc.
    /// 2. config.toml `[dkim]` section
    /// 3. Hardcoded defaults
    pub fn load() -> Result<Self, config::ConfigError> {
        let builder = config::Config::builder()
            // Optional config file — not required to exist.
            .add_source(config::File::with_name("config").required(false))
            // Environment variables: DEEPMAIL_DKIM_DATABASE_URL, etc.
            .add_source(
                config::Environment::with_prefix("DEEPMAIL_DKIM")
                    .separator("_")
                    .try_parsing(true),
            )
            .build()?;

        builder.try_deserialize()
    }
}
