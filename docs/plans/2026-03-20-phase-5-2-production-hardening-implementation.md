# Phase 5.2 — Production Hardening & Operational Readiness Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add OTLP tracing export, three-tier RBAC, soft-delete lifecycle, encrypted backup/restore, schema validation, abuse detection, and production deployment configs to DeepMail.

**Architecture:** Layered middleware approach (Approach A). All new features live in existing crates. RBAC uses Axum extractors. Abuse detection combines inline velocity checks with a background pattern scanner. Backup/restore and abuse admin are Superadmin/Admin-gated API endpoints. A single migration (016) covers all schema changes.

**Tech Stack:** Rust 2021 edition, Axum 0.7, rusqlite 0.31, redis 0.25, opentelemetry-otlp 0.28 (grpc-tonic), aes-gcm 0.10, argon2 0.5, tar 0.4, flate2 1.x

**Codebase reminders:**
- Rust edition 2021 — no `let chains`. Use nested `if let` blocks.
- `redis::Value::Data(bytes)` not `BulkString(bytes)` (redis 0.25).
- `tracing_subscriber::registry()` uses `.with(layer)` pattern, not builder methods.
- `ThreatCache` methods use `&self` with internal `conn.clone()`.
- JWT `sub` claim is the canonical `user_id`.
- Config: `config/base.toml` + `config/<env>.toml` + `DEEPMAIL_*` env vars.
- Always run `cargo fmt --all && cargo check --workspace && cargo test --workspace --no-fail-fast` before declaring complete.

---

### Task 1: Migration 016 — Schema Changes

All schema changes in a single migration so subsequent tasks can use the new tables/columns immediately.

**Files:**
- Modify: `crates/deepmail-common/src/db/migrations.rs:301` (append after migration 015)

**Step 1: Add migration 016 to the MIGRATIONS array**

Append this migration after the closing `},` of migration 015 (line 301):

```rust
    Migration {
        name: "016_add_production_hardening",
        sql: "
            -- Soft-delete lifecycle columns on emails
            ALTER TABLE emails ADD COLUMN archived_at TEXT;
            ALTER TABLE emails ADD COLUMN deleted_at TEXT;
            ALTER TABLE emails ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0;

            -- Soft-delete lifecycle columns on attachments
            ALTER TABLE attachments ADD COLUMN archived_at TEXT;
            ALTER TABLE attachments ADD COLUMN deleted_at TEXT;
            ALTER TABLE attachments ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0;

            -- Soft-delete lifecycle columns on analysis_results
            ALTER TABLE analysis_results ADD COLUMN archived_at TEXT;
            ALTER TABLE analysis_results ADD COLUMN deleted_at TEXT;
            ALTER TABLE analysis_results ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0;

            -- Soft-delete lifecycle columns on sandbox_reports
            ALTER TABLE sandbox_reports ADD COLUMN archived_at TEXT;
            ALTER TABLE sandbox_reports ADD COLUMN deleted_at TEXT;
            ALTER TABLE sandbox_reports ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0;

            -- Soft-delete indexes on emails
            CREATE INDEX IF NOT EXISTS idx_emails_archived_at ON emails(archived_at);
            CREATE INDEX IF NOT EXISTS idx_emails_deleted_at ON emails(deleted_at);
            CREATE INDEX IF NOT EXISTS idx_emails_is_deleted ON emails(is_deleted);

            -- User flagging columns
            ALTER TABLE users ADD COLUMN is_flagged INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE users ADD COLUMN flagged_at TEXT;
            ALTER TABLE users ADD COLUMN flagged_reason TEXT;

            -- Abuse events table
            CREATE TABLE IF NOT EXISTS abuse_events (
                id          TEXT PRIMARY KEY NOT NULL,
                user_id     TEXT NOT NULL,
                event_type  TEXT NOT NULL,
                severity    TEXT NOT NULL DEFAULT 'critical',
                details     TEXT,
                auto_flagged INTEGER NOT NULL DEFAULT 0,
                reviewed_by TEXT,
                reviewed_at TEXT,
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_abuse_events_user ON abuse_events(user_id);
            CREATE INDEX IF NOT EXISTS idx_abuse_events_type ON abuse_events(event_type, created_at);
            CREATE INDEX IF NOT EXISTS idx_abuse_events_severity ON abuse_events(severity, reviewed_at);
        ",
    },
```

**Step 2: Run tests**

Run: `cargo test --workspace --no-fail-fast`
Expected: All existing tests pass. Migration applies cleanly.

**Step 3: Commit**

```bash
git add crates/deepmail-common/src/db/migrations.rs
git commit -m "feat: add migration 016 for soft-delete, user flagging, and abuse events"
```

---

### Task 2: Config Expansion — New Sections

Add `BackupConfig`, `AbuseConfig` to `AppConfig`, update `RetentionConfig` and `ObservabilityConfig`, add `Forbidden` error variant.

**Files:**
- Modify: `crates/deepmail-common/src/config.rs` (add structs + defaults)
- Modify: `crates/deepmail-common/src/errors.rs` (add `Forbidden` variant)
- Modify: `config/base.toml` (add new sections)

**Step 1: Add `Forbidden` error variant**

In `crates/deepmail-common/src/errors.rs`, add after the `Auth` variant (line 30):

```rust
    #[error("Forbidden: {0}")]
    Forbidden(String),
```

In the `IntoResponse` impl, add to the match (after the `Auth` arm, line 50):

```rust
            DeepMailError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
```

In the safe_message match (after the `Auth` arm, line 61):

```rust
            DeepMailError::Forbidden(msg) => msg.clone(),
```

**Step 2: Update `ObservabilityConfig`**

In `crates/deepmail-common/src/config.rs`, replace the `ObservabilityConfig` struct (lines 171-177) with:

```rust
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
```

Add default functions:

```rust
fn default_otlp_enabled() -> bool { false }
fn default_otlp_batch_size() -> u32 { 512 }
fn default_otlp_batch_timeout_secs() -> u64 { 5 }
```

**Step 3: Update `RetentionConfig`**

Replace the `RetentionConfig` struct (lines 193-203) with:

```rust
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
```

Replace the old default functions (`default_retention_emails_ttl_days`, `default_retention_sandbox_ttl_days`) with:

```rust
fn default_retention_archive_after_days() -> u32 { 30 }
fn default_retention_soft_delete_after_days() -> u32 { 30 }
fn default_retention_purge_after_days() -> u32 { 30 }
```

Keep `default_retention_logs_ttl_days` and `default_retention_interval_secs` unchanged.

**Step 4: Add `BackupConfig`**

Add after `CircuitBreakerConfig`:

```rust
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

fn default_backup_dir() -> String { "data/backups".to_string() }
fn default_backup_passphrase_env_var() -> String { "DEEPMAIL_BACKUP_PASSPHRASE".to_string() }
fn default_argon2_memory_kib() -> u32 { 65536 }
fn default_argon2_iterations() -> u32 { 3 }
fn default_argon2_parallelism() -> u32 { 4 }
```

**Step 5: Add `AbuseConfig`**

Add after `BackupConfig`:

```rust
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

fn default_abuse_enabled() -> bool { true }
fn default_abuse_upload_velocity() -> u32 { 20 }
fn default_abuse_sandbox_velocity() -> u32 { 15 }
fn default_abuse_failed_threshold() -> u32 { 10 }
fn default_abuse_pattern_scan_interval() -> u64 { 300 }
fn default_abuse_repeated_hash_threshold() -> u32 { 5 }
fn default_abuse_sandbox_harvest_threshold() -> u32 { 50 }
```

**Step 6: Add `admin_ip_allowlist` to `SecurityConfig`**

Update `SecurityConfig` (lines 69-77) to add:

```rust
    #[serde(default)]
    pub admin_ip_allowlist: Vec<String>,
```

**Step 7: Add new fields to `AppConfig`**

Add `backup` and `abuse` fields to `AppConfig` struct (after `circuit_breaker`, line 29):

```rust
    pub backup: BackupConfig,
    pub abuse: AbuseConfig,
```

**Step 8: Update `config/base.toml`**

Replace the `[retention]` section with:

```toml
[retention]
archive_after_days = 30
soft_delete_after_days = 30
purge_after_days = 30
cleanup_interval_secs = 3600
logs_ttl_days = 14
```

Add the following new sections at the end:

```toml
[backup]
backup_dir = "data/backups"
passphrase_env_var = "DEEPMAIL_BACKUP_PASSPHRASE"
argon2_memory_kib = 65536
argon2_iterations = 3
argon2_parallelism = 4

[abuse]
enabled = true
upload_velocity_per_min = 20
sandbox_velocity_per_min = 15
failed_upload_threshold_5min = 10
pattern_scan_interval_secs = 300
repeated_malicious_hash_threshold = 5
sandbox_harvest_threshold = 50
```

Also add to `[observability]`:
```toml
otlp_enabled = false
otlp_batch_size = 512
otlp_batch_timeout_secs = 5
```

**Step 9: Verify**

Run: `cargo check --workspace`
Expected: Compiles. Some warnings expected about unused fields (they'll be consumed in later tasks).

**Step 10: Commit**

```bash
git add -A
git commit -m "feat: add config structs for backup, abuse, updated retention + observability"
```

---

### Task 3: Shared `init_tracing()` with OTLP Export

Move tracing initialization to `deepmail-common` so all three binaries share identical setup. Wire the OTLP gRPC exporter when enabled.

**Files:**
- Create: `crates/deepmail-common/src/telemetry.rs`
- Modify: `crates/deepmail-common/src/lib.rs:19` (add `pub mod telemetry;`)
- Modify: `crates/deepmail-common/Cargo.toml` (add tracing/otel deps)
- Modify: `crates/deepmail-api/src/main.rs` (use shared init_tracing)
- Modify: `crates/deepmail-worker/src/main.rs` (use shared init_tracing)
- Modify: `crates/deepmail-sandbox-worker/src/main.rs` (use shared init_tracing)

**Step 1: Add OTel dependencies to deepmail-common**

In `crates/deepmail-common/Cargo.toml`, add:

```toml
tracing-subscriber = { workspace = true }
tracing-opentelemetry = { workspace = true }
opentelemetry = { workspace = true }
opentelemetry-otlp = { workspace = true }
opentelemetry_sdk = { workspace = true }
```

**Step 2: Create `crates/deepmail-common/src/telemetry.rs`**

```rust
//! Shared tracing + OpenTelemetry initialization for all DeepMail binaries.
//!
//! Provides a single `init_tracing()` function that configures:
//! - Structured logging (JSON or pretty)
//! - Environment-based log filtering
//! - OpenTelemetry trace context propagation
//! - Optional OTLP gRPC span export (when `otlp_enabled = true`)

use opentelemetry::trace::TracerProvider;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::{LoggingConfig, ObservabilityConfig};

/// Initialize the tracing subscriber with optional OTLP export.
///
/// Call this once at startup in each binary. The `service_name` parameter
/// distinguishes traces from different binaries (e.g. "deepmail-api").
pub fn init_tracing(
    logging: &LoggingConfig,
    observability: &ObservabilityConfig,
    service_name: &str,
) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&logging.level));

    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

    let provider = if observability.otlp_enabled {
        build_otlp_provider(observability, service_name)
    } else {
        opentelemetry_sdk::trace::SdkTracerProvider::builder().build()
    };

    let tracer = provider.tracer(service_name.to_string());
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    match logging.format.as_str() {
        "json" => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(otel_layer)
                .with(tracing_subscriber::fmt::layer().json())
                .init();
        }
        _ => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(otel_layer)
                .with(tracing_subscriber::fmt::layer().pretty())
                .init();
        }
    }
}

/// Build a TracerProvider with an OTLP gRPC batch exporter.
fn build_otlp_provider(
    config: &ObservabilityConfig,
    _service_name: &str,
) -> opentelemetry_sdk::trace::SdkTracerProvider {
    use opentelemetry_otlp::SpanExporter;

    // Build the OTLP span exporter with gRPC (tonic) transport.
    // If the exporter fails to build, fall back to a no-op provider.
    let exporter = match SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&config.otlp_endpoint)
        .build()
    {
        Ok(exp) => exp,
        Err(e) => {
            eprintln!(
                "WARNING: Failed to build OTLP exporter ({}), traces will not be exported: {}",
                config.otlp_endpoint, e
            );
            return opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
        }
    };

    let batch_processor = opentelemetry_sdk::trace::BatchSpanProcessor::builder(exporter)
        .with_max_export_batch_size(config.otlp_batch_size as usize)
        .with_scheduled_delay(std::time::Duration::from_secs(config.otlp_batch_timeout_secs))
        .build();

    opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_span_processor(batch_processor)
        .build()
}
```

**Step 3: Register module in lib.rs**

In `crates/deepmail-common/src/lib.rs`, add:

```rust
pub mod telemetry;
```

**Step 4: Update deepmail-api main.rs**

Replace the `init_tracing` function definition and its call in `crates/deepmail-api/src/main.rs`.

Remove the entire `fn init_tracing(level: &str, format: &str, service_name: &str)` function (lines 124-147).

Remove these imports that are no longer needed locally (they're now in deepmail-common):
- `use opentelemetry::trace::TracerProvider;`
- `use opentelemetry_sdk::propagation::TraceContextPropagator;`
- `use tracing_subscriber::EnvFilter;`
- `use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};`

Replace the `init_tracing(...)` call (lines 42-46) with:

```rust
    deepmail_common::telemetry::init_tracing(
        &config.logging,
        &config.observability,
        "deepmail-api",
    );
```

**Step 5: Update deepmail-worker main.rs**

Replace the tracing init block (lines 31-41) with:

```rust
    let config = DeepMailConfig::load()?;
    deepmail_common::telemetry::init_tracing(
        &config.logging,
        &config.observability,
        "deepmail-worker",
    );
```

Move the `let config = DeepMailConfig::load()?;` line (currently line 46) to before the tracing init (it's needed for the config reference). Remove the duplicate.

Remove unused imports:
- `use opentelemetry::trace::TracerProvider;`
- `use opentelemetry_sdk::propagation::TraceContextPropagator;`
- `use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};`

**Step 6: Update deepmail-sandbox-worker main.rs**

Replace the tracing init block (lines 22-33) with:

```rust
    let config = DeepMailConfig::load()?;
    deepmail_common::telemetry::init_tracing(
        &config.logging,
        &config.observability,
        "deepmail-sandbox-worker",
    );
```

Remove the duplicate `let config = DeepMailConfig::load()?;` on line 35. Remove unused OTel imports.

**Step 7: Verify**

Run: `cargo fmt --all && cargo check --workspace`
Expected: Compiles cleanly.

**Step 8: Commit**

```bash
git add -A
git commit -m "feat: shared init_tracing with OTLP gRPC batch export"
```

---

### Task 4: UserRole Enum + AuthUser Extractor

Add the `UserRole` enum to `deepmail-common` and refactor auth to return role-aware `AuthUser`.

**Files:**
- Create: `crates/deepmail-common/src/auth.rs`
- Modify: `crates/deepmail-common/src/lib.rs` (add `pub mod auth;`)
- Modify: `crates/deepmail-api/src/auth.rs` (rewrite with role extraction + extractors)

**Step 1: Create `crates/deepmail-common/src/auth.rs`**

```rust
//! Role-based authorization primitives shared across all crates.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Three-tier role hierarchy: Superadmin > Admin > Analyst.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    Analyst,
    Admin,
    Superadmin,
}

impl UserRole {
    /// Numeric privilege level for comparison.
    fn level(&self) -> u8 {
        match self {
            UserRole::Analyst => 0,
            UserRole::Admin => 1,
            UserRole::Superadmin => 2,
        }
    }

    /// Returns true if `self` has at least `minimum` privilege.
    pub fn has_at_least(&self, minimum: &UserRole) -> bool {
        self.level() >= minimum.level()
    }
}

impl fmt::Display for UserRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserRole::Analyst => write!(f, "analyst"),
            UserRole::Admin => write!(f, "admin"),
            UserRole::Superadmin => write!(f, "superadmin"),
        }
    }
}

impl std::str::FromStr for UserRole {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "analyst" => Ok(UserRole::Analyst),
            "admin" => Ok(UserRole::Admin),
            "superadmin" => Ok(UserRole::Superadmin),
            other => Err(format!("Unknown role: {other}")),
        }
    }
}
```

**Step 2: Register in lib.rs**

In `crates/deepmail-common/src/lib.rs`, add `pub mod auth;` (alphabetically, before `pub mod audit;` or after — just keep it ordered).

**Step 3: Rewrite `crates/deepmail-api/src/auth.rs`**

Replace the entire file with:

```rust
//! JWT authentication and role-based authorization extractors.
//!
//! Three extractors are provided:
//! - `AuthUser` — extracts user_id + role from JWT. All authenticated routes use this.
//! - `RequireAdmin` — wraps AuthUser, rejects if role < Admin.
//! - `RequireSuperadmin` — wraps AuthUser, rejects if role < Superadmin.

use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use deepmail_common::auth::UserRole;
use deepmail_common::errors::DeepMailError;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
struct Claims {
    pub sub: String,
    #[serde(rename = "exp")]
    pub _exp: usize,
    #[serde(default = "default_role")]
    pub role: String,
}

fn default_role() -> String {
    "analyst".to_string()
}

/// Authenticated user extracted from JWT.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: String,
    pub role: UserRole,
}

impl<S> FromRequestParts<S> for AuthUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = DeepMailError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let config = app_state.config();

        let auth = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| DeepMailError::Auth("Missing Authorization header".to_string()))?;

        let token = auth
            .strip_prefix("Bearer ")
            .ok_or_else(|| DeepMailError::Auth("Invalid auth scheme".to_string()))?;

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;

        let decoded = decode::<Claims>(
            token,
            &DecodingKey::from_secret(config.security.jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|e| DeepMailError::Auth(format!("Invalid token: {e}")))?;

        if decoded.claims.sub.trim().is_empty() {
            return Err(DeepMailError::Auth("Token missing subject".to_string()));
        }

        let role: UserRole = decoded
            .claims
            .role
            .parse()
            .map_err(|e: String| DeepMailError::Auth(e))?;

        Ok(AuthUser {
            user_id: decoded.claims.sub,
            role,
        })
    }
}

/// Extractor that requires Admin or higher role.
#[derive(Debug, Clone)]
pub struct RequireAdmin(pub AuthUser);

impl<S> FromRequestParts<S> for RequireAdmin
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = DeepMailError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        if !user.role.has_at_least(&UserRole::Admin) {
            return Err(DeepMailError::Forbidden(
                "Admin role required".to_string(),
            ));
        }
        Ok(RequireAdmin(user))
    }
}

/// Extractor that requires Superadmin role.
#[derive(Debug, Clone)]
pub struct RequireSuperadmin(pub AuthUser);

impl<S> FromRequestParts<S> for RequireSuperadmin
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = DeepMailError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        if !user.role.has_at_least(&UserRole::Superadmin) {
            return Err(DeepMailError::Forbidden(
                "Superadmin role required".to_string(),
            ));
        }
        Ok(RequireSuperadmin(user))
    }
}

/// Trait import needed for FromRef. Re-export so callers don't need axum::extract::FromRef.
use axum::extract::FromRef;

impl FromRef<AppState> for AppState {
    fn from_ref(input: &AppState) -> Self {
        input.clone()
    }
}
```

**Step 4: Update route handlers to use AuthUser**

In `crates/deepmail-api/src/routes/upload.rs`:
- Replace `use crate::auth::extract_user_id;` with `use crate::auth::AuthUser;`
- Change the handler signature: remove `headers: HeaderMap` parameter, add `auth: AuthUser` parameter
- Replace `let user_id = extract_user_id(&headers, state.config())?;` with `let user_id = auth.user_id;`
- Keep the `headers` parameter only for the `x-request-id` extraction in the job payload. You can get headers from `parts` or just accept `HeaderMap` as a separate extractor alongside `AuthUser`.

In `crates/deepmail-api/src/routes/results.rs`:
- Same pattern: replace `extract_user_id` with `AuthUser` extractor.

In `crates/deepmail-api/src/routes/ws_results.rs`:
- Same pattern.

In `crates/deepmail-api/src/routes/admin_replay.rs`:
- Add `RequireAdmin` extractor.

**Step 5: Verify**

Run: `cargo fmt --all && cargo check --workspace`
Expected: Compiles. Some existing tests may need JWT payload updates to include `role` field.

**Step 6: Commit**

```bash
git add -A
git commit -m "feat: three-tier RBAC with AuthUser/RequireAdmin/RequireSuperadmin extractors"
```

---

### Task 5: IP Allowlist Middleware for Admin Routes

**Files:**
- Create: `crates/deepmail-api/src/middleware/ip_allowlist.rs`
- Modify: `crates/deepmail-api/src/middleware/mod.rs` (if exists, or `main.rs`)
- Modify: `crates/deepmail-api/src/routes/mod.rs` (apply middleware to admin routes)

**Step 1: Create IP allowlist middleware**

```rust
//! IP allowlist middleware for admin route protection.
//!
//! When `security.admin_ip_allowlist` is non-empty, only requests from
//! listed IPs are permitted to access admin endpoints. Empty list = disabled.

use axum::extract::ConnectInfo;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use std::net::SocketAddr;

use deepmail_common::errors::DeepMailError;

/// Middleware that checks the client IP against the configured allowlist.
pub async fn ip_allowlist_check<B>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    allowlist: axum::extract::Extension<IpAllowlist>,
    request: Request<B>,
    next: Next<B>,
) -> Result<Response, DeepMailError> {
    if allowlist.0.is_empty() {
        return Ok(next.run(request).await);
    }

    let client_ip = addr.ip().to_string();

    // Also check X-Forwarded-For if present
    let forwarded_ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string());

    let ip_to_check = forwarded_ip.as_deref().unwrap_or(&client_ip);

    if allowlist.0.contains(&ip_to_check.to_string()) {
        Ok(next.run(request).await)
    } else {
        Err(DeepMailError::Forbidden(format!(
            "IP {ip_to_check} not in admin allowlist"
        )))
    }
}

/// Wrapper type for the IP allowlist, used as an Axum Extension.
#[derive(Clone)]
pub struct IpAllowlist(pub Vec<String>);
```

**Note:** The exact middleware signature depends on the Axum 0.7 middleware pattern. If the generic `B` body approach doesn't compile with Axum 0.7, use `axum::body::Body` directly instead. Axum 0.7 uses `axum::middleware::from_fn` which expects `axum::body::Body`.

**Step 2: Update route registration**

In `crates/deepmail-api/src/routes/mod.rs`, separate admin routes and apply the IP allowlist layer:

```rust
pub fn api_routes(state: AppState) -> Router {
    let public_routes = Router::new()
        .merge(health::routes())
        .merge(upload::routes())
        .merge(results::routes())
        .merge(ws_results::routes())
        .merge(metrics::routes());

    let admin_routes = Router::new()
        .merge(admin_replay::routes())
        // future: .merge(admin_backup::routes())
        // future: .merge(admin_abuse::routes())
        ;

    Router::new()
        .merge(public_routes)
        .merge(admin_routes)
        .with_state(state)
}
```

**Step 3: Verify**

Run: `cargo fmt --all && cargo check --workspace`

**Step 4: Commit**

```bash
git add -A
git commit -m "feat: IP allowlist middleware for admin route protection"
```

---

### Task 6: Schema Version Validation

**Files:**
- Create: `crates/deepmail-common/src/db/schema_validation.rs`
- Modify: `crates/deepmail-common/src/db/mod.rs` (add module, export)
- Modify: `crates/deepmail-api/src/main.rs` (call after init_pool)
- Modify: `crates/deepmail-worker/src/main.rs` (call after init_pool)
- Modify: `crates/deepmail-sandbox-worker/src/main.rs` (call after init_pool)

**Step 1: Create schema validation module**

```rust
//! Schema version validation — refuses to start if the database has
//! more migrations applied than the binary knows about.

use rusqlite::Connection;

use crate::db::migrations::MIGRATION_COUNT;
use crate::errors::DeepMailError;

/// Validate that the database schema version is compatible with this binary.
///
/// - If the DB has more migrations than the binary knows, refuse to start
///   (the binary may be outdated).
/// - If the DB has fewer, `run_migrations()` should have already caught up.
///   If it hasn't, something is wrong.
pub fn validate_schema(conn: &Connection) -> Result<(), DeepMailError> {
    let applied: u32 = conn
        .query_row("SELECT COUNT(*) FROM _migrations", [], |row| row.get(0))
        .map_err(|e| {
            DeepMailError::Database(format!("Failed to count applied migrations: {e}"))
        })?;

    let expected = MIGRATION_COUNT;

    if applied > expected {
        return Err(DeepMailError::Database(format!(
            "Database has {applied} migrations applied but this binary only knows {expected}. \
             Refusing to start — the binary may be outdated for this database."
        )));
    }

    if applied < expected {
        return Err(DeepMailError::Database(format!(
            "Database has only {applied} migrations after run_migrations() — expected {expected}. \
             Some migrations may have failed silently."
        )));
    }

    tracing::info!(
        applied_migrations = applied,
        "Schema version validated"
    );
    Ok(())
}
```

**Step 2: Expose `MIGRATION_COUNT` from migrations.rs**

In `crates/deepmail-common/src/db/migrations.rs`, add after the `MIGRATIONS` array (line 302):

```rust
/// Total number of migrations the binary knows about.
pub const MIGRATION_COUNT: u32 = MIGRATIONS.len() as u32;
```

**Note:** `MIGRATIONS.len()` in a `const` context requires that `MIGRATIONS` is a `const` slice, which it is (`&[Migration]`). However, `.len()` on a `const` slice might not work in const context in Rust 2021. If it doesn't compile, use a hardcoded value:

```rust
pub const MIGRATION_COUNT: u32 = 16; // Must match MIGRATIONS.len()
```

**Step 3: Add to db/mod.rs**

Add `pub mod schema_validation;` to the db module.

**Step 4: Call in all three binaries**

After `let db_pool = db::init_pool(...)`:

```rust
{
    let conn = db_pool.get()?;
    deepmail_common::db::schema_validation::validate_schema(&conn)?;
}
```

**Step 5: Verify**

Run: `cargo check --workspace && cargo test --workspace --no-fail-fast`

**Step 6: Commit**

```bash
git add -A
git commit -m "feat: schema version validation at startup"
```

---

### Task 7: Soft-Delete Retention Overhaul

**Files:**
- Rewrite: `crates/deepmail-common/src/retention.rs`

**Step 1: Rewrite retention.rs**

Replace the entire file with the three-phase lifecycle implementation:

```rust
//! Data retention with three-phase lifecycle:
//! active → archived → soft-deleted → hard-purged.
//!
//! Each phase is time-driven by the background cleanup loop.
//! Children (attachments, analysis_results, sandbox_reports) cascade
//! with their parent email.

use chrono::{Duration, Utc};

use crate::config::RetentionConfig;
use crate::db::DbPool;
use crate::errors::DeepMailError;

/// Run all three retention phases in order.
pub fn run_retention_cleanup(pool: &DbPool, cfg: &RetentionConfig) -> Result<(), DeepMailError> {
    let conn = pool.get()?;

    let archived = run_archive_phase(&conn, cfg)?;
    let soft_deleted = run_soft_delete_phase(&conn, cfg)?;
    let purged = run_purge_phase(&conn, cfg)?;
    let purged_logs = run_logs_purge(&conn, cfg)?;

    tracing::info!(
        archived_emails = archived,
        soft_deleted_emails = soft_deleted,
        purged_emails = purged,
        purged_audit_logs = purged_logs,
        "Retention cleanup completed"
    );

    Ok(())
}

/// Phase 1: Mark active records as archived when they exceed the archive window.
fn run_archive_phase(
    conn: &rusqlite::Connection,
    cfg: &RetentionConfig,
) -> Result<usize, DeepMailError> {
    let cutoff = (Utc::now() - Duration::days(cfg.archive_after_days as i64)).to_rfc3339();
    let now = Utc::now().to_rfc3339();

    // Archive emails
    let email_count = conn.execute(
        "UPDATE emails SET archived_at = ?1
         WHERE submitted_at < ?2 AND archived_at IS NULL AND is_deleted = 0",
        rusqlite::params![now, cutoff],
    )?;

    // Cascade to children of newly archived emails
    conn.execute(
        "UPDATE attachments SET archived_at = ?1
         WHERE email_id IN (SELECT id FROM emails WHERE archived_at = ?1)
         AND archived_at IS NULL",
        rusqlite::params![now],
    )?;
    conn.execute(
        "UPDATE analysis_results SET archived_at = ?1
         WHERE email_id IN (SELECT id FROM emails WHERE archived_at = ?1)
         AND archived_at IS NULL",
        rusqlite::params![now],
    )?;
    conn.execute(
        "UPDATE sandbox_reports SET archived_at = ?1
         WHERE email_id IN (SELECT id FROM emails WHERE archived_at = ?1)
         AND archived_at IS NULL",
        rusqlite::params![now],
    )?;

    Ok(email_count)
}

/// Phase 2: Soft-delete archived records past the grace period.
fn run_soft_delete_phase(
    conn: &rusqlite::Connection,
    cfg: &RetentionConfig,
) -> Result<usize, DeepMailError> {
    let cutoff = (Utc::now() - Duration::days(cfg.soft_delete_after_days as i64)).to_rfc3339();
    let now = Utc::now().to_rfc3339();

    let email_count = conn.execute(
        "UPDATE emails SET deleted_at = ?1, is_deleted = 1
         WHERE archived_at IS NOT NULL AND archived_at < ?2 AND deleted_at IS NULL",
        rusqlite::params![now, cutoff],
    )?;

    // Cascade to children
    conn.execute(
        "UPDATE attachments SET deleted_at = ?1, is_deleted = 1
         WHERE email_id IN (SELECT id FROM emails WHERE deleted_at = ?1 AND is_deleted = 1)
         AND deleted_at IS NULL",
        rusqlite::params![now],
    )?;
    conn.execute(
        "UPDATE analysis_results SET deleted_at = ?1, is_deleted = 1
         WHERE email_id IN (SELECT id FROM emails WHERE deleted_at = ?1 AND is_deleted = 1)
         AND deleted_at IS NULL",
        rusqlite::params![now],
    )?;
    conn.execute(
        "UPDATE sandbox_reports SET deleted_at = ?1, is_deleted = 1
         WHERE email_id IN (SELECT id FROM emails WHERE deleted_at = ?1 AND is_deleted = 1)
         AND deleted_at IS NULL",
        rusqlite::params![now],
    )?;

    Ok(email_count)
}

/// Phase 3: Hard-purge soft-deleted records past the purge window.
/// Children are deleted before parents to respect foreign key constraints.
fn run_purge_phase(
    conn: &rusqlite::Connection,
    cfg: &RetentionConfig,
) -> Result<usize, DeepMailError> {
    let cutoff = (Utc::now() - Duration::days(cfg.purge_after_days as i64)).to_rfc3339();

    // Purge children first
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

    // Purge job_progress for purged emails
    conn.execute(
        "DELETE FROM job_progress WHERE email_id IN (
            SELECT id FROM emails WHERE is_deleted = 1 AND deleted_at < ?1
        )",
        rusqlite::params![cutoff],
    )?;

    // Purge ioc_relations for purged emails
    conn.execute(
        "DELETE FROM ioc_relations WHERE email_id IN (
            SELECT id FROM emails WHERE is_deleted = 1 AND deleted_at < ?1
        )",
        rusqlite::params![cutoff],
    )?;

    // Finally purge emails
    let email_count = conn.execute(
        "DELETE FROM emails WHERE is_deleted = 1 AND deleted_at < ?1",
        rusqlite::params![cutoff],
    )?;

    Ok(email_count)
}

/// Purge old audit logs (hard-delete only — no soft-delete lifecycle).
fn run_logs_purge(
    conn: &rusqlite::Connection,
    cfg: &RetentionConfig,
) -> Result<usize, DeepMailError> {
    let cutoff = (Utc::now() - Duration::days(cfg.logs_ttl_days as i64)).to_rfc3339();
    let count = conn.execute(
        "DELETE FROM audit_logs WHERE timestamp < ?1",
        rusqlite::params![cutoff],
    )?;
    Ok(count)
}
```

**Step 2: Update query filters in results.rs**

In `crates/deepmail-api/src/routes/results.rs`, add `AND is_deleted = 0 AND archived_at IS NULL` to the emails query (line 123-125):

```sql
SELECT id, original_name, sha256_hash, file_size, submitted_at,
       status, current_stage, completed_at, error_message
FROM emails WHERE id = ?1 AND submitted_by = ?2 AND is_deleted = 0 AND archived_at IS NULL
```

**Step 3: Update query filters in upload.rs dedup check**

In `crates/deepmail-api/src/routes/upload.rs`, add `AND is_deleted = 0` to the dedup query (line 94):

```sql
SELECT id, status FROM emails WHERE sha256_hash = ?1 AND status = 'completed' AND is_deleted = 0 LIMIT 1
```

**Step 4: Verify**

Run: `cargo fmt --all && cargo check --workspace && cargo test --workspace --no-fail-fast`

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: three-phase retention lifecycle (archive → soft-delete → purge)"
```

---

### Task 8: Backup/Restore System

**Files:**
- Create: `crates/deepmail-common/src/backup.rs`
- Modify: `crates/deepmail-common/src/lib.rs` (add `pub mod backup;`)
- Modify: `crates/deepmail-common/Cargo.toml` (add aes-gcm, argon2, tar, flate2)
- Modify: `Cargo.toml` (add workspace deps)
- Create: `crates/deepmail-api/src/routes/admin_backup.rs`
- Modify: `crates/deepmail-api/src/routes/mod.rs` (register admin_backup routes)

**Step 1: Add workspace dependencies**

In root `Cargo.toml`, add to `[workspace.dependencies]`:

```toml
aes-gcm = "0.10"
argon2 = "0.5"
tar = "0.4"
flate2 = "1"
rand = "0.8"
```

In `crates/deepmail-common/Cargo.toml`, add:

```toml
aes-gcm = { workspace = true }
argon2 = { workspace = true }
tar = { workspace = true }
flate2 = { workspace = true }
rand = { workspace = true }
```

**Step 2: Create `crates/deepmail-common/src/backup.rs`**

```rust
//! SQLite backup and restore with AES-256-GCM encryption.
//!
//! Backup pipeline:
//!   SQLite .backup → temp .db → tar.gz (db + manifest.json) → AES-256-GCM → .tar.gz.enc
//!
//! Restore pipeline:
//!   .tar.gz.enc → decrypt → extract → verify SHA-256 → SQLite .backup (reverse)

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use chrono::Utc;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::BackupConfig;
use crate::db::DbPool;
use crate::errors::DeepMailError;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupManifest {
    pub version: String,
    pub created_at: String,
    pub schema_version: u32,
    pub migration_count: u32,
    pub db_sha256: String,
    pub db_size_bytes: u64,
    pub deepmail_version: String,
}

#[derive(Debug, Serialize)]
pub struct BackupResult {
    pub path: String,
    pub manifest: BackupManifest,
}

/// Create an encrypted backup of the database.
pub fn create_backup(
    pool: &DbPool,
    config: &BackupConfig,
    migration_count: u32,
) -> Result<BackupResult, DeepMailError> {
    let passphrase = read_passphrase(&config.passphrase_env_var)?;

    // Ensure backup directory exists
    fs::create_dir_all(&config.backup_dir)
        .map_err(|e| DeepMailError::Internal(format!("Failed to create backup dir: {e}")))?;

    // Step 1: SQLite consistent snapshot
    let conn = pool.get()?;
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let temp_db_path = PathBuf::from(&config.backup_dir).join(format!("temp-{timestamp}.db"));

    {
        let dest = rusqlite::Connection::open(&temp_db_path)
            .map_err(|e| DeepMailError::Database(format!("Failed to open backup dest: {e}")))?;
        let backup = rusqlite::backup::Backup::new(&conn, &dest)
            .map_err(|e| DeepMailError::Database(format!("Failed to init backup: {e}")))?;
        backup
            .run_to_completion(100, std::time::Duration::from_millis(10), None)
            .map_err(|e| DeepMailError::Database(format!("Backup failed: {e}")))?;
    }

    // Step 2: Compute SHA-256 of the raw DB
    let db_bytes = fs::read(&temp_db_path)
        .map_err(|e| DeepMailError::Internal(format!("Failed to read backup db: {e}")))?;
    let db_sha256 = hex::encode(Sha256::digest(&db_bytes));
    let db_size = db_bytes.len() as u64;

    // Step 3: Create manifest
    let manifest = BackupManifest {
        version: "1.0".to_string(),
        created_at: Utc::now().to_rfc3339(),
        schema_version: migration_count,
        migration_count,
        db_sha256: db_sha256.clone(),
        db_size_bytes: db_size,
        deepmail_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let manifest_json = serde_json::to_string_pretty(&manifest)?;

    // Step 4: Create tar.gz archive
    let tar_gz_bytes = {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut tar_builder = tar::Builder::new(&mut encoder);

            // Add manifest.json
            let manifest_bytes = manifest_json.as_bytes();
            let mut header = tar::Header::new_gnu();
            header.set_size(manifest_bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar_builder
                .append_data(&mut header, "manifest.json", manifest_bytes)
                .map_err(|e| DeepMailError::Internal(format!("Tar append manifest failed: {e}")))?;

            // Add database
            let mut header = tar::Header::new_gnu();
            header.set_size(db_size);
            header.set_mode(0o600);
            header.set_cksum();
            tar_builder
                .append_data(&mut header, "deepmail.db", db_bytes.as_slice())
                .map_err(|e| DeepMailError::Internal(format!("Tar append db failed: {e}")))?;

            tar_builder
                .finish()
                .map_err(|e| DeepMailError::Internal(format!("Tar finish failed: {e}")))?;
        }
        encoder
            .finish()
            .map_err(|e| DeepMailError::Internal(format!("Gzip finish failed: {e}")))?
    };

    // Step 5: Encrypt with AES-256-GCM
    let encrypted = encrypt_data(&tar_gz_bytes, &passphrase, config)?;

    // Step 6: Write encrypted file
    let output_path =
        PathBuf::from(&config.backup_dir).join(format!("deepmail-backup-{timestamp}.tar.gz.enc"));
    fs::write(&output_path, &encrypted)
        .map_err(|e| DeepMailError::Internal(format!("Failed to write backup: {e}")))?;

    // Cleanup temp db
    let _ = fs::remove_file(&temp_db_path);

    tracing::info!(
        path = %output_path.display(),
        sha256 = %db_sha256,
        size = db_size,
        "Backup created successfully"
    );

    Ok(BackupResult {
        path: output_path.to_string_lossy().to_string(),
        manifest,
    })
}

/// Restore a database from an encrypted backup.
pub fn restore_backup(
    pool: &DbPool,
    backup_path: &str,
    passphrase: &str,
    current_migration_count: u32,
) -> Result<BackupManifest, DeepMailError> {
    // Step 1: Read and decrypt
    let encrypted = fs::read(backup_path)
        .map_err(|e| DeepMailError::Internal(format!("Failed to read backup file: {e}")))?;
    let tar_gz_bytes = decrypt_data(&encrypted, passphrase)?;

    // Step 2: Extract tar.gz
    let decoder = GzDecoder::new(tar_gz_bytes.as_slice());
    let mut archive = tar::Archive::new(decoder);

    let mut manifest_bytes: Option<Vec<u8>> = None;
    let mut db_bytes: Option<Vec<u8>> = None;

    for entry in archive
        .entries()
        .map_err(|e| DeepMailError::Internal(format!("Tar entries failed: {e}")))?
    {
        let mut entry =
            entry.map_err(|e| DeepMailError::Internal(format!("Tar entry failed: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| DeepMailError::Internal(format!("Tar path failed: {e}")))?
            .to_string_lossy()
            .to_string();

        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .map_err(|e| DeepMailError::Internal(format!("Tar read failed: {e}")))?;

        match path.as_str() {
            "manifest.json" => manifest_bytes = Some(buf),
            "deepmail.db" => db_bytes = Some(buf),
            _ => {}
        }
    }

    let manifest_bytes = manifest_bytes
        .ok_or_else(|| DeepMailError::Internal("Backup missing manifest.json".to_string()))?;
    let db_bytes = db_bytes
        .ok_or_else(|| DeepMailError::Internal("Backup missing deepmail.db".to_string()))?;

    // Step 3: Parse and verify manifest
    let manifest: BackupManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| DeepMailError::Internal(format!("Invalid manifest: {e}")))?;

    // Verify SHA-256
    let actual_sha256 = hex::encode(Sha256::digest(&db_bytes));
    if actual_sha256 != manifest.db_sha256 {
        return Err(DeepMailError::Internal(format!(
            "Backup integrity check failed: expected SHA-256 {}, got {}",
            manifest.db_sha256, actual_sha256
        )));
    }

    // Verify migration compatibility
    if manifest.migration_count > current_migration_count {
        return Err(DeepMailError::Internal(format!(
            "Backup has {} migrations but binary only knows {}. Upgrade the binary first.",
            manifest.migration_count, current_migration_count
        )));
    }

    // Step 4: Write temp DB and restore via SQLite backup API
    let temp_path = format!("/tmp/deepmail-restore-{}.db", Utc::now().timestamp());
    fs::write(&temp_path, &db_bytes)
        .map_err(|e| DeepMailError::Internal(format!("Failed to write temp db: {e}")))?;

    {
        let source = rusqlite::Connection::open(&temp_path)
            .map_err(|e| DeepMailError::Database(format!("Failed to open restore source: {e}")))?;
        let dest_conn = pool.get()?;
        let backup = rusqlite::backup::Backup::new(&source, &dest_conn)
            .map_err(|e| DeepMailError::Database(format!("Failed to init restore: {e}")))?;
        backup
            .run_to_completion(100, std::time::Duration::from_millis(10), None)
            .map_err(|e| DeepMailError::Database(format!("Restore failed: {e}")))?;
    }

    let _ = fs::remove_file(&temp_path);

    tracing::info!(
        backup_path = %backup_path,
        schema_version = manifest.schema_version,
        "Database restored from backup"
    );

    Ok(manifest)
}

fn read_passphrase(env_var: &str) -> Result<String, DeepMailError> {
    std::env::var(env_var).map_err(|_| {
        DeepMailError::Config(format!(
            "Backup passphrase not set. Set the {env_var} environment variable."
        ))
    })
}

fn encrypt_data(
    data: &[u8],
    passphrase: &str,
    config: &BackupConfig,
) -> Result<Vec<u8>, DeepMailError> {
    use rand::RngCore;

    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let key = derive_key(passphrase, &salt, config)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| DeepMailError::Internal(format!("Cipher init failed: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| DeepMailError::Internal(format!("Encryption failed: {e}")))?;

    // Output: [salt][nonce][ciphertext (includes GCM tag)]
    let mut output = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

fn decrypt_data(data: &[u8], passphrase: &str) -> Result<Vec<u8>, DeepMailError> {
    if data.len() < SALT_LEN + NONCE_LEN {
        return Err(DeepMailError::Internal(
            "Encrypted data too short".to_string(),
        ));
    }

    let salt = &data[..SALT_LEN];
    let nonce_bytes = &data[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &data[SALT_LEN + NONCE_LEN..];

    // Use default Argon2 params for decryption (must match what was used for encryption).
    // We hardcode the same defaults here since we don't store config in the backup.
    let config = crate::config::BackupConfig {
        backup_dir: String::new(),
        passphrase_env_var: String::new(),
        argon2_memory_kib: 65536,
        argon2_iterations: 3,
        argon2_parallelism: 4,
    };

    let key = derive_key(passphrase, salt, &config)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| DeepMailError::Internal(format!("Cipher init failed: {e}")))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| DeepMailError::Internal(format!("Decryption failed: {e}")))
}

fn derive_key(
    passphrase: &str,
    salt: &[u8],
    config: &BackupConfig,
) -> Result<[u8; 32], DeepMailError> {
    let params = argon2::Params::new(
        config.argon2_memory_kib,
        config.argon2_iterations,
        config.argon2_parallelism,
        Some(32),
    )
    .map_err(|e| DeepMailError::Internal(format!("Argon2 params invalid: {e}")))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| DeepMailError::Internal(format!("Key derivation failed: {e}")))?;

    Ok(key)
}
```

**Step 3: Register in lib.rs**

Add `pub mod backup;` to `crates/deepmail-common/src/lib.rs`.

**Step 4: Create admin backup route**

Create `crates/deepmail-api/src/routes/admin_backup.rs`:

```rust
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use deepmail_common::backup;
use deepmail_common::db::migrations::MIGRATION_COUNT;
use deepmail_common::errors::DeepMailError;

use crate::auth::RequireSuperadmin;
use crate::state::AppState;

#[derive(Debug, Serialize)]
struct BackupResponse {
    path: String,
    manifest: backup::BackupManifest,
}

#[derive(Debug, Deserialize)]
struct RestoreRequest {
    backup_path: String,
    passphrase: String,
}

#[derive(Debug, Serialize)]
struct RestoreResponse {
    manifest: backup::BackupManifest,
    message: String,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin/backup", post(backup_handler))
        .route("/admin/restore", post(restore_handler))
}

async fn backup_handler(
    State(state): State<AppState>,
    RequireSuperadmin(user): RequireSuperadmin,
) -> Result<(StatusCode, Json<BackupResponse>), DeepMailError> {
    let result = backup::create_backup(
        state.db_pool(),
        &state.config().backup,
        MIGRATION_COUNT,
    )?;

    deepmail_common::audit::log_audit(
        state.db_pool(),
        "backup_created",
        "database",
        Some(&result.path),
        Some(&user.user_id),
        None,
    )?;

    Ok((
        StatusCode::OK,
        Json(BackupResponse {
            path: result.path,
            manifest: result.manifest,
        }),
    ))
}

async fn restore_handler(
    State(state): State<AppState>,
    RequireSuperadmin(user): RequireSuperadmin,
    Json(req): Json<RestoreRequest>,
) -> Result<(StatusCode, Json<RestoreResponse>), DeepMailError> {
    let manifest = backup::restore_backup(
        state.db_pool(),
        &req.backup_path,
        &req.passphrase,
        MIGRATION_COUNT,
    )?;

    deepmail_common::audit::log_audit(
        state.db_pool(),
        "backup_restored",
        "database",
        Some(&req.backup_path),
        Some(&user.user_id),
        None,
    )?;

    Ok((
        StatusCode::OK,
        Json(RestoreResponse {
            manifest,
            message: "Database restored. Restart the service for migrations to apply if needed."
                .to_string(),
        }),
    ))
}
```

**Step 5: Register route in mod.rs**

In `crates/deepmail-api/src/routes/mod.rs`, add `pub mod admin_backup;` and `.merge(admin_backup::routes())` in the admin routes section.

**Step 6: Update .gitignore**

Add:
```
data/backups/
*.tar.gz.enc
```

**Step 7: Verify**

Run: `cargo fmt --all && cargo check --workspace`

**Step 8: Commit**

```bash
git add -A
git commit -m "feat: encrypted SQLite backup/restore with AES-256-GCM + Argon2"
```

---

### Task 9: Abuse Detection — Velocity Lua Script + Inline Check

**Files:**
- Create: `crates/deepmail-common/src/redis_scripts/abuse_velocity.lua`
- Create: `crates/deepmail-common/src/abuse.rs`
- Modify: `crates/deepmail-common/src/lib.rs` (add `pub mod abuse;`)
- Modify: `crates/deepmail-common/src/queue/mod.rs` (add abuse velocity method)
- Modify: `crates/deepmail-api/src/routes/upload.rs` (add abuse check)

**Step 1: Create the Lua script**

Create `crates/deepmail-common/src/redis_scripts/abuse_velocity.lua`:

```lua
-- Sliding window velocity counter for abuse detection.
-- KEYS[1] = counter key (e.g. "abuse:uploads:{user_id}")
-- ARGV[1] = current timestamp (ms)
-- ARGV[2] = window size (ms)
-- ARGV[3] = threshold
--
-- Returns: {current_count, exceeded (0 or 1)}

local key = KEYS[1]
local now = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local threshold = tonumber(ARGV[3])

-- Remove entries outside the window
redis.call("ZREMRANGEBYSCORE", key, "-inf", now - window_ms)

-- Add current event
redis.call("ZADD", key, now, now .. ":" .. math.random(1000000))

-- Count events in window
local count = redis.call("ZCARD", key)

-- Set expiry on the key to auto-cleanup
redis.call("PEXPIRE", key, window_ms)

local exceeded = 0
if count > threshold then
    exceeded = 1
end

return {count, exceeded}
```

**Step 2: Create `crates/deepmail-common/src/abuse.rs`**

```rust
//! Abuse detection: velocity checks and pattern scanning.

use crate::config::AbuseConfig;
use crate::db::DbPool;
use crate::errors::DeepMailError;
use crate::models::{new_id, now_utc};

const ABUSE_VELOCITY_SCRIPT: &str = include_str!("redis_scripts/abuse_velocity.lua");

/// Check abuse velocity for a user action. Returns true if the user should be flagged.
pub async fn check_velocity(
    conn: &mut redis::aio::MultiplexedConnection,
    user_id: &str,
    action: &str,
    threshold: u32,
    window_ms: u64,
) -> Result<bool, DeepMailError> {
    let key = format!("abuse:{action}:{user_id}");
    let now_ms = chrono::Utc::now().timestamp_millis();

    let values: Vec<redis::Value> = redis::Script::new(ABUSE_VELOCITY_SCRIPT)
        .key(key)
        .arg(now_ms)
        .arg(window_ms)
        .arg(threshold)
        .invoke_async(conn)
        .await
        .map_err(|e| DeepMailError::Redis(format!("Abuse velocity check failed: {e}")))?;

    if values.len() != 2 {
        return Err(DeepMailError::Redis(
            "Abuse velocity script returned unexpected payload".to_string(),
        ));
    }

    let exceeded = match &values[1] {
        redis::Value::Int(i) => *i == 1,
        _ => false,
    };

    Ok(exceeded)
}

/// Flag a user for abuse in the database.
pub fn flag_user(
    pool: &DbPool,
    user_id: &str,
    reason: &str,
) -> Result<(), DeepMailError> {
    let conn = pool.get()?;
    let now = now_utc();
    conn.execute(
        "UPDATE users SET is_flagged = 1, flagged_at = ?1, flagged_reason = ?2 WHERE id = ?3",
        rusqlite::params![now, reason, user_id],
    )?;
    Ok(())
}

/// Unflag a user.
pub fn unflag_user(pool: &DbPool, user_id: &str) -> Result<(), DeepMailError> {
    let conn = pool.get()?;
    conn.execute(
        "UPDATE users SET is_flagged = 0, flagged_at = NULL, flagged_reason = NULL WHERE id = ?1",
        rusqlite::params![user_id],
    )?;
    Ok(())
}

/// Check if a user is flagged (with Redis cache).
pub async fn is_user_flagged(
    pool: &DbPool,
    redis_conn: &mut redis::aio::MultiplexedConnection,
    user_id: &str,
) -> Result<bool, DeepMailError> {
    use redis::AsyncCommands;

    let cache_key = format!("abuse:flagged:{user_id}");

    // Check Redis cache first
    let cached: Option<String> = redis_conn
        .get(&cache_key)
        .await
        .unwrap_or(None);

    if let Some(val) = cached {
        return Ok(val == "1");
    }

    // Fall back to DB
    let conn = pool.get()?;
    let flagged: bool = conn
        .query_row(
            "SELECT is_flagged FROM users WHERE id = ?1",
            rusqlite::params![user_id],
            |row| row.get::<_, i32>(0),
        )
        .map(|v| v == 1)
        .unwrap_or(false);

    // Cache for 60 seconds
    let _: Result<(), _> = redis_conn
        .set_ex(&cache_key, if flagged { "1" } else { "0" }, 60)
        .await;

    Ok(flagged)
}

/// Record an abuse event in the database.
pub fn record_abuse_event(
    pool: &DbPool,
    user_id: &str,
    event_type: &str,
    severity: &str,
    details: Option<&str>,
    auto_flagged: bool,
) -> Result<String, DeepMailError> {
    let conn = pool.get()?;
    let id = new_id();
    conn.execute(
        "INSERT INTO abuse_events (id, user_id, event_type, severity, details, auto_flagged)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![id, user_id, event_type, severity, details, auto_flagged as i32],
    )?;
    Ok(id)
}

/// Run background pattern scan for abuse.
pub fn run_pattern_scan(pool: &DbPool, config: &AbuseConfig) -> Result<(), DeepMailError> {
    let conn = pool.get()?;

    // Pattern 1: Repeated malicious hash uploads
    {
        let mut stmt = conn.prepare(
            "SELECT submitted_by, sha256_hash, COUNT(*) as cnt
             FROM emails
             WHERE submitted_at > datetime('now', '-1 day')
               AND is_deleted = 0
               AND submitted_by IS NOT NULL
             GROUP BY submitted_by, sha256_hash
             HAVING cnt >= ?1",
        )?;

        let threshold = config.repeated_malicious_hash_threshold as i64;
        let rows = stmt.query_map(rusqlite::params![threshold], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;

        for row in rows.flatten() {
            let (user_id, hash, count) = row;
            // Check if this hash had a high threat score
            let high_score: bool = conn
                .query_row(
                    "SELECT COUNT(*) FROM analysis_results ar
                     JOIN emails e ON ar.email_id = e.id
                     WHERE e.sha256_hash = ?1 AND ar.threat_score >= 80.0",
                    rusqlite::params![hash],
                    |row| row.get::<_, i64>(0),
                )
                .map(|c| c > 0)
                .unwrap_or(false);

            if high_score {
                let details = format!(
                    "Repeated uploads of malicious hash {hash}: {count} times in 24h"
                );
                let _ = record_abuse_event(
                    pool,
                    &user_id,
                    "repeated_malicious",
                    "critical",
                    Some(&details),
                    true,
                );
                let _ = flag_user(pool, &user_id, &details);
                tracing::warn!(user_id = %user_id, hash = %hash, count, "Auto-flagged: repeated malicious hash");
            }
        }
    }

    // Pattern 2: Sandbox harvesting
    {
        let mut stmt = conn.prepare(
            "SELECT user_id, COUNT(*) as cnt
             FROM usage_counters
             WHERE metric = 'sandbox_executions' AND day_bucket = ?1
             GROUP BY user_id
             HAVING cnt >= ?2",
        )?;

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let threshold = config.sandbox_harvest_threshold as i64;
        let rows = stmt.query_map(rusqlite::params![today, threshold], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;

        for row in rows.flatten() {
            let (user_id, count) = row;
            let details = format!("Sandbox harvesting: {count} executions today");
            let _ = record_abuse_event(
                pool,
                &user_id,
                "sandbox_harvest",
                "critical",
                Some(&details),
                true,
            );
            let _ = flag_user(pool, &user_id, &details);
            tracing::warn!(user_id = %user_id, count, "Auto-flagged: sandbox harvesting");
        }
    }

    tracing::info!("Abuse pattern scan completed");
    Ok(())
}
```

**Step 3: Register in lib.rs**

Add `pub mod abuse;` to `crates/deepmail-common/src/lib.rs`.

**Step 4: Add abuse check to upload handler**

In `crates/deepmail-api/src/routes/upload.rs`, after the rate limit check and before quota check, add:

```rust
    // Abuse flag check
    {
        let mut queue = state.redis_queue().await;
        let flagged = deepmail_common::abuse::is_user_flagged(
            state.db_pool(),
            queue.conn_mut(),
            &user_id,
        ).await?;
        if flagged {
            return Err(DeepMailError::Forbidden("Account flagged for abuse".to_string()));
        }
    }
```

**Note:** This requires exposing a `conn_mut()` method on `RedisQueue`. Add to `crates/deepmail-common/src/queue/mod.rs`:

```rust
    /// Get a mutable reference to the underlying Redis connection.
    /// Used by abuse detection and other modules that need direct Redis access.
    pub fn conn_mut(&mut self) -> &mut MultiplexedConnection {
        &mut self.conn
    }
```

**Step 5: Add abuse velocity check after upload enqueue**

After the upload is enqueued, check velocity and auto-flag if exceeded:

```rust
    // Abuse velocity tracking
    if state.config().abuse.enabled {
        let mut queue = state.redis_queue().await;
        let exceeded = deepmail_common::abuse::check_velocity(
            queue.conn_mut(),
            &user_id,
            "uploads",
            state.config().abuse.upload_velocity_per_min,
            60_000, // 1 minute window
        ).await?;
        if exceeded {
            let _ = deepmail_common::abuse::flag_user(state.db_pool(), &user_id, "Upload velocity exceeded");
            let _ = deepmail_common::abuse::record_abuse_event(
                state.db_pool(), &user_id, "velocity_upload", "critical",
                Some("Upload velocity threshold exceeded"), true,
            );
        }
    }
```

**Step 6: Verify**

Run: `cargo fmt --all && cargo check --workspace`

**Step 7: Commit**

```bash
git add -A
git commit -m "feat: abuse detection with velocity checks and pattern scanning"
```

---

### Task 10: Admin Abuse Endpoints

**Files:**
- Create: `crates/deepmail-api/src/routes/admin_abuse.rs`
- Modify: `crates/deepmail-api/src/routes/mod.rs` (register)

**Step 1: Create admin abuse routes**

Create `crates/deepmail-api/src/routes/admin_abuse.rs`:

```rust
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use deepmail_common::abuse;
use deepmail_common::errors::DeepMailError;
use deepmail_common::models::now_utc;

use crate::auth::RequireAdmin;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct AbuseEventsQuery {
    user_id: Option<String>,
    severity: Option<String>,
    reviewed: Option<bool>,
    limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct AbuseEvent {
    id: String,
    user_id: String,
    event_type: String,
    severity: String,
    details: Option<String>,
    auto_flagged: bool,
    reviewed_by: Option<String>,
    reviewed_at: Option<String>,
    created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct FlagRequest {
    reason: String,
}

#[derive(Debug, Deserialize)]
pub struct ReviewRequest {
    notes: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    message: String,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin/abuse/events", get(list_events))
        .route("/admin/abuse/events/{id}", get(get_event))
        .route("/admin/abuse/events/{id}/review", post(review_event))
        .route("/admin/abuse/flag/{user_id}", post(flag_user))
        .route("/admin/abuse/unflag/{user_id}", post(unflag_user))
}

async fn list_events(
    State(state): State<AppState>,
    RequireAdmin(user): RequireAdmin,
    Query(query): Query<AbuseEventsQuery>,
) -> Result<Json<Vec<AbuseEvent>>, DeepMailError> {
    let _ = user; // auth enforced by extractor
    let conn = state.db_pool().get()?;
    let limit = query.limit.unwrap_or(100).min(500);

    let mut sql = String::from(
        "SELECT id, user_id, event_type, severity, details, auto_flagged, \
         reviewed_by, reviewed_at, created_at FROM abuse_events WHERE 1=1",
    );
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

    if let Some(ref uid) = query.user_id {
        sql.push_str(&format!(" AND user_id = ?{}", params.len() + 1));
        params.push(Box::new(uid.clone()));
    }
    if let Some(ref sev) = query.severity {
        sql.push_str(&format!(" AND severity = ?{}", params.len() + 1));
        params.push(Box::new(sev.clone()));
    }
    if let Some(reviewed) = query.reviewed {
        if reviewed {
            sql.push_str(" AND reviewed_at IS NOT NULL");
        } else {
            sql.push_str(" AND reviewed_at IS NULL");
        }
    }

    sql.push_str(&format!(" ORDER BY created_at DESC LIMIT ?{}", params.len() + 1));
    params.push(Box::new(limit as i64));

    let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(param_refs.as_slice(), |row| {
        Ok(AbuseEvent {
            id: row.get(0)?,
            user_id: row.get(1)?,
            event_type: row.get(2)?,
            severity: row.get(3)?,
            details: row.get(4)?,
            auto_flagged: row.get::<_, i32>(5)? == 1,
            reviewed_by: row.get(6)?,
            reviewed_at: row.get(7)?,
            created_at: row.get(8)?,
        })
    })?;

    let events: Vec<AbuseEvent> = rows.filter_map(|r| r.ok()).collect();
    Ok(Json(events))
}

async fn get_event(
    State(state): State<AppState>,
    RequireAdmin(_user): RequireAdmin,
    Path(id): Path<String>,
) -> Result<Json<AbuseEvent>, DeepMailError> {
    let conn = state.db_pool().get()?;
    let event = conn.query_row(
        "SELECT id, user_id, event_type, severity, details, auto_flagged, \
         reviewed_by, reviewed_at, created_at FROM abuse_events WHERE id = ?1",
        rusqlite::params![id],
        |row| {
            Ok(AbuseEvent {
                id: row.get(0)?,
                user_id: row.get(1)?,
                event_type: row.get(2)?,
                severity: row.get(3)?,
                details: row.get(4)?,
                auto_flagged: row.get::<_, i32>(5)? == 1,
                reviewed_by: row.get(6)?,
                reviewed_at: row.get(7)?,
                created_at: row.get(8)?,
            })
        },
    ).map_err(|_| DeepMailError::NotFound(format!("Abuse event '{id}' not found")))?;

    Ok(Json(event))
}

async fn review_event(
    State(state): State<AppState>,
    RequireAdmin(user): RequireAdmin,
    Path(id): Path<String>,
    Json(req): Json<ReviewRequest>,
) -> Result<Json<MessageResponse>, DeepMailError> {
    let conn = state.db_pool().get()?;
    let now = now_utc();
    let details = req.notes.unwrap_or_default();

    conn.execute(
        "UPDATE abuse_events SET reviewed_by = ?1, reviewed_at = ?2 WHERE id = ?3",
        rusqlite::params![user.user_id, now, id],
    )?;

    deepmail_common::audit::log_audit(
        state.db_pool(),
        "abuse_event_reviewed",
        "abuse_events",
        Some(&format!("event_id={id}, notes={details}")),
        Some(&user.user_id),
        None,
    )?;

    Ok(Json(MessageResponse {
        message: format!("Event {id} marked as reviewed"),
    }))
}

async fn flag_user(
    State(state): State<AppState>,
    RequireAdmin(user): RequireAdmin,
    Path(target_user_id): Path<String>,
    Json(req): Json<FlagRequest>,
) -> Result<Json<MessageResponse>, DeepMailError> {
    abuse::flag_user(state.db_pool(), &target_user_id, &req.reason)?;
    abuse::record_abuse_event(
        state.db_pool(),
        &target_user_id,
        "manual_flag",
        "critical",
        Some(&req.reason),
        false,
    )?;

    deepmail_common::audit::log_audit(
        state.db_pool(),
        "user_flagged",
        "users",
        Some(&format!("target={target_user_id}, reason={}", req.reason)),
        Some(&user.user_id),
        None,
    )?;

    Ok(Json(MessageResponse {
        message: format!("User {target_user_id} flagged"),
    }))
}

async fn unflag_user(
    State(state): State<AppState>,
    RequireAdmin(user): RequireAdmin,
    Path(target_user_id): Path<String>,
) -> Result<Json<MessageResponse>, DeepMailError> {
    abuse::unflag_user(state.db_pool(), &target_user_id)?;

    deepmail_common::audit::log_audit(
        state.db_pool(),
        "user_unflagged",
        "users",
        Some(&format!("target={target_user_id}")),
        Some(&user.user_id),
        None,
    )?;

    Ok(Json(MessageResponse {
        message: format!("User {target_user_id} unflagged"),
    }))
}
```

**Step 2: Register in mod.rs**

Add `pub mod admin_abuse;` and `.merge(admin_abuse::routes())`.

**Step 3: Spawn abuse pattern scanner in API main.rs**

In `crates/deepmail-api/src/main.rs`, after the retention cleanup spawn, add:

```rust
    // Start abuse pattern scanner background loop
    if config.abuse.enabled {
        let db_pool = app_state.db_pool().clone();
        let abuse_cfg = config.abuse.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = deepmail_common::abuse::run_pattern_scan(&db_pool, &abuse_cfg) {
                    tracing::error!(error = %e, "Abuse pattern scan failed");
                }
                tokio::time::sleep(Duration::from_secs(abuse_cfg.pattern_scan_interval_secs)).await;
            }
        });
    }
```

**Step 4: Verify**

Run: `cargo fmt --all && cargo check --workspace`

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: admin abuse endpoints and background pattern scanner"
```

---

### Task 11: Production Deployment Configs + Documentation

**Files:**
- Create: `docs/deployment/README.md`
- Create: `docs/deployment/env-vars.md`
- Create: `docs/deployment/system-limits.md`
- Create: `docs/deployment/docker-compose.yml`
- Modify: `config/production.toml` (expand)
- Create: `.env.example`

This task is purely documentation and config templates. No code changes.

**Step 1: Create all documentation files**

Write deployment documentation covering:
- Architecture overview (API + worker + sandbox-worker + Redis + SQLite)
- Complete env var reference (every `DEEPMAIL_*` variable)
- System limits guide (ulimits, file descriptors, WAL settings)
- Docker compose template
- Expanded production.toml
- .env.example template

**Step 2: Commit**

```bash
git add -A
git commit -m "docs: production deployment configs, env var reference, system limits guide"
```

---

### Task 12: Final Verification + Cleanup

**Files:**
- All modified files

**Step 1: Format**

Run: `cargo fmt --all`

**Step 2: Check**

Run: `cargo check --workspace`
Expected: No errors. Warnings only for intentionally unused code (old rate limiter).

**Step 3: Test**

Run: `cargo test --workspace --no-fail-fast`
Expected: All tests pass.

**Step 4: Verify .gitignore**

Ensure `data/backups/` and `*.tar.gz.enc` are in `.gitignore`.

**Step 5: Final commit**

```bash
git add -A
git commit -m "chore: phase 5.2 final cleanup and verification"
```
