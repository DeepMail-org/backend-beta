# Phase 5.2 — Production Hardening & Operational Readiness

**Date:** 2026-03-20
**Status:** Approved
**Approach:** A (Layered middleware + inline modules)

## Overview

Phase 5.2 delivers seven features that bring DeepMail from "functional with reliability primitives" to "production-deployable with operational controls." The work spans observability wiring, access control, data lifecycle management, backup/restore, abuse prevention, and deployment documentation.

## 1. OTLP gRPC Batch Exporter

**Current state:** `init_tracing()` in all three binaries creates an `SdkTracerProvider` with no exporter — traces are generated but discarded.

**Change:** When `observability.otlp_enabled` is `true` (new config flag, default `false`), wire a real OTLP gRPC exporter with a batch span processor.

Config additions to `ObservabilityConfig`:
- `otlp_enabled: bool` — default `false`
- `otlp_batch_size: u32` — default `512`
- `otlp_batch_timeout_secs: u64` — default `5`

When enabled, create `opentelemetry_otlp::SpanExporter` with tonic gRPC transport pointing at `otlp_endpoint`, wrap in `BatchSpanProcessor` with configured queue/timeout, attach to `SdkTracerProvider`.

When disabled, current no-op provider (unchanged).

Shared `init_tracing()` helper moves to `deepmail-common` so all three binaries use identical initialization, taking `&ObservabilityConfig` + `&LoggingConfig` + `service_name`.

**New workspace dependencies:**
- `opentelemetry-otlp` with `grpc-tonic` feature (pinned to match existing 0.28 family)

## 2. Three-Tier RBAC

### Role Hierarchy

Three roles ordered by privilege: `Superadmin > Admin > Analyst`.

- **Superadmin:** backup/restore, abuse management, all admin ops
- **Admin:** DLQ replay, metrics, user management, abuse event review
- **Analyst:** upload, results, WebSocket streaming

### JWT Claims Expansion

```rust
pub struct Claims {
    pub sub: String,   // user_id
    pub exp: usize,    // expiry
    pub role: String,  // NEW: "superadmin", "admin", "analyst"
}
```

### Role Enum

```rust
pub enum UserRole { Superadmin, Admin, Analyst }
```

Implements `PartialOrd` so `Superadmin > Admin > Analyst`. A `require_role(minimum)` check succeeds if `token_role >= minimum`.

### Axum Extractors

- `AuthUser` — extracts `user_id` + `role` from JWT. Replaces current `extract_user_id` calls.
- `RequireAdmin` — wraps `AuthUser`, rejects if `role < Admin`.
- `RequireSuperadmin` — wraps `AuthUser`, rejects if `role < Superadmin`.

### IP Allowlist

New `security.admin_ip_allowlist: Vec<String>` config field (default empty = disabled). Applied as a Tower middleware layer on the `/api/v1/admin/` route group. Checks `ConnectInfo<SocketAddr>` or `X-Forwarded-For`.

### Audit Logging

Every admin action goes through `log_audit()` with `user_id` from the `AuthUser` extractor. New convenience functions: `log_admin_action()`, `log_backup()`, `log_restore()`.

### Route Mapping

| Route | Minimum Role |
|-------|-------------|
| `POST /upload` | Analyst |
| `GET /results/:id` | Analyst (+ ownership) |
| `GET /ws/results/:id` | Analyst (+ ownership) |
| `GET /metrics` | Admin |
| `POST /admin/replay/:queue/:id` | Admin |
| `POST /admin/backup` | Superadmin |
| `POST /admin/restore` | Superadmin |
| `GET /admin/abuse/events` | Admin |
| `POST /admin/abuse/flag/:user_id` | Admin |
| `POST /admin/abuse/unflag/:user_id` | Admin |
| `GET /health/*` | No auth |

## 3. Soft-Delete Lifecycle

### Three-Phase Lifecycle

```
active → archived → soft-deleted → hard-purged
```

| Transition | Trigger | Config Key | Default |
|-----------|---------|------------|---------|
| active → archived | `submitted_at` older than cutoff | `retention.archive_after_days` | 30 |
| archived → soft-deleted | `archived_at` older than cutoff | `retention.soft_delete_after_days` | 30 |
| soft-deleted → hard-purged | `deleted_at` older than cutoff | `retention.purge_after_days` | 30 |

Total data lifetime with defaults: 90 days.

### Schema Changes

Columns added to `emails`, `attachments`, `analysis_results`, `sandbox_reports`:
- `archived_at TEXT`
- `deleted_at TEXT`
- `is_deleted INTEGER NOT NULL DEFAULT 0`

Indexes on `emails(archived_at)`, `emails(deleted_at)`, `emails(is_deleted)`.

### Cascade Behavior

When an email transitions state, all children (attachments, analysis_results, sandbox_reports, job_progress) transition in the same transaction.

### Query Filter Changes

All existing queries gain `WHERE is_deleted = 0 AND archived_at IS NULL` for default views. Admin endpoints support `?include_archived=true` and `?include_deleted=true`.

### Retention Config

```rust
pub struct RetentionConfig {
    pub archive_after_days: u32,       // NEW, default 30
    pub soft_delete_after_days: u32,   // NEW, default 30
    pub purge_after_days: u32,         // NEW, default 30
    pub cleanup_interval_secs: u64,    // existing
    pub logs_ttl_days: u32,            // KEPT — audit_logs hard-purged only
}
```

Old fields `emails_ttl_days` and `sandbox_reports_ttl_days` removed, replaced by the three-phase fields.

### Retention Loop

Three sequential phases per run:
1. **Archive:** SET `archived_at = now()` WHERE `submitted_at < cutoff` AND `archived_at IS NULL` AND `is_deleted = 0`
2. **Soft-delete:** SET `deleted_at = now(), is_deleted = 1` WHERE `archived_at < cutoff` AND `deleted_at IS NULL`
3. **Purge:** DELETE WHERE `deleted_at < cutoff` (children first, then parent emails)

## 4. SQLite Backup/Restore

### Backup Pipeline

```
SQLite .backup API → temp .db → tar.gz (db + manifest.json) → AES-256-GCM encrypt → .tar.gz.enc
```

1. **Consistent snapshot:** `rusqlite::backup::Backup` to copy live DB to temp file.
2. **Integrity manifest:** `manifest.json` with `version`, `created_at`, `schema_version`, `migration_count`, `db_sha256`, `db_size_bytes`, `deepmail_version`.
3. **Archive:** Pack `.db` + `manifest.json` into `.tar.gz` using `flate2` + `tar`.
4. **Encryption:** Argon2id KDF from passphrase → AES-256-GCM. Output format: `[16B salt][12B nonce][ciphertext][16B tag]`. Written to `data/backups/deepmail-backup-{timestamp}.tar.gz.enc`.

### Restore Pipeline

1. Read salt + nonce, derive key with Argon2id, decrypt with AES-256-GCM.
2. Extract `manifest.json` + `.db` from tar.
3. Verify `db_sha256` matches extracted `.db`.
4. Verify `migration_count <= current binary's count`.
5. Use `rusqlite::backup::Backup` to copy restored `.db` over live DB.
6. Response instructs operator to restart the service.

### Config

```rust
pub struct BackupConfig {
    pub backup_dir: String,          // default "data/backups"
    pub passphrase_env_var: String,  // default "DEEPMAIL_BACKUP_PASSPHRASE"
    pub argon2_memory_kib: u32,      // default 65536 (64 MiB)
    pub argon2_iterations: u32,      // default 3
    pub argon2_parallelism: u32,     // default 4
}
```

Passphrase read from env var at backup/restore time — never in config files.

### API Endpoints

- `POST /api/v1/admin/backup` — Superadmin. Returns backup file path + manifest.
- `POST /api/v1/admin/restore` — Superadmin. Accepts backup file path + passphrase.

**New workspace dependencies:**
- `aes-gcm = "0.10"`
- `argon2 = "0.5"`
- `tar = "0.4"`
- `flate2 = "1"`

**Module:** `crates/deepmail-common/src/backup.rs`

## 5. Schema Version Validation at Startup

`validate_schema()` called after `run_migrations()` in all three binaries:

- Counts applied migrations from `_migrations` table.
- If `applied > expected` (DB ahead of binary), refuse to start with an error.
- If `applied == expected`, proceed normally.
- If `applied < expected` after `run_migrations()`, something went wrong — also refuse.

## 6. Abuse Detection

### Velocity Detection (Inline)

Redis sliding window counters checked on every upload and sandbox enqueue:

| Metric | Window | Threshold | Action |
|--------|--------|-----------|--------|
| `abuse:uploads:{user_id}` | 1 min | 20/min | Auto-flag |
| `abuse:sandbox:{user_id}` | 1 min | 15/min | Auto-flag |
| `abuse:failed:{user_id}` | 5 min | 10/5min | Auto-flag |

Implemented as a Lua script for atomic check-and-increment. On breach: set `users.is_flagged = 1`, write `abuse_events` record, subsequent requests from flagged user return 403.

### Pattern Detection (Background)

Background task running every `pattern_scan_interval_secs` (default 300):

1. **Repeated malicious hash uploads:** Users submitting same high-score hash > threshold times in 24h.
2. **Sandbox harvesting:** Users exceeding unique URL threshold per hour.
3. **Dormant re-activation:** Inactive > 30 days, sudden spike > 50% quota in first hour. Logged as `severity = 'warning'` only.

### Schema

```sql
ALTER TABLE users ADD COLUMN is_flagged INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN flagged_at TEXT;
ALTER TABLE users ADD COLUMN flagged_reason TEXT;

CREATE TABLE abuse_events (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'critical',
    details TEXT,
    auto_flagged INTEGER NOT NULL DEFAULT 0,
    reviewed_by TEXT,
    reviewed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

### Config

```rust
pub struct AbuseConfig {
    pub enabled: bool,                          // default true
    pub upload_velocity_per_min: u32,           // default 20
    pub sandbox_velocity_per_min: u32,          // default 15
    pub failed_upload_threshold_5min: u32,      // default 10
    pub pattern_scan_interval_secs: u64,        // default 300
    pub repeated_malicious_hash_threshold: u32, // default 5
    pub sandbox_harvest_threshold: u32,         // default 50
}
```

### Admin Endpoints

| Endpoint | Role | Description |
|----------|------|-------------|
| `GET /admin/abuse/events` | Admin | List events, filter by user/severity/reviewed |
| `GET /admin/abuse/events/:id` | Admin | Single event detail |
| `POST /admin/abuse/flag/:user_id` | Admin | Manual flag |
| `POST /admin/abuse/unflag/:user_id` | Admin | Unflag user |
| `POST /admin/abuse/events/:id/review` | Admin | Mark event reviewed |

### Request-Path Integration

After auth extraction, before processing: check `abuse:flagged:{user_id}` in Redis (cached 60s from DB). Flagged users get `403 Forbidden`.

## 7. Production Deployment Configs

Documentation deliverables (no code):

- `docs/deployment/README.md` — deployment architecture overview
- `docs/deployment/env-vars.md` — complete `DEEPMAIL_*` env var reference
- `docs/deployment/system-limits.md` — ulimits, file descriptors, memory, Redis, SQLite WAL recommendations
- `docs/deployment/docker-compose.yml` — production compose template (API + worker + sandbox-worker + Redis + Jaeger)
- `config/production.toml` — expanded with hardened values
- `.env.example` — template with all required env vars

## Migration 016

Single migration `016_add_production_hardening` covering all schema changes:
- Soft-delete columns on emails, attachments, analysis_results, sandbox_reports
- User flagging columns on users
- `abuse_events` table
- Associated indexes
