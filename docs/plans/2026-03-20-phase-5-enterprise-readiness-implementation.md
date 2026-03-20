# Phase 5 Enterprise Readiness Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Deliver observability, tenant isolation, quotas, distributed rate limiting, reuse caching, sandbox reuse, feature flags, and environment-layered config for production deployment.

**Architecture:** Extend existing API/worker/sandbox-worker/common crates with shared policy primitives and schema changes. Enforce JWT-derived user identity at API boundaries, carry trace/user context across queue payloads, and centralize limits/reuse via DB + Redis controls. Keep runtime roles separated while enabling horizontal scaling.

**Tech Stack:** Rust, Axum, Tokio, Redis Streams/PubSub, Redis counters, SQLite (rusqlite/r2d2), jsonwebtoken, tracing, serde.

---

### Task 1: Extend configuration model for feature flags and environment layers

**Files:**
- Modify: `crates/deepmail-common/src/config.rs`
- Create: `config/base.toml`
- Create: `config/development.toml`
- Create: `config/staging.toml`
- Create: `config/production.toml`
- Modify: `config.toml`

**Step 1: Write the failing test**

```rust
#[test]
fn loads_environment_layered_feature_flags() {
    std::env::set_var("DEEPMAIL_ENV", "development");
    let cfg = deepmail_common::config::AppConfig::load().unwrap();
    assert!(cfg.features.enable_sandbox);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p deepmail-common loads_environment_layered_feature_flags -- --nocapture`
Expected: FAIL due to missing features/env loader.

**Step 3: Write minimal implementation**

Add feature/config structs and loader chain (`base.toml` + env file + env vars).

**Step 4: Run test to verify it passes**

Run: `cargo test -p deepmail-common loads_environment_layered_feature_flags -- --nocapture`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/deepmail-common/src/config.rs config/
git commit -m "feat: add layered environment config and feature flags"
```

### Task 2: Add tenant/quota/reuse database schema

**Files:**
- Modify: `crates/deepmail-common/src/db/migrations.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn migration_creates_quota_and_reuse_tables() {
    let conn = setup_test_db();
    run_migrations(&conn).unwrap();
    assert!(table_exists(&conn, "user_quotas"));
    assert!(table_exists(&conn, "usage_counters"));
    assert!(table_exists(&conn, "result_reuse_index"));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p deepmail-common migration_creates_quota_and_reuse_tables -- --nocapture`
Expected: FAIL.

**Step 3: Write minimal implementation**

Add migration 015 with tables/indexes and `emails` tenant/reuse metadata columns.

**Step 4: Run test to verify it passes**

Run: `cargo test -p deepmail-common migration_creates_quota_and_reuse_tables -- --nocapture`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/deepmail-common/src/db/migrations.rs
git commit -m "feat: add tenant quota and reuse database schema"
```

### Task 3: Implement JWT user extraction and ownership guardrails in API

**Files:**
- Create: `crates/deepmail-api/src/auth.rs`
- Modify: `crates/deepmail-api/Cargo.toml`
- Modify: `crates/deepmail-api/src/routes/upload.rs`
- Modify: `crates/deepmail-api/src/routes/results.rs`
- Modify: `crates/deepmail-api/src/routes/ws_results.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn rejects_requests_without_valid_jwt_sub() {
    let err = parse_user_id("Bearer invalid", "secret").unwrap_err();
    assert!(err.to_string().contains("auth"));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p deepmail-api rejects_requests_without_valid_jwt_sub -- --nocapture`
Expected: FAIL.

**Step 3: Write minimal implementation**

Add JWT claim parser and enforce ownership filters in upload/results/ws handlers.

**Step 4: Run test to verify it passes**

Run: `cargo test -p deepmail-api rejects_requests_without_valid_jwt_sub -- --nocapture`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/deepmail-api/Cargo.toml crates/deepmail-api/src/auth.rs crates/deepmail-api/src/routes
git commit -m "feat: enforce jwt user identity and tenant ownership checks"
```

### Task 4: Implement Redis-backed per-user and per-IP rate limiting

**Files:**
- Modify: `crates/deepmail-common/src/queue/mod.rs`
- Modify: `crates/deepmail-api/src/middleware/rate_limit.rs`
- Modify: `crates/deepmail-api/src/routes/upload.rs`
- Modify: `crates/deepmail-api/src/routes/results.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
async fn rate_limiter_blocks_after_threshold() {
    let rl = RedisRateLimiter::new(...);
    for _ in 0..3 { assert!(rl.check("user", "u1", 3, 60).await.unwrap().allowed); }
    assert!(!rl.check("user", "u1", 3, 60).await.unwrap().allowed);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p deepmail-api rate_limiter_blocks_after_threshold -- --nocapture`
Expected: FAIL.

**Step 3: Write minimal implementation**

Use Redis INCR/EXPIRE fixed window checks and enforce both user+IP limits.

**Step 4: Run test to verify it passes**

Run: `cargo test -p deepmail-api rate_limiter_blocks_after_threshold -- --nocapture`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/deepmail-common/src/queue/mod.rs crates/deepmail-api/src/middleware/rate_limit.rs crates/deepmail-api/src/routes
git commit -m "feat: add distributed user and ip rate limiting"
```

### Task 5: Implement upload/sandbox quotas

**Files:**
- Create: `crates/deepmail-common/src/quota.rs`
- Modify: `crates/deepmail-common/src/lib.rs`
- Modify: `crates/deepmail-api/src/routes/upload.rs`
- Modify: `crates/deepmail-worker/src/pipeline/mod.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn quota_denies_when_daily_limit_exceeded() {
    let denied = enforce_daily_quota(&pool, "u1", "uploads", 1).unwrap();
    assert!(!denied.allowed);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p deepmail-common quota_denies_when_daily_limit_exceeded -- --nocapture`
Expected: FAIL.

**Step 3: Write minimal implementation**

Add quota counter increment/check helper; apply to uploads and sandbox enqueue.

**Step 4: Run test to verify it passes**

Run: `cargo test -p deepmail-common quota_denies_when_daily_limit_exceeded -- --nocapture`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/deepmail-common/src/quota.rs crates/deepmail-common/src/lib.rs crates/deepmail-api/src/routes/upload.rs crates/deepmail-worker/src/pipeline/mod.rs
git commit -m "feat: enforce user upload and sandbox daily quotas"
```

### Task 6: Add global result reuse index integration

**Files:**
- Create: `crates/deepmail-common/src/reuse.rs`
- Modify: `crates/deepmail-common/src/lib.rs`
- Modify: `crates/deepmail-api/src/routes/upload.rs`
- Modify: `crates/deepmail-worker/src/pipeline/mod.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn stores_and_fetches_reuse_entry_for_url() {
    store_reuse_entry(&pool, "url", "https://a.test", "{}").unwrap();
    let hit = lookup_reuse_entry(&pool, "url", "https://a.test").unwrap();
    assert!(hit.is_some());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p deepmail-common stores_and_fetches_reuse_entry_for_url -- --nocapture`
Expected: FAIL.

**Step 3: Write minimal implementation**

Implement reusable index helper; wire hash/url/domain reuse checks and writes.

**Step 4: Run test to verify it passes**

Run: `cargo test -p deepmail-common stores_and_fetches_reuse_entry_for_url -- --nocapture`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/deepmail-common/src/reuse.rs crates/deepmail-common/src/lib.rs crates/deepmail-api/src/routes/upload.rs crates/deepmail-worker/src/pipeline/mod.rs
git commit -m "feat: add reusable result index for hash url and domain"
```

### Task 7: Add sandbox reuse cache and TTL policy

**Files:**
- Modify: `crates/deepmail-sandbox-worker/src/main.rs`
- Modify: `crates/deepmail-common/src/config.rs`
- Modify: `config/*.toml`

**Step 1: Write the failing test**

```rust
#[test]
fn reuses_recent_sandbox_report_when_fresh() {
    let reused = lookup_recent_sandbox_url(&pool, "https://example.com", 3600).unwrap();
    assert!(reused.is_some());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p deepmail-sandbox-worker reuses_recent_sandbox_report_when_fresh -- --nocapture`
Expected: FAIL.

**Step 3: Write minimal implementation**

Check sandbox cache before execution and short-circuit on valid recent hit.

**Step 4: Run test to verify it passes**

Run: `cargo test -p deepmail-sandbox-worker -- --nocapture`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/deepmail-sandbox-worker/src/main.rs crates/deepmail-common/src/config.rs config/
git commit -m "feat: add sandbox detonation reuse cache with freshness window"
```

### Task 8: Add observability metrics and tracing enrichment

**Files:**
- Create: `crates/deepmail-api/src/routes/metrics.rs`
- Modify: `crates/deepmail-api/src/routes/mod.rs`
- Modify: `crates/deepmail-api/src/routes/upload.rs`
- Modify: `crates/deepmail-worker/src/main.rs`
- Modify: `crates/deepmail-worker/src/pipeline/mod.rs`
- Modify: `crates/deepmail-sandbox-worker/src/main.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
async fn metrics_endpoint_returns_job_failure_and_latency_fields() {
    let body = fetch_metrics_json().await;
    assert!(body.get("jobs_processed_total").is_some());
    assert!(body.get("stage_latency").is_some());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p deepmail-api metrics_endpoint_returns_job_failure_and_latency_fields -- --nocapture`
Expected: FAIL.

**Step 3: Write minimal implementation**

Add derived metrics endpoint and include trace/user context in queue payload and worker logs.

**Step 4: Run test to verify it passes**

Run: `cargo test -p deepmail-api metrics_endpoint_returns_job_failure_and_latency_fields -- --nocapture`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/deepmail-api/src/routes crates/deepmail-worker/src crates/deepmail-sandbox-worker/src
git commit -m "feat: add phase5 observability metrics and trace context propagation"
```

### Task 9: Add documentation for observability, multi-tenant, and rate limiting

**Files:**
- Create: `docs/observability/README.md`
- Create: `docs/multi-tenant/README.md`
- Create: `docs/rate-limiting/README.md`

**Step 1: Write the failing test**

N/A (documentation task).

**Step 2: Verify docs missing**

Run: `ls docs/observability/README.md docs/multi-tenant/README.md docs/rate-limiting/README.md`
Expected: missing files initially.

**Step 3: Write minimal implementation**

Document architecture, scale strategy, and security implications.

**Step 4: Verify docs exist**

Run: `ls docs/observability/README.md docs/multi-tenant/README.md docs/rate-limiting/README.md`
Expected: all files exist.

**Step 5: Commit**

```bash
git add docs/observability/README.md docs/multi-tenant/README.md docs/rate-limiting/README.md
git commit -m "docs: add phase5 observability multitenant and rate-limit architecture"
```

### Task 10: Full verification and hardening pass

**Files:**
- Verify: workspace

**Step 1: Run format**

Run: `cargo fmt --all`
Expected: PASS.

**Step 2: Run lint**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS.

**Step 3: Run tests**

Run: `cargo test --workspace --no-fail-fast`
Expected: PASS.

**Step 4: Smoke run services**

Run: `cargo run --bin deepmail-api`
Run: `cargo run --bin deepmail-worker`
Run: `cargo run --bin deepmail-sandbox-worker`
Expected: boot succeeds with env-layered config.

**Step 5: Commit**

```bash
git add .
git commit -m "feat: deliver phase5 enterprise observability and multitenant readiness"
```
