# Phase 5.1 Reliability Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Upgrade DeepMail with production-grade reliability: token-bucket rate limiting, Prometheus metrics, OTel tracing, DLQ + retries, retention workers, health checks, and circuit breakers.

**Architecture:** Implement shared reliability primitives in `deepmail-common`, then wire API/worker/sandbox-worker to use them. Keep existing service boundaries and queue topology while adding resilience and observability controls around failure-prone paths.

**Tech Stack:** Rust, Redis Lua, Axum, Tokio, OpenTelemetry (`tracing-opentelemetry` + OTLP), SQLite.

---

### Task 1: Add reliability config fields

**Files:**
- Modify: `crates/deepmail-common/src/config.rs`
- Modify: `config/base.toml`
- Modify: `config/development.toml`
- Modify: `config/staging.toml`
- Modify: `config/production.toml`

### Task 2: Redis Lua token-bucket limiter

**Files:**
- Modify: `crates/deepmail-common/src/queue/mod.rs`
- Create: `crates/deepmail-common/src/redis_scripts/token_bucket.lua`

### Task 3: Prometheus text metrics endpoint

**Files:**
- Modify: `crates/deepmail-api/src/routes/metrics.rs`
- Modify: `crates/deepmail-api/src/routes/mod.rs`

### Task 4: OpenTelemetry tracing integration

**Files:**
- Modify: `crates/deepmail-api/src/main.rs`
- Modify: `crates/deepmail-worker/src/main.rs`
- Modify: `crates/deepmail-sandbox-worker/src/main.rs`
- Modify: `crates/deepmail-api/Cargo.toml`
- Modify: `crates/deepmail-worker/Cargo.toml`
- Modify: `crates/deepmail-sandbox-worker/Cargo.toml`

### Task 5: DLQ + retry metadata and replay helpers

**Files:**
- Modify: `crates/deepmail-common/src/queue/mod.rs`
- Modify: `crates/deepmail-worker/src/main.rs`
- Modify: `crates/deepmail-sandbox-worker/src/main.rs`
- Create: `crates/deepmail-api/src/routes/admin_replay.rs`
- Modify: `crates/deepmail-api/src/routes/mod.rs`

### Task 6: Data retention worker

**Files:**
- Create: `crates/deepmail-common/src/retention.rs`
- Modify: `crates/deepmail-common/src/lib.rs`
- Modify: `crates/deepmail-api/src/main.rs`

### Task 7: Health endpoint expansion

**Files:**
- Modify: `crates/deepmail-api/src/routes/health.rs`

### Task 8: Circuit breakers for intel and sandbox

**Files:**
- Create: `crates/deepmail-common/src/circuit_breaker.rs`
- Modify: `crates/deepmail-common/src/lib.rs`
- Modify: `crates/deepmail-worker/src/pipeline/mod.rs`
- Modify: `crates/deepmail-sandbox-worker/src/main.rs`

### Task 9: Verification

Run:
- `cargo fmt --all`
- `cargo check --workspace`
- `cargo test --workspace --no-fail-fast`
