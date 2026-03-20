# Phase 4 Sandbox + Realtime + Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement isolated container-based sandbox detonation, real-time pipeline/sandbox updates over WebSocket, and production hardening for concurrency/timeouts/soft-fail behavior.

**Architecture:** Add `deepmail-sandbox` and `deepmail-sandbox-worker` as isolated components, connected through a dedicated Redis queue and pub/sub events. Keep core analysis in `deepmail-worker` and use optional asynchronous sandbox offload. Enforce strict security boundaries and executor abstraction to allow future Firecracker backend without contract changes.

**Tech Stack:** Rust (Tokio, Axum), Redis Streams + Pub/Sub, SQLite (rusqlite/r2d2), Docker runtime integration, Playwright-driven detonation helper.

---

### Task 1: Add workspace crates and shared config

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/deepmail-common/src/config.rs`
- Modify: `config.toml`
- Create: `crates/deepmail-sandbox/Cargo.toml`
- Create: `crates/deepmail-sandbox/src/lib.rs`
- Create: `crates/deepmail-sandbox-worker/Cargo.toml`
- Create: `crates/deepmail-sandbox-worker/src/main.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn sandbox_config_deserializes_defaults() {
    let cfg = deepmail_common::config::AppConfig::load_from("config.toml").unwrap();
    assert!(cfg.sandbox.execution_timeout_ms > 0);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p deepmail-common sandbox_config_deserializes_defaults -- --nocapture`
Expected: FAIL due to missing `sandbox`/pipeline config fields.

**Step 3: Write minimal implementation**

Add config structs for sandbox, worker limits, timeouts, websocket pubsub channels.

**Step 4: Run test to verify it passes**

Run: `cargo test -p deepmail-common sandbox_config_deserializes_defaults -- --nocapture`
Expected: PASS.

**Step 5: Commit**

```bash
git add Cargo.toml config.toml crates/deepmail-common/src/config.rs crates/deepmail-sandbox crates/deepmail-sandbox-worker
git commit -m "feat: add sandbox workspace crates and runtime config"
```

### Task 2: Implement sandbox domain models and executor abstraction

**Files:**
- Create: `crates/deepmail-sandbox/src/model/mod.rs`
- Create: `crates/deepmail-sandbox/src/executor/mod.rs`
- Create: `crates/deepmail-sandbox/src/errors.rs`
- Modify: `crates/deepmail-sandbox/src/lib.rs`
- Test: `crates/deepmail-sandbox/src/executor/mod.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
async fn mock_executor_implements_trait_contract() {
    let exec = MockExecutor::new();
    let handle = exec.execute_url("https://example.com".into()).await.unwrap();
    let report = exec.get_report(&handle).await.unwrap();
    assert_eq!(report.status, SandboxStatus::Completed);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p deepmail-sandbox mock_executor_implements_trait_contract -- --nocapture`
Expected: FAIL because trait/models do not exist.

**Step 3: Write minimal implementation**

Define `SandboxExecutor` trait:
- `execute_url(url)`
- `execute_file(file_path)`
- `get_report()`

Define `ExecutionHandle`, `SandboxReport`, `SandboxJob`, and enums for status/job type.

**Step 4: Run test to verify it passes**

Run: `cargo test -p deepmail-sandbox -- --nocapture`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/deepmail-sandbox/src
git commit -m "feat: define sandbox executor abstraction and report models"
```

### Task 3: Add URL validation and SSRF guardrail module

**Files:**
- Create: `crates/deepmail-sandbox/src/security/url_guard.rs`
- Modify: `crates/deepmail-sandbox/src/lib.rs`
- Test: `crates/deepmail-sandbox/src/security/url_guard.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn blocks_private_and_metadata_targets() {
    assert!(validate_url_for_sandbox("http://127.0.0.1").is_err());
    assert!(validate_url_for_sandbox("http://169.254.169.254").is_err());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p deepmail-sandbox blocks_private_and_metadata_targets -- --nocapture`
Expected: FAIL due to missing validator.

**Step 3: Write minimal implementation**

Implement URL parser/validator allowing only `http`/`https` and rejecting loopback/private/link-local/metadata/local domains.

**Step 4: Run test to verify it passes**

Run: `cargo test -p deepmail-sandbox security -- --nocapture`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/deepmail-sandbox/src/security
git commit -m "feat: add sandbox URL validation and SSRF protections"
```

### Task 4: Implement Docker sandbox executor (hardened)

**Files:**
- Create: `crates/deepmail-sandbox/src/executor/docker.rs`
- Modify: `crates/deepmail-sandbox/src/executor/mod.rs`
- Create: `crates/deepmail-sandbox/assets/seccomp/chromium-minimal.json`
- Test: `crates/deepmail-sandbox/src/executor/docker.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn docker_command_includes_required_hardening_flags() {
    let cmd = build_docker_run_args(&sample_task());
    assert!(cmd.contains(&"--read-only".to_string()));
    assert!(cmd.contains(&"--cap-drop=ALL".to_string()));
    assert!(cmd.contains(&"--security-opt=no-new-privileges".to_string()));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p deepmail-sandbox docker_command_includes_required_hardening_flags -- --nocapture`
Expected: FAIL due to missing Docker executor.

**Step 3: Write minimal implementation**

Add hardened Docker command builder and runtime wrapper with timeout-safe cleanup hooks.

**Step 4: Run test to verify it passes**

Run: `cargo test -p deepmail-sandbox docker_command_includes_required_hardening_flags -- --nocapture`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/deepmail-sandbox/src/executor crates/deepmail-sandbox/assets/seccomp
git commit -m "feat: add hardened docker sandbox executor"
```

### Task 5: Add sandbox queue contracts and DB migration

**Files:**
- Modify: `crates/deepmail-common/src/queue/mod.rs`
- Modify: `crates/deepmail-common/src/db/migrations.rs`
- Test: `crates/deepmail-common/src/db/migrations.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn migration_adds_extended_sandbox_reports_columns() {
    let conn = setup_test_db();
    run_migrations(&conn).unwrap();
    assert!(table_has_column(&conn, "sandbox_reports", "email_id"));
    assert!(table_has_column(&conn, "sandbox_reports", "execution_time_ms"));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p deepmail-common migration_adds_extended_sandbox_reports_columns -- --nocapture`
Expected: FAIL until migration is added.

**Step 3: Write minimal implementation**

Add new migration for sandbox report schema extension and indexes.

**Step 4: Run test to verify it passes**

Run: `cargo test -p deepmail-common migration_adds_extended_sandbox_reports_columns -- --nocapture`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/deepmail-common/src/queue/mod.rs crates/deepmail-common/src/db/migrations.rs
git commit -m "feat: add sandbox report schema and queue contracts"
```

### Task 6: Build dedicated sandbox worker

**Files:**
- Modify: `crates/deepmail-sandbox-worker/src/main.rs`
- Create: `crates/deepmail-sandbox-worker/src/worker.rs`
- Create: `crates/deepmail-sandbox-worker/src/store.rs`
- Test: `crates/deepmail-sandbox-worker/src/worker.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
async fn sandbox_worker_times_out_and_marks_report() {
    let out = run_single_job_with_timeout(fake_long_job()).await;
    assert_eq!(out.status, "timed_out");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p deepmail-sandbox-worker sandbox_worker_times_out_and_marks_report -- --nocapture`
Expected: FAIL until worker exists.

**Step 3: Write minimal implementation**

Consume from `deepmail:queue:sandbox`, run executor with timeout, always kill/remove container on timeout/failure, persist status and report.

**Step 4: Run test to verify it passes**

Run: `cargo test -p deepmail-sandbox-worker -- --nocapture`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/deepmail-sandbox-worker
git commit -m "feat: add isolated sandbox worker with timeout-safe execution"
```

### Task 7: Refactor main worker hardening (timeouts, soft-fail, concurrency)

**Files:**
- Modify: `crates/deepmail-worker/src/main.rs`
- Modify: `crates/deepmail-worker/src/pipeline/mod.rs`
- Modify: `crates/deepmail-worker/src/pipeline/url_analyzer.rs`
- Modify: `crates/deepmail-worker/src/pipeline/attachment_analyzer.rs`
- Test: `crates/deepmail-worker/src/pipeline/mod.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
async fn pipeline_soft_fails_stage_and_completes_email() {
    let out = run_pipeline_with_forced_url_failure().await;
    assert!(out.completed);
    assert!(out.soft_failures.contains("url_analysis"));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p deepmail-worker pipeline_soft_fails_stage_and_completes_email -- --nocapture`
Expected: FAIL.

**Step 3: Write minimal implementation**

Use per-stage timeout wrappers, bounded retries, and non-fatal stage error recording. Replace global mutex cache pattern with cloneable/lock-minimized cache access.

**Step 4: Run test to verify it passes**

Run: `cargo test -p deepmail-worker -- --nocapture`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/deepmail-worker/src/main.rs crates/deepmail-worker/src/pipeline
git commit -m "feat: harden worker pipeline with soft-fail timeouts and concurrency limits"
```

### Task 8: Add real-time WebSocket streaming in API

**Files:**
- Modify: `crates/deepmail-api/src/main.rs`
- Modify: `crates/deepmail-api/src/routes/mod.rs`
- Create: `crates/deepmail-api/src/routes/ws_results.rs`
- Modify: `crates/deepmail-api/src/state.rs`
- Test: `crates/deepmail-api/src/routes/ws_results.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
async fn ws_subscriber_receives_stage_update_for_email_id() {
    let event = emit_test_progress_event("email-123").await;
    assert_eq!(event.email_id, "email-123");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p deepmail-api ws_subscriber_receives_stage_update_for_email_id -- --nocapture`
Expected: FAIL until WS route exists.

**Step 3: Write minimal implementation**

Add `/api/v1/ws/results/{email_id}` endpoint, subscribe to Redis pub/sub stage events, forward only matching `email_id` events.

**Step 4: Run test to verify it passes**

Run: `cargo test -p deepmail-api -- --nocapture`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/deepmail-api/src/main.rs crates/deepmail-api/src/routes crates/deepmail-api/src/state.rs
git commit -m "feat: stream realtime analysis updates via websocket"
```

### Task 9: Add sandbox docs and migration strategy docs

**Files:**
- Create: `crates/deepmail-sandbox/README.md`
- Create: `crates/deepmail-sandbox/src/executor/README.md`
- Create: `crates/deepmail-sandbox-worker/README.md`

**Step 1: Write the failing test**

N/A (documentation task).

**Step 2: Verify doc presence fails initially**

Run: `ls crates/deepmail-sandbox/README.md crates/deepmail-sandbox/src/executor/README.md crates/deepmail-sandbox-worker/README.md`
Expected: missing files.

**Step 3: Write minimal implementation**

Document architecture, isolation boundaries, security controls, and Firecracker migration plan.

**Step 4: Verify presence**

Run: `ls crates/deepmail-sandbox/README.md crates/deepmail-sandbox/src/executor/README.md crates/deepmail-sandbox-worker/README.md`
Expected: all files exist.

**Step 5: Commit**

```bash
git add crates/deepmail-sandbox/README.md crates/deepmail-sandbox/src/executor/README.md crates/deepmail-sandbox-worker/README.md
git commit -m "docs: add sandbox architecture and isolation documentation"
```

### Task 10: Full verification

**Files:**
- Verify: workspace

**Step 1: Run formatting**

Run: `cargo fmt --all`
Expected: no errors.

**Step 2: Run lint**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS.

**Step 3: Run tests**

Run: `cargo test --workspace -- --nocapture`
Expected: PASS.

**Step 4: Smoke run binaries**

Run: `cargo run --bin deepmail-api`
Run: `cargo run --bin deepmail-worker`
Run: `cargo run --bin deepmail-sandbox-worker`
Expected: services boot, connect, and idle cleanly.

**Step 5: Commit**

```bash
git add .
git commit -m "feat: deliver phase 4 sandbox isolation realtime updates and hardening"
```
