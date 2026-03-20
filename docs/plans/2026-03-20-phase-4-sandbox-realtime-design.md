# Phase 4 Sandbox + Realtime + Hardening Design

## Scope

This design introduces strict sandbox isolation, real-time stage updates, and worker/pipeline hardening while preserving clean separation between core analysis and detonation workloads.

## Approved Architecture

- Add `crates/deepmail-sandbox` as a dedicated crate for sandbox abstractions and implementations.
- Add a separate `crates/deepmail-sandbox-worker` binary crate that only consumes `deepmail:queue:sandbox`.
- Keep `crates/deepmail-worker` focused on core analysis; it only enqueues sandbox jobs when heuristics indicate suspicious URLs or attachments.
- Add WebSocket streaming in API for per-`email_id` live stage updates, with Redis pub/sub used as the cross-process event bus.

## Executor Abstraction

Define `SandboxExecutor` trait with methods:

- `execute_url(url)`
- `execute_file(file_path)`
- `get_report()`

Implement `DockerSandboxExecutor` now and keep backend selection pluggable by config. Future `FirecrackerSandboxExecutor` will implement the same trait with no pipeline contract changes.

## Security and Isolation Model

- One sandbox container per detonation task.
- Hardened container runtime:
  - no privileged mode
  - read-only root filesystem
  - all Linux capabilities dropped
  - seccomp profile
  - `no-new-privileges`
  - CPU/memory/PID limits
  - dedicated restricted network
- URL validation before execution:
  - allow `http`/`https` only
  - reject localhost/private/link-local/metadata ranges
  - block suspicious host forms that can bypass SSRF filters
- Enforce execution timeout and always kill/remove container on terminal paths.

## Queue and Data Flow

1. Main pipeline flags suspicious IOC/attachments.
2. Main worker publishes `SandboxJob` to `deepmail:queue:sandbox`.
3. Sandbox worker dequeues, validates target, executes through `SandboxExecutor`.
4. Sandbox worker stores output in `sandbox_reports` and emits progress events.
5. API WebSocket relays progress events to clients subscribed by `email_id`.

## Reliability and Performance

- Replace `Arc<Mutex<ThreatCache>>` with lock-minimized cache usage via cloneable Redis-backed cache handles.
- Add explicit timeouts for heavy stages (`url_analysis`, `attachment_analysis`, sandbox execution).
- Add soft-fail stage semantics so stage failures do not crash entire pipeline.
- Add worker concurrency limits with semaphore-based max in-flight jobs.
- Use batched DB writes where practical and avoid repeated parsing.

## Database Changes

Extend `sandbox_reports` to support URL detonation output and execution state:

- `email_id`
- `url`
- `final_url`
- `redirects` (JSON)
- `network_calls` (JSON)
- `suspicious_behavior` (JSON)
- `execution_time_ms`
- `status`
- `error_message`

Add indexes for high-volume queries (`email_id`, `status`, `submitted_at`).

## Documentation Deliverables

- `crates/deepmail-sandbox/README.md`
- `crates/deepmail-sandbox/src/executor/README.md`
- `crates/deepmail-sandbox-worker/README.md`

Each document explains architecture, isolation boundaries, and Firecracker migration strategy.
