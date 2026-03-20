# Phase 5 Enterprise Features Design

## Objectives

Phase 5 introduces enterprise-grade observability, multi-tenant isolation, abuse controls, result reuse, sandbox reuse, and environment-aware feature configuration while preserving the current crate architecture.

## Chosen Approach

Use incremental monolith hardening in existing crates:

- `deepmail-api`: auth extraction, tenant checks, rate limit enforcement, metrics endpoint.
- `deepmail-worker`: trace propagation, stage metrics, reuse-aware execution.
- `deepmail-sandbox-worker`: sandbox cache reuse and execution metrics.
- `deepmail-common`: shared config, migrations, queue helpers, and policy primitives.

## Multi-Tenant Model

- JWT claim (`sub`) is canonical `user_id`.
- API writes always persist `submitted_by = user_id`.
- Read endpoints filter by ownership and deny cross-user access.
- Reuse can be global for efficiency, but returned resources are materialized per user to avoid direct cross-tenant row exposure.

## Database Extensions

Add migrations for:

- `user_quotas` (policy overrides)
- `usage_counters` (daily counters)
- `result_reuse_index` (hash/url/domain reuse)
- `emails.reused_from_email_id`, `emails.trace_id`
- indexes for quota checks, tenant filters, and reuse lookups

## Observability

- Structured logs enriched with `trace_id`, `request_id`, `email_id`, `user_id`, `stage`.
- Request-to-worker trace propagation via job payload metadata.
- Metrics endpoint exposing:
  - jobs processed/failures
  - per-stage latency
  - sandbox execution duration
  - reuse hit/miss and rate-limit denials

## Rate Limiting

- Redis-backed fixed-window limiter for:
  - per-user limits
  - per-IP limits
- Enforcement on upload/results/ws endpoints before heavy operations.

## Result and Sandbox Reuse

- File hash reuse at upload path.
- URL/domain reuse index consulted in URL analysis stage.
- Sandbox cache checked before detonation using freshness TTL.

## Feature Flags and Config Layers

- Add feature flags:
  - `enable_sandbox`
  - `enable_similarity`
  - `enable_intel_providers`
- Config layering:
  - `config/base.toml`
  - `config/development.toml`
  - `config/staging.toml`
  - `config/production.toml`
  - environment overrides via `DEEPMAIL_*`

## Scalability and Security

- Stateless API scales horizontally with Redis-backed controls.
- Worker throughput controlled by queue consumers + semaphore concurrency.
- Reuse index and quotas reduce expensive duplicate processing.
- Tenant checks and JWT-derived ownership enforce data isolation.
