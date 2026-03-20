# Phase 5.1 Production Hardening Design

## Scope

Phase 5.1 hardens runtime reliability and operability across API, worker, and sandbox worker.

## Approved Architecture

- Shared reliability primitives are implemented in `deepmail-common`.
- API, worker, and sandbox-worker consume the same primitives for consistent behavior.

## Design Decisions

- Redis token-bucket via Lua replaces fixed-window limiter.
- `/metrics` is exposed in Prometheus text format.
- OpenTelemetry spans propagate request/job trace context across services.
- Failed jobs retry with exponential backoff; exhausted jobs move to DLQ streams.
- Manual replay re-enqueues DLQ payloads with reset attempt metadata.
- Data retention runs in a dedicated background worker loop with configurable TTLs.
- Health endpoints include liveness, readiness, and deep dependency checks.
- Circuit breakers are applied to both external intel calls and sandbox execution dispatch.

## Reliability Flows

1. API receives request, applies token-bucket checks (user + IP).
2. API creates trace context and enqueues job metadata.
3. Worker executes with retries and backoff.
4. On terminal failure, worker writes DLQ entry with error reason.
5. Replay endpoint/tool can move DLQ items back into primary queues.

## Observability

- Prometheus metrics are emitted for jobs, failures, latencies, sandbox runtime, and limiter denies.
- OTel trace context is emitted consistently and joined across queue boundaries.

## Security and Operations

- Rate limiting and circuit breakers reduce abuse and cascading failures.
- Retention jobs minimize long-term storage growth and operational risk.
- Deep health checks expose dependency degradation early.
