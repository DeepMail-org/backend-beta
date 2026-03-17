# deepmail-api

## Purpose

Lightweight Axum-based HTTP API server for the DeepMail platform. Handles file
uploads, health checks, and job dispatch to Redis. **No heavy processing** happens
in this service — all analysis is offloaded to workers via the Redis job queue.

## Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/upload` | Submit an email file for analysis |
| `GET` | `/api/v1/health` | Health/readiness probe |

## Entry Point

`src/main.rs` bootstraps the server:
1. Load `config.toml` + env overrides
2. Initialize structured logging (JSON or pretty)
3. Create SQLite pool (WAL mode, auto-migrations)
4. Connect to Redis
5. Initialize quarantine directory
6. Build Axum router with middleware
7. Serve with graceful shutdown (SIGINT/SIGTERM)

## Middleware Stack

Applied bottom-to-top on every request:

1. **TraceLayer** — structured request/response logging
2. **CorsLayer** — Cross-Origin Resource Sharing
3. **RequestBodyLimitLayer** — max body size enforcement

## Module Map

| Module | File(s) | Purpose |
|---|---|---|
| `state` | `state.rs` | `AppState` (DB, Redis, config, quarantine path) |
| `routes` | `routes/mod.rs` | Route tree aggregation |
| `routes::upload` | `routes/upload.rs` | File upload handler |
| `routes::health` | `routes/health.rs` | Health check handler |
| `middleware` | `middleware/mod.rs` | Middleware exports |
| `middleware::rate_limit` | `middleware/rate_limit.rs` | Token-bucket rate limiter |

## Security Considerations

- **Upload validation before disk write** — extension, size, magic bytes, MIME, zip bomb
- **Rate limiting** — per-IP token bucket to prevent brute-force/DoS
- **Request size limit** — enforced by Axum `RequestBodyLimitLayer`
- **No X-Forwarded-For trust** — uses direct connecting IP
- **Error messages** — never leak internal paths or stack traces
- **Graceful shutdown** — handles SIGINT and SIGTERM for clean connection draining

## Future Extensibility

- Add `auth` module: JWT/OAuth2 authentication middleware
- Add `routes::analysis` module: query analysis results
- Add `websocket` module: real-time progress updates
- Add `routes::campaigns` module: campaign cluster queries
