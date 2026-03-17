# DeepMail — Email Threat Intelligence & Analysis System

## Purpose

DeepMail is an enterprise-grade platform for deep analysis of email threats. It
parses `.eml` and `.msg` files, extracts Indicators of Compromise (IOCs), performs
threat intelligence lookups, builds relationship graphs, and scores threats using a
multi-dimensional scoring engine.

## Architecture

```
                  ┌──────────────────┐
                  │   Next.js UI     │  (future phase)
                  └────────┬─────────┘
                           │ REST / WebSocket
                  ┌────────▼─────────┐
                  │  Axum API Server │  ← deepmail-api
                  │  Auth + Rate Lim │
                  └────────┬─────────┘
                           │
                  ┌────────▼─────────┐
                  │   Redis Streams  │  ← Job Queue
                  └────────┬─────────┘
                           │
                  ┌────────▼─────────┐
                  │   Worker Layer   │  ← deepmail-worker
                  │  Analysis Pipeln │
                  └────────┬─────────┘
                           │
                  ┌────────▼─────────┐
                  │  SQLite (WAL)    │  ← Result Storage
                  └──────────────────┘
```

## Workspace Layout

| Crate             | Type    | Purpose                                  |
| ----------------- | ------- | ---------------------------------------- |
| `deepmail-api`    | Binary  | HTTP server — upload, query, auth        |
| `deepmail-common` | Library | Shared types, DB, Redis, validation      |
| `deepmail-worker` | Binary  | Async job consumer and analysis pipeline |

## Quick Start

```bash
# Prerequisites: Rust 1.75+, Redis 6.2+
# 1. Start Redis
redis-server &

# 2. Build
cargo build

# 3. Run API server
cargo run --bin deepmail-api

# 4. Run worker (separate terminal)
cargo run --bin deepmail-worker
```

## Security Model

- **All uploads quarantined** — UUID-renamed, read-only, isolated directory
- **Multi-layer validation** — extension, size, magic bytes, MIME type
- **Prepared statements only** — no string-interpolated SQL
- **Rate limiting** — per-IP token bucket
- **Canonical path validation** — prevents path traversal
- **No execution permissions** — quarantined files are `0o400`

## Configuration

Edit `config.toml` or use environment variables with `DEEPMAIL_` prefix.
See `config.toml` for all available settings.

## Data Flow

1. Client uploads `.eml`/`.msg` via `POST /api/v1/upload`
2. File validated → quarantined → SHA-256 hashed
3. Email record inserted in SQLite
4. Job enqueued to Redis stream `deepmail:jobs`
5. Worker picks job → runs analysis pipeline
6. Results stored → WebSocket notification sent (future)
