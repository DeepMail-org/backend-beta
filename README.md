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

## Key Folders And Responsibilities

| Folder | What it does | How it works |
|---|---|---|
| `crates/deepmail-api/src/routes/` | Public and admin HTTP endpoints | Axum handlers validate auth, apply per-user/IP rate limits, and query SQLite using prepared statements |
| `crates/deepmail-worker/src/pipeline/` | Multi-stage mail analysis engine | `run_pipeline` orchestrates parser/header/IOC/url/attachment/scoring stages and persists results |
| `crates/deepmail-worker/src/pipeline/geo_intel.rs` | Backend geolocation and abuse enrichment | MaxMind GeoLite2 lookup + Redis cache + SQLite persistence + optional AbuseIPDB enrichment |
| `crates/deepmail-common/src/db/` | Schema and migrations | Idempotent migrations tracked in `_migrations`; latest migration adds `ip_geo_intel` TTL cache table |
| `authentication-gen/` | Operational token scripts | CLI scripts bootstrap and rotate auth tokens via API endpoints |
| `docs/` | Architecture and policy docs | Service-level READMEs and security policy documents used for ops and audits |

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

### Threat Intel Keys (local only)

- `DEEPMAIL_ABUSEIPDB_API_KEY` - abuse confidence, TOR/proxy signals
- `DEEPMAIL_VIRUSTOTAL_API_KEY` - optional URL/domain reputation enrichment

Store real keys only in local ignored env files (`.env.local`) or secret providers.

## Data Flow

1. Client uploads `.eml`/`.msg` via `POST /api/v1/upload`
2. File validated → quarantined → SHA-256 hashed
3. Email record inserted in SQLite
4. Job enqueued to Redis stream `deepmail:jobs`
5. Worker picks job → runs analysis pipeline
6. Results stored → WebSocket notification sent (future)

## New Geo-Intel Data Contract

- `ioc_nodes.metadata` for IP IOCs stores enriched geo payload (`lat/lon/country/city/asn/org/abuse flags`)
- `ip_geo_intel` persists resolver output with TTL (`expires_at`) and `confidence_score`
- `GET /api/v1/results/:email_id` now returns:
  - `geo_points` for map rendering
  - `hop_timeline` parsed from the `Received` chain
