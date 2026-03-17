# deepmail-common

## Purpose

Shared library crate containing all types, configuration, database access, Redis queue,
upload validation, and utilities used by both the API server (`deepmail-api`) and worker
(`deepmail-worker`).

## Modules

| Module | File(s) | Purpose |
|---|---|---|
| `config` | `config.rs` | Typed config loaded from TOML + env overlay |
| `errors` | `errors.rs` | Unified error enum with `IntoResponse` impl |
| `db` | `db/mod.rs`, `db/migrations.rs` | SQLite pool (WAL mode) + migration runner |
| `queue` | `queue/mod.rs` | Redis Streams job queue (XADD/XREADGROUP/XACK) |
| `models` | `models/mod.rs` | Domain types: Email, Attachment, IOC, Analysis |
| `upload` | `upload/validation.rs`, `upload/quarantine.rs` | File validation + quarantine system |
| `utils` | `utils/mod.rs` | SHA-256, UUID, filename sanitization, path validation |

## Data Flow

```
Upload bytes  ──►  validation.rs  ──►  quarantine.rs  ──►  db (insert)  ──►  queue (enqueue)
                   (6-layer check)     (UUID rename,       (prepared stmt)   (XADD to stream)
                                        0o400 perms)
```

## Security Considerations

- **No `unwrap()`** — all operations return `Result` with typed errors
- **Prepared statements only** — no string-interpolated SQL
- **Canonical path validation** — all file operations verify paths are within allowed directories
- **Error sanitization** — `IntoResponse` impl never leaks internal details to clients
- **WAL mode** — safe concurrent reads, single writer pattern

## Future Extensibility

- Add `parser/` module for email header parsing (SPF/DKIM/DMARC)
- Add `ioc/` module for IOC extraction
- Add `intel/` module for threat intelligence integrations
- Add `scoring/` module for threat scoring engine
- Add `similarity/` module for SimHash/TLSH comparison
