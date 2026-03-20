# Multi-Tenant Readiness

DeepMail enforces tenant boundaries using JWT-derived `user_id` and ownership checks on read/write paths.

## Architecture

- Uploads persist `submitted_by` from JWT claim `sub`.
- Results and websocket subscriptions require ownership (`emails.submitted_by = user_id`).
- Reuse logic materializes user-scoped records to avoid cross-tenant direct access.

## Scaling Strategy

- Tenant isolation checks are DB-indexed for high-query throughput.
- Quotas use per-day counters and optional user overrides in dedicated tables.

## Security Implications

- API denies unauthorized reads with strict ownership filters.
- Audit logs can include allow/deny decisions for compliance trails.
