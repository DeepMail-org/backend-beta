# Observability Architecture

DeepMail observability combines structured logs, trace context propagation, and metrics snapshots.

## Components

- API attaches request context (`request_id`, JWT `user_id`) to queued jobs.
- Worker and sandbox worker include trace/user/email/stage dimensions in logs.
- `/api/v1/metrics` returns aggregate job, failure, stage latency, and sandbox timing metrics.

## Scaling Strategy

- Metrics are query-derived and safe for horizontally scaled workers.
- Redis queue and progress channels provide distributed event visibility.

## Security Implications

- Avoid high-cardinality sensitive labels in metrics.
- Keep raw identifiers in logs only and avoid exposing secrets.
