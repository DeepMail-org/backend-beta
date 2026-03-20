# DeepMail Production Deployment

This guide covers a baseline production deployment for DeepMail.

## Topology

- `deepmail-api`: public HTTP API
- `deepmail-worker`: email analysis worker
- `deepmail-sandbox-worker`: isolated sandbox execution worker
- `redis`: queue + pub/sub + rate limiting counters
- `sqlite`: persistent DB file on durable volume
- `tempo` (or Jaeger): OTLP trace backend

## Security Baseline

- Set `DEEPMAIL_SECURITY__JWT_SECRET` via environment variable.
- Restrict admin endpoints with `DEEPMAIL_SECURITY__ADMIN_IP_ALLOWLIST`.
- Set `DEEPMAIL_BACKUP_PASSPHRASE` for encrypted backups.
- Run sandbox worker with network and syscall restrictions.

## Startup Order

1. Redis
2. Tempo/Jaeger
3. API + workers

## Health Probes

- Liveness: `/api/v1/health/live`
- Readiness: `/api/v1/health/ready`
- Deep health: `/api/v1/health/deep`
