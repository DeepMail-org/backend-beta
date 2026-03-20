# Rate Limiting and Abuse Protection

DeepMail applies Redis-backed fixed-window limits for both user and IP dimensions.

## Architecture

- API endpoints enforce per-user and per-IP checks before expensive processing.
- Redis counters provide shared enforcement across multiple API instances.
- Violations return `429 Too Many Requests`.

## Scaling Strategy

- Counter keys are shard-friendly and ephemeral via TTL.
- Stateless API instances share enforcement through Redis.

## Security Implications

- Dual scope limits reduce credential stuffing and source-IP abuse.
- Limits are configurable per environment and can be tightened in production.
