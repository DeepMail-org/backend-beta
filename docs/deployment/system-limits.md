# System Limits

## Linux ulimits

- `nofile`: at least `65535`
- `nproc`: at least `8192`

## SQLite

- Use SSD-backed volume.
- Keep WAL mode enabled.
- Ensure enough disk space for WAL growth + backups.

## Redis

- Set `maxmemory` and eviction policy deliberately (`noeviction` recommended for queues).
- Persist data (AOF or RDB) based on RPO requirements.

## Containers

- Set memory/CPU limits for each service.
- Keep sandbox worker isolated from API network plane when possible.
