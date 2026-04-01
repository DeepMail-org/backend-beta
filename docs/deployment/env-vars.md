# Environment Variables

All variables use the `DEEPMAIL_` prefix and `__` as nesting separator.

Examples:

- `DEEPMAIL_SERVER__PORT=3000`
- `DEEPMAIL_SECURITY__JWT_SECRET=...`
- `DEEPMAIL_OBSERVABILITY__OTLP_ENDPOINT=http://tempo:4317`

## Required in Production

- `DEEPMAIL_ENV=production`
- `DEEPMAIL_SECURITY__JWT_SECRET`
- `DEEPMAIL_BACKUP_PASSPHRASE`
- `DEEPMAIL_REDIS__URL`
- `DEEPMAIL_ABUSEIPDB_API_KEY` (if abuse provider enabled)
- `DEEPMAIL_VIRUSTOTAL_API_KEY` (if VirusTotal provider enabled)

## Common Overrides

- `DEEPMAIL_DATABASE__PATH`
- `DEEPMAIL_SECURITY__ADMIN_IP_ALLOWLIST`
- `DEEPMAIL_OBSERVABILITY__OTLP_ENABLED`
- `DEEPMAIL_OBSERVABILITY__OTLP_ENDPOINT`
- `DEEPMAIL_ABUSE__ENABLED`

## Secret Provider Variables

Use file/cmd secret providers instead of plain env vars in production:

- `DEEPMAIL_JWT_SECRET_FILE` / `DEEPMAIL_JWT_SECRET_CMD`
- `DEEPMAIL_ABUSEIPDB_API_KEY_FILE` / `DEEPMAIL_ABUSEIPDB_API_KEY_CMD`
- `DEEPMAIL_VIRUSTOTAL_API_KEY_FILE` / `DEEPMAIL_VIRUSTOTAL_API_KEY_CMD`

Production startup blocks when placeholder values are detected.
