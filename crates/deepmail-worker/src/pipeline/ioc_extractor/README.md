# IOC Extractor Module

The Indicator of Compromise (IOC) engine scans all textual components (headers, text bodies, HTML) for actionable cyber threat indicators.

## Extracted Types

- **IPv4**: Non-private IPs routed to infrastructure.
- **Domains**: Fully Qualified Domain Names (excludes common noise domains like `example.com` or `w3.org`).
- **URLs**: Structured links over `http`, `https`, and `ftp`.
- **Emails**: Embedded target or attacker addresses.
- **Hashes**: MD5, SHA1, and SHA256 cryptographic signatures.

## Performance

The extraction is purely static via `lazy_static` Regex compilations, running linearly against the input document without remote calls, ensuring high throughput for bulk analysis.
