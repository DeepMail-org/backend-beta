# Sandbox System

The Sandbox System provides a fully isolated environment for detonating and
analyzing dynamic threats like malicious URLs and attachments.

## Architecture

- **Isolation**: Runs in a separate process/container from the main worker.
- **Queue**: Uses a dedicated Redis stream `deepmail:sandbox_jobs`.
- **Instrumentation**: Captures network logs, redirects, and visual fingerprints.

## Key Features

1. **URL Detonation**: Headless browser (Playwright) execution of target URLs.
2. **Behavioral Sniffing**: Real-time capture of network connections and redirects.
3. **SSRF Protection**: Strict outbound firewall rules for the browser instance.

## Security Model

The sandbox uses the "Hazmat" principle:
- **Zero Local Persistence**: Disk changes are discarded after each run.
- **Network Restricted**: No access to internal system resources (169.254.x.x, 10.x.x.x, etc.).
- **Time Bound**: Strict 30-second execution limit.
