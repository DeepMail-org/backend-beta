# URL Analyzer Module

The URL Analyzer evaluates web links structurally to identify risks such as obfuscation or suspicious infrastructure.

## Features

- **Redis Caching**: Looks up the domain in the `ThreatCache` to prevent re-analyzing heavily spammed URLs, accelerating pipeline throughput.
- **Static Heuristics**:
    - **IP Hosts**: Detects URLs hiding behind direct IP references (e.g. `http://1.2.3.4/login`).
    - **Suspicious TLDs**: Flags domains using low-cost or high-abuse TLDs (`.tk`, `.top`, `.xyz`, etc).
    - **Obfuscation Checks**: Identifies abnormally long URLs and deep subdomain chains used to evade filters.
    - **Encoding Analysis**: Looks for percent-encoded structural characters designed to fool basic parsers.

## Reputation Enrichment

- Structural signals are always computed offline.
- If `DEEPMAIL_VIRUSTOTAL_API_KEY` is set, domain reputation is enriched from VirusTotal v3 (`/domains/{domain}`).
- The enrichment score is stored in `reputation_score` and cached by domain in Redis.

## Fail-Soft Behavior

If VirusTotal is unavailable, rate-limited, or returns an error, the module returns structural analysis only and does not fail the pipeline.
