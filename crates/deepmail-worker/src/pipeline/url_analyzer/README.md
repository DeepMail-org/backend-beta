# URL Analyzer Module

The URL Analyzer evaluates web links structurally to identify risks such as obfuscation or suspicious infrastructure.

## Features

- **Redis Caching**: Looks up the domain in the `ThreatCache` to prevent re-analyzing heavily spammed URLs, accelerating pipeline throughput.
- **Static Heuristics**:
    - **IP Hosts**: Detects URLs hiding behind direct IP references (e.g. `http://1.2.3.4/login`).
    - **Suspicious TLDs**: Flags domains using low-cost or high-abuse TLDs (`.tk`, `.top`, `.xyz`, etc).
    - **Obfuscation Checks**: Identifies abnormally long URLs and deep subdomain chains used to evade filters.
    - **Encoding Analysis**: Looks for percent-encoded structural characters designed to fool basic parsers.

## Zero-Network Policy (Phase 2)

To maintain privacy and performance, this module operates purely statically offline. It does not issue HTTP requests to the target domains, preventing attackers from confirming email receipt via tracking pixels or unique payload delivery paths.
