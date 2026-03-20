# Attachment Analyzer Module

This module inspects extracted file attachments to generate static threat signals without executing the payloads.

## Features

1. **Redis Caching**: Hashes the file via SHA-256 and checks the `ThreatCache` to skip analysis for known benign or malicious files.
2. **Entropy Calculation**: Computes Shannon Entropy (0.0 - 8.0) across the byte stream. Files approaching 8.0 are flagged as highly suspicious, indicating packed executables, encrypted payloads, or obfuscated malware.
3. **MIME & Extension Analysis**: Compares the file extension against its actual Magic Byte MIME definition (via the `infer` crate). Discrepancies often indicate attempts to bypass simple extension filters (e.g., an `.exe` disguised as a `.pdf`).
4. **Suspicious Categories**: Automatically flags high-risk executable, script, and macro-enabled document types.

## Database Persistence

All analyzed attachments are persisted to the database, allowing for historical correlation of malware campaigns across the tenant space.
