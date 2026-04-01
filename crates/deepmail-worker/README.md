# deepmail-worker

## Purpose

Async job consumer that reads analysis jobs from the Redis `deepmail:jobs` stream
and executes the email analysis pipeline. Runs as a separate binary from the API
server, enabling independent scaling.

## Design

```
Redis Stream  ──►  Consumer Loop  ──►  Analysis Pipeline  ──►  SQLite (results)
(XREADGROUP)       (dequeue_job)       (future phases)          (INSERT)
```

## Current Runtime Behavior

- Connects to Redis with a unique consumer name (`worker-{hostname}-{pid}`)
- Reads from `deepmail:jobs` stream using consumer group `workers`
- Runs full pipeline and persists stage results + progress rows
- Uses retry with bounded exponential backoff before DLQ handoff
- Acknowledges completed jobs (`XACK`)

## Pipeline Modules (folder/function map)

| Module | Main function(s) | Purpose |
|---|---|---|
| `pipeline/mod.rs` | `run_pipeline`, `store_iocs`, `store_analysis_results` | Orchestrates end-to-end stage execution and persistence |
| `pipeline/email_parser.rs` | `parse_email` | Parses RFC 5322 data into structured headers/body/attachments |
| `pipeline/header_analysis.rs` | `analyze_headers` | Builds hop chain + auth result signals (SPF/DKIM/DMARC) |
| `pipeline/ioc_extractor.rs` | `extract_iocs` | Extracts IP/domain/url/hash/email indicators |
| `pipeline/url_analyzer.rs` | `analyze_urls` | Structural URL heuristics with Redis cache + optional VirusTotal score |
| `pipeline/attachment_analyzer.rs` | `analyze_attachments` | Hash/entropy/MIME checks and metadata persistence |
| `pipeline/geo_intel.rs` | `resolve_ip_intel` | MaxMind + Redis + DB TTL + AbuseIPDB enrichment for IP indicators |
| `pipeline/scoring.rs` | `calculate_threat_score` | Weighted threat scoring with confidence |

## Threat Intel Providers

- **MaxMind GeoLite2**: local lookup for coordinates + ASN/org
- **AbuseIPDB**: optional abuse confidence + TOR/proxy enrichment
- **VirusTotal**: optional domain reputation score in URL analysis

All provider integrations are fail-soft (pipeline continues if provider call fails).

## Previous/Future Roadmap

The full analysis pipeline will process jobs in this order:

1. **Header parsing** — SPF, DKIM, DMARC, received chain, sender IP
2. **IOC extraction** — IPs, domains, URLs, hashes
3. **Parallel execution:**
   - URL analysis (domain reputation, phishing heuristics)
   - Attachment analysis (hash, entropy, MIME signals)
   - IP intel enrichment (MaxMind + AbuseIPDB)
4. **Graph correlation** — build IOC relationship graph
5. **Similarity detection** — SimHash, TLSH, HTML structure, URL patterns
6. **Threat scoring** — weighted multi-dimensional risk + confidence
7. **Campaign assignment** — cluster by shared infrastructure + similarity
8. **Store results** — write to SQLite
9. **Emit update** — WebSocket notification to frontend

## Security Considerations

- **Isolated from API server** — can run on separate host
- **No direct external access** — workers only talk to Redis and SQLite
- **Error resilience** — errors in one job don't crash the consumer loop
- **Consumer groups** — prevent duplicate job processing across multiple workers
- **Future: sandbox isolation** — attachment detonation in an isolated VM

## Scaling

Multiple worker instances can run simultaneously — Redis consumer groups ensure
each job is delivered to exactly one worker. Scale horizontally by running more
`deepmail-worker` processes.
