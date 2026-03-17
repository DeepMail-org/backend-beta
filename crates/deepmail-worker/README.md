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

## Phase 1 (Current)

- Connects to Redis with a unique consumer name (`worker-{hostname}-{pid}`)
- Reads from `deepmail:jobs` stream using consumer group `workers`
- Logs received jobs
- Acknowledges processed jobs (XACK)
- Back-off on errors (2-second delay)

## Future Pipeline (Phase 2+)

The full analysis pipeline will process jobs in this order:

1. **Header parsing** — SPF, DKIM, DMARC, received chain, sender IP
2. **IOC extraction** — IPs, domains, URLs, hashes
3. **Parallel execution:**
   - URL analysis (redirect resolution, domain reputation, phishing detection)
   - Attachment analysis (hash, entropy, strings, EXIF, macros)
   - Threat intelligence lookups (VirusTotal, AbuseIPDB)
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
