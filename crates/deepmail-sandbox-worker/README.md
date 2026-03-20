# DeepMail Sandbox Worker

## Role

Dedicated worker that consumes `deepmail:queue:sandbox`, executes detonation tasks via `SandboxExecutor`, stores `sandbox_reports`, publishes realtime stage updates, and acknowledges jobs.

## Data Flow

1. Dequeue sandbox job.
2. Validate target (URL SSRF guards for URL mode).
3. Execute in isolated runtime with timeout.
4. Persist terminal report.
5. Publish progress event.
6. ACK queue entry.

## Security Boundaries

- Separate process and queue from main analysis worker.
- No cross-use of main pipeline execution paths.
- Timeout-enforced execution.
- Cleanup on failure and timeout.

## Future Migration

This worker depends only on `SandboxExecutor`. Switching to Firecracker requires backend implementation and config selection, not worker flow rewrite.
