# DeepMail Sandbox

## Architecture

`deepmail-sandbox` defines sandbox execution contracts and security policies. It contains the `SandboxExecutor` trait, shared task/report models, URL validation, and the Docker-backed executor implementation.

Main analysis workers never detonate content directly. They enqueue sandbox jobs; the dedicated sandbox worker executes them in isolated runtime environments.

## Isolation Model

- One container per task.
- No privileged mode.
- Read-only filesystem.
- All capabilities dropped.
- `no-new-privileges` enabled.
- Seccomp profile enforced.
- CPU/memory/PID limits.
- Dedicated restricted network.

## Security Boundaries

- Input validation before execution (URL scheme and host/IP checks).
- Block loopback/private/link-local/metadata targets.
- Execution timeout enforced per task.
- Runtime container always removed after terminal state.

## Future Firecracker Migration

Add `FirecrackerSandboxExecutor` implementing `SandboxExecutor`. Keep model contracts unchanged and select backend by config (`sandbox.backend`). No queue/pipeline contract changes are required.
