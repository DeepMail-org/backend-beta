# Executor Layer

## Contract

`SandboxExecutor` is the pluggable interface used by sandbox workers:

- `execute_url(url)`
- `execute_file(file_path)`
- `get_report()`

All backends must honor timeout, cleanup, and report semantics.

## Docker Backend

`DockerSandboxExecutor` launches a hardened container per task with strict runtime flags:

- read-only root
- `--cap-drop=ALL`
- seccomp profile
- `no-new-privileges`
- bounded CPU/memory/PIDs
- restricted network

## Firecracker Migration Plan

Implement `FirecrackerSandboxExecutor` in a sibling module with identical trait behavior. Keep `ExecutionHandle` and `SandboxReport` as backend-agnostic contracts so worker orchestration logic remains unchanged.
