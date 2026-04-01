#!/usr/bin/env bash
set -euo pipefail

echo "[migration-smoke] Running migration rollback smoke test"
cargo test -p deepmail-common migration_rollback_smoke -- --nocapture
