#!/usr/bin/env bash
# Safe product prove wrapper — native Rust shieldkit-fri-worker (one prove at a time).
# Python pool_prove is oracle-only; use scripts/safe-prove-oracle.sh or npm run prove:oracle-*.
#
# Usage:
#   scripts/safe-prove.sh prove --kind deposit --depth 20
#   scripts/safe-prove.sh selftest
#   SK_FRI_MEMORY_MAX=8G scripts/safe-prove.sh prove --kind transfer --depth 20
#
# Env:
#   SK_FRI_MEMORY_MAX   — systemd MemoryMax (default 8G for Rust). Empty skips systemd-run.
#   SHIELDKIT_FRI_WORKER — path to release worker binary.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKER="${SHIELDKIT_FRI_WORKER:-$ROOT/.private/cargo-target/release/shieldkit-fri-worker}"
MEM_MAX="${SK_FRI_MEMORY_MAX-8G}"
NODE_ENTRY="$ROOT/scripts/prove-rust.mjs"

if [[ ! -x "$WORKER" && ! -f "$WORKER" ]]; then
  echo "ERROR: missing Rust worker at $WORKER" >&2
  echo "Build: CARGO_TARGET_DIR=.private/cargo-target cargo build -p shieldkit-fri-worker --release" >&2
  exit 2
fi

run() {
  exec node "$NODE_ENTRY" "$@"
}

if [[ -n "$MEM_MAX" ]] && command -v systemd-run >/dev/null 2>&1; then
  exec systemd-run --user --collect --scope \
    -p "MemoryMax=${MEM_MAX}" \
    -p MemorySwapMax=4G \
    --working-directory="$ROOT" \
    -- env SHIELDKIT_FRI_WORKER="$WORKER" node "$NODE_ENTRY" "$@"
fi

run "$@"
