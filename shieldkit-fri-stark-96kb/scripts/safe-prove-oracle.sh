#!/usr/bin/env bash
# Oracle-only prove via pure-Python pool_prove (NOT the product path).
# Product proves: scripts/safe-prove.sh / npm run prove:selftest
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/packages/prove/python/pool_prove.py"
MEM_MAX="${SK_FRI_MEMORY_MAX-24G}"

if [[ ! -f "$PY" ]]; then
  echo "ERROR: missing $PY" >&2
  exit 1
fi

if [[ -n "$MEM_MAX" ]] && command -v systemd-run >/dev/null 2>&1; then
  exec systemd-run --user --collect --scope \
    -p "MemoryMax=${MEM_MAX}" \
    -p MemorySwapMax=8G \
    --working-directory="$ROOT" \
    -- python3 "$PY" "$@"
fi

exec python3 "$PY" "$@"
