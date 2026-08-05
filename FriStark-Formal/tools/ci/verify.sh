#!/usr/bin/env bash
# FriStark-Formal CI — sandbox-only gate suite (Phases 0–3).
# Usage: from repo root: bash tools/ci/verify.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.elan/bin:${PATH}"

echo "=== FriStark-Formal CI ==="
echo "ROOT=$ROOT"
echo "HEAD=$(git rev-parse HEAD 2>/dev/null || echo nogit)"

fail=0
run() {
  local name="$1"; shift
  echo ""
  echo "--- $name ---"
  if "$@"; then
    echo "OK $name"
  else
    echo "FAIL $name" >&2
    fail=1
  fi
}

run params_drift python3 harness/check_params_drift.py

echo ""
echo "--- lake build (critical targets) ---"
if lake build FriStark diff_soundness diff_t4_soundness diff_layout_derive \
    diff_horner_lde diff_opening_consistency diff_pure_verify diff_full_math \
    diff_statement diff_warrant 2>&1; then
  echo "OK lake build"
else
  echo "FAIL lake build" >&2
  fail=1
fi

BIN=".lake/build/bin"
run diff_soundness "$BIN/diff_soundness"
run diff_t4_soundness "$BIN/diff_t4_soundness"
if [[ -x "$BIN/diff_warrant" ]]; then
  run diff_warrant "$BIN/diff_warrant"
fi
run diff_layout_derive "$BIN/diff_layout_derive" .
run diff_horner_lde "$BIN/diff_horner_lde" .
run diff_opening_consistency "$BIN/diff_opening_consistency" .
run diff_public_lde "$BIN/diff_public_lde" . || true
run diff_pure_verify "$BIN/diff_pure_verify" .
run diff_full_math "$BIN/diff_full_math" .
run diff_statement "$BIN/diff_statement" .

if [[ -x "$BIN/diff_multi_product" ]]; then
  run diff_multi_product "$BIN/diff_multi_product"
fi
run multi_stark_prod python3 harness/check_multi_proof_prod.py

echo ""
echo "--- theater audit ---"
if rg -n --glob '*.simple' --glob '*.jsonl' '^(NATEQ\|0\|1)$' vectors/verify 2>/dev/null; then
  echo "FAIL theater NATEQ in vectors" >&2
  fail=1
else
  echo "OK no NATEQ|0|1 lines in vectors/verify"
fi
if rg -n 'deep_compose_ok' harness/export_pure_verify_ir.py harness/export_full_verify_ir.py 2>/dev/null; then
  echo "FAIL deep_compose_ok in exporters" >&2
  fail=1
else
  echo "OK no free deep_compose_ok in exporters"
fi

if [[ $fail -ne 0 ]]; then
  echo "=== CI FAILED ===" >&2
  exit 1
fi
echo "=== CI GREEN ==="
exit 0
