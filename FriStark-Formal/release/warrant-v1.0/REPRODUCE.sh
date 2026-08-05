#!/usr/bin/env bash
# Warrant v1.0 reproduce — from repo root
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.elan/bin:${PATH}"
echo "ROOT=$ROOT"
echo "HEAD=$(git rev-parse HEAD 2>/dev/null || echo nogit)"
bash tools/ci/verify.sh
if [[ -x .lake/build/bin/diff_warrant ]]; then
  .lake/build/bin/diff_warrant
fi
echo "REPRODUCE_OK"
