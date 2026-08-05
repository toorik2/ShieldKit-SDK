#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.elan/bin:${PATH}"
echo "ROOT=$ROOT"
echo "HEAD=$(git rev-parse HEAD)"
bash tools/ci/verify.sh
lake exe diff_warrant
python3 harness/check_multi_proof_prod.py
echo REPRODUCE_OK
