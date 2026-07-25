#!/usr/bin/env bash
# env-setup.sh — verify the vendored cashc rescheduling fork is present, pinned, built, and linked.
# The crown build compiles through mr-zwets/cashscript branch compiler-optimizations,
# pinned at 1c707c1dbf87396b30ba5e0704b1db44475ce893 and tracked by
# verifier.cash under vendor/cashc-resched (not as a nested Git repository).
set -u

PINNED_HASH="1c707c1dbf87396b30ba5e0704b1db44475ce893"
GROTH16_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$GROTH16_DIR/.." && pwd)"
VENDOR_DIR="$REPO_DIR/vendor/cashc-resched"
CASHC_PKG="$VENDOR_DIR/packages/cashc"
LINK="$GROTH16_DIR/node_modules/cashc"
PIN_FILE="$VENDOR_DIR/VENDORED_COMMIT"

recipe() {
  cat >&2 <<EOF

The pinned source is tracked by the outer verifier.cash repository. Restore
vendor/cashc-resched from a clean verifier.cash checkout, then run ./setup.sh.
EOF
  exit 1
}

fail() { echo "env-setup: FAIL — $1" >&2; recipe; }

# 1. vendored source exists and declares the pinned upstream commit
[ -d "$VENDOR_DIR/packages/cashc" ] || fail "$VENDOR_DIR/packages/cashc is missing"
[ -f "$PIN_FILE" ] || fail "$PIN_FILE is missing"
RECORDED_HASH="$(tr -d '[:space:]' < "$PIN_FILE")"
[ "$RECORDED_HASH" = "$PINNED_HASH" ] || fail "$PIN_FILE records $RECORDED_HASH, expected $PINNED_HASH"

# 2. the cashc package is built
[ -f "$CASHC_PKG/dist/index.js" ] || fail "$CASHC_PKG/dist/index.js missing — fork not built"
[ -f "$CASHC_PKG/dist/stack-rescheduling.js" ] || fail "dist present but stack-rescheduling.js missing — wrong build"

# 3. node_modules/cashc resolves to it
[ -e "$LINK" ] || fail "$LINK missing (dangling or absent symlink)"
RESOLVED="$(readlink -f "$LINK" 2>/dev/null)" || fail "cannot resolve $LINK"
[ "$RESOLVED" = "$CASHC_PKG" ] || fail "$LINK resolves to $RESOLVED, expected $CASHC_PKG"

# 4. import('cashc') actually works from this repo
node -e "import('cashc').then(()=>process.exit(0)).catch(e=>{console.error(e.message);process.exit(1)})" \
  || fail "import('cashc') failed from $GROTH16_DIR"

echo "env-setup: OK — cashc source records pin $PINNED_HASH, is built, and is linked at $LINK"
