#!/usr/bin/env bash
# verifier.cash — reconstitute the build toolchain on a fresh clone.
# We commit the pinned cashc fork SOURCE (vendor/cashc-resched) so it can never evaporate, but NOT the
# rebuildable bulk (node_modules, dist) — this script regenerates those. Run once after cloning.
set -uo pipefail
VC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIN=1c707c1dbf87396b30ba5e0704b1db44475ce893
fail=0

echo "== verifier.cash setup =="
command -v node >/dev/null 2>&1 && echo "  node $(node --version)" || { echo "  FAIL node not found"; exit 1; }
command -v bwrap >/dev/null 2>&1 && echo "  bwrap $(bwrap --version | head -n 1)" || { echo "  FAIL bubblewrap not found (required for isolated legacy runs)"; fail=1; }
corepack enable >/dev/null 2>&1 || true

# 1. Build the vendored cashc fork (produces packages/*/dist + its node_modules).
# The source is tracked by verifier.cash; vendor/cashc-resched is intentionally
# not a nested Git repository.
if [ -d "$VC/vendor/cashc-resched/packages/cashc/dist" ]; then
  echo "  ok   vendor/cashc-resched already built"
else
  echo "  .. building vendor/cashc-resched (pinned $PIN)"
  ( cd "$VC/vendor/cashc-resched" && npx -y yarn@1.22.22 install --frozen-lockfile && npx -y yarn@1.22.22 build ) || { echo "  FAIL cashc build"; fail=1; }
fi

# 2. Install root orchestration dependencies.
if [ ! -d "$VC/node_modules" ] || [ -z "$(ls -A "$VC/node_modules" 2>/dev/null)" ]; then
  echo "  .. npm ci at repository root"
  ( cd "$VC" && npm ci --no-audit --no-fund ) || { echo "  FAIL root npm ci"; fail=1; }
fi

# 3. Install the crown build's deps + wire the cashc symlink.
if [ ! -d "$VC/build/node_modules" ] || [ -z "$(ls -A "$VC/build/node_modules" 2>/dev/null)" ]; then
  echo "  .. pnpm install in build/"
  ( cd "$VC/build" && corepack pnpm install --frozen-lockfile ) || { echo "  FAIL build pnpm install"; fail=1; }
fi
mkdir -p "$VC/build/node_modules"
if [ ! -e "$VC/build/node_modules/cashc" ]; then
  ln -s "$VC/vendor/cashc-resched/packages/cashc" "$VC/build/node_modules/cashc"
  echo "  ok   wired build/node_modules/cashc -> vendor/cashc-resched/packages/cashc"
fi

# 4. Install harness dependencies.
if [ ! -d "$VC/harness/node_modules" ] || [ -z "$(ls -A "$VC/harness/node_modules" 2>/dev/null)" ]; then
  echo "  .. pnpm install in harness/"
  ( cd "$VC/harness" && corepack pnpm install --frozen-lockfile ) || { echo "  FAIL harness pnpm install"; fail=1; }
fi

# 5. Verify cashc imports.
if ( cd "$VC/build" && node -e "import('cashc').then(()=>process.exit(0)).catch(()=>process.exit(1))" 2>/dev/null ); then
  echo "  ok   cashc imports from build/"
else
  echo "  FAIL cashc import from build/"; fail=1
fi

# 6. Sibling LeanBCH (consumed by path and linked into arena worktrees).
[ -d "$VC/../LeanBCH" ] && echo "  ok   ../LeanBCH present" || { echo "  FAIL ../LeanBCH missing (required by arena production gates)"; fail=1; }

echo
if [ "$fail" = 0 ]; then
  echo "Setup OK. Rebuild + measure current master native candidate (expect 169738 B; frozen A1 crown is 170366 B):"
  echo "    cd build/chunked/pairing && LEANBCH_ROOT=../../../../LeanBCH CASHC_ROOT=../../../vendor/cashc-resched/packages/cashc node unified_affine.mjs"
else
  echo "Setup incomplete — see FAIL lines above. Restore vendor/cashc-resched from this verifier.cash checkout, then rerun ./setup.sh."
fi
exit $fail
