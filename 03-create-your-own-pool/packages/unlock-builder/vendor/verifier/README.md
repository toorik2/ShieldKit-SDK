# verifier.cash

Our work on the [verifier.cash](https://verifier.cash) competition: **the smallest sound zk-SNARK
verifiers on Bitcoin Cash**. The cashc toolchain and benchmark are vendored; the verified fold pass is
consumed from the sibling `../LeanBCH` repository.

## The two-repo model
Everything competition-related lives here. General, reusable formal-methods tooling lives in the sibling
repo **[LeanBCH](../LeanBCH)** — the machine-checked BCH-2026 VM model, the verified optimizer, the
op-cost floor-provers, and `cost.mjs`/`chunkplan.mjs`. This repo consumes LeanBCH by path
(`../LeanBCH`); LeanBCH does not depend on this one except through a few bridge/measurement scripts.

## Layout
```
lanes/       Agent-owned verifier lanes and hashable candidate manifests (`{id}.json`; see docs/NAMING.md).
packages/    Shared contracts, control-plane CLI, independent judge, and future adapters.
repo.layout.json / control-plane.json
             Checked top-level ownership, worktree bootstrap, and ephemeral retention policy.
build/       The native crown build environment (BN254 Groth16 chunked-covenant verifier).
             chunked/pairing/ = the V3 lazy-reduction fp12 lib, generators, and A1 evidence chain.
             Rebuild + measure:  cd build/chunked/pairing && LEANBCH_ROOT=../../../../LeanBCH \
             CASHC_ROOT=../../../vendor/cashc-resched/packages/cashc node unified_affine.mjs   →  current master 169,738 B; frozen A1 crown 170,366 B
intel/       Competitive intelligence + strategy.
             db/{verifiers,levers}.json · BEST_TRICKS.md · LEADERBOARD.md · RUNBOOK.md
             THEORIES_SUB200K.md (the standing sub-200k battle plan) · tools/frontier.mjs
artifacts/   Per-track built crowns + registry.json (provenance: source commit, compiler, A1 cert).
             Native artifacts remain here; recovered public singleton crowns live in their lanes.
harness/      The verifier.cash scoring harness (mr-zwets/zk-verifier-bench, vendored).
             src/harness/*.ts is the ground truth for the score formula + packaging rules.
vendor/      Vendored build dependencies (committed so the repo is self-contained).
             cashc-resched/ = outer-repo-tracked source for the compiler fork, pinned by VENDORED_COMMIT.
lean/ Groth16* fri_stark/ catalogue/   The repo's own Lean/experimental work.
docs/         PRINCIPLES.md, HARNESS.md, design notes.
```

The lane-oriented migration is documented in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), with operational lifecycle rules in [docs/REPOSITORY.md](docs/REPOSITORY.md). Candidate manifests and independently generated evidence are authoritative; historical entrypoints remain as compatibility shims. Writing agents use scoped arena worktrees, and all builds and evidence write under ignored `.vc/` run directories.

## Standing
- **Sound BN254 native crown: 170,366 B** (beats the 241,518 target by 71,152; supersedes 212,913 and the
  274,607 deployed baseline). The current one-tx frontier is smaller but not completeness-promoted; see
  `catalogue/RESULT.md` for the canonical split between sound crown and experimental measurements. *(Lever F / P2SH20 is DEAD — the harness
  disqualifies P2SH20 lockings; see `intel/db/levers.json` L17.)*
- Current merged-master native rebuild measures `169,738 B` with honest VM/basic-forge green, but remains unbanked and lacks the frozen crown's full independent A1 certificate.
- **Best measured one-tx fixed profile: 81,084 B score / 79,719 B wire** (`DIRECT_FINALIZE_STATE=1`, rank25/rank94 dense tie, `256/256` corpus sweep green); unbanked and not a generic sound crown.
- **Held public singleton size crowns:** BN254 **4,651 score** (4,292 locking) and BLS12-381
  **3,715 score** (3,425 locking). Both are non-deployable size-track entries: the public bench
  reports op-cost blockers of approximately 649 and 2,579 standard inputs, respectively.
- The path under 200k: see `intel/THEORIES_SUB200K.md` (19 ranked theories; sub-200k standard-track "very likely").

## Rebuild / verify
```bash
./setup.sh                                   # sanity-checks the vendored toolchain
npm run check                                # paths + catalogue + harness typecheck + build verdict tests
npm run check:frontiers                      # independently replay all migrated lane frontiers
npm run vc -- arena create sub75-r1 --workers close,packing --target-lane bn254-onetx
npm run vc -- gc                             # dry-run retention plan
cd build/chunked/pairing
LEANBCH_ROOT=../../../../LeanBCH CASHC_ROOT=../../../vendor/cashc-resched/packages/cashc \
  node unified_affine.mjs                         # → current master measurement 169738 B; frozen A1 crown = 170366 B
DIRECT_FINALIZE_STATE=1 SZ_ALLAFF=1 L17SEL=1 SEAMNARROW=1 KSPEC=1 SIBLING_READ=1 FIXED_WDAT=1 DYN_PACK=1 DERIVE_MODE=1 \
  STRIPED=1 STRIPE_BOUNDARY=1 DRIVER_PACK_DERIVED=1 DRIVER_WINDOW_DERIVED=1 KWIN=9 DP=1 STRICT_DEPLOYMENT=1 \
  LEANBCH_ROOT=../../../../LeanBCH CASHC_ROOT=../../../vendor/cashc-resched/packages/cashc PATH=../../../harness/node_modules/.bin:$PATH \
  ELIG_INSTANCE=file ELIG_FILE=../../../harness/src/checkpoints/dense-proof-candidate-25.json \
  node ../../../harness/node_modules/.bin/tsx c7_merge.ts   # → one-tx fixed profile 81084 B score / 79719 B wire
node intel/tools/frontier.mjs                # diff the live competitor frontier (uses `gh api`)
```

Package-manager boundaries are deliberate: root npm orchestrates checks, `build/` and `harness/` use
their pinned pnpm versions and lockfiles, and the upstream-derived compiler source retains Yarn v1.
There is one lockfile per package boundary.

## Provenance / soundness rules
- A1 is the hard gate: **one forgery ⇒ score 0.** Every lever needs an A1 sketch AND a harness-rules check.
- The crown is built with the pinned cashc fork in `vendor/cashc-resched` (commit 1c707c1d) — reproducing
  170,366 byte-exact is the fork-integrity check.
- `build/` tracks upstream `mr-zwets/groth16_cashscript` conceptually but our crown work is original; do not
  attempt to push `build/` anywhere but this repo.
