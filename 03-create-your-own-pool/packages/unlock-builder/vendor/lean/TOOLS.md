# LeanBCH toolset — what we have, and when to reach for each

The always-current catalog of our BCH formal-methods + optimization tooling — the moat our
verifier.cash competitors don't have. Living doc: maintained *with* the code so it can't drift.
Recall pointer: the `reference-leanbch-toolset` memory. Every entry names a real file + entry-point;
verify a name still exists (`grep`) before relying on it.

**Big picture — three layers:**
1. **The executable VM model** (§1–4): run any BCH-2026 script/tx, get accept/reject + the exact
   5-metric op-cost. This *is* the core asset — an executable twin of the consensus VM.
2. **The optimization + floor stack** (§5–8): shrink a verifier and PROVE the shrink is sound + prove
   lower bounds competitors can't.
3. **The trust harness** (§9–10): the differential/conformance/necessity machinery that makes every
   claim above checkable, plus the reproduced BN254 build env (§11) to measure against the real crown.

Build targets (`export PATH="$HOME/.elan/bin:$PATH"` first):
| target | command | what it builds |
|---|---|---|
| core | `lake build` (or `lake build LeanBCH`) | VM + cost + consensus model (fast) |
| optimizer proofs | `lake build LeanBCHOpt` | the `LeanBCH.Opt.*` soundness/floor theorems |
| KATs | `lake build LeanBCHValidation` | runs every build-time known-answer test |
| conformance exe | `lake build vmbconf` → `.lake/build/bin/vmbconf` | the vmb-corpus differential runner |
| necessity | `lake build Meta` | proof-term closure → `Meta/necessity.json` |

---

## 1. The executable VM — run/measure any BCH-2026 script  (`LeanBCH/VM/`)
The heart of it: a total small-step machine over parsed bytecode. Point it at bytecode → run it → read
accept/reject, final stack, error, and metrics. Everything else is built on this.
- `VM/Instr.lean` — `parse : Bytes → Parsed` (bytes → instruction array; only the tail can be `malformed`). Inverse `encodeInstr` (for OP_ACTIVEBYTECODE).
- `VM/Eval.lean` — `eval : Bytes → State` (parse+run, loop-free) · `run : Nat → State → State` (fuel-driven) · `step1`/`stepInstr` (pure per-op core — pushes, stack/alt ops, arithmetic, byte-string, bitwise, comparisons, hashes, inline IF/ELSE + BEGIN/UNTIL). **Frozen keystone core** — proofs freeze here.
- `VM/Extended.lean` — `runExt : Program → Secp256k1 → Nat → State → State` · `stepInstrExt` (the 2026 surface: shifts/INVERT, OP_DEFINE/OP_INVOKE functions, ALL introspection 0xc0–0xd3, CashToken introspection, CHECKSIG/CHECKDATASIG/CHECKMULTISIG via the oracle, CLTV/CSV, REVERSEBYTES, CODESEPARATOR). Enforces per-step limits (budget/ctrl-depth/memory).
- `VM/State.lean` — `State` (stack·alt·ctrl·instrs·ip·metrics·budget·error·functionTable) + the `error` enum (every consensus failure mode).
- `VM/Number.lean`→`LeanBCH/Number.lean` — `bigIntToVmNumber`/`vmNumberToBigInt`/`isMinimallyEncoded`/`intByteLen` (signed-magnitude VM-number codec, roundtrip-proven, models libauth; BigInt CHIP ≤10000B).
- `VM/Straightline.lean` — `foldStraight`/`BlockEquiv` + `splice_congr`: the algebraic block denotation the optimizer's soundness rests on (replace a block with an equivalent one ⇒ whole program unchanged).

## 2. Consensus verification — accept/reject a real input or tx  (`LeanBCH/VM/Verify.lean`, `Standard.lean`)
- `verifyInput : Secp256k1 → Program → Bool` — one input, full consensus: push-only unlock, run unlock→lock (+P2SH-20/32 redeem), clean-stack, ≤10000B/script, op-cost ≤ budget, hash-iters ≤ limit.
- `verifyTransaction : Secp256k1 → Program → Bool` — whole tx: structural (`txValid` size/version/range) + token checks (`verifyTokens`) + every input.
- `verifyStandard`/`classify : … → Policy → Program → …` (`Standard.lean`) — the relay-policy layer (standard vs nonstandard vs invalid; output templates, dust, data-carrier). `policy2026` is the concrete May-2026 policy.
- For non-signature families run with `Secp256k1.reject` (the correct default — cost never depends on the oracle).

## 3. The op-cost model — the rare, high-value part  (`LeanBCH/Cost/`, `Epoch.lean`, `VM/Meter.lean`)
Most VM models under-model gas; ours makes the **5-metric BCH-2026 operationCost** first-class and machine-checked. This is the metric the crown work lives and dies on.
- `Cost/Metrics.lean` — `Metrics {evaluatedInstructionCount, signatureCheckCount, hashDigestIterations, arithmeticCost, stackPushedBytes}` + `operationCost E m = eic·100 + sig·26000 + hash·(192|64) + arith + push`. `operationCost_add`/`_mono` (linearity/monotonicity).
- `VM/Meter.lean` — `evalCost : Epoch → Bytes → Nat` (**the in-Lean op-cost of raw bytecode from empty**) · `kappa`/`stepMeter`/`runMeter` (per-step billing). `copyBytes`/`byteOpBytes`/`shiftBytes`/`widthAt` = the pushed-byte decomposition.
- `Cost/{Arith,Hash,Sig}.lean` — component costs: `arithCost k a b r` (MUL/DIV/MOD pre-charge |a|·|b| + result double-bill) · `hashCost h len` (`hashIterations len = 1+(len+8)/64`, ×2 for HASH160/256) · `sigCost`/`multiSigCost` (26000·nKeys).
- `Epoch.lean` — the versioned pins: `BCH_2026_05` (standard, hash 192) / `BCH_2026_05_CONSENSUS` (block, hash 64). `maxOperationCost E ulen = (41+ulen)·800` (the density budget) + `_mono`. A repricing is a new `Epoch`, not a code edit.
- `VM/Verify.lean` — `opBudget ulen = (41+ulen)·800` · `VM/Extended.lean` `stepOpCost`/`maxOpCostCeiling = 8,032,800` (the absolute per-input ceiling) + `enforceStepLimits` (ctrl-depth ≤100, memory slots ≤1000).
- Consensus witnesses: `Cost/Spine.lean` `chunks E O = ⌈O/800⌉` (bytes needed to HOST an op-cost — reference-only) + `_witness`/`operationCost_309`. Invariants: `VM/Invariants.lean` `verifyInput_cost_within_budget`, `runExt_prefix_within_budget` (acceptance ⇒ every prefix within budget).

## 4. Transactions, sighash, native crypto, oracle  (`LeanBCH/Tx/`, `Crypto.lean`, `Oracle.lean`)
- `Tx/Wire.lean` — `encodeTransaction : Transaction → Bytes` / `decodeTransaction` (byte-exact, roundtrip-proven, canonical-varint enforced, CashToken prefix per CHIP-2022-02) · `decodeProgram txHex srcOutsHex idx : Option Program` (hex → eval context).
- `Tx/Sighash.lean` — `encodeSigningSerialization p covered ty` (14-field BIP143-style preimage; flags ALL/NONE/SINGLE/ANYONECANPAY/UTXOS/FORKID) · `sighashDigest` (= `hash256` of it).
- `Tx/Types.lean` — `Transaction`/`Input`/`Output`/`TokenData`/`Nft`/`Program` (+ total `Program.*` accessors). Note: outpoint hash & token category held in UI order, reversed at the wire boundary.
- `Crypto.lean` — **native Lean** `sha256`/`sha1`/`ripemd160`/`hash256`(=sha256²)/`hash160`(=ripemd∘sha256). FIPS/reference impls, `#eval`-able, build-time KAT-guarded (mismatch fails the build). NOT oracles.
- `Oracle.lean` — `Secp256k1 {verifySchnorr, verifyDERLowS}` = **the ONE opaque trust seam** (accept/reject only; no cost metric reads it). `Secp256k1.reject` = the always-false stub for non-crypto tests.

## 5. Verified optimizer core — `LeanBCH.Opt.*` (Lean 4, 0-sorry, axiom-clean)
The theorems the optimizer's transforms are discharged by. Format-agnostic (proved over abstract `Op α`).
- `Opt/Scheduler.lean` — `schedule_refines` (+`_move_cond`): DAG-reschedule / move-arrange soundness.
- `Opt/FoldTable.lean` — `FoldTable.*` (**2,114 folds** = 1,700 unconditional + 414 depth-guarded, L≤4 window-complete) + `Peephole` (L5).
- `Opt/InvokeCSE.lean` — `invoke_cse` (ONE theorem covers all subroutine factoring). `Opt/Providers.lean` — `invoke_const_provider`.
- `Opt/Codec.lean` — `parse_encode` (byte roundtrip). `Opt/DecompileWF.lean` — `decompile_end_to_end` (decompile→WellFormed bridge).
Axioms: `#print axioms <name>` must be ⊆ {propext, Quot.sound, Classical.choice}.

## 6. General optimizer — `optimizer/` (node, dialect-pluggable, gated, trust-labeling)
Point it at ANY cashc BCH verifier → smaller equivalent + a trust label. `cd optimizer && npm install`.
- `cli.mjs` — `node cli.mjs <in.hex|.cash> [out.hex] [--dialect auto] [--gate] [--report p]`. Compiles `.cash`, selects dialect, runs cse+fold, optional gate; **refuses to emit** on gate-fail or covenant (in-place = unsound).
- `passes/{cse,fold,movearrange}.mjs` — cse+fold = byte-golf; move-arrange = op-cost lever (needs `--arity a.json` cache). `optimize.mjs` = the fixpoint driver.
- `dialect/{dialect,cashc-standard,covenant-wrapped,index}.mjs` — the ONLY format-coupled layer. `covenant-wrapped` = **analyze-only** (deployed chunks hash-commit bodies → in-place edit is forgeable).
- `ir.mjs` (frozen IR contract) · `manifest.mjs` (3-tier PROVEN/VALIDATED/ORACLE per-run report) · `test/byte-identity.mjs` (reproduces the crowns byte-identically = regression gate).

**Re-chunk planner — `optimizer/chunkplan.mjs` ★ FAITHFUL + A1-SAFE (committed).** Picks the chunk
*boundaries* of a chunked covenant verifier to minimize total on-chain bytes, and REPORTS
**compile-verified real bytes** (never a model prediction). A planner, not an in-place body editor — it
never touches the hash-committed body, so it is sound where the covenant dialect refuses to emit.
- **Engine (domain-agnostic):** `planOptimal` = a provably-optimal interval DP (O(n²), brute-force-checked
  in `runSelfTest`), fed a **two-model split**: a MEAN-marginal predictive-bytes model (ranks candidates)
  + a MAX-marginal UPPER-BOUND feasibility model (`opCostWorstCase = intercept + Σ marginMax`,
  `marginMax ≥ marginMean`) gated against `OP_BUDGET − SAFETY_MARGIN`. ⇒ any DP-accepted chunk has REAL
  worst-case op `< OP_BUDGET` **by construction** (A1: the DP cannot propose a budget-buster). Then
  `compileVerify` (deployed `compileFileBytecode` + real BCH-2026 VM at all-bits-set inputs) measures
  every chunk's ACTUAL bytes + worst-case op and `plan()` throws if any exceeds the *true* consensus
  budget; `localBoundarySearch` hill-climbs boundaries ±k in REAL bytes to a real-bytes local optimum.
- **BN254 miller driver:** `bn254_faithful_plan.mjs` (`+ bn254_costvec_deployed.json`, the deployed
  per-class marginal model — supersedes the RAW-compile `bn254_costvec_v3.json` that under-counted real
  op ~40% = a forgery-class hazard). Result: **195,306 B / 21 chunks**, max real worst-op 8,010,157
  (slack 22,643), 0 byte mismatch + 0 over-budget on fresh partitions.
- **Portable external seam:** `bn254_adapter.mjs` takes `LEANBCH_BN254_BUILD_ROOT=/path/to/verifier.cash/build`
  (or convenience-discovers a sibling `../verifier.cash/build`) and validates the generator, compiler,
  libauth, and lazy-library layout before any real compile. The interval-DP core is protocol-agnostic;
  this adapter remains **BN254 Miller-specific**, not an FRI/STARK verifier or a general curve driver.
- **Cost profile — this one COMPILES (not the ms analytic tool):** ~4 min / ~360 real compiles to produce
  + verify a full plan (still ~15× faster than the ~1 hr blind greedy recompile search, and it emits a
  real-bytes report + A1 certificate the blind search never does). Gate: `test/chunkplan.mjs` (self-test
  7/7 + byte-fidelity fresh-partition differential on the real VM; `CHUNKPLAN_SKIP_COMPILE=1` = pure-only).

## 7. Floor-provers — `LeanBCH/Opt/{NlcsFloor,MovementFloor,Floor}.lean` ★ THE MOAT
Machine-checked LOWER BOUNDS on optimization — competitors cannot prove these. Use when a floor "feels"
reached: PROVE the bound instead of asserting it (per the user's doctrine, "floor is defended" is reliably wrong until proven).
- `NlcsFloor.lean` — `movement_lower_bound_nlcs`: `#move-ops ≥ n − LCS(entry,exit)` (the TIGHT per-boundary stack-movement floor — quantifies how much shuffle glue is irreducible).
- `MovementFloor.lean` — `movement_lower_bound` (disjoint-inverted-pairs). `Floor.lean` — `copy_floor` (fanout k ⇒ ≥k−1 dups).

## 8. Op-cost measurement (node harness) — `optimizer/cost.mjs` ★ USE THIS, don't re-implement
The fast measurement loop for the crown work (real libauth BCH-2026 VM; the in-Lean twin is §3's `evalCost`).
- `measureRun(locking, unlocking)` → `{opCost, arith, base(=instr×100), push, instr, …}`.
- `decompose(r)` → `{arithPct, basePct, pushPct}` (arith / shuffle-glue / push split).
- `classifyBound(unlockBytes, opCost)` → op-pad-bound (bytes≈op-cost/800, lever=op-cost) vs code/witness-bound (lever=bytes).
- `measureBody(d, arity, id)` / `measureAllBodies` → per-subroutine op-cost.

## 9. Conformance / differential harness — the VALIDATED trust seam  (`conformance/`)
How we know the model matches reality. This is what makes LeanBCH a *reference oracle*, not just a model.
- `vmbconf` exe (`conformance/Runner.lean`, `lake build vmbconf`) + `conformance/run.mjs <corpusDir> <family…>` — streams the official BCH-2026 vmb_test corpus (standard + nonstandard + invalid) through the VM; emits PASS / REJECTED-VALID / ACCEPTED-INVALID + standardness tallies.
- `conformance/cost/` — the **op-cost differential vs @bitauth/libauth 3.1.0-next.8**: `gen.mjs` runs libauth on **26** battery scripts → `vectors.lean.txt` → `LeanBCH/Validation/CostDifferential.lean` #eval-guards every one of the 5 metrics (any drift = build failure).
- `conformance/RESULTS.md` — the honest results + scope boundaries (signature families oracle-bounded; codesep edges open).

## 10. Trust / necessity / health tooling  (`Meta/`, `tools/`)
- `Meta/Headlines.lean` (the declared headline theorems) + `Meta/Necessity.lean` (`lake build Meta`) → `Meta/necessity.json`: transitive proof-term closure, LOAD-BEARING vs REFERENCE per module, axiom footprint. Closure is diff-gated (a legal refactor never changes what's load-bearing).
- `tools/foldgen/foldgen.py` — regenerates the fold table (`--check LeanBCH/Opt/FoldTable.lean` = byte-identity gate; the committed table IS generator output, no hand-edits).
- `tools/health/map.mjs` → `REPORT.md`+`index.json` (module DAG, orphans, decl index, escape-hatch scan, **the Opt→VM interface lint**). `tools/health/katcount.mjs` — KAT-conservation gate (`>= baseline`) + vacuity lint.
- `tools/manifest/gen.mjs` → `TRUST_MANIFEST.md` (the 3 tiers, computed from necessity.json + health index).
- `tools/opt-ci/verify.sh` — the **6-gate CI** (build · 0-sorry · axiom hygiene · fold-table reproducibility · necessity+KAT+interface closure · health map). Run before any commit to main.

## 11. Reproduced BN254 build env (external — measure against the REAL crown)
Not in this repo, but stood up + working (the enabler for crown research):
- Configure the portable adapter with `LEANBCH_BN254_BUILD_ROOT=/path/to/verifier.cash/build`; absent
  that setting, it only convenience-discovers a sibling `../verifier.cash/build`. The compatible build
  must contain `chunked/pairing/{gen_miller_residue,_millermath}.mjs`, its `@bitauth/libauth` build,
  and `singleton/bn254/lib/lazy/Bn254Lazy.cash`.
- The current local reproduction is `/home/toorik/Projects/verifier.cash/build/chunked/pairing/` —
  mr-zwets's full BN254 chunked-residue build (`gen_miller[_residue].mjs`, `build_vectors.mjs`,
  `_millermath.mjs`), compiled via the cashc RESCHEDULING FORK.
- `/tmp/cashc-resched/` — the cashc fork with `rescheduleStacks` (mr-zwets/cashscript@compiler-optimizations), linked as `groth16_cashscript/node_modules/cashc`.
- Deployed verifier vectors: `git -C /home/toorik/Projects/verifier.cash/harness show 099157d:src/bch/groth16-chunked-covenant-residue-vectors.json` (36 chunks / 274,607 B — the current floor). Sources: `mr-zwets/{groth16_cashscript,zk-verifier-bench}` (public).

---

## Operational rules (MEASURED — the non-obvious part)
- **Measure op-cost via `cost.mjs` (measureRun+decompose) or in-Lean `evalCost`.** Don't hand-roll it.
- **cse/fold = byte-golf: they RAISE op-cost** (cse factors code into OP_INVOKE). On OP-PAD-BOUND chunks (bytes=op-cost/800) that's *illusory* — a byte cut that raises op-cost costs bytes back in padding. cse/fold only help CODE/WITNESS-bound chunks. **`classifyBound` first.**
- **move-arrange = op-cost lever**, but same DAG-reschedule class as cashc's `rescheduleStacks` — measured **not** to beat it on an already-rescheduled build.
- **Op-pad vs code-bound decides the lever.** Deployed BN254 verifier ≈ 86% op-pad / 14% code-bound.
- **Covenant chunks: never optimize in place** — the prologue hash-commits the body; changing it breaks the commitment (unspendable/forgeable). The covenant dialect refuses by design.
- **Floor-provers are the differentiator** — PROVE the lower bound (NlcsFloor), don't assert it.
- **Soundness is the hard gate (A1):** 1 forgery ⇒ score 0. Any size win that removes a check is disqualified.
- **Re-chunking (choosing chunk boundaries): use `chunkplan.mjs`, don't blind-greedy-recompile.** Its DP
  feasibility gate is a per-class UPPER BOUND (never an under-count), so it is A1-safe *by construction*,
  and it REPORTS compile-verified real bytes (not a model number). It compiles (minutes / ~360 compiles),
  so budget the wall-clock — but it is ~15× faster than the blind search and ships an A1 certificate.
  NEVER feed a re-chunk feasibility gate an additive per-op SUM measured in isolation: `rescheduleStacks`
  optimizes ACROSS the chunk, so a naive sum UNDER-counts real chunk op ~40% ⇒ a budget-buster (A1) slips
  through. Extract per-class marginals on the DEPLOYED (rescheduled) compile.
- **The VM model is itself a competitive tool:** `evalCost`/`verifyInput` give an *independent, machine-checked* second opinion on any chunk's op-cost + consensus-fit — a cross-check competitors relying only on libauth don't have.
- **Speed profile — LeanBCH is fast at PROVING, slow at EXECUTING; pick the cheapest sufficient check.** Its edge is kernel proof-checking (`lake build` a floor/bound theorem = seconds), exact cost-model reasoning, and `evalCost`/`measureRun` on an ISOLATED op (seconds). It is NOT a fast executor: running a full high-op-cost chunk (millions of ops) through `verifyInput`/`runExt` in the Lean kernel is *slower* than libauth's compiled JS. So to confirm soundness, prefer the mathematically-sufficient cheap check — confirm the cost model on the isolated `fp12Sqr`/`mul034` body + PROVE the magnitude bound (vertex-enum / floor-prover) — over kernel-executing whole chunks. Exhaustive ≠ slow. Use libauth (`cost.mjs`) to actually RUN a big chunk; use LeanBCH to PROVE or to cross-check the model on a small op.
- **Seeding agents:** subagents inherit none of this — put a `TOOLS.md` pointer + the specific tools AND their cost profile (above) in the agent prompt, or they'll re-run the same harness the build came from and reach for the slowest maximal check.
