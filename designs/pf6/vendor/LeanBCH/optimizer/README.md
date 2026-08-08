# LeanBCH optimizer — a verified, dialect-pluggable BCH Script bytecode optimizer

The runnable companion to the `LeanBCH.Opt` proofs: hand it BCH Script bytecode, get back a
**smaller, semantically-equivalent** program plus a **trust label** saying what is machine-checked
vs differential-gated. Every transform it applies is discharged by a Lean theorem in the
`LeanBCH.Opt` library; nothing is a heuristic byte-golf.

## Why it exists
The transforms (fold / CSE / move-arrange) were proven once in Lean and productized as passes — but
the passes were hardwired to one bytecode shape (one cashc function-framing). This tool extracts the
**format coupling** into a thin **dialect** layer so the same proven optimizer runs on *any* BCH
verifier, not just one. See `../TRUST_MANIFEST.md` for the LeanBCH trust tiers this mirrors.

## Architecture — a clean IR ⟂ dialect seam
```
bytecode ──[dialect.parse]──▶ IR bundle ──[passes: fold/cse/move-arrange]──▶ IR ──[dialect.emit]──▶ bytecode
             (ORACLE,                (format-AGNOSTIC;          (PROVEN, format-agnostic)   (CODEC,
          round-trip-gated)       passes never see bytes)                                proven round-trip)
```
- **`ir.mjs`** — the canonical, dialect-independent IR (the frozen contract). Bundle = `{bodies, main,
  arity, shell}`; `shell` is a dialect-opaque carrier (def framing, wrapper) the passes never touch.
- **`dialect/`** — the ONLY format-coupled code. `dialect.mjs` is the interface; `cashc-standard.mjs`
  is the first adapter (the `[body][id][OP_DEFINE]` framing). Adding a bytecode shape = a new adapter,
  not a pass change.
- **`passes/`** — `cse.mjs`, `fold.mjs` (+ move-arrange, forthcoming). Import only `core/*`; never
  `dialect/*`. They route every minted invoke/define through the dialect via `core/program.mjs`.
- **`core/`** — the shared front-end internals (`asm` parse/serialize, `decompile` the IR, `program`
  dissect/rebuild/probe), format-coupling delegated to the active dialect.
- **`optimize.mjs`** — the driver: alternates cse + fold to a combined fixpoint. No search.

## Trust story (mirrors LeanBCH TRUST_MANIFEST)
- **PROVEN** (format-agnostic, Lean, 0-sorry): the IR→IR transforms — `schedule_refines`(+`_move_cond`),
  `FoldTable` (L≤4 window-complete), `InvokeCSE.invoke_cse`, `Providers.invoke_const_provider` — and the
  emit codec `Codec.parse_encode`.
- **VALIDATED** (per-run, differential-gated): round-trip byte-exact + per-body differential on random
  Fp + E2E accept/reject on the real BCH-2026 VM (`--gate`).
- **ORACLE** (the parse): a dialect's `parseDefs` is validated per-run by the byte-exact round-trip;
  `cashc-standard`'s parse is round-trip-certified (and kept VM-free + total, so it is Lean-upgradeable
  à la `Codec.parse_encode`). Output trust = min(parse tier, transform tier).

## Usage
```
npm install                                  # @bitauth/libauth (pinned)
node optimize.mjs <in.hex> <out.hex>         # optimize
node test/byte-identity.mjs                  # public regression (toy fixture)
LEANBCH_CROWN_DIR=<dir> node test/byte-identity.mjs   # + private crown reduction (4818->4346)
node chunkplan.mjs                           # re-chunk planner self-test (pure, ~20ms, 7/7)
node test/chunkplan.mjs                      # planner regression gate (pure + byte-fidelity fresh-partition, real VM)
LEANBCH_BN254_BUILD_ROOT=/path/to/verifier.cash/build node test/chunkplan.mjs
LEANBCH_BN254_BUILD_ROOT=/path/to/verifier.cash/build node bn254_faithful_plan.mjs [--quick]
```
The public regression optimizes a generic reusable-functions toy (`test/fixtures/{Lib,Toy}.cash`,
129→126 B) to a byte-identical committed result — proving determinism + a behavior-preserving seam.

## Re-chunk planner — `chunkplan.mjs` (FAITHFUL, A1-safe, near-optimal)
A separate tool from the in-place optimizer above: given a chunked BCH covenant verifier, it chooses a
**partition** (the chunk boundaries) that minimizes total on-chain bytes, and REPORTS **compile-verified
real bytes** — never a model prediction. It is a *planner* (it picks boundaries + measures), not an
in-place covenant editor, so it does not touch the hash-committed body (see Non-goals).

**Hybrid workflow — safe DP → compile-verify → local search:**
1. **Safe interval-DP** (`planOptimal`, provably optimal O(n²), brute-force-checked in the self-test).
   It is fed a **two-model split** built from per-op-CLASS marginals measured on the *deployed* compile
   (`cashc rescheduleStacks` ON) via the real BCH-2026 VM: a **MEAN**-marginal predictive model (LSQ
   R²≈1) that ranks candidates by bytes, and a **MAX**-marginal UPPER-BOUND feasibility model
   (`opCostWorstCase = intercept + Σ marginMax`, `marginMax ≥ marginMean` by construction) gated against
   an *effective* budget `OP_BUDGET − SAFETY_MARGIN` (`SAFETY_MARGIN ≥` the max positive LSQ residual +
   headroom). So any chunk the DP accepts has REAL worst-case op `< OP_BUDGET` **by construction** — the
   DP is structurally incapable of proposing a budget-buster (the A1-disqualified vk_x-window merge).
2. **compileVerify** — EVERY chunk of the candidate is compiled with the deployed compiler and driven
   through the real VM at worst-case (all-bits-set) inputs for its **actual** on-chain bytes + worst-case
   op. The reported total is this measured number. `plan()` throws if any real worst-case op exceeds the
   consensus budget (belt-and-suspenders: A1-safe by construction AND confirmed by measurement).
3. **localBoundarySearch** — a bounded hill-climb that shifts each internal boundary ±k, re-measuring
   only the two adjacent chunks (cached), and accepts a move iff it lowers the REAL total AND keeps both
   chunks feasible AND crosses no forced seam — a real-bytes local optimum.

**A1 guarantee:** the DP plans against the shrunk effective budget; the certificate certifies REAL
worst-case op against the *true* consensus budget `8,032,800`. On the BN254 miller stage the committed
plan is **195,306 real compile-verified bytes** (21 chunks), max real worst-op **8,010,157** (slack
22,643); 0 byte mismatch and 0 over-budget across independent fresh partitions.

**Honest speed:** this is *not* the ms analytic tool — it compiles. Producing + compile-verifying +
local-searching a full plan is **minutes and hundreds of real compiles** (~4 min / ~360 compiles on the
348-block miller stage), still ~15× faster than the ~1 hr blind greedy recompile search and, unlike it,
emitting a compile-verified real-bytes report + an A1-by-construction certificate. `test/chunkplan.mjs`
gates this: the pure DP/safe-model self-test (7/7) plus the **byte-fidelity differential** — on a FRESH
partition (real VM), the tool's reported bytes equal an INDEPENDENT recompile (0 mismatch) and every
chunk's real worst-op is `≤` budget (the prior blocker, now a passing regression gate).

**Scope:** built + validated on the miller/residue stage (the dominant 348-block turnkey stage; its op is
magnitude-independent so the committed instance IS its worst case). The architecture is stage-agnostic
(per-class marginals at all-bits-set → compileVerify at all-bits-set); re-extracting the deployed
per-class model for the vk_x / g2check / tail stages is the documented first follow-on.

**External integration boundary:** `bn254_adapter.mjs` resolves a compatible generated build from
`LEANBCH_BN254_BUILD_ROOT` (an absolute or working-directory-relative path to `verifier.cash/build`),
or, for checkout convenience only, from a sibling `../verifier.cash/build`. It validates the Miller
generator, compiler helpers, libauth build, and lazy BN254 library before loading them. The real-VM part
of `test/chunkplan.mjs` skips cleanly when that external build is absent; the pure DP gate still runs.
This removes the workstation-path coupling, but does **not** make the BN254 Miller driver a generic
curve, FRI, or STARK verifier: a new protocol still needs its own adapter, measured cost vector, and
real-VM validation.

## Non-goals (explicit)
- **In-place optimization of a covenant-committed body** (re-threading hash commitments to emit a
  *deployable* optimized chunk *body*) — unsound (it breaks the body-hash commitment); the covenant
  dialect (P3) is therefore **analyze-only**. The re-chunk planner (`chunkplan.mjs`) is compatible with
  this: it only chooses **boundaries** and reports compile-verified bytes of the *unmodified* compiler
  output — it never edits a hash-committed body.
- **The const-derivation passes** (E/inv2/b2/p-pool) — source-level splices in the private `stackcert`
  package, not portable IR passes.
- **New transform proofs** — already proven + format-agnostic; this tool *consumes* them.
- **Stochastic search / annealing** — this is the deterministic, proof-backed rewriter.

## Status
- **P1 ✓:** IR⟂dialect seam; `cse` + `fold` + `move-arrange` all decoupled from format (every minted
  invoke/define routes through the active dialect); runtime dialect injection (`setDialect`); per-body
  op-cost (`measureBody`, bounded VM). Byte-identity proven on the public toy + the private crowns:
  cse+fold **4,346 B**, move-arrange **5,695 B** (`passes/movearrange.mjs --arity a.json`, the op-cost
  lever — cuts executed PICK/ROLL). move-arrange targets the fp-verifier opcode set (decompiler
  coverage) and wants a cached arity for speed — see its header.
- **P2 ✓:** `cost.mjs` (op-cost + op-pad/code bound classification), `manifest.mjs` (3-tier trust report),
  `cli.mjs` (`bch-optimize`, dialect-aware, gated, refuse-to-emit-on-fail).
- **P3 ✓:** `dialect/covenant-wrapped.mjs` — auto-detects a deployed covenant chunk, **refuses in-place
  emit** (the body is hash-committed ⇒ optimizing it is unsound), and classifies op-cost bound-type. On
  the deployed BN254 verifier the tool reports **86% op-pad-bound** (lever: op-cost / move-arrange) **/ 14%
  code-bound** (lever: bytes / fold-cse) — the floor picture, measured.
- **Re-chunk planner ✓ (FAITHFUL + A1-safe, committed):** `chunkplan.mjs` (safe-DP → compileVerify →
  local search; see the section above) + `bn254_faithful_plan.mjs` (BN254 miller driver) +
  `bn254_costvec_deployed.json` (deployed per-class cost model). Reports **compile-verified real bytes**
  (miller stage: **195,306 B / 21 chunks**), **A1-safe by construction** (DP upper-bound feasibility)
  AND by measurement (compileVerify), 0 byte mismatch on fresh partitions. Gated by
  `test/chunkplan.mjs` (self-test 7/7 + byte-fidelity fresh-partition differential on the real VM).

`node cli.mjs <covenant-chunk.hex> --op-cost N --unlock-bytes M` → the analyze-only report (no out.hex).
