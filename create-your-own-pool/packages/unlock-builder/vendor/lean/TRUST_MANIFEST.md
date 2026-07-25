# LeanBCH — TRUST MANIFEST

> **GENERATED** by `tools/manifest/gen.mjs` from `Meta/necessity.json` (necessity analyzer) +
> `tools/health/index.json` (health map) + `tools/health/katcount.mjs` (KAT counter). **DO NOT EDIT.**
> Regenerate: `node tools/manifest/gen.mjs`.

What may a skeptic take on trust, and on what basis? LeanBCH is an *executable* model, so its claims
fall in exactly three tiers. Everything below is **computed** from the kernel-checked proof terms —
the load-bearing set is not asserted, it is the transitive proof-term closure of the headlines in
`Meta/Headlines.lean`. A legal refactor never changes it (CI gate: `Meta/necessity.json` byte-stable).

**At a glance:** 2523 declarations are load-bearing across 65 modules; the entire
proven base rests on exactly these kernel axioms: `Classical.choice`, `Quot.sound`, `propext`
(`propext` + `Quot.sound` + `Classical.choice` — the standard classical Lean base; **no** `sorryAx`,
`native_decide`, or `ofReduceBool`). Independently re-checkable: `#print axioms <headline>`.

## Tier 1 — PROVEN (machine-checked; kernel-verified)

Each theorem below is a promised deliverable, verified by the Lean kernel. The axiom column is the
theorem's *own* footprint (computed per-headline). Any theorem renamed/removed ⇒ CI fails immediately.

### Consensus VM — self-hardening + cost certificate

| Theorem | Axiom footprint |
| --- | --- |
| `VM.runExt_WF_final` | `Classical.choice`, `Quot.sound`, `propext` |
| `VM.runScript_fuel_suffices_final` | `Quot.sound`, `propext` |
| `VM.verifyInput_cost_within_budget` | `Quot.sound`, `propext` |

### Optimizer — semantics-preserving size reduction

| Theorem | Axiom footprint |
| --- | --- |
| `Opt.schedule_refines` | `Classical.choice`, `Quot.sound`, `propext` |
| `Opt.schedule_refines_move_cond` | `Classical.choice`, `Quot.sound`, `propext` |
| `Opt.whole_program_end_to_end` | `Classical.choice`, `Quot.sound`, `propext` |
| `Opt.bridge_block` | `Classical.choice`, `Quot.sound`, `propext` |
| `Opt.decompile_end_to_end` | `Classical.choice`, `Quot.sound`, `propext` |
| `Opt.emit_ops_typed` | `Quot.sound`, `propext` |

### Optimizer — size FLOORS + INVOKE/CSE soundness

| Theorem | Axiom footprint |
| --- | --- |
| `Opt.NlcsFloor.movement_lower_bound_nlcs` | `Classical.choice`, `Quot.sound`, `propext` |
| `Opt.Providers.invoke_const_provider` | `propext` |
| `Opt.InvokeCSE.invoke_cse` | `Quot.sound`, `propext` |

### Rewrite catalogs — sampled (rename/removal caught)

| Theorem | Axiom footprint |
| --- | --- |
| `Opt.FoldTable.u_DUP_SWAP__DUP` | `propext` |
| `Opt.FoldTable.u_2PICK_NIP__DROP_OVER` | `propext` |
| `Opt.FoldTable.c_4PICK_TWODROP__DROP_k5` | `propext` |
| `Opt.FoldTable.c_TWODUP_TWODROP__EMPTY_k2` | `propext` |
| `Opt.over_over` | `propext` |
| `Opt.roll2_rot` | `propext` |

### Real-VM optimizer bridge — capstones (C1)

| Theorem | Axiom footprint |
| --- | --- |
| `Opt.PushButton.push_button_arith` | `Classical.choice`, `Quot.sound`, `propext` |
| `Opt.PushButtonFull.push_button` | `Classical.choice`, `Quot.sound`, `propext` |
| `Opt.PushButtonBytes.push_button_arith_bytes` | `Classical.choice`, `Quot.sound`, `propext` |
| `Opt.OriginalBytes.push_button_arith_bytes_symmetric` | `Classical.choice`, `Quot.sound`, `propext` |

> **Honest scope of the "real-VM bridge" capstones (red-team):** of the C1 group, only
> `OriginalBytes.push_button_arith_bytes_symmetric` runs BOTH the original and the optimized
> bytecode through the genuine consensus VM (`parse` → `VM.run` → `stepInstr`) and proves they
> agree. `PushButton.push_button_arith` / `PushButtonBytes.push_button_arith_bytes` run the
> OPTIMIZED side on the real VM but the ORIGINAL side on the abstract `Opt.run` machine (sound,
> because both are gated by an acceptance hypothesis — but not "both on real hardware"). And
> `schedule_refines` / `whole_program_end_to_end` / `decompile_end_to_end` / `emit_ops_typed` are
> proven over the ABSTRACT value machine (α-generic), not `stepInstr`. All are non-vacuous (they
> fire on a concrete block: 6+2→8 verified) and axiom-clean; the framing above is the honest split.

### (ungrouped headlines — add to a group in tools/manifest/gen.mjs)

- `Opt.TowerRankCompose.fp12_leaves_ge` — `Quot.sound`, `propext`
- `Opt.OpMulFloor.opMul_opCost_ge` — `Quot.sound`, `propext`
- `Opt.OpMulFloor.opMul_bn254_opCost_ge` — `Classical.choice`, `Quot.sound`, `propext`
- `Opt.MovementFloorDag.movement_lower_bound_dag` — `Classical.choice`, `Quot.sound`, `propext`
- `Opt.Fp6Rank.fp6_rank_ge_five` — `Classical.choice`, `Quot.sound`, `propext`
- `Opt.Fp6Rank.f7_fp6_rank_ge_five` — `Classical.choice`, `Quot.sound`, `propext`
- `Opt.Fp12TowerFloorBLS.gFp12Bls_opCost_floor` — `Classical.choice`, `Quot.sound`, `propext`
- `Opt.Fp12TowerFloorBLS.fp12Mul_bls_opCost_floor` — `Quot.sound`, `propext`
- `Opt.Fp12TowerFloorBLS.fp12Mul_bls_fp_mult_floor` — `Quot.sound`, `propext`
- `Opt.Fp12TowerFloor.gFp12_opCost_floor` — `Classical.choice`, `Quot.sound`, `propext`
- `Opt.Fp12TowerFloor.fp12Mul_opCost_floor` — `Quot.sound`, `propext`
- `Opt.Fp12TowerFloor.fp12Mul_fp_mult_floor` — `Quot.sound`, `propext`
- `Opt.Fp12OpCostFloor.fp2_opCost_floor_bn254` — `Classical.choice`, `Quot.sound`, `propext`
- `Opt.Fp12OpCostFloor.fp2_opCost_floor` — `Quot.sound`, `propext`
- `Opt.Fp12OpCostFloor.fp2_arith_floor_bn254` — `Classical.choice`, `Quot.sound`, `propext`
- `Opt.DegreeExtRank.int_degExt_two_min_mults` — `Quot.sound`, `propext`
- `Opt.DegreeExtRank.fp12_over_fp6_rank_ge_three` — `Quot.sound`, `propext`
- `Opt.BilinearRank.int_fp2_min_mults` — `Quot.sound`, `propext`
- `Opt.BilinearRank.CRing.fp2_rank_ge_three` — `Quot.sound`, `propext`

## Tier 2 — VALIDATED (modeled + checked, NOT proven)

These surfaces are trusted by *external agreement*, not by a Lean proof — the same status CompCert
gives its `Valex` re-checker and EELS/KEVM give "the spec is the reference implementation".

**Executable model surfaces** (definitions only — no in-tree proof; exercised by the conformance runner
and the libauth differential):

| Module | defs | Validated by |
| --- | --: | --- |
| `Tx.Wire` | 42 | round-trip vs the vmb corpus + `conformance/Runner` |

**The `LeanBCH.Validation.*` layer** (5 modules) — known-answer tests extracted out of the
model files so the model reads as pure semantics; each `#eval`/`#guard`/`example` still executes under
`lake build LeanBCHValidation`, and the KAT-conservation gate (`tools/health/katcount.mjs`) proves none
was dropped in the move. Includes the libauth cost differential (`Validation.CostDifferential`).

**The validation harness itself** (trusted expected-values — the single differential "trust seam"):

- **@bitauth/libauth 3.1.0-next.8** — the reference JS VM; LeanBCH's numeric cost pins are diffed
  against it (not proven equal). Pinned dependency.
- **The official `vmb_test` conformance corpus** — streamed through the VM by `conformance/Runner.lean`
  (`lake build vmbconf <corpus-dir>`). **External**: passed as a path arg, NOT copied into or pinned
  in this repo (so the RESULTS.md pass-counts are reproduced against your own corpus checkout, not
  gated in CI). The **signature op-cost tier** (`signatureCheckCount`×26000, sig signing-serialization
  hash-iters) is NOT numerically validated: the cost-differential vectors are all `sc=0`, and corpus
  sig families NULLFAIL under the reject-oracle before any cost is compared — so that tier is
  soundness-safe (over-billing never wrong-accepts) but currently **unvalidated**, not "checked elsewhere".
- **327 build-time KAT checks** (`#eval`/`#guard`/`example`) across `LeanBCH/**/*.lean` —
  the exact current count used by the KAT-conservation gate (`tools/health/katcount.mjs`), distinct
  from the health map’s prose `claims` census.

**Proven, but not headline-gated** (`REFERENCE-PROOF`: real theorems, not in any headline's closure —
kept on purpose; a silent break is *not* caught by the axiom gate):

| Module | theorems | Why it is not a headline |
| --- | --: | --- |
| `Cost.Spine` | 11 | reference cost-spine lemmas, superseded by the load-bearing cost model |
| `Opt.AcceptExample` | 5 | a worked end-to-end witness on one real rewrite (demonstration, not a general claim) |
| `Opt.EmitConcreteHash` | 18 | deferred hash capstone (probing SHA-256 forces kernel reduction; `native_decide` forbidden) |
| `Opt.Passthrough` | 27 | abstract PASS-1 justification; the composition re-derives it inline (in `schedule_refines`) |
| `VM.Standard` | 77 | relay-policy (standardness) ≠ consensus; a separate proven model, validated by conformance |
| `Validation.VM.MultiSigBilling` | 2 | proven; complementary to the headline set |

## Tier 3 — ASSUMED (opaque oracle; the ONLY unproven trust input)

- **secp256k1 signature verification** — `LeanBCH/Oracle.lean` `structure Secp256k1` (the whole file,
  ~40 lines; re-exported by `LeanBCH.Crypto` so importers are unchanged). An EXPLICIT parameter
  structure, **not** an axiom: the VM's `OP_CHECKSIG*` arm receives a `Secp256k1` value and calls it.
  It feeds **only** the accept/reject decision and **never any cost metric** — so no cost/limit
  theorem depends on it. No honest implementation is provided in-Lean (consensus verification lives
  in libsecp256k1). This one file is the single point a reader must take on faith.

## Code vs proof (the executable-model ↔ proof seam)

Each module's declarations split into DEFS (the executable model — what *runs*) and THEOREMS (the
proof — what is *guaranteed*). This is CompCert's `Pass.v`/`Passproof.v` legibility, but computed
from the kernel rather than asserted by filename. Rolled up by layer:

| Layer | modules | defs (code) | theorems (proof) |
| --- | --: | --: | --: |
| VM (consensus semantics) | 11 | 725 | 684 |
| Optimizer | 44 | 3046 | 4197 |
| Cost model | 5 | 40 | 66 |
| Tx / sighash / encoding | 4 | 209 | 45 |
| Validation (KATs) | 6 | 30 | 2 |
| Oracle (assumed) | 1 | 12 | 3 |
| (core: Number/Opcode/Crypto/…) | 6 | 284 | 180 |

The optimizer is the CompCert-style layer — a *pass* (code) paired with its *proof* — kept in-tree as
its own build target (not a separate package: the `LeanBCH.Opt.*` public API is frozen for
verifier.cash/stackcert, and lake can't share that namespace across packages). Its VM boundary is
lint-enforced: `LeanBCH.Opt.*` reaches the VM through 5 modules only. Per Opt module:

| Optimizer module | defs (pass) | theorems (proof) |
| --- | --: | --: |
| `Opt.FoldTable` | 2116 | 2134 |
| `Opt.Compose` | 54 | 219 |
| `Opt.Control` | 64 | 106 |
| `Opt.MoveArrange` | 47 | 109 |
| `Opt.Scheduler` | 88 | 52 |
| `Opt.Decompile` | 35 | 92 |
| `Opt.OpFaithful` | 22 | 103 |
| `Opt.BilinearRankFloor` | 51 | 68 |
| `Opt.Dag` | 74 | 43 |
| `Opt.StepLemmas` | 20 | 91 |
| `Opt.MovementFloorDag` | 43 | 67 |
| `Opt.EmitConcreteExt` | 22 | 87 |
| … (32 more Opt modules) | | |

## How a skeptic checks each tier

1. **PROVEN** — `bash tools/opt-ci/verify.sh` (builds all targets, 0 `sorry`, axiom gate over every
   headline, fold-table reproducible, closure byte-stable). Spot-check any theorem: `#print axioms <name>`.
2. **VALIDATED** — `lake build vmbconf && ./…/vmbconf <corpus>` (conformance) and the libauth cost
   differential (`LeanBCH/Validation/CostDifferential.lean`). Disagreement is a bug in *this* model.
3. **ASSUMED** — read one structure in `Oracle.lean`; confirm no cost metric reads its result.

---
_Generated from 65 load-bearing + 6 reference-proof + 6 validated-executable modules; 41 headlines._
