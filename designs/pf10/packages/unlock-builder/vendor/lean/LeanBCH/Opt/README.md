# LeanBCH.Opt

**A Lean 4 framework for building *verified*, size-optimizing recompilers for stack virtual machines** — with machine-checked semantics-preservation **and** size lower-bound proofs. Lean 4 core only, **no mathlib**.

Extracted from the *verifier.cash* singleton-Groth16 project, where it drives and certifies a byte-recompiler that shrinks a general BN254 pairing verifier ~54% (12,351 → 5,695 B) while *proving* the transform can never change what the program computes.

## The idea — refinement

Every block has a high-level **meaning** (a data-flow DAG) and a low-level **bytecode** (stack ops). The keystone theorem says running the bytecode yields exactly the meaning:

```
                denote
     block ───────────────▶ result          ← meaning (DAG of ops)
       │                       ▲
  emit │ (schedule)            │  = ?  ◀── proven EQUAL, ∀ block, ∀ valid schedule
       ▼                       │
    bytecode ──────────────▶ result          ← execution (stack VM)
                run

   schedule_refines : run (emit block) = denote block
```

So an aggressive size-optimizer can be trusted: it provably preserves meaning on **all** inputs, not sampled ones. This is CompCert's approach, applied to stack-machine bytecode.

## What's proven

All theorems are **0-sorry**, axioms `[propext, Quot.sound]` (+ core `Classical.choice` where the standard library's decidability API needs it — never `sorryAx`, `native_decide`, or custom axioms).

- **stack-VM model** — `run` / `denote`, the `StepOk` simulation primitive (`Basic`, `Dag`, `Simulation`, `StepLemmas`)
- **peephole** + **altstack-passthrough** passes (`Peephole`, `Passthrough`)
- **`schedule_refines`** — *any* valid topo-order schedule is meaning-preserving (the keystone; `Compose`)
- **decompile bridge** `bridge_block` + per-block `end_to_end` (`Decompile`)
- **structured control** — `Prog` / `runProg` big-step semantics for `IF`/`ELSE`/`BEGIN`/`UNTIL`/`VERIFY`, fuel-bounded, depth-neutral loop-invariance (`Control`)
- **move-arrange** `schedule_refines_move_cond` — aggressive last-use-`ROLL` arrange, sound for blocks satisfying a **decidable** predicate `D` (`MoveArrange`, `NoNullHome`)
- **floor lemmas (size lower bounds — unusual):** copy floor, movement floor, and the **tight `n−LCS`** movement floor (`Floor`, `MovementFloor`, `NlcsFloor`) — prove a program *cannot* be scheduled below a bound, i.e. when you've hit bedrock.

## Fold-completeness (verified)

Beyond the curated hand-written peephole set, the library ships a **complete,
machine-generated fold table** (`LeanBCH.Opt.FoldTable`): **2,114 theorems** — 1,700
unconditional `Correct src dst` + 414 depth-guarded `run` equalities — that is
**window-complete** over the BCH2026 stack-shuffle algebra. It contains *every* sound
fold whose source is ≤ 4 ops (`PICK`/`ROLL` index ≤ 6), each an individually
machine-checked theorem (0-sorry, axioms `[propext]`).

- **Decidable stack effect, no SMT.** Equivalence is decided by comparing each
  sequence's *effect* — the finite tuple, over all initial depths, of its output stack
  (a symbolic permutation/selection) or underflow. Two sequences are equal on the
  shuffle algebra **iff their effects match**, a decidable finite check. This is the key
  differentiator from Alive / souper / FORVES, which put an **SMT solver in the trusted
  base**; here the trust base is Lean's kernel checking each emitted `Correct` proof, plus
  a small enumerator whose output the kernel re-verifies.
- **Generated + reproducible.** Produced by [`tools/foldgen`](../../tools/foldgen/) via
  `python3 tools/foldgen/foldgen.py > LeanBCH/Opt/FoldTable.lean`. The generator is
  deterministic (byte-identical across runs); `tools/opt-ci/verify.sh` step 4 re-runs it and
  diffs against the checked-in table, so the committed file is provably exactly the
  generator output.
- **Relationship to `Peephole.lean`.** `Peephole.lean` is the **curated** hand-written
  set (the 17 + 2 folds that retire the recompiler's differential-test lines, kept as-is).
  `FoldTable.lean` is the **generated remainder** of the complete window set: the generator
  *validates* that it reproduces every curated `Peephole` fold, then emits everything else
  (excluding those curated folds to avoid duplication, and the `ROLL 0` no-op already
  covered by curated `roll0_nop`). Together `Peephole ∪ FoldTable` is the complete set of
  sound folds in the window.

## Conformance — model ↔ real VM

The BCH-2026 VM this optimizer targets is validated against the reference implementation at three seams (see [`conformance/RESULTS.md`](../../conformance/RESULTS.md)):
- **`vmb_test` corpus** — the compiled runner (`conformance/Runner.lean` → the `vmbconf` exe, driven by `conformance/run.mjs`) streams the official BCH-2026 vmb vectors through `verifyInput`; every accept/reject is checked, and the VM-limit boundary families classify 100%.
- **op-cost differential** — the five consensus cost metrics are pinned to `@bitauth/libauth` 3.1.0-next.8 by a **build-time** differential (`conformance/cost/`, enforced by `LeanBCH.VM.CostDifferential` — a wrong constant fails `lake build`).
- **byte-exact KATs** — the sighash serializer, transaction encoders, and native SHA-256/RIPEMD-160 are cross-checked byte-for-byte against pinned libauth output via build-time `#eval`/`guard` witnesses (`Tx.Sighash`, `Tx.Encoding`, `Crypto`, `VM.Extended`).

The `tools/opt-ci/verify.sh` gate enforces build + zero-`sorry` + axiom hygiene + fold-table reproducibility.

## Structure — CORE ⟂ TARGET

The library is organized along a durable seam between a reusable, value-generic
(`α`-opaque) **CORE** proof framework and a concrete BCH-2026 **TARGET**. The seam
is realized as two *umbrella* modules that classify the flat proof modules (no
physical directory reorg — every module keeps its path). Importing the target
transitively pulls in the core, so `import LeanBCH.Opt` still builds everything.
See [`LeanBCH.Opt/MANIFEST.md`](LeanBCH.Opt/MANIFEST.md) for the full classification.

**`LeanBCH.Opt.Core`** — reusable across any stack VM; no byte-level wire encoding,
no structured-control opcode semantics:

```
Basic Dag Scheduler Simulation StepLemmas   — the generic stack-VM model + IR
Peephole FoldTable Passthrough Compose      — verified transforms + generated fold table
MoveArrange NoNullHome                       — the move-arrange capstone
Floor MovementFloor NlcsFloor                — size lower-bound proofs
```

**`LeanBCH.Opt.Targets.CashVM`** — the BCH-2026 instantiation; the clean *leaves*
of the module DAG (only `Control` imports `Decompile`; no Core module imports
either):

```
Decompile Control                           — bytecode↔IR bridge + structured control
conformance/                                — vmb corpus runner + libauth cost differential
```

**Residual coupling** (deliberately in Core): `Basic`'s concrete `Op` inductive +
`step` semantics is BCH-shaped, but it is the shared, value-opaque VM *model*
every module transitively needs (`Basic` is the DAG root). Extracting it would
require parameterizing `step` over the op set — a deep typeclass refactor
touching every constructor-matching proof — so it stays in Core, flagged as the
single Core-resident coupling a port re-models.

## Build

```
lake build          # 0-sorry
```

## Use

```lean
import LeanBCH.Opt                    -- everything (root = Targets.CashVM + Core)
-- or, along the seam:
import LeanBCH.Opt.Core               -- just the reusable α-generic framework
import LeanBCH.Opt.Targets.CashVM     -- Core + the BCH-2026 opcode instantiation
```

### Retargeting to your own stack VM

The core is generic over the value type `α` (verifier-agnostic). To port to a
different stack VM:

1. `import LeanBCH.Opt.Core` — gives you `run`/`denote`, `StepOk`, the peephole/
   passthrough calculus, `schedule_refines`, `schedule_refines_move_cond`, and
   the movement/floor lower-bound subtree.
2. Re-model the `Op` inductive + `step` semantics for your VM's opcode set (the
   single documented Core-resident coupling — `Basic`).
3. Supply your own encoding + control analogues of `Decompile` (byte wire
   encoding + decompile bridge) and `Control` (structured control semantics),
   mirroring `LeanBCH.Opt.Targets.CashVM`.
4. Optionally differential-test your opcode model against your reference VM, as
   `conformance/` does against libauth BCH2026.

## Status — v0.1

This is the verified project lifted into a standalone library and renamed (`Recompiler → LeanBCH.Opt`). The core is **generic over `α`** with zero coupling to any specific verifier, and is now separated from the BCH-2026 target along the `LeanBCH.Opt.Core` ⟂ `LeanBCH.Opt.Targets.CashVM` seam (above).

**Roadmap:**
1. ✅ Decouple `LeanBCH.Opt.Core` (the reusable framework) from `LeanBCH.Opt.Targets.CashVM` (the opcode instantiation + decompile bridge + conformance harness) — done via the documented umbrella-import seam ([`MANIFEST.md`](LeanBCH.Opt/MANIFEST.md)).
2. ✅ Extend conformance to the control opcodes — done (`IF`/`NOTIF`/`ELSE`/`ENDIF`/`BEGIN`/`UNTIL`/`VERIFY`, 1,100 cases, mutation-gated in `verify.sh`).
3. Tighten the flat-bytecode ↔ structured-control bridge.
4. API docs + a second worked target as a template.

**Honest boundaries:** control flow is verified on a structured `Prog` layer, and that structured layer's semantics are now differential-tested against the real VM (straight-line + control, mutation-gated in CI) — but the **flat-bytecode ↔ structured-control bridge remains a disclosed boundary** (the emitted flat bytecode is related to the `Prog`/`Op`-list model by the JS round-trip gate, not yet by a machine-checked parser/emitter refinement); the move-arrange is `D`-conditional.

## License

TBD.
