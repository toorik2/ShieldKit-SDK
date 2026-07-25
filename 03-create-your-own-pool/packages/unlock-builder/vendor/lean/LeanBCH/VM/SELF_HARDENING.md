# The self-hardening layer — `LeanBCH.VM.Invariants`

> Converting LeanBCH's *differential* trust into *deductive* trust: proving structural
> properties of the verifier itself, so that whole **classes** of bug become
> unprovable-if-present rather than caught vector-by-vector.

## 1. Why this exists (first principles)

`verifyInput : Secp256k1 → Program → Bool` is the artifact everything downstream trusts.
Today that trust rests on three legs of *very different strength*:

| Leg | What it covers | Strength |
|---|---|---|
| **Differential validation** | accept/reject matches libauth on the `vmb_test` corpus | *empirical* — only as good as the corpus; the audit found 5 real bugs the corpus missed |
| **The keystone** (`splice_congr_run`) | the optimizer's block-replacement preserves the run | *proven* `[propext, Quot.sound]` — but only about the optimizer, not the verifier's own guarantees |
| **The oracle boundary** (secp256k1) | signature *correctness* | *trusted by contract* — deliberate, irreducible |

The gap is the first leg. The 2026-07 audit found `OP_CAT`/arithmetic results that skipped
the 10 000-byte gate, a missing memory-slot check, a within-tx double-spend — all
*false-accepts a passing corpus never exercised*. Each was a **missing guard**. The lesson is
structural: **a test suite certifies the inputs it runs; a theorem certifies the inputs it
doesn't.** Self-hardening replaces "we tested that the guard fires" with "the verifier cannot
accept a state in which the guard should have fired" — which closes the *class*, not the case.

This is the highest-leverage investment on the roadmap because it **compounds**: once the
preservation theorems exist, every future opcode added to `stepInstrExt` must *re-establish*
them to typecheck. The proof obligation becomes a permanent, mechanical gate on soundness —
the audit, run automatically, forever.

## 2. What is (and isn't) in scope

Self-hardening proves **internal soundness** — properties provable in Lean with no external
reference: invariant preservation, metering monotonicity, abort soundness, termination,
well-formedness. It does **not** attempt **external conformance** (that our *billed* cost
equals *BCH's* cost) — that stays differential against libauth, the same trust boundary as the
secp256k1 oracle. The distinction matters: internal soundness says *"the verifier is
self-consistent and its guards are complete"*; external conformance says *"self-consistent
about the right rules."* We prove the first; we test the second. Overreaching into the second
without a mechanized BCH reference would be a corner cut in disguise.

## 3. The invariant theory — four axes

### Axis A — Resource safety (the "no guard is missing" guarantee)
Define a **well-formedness** predicate capturing exactly the resource limits a valid execution
must never breach:

```
WF s  :=  (∀ i ∈ s.stack, i.length ≤ maxItemLen)          -- 10 000-byte item cap
        ∧ (∀ i ∈ s.alt,   i.length ≤ maxItemLen)
        ∧ s.stack.length + s.alt.length + s.functionTable.length ≤ maxMemorySlots  -- 1000
        ∧ s.ctrl.length ≤ maxCtrlDepth                     -- 100
```

**Theorem (step preservation).** `WF s → WF (stepMeterExt p crypto s) ∨ (stepMeterExt …).error.isSome`.
Every metered step either preserves well-formedness or aborts. The memory-slot and ctrl-depth
conjuncts fall out *directly* from `stepMeterExt`'s own post-checks (it `setErr`s when either is
exceeded). The item-length conjunct is the deep one: it holds **iff** the `stepInstrExt` wrapper
intercepts every length-growing op (CAT, the arithmetic family, shifts, NUM2BIN…) with a
`length > maxItemLen → setErr` guard — i.e. **the proof of this theorem is a machine-checked
completeness proof of the audit's guard set.** *Closes: the `OP_CAT`/arith-overflow and
memory-slot false-accepts.*

**Theorem (run preservation).** By fuel induction: `WF s → ∀ reachable s', WF s' ∨ s'.error.isSome`.

### Axis B — Metering monotonicity + abort soundness (the "cost is honest" guarantee)
The five metrics are `Nat`-valued and accumulate additively (`s.metrics + kappa s + …`), so:

- **`metrics_mono`**: `s.metrics ≤ (stepMeterExt …).metrics` (componentwise). Cost never
  *decreases* across a step.
- **`stepOpCost_mono`**: `m ≤ m' → stepOpCost m ≤ stepOpCost m'` (the aggregate is a monotone
  linear functional).
- **`abort_permanent`**: once `stepOpCost s.metrics > s.budget`, monotonicity makes it stay
  so — the "withinLimits" budget-abort **cannot be bypassed** by a later step.
- **Corollary (`accept ⇒ within budget`)**: `verifyInput = true` implies the accumulated
  op-cost never exceeded the per-input density budget *at any point* — not just at the final
  post-check. This is the internal-soundness backbone of the fits-BCH claim: acceptance is a
  *certificate of bounded work*. *Closes: the introspection/2ROT under-billing class — an
  under-bill can no longer be masked by a non-monotone meter.*

### Axis C — Termination & totality (the "never hangs, never crashes" guarantee)
- **Totality** is *by construction*: no `partial def`, no `native_decide`, no panics anywhere
  in `stepMeterExt`/`runExt`/`verifyInput`. Post the O(n·log n) `magBytes` fix, no primitive
  is super-linear either. Worth *stating* as a meta-theorem even though the kernel gives it free.
- **Fuel sufficiency**: `runScript` allots `instrs.size + evalFuelSlack` fuel. Theorem: a
  within-budget evaluation reaches a fixpoint (finished or errored) *before* fuel exhaustion —
  so the fuel bound never masks a false result. The `OP_INVOKE` frame-return path is the
  subtle case (bodies aren't counted in `instrs.size`); it is bounded by `maxCtrlDepth` ×
  budget. *Closes: the infinite-loop DoS class at the proof level, complementing the runtime
  budget-abort.*

### Axis D — Error stickiness (the "reject is final" guarantee)
- **`runExt_error_fix`**: `s.error.isSome → runExt p crypto f s = s`. An errored state is a
  fixpoint of the run loop — no state ever *un-rejects*. This underwrites abort soundness (Axis
  B) and the run-preservation induction (Axis A): once any guard fires, the verdict is sealed.

## 4. Build plan (increments — each ships green + axiom-clean)

1. **Order & metering substrate** *(this file's first commit)* — the componentwise `Metrics`
   order (`≤`, refl/trans/antisymm-free preorder), `le_add_right`/`add_le_add`,
   `stepOpCost_mono`, `operationCost_mono`, `metrics_mono` (step level), and Axis D error
   stickiness. The reusable algebra every higher theorem needs.
2. **Axis A, easy half** — ✅ **DONE** (`Invariants.lean`). `WFlen`/`WFmem`/`WF` defs +
   `enforceStepLimits_WFmem` → `stepMeterExt_WFmem` → `runExt_WFmem` (run-level: a `WFmem` start
   stays `WFmem`-or-errored). `WFmem` (memory-slot + ctrl-depth) is **unconditional** — the gate
   `enforceStepLimits` establishes it on every non-errored output. `[propext, Classical.choice, Quot.sound]`.
3. **Axis A, deep half** — ✅ **DONE** (`Invariants.lean`). `runExt_WF_final` (guard-completeness for the
   whole metered run) holds under a SINGLE honest premise: `WFProgram p` (tx well-formedness). The
   `FrozenCore` hypothesis is now **discharged** (`frozenCore_holds` — a real inhabitant, so nothing is
   vacuous): its 4 conjuncts are the audit theorems `frozenCore_core` (all 45 non-excluded `stepInstr`
   arms, incl. hash-output ≤ 32 and `zipBytewise` length proved from scratch), `frozenCore_wrap` (all
   arms leave altstack + stack-tail bounded), `frozenCore_rshiftnum` (via a `decodeDigits` magnitude
   bound + `Int.natAbs_fdiv_le`), `frozenCore_shiftbin` (residual foldr/foldl length preservation).
   **The introspection finding is FULLY RESOLVED**: the
   type-bounded value ops (0xc2/c5/c6/c9/cb/cc) close with NO premise via `bigIntToVmNumber_*_length`;
   the genuinely-unbounded ops (0xc0/c3/c4/c8/ce/d0/d1/d3) close via `introspectIndexed_WFlen_bounded`
   + the matching `WFProgram` conjunct (bounds exactly the 5 unbounded fields — outpoint hash, token
   category/amount, `inputIndex`, in/out counts — mirroring libauth `pushToStack`); the guarded/
   checked ops, INVERT/REVERSEBYTES, DEFINE/INVOKE, all sig ops, CLTV/CSV, CODESEPARATOR are closed
   outright. **Key discovery**: item-length is NOT self-inductive — `OP_DEPTH` pushes
   `ofNum stack.length`, so `WFlen` holds only COUPLED with the memory-slot bound `WFmem`
   (`stack ≤ maxMemorySlots`); hence `runExt_WF_final` threads full `WF`, not `WFlen` alone.
   **Grounded end-to-end**: `decodeProgram_WFProgram` proves `WFProgram` is an INVARIANT of any
   successfully-decoded transaction (the wire reader gives compact-uint-bounded counts `< 2^64`,
   32-byte outpoint hashes, 32-byte token categories, `amount < 2^63`), so `decoded_runExt_WF` chains
   `decodeProgram … = some p → i < 2^64 → WF s → WF (runExt …) ∨ error`: item-length safety traces all
   the way back to "the bytes parsed". The lone surfaced premise `inputIndex < 2^64` is a genuine
   caller bound (`decodeProgram` doesn't validate the input selector; no tx has ≥ 2^64 inputs).
4. **Axis B headline** — ✅ **DONE** (`Invariants.lean`). The `verifyInput ⇒ bounded-work` certificate:
   `enforceStepLimits_bounded` → `stepMeterExt_bounded` → `runExt_bounded` → `runScript_bounded`
   (an accepting metered run ends within its budget — the meter's abort can't be bypassed), the
   `operationCost_consensus_eq` bridge (post-check `operationCost BCH_2026_05_CONSENSUS` = per-step
   `stepOpCost`), and the capstone `verifyInput_cost_within_budget`: **verifyInput accepts ⇒
   accounted op-cost ≤ the density budget `opBudget |unlocking|`**. `[propext, Quot.sound]`.
   *Throughout refinement:* ✅ **DONE** — `runExt_add` (fuel composition) + `runExt_fixed` (halted
   fixpoint) + `runExt_opCost_prefix`/`runExt_prefix_le_final` + `runExt_throughout` (route a) and
   `runExt_accept_throughout` (route b: every prefix's op-cost ≤ the accepting run's FINAL budget —
   bounding by the final budget sidesteps step-level budget-invariance over the full `step1Ext`
   dispatch, documented in-tree).
5. **Axis C** — ✅ **DONE** (`Invariants.lean`). Totality-by-construction (`*_total`) + the stabilization
   core (`Halted`, `runExt_fixed`, `runExt_add`, `runExt_fuel_stable`/`_mono`, `runExt_one_fixed`,
   `runExt_stabilizes`). **Fuel-sufficiency `runScript_fuel_suffices_final`**: `Halted (runScript …)` —
   the run ALWAYS halts within `instrs.size + evalFuelSlack`, under the single true premise
   `budget ≤ maxOpCostCeiling`. Steps 1–3 unconditional (`kappa_evalCount` ⇒ `stepOpCost_step_ge` ⇒
   `runExt_realSteps_le_budget`; total iters ≤ 2·real-steps; fuel arithmetic `omega`-discharged). The
   two per-step obligations `Hframe` (only OP_INVOKE pushes a frame) and `Hbudget` (no step alters
   `.budget`) are now **discharged** by the audit theorems `stepMeterExt_frameCount_le` /
   `stepMeterExt_budget_eq` (full `stepInstrExt` walk, `[propext, Quot.sound]`).

## 5. Architectural safety

`Invariants.lean` is a **strict leaf**: it imports `Verify` (hence `Extended`/`Eval`) and is
imported by nothing (added last in `LeanBCH.lean`, after `Standard`). It proves theorems
*about* the frozen keystone without *touching* it — the freeze forbids changing the
definitions, not reasoning about them. The axiom footprint stays `[propext, Quot.sound]` for
the pure-`Nat`/structural theorems; any lemma that inherits `Classical.choice` (via existing
`Nat`/`List` lemmas) is flagged in-tree, exactly as `Number.lean`'s `wid_band` already is.
