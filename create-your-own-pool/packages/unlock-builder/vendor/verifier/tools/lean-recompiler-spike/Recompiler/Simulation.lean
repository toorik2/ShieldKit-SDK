/-
  PASS-2 DAG-SCHEDULER — the SIMULATION / REFINEMENT relation and the end-to-end statement.

  The scheduler is verified by a CompCert-style simulation: `Inv` relates the emitter's model
  state (Scheduler.ModelState — its modelled stacks `S`,`Salt` + token identities) to the
  concrete VM `State α`, saying the concrete stack is EXACTLY the modelled stack's tokens read
  out as VALUES (`valOf`) under the DAG denotation. Head=top ⇒ the bottom→top model list is
  REVERSED to match the concrete (head=top) stack. This is the invariant the step-lemmas
  (one per emitter primitive) preserve; composing them over the node schedule yields, at exit,
  `concrete stack = denote(block)` ⇒ `run(emit) = denote = run(original)`.

  ★ GETTING THE INVARIANT RIGHT is ~80% of a simulation proof; this file pins it precisely.

  STATUS (honest sorry-frontier): the relation, the value semantics, the entry base case
  (`inv_entry`), and ALL FOUR STEP-LEMMAS (`Recompiler.StepLemmas`, 0 sorry, as composable
  `StepOk` one-step refinements) are machine-checked. What remains for the END-TO-END
  `schedule_refines` (the only `sorry` in the build) is: the denotation link (node `sem` =
  DAG output), the operand-layout bookkeeping, and folding `StepOk.trans` over the schedule
  (see the detailed frontier note above the theorem). Everything ELSE (the DAG, `denote`,
  `WellFormed`, the full emitter model, `Inv`, `valOf`, and the step-lemmas) is `sorry`-free.
-/
import Recompiler.Dag
import Recompiler.Scheduler

namespace Recompiler

/-- The VALUE a token denotes, under entry mains `M`, entry alts `A` (bottom→top) and the
    node-output environment `envF`. `nullTok`/`cTok` carry their own value; slot tokens read
    the entry lists; `vTok` reads the node output. Mirrors `dRef` (Dag.lean) exactly. -/
def valOf [Inhabited α] (M A : List α) (envF : Env α) : Token α → α
  | .inTok k    => M.getD k default
  | .ainTok k   => A.getD k default
  | .vTok id j  => (envF id).getD j default
  | .cTok v     => v
  | .nullTok v  => v

/-- Read a modelled bottom→top stack out as concrete VALUES, head=top (⇒ reversed). -/
def readStack [Inhabited α] (M A : List α) (envF : Env α) (S : List (Entry α)) : List α :=
  (S.map (fun e => valOf M A envF e.tok)).reverse

/-- ★ THE SIMULATION INVARIANT (refinement relation).
    The concrete VM state `(cm, ca)` (head=top) equals the emitter model's stacks read out as
    denoted values. Because every non-transient `Entry` records WHICH ref-value lives at that
    concrete position, this single equation captures the classic "liveRefs ↦ concrete-index,
    holding the ref's denoted value" simulation map (main AND alt), including transients. -/
def Inv [Inhabited α] (M A : List α) (envF : Env α)
    (ms : ModelState α) (st : State α) : Prop :=
  st.1 = readStack M A envF ms.S ∧
  st.2 = readStack M A envF ms.Salt

/-- The node-output environment induced by a block at entry `(M, A)` — the shared `envF`
    used by both `denote` and `Inv` (so the invariant is stated against the block's semantics). -/
def blockEnv [Inhabited α] (b : Block α) (M A : List α) : Env α :=
  denoteNodes M A b.nodes (fun _ => [])

/-- The concrete ENTRY state for a block: entry mains `M`, entry alts `A` (bottom→top),
    presented head=top (⇒ reversed). -/
def entryState (M A : List α) : State α := (M.reverse, A.reverse)

/-- A list is recovered by mapping `getD` over the range of its indices. -/
theorem map_range_getD [Inhabited α] (L : List α) :
    (List.range L.length).map (fun i => L.getD i default) = L := by
  apply List.ext_getElem
  · simp
  · intro i h1 _
    have hi : i < L.length := by simpa using h1
    rw [List.getElem_map, List.getElem_range, List.getD_eq_getElem?_getD,
        List.getElem?_eq_getElem hi]
    rfl

/-- Sanity: the ENTRY invariant holds by construction — the seeded model stacks
    (`inTok i`/`ainTok i`) read out to exactly `M`/`A`. (A genuine, `sorry`-free lemma; the
    base case of the simulation.) Requires the seed lengths to match the entry sizes. -/
theorem inv_entry [DecidableEq α] [Inhabited α] (b : Block α) (M A : List α)
    (hM : M.length = b.entryDepth) (hA : A.length = b.entryAlt) :
    Inv M A (blockEnv b M A)
      { ops  := []
      , S    := (List.range b.entryDepth).map (fun i => (⟨Token.inTok i, false⟩ : Entry α))
      , Salt := (List.range b.entryAlt).map   (fun i => (⟨Token.ainTok i, false⟩ : Entry α))
      , use  := demand b (altPassthrough b) }
      (entryState M A) := by
  constructor
  · -- main stack
    simp only [entryState, readStack, List.map_map]
    apply congrArg List.reverse
    rw [← hM]
    have h : ((fun e => valOf M A (blockEnv b M A) e.tok) ∘
              fun i => (⟨Token.inTok i, false⟩ : Entry α))
           = (fun i => M.getD i default) := by funext i; rfl
    rw [h, map_range_getD]
  · -- alt stack (symmetric)
    simp only [entryState, readStack, List.map_map]
    apply congrArg List.reverse
    rw [← hA]
    have h : ((fun e => valOf M A (blockEnv b M A) e.tok) ∘
              fun i => (⟨Token.ainTok i, false⟩ : Entry α))
           = (fun i => A.getD i default) := by funext i; rfl
    rw [h, map_range_getD]

/-! ### ★ END-TO-END REFINEMENT (the scheduler's correctness theorem).

    For every WellFormed block at matching entry sizes, running the EMITTED ops from the entry
    state reproduces the DAG denotation — i.e. the recompiler's PASS-2 output is a drop-in
    replacement for the original block on ALL inputs (over abstract `α`). Combined with the
    (out-of-scope) decompile bridge `run(original) = denote`, this gives
    `run(emit) = run(original)`.

    STATUS — the STEP-LEMMAS are now MACHINE-CHECKED (0 sorry) in `Recompiler.StepLemmas`,
    packaged as one-step `StepOk` refinements (composable via `StepOk.trans`):
      ✓ (1) emitFetch — `emitFetch_stepOk` (MOVE via `move_stepOk`/`run_moveOps`, COPY via
            `copy_stepOk`/`run_copyOps`; the index-arithmetic crux `depthOfHome_value` +
            `readStack_eraseIdx` — ROLL/PICK depth = concrete depth, transients counted).
      ✓ (2) emitNode CALL — `emitCall_stepOk`: operands-on-top ⇒ output(s)-on-top, `Inv`
            extended (`run_call` + `readStack_append_gen` + `valOf_tokenOf`), given the
            DENOTATION LINK `hout`.  eagerDrop primitive = `del_stepOk` (q=0).
      ✓ (3) emitExit — build via `emitBuildRef_stepOk`; stale-tail/eager DROP via `del_stepOk`
            (`run_delOps`); entry state = `inv_entry` (below).
      ✓ (4) const-CSE — `emitBuildRef_stepOk` + the `const` cases of `emitFetch_stepOk`
            (push-once home, COPY-reuse).

    REMAINING to close `schedule_refines` end-to-end (the genuine frontier):
      (a) DENOTATION LINK — discharge `emitCall_stepOk`'s `hout`
          (`n.op.sem (n.ins.map (dRef …)) = blockEnv b M A n.id`, with nin/nout consistency)
          from `denoteNodes` + the topological order + distinct node ids in `WellFormed`.
          This is the ONE semantic obligation (everything above is pure stack wiring).
      (b) STRUCTURAL bookkeeping — that the operand-materialize fold leaves the top-k slots as
          exactly the node's operands over a base (so `emitCall_stepOk`'s `hS` holds), plus the
          `matchPrefix`/`eagerDrop` fuel arithmetic.
      (c) COMPOSE — fold `StepOk.trans` over drain · nodes · exit-alt · main-arrange, and read
          off `st = denote b M A` at exit (`inv_entry` is the base case).
    The base case `inv_entry` is proven below; the step-lemmas are proven in StepLemmas.lean.
    ★ THE END-TO-END THEOREM `schedule_refines` IS NOW ASSEMBLED IN `Recompiler.Compose`
    (which imports StepLemmas): the reduction + `StepOk.trans` composition over the four
    phases is machine-checked there; the DRAIN phase is fully proven; the residual frontier
    (home/demand liveness invariant, denotation link, arrange bookkeeping) is a small set of
    named, precisely-stated lemmas there. -/

end Recompiler
