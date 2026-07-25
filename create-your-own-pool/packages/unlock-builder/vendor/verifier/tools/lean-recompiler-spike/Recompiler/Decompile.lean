/-
  DECOMPILE-DIRECTION BRIDGE — the INVERSE of the PASS-2 scheduler.

  Models tools/singleton-recompiler/decompile.mjs's per-BLOCK symbolic walk: parse-free
  (the Op-list is the shared semantic interface with the verified scheduler), walk the ops
  maintaining TWO symbolic ref-stacks (main/alt of `Ref α`); straight-line stack ops purely
  mutate the ref arrays; a CALL (= VALOP / INVOKE) pops `nin` refs, creates a `Node`, and
  pushes `nout` `out`-refs. The result is the SAME `Block α` type the scheduler consumes.

  ★ THE BRIDGE THEOREM (`bridge_block`): for a straight-line block,
        run rawOps (entryState M A) = some (denote (decompileBlock rawOps …) M A)
  the exact MIRROR of `schedule_refines`. Composed with `schedule_refines`, this closes the
  end-to-end chain `run (emit (decompileBlock rawOps)) = run rawOps` (`end_to_end`).

  ★ REPRESENTATION NOTE (faithful, documented divergence): decompile.mjs stores main/alt as
  bottom→top JS arrays and pushes/pops at the END. This model stores them HEAD=TOP (the
  reverse — exactly the convention Basic.lean already adopts for the concrete `State α`,
  "isomorphic and makes the ops pattern-match cleanly"). The isomorphism is applied once, at
  `closeBlock` (`exit := main.reverse`, `exitAlt := alt.reverse` recover the bottom→top
  `Block.exit`/`exitAlt`; `Node.ins := (main.take nin).reverse` recovers decompile's
  bottom→top `popN` order). The produced `Block` is therefore byte-identical in WIRING to
  decompile.mjs — this is a transcription, not a stub (see the concrete non-vacuity `example`
  at the end, which walks a real CALL and computes a non-trivial value on both sides).

  Byte-level `parse` (asm.mjs) + `<n> OP_PICK → PICK n` folding are the SYNTACTIC layer,
  scoped out (the Op-model is the semantic interface the scheduler already commits to).

  Lean 4.31 core, NO mathlib.
-/
import Recompiler.Compose

namespace Recompiler
open Op

/-- Decompiler symbolic state. `main`/`alt` are ref-stacks HEAD=TOP (see representation note);
    `nodes` in creation = topological order; `nextId` the next fresh node id. -/
structure DState (α : Type) where
  main   : List (Ref α)
  alt    : List (Ref α)
  nodes  : List (Node α)
  nextId : Nat

/-- ★ THE DECOMPILE-DIRECTION READ-OUT (mirror of `readStack`, but over `List (Ref α)` directly
    — the decompiler has no register-allocation / `Token` layer, refs read straight through
    `dRef`). HEAD=TOP ⇒ no reversal (unlike the bottom→top `readStack`). -/
def sread [Inhabited α] (M A : List α) (envF : Env α) (rs : List (Ref α)) : List α :=
  rs.map (dRef M A envF)

/-- ★ THE DECOMPILE-DIRECTION SIMULATION INVARIANT: each concrete stack equals the symbolic
    ref-stack read out through `dRef` under the FIXED FINAL env `envF` (mirror of `Inv`). -/
def DInv [Inhabited α] (M A : List α) (envF : Env α) (d : DState α) (st : State α) : Prop :=
  st.1 = sread M A envF d.main ∧ st.2 = sread M A envF d.alt

/-- ★ decStep — one op of the symbolic walk, faithful to decompile.mjs's switch. Underflow
    (⇒ decompile.mjs `fail`) is `none`, mirroring `Basic.step`'s `none`. HEAD=TOP throughout. -/
def decStep [Inhabited α] : Op α → DState α → Option (DState α)
  | DUP,      ⟨x :: s,               a, nd, id⟩ => some ⟨x :: x :: s, a, nd, id⟩
  | DROP,     ⟨_ :: s,               a, nd, id⟩ => some ⟨s, a, nd, id⟩
  | OVER,     ⟨x :: y :: s,          a, nd, id⟩ => some ⟨y :: x :: y :: s, a, nd, id⟩
  | SWAP,     ⟨x :: y :: s,          a, nd, id⟩ => some ⟨y :: x :: s, a, nd, id⟩
  | ROT,      ⟨x :: y :: z :: s,     a, nd, id⟩ => some ⟨z :: x :: y :: s, a, nd, id⟩
  | NIP,      ⟨x :: _ :: s,          a, nd, id⟩ => some ⟨x :: s, a, nd, id⟩
  | TUCK,     ⟨x :: y :: s,          a, nd, id⟩ => some ⟨x :: y :: x :: s, a, nd, id⟩
  | PICK n,   ⟨s,                    a, nd, id⟩ => (s[n]?).map (fun v => ⟨v :: s, a, nd, id⟩)
  | ROLL n,   ⟨s,                    a, nd, id⟩ =>
      match s[n]? with
      | some v => some ⟨v :: removeNth s n, a, nd, id⟩
      | none   => none
  | TOALT,    ⟨x :: s,               a, nd, id⟩ => some ⟨s, x :: a, nd, id⟩
  | FROMALT,  ⟨s,                x :: a, nd, id⟩ => some ⟨x :: s, a, nd, id⟩
  | TWODROP,  ⟨_ :: _ :: s,          a, nd, id⟩ => some ⟨s, a, nd, id⟩
  | TWODUP,   ⟨x :: y :: s,          a, nd, id⟩ => some ⟨x :: y :: x :: y :: s, a, nd, id⟩
  | THREEDUP, ⟨x :: y :: z :: s,     a, nd, id⟩ => some ⟨x :: y :: z :: x :: y :: z :: s, a, nd, id⟩
  | TWOOVER,  ⟨x :: y :: z :: w :: s, a, nd, id⟩ => some ⟨z :: w :: x :: y :: z :: w :: s, a, nd, id⟩
  | TWOROT,   ⟨x :: y :: z :: w :: u :: v :: s, a, nd, id⟩ => some ⟨u :: v :: x :: y :: z :: w :: s, a, nd, id⟩
  | TWOSWAP,  ⟨x :: y :: z :: w :: s, a, nd, id⟩ => some ⟨z :: w :: x :: y :: s, a, nd, id⟩
  | PUSH v,   ⟨s,                    a, nd, id⟩ => some ⟨Ref.const v false :: s, a, nd, id⟩
  | CALL nin sem, ⟨s,                a, nd, id⟩ =>
      if nin ≤ s.length then
        let nout := (sem (List.replicate nin (default : α))).length
        some ⟨((List.range nout).map (fun j => Ref.out id j)).reverse ++ s.drop nin,
              a,
              nd ++ [⟨id, ⟨nin, nout, sem⟩, (s.take nin).reverse⟩],
              id + 1⟩
      else none
  | _, _ => none

/-- The monadic op-fold (short-circuit on `none`), the exact mirror of `Basic.run`. -/
def decFold [Inhabited α] : List (Op α) → DState α → Option (DState α)
  | [],      d => some d
  | o :: os, d => match decStep o d with
                  | some d' => decFold os d'
                  | none    => none

/-- ★ decompileBlock — seed entry main/alt slots (`inp i`/`ainp i`, HEAD=TOP), fold the ops,
    close the block (convert HEAD=TOP → bottom→top at the boundary; `denote` expects
    bottom→top exit/exitAlt). `none` iff the walk underflows / hits an unmodelled op. -/
def decompileBlock [Inhabited α] (rawOps : List (Op α)) (ed ea : Nat) : Option (Block α) :=
  let seed : DState α :=
    ⟨((List.range ed).map Ref.inp).reverse, ((List.range ea).map Ref.ainp).reverse, [], 0⟩
  (decFold rawOps seed).map (fun d =>
    { entryDepth := ed, entryAlt := ea, nodes := d.nodes,
      exit := d.main.reverse, exitAlt := d.alt.reverse })

/-! ### sread algebra (HEAD=TOP; `sread = map dRef`). -/

theorem sread_cons {α} [Inhabited α] (M A : List α) (envF : Env α) (r : Ref α) (rs : List (Ref α)) :
    sread M A envF (r :: rs) = dRef M A envF r :: sread M A envF rs := rfl

theorem sread_append {α} [Inhabited α] (M A : List α) (envF : Env α) (xs ys : List (Ref α)) :
    sread M A envF (xs ++ ys) = sread M A envF xs ++ sread M A envF ys := by
  simp [sread]

theorem sread_length {α} [Inhabited α] (M A : List α) (envF : Env α) (rs : List (Ref α)) :
    (sread M A envF rs).length = rs.length := by simp [sread]

theorem sread_reverse {α} [Inhabited α] (M A : List α) (envF : Env α) (rs : List (Ref α)) :
    sread M A envF rs.reverse = (sread M A envF rs).reverse := by simp [sread]

theorem sread_take {α} [Inhabited α] (M A : List α) (envF : Env α) (n : Nat) (rs : List (Ref α)) :
    sread M A envF (rs.take n) = (sread M A envF rs).take n := by simp [sread]

theorem sread_drop {α} [Inhabited α] (M A : List α) (envF : Env α) (n : Nat) (rs : List (Ref α)) :
    sread M A envF (rs.drop n) = (sread M A envF rs).drop n := by simp [sread]

theorem sread_getElem? {α} [Inhabited α] (M A : List α) (envF : Env α) (n : Nat) (rs : List (Ref α)) :
    (sread M A envF rs)[n]? = (rs[n]?).map (dRef M A envF) := by simp [sread]

theorem sread_removeNth {α} [Inhabited α] (M A : List α) (envF : Env α) (n : Nat) (rs : List (Ref α)) :
    sread M A envF (removeNth rs n) = removeNth (sread M A envF rs) n := by
  simp [sread, removeNth]

/-! ### nodes-monotonicity — decStep only ever APPENDS to `nodes` (needed to place a freshly
    created CALL node inside the FINAL block for the denotation link). -/

theorem decStep_nodes_pref {α} [Inhabited α] {o : Op α} {d d' : DState α}
    (h : decStep o d = some d') : ∃ suf, d'.nodes = d.nodes ++ suf := by
  unfold decStep at h
  split at h
  all_goals
    first
    | contradiction
    | (rw [Option.map_eq_some_iff] at h; obtain ⟨v, _, h⟩ := h; subst h
       exact ⟨[], (List.append_nil _).symm⟩)
    | (injection h with h'; subst h'; exact ⟨[], (List.append_nil _).symm⟩)
    | (split at h <;> first
        | contradiction
        | (injection h with h'; subst h'; exact ⟨[], (List.append_nil _).symm⟩))
    | (split at h <;> first
        | contradiction
        | (injection h with h'; subst h'; exact ⟨_, rfl⟩))

/-- decFold likewise only appends to `nodes`: the intermediate node lists are prefixes of the
    final one (so any node created mid-walk lives in the final block). -/
theorem decFold_nodes_pref {α} [Inhabited α] :
    ∀ (os : List (Op α)) (d dfin : DState α),
      decFold os d = some dfin → ∃ suf, dfin.nodes = d.nodes ++ suf := by
  intro os
  induction os with
  | nil =>
      intro d dfin h
      simp only [decFold] at h; injection h with h; subst h
      exact ⟨[], (List.append_nil _).symm⟩
  | cons o os ih =>
      intro d dfin h
      simp only [decFold] at h
      cases hstep : decStep o d with
      | none => rw [hstep] at h; exact absurd h (by simp)
      | some d1 =>
          rw [hstep] at h
          obtain ⟨s1, hs1⟩ := decStep_nodes_pref hstep
          obtain ⟨s2, hs2⟩ := ih d1 dfin h
          exact ⟨s1 ++ s2, by rw [hs2, hs1, List.append_assoc]⟩

/-- Membership corollary: every node in a mid-walk state is in the final state's node list. -/
theorem decFold_nodes_mem {α} [Inhabited α] (os : List (Op α)) (d dfin : DState α)
    (h : decFold os d = some dfin) : ∀ n ∈ d.nodes, n ∈ dfin.nodes := by
  obtain ⟨suf, hsuf⟩ := decFold_nodes_pref os d dfin h
  intro n hn; rw [hsuf]; exact List.mem_append_left _ hn

/-! ### ★ STACK-OP COMMUTATION — for every NON-CALL op, `step` on the read-out stacks equals the
    read-out of `decStep`'s result (both perform the SAME structural list surgery; `sread = map`
    commutes with cons/take/drop/removeNth/getElem?). Underflow aligns: `[].map = []` so both fail
    on exactly the same short stacks. This single lemma discharges all 18 stack ops at once. -/
theorem decStep_step_commute {α} [Inhabited α] (M A : List α) (envF : Env α)
    (o : Op α) (main alt : List (Ref α)) (nd : List (Node α)) (id : Nat)
    (hne : ∀ nin sem, o ≠ CALL nin sem) :
    step o (sread M A envF main, sread M A envF alt)
      = (decStep o ⟨main, alt, nd, id⟩).map
          (fun d' => (sread M A envF d'.main, sread M A envF d'.alt)) := by
  cases o
  case DUP => rcases main with _ | ⟨x, s⟩ <;> simp [step, decStep, sread]
  case DROP => rcases main with _ | ⟨x, s⟩ <;> simp [step, decStep, sread]
  case OVER => rcases main with _ | ⟨x, _ | ⟨y, s⟩⟩ <;> simp [step, decStep, sread]
  case SWAP => rcases main with _ | ⟨x, _ | ⟨y, s⟩⟩ <;> simp [step, decStep, sread]
  case ROT => rcases main with _ | ⟨x, _ | ⟨y, _ | ⟨z, s⟩⟩⟩ <;> simp [step, decStep, sread]
  case NIP => rcases main with _ | ⟨x, _ | ⟨y, s⟩⟩ <;> simp [step, decStep, sread]
  case TUCK => rcases main with _ | ⟨x, _ | ⟨y, s⟩⟩ <;> simp [step, decStep, sread]
  case TOALT => rcases main with _ | ⟨x, s⟩ <;> simp [step, decStep, sread]
  case FROMALT => rcases alt with _ | ⟨x, a⟩ <;> simp [step, decStep, sread]
  case TWODROP => rcases main with _ | ⟨x, _ | ⟨y, s⟩⟩ <;> simp [step, decStep, sread]
  case TWODUP => rcases main with _ | ⟨x, _ | ⟨y, s⟩⟩ <;> simp [step, decStep, sread]
  case THREEDUP => rcases main with _ | ⟨x, _ | ⟨y, _ | ⟨z, s⟩⟩⟩ <;> simp [step, decStep, sread]
  case TWOOVER => rcases main with _ | ⟨x, _ | ⟨y, _ | ⟨z, _ | ⟨w, s⟩⟩⟩⟩ <;> simp [step, decStep, sread]
  case TWOROT =>
    rcases main with _ | ⟨x, _ | ⟨y, _ | ⟨z, _ | ⟨w, _ | ⟨u, _ | ⟨v, s⟩⟩⟩⟩⟩⟩ <;>
      simp [step, decStep, sread]
  case TWOSWAP => rcases main with _ | ⟨x, _ | ⟨y, _ | ⟨z, _ | ⟨w, s⟩⟩⟩⟩ <;> simp [step, decStep, sread]
  case PUSH v => simp [step, decStep, sread, dRef]
  case PICK n =>
    simp only [step, decStep, sread, List.getElem?_map, Option.map_map, Option.map_map]
    rfl
  case ROLL n =>
    simp only [step, decStep, sread]
    rw [List.getElem?_map]
    cases main[n]? <;> simp [removeNth]
  case CALL nin sem => exact absurd rfl (hne nin sem)

/-! ### ★ CALL SIMULATION — the ONE semantic step. A CALL pops `nin` operand refs, creates the
    node, pushes `nout` `out`-refs; concretely `step` pops `nin` values, applies `sem`, pushes
    the results. The `out`-refs read out (under the FIXED FINAL env) to exactly `sem`'s outputs
    by the `denotation_link` (created node ∈ final block, `WellFormed`), with the `nout` count
    matched by `WellFormed`'s `semArity`. This is the mirror of `emitCall_stepOk`. -/
theorem decStep_call_sim {α} [DecidableEq α] [Inhabited α] (b : Block α) (hwf : WellFormed b)
    (M A : List α) (nin : Nat) (sem : List α → List α) (main alt : List (Ref α))
    (nd : List (Node α)) (id : Nat) (d' : DState α)
    (hstep : decStep (CALL nin sem) ⟨main, alt, nd, id⟩ = some d')
    (hmem : ∀ n ∈ d'.nodes, n ∈ b.nodes) :
    step (CALL nin sem) (sread M A (blockEnv b M A) main, sread M A (blockEnv b M A) alt)
      = some (sread M A (blockEnv b M A) d'.main, sread M A (blockEnv b M A) d'.alt) := by
  -- extract the accepted branch (no underflow) and pin `d'`
  simp only [decStep] at hstep
  split at hstep
  next hle =>
    injection hstep with hstep; subst hstep
    -- the created node lives in the final block
    have hmemnode :
        (⟨id, ⟨nin, (sem (List.replicate nin (default : α))).length, sem⟩,
          (main.take nin).reverse⟩ : Node α) ∈ b.nodes := hmem _ (by simp)
    -- denotation link: (blockEnv … id) = sem (operand values)
    have hlink : blockEnv b M A id
        = sem (((main.take nin).reverse).map (dRef M A (blockEnv b M A))) :=
      denotation_link M A b hwf _ hmemnode
    -- semArity ⇒ |blockEnv … id| = nout
    have hsem := hwf.2.2.2.2.2.1 _ hmemnode
    have hlen : (((main.take nin).reverse).map (dRef M A (blockEnv b M A))).length = nin := by
      rw [List.length_map, List.length_reverse, List.length_take]; omega
    have hEnvLen : (blockEnv b M A id).length = (sem (List.replicate nin (default : α))).length := by
      rw [hlink]
      exact hsem (((main.take nin).reverse).map (dRef M A (blockEnv b M A))) (by rw [hlen])
    -- the out-refs read out to sem's outputs
    have houts :
        sread M A (blockEnv b M A)
            (((List.range (sem (List.replicate nin (default : α))).length).map
              (fun j => Ref.out id j)).reverse)
          = (sem (((main.take nin).reverse).map (dRef M A (blockEnv b M A)))).reverse := by
      simp only [sread]
      rw [List.map_reverse, List.map_map]
      congr 1
      rw [← hlink,
          show (List.range (sem (List.replicate nin (default : α))).length).map
                 (dRef M A (blockEnv b M A) ∘ fun j => Ref.out id j)
             = (List.range (blockEnv b M A id).length).map
                 (fun j => (blockEnv b M A id).getD j default) from by
            rw [hEnvLen]; apply List.map_congr_left; intro j _; rfl]
      exact map_range_getD (blockEnv b M A id)
    -- now compute step
    simp only [step]
    rw [if_pos (by rw [sread_length]; exact hle)]
    refine congrArg some (Prod.ext ?_ ?_)
    · -- main
      show (sem (((sread M A (blockEnv b M A) main).take nin).reverse)).reverse
             ++ (sread M A (blockEnv b M A) main).drop nin
         = sread M A (blockEnv b M A)
             (((List.range (sem (List.replicate nin (default : α))).length).map
                 (fun j => Ref.out id j)).reverse ++ main.drop nin)
      rw [sread_append, sread_drop, houts]
      congr 3
      rw [← sread_take, ← sread_reverse]; rfl
    · -- alt (unchanged)
      rfl
  next hle => exact absurd hstep (by simp)

/-- ★ THE PER-OP SIMULATION (mirror of `decStep_sim` in the ARCHITECT spec): one `decStep`
    that succeeds corresponds to one `step` that succeeds, preserving `DInv`. Stack ops via
    `decStep_step_commute`; the sole CALL via `decStep_call_sim`. -/
theorem decStep_sim {α} [DecidableEq α] [Inhabited α] (b : Block α) (hwf : WellFormed b)
    (M A : List α) {o : Op α} {d d' : DState α} {st : State α}
    (hstep : decStep o d = some d')
    (hmem : ∀ n ∈ d'.nodes, n ∈ b.nodes)
    (hinv : DInv M A (blockEnv b M A) d st) :
    ∃ st', step o st = some st' ∧ DInv M A (blockEnv b M A) d' st' := by
  obtain ⟨h1, h2⟩ := hinv
  refine ⟨(sread M A (blockEnv b M A) d'.main, sread M A (blockEnv b M A) d'.alt), ?_, rfl, rfl⟩
  obtain ⟨main, alt, nd, id⟩ := d
  have hst : st = (sread M A (blockEnv b M A) main, sread M A (blockEnv b M A) alt) := by
    rw [Prod.ext_iff]; exact ⟨h1, h2⟩
  rw [hst]
  by_cases hc : ∃ nin sem, o = CALL nin sem
  · obtain ⟨nin, sem, rfl⟩ := hc
    exact decStep_call_sim b hwf M A nin sem main alt nd id d' hstep hmem
  · have hne : ∀ nin sem, o ≠ CALL nin sem := fun nin sem h => hc ⟨nin, sem, h⟩
    rw [decStep_step_commute M A (blockEnv b M A) o main alt nd id hne, hstep]; rfl

/-- ★ WHOLE-WALK COMPOSITION — fold `decStep_sim` over the op list: if the symbolic walk
    accepts `rawOps` (`decFold … = some dfin`) then running `rawOps` concretely tracks it,
    reaching a state `DInv`-related to `dfin`. Mirror of the scheduler's `stepOk_foldl`. -/
theorem decFold_sim {α} [DecidableEq α] [Inhabited α] (b : Block α) (hwf : WellFormed b)
    (M A : List α) :
    ∀ (os : List (Op α)) (d dfin : DState α) (st : State α),
      decFold os d = some dfin →
      (∀ n ∈ dfin.nodes, n ∈ b.nodes) →
      DInv M A (blockEnv b M A) d st →
      ∃ st', run os st = some st' ∧ DInv M A (blockEnv b M A) dfin st' := by
  intro os
  induction os with
  | nil =>
      intro d dfin st h _ hinv
      simp only [decFold] at h; injection h with h; subst h
      exact ⟨st, rfl, hinv⟩
  | cons o os ih =>
      intro d dfin st h hmem hinv
      simp only [decFold] at h
      cases hstep : decStep o d with
      | none => rw [hstep] at h; exact absurd h (by simp)
      | some d1 =>
          rw [hstep] at h
          have hmem1 : ∀ n ∈ d1.nodes, n ∈ b.nodes := fun n hn =>
            hmem n (decFold_nodes_mem os d1 dfin h n hn)
          obtain ⟨st1, hst1, hinv1⟩ := decStep_sim b hwf M A hstep hmem1 hinv
          obtain ⟨st', hrun, hinv'⟩ := ih d1 dfin st1 h hmem hinv1
          refine ⟨st', ?_, hinv'⟩
          show run (o :: os) st = some st'
          simp only [run, hst1]; exact hrun

/-! ### Entry-seed read-out: the seeded `inp`/`ainp` ref-stacks read out to `M.reverse`/`A.reverse`
    (= `entryState`), the base case of the simulation (mirror of `inv_entry`). -/

theorem sread_seed_main {α} [Inhabited α] (M A : List α) (envF : Env α) (ed : Nat)
    (hM : M.length = ed) : sread M A envF (((List.range ed).map Ref.inp).reverse) = M.reverse := by
  simp only [sread]
  rw [List.map_reverse, List.map_map]
  congr 1
  rw [← hM]
  rw [show ((dRef M A envF) ∘ Ref.inp) = (fun i => M.getD i default) from by funext i; rfl]
  exact map_range_getD M

theorem sread_seed_alt {α} [Inhabited α] (M A : List α) (envF : Env α) (ea : Nat)
    (hA : A.length = ea) : sread M A envF (((List.range ea).map Ref.ainp).reverse) = A.reverse := by
  simp only [sread]
  rw [List.map_reverse, List.map_map]
  congr 1
  rw [← hA]
  rw [show ((dRef M A envF) ∘ Ref.ainp) = (fun i => A.getD i default) from by funext i; rfl]
  exact map_range_getD A

/-! ### ★★ THE BRIDGE THEOREM (decompile faithfulness) — the exact MIRROR of `schedule_refines`. -/

/-- ★ For a straight-line block accepted by the decompiler, running the ORIGINAL ops from the
    entry state reproduces the DAG denotation of the decompiled block. This is the SPEC that
    `schedule_refines` took as given; here it is PROVEN by the decompile-direction simulation.
    Combined with `schedule_refines`, closes the end-to-end chain `run(emit ∘ decompile) = run`. -/
theorem bridge_block {α} [DecidableEq α] [Inhabited α]
    (rawOps : List (Op α)) (ed ea : Nat) (M A : List α)
    (hM : M.length = ed) (hA : A.length = ea)
    (b : Block α) (hb : decompileBlock rawOps ed ea = some b) (hwf : WellFormed b) :
    run rawOps (entryState M A) = some (denote b M A) := by
  -- decompileBlock accepted ⇒ ∃ final walk-state `dfin`, and `b` is its close-up
  rw [decompileBlock, Option.map_eq_some_iff] at hb
  obtain ⟨dfin, hfold, hbeq⟩ := hb
  have hnodes : b.nodes = dfin.nodes := by rw [← hbeq]
  have hexit : b.exit = dfin.main.reverse := by rw [← hbeq]
  have hexitAlt : b.exitAlt = dfin.alt.reverse := by rw [← hbeq]
  -- entry invariant (env-agnostic seed read-out)
  have hinv0 : DInv M A (blockEnv b M A)
      ⟨((List.range ed).map Ref.inp).reverse, ((List.range ea).map Ref.ainp).reverse, [], 0⟩
      (entryState M A) := by
    refine ⟨?_, ?_⟩
    · rw [sread_seed_main M A (blockEnv b M A) ed hM]; rfl
    · rw [sread_seed_alt M A (blockEnv b M A) ea hA]; rfl
  -- run the composition simulation to the exit
  obtain ⟨st', hrun, hinv'⟩ :=
    decFold_sim b hwf M A rawOps _ dfin (entryState M A) hfold
      (fun n hn => by rw [hnodes]; exact hn) hinv0
  rw [hrun]
  -- read off `st' = denote b M A`
  obtain ⟨e1, e2⟩ := hinv'
  refine congrArg some (Prod.ext ?_ ?_)
  · rw [e1, denote_fst, hexit]; simp only [sread, List.map_reverse, List.reverse_reverse]
  · rw [e2, denote_snd, hexitAlt]; simp only [sread, List.map_reverse, List.reverse_reverse]

/-! ### ★★★ END-TO-END — `run (recompiled) = run (original)` for a straight-line block.

    optimized := `emit (decompileBlock rawOps)`. `schedule_refines` (the verified scheduler,
    0-sorry) gives `run(optimized) = denote(decompiled)` for the block's topological node order;
    `bridge_block` (this file) gives `run(original) = denote(decompiled)`. Chaining closes the
    verified-recompiler correctness chain over ONE straight-line block, on ALL inputs, over an
    abstract value type `α`. (`denote` is node-order-invariant, so any valid schedule order is
    equally covered by `schedule_refines`; this model emits in `b.nodes` order.) -/
theorem end_to_end {α} [DecidableEq α] [Inhabited α]
    (rawOps : List (Op α)) (ed ea : Nat) (M A : List α)
    (hM : M.length = ed) (hA : A.length = ea)
    (b : Block α) (hb : decompileBlock rawOps ed ea = some b) (hwf : WellFormed b) :
    run (emit b) (entryState M A) = run rawOps (entryState M A) := by
  have hde : b.entryDepth = ed := by
    rw [decompileBlock, Option.map_eq_some_iff] at hb
    obtain ⟨dfin, _, hbeq⟩ := hb; rw [← hbeq]
  have hea : b.entryAlt = ea := by
    rw [decompileBlock, Option.map_eq_some_iff] at hb
    obtain ⟨dfin, _, hbeq⟩ := hb; rw [← hbeq]
  rw [schedule_refines b hwf M A (by rw [hde]; exact hM) (by rw [hea]; exact hA),
      bridge_block rawOps ed ea M A hM hA b hb hwf]

/-! ### ★ NON-VACUITY WITNESS — the decompiler is a real op-walk (not a stub): a concrete block
    over `α := Nat` with a genuine CALL (a binary `sem`) where BOTH sides of the bridge compute
    the same non-trivial value. Guards against a trivializing model. -/

/-- `[a,b] ↦ [a+b]` — a real binary value-op with `nin = 2`, `nout = 1`. -/
private def addSem : List Nat → List Nat := fun l => [l.headD 0 + (l.tail.headD 0)]

/-- Program: PUSH 3; PUSH 4; CALL 2 addSem  ⇒ decompiles to a 1-node DAG computing `3 + 4`. -/
private def egOps : List (Op Nat) := [Op.PUSH 3, Op.PUSH 4, Op.CALL 2 addSem]

/-- The decompiler produces a concrete, non-empty block (one node, one out-ref). -/
example : ∃ b, decompileBlock egOps 0 0 = some b := ⟨_, rfl⟩

/-- Running the original ops computes `[7]` on the main stack (a genuine CALL evaluation). -/
example : run egOps (entryState ([] : List Nat) []) = some ([7], []) := by
  decide

/-- ★ The bridge holds concretely: original run = denotation of the decompiled block, both `[7]`. -/
example :
    ∃ b, decompileBlock egOps 0 0 = some b ∧
      run egOps (entryState ([] : List Nat) []) = some (denote b ([] : List Nat) []) ∧
      denote b ([] : List Nat) [] = ([7], []) := by
  refine ⟨_, rfl, ?_, ?_⟩ <;> decide

/-- The exact block the decompiler produces for `egOps` (one node = `addSem` over two consts). -/
private def egBlock : Block Nat :=
  { entryDepth := 0, entryAlt := 0,
    nodes := [⟨0, ⟨2, 1, addSem⟩, [Ref.const 3 false, Ref.const 4 false]⟩],
    exit := [Ref.out 0 0], exitAlt := [] }

/-- The decompiler yields exactly `egBlock` (faithful walk, computed). -/
example : decompileBlock egOps 0 0 = some egBlock := rfl

/-- ★ `egBlock` is genuinely `WellFormed` — so `bridge_block`/`end_to_end` provably FIRE on this
    concrete program (the `WellFormed` hypothesis is non-vacuously met, not a dead branch). -/
theorem egBlock_wf : WellFormed egBlock := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · -- nodesWF: the single node's ins are constants (always bounded)
    refine ⟨fun r hr => ?_, trivial⟩
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hr
    rcases hr with rfl | rfl <;> trivial
  · -- exit: out 0 0, id 0 declared
    intro r hr
    simp only [egBlock, List.mem_singleton] at hr; subst hr
    show (0 : Nat) ∈ [0]; simp
  · intro r hr; simp only [egBlock, List.not_mem_nil] at hr        -- exitAlt empty
  · simp [egBlock]                                                 -- ids [0] Nodup
  · intro n hn; simp only [egBlock, List.mem_singleton] at hn; subst hn; rfl   -- arity 2
  · intro n hn l _; simp only [egBlock, List.mem_singleton] at hn; subst hn; rfl  -- semArity 1
  · -- outIdx: the only out-ref anywhere is `out 0 0`, and 0 < nout = 1
    intro nid j hmem nd hnd hid
    simp only [egBlock, List.mem_singleton] at hnd; subst hnd
    show j < 1
    simp only [egBlock, List.flatMap_cons, List.flatMap_nil, List.append_nil,
      List.mem_append, List.mem_cons, List.not_mem_nil, or_false,
      reduceCtorEq, false_or, Ref.out.injEq] at hmem
    omega

/-- ★ CAPSTONE: `bridge_block` FIRES on the concrete `egBlock` — original run = decompiled
    denotation, every hypothesis discharged. -/
example : run egOps (entryState ([] : List Nat) []) = some (denote egBlock [] []) :=
  bridge_block egOps 0 0 [] [] rfl rfl egBlock rfl egBlock_wf

/-- ★ CAPSTONE (end-to-end): recompiled(egBlock) run = original run, on the concrete program. -/
example : run (emit egBlock) (entryState ([] : List Nat) []) = run egOps (entryState [] []) :=
  end_to_end egOps 0 0 [] [] rfl rfl egBlock rfl egBlock_wf

end Recompiler
