/-
  VALUE-PRODUCING MOVEMENT FLOOR — a machine-checked LOWER BOUND on stack-MOVEMENT ops for a
  body that COMPUTES (produces fresh values), not merely permutes.

  ★ WHY THIS FILE EXISTS (the gap it closes). `Opt/NlcsFloor.lean` proves the sharp movement floor
    `#move ≥ n − LCS(entry, exit)` — but ONLY for a PURE-PERMUTATION machine (`moveToTop`/`runMoves`):
    `runMoves prog s` is always a permutation of `s`, so it can NEVER equal a value-producing exit
    (fresh outputs are labels ∉ entry). Hence for the Fp12 arithmetic core — whose exit stack is 12
    freshly-COMPUTED numbers — `movement_lower_bound_nlcs` is VACUOUS: its hypothesis "this program
    realizes the exit" is unsatisfiable in the permutation model (there is no move-only program whose
    run equals a fresh-valued exit). This file extends the model to a VALUE-PRODUCING DAG: a machine
    with BOTH movement ops (`mv d` = `moveToTop d`, the SAME height-neutral ROLL/SWAP primitive) AND
    a PRODUCE op (`pr w` = push a fresh computed value on top, the abstraction of an essential
    OP_MUL/OP_ADD landing its result on the stack). The bound then counts MOVEMENT ops ONLY (`mvCount`,
    produce ops are free) and remains a REAL, POSITIVE lower bound in the presence of value production.

  ★ THE CLAIM (the operand-fetch / repositioning floor for a value-producing DAG):
        #movement-ops  ≥  n − LCS(entry, exit)
    where n = |entry| = the number of input operands initially on the stack, and LCS is the longest
    common subsequence of the entry and (value-producing) exit orderings. Mechanism, machine-checked
    below: an entry input NEVER lifted by an `mv` keeps its relative position, and — crucially, unlike
    NlcsFloor — a `pr` op that pushes a FRESH value ALSO preserves that relative order (the fresh value
    is not one of the untouched inputs, so it filters away). So the untouched inputs U form a COMMON
    SUBSEQUENCE of entry and exit even across produce ops, giving |U| ≤ LCS and #mv ≥ n − |U| ≥ n − LCS.
    The freshness of produced values (produced labels ∉ entry) is the one hypothesis — it is exactly
    the "the body COMPUTES new values" property, and is what makes the bound apply where NlcsFloor cannot.

  ★ WHAT THIS IS AND IS NOT (honest scope — read before citing).
    - IS: a rigorous, 0-sorry lower bound on the count of height-neutral MOVEMENT ops (`mv d` =
      moveToTop, the ROLL/SWAP family) needed to REPOSITION the entry operands of a straight-line
      body that also produces fresh values via `pr`. It is NON-VACUOUS for value production (witnessed
      below with a genuinely fresh-valued exit) — precisely the case NlcsFloor cannot express.
    - IS NOT (the open half, stated so the un-proven part is never laundered into the proven one):
      (1) The `pr` op models an essential compute's OUTPUT-on-top but does NOT model its two-operand
          CONSUMPTION (the pop-2). A fully consumption-aware bin machine (pop 2 / push 1) with a
          movement floor accounting for operands buried below the top by prior computation remains a
          STRUCTURAL HYPOTHESIS, not a theorem here. So this is a floor on repositioning moves in the
          "produce-on-top + move" abstraction, not yet on the full consume/produce schedule.
      (2) BRIDGE CAVEAT (identical posture to NlcsFloor.lean / MovementFloor.lean / Floor.lean): `mv d`
          is exactly the main-stack effect of `Op.ROLL d` (see `MovementFloor.moveToTop_faithful_ROLL`),
          but that the scheduler's emitter realizes EXACTLY these move-to-top ops (not a copy+drop
          reroute) is asserted-by-construction of the emitter, NOT a proven property of `emit`.
    Consequently this AUDITS "how much operand repositioning is FORCED by the entry→exit ordering of a
    computing body," a strictly larger applicability than the permutation-only NlcsFloor — but the
    consumption-aware tight shuffle floor stays OPEN research, by design.

  ★ REUSE. This file is FROZEN-CORE + ADDITIVE: it imports `LeanBCH.Opt.NlcsFloor` and reuses its
    proven lemmas verbatim — `MovementFloor.moveToTop`, `NlcsFloor.filter_moveToTop_inv`,
    `NlcsFloor.nodup_length_le`, `NlcsFloor.lcsLen`, `NlcsFloor.lcs_dominates`. Only the value-producing
    run (`runV`), its move-trace (`movedV`), and the produce-aware invariance are NEW. Lean 4.31 core,
    NO mathlib; α := Nat, distinct entry values (hypothesis `s.Nodup`); head = TOP of stack.

  ★ STATUS: REGISTERED HEADLINE (a promised deliverable / root of the necessity closure — see
    `Meta/Headlines.lean`), hence LOAD-BEARING as a headline. It is a LEAF floor theorem: no OTHER proof
    in the tree consumes it. It is the sharp combinatorial reference for the value-producing movement
    floor, subject to the two open items above — the P3 deliverable: a PROVEN weak/partial bound + an
    HONEST gap. (It bounds the abstract mv/pr machine; it is NOT yet instantiated on the crown DAG, so
    it does not by itself certify the shipped shuffle at-floor — see the openParts in the header.)
-/
import LeanBCH.Opt.NlcsFloor

namespace LeanBCH.Opt
namespace MovementFloorDag

open LeanBCH.Opt.MovementFloor (moveToTop)
open List

/-- The counting stack: reuse the movement floor's `Stack` (`= List Nat`, head = top). -/
abbrev Stack := MovementFloor.Stack

/-! ## The value-producing move machine.

    Two instruction kinds over `Stack`:
    * `mv d`  — MOVEMENT: bring the value at depth `d` to the top (`moveToTop`, height-neutral;
                the SAME primitive as ROLL/SWAP/ROT — see `MovementFloor.moveToTop_faithful_ROLL`).
    * `pr w`  — PRODUCE: push a FRESH computed value `w` on the top (height +1; abstracts an
                essential OP_MUL/OP_ADD landing its result). Produce ops cost 0 MOVEMENT ops. -/
inductive Op where
  | mv (d : Nat)
  | pr (w : Nat)
deriving DecidableEq

/-- One step of the value-producing machine. -/
def stepV (s : Stack) : Op → Stack
  | .mv d => moveToTop d s
  | .pr w => w :: s

/-- Run a program (list of ops), folding `stepV` (head-first, like `runMoves`). -/
def runV : List Op → Stack → Stack
  | [],      s => s
  | o :: os, s => runV os (stepV s o)

/-- The number of MOVEMENT ops in a program (produce ops are free). -/
def mvCount : List Op → Nat
  | []             => 0
  | (.mv _) :: os  => 1 + mvCount os
  | (.pr _) :: os  => mvCount os

/-- Ordered list of values successfully lifted to the top by a MOVEMENT op, one per successful `mv`
    (produce ops contribute nothing to movement). The value-producing analog of `NlcsFloor.moved`. -/
def movedV : List Op → Stack → List Nat
  | [],            _ => []
  | (.mv d) :: os, s => (match s[d]? with | some v => [v] | none => []) ++ movedV os (moveToTop d s)
  | (.pr w) :: os, s => movedV os (w :: s)

/-- The predicate carving out the UNTOUCHED ENTRY values: those still in the entry `s` AND never
    lifted by a movement op. `v ∈ s` is essential — it is what makes a `pr`-produced (fresh, ∉ s)
    value filter AWAY, so the untouched set is preserved across produce ops (where NlcsFloor's
    `∉ moved` predicate would wrongly retain fresh values on the exit stack). -/
def keepP (prog : List Op) (s : Stack) : Nat → Bool :=
  fun v => decide (v ∈ s ∧ v ∉ movedV prog s)

/-- The untouched entry values, IN ENTRY ORDER — a common subsequence of entry & exit. -/
def commonU (prog : List Op) (s : Stack) : Stack := s.filter (keepP prog s)

/-- The touched entry values (moved at least once), in entry order. -/
def touched (prog : List Op) (s : Stack) : Stack :=
  s.filter (fun v => decide (v ∈ movedV prog s))

/-! ## (A) The common-subsequence core: `keepP` is invariant across the WHOLE value-producing run. -/

/-- ★ FILTER INVARIANCE over a value-producing run, if every MOVED value and every PRODUCED value
    satisfies `p = false`. The `mv` case reuses `NlcsFloor.filter_moveToTop_inv` verbatim; the NEW
    `pr` case: pushing a fresh `w` with `p w = false` leaves `filter p` unchanged. -/
theorem filter_runV_inv (p : Nat → Bool) :
    ∀ (prog : List Op) (s : Stack),
      (∀ v ∈ movedV prog s, p v = false) →
      (∀ w, Op.pr w ∈ prog → p w = false) →
      (runV prog s).filter p = s.filter p := by
  intro prog
  induction prog with
  | nil => intro s _ _; rfl
  | cons o os ih =>
      intro s hmov hpr
      cases o with
      | mv d =>
          rw [runV]
          cases hd : s[d]? with
          | none =>
              have hmt : moveToTop d s = s := by simp only [moveToTop, hd]
              have hstep : stepV s (Op.mv d) = s := by simp only [stepV, hmt]
              have hmoved : movedV (Op.mv d :: os) s = movedV os s := by
                simp only [movedV, hd, hmt, List.nil_append]
              rw [hstep]
              apply ih s
              · intro v hv; exact hmov v (by rw [hmoved]; exact hv)
              · intro w hw; exact hpr w (List.mem_cons_of_mem _ hw)
          | some v =>
              have hstep : stepV s (Op.mv d) = moveToTop d s := by simp only [stepV]
              have hpv : p v = false := by
                apply hmov
                simp only [movedV, hd, List.singleton_append]
                exact List.mem_cons_self
              have htail : ∀ v' ∈ movedV os (moveToTop d s), p v' = false := by
                intro v' hv'
                apply hmov
                simp only [movedV, hd, List.singleton_append]
                exact List.mem_cons_of_mem v hv'
              have hprtail : ∀ w, Op.pr w ∈ os → p w = false :=
                fun w hw => hpr w (List.mem_cons_of_mem _ hw)
              rw [hstep, ih (moveToTop d s) htail hprtail,
                  NlcsFloor.filter_moveToTop_inv p s d v hd hpv]
      | pr w =>
          rw [runV]
          have hstep : stepV s (Op.pr w) = w :: s := by simp only [stepV]
          have hpw : p w = false := hpr w List.mem_cons_self
          have hmoved : movedV (Op.pr w :: os) s = movedV os (w :: s) := by simp only [movedV]
          have htail : ∀ v' ∈ movedV os (w :: s), p v' = false := by
            intro v' hv'; exact hmov v' (by rw [hmoved]; exact hv')
          have hprtail : ∀ w', Op.pr w' ∈ os → p w' = false :=
            fun w' hw' => hpr w' (List.mem_cons_of_mem _ hw')
          rw [hstep, ih (w :: s) htail hprtail]
          simp [hpw]

/-- Every moved value forces `keepP = false` (it is not an untouched entry value). -/
theorem keepP_moved_false (prog : List Op) (s : Stack) :
    ∀ v ∈ movedV prog s, keepP prog s v = false := by
  intro v hv
  simp only [keepP, decide_eq_false_iff_not]
  exact fun h => h.2 hv

/-- Every produced FRESH value (label ∉ entry `s`) forces `keepP = false`. -/
theorem keepP_pr_false (prog : List Op) (s : Stack)
    (hfresh : ∀ w, Op.pr w ∈ prog → w ∉ s) :
    ∀ w, Op.pr w ∈ prog → keepP prog s w = false := by
  intro w hw
  simp only [keepP, decide_eq_false_iff_not]
  exact fun h => (hfresh w hw) h.1

/-- ★ `commonU` is a SUBSEQUENCE of the ENTRY stack (immediate: it is a filter of `s`). -/
theorem commonU_sub_entry (prog : List Op) (s : Stack) : commonU prog s <+ s :=
  List.filter_sublist

/-- ★ `commonU` is a SUBSEQUENCE of the value-producing EXIT stack — the machine-checked
    "untouched inputs keep their relative order, even across fresh-value production". -/
theorem commonU_sub_exit (prog : List Op) (s : Stack)
    (hfresh : ∀ w, Op.pr w ∈ prog → w ∉ s) :
    commonU prog s <+ runV prog s := by
  have he : (runV prog s).filter (keepP prog s) = commonU prog s :=
    filter_runV_inv (keepP prog s) prog s (keepP_moved_false prog s) (keepP_pr_false prog s hfresh)
  rw [← he]
  exact List.filter_sublist

/-! ## (A) The counting: n − |commonU| ≤ #movement-ops. -/

/-- Length partition of two filters that are COMPLEMENTARY on the list's elements. -/
theorem filter_len_compl_on (a b : Nat → Bool) :
    ∀ l : List Nat, (∀ x ∈ l, a x = !(b x)) →
      (l.filter a).length + (l.filter b).length = l.length := by
  intro l
  induction l with
  | nil => intro _; rfl
  | cons x xs ih =>
      intro h
      have hx : a x = !(b x) := h x List.mem_cons_self
      have hih := ih (fun y hy => h y (List.mem_cons_of_mem x hy))
      cases hb : b x with
      | true  => simp [hx, hb, List.length_cons]; omega
      | false => simp [hx, hb, List.length_cons]; omega

/-- `touched.length + commonU.length = s.length`. -/
theorem len_split (prog : List Op) (s : Stack) :
    (touched prog s).length + (commonU prog s).length = s.length := by
  unfold touched commonU
  apply filter_len_compl_on
  intro x hx
  show decide (x ∈ movedV prog s) = !(keepP prog s x)
  by_cases hm : x ∈ movedV prog s
  · have hkf : keepP prog s x = false := by
      simp only [keepP, decide_eq_false_iff_not]; exact fun h => h.2 hm
    rw [hkf]; simp [hm]
  · have hkt : keepP prog s x = true := by
      simp only [keepP, decide_eq_true_eq]; exact ⟨hx, hm⟩
    rw [hkt]; simp [hm]

/-- Each MOVEMENT op lifts ≤ 1 value; produce ops lift none ⇒ `#moved ≤ #movement-ops`. -/
theorem movedV_len_le : ∀ (prog : List Op) (s : Stack), (movedV prog s).length ≤ mvCount prog := by
  intro prog
  induction prog with
  | nil => intro s; simp [movedV, mvCount]
  | cons o os ih =>
      intro s
      cases o with
      | mv d =>
          cases hd : s[d]? with
          | none =>
              have he : movedV (Op.mv d :: os) s = movedV os (moveToTop d s) := by
                simp only [movedV, hd, List.nil_append]
              rw [he]; have := ih (moveToTop d s); simp only [mvCount]; omega
          | some v =>
              have he : movedV (Op.mv d :: os) s = v :: movedV os (moveToTop d s) := by
                simp only [movedV, hd, List.singleton_append]
              rw [he, List.length_cons]; have := ih (moveToTop d s); simp only [mvCount]; omega
      | pr w =>
          have he : movedV (Op.pr w :: os) s = movedV os (w :: s) := by simp only [movedV]
          rw [he]; have := ih (w :: s); simp only [mvCount]; omega

/-- ★★ (A) THE CORE BOUND (common-subsequence form, no LCS): `n − |commonU| ≤ #movement-ops`. -/
theorem movement_lb_common (prog : List Op) (s : Stack) (hnd : s.Nodup) :
    s.length - (commonU prog s).length ≤ mvCount prog := by
  have hsplit := len_split prog s
  have h1 : s.length - (commonU prog s).length = (touched prog s).length := by omega
  rw [h1]
  have hnd_t : (touched prog s).Nodup := List.Nodup.sublist List.filter_sublist hnd
  have hsub : ∀ x ∈ touched prog s, x ∈ movedV prog s := by
    intro x hx
    unfold touched at hx
    rw [List.mem_filter] at hx
    exact of_decide_eq_true hx.2
  have hle1 := NlcsFloor.nodup_length_le (touched prog s) (movedV prog s) hnd_t hsub
  have hle2 := movedV_len_le prog s
  omega

/-! ## (B) LCS-packaging via a domination parameter (reusing `NlcsFloor.lcs_dominates`). -/

/-- ★ (B) If `L` dominates every common subsequence of entry & value-producing exit, then
    `n − L ≤ #movement-ops`. -/
theorem movement_lb_of_dom (prog : List Op) (s : Stack) (hnd : s.Nodup)
    (hfresh : ∀ w, Op.pr w ∈ prog → w ∉ s) (L : Nat)
    (hdom : ∀ U, U <+ s → U <+ runV prog s → U.length ≤ L) :
    s.length - L ≤ mvCount prog := by
  have hUL : (commonU prog s).length ≤ L :=
    hdom _ (commonU_sub_entry prog s) (commonU_sub_exit prog s hfresh)
  have hcore := movement_lb_common prog s hnd
  omega

/-! ## THE TARGET. -/

/-- ★★★ THE VALUE-PRODUCING MOVEMENT LOWER BOUND: any program of movement (`mv`) and produce (`pr`)
    ops on a `Nodup` entry `s`, whose produced values are FRESH (labels ∉ `s`), uses at least
    `n − LCS(entry, exit)` MOVEMENT ops (produce ops are free). This is the movement floor for a
    body that COMPUTES — the case where `NlcsFloor.movement_lower_bound_nlcs` is vacuous. -/
theorem movement_lower_bound_dag (prog : List Op) (s : Stack) (hnd : s.Nodup)
    (hfresh : ∀ w, Op.pr w ∈ prog → w ∉ s) :
    s.length - NlcsFloor.lcsLen s (runV prog s) ≤ mvCount prog := by
  apply movement_lb_of_dom prog s hnd hfresh (NlcsFloor.lcsLen s (runV prog s))
  intro U hU1 hU2
  exact NlcsFloor.lcs_dominates s (runV prog s) U hU1 hU2

/-! ## NON-VACUITY — a genuinely VALUE-PRODUCING witness where the bound FIRES POSITIVELY and TIGHTLY.

    Entry `s = [1,2,3,4]` (4 distinct input operands). Program `[mv 3, pr 5, mv 3]` (2 movement ops
    + 1 produce): lift depth-3 (value 4) to top, PRODUCE the fresh value 5, lift depth-3 again.
    Exit = `[2, 5, 4, 1, 3]` — it CONTAINS the freshly-produced label 5 (∉ entry), so it is NOT a
    permutation of the entry: `NlcsFloor.movement_lower_bound_nlcs` cannot be instantiated for this
    exit (no move-only `runMoves` program yields it), yet THIS bound fires: `4 − 2 = 2 ≤ 2` (tight). -/

/-- The witness genuinely PRODUCES a fresh value: label 5 (∉ entry) is on the exit stack. -/
theorem witness_produces_fresh : (5 : Nat) ∈ runV [Op.mv 3, Op.pr 5, Op.mv 3] [1, 2, 3, 4] := by
  decide

/-- The witness exit stack, computed. -/
theorem witness_run : runV [Op.mv 3, Op.pr 5, Op.mv 3] [1, 2, 3, 4] = [2, 5, 4, 1, 3] := by decide

/-- The entry is `Nodup`. -/
theorem witness_nodup : ([1, 2, 3, 4] : Stack).Nodup := by decide

/-- The produced values are FRESH (the sole hypothesis): `5 ∉ [1,2,3,4]`. -/
theorem witness_fresh : ∀ w, Op.pr w ∈ [Op.mv 3, Op.pr 5, Op.mv 3] → w ∉ ([1, 2, 3, 4] : Stack) := by
  intro w hw
  simp only [List.mem_cons, List.mem_nil_iff, or_false] at hw
  rcases hw with h | h | h
  · exact absurd h (by simp)
  · injection h with h5; subst h5; decide
  · exact absurd h (by simp)

/-- ★ THE VALUE-PRODUCING MOVEMENT BOUND FIRES on the witness: `4 − LCS = 2 ≤ 2` movement ops. -/
theorem witness_dag_bound :
    ([1, 2, 3, 4] : Stack).length
        - NlcsFloor.lcsLen [1, 2, 3, 4] (runV [Op.mv 3, Op.pr 5, Op.mv 3] [1, 2, 3, 4])
      ≤ mvCount [Op.mv 3, Op.pr 5, Op.mv 3] :=
  movement_lower_bound_dag [Op.mv 3, Op.pr 5, Op.mv 3] [1, 2, 3, 4] witness_nodup witness_fresh

/-- Numerically: the bound value = the achieved movement-op count = 2 (TIGHT, met with equality),
    and there is exactly 1 (free) produce op — so the movement floor is non-degenerate and positive. -/
theorem witness_numbers :
    ([1, 2, 3, 4] : Stack).length
        - NlcsFloor.lcsLen [1, 2, 3, 4] (runV [Op.mv 3, Op.pr 5, Op.mv 3] [1, 2, 3, 4]) = 2
  ∧ mvCount [Op.mv 3, Op.pr 5, Op.mv 3] = 2 := by
  rw [witness_run]; refine ⟨?_, by decide⟩; simp [NlcsFloor.lcsLen]

end MovementFloorDag
end LeanBCH.Opt
