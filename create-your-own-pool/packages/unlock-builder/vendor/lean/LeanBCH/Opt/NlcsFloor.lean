/-
  n-LCS MOVEMENT FLOOR — a machine-checked TIGHT lower bound on stack-MOVEMENT ops.

  ★ THE CLAIM (strictly sharper than MovementFloor's disjoint-inverted-pairs bound):
      #move-ops  ≥  n − LCS(entry, exit)
  where n = entry.length and LCS is the longest common subsequence of the entry and exit
  value-orderings. Each `moveToTop` op lifts EXACTLY ONE value to the top; a value NEVER
  lifted keeps its relative position, so the set U of untouched values is a COMMON
  SUBSEQUENCE of both the entry and the exit stack, hence |U| ≤ LCS. The distinct touched
  values number ≥ n − |U| ≥ n − LCS, and each needs ≥ 1 (first-touching) op ⇒ the bound.
  Only the ACHIEVABILITY (optimality) direction is NP-hard; THIS lower bound is elementary
  and fully constructive.

  ★ SUPERSESSION (relation to MovementFloor.lean). This TIGHT n-LCS bound SUPERSEDES the
  disjoint-inverted-pairs bound (`MovementFloor.movement_lower_bound`) for pure-permutation
  movement floors: any `m` pairwise-disjoint order-inverted pairs force `m` distinct touched
  values, and those `m` values keep the untouched set to `≤ n − m`, so `n − LCS ≥ n − |U| ≥ m`
  — the n-LCS floor is never weaker and is TIGHT (met with equality, `4 − LCS([1,2,3,4],[4,3,2,1]) = 3`
  ops on the reversal witness below, where the disjoint-pairs bound tops out at `⌊n/2⌋ = 2`).
  BOTH are kept: the disjoint-pairs bound is a simpler, still-valid counting argument;
  the n-LCS bound is the sharp per-boundary movement floor. `MovementFloor` is NOT deleted.

  Structure (3 layers, all 0-sorry):
    (A) CORE / common-subsequence form: movement_lb_untouched — carries all combinatorial content.
    (B) LCS-packaging via a domination parameter: movement_lb_of_dom.
    (C) Instantiation with the LCS DP (lcs_dominates) ⇒ the TARGET movement_lower_bound_nlcs.

  ★ INTEGRATION (this file): adapted from the isolated scratch proof into the main verified-
  recompiler project. It REUSES the SAME op-model as `MovementFloor.lean` — `MovementFloor.moveToTop`
  / `MovementFloor.runMoves` (built on the project's real `LeanBCH.Opt.removeNth`, the deletion
  `Op.ROLL` uses, over `LeanBCH.Opt.Floor.Stack = List Nat`) — so the loose disjoint-pairs floor and
  this tight n-LCS floor are provably about the SAME abstract move-to-top machine. Model: Lean 4.31
  core, NO mathlib; α := Nat, distinct values (the hypothesis `s.Nodup`). Head = TOP. The theorem
  lives in the nested `LeanBCH.Opt.NlcsFloor` namespace (parallel to `LeanBCH.Opt.MovementFloor`).

  HONEST BRIDGE CAVEAT (identical to MovementFloor.lean / Floor.lean): this bounds the ABSTRACT
  moveToTop op-count; that the scheduler's emit realizes EXACTLY these moves is asserted-by-
  construction of the emitter, NOT a proven property of `emit` — same posture as MovementFloor/Floor.

  ★ STATUS: REFERENCE LEMMA — NOT LOAD-BEARING. `movement_lower_bound_nlcs` has no downstream proof
  consumer; it is the sharp combinatorial reference for the per-boundary movement floor, NOT a live
  lower bound on the optimizer's real byte output (that link is the unproven bridge caveat above).
-/
import LeanBCH.Opt.Basic
import LeanBCH.Opt.Floor
import LeanBCH.Opt.MovementFloor

namespace LeanBCH.Opt
namespace NlcsFloor

open List
-- Reuse the SAME move-to-top model as MovementFloor.lean (moveToTop / runMoves / Stack), which is
-- built on `LeanBCH.Opt.removeNth`. `moveToTop_faithful_ROLL` + the SWAP/ROT/ROLL examples grounding
-- this model to `Op.ROLL` live in MovementFloor.lean; both floors quantify the same op-count.
open MovementFloor (moveToTop runMoves Stack)

/-! ## The trace of moved values, and the untouched / touched split. -/

/-- Ordered list of values successfully lifted to the top, one per successful op. -/
def moved : List Nat → Stack → List Nat
  | [],      _ => []
  | d :: ds, s => (match s[d]? with | some v => [v] | none => []) ++ moved ds (moveToTop d s)

/-- The untouched values, IN ENTRY ORDER: those never lifted. -/
def untouched (prog : List Nat) (s : Stack) : Stack :=
  s.filter (fun v => decide (v ∉ moved prog s))

/-- The (distinct, since `s` is Nodup) touched values, in entry order. -/
def touched (prog : List Nat) (s : Stack) : Stack :=
  s.filter (fun v => decide (v ∈ moved prog s))

/-! ## (A) The common-subsequence core.

    Generalise MovementFloor's `proj_invariant` (a 2-element projection) to an arbitrary
    boolean predicate `p`: moving a value with `p = false` never changes `filter p`. -/

/-- ★ FILTER INVARIANCE under one op whose moved head satisfies `p v = false`. -/
theorem filter_moveToTop_inv (p : Nat → Bool) (s : Stack) (d v : Nat)
    (hv : s[d]? = some v) (hp : p v = false) :
    (moveToTop d s).filter p = s.filter p := by
  obtain ⟨hd, hval⟩ := List.getElem?_eq_some_iff.mp hv
  have e1 : s = s.take d ++ (v :: s.drop (d + 1)) := by
    have hc := List.getElem_cons_drop hd
    rw [hval] at hc
    rw [hc, List.take_append_drop]
  have hmt : moveToTop d s = v :: (s.take d ++ s.drop (d + 1)) := by
    simp only [moveToTop, hv, removeNth]
  rw [hmt]
  conv => rhs; rw [e1]
  simp [List.filter_append, hp]

/-- ★ FILTER INVARIANCE over the WHOLE run, if every moved value satisfies `p = false`. -/
theorem filter_runMoves_inv (p : Nat → Bool) :
    ∀ (prog : List Nat) (s : Stack), (∀ v ∈ moved prog s, p v = false) →
      (runMoves prog s).filter p = s.filter p := by
  intro prog
  induction prog with
  | nil => intro s _; rfl
  | cons d ds ih =>
      intro s h
      rw [runMoves]
      cases hd : s[d]? with
      | none =>
          have hmt : moveToTop d s = s := by simp only [moveToTop, hd]
          have hmoved : moved (d :: ds) s = moved ds s := by
            simp only [moved, hd, hmt, List.nil_append]
          rw [hmt]
          exact ih s (fun v hv => h v (by rw [hmoved]; exact hv))
      | some v =>
          have hpv : p v = false := by
            apply h
            simp only [moved, hd, List.singleton_append]
            exact List.mem_cons_self
          have htail : ∀ w ∈ moved ds (moveToTop d s), p w = false := by
            intro w hw
            apply h
            simp only [moved, hd, List.singleton_append]
            exact List.mem_cons_of_mem v hw
          rw [ih (moveToTop d s) htail, filter_moveToTop_inv p s d v hd hpv]

/-- Every touched value forces `decide (· ∉ moved) = false`, the hypothesis of the invariance. -/
theorem moved_false (prog : List Nat) (s : Stack) :
    ∀ v ∈ moved prog s, decide (v ∉ moved prog s) = false := by
  intro v hv
  rw [decide_eq_false_iff_not]
  exact fun h => h hv

/-- ★ `untouched` is a SUBSEQUENCE of the ENTRY stack. -/
theorem untouched_sub_entry (prog : List Nat) (s : Stack) : untouched prog s <+ s :=
  List.filter_sublist

/-- ★ `untouched` is a SUBSEQUENCE of the EXIT stack — the machine-checked
    "untouched values keep their relative order", for the WHOLE set at once. -/
theorem untouched_sub_exit (prog : List Nat) (s : Stack) :
    untouched prog s <+ runMoves prog s := by
  have he : (runMoves prog s).filter (fun v => decide (v ∉ moved prog s)) = untouched prog s :=
    filter_runMoves_inv _ prog s (moved_false prog s)
  rw [← he]
  exact List.filter_sublist

/-! ## (A) The counting: n − |untouched| ≤ #ops. -/

/-- Length partition of a filter and its complement. -/
theorem filter_len_compl (q : Nat → Bool) :
    ∀ l : List Nat, (l.filter q).length + (l.filter (fun x => !q x)).length = l.length := by
  intro l
  induction l with
  | nil => rfl
  | cons x xs ih =>
      cases hq : q x with
      | true  => simp [hq, List.length_cons]; omega
      | false => simp [hq, List.length_cons]; omega

/-- `touched.length + untouched.length = s.length`. -/
theorem len_split (prog : List Nat) (s : Stack) :
    (touched prog s).length + (untouched prog s).length = s.length := by
  have hpu : (fun v => decide (v ∉ moved prog s))
           = (fun v => !(decide (v ∈ moved prog s))) := by
    funext v; rw [decide_not]
  unfold touched untouched
  rw [hpu]
  exact filter_len_compl (fun v => decide (v ∈ moved prog s)) s

/-- A Nodup list all of whose elements lie in `m` is no longer than `m` (pigeonhole). -/
theorem nodup_length_le :
    ∀ (l m : List Nat), l.Nodup → (∀ x ∈ l, x ∈ m) → l.length ≤ m.length := by
  intro l
  induction l with
  | nil => intro m _ _; simp
  | cons x xs ih =>
      intro m hnd hsub
      have hxm : x ∈ m := hsub x List.mem_cons_self
      obtain ⟨hxnotin, hxsnd⟩ := List.nodup_cons.mp hnd
      have hsub' : ∀ y ∈ xs, y ∈ m.erase x := by
        intro y hy
        have hyx : y ≠ x := by intro heq; subst heq; exact hxnotin hy
        exact (List.mem_erase_of_ne hyx).mpr (hsub y (List.mem_cons_of_mem x hy))
      have hle := ih (m.erase x) hxsnd hsub'
      have herase : (m.erase x).length = m.length - 1 := List.length_erase_of_mem hxm
      have hpos : 0 < m.length := List.length_pos_of_mem hxm
      simp only [List.length_cons]
      omega

/-- Each op lifts ≤ 1 value ⇒ `#moved ≤ #ops`. -/
theorem moved_len_le : ∀ (prog : List Nat) (s : Stack), (moved prog s).length ≤ prog.length := by
  intro prog
  induction prog with
  | nil => intro s; simp [moved]
  | cons d ds ih =>
      intro s
      cases hd : s[d]? with
      | none =>
          have he : moved (d :: ds) s = moved ds (moveToTop d s) := by
            simp only [moved, hd, List.nil_append]
          rw [he, List.length_cons]
          have := ih (moveToTop d s); omega
      | some v =>
          have he : moved (d :: ds) s = v :: moved ds (moveToTop d s) := by
            simp only [moved, hd, List.singleton_append]
          rw [he, List.length_cons, List.length_cons]
          have := ih (moveToTop d s); omega

/-- ★★ (A) THE CORE BOUND (common-subsequence form, no LCS): `n − |untouched| ≤ #ops`. -/
theorem movement_lb_untouched (prog : List Nat) (s : Stack) (hnd : s.Nodup) :
    s.length - (untouched prog s).length ≤ prog.length := by
  have hsplit := len_split prog s
  have h1 : s.length - (untouched prog s).length = (touched prog s).length := by omega
  rw [h1]
  have hnd_t : (touched prog s).Nodup := List.Nodup.sublist List.filter_sublist hnd
  have hsub : ∀ x ∈ touched prog s, x ∈ moved prog s := by
    intro x hx
    unfold touched at hx
    rw [List.mem_filter] at hx
    exact of_decide_eq_true hx.2
  have hle1 := nodup_length_le (touched prog s) (moved prog s) hnd_t hsub
  have hle2 := moved_len_le prog s
  omega

/-! ## (B) LCS-packaging via a domination parameter. -/

/-- ★ (B) If `L` dominates every common subsequence of entry & exit, then `n − L ≤ #ops`. -/
theorem movement_lb_of_dom (prog : List Nat) (s : Stack) (hnd : s.Nodup) (L : Nat)
    (hdom : ∀ U, U <+ s → U <+ runMoves prog s → U.length ≤ L) :
    s.length - L ≤ prog.length := by
  have hUL : (untouched prog s).length ≤ L :=
    hdom _ (untouched_sub_entry prog s) (untouched_sub_exit prog s)
  have hcore := movement_lb_untouched prog s hnd
  have hmono : s.length - L ≤ s.length - (untouched prog s).length :=
    Nat.sub_le_sub_left hUL s.length
  omega

/-! ## (C) The LCS DP and its domination. -/

/-- Longest common subsequence length (classic DP; always taking the triple max so that
    domination follows from `le_max` alone, no ±1 monotonicity lemma). -/
def lcsLen : List Nat → List Nat → Nat
  | [],      _       => 0
  | _,       []      => 0
  | a :: as, b :: bs =>
      Nat.max (if a == b then 1 + lcsLen as bs else 0)
        (Nat.max (lcsLen (a :: as) bs) (lcsLen as (b :: bs)))
termination_by xs ys => xs.length + ys.length

theorem lcsLen_cons (a b : Nat) (as bs : List Nat) :
    lcsLen (a :: as) (b :: bs)
      = Nat.max (if a == b then 1 + lcsLen as bs else 0)
          (Nat.max (lcsLen (a :: as) bs) (lcsLen as (b :: bs))) := by
  simp only [lcsLen]

/-- ★★ (C) DOMINATION: every common subsequence is no longer than the DP value. -/
theorem lcs_dominates :
    ∀ (xs ys U : List Nat), U <+ xs → U <+ ys → U.length ≤ lcsLen xs ys
  | [],      _,       U, hx, _  => by rw [List.sublist_nil.mp hx]; simp [lcsLen]
  | (_::_),  [],      U, _,  hy => by rw [List.sublist_nil.mp hy]; simp [lcsLen]
  | (a::as), (b::bs), U, hx, hy => by
      rw [lcsLen_cons]
      have hxc := List.sublist_cons_iff.mp hx
      have hyc := List.sublist_cons_iff.mp hy
      rcases hxc with hxl | ⟨r1, hUeq1, hr1⟩
      · -- drop a: U <+ as, so bound by lcsLen as (b::bs)
        have := lcs_dominates as (b :: bs) U hxl hy
        exact Nat.le_trans this (Nat.le_trans (Nat.le_max_right _ _) (Nat.le_max_right _ _))
      · rcases hyc with hyl | ⟨r2, hUeq2, hr2⟩
        · -- drop b: U <+ bs, so bound by lcsLen (a::as) bs
          have := lcs_dominates (a :: as) bs U hx hyl
          exact Nat.le_trans this (Nat.le_trans (Nat.le_max_left _ _) (Nat.le_max_right _ _))
        · -- keep both: U = a::r1 = b::r2 ⇒ a = b, r1 = r2
          subst hUeq1
          injection hUeq2 with hab hr12
          have hbeq : (a == b) = true := by rw [hab]; exact beq_self_eq_true b
          have hr1' : r1 <+ bs := by rw [hr12]; exact hr2
          have hrec := lcs_dominates as bs r1 hr1 hr1'
          simp only [List.length_cons, hbeq, if_true]
          exact Nat.le_trans (by omega) (Nat.le_max_left _ _)
  termination_by xs ys _ => xs.length + ys.length

/-! ## THE TARGET. -/

/-- ★★★ THE n-LCS MOVEMENT LOWER BOUND: any move-to-top program on a Nodup entry uses at
    least `n − LCS(entry, exit)` ops. The SHARP per-boundary movement floor; supersedes
    (but does not replace) `MovementFloor.movement_lower_bound`. -/
theorem movement_lower_bound_nlcs (prog : List Nat) (s : Stack) (hnd : s.Nodup) :
    s.length - lcsLen s (runMoves prog s) ≤ prog.length := by
  apply movement_lb_of_dom prog s hnd (lcsLen s (runMoves prog s))
  intro U hU1 hU2
  exact lcs_dominates s (runMoves prog s) U hU1 hU2

/-! ## NON-VACUITY — reversal n = 4, LCS = 1, bound = 3, ACHIEVED with equality (tight). -/

/-- The witness program `[1,2,3]` reverses `[1,2,3,4]` in 3 ops (the minimum). -/
theorem witness_run : runMoves [1, 2, 3] [1, 2, 3, 4] = [4, 3, 2, 1] := by decide

/-- LCS of a distinct sequence and its reverse is 1. -/
example : lcsLen [1, 2, 3, 4] [4, 3, 2, 1] = 1 := by simp [lcsLen]

/-- The entry is Nodup. -/
theorem witness_nodup : ([1, 2, 3, 4] : Stack).Nodup := by decide

/-- ★ THE n-LCS BOUND FIRES and is MET WITH EQUALITY: `4 − 1 = 3 ≤ 3`. -/
theorem witness_nlcs_bound :
    ([1, 2, 3, 4] : Stack).length - lcsLen [1, 2, 3, 4] (runMoves [1, 2, 3] [1, 2, 3, 4])
      ≤ ([1, 2, 3] : List Nat).length :=
  movement_lower_bound_nlcs [1, 2, 3] [1, 2, 3, 4] witness_nodup

/-- Numerically: bound value = achieved op-count = 3 (tight). This same reversal makes the
    disjoint-inverted-pairs bound (`MovementFloor`) top out at 2 < 3, exhibiting the gap the
    n-LCS floor closes. -/
example :
    ([1, 2, 3, 4] : Stack).length - lcsLen [1, 2, 3, 4] (runMoves [1, 2, 3] [1, 2, 3, 4]) = 3
  ∧ ([1, 2, 3] : List Nat).length = 3 := by
  rw [witness_run]; refine ⟨?_, by decide⟩; simp [lcsLen]

end NlcsFloor
end LeanBCH.Opt
