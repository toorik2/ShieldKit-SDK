/-
  MOVEMENT-FLOOR — a machine-checked LOWER BOUND on stack-MOVEMENT (reorder) instructions.

  ★ THE CLAIM: reproducing a block-exit stack layout that is a non-trivial PERMUTATION of the
  entry layout forces a minimum number of pure reordering ops. Concretely: if `m` pairwise-
  DISJOINT value-pairs are ORDER-INVERTED between entry and exit, then ANY straight-line program
  of move-to-top ops (the abstraction of the scheduler's SWAP/ROT/ROLL `moveOps`) that realises
  that exit uses ≥ `m` movement ops. This is the MOVEMENT analog of the COPY-FLOOR (Floor.lean):
  a pure conservation / counting argument, proved over a minimal move-to-top machine.

  ★ WHY IT MATTERS: the COPY-FLOOR bounds duplications (fan-out); it does NOT bound the
  reordering cost (ROLL/SWAP/deep-PICK), which the demolition called OPEN (optimal stack
  scheduling is NP-hard). This file proves a genuine, HONEST movement bound — quantifying how
  much of the empirical byte "slack" is FORCED by permutation structure. It is deliberately
  LOOSE vs the true optimum (disjoint-inverted-pairs ≤ n − LCS(entry,exit); see the tightness
  note at the end), but it is real: it is met with EQUALITY on a concrete witness.

  ★ INTEGRATION (this file): adapted from the isolated scratch proof into the main verified-
  recompiler project. It REUSES the real project defs — `Recompiler.removeNth` (Basic.lean:28,
  the SAME order-preserving deletion `Op.ROLL` uses) and `Recompiler.Floor.Stack` (`List Nat`,
  the copy-floor's counting stack) — rather than private copies, and the counting model mirrors
  `Floor.lean`'s `evc`/`conserve`/`copy_floor` style. Model: Lean 4.31 core, NO mathlib; α := Nat,
  distinct values; head = TOP of stack, same convention as Basic.lean. The theorem lives in the
  nested `Recompiler.MovementFloor` namespace (parallel to `Recompiler.Floor`).
-/
import Recompiler.Basic
import Recompiler.Floor

namespace Recompiler
namespace MovementFloor

/-! ## The move-to-top counting model. -/

/-- The counting stack: reuse the copy-floor's `Recompiler.Floor.Stack` (`= List Nat`). -/
abbrev Stack := Floor.Stack

/-- The MOVEMENT primitive: bring the value at depth `d` to the TOP, deleting it from its old
    position (an order-preserving deletion). This abstracts the whole `moveOps` family of the
    scheduler (`Scheduler.lean`: SWAP = depth 1, ROT = depth 2, ROLL n = depth n). Uses the
    project's real `Recompiler.removeNth` — the SAME deletion `Op.ROLL` uses (Basic.lean:73).
    Total: an out-of-range depth is a no-op. -/
def moveToTop (d : Nat) (s : Stack) : Stack :=
  match s[d]? with
  | some v => v :: removeNth s d
  | none   => s

/-- A movement PROGRAM is a list of depths; `runMoves` folds it over the stack (like `Floor.run`). -/
def runMoves : List Nat → Stack → Stack
  | [],      s => s
  | d :: ds, s => runMoves ds (moveToTop d s)

/-- Project a stack onto a 2-element value-pair `{a,b}`, recording their RELATIVE ORDER. -/
def proj (a b : Nat) (s : Stack) : Stack := s.filter (fun x => x == a || x == b)

/-- Indicator: is value `v` one of the pair `{a,b}`? (0/1) -/
def inPair (a b v : Nat) : Nat := if v == a || v == b then 1 else 0

/-! ### Faithfulness of `moveToTop` to the real scheduler ops (grounding).
    `moveToTop d` is exactly the main-stack effect of `Op.ROLL d` (Basic.lean:73:
    `some v => some (v :: removeNth s n, a)`, the SAME `removeNth`), and specialises to
    SWAP (d=1) and ROT (d=2). -/

/-- On its success domain, `moveToTop` is the ROLL rewrite `v :: removeNth s d` (Basic.lean ROLL,
    literally the same `Recompiler.removeNth`). -/
theorem moveToTop_faithful_ROLL (d : Nat) (s : Stack) (v : Nat) (h : s[d]? = some v) :
    moveToTop d s = v :: removeNth s d := by
  simp only [moveToTop, h]

/-- SWAP (depth 1): `moveToTop 1 (x::y::s) = y::x::s` — Basic.lean SWAP semantics. -/
example : moveToTop 1 [10, 20, 30, 40] = [20, 10, 30, 40] := by decide
/-- ROT (depth 2): `moveToTop 2 (x::y::z::s) = z::x::y::s` — Basic.lean ROT semantics. -/
example : moveToTop 2 [10, 20, 30, 40] = [30, 10, 20, 40] := by decide
/-- ROLL 3 (depth 3): brings depth-3 value to top, order-preserving deletion below. -/
example : moveToTop 3 [10, 20, 30, 40] = [40, 10, 20, 30] := by decide

/-! ## CONSERVATION CORE: moving a value OUTSIDE the pair preserves the pair's relative order. -/

/-- ★ PROJECTION INVARIANCE: if the moved value `v = s[d]` is NOT in `{a,b}`, then `moveToTop d s`
    leaves the projection onto `{a,b}` unchanged — the relative order of `a` and `b` is conserved.
    (Exact analog of Floor.lean's `cnt_*` conservation, with a 2-element projection in place of a
    count.) Proof: `moveToTop d s = v :: (take d ++ drop (d+1))`; the head `v` filters away
    (`v ∉ {a,b}`), and deleting `v` at depth `d` is an order-preserving deletion, so filtering
    commutes with it. -/
theorem proj_invariant (a b : Nat) (s : Stack) (d v : Nat)
    (hv : s[d]? = some v) (ha : v ≠ a) (hb : v ≠ b) :
    proj a b (moveToTop d s) = proj a b s := by
  obtain ⟨hd, hval⟩ := List.getElem?_eq_some_iff.mp hv
  have hp : (v == a || v == b) = false := by
    simp only [Bool.or_eq_false_iff, beq_eq_false_iff_ne]; exact ⟨ha, hb⟩
  -- `s` split at depth `d`, exposing the moved value `v`.
  have e1 : s = s.take d ++ (v :: s.drop (d + 1)) := by
    have hc := List.getElem_cons_drop hd
    rw [hval] at hc
    rw [hc, List.take_append_drop]
  have hmt : moveToTop d s = v :: (s.take d ++ s.drop (d + 1)) := by
    simp only [moveToTop, hv, removeNth]
  rw [proj, proj, hmt]
  conv => rhs; rw [e1]
  simp [List.filter_append, hp]

/-! ## TOUCH counter: per pair, how many ops move one of the pair's values (trace-based, the
    movement analog of Floor.lean's `evc`). -/

/-- Number of ops along the run whose moved value lies in `{a,b}`. -/
def touch (a b : Nat) : Stack → List Nat → Nat
  | _, []      => 0
  | s, d :: ds =>
      (match s[d]? with | some v => inPair a b v | none => 0)
        + touch a b (moveToTop d s) ds

/-- ★ If NO op touches the pair `{a,b}`, its relative order is invariant end-to-end. -/
theorem touch_zero_proj (a b : Nat) (s : Stack) (prog : List Nat)
    (h : touch a b s prog = 0) : proj a b (runMoves prog s) = proj a b s := by
  induction prog generalizing s with
  | nil => rfl
  | cons d ds ih =>
      rw [runMoves]
      cases hd : s[d]? with
      | none =>
          have hmt : moveToTop d s = s := by simp only [moveToTop, hd]
          have h' : touch a b s ds = 0 := by
            simp only [touch, hd, hmt, Nat.zero_add] at h; exact h
          rw [hmt]; exact ih s h'
      | some v =>
          simp only [touch, hd] at h
          have hpart : inPair a b v = 0 := by omega
          have hrec : touch a b (moveToTop d s) ds = 0 := by omega
          have hcond : (v == a || v == b) = false := by
            unfold inPair at hpart
            cases hcv : (v == a || v == b) with
            | true  => rw [hcv] at hpart; exact absurd hpart (by decide)
            | false => rfl
          obtain ⟨hva, hvb⟩ := Bool.or_eq_false_iff.mp hcond
          have ha : v ≠ a := beq_eq_false_iff_ne.mp hva
          have hb : v ≠ b := beq_eq_false_iff_ne.mp hvb
          have hinv := proj_invariant a b s d v hd ha hb
          rw [ih (moveToTop d s) hrec, hinv]

/-- ★ COROLLARY (per pair): an ORDER-INVERTED pair must be touched by ≥ 1 op. -/
theorem touch_pos_of_inverted (a b : Nat) (s : Stack) (prog : List Nat)
    (hinv : proj a b (runMoves prog s) ≠ proj a b s) : 1 ≤ touch a b s prog := by
  rcases Nat.eq_zero_or_pos (touch a b s prog) with h0 | hpos
  · exact absurd (touch_zero_proj a b s prog h0) hinv
  · exact hpos

/-! ## AGGREGATION over many pairs (mirrors copy_floor's per-value summation; no Finset). -/

/-- Sum of `touch` over a list of pairs. -/
def sumTouch (ps : List (Nat × Nat)) (s : Stack) (prog : List Nat) : Nat :=
  (ps.map (fun P => touch P.1 P.2 s prog)).sum

/-- Number of pairs in `ps` containing value `v` (as a summed indicator). -/
def numContain (ps : List (Nat × Nat)) (v : Nat) : Nat :=
  (ps.map (fun P => inPair P.1 P.2 v)).sum

/-- Sum of a pointwise-added map splits. -/
theorem sum_map_add {β : Type} (l : List β) (f g : β → Nat) :
    (l.map (fun x => f x + g x)).sum = (l.map f).sum + (l.map g).sum := by
  induction l with
  | nil => simp
  | cons x xs ih => simp only [List.map_cons, List.sum_cons, ih]; omega

/-- Sum of a constant-zero map is zero. -/
theorem sum_map_zero {β : Type} (l : List β) : (l.map (fun _ => (0 : Nat))).sum = 0 := by
  induction l with
  | nil => rfl
  | cons x xs ih => simp only [List.map_cons, List.sum_cons, ih]

/-- ★ LOWER half: if every pair in `ps` is order-inverted, then `sumTouch ≥ #pairs`. -/
theorem sumTouch_ge (ps : List (Nat × Nat)) (s : Stack) (prog : List Nat)
    (hinv : ∀ P ∈ ps, proj P.1 P.2 (runMoves prog s) ≠ proj P.1 P.2 s) :
    ps.length ≤ sumTouch ps s prog := by
  induction ps with
  | nil => simp [sumTouch]
  | cons P ps' ih =>
      simp only [sumTouch, List.map_cons, List.sum_cons, List.length_cons]
      have h1 : 1 ≤ touch P.1 P.2 s prog :=
        touch_pos_of_inverted P.1 P.2 s prog (hinv P (List.mem_cons.mpr (Or.inl rfl)))
      have h2 : ps'.length ≤ sumTouch ps' s prog :=
        ih (fun Q hQ => hinv Q (List.mem_cons.mpr (Or.inr hQ)))
      simp only [sumTouch] at h2
      omega

/-- ★ UPPER half: with pairwise-DISJOINT pairs (no value in more than one pair), each op adds
    ≤ 1 to the aggregate touch, so `sumTouch ≤ #ops`. -/
theorem sumTouch_le_length (ps : List (Nat × Nat)) (hdisj : ∀ v, numContain ps v ≤ 1) :
    ∀ (s : Stack) (prog : List Nat), sumTouch ps s prog ≤ prog.length := by
  intro s prog
  induction prog generalizing s with
  | nil => simp only [sumTouch, touch, sum_map_zero, List.length_nil, Nat.le_refl]
  | cons d ds ih =>
      -- Split each pair's touch into (head contribution) + (recursive touch).
      have hadd := sum_map_add ps
        (fun P : Nat × Nat => match s[d]? with | some v => inPair P.1 P.2 v | none => 0)
        (fun P : Nat × Nat => touch P.1 P.2 (moveToTop d s) ds)
      simp only [sumTouch, touch]
      rw [hadd]
      -- recursive part ≤ ds.length
      have hrec : (ps.map (fun P => touch P.1 P.2 (moveToTop d s) ds)).sum ≤ ds.length := by
        have := ih (moveToTop d s); simp only [sumTouch] at this; exact this
      -- head part ≤ 1
      have hhead :
          (ps.map (fun P : Nat × Nat =>
              match s[d]? with | some v => inPair P.1 P.2 v | none => 0)).sum ≤ 1 := by
        cases hd : s[d]? with
        | none  => simp only [sum_map_zero]; omega
        | some v =>
            have hcv := hdisj v
            simp only [numContain] at hcv
            exact hcv
      simp only [List.length_cons]
      omega

/-- ★★ THE MOVEMENT LOWER BOUND: any move-to-top program that realises an exit layout inverting
    `m` pairwise-disjoint value-pairs relative to the entry uses at least `m` movement ops. -/
theorem movement_lower_bound (ps : List (Nat × Nat)) (s : Stack) (prog : List Nat)
    (hdisj : ∀ v, numContain ps v ≤ 1)
    (hinv : ∀ P ∈ ps, proj P.1 P.2 (runMoves prog s) ≠ proj P.1 P.2 s) :
    ps.length ≤ prog.length :=
  Nat.le_trans (sumTouch_ge ps s prog hinv) (sumTouch_le_length ps hdisj s prog)

/-! ## NON-VACUITY — the bound is MET WITH EQUALITY on a concrete witness (over Nat).

    Entry `s = [1,2,3,4]`, program `[1,3]` (2 ops): `moveToTop 1` then `moveToTop 3`.
    Exit = `[4,2,1,3]`. Pairs `{1,2}` and `{3,4}` are disjoint and BOTH order-inverted
    (`[1,2]→[2,1]`, `[3,4]→[4,3]`). The bound says ≥ 2 ops; exactly 2 were used ⇒ TIGHT. -/

/-- The witness program indeed produces `[4,2,1,3]`. -/
example : runMoves [1, 3] [1, 2, 3, 4] = [4, 2, 1, 3] := by decide

/-- Both witness pairs are order-inverted at the exit (relative order of the pair flips). -/
example :
    proj 1 2 (runMoves [1, 3] [1, 2, 3, 4]) ≠ proj 1 2 [1, 2, 3, 4]
  ∧ proj 3 4 (runMoves [1, 3] [1, 2, 3, 4]) ≠ proj 3 4 [1, 2, 3, 4] := by decide

/-- The disjointness hypothesis holds for `[(1,2),(3,4)]`: no value is in more than one pair. -/
theorem witness_disjoint : ∀ v, numContain [(1, 2), (3, 4)] v ≤ 1 := by
  intro v
  simp only [numContain, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, inPair]
  cases h12 : (v == 1 || v == 2) <;> cases h34 : (v == 3 || v == 4) <;>
    simp_all <;> omega

/-- ★ THE BOUND FIRES on the witness and is MET WITH EQUALITY: `2 ≤ 2`. -/
theorem witness_bound :
    ([(1, 2), (3, 4)] : List (Nat × Nat)).length ≤ ([1, 3] : List Nat).length :=
  movement_lower_bound [(1, 2), (3, 4)] [1, 2, 3, 4] [1, 3] witness_disjoint
    (by intro P hP
        simp only [List.mem_cons, List.mem_nil_iff, or_false] at hP
        rcases hP with h | h <;> subst h <;> decide)

/-- Numerically: the bound value equals the achieved op-count (both 2). -/
example : ([(1, 2), (3, 4)] : List (Nat × Nat)).length = 2
        ∧ ([1, 3] : List Nat).length = 2 := by decide

/-! ## BRIDGING the movement floor to the real scheduler (`Recompiler.Scheduler`).

    ★ HONEST BRIDGE CAVEAT (same posture as `Floor.lean`'s copy-floor bridge). `moveToTop d` is
    exactly the main-stack rewrite of `Op.ROLL d` (`moveToTop_faithful_ROLL`, using the project's
    own `removeNth`), and the scheduler's `moveOps` family (`Scheduler.lean`: SWAP=depth 1,
    ROT=depth 2, ROLL n=depth n) emits precisely these move-to-top primitives when it MOVES a
    last-use value to the top. So `movement_lower_bound` is a genuine, machine-checked lower bound
    on the ABSTRACT move-to-top op-count needed to realise a given exit permutation.

    What is NOT mechanised: that `Scheduler.emit` (and the move-arrange in `MoveArrange.lean`)
    realises the exit layout using EXACTLY these move-to-top ops — i.e. that it does not achieve
    the reordering by some copy+drop route that shuffles to-survive values around, which would
    change the op accounting. The correspondence "each forced inversion is paid by one `moveOps`
    emission" is therefore ASSERTED BY CONSTRUCTION of the emitter, NOT a proven property of
    `emit`. This is the exact analog of `Floor.lean`'s bridge caveat (the counting THEOREM is
    proven over the isolated model; the per-op projection of the full emitter trace is not).

    Consequently the bound quantifies how much movement is FORCED by permutation structure, and
    proves that quantity is STRICTLY POSITIVE and computable — but it is deliberately LOOSE
    (disjoint-inverted-pairs ≤ n − LCS(entry,exit), which is the NP-hard-equivalent tight
    quantity), so it does NOT certify the empirical scheduler floor as near-optimal.

    ★ SUPERSEDED (but kept) by the TIGHT n-LCS floor: `Recompiler.NlcsFloor.movement_lower_bound_nlcs`
    (`NlcsFloor.lean`) proves the SHARP per-boundary bound `#move-ops ≥ n − LCS(entry,exit)` over the
    SAME move-to-top model (it reuses this file's `moveToTop`/`runMoves`), so the two floors are about
    the identical op-count. The n-LCS bound is never weaker than this disjoint-inverted-pairs bound and
    is met with EQUALITY on the reversal witness (`4 − 1 = 3`, where this one tops out at `⌊n/2⌋ = 2`).
    This disjoint-pairs argument is retained as the simpler, still-valid counting core; the n-LCS one is
    the sharp movement floor. Neither is deleted. -/

end MovementFloor
end Recompiler
