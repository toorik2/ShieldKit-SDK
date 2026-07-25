/-
  Recompiler PASS-3 peephole rewrites + PASS-2 small-depth folds, PROVEN correct
  for ALL inputs (all stack shapes, incl. underflow) over an abstract Val = α.

  Each `Correct src dst` here is the universally-quantified theorem that retires
  the corresponding line of the 8-random-Fp differential test. Combined with
  `Correct.congr` (Basic.lean), each proven rule is sound wherever it fires.
-/
import Recompiler.Basic

namespace Recompiler
open Op

-- Tactic pattern: destructure the main stack to the max depth the rule touches,
-- then every case (short = both `none`, long = identical result) is `rfl`.

/-! ### PASS-3 peephole rewrites (from E-singleton-step2-recompiler §THE PASSES) -/

/-- `OVER OVER  ⇒  2DUP` -/
theorem over_over {α} : Correct ([OVER, OVER] : List (Op α)) [TWODUP] := by
  intro ⟨m, a⟩
  rcases m with _ | ⟨x, _ | ⟨y, s⟩⟩ <;> rfl

/-- `SWAP OVER  ⇒  TUCK` -/
theorem swap_over {α} : Correct ([SWAP, OVER] : List (Op α)) [TUCK] := by
  intro ⟨m, a⟩
  rcases m with _ | ⟨x, _ | ⟨y, s⟩⟩ <;> rfl

/-- `SWAP DROP  ⇒  NIP` -/
theorem swap_drop {α} : Correct ([SWAP, DROP] : List (Op α)) [NIP] := by
  intro ⟨m, a⟩
  rcases m with _ | ⟨x, _ | ⟨y, s⟩⟩ <;> rfl

/-- `<2>PICK <2>PICK <2>PICK  ⇒  3DUP` -/
theorem pick2_thrice {α} :
    Correct ([PICK 2, PICK 2, PICK 2] : List (Op α)) [THREEDUP] := by
  intro ⟨m, a⟩
  rcases m with _ | ⟨x, _ | ⟨y, _ | ⟨z, s⟩⟩⟩ <;> rfl

/-- `<3>PICK <3>PICK  ⇒  2OVER` -/
theorem pick3_twice {α} :
    Correct ([PICK 3, PICK 3] : List (Op α)) [TWOOVER] := by
  intro ⟨m, a⟩
  rcases m with _ | ⟨x, _ | ⟨y, _ | ⟨z, _ | ⟨w, s⟩⟩⟩⟩ <;> rfl

/-- `<3>ROLL <3>ROLL  ⇒  2SWAP` -/
theorem roll3_twice {α} :
    Correct ([ROLL 3, ROLL 3] : List (Op α)) [TWOSWAP] := by
  intro ⟨m, a⟩
  rcases m with _ | ⟨x, _ | ⟨y, _ | ⟨z, _ | ⟨w, s⟩⟩⟩⟩ <;> rfl

/-- `<5>ROLL <5>ROLL  ⇒  2ROT` -/
theorem roll5_twice {α} :
    Correct ([ROLL 5, ROLL 5] : List (Op α)) [TWOROT] := by
  intro ⟨m, a⟩
  rcases m with
    _ | ⟨x, _ | ⟨y, _ | ⟨z, _ | ⟨w, _ | ⟨u, _ | ⟨v, s⟩⟩⟩⟩⟩⟩ <;> rfl

/-! ### PASS-2 small-depth folds (scheduler.mjs `pushIntOps`/peephole `intVal`) -/

/-- `<0>PICK  ⇒  DUP` -/
theorem pick0_dup {α} : Correct ([PICK 0] : List (Op α)) [DUP] := by
  intro ⟨m, a⟩; rcases m with _ | ⟨x, s⟩ <;> rfl

/-- `<1>PICK  ⇒  OVER` -/
theorem pick1_over {α} : Correct ([PICK 1] : List (Op α)) [OVER] := by
  intro ⟨m, a⟩; rcases m with _ | ⟨x, _ | ⟨y, s⟩⟩ <;> rfl

/-- `<0>ROLL  ⇒  (nothing)`.
    ⚠ CONDITIONAL: only a no-op when the main stack is NONEMPTY. On an empty main, `ROLL 0`
    underflows (`none`) while the empty program succeeds — so deleting it is UNSOUND at depth 0.
    The recompiler is safe because a block's entry depth structurally guarantees the operand
    exists, but this precondition is invisible to a differential test on well-formed stacks. -/
theorem roll0_nop {α} :
    ∀ st : State α, st.1 ≠ [] → run ([ROLL 0] : List (Op α)) st = run [] st := by
  intro ⟨m, a⟩ h; cases m with
  | nil => exact absurd rfl h
  | cons x s => rfl

/-- `<1>ROLL  ⇒  SWAP` -/
theorem roll1_swap {α} : Correct ([ROLL 1] : List (Op α)) [SWAP] := by
  intro ⟨m, a⟩; rcases m with _ | ⟨x, _ | ⟨y, s⟩⟩ <;> rfl

/-- `<2>ROLL  ⇒  ROT` -/
theorem roll2_rot {α} : Correct ([ROLL 2] : List (Op α)) [ROT] := by
  intro ⟨m, a⟩; rcases m with _ | ⟨x, _ | ⟨y, _ | ⟨z, s⟩⟩⟩ <;> rfl

/-! ### Extra algebraic peepholes actually in peephole.mjs
    ⚠ These all fold a pair to the EMPTY program. Unlike the folds above (which target a
    single op that re-checks depth), deleting an op removes its underflow check, so each is
    only correct under a depth PRECONDITION — a genuine soundness caveat the Lean model
    surfaces that the 8-random-Fp differential test (always deep stacks) cannot. -/

/-- `SWAP SWAP  ⇒  (nothing)` — needs main depth ≥ 2. -/
theorem swap_swap {α} :
    ∀ st : State α, 2 ≤ st.1.length → run ([SWAP, SWAP] : List (Op α)) st = run [] st := by
  intro ⟨m, a⟩ h
  rcases m with _ | ⟨x, _ | ⟨y, s⟩⟩ <;> simp_all [run, step] <;> omega

/-- `DUP DROP  ⇒  (nothing)` — needs main depth ≥ 1. -/
theorem dup_drop {α} :
    ∀ st : State α, st.1 ≠ [] → run ([DUP, DROP] : List (Op α)) st = run [] st := by
  intro ⟨m, a⟩ h; cases m with
  | nil => exact absurd rfl h
  | cons x s => rfl

/-- `OVER DROP  ⇒  (nothing)` — needs main depth ≥ 2. -/
theorem over_drop {α} :
    ∀ st : State α, 2 ≤ st.1.length → run ([OVER, DROP] : List (Op α)) st = run [] st := by
  intro ⟨m, a⟩ h
  rcases m with _ | ⟨x, _ | ⟨y, s⟩⟩ <;> simp_all [run, step] <;> omega

end Recompiler
