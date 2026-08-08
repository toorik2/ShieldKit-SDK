/-
  LeanBCH.Opt PASS-3 peephole rewrites + PASS-2 small-depth folds, PROVEN correct
  for ALL inputs (all stack shapes, incl. underflow) over an abstract Val = α.

  Each `Correct src dst` here is the universally-quantified theorem that retires
  the corresponding line of the 8-random-Fp differential test. Combined with
  `Correct.congr` (Basic.lean), each proven rule is sound wherever it fires.
-/
import LeanBCH.Opt.Basic

namespace LeanBCH.Opt
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

/-! ### Fold-completeness additions (BLS12-381 singleton floor push, 2026-07-02).
    Two rewrites the recompiler's peephole fires that were not previously proven here. -/

/-- `DROP DROP  ⇒  2DROP` — UNCONDITIONAL: both consume exactly 2 and produce 0, and both
    underflow on identical inputs (main depth < 2). -/
theorem drop_drop {α} : Correct ([DROP, DROP] : List (Op α)) [TWODROP] := by
  intro ⟨m, a⟩
  rcases m with _ | ⟨x, _ | ⟨y, s⟩⟩ <;> rfl

/-- `ROT ROT ROT  ⇒  (nothing)` — the 3-cycle cubed is the identity permutation; needs main
    depth ≥ 3 (like `swap_swap`: deleting the ops removes their underflow re-check, so the
    deletion is only sound under a depth precondition the recompiler structurally guarantees). -/
theorem rot_rot_rot {α} :
    ∀ st : State α, 3 ≤ st.1.length → run ([ROT, ROT, ROT] : List (Op α)) st = run [] st := by
  intro ⟨m, a⟩ h
  rcases m with _ | ⟨x, _ | ⟨y, _ | ⟨z, s⟩⟩⟩ <;> simp_all [run, step] <;> omega

/-! ### L=5 window folds applied by the BN254 crown (locking 4913, 2026-07-03).
    The BN254 recompiler crown applies the FULL decidable fold table with source
    windows up to length 5 (beyond the length-3 curated peepholes above and the
    window-complete-L4 `FoldTable`). Each of the 13 windows that fired in the crown's
    fold log is a genuine UNCONDITIONAL stack identity: effect-equivalent to its
    replacement at every depth 0..12 AND defined at depth 12 (so agreement extends to
    all deeper runtime stacks — the max slot accessed is ≤ 12). Proven here so that
    every rewrite the crown fires is machine-checked `Correct`. -/

/-- `5PICK 5PICK 6PICK  ⇒  5PICK 5PICK DUP` -/
theorem l5_pick5_pick5_pick6 {α} :
    Correct ([PICK 5, PICK 5, PICK 6] : List (Op α)) [PICK 5, PICK 5, DUP] := by
  intro ⟨m, a⟩
  rcases m with _ | ⟨x, _ | ⟨y, _ | ⟨z, _ | ⟨w, _ | ⟨u, _ | ⟨v, s⟩⟩⟩⟩⟩⟩ <;> rfl

/-- `DUP 2PICK DUP  ⇒  2DUP OVER ROT` -/
theorem l5_dup_pick2_dup {α} :
    Correct ([DUP, PICK 2, DUP] : List (Op α)) [TWODUP, OVER, ROT] := by
  intro ⟨m, a⟩
  rcases m with _ | ⟨x, _ | ⟨y, s⟩⟩ <;> rfl

/-- `ROT DROP SWAP DUP  ⇒  OVER 2SWAP NIP` -/
theorem l5_rot_drop_swap_dup {α} :
    Correct ([ROT, DROP, SWAP, DUP] : List (Op α)) [OVER, TWOSWAP, NIP] := by
  intro ⟨m, a⟩
  rcases m with _ | ⟨x, _ | ⟨y, _ | ⟨z, s⟩⟩⟩ <;> rfl

/-- `DUP 3PICK 3ROLL 5ROLL  ⇒  2SWAP ROT 2DUP SWAP 2ROT` -/
theorem l5_dup_pick3_roll3_roll5 {α} :
    Correct ([DUP, PICK 3, ROLL 3, ROLL 5] : List (Op α)) [TWOSWAP, ROT, TWODUP, SWAP, TWOROT] := by
  intro ⟨m, a⟩
  rcases m with _ | ⟨x, _ | ⟨y, _ | ⟨z, _ | ⟨w, s⟩⟩⟩⟩ <;> rfl

/-- `ROT ROT 2SWAP NIP 3ROLL  ⇒  4PICK 2ROT 2DROP` -/
theorem l5_rotrot_2swap_nip_roll3 {α} :
    Correct ([ROT, ROT, TWOSWAP, NIP, ROLL 3] : List (Op α)) [PICK 4, TWOROT, TWODROP] := by
  intro ⟨m, a⟩
  rcases m with _ | ⟨x, _ | ⟨y, _ | ⟨z, _ | ⟨w, _ | ⟨u, s⟩⟩⟩⟩⟩ <;> rfl

/-- `DROP 3ROLL DROP 3ROLL DROP  ⇒  2ROT 2DROP DROP` -/
theorem l5_drop_roll3_drop_roll3_drop {α} :
    Correct ([DROP, ROLL 3, DROP, ROLL 3, DROP] : List (Op α)) [TWOROT, TWODROP, DROP] := by
  intro ⟨m, a⟩
  rcases m with _ | ⟨x, _ | ⟨y, _ | ⟨z, _ | ⟨w, _ | ⟨u, _ | ⟨v, s⟩⟩⟩⟩⟩⟩ <;> rfl

/-- `3ROLL DROP 3ROLL DROP  ⇒  DUP 2ROT 2DROP DROP` -/
theorem l5_roll3_drop_roll3_drop {α} :
    Correct ([ROLL 3, DROP, ROLL 3, DROP] : List (Op α)) [DUP, TWOROT, TWODROP, DROP] := by
  intro ⟨m, a⟩
  rcases m with _ | ⟨x, _ | ⟨y, _ | ⟨z, _ | ⟨w, _ | ⟨u, s⟩⟩⟩⟩⟩ <;> rfl

/-- `4PICK 2ROT 2DROP 2ROT 2DROP  ⇒  2ROT NIP 2ROT 2DROP` -/
theorem l5_pick4_2rot_2drop_2rot_2drop {α} :
    Correct ([PICK 4, TWOROT, TWODROP, TWOROT, TWODROP] : List (Op α)) [TWOROT, NIP, TWOROT, TWODROP] := by
  intro ⟨m, a⟩
  rcases m with _ | ⟨x, _ | ⟨y, _ | ⟨z, _ | ⟨w, _ | ⟨u, _ | ⟨v, _ | ⟨t, s⟩⟩⟩⟩⟩⟩⟩ <;> rfl

/-- `DROP DUP 2ROT 2DROP DROP  ⇒  2ROT 2DROP DROP` -/
theorem l5_drop_dup_2rot_2drop_drop {α} :
    Correct ([DROP, DUP, TWOROT, TWODROP, DROP] : List (Op α)) [TWOROT, TWODROP, DROP] := by
  intro ⟨m, a⟩
  rcases m with _ | ⟨x, _ | ⟨y, _ | ⟨z, _ | ⟨w, _ | ⟨u, _ | ⟨v, s⟩⟩⟩⟩⟩⟩ <;> rfl

/-- `OVER 3PICK 5PICK  ⇒  2OVER 2SWAP OVER 2ROT` -/
theorem l5_over_pick3_pick5 {α} :
    Correct ([OVER, PICK 3, PICK 5] : List (Op α)) [TWOOVER, TWOSWAP, OVER, TWOROT] := by
  intro ⟨m, a⟩
  rcases m with _ | ⟨x, _ | ⟨y, _ | ⟨z, _ | ⟨w, s⟩⟩⟩⟩ <;> rfl

/-- `6ROLL 6ROLL 6ROLL 6ROLL  ⇒  2ROT 6ROLL 6ROLL 2SWAP ROT` -/
theorem l5_roll6_x4 {α} :
    Correct ([ROLL 6, ROLL 6, ROLL 6, ROLL 6] : List (Op α)) [TWOROT, ROLL 6, ROLL 6, TWOSWAP, ROT] := by
  intro ⟨m, a⟩
  rcases m with _ | ⟨x, _ | ⟨y, _ | ⟨z, _ | ⟨w, _ | ⟨u, _ | ⟨v, _ | ⟨t, s⟩⟩⟩⟩⟩⟩⟩ <;> rfl

/-- `2DROP 2SWAP NIP ROT ROT  ⇒  2DROP 3ROLL DROP` -/
theorem l5_2drop_2swap_nip_rot_rot {α} :
    Correct ([TWODROP, TWOSWAP, NIP, ROT, ROT] : List (Op α)) [TWODROP, ROLL 3, DROP] := by
  intro ⟨m, a⟩
  rcases m with _ | ⟨x, _ | ⟨y, _ | ⟨z, _ | ⟨w, _ | ⟨u, _ | ⟨v, s⟩⟩⟩⟩⟩⟩ <;> rfl

/-- `2PICK 3PICK 4PICK  ⇒  2PICK DUP DUP` -/
theorem l5_pick2_pick3_pick4 {α} :
    Correct ([PICK 2, PICK 3, PICK 4] : List (Op α)) [PICK 2, DUP, DUP] := by
  intro ⟨m, a⟩
  rcases m with _ | ⟨x, _ | ⟨y, _ | ⟨z, s⟩⟩⟩ <;> rfl

end LeanBCH.Opt
