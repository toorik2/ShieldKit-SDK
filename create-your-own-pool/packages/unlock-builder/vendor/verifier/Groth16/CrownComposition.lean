/-
  Crown composition capstone — the E-derivation + const-provider SOURCE rewrites compose
  with the recompiler (`whole_program_end_to_end`) into ONE whole-program refinement.

  A block leaf runs its ops verbatim (`runItem isT fuel (.block ops _ _ _) st = run ops st`),
  so a `Correct` rewrite of a block's ops LIFTS directly to `runProg` (`block_ops_congr`).
  Chaining that with `whole_program_end_to_end` (optProg preserves runProg) gives the shipped
  crown ≡ the trusted baked-constant baseline:

    runProg (optProg  «ederived / provider-CSE»)  =  runProg  «baked-constant baseline»
             └────────── recompiler ──────────┘        └──── source rewrite (Correct) ────┘

  This ties the two arithmetic/CSE levers (`ederive_pushes_E`, `invoke_const_provider`) into
  the same machine-checked end-to-end guarantee as the rescheduling + folds. 0-sorry, [propext].
-/
import LeanBCH.Opt.Control
import Groth16.Ederive
import LeanBCH.Opt.Providers

namespace Groth16.CrownComposition
open LeanBCH.Opt LeanBCH.Opt.Op

/-- **Lift `Correct` to a block leaf.** Rewriting a block's ops by any behavior-preserving
    (`Correct`) sequence preserves the whole program's `runProg` — a block runs its ops
    verbatim, and its DAG is irrelevant to `runProg` (only `optProg` reads it). Works for all
    fuel (0 ⇒ both `none`). -/
theorem block_ops_congr {α : Type} (isT : α → Bool) (fuel : Nat)
    (ops ops' : List (Op α)) (ed ea : Nat) (b b' : Block α) (rest : Prog α) (st : State α)
    (h : Correct ops ops') :
    runProg isT fuel (Item.block ops ed ea b :: rest) st
      = runProg isT fuel (Item.block ops' ed ea b' :: rest) st := by
  cases fuel with
  | zero => simp only [runProg]
  | succ n => simp only [runProg, runItem]; rw [h st]

/-- **Crown ≡ baseline (E-derivation).** The recompiled (`optProg`) program running the on-chain
    E-derivation as a block leaf is behavior-identical, on the given shaped input, to the trusted
    baseline that pushes the baked exponent E — composing `whole_program_end_to_end` (recompiler)
    with `ederive_pushes_E` (the derivation is a `Correct` rewrite of `PUSH E`). -/
theorem crown_refines_baseline_ederive (isT : Int → Bool)
    (ed ea dm da dm' da' fuel : Nat) (bD bE : Block Int) (rest : Prog Int) (st : State Int)
    (hs : Shaped (Item.block Ederive.ederiveOps ed ea bD :: rest) dm da dm' da')
    (hm : st.1.length = dm) (ha : st.2.length = da) :
    runProg isT fuel (optProg (Item.block Ederive.ederiveOps ed ea bD :: rest)) st
      = runProg isT fuel (Item.block [PUSH Ederive.Eval] ed ea bE :: rest) st := by
  rw [whole_program_end_to_end isT (Item.block Ederive.ederiveOps ed ea bD :: rest)
        dm da dm' da' hs fuel st hm ha]
  exact (block_ops_congr isT fuel [PUSH Ederive.Eval] Ederive.ederiveOps ed ea bE bD rest st
          Ederive.ederive_pushes_E).symm

/-- **Crown ≡ baseline (const-provider / global-CSE).** Same composition for a nullary
    const-provider: the recompiled program invoking the provider (`CALL 0 (fun _ => [c])`) is
    behavior-identical to the baseline that pushes `c` inline — `whole_program_end_to_end` ∘
    `invoke_const_provider`. Instantiates at c = p (the p-pool), the twist and tail constants. -/
theorem crown_refines_baseline_provider {α : Type} [DecidableEq α] [Inhabited α] (isT : α → Bool) (c : α)
    (ed ea dm da dm' da' fuel : Nat) (bP bC : Block α) (rest : Prog α) (st : State α)
    (hs : Shaped (Item.block [Providers.provider c] ed ea bP :: rest) dm da dm' da')
    (hm : st.1.length = dm) (ha : st.2.length = da) :
    runProg isT fuel (optProg (Item.block [Providers.provider c] ed ea bP :: rest)) st
      = runProg isT fuel (Item.block [PUSH c] ed ea bC :: rest) st := by
  rw [whole_program_end_to_end isT (Item.block [Providers.provider c] ed ea bP :: rest)
        dm da dm' da' hs fuel st hm ha]
  exact (block_ops_congr isT fuel [PUSH c] [Providers.provider c] ed ea bC bP rest st
          (Providers.invoke_const_provider c)).symm

/-! ### Non-vacuity — the composition provably FIRES on a concrete whole program. -/

/-- A trivial block DAG. `runProg` reads only a block's `ops`, never its DAG, so this suffices
    to exhibit the E-derivation running as a genuine block leaf inside a program. -/
def dummyBlock : Block Int :=
  { entryDepth := 0, entryAlt := 0, nodes := [], exit := [], exitAlt := [] }

/-- WITNESS 1 — the E-derivation, as a real block leaf inside a whole program, computes E under
    `runProg` (not just the flat `run`). The block machinery genuinely fires and yields E. -/
example :
    runProg (fun _ => true) 2 [Item.block Ederive.ederiveOps 0 0 dummyBlock]
      (([] : List Int), ([] : List Int)) = some ([Ederive.Eval], []) := by
  simp [runProg, runItem, Ederive.ederive_computes_E]

/-- WITNESS 2 — `block_ops_congr` fires on a concrete program: the baked-E block and the
    ederived block are `runProg`-identical (both compute E). The capstone's lift is non-vacuous. -/
example :
    runProg (fun _ => true) 2 [Item.block [PUSH Ederive.Eval] 0 0 dummyBlock]
        (([] : List Int), ([] : List Int))
      = runProg (fun _ => true) 2 [Item.block Ederive.ederiveOps 0 0 dummyBlock]
        (([] : List Int), ([] : List Int)) :=
  block_ops_congr (fun _ => true) 2 [PUSH Ederive.Eval] Ederive.ederiveOps 0 0
    dummyBlock dummyBlock [] ([], []) Ederive.ederive_pushes_E

end Groth16.CrownComposition
