/-
  LeanBCH.Opt.PushButton — the real-VM capstone: OPTIMIZED bytecode on the genuine VM computes exactly
  what the ORIGINAL program means. Chains the two close-out tracks at their shared join `denote (bA k)`:
    • Track A (`EmitConcrete.emit_bA_sound`): the scheduler's emitted bytes, encoded by the CONCRETE
      `enc` and run on the real `foldStraight`/`stepInstr` VM without error, = `denote (bA k)`.
    • Track B (`bridge_block` ∘ `decompileBlock_WellFormed`): the ORIGINAL raw program, run on the
      abstract machine, = `denote (bA k)` — the `WellFormed` hypothesis discharged from `decompileBlock`.
  Fully closed for the arithmetic class (a real `rawA k` exhibited, its decompilation and uniformity
  proved), no hypotheses beyond the run accepting. This is the push-button "optimized = original, on
  the real VM" for a genuine compute-op program, incl. the partial div/mod.
-/
import LeanBCH.Opt.EmitConcrete
import LeanBCH.Opt.DecompileWF

namespace LeanBCH.Opt.PushButton
open LeanBCH LeanBCH.VM LeanBCH.Opt LeanBCH.Opt.Op LeanBCH.Opt.OpFaithful LeanBCH.Opt.EmitConcrete

/-- The ORIGINAL raw op-program for a 2-input arithmetic block: one arith node consuming the two entry
    mains. Its decompilation is exactly `EmitConcrete.bA k`. -/
def rawA (k : ArithKind) : List (Op Bytes) := [Op.CALL 2 (arithSem k)]

/-- `rawA k` decompiles to the hand-built block `bA k` (both ground after `cases k`). -/
theorem rawA_decompiles (k : ArithKind) : decompileBlock (rawA k) 2 0 = some (bA k) := by
  cases k <;> rfl

/-- The single arith `CALL` in `rawA k` has uniform output arity (its `sem` returns a 1-element list on
    every length-2 input) — discharging the `OpUniform` premise of `decompileBlock_WellFormed`. -/
theorem rawA_uniform (k : ArithKind) : ∀ o ∈ rawA k, OpUniform o := by
  intro o ho
  simp only [rawA, List.mem_singleton] at ho; subst ho
  intro nin sem h
  injection h with hn hs; subst hn; subst hs
  intro l hl
  rcases l with _ | ⟨a, _ | ⟨b, _ | ⟨c, t⟩⟩⟩ <;> simp_all [arithSem]

/-- ★★★ THE PUSH-BUTTON THEOREM (arithmetic class). For every arithmetic kind `k` on a 2-input entry:
    the OPTIMIZED bytecode `emit (bA k)` (what the PASS-2 scheduler actually emits), encoded by the
    concrete `enc` and run on LeanBCH's real `stepInstr` VM WITHOUT error, computes EXACTLY the value
    the ORIGINAL program `rawA k = [arith CALL]` denotes — both sides `= denote (bA k) M A`. Fully
    closed (only the run's own acceptance assumed); covers the partial div/mod. Track A meets Track B. -/
theorem push_button_arith (k : ArithKind) (M A : List Bytes)
    (hM : M.length = 2) (hA : A.length = 0)
    (hacc : foldStraight ((emit (bA k)).flatMap enc) (entryState M A).1 (entryState M A).2 ≠ none) :
    foldStraight ((emit (bA k)).flatMap enc) (entryState M A).1 (entryState M A).2 = some (denote (bA k) M A)
    ∧ run (rawA k) (entryState M A) = some (denote (bA k) M A) :=
  ⟨ emit_bA_sound k M A hM hA hacc,
    bridge_block (rawA k) 2 0 M A hM hA (bA k) (rawA_decompiles k)
      (decompileBlock_WellFormed (rawA k) 2 0 (bA k) (rawA_uniform k) (rawA_decompiles k)) ⟩

end LeanBCH.Opt.PushButton
