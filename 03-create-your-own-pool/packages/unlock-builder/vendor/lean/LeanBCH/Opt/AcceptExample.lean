/-
  LeanBCH.Opt.AcceptExample — a concrete end-to-end witness that the acceptance bridge COMPOSES for a
  real compute-op rewrite. Not library API; a worked demonstration that the 4c pieces fit.

  The rewrite: `[SWAP, ADD] ⇒ [ADD]` — "a SWAP before a commutative ADD is redundant." A genuine
  algebraic optimization involving a COMPUTE op, proven `Correct` on the abstract machine (via
  `Int.add_comm`), then transported to LeanBCH's real `stepInstr` VM by `rewrite_sound_accept`: the
  optimized `[ADD]` bytecode, run without error, computes exactly what the original `[SWAP, ADD]` means.
-/
import LeanBCH.Opt.AcceptBridge

namespace LeanBCH.Opt.AcceptExample
open LeanBCH LeanBCH.VM LeanBCH.Opt LeanBCH.Opt.Op LeanBCH.Opt.OpFaithful LeanBCH.Opt.Adapter

/-- The original and optimized op-programs. -/
def src : List (Op Bytes) := [Op.SWAP, Op.CALL 2 (arithSem .add)]
def dst : List (Op Bytes) := [Op.CALL 2 (arithSem .add)]

/-- The encoder for this rewrite's ops (SWAP ↦ its byte; the sole CALL ↦ the ADD instruction). -/
def enc : Op Bytes → List Instr
  | .SWAP => [{ opcode := Opcode.OP_SWAP, data := [] }]
  | _     => [arithInstr .add]

/-- **The abstract rewrite is `Correct`**: SWAP before a commutative ADD leaves the same result on
    every input (identical failure on underflow), by `Int.add_comm` under the `ADD` node's `sem`. -/
theorem swap_add_correct : LeanBCH.Opt.Correct src dst := by
  intro st
  obtain ⟨s, a⟩ := st
  cases s with
  | nil => rfl
  | cons x s1 =>
    cases s1 with
    | nil => rfl
    | cons y s2 =>
      simp [src, dst, LeanBCH.Opt.run, LeanBCH.Opt.step, arithSem, Cost.arithResult, Int.add_comm]

/-- ★ END-TO-END: the OPTIMIZED bytecode `[OP_ADD]`, run on LeanBCH's real straight-line `stepInstr`
    VM without error, computes EXACTLY the ORIGINAL program `[OP_SWAP, OP_ADD]`'s abstract semantics.
    A real compute-op optimization, sound under the genuine VM — the full 4c chain fired: the abstract
    `Correct` (`swap_add_correct`), the compute op's faithfulness under its precondition
    (`simOpOn_arith`), and the precondition discharged by the run's own acceptance (`arith_accept_pre`). -/
theorem swap_add_sound_under_VM (st al : Stack)
    (hacc : foldStraight (dst.flatMap enc) st al ≠ none) :
    foldStraight (dst.flatMap enc) st al = LeanBCH.Opt.run src (st, al) := by
  refine rewrite_sound_accept enc (fun _ => ArithPre .add) ?_ ?_ swap_add_correct st al hacc
  · intro op hop
    simp only [dst, List.mem_singleton] at hop
    subst hop
    exact simOpOn_arith .add
  · intro op hop
    simp only [dst, List.mem_singleton] at hop
    subst hop
    intro st al hne
    exact arith_accept_pre .add st al hne

end LeanBCH.Opt.AcceptExample
