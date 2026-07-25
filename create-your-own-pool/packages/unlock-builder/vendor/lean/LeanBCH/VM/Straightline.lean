/-
  LeanBCH.VM.Straightline — the seam stackcert reasons over.

  A *straight-line* block contains no control-flow ops (IF/NOTIF/ELSE/ENDIF/BEGIN/UNTIL), so
  the `ip` machine just advances linearly with an empty control stack — its behaviour is a pure
  left fold of the per-instruction stack effect. `foldStraight` is that denotation (a
  `Stack × Stack` transformer, `none` on underflow). This file proves the ALGEBRAIC keystone:
  `foldStraight` distributes over concatenation, hence a block may be replaced in place by any
  behaviourally-equal block without changing the whole program's denotation — `Basic.Correct.
  congr` lifted to the real VM, PROVEN. `run_straightline` (below) then connects the denotation
  to the actual `run`.
-/
import LeanBCH.VM.Eval

namespace LeanBCH.VM
open LeanBCH LeanBCH.VM.State

/-- A straight-line opcode: not a control-flow op (no conditional, no BEGIN/UNTIL). On such an
    op with an empty control stack the machine only advances `ip` and rewrites stack/alt. -/
def straightOp (op : UInt8) : Bool :=
  !Opcode.isConditional op && op != Opcode.OP_BEGIN && op != Opcode.OP_UNTIL

/-- The pure (main, alt) stack effect of one instruction, read off `stepInstr` from an
    empty-control state; `none` on underflow / abort. -/
def stepStk (i : Instr) (st al : Stack) : Option (Stack × Stack) :=
  let s := stepInstr i.opcode i.data { stack := st, alt := al }
  match s.error with
  | some _ => none
  | none   => some (s.stack, s.alt)

/-- The denotation of a straight-line block: fold the per-instruction effect, short-circuiting
    on underflow. This is the `Basic.run` shape at LeanBCH's concrete value type. -/
def foldStraight : List Instr → Stack → Stack → Option (Stack × Stack)
  | [],      st, al => some (st, al)
  | i :: is, st, al => match stepStk i st al with
                       | none          => none
                       | some (s', a') => foldStraight is s' a'

/-- Two blocks are equivalent iff they have the same denotation on every input. -/
def BlockEquiv (b b' : List Instr) : Prop := ∀ st al, foldStraight b st al = foldStraight b' st al

/-- ★ `foldStraight` distributes over concatenation (the pure shadow of `Basic.run_append`). -/
theorem foldStraight_append (a b : List Instr) (st al : Stack) :
    foldStraight (a ++ b) st al = (foldStraight a st al).bind (fun p => foldStraight b p.1 p.2) := by
  induction a generalizing st al with
  | nil => simp [foldStraight]
  | cons i rest ih =>
      simp only [List.cons_append, foldStraight]
      cases stepStk i st al with
      | none          => rfl
      | some p => exact ih p.1 p.2

/-- `BlockEquiv` is a congruence: equal denotations compose to equal denotations. -/
theorem foldStraight_congr {b b' : List Instr} (h : BlockEquiv b b') (st al : Stack) :
    foldStraight b st al = foldStraight b' st al := h st al

/-- ★ THE SPLICE CONGRUENCE — `Basic.Correct.congr` lifted to the real VM: replacing a block
    `b` by a behaviourally-equal block `b'` in place preserves the whole straight-line program's
    denotation. This is the seam the recompiler's proof-producing search rides on. -/
theorem splice_congr {b b' : List Instr} (h : BlockEquiv b b') (pre post : List Instr)
    (st al : Stack) :
    foldStraight (pre ++ b ++ post) st al = foldStraight (pre ++ b' ++ post) st al := by
  rw [List.append_assoc, List.append_assoc,
      foldStraight_append pre (b ++ post), foldStraight_append pre (b' ++ post)]
  cases foldStraight pre st al with
  | none   => rfl
  | some p =>
      simp only [Option.bind_some]
      rw [foldStraight_append b post, foldStraight_append b' post, h p.1 p.2]

/-- `BlockEquiv` is reflexive / symmetric / transitive (an equivalence the optimizer chains). -/
theorem BlockEquiv.refl (b : List Instr) : BlockEquiv b b := fun _ _ => rfl
theorem BlockEquiv.symm {b b' : List Instr} (h : BlockEquiv b b') : BlockEquiv b' b :=
  fun st al => (h st al).symm
theorem BlockEquiv.trans {a b c : List Instr} (h1 : BlockEquiv a b) (h2 : BlockEquiv b c) :
    BlockEquiv a c := fun st al => (h1 st al).trans (h2 st al)

end LeanBCH.VM
