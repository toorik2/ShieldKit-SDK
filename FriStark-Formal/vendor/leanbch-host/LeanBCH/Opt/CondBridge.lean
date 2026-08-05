/-
  LeanBCH.Opt.CondBridge — CONDITIONAL faithfulness composition (the C1 architectural core).

  `Adapter.SimOp`/`run_via_encode` are UNCONDITIONAL: they require each op's encoding to realize the
  abstract step on EVERY state. That works for the stack-shuffle/PUSH fragment, but NOT for compute
  ops: `OpFaithful.sim_CALL_arith` shows the real `stepInstr` arithmetic op is faithful only when its
  operands are canonically-encoded numbers (the partial/total seam). So the compute-op bridge cannot
  be an unconditional `SimOp` — the precondition must be carried as an INVARIANT across the block.

  This file adds that machinery: `SimOpOn P` (faithfulness gated by a stack-predicate `P`) and
  `run_via_encode_on` (the block-level composition that threads a preserved invariant `Q`). The
  intended instantiation: `Q` = "every value the program will consume as a number is canonically
  encoded", which the value-DAG typing (`Dag.WellFormed`) guarantees and preserves — so each arith
  op's `sim_CALL_arith` precondition holds exactly when it fires. Unconditional `SimOp`s embed via
  `SimOp.toOn`, so the shuffle fragment and the compute fragment compose under one `Q`.
-/
import LeanBCH.Opt.Adapter

namespace LeanBCH.Opt.Adapter
open LeanBCH LeanBCH.VM LeanBCH.Opt LeanBCH.Opt.Op

/-- CONDITIONAL per-op faithfulness: `is` realizes `op` on every `(main, alt)` state satisfying the
    precondition `P`. The unconditional `SimOp` is `P := fun _ _ => True`. For a compute op, `P` is
    "the operands this op consumes are canonically-encoded VM numbers" — the value-DAG typing
    invariant, which the real (partial) VM genuinely requires and which is honestly never dropped. -/
def SimOpOn (P : Stack → Stack → Prop) (op : Op Bytes) (is : List Instr) : Prop :=
  ∀ st al : Stack, P st al → foldStraight is st al = LeanBCH.Opt.step op (st, al)

/-- An unconditional `SimOp` witness is conditional-on-anything: the shuffle/PUSH fragment (whose
    `SimOp`s are unconditional) drops straight into any `SimOpOn Q` composition. -/
theorem SimOp.toOn {op : Op Bytes} {is : List Instr} (h : SimOp op is) (P : Stack → Stack → Prop) :
    SimOpOn P op is := fun st al _ => h st al

/-- ★ **The conditional run-level bridge.** If an invariant `Q` holds at the entry, each op is
    faithful WHENEVER `Q` holds (`SimOpOn Q`), and `Q` is PRESERVED by each op's abstract step, then
    the encoded program's `foldStraight` equals `LeanBCH.Opt.run` — the precondition threaded across
    the whole block. Instantiate `Q` from the value-DAG typing and every compute op's
    minimal-encoding precondition holds exactly when it fires. Generalizes `run_via_encode` (the
    `Q := fun _ _ => True` case). -/
theorem run_via_encode_on (enc : Op Bytes → List Instr) (Q : Stack → Stack → Prop) :
    ∀ (ops : List (Op Bytes)),
      (∀ op ∈ ops, SimOpOn Q op (enc op)) →
      (∀ op ∈ ops, ∀ (st al : Stack) (p : Stack × Stack),
          Q st al → LeanBCH.Opt.step op (st, al) = some p → Q p.1 p.2) →
      ∀ (st al : Stack), Q st al →
        foldStraight (ops.flatMap enc) st al = LeanBCH.Opt.run ops (st, al)
  | [],        _,    _,     st, al, _  => by simp [foldStraight, LeanBCH.Opt.run]
  | op :: ops, hsim, hpres, st, al, hQ => by
      rw [List.flatMap_cons, foldStraight_append,
          hsim op (List.mem_cons.mpr (Or.inl rfl)) st al hQ]
      cases hb : LeanBCH.Opt.step op (st, al) with
      | none   => simp [LeanBCH.Opt.run, hb]
      | some p =>
          simp only [Option.bind, LeanBCH.Opt.run, hb]
          have hQ' : Q p.1 p.2 := hpres op (List.mem_cons.mpr (Or.inl rfl)) st al p hQ hb
          exact run_via_encode_on enc Q ops
            (fun o ho => hsim o (List.mem_cons.mpr (Or.inr ho)))
            (fun o ho => hpres o (List.mem_cons.mpr (Or.inr ho))) p.1 p.2 hQ'

/-- **Conditional `Correct` ⟹ `BlockEquiv`.** If `src` and `dst` are `Correct` and both are faithful
    under a common invariant `Q` that both preserve, then on every `Q`-satisfying entry the encoded
    blocks have equal `foldStraight` denotations — the conditional analogue of `Correct_to_BlockEquiv`.
    (Full `BlockEquiv` requires equality on ALL entries; this gives it on the `Q`-reachable ones, which
    is exactly where the compute-op rewrite is meaningful — the DAG only produces `Q`-valid states.) -/
theorem Correct_to_foldEq_on (enc : Op Bytes → List Instr) (Q : Stack → Stack → Prop)
    {src dst : List (Op Bytes)}
    (hs : ∀ op ∈ src, SimOpOn Q op (enc op)) (hd : ∀ op ∈ dst, SimOpOn Q op (enc op))
    (hps : ∀ op ∈ src, ∀ (st al : Stack) (p : Stack × Stack),
        Q st al → LeanBCH.Opt.step op (st, al) = some p → Q p.1 p.2)
    (hpd : ∀ op ∈ dst, ∀ (st al : Stack) (p : Stack × Stack),
        Q st al → LeanBCH.Opt.step op (st, al) = some p → Q p.1 p.2)
    (h : LeanBCH.Opt.Correct src dst)
    (st al : Stack) (hQ : Q st al) :
    foldStraight (src.flatMap enc) st al = foldStraight (dst.flatMap enc) st al := by
  rw [run_via_encode_on enc Q src hs hps st al hQ, run_via_encode_on enc Q dst hd hpd st al hQ]
  exact h (st, al)

end LeanBCH.Opt.Adapter
