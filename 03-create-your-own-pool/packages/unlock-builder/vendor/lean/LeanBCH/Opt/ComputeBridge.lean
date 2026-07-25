/-
  LeanBCH.Opt.ComputeBridge — where per-opcode faithfulness (OpFaithful) MEETS the conditional
  composition (CondBridge). This is the joint the red-team said was missing: a compute op that is
  genuinely faithful to `stepInstr` AND enters the block-level `run_via_encode_on` bridge.

  The arith faithfulness `OpFaithful.sim_CALL_arith` is CONDITIONAL (operands canonical, divisor
  nonzero). `CondBridge.SimOpOn`/`run_via_encode_on` compose exactly such conditional witnesses under
  a threaded invariant. Here we package the arith witness as a `SimOpOn` over the precise precondition
  (`ArithPre`), so an arith `CALL` node drops into the same composition as the unconditional shuffle
  `SimOp`s (via `SimOp.toOn`) — the abstract-machine guarantee reaching the real VM for compute ops.
-/
import LeanBCH.Opt.OpFaithful
import LeanBCH.Opt.CondBridge

namespace LeanBCH.Opt.Adapter
open LeanBCH LeanBCH.VM LeanBCH.Opt LeanBCH.Opt.Op LeanBCH.Opt.OpFaithful

/-- The precondition an arith `CALL 2 (arithSem k)` node requires to be `stepInstr`-faithful: its two
    operands — the top two stack items `b` (top), `a` (2nd) — are canonically-encoded VM numbers, and
    for div/mod the divisor `b` is nonzero. This is exactly what the value-DAG typing guarantees (a
    node's operands are outputs of number-producing nodes or canonical constants), so it holds
    whenever the node fires — it is threaded as the `run_via_encode_on` invariant, never dropped. -/
def ArithPre (k : ArithKind) : Stack → Stack → Prop := fun st _ =>
  ∃ (a b : Bytes) (rest : Stack), st = b :: a :: rest
    ∧ readNum? a = some (toNum a) ∧ readNum? b = some (toNum b)
    ∧ ((k = .div ∨ k = .mod) → toNum b ≠ 0)

/-- ★ A COMPUTE OP ENTERS THE CONDITIONAL COMPOSITION. The single-instruction encoding `[arithInstr k]`
    realizes the abstract `CALL 2 (arithSem k)` node on every state satisfying `ArithPre k` — i.e.
    `OpFaithful.sim_CALL_arith` packaged as a `CondBridge.SimOpOn`. With `Q := ArithPre k` (and the
    shuffle ops embedded by `SimOp.toOn`), `run_via_encode_on` now carries an arith rewrite from the
    abstract machine to the real `foldStraight`/`stepInstr` VM — the compute-op half of the bridge the
    audit found missing, discharged (not assumed) for the arithmetic class. -/
theorem simOpOn_arith (k : ArithKind) :
    SimOpOn (ArithPre k) (Op.CALL 2 (arithSem k)) [arithInstr k] := by
  rintro st al ⟨a, b, rest, rfl, ha, hb, hnz⟩
  exact sim_CALL_arith k rest al a b ha hb hnz

/-! ### The non-arith compute classes, packaged as `SimOpOn` (item 1: full table connected).

    Each `OpFaithful` witness (increment 2) is packaged over its LOCAL precondition. Note there is NO
    single global "all stack values canonical" invariant: a HASH node pushes a 20/32-byte digest that
    is NOT a canonical VM number, so canonicity is a per-node TYPING property, not a stack invariant —
    which is exactly why discharging these preconditions needs the value-DAG typing (`Dag.WellFormed`),
    the next increment. Here we expose each op's local precondition so the composition can consume it. -/

/-- Unary numeric/bool node precondition: one operand present and canonically encoded. -/
def UnaryPre : Stack → Stack → Prop := fun st _ =>
  ∃ (x : Bytes) (rest : Stack), st = x :: rest ∧ readNum? x = some (toNum x)
/-- Binary numeric/predicate node precondition: top two operands present and canonically encoded. -/
def BinPre : Stack → Stack → Prop := fun st _ =>
  ∃ (a b : Bytes) (rest : Stack), st = b :: a :: rest
    ∧ readNum? a = some (toNum a) ∧ readNum? b = some (toNum b)
/-- Hash node precondition: one operand present (hashes are TOTAL over bytes — no encoding check). -/
def HashPre : Stack → Stack → Prop := fun st _ => ∃ (x : Bytes) (rest : Stack), st = x :: rest

-- Unary numeric (1ADD/1SUB/NEGATE/ABS) ---------------------------------------
theorem simOpOn_1ADD : SimOpOn UnaryPre (Op.CALL 1 (unaryNumSem (· + 1))) [opInstr 0x8b] := by
  rintro st al ⟨x, rest, rfl, hx⟩; exact sim_CALL_1ADD rest al x hx
theorem simOpOn_1SUB : SimOpOn UnaryPre (Op.CALL 1 (unaryNumSem (· - 1))) [opInstr 0x8c] := by
  rintro st al ⟨x, rest, rfl, hx⟩; exact sim_CALL_1SUB rest al x hx
theorem simOpOn_NEGATE : SimOpOn UnaryPre (Op.CALL 1 (unaryNumSem (fun x => -x))) [opInstr 0x8f] := by
  rintro st al ⟨x, rest, rfl, hx⟩; exact sim_CALL_NEGATE rest al x hx
theorem simOpOn_ABS : SimOpOn UnaryPre (Op.CALL 1 (unaryNumSem (fun x => (x.natAbs : Int)))) [opInstr 0x90] := by
  rintro st al ⟨x, rest, rfl, hx⟩; exact sim_CALL_ABS rest al x hx

-- Unary boolean (NOT/0NOTEQUAL) ----------------------------------------------
theorem simOpOn_NOT : SimOpOn UnaryPre (Op.CALL 1 (unaryBoolSem (· == 0))) [opInstr 0x91] := by
  rintro st al ⟨x, rest, rfl, hx⟩; exact sim_CALL_NOT rest al x hx
theorem simOpOn_0NOTEQUAL : SimOpOn UnaryPre (Op.CALL 1 (unaryBoolSem (· != 0))) [opInstr 0x92] := by
  rintro st al ⟨x, rest, rfl, hx⟩; exact sim_CALL_0NOTEQUAL rest al x hx

-- Binary numeric (MIN/MAX) ---------------------------------------------------
theorem simOpOn_MIN : SimOpOn BinPre (Op.CALL 2 (binNumSem (fun a b => if a ≤ b then a else b))) [opInstr 0xa3] := by
  rintro st al ⟨a, b, rest, rfl, ha, hb⟩; exact sim_CALL_MIN rest al a b ha hb
theorem simOpOn_MAX : SimOpOn BinPre (Op.CALL 2 (binNumSem (fun a b => if a ≤ b then b else a))) [opInstr 0xa4] := by
  rintro st al ⟨a, b, rest, rfl, ha, hb⟩; exact sim_CALL_MAX rest al a b ha hb

-- Binary boolean predicates (comparisons) ------------------------------------
theorem simOpOn_BOOLAND : SimOpOn BinPre (Op.CALL 2 (binBoolSem (fun a b => a != 0 && b != 0))) [opInstr 0x9a] := by
  rintro st al ⟨a, b, rest, rfl, ha, hb⟩; exact sim_CALL_BOOLAND rest al a b ha hb
theorem simOpOn_BOOLOR : SimOpOn BinPre (Op.CALL 2 (binBoolSem (fun a b => a != 0 || b != 0))) [opInstr 0x9b] := by
  rintro st al ⟨a, b, rest, rfl, ha, hb⟩; exact sim_CALL_BOOLOR rest al a b ha hb
theorem simOpOn_NUMEQUAL : SimOpOn BinPre (Op.CALL 2 (binBoolSem (fun a b => a == b))) [opInstr 0x9c] := by
  rintro st al ⟨a, b, rest, rfl, ha, hb⟩; exact sim_CALL_NUMEQUAL rest al a b ha hb
theorem simOpOn_NUMNOTEQUAL : SimOpOn BinPre (Op.CALL 2 (binBoolSem (fun a b => a != b))) [opInstr 0x9e] := by
  rintro st al ⟨a, b, rest, rfl, ha, hb⟩; exact sim_CALL_NUMNOTEQUAL rest al a b ha hb
theorem simOpOn_LESSTHAN : SimOpOn BinPre (Op.CALL 2 (binBoolSem (fun a b => decide (a < b)))) [opInstr 0x9f] := by
  rintro st al ⟨a, b, rest, rfl, ha, hb⟩; exact sim_CALL_LESSTHAN rest al a b ha hb
theorem simOpOn_GREATERTHAN : SimOpOn BinPre (Op.CALL 2 (binBoolSem (fun a b => decide (a > b)))) [opInstr 0xa0] := by
  rintro st al ⟨a, b, rest, rfl, ha, hb⟩; exact sim_CALL_GREATERTHAN rest al a b ha hb
theorem simOpOn_LESSTHANOREQUAL : SimOpOn BinPre (Op.CALL 2 (binBoolSem (fun a b => decide (a ≤ b)))) [opInstr 0xa1] := by
  rintro st al ⟨a, b, rest, rfl, ha, hb⟩; exact sim_CALL_LESSTHANOREQUAL rest al a b ha hb
theorem simOpOn_GREATERTHANOREQUAL : SimOpOn BinPre (Op.CALL 2 (binBoolSem (fun a b => decide (a ≥ b)))) [opInstr 0xa2] := by
  rintro st al ⟨a, b, rest, rfl, ha, hb⟩; exact sim_CALL_GREATERTHANOREQUAL rest al a b ha hb

-- Hash ops (UNCONDITIONAL beyond operand presence) ---------------------------
theorem simOpOn_RIPEMD160 : SimOpOn HashPre (Op.CALL 1 (hashSem Crypto.ripemd160)) [opInstr 0xa6] := by
  rintro st al ⟨x, rest, rfl⟩; exact sim_CALL_RIPEMD160 rest al x
theorem simOpOn_SHA1 : SimOpOn HashPre (Op.CALL 1 (hashSem Crypto.sha1)) [opInstr 0xa7] := by
  rintro st al ⟨x, rest, rfl⟩; exact sim_CALL_SHA1 rest al x
theorem simOpOn_SHA256 : SimOpOn HashPre (Op.CALL 1 (hashSem Crypto.sha256)) [opInstr 0xa8] := by
  rintro st al ⟨x, rest, rfl⟩; exact sim_CALL_SHA256 rest al x
theorem simOpOn_HASH160 : SimOpOn HashPre (Op.CALL 1 (hashSem Crypto.hash160)) [opInstr 0xa9] := by
  rintro st al ⟨x, rest, rfl⟩; exact sim_CALL_HASH160 rest al x
theorem simOpOn_HASH256 : SimOpOn HashPre (Op.CALL 1 (hashSem Crypto.hash256)) [opInstr 0xaa] := by
  rintro st al ⟨x, rest, rfl⟩; exact sim_CALL_HASH256 rest al x

end LeanBCH.Opt.Adapter
