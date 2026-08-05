/-
  LeanBCH.Cost.Arith — the arithmeticCost tier (Stage C) of the BCH-2026 cost model.

  Transcribed from `stackcert/Stackcert/Cost/Arith.lean`, re-proven over the LeanBCH
  leaves: `intByteLen` (now `LeanBCH.intByteLen`, Number), `ArithKind`/`billsOperands`
  (now `LeanBCH.ArithKind`, Kinds), `Metrics` (now `LeanBCH.Cost.Metrics`).

  The |a|·|b| operand pre-charge that DOMINATES pairing cost, plus the result-byte
  DOUBLE-BILLING every numeric op pays. Both are read straight off libauth's own
  arithmetic path (instruction-sets/common/arithmetic.js + combinators.js) and pinned
  by the BUILD-TIME cost differential (`conformance/cost/`, run by `LeanBCH.VM.CostDifferential`)
  against real libauth 3.1.0-next.8 — libauth is the spec of record.

  The two libauth mechanisms, verbatim:
   • `measureArithmeticCost` (MUL/DIV/MOD only): reads the top-two stack items and
     `arithmeticCost += firstLength * secondLength` — the two OPERAND byte widths,
     i.e. `intByteLen a * intByteLen b`. ADD/SUB skip this entirely.
   • `pushToStackVmNumberChecked` (ALL five, `hasEncodingCost = true`): the N-byte
     result is charged to `arithmeticCost += encoded.length` AND `pushToStack` charges
     the same N to `stackPushedBytes`. So an N-byte numeric RESULT costs 2N — it is
     billed to BOTH metrics (the double-billing).

  `intByteLen` models libauth's `bigIntToVmNumber` encoded length, so
  `firstLength`/`secondLength`/`encoded.length` all equal `intByteLen` of the value.
  The `result` argument is the pushed value `a <kind> b` under JS-BigInt TRUNCATED
  div/mod (sign follows the dividend, `Int.tdiv`/`Int.tmod` — the eval harness feeds it).

  No epoch dependency: arithCost is width-based, not pin-based.
-/
import LeanBCH.Number
import LeanBCH.Kinds
import LeanBCH.Cost.Metrics

namespace LeanBCH.Cost

open LeanBCH (ArithKind intByteLen)

/-- The pushed value `a <kind> b`, matching libauth (JS BigInt) semantics: truncated
    division/remainder (`Int.tdiv`/`Int.tmod`, sign follows the dividend), so
    `intByteLen (arithResult k a b)` equals `bigIntToVmNumber(result).length`. This is
    both what the `ARITH` node's `sem` pushes and what `kappaStep` bills as result-bytes —
    a single source of truth shared by the cost fold and the differential harness.
    `a` = 2nd-from-top operand, `b` = top. -/
def arithResult : ArithKind → Int → Int → Int
  | .mul, a, b => a * b
  | .add, a, b => a + b
  | .sub, a, b => a - b
  | .div, a, b => Int.tdiv a b
  | .mod, a, b => Int.tmod a b

/-- Per-op `Metrics` delta of a binary arithmetic opcode, EXACTLY matching real libauth
    BCH2026 (`arithmetic.js`::measureArithmeticCost + `combinators.js`::
    pushToStackVmNumberChecked/pushToStack), differentially pinned by `conformance/cost/`
    (build-time, `LeanBCH.VM.CostDifferential`).

    `a`, `b` are the operands (2nd-from-top, top); `result` is the pushed value
    `a <kind> b` (JS-BigInt truncated div/mod). The N-byte result is billed to BOTH
    `arithmeticCost` and `stackPushedBytes` (2N total); MUL/DIV/MOD additionally pre-charge
    `intByteLen a * intByteLen b` to `arithmeticCost`. `evaluatedInstructionCount := 1`
    is the usual per-op tick (a drop-in delta for `kappaStep`). -/
def arithCost (k : ArithKind) (a b result : Int) : Metrics :=
  let operand : Nat := if k.billsOperands then intByteLen a * intByteLen b else 0
  let resultBytes : Nat := intByteLen result
  { evaluatedInstructionCount := 1
    arithmeticCost   := operand + resultBytes
    stackPushedBytes := resultBytes }

/-- THE DOUBLE-BILLING, stated: the result bytes charged to `stackPushedBytes` are ALSO
    inside `arithmeticCost`, on top of the (MUL/DIV/MOD) operand pre-charge. -/
theorem arithCost_double_bill (k : ArithKind) (a b result : Int) :
    (arithCost k a b result).arithmeticCost
      = (if k.billsOperands then intByteLen a * intByteLen b else 0)
        + (arithCost k a b result).stackPushedBytes := rfl

/-- ADD/SUB pay ONLY the result-byte double-bill: `arithmeticCost = stackPushedBytes`
    (both `= intByteLen result`); there is no `|a|·|b|` operand pre-charge. -/
theorem arithCost_addSub_no_operand (k : ArithKind) (h : k.billsOperands = false)
    (a b result : Int) :
    (arithCost k a b result).arithmeticCost = (arithCost k a b result).stackPushedBytes := by
  simp only [arithCost, h, Bool.false_eq_true, if_false, Nat.zero_add]

/-- MUL/DIV/MOD pay the operand pre-charge `|a|·|b|` PLUS the result-byte double-bill. -/
theorem arithCost_mulDivMod_operand (k : ArithKind) (h : k.billsOperands = true)
    (a b result : Int) :
    (arithCost k a b result).arithmeticCost
      = intByteLen a * intByteLen b + intByteLen result := by
  simp only [arithCost, h, if_true]

-- KATs moved to LeanBCH/Validation/Cost/Arith.lean (validation layer).

end LeanBCH.Cost
