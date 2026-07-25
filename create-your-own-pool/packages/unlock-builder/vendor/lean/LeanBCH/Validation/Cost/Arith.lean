/-
  KATs for LeanBCH.Cost.Arith, extracted into the validation layer.

  Edge-case witnesses PINNING the arithmetic billing at the 0x80 boundaries (the spec surface),
  driven through the model's `arithCost`. `decide` reduces the fuel-based `intByteLen`, so no
  `native_decide` — axioms stay clean.
-/
import LeanBCH.Cost.Arith

namespace LeanBCH.Validation

open LeanBCH (ArithKind intByteLen)
open LeanBCH.Cost

-- ADD across the 0x80 boundary: 127+1 = 128 needs a sign pad (2 bytes) ⇒ double-bill 2+2.
example : arithCost .add 127 1 128 =
  { evaluatedInstructionCount := 1, arithmeticCost := 2, stackPushedBytes := 2 } := by decide
-- SUB producing 0: empty result item, 0 bytes ⇒ costs nothing beyond the tick.
example : arithCost .sub 5 5 0 =
  { evaluatedInstructionCount := 1, arithmeticCost := 0, stackPushedBytes := 0 } := by decide
-- MUL: 128(2B) * 2(1B) operand pre-charge = 2; result 256(2B) double-bill ⇒ arith 2+2=4.
example : arithCost .mul 128 2 256 =
  { evaluatedInstructionCount := 1, arithmeticCost := 4, stackPushedBytes := 2 } := by decide
-- DIV: 1000(2B) / 3(1B) operand pre-charge = 2; tdiv 1000/3 = 333 (2B) double-bill ⇒ 2+2.
example : arithCost .div 1000 3 333 =
  { evaluatedInstructionCount := 1, arithmeticCost := 2 + 2, stackPushedBytes := 2 } := by decide
-- MOD: negative dividend ⇒ negative remainder (tmod). |a|·|b| = 2*1 = 2; result -1 is 1B.
example : arithCost .mod (-255) 2 (-1) =
  { evaluatedInstructionCount := 1, arithmeticCost := 2 + 1, stackPushedBytes := 1 } := by decide
-- Zero operand: 0(0B) * b = 0 pre-charge; 0/b = 0 result (0B) ⇒ everything zero.
example : arithCost .div 0 7 0 =
  { evaluatedInstructionCount := 1, arithmeticCost := 0, stackPushedBytes := 0 } := by decide

end LeanBCH.Validation
