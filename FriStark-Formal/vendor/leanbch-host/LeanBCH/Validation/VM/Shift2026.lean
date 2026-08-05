/-
  KATs for LeanBCH.VM.Shift2026, extracted into the validation layer.

  Byte/value witnesses for the BCH-2026 bitwise ops (OP_INVERT, numeric/binary shifts),
  cross-checked against libauth semantics. Fuel-free `decide` obligations the kernel discharges
  every build. The op helpers themselves stay in the model file (used by Meter/Extended/Invariants);
  this module only exercises them.
-/
import LeanBCH.VM.Shift2026

namespace LeanBCH.Validation
open LeanBCH LeanBCH.VM

-- Byte / value witnesses (cross-checked against libauth semantics).
example : opInvert [0x0f, 0xf0] = [0xf0, 0x0f] := by decide
example : opInvert [0x00, 0xff] = [0xff, 0x00] := by decide
example : lshiftNum 1 4 = 16 := by decide
example : lshiftNum 3 2 = 12 := by decide
example : lshiftNum 0 8 = 0 := by decide
example : lshiftNum (-1) 3 = -8 := by decide
example : rshiftNum 16 2 = 4 := by decide
example : rshiftNum 5 1 = 2 := by decide
example : rshiftNum (-1) 1 = -1 := by decide      -- arithmetic shift: -1 stays -1
example : rshiftNum (-5) 1 = -3 := by decide      -- floor(-2.5) = -3
-- binary bit-buffer shifts (fixed length; carry across bytes; boundary at whole-byte shift)
example : lshiftBin [0x01] 1 = [0x02] := by decide
example : lshiftBin [0x80] 1 = [0x00] := by decide           -- top bit dropped
example : lshiftBin [0x00, 0x80] 1 = [0x01, 0x00] := by decide -- carry byte1→byte0
example : lshiftBin [0xab, 0xcd] 8 = [0xcd, 0x00] := by decide -- whole-byte shift
example : rshiftBin [0x02] 1 = [0x01] := by decide
example : rshiftBin [0x01] 1 = [0x00] := by decide           -- low bit dropped
example : rshiftBin [0x80, 0x00] 1 = [0x40, 0x00] := by decide
example : rshiftBin [0xab, 0xcd] 8 = [0x00, 0xab] := by decide -- whole-byte shift

end LeanBCH.Validation
