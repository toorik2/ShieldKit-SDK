/-
  Query + grind security-bits accounting for Params.V1.

  Proved here (kernel / native_decide):
    SECURITY_BITS = QUERIES * (log2(BLOWUP) - 1) + GRIND_BITS
    = 8 * 10 + 24 = 104
    and SECURITY_BITS ≥ SECURITY_TARGET_BITS (100).

  Not proved here: that this bit count is a *cryptographic*
  soundness bound — that rests on Assumptions (capacity regime,
  RO-FS, Merkle CR). See evidence/SOUNDNESS.md.
-/
import FriStark.Params.V1

namespace FriStark.Soundness.QueryModel
open FriStark.Params.V1

/-- Headline bits from the pinned V1 definition. -/
def headlineBits : Nat := SECURITY_BITS

/-- Unfolded capacity-regime formula (same as freeze-a0 / native config). -/
def formulaBits : Nat := QUERIES * (log2Blowup - 1) + GRIND_BITS

/-- V1 `SECURITY_BITS` is definitionally the formula. -/
theorem security_bits_eq_formula : SECURITY_BITS = formulaBits := by
  native_decide

/-- log2 pin: BLOWUP = 2^11. -/
theorem blowup_is_2_pow_log2 : BLOWUP = 2 ^ log2Blowup := by
  native_decide

theorem log2_blowup_eq_11 : log2Blowup = 11 := by native_decide
theorem per_query_bits_eq_10 : perQueryBits = 10 := by native_decide

/-- Per-query contribution under capacity regime: log2(BLOWUP) − 1. -/
theorem per_query_eq_log2_minus_1 : perQueryBits = log2Blowup - 1 := rfl

/--
  Main T4 arithmetic claim:
  SECURITY_BITS = QUERIES * (log2(BLOWUP) - 1) + GRIND_BITS = 104
  for production V1 params (BLOWUP=2048, QUERIES=8, GRIND_BITS=24).
-/
theorem security_bits_eq_104 : SECURITY_BITS = 104 :=
  FriStark.Params.V1.security_bits_eq_104

theorem headline_104 : headlineBits = 104 := security_bits_eq_104

theorem formula_eq_104 : formulaBits = 104 := by
  rw [← security_bits_eq_formula]; exact security_bits_eq_104

/-- Expanded numeric check: 8 * 10 + 24 = 104. -/
theorem expanded_eq_104 :
    QUERIES * perQueryBits + GRIND_BITS = 104 := by
  native_decide

/-- Meets product floor SECURITY_TARGET_BITS = 100. -/
theorem security_meets_target : SECURITY_TARGET_BITS ≤ SECURITY_BITS :=
  FriStark.Params.V1.security_meets_target

theorem security_ge_100 : 100 ≤ SECURITY_BITS := by
  native_decide

/-- Fail-closed: headline is strictly above the 100-bit product gate. -/
theorem security_strictly_above_target : SECURITY_TARGET_BITS < SECURITY_BITS := by
  native_decide

end FriStark.Soundness.QueryModel
