/-
  Production FRI parameter pin (Params.V1).
  Must match vendor/bch-fri-stark/apps/native_ct_air_config.py and freeze-a0/FRI_PARAMS.md.
  Changing any constant requires Params.V2 + new evidence — no silent edit.
-/
namespace FriStark.Params.V1

/-- Goldilocks prime P = 2^64 - 2^32 + 1. -/
def P : Nat := (1 <<< 64) - (1 <<< 32) + 1

def EXT_NONRES : Nat := 7
def BLOWUP : Nat := 2048
def QUERIES : Nat := 8
def GRIND_BITS : Nat := 24
def FOLD : Nat := 8
def MASK_DEG : Nat := 64
def MERKLE_HASH_BYTES : Nat := 32
def SECURITY_TARGET_BITS : Nat := 100

/-- log2(2048) = 11; per-query bits = log2(BLOWUP)-1 = 10. -/
def log2Blowup : Nat := 11
def perQueryBits : Nat := log2Blowup - 1  -- 10

/-- Headline soundness: QUERIES * (log2(BLOWUP)-1) + GRIND_BITS = 8*10+24 = 104. -/
def SECURITY_BITS : Nat := QUERIES * perQueryBits + GRIND_BITS

theorem security_bits_eq_104 : SECURITY_BITS = 104 := by native_decide
theorem security_meets_target : SECURITY_TARGET_BITS ≤ SECURITY_BITS := by native_decide
theorem mask_floor : 4 * QUERIES ≤ MASK_DEG := by native_decide
theorem blowup_pin : BLOWUP = 2048 := rfl
theorem queries_pin : QUERIES = 8 := rfl
theorem grind_pin : GRIND_BITS = 24 := rfl
theorem fold_pin : FOLD = 8 := rfl

end FriStark.Params.V1
