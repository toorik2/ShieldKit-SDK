/-
  T4 FRI reductions: capacity accounting (Capacity.lean) + coset structure.
-/
import FriStark.Params.V1
import FriStark.Soundness.Residual
import FriStark.Soundness.Capacity
import FriStark.Soundness.QueryModel
import FriStark.Soundness.Games
import FriStark.FRI.Coset
import FriStark.Field.Ext

namespace FriStark.Soundness.FRIReduction

open FriStark.Params.V1
open FriStark.Soundness.Residual
open FriStark.Soundness.Capacity
open FriStark.Soundness.QueryModel
open FriStark.Soundness.Games
open FriStark.FRI.Coset
open FriStark.Field.Ext

theorem rate_num_is_two : compositionRateNum = 2 := rfl
theorem rate_den_is_blowup : compositionRateDen = 2048 := by native_decide

theorem per_query_capacity_bits :
    capacityBitsPerQuery = log2Blowup - 1 := by native_decide

theorem per_query_capacity_eq_model :
    capacityBitsPerQuery = perQueryBits := by native_decide

theorem multi_query_fri_bits :
    QUERIES * capacityBitsPerQuery = 80 := by native_decide

/-- Under V1 ethSTARK pack: FRI query bit count. -/
def friCryptoBits (_h : EthStarkCapacityV1) : Nat :=
  QUERIES * capacityBitsPerQuery

theorem fri_crypto_bits_eq_80 (h : EthStarkCapacityV1) :
    friCryptoBits h = 80 := by
  simp only [friCryptoBits, multi_query_fri_bits]

/-- Reductions use residual games: FriSecurityGame ⇒ V1 pack ⇒ 80 FRI bits. -/
theorem fri_bits_of_security_game (h : FriSecurityGame) :
    friCryptoBits (ethStarkV1_of_fri_game h) = 80 :=
  fri_crypto_bits_eq_80 _

theorem fri_plus_grind_of_security_game (h : FriSecurityGame) :
    friCryptoBits (ethStarkV1_of_fri_game h) + GRIND_BITS = 104 := by
  simp only [fri_bits_of_security_game h, GRIND_BITS]

def friCryptoBitsDerived (_h : FriCapacityRegime) : Nat :=
  QUERIES * capacityBitsPerQuery

theorem fri_plus_grind_eq_104 (h : EthStarkCapacityV1) :
    friCryptoBits h + GRIND_BITS = 104 := by
  simp only [friCryptoBits, multi_query_fri_bits, GRIND_BITS]

theorem fri_plus_grind_eq_104' (h : FriCapacityRegime) :
    friCryptoBitsDerived h + GRIND_BITS = 104 :=
  fri_plus_grind_eq_104 h

/-- From expanded capacity residuals alone: FRI bits = 80. -/
theorem fri_bits_from_cap_residuals
    (hCap : CapacityRegimeAtRate 2 BLOWUP bitsPerQueryV1)
    (hInd : IndependentFRIQueries QUERIES bitsPerQueryV1) :
    friCryptoBits (ethStarkV1_of_residuals hCap hInd) = 80 :=
  fri_crypto_bits_eq_80 _

example : cosetFold ([] : List E) [] 0 0 1 1 1 2 = none := by native_decide
example : cosetFold [zero] [] 0 0 0 1 1 2 = some zero := by native_decide

theorem verifyCosetFold_def (coset : List E) (betas : List E)
    (base li0 s off oN N : Nat) (expect : E) :
    verifyCosetFold coset betas base li0 s off oN N expect =
      (cosetFold coset betas base li0 s off oN N).any (fun got => eq got expect) := rfl

theorem fold_pin_8 : FOLD = 8 := fold_pin
theorem blowup_pow2 : BLOWUP = 2 ^ log2Blowup := by native_decide

theorem fri_capacity_is_ethstark :
    FriCapacityRegime ↔ EthStarkCapacity BLOWUP QUERIES compositionRateNum compositionRateDen :=
  Iff.rfl

theorem capacity_bits_at_rate_v1 :
    capacityBitsAtRate 2 BLOWUP = some 10 := capacityBits_v1_rate

theorem config_v1_wf : configV1.wellFormed := configV1_wellFormed

end FriStark.Soundness.FRIReduction
