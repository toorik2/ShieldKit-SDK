/-
  Conjectural crypto layer — structured capacity + standard hash residuals.
-/
import FriStark.Soundness.Assumptions
import FriStark.Soundness.Residual
import FriStark.Soundness.Capacity
import FriStark.Params.V1

namespace FriStark.Soundness.Conjecture

open FriStark.Soundness.Residual
open FriStark.Soundness.Capacity
open FriStark.Params.V1

def residualOpaqueNames : List String := Residual.residualNames

theorem residual_names_match_assumptions :
    residualOpaqueNames = Residual.residualNames := rfl

def assumptionToConjecture : List (String × String) :=
  [ ("FriCapacityRegime", "CapacityRegimeAtRate+IndependentFRIQueries")
  , ("FiatShamirRandomOracle", "Sha256RandomOracle")
  , ("MerkleCollisionResistance", "Sha256CollisionResistance")
  ]

theorem assumption_map_count : assumptionToConjecture.length = 3 := by native_decide

/-- Residuals are Props used as premises (list non-empty). -/
theorem residual_surface_nonempty : residualOpaqueNames.length = 4 := by native_decide

theorem merkle_discharged_to_sha256 :
    MerkleCollisionResistance = Sha256CollisionResistance := rfl

theorem fs_discharged_to_sha256_ro :
    FiatShamirRandomOracle ↔ Sha256RandomOracle := Iff.rfl

theorem fri_discharged_to_ethstark :
    FriCapacityRegime ↔ EthStarkCapacityV1 := Iff.rfl

theorem ethstark_is_pack_not_axiom :
    EthStarkCapacity BLOWUP QUERIES 2 BLOWUP ↔ EthStarkCapacityPack BLOWUP QUERIES 2 BLOWUP :=
  Iff.rfl

end FriStark.Soundness.Conjecture
