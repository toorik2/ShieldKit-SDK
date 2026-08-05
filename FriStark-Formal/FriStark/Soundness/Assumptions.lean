/-
  Residual trust assumptions — compatibility façade.
-/
import FriStark.Soundness.Residual
import FriStark.Soundness.Capacity
import FriStark.Params.V1

namespace FriStark.Soundness.Assumptions

open FriStark.Soundness.Residual
open FriStark.Soundness.Capacity
open FriStark.Params.V1

abbrev friCapacityRegime : Prop := FriCapacityRegime
abbrev randomOracleFiatShamir : Prop := FiatShamirRandomOracle
abbrev merkleCollisionResistance : Prop := Sha256CollisionResistance
abbrev sha256CollisionResistance : Prop := Sha256CollisionResistance
abbrev ethStarkCapacity : Prop := EthStarkCapacityV1
abbrev sha256RandomOracle : Prop := Sha256RandomOracle
abbrev capacityRegimeAtRate : Prop := CapacityRegimeAtRate 2 BLOWUP bitsPerQueryV1
abbrev independentFRIQueries : Prop := IndependentFRIQueries QUERIES bitsPerQueryV1

def residualNames : List String := Residual.residualNames

theorem residual_count : residualNames.length = 4 := Residual.residual_count

def legacyResidualNames : List String :=
  [ "friCapacityRegime"
  , "randomOracleFiatShamir"
  , "merkleCollisionResistance"
  ]

theorem legacy_residual_count : legacyResidualNames.length = 3 := by native_decide

def dischargeMap : List (String × String) :=
  [ ("EthStarkCapacity", "CapacityRegimeAtRate+IndependentFRIQueries (package)")
  , ("FriCapacityRegime", "EthStarkCapacityV1")
  , ("FiatShamirRandomOracle", "Sha256RandomOracle")
  , ("MerkleCollisionResistance", "Sha256CollisionResistance")
  ]

theorem discharge_map_count : dischargeMap.length = 4 := by native_decide

theorem fri_is_v1_pack : FriCapacityRegime ↔ EthStarkCapacityV1 := fri_capacity_is_v1_pack

end FriStark.Soundness.Assumptions
