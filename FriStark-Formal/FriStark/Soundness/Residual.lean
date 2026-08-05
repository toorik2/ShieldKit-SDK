/-
  T4 residual surface after full ethSTARK capacity build-out.

  **Capacity (fully structured — see Capacity.lean):**
  - Proved: rate formula, V1 bits/query=10, multi-query 80, +grind 104, config WF
  - Axioms (literature only):
      CapacityRegimeAtRate, IndependentFRIQueries
  - `EthStarkCapacity` / `FriCapacityRegime` are **derived packages**, not axioms

  **Hash (standard crypto):**
  - Sha256RandomOracle, Sha256CollisionResistance

  **Canonical residual axiom list (4):**
  CapacityRegimeAtRate, IndependentFRIQueries, Sha256RandomOracle, Sha256CollisionResistance
-/
import FriStark.Params.V1
import FriStark.Soundness.Capacity

namespace FriStark.Soundness.Residual

open FriStark.Params.V1
open FriStark.Soundness.Capacity

/-! ### Re-export capacity residuals (axioms live in Capacity.lean) -/

export Capacity (CapacityRegimeAtRate IndependentFRIQueries EthStarkCapacityPack
  EthStarkCapacityV1 capacityBitsAtRate bitsPerQueryV1 configV1
  ethStarkV1_of_residuals capacityResidualNames ethStark_pack_shape)

/--
  Parameterized ethSTARK capacity — **derived package** (not an axiom).
  Requires well-formed rate + single-query capacity residual + query independence.
-/
def EthStarkCapacity (blowup queries rateNum rateDen : Nat) : Prop :=
  EthStarkCapacityPack blowup queries rateNum rateDen

/-- V1 composition rate pins. -/
def compositionRateNum : Nat := 2
def compositionRateDen : Nat := BLOWUP

theorem composition_rate_num_is_two : compositionRateNum = 2 := rfl
theorem composition_rate_den_eq_blowup : compositionRateDen = BLOWUP := rfl
theorem blowup_eq_2048 : BLOWUP = 2048 := blowup_pin

/-- FRI capacity for product pin — derived ethSTARK V1 pack. -/
def FriCapacityRegime : Prop := EthStarkCapacityV1

theorem friCapacity_iff_ethStarkV1 : FriCapacityRegime ↔ EthStarkCapacityV1 := Iff.rfl

theorem friCapacity_iff_ethStark_params :
    FriCapacityRegime ↔ EthStarkCapacity BLOWUP QUERIES 2 BLOWUP := Iff.rfl

/-!
### Hash residuals (standard crypto)
-/
axiom Sha256RandomOracle : Prop
axiom Sha256CollisionResistance : Prop

def FiatShamirRandomOracle : Prop := Sha256RandomOracle

theorem fiatShamir_of_sha256RO (h : Sha256RandomOracle) :
    FiatShamirRandomOracle := h

theorem friCapacity_of_ethStark
    (h : EthStarkCapacity BLOWUP QUERIES compositionRateNum compositionRateDen) :
    FriCapacityRegime := h

/-- Canonical **axiom** residual names (capacity structured + hash). -/
def residualNames : List String :=
  [ "CapacityRegimeAtRate"
  , "IndependentFRIQueries"
  , "Sha256RandomOracle"
  , "Sha256CollisionResistance"
  ]

theorem residual_count : residualNames.length = 4 := by native_decide

/-- Derived package names (not axioms). -/
def derivedResidualNames : List String :=
  [ "EthStarkCapacity"
  , "EthStarkCapacityV1"
  , "FriCapacityRegime"
  , "FiatShamirRandomOracle"
  ]

theorem derived_residual_count : derivedResidualNames.length = 4 := by native_decide

/-- Legacy aliases. -/
abbrev CapacityRegimeHolds : Prop := FriCapacityRegime
abbrev RandomOracleFiatShamir : Prop := FiatShamirRandomOracle
abbrev MerkleCollisionResistance : Prop := Sha256CollisionResistance

def capacityBitsPerQuery : Nat := bitsPerQueryV1

theorem capacity_bits_per_query_eq_10 : capacityBitsPerQuery = 10 := by native_decide
theorem capacity_bits_eq_perQueryBits : capacityBitsPerQuery = perQueryBits := by native_decide
theorem capacity_bits_eq_log_form : capacityBitsPerQuery = log2Blowup - 1 := by native_decide

def friQueryBitsAccounting : Nat := QUERIES * capacityBitsPerQuery

theorem fri_query_bits_eq_80 : friQueryBitsAccounting = 80 := by native_decide

def formulaBits : Nat := friQueryBitsAccounting + GRIND_BITS

theorem formula_bits_eq_104 : formulaBits = 104 := by native_decide
theorem formula_bits_eq_security : formulaBits = SECURITY_BITS := by native_decide

/--
  **Accounting only** (M1): V1 formula bits under the modeling package.
  Residual proof terms are **not** used — this is not a security theorem of those premises.
  Prefer `formulaBits` / `v1ScoreboardAccounting` in full-formalization crown.
-/
def cryptoSecurityBits
    (_hFri : EthStarkCapacityV1)
    (_hRO : Sha256RandomOracle)
    (_hCR : Sha256CollisionResistance) : Nat :=
  formulaBits

theorem crypto_security_bits_eq_104
    (hFri : EthStarkCapacityV1)
    (hRO : Sha256RandomOracle)
    (hCR : Sha256CollisionResistance) :
    cryptoSecurityBits hFri hRO hCR = 104 := by
  simp [cryptoSecurityBits, formula_bits_eq_104]

/-- Alias: explicit non-security name for scoreboard. -/
abbrev v1ScoreboardAccounting : Nat := formulaBits
theorem v1_scoreboard_is_formula : v1ScoreboardAccounting = formulaBits := rfl

/-- From the two capacity literature axioms → full V1 pack → 104 with hash. -/
def cryptoSecurityBitsFromCap
    (hCap : CapacityRegimeAtRate 2 BLOWUP bitsPerQueryV1)
    (hInd : IndependentFRIQueries QUERIES bitsPerQueryV1)
    (hRO : Sha256RandomOracle)
    (hCR : Sha256CollisionResistance) : Nat :=
  cryptoSecurityBits (ethStarkV1_of_residuals hCap hInd) hRO hCR

theorem crypto_from_cap_eq_104
    (hCap : CapacityRegimeAtRate 2 BLOWUP bitsPerQueryV1)
    (hInd : IndependentFRIQueries QUERIES bitsPerQueryV1)
    (hRO : Sha256RandomOracle)
    (hCR : Sha256CollisionResistance) :
    cryptoSecurityBitsFromCap hCap hInd hRO hCR = 104 :=
  crypto_security_bits_eq_104 (ethStarkV1_of_residuals hCap hInd) hRO hCR

def cryptoSecurityBitsDerived
    (hC : FriCapacityRegime)
    (hFS : FiatShamirRandomOracle)
    (hM : Sha256CollisionResistance) : Nat :=
  cryptoSecurityBits hC hFS hM

theorem crypto_security_bits_derived_eq_104
    (hC : FriCapacityRegime)
    (hFS : FiatShamirRandomOracle)
    (hM : Sha256CollisionResistance) :
    cryptoSecurityBitsDerived hC hFS hM = 104 :=
  crypto_security_bits_eq_104 hC hFS hM

inductive ResidualBreakClass where
  | capacityRegimeAtRate
  | independentFRIQueries
  | sha256RO
  | sha256CR
  deriving DecidableEq, Repr

def residualBreakName : ResidualBreakClass → String
  | .capacityRegimeAtRate => "CapacityRegimeAtRate"
  | .independentFRIQueries => "IndependentFRIQueries"
  | .sha256RO => "Sha256RandomOracle"
  | .sha256CR => "Sha256CollisionResistance"

inductive BreaksResidual where
  | capacityRegimeAtRate
  | independentFRIQueries
  | sha256RO
  | sha256CR
  deriving DecidableEq, Repr

def BreaksResidual.toClass : BreaksResidual → ResidualBreakClass
  | .capacityRegimeAtRate => .capacityRegimeAtRate
  | .independentFRIQueries => .independentFRIQueries
  | .sha256RO => .sha256RO
  | .sha256CR => .sha256CR

structure ResidualPremises where
  ethStark : EthStarkCapacityV1
  shaRO : Sha256RandomOracle
  shaCR : Sha256CollisionResistance

def ResidualPremises.fri (R : ResidualPremises) : FriCapacityRegime := R.ethStark
def ResidualPremises.fs (R : ResidualPremises) : FiatShamirRandomOracle := R.shaRO
def ResidualPremises.sha (R : ResidualPremises) : Sha256CollisionResistance := R.shaCR

def ResidualPremises.cryptoBits (R : ResidualPremises) : Nat :=
  cryptoSecurityBits R.ethStark R.shaRO R.shaCR

theorem ResidualPremises.cryptoBits_eq_104 (R : ResidualPremises) :
    R.cryptoBits = 104 :=
  crypto_security_bits_eq_104 R.ethStark R.shaRO R.shaCR

/-- Premises from the four literature/hash axioms. -/
structure ResidualPremisesExpanded where
  cap : CapacityRegimeAtRate 2 BLOWUP bitsPerQueryV1
  indep : IndependentFRIQueries QUERIES bitsPerQueryV1
  shaRO : Sha256RandomOracle
  shaCR : Sha256CollisionResistance

def ResidualPremisesExpanded.toPack (R : ResidualPremisesExpanded) : ResidualPremises where
  ethStark := ethStarkV1_of_residuals R.cap R.indep
  shaRO := R.shaRO
  shaCR := R.shaCR

theorem ResidualPremisesExpanded.cryptoBits_eq_104 (R : ResidualPremisesExpanded) :
    (R.toPack).cryptoBits = 104 :=
  ResidualPremises.cryptoBits_eq_104 R.toPack

abbrev ResidualBreak := ResidualBreakClass

/-- Derived pack is EthStarkCapacityV1 (definitional), not a Bool flag. -/
theorem fri_capacity_is_v1_pack : FriCapacityRegime ↔ EthStarkCapacityV1 := Iff.rfl

end FriStark.Soundness.Residual
