/-
  Wave D — residual surface as named cryptographic games.

  Games are not discharged from ℤ. They package the four literature residuals
  in adversary-style form so SOUNDNESS/Warrant can cite games, not monoline fog.
-/
import FriStark.Soundness.Residual
import FriStark.Soundness.Capacity
import FriStark.Hash.Sha256
import FriStark.Params.V1

namespace FriStark.Soundness.Games

open FriStark.Soundness.Residual
open FriStark.Soundness.Capacity
open FriStark.Hash.Sha256
open FriStark.Params.V1

/-! ### SHA-256 collision game -/

/-- Adversary output: two messages. -/
structure CollisionAdv where
  m0 : Bytes
  m1 : Bytes

/-- Break: distinct messages, same digest under project SHA-256. -/
def BreaksCollisionResistance (A : CollisionAdv) : Prop :=
  A.m0 ≠ A.m1 ∧ FriStark.Hash.Sha256.hash A.m0 = FriStark.Hash.Sha256.hash A.m1
/-- Residual premise: no collision adversary wins (literature CR). -/
def CollisionResistanceGame : Prop :=
  Sha256CollisionResistance

theorem collision_game_of_shaCR (h : Sha256CollisionResistance) :
    CollisionResistanceGame := h

/-! ### Fiat–Shamir / RO game (transcript-level residual) -/

/-- Residual: FS challenges behave as RO for the exact absorb/challenge API. -/
def FiatShamirROGame : Prop :=
  FiatShamirRandomOracle

theorem fs_game_of_shaRO (h : Sha256RandomOracle) : FiatShamirROGame :=
  fiatShamir_of_sha256RO h

/-! ### FRI proximity / capacity game (single residual packaging) -/

/--
  FRI security game at V1 rate: capacity-regime + multi-query independence
  at (ρ=2/BLOWUP, queries=QUERIES, bits/query=10).

  Literature residual — not proved from field arithmetic (see SOUNDNESS.md).
-/
def FriSecurityGame : Prop :=
  CapacityRegimeAtRate 2 BLOWUP bitsPerQueryV1 ∧
  IndependentFRIQueries QUERIES bitsPerQueryV1

theorem fri_game_of_cap_residuals
    (hC : CapacityRegimeAtRate 2 BLOWUP bitsPerQueryV1)
    (hI : IndependentFRIQueries QUERIES bitsPerQueryV1) :
    FriSecurityGame := ⟨hC, hI⟩

theorem ethStarkV1_of_fri_game (h : FriSecurityGame) : EthStarkCapacityV1 :=
  ethStarkV1_of_residuals h.1 h.2

/-! ### ResidualGames (Wave D canonical) -/

structure ResidualGames where
  fri : FriSecurityGame
  fs : FiatShamirROGame
  cr : CollisionResistanceGame

def ResidualGames.toPremises (R : ResidualGames) : ResidualPremises where
  ethStark := ethStarkV1_of_fri_game R.fri
  shaRO := R.fs
  shaCR := R.cr

theorem ResidualGames.cryptoBits_eq_104 (R : ResidualGames) :
    (R.toPremises).cryptoBits = 104 :=
  ResidualPremises.cryptoBits_eq_104 R.toPremises

/-- Canonical residual game names (3 games; capacity split packaged inside FriSecurityGame). -/
def residualGameNames : List String :=
  [ "FriSecurityGame"
  , "FiatShamirROGame"
  , "CollisionResistanceGame"
  ]

theorem residual_game_count : residualGameNames.length = 3 := by native_decide

/-- Underlying axioms still 4 (FriSecurityGame expands to 2 capacity axioms + 2 hash). -/
def underlyingAxiomNames : List String := residualNames

theorem underlying_axiom_count : underlyingAxiomNames.length = 4 := by native_decide

/-- Break surface aligned with games. -/
inductive BreaksGame where
  | friSecurity
  | fiatShamirRO
  | collisionResistance
  deriving DecidableEq, Repr

def breaksGameName : BreaksGame → String
  | .friSecurity => "FriSecurityGame"
  | .fiatShamirRO => "FiatShamirROGame"
  | .collisionResistance => "CollisionResistanceGame"

/--
  Residual break **evidence** (not a free enum).
  Three typed classes matching ResidualGames — each requires real proof material:
  - fri: prove ¬FriSecurityGame (capacity/independence residual fails)
  - fs: prove ¬FiatShamirROGame
  - collision: concrete SHA-256 collision adversary
  Therefore `Nonempty ResidualBreakEvidence` is **not** automatically true.
-/
inductive ResidualBreakEvidence where
  | fri (hBreak : ¬ FriSecurityGame)
  | fs (hBreak : ¬ FiatShamirROGame)
  | collision (A : CollisionAdv) (hBreak : BreaksCollisionResistance A)

/-- Which residual game this evidence breaks. -/
def ResidualBreakEvidence.breaksWhich : ResidualBreakEvidence → BreaksGame
  | .fri _ => .friSecurity
  | .fs _ => .fiatShamirRO
  | .collision _ _ => .collisionResistance

/--
  Under residual games R (the three-game package), a break is inhabited only by
  ResidualBreakEvidence. R is the package the crown is stated under; evidence
  targets the same game surface (fri / fs / collision).
-/
def ResidualBroken (_R : ResidualGames) : Prop :=
  Nonempty ResidualBreakEvidence

/-- Map legacy BreaksResidual labels into game names (bookkeeping only). -/
def BreaksResidual.toBreaksGame : BreaksResidual → BreaksGame
  | .capacityRegimeAtRate => .friSecurity
  | .independentFRIQueries => .friSecurity
  | .sha256RO => .fiatShamirRO
  | .sha256CR => .collisionResistance

/-- Every evidence targets one of the three residual games (not free labels). -/
theorem residual_break_evidence_targets_game
    (e : ResidualBreakEvidence) :
    e.breaksWhich = .friSecurity ∨
    e.breaksWhich = .fiatShamirRO ∨
    e.breaksWhich = .collisionResistance := by
  cases e <;> simp [ResidualBreakEvidence.breaksWhich]

/-- Collision evidence carries a concrete CR break. -/
theorem residual_break_collision_has_adv
    (A : CollisionAdv) (h : BreaksCollisionResistance A) :
    BreaksCollisionResistance A := h

end FriStark.Soundness.Games
