/-
  S0 residual classification — kill-list complete.
  R1/R2 frozen eternal literature (proximity STARK hyps); R3/R4 eternal crypto;
  scoreboard is formula accounting, not residual-premise security.
-/
import FriStark.Soundness.Residual
import FriStark.Soundness.Capacity
import FriStark.Soundness.Games
import FriStark.Params.V1

namespace FriStark.Soundness.ResidualKill

open FriStark.Soundness.Residual
open FriStark.Soundness.Capacity
open FriStark.Soundness.Games
open FriStark.Params.V1
-- capacityBitsAtRate, multiQueryFriBits, bitsPerQueryV1, formulaBits, cryptoSecurityBits

/-- Residual disposition. No free "activeBuild" fog after R1/R2 freeze. -/
inductive ResidualDisposition where
  | eternalLiterature -- proximity/capacity STARK literature hyp (not from ℤ)
  | eternalCrypto     -- standard hash RO/CR modeling
  | packageOnly       -- alias of other residuals
  | eternalOps        -- process / ops NONCLAIM
  deriving DecidableEq, Repr

structure ResidualEntry where
  id : String
  name : String
  disposition : ResidualDisposition
  reason : String
  deriving Repr

def residualKillTable : List ResidualEntry :=
  [ { id := "R1", name := "CapacityRegimeAtRate"
    , disposition := .eternalLiterature
    , reason := "ethSTARK-style capacity/proximity literature hyp; not theorem of Goldilocks alone" }
  , { id := "R2", name := "IndependentFRIQueries"
    , disposition := .eternalLiterature
    , reason := "multi-query FRI independence literature hyp; not theorem of field arithmetic alone" }
  , { id := "R3", name := "Sha256RandomOracle"
    , disposition := .eternalCrypto
    , reason := "FS modeled as RO; standard crypto assumption, not from ℤ" }
  , { id := "R4", name := "Sha256CollisionResistance"
    , disposition := .eternalCrypto
    , reason := "Merkle/FS hash CR; standard crypto assumption, not from ℤ" }
  , { id := "G1", name := "FriSecurityGame"
    , disposition := .packageOnly
    , reason := "package of R1 ∧ R2 only" }
  , { id := "G2", name := "FiatShamirROGame"
    , disposition := .packageOnly
    , reason := "alias of R3" }
  , { id := "G3", name := "CollisionResistanceGame"
    , disposition := .packageOnly
    , reason := "alias of R4" }
  , { id := "E1", name := "ProverCorrectness"
    , disposition := .eternalOps
    , reason := "separate program" }
  , { id := "E2", name := "PrivateTraceReDerive"
    , disposition := .eternalOps
    , reason := "openings model; no private-trace re-derive" }
  ]

theorem residual_kill_table_len : residualKillTable.length = 9 := by native_decide

/-- No residual remains in active-build fog (constructor removed after R1/R2 freeze). -/
def activeBuildNames : List String := []

theorem no_active_build_residuals : activeBuildNames = [] := rfl

/-- Eternal literature names (R1/R2 frozen). -/
def eternalLiteratureNames : List String :=
  residualKillTable.filterMap fun e =>
    if e.disposition == .eternalLiterature then some e.name else none

theorem eternal_literature_is_capacity :
    eternalLiteratureNames = ["CapacityRegimeAtRate", "IndependentFRIQueries"] := by
  native_decide

/-- Eternal crypto names (R3/R4). -/
def eternalCryptoNames : List String :=
  residualKillTable.filterMap fun e =>
    if e.disposition == .eternalCrypto then some e.name else none

theorem eternal_crypto_is_sha :
    eternalCryptoNames = ["Sha256RandomOracle", "Sha256CollisionResistance"] := by
  native_decide

/-- V1 scoreboard is pure formula accounting — not crypto theorem of residual proofs. -/
def v1ScoreboardAccounting : Nat := formulaBits

theorem v1_scoreboard_accounting_eq_104 : v1ScoreboardAccounting = 104 :=
  formula_bits_eq_104

theorem scoreboard_independent_of_residual_proofs
    (h1 h1' : EthStarkCapacityV1)
    (h2 h2' : Sha256RandomOracle)
    (h3 h3' : Sha256CollisionResistance) :
    cryptoSecurityBits h1 h2 h3 = cryptoSecurityBits h1' h2' h3' := by
  simp [cryptoSecurityBits, formula_bits_eq_104]

/-- Kill-list complete: zero active-build fog entries. -/
theorem residual_kill_list_complete : activeBuildNames = [] ∧ residualKillTable.length = 9 :=
  ⟨no_active_build_residuals, residual_kill_table_len⟩

/-! ### M1 residual honesty — what is *proved* vs eternal literature necessity -/

/--
  Proved capacity **accounting** (no literature hyp): rate formula, bits/query,
  multi-query product, + grind. This is formulaBits — not a proximity theorem.
-/
def capacityAccountingProved : List String :=
  [ "capacityBitsAtRate_2_2048_eq_10"
  , "multiQueryFriBits_8_10_eq_80"
  , "securityBitsCapacity_8_10_24_eq_104"
  , "configV1_wellFormed"
  , "formulaBits_eq_104"
  ]

theorem capacity_accounting_proved_count :
    capacityAccountingProved.length = 5 := by native_decide

/-- Machine-checked accounting facts (no R1/R2 hypothesis). -/
theorem capacity_accounting_discharged :
    capacityBitsAtRate 2 BLOWUP = some 10 ∧
    multiQueryFriBits QUERIES bitsPerQueryV1 = 80 ∧
    securityBitsCapacity QUERIES bitsPerQueryV1 GRIND_BITS = 104 ∧
    formulaBits = 104 :=
  ⟨capacityBits_v1_rate, multiQuery_v1, securityBits_v1_formula, formula_bits_eq_104⟩

/-- Bool surface for DiffWarrant (no literature hyp). -/
def capacityAccountingOk : Bool :=
  (capacityBitsAtRate 2 BLOWUP == some 10) &&
  (decide (multiQueryFriBits QUERIES bitsPerQueryV1 = 80)) &&
  (decide (securityBitsCapacity QUERIES bitsPerQueryV1 GRIND_BITS = 104)) &&
  (decide (formulaBits = 104))

theorem capacity_accounting_ok : capacityAccountingOk = true := by native_decide
/--
  Eternal literature necessity (1:1 with R1/R2 names).
  These are proximity / multi-query independence STARK literature hyps —
  not theorems of Goldilocks field arithmetic; not dischargeable in this TCB.
-/
def residualLiteratureNecessity : List (String × String) :=
  [ ("CapacityRegimeAtRate",
      "ethSTARK/BCIKS capacity-regime proximity: one FRI query ≈ 2^{-bits} soundness is literature, not ℤ/field arithmetic.")
  , ("IndependentFRIQueries",
      "Multi-query additive security under independent challenges is a modeling hyp; adaptive/correlated gaps out of TCB.")
  ]

theorem residual_literature_necessity_len :
    residualLiteratureNecessity.length = 2 := by native_decide

theorem residual_literature_names_covered :
    eternalLiteratureNames = residualLiteratureNecessity.map (·.1) := by
  native_decide

/-- Eternal crypto necessity (1:1 with R3/R4). -/
def residualCryptoNecessity : List (String × String) :=
  [ ("Sha256RandomOracle",
      "Fiat–Shamir modeled as random oracle; standard external crypto assumption, not from ℤ.")
  , ("Sha256CollisionResistance",
      "Merkle/FS collision resistance; standard external crypto assumption, not from ℤ.")
  ]

theorem residual_crypto_necessity_len :
    residualCryptoNecessity.length = 2 := by native_decide

theorem residual_crypto_names_covered :
    eternalCryptoNames = residualCryptoNecessity.map (·.1) := by
  native_decide

/--
  Crown independence: primary utxo_stark_warrant needs only CovenantAccept;
  formulaBits/scoreboard is pure arithmetic (no CapacityRegimeAtRate hyp).
  Scoreboard must not be sold as residual-premise security.
-/
theorem crown_scoreboard_is_pure_arithmetic : formulaBits = 104 :=
  formula_bits_eq_104

theorem crown_scoreboard_not_residual_security
    (h1 h1' : EthStarkCapacityV1)
    (h2 h2' : Sha256RandomOracle)
    (h3 h3' : Sha256CollisionResistance) :
    cryptoSecurityBits h1 h2 h3 = formulaBits ∧
    cryptoSecurityBits h1' h2' h3' = formulaBits := by
  simp [cryptoSecurityBits, formula_bits_eq_104]

/-- M1 freeze status string (harness surface). -/
def m1ResidualFreezeStatus : String :=
  "capacity_accounting_discharged_R1_R2_eternal_literature_with_necessity"

theorem m1_residual_freeze_status_nonempty :
    m1ResidualFreezeStatus.length > 20 := by native_decide

end FriStark.Soundness.ResidualKill
