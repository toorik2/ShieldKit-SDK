/-
  Name-on-the-line crown:
  Under residual games R (assumptions), production CovenantAccept
  (mandatory product + productAir on kernel + binding + verify∘unpack)
  implies PublicStatementΦ of that product + V1 scoreboard accounting (104).
-/
import FriStark.Full.Verify
import FriStark.Soundness.Residual
import FriStark.Soundness.Statement
import FriStark.Soundness.EndToEnd
import FriStark.Soundness.Phi
import FriStark.Soundness.Games
import FriStark.Soundness.StepAlgebra
import FriStark.Packing.Unpack
import FriStark.Packing.Topology
import FriStark.Binding.Presence
import FriStark.AIR.ProductV1
import FriStark.Params.V1

namespace FriStark.Soundness.Warrant

open FriStark.Full.Verify
open FriStark.Soundness.Residual
open FriStark.Soundness.Statement
open FriStark.Soundness.EndToEnd
open FriStark.Soundness.Phi
open FriStark.Soundness.Games
open FriStark.Packing.Unpack
open FriStark.Packing.Topology
open FriStark.Binding.Presence
open FriStark.AIR.ProductV1
open FriStark.Params.V1
-- formulaBits scoreboard accounting

/-- Legacy residual package scoreboard (accounting only — premises unused in formula). -/
theorem residual_games_crypto_bits_eq_104 (R : ResidualGames) :
    (R.toPremises).cryptoBits = 104 :=
  ResidualGames.cryptoBits_eq_104 R

/-- M1: V1 scoreboard is pure formula accounting, not residual-premise security. -/
theorem v1_scoreboard_accounting_eq_104 : formulaBits = 104 :=
  formula_bits_eq_104

/-! ### Bundle-level human claim — no optional True for product/binding -/

/--
  Human claim on an accept bundle: topology + **required** binding + **required** product Φ.
  No `| none => True` loopholes.
-/
def PublicStatementΦ_of (a : AcceptBundle) : Prop :=
  Phi2Topology a.topology ∧
  (∃ m, a.binding? = some m ∧ Phi2Binding m) ∧
  (∃ c, a.product? = some c ∧ PublicStatementΦ c)

theorem publicStatementΦ_of_parts (a : AcceptBundle) (c : ProductClaim) (m : BindingModel)
    (hT : Phi2Topology a.topology)
    (hB : a.binding? = some m) (hBm : Phi2Binding m)
    (hP : a.product? = some c) (hΦ : PublicStatementΦ c) :
    PublicStatementΦ_of a :=
  ⟨hT, ⟨m, hB, hBm⟩, ⟨c, hP, hΦ⟩⟩

/-! ### Kernel bridges -/

theorem warrant_verify_to_phi
    (b : Bundle) (st : ProductStatement) (w : ProductWitness)
    (h : verify b = .ok)
    (hMem : Step.productAir st w ∈ b.steps) :
    PublicStatementΦ ⟨st, w⟩ :=
  publicStatementΦ_of_statementHolds _ (verify_ok_implies_statement b st w h hMem)

theorem warrant_verify_ok_iff (b : Bundle) :
    verify b = .ok ↔
      paramsFail b = false ∧ b.steps ≠ [] ∧ stepsAllRunOk b.steps :=
  verify_ok_iff b

/-! ### Peel Accept → Φ_of -/

private theorem topo_of_covenant (a : AcceptBundle)
    (h : CovenantAccept a = true) : wellFormedTopology a.topology = true := by
  simp only [CovenantAccept] at h
  cases ht : wellFormedTopology a.topology
  · simp [ht] at h
  · rfl

private theorem phi_of_covenant (a : AcceptBundle)
    (h : CovenantAccept a = true) : PublicStatementΦ_of a := by
  refine ⟨topo_of_covenant a h, ?hBind, ?hProd⟩
  · obtain ⟨m, hm, hwf⟩ := covenant_implies_binding_some a h
    exact ⟨m, hm, hwf⟩
  · obtain ⟨c, hP⟩ := covenant_implies_product_some a h
    exact ⟨c, hP, covenant_product_phi a c h hP⟩

/-! ### Crown under residual games R -/

inductive WarrantOutcome (a : AcceptBundle) (R : ResidualGames) where
  | holds
      (hΦ : PublicStatementΦ_of a)
      (hBits : (R.toPremises).cryptoBits = 104)
  | broken (e : ResidualBreakEvidence)

/-- Constructive crown Type: Accept ⇒ holds (Φ_of ∧ bits(R)). -/
def utxo_stark_warrant_outcome (a : AcceptBundle) (R : ResidualGames)
    (h : CovenantAccept a = true) : WarrantOutcome a R :=
  .holds (phi_of_covenant a h) (residual_games_crypto_bits_eq_104 R)

/--
  **Primary product crown (full track):** production CovenantAccept ⇒ mandatory product Φ.
  Does **not** package residual premises as free soundness for 104 bits.
-/
theorem utxo_stark_warrant (a : AcceptBundle)
    (h : CovenantAccept a = true) :
    ∃ c, a.product? = some c ∧ PublicStatementΦ c :=
  (phi_of_covenant a h).2.2

/-- Full packing claim: topo + binding + product Φ. -/
theorem utxo_stark_warrant_phi (a : AcceptBundle)
    (h : CovenantAccept a = true) : PublicStatementΦ_of a :=
  phi_of_covenant a h

/-- Separate **accounting** fact (not a residual-security theorem). -/
theorem utxo_stark_warrant_scoreboard_accounting :
    formulaBits = 104 :=
  v1_scoreboard_accounting_eq_104

/-- Legacy form: product Φ ∧ residual-package scoreboard accounting (explicitly accounting). -/
theorem utxo_stark_warrant_phi_and_bits (a : AcceptBundle) (R : ResidualGames)
    (h : CovenantAccept a = true) :
    PublicStatementΦ_of a ∧ (R.toPremises).cryptoBits = 104 :=
  ⟨phi_of_covenant a h, residual_games_crypto_bits_eq_104 R⟩

/-- Claim B: productAir on kernel + Φ. -/
theorem utxo_stark_warrant_product_on_kernel (a : AcceptBundle)
    (h : CovenantAccept a = true) :
    ∃ c b, a.product? = some c ∧
      acceptKernel a.lean a.blob? = some b ∧
      Step.productAir c.st c.w ∈ b.steps ∧
      PublicStatementΦ c :=
  covenant_implies_product_on_kernel a h

theorem utxo_stark_warrant_product (a : AcceptBundle) (c : ProductClaim)
    (h : CovenantAccept a = true) (hP : a.product? = some c) :
    PublicStatementΦ c :=
  covenant_product_phi a c h hP

theorem utxo_stark_warrant_core (a : AcceptBundle)
    (h : CovenantAccept a = true) :
    kernelVerify a = .ok :=
  covenant_implies_kernel_ok a h

theorem utxo_stark_covenant_unpack (a : AcceptBundle) (π : ProofBlob)
    (hB : a.blob? = some π) (h : CovenantAccept a = true) :
    wellFormedTopology a.topology = true ∧
    bindingOk a.binding? = true ∧
    productOk a.product? = true ∧
    productAirOnKernel a = true ∧
    ∃ b, unpack π = some b ∧ (verify b).isOk = true :=
  covenant_blob_iff a π hB h

theorem utxo_stark_warrant_unpack (a : AcceptBundle) (π : ProofBlob)
    (h : CovenantAccept a = true) (hB : a.blob? = some π) :
    ∃ b, unpack π = some b ∧ verify b = .ok :=
  covenant_blob_verify_unpack a π h hB

/-- No vacuous product on crown. -/
theorem utxo_stark_rejects_no_product (a : AcceptBundle) (hP : a.product? = none) :
    CovenantAccept a = false :=
  covenant_rejects_no_product a hP

theorem utxo_stark_rejects_no_binding (a : AcceptBundle) (hB : a.binding? = none) :
    CovenantAccept a = false :=
  covenant_rejects_no_binding a hB

def IdealWarrantClaim (c : ProductClaim) : Prop := PublicStatementΦ c

theorem warrant_productAir_to_ideal
    (st : ProductStatement) (w : ProductWitness)
    (h : runStep (.productAir st w) = .ok) :
    IdealWarrantClaim ⟨st, w⟩ :=
  publicStatementΦ_of_statementHolds _ (productAir_step_implies_statement st w h)

theorem warrant_scoreboard_accounting : formulaBits = 104 :=
  v1_scoreboard_accounting_eq_104

/-- Legacy residual-package scoreboard (accounting). -/
theorem warrant_scoreboard (R : ResidualGames) : (R.toPremises).cryptoBits = 104 :=
  residual_games_crypto_bits_eq_104 R

/-! ### SemanticAccept is lemma only -/

theorem warrant_semantic_lemma
    (b : Bundle) (st : ProductStatement) (w : ProductWitness)
    (hSem : SemanticAccept b)
    (hClaim : HasProductClaim b st w) :
    PublicStatementΦ ⟨st, w⟩ :=
  publicStatementΦ_of_statementHolds _ (e2e_accept_to_statement b st w hSem hClaim)

def warrantApexStatus : String :=
  "covenant_mandatory_product_phi_full_ir_track"

def warrantCrownTheoremNames : List String :=
  [ "utxo_stark_warrant"
  , "utxo_stark_warrant_phi"
  , "utxo_stark_warrant_product_on_kernel"
  , "utxo_stark_warrant_product"
  , "utxo_stark_warrant_core"
  , "utxo_stark_covenant_unpack"
  , "utxo_stark_warrant_unpack"
  , "utxo_stark_rejects_no_product"
  , "utxo_stark_rejects_no_binding"
  , "warrant_scoreboard_accounting"
  ]

theorem warrant_crown_theorem_count :
    warrantCrownTheoremNames.length = 10 := by native_decide

def spineTagProductPresent : String := "product_present"
def spineTagProductAirMem : String := "productAir_mem"
def spineTagUnpackKernel : String := "unpack_kernel"
def spineTagPhiForced : String := "phi_forced"

end FriStark.Soundness.Warrant
