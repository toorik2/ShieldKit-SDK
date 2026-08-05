/-
  T4 end-to-end reduction (semantic apex):

    runStep(productAir) = ok  ⇒  StatementHolds
    SemanticAccept with product step  ⇒  StatementHolds
    Under residual premises: StatementHolds ∧ cryptoBits = 104
    Disjunctive form: StatementHolds ∨ BreaksResidual
      (left proved for product-accept; BreaksResidual is the named residual surface)

  No tautological AlgebraicAccept := (verify = .ok) as the “statement”.
-/
import FriStark.Full.Verify
import FriStark.Soundness.Residual
import FriStark.Soundness.Statement
import FriStark.Soundness.Semantic
import FriStark.Soundness.FRIReduction
import FriStark.Soundness.FSReduction
import FriStark.Soundness.MerkleReduction
import FriStark.Soundness.DeepReduction
import FriStark.Soundness.QueryModel
import FriStark.Params.V1
import FriStark.AIR.ProductV1

namespace FriStark.Soundness.EndToEnd

open FriStark.Full.Verify
open FriStark.Soundness.Residual
open FriStark.Soundness.Statement
open FriStark.Soundness.Semantic
open FriStark.Soundness.QueryModel
open FriStark.Params.V1
open FriStark.AIR.ProductV1

/-! ### Semantic accept (lemma form of step-wise OK; apex is Full.Verify.verify after Wave B) -/

/-- Alias of `Full.Verify.stepsAllRunOk` (one Accept story). -/
abbrev stepsAllOk : List Step → Prop := stepsAllRunOk

def paramsOk (b : Bundle) : Prop := paramsGate b

/-- Semantic accept: param gate + nonempty steps + all steps ok. -/
def SemanticAccept (b : Bundle) : Prop :=
  paramsOk b ∧ b.steps ≠ [] ∧ stepsAllOk b.steps

theorem stepsAllOk_head (s : Step) (rest : List Step)
    (h : stepsAllOk (s :: rest)) : runStep s = .ok := h.1

theorem stepsAllOk_tail (s : Step) (rest : List Step)
    (h : stepsAllOk (s :: rest)) : stepsAllOk rest := h.2

theorem stepsAllOk_of_mem (steps : List Step) (s : Step)
    (hAll : stepsAllOk steps) (hMem : s ∈ steps) : runStep s = .ok :=
  stepsAllRunOk_of_mem steps s hAll hMem

/--
  When paramsFail is false, SemanticAccept coincides with verify = .ok
  on the step/nonempty surface. Full equivalence uses `verify_ok_iff`
  (paramsFail = false ∧ …) — product eligibility is the main paramsFail case.
-/
theorem verify_ok_implies_steps_surface (b : Bundle) (h : verify b = .ok) :
    b.steps ≠ [] ∧ stepsAllOk b.steps :=
  let h' := (verify_ok_iff b).mp h
  ⟨h'.2.1, h'.2.2⟩

/-! ### productAir step ⇒ StatementHolds (independent of Full.Verify name) -/

theorem productAir_runStep_iff (st : ProductStatement) (w : ProductWitness) :
    runStep (.productAir st w) = .ok ↔ verifyProductAir st w = true := by
  simp only [runStep]
  split <;> simp_all

theorem productAir_step_implies_statement (st : ProductStatement) (w : ProductWitness)
    (h : runStep (.productAir st w) = .ok) :
    StatementHolds ⟨st, w⟩ := by
  have := (productAir_runStep_iff st w).mp h
  exact statement_holds_of_bool st w this

/-- Core disjunction: product step accept ⇒ StatementHolds ∨ BreaksResidual. -/
theorem accept_implies_statement_or_break
    (st : ProductStatement) (w : ProductWitness)
    (h : runStep (.productAir st w) = .ok) :
    StatementHolds ⟨st, w⟩ ∨ Nonempty BreaksResidual :=
  Or.inl (productAir_step_implies_statement st w h)

/-- SemanticAccept + membership ⇒ StatementHolds. -/
theorem semantic_accept_product_holds (b : Bundle)
    (st : ProductStatement) (w : ProductWitness)
    (hSem : SemanticAccept b)
    (hMem : Step.productAir st w ∈ b.steps) :
    StatementHolds ⟨st, w⟩ := by
  have hStep : runStep (.productAir st w) = .ok :=
    stepsAllOk_of_mem b.steps _ hSem.2.2 hMem
  exact productAir_step_implies_statement st w hStep

theorem semantic_accept_implies_statement_or_break (b : Bundle)
    (st : ProductStatement) (w : ProductWitness)
    (hSem : SemanticAccept b)
    (hMem : Step.productAir st w ∈ b.steps) :
    StatementHolds ⟨st, w⟩ ∨ Nonempty BreaksResidual :=
  Or.inl (semantic_accept_product_holds b st w hSem hMem)

/-! ### Multi-kind productAir ⇒ StatementHolds -/

theorem multi_kind_deposit
    (h : runStep (.productAir honestDeposit.1 honestDeposit.2) = .ok) :
    StatementHolds ⟨honestDeposit.1, honestDeposit.2⟩ :=
  productAir_step_implies_statement _ _ h

theorem multi_kind_transfer
    (h : runStep (.productAir honestTransfer.1 honestTransfer.2) = .ok) :
    StatementHolds ⟨honestTransfer.1, honestTransfer.2⟩ :=
  productAir_step_implies_statement _ _ h

theorem multi_kind_withdrawal
    (h : runStep (.productAir honestWithdrawal.1 honestWithdrawal.2) = .ok) :
    StatementHolds ⟨honestWithdrawal.1, honestWithdrawal.2⟩ :=
  productAir_step_implies_statement _ _ h

/-- All productAir steps in a semantically accepted bundle satisfy StatementHolds. -/
def allProductClaimsHold (b : Bundle) : Prop :=
  ∀ st w, Step.productAir st w ∈ b.steps → StatementHolds ⟨st, w⟩

theorem semantic_accept_all_products (b : Bundle) (hSem : SemanticAccept b) :
    allProductClaimsHold b := by
  intro st w hMem
  exact semantic_accept_product_holds b st w hSem hMem

theorem semantic_accept_all_products_or_break (b : Bundle) (hSem : SemanticAccept b) :
    allProductClaimsHold b ∨ Nonempty BreaksResidual :=
  Or.inl (semantic_accept_all_products b hSem)

/-- Extractable product claim predicate for E2E docs. -/
def HasProductClaim (b : Bundle) (st : ProductStatement) (w : ProductWitness) : Prop :=
  Step.productAir st w ∈ b.steps

theorem e2e_accept_to_statement
    (b : Bundle) (st : ProductStatement) (w : ProductWitness)
    (hSem : SemanticAccept b)
    (hClaim : HasProductClaim b st w) :
    StatementHolds ⟨st, w⟩ :=
  semantic_accept_product_holds b st w hSem hClaim

/-!
  Full.Verify.verify is the executable accept kernel (pure `verifySteps`, no Id.run).
  Wave B: verify = .ok implies all productAir steps' StatementHolds.
-/

/-- Crown-facing: full kernel accept ⇒ every productAir step satisfies StatementHolds. -/
theorem verify_ok_implies_all_product_claims (b : Bundle)
    (h : verify b = .ok) : allProductClaimsHold b := by
  intro st w hMem
  have hStep : runStep (.productAir st w) = .ok :=
    verify_ok_implies_step b _ h hMem
  exact productAir_step_implies_statement st w hStep

theorem verify_ok_implies_statement
    (b : Bundle) (st : ProductStatement) (w : ProductWitness)
    (h : verify b = .ok)
    (hMem : Step.productAir st w ∈ b.steps) :
    StatementHolds ⟨st, w⟩ :=
  verify_ok_implies_all_product_claims b h st w hMem

theorem verify_ok_implies_statement_or_break
    (b : Bundle) (st : ProductStatement) (w : ProductWitness)
    (h : verify b = .ok)
    (hMem : Step.productAir st w ∈ b.steps) :
    StatementHolds ⟨st, w⟩ ∨ Nonempty BreaksResidual :=
  Or.inl (verify_ok_implies_statement b st w h hMem)

theorem single_product_semantic
    (st : ProductStatement) (w : ProductWitness)
    (h : runStep (.productAir st w) = .ok) :
    SemanticAccept {
      steps := [.productAir st w]
      accept := true
      label := "product"
      eligibility := "dev"
      blowup := BLOWUP
      queries := QUERIES
      grindBits := GRIND_BITS
      fold := FOLD
    } := by
  refine And.intro ?params (And.intro ?nonempty ?steps)
  · -- eligibility "dev" ≠ "product"
    exact Or.inl (by decide : ("dev" : String) ≠ "product")
  · exact List.cons_ne_nil _ _
  · exact ⟨h, trivial⟩

/-- Single productAir step bundle is accepted by `verify` under eligibility "dev". -/
theorem single_product_verify_ok
    (st : ProductStatement) (w : ProductWitness)
    (h : runStep (.productAir st w) = .ok) :
    verify {
      steps := [.productAir st w]
      accept := true
      label := "product"
      eligibility := "dev"
      blowup := BLOWUP
      queries := QUERIES
      grindBits := GRIND_BITS
      fold := FOLD
    } = .ok := by
  apply (verify_ok_iff _).mpr
  refine ⟨?pf, List.cons_ne_nil _ _, ⟨h, trivial⟩⟩
  -- paramsFail: eligibility "dev" ≠ "product" ⇒ false
  simp [paramsFail]

/-- Ideal claim under residual premises: statement + 104 crypto bits. -/
def IdealProductClaim (R : ResidualPremises) (c : ProductClaim) : Prop :=
  StatementHolds c ∧ R.cryptoBits = 104

theorem product_accept_to_ideal (R : ResidualPremises)
    (st : ProductStatement) (w : ProductWitness)
    (h : runStep (.productAir st w) = .ok) :
    IdealProductClaim R ⟨st, w⟩ :=
  ⟨productAir_step_implies_statement st w h, R.cryptoBits_eq_104⟩

theorem product_accept_to_ideal_or_break (R : ResidualPremises)
    (st : ProductStatement) (w : ProductWitness)
    (h : runStep (.productAir st w) = .ok) :
    IdealProductClaim R ⟨st, w⟩ ∨ Nonempty BreaksResidual :=
  Or.inl (product_accept_to_ideal R st w h)

/-! ### Crypto accounting under residuals (not “proved soundness” alone) -/

def securityLevel (R : ResidualPremises) : Nat := R.cryptoBits

theorem securityLevel_eq_104 (R : ResidualPremises) : securityLevel R = 104 :=
  R.cryptoBits_eq_104

theorem arithmetic_104_unconditional : SECURITY_BITS = 104 :=
  QueryModel.security_bits_eq_104

theorem crypto_104_needs_residuals (R : ResidualPremises) :
    securityLevel R = SECURITY_BITS := by
  simp only [securityLevel, ResidualPremises.cryptoBits, cryptoSecurityBits,
    formula_bits_eq_security]

/-! ### Semantic step bridges (from Semantic.lean) re-exported for E2E -/

theorem deep_step_to_semantic (inp : Deep.QAt.QAtInput) (expect : Field.Ext.E)
    (h : runStep (.deepQAt inp expect) = .ok) :
    DeepFri0Bind inp expect :=
  runStep_deepQAt_implies_deepFri0 inp expect h

theorem deep_step_to_exists_eval (inp : Deep.QAt.QAtInput) (expect : Field.Ext.E)
    (h : runStep (.deepQAt inp expect) = .ok) :
    ∃ q, Deep.QAt.eval inp = some q ∧ Field.Ext.eq q expect = true :=
  runStep_deepQAt_has_eval inp expect h

theorem coset_step_to_semantic
    (coset : List Field.Ext.E) (betas : List Field.Ext.E)
    (base li0 s off oN N : Nat) (expect : Field.Ext.E)
    (h : runStep (.cosetFold coset betas base li0 s off oN N expect) = .ok) :
    CosetFoldBind coset betas base li0 s off oN N expect :=
  runStep_coset_implies_bind coset betas base li0 s off oN N expect h

theorem coset_step_to_exists_eval
    (coset : List Field.Ext.E) (betas : List Field.Ext.E)
    (base li0 s off oN N : Nat) (expect : Field.Ext.E)
    (h : runStep (.cosetFold coset betas base li0 s off oN N expect) = .ok) :
    ∃ got, FRI.Coset.cosetFold coset betas base li0 s off oN N = some got ∧
      Field.Ext.eq got expect = true :=
  runStep_coset_has_eval coset betas base li0 s off oN N expect h

theorem compose_step_to_semantic (pack : ComposePack)
    (h : runStep (.composeCheck pack) = .ok) :
    CompositionEquals pack.cur pack.nxt pack.z pack.wNext pack.lastF pack.zhInv pack.Hd
      pack.pub pack.rc pack.chainMinv pack.alphasT pack.alphasB pack.bounds
      pack.Mext pack.Minv pack.diag pack.Minv0 pack.held pack.expectCompZ :=
  runStep_compose_implies_composition pack h

/-- Residual names surface for harness. -/
def residualBreakNames : List String := residualNames

theorem residual_break_names_match : residualBreakNames = residualNames := rfl

/--
  StatementHolds is independent of Full.Verify: it is ProductV1.verifyProductAir.
  (Proved as definitional Iff in Statement.statement_holds_iff_verifyProductAir.)
-/
theorem statement_holds_not_full_verify :
    (∀ c, StatementHolds c ↔ FriStark.AIR.ProductV1.verifyProductAir c.st c.w = true) :=
  fun c => statement_holds_iff_verifyProductAir c

end FriStark.Soundness.EndToEnd
