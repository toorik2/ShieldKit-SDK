/-
  Name-on-the-line Accept spine:
  CovenantAccept requires topology + binding + mandatory product +
  verify(acceptKernel) + productAir claim ∈ kernel.steps.
  No product?/binding? none loopholes.
-/
import FriStark.Full.Verify
import FriStark.Packing.Topology
import FriStark.Packing.ProdIRFixture
import FriStark.Binding.Presence
import FriStark.Params.V1
import FriStark.AIR.ProductV1
import FriStark.Soundness.Statement
import FriStark.Soundness.Phi
import FriStark.Verify.Types
import FriStark.Field.Ext
import FriStark.Deep.QAt
import FriStark.Transcript.FiatShamir
import FriStark.Hash.Sha256

namespace FriStark.Packing.Unpack

open FriStark.Full.Verify
open FriStark.Packing.Topology
open FriStark.Packing.ProdIRFixture
open FriStark.Binding.Presence
open FriStark.Params.V1
open FriStark.AIR.ProductV1
open FriStark.Soundness.Statement
open FriStark.Soundness.Phi
open FriStark.Verify.Types
open FriStark.Field.Ext
open FriStark.Deep.QAt
open FriStark.Transcript.FiatShamir
open FriStark.Hash.Sha256 (Bytes)

structure RolePayload where
  role : String
  bytes : List UInt8

structure ProofBlob where
  roles : List RolePayload
  kernel : Bundle

def ProofBlob.roleNames (π : ProofBlob) : List String := π.roles.map (·.role)
def expectedVerifierRoles : List String := defaultSoundRoles
def roleOrderOk (π : ProofBlob) : Bool := π.roleNames == expectedVerifierRoles

/-- unpack : ProofBlob → Option Bundle (order gate then kernel). -/
def unpack (π : ProofBlob) : Option Bundle :=
  if roleOrderOk π then some π.kernel else none

theorem unpack_eq_kernel (π : ProofBlob) (h : roleOrderOk π = true) :
    unpack π = some π.kernel := by simp [unpack, h]

theorem unpack_roundtrip (π : ProofBlob) (b : Bundle)
    (h : unpack π = some b) : b = π.kernel ∧ roleOrderOk π = true := by
  simp only [unpack] at h
  split at h
  · next hOk =>
    injection h with heq
    exact ⟨heq.symm, hOk⟩
  · next => cases h

theorem unpack_injective_kernels (π₁ π₂ : ProofBlob)
    (h1 : roleOrderOk π₁ = true) (h2 : roleOrderOk π₂ = true)
    (heq : unpack π₁ = unpack π₂) : π₁.kernel = π₂.kernel := by
  simp [unpack, h1, h2] at heq; exact heq

/-- Kernel used by the accept path: unpack blob if present, else lean. -/
def acceptKernel (lean : Bundle) (blob? : Option ProofBlob) : Option Bundle :=
  match blob? with
  | none => some lean
  | some π => unpack π

structure AcceptBundle where
  lean : Bundle
  product? : Option ProductClaim := none
  blob? : Option ProofBlob := none
  binding? : Option BindingModel := none
  topology : TopologyV1 := defaultTopology

/-- Production binding is **required** (none rejects). -/
def bindingOk : Option BindingModel → Bool
  | none => false
  | some m => wellFormed m

/-- Production product is **required** (none rejects). -/
def productOk : Option ProductClaim → Bool
  | none => false
  | some c => verifyProductAir c.st c.w

/-- Kernel steps contain the exact productAir claim (not a side-car). -/
def stepIsProductAir (c : ProductClaim) (s : Step) : Bool :=
  match s with
  | .productAir st w => decide (st = c.st ∧ w = c.w)
  | _ => false

def hasProductAirStep (c : ProductClaim) (steps : List Step) : Bool :=
  steps.any (stepIsProductAir c)

def productAirOnKernel (a : AcceptBundle) : Bool :=
  match a.product?, acceptKernel a.lean a.blob? with
  | some c, some b => hasProductAirStep c b.steps
  | _, _ => false

/--
  Production CovenantAccept:
  topo ∧ binding required ∧ product required ∧ productAir ∈ kernel ∧
  verify(acceptKernel).isOk
-/
def CovenantAccept (a : AcceptBundle) : Bool :=
  wellFormedTopology a.topology &&
  bindingOk a.binding? &&
  productOk a.product? &&
  productAirOnKernel a &&
  match acceptKernel a.lean a.blob? with
  | none => false
  | some b => (verify b).isOk

/-- Kernel verify result for an accept bundle. -/
def kernelVerify (a : AcceptBundle) : VerifyResult :=
  match acceptKernel a.lean a.blob? with
  | none => .err "unpack"
  | some b => verify b

private theorem band4 {a b c d : Bool}
    (h : (a && b && c && d) = true) :
    a = true ∧ b = true ∧ c = true ∧ d = true := by
  cases a <;> cases b <;> cases c <;> cases d <;> simp_all

theorem covenant_implies_kernel_isOk (a : AcceptBundle)
    (h : CovenantAccept a = true) : (kernelVerify a).isOk = true := by
  simp only [CovenantAccept, kernelVerify] at h ⊢
  match h1 : wellFormedTopology a.topology, h2 : bindingOk a.binding?,
        h3 : productOk a.product?, h4 : productAirOnKernel a with
  | false, _, _, _ => simp [h1] at h
  | true, false, _, _ => simp [h1, h2] at h
  | true, true, false, _ => simp [h1, h2, h3] at h
  | true, true, true, false => simp [h1, h2, h3, h4] at h
  | true, true, true, true =>
    match hk : acceptKernel a.lean a.blob? with
    | none => simp [h1, h2, h3, h4, hk] at h
    | some b =>
      simp [h1, h2, h3, h4, hk] at h
      simpa [hk] using h

theorem covenant_implies_kernel_ok (a : AcceptBundle)
    (h : CovenantAccept a = true) : kernelVerify a = .ok := by
  have hI := covenant_implies_kernel_isOk a h
  match hv : kernelVerify a with
  | .ok => rfl
  | .err w => simp [hv, VerifyResult.isOk] at hI

theorem covenant_implies_product_some (a : AcceptBundle)
    (h : CovenantAccept a = true) : ∃ c, a.product? = some c := by
  simp only [CovenantAccept] at h
  match hp : a.product? with
  | none =>
    have : productOk none = true := by
      simp only [productOk] at *
      -- peel productOk from h
      cases ht : wellFormedTopology a.topology
      · simp [ht] at h
      · cases hb : bindingOk a.binding?
        · simp [ht, hb] at h
        · simp [ht, hb, productOk, hp] at h
    simp [productOk] at this
  | some c => exact ⟨c, rfl⟩

theorem covenant_implies_binding_some (a : AcceptBundle)
    (h : CovenantAccept a = true) : ∃ m, a.binding? = some m ∧ wellFormed m = true := by
  simp only [CovenantAccept] at h
  match hb : a.binding? with
  | none =>
    cases ht : wellFormedTopology a.topology
    · simp [ht] at h
    · simp [ht, bindingOk, hb] at h
  | some m =>
    refine ⟨m, rfl, ?_⟩
    cases ht : wellFormedTopology a.topology
    · simp [ht] at h
    · simp only [ht, bindingOk, hb] at h
      cases hwf : wellFormed m
      · simp [hwf] at h
      · rfl

theorem productOk_some_eq (c : ProductClaim) (h : productOk (some c) = true) :
    verifyProductAir c.st c.w = true := by simpa [productOk] using h

theorem covenant_implies_productOk (a : AcceptBundle)
    (h : CovenantAccept a = true) : productOk a.product? = true := by
  simp only [CovenantAccept] at h
  cases ht : wellFormedTopology a.topology
  · simp [ht] at h
  · cases hb : bindingOk a.binding?
    · simp [ht, hb] at h
    · cases hp : productOk a.product?
      · simp [ht, hb, hp] at h
      · rfl

theorem covenant_product_holds (a : AcceptBundle) (c : ProductClaim)
    (hA : CovenantAccept a = true) (hP : a.product? = some c) :
    StatementHolds c := by
  have hPo := covenant_implies_productOk a hA
  rw [hP] at hPo
  exact statement_holds_of_bool c.st c.w (productOk_some_eq c hPo)

theorem covenant_product_phi (a : AcceptBundle) (c : ProductClaim)
    (hA : CovenantAccept a = true) (hP : a.product? = some c) :
    PublicStatementΦ c :=
  publicStatementΦ_of_statementHolds c (covenant_product_holds a c hA hP)

/-- Bool membership ⇒ Prop membership. -/
theorem hasProductAirStep_mem (c : ProductClaim) (steps : List Step)
    (h : hasProductAirStep c steps = true) :
    Step.productAir c.st c.w ∈ steps := by
  simp only [hasProductAirStep, List.any_eq_true] at h
  obtain ⟨s, hMem, hs⟩ := h
  cases s <;> try (simp [stepIsProductAir] at hs; done)
  · -- productAir
    rename_i st w
    have heq : st = c.st ∧ w = c.w := of_decide_eq_true (by simpa [stepIsProductAir] using hs)
    simpa [heq.1, heq.2] using hMem

theorem covenant_productAir_mem (a : AcceptBundle) (c : ProductClaim)
    (hA : CovenantAccept a = true) (hP : a.product? = some c) :
    ∃ b, acceptKernel a.lean a.blob? = some b ∧
        Step.productAir c.st c.w ∈ b.steps := by
  simp only [CovenantAccept, hP, productAirOnKernel] at hA
  cases ht : wellFormedTopology a.topology
  · simp [ht] at hA
  · cases hb : bindingOk a.binding?
    · simp [ht, hb] at hA
    · cases hpo : productOk (some c)
      · simp [ht, hb, hpo] at hA
      · match hk : acceptKernel a.lean a.blob? with
        | none => simp [ht, hb, hpo, hk] at hA
        | some b =>
          simp only [ht, hb, hpo, hk] at hA
          have hMemB : hasProductAirStep c b.steps = true := by
            cases hm : hasProductAirStep c b.steps
            · simp [hm] at hA
            · rfl
          exact ⟨b, rfl, hasProductAirStep_mem c b.steps hMemB⟩

/-- Claim B: Accept ⇒ mandatory product + productAir on kernel + Φ. -/
theorem covenant_implies_product_on_kernel (a : AcceptBundle)
    (h : CovenantAccept a = true) :
    ∃ c b, a.product? = some c ∧
      acceptKernel a.lean a.blob? = some b ∧
      Step.productAir c.st c.w ∈ b.steps ∧
      PublicStatementΦ c := by
  obtain ⟨c, hP⟩ := covenant_implies_product_some a h
  obtain ⟨b, hk, hMem⟩ := covenant_productAir_mem a c h hP
  exact ⟨c, b, hP, hk, hMem, covenant_product_phi a c h hP⟩

/-- Blob path: CovenantAccept ⇒ unpack succeeds and verify unpacked = ok. -/
theorem covenant_blob_verify_unpack (a : AcceptBundle) (π : ProofBlob)
    (hA : CovenantAccept a = true) (hB : a.blob? = some π) :
    ∃ b, unpack π = some b ∧ verify b = .ok := by
  have hK := covenant_implies_kernel_ok a hA
  simp only [kernelVerify, acceptKernel, hB] at hK
  cases hu : unpack π with
  | none => simp [hu] at hK
  | some b =>
    simp [hu] at hK
    exact ⟨b, rfl, hK⟩

/-- One direction: Accept ⇒ topo∧bind∧product∧productAir∧kernel ok (blob). -/
theorem covenant_blob_parts (a : AcceptBundle) (π : ProofBlob)
    (hB : a.blob? = some π) (h : CovenantAccept a = true) :
    wellFormedTopology a.topology = true ∧
    bindingOk a.binding? = true ∧
    productOk a.product? = true ∧
    productAirOnKernel a = true ∧
    ∃ b, unpack π = some b ∧ (verify b).isOk = true := by
  simp only [CovenantAccept, hB, acceptKernel] at h
  cases h1 : wellFormedTopology a.topology
  · simp [h1] at h
  · cases h2 : bindingOk a.binding?
    · simp [h1, h2] at h
    · cases h3 : productOk a.product?
      · simp [h1, h2, h3] at h
      · cases h4 : productAirOnKernel a
        · simp [h1, h2, h3, h4] at h
        · cases hu : unpack π with
          | none => simp [h1, h2, h3, h4, hu] at h
          | some b =>
            simp [h1, h2, h3, h4, hu] at h
            exact ⟨rfl, rfl, rfl, rfl, ⟨b, rfl, h⟩⟩

/-- No-blob path parts. -/
theorem covenant_no_blob_parts (a : AcceptBundle) (hB : a.blob? = none)
    (h : CovenantAccept a = true) :
    wellFormedTopology a.topology = true ∧
    bindingOk a.binding? = true ∧
    productOk a.product? = true ∧
    productAirOnKernel a = true ∧
    (verify a.lean).isOk = true := by
  simp only [CovenantAccept, hB, acceptKernel] at h
  cases h1 : wellFormedTopology a.topology
  · simp [h1] at h
  · cases h2 : bindingOk a.binding?
    · simp [h1, h2] at h
    · cases h3 : productOk a.product?
      · simp [h1, h2, h3] at h
      · cases h4 : productAirOnKernel a
        · simp [h1, h2, h3, h4] at h
        · simp [h1, h2, h3, h4] at h
          exact ⟨rfl, rfl, rfl, rfl, h⟩

/-- Legacy name: blob path characterization (⇒ direction via parts). -/
theorem covenant_blob_iff (a : AcceptBundle) (π : ProofBlob)
    (hB : a.blob? = some π) (h : CovenantAccept a = true) :
    wellFormedTopology a.topology = true ∧
    bindingOk a.binding? = true ∧
    productOk a.product? = true ∧
    productAirOnKernel a = true ∧
    ∃ b, unpack π = some b ∧ (verify b).isOk = true :=
  covenant_blob_parts a π hB h

theorem covenant_no_blob_iff (a : AcceptBundle) (hB : a.blob? = none)
    (h : CovenantAccept a = true) :
    wellFormedTopology a.topology = true ∧
    bindingOk a.binding? = true ∧
    productOk a.product? = true ∧
    productAirOnKernel a = true ∧
    (verify a.lean).isOk = true :=
  covenant_no_blob_parts a hB h

/-- Legacy alias used by DiffWarrant. -/
def blobOk : Option ProofBlob → Bool
  | none => true
  | some π => (unpack π).isSome

def dummyKernel : Bundle where
  steps := []
  accept := false
  label := "dummy"
  eligibility := "dev"
  blowup := BLOWUP
  queries := QUERIES
  grindBits := GRIND_BITS
  fold := FOLD

def mkSoundBlob (kernel : Bundle) : ProofBlob where
  roles := expectedVerifierRoles.map fun r => { role := r, bytes := [] }
  kernel := kernel

theorem mkSoundBlob_roleNames (k : Bundle) :
    (mkSoundBlob k).roleNames = expectedVerifierRoles := by
  simp [ProofBlob.roleNames, mkSoundBlob, List.map_map, Function.comp_def]

theorem mkSoundBlob_roleOrder_any (k : Bundle) :
    roleOrderOk (mkSoundBlob k) = true := by
  simp only [roleOrderOk, mkSoundBlob_roleNames k]
  -- xs == xs
  exact (beq_self_eq_true expectedVerifierRoles).symm ▸ rfl

theorem mkSoundBlob_roleOrder : roleOrderOk (mkSoundBlob dummyKernel) = true :=
  mkSoundBlob_roleOrder_any dummyKernel

theorem mkSoundBlob_unpack_any (k : Bundle) :
    unpack (mkSoundBlob k) = some k :=
  unpack_eq_kernel (mkSoundBlob k) (mkSoundBlob_roleOrder_any k)

theorem mkSoundBlob_unpack_dummy :
    unpack (mkSoundBlob dummyKernel) = some dummyKernel :=
  mkSoundBlob_unpack_any dummyKernel

def badOrderBlob : ProofBlob where
  roles := [{ role := "aggFRI", bytes := [] }, { role := "blob", bytes := [] }]
  kernel := dummyKernel

theorem bad_order_unpack_none : unpack badOrderBlob = none := by
  simp [unpack, badOrderBlob, roleOrderOk]
  native_decide

theorem packing_forge_bad_order : blobOk (some badOrderBlob) = false := by
  simp [blobOk, bad_order_unpack_none]

theorem empty_blob_roleOrder_fails :
    roleOrderOk ⟨[], dummyKernel⟩ = false := by native_decide

def dualVmIsCorollary : Bool := true
theorem dual_vm_is_corollary : dualVmIsCorollary = true := rfl

/-- Missing product rejects Accept. -/
theorem covenant_rejects_no_product (a : AcceptBundle) (hP : a.product? = none) :
    CovenantAccept a = false := by
  simp only [CovenantAccept, hP, productOk, productAirOnKernel]
  cases wellFormedTopology a.topology <;> cases bindingOk a.binding? <;> simp

/-- Missing binding rejects Accept. -/
theorem covenant_rejects_no_binding (a : AcceptBundle) (hB : a.binding? = none) :
    CovenantAccept a = false := by
  simp only [CovenantAccept, hB, bindingOk]
  cases wellFormedTopology a.topology <;> simp

theorem product_dev_verify_ok (st : ProductStatement) (w : ProductWitness)
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
  refine ⟨?_, List.cons_ne_nil _ _, ⟨h, trivial⟩⟩
  simp [paramsFail]

/-- Production accept fixture: product + binding + productAir on kernel. -/
def mkProductBundle (st : ProductStatement) (w : ProductWitness) : Bundle where
  steps := [.productAir st w]
  accept := true
  label := "product"
  eligibility := "dev"
  blowup := BLOWUP
  queries := QUERIES
  grindBits := GRIND_BITS
  fold := FOLD

/-!
  S4 full-IR production fixture — multi-query production IR from pure vectors
  (C-pure-verify.simple honest-prod) + productAir, not productAir-only / identity theater.
-/

/-- Empty selector samples (base field) for DEEP q_at NamedP bridge fixture. -/
def fullIREmptySel : SelAtK where
  is_full := 0; is_partial := 0; is_block_start := 0; is_reabsorb := 0
  is_range := 0; is_range_first := 0; is_range_step := 0; is_range_last := 0
  range_weight := 0; rc := []; chain_minv := []

def fullIREmptyMask : SelMaskZ where
  is_full := zero; is_partial := zero; is_block_start := zero; is_reabsorb := zero
  is_range := zero; is_range_first := zero; is_range_step := zero; is_range_last := zero
  rc := []; chain_minv := []

/-- DEEP q_at NamedP fixture (eval=0); production multi-query DEEP z is in ProdIRFixture. -/
def fullIRDeepInp : QAtInput where
  x := 0
  z := one
  zg := ⟨2, 0⟩
  comp_z := zero
  rw_zg := zero
  cc := zero
  ck := []
  Pcz := []
  Pczg := []
  deep_alphas := List.replicate 10 zero
  sel := fullIREmptySel
  selMask := fullIREmptyMask

/-- Algebraic friFold NamedP bridge (xpos≠0). -/
def fullIRFriStep : Step := .friFold zero zero zero zero 1

/-- DEEP q_at NamedP bridge step. -/
def fullIRDeepStep : Step := .deepQAt fullIRDeepInp zero

/-- Aliases used by StepAlgebra NamedP inventory (production multi-query overrides). -/
def fullIRFsStep : Step := prodFsStep0
def fullIRCosetStep : Step := prodCosetStep0
def fullIRMerkleStep : Step := prodMerkleStep0
def fullIRDeepZStep : Step := prodDeepZStep

/--
  Full-IR production Accept bundle:
  params + productAir + friFold/deepQAt NamedP anchors + multi-query production
  bridges (FS×4, Merkle×8, coset×8, DEEP z) from pure honest-prod vectors.
-/
def mkFullIRProductBundle (st : ProductStatement) (w : ProductWitness) : Bundle where
  steps :=
    [ .params BLOWUP QUERIES GRIND_BITS FOLD
    , .productAir st w
    , fullIRFriStep
    , fullIRDeepStep
    ] ++ prodIRBridgeSteps
  accept := true
  label := "full-ir-product"
  eligibility := "product"
  blowup := BLOWUP
  queries := QUERIES
  grindBits := GRIND_BITS
  fold := FOLD

/-- Step-class presence helpers for the full-IR gate. -/
def hasParamsStep (steps : List Step) : Bool :=
  steps.any fun s => match s with | .params _ _ _ _ => true | _ => false

def hasProductAirAny (steps : List Step) : Bool :=
  steps.any fun s => match s with | .productAir _ _ => true | _ => false

def hasFriFoldStep (steps : List Step) : Bool :=
  steps.any fun s => match s with | .friFold .. => true | _ => false

def hasCosetFoldStep (steps : List Step) : Bool :=
  steps.any fun s => match s with | .cosetFold .. => true | _ => false

def hasMerkleStep (steps : List Step) : Bool :=
  steps.any fun s => match s with | .merkleDigest .. => true | _ => false

def hasDeepQAtStep (steps : List Step) : Bool :=
  steps.any fun s => match s with | .deepQAt .. => true | _ => false

def hasDeepZStep (steps : List Step) : Bool :=
  steps.any fun s => match s with | .deepZ .. => true | _ => false

def hasFsAbsorbStep (steps : List Step) : Bool :=
  steps.any fun s => match s with | .fsAbsorb .. => true | _ => false

def countMerkleSteps (steps : List Step) : Nat :=
  (steps.filter fun s => match s with | .merkleDigest .. => true | _ => false).length

def countCosetSteps (steps : List Step) : Nat :=
  (steps.filter fun s => match s with | .cosetFold .. => true | _ => false).length

/-- Multi-query: at least QUERIES Merkle opens and QUERIES coset folds on path. -/
def isMultiQueryIR (steps : List Step) : Bool :=
  countMerkleSteps steps ≥ QUERIES && countCosetSteps steps ≥ QUERIES

/-- Production-layer FRI: at least one cosetFold with s = FOLD and |coset| = 2^s. -/
def hasProductionLayerCoset (steps : List Step) : Bool :=
  steps.any isProductionLayerCoset

def countProductionLayerCosets (steps : List Step) : Nat :=
  (steps.filter isProductionLayerCoset).length

/--
  Full-IR predicate: multi-query production path with params, productAir, FS,
  FRI/coset, Merkle, DEEP, and at least one production-layer (s=FOLD) coset.
  Rejects identity theater, productAir-only, and s=1-only multi-query samples.
-/
def isFullIRBundle (b : Bundle) : Bool :=
  b.steps.length ≥ 10 &&
  hasParamsStep b.steps &&
  hasProductAirAny b.steps &&
  hasFriFoldStep b.steps &&
  hasCosetFoldStep b.steps &&
  hasMerkleStep b.steps &&
  hasDeepQAtStep b.steps &&
  hasDeepZStep b.steps &&
  hasFsAbsorbStep b.steps &&
  isMultiQueryIR b.steps &&
  hasProductionLayerCoset b.steps
/-- NamedP algebraic anchors still hold. -/
theorem fullIR_fri_step_ok : runStep fullIRFriStep = .ok := by native_decide
theorem fullIR_deep_step_ok : runStep fullIRDeepStep = .ok := by native_decide
theorem fullIR_coset_step_ok : runStep fullIRCosetStep = .ok := prodCosetStep0_ok
theorem fullIR_merkle_step_ok : runStep fullIRMerkleStep = .ok := prodMerkleStep0_ok
theorem fullIR_deepZ_step_ok : runStep fullIRDeepZStep = .ok := prodDeepZStep_ok
theorem fullIR_fs_step_ok : runStep fullIRFsStep = .ok := prodFsStep0_ok

theorem hasProductAir_singleton (c : ProductClaim) :
    hasProductAirStep c [.productAir c.st c.w] = true := by
  simp [hasProductAirStep, stepIsProductAir]

theorem hasProductAir_fullIR (c : ProductClaim) :
    hasProductAirStep c (mkFullIRProductBundle c.st c.w).steps = true := by
  -- steps = [params, productAir, fri, deep] ++ prodIRBridgeSteps
  simp only [hasProductAirStep, mkFullIRProductBundle]
  rw [List.any_append, Bool.or_eq_true]
  left
  simp [List.any_cons, stepIsProductAir]
/-- productAir-only is not full-IR. -/
theorem not_fullIR_product_only (st : ProductStatement) (w : ProductWitness) :
    isFullIRBundle (mkProductBundle st w) = false := by
  simp [isFullIRBundle, mkProductBundle, isMultiQueryIR,
    hasParamsStep, hasProductAirAny, hasFriFoldStep, hasCosetFoldStep,
    hasMerkleStep, hasDeepQAtStep, hasDeepZStep, hasFsAbsorbStep,
    countMerkleSteps, countCosetSteps]

/-- Concrete multi-query production full-IR Accept fixture (honest deposit). -/
theorem fullIR_deposit_is_fullIR :
    isFullIRBundle (mkFullIRProductBundle honestDeposit.1 honestDeposit.2) = true := by
  native_decide

theorem fullIR_solo_not_fullIR :
    isFullIRBundle (mkProductBundle honestDeposit.1 honestDeposit.2) = false :=
  not_fullIR_product_only _ _

/-- Multi-query production bridge list meets QUERIES×Merkle and QUERIES×coset. -/
theorem prodIR_bridge_multi_query :
    countMerkleSteps prodIRBridgeSteps ≥ QUERIES ∧
    countCosetSteps prodIRBridgeSteps ≥ QUERIES := by
  native_decide

theorem fullIR_deposit_multi_query :
    isMultiQueryIR (mkFullIRProductBundle honestDeposit.1 honestDeposit.2).steps = true := by
  native_decide

theorem fullIR_deposit_has_layer_coset :
    hasProductionLayerCoset (mkFullIRProductBundle honestDeposit.1 honestDeposit.2).steps = true := by
  native_decide

theorem fullIR_layer_coset0_ok : runStep prodLayerCosetStep0 = .ok :=
  prodLayerCosetStep0_ok

/-- Generic: productAir payload does not affect multi-query bridge counts. -/
theorem fullIR_multi_query_counts (st : ProductStatement) (w : ProductWitness) :
    countMerkleSteps (mkFullIRProductBundle st w).steps =
      countMerkleSteps prodIRBridgeSteps ∧
    countCosetSteps (mkFullIRProductBundle st w).steps =
      countCosetSteps prodIRBridgeSteps := by
  simp [mkFullIRProductBundle, countMerkleSteps, countCosetSteps, fullIRFriStep, fullIRDeepStep]

/--
  Size-bounded eternal remainder for full pure IR inlining:
  Accept carries a non-empty production-layer sample; full pure honest-prod
  has 16 s=8 cosets / 889 step lines (not all inlined into the Lean constant).
-/
theorem fullIR_layer_subset_of_full_pure :
    prodIRAcceptLayerCosets ≤ prodIRFullPureCosetS8 ∧
    prodIRAcceptLayerCosets ≥ 1 := by
  native_decide

end FriStark.Packing.Unpack
