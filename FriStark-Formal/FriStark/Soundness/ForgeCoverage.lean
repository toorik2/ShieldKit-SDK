/-
  Wave F — forge ontology with **real** reject predicates (no `:= true` theater).
  Each class drives shipped reject path; DiffWarrant fails if any becomes false.
-/
import FriStark.Full.Verify
import FriStark.Packing.Unpack
import FriStark.Binding.Forges
import FriStark.Binding.Presence
import FriStark.AIR.ProductV1
import FriStark.Params.V1
import FriStark.Soundness.Statement
import FriStark.Deep.QAt
import FriStark.Field.Ext
import FriStark.Field.Goldilocks
import FriStark.FRI.Fold

namespace FriStark.Soundness.ForgeCoverage

open FriStark.Full.Verify
open FriStark.Packing.Unpack
open FriStark.Packing.Topology
open FriStark.Binding.Forges
open FriStark.Binding.Presence
open FriStark.AIR.ProductV1
open FriStark.Params.V1
open FriStark.Field.Ext
open FriStark.Field.Goldilocks (F)
open FriStark.Deep.QAt
open FriStark.Verify.Types

/-- F-ST: wrong-statement mutation fails product AIR (shipped ProductV1 mutators). -/
def forge_ST_reject : Bool :=
  !(verifyProductAir mutWrongKind.stmt mutWrongKind.wit) &&
  !(verifyProductAir mutPacketCommitMismatch.stmt mutPacketCommitMismatch.wit) &&
  !(verifyProductAir mutWrongRoots.stmt mutWrongRoots.wit)

/-- F-BIND: all named binding forges rejected on honest model (Binding.Forges). -/
def forge_BIND_reject : Bool :=
  allForgesRejected && wellFormed honestModel &&
  forgeRejected honestModel "omit_binding" &&
  forgeRejected honestModel "omit_state" &&
  !wellFormed (applyForge honestModel "unlocking_bind")

/-- F-FRI: inconsistent fri fold step fails runStep. -/
def forge_FRI_bad_fold : Bool :=
  !(runStep (.friFold zero zero zero one 0)).isOk

/-- F-DEEP: DEEP q_at with x=z (inv fails) rejects matchesExpect / runStep. -/
def badDeepInp : QAtInput where
  x := 0
  z := zero
  zg := zero
  comp_z := zero
  rw_zg := zero
  cc := zero
  ck := []
  Pcz := []
  Pczg := []
  deep_alphas := []
  sel := {
    is_full := 0, is_partial := 0, is_block_start := 0, is_reabsorb := 0
    is_range := 0, is_range_first := 0, is_range_step := 0, is_range_last := 0
    rc := [], chain_minv := [], range_weight := 0
  }
  selMask := {
    is_full := zero, is_partial := zero, is_block_start := zero, is_reabsorb := zero
    is_range := zero, is_range_first := zero, is_range_step := zero, is_range_last := zero
    rc := [], chain_minv := []
  }

def forge_DEEP_reject : Bool :=
  !(runStep (.deepQAt badDeepInp one)).isOk &&
  !(matchesExpect badDeepInp one)

/-- F-FS: wrong absorb post rejects. -/
def forge_FS_bad_absorb : Bool :=
  !(runStep (.fsAbsorb [] [1] [9, 9, 9])).isOk

/-- F-MERK: bad merkle path rejects. -/
def forge_MERK_bad : Bool :=
  !(runStep (.merkleDigest [1] [2] [])).isOk

/-- F-PACK: bad role order → unpack none. -/
def forge_PACK_bad_order : Bool :=
  (unpack badOrderBlob).isNone && blobOk (some badOrderBlob) == false

/-- F-PARAM: product eligibility with non-prod blowup rejects verify. -/
def forge_PARAM_bad : Bool :=
  let b : Bundle := {
    steps := [.natEq 0 0]
    accept := true
    label := "x"
    eligibility := "product"
    blowup := 1
    queries := QUERIES
    grindBits := GRIND_BITS
    fold := FOLD
  }
  !(verify b).isOk && paramsFail b

/-- F-GRIND: grindBits=64 ⇒ bound 1; empty transcript hash fails grindOk almost always. -/
def forge_GRIND_reject : Bool :=
  !(runStep (.grindCheck [] [] 64)).isOk &&
  !FriStark.Transcript.FiatShamir.grindOk [] [] 64

/-- F-PROD: all product mutations rejected. -/
def forge_PROD_mutations : Bool := mutationsAllRejected

/-- Coverage table: class → real predicate (must not be constant true). -/
def forgeCoverageTable : List (String × Bool) :=
  [ ("F-ST", forge_ST_reject)
  , ("F-BIND", forge_BIND_reject)
  , ("F-FRI", forge_FRI_bad_fold)
  , ("F-DEEP", forge_DEEP_reject)
  , ("F-FS", forge_FS_bad_absorb)
  , ("F-MERK", forge_MERK_bad)
  , ("F-PACK", forge_PACK_bad_order)
  , ("F-PARAM", forge_PARAM_bad)
  , ("F-GRIND", forge_GRIND_reject)
  , ("F-PROD", forge_PROD_mutations)
  ]

def allForgesCovered : Bool :=
  forgeCoverageTable.length == 10 && forgeCoverageTable.all (·.2)

theorem forge_coverage_count : forgeCoverageTable.length = 10 := by native_decide

/-- Machine-checked that key forge classes actually reject (not constant true). -/
theorem forge_ST_ok : forge_ST_reject = true := by native_decide
theorem forge_BIND_ok : forge_BIND_reject = true := by native_decide
theorem forge_FRI_ok : forge_FRI_bad_fold = true := by native_decide
theorem forge_DEEP_ok : forge_DEEP_reject = true := by native_decide
theorem forge_FS_ok : forge_FS_bad_absorb = true := by native_decide
theorem forge_MERK_ok : forge_MERK_bad = true := by native_decide
theorem forge_PACK_ok : forge_PACK_bad_order = true := by native_decide
theorem forge_PARAM_ok : forge_PARAM_bad = true := by native_decide
theorem forge_GRIND_ok : forge_GRIND_reject = true := by native_decide
theorem forge_PROD_ok : forge_PROD_mutations = true := by native_decide
theorem all_forges_covered_ok : allForgesCovered = true := by native_decide

/-! ### Pattern Props on real inputs + Accept/verify/unpack ⇒ ¬pattern -/

open FriStark.Soundness.Statement (ProductClaim)
open FriStark.Verify.Types (VerifyResult)
open FriStark.Field.Ext (E)
open FriStark.Field.Ext

/-- Generic: a failing step in a bundle blocks verify. -/
theorem runStep_fail_blocks_verify (s : Step) (b : Bundle)
    (hFail : (runStep s).isOk = false)
    (hMem : s ∈ b.steps)
    (hOk : verify b = .ok) : False := by
  have hAll := verify_ok_implies_stepsAllRunOk b hOk
  have hs := stepsAllRunOk_of_mem b.steps s hAll hMem
  simp only [hs, VerifyResult.isOk] at hFail
  exact Bool.noConfusion hFail

/-- F-ST: product claim fails product-AIR ⇒ productOk false ⇒ Accept false. -/
def Pattern_ST (c : ProductClaim) : Prop := verifyProductAir c.st c.w = false

theorem pattern_ST_implies_not_productOk (c : ProductClaim) (h : Pattern_ST c) :
    productOk (some c) = false := by simpa [productOk, Pattern_ST] using h

theorem pattern_ST_blocks_accept (a : AcceptBundle) (c : ProductClaim)
    (hP : a.product? = some c) (h : Pattern_ST c) :
    CovenantAccept a = false := by
  have hpo : productOk a.product? = false := by
    simp only [hP]; exact pattern_ST_implies_not_productOk c h
  unfold CovenantAccept
  simp [hpo]

theorem pattern_ST_mutWrongKind :
    Pattern_ST ⟨mutWrongKind.stmt, mutWrongKind.wit⟩ := by
  simp only [Pattern_ST]; native_decide

/-- F-BIND: ill-formed binding ⇒ bindingOk false ⇒ Accept false. -/
def Pattern_BIND (m : BindingModel) : Prop := wellFormed m = false

theorem pattern_BIND_implies_not_bindingOk (m : BindingModel) (h : Pattern_BIND m) :
    bindingOk (some m) = false := by simpa [bindingOk, Pattern_BIND] using h

theorem pattern_BIND_blocks_accept (a : AcceptBundle) (m : BindingModel)
    (hB : a.binding? = some m) (h : Pattern_BIND m) :
    CovenantAccept a = false := by
  have hb : bindingOk a.binding? = false := by
    simp only [hB]; exact pattern_BIND_implies_not_bindingOk m h
  unfold CovenantAccept
  simp [hb]

theorem pattern_BIND_unlocking :
    Pattern_BIND (applyForge honestModel "unlocking_bind") := by
  simp only [Pattern_BIND]; native_decide

/-- F-FRI: friFold inputs that fail the fold checker. -/
def Pattern_FRI (v w beta folded : E) (xpos : Nat) : Prop :=
  (runStep (.friFold v w beta folded xpos)).isOk = false

theorem pattern_FRI_blocks_verify (v w beta folded : E) (xpos : Nat)
    (h : Pattern_FRI v w beta folded xpos) (b : Bundle)
    (hMem : Step.friFold v w beta folded xpos ∈ b.steps)
    (hOk : verify b = .ok) : False :=
  runStep_fail_blocks_verify _ b h hMem hOk

theorem pattern_FRI_bad : Pattern_FRI zero zero zero one 0 := by
  simp only [Pattern_FRI]; native_decide

/-- F-DEEP: deepQAt inputs that fail matchesExpect/runStep. -/
def Pattern_DEEP (inp : QAtInput) (expect : E) : Prop :=
  (runStep (.deepQAt inp expect)).isOk = false

theorem pattern_DEEP_blocks_verify (inp : QAtInput) (expect : E)
    (h : Pattern_DEEP inp expect) (b : Bundle)
    (hMem : Step.deepQAt inp expect ∈ b.steps)
    (hOk : verify b = .ok) : False :=
  runStep_fail_blocks_verify _ b h hMem hOk

theorem pattern_DEEP_bad : Pattern_DEEP badDeepInp one := by
  simp only [Pattern_DEEP]; native_decide

/-- F-FS: fsAbsorb with wrong post. -/
def Pattern_FS (pre data post : List UInt8) : Prop :=
  (runStep (.fsAbsorb pre data post)).isOk = false

theorem pattern_FS_blocks_verify (pre data post : List UInt8)
    (h : Pattern_FS pre data post) (b : Bundle)
    (hMem : Step.fsAbsorb pre data post ∈ b.steps)
    (hOk : verify b = .ok) : False :=
  runStep_fail_blocks_verify _ b h hMem hOk

theorem pattern_FS_bad : Pattern_FS [] [1] [9, 9, 9] := by
  simp only [Pattern_FS]; native_decide

/-- F-MERK: bad merkle path. -/
def Pattern_MERK (r l : List UInt8) (p : List (List UInt8 × Nat)) : Prop :=
  (runStep (.merkleDigest r l p)).isOk = false

theorem pattern_MERK_blocks_verify (r l : List UInt8) (p : List (List UInt8 × Nat))
    (h : Pattern_MERK r l p) (b : Bundle)
    (hMem : Step.merkleDigest r l p ∈ b.steps)
    (hOk : verify b = .ok) : False :=
  runStep_fail_blocks_verify _ b h hMem hOk

theorem pattern_MERK_bad : Pattern_MERK [1] [2] [] := by
  simp only [Pattern_MERK]; native_decide

/-- F-PACK: unpack fails (bad role order) ⇒ blob path Accept cannot use that π. -/
def Pattern_PACK (π : ProofBlob) : Prop := unpack π = none

theorem pattern_PACK_implies_blobOk_false (π : ProofBlob) (h : Pattern_PACK π) :
    blobOk (some π) = false := by
  simp only [blobOk, Pattern_PACK] at h ⊢; simp [h]

theorem pattern_PACK_blocks_accept_blob (a : AcceptBundle) (π : ProofBlob)
    (hB : a.blob? = some π) (h : Pattern_PACK π) :
    CovenantAccept a = false := by
  have hk : acceptKernel a.lean a.blob? = none := by
    simp only [acceptKernel, hB, Pattern_PACK] at h ⊢; exact h
  unfold CovenantAccept
  simp [hk]

theorem pattern_PACK_bad_order : Pattern_PACK badOrderBlob := bad_order_unpack_none

/-- F-PARAM: non-production params on product eligibility. -/
def Pattern_PARAM (b : Bundle) : Prop := paramsFail b = true

theorem pattern_PARAM_blocks_verify (b : Bundle) (h : Pattern_PARAM b) :
    verify b ≠ .ok := by
  intro hok
  have := (verify_eq_ok_iff b).mp hok
  simp only [Pattern_PARAM] at h
  exact absurd this.1 (by simp [h])

theorem pattern_PARAM_bad_blowup : Pattern_PARAM {
      steps := [.natEq 0 0]
      accept := true
      label := "x"
      eligibility := "product"
      blowup := 1
      queries := QUERIES
      grindBits := GRIND_BITS
      fold := FOLD
    } := by
  simp only [Pattern_PARAM, paramsFail]; native_decide

/-- F-GRIND: grindCheck inputs that fail. -/
def Pattern_GRIND (st n : List UInt8) (bits : Nat) : Prop :=
  (runStep (.grindCheck st n bits)).isOk = false

theorem pattern_GRIND_blocks_verify (st n : List UInt8) (bits : Nat)
    (h : Pattern_GRIND st n bits) (b : Bundle)
    (hMem : Step.grindCheck st n bits ∈ b.steps)
    (hOk : verify b = .ok) : False :=
  runStep_fail_blocks_verify _ b h hMem hOk

theorem pattern_GRIND_bad : Pattern_GRIND [] [] 64 := by
  simp only [Pattern_GRIND]; native_decide

/-- F-PROD: product mutation fails product-AIR (same spine as F-ST). -/
def Pattern_PROD (c : ProductClaim) : Prop := Pattern_ST c

theorem pattern_PROD_blocks_accept (a : AcceptBundle) (c : ProductClaim)
    (hP : a.product? = some c) (h : Pattern_PROD c) :
    CovenantAccept a = false :=
  pattern_ST_blocks_accept a c hP h

theorem pattern_PROD_mutWrongKind :
    Pattern_PROD ⟨mutWrongKind.stmt, mutWrongKind.wit⟩ :=
  pattern_ST_mutWrongKind

theorem accept_rejects_bad_pack_blob :
    blobOk (some badOrderBlob) = false := packing_forge_bad_order

theorem accept_rejects_no_product (a : AcceptBundle) (h : a.product? = none) :
    CovenantAccept a = false := covenant_rejects_no_product a h

theorem accept_rejects_no_binding (a : AcceptBundle) (h : a.binding? = none) :
    CovenantAccept a = false := covenant_rejects_no_binding a h

def forgePatternTheoremNames : List String :=
  [ "pattern_ST_blocks_accept", "pattern_BIND_blocks_accept", "pattern_FRI_blocks_verify"
  , "pattern_DEEP_blocks_verify", "pattern_FS_blocks_verify", "pattern_MERK_blocks_verify"
  , "pattern_PACK_blocks_accept_blob", "pattern_PARAM_blocks_verify"
  , "pattern_GRIND_blocks_verify", "pattern_PROD_blocks_accept"
  ]

theorem forge_pattern_theorem_count :
    forgePatternTheoremNames.length = 10 := by native_decide

end FriStark.Soundness.ForgeCoverage
