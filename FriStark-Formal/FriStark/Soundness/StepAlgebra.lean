/-
  Production-path Step constructors: runStep = .ok ⇒ named Prop.
-/
import FriStark.Full.Verify
import FriStark.Soundness.Semantic
import FriStark.Soundness.Statement
import FriStark.AIR.ProductV1
import FriStark.Params.V1
import FriStark.Hash.Sha256
import FriStark.Transcript.FiatShamir
import FriStark.Deep.QAt
import FriStark.Deep.Replay
import FriStark.Domain.SelRebuild
import FriStark.Packing.Unpack
import FriStark.Packing.ProdIRFixture

namespace FriStark.Soundness.StepAlgebra

open FriStark.Full.Verify
open FriStark.Soundness.Semantic
open FriStark.Soundness.Statement
open FriStark.AIR.ProductV1
open FriStark.Params.V1
open FriStark.Hash.Sha256 (Bytes)
open FriStark.Transcript.FiatShamir
open FriStark.Field.Ext
open FriStark.Field.Ext (E)
open FriStark.Deep.QAt
open FriStark.Deep.Replay
open FriStark.Domain.SelRebuild
open FriStark.Packing.Unpack
open FriStark.Packing.ProdIRFixture

def ParamsPinHolds (b q g f : Nat) : Prop :=
  b = BLOWUP ∧ q = QUERIES ∧ g = GRIND_BITS ∧ f = FOLD

theorem runStep_params_implies_pin (b q g f : Nat)
    (h : runStep (.params b q g f) = .ok) : ParamsPinHolds b q g f := by
  simp only [runStep] at h
  cases h1 : b == BLOWUP <;> cases h2 : q == QUERIES <;>
    cases h3 : g == GRIND_BITS <;> cases h4 : f == FOLD <;> simp_all [ParamsPinHolds]

def FsAbsorbHolds (pre data post : Bytes) : Prop :=
  (absorb ⟨pre⟩ data).bytes = post

theorem runStep_fsAbsorb_implies (pre data post : Bytes)
    (h : runStep (.fsAbsorb pre data post) = .ok) : FsAbsorbHolds pre data post := by
  simp only [runStep, FsAbsorbHolds] at h ⊢
  cases he : (absorb ⟨pre⟩ data).bytes == post <;> simp_all

def GrindHolds (st n : Bytes) (bits : Nat) : Prop := grindOk st n bits = true

theorem runStep_grind_implies (st n : Bytes) (bits : Nat)
    (h : runStep (.grindCheck st n bits) = .ok) : GrindHolds st n bits := by
  simp only [runStep, GrindHolds] at h ⊢
  cases he : grindOk st n bits <;> simp_all

def NatEqHolds (a b : Nat) : Prop := a = b

theorem runStep_natEq_implies (a b : Nat)
    (h : runStep (.natEq a b) = .ok) : NatEqHolds a b := by
  simp only [runStep, NatEqHolds] at h ⊢
  cases he : a == b <;> simp_all

def NatListEqHolds (a b : List Nat) : Prop := a = b

theorem runStep_natListEq_implies (a b : List Nat)
    (h : runStep (.natListEq a b) = .ok) : NatListEqHolds a b := by
  simp only [runStep, NatListEqHolds] at h ⊢
  cases he : a == b <;> simp_all

def BytesEqHolds (a b : Bytes) : Prop := a = b

theorem runStep_bytesEq_implies (a b : Bytes)
    (h : runStep (.bytesEq a b) = .ok) : BytesEqHolds a b := by
  simp only [runStep, BytesEqHolds] at h ⊢
  cases he : a == b <;> simp_all

def ExtEqHolds (a b : E) : Prop := eq a b = true

theorem runStep_extEq_implies (a b : E)
    (h : runStep (.extEq a b) = .ok) : ExtEqHolds a b := by
  simp only [runStep, ExtEqHolds] at h ⊢
  cases he : eq a b <;> simp_all

def ProductAirHolds (st : ProductStatement) (w : ProductWitness) : Prop :=
  StatementHolds ⟨st, w⟩

theorem runStep_productAir_implies (st : ProductStatement) (w : ProductWitness)
    (h : runStep (.productAir st w) = .ok) : ProductAirHolds st w := by
  simp only [runStep, ProductAirHolds, StatementHolds] at h ⊢
  cases he : verifyProductAir st w <;> simp_all

theorem deep_bridge (inp : Deep.QAt.QAtInput) (expect : E)
    (h : runStep (.deepQAt inp expect) = .ok) : DeepFri0Bind inp expect :=
  runStep_deepQAt_implies_deepFri0 inp expect h

theorem fri_bridge (v w beta folded : E) (xpos : Nat)
    (h : runStep (.friFold v w beta folded xpos) = .ok) :
    FriFoldBind v w beta xpos folded :=
  runStep_friFold_implies_bind v w beta folded xpos h

theorem coset_bridge (coset : List E) (betas : List E)
    (base li0 s off oN N : Nat) (expect : E)
    (h : runStep (.cosetFold coset betas base li0 s off oN N expect) = .ok) :
    CosetFoldBind coset betas base li0 s off oN N expect :=
  runStep_coset_implies_bind coset betas base li0 s off oN N expect h

theorem compose_bridge (pack : ComposePack)
    (h : runStep (.composeCheck pack) = .ok) :
    CompositionEquals pack.cur pack.nxt pack.z pack.wNext pack.lastF pack.zhInv pack.Hd
      pack.pub pack.rc pack.chainMinv pack.alphasT pack.alphasB pack.bounds
      pack.Mext pack.Minv pack.diag pack.Minv0 pack.held pack.expectCompZ :=
  runStep_compose_implies_composition pack h

theorem merkle_bridge (r l : Bytes) (p : List (Bytes × Nat))
    (h : runStep (.merkleDigest r l p) = .ok) : MerkleOpenHolds r l p :=
  runStep_merkle_implies_open r l p h

def DeepAlphasHolds (got expect : List E) : Prop := got = expect

theorem runStep_deepAlphas_implies (got expect : List E)
    (h : runStep (.deepAlphas got expect) = .ok) : DeepAlphasHolds got expect := by
  simp only [runStep, DeepAlphasHolds] at h ⊢
  cases he : got == expect <;> simp_all

def FsAbsorbIntHolds (pre : Bytes) (v : Nat) (post : Bytes) : Prop :=
  (absorbInt ⟨pre⟩ v).bytes = post

theorem runStep_fsAbsorbInt_implies (pre : Bytes) (v : Nat) (post : Bytes)
    (h : runStep (.fsAbsorbInt pre v post) = .ok) : FsAbsorbIntHolds pre v post := by
  simp only [runStep, FsAbsorbIntHolds] at h ⊢
  cases he : (absorbInt ⟨pre⟩ v).bytes == post <;> simp_all

/-! ### Remaining production-path Step constructors (real checker Props, not runStep=.ok) -/

open FriStark.Field.Goldilocks (F)
open FriStark.Deep.Replay (checkZ)

/-- FS challenge: challenge(pre) yields (expect, post). -/
def FsChallengeHolds (pre : Bytes) (expect : F) (post : Bytes) : Prop :=
  let p := challenge ⟨pre⟩
  p.1 = expect ∧ p.2.bytes = post

theorem runStep_fsChallenge_implies (pre : Bytes) (expect : F) (post : Bytes)
    (h : runStep (.fsChallenge pre expect post) = .ok) :
    FsChallengeHolds pre expect post := by
  simp only [runStep, FsChallengeHolds] at h ⊢
  cases h1 : (challenge ⟨pre⟩).1 == expect <;>
    cases h2 : (challenge ⟨pre⟩).2.bytes == post <;> simp_all

/-- FS ext challenge: two successive challenges match (a0,a1) and post. -/
def FsExtChallengeHolds (pre : Bytes) (a0 a1 : F) (post : Bytes) : Prop :=
  let p0 := challenge ⟨pre⟩
  let p1 := challenge p0.2
  p0.1 = a0 ∧ p1.1 = a1 ∧ p1.2.bytes = post

theorem runStep_fsExtChallenge_implies (pre : Bytes) (a0 a1 : F) (post : Bytes)
    (h : runStep (.fsExtChallenge pre a0 a1 post) = .ok) :
    FsExtChallengeHolds pre a0 a1 post := by
  simp only [runStep, FsExtChallengeHolds] at h ⊢
  cases h1 : (challenge ⟨pre⟩).1 == a0 <;>
    cases h2 : (challenge (challenge ⟨pre⟩).2).1 == a1 <;>
    cases h3 : (challenge (challenge ⟨pre⟩).2).2.bytes == post <;> simp_all

/-- FS challenge index: challengeIdx matches expectIdx and post. -/
def FsChallengeIdxHolds (pre : Bytes) (domain expectIdx : Nat) (post : Bytes) : Prop :=
  let p := challengeIdx ⟨pre⟩ domain
  p.1 = expectIdx ∧ p.2.bytes = post

theorem runStep_fsChallengeIdx_implies (pre : Bytes) (domain expectIdx : Nat) (post : Bytes)
    (h : runStep (.fsChallengeIdx pre domain expectIdx post) = .ok) :
    FsChallengeIdxHolds pre domain expectIdx post := by
  simp only [runStep, FsChallengeIdxHolds] at h ⊢
  cases h1 : (challengeIdx ⟨pre⟩ domain).1 == expectIdx <;>
    cases h2 : (challengeIdx ⟨pre⟩ domain).2.bytes == post <;> simp_all

/-- DEEP z check Bool as Prop. -/
def DeepZHolds (zp zgp zg : E) (oT : F) : Prop :=
  checkZ zp zgp zg oT = true

theorem runStep_deepZ_implies (zp zgp zg : E) (oT : F)
    (h : runStep (.deepZ zp zgp zg oT) = .ok) : DeepZHolds zp zgp zg oT := by
  simp only [runStep, DeepZHolds] at h ⊢
  cases he : checkZ zp zgp zg oT <;> simp_all

/-- DEEP layout q_at: matchesExpect on rebuilt input. -/
def DeepQAtLayoutHolds (layout : HLayout) (core : DeepQAtCore) : Prop :=
  matchesExpect (qatFromLayout layout core) core.expectFri0 = true

theorem runStep_deepQAtLayout_implies (layout : HLayout) (core : DeepQAtCore)
    (h : runStep (.deepQAtLayout layout core) = .ok) :
    DeepQAtLayoutHolds layout core := by
  simp only [runStep, DeepQAtLayoutHolds] at h ⊢
  cases he : matchesExpect (qatFromLayout layout core) core.expectFri0 <;> simp_all

/-- All production-path Step constructors (20 IR classes). -/
def stepAlgebraNames : List String :=
  [ "runStep_params_implies_pin", "runStep_fsAbsorb_implies", "runStep_fsAbsorbInt_implies"
  , "runStep_fsChallenge_implies", "runStep_fsExtChallenge_implies", "runStep_fsChallengeIdx_implies"
  , "runStep_grind_implies", "runStep_natEq_implies", "runStep_natListEq_implies"
  , "runStep_bytesEq_implies", "runStep_extEq_implies", "runStep_productAir_implies"
  , "runStep_deepAlphas_implies", "runStep_deepZ_implies", "runStep_deepQAtLayout_implies"
  , "deep_bridge", "fri_bridge", "coset_bridge", "compose_bridge", "merkle_bridge"
  ]

theorem step_algebra_count : stepAlgebraNames.length = 20 := by native_decide

/-! ### Full-IR fixture steps ⇒ NamedP bridges (S4 multi-query production path) -/

theorem fullIR_fri_namedP : FriFoldBind zero zero zero 1 zero :=
  fri_bridge zero zero zero zero 1 fullIR_fri_step_ok

/-- Production cosetFold (s=1 multi-query sample) ⇒ CosetFoldBind. -/
theorem fullIR_coset_namedP :
    match fullIRCosetStep with
    | .cosetFold coset betas base li0 s off oN N expect =>
        CosetFoldBind coset betas base li0 s off oN N expect
    | _ => False := by
  simp only [fullIRCosetStep, prodCosetStep0]
  exact coset_bridge _ _ _ _ _ _ _ _ _ (by simpa [fullIRCosetStep, prodCosetStep0] using fullIR_coset_step_ok)

/-- Production Merkle open ⇒ MerkleOpenHolds. -/
theorem fullIR_merkle_namedP :
    match fullIRMerkleStep with
    | .merkleDigest r l p => MerkleOpenHolds r l p
    | _ => False := by
  simp only [fullIRMerkleStep, prodMerkleStep0]
  exact merkle_bridge _ _ _ (by simpa [fullIRMerkleStep, prodMerkleStep0] using fullIR_merkle_step_ok)

theorem fullIR_deep_namedP : DeepFri0Bind fullIRDeepInp zero :=
  deep_bridge fullIRDeepInp zero fullIR_deep_step_ok

theorem fullIR_deep_has_eval :
    ∃ q, eval fullIRDeepInp = some q ∧ eq q zero = true :=
  runStep_deepQAt_has_eval fullIRDeepInp zero fullIR_deep_step_ok

theorem fullIR_fri_has_eval :
    ∃ f, FriStark.FRI.Fold.foldOnce zero zero zero 1 = some f ∧ eq f zero = true :=
  runStep_friFold_has_eval zero zero zero zero 1 fullIR_fri_step_ok

/-- Production FS absorb ⇒ FsAbsorbHolds. -/
theorem fullIR_fs_namedP :
    match fullIRFsStep with
    | .fsAbsorb pre data post => FsAbsorbHolds pre data post
    | _ => False := by
  simp only [fullIRFsStep, prodFsStep0]
  exact runStep_fsAbsorb_implies _ _ _ (by simpa [fullIRFsStep, prodFsStep0] using fullIR_fs_step_ok)

/-- Production DEEP z ⇒ DeepZHolds. -/
theorem fullIR_deepZ_namedP :
    match fullIRDeepZStep with
    | .deepZ zp zgp zg oT => DeepZHolds zp zgp zg oT
    | _ => False := by
  simp only [fullIRDeepZStep, prodDeepZStep]
  exact runStep_deepZ_implies _ _ _ _ (by simpa [fullIRDeepZStep, prodDeepZStep] using fullIR_deepZ_step_ok)

/-- Inventory of full-IR fixture NamedP bridges (harness surface). -/
def fullIRBridgeNames : List String :=
  [ "fullIR_fri_namedP", "fullIR_coset_namedP", "fullIR_merkle_namedP"
  , "fullIR_deep_namedP", "fullIR_deep_has_eval", "fullIR_fri_has_eval"
  , "fullIR_fs_namedP", "fullIR_deepZ_namedP"
  ]

theorem fullIR_bridge_count : fullIRBridgeNames.length = 8 := by native_decide

/-- Multi-query production counts on the Accept path. -/
theorem fullIR_prod_multi_query :
    prodIRMerkleCount ≥ QUERIES ∧ prodIRCosetCount ≥ QUERIES := by
  native_decide

end FriStark.Soundness.StepAlgebra
