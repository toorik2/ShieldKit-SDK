/-
  Non-tautological semantic predicates — field-equation form (∃ eval = some q).

  Checkers use Option.any so `matchesExpect_iff_deepEval` etc. give real
  ∃-eval characterizations without kernel-deep-unfolding Id.run bodies.
-/
import FriStark.Deep.QAt
import FriStark.FRI.Coset
import FriStark.FRI.Verify
import FriStark.FRI.Fold
import FriStark.Field.Ext
import FriStark.Field.Goldilocks
import FriStark.Field.NTT
import FriStark.AIR.ComposeExt
import FriStark.Domain.PublicEval
import FriStark.Domain.SelRebuild
import FriStark.Full.Verify
import FriStark.Hash.Merkle

namespace FriStark.Soundness.Semantic

open FriStark.Deep.QAt
open FriStark.FRI.Coset
open FriStark.FRI.Verify
open FriStark.FRI.Fold
open FriStark.Field.Ext
open FriStark.Field.Goldilocks (F)
open FriStark.Field.NTT
open FriStark.AIR.ComposeExt
open FriStark.Domain.PublicEval
open FriStark.Domain.SelRebuild
open FriStark.Full.Verify
open FriStark.Hash.Merkle

/-! ### DEEP quotient — real field equations -/

/-- Semantic DEEP fri0 bind: ∃ q, eval = some q ∧ q = expect (not runStep, not bare Bool). -/
abbrev DeepFri0Bind (inp : QAtInput) (expect : E) : Prop :=
  DeepEvalEquals inp expect

theorem matchesExpect_implies_deepFri0 (inp : QAtInput) (expect : E)
    (h : matchesExpect inp expect = true) : DeepFri0Bind inp expect :=
  matchesExpect_implies_deepEval inp expect h

theorem deepFri0_iff_matchesExpect (inp : QAtInput) (expect : E) :
    DeepFri0Bind inp expect ↔ matchesExpect inp expect = true :=
  (matchesExpect_iff_deepEval inp expect).symm

theorem deepFri0_has_eval (inp : QAtInput) (expect : E)
    (h : DeepFri0Bind inp expect) :
    ∃ q, eval inp = some q ∧ eq q expect = true := h

theorem deepQAtLayout_implies_deepFri0 (layout : HLayout) (core : DeepQAtCore)
    (h : matchesExpect (qatFromLayout layout core) core.expectFri0 = true) :
    DeepFri0Bind (qatFromLayout layout core) core.expectFri0 :=
  matchesExpect_implies_deepFri0 _ _ h

theorem qatFromLayout_sel_is_publicEval (layout : HLayout) (core : DeepQAtCore) :
    (qatFromLayout layout core).sel = selAtBase layout core.x ∧
    (qatFromLayout layout core).selMask = selMaskAtZ layout core.z ∧
    (qatFromLayout layout core).rw_zg = rwAtZg layout core.zg := by
  simp [qatFromLayout]

def PublicEvalAtBase (hVals : List F) (oT x v : F) : Prop :=
  evalAtBase hVals oT x = v

theorem selAtBase_is_full_publicEval (L : HLayout) (x : F) :
    PublicEvalAtBase L.is_full L.oT x (selAtBase L x).is_full := rfl

theorem selAtBase_range_weight_publicEval (L : HLayout) (x : F) :
    PublicEvalAtBase L.range_weight L.oT x (selAtBase L x).range_weight := rfl

def PublicEvalAtExt (hVals : List F) (oT : F) (z : E) (v : E) : Prop :=
  evalAtExt hVals oT z = v

theorem selMask_is_full_publicEval (L : HLayout) (z : E) :
    PublicEvalAtExt L.is_full L.oT z (selMaskAtZ L z).is_full := rfl

theorem evalAtBase_eq_horner (hVals : List F) (oT x : F) :
    evalAtBase hVals oT x = hornerBase (coeffsFromH hVals oT) x := rfl

theorem evalAtExt_eq_hornerExt (hVals : List F) (oT : F) (z : E) :
    evalAtExt hVals oT z = hornerExt (coeffsFromH hVals oT) z := rfl

theorem coeffsFromH_is_intt (hVals : List F) (oT : F) :
    coeffsFromH hVals oT = intt hVals oT := rfl

/-! ### Composition at z — eq ∘ composeAtExt -/

def CompositionEquals
    (cur nxt : List (String × E))
    (z : E) (wNext : E) (last : F)
    (zhInvV : E) (Hd : List F)
    (pub : List (String × E)) (rc chainMinv : List E)
    (alphasT alphasB : List E)
    (bounds : List Boundary)
    (Mext Minv : List (List F)) (diag Minv0 : List F)
    (held : List String) (expect : E) : Prop :=
  eq (composeAtExt cur nxt z wNext last zhInvV Hd pub rc chainMinv
        alphasT alphasB bounds Mext Minv diag Minv0 held) expect = true

theorem matchesCompZ_def
    (cur nxt : List (String × E))
    (z : E) (wNext : E) (last : F)
    (zhInvV : E) (Hd : List F)
    (pub : List (String × E)) (rc chainMinv : List E)
    (alphasT alphasB : List E)
    (bounds : List Boundary)
    (Mext Minv : List (List F)) (diag Minv0 : List F)
    (held : List String) (expect : E) :
    matchesCompZ cur nxt z wNext last zhInvV Hd pub rc chainMinv
      alphasT alphasB bounds Mext Minv diag Minv0 held expect =
    eq (composeAtExt cur nxt z wNext last zhInvV Hd pub rc chainMinv
          alphasT alphasB bounds Mext Minv diag Minv0 held) expect := rfl

theorem matchesCompZ_implies_composition
    (cur nxt : List (String × E))
    (z : E) (wNext : E) (last : F)
    (zhInvV : E) (Hd : List F)
    (pub : List (String × E)) (rc chainMinv : List E)
    (alphasT alphasB : List E)
    (bounds : List Boundary)
    (Mext Minv : List (List F)) (diag Minv0 : List F)
    (held : List String) (expect : E)
    (h : matchesCompZ cur nxt z wNext last zhInvV Hd pub rc chainMinv
          alphasT alphasB bounds Mext Minv diag Minv0 held expect = true) :
    CompositionEquals cur nxt z wNext last zhInvV Hd pub rc chainMinv
      alphasT alphasB bounds Mext Minv diag Minv0 held expect := by
  simpa [CompositionEquals, matchesCompZ_def] using h

theorem composeCheck_implies_composition (pack : ComposePack)
    (h : matchesCompZ pack.cur pack.nxt pack.z pack.wNext pack.lastF pack.zhInv pack.Hd
          pack.pub pack.rc pack.chainMinv pack.alphasT pack.alphasB pack.bounds
          pack.Mext pack.Minv pack.diag pack.Minv0 pack.held pack.expectCompZ = true) :
    CompositionEquals pack.cur pack.nxt pack.z pack.wNext pack.lastF pack.zhInv pack.Hd
      pack.pub pack.rc pack.chainMinv pack.alphasT pack.alphasB pack.bounds
      pack.Mext pack.Minv pack.diag pack.Minv0 pack.held pack.expectCompZ :=
  matchesCompZ_implies_composition _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ h

/-! ### Coset fold — ∃ got, cosetFold = some got -/

abbrev CosetFoldBind (coset : List E) (betas : List E)
    (base li0 s off oN N : Nat) (expect : E) : Prop :=
  CosetEvalEquals coset betas base li0 s off oN N expect

theorem verifyCosetFold_implies_bind
    (coset : List E) (betas : List E)
    (base li0 s off oN N : Nat) (expect : E)
    (h : verifyCosetFold coset betas base li0 s off oN N expect = true) :
    CosetFoldBind coset betas base li0 s off oN N expect :=
  verifyCosetFold_implies_cosetEval coset betas base li0 s off oN N expect h

theorem cosetFold_has_eval
    (coset : List E) (betas : List E)
    (base li0 s off oN N : Nat) (expect : E)
    (h : CosetFoldBind coset betas base li0 s off oN N expect) :
    ∃ got, cosetFold coset betas base li0 s off oN N = some got ∧ eq got expect = true := h

theorem cosetFold_bad_length_s1 :
    cosetFold ([] : List E) [] 0 0 1 1 1 2 = none := by native_decide

theorem cosetFold_s0_singleton :
    cosetFold [zero] [] 0 0 0 1 1 2 = some zero := by native_decide

/-! ### FRI fold step — ∃ f, foldOnce = some f -/

abbrev FriFoldBind (v w beta : E) (xpos : Nat) (folded : E) : Prop :=
  FriFoldEvalEquals v w beta xpos folded

theorem verifyFoldStep_implies_friFoldBind
    (v w folded beta : E) (xpos : Nat)
    (h : verifyFoldStep v w folded beta xpos = true) :
    FriFoldBind v w beta xpos folded :=
  verifyFoldStep_implies_friFoldEval v w folded beta xpos h

theorem friFold_has_eval (v w beta : E) (xpos : Nat) (folded : E)
    (h : FriFoldBind v w beta xpos folded) :
    ∃ f, foldOnce v w beta xpos = some f ∧ eq f folded = true := h

/-! ### Merkle -/

def MerkleOpenHolds (root leaf : List UInt8) (path : List (List UInt8 × Nat)) : Prop :=
  verifyDigest root leaf path = true

theorem merkle_check_implies_open (root leaf : List UInt8)
    (path : List (List UInt8 × Nat))
    (h : verifyDigest root leaf path = true) :
    MerkleOpenHolds root leaf path := h

/-! ### runStep ⇒ semantic field equations -/

theorem runStep_deepQAt_implies_deepFri0 (inp : QAtInput) (expect : E)
    (h : runStep (.deepQAt inp expect) = .ok) :
    DeepFri0Bind inp expect := by
  simp only [runStep] at h
  split at h
  · exact matchesExpect_implies_deepFri0 inp expect (by assumption)
  · cases h

theorem runStep_deepQAt_has_eval (inp : QAtInput) (expect : E)
    (h : runStep (.deepQAt inp expect) = .ok) :
    ∃ q, eval inp = some q ∧ eq q expect = true :=
  deepFri0_has_eval inp expect (runStep_deepQAt_implies_deepFri0 inp expect h)

theorem runStep_coset_implies_bind
    (coset : List E) (betas : List E)
    (base li0 s off oN N : Nat) (expect : E)
    (h : runStep (.cosetFold coset betas base li0 s off oN N expect) = .ok) :
    CosetFoldBind coset betas base li0 s off oN N expect := by
  simp only [runStep] at h
  split at h
  · exact verifyCosetFold_implies_bind _ _ _ _ _ _ _ _ _ (by assumption)
  · cases h

theorem runStep_coset_has_eval
    (coset : List E) (betas : List E)
    (base li0 s off oN N : Nat) (expect : E)
    (h : runStep (.cosetFold coset betas base li0 s off oN N expect) = .ok) :
    ∃ got, cosetFold coset betas base li0 s off oN N = some got ∧ eq got expect = true :=
  cosetFold_has_eval _ _ _ _ _ _ _ _ _
    (runStep_coset_implies_bind coset betas base li0 s off oN N expect h)

theorem runStep_compose_implies_composition (pack : ComposePack)
    (h : runStep (.composeCheck pack) = .ok) :
    CompositionEquals pack.cur pack.nxt pack.z pack.wNext pack.lastF pack.zhInv pack.Hd
      pack.pub pack.rc pack.chainMinv pack.alphasT pack.alphasB pack.bounds
      pack.Mext pack.Minv pack.diag pack.Minv0 pack.held pack.expectCompZ := by
  simp only [runStep] at h
  split at h
  · exact composeCheck_implies_composition pack (by assumption)
  · cases h

theorem runStep_merkle_implies_open (r l : List UInt8) (p : List (List UInt8 × Nat))
    (h : runStep (.merkleDigest r l p) = .ok) :
    MerkleOpenHolds r l p := by
  simp only [runStep] at h
  split at h
  · exact merkle_check_implies_open r l p (by assumption)
  · cases h

theorem runStep_friFold_implies_bind
    (v w beta folded : E) (xpos : Nat)
    (h : runStep (.friFold v w beta folded xpos) = .ok) :
    FriFoldBind v w beta xpos folded := by
  simp only [runStep] at h
  split at h
  · exact verifyFoldStep_implies_friFoldBind v w folded beta xpos (by assumption)
  · cases h

theorem runStep_friFold_has_eval
    (v w beta folded : E) (xpos : Nat)
    (h : runStep (.friFold v w beta folded xpos) = .ok) :
    ∃ f, foldOnce v w beta xpos = some f ∧ eq f folded = true :=
  friFold_has_eval v w beta xpos folded
    (runStep_friFold_implies_bind v w beta folded xpos h)

/-- DeepFri0Bind is definitionally the ∃-eval form (not runStep=.ok). -/
theorem deepFri0_is_exists_eval (inp : QAtInput) (expect : E) :
    DeepFri0Bind inp expect ↔ ∃ q, eval inp = some q ∧ eq q expect = true := Iff.rfl

end FriStark.Soundness.Semantic
