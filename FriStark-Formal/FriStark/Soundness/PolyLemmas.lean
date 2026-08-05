/-
  Phase 3 — deeper FRI/DEEP/compose/public algebraic lemmas on accept-path defs.
  No Bool theater flags; DiffT4 exercises real theorems and field identities.
-/
import FriStark.Deep.QAt
import FriStark.FRI.Coset
import FriStark.FRI.Fold
import FriStark.FRI.Verify
import FriStark.Field.Ext
import FriStark.Field.Goldilocks
import FriStark.Field.NTT
import FriStark.AIR.ComposeExt
import FriStark.Domain.PublicEval
import FriStark.Domain.SelRebuild
import FriStark.Full.Verify
import FriStark.Soundness.Semantic
import FriStark.Params.V1

namespace FriStark.Soundness.PolyLemmas

open FriStark.Deep.QAt
open FriStark.FRI.Coset
open FriStark.FRI.Fold
open FriStark.FRI.Verify
open FriStark.Field.Ext
open FriStark.Field.Goldilocks (F)
open FriStark.Field.NTT
open FriStark.AIR.ComposeExt
open FriStark.Domain.PublicEval
open FriStark.Domain.SelRebuild
open FriStark.Full.Verify
open FriStark.Soundness.Semantic
open FriStark.Params.V1

/-! ### DEEP quotient field meaning -/

theorem deep_fri0_is_field_eq (inp : QAtInput) (expect : E)
    (h : matchesExpect inp expect = true) :
    ∃ q : E, eval inp = some q ∧ eq q expect = true :=
  matchesExpect_implies_deepEval inp expect h

theorem qatFromLayout_comp_z (layout : HLayout) (core : DeepQAtCore) :
    (qatFromLayout layout core).comp_z = core.proofCompZ ∧
    (qatFromLayout layout core).cc = core.cc ∧
    (qatFromLayout layout core).x = core.x := by
  simp [qatFromLayout]

theorem qatFromLayout_rebuilds_public (layout : HLayout) (core : DeepQAtCore) :
    (qatFromLayout layout core).sel = selAtBase layout core.x ∧
    (qatFromLayout layout core).selMask = selMaskAtZ layout core.z := by
  simp [qatFromLayout]

/-! ### Composition poly structure (real residual list structure) -/

/-- Capacity residual count = WIDTH − RATE = 4 (CT-AIR structure). -/
theorem capacity_residuals_len (cur : List (String × E)) (isbs : E)
    (Minv : List (List F)) :
    (capacityResiduals cur isbs Minv).length = WIDTH - RATE := by
  simp [capacityResiduals, List.length_map, List.length_range]

theorem capacity_residuals_len_num :
    (capacityResiduals [] zero []).length = 4 := by
  native_decide

/-- Range residual vector has fixed length 5. -/
theorem range_residuals_len
    (cur nxt : List (String × E)) (isr isf ist isl wNext : E) :
    (rangeResiduals cur nxt isr isf ist isl wNext).length = 5 := by
  simp [rangeResiduals]

theorem range_residuals_len_num :
    (rangeResiduals [] [] zero zero zero zero zero).length = 5 := by
  native_decide

/-- Hold residuals length = held columns. -/
theorem hold_residuals_len (cur nxt : List (String × E)) (held : List String) :
    (holdResiduals cur nxt held).length = held.length := by
  simp [holdResiduals, List.length_map]

/-- matchesCompZ is definitionally eq∘composeAtExt. -/
theorem composition_is_composeAtExt_eq
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
    eq (composeAtExt cur nxt z wNext last zhInvV Hd pub rc chainMinv
          alphasT alphasB bounds Mext Minv diag Minv0 held) expect = true := by
  simpa [matchesCompZ] using h

theorem compose_width_12 : WIDTH = 12 := rfl
theorem compose_rate_8 : RATE = 8 := rfl
theorem compose_capacity_slots : WIDTH - RATE = 4 := by native_decide

/-! ### Coset / fold algebra -/

theorem coset_s0_is_head :
    cosetFold [zero] [] 0 0 0 1 1 2 = some zero := by native_decide

theorem coset_s1_needs_len2 :
    cosetFold [zero] [] 0 0 1 1 1 2 = none := by native_decide

theorem coset_s1_empty_fails :
    cosetFold ([] : List E) [] 0 0 1 1 1 2 = none := by native_decide

/-- s=1 with correct length-2 coset returns some (foldOnce applied). -/
theorem coset_s1_len2_is_some :
    (cosetFold [zero, one] [zero] 0 0 1 1 1 2).isSome = true := by
  native_decide

theorem foldOnce_eq_friFold (v w beta : E) (xpos : F) :
    foldOnce v w beta xpos = friFold v w beta xpos := rfl

theorem fri_fold_step_field_eq (v w folded beta : E) (xpos : Nat)
    (h : verifyFoldStep v w folded beta xpos = true) :
    ∃ f, foldOnce v w beta xpos = some f ∧ eq f folded = true :=
  (verifyFoldStep_iff_friFoldEval v w folded beta xpos).mp h

theorem fold_pin_production : FOLD = 8 := fold_pin

/-! ### Public Horner ≡ INTT (accept path; not full N=2²⁰) -/

theorem public_eval_base_is_horner_intt (hVals : List F) (oT x : F) :
    evalAtBase hVals oT x = hornerBase (intt hVals oT) x := by
  simp only [evalAtBase, coeffsFromH]

theorem public_eval_ext_is_horner_intt (hVals : List F) (oT : F) (z : E) :
    evalAtExt hVals oT z = hornerExt (intt hVals oT) z := by
  simp only [evalAtExt, coeffsFromH]

theorem sel_is_full_lde (L : HLayout) (x : F) :
    (selAtBase L x).is_full = hornerBase (intt L.is_full L.oT) x := by
  simp only [selAtBase, public_eval_base_is_horner_intt]

theorem sel_mask_is_full_ood (L : HLayout) (z : E) :
    (selMaskAtZ L z).is_full = hornerExt (intt L.is_full L.oT) z := by
  simp only [selMaskAtZ, public_eval_ext_is_horner_intt]

/-- Inventory for STATUS (names of real theorems only). -/
def polyLemmaNames : List String :=
  [ "deep_fri0_is_field_eq"
  , "qatFromLayout_comp_z"
  , "qatFromLayout_rebuilds_public"
  , "capacity_residuals_len"
  , "range_residuals_len"
  , "hold_residuals_len"
  , "composition_is_composeAtExt_eq"
  , "coset_s0_is_head"
  , "coset_s1_needs_len2"
  , "coset_s1_len2_is_some"
  , "foldOnce_eq_friFold"
  , "fri_fold_step_field_eq"
  , "public_eval_base_is_horner_intt"
  , "public_eval_ext_is_horner_intt"
  , "sel_is_full_lde"
  , "sel_mask_is_full_ood"
  ]

theorem poly_lemma_count : polyLemmaNames.length = 16 := by native_decide

end FriStark.Soundness.PolyLemmas
