/-
  T4 DEEP / composition reductions — wired to ∃-eval Semantic surface.
-/
import FriStark.Deep.QAt
import FriStark.FRI.Coset
import FriStark.Field.Ext
import FriStark.Domain.SelRebuild
import FriStark.Full.Verify
import FriStark.AIR.ComposeExt
import FriStark.Soundness.Semantic

namespace FriStark.Soundness.DeepReduction

open FriStark.Deep.QAt
open FriStark.FRI.Coset
open FriStark.Field.Ext
open FriStark.Domain.SelRebuild
open FriStark.Soundness.Semantic

/-- Algebraic DEEP bind = ∃-eval DeepEvalEquals. -/
def deepBindHolds (inp : QAtInput) (fri0 : E) : Prop :=
  DeepFri0Bind inp fri0

theorem deepBind_of_matchesExpect (inp : QAtInput) (fri0 : E)
    (h : matchesExpect inp fri0 = true) : deepBindHolds inp fri0 :=
  matchesExpect_implies_deepFri0 inp fri0 h

theorem matchesExpect_eq (inp : QAtInput) (expect : E) :
    matchesExpect inp expect = true ↔ DeepFri0Bind inp expect :=
  matchesExpect_iff_deepEval inp expect

theorem deepBind_iff_eval (inp : QAtInput) (fri0 : E) :
    deepBindHolds inp fri0 ↔ DeepEvalEquals inp fri0 := Iff.rfl

theorem deepBind_exists (inp : QAtInput) (fri0 : E)
    (h : deepBindHolds inp fri0) :
    ∃ q, eval inp = some q ∧ eq q fri0 = true :=
  deepFri0_has_eval inp fri0 h

def cosetBindHolds (coset : List E) (betas : List E)
    (base li0 s off oN N : Nat) (expect : E) : Prop :=
  CosetFoldBind coset betas base li0 s off oN N expect

theorem cosetBind_of_verify
    (coset : List E) (betas : List E)
    (base li0 s off oN N : Nat) (expect : E)
    (h : verifyCosetFold coset betas base li0 s off oN N expect = true) :
    cosetBindHolds coset betas base li0 s off oN N expect :=
  verifyCosetFold_implies_bind coset betas base li0 s off oN N expect h

theorem verifyCosetFold_eq
    (coset : List E) (betas : List E)
    (base li0 s off oN N : Nat) (expect : E) :
    verifyCosetFold coset betas base li0 s off oN N expect = true ↔
      CosetFoldBind coset betas base li0 s off oN N expect :=
  verifyCosetFold_iff_cosetEval coset betas base li0 s off oN N expect

theorem cosetBind_iff_fold (coset : List E) (betas : List E)
    (base li0 s off oN N : Nat) (expect : E) :
    cosetBindHolds coset betas base li0 s off oN N expect ↔
      CosetEvalEquals coset betas base li0 s off oN N expect := Iff.rfl

theorem cosetBind_exists
    (coset : List E) (betas : List E)
    (base li0 s off oN N : Nat) (expect : E)
    (h : cosetBindHolds coset betas base li0 s off oN N expect) :
    ∃ got, cosetFold coset betas base li0 s off oN N = some got ∧ eq got expect = true :=
  cosetFold_has_eval coset betas base li0 s off oN N expect h

example : cosetFold [zero] [] 0 0 0 1 1 2 = some zero := by native_decide

/-- Composition semantic equals is CompositionEquals (Semantic), not a free Bool. -/
theorem composition_uses_semantic_equals
    (pack : FriStark.Full.Verify.ComposePack)
    (h : FriStark.AIR.ComposeExt.matchesCompZ pack.cur pack.nxt pack.z pack.wNext pack.lastF
          pack.zhInv pack.Hd pack.pub pack.rc pack.chainMinv pack.alphasT pack.alphasB
          pack.bounds pack.Mext pack.Minv pack.diag pack.Minv0 pack.held pack.expectCompZ = true) :
    FriStark.Soundness.Semantic.CompositionEquals pack.cur pack.nxt pack.z pack.wNext pack.lastF
      pack.zhInv pack.Hd pack.pub pack.rc pack.chainMinv pack.alphasT pack.alphasB pack.bounds
      pack.Mext pack.Minv pack.diag pack.Minv0 pack.held pack.expectCompZ :=
  FriStark.Soundness.Semantic.composeCheck_implies_composition pack h

end FriStark.Soundness.DeepReduction
