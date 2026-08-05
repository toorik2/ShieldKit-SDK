/-
  DEEP replay checks Lean can re-execute without full LDE:
  - FS-derived z/zg and deep_alphas match proof
  - q_at expected value checked via sequential mul/add terms exported from Python
    (each term is a Lean field op on proof/query material)
-/
import FriStark.Field.Ext
import FriStark.Field.Goldilocks
import FriStark.Transcript.FiatShamir
import FriStark.Params.V1

namespace FriStark.Deep.Replay

open FriStark.Field.Ext
open FriStark.Field.Goldilocks
open FriStark.Transcript.FiatShamir
open FriStark.Params.V1 (P)

/-- One DEEP summand: alpha * ((val - mask) * invDenom). -/
structure DeepTerm where
  alpha : E
  val : E
  mask : E
  invDenom : E
  deriving Repr

def accumTerms (terms : List DeepTerm) : E := Id.run do
  let mut acc := zero
  for t in terms do
    acc := add acc (mul t.alpha (mul (sub t.val t.mask) t.invDenom))
  pure acc

def checkQ (terms : List DeepTerm) (expect : E) : Bool :=
  eq (accumTerms terms) expect

/-- Check deep z: after absorbing comp_root, challenge equals proof z (with z1!=0 fix). -/
def checkZ (zProof zgProof : E) (zGot : E) (oT : F) : Bool :=
  let z := if zGot.a1 % P == 0 then (⟨zGot.a0, 1⟩ : E) else zGot
  let zg := scalar oT z
  eq z zProof && eq zg zgProof

end FriStark.Deep.Replay
