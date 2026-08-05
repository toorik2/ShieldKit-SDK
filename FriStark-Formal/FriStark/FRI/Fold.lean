/-
  FRI fold over GF(p^2) matching native_ct_air_stark fold form.
-/
import FriStark.Field.Ext
import FriStark.Field.Goldilocks

namespace FriStark.FRI.Fold

open FriStark.Field.Ext
open FriStark.Field.Goldilocks

/-- Single fold-2 step. -/
def foldOnce (v w : E) (beta : E) (xpos : F) : Option E :=
  friFold v w beta xpos

/-- Coset multi-fold: successive fold-2 over a power-of-two coset (simplified sequential). -/
def foldChain (vals : List E) (betas : List E) (x0 : F) (omega : F) : Option E := Id.run do
  if vals.isEmpty then return none
  let mut layer := vals
  let mut xpos := x0
  let mut bi := 0
  while layer.length > 1 do
    if bi >= betas.length then return none
    let beta := betas[bi]!
    let mut nxt : List E := []
    let mut i := 0
    let mut x := xpos
    while i + 1 < layer.length do
      match foldOnce layer[i]! layer[i+1]! beta x with
      | none => return none
      | some f => nxt := nxt ++ [f]
      x := mul x omega  -- advance; production uses domain-specific xpos
      i := i + 2
    layer := nxt
    bi := bi + 1
    xpos := mul xpos xpos  -- square domain map under fold
  return layer[0]?

end FriStark.FRI.Fold
