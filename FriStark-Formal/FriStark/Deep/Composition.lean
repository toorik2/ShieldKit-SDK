/-
  DEEP/composition ops — linear combination over GF(p^2).
-/
import FriStark.Field.Ext

namespace FriStark.Deep.Composition

open FriStark.Field.Ext

def combine (alphas terms : List E) : E := Id.run do
  let mut acc : E := zero
  let n := min alphas.length terms.length
  for i in [0:n] do
    acc := add acc (mul alphas[i]! terms[i]!)
  return acc

end FriStark.Deep.Composition
