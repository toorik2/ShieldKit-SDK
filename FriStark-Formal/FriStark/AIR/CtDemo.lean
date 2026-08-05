/-
  CT-AIR public statement shape (upstream demo): root, nf, cm_out, depth.
-/
import FriStark.Field.Goldilocks

namespace FriStark.AIR.CtDemo

open FriStark.Field.Goldilocks

structure CtStmt where
  root : F
  nf : F
  cmOut : List F
  depth : Nat
  deriving Repr

def publicInputs (s : CtStmt) : List F :=
  [s.root, s.nf] ++ s.cmOut ++ [s.depth]

end FriStark.AIR.CtDemo
