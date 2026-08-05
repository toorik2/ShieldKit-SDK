import FriStark.Packing.Topology
import FriStark.Binding.Roles

namespace FriStark.Packing.TxModel

open FriStark.Packing.Topology
open FriStark.Binding.Roles

structure InputRole where
  index : Nat
  role : String
  accept : Bool
  deriving Repr

structure TxModel where
  topology : TopologyV1
  inputs : List InputRole
  deriving Repr

def dualVmAgree (libauth leanbch : List Bool) : Bool :=
  libauth.length == leanbch.length &&
  (List.zip libauth leanbch).all (fun p => p.1 == p.2)

end FriStark.Packing.TxModel
