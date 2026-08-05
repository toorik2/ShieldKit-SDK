/-
  Dual-VM accept parity model (libauth × LeanBCH xcheck).
-/
import FriStark.Packing.TxModel

namespace FriStark.Host.DualVm

open FriStark.Packing.TxModel

structure DualVmReport where
  libauthAccept : List Bool
  leanbchAccept : List Bool
  deriving Repr

def dualVmAcceptGreen (r : DualVmReport) : Bool :=
  dualVmAgree r.libauthAccept r.leanbchAccept &&
  r.libauthAccept.all id

def dualVmForgeRejectGreen (r : DualVmReport) : Bool :=
  dualVmAgree r.libauthAccept r.leanbchAccept &&
  r.libauthAccept.all (fun a => !a)

end FriStark.Host.DualVm
