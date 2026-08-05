/-
  TopologyV1 — ordered verifier roles + product roles.
-/
import FriStark.Binding.Roles
import FriStark.Params.V1

namespace FriStark.Packing.Topology

open FriStark.Binding.Roles
open FriStark.Params.V1

structure TopologyV1 where
  friParamId : String
  scheme : String := "deep-ali-fri-stark"
  verifierRoles : List String
  binding : String := "v2-stark-binding-v1"
  state : String := "v2-stark-state-v1"
  funding : String := "p2pkh-single-v1"
  blobIndex : Nat := 0
  deriving Repr

def wellFormedTopology (t : TopologyV1) : Bool :=
  t.blobIndex == 0 &&
  t.verifierRoles.length ≥ 1 &&
  t.scheme == "deep-ali-fri-stark" &&
  t.binding.length > 0 &&
  t.state.length > 0

/-- Default sound packing roles from upstream CT shard layout (names). -/
def defaultSoundRoles : List String :=
  ["blob", "deepquery", "aggFRI", "comp_trans", "comp_final"]

def defaultTopology : TopologyV1 where
  friParamId := "SKFRI1-prod-2048-8-24-8"
  verifierRoles := defaultSoundRoles

#guard wellFormedTopology defaultTopology

end FriStark.Packing.Topology
