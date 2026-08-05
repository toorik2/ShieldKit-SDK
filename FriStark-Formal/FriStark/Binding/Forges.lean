/-
  ≥10 named forge classes — all must be rejected by the binding model.
-/
import FriStark.Binding.Presence
import FriStark.Binding.Roles

namespace FriStark.Binding.Forges

open FriStark.Binding.Presence
open FriStark.Binding.Roles

def honestModel : BindingModel where
  blobIndex := 0
  roles := [
    { name := .blob, lockingHash := String.ofList (List.replicate 64 'a'), present := true, isFiller := false },
    { name := .deepQuery, lockingHash := String.ofList (List.replicate 64 'b'), present := true, isFiller := false },
    { name := .aggFRI, lockingHash := String.ofList (List.replicate 64 'c'), present := true, isFiller := false },
    { name := .compTrans, lockingHash := String.ofList (List.replicate 64 'd'), present := true, isFiller := false },
    { name := .compFinal, lockingHash := String.ofList (List.replicate 64 'e'), present := true, isFiller := false },
    { name := .binding, lockingHash := String.ofList (List.replicate 64 'f'), present := true, isFiller := false },
    { name := .state, lockingHash := String.ofList (List.replicate 64 '1'), present := true, isFiller := false },
    { name := .funding, lockingHash := String.ofList (List.replicate 64 '2'), present := true, isFiller := false }
  ]
  freeWitnesses := ["alpha", "beta", "z", "query_pos"]
  sourcedFromBlob := ["alpha", "beta", "z", "query_pos"]
  bindMode := "locking"

def forgeClasses : List String := [
  "drop_terminal",
  "swap_filler",
  "unlocking_bind",
  "free_witness",
  "drop_blob",
  "omit_binding",
  "omit_state",
  "omit_funding",
  "swap_wrong_covenant",
  "bare_filler_producer",
  "drop_deepquery",
  "drop_aggFRI"
]

def allForgesRejected : Bool :=
  forgeClasses.all (fun f => forgeRejected honestModel f)

#guard wellFormed honestModel == true
#guard product_roles_present honestModel == true
#guard allForgesRejected == true
#guard forgeClasses.length >= 10

end FriStark.Binding.Forges
