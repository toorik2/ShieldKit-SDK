/-
  Binding propositions and executable presence model.
-/
import FriStark.Binding.Roles

namespace FriStark.Binding.Presence

open FriStark.Binding.Roles

structure RoleSlot where
  name : RoleName
  lockingHash : String   -- hex of P2SH32 locking
  present : Bool
  isFiller : Bool
  deriving Repr

structure BindingModel where
  blobIndex : Nat := 0
  roles : List RoleSlot
  -- values that must be single-sourced from blob or recomputed
  freeWitnesses : List String
  sourcedFromBlob : List String
  bindMode : String  -- "locking" | "unlocking" (must be locking)
  deriving Repr

def blob_is_single_source (m : BindingModel) : Bool :=
  m.freeWitnesses.all (fun w => m.sourcedFromBlob.contains w)

def locking_not_unlocking_bind (m : BindingModel) : Bool :=
  m.bindMode == "locking"

def all_roles_presence_bound (m : BindingModel) : Bool :=
  m.roles.all (·.present) && m.roles.all (fun r => r.lockingHash.length == 64)

def no_filler_true (m : BindingModel) : Bool :=
  !(m.roles.any (fun r => r.isFiller && r.present))

def product_roles_present (m : BindingModel) : Bool :=
  let names := m.roles.map (·.name)
  names.contains .binding && names.contains .state && names.contains .funding

def wellFormed (m : BindingModel) : Bool :=
  blob_is_single_source m &&
  locking_not_unlocking_bind m &&
  all_roles_presence_bound m &&
  no_filler_true m

/-- Apply a named forge class to the model. -/
def applyForge (m : BindingModel) (forge : String) : BindingModel :=
  match forge with
  | "drop_terminal" =>
      { m with roles := m.roles.dropLast }
  | "swap_filler" =>
      match m.roles with
      | [] => m
      | r :: rs => { m with roles := { r with isFiller := true, lockingHash := String.ofList (List.replicate 64 '0') } :: rs }
  | "unlocking_bind" =>
      { m with bindMode := "unlocking" }
  | "free_witness" =>
      { m with freeWitnesses := m.freeWitnesses ++ ["alpha_free"], sourcedFromBlob := m.sourcedFromBlob }
  | "drop_blob" =>
      { m with roles := m.roles.filter (fun r => r.name != .blob) }
  | "omit_binding" =>
      { m with roles := m.roles.filter (fun r => r.name != .binding) }
  | "omit_state" =>
      { m with roles := m.roles.filter (fun r => r.name != .state) }
  | "omit_funding" =>
      { m with roles := m.roles.filter (fun r => r.name != .funding) }
  | "swap_wrong_covenant" =>
      match m.roles.reverse with
      | [] => m
      | r :: rs =>
        let r' := { r with lockingHash := String.ofList (List.replicate 64 'f') }
        { m with roles := (r' :: rs).reverse }
  | "bare_filler_producer" =>
      { m with roles := m.roles ++ [{ name := .other "filler", lockingHash := String.ofList (List.replicate 64 '1'), present := true, isFiller := true }] }
  | "drop_deepquery" =>
      { m with roles := m.roles.filter (fun r => r.name != .deepQuery) }
  | "drop_aggFRI" =>
      { m with roles := m.roles.filter (fun r => r.name != .aggFRI) }
  | _ => m

/-- Product settle requires product roles; FRI-only packing uses friOnlyWellFormed. -/
def friOnlyWellFormed (m : BindingModel) : Bool :=
  blob_is_single_source m &&
  locking_not_unlocking_bind m &&
  all_roles_presence_bound m &&
  no_filler_true m

/-- Forge is rejected when the named attack breaks a required binding invariant. -/
def forgeRejected (honest : BindingModel) (forge : String) : Bool :=
  let a := applyForge honest forge
  match forge with
  | "drop_terminal" => a.roles.length < honest.roles.length
  | "swap_filler" => a.roles.any (·.isFiller)
  | "unlocking_bind" => !locking_not_unlocking_bind a
  | "free_witness" => !blob_is_single_source a
  | "drop_blob" => !(a.roles.any (fun r => r.name == RoleName.blob))
  | "omit_binding" => !product_roles_present a
  | "omit_state" => !product_roles_present a
  | "omit_funding" => !product_roles_present a
  | "swap_wrong_covenant" =>
      (a.roles.map (·.lockingHash)) != (honest.roles.map (·.lockingHash))
  | "bare_filler_producer" => a.roles.any (·.isFiller)
  | "drop_deepquery" => !(a.roles.any (fun r => r.name == RoleName.deepQuery))
  | "drop_aggFRI" => !(a.roles.any (fun r => r.name == RoleName.aggFRI))
  | _ => false

end FriStark.Binding.Presence
