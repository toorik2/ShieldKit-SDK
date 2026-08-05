/-
  Verifier role names for multi-input packing (topology freeze).
-/
namespace FriStark.Binding.Roles

inductive RoleName where
  | blob
  | deepQuery
  | aggFRI
  | compTrans
  | compFinal
  | binding
  | state
  | funding
  | other (name : String)
  deriving DecidableEq, Repr, Inhabited

def RoleName.toString : RoleName → String
  | .blob => "blob"
  | .deepQuery => "deepquery"
  | .aggFRI => "aggFRI"
  | .compTrans => "comp_trans"
  | .compFinal => "comp_final"
  | .binding => "binding"
  | .state => "state"
  | .funding => "funding"
  | .other n => n

end FriStark.Binding.Roles
