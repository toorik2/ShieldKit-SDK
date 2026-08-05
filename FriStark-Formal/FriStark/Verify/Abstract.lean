/-
  Abstract accept predicate: all atomic checks hold.
-/
import FriStark.Verify.Types
import FriStark.Verify.Executable

namespace FriStark.Verify.Abstract

open FriStark.Verify.Types
open FriStark.Verify.Executable

def Accept (bundle : ProofBundle) : Prop :=
  verify bundle = .ok

end FriStark.Verify.Abstract
