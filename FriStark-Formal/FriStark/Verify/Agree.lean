import FriStark.Verify.Abstract
import FriStark.Verify.Executable
import FriStark.Verify.Types

namespace FriStark.Verify.Agree

open FriStark.Verify.Types
open FriStark.Verify.Executable
open FriStark.Verify.Abstract

theorem exec_iff_abstract (b : ProofBundle) :
    Accept b ↔ verify b = .ok := Iff.rfl

end FriStark.Verify.Agree
