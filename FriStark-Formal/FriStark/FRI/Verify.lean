/-
  FRI query verification: merkle open of ext leaf + fold consistency.
-/
import FriStark.FRI.Fold
import FriStark.Hash.Merkle
import FriStark.Field.Ext
import FriStark.Hash.Sha256

namespace FriStark.FRI.Verify

open FriStark.FRI.Fold
open FriStark.Hash.Merkle
open FriStark.Field.Ext
open FriStark.Hash.Sha256

/-- Encode extension element as 16-byte little-endian pair for leaf materialization
    (matches common salt-free packing used in tests; production uses salted leaves). -/
def encodeExt (e : E) : Bytes :=
  let pack (n : Nat) : Bytes :=
    (List.range 8).map (fun i => UInt8.ofNat ((n >>> (8 * i)) % 256))
  pack e.a0 ++ pack e.a1

/-- Single fold binds `folded` — `Option.any` form for ∃-eval semantic theorems. -/
def verifyFoldStep (v w folded : E) (beta : E) (xpos : Nat) : Bool :=
  (foldOnce v w beta xpos).any (fun f => eq f folded)

def FriFoldEvalEquals (v w beta : E) (xpos : Nat) (folded : E) : Prop :=
  ∃ f, foldOnce v w beta xpos = some f ∧ eq f folded = true

theorem verifyFoldStep_iff_friFoldEval
    (v w folded beta : E) (xpos : Nat) :
    verifyFoldStep v w folded beta xpos = true ↔
      FriFoldEvalEquals v w beta xpos folded := by
  simp only [verifyFoldStep, FriFoldEvalEquals, Option.any_eq_true]

theorem verifyFoldStep_implies_friFoldEval
    (v w folded beta : E) (xpos : Nat)
    (h : verifyFoldStep v w folded beta xpos = true) :
    FriFoldEvalEquals v w beta xpos folded :=
  (verifyFoldStep_iff_friFoldEval v w folded beta xpos).mp h

end FriStark.FRI.Verify
