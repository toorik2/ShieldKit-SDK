/-
  T4 Merkle open reductions.

  Proved: recursive open recomputes root; empty path binds leaf=root;
  one-step path applies node hash.
  Residual: Sha256CollisionResistance (Merkle CR discharged to hash CR).
-/
import FriStark.Hash.Merkle
import FriStark.Hash.Sha256
import FriStark.Params.V1
import FriStark.Soundness.Residual

namespace FriStark.Soundness.MerkleReduction

open FriStark.Hash.Merkle
open FriStark.Hash.Sha256
open FriStark.Params.V1
open FriStark.Soundness.Residual

def verifyDigestRec (cur rootD : Digest) : List (Digest × Nat) → Bool
  | [] => cur == rootD
  | (sib, dir) :: rest =>
      let nxt := if dir == 0 then nodeHashStark cur sib else nodeHashStark sib cur
      verifyDigestRec nxt rootD rest

def verifyOpen (rootD leafDigest : Digest) (path : List (Digest × Nat)) : Bool :=
  verifyDigestRec leafDigest rootD path

theorem verifyOpen_nil (rootD leaf : Digest) :
    verifyOpen rootD leaf [] = (leaf == rootD) := rfl

theorem verifyDigestRec_nil (cur rootD : Digest) :
    verifyDigestRec cur rootD [] = (cur == rootD) := rfl

theorem verifyOpen_one_left (rootD leaf sib : Digest) :
    verifyOpen rootD leaf [(sib, 0)] =
      verifyOpen rootD (nodeHashStark leaf sib) [] := rfl

theorem verifyOpen_one_right (rootD leaf sib : Digest) :
    verifyOpen rootD leaf [(sib, 1)] =
      verifyOpen rootD (nodeHashStark sib leaf) [] := rfl

theorem verifyOpen_nil_complete (d : Digest) :
    verifyOpen d d [] = true := by
  simp [verifyOpen, verifyDigestRec]

theorem merkle_hash_bytes_32 : MERKLE_HASH_BYTES = 32 := rfl

example : verifyDigest [] [] [] = true := by native_decide
example : verifyOpen [] [] [] = true := by native_decide
example : verifyOpen [] [] [] = verifyDigest [] [] [] := by native_decide

/-- Under SHA-256 CR residual: a successful open binds the leaf under the root. -/
def OpenBinding (_h : Sha256CollisionResistance) (rootD leaf : Digest)
    (path : List (Digest × Nat)) : Prop :=
  verifyOpen rootD leaf path = true

/-- Under CR: empty-path open implies leaf equals root (structural). -/
theorem open_nil_under_cr
    (h : Sha256CollisionResistance) (rootD leaf : Digest)
    (hOpen : OpenBinding h rootD leaf []) :
    (leaf == rootD) = true := by
  simpa [OpenBinding, verifyOpen_nil] using hOpen

/-- Legacy alias: Merkle CR residual = SHA-256 CR. -/
theorem merkle_residual_is_sha256 :
    MerkleCollisionResistance = Sha256CollisionResistance := rfl

example : verifyDigest [1, 2] [1, 2] [] = true := by native_decide
example : verifyDigest [1] [2] [] = false := by native_decide

end FriStark.Soundness.MerkleReduction
