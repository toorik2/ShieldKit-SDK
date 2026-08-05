/-
  Shared verifier types (API freeze).
-/
import FriStark.Field.Ext
import FriStark.Field.Goldilocks
import FriStark.Hash.Sha256

namespace FriStark.Verify.Types

open FriStark.Field.Ext
open FriStark.Field.Goldilocks
open FriStark.Hash.Sha256

inductive VerifyResult where
  | ok
  | err (why : String)
  deriving Repr, DecidableEq

def VerifyResult.isOk : VerifyResult → Bool
  | .ok => true
  | .err _ => false

/-- Atomic checks re-executed by Lean on exported proof material. No pre-labeled bool theater. -/
inductive AtomicCheck where
  | merkleOpen (root leaf : Bytes) (index : Nat) (path : List (Bytes × Nat))
  | merkleOpenDigest (root leafDigest : Bytes) (path : List (Bytes × Nat))
  | friFold (v0 v1 beta folded : E) (xpos : Nat)
  | fieldEq (a b : F)
  | extEq (a b : E)
  /-- Recompute grind: SHA256(state||nonce)[:8] LE < 2^(64-grindBits). -/
  | grindCheck (state nonce : Bytes) (grindBits : Nat)
  /-- Query index list must match. -/
  | natListEq (a b : List Nat)
  /-- fri_roots length must equal expected count from domain walk. -/
  | natEq (a b : Nat)
  /-- Final layer root bind: recomputed root equals fri_roots[-1]. -/
  | bytesEq (a b : Bytes)
  deriving Repr

structure ProofBundle where
  checks : List AtomicCheck
  accept : Bool
  label : String
  eligibility : String
  blowup : Nat
  queries : Nat
  grindBits : Nat
  fold : Nat
  deriving Repr

end FriStark.Verify.Types
