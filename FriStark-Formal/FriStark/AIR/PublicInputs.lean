/-
  Product statement FE encoding per PUBLIC_STATEMENT.md / shieldkit-v2-stark-statement-v1.
-/
import FriStark.Field.Goldilocks
import FriStark.Params.V1

namespace FriStark.AIR.PublicInputs

open FriStark.Field.Goldilocks
open FriStark.Params.V1 (P)

/-- GDig32 = 4× Goldilocks FE from 32 bytes (8-byte LE limbs). -/
def gdig32FromBytes (bs : List UInt8) : List F := Id.run do
  let mut out : List F := []
  for i in [0:4] do
    let mut n : Nat := 0
    for j in [0:8] do
      let b := bs.getD (i*8 + j) 0
      n := n + b.toNat * (256 ^ j)
    out := out ++ [n % P]
  return out

/-- 32-byte hash → 5 FE via 56-bit limbs (PUBLIC_STATEMENT.md). -/
def hashBytesToFE (H : List UInt8) : List F := Id.run do
  let mut limbs : List F := []
  for i in [0:4] do
    -- BE_u64(0x00 || H[7*i : 7*i+7])
    let mut n : Nat := 0
    for j in [0:7] do
      let b := H.getD (7*i + j) 0
      n := n * 256 + b.toNat
    limbs := limbs ++ [n % P]
  -- limb_4 = BE_u64(0x00000000 || H[28:32])
  let mut n4 : Nat := 0
  for j in [28:32] do
    n4 := n4 * 256 + (H.getD j 0).toNat
  limbs := limbs ++ [n4 % P]
  return limbs

/-- Full public input list for product statement (field count check). -/
structure StatementFE where
  packetCommit : List F  -- 4
  preState : List F      -- 16
  postState : List F     -- 16
  publicNullifier : List F -- 4
  outputNoteLeaf : List F  -- 4
  withdrawalHash : List F  -- 5
  deriving Repr

def StatementFE.flatten (s : StatementFE) : List F :=
  s.packetCommit ++ s.preState ++ s.postState ++ s.publicNullifier ++
  s.outputNoteLeaf ++ s.withdrawalHash

def encodeDemo : StatementFE where
  packetCommit := gdig32FromBytes (List.replicate 32 1)
  preState := List.replicate 16 0
  postState := List.replicate 16 0
  publicNullifier := gdig32FromBytes (List.replicate 32 0)
  outputNoteLeaf := gdig32FromBytes (List.replicate 32 2)
  withdrawalHash := hashBytesToFE (List.replicate 32 3)

#guard encodeDemo.packetCommit.length == 4
#guard encodeDemo.withdrawalHash.length == 5
#guard encodeDemo.flatten.length == 4+16+16+4+4+5

end FriStark.AIR.PublicInputs
