/-
  SHA-256 binary Merkle matching both:
  - structures_merkle.py (hash leaf bytes, then nodes)
  - stark.py m_verify (leaf is already a digest; path bit 1 => sib||cur)
-/
import FriStark.Hash.Sha256
import FriStark.Params.V1

namespace FriStark.Hash.Merkle

open FriStark.Hash.Sha256
open FriStark.Params.V1 (MERKLE_HASH_BYTES)

abbrev Digest := Bytes

def leafHash (v : Bytes) : Digest := truncate MERKLE_HASH_BYTES (hash v)
def nodeHash (l r : Digest) : Digest := truncate MERKLE_HASH_BYTES (hash (l ++ r))

/-- STARK kernel node: full SHA-256 of concatenation (no extra truncate if width=32). -/
def nodeHashStark (l r : Digest) : Digest := hash (l ++ r)

def buildTree (leaves : List Bytes) : List (List Digest) := Id.run do
  let mut level := leaves.map leafHash
  let mut layers : List (List Digest) := [level]
  while level.length > 1 do
    let mut nxt : List Digest := []
    let mut i := 0
    while i < level.length do
      let l := level[i]!
      let r := if i + 1 < level.length then level[i+1]! else level[i]!
      nxt := nxt ++ [nodeHash l r]
      i := i + 2
    level := nxt
    layers := layers ++ [level]
  return layers

def root (layers : List (List Digest)) : Digest :=
  match layers.getLast? with
  | some (r :: _) => r
  | _ => []

def proof (layers : List (List Digest)) (index : Nat) : List (Digest × Nat) := Id.run do
  let mut path : List (Digest × Nat) := []
  let mut idx := index
  for d in [0:layers.length - 1] do
    let level := layers[d]!
    if idx % 2 == 0 then
      let sib := if idx + 1 < level.length then level[idx+1]! else level[idx]!
      path := path ++ [(sib, 0)]
    else
      path := path ++ [(level[idx-1]!, 1)]
    idx := idx / 2
  return path

/-- structures_merkle style: hash raw leaf first. -/
def verify (rootD : Digest) (leaf : Bytes) (_index : Nat) (path : List (Digest × Nat)) : Bool := Id.run do
  let mut cur := leafHash leaf
  for (sib, dir) in path do
    if dir == 0 then cur := nodeHash cur sib
    else cur := nodeHash sib cur
  return cur == rootD

/-- stark.py m_verify: leaf is already commitment digest; bit 1 => H(sib||cur). -/
def verifyDigest (rootD : Digest) (leafDigest : Bytes) (path : List (Digest × Nat)) : Bool := Id.run do
  let mut cur := leafDigest
  for (sib, dir) in path do
    if dir == 0 then cur := nodeHashStark cur sib
    else cur := nodeHashStark sib cur
  return cur == rootD

end FriStark.Hash.Merkle
