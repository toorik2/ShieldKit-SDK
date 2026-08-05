/-
  Poseidon2 sponge (rate=8, capacity=4) matching native_poseidon2.hash_to_1 / merkle_compress.
-/
import FriStark.Hash.Poseidon2.Perm
import FriStark.Field.Goldilocks
import FriStark.Hash.Poseidon2.Constants
import FriStark.Params.V1

namespace FriStark.Hash.Poseidon2.Sponge

open FriStark.Field.Goldilocks
open FriStark.Hash.Poseidon2.Constants
open FriStark.Hash.Poseidon2.Perm
open FriStark.Params.V1 (P)

def hashTo1 (inputs : List F) : F := Id.run do
  let mut state : Array F := Array.replicate WIDTH 0
  let mut items := inputs.map (fun v => v % P)
  if items.isEmpty then items := [0]
  let pad := (RATE - items.length % RATE) % RATE
  items := items ++ List.replicate pad 0
  let mut off := 0
  while off < items.length do
    for i in [0:RATE] do
      state := state.set! i (add state[i]! items[off + i]!)
    state := permutation state
    off := off + RATE
  return state[0]!

def merkleCompress (a b : F) : F :=
  hashTo1 [a, b]

/-- Squeeze 4 field elements (GDig32 payload). Matches product `hashTo4`. -/
def hashTo4 (inputs : List F) : List F := Id.run do
  let mut state : Array F := Array.replicate WIDTH 0
  let mut items := inputs.map (fun v => v % P)
  if items.isEmpty then items := [0]
  let pad := (RATE - items.length % RATE) % RATE
  items := items ++ List.replicate pad 0
  let mut off := 0
  while off < items.length do
    for i in [0:RATE] do
      state := state.set! i (add state[i]! items[off + i]!)
    state := permutation state
    off := off + RATE
  let mut out : List F := []
  while out.length < 4 do
    let mut i := 0
    while i < RATE && out.length < 4 do
      out := out ++ [state[i]!]
      i := i + 1
    if out.length < 4 then
      state := permutation state
  return out

#guard hashTo1 [0, 1, 2, 3] == 6276405055127055335
#guard (hashTo4 [1, 2, 3, 4]).length == 4
#guard (hashTo4 [1, 2, 3, 4]).head! == hashTo1 [1, 2, 3, 4]

end FriStark.Hash.Poseidon2.Sponge
