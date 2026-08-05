/-
  Poseidon2 permutation over Goldilocks t=12, matching native_poseidon2.py exactly.
-/
import FriStark.Field.Goldilocks
import FriStark.Hash.Poseidon2.Constants
import FriStark.Params.V1

namespace FriStark.Hash.Poseidon2.Perm

open FriStark.Field.Goldilocks
open FriStark.Hash.Poseidon2.Constants
open FriStark.Params.V1 (P)

def sbox (x : F) : F :=
  let x2 := mul x x
  let x4 := mul x2 x2
  let x6 := mul x4 x2
  mul x6 x

def matmulM4 (s : Array F) : Array F := Id.run do
  let mut s := s
  for i in [0:WIDTH:4] do
    let t0 := add s[i]! s[i+1]!
    let t1 := add s[i+2]! s[i+3]!
    let t2 := add (mul 2 s[i+1]!) t1
    let t3 := add (mul 2 s[i+3]!) t0
    let t4 := add (mul 4 t1) t3
    let t5 := add (mul 4 t0) t2
    let t6 := add t3 t5
    let t7 := add t2 t4
    s := s.set! i t6
    s := s.set! (i+1) t5
    s := s.set! (i+2) t7
    s := s.set! (i+3) t4
  return s

def matmulExternal (s : Array F) : Array F := Id.run do
  let mut s := matmulM4 s
  let mut stored : Array F := #[0,0,0,0]
  let t4 := WIDTH / 4
  for l in [0:4] do
    let mut acc := s[l]!
    for j in [1:t4] do
      acc := add acc s[4*j + l]!
    stored := stored.set! l acc
  for i in [0:WIDTH] do
    s := s.set! i (add s[i]! stored[i % 4]!)
  return s

def matmulInternal (s : Array F) : Array F := Id.run do
  let mut total : F := 0
  for i in [0:WIDTH] do
    total := add total s[i]!
  let mut s := s
  for i in [0:WIDTH] do
    s := s.set! i (add (mul s[i]! matDiag12[i]!) total)
  return s

def permutation (stateIn : Array F) : Array F := Id.run do
  assert! stateIn.size == WIDTH
  let mut s := stateIn.map (fun v => v % P)
  s := matmulExternal s
  let rfHalf := ROUNDS_F / 2
  for r in [0:rfHalf] do
    for i in [0:WIDTH] do
      s := s.set! i (sbox (add s[i]! RC[r]![i]!))
    s := matmulExternal s
  let pEnd := rfHalf + ROUNDS_P
  for r in [rfHalf:pEnd] do
    s := s.set! 0 (sbox (add s[0]! RC[r]![0]!))
    s := matmulInternal s
  for r in [pEnd:ROUNDS_F + ROUNDS_P] do
    for i in [0:WIDTH] do
      s := s.set! i (sbox (add s[i]! RC[r]![i]!))
    s := matmulExternal s
  return s

/-- Official KAT: permutation([0..11]). -/
def officialKat : Array F := #[138186169299091649, 2237493815125627916, 7098449130000758157, 16681569560651424230, 2885694034573886267, 1987263728465303211, 4895658260063552408, 16782691522897809445, 6250362358359317026, 8723968546836371205, 17025428646788054631, 7660698892044183277]

#guard (permutation (Array.ofFn (fun i : Fin WIDTH => (i.val : Nat)))) == officialKat

end FriStark.Hash.Poseidon2.Perm
