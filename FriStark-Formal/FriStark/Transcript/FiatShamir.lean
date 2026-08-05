/-
  Fiat–Shamir matching vendor stark.py FS (SHA-256 sponge).
-/
import FriStark.Hash.Sha256
import FriStark.Field.Goldilocks
import FriStark.Params.V1

namespace FriStark.Transcript.FiatShamir

open FriStark.Hash.Sha256
open FriStark.Field.Goldilocks
open FriStark.Params.V1 (P)

structure State where
  bytes : Bytes
  deriving Repr

def empty : State := ⟨"STARK-v0".toUTF8.toList⟩

def absorb (s : State) (b : Bytes) : State := ⟨FriStark.Hash.Sha256.hash (s.bytes ++ b)⟩

def encU64LE (n : Nat) : Bytes :=
  (List.range 8).map (fun i => UInt8.ofNat ((n >>> (8 * i)) % 256))

def absorbInt (s : State) (v : Nat) : State := absorb s (encU64LE (v % P))

def challenge (s : State) : F × State :=
  let s' := absorb s ("chal".toUTF8.toList)
  let d := s'.bytes
  let n := Id.run do
    let mut n : Nat := 0
    for i in [0:min 8 d.length] do
      n := n + d[i]!.toNat * (256 ^ i)
    pure n
  (n % P, s')

def challengeIdx (s : State) (N : Nat) : Nat × State :=
  let s' := absorb s ("idx".toUTF8.toList)
  let d := s'.bytes
  let n := Id.run do
    let mut n : Nat := 0
    for i in [0:min 8 d.length] do
      n := n + d[i]!.toNat * (256 ^ i)
    pure n
  (if N == 0 then 0 else n % N, s')

/-- grind: int.from_bytes(SHA256(state||nonce)[:8], little) < 2^(64-grind_b) -/
def grindOk (state nonce : Bytes) (grindBits : Nat) : Bool :=
  let d := FriStark.Hash.Sha256.hash (state ++ nonce)
  let n := Id.run do
    let mut n : Nat := 0
    for i in [0:min 8 d.length] do
      n := n + d[i]!.toNat * (256 ^ i)
    pure n
  let bound := 1 <<< (64 - grindBits)
  n < bound

end FriStark.Transcript.FiatShamir
