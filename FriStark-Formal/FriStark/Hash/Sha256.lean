/-
  SHA-256 (FIPS 180-4) — ported for FriStark sandbox (Merkle leaves/nodes).
  Matches Python hashlib.sha256 and LeanBCH.Crypto.Sha256 digests.
-/
namespace FriStark.Hash.Sha256

abbrev Bytes := List UInt8

@[inline] def beWord (a b c d : UInt8) : UInt32 :=
  (a.toUInt32 <<< 24) ||| (b.toUInt32 <<< 16) ||| (c.toUInt32 <<< 8) ||| d.toUInt32

@[inline] def word4BE (x : UInt32) : List UInt8 :=
  [(x >>> 24).toUInt8, (x >>> 16).toUInt8, (x >>> 8).toUInt8, x.toUInt8]

def nat64BE (n : Nat) : List UInt8 :=
  (List.range 8).map (fun i => UInt8.ofNat (n >>> (8 * (7 - i))))

def padBE (msg : List UInt8) : List UInt8 :=
  let withOne := msg ++ [(0x80 : UInt8)]
  let k := (56 + 64 - withOne.length % 64) % 64
  withOne ++ List.replicate k (0 : UInt8) ++ nat64BE (8 * msg.length)

def toHex (bs : List UInt8) : String :=
  let digits := "0123456789abcdef".toList
  String.ofList (bs.flatMap (fun b =>
    [digits.getD (b.toNat / 16) '?', digits.getD (b.toNat % 16) '?']))

@[inline] def rotr (x : UInt32) (n : UInt32) : UInt32 := (x >>> n) ||| (x <<< (32 - n))

def K : Array UInt32 := #[
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

def H0 : Array UInt32 := #[
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

def hashPadded (padded : Array UInt8) : Array UInt32 := Id.run do
  let mut H := H0
  let numBlocks := padded.size / 64
  for blk in [0:numBlocks] do
    let base := blk * 64
    let mut w : Array UInt32 := Array.mkEmpty 64
    for i in [0:16] do
      let j := base + 4 * i
      w := w.push (beWord padded[j]! padded[j+1]! padded[j+2]! padded[j+3]!)
    for t in [16:64] do
      let s0 := rotr w[t-15]! 7  ^^^ rotr w[t-15]! 18 ^^^ (w[t-15]! >>> 3)
      let s1 := rotr w[t-2]!  17 ^^^ rotr w[t-2]!  19 ^^^ (w[t-2]!  >>> 10)
      w := w.push (s1 + w[t-7]! + s0 + w[t-16]!)
    let mut a := H[0]!
    let mut b := H[1]!
    let mut c := H[2]!
    let mut d := H[3]!
    let mut e := H[4]!
    let mut f := H[5]!
    let mut g := H[6]!
    let mut h := H[7]!
    for t in [0:64] do
      let bigS1 := rotr e 6 ^^^ rotr e 11 ^^^ rotr e 25
      let ch := (e &&& f) ^^^ ((~~~e) &&& g)
      let t1 := h + bigS1 + ch + K[t]! + w[t]!
      let bigS0 := rotr a 2 ^^^ rotr a 13 ^^^ rotr a 22
      let maj := (a &&& b) ^^^ (a &&& c) ^^^ (b &&& c)
      let t2 := bigS0 + maj
      h := g; g := f; f := e; e := d + t1
      d := c; c := b; b := a; a := t1 + t2
    H := #[H[0]! + a, H[1]! + b, H[2]! + c, H[3]! + d,
           H[4]! + e, H[5]! + f, H[6]! + g, H[7]! + h]
  return H

def hash (msg : Bytes) : Bytes :=
  ((hashPadded (padBE msg).toArray).toList.map word4BE).flatten

/-- Truncate digest to n bytes (Merkle node width lever). -/
def truncate (n : Nat) (d : Bytes) : Bytes := d.take n

-- KATs (FIPS)
#guard toHex (hash []) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#guard toHex (hash ("abc".toUTF8.toList)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

end FriStark.Hash.Sha256
