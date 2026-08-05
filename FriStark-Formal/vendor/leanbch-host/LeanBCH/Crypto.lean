/-
  LeanBCH.Crypto — native SHA-256 / RIPEMD-160 hashes + the secp256k1 oracle.

  TRUST STORY (three tiers, honest):
   • SHA-256 and RIPEMD-160 are MODELLED, not axiomatized: full FIPS 180-4 / RIPEMD
     implementations over `Bytes := List UInt8`, `#eval`-executable. This is the only way to
     reproduce the in-scope consensus cost metric `hashDigestIterations` and to compute the
     sighash digest byte-exactly. Correctness is pinned by KNOWN-ANSWER TESTS enforced at
     build time via `#eval` guards (see bottom of file) — a wrong digest fails `lake build`.
     NB: `#eval` is the endorsed acceptance seam here; there is NO `native_decide` proof term
     and NO axiom in this file.
   • `hash256` / `hash160` are the OP_HASH256 / OP_HASH160 double rounds.
   • `Secp256k1` is the EXPLICIT, opaque ORACLE — a *parameter structure*, not an axiom and
     not `native_decide`. It is the validated-not-proven boundary. By design it feeds
     accept/reject ONLY and NEVER any cost metric. The VM's checksig arm receives a
     `Secp256k1` value and calls it; no implementation is (or should be) provided here.

  Faithfulness: byte formats follow FIPS 180-4 (SHA-256), the RIPEMD-160 reference
  (Dobbertin/Bosselaers/Preneel), and match `@bitauth/libauth` 3.1.0-next.8
  (`node_modules/@bitauth/libauth/src/lib/crypto/sha256.ts`, `ripemd160.ts`) byte-for-byte.
-/
import LeanBCH.Core
import LeanBCH.Oracle  -- re-exports `Secp256k1` (the assumed-trust oracle, now isolated to one file)

namespace LeanBCH.Crypto

/-! ## Shared little helpers (word packing, hex, padding) -/

/-- Big-endian 4-byte → 32-bit word (SHA-256 reads message words big-endian). -/
@[inline] def beWord (a b c d : UInt8) : UInt32 :=
  (a.toUInt32 <<< 24) ||| (b.toUInt32 <<< 16) ||| (c.toUInt32 <<< 8) ||| d.toUInt32

/-- Little-endian 4-byte → 32-bit word (RIPEMD-160 reads message words little-endian). -/
@[inline] def leWord (a b c d : UInt8) : UInt32 :=
  a.toUInt32 ||| (b.toUInt32 <<< 8) ||| (c.toUInt32 <<< 16) ||| (d.toUInt32 <<< 24)

/-- 32-bit word → 4 big-endian bytes. -/
@[inline] def word4BE (x : UInt32) : List UInt8 :=
  [(x >>> 24).toUInt8, (x >>> 16).toUInt8, (x >>> 8).toUInt8, x.toUInt8]

/-- 32-bit word → 4 little-endian bytes. -/
@[inline] def word4LE (x : UInt32) : List UInt8 :=
  [x.toUInt8, (x >>> 8).toUInt8, (x >>> 16).toUInt8, (x >>> 24).toUInt8]

/-- 64-bit big-endian encoding of a `Nat` (bit length field). -/
def nat64BE (n : Nat) : List UInt8 :=
  (List.range 8).map (fun i => UInt8.ofNat (n >>> (8 * (7 - i))))

/-- 64-bit little-endian encoding of a `Nat` (bit length field). -/
def nat64LE (n : Nat) : List UInt8 :=
  (List.range 8).map (fun i => UInt8.ofNat (n >>> (8 * i)))

/-- Merkle–Damgård padding with a BIG-endian length trailer (SHA-256). -/
def padBE (msg : List UInt8) : List UInt8 :=
  let withOne := msg ++ [(0x80 : UInt8)]
  let k := (56 + 64 - withOne.length % 64) % 64
  withOne ++ List.replicate k (0 : UInt8) ++ nat64BE (8 * msg.length)

/-- Merkle–Damgård padding with a LITTLE-endian length trailer (RIPEMD-160). -/
def padLE (msg : List UInt8) : List UInt8 :=
  let withOne := msg ++ [(0x80 : UInt8)]
  let k := (56 + 64 - withOne.length % 64) % 64
  withOne ++ List.replicate k (0 : UInt8) ++ nat64LE (8 * msg.length)

/-- Lowercase hex rendering (for KAT reporting / build-time guards). -/
def toHex (bs : List UInt8) : String :=
  let digits := "0123456789abcdef".toList
  String.ofList (bs.flatMap (fun b =>
    [digits.getD (b.toNat / 16) '?', digits.getD (b.toNat % 16) '?']))

/-! ## SHA-256 (FIPS 180-4) -/

namespace Sha256

/-- Right rotation on 32-bit words (n ∈ 1..31 for all SHA-256 uses). -/
@[inline] def rotr (x : UInt32) (n : UInt32) : UInt32 := (x >>> n) ||| (x <<< (32 - n))

/-- The 64 round constants K (first 32 bits of the fractional parts of the cube roots
    of the first 64 primes). -/
def K : Array UInt32 := #[
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

/-- Initial hash values H (first 32 bits of the fractional parts of the square roots
    of the first 8 primes). -/
def H0 : Array UInt32 := #[
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

/-- Compress all 64-byte blocks of the padded message into the 8-word state. -/
def hashPadded (padded : Array UInt8) : Array UInt32 := Id.run do
  let mut H := H0
  let numBlocks := padded.size / 64
  for blk in [0:numBlocks] do
    let base := blk * 64
    -- message schedule W[0..63]
    let mut w : Array UInt32 := Array.mkEmpty 64
    for i in [0:16] do
      let j := base + 4 * i
      w := w.push (beWord padded[j]! padded[j+1]! padded[j+2]! padded[j+3]!)
    for t in [16:64] do
      let s0 := rotr w[t-15]! 7  ^^^ rotr w[t-15]! 18 ^^^ (w[t-15]! >>> 3)
      let s1 := rotr w[t-2]!  17 ^^^ rotr w[t-2]!  19 ^^^ (w[t-2]!  >>> 10)
      w := w.push (s1 + w[t-7]! + s0 + w[t-16]!)
    -- compression
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

/-- FIPS 180-4 SHA-256 over a byte string, producing a 32-byte digest. -/
def hash (msg : Bytes) : Bytes :=
  ((hashPadded (padBE msg).toArray).toList.map word4BE).flatten

end Sha256

/-! ## SHA-1 (FIPS 180-4)

  Same Merkle–Damgård frame as SHA-256 (64-byte blocks, big-endian message words, a
  64-bit big-endian bit-length trailer via `padBE`, big-endian digest packing) but with a
  5-word state, 80 rounds, LEFT rotations, and the classic four-quarter round function /
  constant schedule. The message schedule extends by
  `w[t] = rotl1 (w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16])`. -/

namespace Sha1

/-- Left rotation on 32-bit words (n ∈ {1,5,30} for all SHA-1 uses). -/
@[inline] def rotl (x : UInt32) (n : UInt32) : UInt32 := (x <<< n) ||| (x >>> (32 - n))

/-- Initial hash values H (FIPS 180-4 §5.3.1). -/
def H0 : Array UInt32 := #[0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]

/-- The four round constants, selected by the quarter index `t / 20`. -/
@[inline] def K (t : Nat) : UInt32 :=
  if t < 20 then 0x5a827999
  else if t < 40 then 0x6ed9eba1
  else if t < 60 then 0x8f1bbcdc
  else 0xca62c1d6

/-- Nonlinear round function, selected by the quarter index `t / 20`
    (ch / parity / maj / parity). -/
@[inline] def f (t : Nat) (b c d : UInt32) : UInt32 :=
  if t < 20 then (b &&& c) ||| ((~~~b) &&& d)
  else if t < 40 then b ^^^ c ^^^ d
  else if t < 60 then (b &&& c) ||| (b &&& d) ||| (c &&& d)
  else b ^^^ c ^^^ d

/-- Compress all 64-byte blocks of the padded message into the 5-word state. -/
def hashPadded (padded : Array UInt8) : Array UInt32 := Id.run do
  let mut H := H0
  let numBlocks := padded.size / 64
  for blk in [0:numBlocks] do
    let base := blk * 64
    -- message schedule W[0..79]
    let mut w : Array UInt32 := Array.mkEmpty 80
    for i in [0:16] do
      let j := base + 4 * i
      w := w.push (beWord padded[j]! padded[j+1]! padded[j+2]! padded[j+3]!)
    for t in [16:80] do
      w := w.push (rotl (w[t-3]! ^^^ w[t-8]! ^^^ w[t-14]! ^^^ w[t-16]!) 1)
    -- compression
    let mut a := H[0]!
    let mut b := H[1]!
    let mut c := H[2]!
    let mut d := H[3]!
    let mut e := H[4]!
    for t in [0:80] do
      let temp := rotl a 5 + f t b c d + e + K t + w[t]!
      e := d; d := c; c := rotl b 30; b := a; a := temp
    H := #[H[0]! + a, H[1]! + b, H[2]! + c, H[3]! + d, H[4]! + e]
  return H

/-- FIPS 180-4 SHA-1 over a byte string, producing a 20-byte digest. -/
def hash (msg : Bytes) : Bytes :=
  ((hashPadded (padBE msg).toArray).toList.map word4BE).flatten

end Sha1

/-! ## RIPEMD-160 -/

namespace Ripemd160

/-- Left rotation on 32-bit words (n ∈ 5..15 for all RIPEMD-160 uses). -/
@[inline] def rotl (x : UInt32) (n : UInt32) : UInt32 := (x <<< n) ||| (x >>> (32 - n))

/-- Nonlinear round function, selected by round index `j / 16`. -/
@[inline] def f (round : Nat) (x y z : UInt32) : UInt32 :=
  match round with
  | 0 => x ^^^ y ^^^ z
  | 1 => (x &&& y) ||| ((~~~x) &&& z)
  | 2 => (x ||| (~~~y)) ^^^ z
  | 3 => (x &&& z) ||| (y &&& (~~~z))
  | _ => x ^^^ (y ||| (~~~z))

def KL : Array UInt32 := #[0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e]
def KR : Array UInt32 := #[0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000]

/-- Message word selection, left line (80 entries). -/
def rL : Array Nat := #[
  0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
  7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
  3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
  1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
  4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]

/-- Message word selection, right line (80 entries). -/
def rR : Array Nat := #[
  5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
  6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
  15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
  8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
  12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]

/-- Rotate amounts, left line. -/
def sL : Array UInt32 := #[
  11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
  7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
  11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
  11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
  9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]

/-- Rotate amounts, right line. -/
def sR : Array UInt32 := #[
  8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
  9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
  9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
  15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
  8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]

def H0 : Array UInt32 := #[0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]

def hashPadded (padded : Array UInt8) : Array UInt32 := Id.run do
  let mut H := H0
  let numBlocks := padded.size / 64
  for blk in [0:numBlocks] do
    let base := blk * 64
    -- 16 little-endian message words
    let mut X : Array UInt32 := Array.mkEmpty 16
    for i in [0:16] do
      let j := base + 4 * i
      X := X.push (leWord padded[j]! padded[j+1]! padded[j+2]! padded[j+3]!)
    let mut al := H[0]!; let mut bl := H[1]!; let mut cl := H[2]!
    let mut dl := H[3]!; let mut el := H[4]!
    let mut ar := H[0]!; let mut br := H[1]!; let mut cr := H[2]!
    let mut dr := H[3]!; let mut er := H[4]!
    for j in [0:80] do
      let round := j / 16
      -- left line
      let tl := rotl (al + f round bl cl dl + X[rL[j]!]! + KL[round]!) sL[j]! + el
      al := el; el := dl; dl := rotl cl 10; cl := bl; bl := tl
      -- right line (function/constant index is 4 - round)
      let tr := rotl (ar + f (4 - round) br cr dr + X[rR[j]!]! + KR[round]!) sR[j]! + er
      ar := er; er := dr; dr := rotl cr 10; cr := br; br := tr
    H := #[H[1]! + cl + dr, H[2]! + dl + er, H[3]! + el + ar,
           H[4]! + al + br, H[0]! + bl + cr]
  return H

/-- RIPEMD-160 over a byte string, producing a 20-byte digest. -/
def hash (msg : Bytes) : Bytes :=
  ((hashPadded (padLE msg).toArray).toList.map word4LE).flatten

end Ripemd160

/-! ## Top-level hash exports (OP_SHA256 / OP_RIPEMD160 / OP_HASH256 / OP_HASH160) -/

/-- OP_SHA256. -/
def sha256 : Bytes → Bytes := Sha256.hash
/-- OP_SHA1. -/
def sha1 : Bytes → Bytes := Sha1.hash
/-- OP_RIPEMD160. -/
def ripemd160 : Bytes → Bytes := Ripemd160.hash
/-- OP_HASH256 = SHA-256 ∘ SHA-256. -/
def hash256 : Bytes → Bytes := fun b => Sha256.hash (Sha256.hash b)
/-- OP_HASH160 = RIPEMD-160 ∘ SHA-256. -/
def hash160 : Bytes → Bytes := fun b => Ripemd160.hash (Sha256.hash b)

/-! ## The secp256k1 ORACLE (validated-not-proven boundary)

  `structure Secp256k1` + `Secp256k1.reject` now live in `LeanBCH/Oracle.lean` — the sole
  assumed-trust surface, isolated to one file — and are re-exported here (`import LeanBCH.Oracle`
  above) so every existing importer of `LeanBCH.Crypto` resolves `Secp256k1` unchanged.
  See TRUST_MANIFEST.md, Tier 3. -/

/-! ## Known-answer tests — enforced at BUILD TIME.

  Each `#eval` runs during `lake build`; a mismatch `throw`s an `IO.userError`, which fails
  the build. This pins the implementations to the FIPS / RIPEMD reference vectors without any
  `native_decide` proof term or axiom. (Proofs elsewhere stay ABSTRACT over `hash256`; the
  concrete digest is only asserted here, at the conformance/eval seam.) -/

/-- Build-time KAT guard. -/
private def kat (name expected : String) (got : String) : IO Unit := do
  unless got = expected do
    throw (IO.userError s!"[Crypto KAT] {name}: expected {expected}, got {got}")

-- SHA-256 (FIPS 180-4 examples)
#eval kat "sha256 empty"
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  (toHex (sha256 []))
#eval kat "sha256 abc"
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  (toHex (sha256 "abc".toUTF8.toList))
-- 56-byte, multi-block (> 55) FIPS vector
#eval kat "sha256 448-bit"
  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
  (toHex (sha256 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".toUTF8.toList))

-- SHA-1 (FIPS 180-4 examples)
#eval kat "sha1 empty"
  "da39a3ee5e6b4b0d3255bfef95601890afd80709"
  (toHex (sha1 []))
#eval kat "sha1 abc"
  "a9993e364706816aba3e25717850c26c9cd0d89d"
  (toHex (sha1 "abc".toUTF8.toList))
-- 56-byte, multi-block (> 55) FIPS vector
#eval kat "sha1 448-bit"
  "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
  (toHex (sha1 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".toUTF8.toList))

-- RIPEMD-160 (reference vectors)
#eval kat "ripemd160 empty"
  "9c1185a5c5e9fc54612808977ee8f548b2258d31"
  (toHex (ripemd160 []))
#eval kat "ripemd160 abc"
  "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
  (toHex (ripemd160 "abc".toUTF8.toList))
-- multi-block RIPEMD-160 vector (56 bytes)
#eval kat "ripemd160 448-bit"
  "12a053384a9c0c88e405a06c27dcf49ada62eb2b"
  (toHex (ripemd160 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".toUTF8.toList))

-- double-round exports
#eval kat "hash256 empty (SHA256d)"
  "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
  (toHex (hash256 []))
#eval kat "hash160 empty (RIPEMD160∘SHA256)"
  "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"
  (toHex (hash160 []))

end LeanBCH.Crypto
