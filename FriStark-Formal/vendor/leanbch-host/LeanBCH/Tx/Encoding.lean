/-
  LeanBCH.Tx.Encoding — byte-exact BCH transaction-component encoders.

  These reproduce, as pure `Bytes` concatenations, the `@bitauth/libauth` 3.1.0-next.8
  wire encoders used by the BCH signing serialization, transcribed byte-for-byte from
    • `vm/instruction-sets/common/signing-serialization.js`
        (`hashPrevouts`/`hashUtxos`/`hashSequence`/`hashOutputs`)
    • `message/transaction-encoding.js`
        (`encodeTokenPrefix`, `encodeTransactionOutput`, `encodeTransactionOutpoints`,
         `encodeTransactionOutputsForSigning`, `encodeTransactionInputSequenceNumbersForSigning`)
    • `format/number.js`
        (`bigIntToCompactUint`, `numberToBinUint32LE`, `bigIntToBinUint64LE = valueSatoshisToBin`)

  BYTE-ORDER: `Input.outpointTransactionHash` and `TokenData.category` are held in UI /
  internal (reversed-vs-wire) order in `Tx.Types`; every encoder that emits them reverses
  at the wire boundary here (matching every libauth `.slice().reverse()`).

  The aggregate hashes (`hashPrevouts`/`hashUtxos`/`hashSequence`/`hashOutputs`) stay
  ABSTRACT over `hash256`: they call `Crypto.hash256` but no proof reduces the digest;
  the concrete digest is only asserted at the `#eval` conformance seam (Sighash.lean).
-/
import LeanBCH.Tx.Types
import LeanBCH.Crypto
import LeanBCH.Number

namespace LeanBCH.Tx

open LeanBCH
open LeanBCH.Crypto (hash256)

-- Totality helpers: default `Input`/`Output` for out-of-range accessor fallbacks
-- (never consensus-relevant; the in-range case is the only real one).
deriving instance Inhabited for Input
deriving instance Inhabited for Output

/-! ## Fixed-width little-endian integer encoders

  `numberToBinUint32LE` / `bigIntToBinUint64LE` (libauth `format/number.js`). -/

/-- A single byte (libauth `Uint8Array.of(b)`). -/
@[inline] def uint8 (b : UInt8) : Bytes := [b]

/-- `n`-byte little-endian encoding of a `Nat` (low byte first). -/
def natLE (bytes : Nat) (n : Nat) : Bytes :=
  (List.range bytes).map (fun i => UInt8.ofNat (n >>> (8 * i)))

/-- 2-byte little-endian (libauth `numberToBinUint16LE`). -/
def uint16LE (n : UInt16) : Bytes := natLE 2 n.toNat

/-- 4-byte little-endian (libauth `numberToBinUint32LE`). -/
def uint32LE (n : UInt32) : Bytes := natLE 4 n.toNat

/-- 8-byte little-endian (libauth `bigIntToBinUint64LE` = `valueSatoshisToBin`). -/
def uint64LE (n : UInt64) : Bytes := natLE 8 n.toNat

/-! ## CompactUint (Bitcoin varint)

  libauth `bigIntToCompactUint`: `≤252` → 1 raw byte; `≤0xffff` → `0xfd` ++ 2LE;
  `≤0xffffffff` → `0xfe` ++ 4LE; else `0xff` ++ 8LE. (NB the single-byte cutoff is
  `252`/`0xfc`, NOT `0xfd` — `0xfd`/`0xfe`/`0xff` are the multi-byte prefixes.) -/
def compactUint (n : Nat) : Bytes :=
  if n ≤ 252 then [UInt8.ofNat n]
  else if n ≤ 65535 then (0xfd : UInt8) :: natLE 2 n
  else if n ≤ 4294967295 then (0xfe : UInt8) :: natLE 4 n
  else (0xff : UInt8) :: natLE 8 n

/-! ## Token prefix (CHIP-2022-02-CashTokens)

  libauth `encodeTokenPrefix`. Empty when there is no token, or when the token
  carries neither an NFT nor a positive amount. Otherwise:
    `0xef` ++ reverse(category) ++ [bitfield]
         ++ (HAS_COMMITMENT_LENGTH? compactUint(len) ++ commitment)
         ++ (HAS_AMOUNT? compactUint(amount))
  bitfield = HAS_NFT(0x20) | HAS_COMMITMENT_LENGTH(0x40) | HAS_AMOUNT(0x10) | capability. -/
def nftCapabilityInt : NftCapability → Nat
  | .none => 0
  | .mutable => 1
  | .minting => 2

def encodeTokenPrefix : Option TokenData → Bytes
  | none => []
  | some t =>
    if t.nft.isNone && t.amount < 1 then []
    else
      let hasNft := if t.nft.isNone then 0 else 32
      let capabilityInt := match t.nft with
        | none => 0
        | some nft => nftCapabilityInt nft.capability
      let commitment := match t.nft with
        | none => []
        | some nft => nft.commitment
      let hasCommitmentLength := if commitment.length > 0 then 64 else 0
      let hasAmount := if t.amount > 0 then 16 else 0
      let bitfield : UInt8 := UInt8.ofNat (hasNft ||| hasCommitmentLength ||| hasAmount ||| capabilityInt)
      (0xef : UInt8) :: (t.category.reverse ++ [bitfield]
        ++ (if hasCommitmentLength == 0 then [] else compactUint commitment.length ++ commitment)
        ++ (if hasAmount == 0 then [] else compactUint t.amount))

/-! ## Output + outpoint encoders -/

/-- libauth `encodeTransactionOutput` (a.k.a. `encodeTransactionOutputsForSigning`
    per output): `value(8LE) ++ compactUint(|field|) ++ field`, where
    `field = tokenPrefix ++ lockingBytecode`. -/
def encodeOutput (o : Output) : Bytes :=
  let field := encodeTokenPrefix o.token ++ o.lockingBytecode
  uint64LE o.valueSatoshis ++ compactUint field.length ++ field

/-- libauth outpoint encoder (per input, inside `encodeTransactionOutpoints`):
    `reverse(outpointTransactionHash) ++ outpointIndex(4LE)`. -/
def encodeOutpoint (i : Input) : Bytes :=
  i.outpointTransactionHash.reverse ++ uint32LE i.outpointIndex

/-! ## Per-transaction concatenations (pre-hash streams) -/

/-- libauth `encodeTransactionOutpoints`. -/
def transactionOutpoints (t : Transaction) : Bytes :=
  (t.inputs.toList.map encodeOutpoint).flatten

/-- libauth `encodeTransactionInputSequenceNumbersForSigning`. -/
def transactionSequenceNumbers (t : Transaction) : Bytes :=
  (t.inputs.toList.map (fun i => uint32LE i.sequenceNumber)).flatten

/-- libauth `encodeTransactionOutputsForSigning` over the tx outputs. -/
def transactionOutputs (t : Transaction) : Bytes :=
  (t.outputs.toList.map encodeOutput).flatten

/-- libauth `encodeTransactionOutputsForSigning` over the source outputs (UTXOs). -/
def transactionUtxos (sourceOutputs : Array Output) : Bytes :=
  (sourceOutputs.toList.map encodeOutput).flatten

/-! ## Double-hash aggregates (gated by sighash flags)

  These match libauth exactly. `emptyHash` is 32 zero bytes; a gated-out UTXOS hash is
  LENGTH-0 (not 32 zeros) — the footgun the lane calls out. Kept ABSTRACT over `hash256`. -/

/-- 32 zero bytes (libauth `emptyHash`). -/
def emptyHash : Bytes := List.replicate 32 (0 : UInt8)

/-- libauth `hashPrevouts`: empty-hash under ANYONECANPAY, else `hash256(outpoints)`. -/
def hashPrevouts (t : Transaction) (anyoneCanPay : Bool) : Bytes :=
  if anyoneCanPay then emptyHash else hash256 (transactionOutpoints t)

/-- libauth `hashUtxos`: `hash256(utxos)` when the UTXOS(0x20) flag is set, else
    LENGTH-0 (`Uint8Array.of()`) — NOT a 32-zero emptyHash. -/
def hashUtxos (sourceOutputs : Array Output) (serializeUtxos : Bool) : Bytes :=
  if serializeUtxos then hash256 (transactionUtxos sourceOutputs) else []

/-- libauth `hashSequence`: `hash256(sequenceNumbers)` unless ANYONECANPAY, SINGLE,
    or NONE — in which case empty-hash. -/
def hashSequence (t : Transaction) (anyoneCanPay single noOutputs : Bool) : Bytes :=
  if !anyoneCanPay && !single && !noOutputs then hash256 (transactionSequenceNumbers t)
  else emptyHash

/-- libauth `hashOutputs`: `hash256(all outputs)` normally; under SINGLE, `hash256` of
    the single corresponding output (`outputs[inputIndex]`) or empty-hash if none;
    under NONE, empty-hash. -/
def hashOutputs (t : Transaction) (inputIndex : Nat) (single noOutputs : Bool) : Bytes :=
  if !single && !noOutputs then hash256 (transactionOutputs t)
  else if single then
    match t.outputs[inputIndex]? with
    | some o => hash256 (encodeOutput o)
    | none => emptyHash
  else emptyHash

-- KATs moved to LeanBCH/Validation/Tx/Encoding.lean (validation layer).

end LeanBCH.Tx
