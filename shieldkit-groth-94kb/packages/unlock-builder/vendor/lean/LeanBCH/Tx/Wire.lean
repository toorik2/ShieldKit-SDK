/-
  LeanBCH.Tx.Wire — the P2P/consensus transaction serialization codec (encode + DECODE).

  The sighash serialization (`Tx.Encoding`/`Tx.Sighash`) deliberately omits the unlocking
  bytecode; the WIRE form includes it. This module is the full round-trippable codec:

    tx     = version(4LE) ‖ compactUint(#in) ‖ input* ‖ compactUint(#out) ‖ output* ‖ locktime(4LE)
    input  = reverse(outpointTxHash)(32) ‖ outpointIndex(4LE) ‖ compactUint(|scriptSig|) ‖ scriptSig ‖ sequence(4LE)
    output = value(8LE) ‖ compactUint(|field|) ‖ field       -- field = tokenPrefix ‖ lockingBytecode

  The DECODER is what unlocks conformance ingestion: the official vmb_test corpus supplies each
  case as `testTransactionHex` + `sourceOutputsHex`, which decode straight into `Program`. Wire
  byte-order (outpoint hash + token category are reversed vs the UI/internal form the records
  hold) is handled at this boundary, mirroring the encoders. Validated by round-trip: `decode ∘
  encode = id` (main + token-carrying transactions), independent of the VM — the KERNEL-CHECKED
  (`by decide`) witnesses (`decodeTransaction (encodeTransaction t) = some t` for main / NFT /
  fungible / max-amount txs, plus the `decodeOutputList` list form) live in the validation layer
  at LeanBCH/Validation/Tx/Wire.lean.
-/
import LeanBCH.Tx.Types
import LeanBCH.Tx.Encoding

namespace LeanBCH.Tx
open LeanBCH

/-! ## Full wire encoders (complementing the sighash-only encoders in `Tx.Encoding`) -/

/-- A full transaction input on the wire (includes the unlocking bytecode). -/
def encodeInput (i : Input) : Bytes :=
  i.outpointTransactionHash.reverse ++ uint32LE i.outpointIndex
    ++ compactUint i.unlockingBytecode.length ++ i.unlockingBytecode
    ++ uint32LE i.sequenceNumber

/-- A complete transaction on the wire. -/
def encodeTransaction (t : Transaction) : Bytes :=
  uint32LE t.version
    ++ compactUint t.inputs.size ++ (t.inputs.toList.map encodeInput).flatten
    ++ compactUint t.outputs.size ++ (t.outputs.toList.map encodeOutput).flatten
    ++ uint32LE t.locktime

/-- A bare, count-prefixed output list (the `sourceOutputsHex` shape). -/
def encodeOutputList (os : Array Output) : Bytes :=
  compactUint os.size ++ (os.toList.map encodeOutput).flatten

/-! ## Decoders — reader style `Bytes → Option (α × Bytes)` (`none` = malformed/short) -/

/-- Split `n` bytes off the front. -/
def takeBytes : Nat → Bytes → Option (Bytes × Bytes)
  | 0,   bs      => some ([], bs)
  | _+1, []      => none
  | n+1, b :: bs => (takeBytes n bs).map (fun (d, r) => (b :: d, r))

/-- Read a `k`-byte little-endian natural. -/
def readNatLE : Nat → Bytes → Option (Nat × Bytes)
  | 0,   bs      => some (0, bs)
  | _+1, []      => none
  | k+1, b :: bs => (readNatLE k bs).map (fun (n, r) => (b.toNat + 256 * n, r))

def readU32 (bs : Bytes) : Option (UInt32 × Bytes) := (readNatLE 4 bs).map (fun (n, r) => (UInt32.ofNat n, r))
def readU64 (bs : Bytes) : Option (UInt64 × Bytes) := (readNatLE 8 bs).map (fun (n, r) => (UInt64.ofNat n, r))

/-- Read a Bitcoin compact-uint (varint), enforcing CANONICAL minimality (BCHN `ReadCompactSize`
    rejects a non-canonical encoding, e.g. `fd 01 00` for 1): a 3/5/9-byte form must carry a value
    that could not have fit in the shorter form. -/
def readCompactUint (bs : Bytes) : Option (Nat × Bytes) :=
  match bs with
  | []        => none
  | b :: rest =>
      let n := b.toNat
      if n ≤ 252 then some (n, rest)
      else if n == 0xfd then (readNatLE 2 rest).bind (fun (v, r) => if v ≥ 0xfd       then some (v, r) else none)
      else if n == 0xfe then (readNatLE 4 rest).bind (fun (v, r) => if v ≥ 0x10000    then some (v, r) else none)
      else                   (readNatLE 8 rest).bind (fun (v, r) => if v ≥ 0x100000000 then some (v, r) else none)

def capOfInt : Nat → NftCapability
  | 1 => .mutable
  | 2 => .minting
  | _ => .none

/-- Decode an output `field` into its (optional) token prefix + locking bytecode. A token
    prefix is present iff the field begins with 0xef (PREFIX_TOKEN); it carries the 32-byte
    category (reversed back to UI order), a bitfield, and optional commitment / amount. -/
def decodeField (field : Bytes) : Option (Option TokenData × Bytes) :=
  match field with
  | 0xef :: rest => do
      let (catRev, bs) ← takeBytes 32 rest
      let (bf, bs) ← (match bs with | b :: r => some (b, r) | [] => none)
      let bfN := bf.toNat
      let cap := bfN &&& 0x0f
      let hasNft := bfN &&& 0x20 != 0
      let hasCommitLen := bfN &&& 0x40 != 0
      let hasAmount := bfN &&& 0x10 != 0
      -- CHIP-2022-02 token-prefix validity: a malformed prefix ⇒ the transaction does not decode.
      if bfN &&& 0x80 != 0 then none                          -- reserved bit set
      else if cap > 2 then none                                -- capability must be none/mutable/minting
      else if hasCommitLen && !hasNft then none                -- commitment requires an NFT
      else if !hasNft && cap != 0 then none                    -- capability requires an NFT
      else do
        let (commitment, bs) ←
          (if hasCommitLen then do let (cl, bs') ← readCompactUint bs; takeBytes cl bs'
           else some ([], bs))
        let (amount, bs) ← (if hasAmount then readCompactUint bs else some (0, bs))
        if hasCommitLen && commitment.length == 0 then none    -- if encoded, commitment length > 0
        else if hasAmount && amount == 0 then none             -- if encoded, amount > 0
        else if amount > 9223372036854775807 then none         -- ≤ maximum fungible amount (2^63−1)
        else if !hasNft && !hasAmount then none                -- must encode at least one token
        else
          let nft := if hasNft then some ({ capability := capOfInt cap, commitment := commitment } : Nft) else none
          some (some ({ category := catRev.reverse, amount := amount, nft := nft } : TokenData), bs)
  | _ => some (none, field)

def readOutput (bs : Bytes) : Option (Output × Bytes) := do
  let (val, bs) ← readU64 bs
  let (flen, bs) ← readCompactUint bs
  let (field, bs) ← takeBytes flen bs
  let (token, locking) ← decodeField field
  some ({ valueSatoshis := val, lockingBytecode := locking, token := token }, bs)

def readInput (bs : Bytes) : Option (Input × Bytes) := do
  let (hashWire, bs) ← takeBytes 32 bs
  let (idx, bs) ← readU32 bs
  let (slen, bs) ← readCompactUint bs
  let (script, bs) ← takeBytes slen bs
  let (seqn, bs) ← readU32 bs
  some ({ outpointTransactionHash := hashWire.reverse, outpointIndex := idx,
          unlockingBytecode := script, sequenceNumber := seqn }, bs)

/-- Read `n` items with `rd`, threading the remaining bytes. -/
def readN (rd : Bytes → Option (α × Bytes)) : Nat → Bytes → Option (List α × Bytes)
  | 0,   bs => some ([], bs)
  | n+1, bs => do
      let (x, bs)  ← rd bs
      let (xs, bs) ← readN rd n bs
      some (x :: xs, bs)

/-- ★ Decode a full wire transaction (ignores any trailing bytes). -/
def decodeTransaction (bs : Bytes) : Option Transaction := do
  let (ver, bs)  ← readU32 bs
  let (nIn, bs)  ← readCompactUint bs
  let (ins, bs)  ← readN readInput nIn bs
  let (nOut, bs) ← readCompactUint bs
  let (outs, bs) ← readN readOutput nOut bs
  let (lock, _)  ← readU32 bs
  some { version := ver, inputs := ins.toArray, outputs := outs.toArray, locktime := lock }

/-- ★ Decode a count-prefixed output list (the vmb `sourceOutputsHex` shape). -/
def decodeOutputList (bs : Bytes) : Option (Array Output) := do
  let (n, bs)  ← readCompactUint bs
  let (os, _)  ← readN readOutput n bs
  some os.toArray

/-- Assemble a `Program` from decoded wire transaction + source outputs at an input index. -/
def decodeProgram (txHex sourceOutputsHex : Bytes) (inputIndex : Nat) : Option Program := do
  let tx  ← decodeTransaction txHex
  let sos ← decodeOutputList sourceOutputsHex
  some { transaction := tx, sourceOutputs := sos, inputIndex := inputIndex }

-- KATs moved to LeanBCH/Validation/Tx/Wire.lean (validation layer).

end LeanBCH.Tx
