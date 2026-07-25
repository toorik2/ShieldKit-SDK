/-
  LeanBCH.VM.Extended — the extended step that adds ops NOT in the keystone-proven core.

  `stepInstr` (Eval) is frozen: `run_straightline`/`splice_congr_run` are proven over it, and any
  new arm would force re-proving the hand-peeled `stepInstr_local`. So ops that arrive later —
  the BCH-2026 bitwise/shift ops here, and the BCH-2026 introspection ops that need the
  transaction context — live in `stepInstrExt`, which handles them and delegates everything else
  to `stepInstr`. The consensus VM (`verifyInput`) runs on this extended step; the optimizer's
  straight-line reasoning stays on the pure `stepInstr` core (verifier blocks are field
  arithmetic — no shifts / introspection / signatures), so the keystone remains valid.

  The introspection ops thread the `Program` context (`p`) — the transaction + resolved source
  outputs + evaluated input index — exactly as libauth's `common/inspection.js` reads it.
-/
import LeanBCH.VM.Meter
import LeanBCH.VM.Shift2026
import LeanBCH.Tx.Types
import LeanBCH.Tx.Sighash

namespace LeanBCH.VM
open LeanBCH LeanBCH.VM.State LeanBCH.Tx LeanBCH.Crypto

/-- Two's-complement signed reading of a 32-bit field (libauth `int32UnsignedToSigned`):
    `OP_TXVERSION` pushes the version reinterpreted as a signed int32 (BCHN `int32_t nVersion`),
    whereas locktime / sequence / outpoint-index stay unsigned. -/
def int32Signed (x : UInt32) : Int :=
  if x.toNat < 2147483648 then Int.ofNat x.toNat            -- < 2^31 : non-negative
  else Int.ofNat x.toNat - 4294967296                        -- ≥ 2^31 : subtract 2^32

/-- Re-encode one instruction to its bytecode (inverse of `parse`'s decode): opcode byte, plus
    the PUSHDATA1/2/4 little-endian length prefix for those push forms, then the data. Used by
    OP_ACTIVEBYTECODE (libauth `encodeAuthenticationInstructions`). -/
def encodeInstr (i : Instr) : Bytes :=
  let n := i.data.length
  if i.opcode == 0x4c then i.opcode :: UInt8.ofNat (n % 256) :: i.data
  else if i.opcode == 0x4d then i.opcode :: UInt8.ofNat (n % 256) :: UInt8.ofNat (n / 256 % 256) :: i.data
  else if i.opcode == 0x4e then i.opcode :: UInt8.ofNat (n % 256) :: UInt8.ofNat (n / 256 % 256)
                                  :: UInt8.ofNat (n / 65536 % 256) :: UInt8.ofNat (n / 16777216 % 256) :: i.data
  else i.opcode :: i.data                                     -- direct push (opcode = length) or a plain op

/-- Read the top item as a locktime/sequence VM number for OP_CHECKLOCKTIMEVERIFY /
    OP_CHECKSEQUENCEVERIFY: ≤ 5 bytes, minimally encoded, non-negative (libauth `useLocktime`). -/
def readLocktime? (b : Bytes) : Option Nat :=
  if b.length ≤ 5 && isMinimallyEncoded b then
    let v := vmNumberToBigInt b
    if v ≥ 0 then some v.toNat else none
  else none

/-- The index-popping introspection shell (libauth `useTransaction{Utxo,Input,Output}` + push):
    the popped `i` is the resolved VM-number index; a negative index or an out-of-range lookup is
    `invalidTxIndex`. `lookup n` yields the raw bytes to push for a valid index (a VM number for
    value/seq/index ops; raw bytecode/hash for the byte ops), or `none` when `n` is out of range.
    `checkLen` applies the `maximumStackItemLength` guard (libauth `pushToStackChecked`, used by
    the bytecode ops; the value/hash ops use the unchecked `pushToStack`). -/
def introspectIndexed (base : State) (rest : Stack) (i : Int)
    (lookup : Nat → Option Bytes) (checkLen : Bool) : State :=
  if i < 0 then base.setErr .invalidTxIndex
  else match lookup i.toNat with
    | some bytes =>
        if checkLen && bytes.length > maxItemLen then base.setErr .itemTooLarge
        else { base.advance with stack := bytes :: rest }
    | none => base.setErr .invalidTxIndex

/-! ## CashToken introspection payloads (libauth `bch/2023/bch-2023-tokens.js`).

    `pushTokenExtendedCategory` / `pushTokenCommitment` / `pushTokenAmount` compute the raw bytes an
    output's token contributes; the opcode arms below thread them through the same
    `introspectIndexed` shell as the non-token introspection ops (pop a minimal VM-number index,
    read `sourceOutputs[i]` for the UTXO variants / `transaction.outputs[i]` for the OUTPUT
    variants, out-of-range → `invalidTxIndex`). -/

/-- libauth `pushTokenExtendedCategory`: no token → empty (`pushToStackVmNumber 0n = []`); token
    present → the 32-byte `category` in WIRE order (the reverse of the UI-order storage, exactly
    `token.category.slice().reverse()`) followed by the CAPABILITY suffix byte — mutable NFT →
    `[0x01]`, minting NFT → `[0x02]`, immutable NFT or fungible-only → no suffix. Pushed UNCHECKED
    (libauth `pushToStack`). -/
def tokenCategoryBytes : Option TokenData → Bytes
  | none   => []
  | some t =>
      let suffix : Bytes :=
        match t.nft with
        | some nft =>
            match nft.capability with
            | .minting => [0x02]
            | .mutable => [0x01]
            | .none    => []
        | none => []
      t.category.reverse ++ suffix

/-- libauth `pushTokenCommitment`: an NFT present → its `commitment` bytes; no NFT / no token →
    empty (`pushToStackVmNumber 0n = []`). Pushed CHECKED (libauth `pushToStackChecked`). -/
def tokenCommitmentBytes : Option TokenData → Bytes
  | none   => []
  | some t =>
      match t.nft with
      | some nft => nft.commitment
      | none     => []

/-- libauth `pushTokenAmount`: the fungible `amount` as a minimal VM number; no token → `0` (which
    encodes to `[]`, same as an amount of 0). -/
def tokenAmountBytes : Option TokenData → Bytes
  | none   => bigIntToVmNumber 0
  | some t => bigIntToVmNumber (Int.ofNat t.amount)

/-! ## Signature-checking ops (libauth `common/crypto.js` `opCheckSig`/`opCheckDataSig`/
    `opCheckMultiSig`).

    secp256k1 is the explicit `crypto` ORACLE (accept/reject only). The covered bytecode
    ("scriptCode") is `s.scriptCode` — the raw bytes of the running script, correct for the
    common NO-codeseparator case. NULLFAIL and the multisig in-order matching are the
    correctness-critical bits and follow libauth exactly.

    DEFERRED / not modeled (honest scope): the encoding-validity gates
    (`isValidPublicKeyEncoding`, strict-DER `isValidSignatureEncoding`) — the oracle owns
    accept/reject and malformed-encoding *rejection* is not enforced; the Schnorr-multisig
    checkbits path (non-empty dummy element); a mid-script OP_CODESEPARATOR trimming the covered
    bytecode; and the legacy `operationCount` (201-op) limit (BCH-2026 uses the op-cost budget). -/

/-- Pop the top item and require truthiness WITHOUT advancing `ip` — the `OP_VERIFY` tail of a
    fused `*VERIFY` op, whose base transition has ALREADY advanced `ip` (libauth
    `combineOperations base opVerify` is a single instruction here). -/
def verifyTopInPlace (s : State) : State :=
  match s.stack with
  | x :: xs => if isTruthy x then { s with stack := xs } else s.setErr .verifyFailed
  | []      => s.setErr .stackUnderflow

/-- The checksig COVERED BYTECODE: the current script re-encoded from AFTER the last executed
    OP_CODESEPARATOR (`lastCodeSep` = sepIp+1, 0 = none). libauth trims the sighash's scriptCode at
    each code-separator; for no separator this re-encodes to the whole script. Replaces the raw
    `s.scriptCode` (which ignored code separators — a wrong digest under a real oracle). -/
def coveredBytecode (s : State) : Bytes :=
  ((s.instrs.toList.drop s.lastCodeSep).map encodeInstr).flatten

/-- OP_CHECKSIG (0xac). Pops pubkey (TOP) and sig (2nd). Faithful to libauth `opCheckSig`:
    an EMPTY signature pushes false with NO error; otherwise the LAST sig byte is the sighash
    type and the rest is the DER/Schnorr body, hashed against the BCH signing serialization
    (`Tx.sighashDigest` over the code-separator-trimmed `coveredBytecode`). A 64-byte body ⇒
    Schnorr (BIP-340), else ECDSA-DER. NULLFAIL: a failed non-empty check is an ERROR, not a false push. -/
def opCheckSig (crypto : Secp256k1) (p : Program) (s : State) : State :=
  let adv := s.advance
  match s.stack with
  | pubkey :: sig :: rest =>
      if sig.isEmpty then { adv with stack := ofBool false :: rest }     -- empty sig ⇒ false, no error
      else
        let sigHashType : UInt32 := UInt32.ofNat (sig.getLast?.getD 0).toNat
        let body := sig.dropLast
        let digest := Tx.sighashDigest p (coveredBytecode s) sigHashType
        let ok := if body.length == 64 then crypto.verifySchnorr body pubkey digest
                  else crypto.verifyDERLowS body pubkey digest
        if ok then { adv with stack := ofBool true :: rest }
        else s.setErr .verifyFailed                                      -- NULLFAIL (non-null sig failed)
  | _ => s.setErr .stackUnderflow

/-- OP_CHECKDATASIG (0xba). Pops pubkey (TOP), message (2nd), sig (3rd). The digest is a PLAIN
    `sha256(message)` (NOT a tx sighash) and the signature is RAW (no sighash-type byte, so the
    whole item is the body). Empty sig ⇒ false; a 64-byte sig ⇒ Schnorr, else ECDSA-DER. NULLFAIL
    on a failed non-empty check. -/
def opCheckDataSig (crypto : Secp256k1) (s : State) : State :=
  let adv := s.advance
  match s.stack with
  | pubkey :: message :: sig :: rest =>
      if sig.isEmpty then { adv with stack := ofBool false :: rest }
      else
        let digest := Crypto.sha256 message
        let ok := if sig.length == 64 then crypto.verifySchnorr sig pubkey digest
                  else crypto.verifyDERLowS sig pubkey digest
        if ok then { adv with stack := ofBool true :: rest }
        else s.setErr .verifyFailed
  | _ => s.setErr .stackUnderflow

/-- The ECDSA-multisig in-order matching loop (libauth `opCheckMultiSig` legacy path). `pubkeys`
    and `sigs` are in libauth splice order (index 0 = deepest / first-pushed); the loop walks BOTH
    from the top (highest index) downward, consuming a public key each round and a signature only
    on a verifying match — exactly Bitcoin's greedy in-order match. Returns the number of approving
    keys, or `none` on a Schnorr-sized (64-byte body) signature in ECDSA mode
    (`schnorrSizedSignatureInEcdsaMultiSig`). `fuel = |sigs| + |pubkeys| + 1` never runs out. -/
def cmsMatch (crypto : Secp256k1) (p : Program) (sc : Bytes) (pubkeys sigs : Array Bytes)
    (required : Nat) : Nat → Nat → Nat → Nat → Option Nat
  | 0,      approving, _,      _     => some approving
  | fuel+1, approving, remSig, remPk =>
      if remSig > 0 ∧ remPk > 0 ∧ approving + remPk ≥ remSig ∧ approving ≠ required then
        let publicKey := pubkeys[remPk-1]!
        let sig := sigs[remSig-1]!
        if sig.isEmpty then                                             -- null sig: skip, keep the key
          cmsMatch crypto p sc pubkeys sigs required fuel approving (remSig-1) remPk
        else
          let sigHashType : UInt32 := UInt32.ofNat (sig.getLast?.getD 0).toNat
          let body := sig.dropLast
          let digest := Tx.sighashDigest p sc sigHashType
          if body.length == 64 then none                               -- Schnorr-sized sig in ECDSA multisig
          else if crypto.verifyDERLowS body publicKey digest then
            cmsMatch crypto p sc pubkeys sigs required fuel (approving+1) (remSig-1) (remPk-1)
          else
            cmsMatch crypto p sc pubkeys sigs required fuel approving remSig (remPk-1)
      else some approving

/-- OP_CHECKMULTISIG (0xae). Stack (top→bottom): `n, pkₙ … pk₁, m, sigₘ … sig₁, dummy`. Pops `n`,
    the `n` public keys, `m`, the `m` signatures, and the extra `dummy` element (BCH still requires
    it). The `m` sigs are matched to the `n` keys IN ORDER (`cmsMatch`). NULLFAIL: unless EVERY sig
    is null, a non-success is an error. A NON-empty dummy selects the Schnorr-multisig checkbits
    path, which is DEFERRED (`.unimplemented`). -/
def opCheckMultiSig (crypto : Secp256k1) (p : Program) (s : State) : State :=
  let adv := s.advance
  match s.stack with
  | nItem :: rest0 =>
      match readNum? nItem with
      | none    => s.setErr .minimalEncoding
      | some nI =>
        if nI < 0 ∨ nI > 20 then s.setErr .verifyFailed                 -- key-count bounds (invalidNaturalNumber / exceedsMax)
        else
          let n := nI.toNat
          if rest0.length < n then s.setErr .stackUnderflow
          else
            let pubkeys := ((rest0.take n).reverse).toArray             -- → libauth splice order [pk₁ … pkₙ]
            match rest0.drop n with
            | mItem :: rest2 =>
                match readNum? mItem with
                | none    => s.setErr .minimalEncoding
                | some mI =>
                  if mI < 0 ∨ mI > nI then s.setErr .verifyFailed        -- required-sig bounds (insufficientPublicKeys)
                  else
                    let m := mI.toNat
                    if rest2.length < m then s.setErr .stackUnderflow
                    else
                      let sigs := ((rest2.take m).reverse).toArray       -- → [sig₁ … sigₘ]
                      match rest2.drop m with
                      | dummy :: rest =>
                          if !dummy.isEmpty then s.setErr .unimplemented -- Schnorr-multisig checkbits: DEFERRED
                          else
                            match cmsMatch crypto p (coveredBytecode s) pubkeys sigs m (m + n + 1) 0 m n with
                            | none           => s.setErr .verifyFailed   -- Schnorr-sized sig in ECDSA multisig
                            | some approving =>
                                let success := approving == m
                                let allNull := sigs.all (·.isEmpty)
                                if !allNull ∧ !success then s.setErr .verifyFailed   -- NULLFAIL
                                else { adv with stack := ofBool success :: rest }
                      | [] => s.setErr .stackUnderflow
            | [] => s.setErr .stackUnderflow
  | [] => s.setErr .stackUnderflow

/-! ## BCH-2026 FUNCTIONS chip (libauth `bch/2026/bch-2026-functions.js`).

    `OP_DEFINE` (0x89) binds an identifier to a body of raw bytes (NOT decoded — a malformed body is
    only rejected at invoke time); `OP_INVOKE` (0x8a) decodes the body and jumps into it, leaving a
    RETURN FRAME on the control stack (`Ctrl.frame` = the caller's instrs + resume ip). The frame
    return is executed by `runExt` when the current instructions are exhausted. The identifier
    length limit, the previously-defined / undefined / malformed guards, the control-stack-depth
    cap, and the combined `maximumMemorySlots` limit (stack + alt + functionCount, `functionCount`
    = `functionTable.length`; the two latter are per-op `every`-hook checks in `stepMeterExt`) all
    follow libauth exactly. -/

/-- libauth `ConsensusBch2026.maximumFunctionIdentifierLength`: an OP_DEFINE identifier longer than
    this is `functionIdentifierExcessiveLength`. (Mirrors `BCH_2026_05`; a local pin like
    `maxItemLen`.) -/
def maxFunctionIdLen : Nat := 7

/-- libauth `ConsensusCommon.maximumControlStackDepth`: the control stack (IF/BEGIN conds + INVOKE
    frames) may not exceed this depth. Checked AFTER each op (libauth's `every` hook), so it uniformly
    covers IF/BEGIN nesting and INVOKE recursion. (Mirrors `BCH_2026_05.maximumControlStackDepth`.) -/
def maxCtrlDepth : Nat := 100

/-- BCH-2026 libauth `ConsensusBch2026.maximumMemorySlots`: `stack + altstack + functionCount` may
    not exceed this, checked AFTER each op (the 2026 `every` hook). Subsumes the classic
    `maximumStackDepth` check (`stack + altstack > 1000`) for accept/reject purposes, since
    `functionCount ≥ 0` and both limits are 1000. (Mirrors `BCH_2026_05.maximumMemorySlots`.) -/
def maxMemorySlots : Nat := 1000

/-- Look up a function body by identifier. libauth keys `functionTable` by `binToHex(identifier)`;
    over raw `Bytes` (`List UInt8` `DecidableEq`) a direct equality lookup is the exact equivalent.
    `find?` returns the first match; OP_DEFINE forbids redefinition, so there is at most one. -/
def lookupFn (tbl : List (Bytes × Bytes)) (id : Bytes) : Option Bytes :=
  (tbl.find? (fun p => p.1 == id)).map (·.2)

/-- The extended per-opcode transition: the 2026 bitwise ops (INVERT + numeric/binary shifts), the
    FUNCTIONS chip (DEFINE/INVOKE), the BCH-2026 introspection ops (transaction context via `p`), the
    signature ops (via `p` + the secp256k1 oracle `crypto`), then delegation to the keystone-proven
    `stepInstr`. -/
def stepInstrExt (p : Program) (crypto : Secp256k1) (op : UInt8) (data : Bytes) (s : State) : State :=
  let adv := s.advance
  if op == 0x83 then                                    -- OP_INVERT
    match s.stack with
    | x :: rest => { adv with stack := opInvert x :: rest }
    | []        => s.setErr .stackUnderflow
  else if op == 0x8d || op == 0x8e then                 -- OP_LSHIFTNUM / OP_RSHIFTNUM (count, value)
    match s.stack with
    | cnt :: val :: rest =>
        match readNum? cnt, readNum? val with
        | some c, some v =>
            -- Guards mirror libauth bch-2026-bitwise (they AVOID materializing 2^c for a huge count,
            -- which would otherwise overflow Nat.pow): value 0 is unshiftable; LSHIFTNUM fast-fails
            -- above maxItemLen·8 bits; RSHIFTNUM past the value's bit-width collapses to 0 / −1.
            if c < 0 then s.setErr .numberTooLarge
            else if v == 0 then { adv with stack := ofNum 0 :: rest }
            else
              let cn := c.toNat
              if op == 0x8d then                            -- OP_LSHIFTNUM
                if cn > maxItemLen * 8 then s.setErr .itemTooLarge   -- fastFailBitCount: abandon excessive shift
                else
                  let r := lshiftNum v cn
                  if (ofNum r).length > maxItemLen then s.setErr .itemTooLarge
                  else { adv with stack := ofNum r :: rest }
              else                                          -- OP_RSHIFTNUM
                if cn > val.length * 8 then { adv with stack := ofNum (if v < 0 then -1 else 0) :: rest }
                else { adv with stack := ofNum (rshiftNum v cn) :: rest }
        | _, _ => s.setErr .minimalEncoding
    | _ => s.setErr .stackUnderflow
  else if op == 0x98 || op == 0x99 then                 -- OP_LSHIFTBIN / OP_RSHIFTBIN (count, data)
    match s.stack with
    | cnt :: dat :: rest =>
        match readNum? cnt with
        | some c => if c < 0 then s.setErr .numberTooLarge
                    else { adv with stack := (if op == 0x98 then lshiftBin dat c.toNat else rshiftBin dat c.toNat) :: rest }
        | none   => s.setErr .minimalEncoding
    | _ => s.setErr .stackUnderflow
  -- ── BCH-2026 FUNCTIONS chip (libauth `bch/2026/bch-2026-functions.js`) ──
  else if op == 0x89 then                               -- OP_DEFINE
    -- Pop `functionIdentifier` (TOP); reject an over-length or already-defined id; else pop
    -- `functionBody` (2nd) and bind identifier ↦ body (raw bytes, undecoded). Two items popped.
    match s.stack with
    | fnId :: rest =>
        let s1 := { s with stack := rest }                                -- id popped (libauth nextState)
        if fnId.length > maxFunctionIdLen then s1.setErr .functionIdExcessive
        else if (s.functionTable.find? (fun q => q.1 == fnId)).isSome then s1.setErr .functionIdRedefined
        else match rest with
          | body :: rest2 =>
              { adv with stack := rest2, functionTable := s.functionTable ++ [(fnId, body)] }
          | [] => s1.setErr .stackUnderflow
    | [] => s.setErr .stackUnderflow
  else if op == 0x8a then                               -- OP_INVOKE
    -- Pop `functionIdentifier` (TOP); look up the body (undefined → error); decode it (malformed →
    -- error); else push a RETURN FRAME (caller instrs + resume ip) and JUMP into the body (ip := 0,
    -- NOT the normal advance). The frame is returned by `runExt` when the body is exhausted.
    match s.stack with
    | fnId :: rest =>
        match lookupFn s.functionTable fnId with
        | none      => { s with stack := rest }.setErr .functionIdUndefined
        | some body =>
            match parse body with
            | .malformed _  => { s with stack := rest }.setErr .malformedFunction
            | .ok bodyInstrs =>
                { s with stack := rest, instrs := bodyInstrs, ip := 0,
                         ctrl := Ctrl.frame s.instrs (s.ip + 1) :: s.ctrl }
    | [] => s.setErr .stackUnderflow
  -- ── BCH-2026 introspection (bytes verbatim from libauth OpcodesBch2023 additions 192..205) ──
  -- Nullary ops (no stack input): push a transaction-context value.
  else if op == 0xc0 then                               -- OP_INPUTINDEX (192)
    adv.push (bigIntToVmNumber (Int.ofNat p.inputIndex))
  else if op == 0xc1 then                               -- OP_ACTIVEBYTECODE (193)
    -- libauth: encode(instructions.slice(lastCodeSeparator + 1)) — the RE-ENCODING of the CURRENT
    -- instructions after the last code-separator. Using `s.instrs` (not `scriptCode`) is exact for
    -- the top level (re-encode ∘ parse = id) AND correct inside an OP_INVOKE function body (where
    -- `s.instrs` is the body). `lastCodeSep` here is the intercepted (sepIp+1) form: 0 = no
    -- separator ⇒ from index 0, else sepIp+1 ⇒ start after the separator (distinguishes sep-at-0).
    let startIdx := s.lastCodeSep
    let ab := ((s.instrs.toList.drop startIdx).map encodeInstr).flatten
    if ab.length > maxItemLen then s.setErr .itemTooLarge else adv.push ab
  else if op == 0xc2 then                               -- OP_TXVERSION (194) — signed int32
    adv.push (bigIntToVmNumber (int32Signed p.version))
  else if op == 0xc3 then                               -- OP_TXINPUTCOUNT (195)
    adv.push (bigIntToVmNumber (Int.ofNat p.inputCount))
  else if op == 0xc4 then                               -- OP_TXOUTPUTCOUNT (196)
    adv.push (bigIntToVmNumber (Int.ofNat p.outputCount))
  else if op == 0xc5 then                               -- OP_TXLOCKTIME (197) — unsigned
    adv.push (bigIntToVmNumber (Int.ofNat p.locktime.toNat))
  -- Index-popping ops: pop a minimal VM-number index, look it up, push the field.
  else if op == 0xc6 then                               -- OP_UTXOVALUE (198): sourceOutputs[i].value
    match s.stack with
    | idx :: rest =>
        match readNum? idx with
        | some i => introspectIndexed s rest i
            (fun n => (p.sourceOutputs[n]?).map (fun u => bigIntToVmNumber (Int.ofNat u.valueSatoshis.toNat))) false
        | none => s.setErr .minimalEncoding
    | [] => s.setErr .stackUnderflow
  else if op == 0xc7 then                               -- OP_UTXOBYTECODE (199): sourceOutputs[i].locking
    match s.stack with
    | idx :: rest =>
        match readNum? idx with
        | some i => introspectIndexed s rest i (fun n => (p.sourceOutputs[n]?).map (·.lockingBytecode)) true
        | none => s.setErr .minimalEncoding
    | [] => s.setErr .stackUnderflow
  else if op == 0xc8 then                               -- OP_OUTPOINTTXHASH (200): input[i].hash REVERSED
    match s.stack with
    | idx :: rest =>
        match readNum? idx with
        | some i => introspectIndexed s rest i
            (fun n => (p.transaction.inputs[n]?).map (fun inp => inp.outpointTransactionHash.reverse)) false
        | none => s.setErr .minimalEncoding
    | [] => s.setErr .stackUnderflow
  else if op == 0xc9 then                               -- OP_OUTPOINTINDEX (201): input[i].outpointIndex
    match s.stack with
    | idx :: rest =>
        match readNum? idx with
        | some i => introspectIndexed s rest i
            (fun n => (p.transaction.inputs[n]?).map (fun inp => bigIntToVmNumber (Int.ofNat inp.outpointIndex.toNat))) false
        | none => s.setErr .minimalEncoding
    | [] => s.setErr .stackUnderflow
  else if op == 0xca then                               -- OP_INPUTBYTECODE (202): input[i].unlocking
    match s.stack with
    | idx :: rest =>
        match readNum? idx with
        | some i => introspectIndexed s rest i (fun n => (p.transaction.inputs[n]?).map (·.unlockingBytecode)) true
        | none => s.setErr .minimalEncoding
    | [] => s.setErr .stackUnderflow
  else if op == 0xcb then                               -- OP_INPUTSEQUENCENUMBER (203): input[i].seq
    match s.stack with
    | idx :: rest =>
        match readNum? idx with
        | some i => introspectIndexed s rest i
            (fun n => (p.transaction.inputs[n]?).map (fun inp => bigIntToVmNumber (Int.ofNat inp.sequenceNumber.toNat))) false
        | none => s.setErr .minimalEncoding
    | [] => s.setErr .stackUnderflow
  else if op == 0xcc then                               -- OP_OUTPUTVALUE (204): output[i].value
    match s.stack with
    | idx :: rest =>
        match readNum? idx with
        | some i => introspectIndexed s rest i
            (fun n => (p.transaction.outputs[n]?).map (fun o => bigIntToVmNumber (Int.ofNat o.valueSatoshis.toNat))) false
        | none => s.setErr .minimalEncoding
    | [] => s.setErr .stackUnderflow
  else if op == 0xcd then                               -- OP_OUTPUTBYTECODE (205): output[i].locking
    match s.stack with
    | idx :: rest =>
        match readNum? idx with
        | some i => introspectIndexed s rest i (fun n => (p.transaction.outputs[n]?).map (·.lockingBytecode)) true
        | none => s.setErr .minimalEncoding
    | [] => s.setErr .stackUnderflow
  -- ── BCH-2026 CashToken introspection (libauth `bch/2023/bch-2023-tokens.js`, bytes 206..211) ──
  -- UTXO variants: pop an index, read sourceOutputs[i] (like OP_UTXOVALUE 0xc6).
  else if op == 0xce then                               -- OP_UTXOTOKENCATEGORY (206)
    match s.stack with
    | idx :: rest =>
        match readNum? idx with
        | some i => introspectIndexed s rest i
            (fun n => (p.sourceOutputs[n]?).map (fun u => tokenCategoryBytes u.token)) false
        | none => s.setErr .minimalEncoding
    | [] => s.setErr .stackUnderflow
  else if op == 0xcf then                               -- OP_UTXOTOKENCOMMITMENT (207)
    match s.stack with
    | idx :: rest =>
        match readNum? idx with
        | some i => introspectIndexed s rest i
            (fun n => (p.sourceOutputs[n]?).map (fun u => tokenCommitmentBytes u.token)) true
        | none => s.setErr .minimalEncoding
    | [] => s.setErr .stackUnderflow
  else if op == 0xd0 then                               -- OP_UTXOTOKENAMOUNT (208)
    match s.stack with
    | idx :: rest =>
        match readNum? idx with
        | some i => introspectIndexed s rest i
            (fun n => (p.sourceOutputs[n]?).map (fun u => tokenAmountBytes u.token)) false
        | none => s.setErr .minimalEncoding
    | [] => s.setErr .stackUnderflow
  -- OUTPUT variants: pop an index, read transaction.outputs[i] (like OP_OUTPUTVALUE 0xcc).
  else if op == 0xd1 then                               -- OP_OUTPUTTOKENCATEGORY (209)
    match s.stack with
    | idx :: rest =>
        match readNum? idx with
        | some i => introspectIndexed s rest i
            (fun n => (p.transaction.outputs[n]?).map (fun o => tokenCategoryBytes o.token)) false
        | none => s.setErr .minimalEncoding
    | [] => s.setErr .stackUnderflow
  else if op == 0xd2 then                               -- OP_OUTPUTTOKENCOMMITMENT (210)
    match s.stack with
    | idx :: rest =>
        match readNum? idx with
        | some i => introspectIndexed s rest i
            (fun n => (p.transaction.outputs[n]?).map (fun o => tokenCommitmentBytes o.token)) true
        | none => s.setErr .minimalEncoding
    | [] => s.setErr .stackUnderflow
  else if op == 0xd3 then                               -- OP_OUTPUTTOKENAMOUNT (211)
    match s.stack with
    | idx :: rest =>
        match readNum? idx with
        | some i => introspectIndexed s rest i
            (fun n => (p.transaction.outputs[n]?).map (fun o => tokenAmountBytes o.token)) false
        | none => s.setErr .minimalEncoding
    | [] => s.setErr .stackUnderflow
  -- ── BCH signature-checking ops (secp256k1 oracle + `p` sighash context) ──
  else if op == 0xac then opCheckSig crypto p s                        -- OP_CHECKSIG
  else if op == 0xad then                                             -- OP_CHECKSIGVERIFY = CHECKSIG ; VERIFY
    let s' := opCheckSig crypto p s
    if s'.error.isSome then s' else verifyTopInPlace s'
  else if op == 0xba then opCheckDataSig crypto s                      -- OP_CHECKDATASIG
  else if op == 0xbb then                                             -- OP_CHECKDATASIGVERIFY
    let s' := opCheckDataSig crypto s
    if s'.error.isSome then s' else verifyTopInPlace s'
  else if op == 0xae then opCheckMultiSig crypto p s                   -- OP_CHECKMULTISIG
  else if op == 0xaf then                                             -- OP_CHECKMULTISIGVERIFY
    let s' := opCheckMultiSig crypto p s
    if s'.error.isSome then s' else verifyTopInPlace s'
  else if op == 0xbc then                                            -- OP_REVERSEBYTES (libauth opReverseBytes)
    match s.stack with
    | x :: rest => { adv with stack := x.reverse :: rest }
    | []        => s.setErr .stackUnderflow
  -- OP_CHECKLOCKTIMEVERIFY (0xb1) — verify (does NOT pop the locktime), libauth opCheckLockTimeVerify.
  -- Intercepted here so it is NOT the NOP that stepInstr treats 0xb0..0xb9 as.
  else if op == 0xb1 then
    match s.stack with
    | item :: _ =>
        match readLocktime? item with
        | none => s.setErr .minimalEncoding                     -- non-minimal / >5B / negative locktime
        | some required =>
            let txLock := p.transaction.locktime.toNat
            let bothBlock := required < 500000000 && txLock < 500000000
            let bothTime  := required ≥ 500000000 && txLock ≥ 500000000
            let seqFinal  := (p.currentInput.map (fun i => i.sequenceNumber == 0xffffffff)).getD false
            if !(bothBlock || bothTime) then s.setErr .verifyFailed    -- incompatible locktime type
            else if required > txLock then s.setErr .verifyFailed      -- unsatisfied locktime
            else if seqFinal then s.setErr .verifyFailed              -- locktime disabled (final sequence)
            else adv                                                 -- pass; item stays on the stack
    | [] => s.setErr .stackUnderflow
  -- OP_CHECKSEQUENCEVERIFY (0xb2) — relative locktime, libauth opCheckSequenceVerify.
  else if op == 0xb2 then
    match s.stack with
    | item :: _ =>
        match readLocktime? item with
        | none => s.setErr .minimalEncoding
        | some required =>
            let seqN := (p.currentInput.map (fun i => i.sequenceNumber.toNat)).getD 0
            if required &&& 0x80000000 != 0 then adv                  -- disable flag set ⇒ no-op pass
            else if p.transaction.version.toNat < 2 then s.setErr .verifyFailed  -- CSV needs tx version ≥ 2
            else if seqN &&& 0x80000000 != 0 then s.setErr .verifyFailed         -- input disables relative locktime
            else if (required &&& 0x400000) != (seqN &&& 0x400000) then s.setErr .verifyFailed  -- type mismatch
            else if (required &&& 0xffff) > (seqN &&& 0xffff) then s.setErr .verifyFailed        -- unsatisfied
            else adv
    | [] => s.setErr .stackUnderflow
  -- OP_CODESEPARATOR: store sepIp+1 so 0 stays reserved for "no separator" (the frozen core stores
  -- the raw ip, conflating a separator at ip 0 with none — fixed here for OP_ACTIVEBYTECODE).
  else if op == 0xab then { adv with lastCodeSep := s.ip + 1 }
  -- ── Keystone-safe result-size / index guards (the frozen `stepInstr` omits these consensus
  --    gates; we intercept here, so `run_straightline` over `stepInstr` stays untouched) ──
  -- CAT / arithmetic / unary-numeric / MIN-MAX push a result that libauth+BCHN reject when it
  -- exceeds maximumStackItemLength / maximumVmNumberByteLength (both 10000 in 2026). Delegate to the
  -- core, then reject an oversize pushed result.
  else if op == 0x7e || (0x93 ≤ op.toNat && op.toNat ≤ 0x97) || op == 0x8b || op == 0x8c
          || op == 0x8f || op == 0x90 || op == 0xa3 || op == 0xa4 then
    let s' := stepInstr op data s
    match s'.error, s'.stack with
    | none, r :: _ => if r.length > maxItemLen then s'.setErr .itemTooLarge else s'
    | _,    _      => s'
  -- PICK / ROLL / SPLIT: the depth/index must be minimally encoded and non-negative — the core
  -- reads `vmNumberToBigInt · .toNat`, which silently clamps a negative index to 0 and accepts a
  -- non-minimal encoding (both consensus-rejected: n<0 / SCRIPT_VERIFY_MINIMALDATA).
  else if op == 0x79 || op == 0x7a || op == 0x7f then
    match s.stack with
    | idx :: _ =>
        match readNum? idx with
        | some n => if n < 0 then s.setErr .numberTooLarge else stepInstr op data s
        | none   => s.setErr .minimalEncoding
    | [] => s.setErr .stackUnderflow
  else stepInstr op data s                              -- the keystone-proven pure-op core

/-- One extended step (same fExec skip rule as `step1`). -/
def step1Ext (p : Program) (crypto : Secp256k1) (s : State) : State :=
  match s.current? with
  | none        => s
  | some instr  =>
      if s.executionIsActive || Opcode.isConditional instr.opcode
      then stepInstrExt p crypto instr.opcode instr.data s
      else s.advance

/-- Absolute per-input op-cost ceiling = the LARGEST any per-input budget can be:
    `(maximumBytecodeLength 10000 + densityControlBaseLength 41) · operationCostBudgetPerByte 800`.
    A single script run whose accumulated op-cost exceeds this cannot be within ANY real budget, so
    it is cut off HERE (the "withinLimits budget-abort") — this is what rejects an infinite/looping
    or otherwise excessive script PROMPTLY instead of grinding to fuel exhaustion. The exact
    per-input budget is still enforced by the tighter `cost ≤ budget` post-check in `verifyInput`. -/
def maxOpCostCeiling : Nat := (10000 + 41) * 800

/-- BCH_2026_05-pinned op-cost of accumulated metrics (rates mirror `Epoch.operationCost`; local
    pin, like `maxCtrlDepth`, to keep `stepMeterExt` epoch-free). -/
def stepOpCost (m : Cost.Metrics) : Nat :=
  m.evaluatedInstructionCount * 100 + m.signatureCheckCount * 26000
    + m.hashDigestIterations * 64 + m.arithmeticCost + m.stackPushedBytes  -- 64 = CONSENSUS hash factor

/-- The post-step limit gate (libauth's 2026 `every` hook), applied to the already-metrics-assigned
    state: abort if accumulated op-cost exceeds the budget (the withinLimits abort), the control
    stack is too deep, or memory slots are exceeded. **Metrics-preserving** — it only ever sets
    `error`. Factored out of `stepMeterExt` so this invariance is a one-line proof over a plain
    variable (`Invariants.enforceStepLimits_metrics`), the backbone of run-level cost monotonicity. -/
def enforceStepLimits (s' : State) : State :=
  if s'.error.isSome then s'
  else if stepOpCost s'.metrics > s'.budget then s'.setErr .budgetExceeded   -- withinLimits budget-abort
  else if s'.ctrl.length > maxCtrlDepth then s'.setErr .controlStackDepth
  else if s'.stack.length + s'.alt.length + s'.functionTable.length > maxMemorySlots then
    s'.setErr .memorySlots
  else s'

/-- One metered extended step (bills the pre-state `kappa`, then the extended transition). The
    post-step control-stack-depth cap is libauth's `every`-hook check (`state.controlStack.length >
    maximumControlStackDepth`): it fires uniformly for IF/BEGIN nesting AND INVOKE recursion (an
    infinite `OP_INVOKE` piles up return frames and aborts here at depth > 100). The op-cost ceiling
    is the analogous abort for excessive WORK (looping OP_INVERT/shift/etc.). -/
def stepMeterExt (p : Program) (crypto : Secp256k1) (s : State) : State :=
  let stepped := step1Ext p crypto s
  -- Introspection / CashToken byte-push ops (0xc0..0xd3, incl. OP_ACTIVEBYTECODE) push a p-derived
  -- value whose length `kappa` cannot size from the pre-state (no `p`); add its post-state pushed
  -- length here, mirroring BCHN `TallyPushOp` / libauth `pushToStack` (else op-cost under-bills them).
  let introBytes : Nat :=
    match s.current? with
    | some instr =>
        if s.executionIsActive && stepped.error.isNone
           && 0xc0 ≤ instr.opcode.toNat && instr.opcode.toNat ≤ 0xd3
        then widthAt stepped 0 else 0
    | none => 0
  -- ── OP_DEFINE (0x89) function-body op-cost tally (Finding #001 / F0) ──
  -- ACTIVATED BCH-2026 consensus charges OP_DEFINE opCost = baseInstructionCost +
  -- stackPushedBytes(functionBody): BCHN v29.0.0 calls `metrics.TallyPushOp(body.size())` when the
  -- define binds the body. The SUPERSEDED libauth 3.1.0-next.8 billed BASE-ONLY, and `kappa` mirrors
  -- that (DEFINE is not a push/copy op ⇒ it bills `stackPushedBytes := 0`). Add the bound body's byte
  -- length here: on a SUCCESSFUL active define the pre-state stack is `functionId :: functionBody ::`,
  -- so the body is the 2nd item, `widthAt s 1` = `body.size()`. Gate on `stepped.error.isNone` so an
  -- errored DEFINE (excessive id / redefined / underflow ⇒ the script rejects, op-cost moot) and a
  -- branch-skipped one bill nothing — exactly like `introBytes`. Soundness-safe: over-bill never accepts.
  let defineBytes : Nat :=
    match s.current? with
    | some instr =>
        if s.executionIsActive && instr.opcode == 0x89 && stepped.error.isNone
        then widthAt s 1 else 0
    | none => 0
  -- CHECKSIG/CHECKSIGVERIFY hash-iteration correction: kappa bills `1 + hashIterations 0` (serLen=0
  -- placeholder); the real signing-serialization is `1 + hashIterations serLen`. Add the difference
  -- (`hashIterations serLen − 1`) here where `p` + the codesep-trimmed covered bytecode are known.
  -- Non-empty sig only (an empty sig does no sighash). Sound (over-bill never wrong-accepts).
  let sigHashExtra : Nat :=
    match s.current? with
    | some instr =>
        if s.executionIsActive && (instr.opcode == 0xac || instr.opcode == 0xad) then
          match s.stack with
          | _ :: sig :: _ =>
              if sig.isEmpty then 0
              else
                let sht : UInt32 := UInt32.ofNat (sig.getLast?.getD 0).toNat
                Cost.hashIterations (Tx.encodeSigningSerialization p (coveredBytecode s) sht).length - 1
          | _ => 0
        else 0
    | none => 0
  -- CHECKMULTISIG/CHECKMULTISIGVERIFY per-verified-sig hash-iteration correction: `kappa` bills the
  -- sig-CHECK count (`multiSigCost nKeys`) but ZERO hash iterations, so each signature's signing
  -- serialization is un-billed. Add `hashIterations serLen` per NON-NULL sig (each computes its own
  -- sighash once, over the codesep-trimmed covered bytecode + that sig's sighash-type byte), mirroring
  -- `opCheckMultiSig`'s exact `<dummy><sig₁..sig_M><M><pk₁..pk_N><N>` layout. Sound + inert on the
  -- reject-oracle (a non-null-sig multisig NULLFAILs, so the op errors before the budget check).
  let multiSigHashExtra : Nat :=
    match s.current? with
    | some instr =>
        if s.executionIsActive && (instr.opcode == 0xae || instr.opcode == 0xaf) then
          match s.stack with
          | nItem :: rest0 =>
              match readNum? nItem with
              | some nI =>
                  if nI < 0 ∨ nI > 20 then 0
                  else match rest0.drop nI.toNat with
                    | mItem :: rest2 =>
                        match readNum? mItem with
                        | some mI =>
                            if mI < 0 ∨ mI > nI then 0
                            else (rest2.take mI.toNat).foldl (fun acc sig =>
                              if sig.isEmpty then acc
                              else
                                let sht : UInt32 := UInt32.ofNat (sig.getLast?.getD 0).toNat
                                acc + Cost.hashIterations
                                  (Tx.encodeSigningSerialization p (coveredBytecode s) sht).length) 0
                        | none => 0
                    | [] => 0
              | none => 0
          | [] => 0
        else 0
    | none => 0
  let s' := { stepped with metrics :=
                s.metrics + kappa s +
                  { stackPushedBytes := introBytes + defineBytes, hashDigestIterations := sigHashExtra + multiSigHashExtra } }
  enforceStepLimits s'

/-- Metered extended run (fuel-driven). Replaces the plain `finished` test with libauth's `continue`
    loop: an error stops; while the current instructions are exhausted (`ip ≥ size`) with a RETURN
    FRAME on top of the control stack, pop it and resume the caller (a return — NO op cost / no
    `kappa`); otherwise, if there is an instruction to run, step; else the run is genuinely finished
    (`ip ≥ size` with no frame — an empty/dangling-cond control stack). -/
def runExt (p : Program) (crypto : Secp256k1) : Nat → State → State
  | 0,   s => s
  | f+1, s =>
      if s.error.isSome then s
      else if s.ip < s.instrs.size then
        runExt p crypto f (stepMeterExt p crypto s)
      else
        match s.ctrl with
        | Ctrl.frame retInstrs retIp :: rest =>
            runExt p crypto f { s with instrs := retInstrs, ip := retIp, ctrl := rest }
        | _ => s

/-! ## Introspection witnesses — a hand-built Program run through `stepInstrExt`.

    `decide` reduces the concrete transition (fuel-free `magBytes` / no `native_decide`), so the
    equalities below are KERNEL-checked; the `#eval`s print the same values. Cross-checked to
    libauth `common/inspection.js`. -/

/-- A hand-built program: input **1** under evaluation, a distinctive 32-byte outpoint hash on
    input 0 (`0x01..0x20`, to exhibit wire-reversal), two source UTXOs, two outputs. -/
def demoProg : Program :=
  let hash0 : Bytes := (List.range 32).map (fun i => UInt8.ofNat (i + 1))    -- 0x01 .. 0x20
  { transaction :=
      { version := 2
        inputs := #[
          { outpointTransactionHash := hash0, outpointIndex := 3,
            unlockingBytecode := [0x51, 0x52], sequenceNumber := 0xfffffffe },
          { outpointTransactionHash := List.replicate 32 (0xAA : UInt8), outpointIndex := 0,
            unlockingBytecode := [], sequenceNumber := 0 } ]
        outputs := #[
          { valueSatoshis := 1000, lockingBytecode := [0x6a, 0x01, 0x99], token := none },
          { valueSatoshis := 4242, lockingBytecode := [0x51], token := none } ]
        locktime := 500000 }
    sourceOutputs := #[
      { valueSatoshis := 6000, lockingBytecode := [0x76, 0xa9], token := none },
      { valueSatoshis := 9000, lockingBytecode := [0x52], token := none } ]
    inputIndex := 1 }

/-- Run one introspection opcode on `demoProg` from an initial stack; return the result stack.
    (The oracle is irrelevant to the introspection ops — `reject` is a fine inert default.) -/
def fire (op : UInt8) (stk : Stack) : Stack :=
  (stepInstrExt demoProg Secp256k1.reject op [] { stack := stk }).stack

-- OP_REVERSEBYTES (0xbc): pop the top item, push its byte-reverse -------------
#eval fire 0xbc [[0x01, 0x02, 0x03]]  -- OP_REVERSEBYTES → [[0x03,0x02,0x01]]
example : fire 0xbc [[0x01, 0x02, 0x03]] = [[0x03, 0x02, 0x01]] := by decide
example : (stepInstrExt demoProg Secp256k1.reject 0xbc [] { stack := [] }).error
    = some .stackUnderflow := by decide
-- Nullary ops -----------------------------------------------------------------
#eval fire 0xc0 []                    -- OP_INPUTINDEX  → 1        = [[0x01]]
#eval fire 0xc2 []                    -- OP_TXVERSION   → 2        = [[0x02]]
-- OP_TXINPUTCOUNT / OP_TXOUTPUTCOUNT — asserted (red-team: were bare prints, the sole witness for
-- these two introspection ops, which the `decide` block below does not cover).
example : fire 0xc3 [] = [[0x02]] := by decide   -- OP_TXINPUTCOUNT  → 2
example : fire 0xc4 [] = [[0x02]] := by decide   -- OP_TXOUTPUTCOUNT → 2
#eval fire 0xc5 []                    -- OP_TXLOCKTIME  → 500000   = [[0x20,0xa1,0x07]]
-- Index-popping ops -----------------------------------------------------------
#eval fire 0xc6 [bigIntToVmNumber 0]  -- OP_UTXOVALUE   [i=0] → 6000  = [[0x70,0x17]]
#eval fire 0xcc [bigIntToVmNumber 1]  -- OP_OUTPUTVALUE [i=1] → 4242  = [[0x92,0x10]]
#eval fire 0xc8 [bigIntToVmNumber 0]  -- OP_OUTPOINTTXHASH [i=0] → hash0 REVERSED (0x20..0x01)
#eval fire 0xcb [bigIntToVmNumber 0]  -- OP_INPUTSEQUENCENUMBER [i=0] → 0xfffffffe UNSIGNED
#eval fire 0xcd [bigIntToVmNumber 0]  -- OP_OUTPUTBYTECODE [i=0] → [[0x6a,0x01,0x99]]
#eval (stepInstrExt demoProg Secp256k1.reject 0xcc [] { stack := [bigIntToVmNumber 9] }).error
                                      -- out-of-range index → some invalidTxIndex

-- Kernel-checked assertions (a representative subset) --------------------------
example : fire 0xc0 [] = [[0x01]] := by decide                        -- inputIndex 1
example : fire 0xc2 [] = [[0x02]] := by decide                        -- version 2
example : fire 0xc5 [] = [[0x20, 0xa1, 0x07]] := by decide            -- locktime 500000
example : fire 0xc6 [bigIntToVmNumber 0] = [[0x70, 0x17]] := by decide          -- UTXO value 6000
example : fire 0xcc [bigIntToVmNumber 1] = [[0x92, 0x10]] := by decide          -- output 1 value 4242
-- OP_OUTPOINTTXHASH pushes the WIRE-order (reversed) hash: 0x20,0x1f,…,0x01
example : fire 0xc8 [bigIntToVmNumber 0]
    = [((List.range 32).map (fun i => UInt8.ofNat (i + 1))).reverse] := by decide
-- sequence number is UNSIGNED (0xfffffffe → 4294967294, not -2): 5-byte positive VM number
example : fire 0xcb [bigIntToVmNumber 0] = [[0xfe, 0xff, 0xff, 0xff, 0x00]] := by decide
example : fire 0xcd [bigIntToVmNumber 0] = [[0x6a, 0x01, 0x99]] := by decide    -- output 0 bytecode
-- out-of-range index rejects
example : (stepInstrExt demoProg Secp256k1.reject 0xcc [] { stack := [bigIntToVmNumber 9] }).error
    = some .invalidTxIndex := by decide
-- negative index rejects (bigIntToVmNumber (-1) = [0x81])
example : (stepInstrExt demoProg Secp256k1.reject 0xc6 [] { stack := [bigIntToVmNumber (-1)] }).error
    = some .invalidTxIndex := by decide

/-! ## CashToken introspection witnesses — a token-bearing Program through `stepInstrExt`.

    `demoTokenProg` (input 0 under evaluation) carries tokens exercising every case:
      • sourceOutputs[0]: minting NFT (suffix 0x02) + fungible amount 100 + commitment `ca fe`
      • sourceOutputs[1]: NO token
      • outputs[0]:       mutable NFT (suffix 0x01) + amount 0 + commitment `de ad be ef`
      • outputs[1]:       fungible-only (NO NFT ⇒ no suffix, empty commitment) + amount 42
    Cross-checked to libauth `pushTokenExtendedCategory`/`pushTokenCommitment`/`pushTokenAmount`. -/

/-- A distinctive 32-byte category `0x01 … 0x20` in UI/storage order; the ops push it REVERSED
    (wire order, `0x20 … 0x01`) with a capability suffix, exactly libauth's `category.reverse()`. -/
def demoCat : Bytes := (List.range 32).map (fun i => UInt8.ofNat (i + 1))

def demoTokenProg : Program :=
  { transaction :=
      { version := 2
        inputs := #[
          { outpointTransactionHash := List.replicate 32 (0x00 : UInt8)
            outpointIndex := 0
            unlockingBytecode := []
            sequenceNumber := 0 } ]
        outputs := #[
          { valueSatoshis := 1000
            lockingBytecode := [0x51]
            token := some
              { category := demoCat
                amount := 0
                nft := some { capability := .mutable, commitment := [0xde, 0xad, 0xbe, 0xef] } } },
          { valueSatoshis := 2000
            lockingBytecode := [0x52]
            token := some { category := demoCat, amount := 42, nft := none } } ]
        locktime := 0 }
    sourceOutputs := #[
      { valueSatoshis := 6000
        lockingBytecode := [0x51]
        token := some
          { category := demoCat
            amount := 100
            nft := some { capability := .minting, commitment := [0xca, 0xfe] } } },
      { valueSatoshis := 9000, lockingBytecode := [0x52], token := none } ]
    inputIndex := 0 }

/-- Fire one token opcode on `demoTokenProg` from an initial stack; return the result stack. -/
def fireTok (op : UInt8) (stk : Stack) : Stack :=
  (stepInstrExt demoTokenProg Secp256k1.reject op [] { stack := stk }).stack

-- UTXO variants (read sourceOutputs[i]) ---------------------------------------
#eval fireTok 0xce [bigIntToVmNumber 0]   -- OP_UTXOTOKENCATEGORY   [i=0] → cat.rev ++ [0x02] (minting)
#eval fireTok 0xcf [bigIntToVmNumber 0]   -- OP_UTXOTOKENCOMMITMENT [i=0] → [0xca,0xfe]
#eval fireTok 0xd0 [bigIntToVmNumber 0]   -- OP_UTXOTOKENAMOUNT     [i=0] → 100 = [0x64]
#eval fireTok 0xce [bigIntToVmNumber 1]   -- OP_UTXOTOKENCATEGORY   [i=1] → no token → []
#eval fireTok 0xd0 [bigIntToVmNumber 1]   -- OP_UTXOTOKENAMOUNT     [i=1] → no token → []
-- OUTPUT variants (read transaction.outputs[i]) -------------------------------
#eval fireTok 0xd1 [bigIntToVmNumber 0]   -- OP_OUTPUTTOKENCATEGORY   [i=0] → cat.rev ++ [0x01] (mutable)
#eval fireTok 0xd2 [bigIntToVmNumber 0]   -- OP_OUTPUTTOKENCOMMITMENT [i=0] → [0xde,0xad,0xbe,0xef]
#eval fireTok 0xd3 [bigIntToVmNumber 0]   -- OP_OUTPUTTOKENAMOUNT     [i=0] → 0 → []
#eval fireTok 0xd1 [bigIntToVmNumber 1]   -- OP_OUTPUTTOKENCATEGORY   [i=1] → cat.rev (NO suffix, fungible)
#eval fireTok 0xd2 [bigIntToVmNumber 1]   -- OP_OUTPUTTOKENCOMMITMENT [i=1] → no NFT → []
#eval fireTok 0xd3 [bigIntToVmNumber 1]   -- OP_OUTPUTTOKENAMOUNT     [i=1] → 42 = [0x2a]

-- Kernel-checked assertions (fuel-free `decide`, no `native_decide`) -----------
-- CATEGORY: minting UTXO token ⇒ 32 wire-order (reversed) bytes + suffix 0x02.
example : fireTok 0xce [bigIntToVmNumber 0] = [demoCat.reverse ++ [0x02]] := by decide
-- CATEGORY: mutable output token ⇒ reversed category + suffix 0x01.
example : fireTok 0xd1 [bigIntToVmNumber 0] = [demoCat.reverse ++ [0x01]] := by decide
-- CATEGORY: fungible-only (no NFT) ⇒ reversed category, NO suffix.
example : fireTok 0xd1 [bigIntToVmNumber 1] = [demoCat.reverse] := by decide
-- CATEGORY: absent token ⇒ empty push.
example : fireTok 0xce [bigIntToVmNumber 1] = [[]] := by decide
-- COMMITMENT: NFT present ⇒ its commitment; no NFT / no token ⇒ empty.
example : fireTok 0xcf [bigIntToVmNumber 0] = [[0xca, 0xfe]] := by decide
example : fireTok 0xd2 [bigIntToVmNumber 0] = [[0xde, 0xad, 0xbe, 0xef]] := by decide
example : fireTok 0xd2 [bigIntToVmNumber 1] = [[]] := by decide          -- fungible-only ⇒ no commitment
-- AMOUNT: fungible amount as a minimal VM number; 0 / no token ⇒ empty.
example : fireTok 0xd0 [bigIntToVmNumber 0] = [[0x64]] := by decide      -- 100
example : fireTok 0xd3 [bigIntToVmNumber 1] = [[0x2a]] := by decide      -- 42
example : fireTok 0xd3 [bigIntToVmNumber 0] = [[]] := by decide          -- amount 0 → []
example : fireTok 0xd0 [bigIntToVmNumber 1] = [[]] := by decide          -- no token → []
-- Out-of-range / negative index reject with invalidTxIndex.
example : (stepInstrExt demoTokenProg Secp256k1.reject 0xd1 [] { stack := [bigIntToVmNumber 9] }).error
    = some .invalidTxIndex := by decide
example : (stepInstrExt demoTokenProg Secp256k1.reject 0xce [] { stack := [bigIntToVmNumber (-1)] }).error
    = some .invalidTxIndex := by decide
-- BUDGET ABORT (M2): accumulated op-cost over budget ⇒ the purpose-built `budgetExceeded`, NOT a
-- generic `itemTooLarge`. One instruction (op-cost 100) already exceeds a 0 budget; within budget
-- (100 ≤ 100) it passes clean (no error).
example : (enforceStepLimits { budget := 0, metrics := { evaluatedInstructionCount := 1 } }).error
    = some .budgetExceeded := by decide
example : (enforceStepLimits { budget := 100, metrics := { evaluatedInstructionCount := 1 } }).error
    = none := by decide

/-! ## Signature-op witnesses — a MOCK secp256k1 oracle drives the accept/reject seam.

    The vmb signature corpus needs REAL curve signatures (outside this mathlib-free core), so the
    sig families cannot be conformance-numbered. Instead we drive the PLUMBING with stub oracles:
    an accept-all stub, a digest-checking stub (proving the digest handed to the oracle is exactly
    `Tx.sighashDigest`), a tag-matching stub (for in-order multisig matching), and
    `Secp256k1.reject`. These are `#eval` witnesses (the endorsed acceptance seam — no
    `native_decide`, no kernel SHA-256 blow-up); `guard` throws at BUILD time on a mismatch. -/

/-- Accept-everything stub oracle. -/
def acceptAll : Secp256k1 := ⟨fun _ _ _ => true, fun _ _ _ => true⟩

/-- Accept iff the digest handed to the oracle equals `expected` (either algorithm). -/
def acceptIfDigest (expected : Bytes) : Secp256k1 :=
  ⟨fun _ _ d => d == expected, fun _ _ d => d == expected⟩

/-- Tag-matching stub: a signature whose body equals the public key verifies (ECDSA path). -/
def acceptTagMatch : Secp256k1 :=
  ⟨fun _ _ _ => false, fun body pk _ => body == pk⟩

/-- Fire one sig opcode: build a bare state with `stk` on the stack and covered bytecode `sc`. -/
def fireSig (crypto : Secp256k1) (p : Program) (op : UInt8) (sc : Bytes) (stk : Stack) : State :=
  -- seed `instrs` from `sc` so the codeseparator-aware `coveredBytecode` re-encodes back to `sc`.
  stepInstrExt p crypto op [] { stack := stk, scriptCode := sc,
                                instrs := (match parse sc with | .ok is => is | .malformed is => is) }

open LeanBCH.Tx (exampleProgram sighashDigest)

/-- A 65-byte bitcoin-encoded Schnorr signature: a 64-byte body + the 0x41 (ALL|FORKID) sighash. -/
def schnorrSig : Bytes := List.replicate 64 (0xAB : UInt8) ++ [0x41]
def demoPubkey : Bytes := List.replicate 33 (0x02 : UInt8)
def demoCov : Bytes := [0x51]        -- the covered bytecode used by the Sighash KAT

private def guard (name : String) (cond : Bool) : IO Unit := do
  unless cond do throw (IO.userError s!"[CHECKSIG witness] {name}")

-- CHECKSIG · accept stub ⇒ pushes true [0x01].
#eval (fireSig acceptAll exampleProgram 0xac demoCov [demoPubkey, schnorrSig]).stack
#eval guard "checksig accept ⇒ true"
  ((fireSig acceptAll exampleProgram 0xac demoCov [demoPubkey, schnorrSig]).stack == [[1]])
-- CHECKSIG · EMPTY sig ⇒ false [], and NO error.
#eval guard "checksig empty-sig ⇒ false"
  ((fireSig acceptAll exampleProgram 0xac demoCov [demoPubkey, []]).stack == [[]])
#eval guard "checksig empty-sig ⇒ no error"
  ((fireSig acceptAll exampleProgram 0xac demoCov [demoPubkey, []]).error == none)
-- CHECKSIG · NULLFAIL: reject stub + NON-empty sig ⇒ ERROR (not a false push).
#eval guard "checksig NULLFAIL ⇒ error"
  ((fireSig Secp256k1.reject exampleProgram 0xac demoCov [demoPubkey, schnorrSig]).error.isSome)
-- The digest handed to the oracle IS `Tx.sighashDigest exampleProgram demoCov 0x41`: the
-- digest-checking stub accepts, so the pushed verdict is true.  (sighashDigest itself is the
-- byte-exact, libauth-cross-checked value pinned in `Tx.Sighash`.)
#eval guard "checksig digest = sighashDigest exampleProgram demoCov 0x41"
  ((fireSig (acceptIfDigest (sighashDigest exampleProgram demoCov 0x41))
      exampleProgram 0xac demoCov [demoPubkey, schnorrSig]).stack == [[1]])
-- CHECKSIGVERIFY · accept ⇒ consumes the true and continues (stack emptied, no error).
#eval guard "checksigverify accept ⇒ ok"
  (let r := fireSig acceptAll exampleProgram 0xad demoCov [demoPubkey, schnorrSig]
   r.error == none && r.stack == ([] : Stack))

-- CHECKDATASIG · digest = sha256(message); accept ⇒ true.
def cdsMsg : Bytes := [0xDE, 0xAD, 0xBE, 0xEF]
def cdsRaw : Bytes := List.replicate 64 (0x07 : UInt8)     -- 64-byte raw Schnorr data-sig (no sighash byte)
#eval guard "checkdatasig accept ⇒ true"
  ((fireSig acceptAll exampleProgram 0xba [] [demoPubkey, cdsMsg, cdsRaw]).stack == [[1]])
#eval guard "checkdatasig digest = sha256(message)"
  ((fireSig (acceptIfDigest (Crypto.sha256 cdsMsg)) exampleProgram 0xba [] [demoPubkey, cdsMsg, cdsRaw]).stack == [[1]])
#eval guard "checkdatasig empty-sig ⇒ false, no error"
  (let r := fireSig acceptAll exampleProgram 0xba [] [demoPubkey, cdsMsg, []]
   r.stack == [[]] && r.error == none)
#eval guard "checkdatasig NULLFAIL ⇒ error"
  ((fireSig Secp256k1.reject exampleProgram 0xba [] [demoPubkey, cdsMsg, cdsRaw]).error.isSome)

-- CHECKMULTISIG · 2-of-3, IN ORDER (tag-matching stub). Public keys pk₁<pk₂<pk₃ (tags A/B/C);
-- the two sigs cover pk₁ and pk₃. Stack top→bottom: n=3, pk₃,pk₂,pk₁, m=2, sig₃,sig₁, dummy=[].
def pkA : Bytes := [0xA1]
def pkB : Bytes := [0xB2]
def pkC : Bytes := [0xC3]
def sigFor (pk : Bytes) : Bytes := pk ++ [0x41]            -- body = pk (ECDSA path), + sighash byte
def cmsStackInOrder : Stack :=
  [bigIntToVmNumber 3, pkC, pkB, pkA, bigIntToVmNumber 2, sigFor pkC, sigFor pkA, []]
#eval (fireSig acceptTagMatch exampleProgram 0xae demoCov cmsStackInOrder).stack
#eval guard "multisig 2-of-3 in order ⇒ true"
  ((fireSig acceptTagMatch exampleProgram 0xae demoCov cmsStackInOrder).stack == [[1]])
-- OUT-OF-ORDER sigs (sig₃ deep, sig₁ on top) ⇒ greedy match fails ⇒ NULLFAIL error.
def cmsStackOutOfOrder : Stack :=
  [bigIntToVmNumber 3, pkC, pkB, pkA, bigIntToVmNumber 2, sigFor pkA, sigFor pkC, []]
#eval guard "multisig out-of-order ⇒ NULLFAIL error"
  ((fireSig acceptTagMatch exampleProgram 0xae demoCov cmsStackOutOfOrder).error.isSome)
-- All-null sigs (0-of-3 with both slots empty) ⇒ false, NO NULLFAIL error.
#eval guard "multisig all-null ⇒ false, no error"
  (let r := fireSig acceptTagMatch exampleProgram 0xae demoCov
              [bigIntToVmNumber 3, pkC, pkB, pkA, bigIntToVmNumber 2, [], [], []]
   r.stack == [[]] && r.error == none)
-- Non-empty dummy element ⇒ the Schnorr-multisig checkbits path, DEFERRED (unimplemented error).
#eval guard "multisig non-empty dummy ⇒ deferred"
  ((fireSig acceptTagMatch exampleProgram 0xae demoCov
      [bigIntToVmNumber 1, pkA, bigIntToVmNumber 1, sigFor pkA, [0x01]]).error == some .unimplemented)

end LeanBCH.VM
