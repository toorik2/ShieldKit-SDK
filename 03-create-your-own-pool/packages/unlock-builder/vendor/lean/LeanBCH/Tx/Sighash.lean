/-
  LeanBCH.Tx.Sighash — the BCH signing serialization (14-field preimage) + sighash digest.

  Transcribed byte-for-byte from `@bitauth/libauth` 3.1.0-next.8
  `vm/instruction-sets/common/signing-serialization.js`:
  `encodeSigningSerializationBch` (the flattened field list) and its flag helpers
  `shouldSerializeSingleInput`/`shouldSerializeCorrespondingOutput`/
  `shouldSerializeNoOutputs`/`shouldSerializeUtxos`.

  Flag decode (over the low sighash byte, `type[0]`):
    ANYONECANPAY (single input) = `type & 0x80`
    CORRESPONDING output (SINGLE) = `(type & 0x1f) == 3`
    NO outputs (NONE)            = `(type & 0x1f) == 2`
    UTXOS                        = `type & 0x20`

  The `signingSerializationType` field emits the SINGLE low byte of the sighash type
  (libauth takes `encodedSignature.slice(-1)`); the high 3 bytes of the classic 4-byte
  BCH `nHashType` are the separate `forkId` field (default `[0,0,0]`, i.e. BCH fork id 0).

  The digest stays ABSTRACT over `hash256` here; the concrete digest is asserted only at
  the `#eval` conformance seam at the bottom (cross-checked against real libauth).
-/
import LeanBCH.Tx.Encoding

namespace LeanBCH.Tx

open LeanBCH
open LeanBCH.Crypto (hash256)

/-! ## Sighash-type flag decode (libauth `match`/`equals` over `type[0]`) -/

/-- ANYONECANPAY / single-input: `type & 0x80 ≠ 0`. -/
@[inline] def sigHashSingleInput (ty : UInt32) : Bool := (ty &&& 0x80) != 0
/-- SINGLE / corresponding-output: `(type & 0x1f) == 3`. -/
@[inline] def sigHashCorrespondingOutput (ty : UInt32) : Bool := (ty &&& 0x1f) == 3
/-- NONE / no-outputs: `(type & 0x1f) == 2`. -/
@[inline] def sigHashNoOutputs (ty : UInt32) : Bool := (ty &&& 0x1f) == 2
/-- UTXOS: `type & 0x20 ≠ 0`. -/
@[inline] def sigHashUtxos (ty : UInt32) : Bool := (ty &&& 0x20) != 0

/-! ## The 14-field signing serialization -/

/--
  The BCH signing serialization preimage for the input under evaluation in `p`,
  covering `coveredBytecode` with sighash type `sigHashType` (and BCH `forkId`,
  default `[0,0,0]`). A pure `Bytes` concat, field-for-field with libauth
  `encodeSigningSerializationBch`:

  1. `version` (4LE)
  2. `hashPrevouts` (gated by ANYONECANPAY)
  3. `hashUtxos` (gated by UTXOS — LENGTH-0 when absent)
  4. `hashSequence` (gated by ANYONECANPAY/SINGLE/NONE)
  5. reverse(`outpointTransactionHash`) — wire order
  6. `outpointIndex` (4LE)
  7. `outputTokenPrefix` — token prefix of the SPENT output (sourceOutputs[inputIndex])
  8. `compactUint(|coveredBytecode|)`
  9. `coveredBytecode`
  10. `outputValue` — value of the spent output (8LE)
  11. `sequenceNumber` (4LE)
  12. `hashOutputs` (gated by SINGLE/NONE)
  13. `locktime` (4LE)
  14. `signingSerializationType` (low byte) ++ `forkId` (3 bytes)

  Totality: an out-of-range `inputIndex` falls back to a zero input / empty spent output
  (never partial); in-range is the only consensus-relevant case. -/
def encodeSigningSerialization (p : Program) (coveredBytecode : Bytes)
    (sigHashType : UInt32) (forkId : Bytes := [0, 0, 0]) : Bytes :=
  let t := p.transaction
  let anyoneCanPay := sigHashSingleInput sigHashType
  let single := sigHashCorrespondingOutput sigHashType
  let noOutputs := sigHashNoOutputs sigHashType
  let utxos := sigHashUtxos sigHashType
  let inp := p.currentInput.getD
    { outpointTransactionHash := [], outpointIndex := 0, unlockingBytecode := [], sequenceNumber := 0 }
  let srcOut := p.currentSourceOutput.getD
    { valueSatoshis := 0, lockingBytecode := [], token := none }
  uint32LE t.version
    ++ hashPrevouts t anyoneCanPay
    ++ hashUtxos p.sourceOutputs utxos
    ++ hashSequence t anyoneCanPay single noOutputs
    ++ inp.outpointTransactionHash.reverse
    ++ uint32LE inp.outpointIndex
    ++ encodeTokenPrefix srcOut.token
    ++ compactUint coveredBytecode.length
    ++ coveredBytecode
    ++ uint64LE srcOut.valueSatoshis
    ++ uint32LE inp.sequenceNumber
    ++ hashOutputs t p.inputIndex single noOutputs
    ++ uint32LE t.locktime
    ++ uint8 sigHashType.toUInt8
    ++ forkId

/-- The BCH sighash digest = `hash256` (SHA-256d) of the signing serialization. -/
def sighashDigest (p : Program) (coveredBytecode : Bytes)
    (sigHashType : UInt32) (forkId : Bytes := [0, 0, 0]) : Bytes :=
  hash256 (encodeSigningSerialization p coveredBytecode sigHashType forkId)

/-! ## Abstract structural facts (hash-free / hash-abstract) -/

-- Flag decode: standard BCH sighash types.
-- 0x41 = ALL|FORKID: not SINGLE, not NONE, not ANYONECANPAY, not UTXOS.
example : sigHashCorrespondingOutput 0x41 = false := by decide
example : sigHashNoOutputs 0x41 = false := by decide
example : sigHashSingleInput 0x41 = false := by decide
example : sigHashUtxos 0x41 = false := by decide
-- 0x61 = ALL|UTXOS|FORKID: UTXOS on.
example : sigHashUtxos 0x61 = true := by decide
-- 0xc3 = SINGLE|ANYONECANPAY|FORKID: SINGLE + single-input.
example : sigHashCorrespondingOutput 0xc3 = true := by decide
example : sigHashSingleInput 0xc3 = true := by decide
-- 0x42 = NONE|FORKID.
example : sigHashNoOutputs 0x42 = true := by decide

/-! ## libauth conformance seam — BUILD-TIME cross-check (the trust anchor)

  Each `#eval` runs during `lake build`; a mismatch `throw`s `IO.userError` and FAILS the
  build. The expected hex was produced by running real `@bitauth/libauth` 3.1.0-next.8
  (`encodeSigningSerializationBch` + component encoders + `hash256`) on `Tx.exampleProgram`
  (the 2-in / 2-out program from `Tx.Types`, one token output, evaluating input 0), covered
  bytecode `[0x51]`. This is the byte-for-byte trust anchor for the whole sig path — the
  digest is concrete ONLY here; every other decl stays abstract over `hash256`. -/

open LeanBCH.Crypto (toHex)

private def katS (name expected got : String) : IO Unit := do
  unless got = expected do
    throw (IO.userError s!"[Sighash KAT] {name}: expected {expected}, got {got}")

-- Component encoders (hashless byte streams) vs libauth.
#eval katS "transactionOutpoints"
  "111111111111111111111111111111111111111111111111111111111111111100000000222222222222222222222222222222222222222222222222222222222222222207000000"
  (toHex (transactionOutpoints Tx.exampleProgram.transaction))
#eval katS "transactionSequenceNumbers"
  "ffffffff00000000"
  (toHex (transactionSequenceNumbers Tx.exampleProgram.transaction))
#eval katS "transactionOutputs (for signing)"
  "e8030000000000000276a9921000000000000027efabababababababababababababababababababababababababababababababab7102dead646a"
  (toHex (transactionOutputs Tx.exampleProgram.transaction))
#eval katS "transactionUtxos (source outputs)"
  "7017000000000000015128230000000000000152"
  (toHex (transactionUtxos Tx.exampleProgram.sourceOutputs))
#eval katS "encodeTokenPrefix (output 1 token)"
  "efabababababababababababababababababababababababababababababababab7102dead64"
  (toHex (encodeTokenPrefix (Tx.exampleProgram.transaction.outputs[1]!).token))
#eval katS "encodeOutput (output 1, token)"
  "921000000000000027efabababababababababababababababababababababababababababababababab7102dead646a"
  (toHex (encodeOutput (Tx.exampleProgram.transaction.outputs[1]!)))

-- Full 14-field serialization + SHA-256d digest vs libauth, across the sighash-type matrix:
--   0x41 ALL|FORKID · 0x61 ALL|UTXOS|FORKID · 0xc3 SINGLE|ANYONECANPAY|FORKID
--   0x42 NONE|FORKID · 0x43 SINGLE|FORKID
private def cov : Bytes := [0x51]

#eval katS "serialization 0x41"
  "0200000009fd2aff5f2d8b52169b79ce9fdbcf4f7934c1c0d845123b997e4c92be7767578672e0f0352462953276cdb32a23bb15677fc5eea97f5025164ba03359d572b111111111111111111111111111111111111111111111111111111111111111110000000001517017000000000000ffffffff436a2e636e0eab82aa845c88bc655b2080b06adfab99ecbdf9d2b564571e8bd820a1070041000000"
  (toHex (encodeSigningSerialization Tx.exampleProgram cov 0x41))
#eval katS "digest 0x41"
  "301307fa2d1c9e3d29046cb16f72ea418182d147596f0ec710fe10d5499abc97"
  (toHex (sighashDigest Tx.exampleProgram cov 0x41))

#eval katS "serialization 0x61 (UTXOS)"
  "0200000009fd2aff5f2d8b52169b79ce9fdbcf4f7934c1c0d845123b997e4c92be7767572a56bb4c7ffabdadb252dd85927ec9f150e282d16d09d5a7d17f7a47213d5d2f8672e0f0352462953276cdb32a23bb15677fc5eea97f5025164ba03359d572b111111111111111111111111111111111111111111111111111111111111111110000000001517017000000000000ffffffff436a2e636e0eab82aa845c88bc655b2080b06adfab99ecbdf9d2b564571e8bd820a1070061000000"
  (toHex (encodeSigningSerialization Tx.exampleProgram cov 0x61))
#eval katS "digest 0x61 (UTXOS)"
  "fe3a4f43a632001f88511b293de523390ef064a121f1f9b3bd7c3e2876871836"
  (toHex (sighashDigest Tx.exampleProgram cov 0x61))

#eval katS "serialization 0xc3 (SINGLE|ANYONECANPAY)"
  "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011111111111111111111111111111111111111111111111111111111111111110000000001517017000000000000ffffffff8a7561a0f325608385b738e9cc5d4f82c5596e85e61cd2f18638076477fc0cb520a10700c3000000"
  (toHex (encodeSigningSerialization Tx.exampleProgram cov 0xc3))
#eval katS "digest 0xc3 (SINGLE|ANYONECANPAY)"
  "20043ec130ae557a0079c111f85d77f812b13673616ab2955245cd3a2e4635fa"
  (toHex (sighashDigest Tx.exampleProgram cov 0xc3))

#eval katS "serialization 0x42 (NONE)"
  "0200000009fd2aff5f2d8b52169b79ce9fdbcf4f7934c1c0d845123b997e4c92be776757000000000000000000000000000000000000000000000000000000000000000011111111111111111111111111111111111111111111111111111111111111110000000001517017000000000000ffffffff000000000000000000000000000000000000000000000000000000000000000020a1070042000000"
  (toHex (encodeSigningSerialization Tx.exampleProgram cov 0x42))
#eval katS "digest 0x42 (NONE)"
  "497c49436eae4b1e134fd6606ccda7bb62b0dae98bc0e0c40fc6535d12e9a336"
  (toHex (sighashDigest Tx.exampleProgram cov 0x42))

#eval katS "serialization 0x43 (SINGLE)"
  "0200000009fd2aff5f2d8b52169b79ce9fdbcf4f7934c1c0d845123b997e4c92be776757000000000000000000000000000000000000000000000000000000000000000011111111111111111111111111111111111111111111111111111111111111110000000001517017000000000000ffffffff8a7561a0f325608385b738e9cc5d4f82c5596e85e61cd2f18638076477fc0cb520a1070043000000"
  (toHex (encodeSigningSerialization Tx.exampleProgram cov 0x43))
#eval katS "digest 0x43 (SINGLE)"
  "7c4623d988f4dbc1dc5550a0dd56feac32ed219d4aa6422a222b6f05e541bd46"
  (toHex (sighashDigest Tx.exampleProgram cov 0x43))

end LeanBCH.Tx
