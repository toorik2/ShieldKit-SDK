/-
  LeanBCH.Tx.Types — the transaction / UTXO context record types.

  These records mirror `@bitauth/libauth` (pin 3.1.0-next.8) EXACTLY, faithful to:
    - `build/lib/message/transaction-types.d.ts:11-215`  (Input, Output, TokenData,
      NonFungibleTokenCapability, TransactionCommon)
    - `build/lib/vm/vm-types.d.ts:89-99`  (ResolvedTransactionCommon, AuthenticationProgramCommon)

  This is Phase-1 Lane B, but it is INDEPENDENT of the VM: pure records over
  `Bytes := List UInt8`. It lands now to unblock the sighash (Phase 2) and every
  introspection op (Phase 3). No VM dependency; the accessors stay total.

  ─────────────────────────────────────────────────────────────────────────────
  BYTE-ORDER CONVENTION (pinned — do NOT silently get this wrong):

  Two fields are stored here in UI / internal ("big-endian-ish", reversed-vs-wire)
  byte order, matching how libauth holds them in-memory:

    • `Input.outpointTransactionHash` — libauth stores this in *user-interface*
      byte order (`hashTransactionUiOrder`), the reverse of the little-endian order
      used on the P2P wire, in the VM, and by SHA-256 libraries. See
      transaction-types.d.ts Input.outpointTransactionHash remarks.

    • `TokenData.category` — libauth stores the 32-byte category ID in *big-endian*
      (block-explorer / UI) byte order, the reverse of the little-endian P2P order.
      See transaction-types.d.ts Output.token.category remarks.

  DECISION: the TYPES fix the UI/internal convention (exactly libauth's in-memory
  form). Every libauth `.reverse` at the wire boundary therefore maps 1:1 onto a
  reversal the Phase-2 encoders will perform; the records themselves carry the
  un-reversed (UI) bytes. Nothing here reverses — encoders own the wire boundary.
  ─────────────────────────────────────────────────────────────────────────────
-/
import LeanBCH.Core

namespace LeanBCH.Tx

open LeanBCH

/-- The capability assigned to a particular non-fungible token.
    Mirrors libauth `NonFungibleTokenCapability` (transaction-types.d.ts):
    `none` (immutable), `mutable` (0x01), `minting` (0x02). -/
inductive NftCapability
  | none
  | mutable
  | minting
  deriving DecidableEq, Repr

/-- A non-fungible token held by an output.
    Mirrors libauth `Output.token.nft`: `{ capability, commitment }`.
    `commitment` is arbitrary-length token commitment bytes. -/
structure Nft where
  capability : NftCapability
  commitment : Bytes
  deriving Repr, DecidableEq

/-- The CashToken contents of an output (`CHIP-2022-02-CashTokens`).
    Mirrors libauth `Output.token`: `{ amount, category, nft? }`.

    `category` is the 32-byte token category ID in UI / big-endian byte order
    (reversed vs the P2P wire — see the byte-order note at the top of this file).
    `amount` is the fungible-token count; libauth encodes it as a `bigint` because
    the max (`9223372036854775807`) exceeds `Number.MAX_SAFE_INTEGER`, so we model
    it as `Nat` (unbounded, exact). -/
structure TokenData where
  /-- 32-byte category ID, UI/internal (reversed-vs-wire) order. -/
  category : Bytes
  amount : Nat
  nft : Option Nft
  deriving Repr, DecidableEq

/-- A transaction output.
    Mirrors libauth `Output`: `{ lockingBytecode, token?, valueSatoshis }`.

    `valueSatoshis` uses `UInt64` — libauth encodes it as a 64-bit unsigned
    little-endian integer (`bigint` in TS only to cover the full uint64 range,
    incl. `excessiveSatoshis = 0xffffffffffffffff`). `token` is `Option` since the
    field is only present when the output carries token(s). -/
structure Output where
  valueSatoshis : UInt64
  lockingBytecode : Bytes
  token : Option TokenData
  deriving Repr, DecidableEq

/-- A transaction input.
    Mirrors libauth `Input`:
    `{ outpointIndex, outpointTransactionHash, sequenceNumber, unlockingBytecode }`.

    `outpointTransactionHash` is the 32-byte spent-tx hash in UI / internal byte
    order (reversed vs wire — see the byte-order note). `outpointIndex` and
    `sequenceNumber` are 32-bit unsigned. -/
structure Input where
  /-- 32-byte spent-tx hash, UI/internal (reversed-vs-wire) order. -/
  outpointTransactionHash : Bytes
  outpointIndex : UInt32
  unlockingBytecode : Bytes
  sequenceNumber : UInt32
  deriving Repr, DecidableEq

/-- A transaction (version 1/2 common format).
    Mirrors libauth `TransactionCommon`: `{ inputs, locktime, outputs, version }`.
    `version` and `locktime` are 32-bit unsigned. Input/output ORDER is
    consensus-critical (signing serializations depend on it) — modeled as `Array`. -/
structure Transaction where
  version : UInt32
  inputs : Array Input
  outputs : Array Output
  locktime : UInt32
  deriving Repr, DecidableEq

/-- The complete context needed to validate a specified input in a transaction.
    Mirrors libauth `AuthenticationProgramCommon`
      = `ResolvedTransactionCommon & { inputIndex }`
      = `{ transaction, sourceOutputs, inputIndex }`  (vm-types.d.ts:89-99).

    `sourceOutputs` are the spent UTXOs — and they REUSE the same `Output` type as
    the transaction's own outputs, exactly as libauth does (`ResolvedTransactionCommon`).
    There is no separate "UTXO" type. `inputIndex` selects which input is under
    evaluation. -/
structure Program where
  transaction : Transaction
  sourceOutputs : Array Output
  inputIndex : Nat
  deriving Repr

/-! ## Accessor helpers

  Total projections the Phase-2 sighash and Phase-3 introspection ops will consume.
  Everything is `Option`/`getD` — never partial, never VM-dependent. -/

/-- The input currently under evaluation (`transaction.inputs[inputIndex]`),
    or `none` if the index is out of range. -/
def Program.currentInput (p : Program) : Option Input :=
  p.transaction.inputs[p.inputIndex]?

/-- The source output (spent UTXO) for the input currently under evaluation
    (`sourceOutputs[inputIndex]`), or `none` if the index is out of range. -/
def Program.currentSourceOutput (p : Program) : Option Output :=
  p.sourceOutputs[p.inputIndex]?

/-- The transaction version. -/
def Program.version (p : Program) : UInt32 :=
  p.transaction.version

/-- The transaction locktime. -/
def Program.locktime (p : Program) : UInt32 :=
  p.transaction.locktime

/-- The number of inputs in the transaction. -/
def Program.inputCount (p : Program) : Nat :=
  p.transaction.inputs.size

/-- The number of outputs in the transaction. -/
def Program.outputCount (p : Program) : Nat :=
  p.transaction.outputs.size

/-- The output at index `i` in the transaction, or `none` if out of range. -/
def Program.output? (p : Program) (i : Nat) : Option Output :=
  p.transaction.outputs[i]?

/-- The input at index `i` in the transaction, or `none` if out of range. -/
def Program.input? (p : Program) (i : Nat) : Option Input :=
  p.transaction.inputs[i]?

/-- Value (in satoshis) of the transaction's output at index `i`,
    `0` if the index is out of range. -/
def Program.outputValue (p : Program) (i : Nat) : UInt64 :=
  match p.transaction.outputs[i]? with
  | some o => o.valueSatoshis
  | none   => 0

/-- Locking bytecode of the transaction's output at index `i`,
    `[]` if the index is out of range. -/
def Program.outputBytecode (p : Program) (i : Nat) : Bytes :=
  match p.transaction.outputs[i]? with
  | some o => o.lockingBytecode
  | none   => []

/-- The outpoint `(txHash, index)` of the transaction's input at index `i`,
    or `none` if out of range. The hash is in UI/internal byte order. -/
def Program.inputOutpoint (p : Program) (i : Nat) : Option (Bytes × UInt32) :=
  match p.transaction.inputs[i]? with
  | some inp => some (inp.outpointTransactionHash, inp.outpointIndex)
  | none     => none

/-! ## Example + accessor sanity checks -/

/-- A tiny two-input, two-output program with one token output, evaluating input 0. -/
def exampleProgram : Program :=
  let hashA : Bytes := List.replicate 32 (0x11 : UInt8)
  let hashB : Bytes := List.replicate 32 (0x22 : UInt8)
  let categoryC : Bytes := List.replicate 32 (0xAB : UInt8)
  { transaction :=
      { version := 2
        inputs := #[
          { outpointTransactionHash := hashA
            outpointIndex := 0
            unlockingBytecode := [0x51]      -- OP_1
            sequenceNumber := 0xffffffff },
          { outpointTransactionHash := hashB
            outpointIndex := 7
            unlockingBytecode := []
            sequenceNumber := 0 } ]
        outputs := #[
          { valueSatoshis := 1000
            lockingBytecode := [0x76, 0xa9]   -- OP_DUP OP_HASH160 …
            token := none },
          { valueSatoshis := 4242
            lockingBytecode := [0x6a]         -- OP_RETURN
            token := some
              { category := categoryC
                amount := 100
                nft := some { capability := .mutable, commitment := [0xde, 0xad] } } } ]
        locktime := 500000 }
    sourceOutputs := #[
      { valueSatoshis := 6000, lockingBytecode := [0x51], token := none },
      { valueSatoshis := 9000, lockingBytecode := [0x52], token := none } ]
    inputIndex := 0 }

-- Accessor sanity checks (kernel-checked equalities).
example : exampleProgram.version = 2 := by decide
example : exampleProgram.locktime = 500000 := by decide
example : exampleProgram.inputCount = 2 := by decide
example : exampleProgram.outputCount = 2 := by decide
example : exampleProgram.outputValue 0 = 1000 := by decide
example : exampleProgram.outputValue 1 = 4242 := by decide
example : exampleProgram.outputValue 5 = 0 := by decide          -- out of range → 0
example : exampleProgram.outputBytecode 1 = [0x6a] := by decide
example : exampleProgram.outputBytecode 9 = [] := by decide      -- out of range → []
example : (exampleProgram.currentInput.map (·.outpointIndex)) = some 0 := by decide
example : (exampleProgram.currentSourceOutput.map (·.valueSatoshis)) = some 6000 := by decide
example : exampleProgram.inputOutpoint 1 = some (List.replicate 32 (0x22 : UInt8), 7) := by decide
example : exampleProgram.inputOutpoint 3 = none := by decide     -- out of range → none
-- token / nft plumbing reaches through Option correctly
example :
    ((exampleProgram.output? 1).bind (·.token) |>.map (·.amount)) = some 100 := by decide
example :
    ((exampleProgram.output? 1).bind (·.token) |>.bind (·.nft) |>.map (·.capability))
      = some NftCapability.mutable := by decide

#eval exampleProgram.inputCount        -- 2
#eval exampleProgram.outputValue 1     -- 4242
#eval (exampleProgram.currentInput.map (·.outpointIndex))  -- some 0

end LeanBCH.Tx
