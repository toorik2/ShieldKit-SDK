/-
  LeanBCH.VM.Verify — the consensus input-verification predicate.

  Faithful to BCH: run the input's UNLOCKING bytecode from the empty stack, then run the source
  output's LOCKING bytecode on the resulting stack; the input is valid iff evaluation succeeds and
  leaves exactly one truthy item (the CLEAN-STACK rule). P2SH (HASH160-20) is handled: when the
  locking script is the P2SH template, the top unlocking item is a redeem script that is run on the
  remaining stack after the template check passes.

  This runs on `runExt` (the extended VM = pure `stepInstr` core + the 2026 bitwise/shift ops +
  the BCH-2026 introspection ops, which read the threaded `Program` context `p`, + the signature
  ops CHECKSIG/CHECKDATASIG/CHECKMULTISIG, which additionally read the secp256k1 oracle `crypto`).
  OP_ACTIVEBYTECODE is implemented (re-encodes s.instrs after lastCodeSep). For the non-signature
  families the oracle is never consulted, so `Secp256k1.reject` is the correct default there.
-/
import LeanBCH.VM.Extended
import LeanBCH.Tx.Types
import LeanBCH.Tx.Wire

namespace LeanBCH.VM
open LeanBCH LeanBCH.VM.State LeanBCH.Tx LeanBCH.Cost LeanBCH.Crypto

/-- Load bytecode into a fresh state seeded with an initial main stack. The raw bytes become the
    state's `scriptCode` — the checksig covered bytecode for the common no-codeseparator case. -/
def loadFrom (stk : Stack) (bs : Bytes) : State :=
  match parse bs with
  | .ok is        => { instrs := is, stack := stk, scriptCode := bs }
  | .malformed is => { instrs := is, stack := stk, scriptCode := bs, error := some .malformedPush }

/-- Evaluation fuel for one script. Straight-line scripts finish in `instrs.size` steps, but
    OP_INVOKE runs function bodies decoded from the STACK — instructions not counted in
    `instrs.size` — and each frame return consumes one step, so the fuel must exceed the top-level
    instruction count. Two consensus limits bound the extra: INVOKE recursion is capped by the
    control-stack-depth check (`maxCtrlDepth`, per-op in `stepMeterExt`), and total billed work by
    the per-input op-cost budget (≤ `maxOperationCost E maximumBytecodeLength / baseInstructionCost`
    = 80 328 at BCH_2026_05). This slack covers that plus its frame returns; a within-budget
    evaluation always terminates first, and an over-budget/looping one is cut off here and rejected
    (non-clean stack / the `cost12 ≤ budget` post-check). -/
def evalFuelSlack : Nat := 200000

/-- Run a script from a given initial stack (metered), under the transaction context `p` (threaded
    to the introspection ops in `stepInstrExt`) and the secp256k1 oracle `crypto` (threaded to the
    checksig ops). Fuel = the top-level instruction count + `evalFuelSlack` (for OP_INVOKE bodies /
    frame returns). -/
def runScript (crypto : Secp256k1) (p : Program) (stk : Stack) (bs : Bytes)
    (budget : Nat := (10000 + 41) * 800) : State :=
  let s0 := { loadFrom stk bs with budget := budget }
  runExt p crypto (s0.instrs.size + evalFuelSlack) s0

/-- The BCH clean-stack rule: no error, a balanced control stack (every IF/BEGIN closed), and
    the main stack is exactly one truthy item. -/
def cleanTruthy (s : State) : Bool :=
  s.error.isNone && s.ctrl.isEmpty && (match s.stack with | [x] => isTruthy x | _ => false)

/-- The P2SH-20 locking template: `OP_HASH160 <20-byte push> OP_EQUAL` (0xa9 0x14 … 0x87). -/
def isP2SH20 (locking : Bytes) : Bool :=
  locking.length == 23 && locking[0]? == some 0xa9 && locking[1]? == some 0x14
    && locking[22]? == some 0x87

/-- The P2SH-32 locking template: `OP_HASH256 <32-byte push> OP_EQUAL` (0xaa 0x20 … 0x87). -/
def isP2SH32 (locking : Bytes) : Bool :=
  locking.length == 35 && locking[0]? == some 0xaa && locking[1]? == some 0x20
    && locking[34]? == some 0x87

/-- Either P2SH template (both spend a redeem script pushed as the top unlocking item). -/
def isP2SH (locking : Bytes) : Bool := isP2SH20 locking || isP2SH32 locking

/-- BCH_2026 `maximumBytecodeLength` (a script — unlocking, locking, or redeem — over this many
    bytes is consensus-invalid). Baked to the BCH_2026_05 pin; the VM is epoch-specialized. -/
def maxBytecodeLen : Nat := 10000

/-- The per-input op-cost budget: `(densityControlBaseLength + |unlockingBytecode|) ×
    operationCostBudgetPerByte`. The accumulated operation cost of the whole input evaluation
    (unlocking + locking + redeem) must not exceed it (the BCH-2026 density limit). -/
def opBudget (unlockingLen : Nat) : Nat :=
  (BCH_2026_05.densityControlBaseLength + unlockingLen) * BCH_2026_05.operationCostBudgetPerByte

/-- The unlocking bytecode must be PUSH-ONLY (every opcode ≤ OP_16 = 0x60): no control flow or
    operations, only data/value pushes (libauth verify-level IsPushOnly — stricter than BCHN block-consensus, which enforces scriptSig push-only only in the P2SH branch). A malformed push fails. -/
def isPushOnly (bs : Bytes) : Bool :=
  match parse bs with
  | .ok is       => is.all (fun i => decide (i.opcode ≤ (0x60 : UInt8)))
  | .malformed _ => false

-- NOTE: BCH-2026 has NO disabled opcodes among the historical set — OP_INVERT (0x83) is re-enabled
-- and 0x8d/0x8e/0x98/0x99 are the new shift ops. All are IMPLEMENTED in stepInstrExt, so there is
-- no static disabled-op rejection here. (2023/2025 disabled semantics are a different, out-of-scope epoch.)

/-- ★ The consensus input-validity predicate for the currently-evaluated input of a program.
    `true` iff the input's unlocking + the UTXO's locking bytecode evaluate to a clean truthy
    stack (with P2SH-20/32 redeem execution), enforcing the per-script bytecode-length limit and
    the per-input op-cost density budget. -/
def verifyInput (crypto : Secp256k1) (p : Program) : Bool :=
  match p.currentInput, p.currentSourceOutput with
  | some inp, some src =>
      if inp.unlockingBytecode.length > maxBytecodeLen || src.lockingBytecode.length > maxBytecodeLen then false else
      if !isPushOnly inp.unlockingBytecode then false else
      let budget := opBudget inp.unlockingBytecode.length
      -- Consensus hashing-density limit (VM-Limits CHIP `GetInputHashItersLimit`): the accumulated
      -- hash-digest iterations of an input must be ≤ (|scriptSig| + 41)·7/2 (the ·7 is the
      -- block-txn / non-standard bonus; standard-relay uses ·1 — enforced in the standardness layer).
      let hashLimit := (inp.unlockingBytecode.length + 41) * 7 / 2
      let s1 := runScript crypto p [] inp.unlockingBytecode budget
      if s1.error.isSome then false else
      let s2 := runScript crypto p s1.stack src.lockingBytecode budget
      if s2.error.isSome then false else
      let cost12 := operationCost BCH_2026_05_CONSENSUS s1.metrics + operationCost BCH_2026_05_CONSENSUS s2.metrics
      let iters12 := s1.metrics.hashDigestIterations + s2.metrics.hashDigestIterations
      if isP2SH src.lockingBytecode then
        -- P2SH: the template (HASH160/256 <h> EQUAL) leaves [bool, args…] — the redeem hash
        -- matched iff its top is truthy; then run the redeem script (top unlock item) on the args.
        match s1.stack with
        | redeem :: rest =>
            if redeem.length > maxBytecodeLen then false else
            let s3 := runScript crypto p rest redeem budget
            let templateOk := s2.ctrl.isEmpty && (match s2.stack with | t :: _ => isTruthy t | [] => false)
            templateOk && cleanTruthy s3
              && (cost12 + operationCost BCH_2026_05_CONSENSUS s3.metrics ≤ budget)
              && (iters12 + s3.metrics.hashDigestIterations ≤ hashLimit)
        | []             => false
      else cleanTruthy s2 && (cost12 ≤ budget) && (iters12 ≤ hashLimit)
  | _, _ => false

/-- Total hash-digest iterations an input's evaluation performs (unlocking + locking + P2SH
    redeem). Mode-independent — the COUNT is the same for consensus and standard; only the LIMIT
    differs (·7 vs ·1). Exposed so the standardness layer can apply the tighter relay bound. -/
def inputHashIters (crypto : Secp256k1) (p : Program) : Nat :=
  match p.currentInput, p.currentSourceOutput with
  | some inp, some src =>
      let s1 := runScript crypto p [] inp.unlockingBytecode
      let s2 := runScript crypto p s1.stack src.lockingBytecode
      let base := s1.metrics.hashDigestIterations + s2.metrics.hashDigestIterations
      if isP2SH src.lockingBytecode then
        match s1.stack with
        | redeem :: rest => base + (runScript crypto p rest redeem).metrics.hashDigestIterations
        | []             => base
      else base
  | _, _ => 0

/-- Maximum representable money (21 000 000 BCH in satoshis). A value over this is invalid. -/
def maxMoney : Nat := 2100000000000000

/-- Transaction-STRUCTURAL validity (the tx-level rules `verifyInput` deliberately omits): a
    valid version (1 or 2), non-empty inputs and outputs, and every UTXO / output value within
    the money range. Layered ABOVE the per-input script validity. -/
def txValid (p : Program) : Bool :=
  -- Serialized transaction size ∈ [MIN_TX_SIZE_UPGRADE9 (65), MAX_TX_SIZE (1 000 000)]. The 65-byte
  -- floor is the anti-Merkle-tree exploit rule (a 64-byte tx can collide with an inner Merkle node,
  -- CVE-2017-12842); BCHN rejects an undersize tx at consensus ("bad-txns-undersize", DoS 100).
  let txSize := (LeanBCH.Tx.encodeTransaction p.transaction).length
  -- Every input must spend a DISTINCT outpoint (no within-tx double-spend), and no NULL prevout
  -- (the coinbase marker {0×32, 0xffffffff} is illegal in a regular tx) — BCHN CheckRegularTransaction.
  let outpoints := p.transaction.inputs.toList.map (fun i => (i.outpointTransactionHash, i.outpointIndex))
  -- Absolute Σoutputs money cap (BCHN CheckTransactionCommon `bad-txns-txouttotal-toolarge`).
  let outSum := p.transaction.outputs.foldl (fun acc o => acc + o.valueSatoshis.toNat) 0
  -- Σinputs, from the spent UTXOs (`sourceOutputs`). VALUE CONSERVATION: no BCH may be created —
  -- `outSum ≤ inSum`, the fee being the non-negative remainder (BCHN CheckTxInputs
  -- `bad-txns-in-belowout`: `nValueIn < value_out` is rejected). Absent this, a tx can mint BCH
  -- from nothing while every output still passes the absolute `maxMoney` cap.
  let inSum := p.sourceOutputs.foldl (fun acc o => acc + o.valueSatoshis.toNat) 0
  (p.transaction.version == 1 || p.transaction.version == 2)
    && !p.transaction.inputs.isEmpty && !p.transaction.outputs.isEmpty
    && decide (65 ≤ txSize) && decide (txSize ≤ 1000000)
    && decide outpoints.Nodup
    && p.transaction.inputs.all
         (fun i => !(i.outpointTransactionHash.all (· == 0) && i.outpointIndex == 0xffffffff))
    && decide (outSum ≤ maxMoney)
    && decide (outSum ≤ inSum)
    && p.sourceOutputs.all (fun o => decide (o.valueSatoshis.toNat ≤ maxMoney))
    && p.transaction.outputs.all (fun o => decide (o.valueSatoshis.toNat ≤ maxMoney))

/-! ## CashToken (CHIP-2022-02) transaction-level token validation

  A faithful, pure/total transcription of libauth `verifyTransactionTokens`
  (`bch/2023/bch-2023-tokens.js`, the BCH_2023/2026 CashToken consensus rules). Tokens are
  aggregated by 32-byte category id and five conservation laws are enforced:

    1. commitment length ≤ maxTokenCommitmentLength (128 in BCH_2026; source + output nfts);
    2. an output MINTING nft's category must be authorised = genesis ∪ input-minting;
    3. fungibles: per category, `outSum ≤ maxFungibleAmount`, a category absent from inputs may
       only create fungibles if it is a genesis category, and otherwise `outSum ≤ inSum`
       (no inflation);
    4. mutable nfts: a non-minting category emits at most as many mutable nfts as it holds;
    5. immutable nfts: new immutable nfts (not matched 1:1 by an identical input immutable of the
       same category+commitment, non-minting categories) must be covered by leftover mutable
       input tokens (the mutable→immutable downgrade), `required ≤ availableMutable − outputMutable`.

  BYTE ORDER: libauth compares categories via `binToHex` of the in-memory bytes; the LeanBCH
  records hold both `Input.outpointTransactionHash` and `TokenData.category` in that same
  UI/internal order (the wire decoder reverses both), so category equality is a direct `Bytes`
  comparison — no reversal here. Everything folds structurally over the finite input/output
  arrays, so no fuel is needed. -/

/-- BCH_2026 `maximumTokenCommitmentLength`. RAISED from the 2023/2025 value of 40 to 128 by the
    2026 upgrade (`ConsensusBch2026Overrides.maximumTokenCommitmentLength`); this VM is 2026-pinned. -/
def maxTokenCommitmentLength : Nat := 128

/-- BCH_2023/2025/2026 `maximumFungibleTokenAmount` (`2^63 − 1`; unchanged across epochs). -/
def maxFungibleTokenAmount : Nat := 9223372036854775807

/-- Token category id (32 bytes, UI/internal order — see the byte-order note). -/
abbrev TokenCat := Bytes

/-- All token records carried by the spent UTXOs (source outputs). -/
def sourceTokens (p : Program) : List TokenData :=
  p.sourceOutputs.toList.filterMap (·.token)

/-- All token records carried by the transaction's own outputs. -/
def outputTokens (p : Program) : List TokenData :=
  p.transaction.outputs.toList.filterMap (·.token)

/-- Genesis categories = the outpoint txids of inputs spending output index `0` (libauth
    `extractGenesisCategories`). A category may be created only if it is one of these. -/
def genesisCategories (p : Program) : List TokenCat :=
  p.transaction.inputs.toList.filterMap (fun inp =>
    if inp.outpointIndex == 0 then some inp.outpointTransactionHash else none)

/-- Categories carrying a MINTING nft among the tokens (libauth `inputMintingCategories` /
    `outputMintingCategories`). -/
def mintingCatsOf (toks : List TokenData) : List TokenCat :=
  toks.filterMap (fun t => match t.nft with
    | some n => match n.capability with | .minting => some t.category | _ => none
    | none   => none)

/-- The `(category, commitment)` of every IMMUTABLE (capability `none`) nft among the tokens
    (libauth `availableImmutableTokens` / `outputImmutableTokens`). -/
def immutablesOf (toks : List TokenData) : List (TokenCat × Bytes) :=
  toks.filterMap (fun t => match t.nft with
    | some n => match n.capability with | .none => some (t.category, n.commitment) | _ => none
    | none   => none)

/-- Count of MUTABLE nfts of category `c` (libauth `…MutableTokensByCategory` at `c`). -/
def mutableCount (toks : List TokenData) (c : TokenCat) : Nat :=
  (toks.filter (fun t => match t.nft with
    | some n => match n.capability with | .mutable => t.category == c | _ => false
    | none   => false)).length

/-- Σ of fungible `amount`s of category `c` (libauth `…SumsByCategory` at `c`). -/
def sumByCat (toks : List TokenData) (c : TokenCat) : Nat :=
  (toks.filter (fun t => t.category == c)).foldl (fun s t => s + t.amount) 0

/-- Whether any token of category `c` is present — i.e. libauth's sums map has `c` as a key
    (`availableSumsByCategory[c] !== undefined`). NOTE: present even at `amount = 0` (an
    NFT-only token), matching libauth exactly. -/
def catPresent (toks : List TokenData) (c : TokenCat) : Bool :=
  toks.any (fun t => t.category == c)

/-- Membership of a category in a category list (BEq over the 32-byte ids). -/
def catElem (c : TokenCat) (l : List TokenCat) : Bool := l.any (· == c)

/-- Distinct categories, first-seen order (mirrors iterating an `Object.entries` key set). -/
def distinctCats (l : List TokenCat) : List TokenCat :=
  l.foldl (fun acc c => if acc.any (· == c) then acc else acc ++ [c]) []

/-- (1) Every nft commitment (source + output) is within the maxTokenCommitmentLength consensus limit (128 in 2026)
    (libauth `tokenValidationExcessiveCommitmentLength`). -/
def commitmentsOk (p : Program) : Bool :=
  (sourceTokens p ++ outputTokens p).all (fun t => match t.nft with
    | some n => decide (n.commitment.length ≤ maxTokenCommitmentLength)
    | none   => true)

/-- (2) No output MINTING nft of an unauthorised category (libauth
    `tokenValidationInvalidMintingToken`). Authorised = genesis ∪ input-minting. -/
def mintingOk (p : Program) : Bool :=
  let avail := genesisCategories p ++ mintingCatsOf (sourceTokens p)
  (mintingCatsOf (outputTokens p)).all (fun c => catElem c avail)

/-- (3) Per output category: within `maxFungibleTokenAmount`; a category absent from inputs may
    create fungibles only if genesis; otherwise `outSum ≤ inSum` (libauth
    `tokenValidationExcessiveAmount` / `tokenValidationInvalidFungibleMint` /
    `tokenValidationOutputsExceedInputs`). -/
def fungibleOk (p : Program) : Bool :=
  let outToks := outputTokens p
  let srcToks := sourceTokens p
  let gen := genesisCategories p
  (distinctCats (outToks.map (·.category))).all (fun c =>
    let sum := sumByCat outToks c
    if decide (sum > maxFungibleTokenAmount) then false
    else if !catPresent srcToks c then
      -- availableSum undefined: only a genesis category may create fungibles from nothing
      if decide (0 < sum) && !catElem c gen then false else true
    else
      -- availableSum defined: outputs must not exceed inputs (no inflation)
      decide (sum ≤ sumByCat srcToks c))

/-- (4) Excessive mutable: a non-minting category emits at most as many mutable nfts as it holds
    (libauth `tokenValidationExcessiveMutableTokens`). -/
def mutableOk (p : Program) : Bool :=
  let outToks := outputTokens p
  let srcToks := sourceTokens p
  let availMint := genesisCategories p ++ mintingCatsOf srcToks
  (distinctCats (outToks.filterMap (fun t => match t.nft with
      | some n => match n.capability with | .mutable => some t.category | _ => none
      | none   => none))).all (fun c =>
    if catElem c availMint then true
    else decide (mutableCount outToks c ≤ mutableCount srcToks c))

/-- Remove the first `(category, commitment)` match from an available-immutable pool, or `none`
    if absent (libauth `availableImmutableTokens.splice(firstMatch, 1)`). -/
def removeFirstImmutable (avail : List (TokenCat × Bytes)) (c : TokenCat) (m : Bytes)
    : Option (List (TokenCat × Bytes)) :=
  match avail with
  | []            => none
  | (c', m') :: r =>
      if c' == c && m' == m then some r
      else (removeFirstImmutable r c m).map (fun rr => (c', m') :: rr)

/-- Fold output immutable nfts against the available input-immutable pool, returning the
    categories left UNMATCHED (minting-covered categories are skipped) — libauth's
    `unmatchedImmutableTokens`, projected to categories. -/
def unmatchedImmutables (availMint : List TokenCat) (avail : List (TokenCat × Bytes))
    (outImm : List (TokenCat × Bytes)) : List TokenCat :=
  match outImm with
  | []           => []
  | (c, m) :: rest =>
      if catElem c availMint then unmatchedImmutables availMint avail rest
      else match removeFirstImmutable avail c m with
        | some avail' => unmatchedImmutables availMint avail' rest
        | none        => c :: unmatchedImmutables availMint avail rest

/-- (5) Excessive immutable: new immutable nfts (unmatched against identical input immutables,
    non-minting categories) must be covered by leftover mutable input tokens — the
    mutable→immutable downgrade (libauth `tokenValidationExcessiveImmutableTokens`).
    `required(c) ≤ availableMutable(c) − outputMutable(c)`, computed over ℤ to mirror libauth's
    possibly-negative `remainingMutableTokens`. -/
def immutableOk (p : Program) : Bool :=
  let outToks := outputTokens p
  let srcToks := sourceTokens p
  let availMint := genesisCategories p ++ mintingCatsOf srcToks
  let unmatched := unmatchedImmutables availMint (immutablesOf srcToks) (immutablesOf outToks)
  (distinctCats unmatched).all (fun c =>
    let required  : Int := (unmatched.filter (· == c)).length
    let remaining : Int := (mutableCount srcToks c : Int) - (mutableCount outToks c : Int)
    decide (required ≤ remaining))

/-- (0) Token-PREFIX encoding invariant (libauth `readTokenPrefix`: the `noTokens` / `zeroAmount`
    / `excessiveAmount` rules, and the encoder invariant at `transaction-encoding.js:282`
    `token.nft !== undefined || token.amount >= 1n`). Every token — source or output — must encode
    at least one token (an nft, or a nonzero fungible amount) and stay within
    `maxFungibleTokenAmount`. libauth rejects violations at DECODE; our permissive wire decoder
    does not, so we re-enforce the two post-decode-reconstructable rules here.

    SAFE (0 rejected-valid): no well-formed token can have `amount = 0` with no nft, nor an amount
    above the max — so this never rejects a transaction libauth would accept. (The remaining
    bitfield-level prefix rules — reserved bit, capability > 2, commitment-without-nft,
    zero-length-encoded-commitment — are LOST at decode and stay a decoder-layer concern.) -/
def tokensWellFormed (p : Program) : Bool :=
  (sourceTokens p ++ outputTokens p).all (fun t =>
    (t.nft.isSome || decide (1 ≤ t.amount)) && decide (t.amount ≤ maxFungibleTokenAmount))

/-- ★ CHIP-2022-02 CashToken transaction-level validity (libauth `verifyTransactionTokens`, plus
    the `readTokenPrefix` encoding invariant our permissive decoder doesn't check — see
    `tokensWellFormed`). `true` for token-less transactions (all aggregates empty). Pure & total. -/
def verifyTokens (p : Program) : Bool :=
  tokensWellFormed p
    && commitmentsOk p && mintingOk p && fungibleOk p && mutableOk p && immutableOk p

/-- ★ Consensus transaction validity: the structural rules hold (including satoshi value
    conservation Σoutputs ≤ Σinputs, enforced in `txValid`), the CashToken rules hold, AND every
    input verifies (under the secp256k1 oracle `crypto`). -/
def verifyTransaction (crypto : Secp256k1) (p : Program) : Bool :=
  txValid p && verifyTokens p
    && (List.range p.transaction.inputs.size).all (fun i => verifyInput crypto { p with inputIndex := i })

/-- The op-cost the currently-evaluated input spends (unlocking + locking), for the density
    budget. (Per-input; the tx-level aggregate is `∑` over inputs.) -/
def inputOpCost (E : Epoch) (crypto : Secp256k1) (p : Program) : Nat :=
  match p.currentInput, p.currentSourceOutput with
  | some inp, some src =>
      let s1 := runScript crypto p [] inp.unlockingBytecode
      let s2 := runScript crypto p s1.stack src.lockingBytecode
      operationCost E s1.metrics + operationCost E s2.metrics
  | _, _ => 0

-- The BCH-2026 FUNCTIONS-chip witnesses + value-conservation KATs that lived here now sit in the
-- validation layer: LeanBCH/Validation/Verify.lean (their shared fixtures fnProg/fnRun are in
-- LeanBCH/Validation/Fixtures.lean). This file is now pure model — no build-time assertions.

end LeanBCH.VM
