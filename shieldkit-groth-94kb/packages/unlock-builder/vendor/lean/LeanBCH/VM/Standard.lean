/-
  LeanBCH.VM.Standard — the OPTIONAL relay-policy (standardness) layer.

  Consensus (`verifyTransaction`) answers "could a MINER put this in a valid block?". Standardness
  answers "will a NODE relay/mempool this by default?". They are distinct: a transaction can be
  consensus-valid yet non-standard (a miner may include it; ordinary wallets won't propagate it).

  This module is a strict LEAF: it imports the consensus `Verify` and is never imported back, so
  the frozen keystone (`stepInstr`/`run_straightline`) is untouched. Policy is DATA — the `Policy`
  record carries every tunable, so a future relay-rule change (new template, dust factor, …) is a
  value edit, not a logic rewrite; versioned policies are both a historical record and a one-line
  future extension.

  Rules are transcribed from the BCHN reference (`policy.cpp` / `standard.cpp` / `consensus`),
  cross-checked against libauth; where they diverge we follow BCHN (it generated the vmb corpus).
-/
import LeanBCH.VM.Verify

namespace LeanBCH.VM.Standard
open LeanBCH LeanBCH.VM LeanBCH.Tx LeanBCH.Crypto

/-- Versioned relay-policy parameters (BCHN `policy.h` / `standard.h` / `consensus.h` constants).
    The defaults ARE the May-2026 policy; older epochs override a few fields. -/
structure Policy where
  p2sh32Enabled      : Bool := true     -- SCRIPT_ENABLE_P2SH_32: recognise OP_HASH256 <32> OP_EQUAL
  bareScriptStandard : Bool := true     -- SCRIPT_ENABLE_MAY2026: a ≤201-byte non-template spk is TX_SCRIPT
  maxTxSize          : Nat  := 100000   -- MAX_STANDARD_TX_SIZE
  maxScriptSigSize   : Nat  := 10000    -- per-input scriptSig cap (MAY2026: MAX_SCRIPT_SIZE; legacy 1650)
  maxP2sScriptSize   : Nat  := 201      -- MAX_P2S_SCRIPT_SIZE (the bare-script standard length cap)
  maxScriptSize      : Nat  := 10000    -- MAX_SCRIPT_SIZE (IsUnspendable oversize ⇒ dust threshold 0)
  dustRelayFee       : Nat  := 1000     -- DUST_RELAY_TX_FEE (sat/kB); also the fee divisor
  dustMult           : Nat  := 3        -- the 3× factor in GetDustThreshold
  dustPad            : Nat  := 148       -- assumed P2PKH spend-input size (32+4+1+107+4)
  maxDataCarrier     : Nat  := 223      -- MAX_OP_RETURN_RELAY (sum of TX_NULL_DATA scriptPubKey sizes)
  bareMultisigStd    : Bool := true     -- -permitbaremultisig
  bareMultisigMaxN   : Nat  := 3        -- standard bare-multisig cap: n ∈ [1,3]
  deriving Repr

/-- The concrete BCH May-2026 relay policy. -/
def policy2026 : Policy := {}

/-- Standard output-template classification (BCHN Solver `txnouttype`). -/
inductive OutputKind
  | p2pkh | p2sh20 | p2sh32 | p2pk | bareMultisig (n : Nat) | opReturn | bareScript | nonStandard
  deriving DecidableEq, Repr
open OutputKind

/-- A pubkey is validly encoded iff its header byte implies its length (BCHN `CPubKey::ValidSize`):
    0x02/0x03 ⇒ 33 bytes (compressed), 0x04/0x06/0x07 ⇒ 65 bytes (uncompressed/hybrid). -/
def validPubkeySize (pk : Bytes) : Bool :=
  match pk with
  | h :: _ =>
      let n := pk.length
      ((h == 0x02 || h == 0x03) && n == 33) || ((h == 0x04 || h == 0x06 || h == 0x07) && n == 65)
  | [] => false

/-- `b` is a small-integer opcode OP_1..OP_16 (0x51..0x60). -/
def isOpN (b : UInt8) : Bool := 0x51 ≤ b.toNat && b.toNat ≤ 0x60
/-- The integer 1..16 that OP_1..OP_16 encodes. -/
def opNval (b : UInt8) : Nat := b.toNat - 0x50

/-- Parse the pubkey-push run of a bare multisig (the bytes AFTER OP_m), fuel-bounded. Each key is
    a minimal direct push (0x21/0x41) of a `ValidSize` pubkey; the run ends at `OP_n OP_CHECKMULTISIG`.
    Returns `(#pubkeys, n)`. -/
def parseMultisigKeys : Nat → Bytes → Nat → Option (Nat × Nat)
  | 0,   _,            _   => none
  | _+1, [nOp, 0xae],  acc => if isOpN nOp then some (acc, opNval nOp) else none
  | f+1, l :: rest,    acc =>
      let len := l.toNat
      if (len == 33 || len == 65) && rest.length ≥ len && validPubkeySize (rest.take len)
      then parseMultisigKeys f (rest.drop len) (acc + 1)
      else none
  | _,   _,            _   => none

/-- Structural bare-multisig match (BCHN `MatchMultisig`): `OP_m <keys> OP_n OP_CHECKMULTISIG`
    with `#keys = n` and `n ≥ m ≥ 1`. Returns `(m, n)`; the standard n≤3 cap is applied later. -/
def matchMultisig (spk : Bytes) : Option (Nat × Nat) :=
  match spk with
  | mOp :: rest =>
      if isOpN mOp then
        match parseMultisigKeys spk.length rest 0 with
        | some (numPk, n) => if numPk == n && n ≥ opNval mOp then some (opNval mOp, n) else none
        | none            => none
      else none
  | [] => none

/-- Classify a locking bytecode by BCHN's Solver order (first match wins): P2SH shortcut →
    OP_RETURN → P2PK → P2PKH → bare multisig → (2026) ≤201-byte bare script → non-standard. -/
def classifyOutput (pol : Policy) (spk : Bytes) : OutputKind :=
  let n := spk.length
  if n == 23 && spk[0]? == some 0xa9 && spk[1]? == some 0x14 && spk[22]? == some 0x87 then p2sh20
  else if pol.p2sh32Enabled && n == 35 && spk[0]? == some 0xaa && spk[1]? == some 0x20 && spk[34]? == some 0x87 then p2sh32
  else if n ≥ 1 && spk[0]? == some 0x6a && isPushOnly (spk.drop 1) then opReturn
  else if n == 67 && spk[0]? == some 0x41 && spk[66]? == some 0xac && validPubkeySize ((spk.drop 1).take 65) then p2pk
  else if n == 35 && spk[0]? == some 0x21 && spk[34]? == some 0xac && validPubkeySize ((spk.drop 1).take 33) then p2pk
  else if n == 25 && spk[0]? == some 0x76 && spk[1]? == some 0xa9 && spk[2]? == some 0x14
          && spk[23]? == some 0x88 && spk[24]? == some 0xac then p2pkh
  else match matchMultisig spk with
       | some (_, nn) => bareMultisig nn
       | none         => if pol.bareScriptStandard && n ≤ pol.maxP2sScriptSize then bareScript else nonStandard

/-- BCHN `IsUnspendable`: a script beginning with OP_RETURN, or exceeding MAX_SCRIPT_SIZE. Such an
    output is never dust (threshold 0). -/
def isUnspendable (pol : Policy) (spk : Bytes) : Bool :=
  spk[0]? == some 0x6a || spk.length > pol.maxScriptSize

/-- BCHN `CFeeRate::GetFee`: `⌊sz·rate/1000⌋`, floored up to 1 sat when the product is nonzero. -/
def feeFor (pol : Policy) (sz : Nat) : Nat :=
  let f := sz * pol.dustRelayFee / 1000
  if f == 0 && sz != 0 && pol.dustRelayFee > 0 then 1 else f

/-- Token-aware dust threshold: `dustMult · GetFee(L + dustPad)` where `L` is the FULL serialized
    output length (`encodeOutput`, token prefix included — so token outputs get their higher
    threshold with no special-casing). For the default 1000 sat/kB rate this is `3·(L+148)`. -/
def dustThreshold (pol : Policy) (o : Output) : Nat :=
  if isUnspendable pol o.lockingBytecode then 0
  else pol.dustMult * feeFor pol ((encodeOutput o).length + pol.dustPad)

def isDust (pol : Policy) (o : Output) : Bool :=
  o.valueSatoshis.toNat < dustThreshold pol o

/-- A single output is standard. Branch order mirrors BCHN's `IsStandardTx`: NULL_DATA and
    (relay-permitted) bare-multisig outputs are dust-EXEMPT; all other templates are dust-checked. -/
def outputStandard (pol : Policy) (o : Output) : Bool :=
  match classifyOutput pol o.lockingBytecode with
  | opReturn        => true                                      -- ONLY NULL_DATA is dust-exempt (BCHN)
  | bareMultisig nn => pol.bareMultisigStd && nn ≤ pol.bareMultisigMaxN && !isDust pol o
  | nonStandard     => false
  | _               => !isDust pol o                             -- p2pkh/p2sh/p2pk/bare-script

/-- Sum of scriptPubKey sizes across all TX_NULL_DATA outputs (the data-carrier budget). -/
def dataCarrierTotal (pol : Policy) (tx : Transaction) : Nat :=
  tx.outputs.foldl (fun acc o =>
    if classifyOutput pol o.lockingBytecode == opReturn then acc + o.lockingBytecode.length else acc) 0

/-- The relay-policy predicate (BCHN `IsStandardTx` + `AreInputsStandard`), layered ABOVE consensus:
    size ≤ max-standard, every scriptSig push-only + ≤ cap, every output a standard template (dust /
    data-carrier respected), and every spent UTXO a standard template. -/
def isStandard (pol : Policy) (p : Program) : Bool :=
  decide ((encodeTransaction p.transaction).length ≤ pol.maxTxSize)
    && p.transaction.inputs.all
         (fun i => isPushOnly i.unlockingBytecode && decide (i.unlockingBytecode.length ≤ pol.maxScriptSigSize))
    && p.transaction.outputs.all (fun o => outputStandard pol o)
    && decide (dataCarrierTotal pol p.transaction ≤ pol.maxDataCarrier)
    && p.sourceOutputs.all (fun o => classifyOutput pol o.lockingBytecode != nonStandard)

/-- Discouraged upgradable-NOP opcodes: OP_NOP1 (0xb0) and OP_NOP4..OP_NOP10 (0xb3..0xb9), reserved
    for future soft-forks. STANDARD relay rejects a tx that EXECUTES one (BCHN
    DISCOURAGE_UPGRADABLE_NOPS). NOT discouraged: OP_NOP (0x61), OP_CLTV/CSV (0xb1/0xb2 — real ops). -/
def isDiscouragedNop (op : UInt8) : Bool :=
  op == 0xb0 || (0xb3 ≤ op.toNat && op.toNat ≤ 0xb9)

/-- Does a bytecode contain a discouraged-NOP opcode? Static over-approximation of "executes one"
    (flags a discouraged NOP even in a dead branch — validated not to over-reject the corpus). -/
def hasDiscouragedNop (bs : Bytes) : Bool :=
  match parse bs with
  | .ok is       => is.any (fun i => isDiscouragedNop i.opcode)
  | .malformed _ => false

/-- INTERPRETER-level standardness of the currently-evaluated input (relay rules enforced DURING
    execution, beyond the structural template/dust layer): no discouraged upgradable NOP in the
    executed scripts, and the accumulated hash-digest iterations within the tighter STANDARD
    (relay, ·1) hashing-density limit `(|scriptSig|+41)/2` (vs the consensus ·7). -/
def standardInterpreterOk (crypto : Secp256k1) (p : Program) : Bool :=
  match p.currentInput, p.currentSourceOutput with
  | some inp, some src =>
      let redeemNop :=
        if isP2SH src.lockingBytecode then
          match (runScript crypto p [] inp.unlockingBytecode).stack with
          | redeem :: _ => hasDiscouragedNop redeem
          | []          => false
        else false
      !hasDiscouragedNop inp.unlockingBytecode && !hasDiscouragedNop src.lockingBytecode && !redeemNop
        && decide (inputHashIters crypto p ≤ (inp.unlockingBytecode.length + 41) / 2)
  | _, _ => true

/-- The three-way verdict every BCH node actually computes. -/
inductive TxClass
  | invalid       -- fails consensus
  | nonstandard   -- consensus-valid but relay-rejected
  | standard      -- both
  deriving DecidableEq, Repr

/-- Classify a program: consensus first (`verifyTransaction`), then relay policy — the structural
    template/dust/size layer (`isStandard`) AND the interpreter-level layer (`standardInterpreterOk`). -/
def classify (crypto : Secp256k1) (pol : Policy) (p : Program) : TxClass :=
  if !verifyTransaction crypto p then .invalid
  else if isStandard pol p && standardInterpreterOk crypto p then .standard
  else .nonstandard

/-- The relay-mode verifier: consensus-valid AND standard (structural + interpreter-level). -/
def verifyStandard (crypto : Secp256k1) (pol : Policy) (p : Program) : Bool :=
  verifyTransaction crypto p && isStandard pol p && standardInterpreterOk crypto p

-- KATs moved to LeanBCH/Validation/VM/Standard.lean (validation layer).

end LeanBCH.VM.Standard
