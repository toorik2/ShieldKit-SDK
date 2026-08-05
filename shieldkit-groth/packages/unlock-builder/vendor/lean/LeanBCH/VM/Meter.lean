/-
  LeanBCH.VM.Meter — the per-step cost fold `kappa` + the metered run.

  `kappa s` is the `Metrics` delta the current instruction bills from the PRE-state,
  reproducing libauth's per-op metering: every stepped op bills one instruction tick (even a
  skipped one under an inactive branch); active ops additionally bill their pushed-byte width
  (a copied/pushed item's byte length) and, for arithmetic, the `|a|·|b|` operand pre-charge +
  result double-bill (via `Cost.arithCost`). `step` then factors as `step1` (the pure state
  transition) plus this delta — the observation-not-interference seam. `operationCost E` rolls
  the accumulated `Metrics` up to the consensus op-cost.
-/
import LeanBCH.VM.Eval
import LeanBCH.VM.Shift2026
import LeanBCH.Cost.Hash
import LeanBCH.Cost.Sig

namespace LeanBCH.VM
open LeanBCH LeanBCH.VM.State LeanBCH.Cost

/-- Width (byte length) of the stack item at depth `d`, or 0 if absent. -/
def widthAt (s : State) (d : Nat) : Nat := (s.stack[d]?.map (·.length)).getD 0

/-- The pushed-byte contribution of a copy op (matches libauth `pushToStack`): the byte length of
    the item(s) it materializes onto the stack. Pure reorder ops (SWAP/ROT/NIP/DROP/TOALTSTACK)
    push nothing. Covers every op whose pushed bytes are a COPY of existing item(s). -/
def copyBytes (op : UInt8) (s : State) : Nat :=
  if op == Opcode.OP_DUP then widthAt s 0
  else if op == Opcode.OP_OVER then widthAt s 1
  else if op == Opcode.OP_TUCK then widthAt s 0
  else if op == 0x6e then widthAt s 0 + widthAt s 1                       -- OP_2DUP: copies top two
  else if op == 0x6f then widthAt s 0 + widthAt s 1 + widthAt s 2         -- OP_3DUP: copies top three
  else if op == 0x70 then widthAt s 2 + widthAt s 3                       -- OP_2OVER: copies depth 2/3
  else if op == 0x71 then widthAt s 4 + widthAt s 5                       -- OP_2ROT: re-pushes the two deepest of six
  else if op == 0x73 then (if (s.stack[0]?.map isTruthy).getD false then widthAt s 0 else 0)  -- OP_IFDUP
  else if op == 0x6c then (s.alt[0]?.map (·.length)).getD 0               -- OP_FROMALTSTACK: moves alt-top
  else if op == Opcode.OP_PICK then
    (match s.stack with | nb :: rest => (rest[(vmNumberToBigInt nb).toNat]?.map (·.length)).getD 0 | [] => 0)
  else if op == 0x7a then                                                 -- OP_ROLL: item bytes + numeric depth surcharge
    (match s.stack with | nb :: rest => let d := (vmNumberToBigInt nb).toNat; (rest[d]?.map (·.length)).getD 0 + d | [] => 0)
  else 0   -- SWAP/ROT/NIP/TOALTSTACK/DROP/… bill only the instruction tick

/-- The pushed-byte contribution of a byte/data-output op: the byte length of the (single) result
    item it materializes — plain `pushToStack`, NO arithmetic double-bill (matches libauth). -/
def byteOpBytes (op : UInt8) (s : State) : Nat :=
  if op == 0x7e then widthAt s 0 + widthAt s 1                            -- OP_CAT: a ‖ b
  else if op == 0x7f then widthAt s 1                                     -- OP_SPLIT: two halves sum to |data| (2nd item; top is index)
  else if op == 0x80 then (vmNumberToBigInt (s.stack[0]?.getD [])).toNat  -- OP_NUM2BIN: requested output size (value of top)
  else if op == 0x81 then intByteLen (vmNumberToBigInt (s.stack[0]?.getD []))  -- OP_BIN2NUM: minimal re-encoding
  else if op == 0x83 || op == 0x84 || op == 0x85 || op == 0x86 then widthAt s 0  -- INVERT/AND/OR/XOR: result = operand length
  else if op == 0xbc then widthAt s 0                                     -- OP_REVERSEBYTES: result = input length
  else if op == 0x82 then intByteLen (Int.ofNat (widthAt s 0))            -- OP_SIZE: encoded length number (data NOT re-billed)
  else if op == 0x74 then intByteLen (Int.ofNat s.stack.length)           -- OP_DEPTH: encoded depth number
  else 0

/-- The byte/data-output ops routed through `byteOpBytes` (bill their result bytes, not `arithmeticCost`). -/
def isByteOutputOp (op : UInt8) : Bool :=
  op == 0x7e || op == 0x7f || op == 0x80 || op == 0x81 || op == 0x83 || op == 0x84
    || op == 0x85 || op == 0x86 || op == 0xbc || op == 0x82 || op == 0x74

/-- Pushed result bytes of a 2026 shift op (single-billed, `hasEncodingCost:false` in libauth):
    binary shifts are fixed-length (= data width); numeric shifts push the computed number's
    minimal encoding — guarded exactly like the VM step so a huge count never materializes `2^c`. -/
def shiftBytes (op : UInt8) (s : State) : Nat :=
  if op == 0x98 || op == 0x99 then widthAt s 1                    -- LSHIFTBIN/RSHIFTBIN: output length = data length
  else
    match s.stack with                                            -- LSHIFTNUM (0x8d) / RSHIFTNUM (0x8e)
    | cnt :: val :: _ =>
        match readNum? cnt, readNum? val with
        | some c, some v =>
            if c < 0 || v == 0 then 0
            else
              let cn := c.toNat
              if op == 0x8d then (if cn > 80000 then 0 else intByteLen (lshiftNum v cn))  -- 80000 = maxItemLen·8
              else (if cn > val.length * 8 then intByteLen (if v < 0 then -1 else 0) else intByteLen (rshiftNum v cn))
        | _, _ => 0
    | _ => 0

def isShiftOp (op : UInt8) : Bool := op == 0x8d || op == 0x8e || op == 0x98 || op == 0x99

/-- Value-numeric ops that push a NUMBER result — double-billed like arithmetic (result bytes to
    BOTH arithmeticCost and stackPushedBytes; NO operand pre-charge): 1ADD/1SUB/NEGATE/ABS/MIN/MAX. -/
def isValueNumericOp (op : UInt8) : Bool :=
  op == 0x8b || op == 0x8c || op == 0x8f || op == 0x90 || op == 0xa3 || op == 0xa4
/-- Boolean-result ops that push {} / {0x01} — single-billed to stackPushedBytes, no arithmeticCost
    (non-VERIFY): EQUAL, NOT, 0NOTEQUAL, BOOLAND/BOOLOR, NUMEQUAL/NUMNOTEQUAL, the four comparisons, WITHIN. -/
def isBoolResultOp (op : UInt8) : Bool :=
  op == 0x87 || op == 0x91 || op == 0x92 || op == 0x9a || op == 0x9b || op == 0x9c
    || op == 0x9e || op == 0x9f || op == 0xa0 || op == 0xa1 || op == 0xa2 || op == 0xa5
/-- Fused *VERIFY comparisons (EQUALVERIFY 0x88, NUMEQUALVERIFY 0x9d): the boolean is pushed then
    consumed; a PASSING op materialized {0x01} (1 byte). (A failing one errors ⇒ op-cost is moot.) -/
def isBoolVerifyOp (op : UInt8) : Bool := op == 0x88 || op == 0x9d

/-- Cost-family of a signature opcode, INCLUDING the fused `*VERIFY` forms. `Opcode.sigKind?`
    deliberately leaves 0xad/0xaf/0xbb unmapped (they decompose into base + OP_VERIFY); this VM
    handles each fused op ATOMICALLY in `stepInstrExt`, so for the metering fold they must bill
    through their base kind. CHECKSIGVERIFY 0xad → checkSig, CHECKMULTISIGVERIFY 0xaf →
    checkMultiSig, CHECKDATASIGVERIFY 0xbb → checkDataSig. -/
def sigCostKind? (op : UInt8) : Option SigKind :=
  if op == 0xac || op == 0xad then some .checkSig
  else if op == 0xae || op == 0xaf then some .checkMultiSig
  else if op == 0xba || op == 0xbb then some .checkDataSig
  else none

/-- The per-instruction `Metrics` delta from the pre-state `s` under epoch `E`. -/
def kappa (s : State) : Metrics :=
  match s.current? with
  | none => {}
  | some instr =>
    let op := instr.opcode
    let base : Metrics := { evaluatedInstructionCount := 1 }
    if !s.executionIsActive && !Opcode.isConditional op then base   -- skipped: tick only
    else if Opcode.isPushOp op then { base with stackPushedBytes := (pushValue op instr.data).length }
    else match Opcode.arithKind? op with
      | some k =>
          match s.stack with
          | b :: a :: _ =>
              let av := vmNumberToBigInt a; let bv := vmNumberToBigInt b
              Cost.arithCost k av bv (Cost.arithResult k av bv)
          | _ => base
      | none =>
          -- hash ops bill hashDigestIterations (over the input length) + the digest push
          match Opcode.hashKind? op with
          | some hk => Cost.hashCost hk (widthAt s 0)
          | none    =>
            -- signature ops bill `signatureCheckCount` + the sighash `hashDigestIterations`
            -- (via `Cost.sigCost`, mirroring the hash arm). What is state-derivable is billed
            -- exactly; what is not is documented as un-modeled here:
            --   • CHECKDATASIG hashes the ON-STACK message (2nd item, `widthAt s 1`) → exact.
            --   • CHECKSIG hashes the tx SIGNING SERIALIZATION whose length is EXTERNAL to the
            --     stack (built from `p`, not on the stack); `Cost.sigCost` documents `serLen` as
            --     an emitter-supplied parameter, so only the double-SHA256 `+1` base is billed
            --     here (serLen = 0). The verdict's pushed byte (0/1) is oracle-dependent, hence
            --     not known pre-state → billed 0. CHECKMULTISIG is the documented 1-tick under-model.
            match sigCostKind? op with
            | some sk =>
                match sk with
                | .checkDataSig  => Cost.sigCost .checkDataSig 0 (widthAt s 1) 1  -- verdict byte (1 on pass; upper-bounds a fail)
                | .checkSig      => Cost.sigCost .checkSig 0 0 1
                | .checkMultiSig =>
                    -- Stack: <dummy> <sig₁..sig_M> <M> <pk₁..pk_N> <N> (N on top). The DUMMY element
                    -- selects the billing rule, and BCH-2026 consensus bills the two paths
                    -- DIFFERENTLY (BCHN `interpreter.cpp:1543-1544` dispatches on it):
                    --  • dummy EMPTY  ⇒ legacy/ECDSA: nKeys in one shot, gated on "not all sigs null"
                    --    (`interpreter.cpp:1689-1692`; libauth `crypto.js:246-250` agrees). UNCHANGED.
                    --  • dummy NON-EMPTY ⇒ Schnorr checkbits: ONE per signature, billed only after
                    --    that signature passes `CheckSig` (`interpreter.cpp:1616`, loop at `:1574`),
                    --    which returns SIG_NULLFAIL on the first failure (`:1611`).
                    -- The exact Schnorr count is ORACLE-DEPENDENT (it stops at the first signature
                    -- that fails to verify), which a pre-state, oracle-free `kappa` cannot know. We
                    -- bill the leading non-empty run, which IS oracle-free because an empty signature
                    -- always fails `CheckSig` (`interpreter.cpp:2562-2564`). See
                    -- `Cost.multiSigSchnorrCost` for the exact/upper-bound table: EXACT on the accept
                    -- path, on nSigs = 0, and when a signature is empty; an UPPER BOUND otherwise.
                    match s.stack[0]? with
                    | some nTop =>
                        let nKeys := (vmNumberToBigInt nTop).toNat
                        let nSigs := (s.stack[nKeys + 1]?.map (fun m => (vmNumberToBigInt m).toNat)).getD 0
                        let sigs  := (s.stack.drop (nKeys + 2)).take nSigs
                        let dummy := (s.stack[nKeys + 2 + nSigs]?).getD []
                        if !dummy.isEmpty then
                          -- `.reverse` is LOAD-BEARING: `sigs` is top-first, but BCHN's `iSig = 0` is
                          -- the DEEPEST signature (`idxBottomSig = idxTopSig + nSigsCount - 1`,
                          -- `interpreter.cpp:1571`, read at `:1593`) — the same order `Extended.lean:225`
                          -- reverses into. Scanning from the wrong end UNDER-bills (measured: deepest
                          -- sig non-null + shallower null ⇒ 0 without `.reverse`, consensus bills 1).
                          Cost.multiSigSchnorrCost (sigs.reverse.takeWhile (fun sg => !sg.isEmpty)).length
                        else if sigs.all (·.isEmpty) then Cost.sigCost .checkMultiSig 0 0 0  -- all null ⇒ no sig checks
                        else Cost.multiSigCost nKeys                                    -- 26000·nKeys
                    | none => Cost.sigCost .checkMultiSig 0 0 0
            | none =>
                if isByteOutputOp op then { base with stackPushedBytes := byteOpBytes op s }
                else if isShiftOp op then { base with stackPushedBytes := shiftBytes op s }
                else if isValueNumericOp op then
                  -- double-bill the pushed number: its byte length is the post-state top width
                  -- (Eval's own result — no re-implementation of the numeric semantics in the cost layer).
                  let r := widthAt (step1 s) 0
                  { base with arithmeticCost := r, stackPushedBytes := r }
                else if isBoolVerifyOp op then { base with stackPushedBytes := 1 }
                else if isBoolResultOp op then { base with stackPushedBytes := widthAt (step1 s) 0 }
                else { base with stackPushedBytes := copyBytes op s }

/-- One metered step: bill the pre-state's `kappa`, then take the pure state transition. -/
def stepMeter (s : State) : State :=
  { step1 s with metrics := s.metrics + kappa s }

/-- Metered run (fuel-driven). -/
def runMeter : Nat → State → State
  | 0,   s => s
  | f+1, s => if finished s then s else runMeter f (stepMeter s)

/-- The consensus op-cost of running raw bytecode from empty (loop-free fuel). -/
def evalCost (E : Epoch) (bs : Bytes) : Nat :=
  let s0 := load bs
  operationCost E (runMeter (s0.instrs.size + 1) s0).metrics

end LeanBCH.VM
