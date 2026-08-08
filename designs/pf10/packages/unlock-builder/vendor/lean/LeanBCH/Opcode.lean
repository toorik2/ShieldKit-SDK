/-
  LeanBCH.Opcode — the opcode-byte classifiers + family constants.

  LeanBCH keeps instructions FLAT (blueprint S4: `Instr {opcode : UInt8, data : Bytes}`),
  so opcode *classification* does not live on a constructor — it lives here, as decidable
  `UInt8 → …` functions consumed by the VM `step` arms and the `kappa` cost fold. This is the
  seam that lets a flat, function-free instruction still feed the Kind-keyed cost tiers
  (`LeanBCH.Cost.{Arith,Hash,Sig}`), which key on `LeanBCH.Kinds.{ArithKind,HashKind,SigKind}`.

  BYTE VALUES cited verbatim to the pinned spec-of-record `@bitauth/libauth` 3.1.0-next.8:
    verifier.cash/node_modules/@bitauth/libauth/build/lib/vm/instruction-sets/bch/2023/bch-2023-opcodes.js
    verifier.cash/node_modules/@bitauth/libauth/build/lib/vm/instruction-sets/bch/2026/bch-2026-opcodes.js
  The 2026 set is `{ ...OpcodesBch2023, ...OpcodesBch2026Additions }`: BCH_2026_05 repurposes
  the four formerly-disabled codepoints 0x65/0x66 (VERIF/VERNOTIF → BEGIN/UNTIL) and
  0x89/0x8a (RESERVED1/2 → DEFINE/INVOKE), and renames the shift ops
  (0x8d/0x8e → LSHIFTNUM/RSHIFTNUM, 0x98/0x99 → LSHIFTBIN/RSHIFTBIN). libauth's enum stores
  decimals; the decimal→hex is noted at each constant.
-/
import LeanBCH.Kinds

namespace LeanBCH.Opcode

/-! ## Named opcode constants (byte values verbatim from libauth)

    Only the families LeanBCH v1 covers are named. Each `:= 0x..` equals libauth's decimal
    value (shown in `-- =NNN` comments). -/

/-- OP_0 / OP_FALSE / OP_PUSHBYTES_0. -/
def OP_0 : UInt8 := 0x00              -- =0
/-- OP_PUSHBYTES_1 (push exactly 1 byte). Start of the direct-push run 0x01..0x4b. -/
def OP_PUSHBYTES_1 : UInt8 := 0x01    -- =1
/-- OP_PUSHBYTES_75 (push exactly 75 bytes). End of the direct-push run. -/
def OP_PUSHBYTES_75 : UInt8 := 0x4b   -- =75
/-- OP_PUSHDATA_1: read a 1-byte LE length prefix, then push that many bytes. -/
def OP_PUSHDATA_1 : UInt8 := 0x4c     -- =76
/-- OP_PUSHDATA_2: read a 2-byte LE length prefix. -/
def OP_PUSHDATA_2 : UInt8 := 0x4d     -- =77
/-- OP_PUSHDATA_4: read a 4-byte LE length prefix. -/
def OP_PUSHDATA_4 : UInt8 := 0x4e     -- =78
/-- OP_1NEGATE: value push of -1 (no following bytes). -/
def OP_1NEGATE : UInt8 := 0x4f        -- =79
/-- OP_RESERVED (0x50): NOT a push; fails if executed. Sits between 1NEGATE and OP_1. -/
def OP_RESERVED : UInt8 := 0x50       -- =80
/-- OP_1 / OP_TRUE: value push of 1. Start of the value-push run 0x51..0x60. -/
def OP_1 : UInt8 := 0x51              -- =81
/-- OP_16: value push of 16. End of the value-push run. -/
def OP_16 : UInt8 := 0x60             -- =96

/-- OP_NOP (0x61). -/
def OP_NOP : UInt8 := 0x61            -- =97
/-- OP_IF (0x63). -/
def OP_IF : UInt8 := 0x63             -- =99
/-- OP_NOTIF (0x64). -/
def OP_NOTIF : UInt8 := 0x64          -- =100
/-- OP_BEGIN (0x65) — BCH_2026 loop head (formerly OP_VERIF). -/
def OP_BEGIN : UInt8 := 0x65          -- =101
/-- OP_UNTIL (0x66) — BCH_2026 loop tail (formerly OP_VERNOTIF). -/
def OP_UNTIL : UInt8 := 0x66          -- =102
/-- OP_ELSE (0x67). -/
def OP_ELSE : UInt8 := 0x67           -- =103
/-- OP_ENDIF (0x68). -/
def OP_ENDIF : UInt8 := 0x68          -- =104
/-- OP_VERIFY (0x69). -/
def OP_VERIFY : UInt8 := 0x69         -- =105
/-- OP_RETURN (0x6a). -/
def OP_RETURN : UInt8 := 0x6a         -- =106

/-- OP_TOALTSTACK (0x6b). -/
def OP_TOALTSTACK : UInt8 := 0x6b     -- =107
/-- OP_FROMALTSTACK (0x6c). -/
def OP_FROMALTSTACK : UInt8 := 0x6c   -- =108
/-- OP_2DROP (0x6d). Start of the 2-item stack run 0x6d..0x72. -/
def OP_2DROP : UInt8 := 0x6d          -- =109
/-- OP_2DUP (0x6e). -/
def OP_2DUP : UInt8 := 0x6e           -- =110
/-- OP_3DUP (0x6f). -/
def OP_3DUP : UInt8 := 0x6f           -- =111
/-- OP_2OVER (0x70). -/
def OP_2OVER : UInt8 := 0x70          -- =112
/-- OP_2ROT (0x71). -/
def OP_2ROT : UInt8 := 0x71           -- =113
/-- OP_2SWAP (0x72). End of the 2-item stack run. -/
def OP_2SWAP : UInt8 := 0x72          -- =114
/-- OP_IFDUP (0x73). -/
def OP_IFDUP : UInt8 := 0x73          -- =115
/-- OP_DEPTH (0x74). -/
def OP_DEPTH : UInt8 := 0x74          -- =116
/-- OP_DROP (0x75). -/
def OP_DROP : UInt8 := 0x75           -- =117
/-- OP_DUP (0x76). -/
def OP_DUP : UInt8 := 0x76            -- =118
/-- OP_NIP (0x77). -/
def OP_NIP : UInt8 := 0x77            -- =119
/-- OP_OVER (0x78). -/
def OP_OVER : UInt8 := 0x78           -- =120
/-- OP_PICK (0x79). -/
def OP_PICK : UInt8 := 0x79           -- =121
/-- OP_ROLL (0x7a). -/
def OP_ROLL : UInt8 := 0x7a           -- =122
/-- OP_ROT (0x7b). -/
def OP_ROT : UInt8 := 0x7b            -- =123
/-- OP_SWAP (0x7c). -/
def OP_SWAP : UInt8 := 0x7c           -- =124
/-- OP_TUCK (0x7d). -/
def OP_TUCK : UInt8 := 0x7d           -- =125
/-- OP_SIZE (0x82). -/
def OP_SIZE : UInt8 := 0x82           -- =130

/-- OP_INVERT (0x83) — bitwise NOT (re-enabled in BCH_2026). -/
def OP_INVERT : UInt8 := 0x83         -- =131
/-- OP_AND (0x84). -/
def OP_AND : UInt8 := 0x84            -- =132
/-- OP_OR (0x85). -/
def OP_OR : UInt8 := 0x85             -- =133
/-- OP_XOR (0x86). -/
def OP_XOR : UInt8 := 0x86            -- =134
/-- OP_EQUAL (0x87). -/
def OP_EQUAL : UInt8 := 0x87          -- =135
/-- OP_EQUALVERIFY (0x88). -/
def OP_EQUALVERIFY : UInt8 := 0x88    -- =136

/-- OP_LSHIFTNUM (0x8d) — BCH_2026 numeric left shift (formerly disabled OP_2MUL); implemented. -/
def OP_LSHIFTNUM : UInt8 := 0x8d      -- =141
/-- OP_RSHIFTNUM (0x8e) — BCH_2026 numeric right shift (formerly disabled OP_2DIV); implemented. -/
def OP_RSHIFTNUM : UInt8 := 0x8e      -- =142

/-- The five binary arithmetic opcodes billed through libauth's `measureArithmeticCost`. -/
def OP_ADD : UInt8 := 0x93            -- =147
def OP_SUB : UInt8 := 0x94            -- =148
def OP_MUL : UInt8 := 0x95            -- =149
def OP_DIV : UInt8 := 0x96            -- =150
def OP_MOD : UInt8 := 0x97            -- =151

/-- OP_LSHIFTBIN (0x98) — BCH_2026 binary left shift (formerly disabled OP_LSHIFT); implemented. -/
def OP_LSHIFTBIN : UInt8 := 0x98      -- =152
/-- OP_RSHIFTBIN (0x99) — BCH_2026 binary right shift (formerly disabled OP_RSHIFT); implemented. -/
def OP_RSHIFTBIN : UInt8 := 0x99      -- =153

/-- The five BCH hash opcodes, contiguous 0xa6..0xaa. -/
def OP_RIPEMD160 : UInt8 := 0xa6      -- =166
def OP_SHA1 : UInt8 := 0xa7           -- =167
def OP_SHA256 : UInt8 := 0xa8         -- =168
def OP_HASH160 : UInt8 := 0xa9        -- =169
def OP_HASH256 : UInt8 := 0xaa        -- =170

/-- OP_CODESEPARATOR (0xab). -/
def OP_CODESEPARATOR : UInt8 := 0xab  -- =171
/-- The signature-checking opcodes. -/
def OP_CHECKSIG : UInt8 := 0xac       -- =172
def OP_CHECKSIGVERIFY : UInt8 := 0xad -- =173  (fused CHECKSIG;VERIFY)
def OP_CHECKMULTISIG : UInt8 := 0xae  -- =174
def OP_CHECKMULTISIGVERIFY : UInt8 := 0xaf -- =175  (fused CHECKMULTISIG;VERIFY)
def OP_CHECKDATASIG : UInt8 := 0xba   -- =186
def OP_CHECKDATASIGVERIFY : UInt8 := 0xbb -- =187  (fused CHECKDATASIG;VERIFY)

/-- OP_DEFINE (0x89) — BCH_2026 function definition (formerly OP_RESERVED1); implemented. -/
def OP_DEFINE : UInt8 := 0x89         -- =137
/-- OP_INVOKE (0x8a) — BCH_2026 function call (formerly OP_RESERVED2); implemented. -/
def OP_INVOKE : UInt8 := 0x8a         -- =138

/-! ## Kind classifiers — the point of the lane

    Each returns `some k` exactly on its family's bytes, `none` elsewhere. `none` is the
    honest "this byte is not billed through this tier"; it is NOT a claim the byte is
    invalid. -/

/-- Binary-arithmetic classifier: 0x93→add, 0x94→sub, 0x95→mul, 0x96→div, 0x97→mod.
    Unary/compare arithmetic (0x8b..0x92, 0x9a..0xa5) is NOT here — it is billed as a plain
    op, not through `measureArithmeticCost`. -/
def arithKind? : UInt8 → Option ArithKind
  | 0x93 => some .add
  | 0x94 => some .sub
  | 0x95 => some .mul
  | 0x96 => some .div
  | 0x97 => some .mod
  | _    => none

/-- Hash classifier: contiguous 0xa6..0xaa. -/
def hashKind? : UInt8 → Option HashKind
  | 0xa6 => some .ripemd160
  | 0xa7 => some .sha1
  | 0xa8 => some .sha256
  | 0xa9 => some .hash160
  | 0xaa => some .hash256
  | _    => none

/-- Signature classifier: CHECKSIG 0xac, CHECKMULTISIG 0xae, CHECKDATASIG 0xba.
    The fused `*VERIFY` forms (0xad/0xaf/0xbb) are intentionally NOT mapped: the VM
    decomposes them into the base check + an OP_VERIFY, so they bill through the base kind. -/
def sigKind? : UInt8 → Option SigKind
  | 0xac => some .checkSig
  | 0xae => some .checkMultiSig
  | 0xba => some .checkDataSig
  | _    => none

/-! ## Push classifier

    A push either (a) reads a fixed count of following bytes, (b) reads an LE length prefix
    then that many bytes, or (c) synthesizes a value with no following bytes. -/

/-- The immediate-data shape of a push opcode. -/
inductive PushShape
  /-- Push exactly `n` following bytes (OP_0 → 0, OP_PUSHBYTES_k → k, for k ∈ 1..75). -/
  | direct (n : Nat)
  /-- Read an LE length prefix of `prefixBytes` bytes (1/2/4 for PUSHDATA1/2/4), then push
      that many bytes. -/
  | readLen (prefixBytes : Nat)
  /-- Value push with no following bytes (OP_1NEGATE, OP_1..OP_16). -/
  | value
deriving DecidableEq, Repr

/-- The push-immediate-length rule for a byte, or `none` if the byte is not a push opcode.
    OP_RESERVED (0x50) sits inside the numeric gap and is correctly `none`. -/
def pushDataLen? (b : UInt8) : Option PushShape :=
  let n := b.toNat
  if n == 0 then some (.direct 0)
  else if 1 ≤ n ∧ n ≤ 0x4b then some (.direct n)
  else if n == 0x4c then some (.readLen 1)
  else if n == 0x4d then some (.readLen 2)
  else if n == 0x4e then some (.readLen 4)
  else if n == 0x4f then some .value
  else if 0x51 ≤ n ∧ n ≤ 0x60 then some .value
  else none

/-- Is this byte any push opcode? (`pushDataLen?` succeeds.) Equivalently the bytes
    0x00..0x4f and 0x51..0x60, i.e. everything ≤ 0x60 except OP_RESERVED 0x50. -/
def isPushOp (b : UInt8) : Bool := (pushDataLen? b).isSome

/-! ## Control-flow predicates -/

/-- Conditional (branch) opcodes that push/pop the control stack: IF, NOTIF, ELSE, ENDIF.
    Loop control (BEGIN/UNTIL) is separate — see `isControlOp`. -/
def isConditional (b : UInt8) : Bool :=
  b == 0x63 || b == 0x64 || b == 0x67 || b == 0x68

/-- The standalone OP_VERIFY (0x69). The fused `*VERIFY` opcodes (EQUALVERIFY 0x88,
    NUMEQUALVERIFY 0x9d, CHECKSIGVERIFY 0xad, CHECKMULTISIGVERIFY 0xaf,
    CHECKDATASIGVERIFY 0xbb) are their base op + a verify and are not folded in here. -/
def isVerify (b : UInt8) : Bool := b == 0x69

/-- Flow-control opcodes: the conditionals (IF/NOTIF/ELSE/ENDIF), the BCH_2026 loop pair
    (BEGIN 0x65/UNTIL 0x66), VERIFY (0x69) and RETURN (0x6a). These alter `ip`/control state
    rather than the data stack. -/
def isControlOp (b : UInt8) : Bool :=
  isConditional b || b == 0x65 || b == 0x66 || isVerify b || b == 0x6a

/-! ## Deferred families (HONEST scope boundary)

    These bytes are the GENUINELY-UNMODELED BCH_2026 codepoints (0xbd..0xbf, 0xd4..0xff). They are named
    here so callers can detect them explicitly; the Kind classifiers above return `none` on
    them (never a silent mis-map), and `isDeferred` flags them positively.

    * Nullary/token introspection OP_INPUTINDEX..OP_OUTPUTTOKENAMOUNT (0xc0..0xd3 = 192..211).
    * The function/loop-adjacent ops OP_DEFINE (0x89) and OP_INVOKE (0x8a) — blueprint S4
      defers OP_EVAL/OP_INVOKE reasoning in v1.
    * The re-enabled shift ops LSHIFTNUM/RSHIFTNUM (0x8d/0x8e) and LSHIFTBIN/RSHIFTBIN
      (0x98/0x99).
    * CashToken prefix / undefined codepoints 0xbc..0xbf and 0xd4..0xff. -/
def isDeferred (b : UInt8) : Bool :=
  let n := b.toNat
  -- Genuinely-unmodeled BCH-2026 codepoints ONLY. The shifts (0x8d/8e/98/99), DEFINE/INVOKE
  -- (0x89/8a), introspection + token introspection (0xc0..0xd3) and REVERSEBYTES (0xbc) are now
  -- IMPLEMENTED and are NOT flagged (else a maintainer wiring this into a gate would wrong-reject them).
  (0xbd ≤ n ∧ n ≤ 0xbf)             -- undefined 0xbd..0xbf
    || (0xd4 ≤ n ∧ n ≤ 0xff)        -- undefined / above the top defined opcode (0xd3)

/-! ## Sanity witnesses — decide-checked against the libauth byte values. -/

example : arithKind? 0x95 = some .mul := by decide
example : arithKind? 0x93 = some .add := by decide
example : arithKind? 0x97 = some .mod := by decide
example : arithKind? OP_DIV = some .div := by decide
example : arithKind? 0x9a = none := by decide            -- OP_BOOLAND is not billed here

example : hashKind? 0xaa = some .hash256 := by decide
example : hashKind? 0xa6 = some .ripemd160 := by decide
example : hashKind? OP_SHA256 = some .sha256 := by decide

example : sigKind? 0xba = some .checkDataSig := by decide
example : sigKind? 0xac = some .checkSig := by decide
example : sigKind? 0xae = some .checkMultiSig := by decide
example : sigKind? 0xad = none := by decide              -- CHECKSIGVERIFY not folded here

example : pushDataLen? 0x4c = some (.readLen 1) := by decide
example : pushDataLen? 0x4d = some (.readLen 2) := by decide
example : pushDataLen? 0x4e = some (.readLen 4) := by decide
example : pushDataLen? 0x01 = some (.direct 1) := by decide
example : pushDataLen? 0x4b = some (.direct 75) := by decide
example : pushDataLen? 0x00 = some (.direct 0) := by decide
example : pushDataLen? OP_1NEGATE = some .value := by decide
example : pushDataLen? 0x51 = some .value := by decide
example : pushDataLen? 0x60 = some .value := by decide
example : pushDataLen? 0x50 = none := by decide          -- OP_RESERVED is not a push
example : isPushOp 0x76 = false := by decide             -- OP_DUP is not a push

example : isConditional 0x63 = true := by decide
example : isConditional 0x69 = false := by decide        -- VERIFY is not a branch
example : isVerify 0x69 = true := by decide
example : isControlOp 0x67 = true := by decide           -- ELSE
example : isControlOp 0x65 = true := by decide           -- BEGIN
example : isControlOp 0x76 = false := by decide          -- OP_DUP is not control

example : isDeferred 0xbd = true := by decide            -- 0xbd genuinely undefined in 2026
example : isDeferred 0x8a = false := by decide           -- OP_INVOKE is IMPLEMENTED
example : isDeferred 0xc0 = false := by decide           -- OP_INPUTINDEX is IMPLEMENTED
example : isDeferred 0x93 = false := by decide           -- OP_ADD is modeled

end LeanBCH.Opcode
