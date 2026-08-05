/-
  LeanBCH.Kinds — the arithmetic / hash / signature opcode families, as zero-dependency
  tag types. Consumed by `LeanBCH.Opcode` (byte → kind classifiers), the cost tiers
  (`LeanBCH.Cost.{Arith,Hash,Sig}`), and the VM step's arithmetic/hash/sig arms.
-/
namespace LeanBCH

/-- The five binary arithmetic opcodes billed through libauth's `measureArithmeticCost` /
    `pushToStackVmNumberChecked` path (OP_ADD 0x93, OP_SUB 0x94, OP_MUL 0x95, OP_DIV 0x96,
    OP_MOD 0x97). -/
inductive ArithKind
  | mul | div | mod | add | sub
deriving DecidableEq, Repr

/-- Does the op run libauth's `measureArithmeticCost` operand pre-charge (`|a|·|b|`)?
    Only MUL/DIV/MOD do; ADD/SUB skip it. -/
def ArithKind.billsOperands : ArithKind → Bool
  | mul | div | mod => true
  | add | sub       => false

/-- The five BCH hash opcodes: OP_RIPEMD160 0xa6, OP_SHA1 0xa7, OP_SHA256 0xa8,
    OP_HASH160 0xa9, OP_HASH256 0xaa. HASH160/HASH256 are double-round (hash of hash). -/
inductive HashKind
  | ripemd160 | sha1 | sha256 | hash160 | hash256
deriving DecidableEq, Repr

/-- Double-round ops rehash the first digest, costing one extra iteration
    (libauth `resultIsHashed`). -/
def HashKind.doubleRound : HashKind → Bool
  | hash160 | hash256 => true
  | _                 => false

/-- Digest byte length pushed: RIPEMD160/SHA1/HASH160 → 20, SHA256/HASH256 → 32. -/
def HashKind.digestLen : HashKind → Nat
  | ripemd160 | sha1 | hash160 => 20
  | sha256 | hash256           => 32

/-- The BCH signature opcodes: OP_CHECKSIG 0xac, OP_CHECKDATASIG 0xba,
    OP_CHECKMULTISIG 0xae. -/
inductive SigKind
  | checkSig | checkDataSig | checkMultiSig
deriving DecidableEq, Repr

end LeanBCH
