/-
  LeanBCH.Opt.OpFaithful — CONCRETE compute-op faithfulness (the C1 bridge, real opcodes).

  The Adapter's `sim_CALL_of_faithful` is an INTERFACE: it takes the faithfulness of a `CALL` node
  as a hypothesis. This file DISCHARGES that hypothesis for real BCH compute opcodes, closing the
  gap the red-team flagged (the optimizer emits every compute node as `Op.CALL`, and nothing proved
  those CALLs realize a real `stepInstr` op).

  ★ THE PARTIAL/TOTAL SEAM. The abstract `Op.CALL nin sem` (Basic.lean) SUCCEEDS whenever there are
  `nin` operands — it has no notion of a malformed operand. The real `stepInstr` arithmetic op FAILS
  (`.minimalEncoding`) on a non-canonically-encoded operand, and (`.divByZero`) on a zero divisor. So
  faithfulness is NOT unconditional: it holds exactly WHEN the consumed operands are minimally-encoded
  numbers (and, for div/mod, the divisor is nonzero) — which is precisely the value-DAG invariant
  (`Dag.WellFormed`/`Simulation.Inv`: every node value is a canonical VM number). This file states
  that precondition explicitly and proves the equality under it — honest, never assumed away.
-/
import LeanBCH.Opt.Basic
import LeanBCH.VM.Straightline
import LeanBCH.Cost.Arith

namespace LeanBCH.Opt.OpFaithful
open LeanBCH LeanBCH.VM LeanBCH.Opt LeanBCH.Opt.Op

/-- The single-byte opcode of a binary arithmetic kind (inverse of `Opcode.arithKind?`). -/
def arithByte : ArithKind → UInt8
  | .add => 0x93 | .sub => 0x94 | .mul => 0x95 | .div => 0x96 | .mod => 0x97

/-- The single-instruction encoding of a binary arithmetic op. -/
def arithInstr (k : ArithKind) : Instr := { opcode := arithByte k, data := [] }

/-- The CONCRETE value-DAG semantics of a binary arithmetic node over `Bytes`, matching the real
    `stepInstr` arith arm: pops `[a, b]` (bottom→top, so `a` = 2nd-from-top, `b` = top) and pushes
    the single canonically-encoded result `ofNum (arithResult k a b)`. This is the `sem` a decompiler
    must attach to an arith `CALL` node for `sim_CALL_arith` to fire. -/
def arithSem (k : ArithKind) : List Bytes → List Bytes
  | [a, b] => [ofNum (Cost.arithResult k (toNum a) (toNum b))]
  | _      => []

/-- ★ CONCRETE COMPUTE-OP FAITHFULNESS (arithmetic), the C1 seam discharged for real opcodes.
    When the top two operands `b` (top), `a` (2nd) are minimally-encoded VM numbers and — for div/mod
    — the divisor `b` is nonzero, the real `stepInstr` arithmetic op computes EXACTLY the abstract
    `Op.CALL 2 (arithSem k)`. The `readNum? · = some (toNum ·)` premises are the minimal-encoding
    invariant the value-DAG maintains; this is `Adapter.sim_CALL_of_faithful`'s hypothesis, proven. -/
theorem sim_CALL_arith (k : ArithKind) (rest al : Stack) (a b : Bytes)
    (ha : readNum? a = some (toNum a)) (hb : readNum? b = some (toNum b))
    (hnz : (k = .div ∨ k = .mod) → toNum b ≠ 0) :
    foldStraight [arithInstr k] (b :: a :: rest) al
      = LeanBCH.Opt.step (Op.CALL 2 (arithSem k)) (b :: a :: rest, al) := by
  have hfold : foldStraight [arithInstr k] (b :: a :: rest) al = stepStk (arithInstr k) (b :: a :: rest) al := by
    simp only [foldStraight]; cases stepStk (arithInstr k) (b :: a :: rest) al <;> rfl
  rw [hfold]
  -- The frozen `stepInstr` guard chain reduces in the kernel on the concrete arith opcode literal
  -- (per `cases k`); `ha`/`hb` collapse the `readNum?` matches to their `some` branch; the arith arm
  -- then computes exactly the abstract `CALL 2 (arithSem k)` (take [b,a] ⟹ reverse [a,b] ⟹ arithSem).
  cases k with
  | add => simp (config := { decide := true }) [arithInstr, arithByte, arithSem, stepStk, stepInstr,
             LeanBCH.Opt.step, ha, hb, Cost.arithResult, Opcode.arithKind?, State.advance]
  | sub => simp (config := { decide := true }) [arithInstr, arithByte, arithSem, stepStk, stepInstr,
             LeanBCH.Opt.step, ha, hb, Cost.arithResult, Opcode.arithKind?, State.advance]
  | mul => simp (config := { decide := true }) [arithInstr, arithByte, arithSem, stepStk, stepInstr,
             LeanBCH.Opt.step, ha, hb, Cost.arithResult, Opcode.arithKind?, State.advance]
  | div =>
    have hbz : (toNum b == 0) = false := by simp [hnz (Or.inl rfl)]
    simp (config := { decide := true }) [arithInstr, arithByte, arithSem, stepStk, stepInstr,
      LeanBCH.Opt.step, ha, hb, Cost.arithResult, Opcode.arithKind?, State.advance, hbz]
  | mod =>
    have hbz : (toNum b == 0) = false := by simp [hnz (Or.inr rfl)]
    simp (config := { decide := true }) [arithInstr, arithByte, arithSem, stepStk, stepInstr,
      LeanBCH.Opt.step, ha, hb, Cost.arithResult, Opcode.arithKind?, State.advance, hbz]

/-! ## Shared plumbing for the single-op compute classes below.

    Every non-arith compute opcode the optimizer emits is a one-instruction block `[opInstr op]`.
    `foldStraight_single` collapses that block's denotation to a single `stepStk` — exactly the
    reduction `sim_CALL_arith` did inline — so each class proof below is a one-line `simp`. -/

/-- The single-instruction encoding of an opcode with no immediate data. -/
def opInstr (op : UInt8) : Instr := { opcode := op, data := [] }

/-- A one-instruction straight-line block denotes exactly that instruction's stack effect. -/
theorem foldStraight_single (i : Instr) (st al : Stack) :
    foldStraight [i] st al = stepStk i st al := by
  simp only [foldStraight]; cases stepStk i st al <;> rfl

/-! ## 1. Unary numeric ops (`unaryNumOp?`): 1ADD / 1SUB / NEGATE / ABS.
    Each pops one minimally-encoded operand `x` and pushes `ofNum (f (toNum x))`. The
    `readNum? x = some (toNum x)` premise is the minimal-encoding invariant (as for arith). -/

/-- The value-DAG semantics of a unary numeric node: pops one operand, pushes `ofNum (f (toNum ·))`. -/
def unaryNumSem (f : Int → Int) : List Bytes → List Bytes
  | [x] => [ofNum (f (toNum x))]
  | _   => []

/-- CONCRETE faithfulness of `OP_1ADD` (0x8b): with a minimally-encoded operand the real `stepInstr`
    computes exactly `CALL 1 (unaryNumSem (·+1))`. -/
theorem sim_CALL_1ADD (rest al : Stack) (x : Bytes) (hx : readNum? x = some (toNum x)) :
    foldStraight [opInstr 0x8b] (x :: rest) al
      = LeanBCH.Opt.step (Op.CALL 1 (unaryNumSem (· + 1))) (x :: rest, al) := by
  rw [foldStraight_single]
  simp (config := { decide := true }) [opInstr, unaryNumSem, stepStk, stepInstr,
    LeanBCH.Opt.step, hx, Opcode.arithKind?, unaryNumOp?, State.advance]

/-- CONCRETE faithfulness of `OP_1SUB` (0x8c). -/
theorem sim_CALL_1SUB (rest al : Stack) (x : Bytes) (hx : readNum? x = some (toNum x)) :
    foldStraight [opInstr 0x8c] (x :: rest) al
      = LeanBCH.Opt.step (Op.CALL 1 (unaryNumSem (· - 1))) (x :: rest, al) := by
  rw [foldStraight_single]
  simp (config := { decide := true }) [opInstr, unaryNumSem, stepStk, stepInstr,
    LeanBCH.Opt.step, hx, Opcode.arithKind?, unaryNumOp?, State.advance]

/-- CONCRETE faithfulness of `OP_NEGATE` (0x8f). -/
theorem sim_CALL_NEGATE (rest al : Stack) (x : Bytes) (hx : readNum? x = some (toNum x)) :
    foldStraight [opInstr 0x8f] (x :: rest) al
      = LeanBCH.Opt.step (Op.CALL 1 (unaryNumSem (fun x => -x))) (x :: rest, al) := by
  rw [foldStraight_single]
  simp (config := { decide := true }) [opInstr, unaryNumSem, stepStk, stepInstr,
    LeanBCH.Opt.step, hx, Opcode.arithKind?, unaryNumOp?, State.advance]

/-- CONCRETE faithfulness of `OP_ABS` (0x90). -/
theorem sim_CALL_ABS (rest al : Stack) (x : Bytes) (hx : readNum? x = some (toNum x)) :
    foldStraight [opInstr 0x90] (x :: rest) al
      = LeanBCH.Opt.step (Op.CALL 1 (unaryNumSem (fun x => (x.natAbs : Int)))) (x :: rest, al) := by
  rw [foldStraight_single]
  simp (config := { decide := true }) [opInstr, unaryNumSem, stepStk, stepInstr,
    LeanBCH.Opt.step, hx, Opcode.arithKind?, unaryNumOp?, State.advance]

/-! ## 2. Unary boolean ops (`unaryBoolOp?`): NOT / 0NOTEQUAL.
    Same operand shape, but the result is a BCH boolean `ofBool (f (toNum x))`. -/

/-- The value-DAG semantics of a unary predicate node: pops one operand, pushes `ofBool (f (toNum ·))`. -/
def unaryBoolSem (f : Int → Bool) : List Bytes → List Bytes
  | [x] => [ofBool (f (toNum x))]
  | _   => []

/-- CONCRETE faithfulness of `OP_NOT` (0x91): logical negation `(· == 0)`. -/
theorem sim_CALL_NOT (rest al : Stack) (x : Bytes) (hx : readNum? x = some (toNum x)) :
    foldStraight [opInstr 0x91] (x :: rest) al
      = LeanBCH.Opt.step (Op.CALL 1 (unaryBoolSem (· == 0))) (x :: rest, al) := by
  rw [foldStraight_single]
  simp (config := { decide := true }) [opInstr, unaryBoolSem, stepStk, stepInstr,
    LeanBCH.Opt.step, hx, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, State.advance]

/-- CONCRETE faithfulness of `OP_0NOTEQUAL` (0x92): `(· != 0)`. -/
theorem sim_CALL_0NOTEQUAL (rest al : Stack) (x : Bytes) (hx : readNum? x = some (toNum x)) :
    foldStraight [opInstr 0x92] (x :: rest) al
      = LeanBCH.Opt.step (Op.CALL 1 (unaryBoolSem (· != 0))) (x :: rest, al) := by
  rw [foldStraight_single]
  simp (config := { decide := true }) [opInstr, unaryBoolSem, stepStk, stepInstr,
    LeanBCH.Opt.step, hx, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, State.advance]

/-! ## 3. Binary numeric ops (`binNumOp?`): MIN / MAX.
    Pops `b` (top), `a` (2nd), both minimally encoded, pushes `ofNum (f (toNum a) (toNum b))`. -/

/-- The value-DAG semantics of a binary numeric node: pops `[a, b]` (bottom→top), pushes
    `ofNum (f (toNum a) (toNum b))` — the same operand order as the arith `sem`. -/
def binNumSem (f : Int → Int → Int) : List Bytes → List Bytes
  | [a, b] => [ofNum (f (toNum a) (toNum b))]
  | _      => []

/-- CONCRETE faithfulness of `OP_MIN` (0xa3). -/
theorem sim_CALL_MIN (rest al : Stack) (a b : Bytes)
    (ha : readNum? a = some (toNum a)) (hb : readNum? b = some (toNum b)) :
    foldStraight [opInstr 0xa3] (b :: a :: rest) al
      = LeanBCH.Opt.step (Op.CALL 2 (binNumSem (fun a b => if a ≤ b then a else b))) (b :: a :: rest, al) := by
  rw [foldStraight_single]
  simp (config := { decide := true }) [opInstr, binNumSem, stepStk, stepInstr,
    LeanBCH.Opt.step, ha, hb, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, State.advance]

/-- CONCRETE faithfulness of `OP_MAX` (0xa4). -/
theorem sim_CALL_MAX (rest al : Stack) (a b : Bytes)
    (ha : readNum? a = some (toNum a)) (hb : readNum? b = some (toNum b)) :
    foldStraight [opInstr 0xa4] (b :: a :: rest) al
      = LeanBCH.Opt.step (Op.CALL 2 (binNumSem (fun a b => if a ≤ b then b else a))) (b :: a :: rest, al) := by
  rw [foldStraight_single]
  simp (config := { decide := true }) [opInstr, binNumSem, stepStk, stepInstr,
    LeanBCH.Opt.step, ha, hb, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, State.advance]

/-! ## 4. Binary boolean predicates (`binBoolOp?`): the numeric comparisons.
    BOOLAND/BOOLOR/NUMEQUAL/NUMNOTEQUAL/LESSTHAN/GREATERTHAN/LESSTHANOREQUAL/GREATERTHANOREQUAL.
    Same two-operand shape, result `ofBool (f (toNum a) (toNum b))`. -/

/-- The value-DAG semantics of a binary predicate node: pops `[a, b]`, pushes `ofBool (f (toNum a) (toNum b))`. -/
def binBoolSem (f : Int → Int → Bool) : List Bytes → List Bytes
  | [a, b] => [ofBool (f (toNum a) (toNum b))]
  | _      => []

/-- CONCRETE faithfulness of `OP_BOOLAND` (0x9a). -/
theorem sim_CALL_BOOLAND (rest al : Stack) (a b : Bytes)
    (ha : readNum? a = some (toNum a)) (hb : readNum? b = some (toNum b)) :
    foldStraight [opInstr 0x9a] (b :: a :: rest) al
      = LeanBCH.Opt.step (Op.CALL 2 (binBoolSem (fun a b => a != 0 && b != 0))) (b :: a :: rest, al) := by
  rw [foldStraight_single]
  simp (config := { decide := true }) [opInstr, binBoolSem, stepStk, stepInstr,
    LeanBCH.Opt.step, ha, hb, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.advance]

/-- CONCRETE faithfulness of `OP_BOOLOR` (0x9b). -/
theorem sim_CALL_BOOLOR (rest al : Stack) (a b : Bytes)
    (ha : readNum? a = some (toNum a)) (hb : readNum? b = some (toNum b)) :
    foldStraight [opInstr 0x9b] (b :: a :: rest) al
      = LeanBCH.Opt.step (Op.CALL 2 (binBoolSem (fun a b => a != 0 || b != 0))) (b :: a :: rest, al) := by
  rw [foldStraight_single]
  simp (config := { decide := true }) [opInstr, binBoolSem, stepStk, stepInstr,
    LeanBCH.Opt.step, ha, hb, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.advance]

/-- CONCRETE faithfulness of `OP_NUMEQUAL` (0x9c). -/
theorem sim_CALL_NUMEQUAL (rest al : Stack) (a b : Bytes)
    (ha : readNum? a = some (toNum a)) (hb : readNum? b = some (toNum b)) :
    foldStraight [opInstr 0x9c] (b :: a :: rest) al
      = LeanBCH.Opt.step (Op.CALL 2 (binBoolSem (fun a b => a == b))) (b :: a :: rest, al) := by
  rw [foldStraight_single]
  simp (config := { decide := true }) [opInstr, binBoolSem, stepStk, stepInstr,
    LeanBCH.Opt.step, ha, hb, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.advance]

/-- CONCRETE faithfulness of `OP_NUMNOTEQUAL` (0x9e). -/
theorem sim_CALL_NUMNOTEQUAL (rest al : Stack) (a b : Bytes)
    (ha : readNum? a = some (toNum a)) (hb : readNum? b = some (toNum b)) :
    foldStraight [opInstr 0x9e] (b :: a :: rest) al
      = LeanBCH.Opt.step (Op.CALL 2 (binBoolSem (fun a b => a != b))) (b :: a :: rest, al) := by
  rw [foldStraight_single]
  simp (config := { decide := true }) [opInstr, binBoolSem, stepStk, stepInstr,
    LeanBCH.Opt.step, ha, hb, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.advance]

/-- CONCRETE faithfulness of `OP_LESSTHAN` (0x9f). -/
theorem sim_CALL_LESSTHAN (rest al : Stack) (a b : Bytes)
    (ha : readNum? a = some (toNum a)) (hb : readNum? b = some (toNum b)) :
    foldStraight [opInstr 0x9f] (b :: a :: rest) al
      = LeanBCH.Opt.step (Op.CALL 2 (binBoolSem (fun a b => decide (a < b)))) (b :: a :: rest, al) := by
  rw [foldStraight_single]
  simp (config := { decide := true }) [opInstr, binBoolSem, stepStk, stepInstr,
    LeanBCH.Opt.step, ha, hb, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.advance]

/-- CONCRETE faithfulness of `OP_GREATERTHAN` (0xa0). -/
theorem sim_CALL_GREATERTHAN (rest al : Stack) (a b : Bytes)
    (ha : readNum? a = some (toNum a)) (hb : readNum? b = some (toNum b)) :
    foldStraight [opInstr 0xa0] (b :: a :: rest) al
      = LeanBCH.Opt.step (Op.CALL 2 (binBoolSem (fun a b => decide (a > b)))) (b :: a :: rest, al) := by
  rw [foldStraight_single]
  simp (config := { decide := true }) [opInstr, binBoolSem, stepStk, stepInstr,
    LeanBCH.Opt.step, ha, hb, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.advance]

/-- CONCRETE faithfulness of `OP_LESSTHANOREQUAL` (0xa1). -/
theorem sim_CALL_LESSTHANOREQUAL (rest al : Stack) (a b : Bytes)
    (ha : readNum? a = some (toNum a)) (hb : readNum? b = some (toNum b)) :
    foldStraight [opInstr 0xa1] (b :: a :: rest) al
      = LeanBCH.Opt.step (Op.CALL 2 (binBoolSem (fun a b => decide (a ≤ b)))) (b :: a :: rest, al) := by
  rw [foldStraight_single]
  simp (config := { decide := true }) [opInstr, binBoolSem, stepStk, stepInstr,
    LeanBCH.Opt.step, ha, hb, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.advance]

/-- CONCRETE faithfulness of `OP_GREATERTHANOREQUAL` (0xa2). -/
theorem sim_CALL_GREATERTHANOREQUAL (rest al : Stack) (a b : Bytes)
    (ha : readNum? a = some (toNum a)) (hb : readNum? b = some (toNum b)) :
    foldStraight [opInstr 0xa2] (b :: a :: rest) al
      = LeanBCH.Opt.step (Op.CALL 2 (binBoolSem (fun a b => decide (a ≥ b)))) (b :: a :: rest, al) := by
  rw [foldStraight_single]
  simp (config := { decide := true }) [opInstr, binBoolSem, stepStk, stepInstr,
    LeanBCH.Opt.step, ha, hb, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.advance]

/-! ## 5. Hash ops (`hashOp?`): RIPEMD160 / SHA1 / SHA256 / HASH160 / HASH256.
    Hashes are TOTAL over `Bytes` — no `readNum?` operand check — so faithfulness is UNCONDITIONAL
    (no minimal-encoding premise). Pops one item `x`, pushes `hashfn x`. -/

/-- The value-DAG semantics of a hash node: pops one item, pushes `h x`. -/
def hashSem (h : Bytes → Bytes) : List Bytes → List Bytes
  | [x] => [h x]
  | _   => []

/-- CONCRETE UNCONDITIONAL faithfulness of `OP_RIPEMD160` (0xa6). -/
theorem sim_CALL_RIPEMD160 (rest al : Stack) (x : Bytes) :
    foldStraight [opInstr 0xa6] (x :: rest) al
      = LeanBCH.Opt.step (Op.CALL 1 (hashSem Crypto.ripemd160)) (x :: rest, al) := by
  rw [foldStraight_single]
  simp (config := { decide := true }) [opInstr, hashSem, stepStk, stepInstr,
    LeanBCH.Opt.step, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?,
    bitwiseOp?, hashOp?, State.advance]

/-- CONCRETE UNCONDITIONAL faithfulness of `OP_SHA1` (0xa7). -/
theorem sim_CALL_SHA1 (rest al : Stack) (x : Bytes) :
    foldStraight [opInstr 0xa7] (x :: rest) al
      = LeanBCH.Opt.step (Op.CALL 1 (hashSem Crypto.sha1)) (x :: rest, al) := by
  rw [foldStraight_single]
  simp (config := { decide := true }) [opInstr, hashSem, stepStk, stepInstr,
    LeanBCH.Opt.step, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?,
    bitwiseOp?, hashOp?, State.advance]

/-- CONCRETE UNCONDITIONAL faithfulness of `OP_SHA256` (0xa8). -/
theorem sim_CALL_SHA256 (rest al : Stack) (x : Bytes) :
    foldStraight [opInstr 0xa8] (x :: rest) al
      = LeanBCH.Opt.step (Op.CALL 1 (hashSem Crypto.sha256)) (x :: rest, al) := by
  rw [foldStraight_single]
  simp (config := { decide := true }) [opInstr, hashSem, stepStk, stepInstr,
    LeanBCH.Opt.step, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?,
    bitwiseOp?, hashOp?, State.advance]

/-- CONCRETE UNCONDITIONAL faithfulness of `OP_HASH160` (0xa9). -/
theorem sim_CALL_HASH160 (rest al : Stack) (x : Bytes) :
    foldStraight [opInstr 0xa9] (x :: rest) al
      = LeanBCH.Opt.step (Op.CALL 1 (hashSem Crypto.hash160)) (x :: rest, al) := by
  rw [foldStraight_single]
  simp (config := { decide := true }) [opInstr, hashSem, stepStk, stepInstr,
    LeanBCH.Opt.step, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?,
    bitwiseOp?, hashOp?, State.advance]

/-- CONCRETE UNCONDITIONAL faithfulness of `OP_HASH256` (0xaa). -/
theorem sim_CALL_HASH256 (rest al : Stack) (x : Bytes) :
    foldStraight [opInstr 0xaa] (x :: rest) al
      = LeanBCH.Opt.step (Op.CALL 1 (hashSem Crypto.hash256)) (x :: rest, al) := by
  rw [foldStraight_single]
  simp (config := { decide := true }) [opInstr, hashSem, stepStk, stepInstr,
    LeanBCH.Opt.step, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?,
    bitwiseOp?, hashOp?, State.advance]

/-! ## Scope note (HONEST boundary).
    The three remaining numeric-family compute opcodes are deliberately NOT given a `CALL`
    faithfulness lemma here, because they are not a single push-a-value node the optimizer emits
    as `CALL nin sem`:
    * `OP_NUMEQUALVERIFY` (0x9d) and `OP_WITHIN` (0xa5, a 3-ary conditional) — VERIFY/ternary
      shapes whose effect is not a pure `sem` push (WITHIN is coverable but is 3-ary, outside the
      1/2-operand `CALL` classes above).
    * The bytewise ops `OP_AND/OR/XOR` (0x84–0x86) are PARTIAL (they abort on length-mismatched
      operands, like div-by-zero) and were not in the requested classes; covering them would need
      an equal-length side condition analogous to the arith `hnz`. -/

end LeanBCH.Opt.OpFaithful
