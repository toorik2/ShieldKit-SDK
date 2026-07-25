/-
  LeanBCH.VM.Eval — the step transition + the fuel-driven run loop, for the pure families:
  pushes, the stack/altstack ops, and INLINE control flow (IF/NOTIF/ELSE/ENDIF/VERIFY/RETURN/
  BEGIN/UNTIL) via the `ctrl` stack.

  This is the state transition only (metrics are the separate `kappa` fold, wired in `Step`).
  Faithful to libauth: only the conditional ops (IF/NOTIF/ELSE/ENDIF) process when the branch
  is inactive (to keep the conditional stack balanced, Bitcoin's fExec rule); everything else
  is skipped (advance only, still billed a tick later). Nested / repeated ELSE is representable
  directly — the inline model has no two-arm limitation. Arithmetic and hash/sig arms land in
  later modules (`VM.Arith`, `VM.Sig`).
-/
import LeanBCH.VM.State
import LeanBCH.Number
import LeanBCH.Opcode
import LeanBCH.Cost.Arith
import LeanBCH.Crypto

namespace LeanBCH.VM
open LeanBCH LeanBCH.VM.State

/-- libauth stack-item truthiness: false iff every byte is zero except an optional trailing
    0x80 (negative zero); any other nonzero byte makes it true. -/
def isTruthy : Bytes → Bool
  | []      => false
  | [x]     => x != 0 && x != 0x80
  | x :: xs => if x != 0 then true else isTruthy xs

/-- The VM-number a push opcode contributes (OP_0 → [], OP_1NEGATE → 0x81, OP_1..16 → k;
    a data push → its literal bytes). -/
def pushValue (op : UInt8) (data : Bytes) : Bytes :=
  let n := op.toNat
  if n == 0x4f then bigIntToVmNumber (-1)                                   -- OP_1NEGATE
  else if 0x51 ≤ n ∧ n ≤ 0x60 then bigIntToVmNumber (Int.ofNat (n - 0x50)) -- OP_1..OP_16
  else data                                                                -- data / OP_0

/-- Remove the element at 0-based depth `n` (0 = top). -/
def removeNth (l : Stack) (n : Nat) : Stack := l.take n ++ l.drop (n + 1)

/-- BCH_2026 `maximumStackItemLength` (a pushed item over this many bytes is invalid). -/
def maxItemLen : Nat := 10000

/-- Minimal push encoding (BCH `requireMinimalPush`): a push must use the SHORTEST opcode for
    its data — value opcodes for 0 / -1 / 1..16, the direct push for ≤75 bytes, then PUSHDATA1/
    2/4 at their thresholds. A non-minimal push is a consensus failure. -/
def isMinimalPush (op : UInt8) (data : Bytes) : Bool :=
  let n := data.length
  let o := op.toNat
  if o == 0x00 || o == 0x4f || (0x51 ≤ o && o ≤ 0x60) then true      -- OP_0 / OP_1NEGATE / OP_1..16
  else if o ≤ 0x4b then                                              -- direct push (opcode = length)
    if n == 1 then let b := (data.headD 0).toNat; !((1 ≤ b && b ≤ 16) || b == 0x81)
    else true
  else if o == 0x4c then n ≥ 76                                      -- PUSHDATA1 iff ≥ 76 bytes
  else if o == 0x4d then n ≥ 256                                     -- PUSHDATA2 iff ≥ 256
  else if o == 0x4e then n ≥ 65536                                   -- PUSHDATA4 iff ≥ 65536
  else true

/-! ## Numeric / byte-op helpers (consolidate opcode families into few dispatch arms) -/

/-- Interpret a stack item as a VM number (unchecked). -/
def toNum (b : Bytes) : Int := vmNumberToBigInt b
/-- Minimal VM-number encoding of an integer result. -/
def ofNum (n : Int) : Bytes := bigIntToVmNumber n
/-- BCH boolean: true → 0x01, false → the empty item. -/
def ofBool (b : Bool) : Bytes := if b then [1] else []

/-- BCH_2026 `maximumVmNumberByteLength` (a numeric operand over this many bytes is invalid). -/
def maxNumLen : Nat := 10000
/-- Read a stack item as a numeric OPERAND: consensus requires it be minimally encoded and
    within the VM-number length limit, else the numeric operation fails. -/
def readNum? (b : Bytes) : Option Int :=
  if b.length ≤ maxNumLen && isMinimallyEncoded b then some (vmNumberToBigInt b) else none

/-- Unary numeric ops that yield an integer (1ADD/1SUB/NEGATE/ABS). -/
def unaryNumOp? (op : UInt8) : Option (Int → Int) :=
  if op == 0x8b then some (· + 1)
  else if op == 0x8c then some (· - 1)
  else if op == 0x8f then some (fun x => -x)
  else if op == 0x90 then some (fun x => (x.natAbs : Int))
  else none

/-- Unary numeric predicates that yield a boolean (NOT / 0NOTEQUAL). -/
def unaryBoolOp? (op : UInt8) : Option (Int → Bool) :=
  if op == 0x91 then some (· == 0)
  else if op == 0x92 then some (· != 0)
  else none

/-- Binary numeric ops that yield an integer (MIN/MAX). -/
def binNumOp? (op : UInt8) : Option (Int → Int → Int) :=
  if op == 0xa3 then some (fun a b => if a ≤ b then a else b)
  else if op == 0xa4 then some (fun a b => if a ≤ b then b else a)
  else none

/-- Binary numeric predicates (BOOLAND/BOOLOR/NUMEQUAL/NUMNOTEQUAL/comparisons). -/
def binBoolOp? (op : UInt8) : Option (Int → Int → Bool) :=
  if op == 0x9a then some (fun a b => a != 0 && b != 0)
  else if op == 0x9b then some (fun a b => a != 0 || b != 0)
  else if op == 0x9c then some (fun a b => a == b)
  else if op == 0x9e then some (fun a b => a != b)
  else if op == 0x9f then some (fun a b => decide (a < b))
  else if op == 0xa0 then some (fun a b => decide (a > b))
  else if op == 0xa1 then some (fun a b => decide (a ≤ b))
  else if op == 0xa2 then some (fun a b => decide (a ≥ b))
  else none

/-- Byte-wise binary op over equal-length items (AND/OR/XOR); `none` on length mismatch. -/
def zipBytewise (f : UInt8 → UInt8 → UInt8) : Bytes → Bytes → Option Bytes
  | [],      []      => some []
  | x :: xs, y :: ys => (zipBytewise f xs ys).map (fun r => f x y :: r)
  | _,       _       => none

def bitwiseOp? (op : UInt8) : Option (UInt8 → UInt8 → UInt8) :=
  if op == 0x84 then some (· &&& ·)
  else if op == 0x85 then some (· ||| ·)
  else if op == 0x86 then some (· ^^^ ·)
  else none

/-- Hash ops backed by the Crypto layer (RIPEMD160 0xa6, SHA-1 0xa7, SHA-256 0xa8,
    HASH160 0xa9, HASH256 0xaa). -/
def hashOp? (op : UInt8) : Option (Bytes → Bytes) :=
  if op == 0xa6 then some Crypto.ripemd160
  else if op == 0xa7 then some Crypto.sha1
  else if op == 0xa8 then some Crypto.sha256
  else if op == 0xa9 then some Crypto.hash160
  else if op == 0xaa then some Crypto.hash256
  else none

/-- OP_NUM2BIN: encode integer `n` as exactly `size` little-endian sign-magnitude bytes, or
    `none` if it does not fit. Clears the sign bit off the minimal encoding, zero-pads to
    `size`, then sets the sign bit on the new final byte when negative. -/
def num2bin (n : Int) (size : Nat) : Option Bytes :=
  let m := bigIntToVmNumber n
  if m.length > size then none
  else
    let last := m.getLast?.getD 0
    let neg  := last &&& 0x80 != 0
    let mag  := m.dropLast ++ (if m.isEmpty then [] else [last &&& 0x7f])
    let padded := mag ++ List.replicate (size - mag.length) (0 : UInt8)
    if neg then some (padded.dropLast ++ [(padded.getLast?.getD 0) ||| 0x80])
    else some padded

/-- The per-opcode state transition (ip managed here; underflow / abort set `error`). Fires
    only when the branch is active or the op is conditional (guaranteed by `step1`). -/
def stepInstr (op : UInt8) (data : Bytes) (s : State) : State :=
  let adv := s.advance
  if Opcode.isPushOp op then
    let v := pushValue op data
    if !isMinimalPush op data then s.setErr .minimalEncoding
    else if v.length > maxItemLen then s.setErr .itemTooLarge
    else adv.push v
  -- inline conditional / loop control
  else if op == Opcode.OP_IF || op == Opcode.OP_NOTIF then
    if s.executionIsActive then
      match s.stack with
      | x :: xs =>
          let b := if op == Opcode.OP_IF then isTruthy x else !isTruthy x
          { adv with stack := xs, ctrl := .cond b :: s.ctrl }
      | [] => s.setErr .stackUnderflow
    else { adv with ctrl := .cond false :: s.ctrl }
  else if op == Opcode.OP_ELSE then
    match s.ctrl with
    | .cond b :: rest => { adv with ctrl := .cond (!b) :: rest }
    | _ => s.setErr .unbalancedConditional
  else if op == Opcode.OP_ENDIF then
    match s.ctrl with
    | .cond _ :: rest => { adv with ctrl := rest }
    | _ => s.setErr .unbalancedConditional
  else if op == Opcode.OP_VERIFY then
    match s.stack with
    | x :: xs => if isTruthy x then { adv with stack := xs } else s.setErr .verifyFailed
    | [] => s.setErr .stackUnderflow
  else if op == Opcode.OP_RETURN then s.setErr .opReturn
  else if op == Opcode.OP_BEGIN then { adv with ctrl := .mark s.ip :: s.ctrl }
  else if op == Opcode.OP_UNTIL then
    match s.ctrl, s.stack with
    | .mark m :: crest, x :: xs =>
        if isTruthy x then { s with stack := xs, ctrl := crest, ip := s.ip + 1 }  -- exit loop
        else { s with stack := xs, ip := m + 1 }                                   -- loop back
    | .mark _ :: _, [] => s.setErr .stackUnderflow
    | _, _ => s.setErr .unbalancedConditional
  -- stack / altstack ops (over Bytes; head = TOP)
  else if op == Opcode.OP_DUP then
    match s.stack with | x :: _ => adv.push x | [] => s.setErr .stackUnderflow
  else if op == Opcode.OP_DROP then
    match s.stack with | _ :: xs => { adv with stack := xs } | [] => s.setErr .stackUnderflow
  else if op == Opcode.OP_OVER then
    match s.stack with | x :: y :: xs => { adv with stack := y :: x :: y :: xs } | _ => s.setErr .stackUnderflow
  else if op == Opcode.OP_SWAP then
    match s.stack with | x :: y :: xs => { adv with stack := y :: x :: xs } | _ => s.setErr .stackUnderflow
  else if op == Opcode.OP_ROT then
    match s.stack with | x :: y :: z :: xs => { adv with stack := z :: x :: y :: xs } | _ => s.setErr .stackUnderflow
  else if op == Opcode.OP_NIP then
    match s.stack with | x :: _ :: xs => { adv with stack := x :: xs } | _ => s.setErr .stackUnderflow
  else if op == Opcode.OP_TUCK then
    match s.stack with | x :: y :: xs => { adv with stack := x :: y :: x :: xs } | _ => s.setErr .stackUnderflow
  else if op == Opcode.OP_TOALTSTACK then
    match s.stack with | x :: xs => { adv with stack := xs, alt := x :: s.alt } | [] => s.setErr .stackUnderflow
  else if op == Opcode.OP_FROMALTSTACK then
    match s.alt with | x :: a => { adv with stack := x :: s.stack, alt := a } | [] => s.setErr .altUnderflow
  else if op == Opcode.OP_PICK || op == Opcode.OP_ROLL then
    match s.stack with
    | nb :: rest =>
        let n := (vmNumberToBigInt nb).toNat
        match rest[n]? with
        | some v => if op == Opcode.OP_PICK then { adv with stack := v :: rest }
                    else { adv with stack := v :: removeNth rest n }
        | none => s.setErr .stackUnderflow
    | [] => s.setErr .stackUnderflow
  -- binary arithmetic (ADD/SUB/MUL/DIV/MOD): operands are VM numbers, `a` = 2nd, `b` = top
  else if let some k := Opcode.arithKind? op then
    match s.stack with
    | b :: a :: rest =>
        match readNum? a, readNum? b with
        | some av, some bv =>
            let divZero := match k with | .div | .mod => bv == 0 | _ => false
            if divZero then s.setErr .divByZero
            else { adv with stack := ofNum (Cost.arithResult k av bv) :: rest }
        | _, _ => s.setErr .minimalEncoding
    | _ => s.setErr .stackUnderflow
  -- byte-equality (OP_EQUAL / OP_EQUALVERIFY)
  else if op == Opcode.OP_EQUAL then
    match s.stack with
    | x :: y :: rest => { adv with stack := (if x == y then [1] else []) :: rest }
    | _ => s.setErr .stackUnderflow
  else if op == Opcode.OP_EQUALVERIFY then
    match s.stack with
    | x :: y :: rest => if x == y then { adv with stack := rest } else s.setErr .verifyFailed
    | _ => s.setErr .stackUnderflow
  -- unary numeric (1ADD/1SUB/NEGATE/ABS) and unary predicate (NOT/0NOTEQUAL); operand minimal
  else if let some f := unaryNumOp? op then
    match s.stack with
    | x :: rest => match readNum? x with | some xv => { adv with stack := ofNum (f xv) :: rest } | none => s.setErr .minimalEncoding
    | [] => s.setErr .stackUnderflow
  else if let some f := unaryBoolOp? op then
    match s.stack with
    | x :: rest => match readNum? x with | some xv => { adv with stack := ofBool (f xv) :: rest } | none => s.setErr .minimalEncoding
    | [] => s.setErr .stackUnderflow
  -- binary numeric (MIN/MAX) and binary predicates (BOOLAND/BOOLOR/NUM(NOT)EQUAL/compares)
  else if let some f := binNumOp? op then
    match s.stack with
    | b :: a :: rest => match readNum? a, readNum? b with
                        | some av, some bv => { adv with stack := ofNum (f av bv) :: rest } | _, _ => s.setErr .minimalEncoding
    | _ => s.setErr .stackUnderflow
  else if let some f := binBoolOp? op then
    match s.stack with
    | b :: a :: rest => match readNum? a, readNum? b with
                        | some av, some bv => { adv with stack := ofBool (f av bv) :: rest } | _, _ => s.setErr .minimalEncoding
    | _ => s.setErr .stackUnderflow
  else if op == 0x9d then                        -- OP_NUMEQUALVERIFY
    match s.stack with
    | b :: a :: rest => match readNum? a, readNum? b with
                        | some av, some bv => if av == bv then { adv with stack := rest } else s.setErr .verifyFailed
                        | _, _ => s.setErr .minimalEncoding
    | _ => s.setErr .stackUnderflow
  else if op == 0xa5 then                        -- OP_WITHIN (x min max → min ≤ x < max)
    match s.stack with
    | mx :: mn :: x :: rest => match readNum? x, readNum? mn, readNum? mx with
        | some xv, some mnv, some mxv => { adv with stack := ofBool (decide (mnv ≤ xv) && decide (xv < mxv)) :: rest }
        | _, _, _ => s.setErr .minimalEncoding
    | _ => s.setErr .stackUnderflow
  -- byte-wise bitwise (AND/OR/XOR) — equal length required
  else if let some f := bitwiseOp? op then
    match s.stack with
    | b :: a :: rest => match zipBytewise f a b with | some r => { adv with stack := r :: rest } | none => s.setErr .itemTooLarge
    | _ => s.setErr .stackUnderflow
  -- hashes (RIPEMD160/SHA256/HASH160/HASH256)
  else if let some h := hashOp? op then
    match s.stack with | x :: rest => { adv with stack := h x :: rest } | [] => s.setErr .stackUnderflow
  -- depth / size / ifdup
  else if op == Opcode.OP_DEPTH then adv.push (ofNum (Int.ofNat s.stack.length))
  else if op == Opcode.OP_SIZE then
    match s.stack with | x :: rest => { adv with stack := ofNum (Int.ofNat x.length) :: x :: rest } | [] => s.setErr .stackUnderflow
  else if op == Opcode.OP_IFDUP then
    match s.stack with | x :: rest => if isTruthy x then { adv with stack := x :: x :: rest } else adv | [] => s.setErr .stackUnderflow
  -- 2-item stack ops
  else if op == Opcode.OP_2DROP then
    match s.stack with | _ :: _ :: rest => { adv with stack := rest } | _ => s.setErr .stackUnderflow
  else if op == Opcode.OP_2DUP then
    match s.stack with | a :: b :: rest => { adv with stack := a :: b :: a :: b :: rest } | _ => s.setErr .stackUnderflow
  else if op == Opcode.OP_3DUP then
    match s.stack with | a :: b :: c :: rest => { adv with stack := a :: b :: c :: a :: b :: c :: rest } | _ => s.setErr .stackUnderflow
  else if op == Opcode.OP_2OVER then
    match s.stack with | a :: b :: c :: d :: rest => { adv with stack := c :: d :: a :: b :: c :: d :: rest } | _ => s.setErr .stackUnderflow
  else if op == Opcode.OP_2ROT then
    match s.stack with | a :: b :: c :: d :: e :: f :: rest => { adv with stack := e :: f :: a :: b :: c :: d :: rest } | _ => s.setErr .stackUnderflow
  else if op == Opcode.OP_2SWAP then
    match s.stack with | a :: b :: c :: d :: rest => { adv with stack := c :: d :: a :: b :: rest } | _ => s.setErr .stackUnderflow
  -- byte-string ops: CAT / SPLIT / BIN2NUM / NUM2BIN
  else if op == 0x7e then                        -- OP_CAT (2nd ++ top)
    match s.stack with | b :: a :: rest => { adv with stack := (a ++ b) :: rest } | _ => s.setErr .stackUnderflow
  else if op == 0x7f then                        -- OP_SPLIT (x n → x[:n] x[n:])
    match s.stack with
    | n :: x :: rest =>
        let i := (toNum n).toNat
        if i ≤ x.length then { adv with stack := x.drop i :: x.take i :: rest } else s.setErr .itemTooLarge
    | _ => s.setErr .stackUnderflow
  else if op == 0x81 then                        -- OP_BIN2NUM (minimal re-encode)
    match s.stack with | x :: rest => { adv with stack := ofNum (toNum x) :: rest } | [] => s.setErr .stackUnderflow
  else if op == 0x80 then                        -- OP_NUM2BIN (n size → size bytes)
    match s.stack with
    | sz :: n :: rest =>
        -- the VALUE `n` is re-encoded (minimal NOT required, only length-bounded); the SIZE is a
        -- normal minimally-encoded non-negative number.
        match readNum? sz with
        | some szv =>
            if n.length > maxNumLen || szv < 0 then s.setErr .itemTooLarge
            else match num2bin (toNum n) szv.toNat with
                 | some r => if r.length ≤ maxNumLen then { adv with stack := r :: rest } else s.setErr .itemTooLarge
                 | none   => s.setErr .itemTooLarge
        | none => s.setErr .minimalEncoding
    | _ => s.setErr .stackUnderflow
  -- code separator + NOPs (OP_NOP, OP_NOP1..OP_NOP10 = 0xb0..0xb9)
  else if op == Opcode.OP_CODESEPARATOR then { adv with lastCodeSep := s.ip }
  else if op == Opcode.OP_NOP || (0xb0 ≤ op.toNat && op.toNat ≤ 0xb9) then adv
  else s.setErr .unimplemented

/-- One step: skip (advance only) when the branch is inactive and the op is not conditional. -/
def step1 (s : State) : State :=
  match s.current? with
  | none        => s
  | some instr  =>
      if s.executionIsActive || Opcode.isConditional instr.opcode
      then stepInstr instr.opcode instr.data s
      else s.advance

/-- Evaluation finished: an error, or the program counter is past the end. -/
def finished (s : State) : Bool := s.error.isSome || s.ip ≥ s.instrs.size

/-- Fuel-driven run: step until finished or fuel exhausted. -/
def run : Nat → State → State
  | 0,   s => s
  | f+1, s => if finished s then s else run f (step1 s)

/-- Load bytecode into a fresh state (parse; a malformed push pre-sets the error). -/
def load (bs : Bytes) : State :=
  match parse bs with
  | .ok is        => { instrs := is }
  | .malformed is => { instrs := is, error := some .malformedPush }

/-- Run raw bytecode from empty with fuel = instruction count + 1 (adequate for loop-free
    scripts; loops need explicit fuel via `run`). -/
def eval (bs : Bytes) : State :=
  let s0 := load bs
  run (s0.instrs.size + 1) s0

end LeanBCH.VM
