/-
  LeanBCH.VM.State — the machine state + the inline control stack.

  ONE state record threads a program counter over a parsed `Array Instr`. Control flow is
  INLINE (no structured `Prog`/`Item` tree): the `ctrl` stack carries libauth's mixed
  conditional/loop/return frames, so IF/NOTIF/ELSE/ENDIF/BEGIN/UNTIL/EVAL are ordinary steps.
  Stacks are `List Bytes`, head = TOP. The transaction context is NOT in the state — it is a
  separate parameter to `step` — which keeps cost/correctness reasoning transaction-free.

  Cost is a real accumulator here (BCH-2026 op-cost aborts are genuine consensus semantics),
  but `step` factors as `stepCore` (this state transition, metrics-free) plus a `kappa` metric
  delta — so within budget the metering is provably observation-only (the `step_factor` seam).
-/
import LeanBCH.Core
import LeanBCH.VM.Instr
import LeanBCH.Cost.Metrics

namespace LeanBCH.VM
open LeanBCH LeanBCH.Cost

/-- A VM stack: a list of byte-string items, head = TOP. -/
abbrev Stack := List Bytes

/-- A control-stack entry. `cond` = an IF/NOTIF branch flag (whether this branch executes);
    `mark ip` = a BEGIN loop's re-entry instruction pointer; `frame body ret` = an EVAL/INVOKE
    return frame (restore `body`/`ret` on completion). Mirrors libauth's mixed control stack. -/
inductive Ctrl where
  | cond  : Bool → Ctrl
  | mark  : Nat → Ctrl
  | frame : Array Instr → Nat → Ctrl
deriving Repr, Inhabited

/-- Abort reasons (libauth `applyError` kinds; total — a stuck state carries one). -/
inductive Err where
  | stackUnderflow | altUnderflow | invalidOpcode | disabledOpcode
  | unbalancedConditional | verifyFailed | opReturn | malformedPush
  | numberTooLarge | itemTooLarge | minimalEncoding | budgetExceeded
  | divByZero | unimplemented
  /-- An introspection index (OP_UTXOVALUE / OP_OUTPUTBYTECODE / …) that is negative or names a
      non-existent input / output / UTXO. Mirrors libauth `invalidTransaction{Utxo,Input,Output}Index`. -/
  | invalidTxIndex
  /-- BCH-2026 FUNCTIONS chip (libauth `bch-2026-functions.js` / `bch-2026-errors.js`):
      an OP_DEFINE identifier longer than `maximumFunctionIdentifierLength`
      (`functionIdentifierExcessiveLength`). -/
  | functionIdExcessive
  /-- OP_DEFINE of an identifier already in the function table
      (`functionIdentifierPreviouslyDefined`). -/
  | functionIdRedefined
  /-- OP_INVOKE of an identifier with no table entry (`functionIdentifierUndefined`). -/
  | functionIdUndefined
  /-- OP_INVOKE of a function whose stored body does not decode (`malformedFunction`). -/
  | malformedFunction
  /-- The control stack (IF/BEGIN conds + INVOKE frames) exceeded `maximumControlStackDepth`
      (libauth `exceededMaximumControlStackDepth`, an `every`-hook check). -/
  | controlStackDepth
  /-- The memory slots `stack + altstack + functionCount` exceeded `maximumMemorySlots`
      (BCH-2026 libauth `exceededMaximumMemorySlots`, an `every`-hook check). Subsumes the
      classic `exceededMaximumStackDepth` (`stack + altstack > maximumStackDepth`) for
      accept/reject, since `functionCount ≥ 0` and both limits are 1000. -/
  | memorySlots
deriving DecidableEq, Repr, Inhabited

/-- The full machine state. -/
structure State where
  stack   : Stack := []
  alt     : Stack := []
  ctrl    : List Ctrl := []
  instrs  : Array Instr := #[]
  ip      : Nat := 0
  metrics : Metrics := {}
  /-- Byte offset of the last executed OP_CODESEPARATOR (for the checksig covered-bytecode). -/
  lastCodeSep : Nat := 0
  /-- The raw bytecode of the CURRENTLY-running script (unlocking / locking / redeem), set by
      `loadFrom`/`runScript`. This is the checksig "covered bytecode" (scriptCode) for the common
      NO-codeseparator case (`lastCodeSep = 0`). A mid-script OP_CODESEPARATOR that would trim the
      covered bytecode to the suffix after it is NOT reflected here (deferred — see `Extended`). -/
  scriptCode : Bytes := []
  /-- BCH-2026 FUNCTIONS chip (libauth `AuthenticationProgramStateFunctions.functionTable`): the
      identifier → body-bytes map built by OP_DEFINE and read by OP_INVOKE. An assoc list (libauth
      keys it by `binToHex`; here the raw identifier `Bytes` and `List UInt8` `DecidableEq` are the
      equivalent key). Its length is libauth's `functionCount` (the memory-slot contribution). A
      pure State field — keystone-safe (like `scriptCode`; the frozen straight-line proofs match on
      `error`/stack/alt/ctrl/ip only). -/
  functionTable : List (Bytes × Bytes) := []
  /-- Per-input op-cost budget for the "withinLimits" mid-execution abort (the metered run cuts off
      an excessive/looping script the moment `operationCost` exceeds this, rather than grinding to
      fuel exhaustion). Default = the largest any per-input budget can be, so a State built without
      an explicit budget (witnesses / core runs) never aborts early. Pure field — keystone-safe
      (like `scriptCode`/`functionTable`; the frozen straight-line proofs match on `stack`/`ip`). -/
  budget  : Nat := (10000 + 41) * 800
  error   : Option Err := none
deriving Repr, Inhabited

namespace State

/-- Whether the current branch is live: no `cond false` anywhere on the control stack. -/
def executionIsActive (s : State) : Bool := s.ctrl.all (fun c => match c with | .cond b => b | _ => true)

/-- The instruction under the program counter, if in range. -/
def current? (s : State) : Option Instr := s.instrs[s.ip]?

/-- Advance the program counter by one. -/
def advance (s : State) : State := { s with ip := s.ip + 1 }

/-- Set the abort reason (idempotent-ish: keep the first error). -/
def setErr (s : State) (e : Err) : State := { s with error := some e }

/-- Push an item on the main stack. -/
def push (s : State) (b : Bytes) : State := { s with stack := b :: s.stack }

/-- Pop the top item, or `none` on underflow. -/
def pop1? (s : State) : Option (Bytes × State) :=
  match s.stack with
  | []      => none
  | x :: xs => some (x, { s with stack := xs })

/-- Pop the top two items (`(top, second)`), or `none` on underflow. -/
def pop2? (s : State) : Option (Bytes × Bytes × State) :=
  match s.stack with
  | x :: y :: xs => some (x, y, { s with stack := xs })
  | _            => none

end State
end LeanBCH.VM
