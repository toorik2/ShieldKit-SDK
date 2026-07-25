/-
  LeanBCH.VM.Instr — the flat, function-free instruction + the bytecode parser.

  Per the blueprint's unified design, an instruction is just `{ opcode : UInt8; data }` — no
  semantic function field (that lives in `step`), so it `deriving DecidableEq, Repr` and is a
  faithful mirror of libauth's opcode-table dispatch. `parse` is a left-to-right fold over the
  raw bytes: an operation is one byte; a push opcode consumes its immediate data (a fixed count
  for 0x01..0x4b, or a 1/2/4-byte little-endian length prefix for PUSHDATA1/2/4). Only the FINAL
  instruction can be `malformed` (a push wanting more bytes than remain) — a consensus failure
  the whole evaluation must reject.
-/
import LeanBCH.Core
import LeanBCH.Opcode

namespace LeanBCH.VM
open LeanBCH

/-- One decoded instruction: the opcode byte plus, for push opcodes, its immediate data. -/
structure Instr where
  opcode : UInt8
  data   : Bytes := []
deriving DecidableEq, Repr, Inhabited

/-- Read a little-endian `k`-byte length prefix off the front of `bs`; `none` if short. -/
def readLE : (k : Nat) → Bytes → Option (Nat × Bytes)
  | 0,     bs      => some (0, bs)
  | _+1,   []      => none
  | k+1,   b :: bs => (readLE k bs).map (fun (n, rest) => (b.toNat + 256 * n, rest))

/-- Split `n` data bytes off the front; `none` if fewer than `n` remain (malformed tail). -/
def takeData : (n : Nat) → Bytes → Option (Bytes × Bytes)
  | 0,   bs      => some ([], bs)
  | _+1, []      => none
  | n+1, b :: bs => (takeData n bs).map (fun (d, rest) => (b :: d, rest))

/-- Result of parsing: a fully-decoded instruction array, or a decoded prefix ending in a
    malformed push (consensus-invalid). -/
inductive Parsed where
  | ok        : Array Instr → Parsed
  | malformed : Array Instr → Parsed
deriving Repr

/-- One decode step: given the opcode byte and the remaining bytes, produce the instruction
    and the leftover, or `none` on a malformed push tail. -/
def decode1 (op : UInt8) (rest : Bytes) : Option (Instr × Bytes) :=
  match Opcode.pushDataLen? op with
  | some (.direct n)      => (takeData n rest).map (fun (d, r) => ({ opcode := op, data := d }, r))
  | some (.readLen k)     =>
      (readLE k rest).bind (fun (n, r1) =>
        (takeData n r1).map (fun (d, r2) => ({ opcode := op, data := d }, r2)))
  | some .value | none    => some ({ opcode := op, data := [] }, rest)

/-- Fuel-driven parse fold (fuel ≥ byte count always suffices; `parse` supplies it). -/
def parseFuel : Nat → Array Instr → Bytes → Parsed
  | 0,     acc, _       => .ok acc
  | _+1,   acc, []      => .ok acc
  | f+1,   acc, b :: bs =>
      match decode1 b bs with
      | some (i, rest) => parseFuel f (acc.push i) rest
      | none           => .malformed (acc.push { opcode := b, data := bs })

/-- Parse raw bytecode into instructions. `malformed` iff a push's data runs past the end. -/
def parse (bs : Bytes) : Parsed := parseFuel (bs.length + 1) #[] bs

end LeanBCH.VM
