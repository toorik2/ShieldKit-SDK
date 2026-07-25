/-
  LeanBCH.VM.Shift2026 — the BCH-2026 re-enabled/added bitwise ops as PURE helpers.

  A leaf module (no VM dependency) so it can be built + validated independently, then wired into
  `stepInstr` once the straight-line keystone is re-integrated. Semantics transcribed from
  libauth `bch-2026-bitwise.js`:
    • OP_INVERT      — bitwise NOT of every byte (`v ^ 0xff`).
    • OP_LSHIFTNUM   — numeric left shift: `value << bitCount` = `value · 2^bitCount`.
    • OP_RSHIFTNUM   — numeric (arithmetic) right shift: `value >> bitCount` = `⌊value / 2^bitCount⌋`.
    • OP_LSHIFTBIN / OP_RSHIFTBIN — fixed-length sub-byte bit-buffer shifts (implemented below).
  All four are wired into `stepInstrExt`; this leaf carries only the pure helpers.
-/
import LeanBCH.Core

namespace LeanBCH.VM
open LeanBCH

/-- OP_INVERT: flip every bit of every byte. -/
def opInvert (data : Bytes) : Bytes := data.map (fun v => v ^^^ 0xff)

/-- OP_LSHIFTNUM: numeric left shift (multiply by 2^bitCount). `bitCount` is the popped
    non-negative shift amount; `value = 0` stays 0 automatically. Uses `1 <<< bitCount` (GMP-backed
    `Nat.shiftLeft`, O(bitCount) bits) rather than `2 ^ bitCount` (naive `Nat.pow`, O(bitCount)
    multiplications) — callers MUST bound `bitCount` (≤ maxItemLen·8) so the shift can't blow up. -/
def lshiftNum (value : Int) (bitCount : Nat) : Int := value * ((1 : Nat) <<< bitCount : Nat)

/-- OP_RSHIFTNUM: numeric arithmetic right shift = floor division by 2^bitCount (matches BigInt
    `>>`, flooring toward −∞ so negatives round down). Same `1 <<< bitCount` fast path. -/
def rshiftNum (value : Int) (bitCount : Nat) : Int := Int.fdiv value ((1 : Nat) <<< bitCount : Nat)

/-! ## Binary bit-buffer shifts (fixed length) — libauth `opLShiftBin` / `opRShiftBin`.

    A bit-string shift over the raw byte buffer, output length = input length: whole-byte move
    (toward index 0 for left / index n-1 for right) then a sub-byte residual with byte-to-byte
    carry. Bits shifted past either end are dropped; zeros fill in. -/

/-- Sub-byte left residual: process right-to-left, carrying a byte's high `bitShift` bits into
    the next lower-index byte. `bitShift = 0` is the identity (guarded: `v >>> (8-0)` would be
    `v >>> 8`, which UInt8 evaluates mod-8 as `v >>> 0 = v` — a wrong non-zero carry). -/
def residualLeft (bitShift : Nat) (data : Bytes) : Bytes :=
  if bitShift == 0 then data else
  (data.foldr (fun v (p : Bytes × UInt8) =>
      ((v <<< UInt8.ofNat bitShift ||| p.2) :: p.1, v >>> UInt8.ofNat (8 - bitShift))) ([], 0)).1

/-- Sub-byte right residual: process left-to-right, carrying a byte's low `bitShift` bits into
    the next higher-index byte. `bitShift = 0` is the identity (same UInt8 mod-8 guard as above). -/
def residualRight (bitShift : Nat) (data : Bytes) : Bytes :=
  if bitShift == 0 then data else
  (data.foldl (fun (p : Bytes × UInt8) v =>
      (p.1 ++ [v >>> UInt8.ofNat bitShift ||| p.2], v <<< UInt8.ofNat (8 - bitShift))) ([], 0)).1

/-- OP_LSHIFTBIN: shift the byte buffer left (toward index 0) by `bitCount` bits, same length. -/
def lshiftBin (data : Bytes) (bitCount : Nat) : Bytes :=
  let byteShift := bitCount / 8
  let whole := data.drop byteShift ++ List.replicate (min byteShift data.length) (0 : UInt8)
  residualLeft (bitCount % 8) whole

/-- OP_RSHIFTBIN: shift the byte buffer right (toward index n-1) by `bitCount` bits, same length. -/
def rshiftBin (data : Bytes) (bitCount : Nat) : Bytes :=
  let byteShift := bitCount / 8
  let whole := List.replicate (min byteShift data.length) (0 : UInt8) ++ data.take (data.length - byteShift)
  residualRight (bitCount % 8) whole

-- KATs moved to LeanBCH/Validation/VM/Shift2026.lean (validation layer).

end LeanBCH.VM
