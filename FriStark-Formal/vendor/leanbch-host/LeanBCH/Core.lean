/-
  LeanBCH.Core — shared primitives.

  The BCH VM value is a byte string. The whole proof-facing core uses `Bytes := List UInt8`,
  chosen deliberately: `List UInt8` is kernel-reducible, so both `by decide` boundary
  witnesses and `#eval` conformance runs work over the same representation. A `ByteArray`
  mirror appears ONLY at the conformance ingestion edge (hex decode), kept provably equal to
  its `List UInt8` image.
-/
namespace LeanBCH

/-- A VM byte string (stack item, script fragment, tx field). Head-order is context-local:
    stacks are head = TOP; scripts/serializations are head = FIRST byte. -/
abbrev Bytes := List UInt8

end LeanBCH
