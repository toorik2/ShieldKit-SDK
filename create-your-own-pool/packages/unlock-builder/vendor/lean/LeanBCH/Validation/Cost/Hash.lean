/-
  KATs for LeanBCH.Cost.Hash, extracted into the validation layer.
-/
import LeanBCH.Cost.Hash

namespace LeanBCH.Validation
open LeanBCH LeanBCH.Cost

-- Edge-case witnesses PINNING `hashDigestIterations` at every 64-byte compression-block
-- boundary + the double-round +1. `decide` reduces the Nat floor-div — no `native_decide`,
-- axioms stay [propext]. Mirrors arithCost's boundary witnesses (Arith.lean tail).

-- sha256 of 55B ⇒ 1 iter: 1 + (55+8)/64 = 1 + 63/64 = 1 (JUST under the first block edge).
example : hashIterations 55 = 1 := by decide
-- sha256 of 56B ⇒ 2 iters: 1 + (56+8)/64 = 1 + 64/64 = 2 (the length-padding tips into a
-- SECOND 64-byte compression block — the canonical off-by-one surface).
example : hashIterations 56 = 2 := by decide
-- sha256 of 119B ⇒ 2 iters: 1 + 127/64 = 1 + 1 = 2 (just under the next block edge).
example : hashIterations 119 = 2 := by decide
-- sha256 of 120B ⇒ 3 iters: 1 + 128/64 = 1 + 2 = 3 (the second block boundary).
example : hashIterations 120 = 3 := by decide

-- Full-Metrics witnesses: the digest push + iteration count together, at the boundaries.
-- SHA256 (single-round, 32-byte digest) of 55B: 1 iter, 32 pushed.
example : hashCost .sha256 55 =
  { evaluatedInstructionCount := 1, hashDigestIterations := 1, stackPushedBytes := 32 } := by decide
-- SHA256 of 56B: the block-boundary tip ⇒ 2 iters, 32 pushed.
example : hashCost .sha256 56 =
  { evaluatedInstructionCount := 1, hashDigestIterations := 2, stackPushedBytes := 32 } := by decide
-- HASH256 (double-round, 32-byte digest) of 0B: 1 + 8/64 = 1 single-round iter, +1 rehash
-- ⇒ 2 iters, 32 pushed. Pins the double-round +1 at the empty-preimage floor.
example : hashCost .hash256 0 =
  { evaluatedInstructionCount := 1, hashDigestIterations := 2, stackPushedBytes := 32 } := by decide
-- RIPEMD160 (single-round) of 0B: 1 iter, digestLen 20 pushed — the 20-vs-32 digest split.
example : hashCost .ripemd160 0 =
  { evaluatedInstructionCount := 1, hashDigestIterations := 1, stackPushedBytes := 20 } := by decide
-- The digestLen contrast, pinned directly: RIPEMD160/SHA1/HASH160 → 20, SHA256/HASH256 → 32.
example : HashKind.digestLen .ripemd160 = 20 := by decide
example : HashKind.digestLen .sha256 = 32 := by decide
-- HASH160 (double-round, but 20-byte RIPEMD160 outer digest) of 120B: single-round 3 + 1
-- rehash ⇒ 4 iters, 20 pushed. Double-round with the SHORT digest — distinct from HASH256.
example : hashCost .hash160 120 =
  { evaluatedInstructionCount := 1, hashDigestIterations := 4, stackPushedBytes := 20 } := by decide

end LeanBCH.Validation
