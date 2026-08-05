/-
  LeanBCH.Cost.Hash — the hashDigestIterations tier of the BCH-2026 cost model.

  libauth bills a hash op `hashDigestIterations += lengthToHashDigestIterationCount(msgLen)`
  where the count is `1 + floor((msgLen + 8) / 64)` (the number of 64-byte compression
  blocks over the length-padded message), plus one extra iteration for the double-round ops
  (HASH160/HASH256 rehash the first digest). The digest itself is pushed
  (`digestLen` bytes → stackPushedBytes). Formula is DIFFERENTIALLY pinned against real libauth
  3.1.0-next.8 by the build-time differential (`conformance/cost/`, run by
  `LeanBCH.VM.CostDifferential` — SHA1/SHA256/RIPEMD160/HASH160/HASH256 over 1-byte and 40-byte
  inputs all match exactly), not proven — libauth is the spec of record, as for `kappaStep`/`arithCost`.

  Confined to the cost layer; the VM step's HASH arm carries only the `HashKind` tag.
  This module supplies the FORMULA; the by-decide boundary witnesses + the differential
  harness are the cost-breadth HASH flesh-out.

  Transcribed from `stackcert/Stackcert/Cost/Hash.lean` (HashKind/Metrics now `LeanBCH.*`).
-/
import LeanBCH.Kinds
import LeanBCH.Cost.Metrics

namespace LeanBCH.Cost
open LeanBCH

/-- libauth `lengthToHashDigestIterationCount`: the number of 64-byte SHA/RIPEMD
    compression blocks over an 8-byte-length-padded `msgLen`-byte message. Nat floor div. -/
def hashIterations (msgLen : Nat) : Nat := 1 + (msgLen + 8) / 64

/-- Per-op `Metrics` delta of a hash opcode: `hashDigestIterations` for the preimage of byte
    length `msgLen` (+1 for the double-round HASH160/HASH256), the `digestLen`-byte digest
    billed to `stackPushedBytes`, and the usual instruction tick. -/
def hashCost (h : HashKind) (msgLen : Nat) : Metrics :=
  { evaluatedInstructionCount := 1,
    hashDigestIterations := hashIterations msgLen + (if h.doubleRound then 1 else 0),
    stackPushedBytes := h.digestLen }

/-- THE DOUBLE-ROUND SURCHARGE, stated: HASH160/HASH256 bill exactly one extra
    `hashDigestIterations` (the rehash of the first digest) over the single-round count
    `hashIterations msgLen`; the single-round ops bill exactly that count. -/
theorem hashCost_doubleRound (h : HashKind) (msgLen : Nat) :
    (hashCost h msgLen).hashDigestIterations
      = hashIterations msgLen + (if h.doubleRound then 1 else 0) := rfl

/-- The single-round ops (RIPEMD160/SHA1/SHA256) bill EXACTLY the compression-block count,
    no rehash surcharge. -/
theorem hashCost_singleRound (h : HashKind) (hs : h.doubleRound = false) (msgLen : Nat) :
    (hashCost h msgLen).hashDigestIterations = hashIterations msgLen := by
  simp only [hashCost, hs, Bool.false_eq_true, if_false, Nat.add_zero]

-- KATs moved to LeanBCH/Validation/Cost/Hash.lean (validation layer).

end LeanBCH.Cost
