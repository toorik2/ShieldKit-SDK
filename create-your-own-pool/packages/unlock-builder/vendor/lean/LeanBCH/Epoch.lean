/-
  LeanBCH.Epoch — the consensus-epoch record.

  A BCH VM version fixes a set of pins + structural limits. `Epoch` collects them so a
  single value (`BCH_2026_05`) parameterizes the whole model, and a May repricing is a NEW
  epoch value rather than an edit-and-reprove across every proof. Every VM/cost signature
  carries an `Epoch`. (Precedent: the transcribed `Cost.Spine` already carries
  `maximumBytecodeLength` as an explicit theorem hypothesis.)

  HONEST CAVEAT (red-team): the *cost* pins flow through `Epoch`, but a few structural
  execution limits are still bare top-level `def`s read directly by the runtime, decoupled
  from this record — `maxItemLen`/`maxNumLen` (VM/Eval), `maxMemorySlots` (VM/Extended),
  `maxBytecodeLen` (VM/Verify), `maxCtrlDepth`. Those are NOT baked into `Epoch`; they are
  pinned to their consensus values by build-time KATs in `LeanBCH/Validation/VM/Limits.lean`
  so a silent edit fails the build. Folding them into `Epoch` is future work.

  Constants read from `@bitauth/libauth` 3.1.0-next.8, `vm/instruction-sets/bch/`, where
  the 2026 consensus SPREADS 2025 SPREADS 2023:
   • 2023: baseInstructionCost 100, signatureCheckCost 26000, hashDigestIterationCost 192
     (standard) / 64 (consensus), densityControlBaseLength 41, operationCostBudgetPerByte
     800, maximumBytecodeLength 10000, maximumStackDepth 1000, maximumControlStackDepth 100,
     schnorrSignatureLength 64.
   • 2025 (BigInt CHIP): maximumStackItemLength 10000, maximumVmNumberByteLength 10000
     (were 520 / 8 in 2023).
   • 2026: baseInstructionCost re-pinned 100, maximumMemorySlots 1000,
     maximumTokenCommitmentLength 128.

  The per-input ABORT budgets (operation cost / hash iterations / sig checks) are DERIVED
  from the density-control length, not fixed pins — see the budget functions below.
-/
import LeanBCH.Core

namespace LeanBCH

/-- The consensus pins + structural limits of one BCH VM version. -/
structure Epoch where
  -- op-cost RATE pins
  baseInstructionCost          : Nat  -- 100    : per evaluated instruction
  signatureCheckCost           : Nat  -- 26000  : per signature check
  hashDigestIterationCost      : Nat  -- 192 standard / 64 consensus
  -- density: the 800:1 op→byte inversion
  densityControlBaseLength     : Nat  -- 41
  operationCostBudgetPerByte   : Nat  -- 800
  -- structural limits
  maximumBytecodeLength        : Nat  -- 10000
  maximumStackItemLength       : Nat  -- 10000 (2025; was 520)
  maximumVmNumberByteLength    : Nat  -- 10000 (2025 BigInt; was 8)
  maximumStackDepth            : Nat  -- 1000
  maximumControlStackDepth     : Nat  -- 100
  maximumMemorySlots           : Nat  -- 1000 (2026)
  maximumTokenCommitmentLength : Nat  -- 128 (2026)
  schnorrSignatureLength       : Nat  -- 64
deriving Repr, DecidableEq

/-- **BCH_2026_05** — the May-2026 consensus (2026 ∘ 2025 ∘ 2023), standard hash rate (192).
    The single re-audit surface on a VM upgrade: bump this record. -/
def BCH_2026_05 : Epoch where
  baseInstructionCost          := 100
  signatureCheckCost           := 26000
  hashDigestIterationCost      := 192
  densityControlBaseLength     := 41
  operationCostBudgetPerByte   := 800
  maximumBytecodeLength        := 10000
  maximumStackItemLength       := 10000
  maximumVmNumberByteLength    := 10000
  maximumStackDepth            := 1000
  maximumControlStackDepth     := 100
  maximumMemorySlots           := 1000
  maximumTokenCommitmentLength := 128
  schnorrSignatureLength       := 64

/-- **BCH_2026_05_CONSENSUS** — identical to `BCH_2026_05` except the hash-iteration op-cost factor
    is the CONSENSUS (block) rate 64 rather than the STANDARD (relay) rate 192 (they relate by the
    3× `HASH_COST_PENALTY_FOR_STD_TXNS`). The vmb corpus is generated at the standard rate, so
    `verifyInput`/`verifyTransaction` use `BCH_2026_05` (192) to match it; this epoch is the value a
    pure block-validator would select — the 64 is now a live constant, not a comment. -/
def BCH_2026_05_CONSENSUS : Epoch := { BCH_2026_05 with hashDigestIterationCost := 64 }

namespace Epoch

/-- Density-control length for an input whose unlocking bytecode is `ulen` bytes
    (libauth: `densityControlBaseLength + unlockingBytecode.length`). -/
def densityControlLength (E : Epoch) (ulen : Nat) : Nat :=
  E.densityControlBaseLength + ulen

/-- The per-input operation-cost BUDGET = `densityControlLength · operationCostBudgetPerByte`
    — the maximum `operationCost` an input of unlocking length `ulen` may spend. This is the
    800:1 op→byte inversion, epoch-relative and derived (not a baked ceiling). -/
def maxOperationCost (E : Epoch) (ulen : Nat) : Nat :=
  E.densityControlLength ulen * E.operationCostBudgetPerByte

/-- The op-cost budget is monotone in the unlocking length — a bigger witness buys a bigger
    budget (the witness↔budget trade the offload law rests on), epoch-relative. -/
theorem maxOperationCost_mono (E : Epoch) {u1 u2 : Nat} (h : u1 ≤ u2) :
    E.maxOperationCost u1 ≤ E.maxOperationCost u2 := by
  unfold maxOperationCost densityControlLength
  exact Nat.mul_le_mul_right _ (Nat.add_le_add_left h _)

end Epoch
end LeanBCH
