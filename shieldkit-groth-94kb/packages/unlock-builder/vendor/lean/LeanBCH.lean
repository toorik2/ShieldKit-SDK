/-
  LeanBCH — a formalized, differentially-validated model of the Bitcoin Cash (BCH-2026)
  script VM and its consensus op-cost model, in Lean 4 core (NO mathlib). Apache-2.0.

  A *model* validated against reality (libauth + the official vmb_tests) — NOT the
  authoritative consensus spec (BCHN is canonical) and NOT proven-equivalent. secp256k1 is
  an explicit oracle touching only accept/reject, never a cost metric. The differential is
  the one trust seam; everything above it is machine-checked.
-/
import LeanBCH.Core
import LeanBCH.Epoch
import LeanBCH.Kinds
import LeanBCH.Number
import LeanBCH.Opcode
import LeanBCH.Crypto
import LeanBCH.Cost.Metrics
import LeanBCH.Cost.Spine
import LeanBCH.Cost.Arith
import LeanBCH.Cost.Hash
import LeanBCH.Cost.Sig
import LeanBCH.Tx.Types
import LeanBCH.Tx.Encoding
import LeanBCH.Tx.Sighash
import LeanBCH.VM.Instr
import LeanBCH.VM.State
import LeanBCH.VM.Eval
import LeanBCH.VM.Meter
import LeanBCH.VM.Straightline
import LeanBCH.VM.Verify
import LeanBCH.Tx.Wire
import LeanBCH.VM.Shift2026
import LeanBCH.VM.RunStraight
import LeanBCH.VM.Extended
import LeanBCH.VM.Standard
import LeanBCH.VM.Invariants
-- The libauth cost differential moved to the validation layer: LeanBCH/Validation/CostDifferential.lean
-- (built via `lake build LeanBCHValidation`); the core barrel stays pure model.
