/-
  LeanBCH.Validation — the VALIDATION layer barrel.

  Known-answer tests, differentials, and their shared fixtures, extracted OUT of the model files so
  `LeanBCH/**` reads as pure semantics. Everything here imports the model; the model never imports
  this. `lake build LeanBCHValidation` builds it, so every #eval/#guard/example still EXECUTES.
  See TRUST_MANIFEST.md (Tier 2) and the KAT-conservation gate (tools/health/katcount.mjs).
-/
import LeanBCH.Validation.Fixtures
import LeanBCH.Validation.Verify
import LeanBCH.Validation.CostDifferential
import LeanBCH.Validation.DefineCost
import LeanBCH.Validation.Cost.Hash
import LeanBCH.Validation.Cost.Arith
import LeanBCH.Validation.VM.Shift2026
import LeanBCH.Validation.VM.Standard
import LeanBCH.Validation.VM.Limits
import LeanBCH.Validation.VM.MultiSigBilling
import LeanBCH.Validation.Tx.Wire
import LeanBCH.Validation.Tx.Encoding
