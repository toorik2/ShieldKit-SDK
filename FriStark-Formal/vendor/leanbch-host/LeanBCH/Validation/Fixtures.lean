/-
  LeanBCH.Validation.Fixtures — SHARED test fixtures for the validation layer.

  Definitions only (no assertions). These are the fixtures used by MORE THAN ONE validation module,
  so they live here rather than in any single one. Validation modules import the model + this file;
  the model never imports validation.
-/
import LeanBCH.VM.Verify

namespace LeanBCH.Validation
open LeanBCH LeanBCH.VM LeanBCH.VM.State LeanBCH.Tx LeanBCH.Cost LeanBCH.Crypto

/-- A minimal 1-input Program whose spent UTXO's locking bytecode is `locking` (P2S style: the whole
    tested script IS the locking script; empty push-only unlocking). Shared by the FUNCTIONS-chip
    witnesses (Validation.Verify) and the libauth cost differential (Validation.CostDifferential). -/
def fnProg (locking : Bytes) : Program :=
  { transaction :=
      { version := 2
        inputs := #[{ outpointTransactionHash := List.replicate 32 (0x00 : UInt8),
                      outpointIndex := 0, unlockingBytecode := [], sequenceNumber := 0 }]
        outputs := #[{ valueSatoshis := 1000, lockingBytecode := [0x51], token := none }]
        locktime := 0 }
    sourceOutputs := #[{ valueSatoshis := 6000, lockingBytecode := locking, token := none }]
    inputIndex := 0 }

/-- Run raw script bytes from the empty stack through the metered `runExt`. -/
def fnRun (bs : Bytes) : State := runScript Secp256k1.reject (fnProg bs) [] bs

end LeanBCH.Validation
