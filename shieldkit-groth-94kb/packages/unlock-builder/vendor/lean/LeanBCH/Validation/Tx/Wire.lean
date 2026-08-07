/-
  KATs for LeanBCH.Tx.Wire, extracted into the validation layer.

  The wire codec's round-trip witnesses (`decode ∘ encode = id`) and their test-only fixtures,
  moved out of the model file so `LeanBCH/Tx/Wire.lean` reads as pure semantics. All KATs still
  EXECUTE under `lake build LeanBCHValidation`.
-/
import LeanBCH.Tx.Wire

namespace LeanBCH.Validation
open LeanBCH
open LeanBCH.Tx

/-! ## Round-trip validation — `decode ∘ encode = id` (kernel-checked, `by decide`).

    The header's "validated by round-trip" claim, made concrete: these witnesses run the real
    encoder then decoder and check the result is the ORIGINAL structure (needs `DecidableEq` on the
    tx types). Fixed byte streams, fuel-free — no `native_decide`, no VM. A minimal 1-in/1-out tx
    with a 32-byte outpoint hash and a non-`0xef` locking script (so `decodeField` reads no token),
    exercised token-less, with an NFT (commitment), with a fungible amount, and at the maximum
    fungible amount. -/

/-- Token-less main transaction (32-byte hash, OP_1 locking). -/
def rtMainTx : Transaction :=
  { version := 2
    inputs := #[{ outpointTransactionHash := List.replicate 32 (0x11 : UInt8), outpointIndex := 0
                  unlockingBytecode := [0x51], sequenceNumber := 0xffffffff }]
    outputs := #[{ valueSatoshis := 1000, lockingBytecode := [0x51], token := none }]
    locktime := 0 }

/-- NFT (immutable, with commitment). -/
def rtNftTok : TokenData :=
  { category := List.replicate 32 (0x22 : UInt8), amount := 0
    nft := some { capability := .none, commitment := [0xaa, 0xbb] } }
/-- Fungible amount, no NFT. -/
def rtAmtTok : TokenData := { category := List.replicate 32 (0x33 : UInt8), amount := 5000, nft := none }
/-- The MAXIMUM fungible amount `2^63−1` (`maxFungibleTokenAmount`) — the decoder's `amount > 2^63−1`
    reject bound IS this consensus cap, so a well-formed token round-trips and an over-cap amount is
    correctly rejected on decode (reconciling the encoder's unbounded `Nat` field with the decoder). -/
def rtMaxTok : TokenData := { category := List.replicate 32 (0x44 : UInt8), amount := 9223372036854775807, nft := none }
/-- Over the cap by one — must NOT decode. -/
def rtOverTok : TokenData := { category := List.replicate 32 (0x44 : UInt8), amount := 9223372036854775808, nft := none }

private def rtWith (t : TokenData) : Transaction :=
  { rtMainTx with outputs := #[{ valueSatoshis := 1000, lockingBytecode := [0x51], token := some t }] }

example : decodeTransaction (encodeTransaction rtMainTx)         = some rtMainTx         := by decide
example : decodeTransaction (encodeTransaction (rtWith rtNftTok)) = some (rtWith rtNftTok) := by decide
example : decodeTransaction (encodeTransaction (rtWith rtAmtTok)) = some (rtWith rtAmtTok) := by decide
example : decodeTransaction (encodeTransaction (rtWith rtMaxTok)) = some (rtWith rtMaxTok) := by decide
-- amount-bound reconciliation: one over the consensus cap does NOT decode.
example : decodeTransaction (encodeTransaction (rtWith rtOverTok)) = none := by decide

/-- The `sourceOutputsHex` list form (`decodeProgram`'s second input) round-trips too. -/
def rtSos : Array Output :=
  #[{ valueSatoshis := 6000, lockingBytecode := [0x51], token := none },
    { valueSatoshis := 9000, lockingBytecode := [0x52], token := some rtAmtTok }]
example : decodeOutputList (encodeOutputList rtSos) = some rtSos := by decide

end LeanBCH.Validation
