/-
  KATs for LeanBCH.Tx.Encoding, extracted into the validation layer.
-/
import LeanBCH.Tx.Encoding

namespace LeanBCH.Validation
open LeanBCH
open LeanBCH.Crypto (hash256)
open LeanBCH.Tx

/-! ## Encoder sanity checks (kernel-checked, hash-free) -/

-- Fixed-width encoders are exactly the right length and little-endian.
example : uint32LE 1 = [1, 0, 0, 0] := by decide
example : uint32LE 0xdeadbeef = [0xef, 0xbe, 0xad, 0xde] := by decide
example : uint64LE 1000 = [0xe8, 0x03, 0, 0, 0, 0, 0, 0] := by decide
example : uint64LE 0xffffffffffffffff = List.replicate 8 (0xff : UInt8) := by decide

-- CompactUint boundaries.
example : compactUint 0 = [0x00] := by decide
example : compactUint 252 = [0xfc] := by decide
example : compactUint 253 = [0xfd, 0xfd, 0x00] := by decide
example : compactUint 0xffff = [0xfd, 0xff, 0xff] := by decide
example : compactUint 0x10000 = [0xfe, 0x00, 0x00, 0x01, 0x00] := by decide
example : compactUint 0x1_0000_0000 = [0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0, 0, 0] := by decide

-- Outpoint reverses the UI-order hash to wire order and appends the 4LE index.
example :
    encodeOutpoint { outpointTransactionHash := (List.range 32).map (fun i => UInt8.ofNat i),
                     outpointIndex := 7, unlockingBytecode := [], sequenceNumber := 0 }
      = ((List.range 32).map (fun i => UInt8.ofNat i)).reverse ++ [7, 0, 0, 0] := by decide

-- No-token output: value(8LE) ++ compactUint(|lock|) ++ lock.
example :
    encodeOutput { valueSatoshis := 1000, lockingBytecode := [0x76, 0xa9], token := none }
      = [0xe8, 0x03, 0, 0, 0, 0, 0, 0] ++ [0x02] ++ [0x76, 0xa9] := by decide

-- No token → empty prefix; positive amount with no NFT → HAS_AMOUNT bitfield 0x10.
example : encodeTokenPrefix none = [] := by decide
example :
    encodeTokenPrefix (some { category := List.replicate 32 (0xAB : UInt8), amount := 100, nft := none })
      = (0xef : UInt8) :: (List.replicate 32 (0xAB : UInt8)) ++ [0x10] ++ compactUint 100 := by decide

-- UTXOS gate: length-0 when absent (NOT emptyHash), regardless of source outputs.
example : hashUtxos #[{ valueSatoshis := 1, lockingBytecode := [0x51], token := none }] false = [] := by
  decide
example : (hashUtxos #[] false).length = 0 := by decide
example : emptyHash.length = 32 := by decide

end LeanBCH.Validation
