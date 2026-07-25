/-
  LeanBCH.Validation.VM.Standard — KATs for LeanBCH.VM.Standard, extracted into the validation layer.

  Known-answer tests for the OPTIONAL relay-policy (standardness) layer: output-template
  classification (`classifyOutput`) and the token-aware dust threshold (`dustThreshold`). The
  structural template facts are `decide`-checked (fuel-free, kernel-verified); the OP_RETURN witness
  is an `#eval` because `classifyOutput` reaches `parse` via `isPushOnly` (compiled-only, not
  kernel-reducible). Validation imports the model; the model never imports this.
-/
import LeanBCH.VM.Standard

namespace LeanBCH.Validation
open LeanBCH LeanBCH.VM LeanBCH.Tx LeanBCH.Crypto
open LeanBCH.VM.Standard

/-! ### Self-tests (kernel `decide`, no oracle) -/

-- P2PKH template (25 bytes) classifies as P2PKH; a 1-byte bare script is bareScript in 2026.
example : classifyOutput policy2026
    ([0x76,0xa9,0x14] ++ List.replicate 20 0x00 ++ [0x88,0xac]) = OutputKind.p2pkh := by decide
example : classifyOutput policy2026 [0x51] = OutputKind.bareScript := by decide
-- P2SH-20 / P2SH-32 templates.
example : classifyOutput policy2026 ([0xa9,0x14] ++ List.replicate 20 0x11 ++ [0x87]) = OutputKind.p2sh20 := by decide
example : classifyOutput policy2026 ([0xaa,0x20] ++ List.replicate 32 0x22 ++ [0x87]) = OutputKind.p2sh32 := by decide
-- OP_RETURN is standard + dust-exempt (threshold 0). (classifyOutput uses `parse` via isPushOnly,
-- which is compiled-only, not kernel-reducible — so this is a runtime #eval witness, not `decide`.
-- It ASSERTS: throws (fails the build) unless the classification is `opReturn`. [red-team: was a
-- bare print — the sole witness for the OP_RETURN classify branch, which no `decide` KAT covers.])
#eval (match classifyOutput policy2026 [0x6a, 0x02, 0xab, 0xcd] with
       | OutputKind.opReturn => (pure () : IO Unit)
       | k => throw (IO.userError s!"OP_RETURN misclassified as {repr k}"))
example : dustThreshold policy2026 { valueSatoshis := 0, lockingBytecode := [0x6a], token := none } = 0 := by decide
-- A plain P2PKH output serializes to 34 bytes ⇒ dust threshold 3·(34+148) = 546 sat.
example : dustThreshold policy2026
    { valueSatoshis := 0, lockingBytecode := [0x76,0xa9,0x14] ++ List.replicate 20 0x00 ++ [0x88,0xac], token := none }
    = 546 := by decide
-- A non-template script is non-standard when the bare-script (P2S) rule is off (pre-May-2026).
example : classifyOutput { bareScriptStandard := false } [0xba, 0xbe, 0xef] = OutputKind.nonStandard := by decide

end LeanBCH.Validation
