/-
  LeanBCH.Validation.VM.Limits — consensus-limit PINS (red-team remediation).

  A red-team audit showed the necessity closure gate is blind to a pure numeric-literal edit: the bare
  structural limits below (read directly by the runtime, not routed through `Epoch`) could be weakened
  — e.g. `maxMemorySlots 1000 → 9999999` — with `Meta/necessity.json` byte-identical and the whole
  build green, silently certifying a 10000x weaker consensus envelope. These `by decide` KATs pin each
  bare limit to its BCH-2026 consensus value (source: @bitauth/libauth 3.1.0-next.8, `vm/…/bch/`), so
  any silent edit now FAILS `lake build LeanBCHValidation`. This is the defense for the literal VALUES;
  the closure gate defends the proof-term name-set. Update deliberately on a genuine consensus repricing.
-/
import LeanBCH.VM.Extended
import LeanBCH.VM.Verify

namespace LeanBCH.Validation
open LeanBCH.VM

-- Item / number byte-length caps (VM/Eval).
example : maxItemLen = 10000 := by decide
example : maxNumLen = 10000 := by decide
-- Per-input bytecode-length cap (VM/Verify).
example : maxBytecodeLen = 10000 := by decide
-- FUNCTIONS-chip limits (VM/Extended): id length, control-stack depth, memory slots.
example : maxFunctionIdLen = 7 := by decide
example : maxCtrlDepth = 100 := by decide
example : maxMemorySlots = 1000 := by decide

end LeanBCH.Validation
