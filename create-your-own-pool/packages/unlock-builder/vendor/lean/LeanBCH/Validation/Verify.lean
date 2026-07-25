/-
  LeanBCH.Validation.Verify — BCH-2026 FUNCTIONS chip witnesses, extracted from VM/Verify.lean.

  Known-answer tests for DEFINE/INVOKE, driven through `runScript` (the metered `runExt` loop, so
  they EXERCISE the frame return) and the consensus predicates `verifyInput`/`verifyTransaction`.
  The single-step DEFINE/INVOKE facts are `decide`-checked (fuel-free, kernel-verified); the
  end-to-end runs use native `#eval` + a build-time `guard` (a full metered run is not a kernel
  `decide` candidate). Bodies/identifiers are raw bytes: `0x89`/`0x8a` are DEFINE/INVOKE;
  `0x52 0x53 0x93` = `OP_2 OP_3 OP_ADD`.
-/
import LeanBCH.VM.Verify
import LeanBCH.Validation.Fixtures

namespace LeanBCH.Validation
open LeanBCH LeanBCH.VM LeanBCH.VM.State LeanBCH.Tx LeanBCH.Cost LeanBCH.Crypto

-- Single-step, kernel-checked (fuel-free `decide`) ----------------------------
-- OP_DEFINE binds identifier ↦ body (raw, undecoded) in the function table.
example : (stepInstrExt exampleProgram Secp256k1.reject 0x89 []
    { stack := [[0x07], [0x52, 0x53, 0x93]] }).functionTable = [([0x07], [0x52, 0x53, 0x93])] := by decide
-- OP_DEFINE of an identifier longer than `maxFunctionIdLen` (8 > 7) ⇒ excessive-length error.
example : (stepInstrExt exampleProgram Secp256k1.reject 0x89 []
    { stack := [List.replicate 8 (0x01 : UInt8), [0x52]] }).error = some .functionIdExcessive := by decide
-- OP_DEFINE of an already-bound identifier ⇒ previously-defined error.
example : (stepInstrExt exampleProgram Secp256k1.reject 0x89 []
    { stack := [[0x07], [0x52]], functionTable := [([0x07], [0x99])] }).error
    = some .functionIdRedefined := by decide
-- OP_INVOKE of an undefined identifier ⇒ undefined error.
example : (stepInstrExt exampleProgram Secp256k1.reject 0x8a []
    { stack := [[0x07]] }).error = some .functionIdUndefined := by decide
-- OP_INVOKE of a body that does not decode (`0x04` = PUSHBYTES_4 with no data) ⇒ malformed error.
example : (stepInstrExt exampleProgram Secp256k1.reject 0x8a []
    { stack := [[0x07]], functionTable := [([0x07], [0x04])] }).error
    = some .malformedFunction := by decide
-- OP_INVOKE pushes a RETURN FRAME (caller instrs + resume ip) and jumps into the body (ip := 0).
example : (stepInstrExt exampleProgram Secp256k1.reject 0x8a []
    { stack := [[0x07]], functionTable := [([0x07], [0x52, 0x53, 0x93])] }).ctrl.length = 1 := by decide

-- End-to-end through `runScript` (metered `runExt`, so the frame return fires) ---
-- NOTE: identifiers use the byte `0xab` (NOT in 1..16, so `PUSHBYTES_1 0xab` is a MINIMAL push —
-- a `0x07` id would push non-minimally and be rejected before DEFINE, exactly like the vmb corpus).
/-- `<0x525393> <0xab> OP_DEFINE <0xab> OP_INVOKE` — define id `ab` ↦ body `OP_2 OP_3 OP_ADD`, then
    invoke; after the frame returns the stack is `[5]`. -/
def defInvoke5 : Bytes := [0x03, 0x52, 0x53, 0x93, 0x01, 0xab, 0x89, 0x01, 0xab, 0x8a]
/-- …then `OP_5 OP_EQUAL` — POST-invoke ops run (the return frame restored the caller): `[5]=5 ⇒ 1`. -/
def defInvokePost : Bytes := defInvoke5 ++ [0x55, 0x87]
/-- Redefine id `ab` ⇒ previously-defined error. -/
def doubleDef : Bytes := [0x01, 0x51, 0x01, 0xab, 0x89, 0x01, 0x51, 0x01, 0xab, 0x89]
/-- Invoke undefined id `ab` ⇒ undefined error. -/
def invokeUndef : Bytes := [0x01, 0xab, 0x8a]
/-- Define id `ab` ↦ malformed body `0x4c` (PUSHDATA1 with no length byte), then invoke ⇒ malformed
    error. (`0x4c` pushes minimally via PUSHBYTES_1 and is malformed only when DECODED at invoke.) -/
def defMalformedInvoke : Bytes := [0x01, 0x4c, 0x01, 0xab, 0x89, 0x01, 0xab, 0x8a]
/-- Define id `ab` ↦ malformed body `0x4c` but DO NOT invoke, then `OP_1` — DEFINE never decodes the
    body, so this SUCCEEDS (leaves `[1]`). -/
def defMalformedNoInvoke : Bytes := [0x01, 0x4c, 0x01, 0xab, 0x89, 0x51]

private def wguard (name : String) (cond : Bool) : IO Unit := do
  unless cond do throw (IO.userError s!"[FUNCTIONS witness] {name}")

#eval (fnRun defInvoke5).stack                          -- [[5]]
#eval (fnRun defInvokePost).stack                       -- [[1]]
#eval (fnRun doubleDef).error                            -- some functionIdRedefined
#eval (fnRun invokeUndef).error                          -- some functionIdUndefined
#eval (fnRun defMalformedInvoke).error                   -- some malformedFunction

#eval wguard "define+invoke OP_2 OP_3 OP_ADD ⇒ stack [5], no error, empty ctrl (frame returned)"
  (let r := fnRun defInvoke5; r.stack == [[0x05]] && r.error == none && r.ctrl.isEmpty)
#eval wguard "post-invoke OP_5 OP_EQUAL runs after the return frame ⇒ stack [1]"
  (let r := fnRun defInvokePost; r.stack == [[0x01]] && r.error == none && r.ctrl.isEmpty)
#eval wguard "double-define ⇒ functionIdRedefined"
  ((fnRun doubleDef).error == some .functionIdRedefined)
#eval wguard "invoke-undefined ⇒ functionIdUndefined"
  ((fnRun invokeUndef).error == some .functionIdUndefined)
#eval wguard "invoke malformed body ⇒ malformedFunction"
  ((fnRun defMalformedInvoke).error == some .malformedFunction)
#eval wguard "define malformed body WITHOUT invoking ⇒ succeeds (DEFINE does not decode)"
  (let r := fnRun defMalformedNoInvoke; r.stack == [[0x01]] && r.error == none)

-- End-to-end through `verifyInput` (the consensus predicate) -------------------
#eval wguard "verifyInput accepts a define+invoke P2S script ending clean-truthy ([1])"
  (verifyInput Secp256k1.reject (fnProg defInvokePost) == true)
#eval wguard "verifyInput accepts define+invoke leaving [5] (single truthy item)"
  (verifyInput Secp256k1.reject (fnProg defInvoke5) == true)
#eval wguard "verifyInput REJECTS invoke-undefined"
  (verifyInput Secp256k1.reject (fnProg invokeUndef) == false)

-- Value conservation at the tx level (`verifyTransaction`, NOT `verifyInput`) ----
/-- A 1-input P2S tx spending a 6000-sat UTXO (OP_1 locking, empty push-only unlocking, so the input
    itself verifies), with a single output of `outVal` sat. The output's locking bytecode is a 20-byte
    pad (outputs are never executed) purely to clear the 65-byte anti-Merkle size floor, so a
    conserving vs inflating pair differs ONLY in Σoutputs — isolating the value-conservation rule. -/
def valProg (outVal : UInt64) : Program :=
  { fnProg [0x51] with
      transaction := { (fnProg [0x51]).transaction with
        outputs := #[{ valueSatoshis := outVal, lockingBytecode := List.replicate 20 (0x00 : UInt8),
                       token := none }] } }

#eval wguard "verifyTransaction REJECTS an inflation tx (Σout 2e12 > Σin 6000, both ≤ maxMoney)"
  (verifyTransaction Secp256k1.reject (valProg 2000000000000) == false)
#eval wguard "verifyTransaction ACCEPTS a value-conserving tx (Σout 1000 ≤ Σin 6000, input verifies)"
  (verifyTransaction Secp256k1.reject (valProg 1000) == true)

end LeanBCH.Validation
