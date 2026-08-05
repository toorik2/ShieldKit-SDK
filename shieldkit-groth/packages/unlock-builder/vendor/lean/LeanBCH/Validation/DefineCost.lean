/-
  STAGED known-answer test — LeanBCH OP_DEFINE op-cost body-tally (Finding #001 / F0).

  Proposed drop-in for `LeanBCH/Validation/` (e.g. append to `Validation/Verify.lean`, or add as
  `Validation/DefineCost.lean` and import from `LeanBCH.lean`). It PINS the CORRECTED OP_DEFINE
  op-cost DIRECTLY (hand-computed from the ACTIVATED BCH-2026 / BCHN v29 semantics
  `opCost = baseInstructionCost + stackPushedBytes(functionBody)`), so verification does NOT depend
  on the superseded libauth 3.1.0-next.8 reference that the existing `CostDifferential` still pins to.

  Style mirrors `Validation/CostDifferential.lean`: a build-time `#eval` IO guard that throws (fails
  `lake build LeanBCHValidation`) on any mismatch. The body-tally correction lives in `stepMeterExt`
  (NOT `stepInstrExt`), so these witnesses run the full metered loop via `fnRun` — a single
  `stepInstrExt` call would NOT exercise the correction.

  Expected numbers (BCH_2026_05 pins: 100·ops + 26000·sig + 64·hashIter + arith + pushedBytes):

    defineBody3 = <push 3-byte body> <push 1-byte id 0xab> OP_DEFINE
      metrics: evaluatedInstructionCount = 3, stackPushedBytes = 3(body push)+1(id push)+3(DEFINE body tally) = 7
      opCost   = 3·100 + 7 = 307        (BEFORE the fix: pushedBytes 4, opCost 304 — under-bill of 3 = body.size())

    defineBody5 = <push 5-byte body> <push 1-byte id 0xab> OP_DEFINE
      metrics: evaluatedInstructionCount = 3, stackPushedBytes = 5+1+5 = 11
      opCost   = 3·100 + 11 = 311       (BEFORE the fix: pushedBytes 6, opCost 306 — under-bill of 5 = body.size())

  The delta stackPushedBytes(after) − stackPushedBytes(before) = body.size() EXACTLY, for both widths
  ⇒ pins the linear body tally, which is the whole content of the fix. (DEFINE never decodes the body,
  so the 5-byte body may be arbitrary raw bytes.)
-/
import LeanBCH.VM.Verify
import LeanBCH.Validation.Fixtures

namespace LeanBCH.Validation
open LeanBCH LeanBCH.VM LeanBCH.VM.State LeanBCH.Cost

/-- `<0x525393> <0xab> OP_DEFINE` — define id `ab` ↦ 3-byte body (raw, undecoded). No invoke. -/
def defineBody3 : Bytes := [0x03, 0x52, 0x53, 0x93, 0x01, 0xab, 0x89]
/-- `<0x5253935455> <0xab> OP_DEFINE` — define id `ab` ↦ 5-byte body (raw, undecoded). No invoke. -/
def defineBody5 : Bytes := [0x05, 0x52, 0x53, 0x93, 0x54, 0x55, 0x01, 0xab, 0x89]

/-- Build-time guard pinning the CORRECTED OP_DEFINE body tally. Throws (fails `lake build`) on
    mismatch. Each tuple: (script, evaluatedInstructionCount, stackPushedBytes, opCost@BCH_2026_05). -/
def defineCostGuard : IO Unit := do
  for (bs, ei, pb, oc) in
      [ (defineBody3, 3, 7, 307),
        (defineBody5, 3, 11, 311) ] do
    let s := fnRun bs
    let m := s.metrics
    unless s.error == none do
      throw (IO.userError s!"[define cost] script {bs} unexpectedly errored: {repr s.error}")
    unless m.evaluatedInstructionCount == ei && m.stackPushedBytes == pb
        && m.arithmeticCost == 0 && m.hashDigestIterations == 0 && m.signatureCheckCount == 0 do
      throw (IO.userError s!"[define cost] script {bs}: metrics (ei={m.evaluatedInstructionCount}, \
        pb={m.stackPushedBytes}) ≠ expected (ei={ei}, pb={pb}) — did the OP_DEFINE body tally regress?")
    unless operationCost BCH_2026_05 m == oc do
      throw (IO.userError s!"[define cost] script {bs}: opCost {operationCost BCH_2026_05 m} ≠ {oc}")

#eval defineCostGuard

end LeanBCH.Validation
