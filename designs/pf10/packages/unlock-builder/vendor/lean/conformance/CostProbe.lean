/-
  conformance/CostProbe.lean — emit the RAW consensus cost metrics per vmb vector.

  `vmbconf` (conformance/Runner.lean) reports only the accept/reject verdict. This runner reports
  the five metrics that the op-cost formula sums, so they can be differentially compared against the
  reference implementation (@bitauth/libauth) on the SAME vectors. Its whole reason to exist is the
  `26000·signatureCheckCount` term: under `Secp256k1.reject` a non-empty signature NULLFAILs before
  its cost is compared to anything, so that term was never observable. With the native oracle
  signatures succeed and the count becomes measurable.

  The accumulation MIRRORS `LeanBCH.VM.verifyInput` (LeanBCH/VM/Verify.lean:93-120) exactly — same
  budget, same push-only and length pre-checks, same P2SH-redeem third script — so the numbers
  printed here are the numbers that predicate actually compares to the budget, not a re-derivation.

  Output, one line per vector:
    METRICS <id> <verdict> <instr> <sigchecks> <hashiters> <arith> <pushed> <opCostConsensus>
  `verdict` is `verifyInput`'s answer. A vector whose evaluation never reaches the metric phase
  (decode failure, over-length, non-push-only unlocking, or an error in script 1/2) prints
  `SKIP <id> <reason>` — those have no meaningful metric total to compare.

  Build: `ffi/build.sh && lake build costprobe`. Oracle via LEANBCH_SECP (default reject).
-/
import LeanBCH.Tx.Wire
import LeanBCH.VM.Verify
import LeanBCH.Crypto.Native

open LeanBCH LeanBCH.Tx LeanBCH.VM

def hexNib (c : Char) : Nat :=
  if '0' ≤ c ∧ c ≤ '9' then c.toNat - '0'.toNat
  else if 'a' ≤ c ∧ c ≤ 'f' then c.toNat - 'a'.toNat + 10
  else if 'A' ≤ c ∧ c ≤ 'F' then c.toNat - 'A'.toNat + 10
  else 0

partial def hexToBytes : List Char → List UInt8
  | a :: b :: rest => UInt8.ofNat (hexNib a * 16 + hexNib b) :: hexToBytes rest
  | _              => []

/-- The metric total for an input, accumulated exactly as `verifyInput` accumulates it.
    `none` = the evaluation never reached a comparable total (see the header). -/
def probeMetrics (crypto : Crypto.Secp256k1) (p : Program) : Option Cost.Metrics :=
  match p.currentInput, p.currentSourceOutput with
  | some inp, some src =>
      if inp.unlockingBytecode.length > maxBytecodeLen || src.lockingBytecode.length > maxBytecodeLen then none else
      if !isPushOnly inp.unlockingBytecode then none else
      let budget := opBudget inp.unlockingBytecode.length
      let s1 := runScript crypto p [] inp.unlockingBytecode budget
      if s1.error.isSome then none else
      let s2 := runScript crypto p s1.stack src.lockingBytecode budget
      if s2.error.isSome then none else
      let m12 := s1.metrics + s2.metrics
      if isP2SH src.lockingBytecode then
        match s1.stack with
        | redeem :: rest =>
            if redeem.length > maxBytecodeLen then none else
            some (m12 + (runScript crypto p rest redeem budget).metrics)
        | []             => none
      else some m12
  | _, _ => none

def main : IO Unit := do
  let (crypto, oracleName) ← Crypto.oracleFromEnv
  IO.println s!"ORACLE {oracleName}"
  let input ← (← IO.getStdin).readToEnd
  let lines := (input.splitOn "\n").filter (fun l => !l.trim.isEmpty)
  for line in lines do
    match line.trim.splitOn " " with
    | [_exp, id, txHex, soHex, idxStr] =>
        let idx := (idxStr.toNat?).getD 0
        let txB := hexToBytes txHex.toList
        let soB := hexToBytes soHex.toList
        match decodeProgram txB soB idx with
        | none   => IO.println s!"SKIP {id} decode"
        | some p =>
            match probeMetrics crypto p with
            | none   => IO.println s!"SKIP {id} no-metric-phase"
            | some m =>
                let verdict := if verifyInput crypto p then "1" else "0"
                let cost := Cost.operationCost BCH_2026_05_CONSENSUS m
                let fields := [id, verdict, toString m.evaluatedInstructionCount,
                  toString m.signatureCheckCount, toString m.hashDigestIterations,
                  toString m.arithmeticCost, toString m.stackPushedBytes, toString cost]
                IO.println ("METRICS " ++ String.intercalate " " fields)
    | _ => IO.println "SKIP - malformed-line"
