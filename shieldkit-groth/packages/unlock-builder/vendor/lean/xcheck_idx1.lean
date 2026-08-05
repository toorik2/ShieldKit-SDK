import LeanBCH.Tx.Wire
import LeanBCH.VM.Verify
import LeanBCH.Crypto.Native

open LeanBCH LeanBCH.Tx LeanBCH.VM LeanBCH.Cost

def hexNib (c : Char) : Nat :=
  if '0' ≤ c ∧ c ≤ '9' then c.toNat - '0'.toNat
  else if 'a' ≤ c ∧ c ≤ 'f' then c.toNat - 'a'.toNat + 10
  else if 'A' ≤ c ∧ c ≤ 'F' then c.toNat - 'A'.toNat + 10
  else 0

partial def hexToBytes : List Char → List UInt8
  | a :: b :: rest => UInt8.ofNat (hexNib a * 16 + hexNib b) :: hexToBytes rest
  | _              => []

-- full per-input op-cost INCLUDING the P2SH redeem execution (mirrors verifyInput's P2SH branch)
def fullOpCost (crypto : Crypto.Secp256k1) (p : Program) : Nat :=
  match p.currentInput, p.currentSourceOutput with
  | some inp, some src =>
      let budget := opBudget inp.unlockingBytecode.length
      let s1 := runScript crypto p [] inp.unlockingBytecode budget
      let s2 := runScript crypto p s1.stack src.lockingBytecode budget
      let c12 := operationCost BCH_2026_05_CONSENSUS s1.metrics + operationCost BCH_2026_05_CONSENSUS s2.metrics
      if isP2SH src.lockingBytecode then
        match s1.stack with
        | redeem :: rest =>
            let s3 := runScript crypto p rest redeem budget
            c12 + operationCost BCH_2026_05_CONSENSUS s3.metrics
        | [] => c12
      else c12
  | _, _ => 0

-- Index-1 variant of the prefix-arg xcheck main: evaluates the SECOND input (inputIndex 1),
-- which is the bw1-cert exec input (input 0 is the lib DATA input referenced via OP_INPUTBYTECODE 0).
def main (args : List String) : IO Unit := do
  let (crypto, oracleName) := (← Crypto.oracleFromEnv)
  let pfx := args.headD "/tmp/xcheck"
  let txHex ← IO.FS.readFile (pfx ++ "_tx.hex")
  let soHex ← IO.FS.readFile (pfx ++ "_srcouts.hex")
  let txB := hexToBytes txHex.trim.toList
  let soB := hexToBytes soHex.trim.toList
  match decodeProgram txB soB 1 with
  | none => IO.println "DECODE_FAIL"
  | some p =>
      let acc := verifyInput crypto p
      let tv := txValid p
      let tk := verifyTokens p
      let cost := fullOpCost crypto p
      IO.println s!"ORACLE={oracleName} PREFIX={pfx} leanVerifyInput={acc} txValid={tv} verifyTokens={tk} leanFullOpCost={cost}"
