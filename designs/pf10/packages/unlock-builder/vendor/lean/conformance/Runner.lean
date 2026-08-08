/-
  conformance/Runner.lean — a runtime vmb driver (run via `lake env lean --run`).

  Reads vmb vectors from stdin (one per line: `expected id txHex sourceOutputsHex`), decodes each
  transaction + source outputs, verifies the tested input (index = the vmb vector's 7th field, default 0; see below). The
  signed prefix), and tallies matches against the corpus verdict. Hex is parsed at RUNTIME, so
  there is no giant-literal elaboration cost — the whole corpus streams through the compiled VM.
-/
import LeanBCH.Tx.Wire
import LeanBCH.VM.Verify
import LeanBCH.VM.Standard
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

-- The oracle is a PARAMETER, chosen at runtime from `LEANBCH_SECP` (see LeanBCH/Crypto/Native.lean).
-- Unset ⇒ `Secp256k1.reject`, which is exactly what this runner used unconditionally before the FFI
-- binding existed — so every previously recorded conformance number stays reproducible verbatim.
-- With `LEANBCH_SECP=native` the same code path consults the pinned libsecp256k1 instead, which is
-- the only way the signature families can pass. `idx` is the vmb vector's tested input index (its
-- 7th field, defaulting to 0 when absent).
def verifyVec (crypto : Crypto.Secp256k1) (idx : Nat) (txH soH : List UInt8) : Bool :=
  ((decodeProgram txH soH idx).map
     (fun p => txValid p && verifyTokens p && verifyInput crypto p)).getD false

-- Relay-policy verdict, for measuring the standardness layer. `isStandard` is oracle-independent;
-- `standardInterpreterOk` runs the interpreter and so does consult the oracle.
def stdVec (crypto : Crypto.Secp256k1) (idx : Nat) (txH soH : List UInt8) : Bool :=
  ((decodeProgram txH soH idx).map (fun p =>
     Standard.isStandard Standard.policy2026 p
       && Standard.standardInterpreterOk crypto p)).getD false

def main : IO Unit := do
  let (crypto, oracleName) ← Crypto.oracleFromEnv
  let input ← (← IO.getStdin).readToEnd
  let lines := (input.splitOn "\n").filter (fun l => !l.trim.isEmpty)
  let mut pass := 0
  let mut rejValid : List String := []      -- expected pass, we FAILED it (missing feature)
  let mut accInvalid : List String := []    -- expected fail, we ACCEPTED it (missing check)
  let mut stdTrue := 0                       -- isStandard = true
  let mut stdFalse := 0                      -- isStandard = false
  let mut stdTrueIds : List String := []     -- ids the policy layer classifies STANDARD
  let mut stdFalseIds : List String := []    -- ids the policy layer classifies NONSTANDARD
  for line in lines do
    match line.trim.splitOn " " with
    | [exp, id, txHex, soHex, idxStr] =>
        let idx := (idxStr.toNat?).getD 0
        let txB := hexToBytes txHex.toList
        let soB := hexToBytes soHex.toList
        let expected := exp == "1"
        let got := verifyVec crypto idx txB soB
        if got == expected then pass := pass + 1
        else if expected then rejValid := id :: rejValid
        else accInvalid := id :: accInvalid
        if stdVec crypto idx txB soB then
          stdTrue := stdTrue + 1
          stdTrueIds := id :: stdTrueIds
        else
          stdFalse := stdFalse + 1
          stdFalseIds := id :: stdFalseIds
    | _ => pure ()
  -- Printed FIRST and always: a conformance tally whose oracle is unknown is not a measurement.
  IO.println s!"ORACLE {oracleName}"
  IO.println s!"PASS {pass} / {lines.length}"
  IO.println s!"REJECTED-VALID {rejValid.length}: {(rejValid.reverse.take 20)}"
  IO.println s!"ACCEPTED-INVALID {accInvalid.length}: {(accInvalid.reverse.take 20)}"
  IO.println s!"STD-TRUE {stdTrue} STD-FALSE {stdFalse}"
  IO.println s!"STD-TRUE-IDS: {(stdTrueIds.reverse.take 200)}"
  IO.println s!"STD-FALSE-IDS: {(stdFalseIds.reverse.take 200)}"
