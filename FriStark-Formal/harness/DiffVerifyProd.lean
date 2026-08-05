import FriStark.Verify.Executable
import FriStark.Verify.Types
import FriStark.Field.Ext
import FriStark.Hash.Sha256
import FriStark.Binding.Forges
import FriStark.Params.V1

open FriStark.Verify.Executable
open FriStark.Verify.Types
open FriStark.Field.Ext
open FriStark.Hash.Sha256
open FriStark.Binding.Forges
open FriStark.Params.V1

def parseHexByte (c : Char) : Nat :=
  if '0' ≤ c ∧ c ≤ '9' then c.toNat - '0'.toNat
  else if 'a' ≤ c ∧ c ≤ 'f' then 10 + c.toNat - 'a'.toNat
  else if 'A' ≤ c ∧ c ≤ 'F' then 10 + c.toNat - 'A'.toNat
  else 0

def hexToBytes (s : String) : List UInt8 := Id.run do
  let cs := s.toList
  let mut out : List UInt8 := []
  let mut i := 0
  while i + 1 < cs.length do
    out := out ++ [UInt8.ofNat (parseHexByte cs[i]! * 16 + parseHexByte cs[i+1]!)]
    i := i + 2
  pure out

def parsePath (s : String) : List (List UInt8 × Nat) := Id.run do
  if s.isEmpty then return []
  let mut out : List (List UInt8 × Nat) := []
  for part in s.splitOn "," do
    let kv := part.splitOn ":"
    if kv.length ≥ 2 then
      out := out ++ [(hexToBytes kv[0]!, kv[1]!.toNat!)]
  pure out

def parseNatList (s : String) : List Nat :=
  if s.isEmpty then [] else (s.splitOn ",").map String.toNat!

structure Stats where
  honestOk : Nat := 0
  honestN : Nat := 0
  forgeRej : Nat := 0
  forgeN : Nat := 0
  leanAccForge : Nat := 0
  agree : Nat := 0
  total : Nat := 0
  deriving Repr

def main (args : List String) : IO UInt32 := do
  let root := args.getD 0 "."
  let path := System.FilePath.mk (root ++ "/vectors/verify/C-verify-prod.simple")
  if !(← path.pathExists) then
    IO.eprintln s!"missing {path}"; return 2
  let content ← IO.FS.readFile path
  let mut st : Stats := {}
  let mut curLabel := ""
  let mut curAccept := false
  let mut curElig := "product"
  let mut curB := BLOWUP
  let mut curQ := QUERIES
  let mut curG := GRIND_BITS
  let mut curF := FOLD
  let mut checks : List AtomicCheck := []
  let bindingOk := allForgesRejected
  for line in content.splitOn "\n" do
    if line.isEmpty then continue
    let parts := line.splitOn "|"
    let tag := parts.headD ""
    if tag == "BUNDLE" then
      curLabel := parts[1]!
      curAccept := parts[2]! == "1"
      curElig := parts[3]!
      curB := parts[4]!.toNat!
      curQ := parts[5]!.toNat!
      curG := parts[6]!.toNat!
      curF := parts[7]!.toNat!
      checks := []
    else if tag == "MERKLE_DIGEST" then
      checks := checks ++ [AtomicCheck.merkleOpenDigest (hexToBytes parts[1]!) (hexToBytes parts[2]!) (parsePath (parts.getD 3 ""))]
    else if tag == "MERKLE" then
      checks := checks ++ [AtomicCheck.merkleOpen (hexToBytes parts[1]!) (hexToBytes parts[2]!) parts[3]!.toNat! (parsePath (parts.getD 4 ""))]
    else if tag == "FRIFOLD" then
      checks := checks ++ [AtomicCheck.friFold ⟨parts[1]!.toNat!, parts[2]!.toNat!⟩ ⟨parts[3]!.toNat!, parts[4]!.toNat!⟩ ⟨parts[5]!.toNat!, parts[6]!.toNat!⟩ ⟨parts[7]!.toNat!, parts[8]!.toNat!⟩ parts[9]!.toNat!]
    else if tag == "EXTEQ" then
      checks := checks ++ [AtomicCheck.extEq ⟨parts[1]!.toNat!, parts[2]!.toNat!⟩ ⟨parts[3]!.toNat!, parts[4]!.toNat!⟩]
    else if tag == "FIELDEQ" then
      checks := checks ++ [AtomicCheck.fieldEq parts[1]!.toNat! parts[2]!.toNat!]
    else if tag == "GRINDCHECK" then
      checks := checks ++ [AtomicCheck.grindCheck (hexToBytes parts[1]!) (hexToBytes parts[2]!) parts[3]!.toNat!]
    else if tag == "NATLISTEQ" then
      checks := checks ++ [AtomicCheck.natListEq (parseNatList parts[1]!) (parseNatList parts[2]!)]
    else if tag == "NATEQ" then
      checks := checks ++ [AtomicCheck.natEq parts[1]!.toNat! parts[2]!.toNat!]
    else if tag == "BYTESEQ" then
      checks := checks ++ [AtomicCheck.bytesEq (hexToBytes parts[1]!) (hexToBytes parts[2]!)]
    else if tag == "REJECT" || tag == "GRIND" then
      IO.eprintln s!"forbidden tag in product corpus: {tag}"
      return 3
    else if tag == "END" then
      let b : ProofBundle := {
        checks := checks, accept := curAccept, label := curLabel, eligibility := curElig,
        blowup := curB, queries := curQ, grindBits := curG, fold := curF
      }
      st := { st with total := st.total + 1 }
      let leanOk := (verify b).isOk
      if agreesWithOracle b then st := { st with agree := st.agree + 1 }
      if curAccept then
        st := { st with honestN := st.honestN + 1 }
        if leanOk then st := { st with honestOk := st.honestOk + 1 }
      else
        st := { st with forgeN := st.forgeN + 1 }
        if leanOk then st := { st with leanAccForge := st.leanAccForge + 1 }
        else st := { st with forgeRej := st.forgeRej + 1 }
      checks := []
  IO.println s!"prod_bundles={st.total} honest={st.honestOk}/{st.honestN} forge_reject={st.forgeRej}/{st.forgeN} lean_acc_forge={st.leanAccForge} agree={st.agree}/{st.total} binding={bindingOk}"
  let ok := st.honestN ≥ 1 && st.honestOk == st.honestN && st.leanAccForge == 0 &&
            st.forgeN ≥ 10 && st.forgeRej == st.forgeN && st.agree == st.total && bindingOk
  if ok then IO.println "DIFF_VERIFY_PROD_OK"; pure 0
  else IO.println "DIFF_VERIFY_PROD_FAIL"; pure 1
