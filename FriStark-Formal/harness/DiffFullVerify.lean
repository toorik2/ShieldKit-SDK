/-
  Diff harness for full DEEP+FS verify.
  Rejects synthetic theater: only real Step constructors from forged material.
-/
import FriStark.Full.Verify
import FriStark.Field.Ext
import FriStark.Deep.Replay
import FriStark.Hash.Sha256
import FriStark.Params.V1
import FriStark.Binding.Forges

open FriStark.Full.Verify
open FriStark.Field.Ext
open FriStark.Deep.Replay
open FriStark.Hash.Sha256
open FriStark.Params.V1
open FriStark.Binding.Forges

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
    if kv.length ≥ 2 then out := out ++ [(hexToBytes kv[0]!, kv[1]!.toNat!)]
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
  fsSteps : Nat := 0
  deriving Repr

def main (args : List String) : IO UInt32 := do
  let root := args.getD 0 "."
  let path := System.FilePath.mk (root ++ "/vectors/verify/C-full-verify.simple")
  if !(← path.pathExists) then
    IO.eprintln s!"missing {path}"; return 2
  let content ← IO.FS.readFile path
  -- skeptic: ban synthetic reject theater in corpus
  if content.splitOn "\n" |>.any (· == "NATEQ|0|1") then
    IO.eprintln "SYNTHETIC_REJECT NATEQ|0|1 present — REJECT theater"
    return 3
  let mut st : Stats := {}
  let mut curLabel := ""
  let mut curAccept := false
  let mut curElig := "product"
  let mut curB := BLOWUP
  let mut curQ := QUERIES
  let mut curG := GRIND_BITS
  let mut curF := FOLD
  let mut steps : List Step := []
  let mut deepTerms : List DeepTerm := []
  let mut deepExpect : E := zero
  let bindingOk := allForgesRejected
  for line in content.splitOn "\n" do
    if line.isEmpty then continue
    let p := line.splitOn "|"
    let tag := p.headD ""
    if tag == "BUNDLE" then
      curLabel := p[1]!; curAccept := p[2]! == "1"; curElig := p[3]!
      curB := p[4]!.toNat!; curQ := p[5]!.toNat!; curG := p[6]!.toNat!; curF := p[7]!.toNat!
      steps := []
    else if tag == "PARAMS" then
      steps := steps ++ [Step.params p[1]!.toNat! p[2]!.toNat! p[3]!.toNat! p[4]!.toNat!]
    else if tag == "FSABSORB" then
      steps := steps ++ [Step.fsAbsorb (hexToBytes p[1]!) (hexToBytes p[2]!) (hexToBytes p[3]!)]
      st := { st with fsSteps := st.fsSteps + 1 }
    else if tag == "FSABSORBINT" then
      steps := steps ++ [Step.fsAbsorbInt (hexToBytes p[1]!) p[2]!.toNat! (hexToBytes p[3]!)]
      st := { st with fsSteps := st.fsSteps + 1 }
    else if tag == "FSCHAL" then
      steps := steps ++ [Step.fsChallenge (hexToBytes p[1]!) p[2]!.toNat! (hexToBytes p[3]!)]
      st := { st with fsSteps := st.fsSteps + 1 }
    else if tag == "FSEXTCHAL" then
      steps := steps ++ [Step.fsExtChallenge (hexToBytes p[1]!) p[2]!.toNat! p[3]!.toNat! (hexToBytes p[4]!)]
      st := { st with fsSteps := st.fsSteps + 1 }
    else if tag == "FSIDX" then
      steps := steps ++ [Step.fsChallengeIdx (hexToBytes p[1]!) p[2]!.toNat! p[3]!.toNat! (hexToBytes p[4]!)]
      st := { st with fsSteps := st.fsSteps + 1 }
    else if tag == "GRINDCHECK" then
      steps := steps ++ [Step.grindCheck (hexToBytes p[1]!) (hexToBytes p[2]!) p[3]!.toNat!]
    else if tag == "NATLISTEQ" then
      steps := steps ++ [Step.natListEq (parseNatList p[1]!) (parseNatList p[2]!)]
    else if tag == "NATEQ" then
      steps := steps ++ [Step.natEq p[1]!.toNat! p[2]!.toNat!]
    else if tag == "BYTESEQ" then
      steps := steps ++ [Step.bytesEq (hexToBytes p[1]!) (hexToBytes p[2]!)]
    else if tag == "MERKLE" then
      steps := steps ++ [Step.merkleDigest (hexToBytes p[1]!) (hexToBytes p[2]!) (parsePath (p.getD 3 ""))]
    else if tag == "FRIFOLD" then
      steps := steps ++ [Step.friFold ⟨p[1]!.toNat!,p[2]!.toNat!⟩ ⟨p[3]!.toNat!,p[4]!.toNat!⟩ ⟨p[5]!.toNat!,p[6]!.toNat!⟩ ⟨p[7]!.toNat!,p[8]!.toNat!⟩ p[9]!.toNat!]
    else if tag == "EXTEQ" then
      steps := steps ++ [Step.extEq ⟨p[1]!.toNat!,p[2]!.toNat!⟩ ⟨p[3]!.toNat!,p[4]!.toNat!⟩]
    else if tag == "DEEPZ" then
      steps := steps ++ [Step.deepZ ⟨p[1]!.toNat!,p[2]!.toNat!⟩ ⟨p[3]!.toNat!,p[4]!.toNat!⟩ ⟨p[5]!.toNat!,p[6]!.toNat!⟩ p[7]!.toNat!]
    else if tag == "DEEPQ_BEGIN" || tag == "DEEPQ_TERM" || tag == "DEEPQ_END" then
      pure ()  -- legacy term path demoted; pure path uses deepQAtLayout
    else if tag == "END" then
      let b : Bundle := {
        steps := steps, accept := curAccept, label := curLabel, eligibility := curElig,
        blowup := curB, queries := curQ, grindBits := curG, fold := curF
      }
      st := { st with total := st.total + 1 }
      let leanOk := (verify b).isOk
      if agrees b then st := { st with agree := st.agree + 1 }
      if curAccept then
        st := { st with honestN := st.honestN + 1 }
        if leanOk then st := { st with honestOk := st.honestOk + 1 }
        else
          let why := match verify b with | .ok => "ok" | .err w => w
          IO.eprintln s!"honest lean reject: {curLabel} why={why}"
      else
        st := { st with forgeN := st.forgeN + 1 }
        if leanOk then
          st := { st with leanAccForge := st.leanAccForge + 1 }
          IO.eprintln s!"forge lean ACCEPT: {curLabel}"
        else st := { st with forgeRej := st.forgeRej + 1 }
  IO.println s!"full_bundles={st.total} honest={st.honestOk}/{st.honestN} forge_reject={st.forgeRej}/{st.forgeN} lean_acc_forge={st.leanAccForge} agree={st.agree}/{st.total} binding={bindingOk} fs_steps={st.fsSteps}"
  let ok := st.honestN ≥ 1 && st.honestOk == st.honestN && st.leanAccForge == 0 &&
            st.forgeN ≥ 10 && st.forgeRej == st.forgeN && st.agree == st.total && bindingOk &&
            st.fsSteps ≥ 1
  if ok then IO.println "DIFF_FULL_VERIFY_OK"; pure 0
  else IO.println "DIFF_FULL_VERIFY_FAIL"; pure 1
