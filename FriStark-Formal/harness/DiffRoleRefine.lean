/-
  Per-role refinement: link abstract Lean merkle/fri multi-sample checks to
  host dual-vm accept on sound-secure packing inputs (comparisons[] by role).

  Inputs:
    vectors/refinement/merkle.simple
    vectors/refinement/fri.simple
    vectors/refinement/dual_vm_roles.simple  (from export_role_dual_vm.py)

  Writes evidence/refinement/{role}.json with measured fields only.
  Prints ROLE_REFINE_OK when every role has dual-vm n≥1, abstract mismatches=0,
  and dual-vm agreeAccept all true for that role's inputs.
-/
import FriStark.Hash.Merkle
import FriStark.FRI.Verify
import FriStark.Field.Ext
import FriStark.Hash.Sha256

open FriStark.Hash.Merkle
open FriStark.FRI.Verify
open FriStark.Field.Ext
open FriStark.Hash.Sha256

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

def boolLit (b : Bool) : String := if b then "true" else "false"

/-- Role → which abstract corpora it exercises (matches vectors/refinement/role_map.json). -/
def roleUsesMerkle (role : String) : Bool :=
  role == "blob" || role == "deepquery" || role == "aggFRI" || role == "comp_final"

def roleUsesFri (role : String) : Bool :=
  role == "aggFRI" || role == "comp_trans" || role == "comp_final"

structure DualSample where
  index : Nat
  role : String
  libauthAccepted : Bool
  leanVerifyInput : Bool
  agreeAccept : Bool
  deriving Repr

structure DualAgg where
  n : Nat
  agreeOk : Nat
  libauthOk : Nat
  leanOk : Nat
  disagree : Nat
  samplesJson : String
  deriving Repr, Inhabited

def emptyDual : DualAgg :=
  { n := 0, agreeOk := 0, libauthOk := 0, leanOk := 0, disagree := 0, samplesJson := "" }

def pushSample (a : DualAgg) (s : DualSample) : DualAgg :=
  let sep := if a.samplesJson.isEmpty then "" else ",\n"
  let line :=
    "    {\"index\": " ++ toString s.index ++
    ", \"label\": \"" ++ toString s.index ++ ":" ++ s.role ++ "\"" ++
    ", \"libauthAccepted\": " ++ boolLit s.libauthAccepted ++
    ", \"leanVerifyInput\": " ++ boolLit s.leanVerifyInput ++
    ", \"agreeAccept\": " ++ boolLit s.agreeAccept ++ "}"
  { n := a.n + 1
    , agreeOk := a.agreeOk + (if s.agreeAccept then 1 else 0)
    , libauthOk := a.libauthOk + (if s.libauthAccepted then 1 else 0)
    , leanOk := a.leanOk + (if s.leanVerifyInput then 1 else 0)
    , disagree := a.disagree + (if s.agreeAccept then 0 else 1)
    , samplesJson := a.samplesJson ++ sep ++ line }

def main (args : List String) : IO UInt32 := do
  let root := args.getD 0 "."
  let mpath := System.FilePath.mk (root ++ "/vectors/refinement/merkle.simple")
  let fpath := System.FilePath.mk (root ++ "/vectors/refinement/fri.simple")
  let dpath := System.FilePath.mk (root ++ "/vectors/refinement/dual_vm_roles.simple")
  if !(← mpath.pathExists) || !(← fpath.pathExists) then
    IO.eprintln "missing refinement simple corpora (merkle.simple / fri.simple)"; return 2
  if !(← dpath.pathExists) then
    IO.eprintln "missing dual_vm_roles.simple — run harness/export_role_dual_vm.py first"; return 2

  -- Abstract multi-sample: Lean re-executes shipped primitives
  let mut mOk := 0; let mut mN := 0; let mut mMismatch := 0
  for line in (← IO.FS.readFile mpath).splitOn "\n" do
    if line.isEmpty then continue
    let p := line.splitOn "|"
    if p.length < 4 then continue
    let expectOk := p[0]! == "1"
    let leaf := hexToBytes p[1]!
    let rootD := hexToBytes p[2]!
    let mut path : List (List UInt8 × Nat) := []
    if !(p[3]!.isEmpty) then
      for part in p[3]!.splitOn "," do
        let kv := part.splitOn ":"
        if kv.length ≥ 2 then
          path := path ++ [(hexToBytes kv[0]!, kv[1]!.toNat!)]
    let got := verifyDigest rootD (FriStark.Hash.Sha256.hash leaf) path
    mN := mN + 1
    if got == expectOk then mOk := mOk + 1 else mMismatch := mMismatch + 1

  let mut fOk := 0; let mut fN := 0; let mut fMismatch := 0
  for line in (← IO.FS.readFile fpath).splitOn "\n" do
    if line.isEmpty then continue
    let p := line.splitOn "|"
    if p.length < 10 then continue
    let expectOk := p[0]! == "1"
    let v : E := ⟨p[1]!.toNat!, p[2]!.toNat!⟩
    let w : E := ⟨p[3]!.toNat!, p[4]!.toNat!⟩
    let beta : E := ⟨p[5]!.toNat!, p[6]!.toNat!⟩
    let folded : E := ⟨p[7]!.toNat!, p[8]!.toNat!⟩
    let xpos := p[9]!.toNat!
    let got := verifyFoldStep v w folded beta xpos
    fN := fN + 1
    if got == expectOk then fOk := fOk + 1 else fMismatch := fMismatch + 1

  IO.println s!"abstract_merkle ok={mOk}/{mN} mismatch={mMismatch}"
  IO.println s!"abstract_fri ok={fOk}/{fN} mismatch={fMismatch}"

  -- Dual-vm samples by role (from sound-secure comparisons[])
  let roles := #["blob", "deepquery", "aggFRI", "comp_trans", "comp_final"]
  let mut aggs : Array DualAgg := Array.replicate roles.size emptyDual
  for line in (← IO.FS.readFile dpath).splitOn "\n" do
    if line.isEmpty then continue
    let p := line.splitOn "|"
    if p.length < 5 then continue
    let idx := p[0]!.toNat!
    let role := p[1]!
    let s : DualSample := {
      index := idx
      role := role
      libauthAccepted := p[2]! == "1"
      leanVerifyInput := p[3]! == "1"
      agreeAccept := p[4]! == "1"
    }
    match roles.findIdx? (· == role) with
    | some i => aggs := aggs.set! i (pushSample aggs[i]! s)
    | none => IO.eprintln s!"unknown dual-vm role: {role}"

  let mut allOk := true
  let mut indexPaths : List String := []
  for i in [0:roles.size] do
    let r := roles[i]!
    let d := aggs[i]!
    let useM := roleUsesMerkle r
    let useF := roleUsesFri r
    let absN := (if useM then mN else 0) + (if useF then fN else 0)
    let absMis := (if useM then mMismatch else 0) + (if useF then fMismatch else 0)
    let absOkN := (if useM then mOk else 0) + (if useF then fOk else 0)
    let mN' := if useM then mN else 0
    let mOk' := if useM then mOk else 0
    let mMis' := if useM then mMismatch else 0
    let fN' := if useF then fN else 0
    let fOk' := if useF then fOk else 0
    let fMis' := if useF then fMismatch else 0
    let corpusSize := absN + d.n
    let mismatches := absMis + d.disagree
    let dualAllAgree := d.n ≥ 1 && d.disagree == 0
    let roleOk := dualAllAgree && absMis == 0 && d.n ≥ 1
    if !roleOk then allOk := false
    let samplesBlock :=
      if d.samplesJson.isEmpty then "[]" else "[\n" ++ d.samplesJson ++ "\n  ]"
    let body :=
      "{\n" ++
      "  \"role\": \"" ++ r ++ "\",\n" ++
      "  \"corpusSize\": " ++ toString corpusSize ++ ",\n" ++
      "  \"mismatches\": " ++ toString mismatches ++ ",\n" ++
      "  \"samples\": " ++ samplesBlock ++ ",\n" ++
      "  \"abstractDiff\": {\n" ++
      "    \"merkle\": {\"n\": " ++ toString mN' ++ ", \"ok\": " ++ toString mOk' ++
        ", \"mismatch\": " ++ toString mMis' ++ "},\n" ++
      "    \"fri\": {\"n\": " ++ toString fN' ++ ", \"ok\": " ++ toString fOk' ++
        ", \"mismatch\": " ++ toString fMis' ++ "}\n" ++
      "  },\n" ++
      "  \"dualVm\": {\n" ++
      "    \"n\": " ++ toString d.n ++ ",\n" ++
      "    \"agreeAcceptOk\": " ++ toString d.agreeOk ++ ",\n" ++
      "    \"libauthAcceptedOk\": " ++ toString d.libauthOk ++ ",\n" ++
      "    \"leanVerifyInputOk\": " ++ toString d.leanOk ++ ",\n" ++
      "    \"disagree\": " ++ toString d.disagree ++ ",\n" ++
      "    \"source\": \"vectors/xcheck/sound-secure-xcheck-report.json#comparisons\"\n" ++
      "  },\n" ++
      "  \"method\": \"abstract Lean verifyDigest+verifyFoldStep (role_map) + dual-vm sound-secure host accept (libauthAccepted ⇔ leanVerifyInput via agreeAccept)\",\n" ++
      "  \"ok\": " ++ boolLit roleOk ++ "\n" ++
      "}\n"
    let outp := root ++ "/evidence/refinement/" ++ r ++ ".json"
    IO.FS.writeFile (System.FilePath.mk outp) body
    indexPaths := indexPaths ++ [outp]
    IO.println s!"role={r} dualVm.n={d.n} abstract={absOkN}/{absN} mis={mismatches} corpusSize={corpusSize} ok={roleOk}"

  -- INDEX.json listing absolute-ish paths written
  let idxBody :=
    "[\n" ++
    String.intercalate ",\n" (indexPaths.map (fun p => "  \"" ++ p ++ "\"")) ++
    "\n]\n"
  IO.FS.writeFile (System.FilePath.mk (root ++ "/evidence/refinement/INDEX.json")) idxBody

  if allOk then
    IO.println "ROLE_REFINE_OK"; pure 0
  else
    IO.println "ROLE_REFINE_FAIL"; pure 1
