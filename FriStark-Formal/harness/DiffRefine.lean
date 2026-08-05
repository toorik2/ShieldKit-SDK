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

def main (args : List String) : IO UInt32 := do
  let root := args.getD 0 "."
  let mpath := System.FilePath.mk (root ++ "/vectors/refinement/merkle.simple")
  let fpath := System.FilePath.mk (root ++ "/vectors/refinement/fri.simple")
  if !(← mpath.pathExists) || !(← fpath.pathExists) then
    IO.eprintln "missing refinement simple corpora"; return 2
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
    -- gen uses H(raw leaf) as tree leaf
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
  IO.println s!"refine_merkle ok={mOk}/{mN} mismatch={mMismatch}"
  IO.println s!"refine_fri ok={fOk}/{fN} mismatch={fMismatch}"
  -- Abstract-only gate. Per-role dual-vm linkage is owned by diff_role_refine
  -- (do not write fabricated identical role stubs here).
  let corpusSize := mN + fN
  let mismatches := mMismatch + fMismatch
  let okFlag := mismatches == 0 && corpusSize ≥ 100
  IO.println s!"abstract_corpus n={corpusSize} mismatches={mismatches}"
  if okFlag then
    IO.println "DIFF_REFINE_OK"; pure 0
  else
    IO.println "DIFF_REFINE_FAIL"; pure 1
