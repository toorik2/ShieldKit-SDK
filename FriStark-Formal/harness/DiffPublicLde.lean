/-
  Public LDE gate: Lean INTT+Horner recomputes selector samples at k and OOD at z
  matching Python oracle KATs in vectors/layout/prod_public.simple.
-/
import FriStark.Domain.PublicEval
import FriStark.Field.Goldilocks
import FriStark.Field.Ext
import FriStark.Params.V1

open FriStark.Domain.PublicEval
open FriStark.Field.Goldilocks
open FriStark.Field.Ext
open FriStark.Params.V1 (P)

def parseNatList (s : String) : List Nat :=
  if s.isEmpty then [] else (s.splitOn ",").map String.toNat!

def findH (tables : List (String × List Nat)) (name : String) : Option (List Nat) :=
  (tables.find? (fun p => p.1 == name)).map (·.2)

def main (args : List String) : IO UInt32 := do
  let root := args.getD 0 "."
  let path := System.FilePath.mk (root ++ "/vectors/layout/prod_public.simple")
  if !(← path.pathExists) then
    IO.eprintln s!"missing {path}"; return 2
  let content ← IO.FS.readFile path
  let mut T : Nat := 0
  let mut oT : Nat := 0
  let mut oN : Nat := 0
  let mut off : Nat := 0
  let mut tables : List (String × List Nat) := []
  let mut chainRows : Array (List Nat) := #[]
  let mut z0 : E := zero
  let mut zg0 : E := zero
  let mut fails : Nat := 0
  let mut checks : Nat := 0

  for line in content.splitOn "\n" do
    if line.isEmpty then continue
    let p := line.splitOn "|"
    let tag := p.headD ""
    if tag == "Z" then
      z0 := ⟨p[1]!.toNat!, p[2]!.toNat!⟩
      zg0 := ⟨p[3]!.toNat!, p[4]!.toNat!⟩
    else if tag == "META" then
      T := p[1]!.toNat!
      oT := p[3]!.toNat!
      oN := p[4]!.toNat!
      off := p[5]!.toNat!
      chainRows := Array.replicate T []
    else if tag == "H" then
      tables := tables ++ [(p[1]!, parseNatList (p.getD 2 ""))]
    else if tag == "RC" then
      tables := tables ++ [(s!"rc{p[1]!}", parseNatList (p.getD 2 ""))]
    else if tag == "CHAIN" then
      let r := p[1]!.toNat!
      let row := parseNatList (p.getD 2 "")
      if r < chainRows.size then
        chainRows := chainRows.set! r row

  -- rebuild chain columns
  if T > 0 then
    for j in [0:12] do
      let mut col : List Nat := []
      for r in [0:T] do
        col := col ++ [(chainRows[r]!).getD j 0]
      tables := tables ++ [(s!"chain{j}", col)]

  if T == 0 then IO.eprintln "no META"; return 3

  for line in content.splitOn "\n" do
    if line.isEmpty then continue
    let p := line.splitOn "|"
    let tag := p.headD ""
    if tag == "KAT_BASE" then
      let k := p[2]!.toNat!
      let xExpect := p[3]!.toNat!
      let xGot := domainPoint off oN k
      checks := checks + 1
      if xGot % P != xExpect % P then
        fails := fails + 1
        IO.eprintln s!"domainPoint mismatch k={k}"
      let samples := parseNatList (p.getD 4 "")
      let keys := [
        "is_full", "is_partial", "is_block_start", "is_reabsorb",
        "is_range", "is_range_first", "is_range_step", "is_range_last"
      ]
      let mut idx := 0
      for key in keys do
        match findH tables key with
        | none => fails := fails + 1; IO.eprintln s!"missing {key}"
        | some h =>
          let got := evalAtBase h oT xGot
          let exp := samples.getD idx 0
          checks := checks + 1
          if got % P != exp % P then
            fails := fails + 1
            IO.eprintln s!"base {key} k={k} got={got} exp={exp}"
        idx := idx + 1
      for j in [0:12] do
        match findH tables s!"rc{j}" with
        | none => fails := fails + 1
        | some h =>
          let got := evalAtBase h oT xGot
          let exp := samples.getD idx 0
          checks := checks + 1
          if got % P != exp % P then
            fails := fails + 1
            IO.eprintln s!"rc{j} mismatch"
        idx := idx + 1
      for j in [0:12] do
        match findH tables s!"chain{j}" with
        | none => fails := fails + 1
        | some h =>
          let got := evalAtBase h oT xGot
          let exp := samples.getD idx 0
          checks := checks + 1
          if got % P != exp % P then
            fails := fails + 1
            IO.eprintln s!"chain{j} mismatch"
        idx := idx + 1
      match findH tables "range_weight" with
      | none => fails := fails + 1
      | some h =>
        let got := evalAtBase h oT xGot
        let exp := samples.getD idx 0
        checks := checks + 1
        if got % P != exp % P then
          fails := fails + 1
          IO.eprintln "range_weight mismatch"
    else if tag == "KAT_OOD" then
      pure ()

  -- OOD checks
  match findH tables "is_full" with
  | none => fails := fails + 1
  | some h =>
    let got := evalAtExt h oT z0
    for line in content.splitOn "\n" do
      let p := line.splitOn "|"
      if p.headD "" == "KAT_OOD" && p.getD 2 "" == "is_full" then
        let exp : E := ⟨p[3]!.toNat!, p[4]!.toNat!⟩
        checks := checks + 1
        if !eq got exp then
          fails := fails + 1
          IO.eprintln s!"OOD is_full mismatch"
        break
  match findH tables "range_weight" with
  | none => fails := fails + 1
  | some h =>
    let got := evalAtExt h oT zg0
    for line in content.splitOn "\n" do
      let p := line.splitOn "|"
      if p.headD "" == "KAT_OOD" && p.getD 2 "" == "range_weight_zg" then
        let exp : E := ⟨p[3]!.toNat!, p[4]!.toNat!⟩
        checks := checks + 1
        if !eq got exp then
          fails := fails + 1
          IO.eprintln "OOD range_weight_zg mismatch"
        break

  IO.println s!"public_lde_checks={checks} fails={fails} T={T}"
  if fails == 0 && checks ≥ 10 then
    IO.println "PUBLIC_LDE_OK"
    pure 0
  else
    IO.println "PUBLIC_LDE_FAIL"
    pure 1
