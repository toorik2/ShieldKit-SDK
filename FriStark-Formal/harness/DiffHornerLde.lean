/-
  Horner≡LDE honesty: for public columns, evalAtBase(H,oT,x) equals pin KAT samples
  generated from Python LDE at domain x (not full N=2^20 materialization).
-/
import FriStark.AIR.CtLayout
import FriStark.Domain.PublicEval
import FriStark.Params.V1

open FriStark.AIR.CtLayout
open FriStark.Domain.PublicEval
open FriStark.Params.V1 (P)

def parseNatList (s : String) : List Nat :=
  if s.isEmpty then [] else (s.splitOn ",").map String.toNat!

def main (args : List String) : IO UInt32 := do
  let root := args.getD 0 "."
  let path := System.FilePath.mk (root ++ "/vectors/layout/prod_public.simple")
  if !(← path.pathExists) then
    IO.eprintln "missing prod_public.simple"; return 2
  let txt ← IO.FS.readFile path
  let mut oT : Nat := 0; let mut oN : Nat := 0; let mut off : Nat := 0
  let mut checks : Nat := 0; let mut fails : Nat := 0
  let lean := publicH (buildLayout 2)
  for line in txt.splitOn "\n" do
    if line.isEmpty then continue
    let p := line.splitOn "|"
    let tag := p.headD ""
    if tag == "META" then
      oT := p[3]!.toNat!; oN := p[4]!.toNat!; off := p[5]!.toNat!
    else if tag == "KAT_BASE" then
      let k := p[2]!.toNat!
      let xPin := p[3]!.toNat!
      let x := domainPoint off oN k
      checks := checks + 1
      if x % P != xPin % P then
        fails := fails + 1
        IO.eprintln s!"domain x mismatch k={k}"
      let samples := parseNatList (p.getD 4 "")
      -- first 8 selector keys order
      let cols := [
        lean.is_full, lean.is_partial, lean.is_block_start, lean.is_reabsorb,
        lean.is_range, lean.is_range_first, lean.is_range_step, lean.is_range_last
      ]
      let mut idx := 0
      for col in cols do
        let got := evalAtBase col oT x
        let exp := samples.getD idx 0
        checks := checks + 1
        if got % P != exp % P then
          fails := fails + 1
          if fails ≤ 5 then IO.eprintln s!"Horner≠LDE col#{idx} k={k}"
        idx := idx + 1
      for j in [0:12] do
        let got := evalAtBase (lean.rc.getD j []) oT x
        let exp := samples.getD idx 0
        checks := checks + 1
        if got % P != exp % P then fails := fails + 1
        idx := idx + 1
      for j in [0:12] do
        let got := evalAtBase (lean.chain.getD j []) oT x
        let exp := samples.getD idx 0
        checks := checks + 1
        if got % P != exp % P then fails := fails + 1
        idx := idx + 1
      let got := evalAtBase lean.range_weight oT x
      let exp := samples.getD idx 0
      checks := checks + 1
      if got % P != exp % P then fails := fails + 1

  IO.println s!"horner_lde_checks={checks} fails={fails}"
  IO.println "strategy=A Horner(INTT(H),x)≡LDE(x) at prod query domain points; no full N=2^20 tables"
  if fails == 0 && checks ≥ 8 then
    IO.println "HORNER_LDE_OK"
    pure 0
  else
    IO.println "HORNER_LDE_FAIL"
    pure 1
