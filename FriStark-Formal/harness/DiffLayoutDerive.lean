/-
  Gate: Lean CtLayout.publicH(buildLayout depth) matches pin prod_public.simple H tables.
  Pin file is cross-check only; accept path uses Lean-derived H.
-/
import FriStark.AIR.CtLayout
import FriStark.Domain.SelRebuild
import FriStark.Params.V1

open FriStark.AIR.CtLayout
open FriStark.Domain.SelRebuild
open FriStark.Params.V1 (P)

def parseNatList (s : String) : List Nat :=
  if s.isEmpty then [] else (s.splitOn ",").map String.toNat!

def colMatch (a b : List Nat) (name : String) : IO Nat := do
  let mut fails := 0
  if a.length != b.length then
    IO.eprintln s!"{name} len {a.length} vs {b.length}"
    return 1
  for i in [0:a.length] do
    if a[i]! % P != b[i]! % P then
      fails := fails + 1
      if fails ≤ 3 then
        IO.eprintln s!"{name}[{i}] lean={a[i]!} pin={b[i]!}"
  pure fails

def main (args : List String) : IO UInt32 := do
  let root := args.getD 0 "."
  let path := System.FilePath.mk (root ++ "/vectors/layout/prod_public.simple")
  if !(← path.pathExists) then
    IO.eprintln "missing prod_public.simple cross-check pin"; return 2
  let txt ← IO.FS.readFile path
  let mut oT : Nat := 0
  let mut pin : List (String × List Nat) := []
  let mut pinRc : Array (List Nat) := Array.replicate 12 []
  let mut pinChainRows : Array (List Nat) := #[]
  let mut Tpin : Nat := 0
  for line in txt.splitOn "\n" do
    if line.isEmpty then continue
    let p := line.splitOn "|"
    let tag := p.headD ""
    if tag == "META" then
      Tpin := p[1]!.toNat!; oT := p[3]!.toNat!
      pinChainRows := Array.replicate Tpin []
    else if tag == "H" then
      pin := pin ++ [(p[1]!, parseNatList (p.getD 2 ""))]
    else if tag == "RC" then
      let i := p[1]!.toNat!
      if i < 12 then pinRc := pinRc.set! i (parseNatList (p.getD 2 ""))
    else if tag == "CHAIN" then
      let r := p[1]!.toNat!
      if r < pinChainRows.size then
        pinChainRows := pinChainRows.set! r (parseNatList (p.getD 2 ""))

  let m := buildLayout 2
  let lean := publicH m
  IO.println s!"lean_T={m.T} pin_T={Tpin} raw={m.raw} cons_row={m.cons_row} n_blocks={m.blocks.length}"
  let mut fails : Nat := 0
  if m.T != Tpin then
    fails := fails + 1
    IO.eprintln s!"T mismatch lean={m.T} pin={Tpin}"

  let getPin (n : String) : List Nat :=
    match pin.find? (fun p => p.1 == n) with
    | some (_, v) => v
    | none => []

  fails := fails + (← colMatch lean.is_full (getPin "is_full") "is_full")
  fails := fails + (← colMatch lean.is_partial (getPin "is_partial") "is_partial")
  fails := fails + (← colMatch lean.is_block_start (getPin "is_block_start") "is_block_start")
  fails := fails + (← colMatch lean.is_reabsorb (getPin "is_reabsorb") "is_reabsorb")
  fails := fails + (← colMatch lean.is_range (getPin "is_range") "is_range")
  fails := fails + (← colMatch lean.is_range_first (getPin "is_range_first") "is_range_first")
  fails := fails + (← colMatch lean.is_range_step (getPin "is_range_step") "is_range_step")
  fails := fails + (← colMatch lean.is_range_last (getPin "is_range_last") "is_range_last")
  fails := fails + (← colMatch lean.range_weight (getPin "range_weight") "range_weight")
  for k in [0:12] do
    fails := fails + (← colMatch (lean.rc.getD k []) (pinRc[k]!) s!"rc{k}")
  -- chain columns
  for j in [0:12] do
    let mut pinCol : List Nat := []
    for r in [0:Tpin] do
      pinCol := pinCol ++ [(pinChainRows[r]!).getD j 0]
    fails := fails + (← colMatch (lean.chain.getD j []) pinCol s!"chain{j}")

  -- domain oT attach smoke
  let hOt := prodHLayout oT
  if hOt.oT != oT then fails := fails + 1

  IO.println s!"layout_derive_fails={fails}"
  if fails == 0 then
    IO.println "LAYOUT_DERIVE_OK"
    IO.println "H_source=Lean CtLayout.buildLayout(depth)  pin=cross-check only"
    pure 0
  else
    IO.println "LAYOUT_DERIVE_FAIL"
    pure 1
