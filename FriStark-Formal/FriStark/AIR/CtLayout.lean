/-
  CT public layout derived from membership depth D alone (public).
  Matches native_ct_air_prover.ct_build_layout + ct_public_layout.
-/
import FriStark.AIR.LayoutConstants
import FriStark.Field.Goldilocks
import FriStark.Params.V1
import FriStark.Domain.SelRebuild

namespace FriStark.AIR.CtLayout

open FriStark.AIR.LayoutConstants
open FriStark.Field.Goldilocks
open FriStark.Params.V1 (P)
open FriStark.Domain.SelRebuild

structure BlockMeta where
  name : String
  offset : Nat
  n : Nat
  chain : List (Nat × String)
  deriving Repr, Inhabited

structure RangeMeta where
  vname : String
  offset : Nat
  n : Nat
  src : Option String
  deriving Repr, Inhabited

structure RowMeta where
  block : String
  typ : String
  rc : List F
  deriving Repr, Inhabited

structure Meta where
  rows : List RowMeta
  blocks : List BlockMeta
  ranges : List RangeMeta
  cons_row : Nat
  raw : Nat
  T : Nat
  deriving Repr, Inhabited

def isFullRound (r : Nat) : Bool :=
  r < RF_HALF || r ≥ RF_HALF + ROUNDS_P

def blockRcFull (nRows : Nat) : List (List F) × List Bool := Id.run do
  let mut rcRows : List (List F) := []
  let mut fullRows : List Bool := []
  for r in [0:nRows - 1] do
    let rc :=
      if r < ROUNDS && r < RC_LAYOUT.size then
        (RC_LAYOUT[r]!).toList.map (fun x => x % P)
      else List.replicate WIDTH 0
    rcRows := rcRows ++ [rc]
    fullRows := fullRows ++ [isFullRound r]
  pure (rcRows, fullRows)

def buildLayout (D : Nat) : Meta := Id.run do
  let nBlk := ROUNDS + 1
  let mut seq : List String := ["owner", "cm_in"]
  for j in [0:D] do
    seq := seq ++ [s!"memb{j}"]
  seq := seq ++ ["nf", "cm_out0", "cm_out1"]
  let mut chainOf : List (String × List (Nat × String)) := [("cm_in", [(1, "owner")])]
  let mut prev := "cm_in"
  for j in [0:D] do
    let name := s!"memb{j}"
    chainOf := chainOf ++ [(name, [(0, prev)])]
    prev := name
  let mut blocks : List BlockMeta := []
  let mut layout : List RowMeta := []
  let mut off : Nat := 0
  for name in seq do
    let (rcRows, fullRows) := blockRcFull nBlk
    let ch :=
      match chainOf.find? (fun p => p.1 == name) with
      | some (_, c) => c
      | none => []
    blocks := blocks ++ [{ name := name, offset := off, n := nBlk, chain := ch }]
    for r in [0:nBlk] do
      if r == nBlk - 1 then
        layout := layout ++ [{
          block := name, typ := "boundary", rc := List.replicate WIDTH 0
        }]
      else
        let typ := if fullRows[r]! then "round_full" else "round_partial"
        layout := layout ++ [{ block := name, typ := typ, rc := rcRows[r]! }]
    off := off + nBlk
  let mut rangeMeta : List RangeMeta := []
  let rangeSpecs : List (String × Option String) := [
    ("value_in", some "cm_in"),
    ("value_out0", some "cm_out0"),
    ("value_out1", some "cm_out1"),
    ("fee", none)
  ]
  for (vname, src) in rangeSpecs do
    let roff := off
    for _ in [0:RANGE_BITS] do
      layout := layout ++ [{
        block := s!"range:{vname}", typ := "range", rc := List.replicate WIDTH 0
      }]
    rangeMeta := rangeMeta ++ [{ vname := vname, offset := roff, n := RANGE_BITS, src := src }]
    off := off + RANGE_BITS
  let consRow := off
  layout := layout ++ [{ block := "cons", typ := "cons", rc := List.replicate WIDTH 0 }]
  off := off + 1
  let raw := off
  let mut T : Nat := 1
  while T < raw do
    T := T * 2
  for _ in [0:T - raw] do
    layout := layout ++ [{ block := "_pad", typ := "pad", rc := List.replicate WIDTH 0 }]
  pure {
    rows := layout, blocks := blocks, ranges := rangeMeta,
    cons_row := consRow, raw := raw, T := T
  }

def publicH (m : Meta) : HLayout := Id.run do
  let T := m.T
  let mut isFull : Array F := Array.replicate T 0
  let mut isPartial : Array F := Array.replicate T 0
  let mut rc : Array (Array F) := Array.replicate WIDTH (Array.replicate T 0)
  for r in [0:m.rows.length] do
    let rm : RowMeta := m.rows[r]!
    if rm.typ == "round_full" then
      isFull := isFull.set! r 1
    else if rm.typ == "round_partial" then
      isPartial := isPartial.set! r 1
    if rm.typ == "round_full" || rm.typ == "round_partial" then
      for k in [0:WIDTH] do
        let col := rc[k]!
        rc := rc.set! k (col.set! r (rm.rc.getD k 0 % P))
  let mut isBlockStart : Array F := Array.replicate T 0
  let mut isReabsorb : Array F := Array.replicate T 0
  let mut chainMinv : Array (Array F) := Array.replicate T (Array.replicate WIDTH 0)
  for b in m.blocks do
    if b.offset < T then
      isBlockStart := isBlockStart.set! b.offset 1
    for (idx, srcName) in b.chain do
      match m.blocks.find? (fun x => x.name == srcName) with
      | none => pure ()
      | some _s =>
        let ra := b.offset - 1
        if ra < T - 1 then
          isReabsorb := isReabsorb.set! ra 1
          let invRow :=
            if idx < M_EXT_INV.size then
              (M_EXT_INV[idx]!).map (fun x => x % P)
            else Array.replicate WIDTH 0
          chainMinv := chainMinv.set! ra invRow
  let mut isRange : Array F := Array.replicate T 0
  let mut isRangeFirst : Array F := Array.replicate T 0
  let mut isRangeStep : Array F := Array.replicate T 0
  let mut isRangeLast : Array F := Array.replicate T 0
  let mut rangeWeight : Array F := Array.replicate T 0
  for rmv in m.ranges do
    for loc in [0:rmv.n] do
      let r := rmv.offset + loc
      if r < T then
        isRange := isRange.set! r 1
        rangeWeight := rangeWeight.set! r ((1 <<< loc) % P)
        if loc == 0 then
          isRangeFirst := isRangeFirst.set! r 1
        if loc == rmv.n - 1 then
          isRangeLast := isRangeLast.set! r 1
        else
          isRangeStep := isRangeStep.set! r 1
  let mut chainCols : List (List F) := []
  for j in [0:WIDTH] do
    let mut col : List F := []
    for r in [0:T] do
      col := col ++ [(chainMinv[r]!)[j]!]
    chainCols := chainCols ++ [col]
  let rcLists := (List.range WIDTH).map fun k => (rc[k]!).toList
  pure {
    oT := 0
    is_full := isFull.toList
    is_partial := isPartial.toList
    is_block_start := isBlockStart.toList
    is_reabsorb := isReabsorb.toList
    is_range := isRange.toList
    is_range_first := isRangeFirst.toList
    is_range_step := isRangeStep.toList
    is_range_last := isRangeLast.toList
    rc := rcLists
    chain := chainCols
    range_weight := rangeWeight.toList
  }

def prodDepth : Nat := 2
def prodMeta : Meta := buildLayout prodDepth
def prodHLayout (oT : F) : HLayout :=
  let h := publicH prodMeta
  { h with oT := oT }

end FriStark.AIR.CtLayout
