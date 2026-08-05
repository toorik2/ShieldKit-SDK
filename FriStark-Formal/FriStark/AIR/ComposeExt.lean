/-
  GF(p²) CT-AIR composition at OOD z matching native_ct_air_stark._compose_at_ext
  and ct_transition_residuals_ext (fixed residual order).
-/
import FriStark.Field.Ext
import FriStark.Field.Goldilocks
import FriStark.Domain.PublicEval
import FriStark.Params.V1

namespace FriStark.AIR.ComposeExt

open FriStark.Field.Ext
open FriStark.Field.Goldilocks
open FriStark.Domain.PublicEval
open FriStark.Params.V1 (P)

def WIDTH : Nat := 12
def RATE : Nat := 8

def getCol (m : List (String × E)) (name : String) : E :=
  match m.find? (fun p => p.1 == name) with
  | some (_, v) => v
  | none => zero

def matvec (row : List F) (y : List E) : E := Id.run do
  let mut acc := zero
  for k in [0:WIDTH] do
    acc := add acc (scalar (row.getD k 0) (y.getD k zero))
  pure acc

def matvecState (row : List F) (cur : List (String × E)) : E := Id.run do
  let mut acc := zero
  for j in [0:WIDTH] do
    acc := add acc (scalar (row.getD j 0) (getCol cur s!"s{j}"))
  pure acc

def extApply (M : List (List F)) (y : List E) : List E :=
  (List.range WIDTH).map (fun j => matvec (M.getD j []) y)

def intApply (diag : List F) (y : List E) : List E := Id.run do
  let mut s := zero
  for e in y do s := add s e
  pure ((List.range WIDTH).map fun i =>
    add (scalar (diag.getD i 0) (y.getD i zero)) s)

def capacityResiduals (cur : List (String × E)) (isbs : E)
    (Minv : List (List F)) : List E :=
  (List.range (WIDTH - RATE)).map fun i =>
    let k := RATE + i
    mul isbs (matvecState (Minv.getD k []) cur)

def reabsorbResidual (cur nxt : List (String × E)) (isra : E)
    (minvRow : List E) : E := Id.run do
  let mut chained := zero
  for j in [0:WIDTH] do
    chained := add chained (mul (minvRow.getD j zero) (getCol nxt s!"s{j}"))
  pure (mul isra (sub chained (getCol cur "s0")))

def holdResiduals (cur nxt : List (String × E)) (held : List String) : List E :=
  held.map fun c => sub (getCol nxt c) (getCol cur c)

def rangeResiduals (cur nxt : List (String × E))
    (isr isf ist isl wNext : E) : List E :=
  let b := getCol cur "s0"
  [
    mul isr (mul b (sub b one)),
    mul isf (sub (getCol cur "s1") b),
    mul ist (sub (sub (getCol nxt "s1") (getCol cur "s1")) (mul (getCol nxt "s0") wNext)),
    mul ist (sub (getCol nxt "s2") (getCol cur "s2")),
    mul isl (sub (getCol cur "s1") (getCol cur "s2"))
  ]

/-- Full transition residual list (order matches Python). -/
def allTransitionResiduals
    (cur nxt : List (String × E))
    (pub : List (String × E))
    (rc chainMinv : List E)
    (wNext : E)
    (Mext Minv : List (List F)) (diag : List F)
    (held : List String) : List E := Id.run do
  let isFull := getCol pub "is_full"
  let isPartial := getCol pub "is_partial"
  let isbs := getCol pub "is_block_start"
  let isra := getCol pub "is_reabsorb"
  let isr := getCol pub "is_range"
  let isrf := getCol pub "is_range_first"
  let isrs := getCol pub "is_range_step"
  let isrl := getCol pub "is_range_last"
  let mut res : List E := []
  let isRound := add isFull isPartial
  let mut yFull : Array E := Array.replicate WIDTH zero
  let mut yPart : Array E := Array.replicate WIDTH zero
  for k in [0:WIDTH] do
    let x := add (getCol cur s!"s{k}") (rc.getD k zero)
    let u2 := getCol cur s!"u2_{k}"
    let u4 := getCol cur s!"u4_{k}"
    let u6 := getCol cur s!"u6_{k}"
    let gate := if k == 0 then isRound else isFull
    res := res ++ [mul gate (sub u2 (mul x x))]
    res := res ++ [mul gate (sub u4 (mul u2 u2))]
    res := res ++ [mul gate (sub u6 (mul u4 u2))]
    let yk := mul u6 x
    yFull := yFull.set! k yk
    yPart := yPart.set! k (if k == 0 then yk else getCol cur s!"s{k}")
  let ef := extApply Mext yFull.toList
  let ip := intApply diag yPart.toList
  for j in [0:WIDTH] do
    let sj := getCol nxt s!"s{j}"
    res := res ++ [
      add (mul isFull (sub sj (ef.getD j zero)))
          (mul isPartial (sub sj (ip.getD j zero)))
    ]
  res := res ++ capacityResiduals cur isbs Minv
  res := res ++ [reabsorbResidual cur nxt isra chainMinv]
  res := res ++ holdResiduals cur nxt held
  res := res ++ rangeResiduals cur nxt isr isrf isrs isrl wNext
  pure res

inductive BndKind where
  | root | nf | cm | link | cmbind | cons
  deriving Repr, DecidableEq, Inhabited

structure Boundary where
  row : Nat
  kind : BndKind
  payload : F
  held : String := ""
  deriving Repr, Inhabited

def boundaryResidual (b : Boundary) (cur : List (String × E))
    (Minv0 : List F) : E :=
  match b.kind with
  | .root => sub (getCol cur "s0") (fromBase b.payload)
  | .nf => sub (getCol cur "s0") (fromBase b.payload)
  | .cm => sub (getCol cur "s0") (fromBase b.payload)
  | .link =>
      let hc := if b.held.isEmpty then "vh_value_in" else b.held
      sub (getCol cur hc) (getCol cur "s2")
  | .cmbind => Id.run do
      let hc := if b.held.isEmpty then "vh_value_in" else b.held
      let mut acc := zero
      for j in [0:WIDTH] do
        acc := add acc (scalar (Minv0.getD j 0) (getCol cur s!"s{j}"))
      pure (sub (getCol cur hc) acc)
  | .cons =>
      sub (getCol cur "vh_value_in")
        (add (add (getCol cur "vh_value_out0") (getCol cur "vh_value_out1"))
             (getCol cur "vh_fee"))

def composeAtExt
    (cur nxt : List (String × E))
    (z : E) (wNext : E) (last : F)
    (zhInvV : E) (Hd : List F)
    (pub : List (String × E)) (rc chainMinv : List E)
    (alphasT alphasB : List E)
    (bounds : List Boundary)
    (Mext Minv : List (List F)) (diag Minv0 : List F)
    (held : List String) : E := Id.run do
  let zl := sub z (fromBase last)
  let tres := allTransitionResiduals cur nxt pub rc chainMinv wNext Mext Minv diag held
  let mut acc := zero
  let nT := min alphasT.length tres.length
  for i in [0:nT] do
    let v := tres[i]!
    let a := alphasT[i]!
    acc := add acc (mul (mul (mul v zl) zhInvV) a)
  let nB := min alphasB.length bounds.length
  for i in [0:nB] do
    let b := bounds[i]!
    let a := alphasB[i]!
    let r := boundaryResidual b cur Minv0
    let den := sub z (fromBase (Hd.getD b.row 0))
    match inv den with
    | none => pure ()
    | some iden => acc := add acc (mul (mul r iden) a)
  pure acc

def matchesCompZ
    (cur nxt : List (String × E))
    (z : E) (wNext : E) (last : F)
    (zhInvV : E) (Hd : List F)
    (pub : List (String × E)) (rc chainMinv : List E)
    (alphasT alphasB : List E)
    (bounds : List Boundary)
    (Mext Minv : List (List F)) (diag Minv0 : List F)
    (held : List String) (expect : E) : Bool :=
  eq (composeAtExt cur nxt z wNext last zhInvV Hd pub rc chainMinv
        alphasT alphasB bounds Mext Minv diag Minv0 held) expect

end FriStark.AIR.ComposeExt
