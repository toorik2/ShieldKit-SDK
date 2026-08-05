/-
  Build ComposePack public OOD fields from H-layout via PublicEval/SelRebuild.
  Proof openings (Pcz/Pczg, alphas, boundaries, Hd, matrices) remain proof material.
-/
import FriStark.Domain.SelRebuild
import FriStark.Domain.PublicEval
import FriStark.AIR.ComposeExt
import FriStark.Full.Verify
import FriStark.Field.Ext
import FriStark.Field.Goldilocks

namespace FriStark.Domain.ComposeFromLayout

open FriStark.Domain.SelRebuild
open FriStark.Domain.PublicEval
open FriStark.AIR.ComposeExt
open FriStark.Full.Verify
open FriStark.Field.Ext
open FriStark.Field.Goldilocks (F)

/-- Public OOD map at z rebuilt in Lean (not export PUB tables). -/
def pubMapAtZ (L : HLayout) (z : E) : List (String × E) :=
  let m := selMaskAtZ L z
  [
    ("is_full", m.is_full),
    ("is_partial", m.is_partial),
    ("is_block_start", m.is_block_start),
    ("is_reabsorb", m.is_reabsorb),
    ("is_range", m.is_range),
    ("is_range_first", m.is_range_first),
    ("is_range_step", m.is_range_step),
    ("is_range_last", m.is_range_last)
  ]

/-- ComposePack with public OOD + rw_zg + zhInv from Lean H-layout math. -/
def packFromLayout
    (L : HLayout) (T : Nat)
    (z : E)
    (cur nxt : List (String × E))
    (lastF : F)
    (Hd : List F)
    (alphasT alphasB : List E)
    (bounds : List Boundary)
    (Mext Minv : List (List F))
    (diag Minv0 : List F)
    (held : List String)
    (expectCompZ : E) : Option ComposePack :=
  match zhInv z T with
  | none => none
  | some zh =>
    let m := selMaskAtZ L z
    let zg := scalar L.oT z  -- zg = oT · z matching DEEP (oT is base generator)
    -- Note: production zg = scalar(oT, z) with oT as F — SelRebuild.rwAtZg uses layout.oT
    let wNext := rwAtZg L zg
    some {
      cur := cur
      nxt := nxt
      z := z
      wNext := wNext
      lastF := lastF
      zhInv := zh
      Hd := Hd
      pub := pubMapAtZ L z
      rc := m.rc
      chainMinv := m.chain_minv
      alphasT := alphasT
      alphasB := alphasB
      bounds := bounds
      Mext := Mext
      Minv := Minv
      diag := diag
      Minv0 := Minv0
      held := held
      expectCompZ := expectCompZ
    }

/-- Same as packFromLayout but uses proof zg for range_weight(zg) (matches DEEP). -/
def packFromLayoutWithZg
    (L : HLayout) (T : Nat)
    (z zg : E)
    (cur nxt : List (String × E))
    (lastF : F)
    (Hd : List F)
    (alphasT alphasB : List E)
    (bounds : List Boundary)
    (Mext Minv : List (List F))
    (diag Minv0 : List F)
    (held : List String)
    (expectCompZ : E) : Option ComposePack :=
  match zhInv z T with
  | none => none
  | some zh =>
    let m := selMaskAtZ L z
    let wNext := rwAtZg L zg
    some {
      cur := cur
      nxt := nxt
      z := z
      wNext := wNext
      lastF := lastF
      zhInv := zh
      Hd := Hd
      pub := pubMapAtZ L z
      rc := m.rc
      chainMinv := m.chain_minv
      alphasT := alphasT
      alphasB := alphasB
      bounds := bounds
      Mext := Mext
      Minv := Minv
      diag := diag
      Minv0 := Minv0
      held := held
      expectCompZ := expectCompZ
    }

end FriStark.Domain.ComposeFromLayout
