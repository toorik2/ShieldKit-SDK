/-
  AIR composition gate: H from Lean CtLayout.prodHLayout (sole H source);
  pin prod_public.simple only for domain oT/zg and optional cross-check.
  Public OOD via packFromLayoutWithZg. Includes composition-breaking forges.
-/
import FriStark.AIR.ComposeExt
import FriStark.AIR.CtLayout
import FriStark.Domain.ComposeFromLayout
import FriStark.Domain.SelRebuild
import FriStark.Domain.PublicEval
import FriStark.Full.Verify
import FriStark.Field.Ext
import FriStark.Field.Goldilocks
import FriStark.Params.V1

open FriStark.AIR.ComposeExt
open FriStark.AIR.CtLayout
open FriStark.Domain.ComposeFromLayout
open FriStark.Domain.SelRebuild
open FriStark.Domain.PublicEval
open FriStark.Full.Verify
open FriStark.Field.Ext
open FriStark.Field.Goldilocks
open FriStark.Params.V1

def parseNatList (s : String) : List Nat :=
  if s.isEmpty then [] else (s.splitOn ",").map String.toNat!

def parseKind (s : String) : BndKind :=
  match s with
  | "root" => .root | "nf" => .nf | "cm" => .cm
  | "link" => .link | "cmbind" => .cmbind | _ => .cons

def main (args : List String) : IO UInt32 := do
  let root := args.getD 0 "."
  let layoutPath := System.FilePath.mk (root ++ "/vectors/layout/prod_public.simple")
  let composePath := System.FilePath.mk (root ++ "/vectors/layout/prod_compose.simple")
  if !(← layoutPath.pathExists) || !(← composePath.pathExists) then
    IO.eprintln "missing layout/compose"; return 2

  -- Domain params + zg from pin META/Z only (not H columns)
  let layoutTxt ← IO.FS.readFile layoutPath
  let mut oT : Nat := 0; let mut zg : E := zero
  for line in layoutTxt.splitOn "\n" do
    if line.isEmpty then continue
    let p := line.splitOn "|"
    if p.headD "" == "META" then oT := p[3]!.toNat!
    else if p.headD "" == "Z" then zg := ⟨p[3]!.toNat!, p[4]!.toNat!⟩

  -- SOLE H source: Lean CtLayout from depth
  let m := buildLayout 2
  let layout : HLayout := prodHLayout oT
  let T := m.T
  IO.println s!"H_source=Lean CtLayout.buildLayout/prodHLayout T={T} oT={oT}"

  -- Proof openings only from compose file
  let content ← IO.FS.readFile composePath
  let mut last : Nat := 0
  let mut z : E := zero
  let mut expect : E := zero
  let mut cur : List (String × E) := []; let mut nxt : List (String × E) := []
  let mut alphasT : List E := []; let mut alphasB : List E := []
  let mut bounds : List Boundary := []
  let mut Hd : List Nat := []
  let mut Mext : Array (List Nat) := Array.replicate 12 []
  let mut Minv : Array (List Nat) := Array.replicate 12 []
  let mut diag : List Nat := []; let mut held : List String := []
  let mut expRw : E := zero; let mut expZh : E := zero
  for line in content.splitOn "\n" do
    if line.isEmpty then continue
    let p := line.splitOn "|"
    let tag := p.headD ""
    if tag == "META" then last := p[2]!.toNat!
    else if tag == "Z" then z := ⟨p[1]!.toNat!, p[2]!.toNat!⟩
    else if tag == "COMPZ" then expect := ⟨p[1]!.toNat!, p[2]!.toNat!⟩
    else if tag == "RWZG" then expRw := ⟨p[1]!.toNat!, p[2]!.toNat!⟩
    else if tag == "ZHINV" then expZh := ⟨p[1]!.toNat!, p[2]!.toNat!⟩
    else if tag == "PCZ" then cur := (p[1]!, ⟨p[2]!.toNat!, p[3]!.toNat!⟩) :: cur
    else if tag == "PCZG" then nxt := (p[1]!, ⟨p[2]!.toNat!, p[3]!.toNat!⟩) :: nxt
    else if tag == "ALPHAT" then alphasT := alphasT ++ [⟨p[1]!.toNat!, p[2]!.toNat!⟩]
    else if tag == "ALPHAB" then alphasB := alphasB ++ [⟨p[1]!.toNat!, p[2]!.toNat!⟩]
    else if tag == "BND" then
      bounds := bounds ++ [{
        row := p[2]!.toNat!, kind := parseKind p[1]!, payload := p[3]!.toNat!, held := p.getD 4 ""
      }]
    else if tag == "HD" then Hd := parseNatList (p.getD 1 "")
    else if tag == "MEXT" then
      let i := p[1]!.toNat!
      if i < 12 then Mext := Mext.set! i (parseNatList (p.getD 2 ""))
    else if tag == "MEXTINV" then
      let i := p[1]!.toNat!
      if i < 12 then Minv := Minv.set! i (parseNatList (p.getD 2 ""))
    else if tag == "DIAG" then diag := parseNatList (p.getD 1 "")
    else if tag == "HELD" then
      held := if (p.getD 1 "").isEmpty then [] else (p[1]!).splitOn ","

  match packFromLayoutWithZg layout T z zg cur nxt last Hd alphasT alphasB bounds
      Mext.toList Minv.toList diag (Minv[0]!) held expect with
  | none => IO.eprintln "packFromLayout failed"; return 3
  | some pack =>
    if !eq pack.wNext expRw then
      IO.eprintln "Lean rw_zg != export RWZG (cross-check)"; return 4
    if !eq pack.zhInv expZh then
      IO.eprintln "Lean zhInv != export ZHINV (cross-check)"; return 4
    let tres := allTransitionResiduals pack.cur pack.nxt pack.pub pack.rc pack.chainMinv
      pack.wNext pack.Mext pack.Minv pack.diag pack.held
    IO.println s!"n_transition_residuals={tres.length} n_boundary={pack.bounds.length}"
    IO.println "public_ood_source=Lean CtLayout H + PublicEval (not pin H columns)"
    let honest : Bundle := {
      steps := [Step.composeCheck pack], accept := true, label := "compose-honest",
      eligibility := "product", blowup := BLOWUP, queries := QUERIES,
      grindBits := GRIND_BITS, fold := FOLD
    }
    if !(verify honest).isOk then
      IO.eprintln "honest composeCheck FAIL"; return 5
    IO.println "composeCheck honest ok"
    let forgedExpect : E := ⟨(pack.expectCompZ.a0 + 1) % P, pack.expectCompZ.a1⟩
    let forgePack := { pack with expectCompZ := forgedExpect }
    let forgeB : Bundle := {
      steps := [Step.composeCheck forgePack], accept := false, label := "compose-forge-compz",
      eligibility := "product", blowup := BLOWUP, queries := QUERIES,
      grindBits := GRIND_BITS, fold := FOLD
    }
    if (verify forgeB).isOk then
      IO.eprintln "compose forge FALSE ACCEPT"; return 6
    IO.println "composeCheck forge-compz rejected"
    let forgeCur := match pack.cur with
      | [] => []
      | (n, v) :: rest => (n, ⟨(v.a0 + 1) % P, v.a1⟩) :: rest
    let forgePack2 := { pack with cur := forgeCur }
    let forgeB2 : Bundle := {
      steps := [Step.composeCheck forgePack2], accept := false, label := "compose-forge-pcz",
      eligibility := "product", blowup := BLOWUP, queries := QUERIES,
      grindBits := GRIND_BITS, fold := FOLD
    }
    if (verify forgeB2).isOk then
      IO.eprintln "compose forge-pcz FALSE ACCEPT"; return 7
    IO.println "composeCheck forge-pcz rejected"
    if tres.length == 62 then
      IO.println "AIR_COMPOSE_OK"
      pure 0
    else
      IO.println "AIR_COMPOSE_FAIL residual count"
      pure 1
