/-
  Full STARK math accept entry.
  H sole source: Lean CtLayout.prodHLayout (pin only for oT/zg/KAT cross-check).
  Compose: packFromLayoutWithZg only. Re-runs pure layout-deep verify.
-/
import FriStark.Full.Verify
import FriStark.AIR.ProductV1
import FriStark.AIR.ComposeExt
import FriStark.AIR.CtLayout
import FriStark.Domain.SelRebuild
import FriStark.Domain.PublicEval
import FriStark.Domain.ComposeFromLayout
import FriStark.Binding.Forges
import FriStark.Params.V1
import FriStark.Field.Ext

open FriStark.Full.Verify
open FriStark.AIR.ProductV1
open FriStark.AIR.ComposeExt
open FriStark.AIR.CtLayout
open FriStark.Domain.SelRebuild
open FriStark.Domain.PublicEval
open FriStark.Domain.ComposeFromLayout
open FriStark.Binding.Forges
open FriStark.Params.V1
open FriStark.Field.Ext

def parseNatList (s : String) : List Nat :=
  if s.isEmpty then [] else (s.splitOn ",").map String.toNat!

def parseKind (s : String) : BndKind :=
  match s with
  | "root" => .root | "nf" => .nf | "cm" => .cm
  | "link" => .link | "cmbind" => .cmbind | _ => .cons

def main (args : List String) : IO UInt32 := do
  let root := args.getD 0 "."
  let mut fails : Nat := 0

  if !honestAllAccepted then fails := fails + 1; IO.eprintln "product honest"
  if !mutationsAllRejected then fails := fails + 1; IO.eprintln "product mut"
  let (sd, wd) := honestDeposit
  let (st, wt) := honestTransfer
  let (sw, ww) := honestWithdrawal
  let prodSteps : List Step := [
    Step.productAir sd wd, Step.productAir st wt, Step.productAir sw ww
  ]
  if !(verify {
    steps := prodSteps, accept := true, label := "product-e2e",
    eligibility := "product", blowup := BLOWUP, queries := QUERIES,
    grindBits := GRIND_BITS, fold := FOLD
  }).isOk then fails := fails + 1; IO.eprintln "productAir bundle"

  if (verify {
    steps := [Step.params 8 8 24 8], accept := false, label := "bad",
    eligibility := "product", blowup := 8, queries := 8, grindBits := 24, fold := 8
  }).isOk then fails := fails + 1; IO.eprintln "params fail-closed"

  let layoutPath := System.FilePath.mk (root ++ "/vectors/layout/prod_public.simple")
  let composePath := System.FilePath.mk (root ++ "/vectors/layout/prod_compose.simple")
  if !(← layoutPath.pathExists) then fails := fails + 1; IO.eprintln "no layout"
  if !(← composePath.pathExists) then fails := fails + 1; IO.eprintln "no compose"

  if (← layoutPath.pathExists) && (← composePath.pathExists) then
    -- Pin: domain oT/zg + KAT expect only (not H columns for accept)
    let layoutTxt ← IO.FS.readFile layoutPath
    let mut oT : Nat := 0
    let mut katX : Nat := 0; let mut katExp : Nat := 0
    let mut zg : E := zero
    for line in layoutTxt.splitOn "\n" do
      if line.isEmpty then continue
      let p := line.splitOn "|"
      let tag := p.headD ""
      if tag == "META" then oT := p[3]!.toNat!
      else if tag == "Z" then zg := ⟨p[3]!.toNat!, p[4]!.toNat!⟩
      else if tag == "KAT_BASE" && katX == 0 then
        katX := p[3]!.toNat!
        katExp := (parseNatList (p.getD 4 "")).getD 0 0

    -- SOLE H source for accept
    let m := buildLayout 2
    let layout : HLayout := prodHLayout oT
    let T := m.T
    IO.println s!"H_source=Lean CtLayout.prodHLayout T={T}"

    -- Public LDE smoke on Lean-derived is_full
    let got := evalAtBase layout.is_full oT katX
    if got % P != katExp % P then
      fails := fails + 1
      IO.eprintln s!"public LDE recompute fail got={got} exp={katExp}"
    else IO.println "full_math public_lde_recompute ok (Lean H)"

    -- Proof openings from compose file only
    let txt ← IO.FS.readFile composePath
    let mut cLast : Nat := 0
    let mut cZ : E := zero; let mut cExpect : E := zero
    let mut expRw : E := zero; let mut expZh : E := zero
    let mut cCur : List (String × E) := []; let mut cNxt : List (String × E) := []
    let mut cAT : List E := []; let mut cAB : List E := []
    let mut cBnd : List Boundary := []
    let mut cHd : List Nat := []
    let mut cMext : Array (List Nat) := Array.replicate 12 []
    let mut cMinv : Array (List Nat) := Array.replicate 12 []
    let mut cDiag : List Nat := []; let mut cHeld : List String := []
    for line in txt.splitOn "\n" do
      if line.isEmpty then continue
      let p := line.splitOn "|"
      let tag := p.headD ""
      if tag == "META" then cLast := p[2]!.toNat!
      else if tag == "Z" then cZ := ⟨p[1]!.toNat!, p[2]!.toNat!⟩
      else if tag == "COMPZ" then cExpect := ⟨p[1]!.toNat!, p[2]!.toNat!⟩
      else if tag == "RWZG" then expRw := ⟨p[1]!.toNat!, p[2]!.toNat!⟩
      else if tag == "ZHINV" then expZh := ⟨p[1]!.toNat!, p[2]!.toNat!⟩
      else if tag == "PCZ" then cCur := (p[1]!, ⟨p[2]!.toNat!, p[3]!.toNat!⟩) :: cCur
      else if tag == "PCZG" then cNxt := (p[1]!, ⟨p[2]!.toNat!, p[3]!.toNat!⟩) :: cNxt
      else if tag == "ALPHAT" then cAT := cAT ++ [⟨p[1]!.toNat!, p[2]!.toNat!⟩]
      else if tag == "ALPHAB" then cAB := cAB ++ [⟨p[1]!.toNat!, p[2]!.toNat!⟩]
      else if tag == "BND" then
        cBnd := cBnd ++ [{
          row := p[2]!.toNat!, kind := parseKind p[1]!, payload := p[3]!.toNat!, held := p.getD 4 ""
        }]
      else if tag == "HD" then cHd := parseNatList (p.getD 1 "")
      else if tag == "MEXT" then
        let i := p[1]!.toNat!
        if i < 12 then cMext := cMext.set! i (parseNatList (p.getD 2 ""))
      else if tag == "MEXTINV" then
        let i := p[1]!.toNat!
        if i < 12 then cMinv := cMinv.set! i (parseNatList (p.getD 2 ""))
      else if tag == "DIAG" then cDiag := parseNatList (p.getD 1 "")
      else if tag == "HELD" then
        cHeld := if (p.getD 1 "").isEmpty then [] else (p[1]!).splitOn ","

    match packFromLayoutWithZg layout T cZ zg cCur cNxt cLast cHd cAT cAB cBnd
        cMext.toList cMinv.toList cDiag (cMinv[0]!) cHeld cExpect with
    | none => fails := fails + 1; IO.eprintln "packFromLayoutWithZg failed"
    | some pack =>
      if !eq pack.wNext expRw then
        fails := fails + 1; IO.eprintln "Lean rw_zg != export RWZG cross-check"
      if !eq pack.zhInv expZh then
        fails := fails + 1; IO.eprintln "Lean zhInv != export ZHINV cross-check"
      if !(verify {
        steps := [Step.composeCheck pack], accept := true, label := "compose-e2e",
        eligibility := "product", blowup := BLOWUP, queries := QUERIES,
        grindBits := GRIND_BITS, fold := FOLD
      }).isOk then fails := fails + 1; IO.eprintln "composeCheck e2e FAIL"
      else IO.println "full_math composeCheck ok (Lean CtLayout H + packFromLayoutWithZg)"

  if !allForgesRejected then fails := fails + 1; IO.eprintln "binding"

  let purePath := System.FilePath.mk (root ++ "/vectors/verify/C-pure-verify.simple")
  if !(← purePath.pathExists) then fails := fails + 1; IO.eprintln "no pure corpus"
  else
    let binCandidates := #[
      System.FilePath.mk (root ++ "/.lake/build/bin/diff_pure_verify"),
      System.FilePath.mk ".lake/build/bin/diff_pure_verify"
    ]
    let mut ran := false
    for bin in binCandidates do
      if (← bin.pathExists) && !ran then
        let out ← IO.Process.output { cmd := bin.toString, args := #[root] }
        ran := true
        if out.exitCode != 0 then
          fails := fails + 1
          IO.eprintln "diff_pure_verify re-run FAIL"
        else
          IO.println "full_math re-ran diff_pure_verify OK"
          if !(out.stdout.splitOn "\n" |>.any (·.contains "layout_deep=")) then
            fails := fails + 1
            IO.eprintln "pure output missing layout_deep"
    if !ran then fails := fails + 1; IO.eprintln "diff_pure_verify binary missing"

  IO.println s!"full_math_fails={fails}"
  if fails == 0 then
    IO.println "DIFF_FULL_MATH_OK"
    IO.println "H_source=Lean CtLayout; accept=productAir+composeCheck+publicLde+pure(layoutDeep)"
    pure 0
  else
    IO.println "DIFF_FULL_MATH_FAIL"
    pure 1
