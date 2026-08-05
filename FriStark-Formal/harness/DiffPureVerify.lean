/-
  Pure Lean FullVerify gate: DEEP via QAt.eval (no deep_q_terms).
  Also binds ProductV1 AIR for product eligibility KATs.
-/
import FriStark.Full.Verify
import FriStark.Field.Ext
import FriStark.Deep.QAt
import FriStark.Deep.Replay
import FriStark.Domain.SelRebuild
import FriStark.Domain.PublicEval
import FriStark.Domain.ComposeFromLayout
import FriStark.AIR.CtLayout
import FriStark.AIR.ComposeExt
import FriStark.Hash.Sha256
import FriStark.Params.V1
import FriStark.Binding.Forges
import FriStark.AIR.ProductV1

open FriStark.Full.Verify
open FriStark.Field.Ext
open FriStark.Deep.QAt
open FriStark.Deep.Replay
open FriStark.Domain.SelRebuild
open FriStark.Domain.PublicEval
open FriStark.Domain.ComposeFromLayout
open FriStark.AIR.CtLayout
open FriStark.AIR.ComposeExt
open FriStark.Hash.Sha256
open FriStark.Params.V1
open FriStark.Binding.Forges
open FriStark.AIR.ProductV1

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

def parsePath (s : String) : List (List UInt8 × Nat) := Id.run do
  if s.isEmpty then return []
  let mut out : List (List UInt8 × Nat) := []
  for part in s.splitOn "," do
    let kv := part.splitOn ":"
    if kv.length ≥ 2 then out := out ++ [(hexToBytes kv[0]!, kv[1]!.toNat!)]
  pure out

def parseNatList (s : String) : List Nat :=
  if s.isEmpty then [] else (s.splitOn ",").map String.toNat!

def parseExtList (s : String) : List E :=
  if s.isEmpty then []
  else
    (s.splitOn ";").map fun pair =>
      let ab := pair.splitOn ","
      ⟨ab[0]!.toNat!, ab[1]!.toNat!⟩

def parseFList (s : String) : List Nat := parseNatList s

structure Stats where
  honestOk : Nat := 0
  honestN : Nat := 0
  forgeRej : Nat := 0
  forgeN : Nat := 0
  leanAccForge : Nat := 0
  agree : Nat := 0
  total : Nat := 0
  fsSteps : Nat := 0
  pureQAt : Nat := 0
  cosetFolds : Nat := 0
  layoutDeep : Nat := 0
  composeChecks : Nat := 0
  deriving Repr

def main (args : List String) : IO UInt32 := do
  let root := args.getD 0 "."
  let path := System.FilePath.mk (root ++ "/vectors/verify/C-pure-verify.simple")
  if !(← path.pathExists) then
    IO.eprintln s!"missing {path}"; return 2
  let content ← IO.FS.readFile path
  if content.splitOn "\n" |>.any (· == "NATEQ|0|1") then
    IO.eprintln "SYNTHETIC_REJECT NATEQ|0|1"; return 3
  if content.splitOn "\n" |>.any (fun ln => ln.startsWith "DEEPQ_TERM" || ln.startsWith "DEEPQ_BEGIN|") then
    -- DEEPQ_BEGIN without AT is old term path; pure uses DEEPQAT_BEGIN
    if content.splitOn "\n" |>.any (·.startsWith "DEEPQ_TERM") then
      IO.eprintln "deep_q_terms theater present"; return 4

  -- Product AIR bind on pure verify path (not KAT-only side exe)
  let mut airFails : Nat := 0
  if !honestAllAccepted then
    IO.eprintln "product AIR honest reject on pure path"; airFails := airFails + 1
  if !mutationsAllRejected then
    IO.eprintln "product AIR mutation false accept on pure path"; airFails := airFails + 1
  -- Run as Full.Verify productAir steps
  let (sd, wd) := honestDeposit
  let (st, wt) := honestTransfer
  let (sw, ww) := honestWithdrawal
  let airSteps : List Step := [
    Step.productAir sd wd,
    Step.productAir st wt,
    Step.productAir sw ww
  ]
  let airBundle : Bundle := {
    steps := airSteps, accept := true, label := "product-air-bind",
    eligibility := "product", blowup := BLOWUP, queries := QUERIES,
    grindBits := GRIND_BITS, fold := FOLD
  }
  if !(verify airBundle).isOk then
    IO.eprintln "productAir steps failed in Full.Verify"; airFails := airFails + 1
  -- mutant must fail productAir step
  for m in allMutations do
    let mb : Bundle := {
      steps := [Step.productAir m.stmt m.wit], accept := false, label := m.name,
      eligibility := "product", blowup := BLOWUP, queries := QUERIES,
      grindBits := GRIND_BITS, fold := FOLD
    }
    if (verify mb).isOk then
      IO.eprintln s!"productAir mutant accepted: {m.name}"; airFails := airFails + 1


  -- Domain params from pin META (public); H columns from Lean CtLayout only
  let layoutPath := System.FilePath.mk (root ++ "/vectors/layout/prod_public.simple")
  if !(← layoutPath.pathExists) then
    IO.eprintln "missing prod_public.simple (domain params / cross-check)"; return 5
  let layoutTxt ← IO.FS.readFile layoutPath
  let mut oT : Nat := 0; let mut Tpin : Nat := 0
  for line in layoutTxt.splitOn "
" do
    let p := line.splitOn "|"
    if p.headD "" == "META" then
      Tpin := p[1]!.toNat!; oT := p[3]!.toNat!
  let layout : HLayout := prodHLayout oT
  let T := (buildLayout 2).T
  if layout.is_full.length != T then
    IO.eprintln s!"derived layout incomplete T={T} hFull={layout.is_full.length}"; return 6
  if T != Tpin then
    IO.eprintln s!"derived T={T} != pin T={Tpin}"; return 6


  -- Compose pack: public OOD from H-layout (not export PUB/RWZG/ZHINV)
  let composePath := System.FilePath.mk (root ++ "/vectors/layout/prod_compose.simple")
  if !(← composePath.pathExists) then
    IO.eprintln "missing prod_compose.simple"; return 7
  let composeTxt ← IO.FS.readFile composePath
  let mut cLast : Nat := 0
  let mut cZ : E := zero; let mut cZg : E := zero; let mut cExpect : E := zero
  let mut cCur : List (String × E) := []; let mut cNxt : List (String × E) := []
  let mut cAT : List E := []; let mut cAB : List E := []
  let mut cBnd : List Boundary := []
  let mut cHd : List Nat := []
  let mut cMext : Array (List Nat) := Array.replicate 12 []
  let mut cMinv : Array (List Nat) := Array.replicate 12 []
  let mut cDiag : List Nat := []; let mut cHeld : List String := []
  for line in composeTxt.splitOn "\n" do
    if line.isEmpty then continue
    let p := line.splitOn "|"
    let tag := p.headD ""
    if tag == "META" then cLast := p[2]!.toNat!
    else if tag == "Z" then cZ := ⟨p[1]!.toNat!, p[2]!.toNat!⟩
    else if tag == "COMPZ" then cExpect := ⟨p[1]!.toNat!, p[2]!.toNat!⟩
    else if tag == "PCZ" then cCur := (p[1]!, ⟨p[2]!.toNat!, p[3]!.toNat!⟩) :: cCur
    else if tag == "PCZG" then cNxt := (p[1]!, ⟨p[2]!.toNat!, p[3]!.toNat!⟩) :: cNxt
    else if tag == "ALPHAT" then cAT := cAT ++ [⟨p[1]!.toNat!, p[2]!.toNat!⟩]
    else if tag == "ALPHAB" then cAB := cAB ++ [⟨p[1]!.toNat!, p[2]!.toNat!⟩]
    else if tag == "BND" then
      let k := match p[1]! with
        | "root" => BndKind.root | "nf" => BndKind.nf | "cm" => BndKind.cm
        | "link" => BndKind.link | "cmbind" => BndKind.cmbind | _ => BndKind.cons
      cBnd := cBnd ++ [{ row := p[2]!.toNat!, kind := k, payload := p[3]!.toNat!, held := p.getD 4 "" }]
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
  -- zg from layout Z line
  for line in layoutTxt.splitOn "\n" do
    let p := line.splitOn "|"
    if p.headD "" == "Z" then cZg := ⟨p[3]!.toNat!, p[4]!.toNat!⟩
  let composePack? := packFromLayoutWithZg layout T cZ cZg cCur cNxt cLast cHd cAT cAB cBnd
    cMext.toList cMinv.toList cDiag (cMinv[0]!) cHeld cExpect
  let composePack ← match composePack? with
    | none => do IO.eprintln "packFromLayoutWithZg failed"; return 8
    | some pk => pure pk
  -- Composition forge must reject
  let forgePack := { composePack with expectCompZ := ⟨(composePack.expectCompZ.a0 + 1) % P, composePack.expectCompZ.a1⟩ }
  if (verify {
    steps := [Step.composeCheck forgePack], accept := false, label := "compose-forge",
    eligibility := "product", blowup := BLOWUP, queries := QUERIES,
    grindBits := GRIND_BITS, fold := FOLD
  }).isOk then
    IO.eprintln "compose forge false accept"; return 9



  let mut st : Stats := {}
  let mut curLabel := ""
  let mut curAccept := false
  let mut curElig := "product"
  let mut curB := BLOWUP
  let mut curQ := QUERIES
  let mut curG := GRIND_BITS
  let mut curF := FOLD
  let mut steps : List Step := []
  -- DEEPQAT assembly
  let mut qatX : Nat := 0
  let mut qatZ : E := zero
  let mut qatZg : E := zero
  let mut qatComp : E := zero
  let mut qatRw : E := zero
  let mut qatCc : E := zero
  let mut qatExpect : E := zero
  let mut qatCk : List Nat := []
  let mut qatPcz : List E := []
  let mut qatPczg : List E := []
  let mut qatAlpha : List E := []
  let mut qatSel : SelAtK := {
    is_full := 0, is_partial := 0, is_block_start := 0, is_reabsorb := 0,
    is_range := 0, is_range_first := 0, is_range_step := 0, is_range_last := 0,
    rc := [], chain_minv := [], range_weight := 0
  }
  let mut qatMask : SelMaskZ := {
    is_full := zero, is_partial := zero, is_block_start := zero, is_reabsorb := zero,
    is_range := zero, is_range_first := zero, is_range_step := zero, is_range_last := zero,
    rc := [], chain_minv := []
  }
  -- cosetFold assembly
  let mut cfBase : Nat := 0
  let mut cfLi0 : Nat := 0
  let mut cfS : Nat := 0
  let mut cfOff : Nat := 0
  let mut cfON : Nat := 0
  let mut cfN : Nat := 0
  let mut cfExpect : E := zero
  let mut cfCoset : List E := []
  let mut cfBetas : List E := []
  let bindingOk := allForgesRejected
  for line in content.splitOn "\n" do
    if line.isEmpty then continue
    let p := line.splitOn "|"
    let tag := p.headD ""
    if tag == "BUNDLE" then
      curLabel := p[1]!; curAccept := p[2]! == "1"; curElig := p[3]!
      curB := p[4]!.toNat!; curQ := p[5]!.toNat!; curG := p[6]!.toNat!; curF := p[7]!.toNat!
      steps := []
    else if tag == "PARAMS" then
      steps := steps ++ [Step.params p[1]!.toNat! p[2]!.toNat! p[3]!.toNat! p[4]!.toNat!]
    else if tag == "FSABSORB" then
      steps := steps ++ [Step.fsAbsorb (hexToBytes p[1]!) (hexToBytes p[2]!) (hexToBytes p[3]!)]
      st := { st with fsSteps := st.fsSteps + 1 }
    else if tag == "FSABSORBINT" then
      steps := steps ++ [Step.fsAbsorbInt (hexToBytes p[1]!) p[2]!.toNat! (hexToBytes p[3]!)]
      st := { st with fsSteps := st.fsSteps + 1 }
    else if tag == "FSEXTCHAL" then
      steps := steps ++ [Step.fsExtChallenge (hexToBytes p[1]!) p[2]!.toNat! p[3]!.toNat! (hexToBytes p[4]!)]
      st := { st with fsSteps := st.fsSteps + 1 }
    else if tag == "FSIDX" then
      steps := steps ++ [Step.fsChallengeIdx (hexToBytes p[1]!) p[2]!.toNat! p[3]!.toNat! (hexToBytes p[4]!)]
      st := { st with fsSteps := st.fsSteps + 1 }
    else if tag == "GRINDCHECK" then
      steps := steps ++ [Step.grindCheck (hexToBytes p[1]!) (hexToBytes p[2]!) p[3]!.toNat!]
    else if tag == "NATLISTEQ" then
      steps := steps ++ [Step.natListEq (parseNatList p[1]!) (parseNatList p[2]!)]
    else if tag == "NATEQ" then
      steps := steps ++ [Step.natEq p[1]!.toNat! p[2]!.toNat!]
    else if tag == "BYTESEQ" then
      steps := steps ++ [Step.bytesEq (hexToBytes p[1]!) (hexToBytes p[2]!)]
    else if tag == "MERKLE" then
      steps := steps ++ [Step.merkleDigest (hexToBytes p[1]!) (hexToBytes p[2]!) (parsePath (p.getD 3 ""))]
    else if tag == "FRIFOLD" then
      steps := steps ++ [Step.friFold ⟨p[1]!.toNat!,p[2]!.toNat!⟩ ⟨p[3]!.toNat!,p[4]!.toNat!⟩ ⟨p[5]!.toNat!,p[6]!.toNat!⟩ ⟨p[7]!.toNat!,p[8]!.toNat!⟩ p[9]!.toNat!]
    else if tag == "EXTEQ" then
      steps := steps ++ [Step.extEq ⟨p[1]!.toNat!,p[2]!.toNat!⟩ ⟨p[3]!.toNat!,p[4]!.toNat!⟩]
    else if tag == "DEEPZ" then
      steps := steps ++ [Step.deepZ ⟨p[1]!.toNat!,p[2]!.toNat!⟩ ⟨p[3]!.toNat!,p[4]!.toNat!⟩ ⟨p[5]!.toNat!,p[6]!.toNat!⟩ p[7]!.toNat!]
    else if tag == "DEEPQAT_BEGIN" then
      qatX := p[1]!.toNat!
      qatZ := ⟨p[2]!.toNat!, p[3]!.toNat!⟩
      qatZg := ⟨p[4]!.toNat!, p[5]!.toNat!⟩
      qatComp := ⟨p[6]!.toNat!, p[7]!.toNat!⟩
      qatRw := ⟨p[8]!.toNat!, p[9]!.toNat!⟩
      qatCc := ⟨p[10]!.toNat!, p[11]!.toNat!⟩
      qatExpect := ⟨p[12]!.toNat!, p[13]!.toNat!⟩
    else if tag == "DEEPQAT_CK" then
      qatCk := parseFList (p.getD 1 "")
    else if tag == "DEEPQAT_PCZ" then
      qatPcz := parseExtList (p.getD 1 "")
    else if tag == "DEEPQAT_PCZG" then
      qatPczg := parseExtList (p.getD 1 "")
    else if tag == "DEEPQAT_ALPHA" then
      qatAlpha := parseExtList (p.getD 1 "")
    else if tag == "DEEPQAT_SEL" || tag == "DEEPQAT_SELMASK" then
      pure ()  -- IGNORED: accept kernel rebuilds via SelRebuild from H-layout
    else if tag == "DEEPQAT_END" then
      -- ACCEPT KERNEL: rebuild sel/selMask/rw_zg from H-layout (not DEEPQAT_SEL export tables)
      let core : DeepQAtCore := {
        x := qatX, z := qatZ, zg := qatZg, proofCompZ := qatComp,
        cc := qatCc, ck := qatCk, Pcz := qatPcz, Pczg := qatPczg,
        deep_alphas := qatAlpha, expectFri0 := qatExpect
      }
      steps := steps ++ [Step.deepQAtLayout layout core]
      st := { st with pureQAt := st.pureQAt + 1, layoutDeep := st.layoutDeep + 1 }
    else if tag == "COSETFOLD_BEGIN" then
      -- base|li0|s|off|oN|N|e0|e1|n_coset|n_betas
      cfBase := p[1]!.toNat!; cfLi0 := p[2]!.toNat!; cfS := p[3]!.toNat!
      cfOff := p[4]!.toNat!; cfON := p[5]!.toNat!; cfN := p[6]!.toNat!
      cfExpect := ⟨p[7]!.toNat!, p[8]!.toNat!⟩
      cfCoset := []; cfBetas := []
    else if tag == "COSETFOLD_C" then
      cfCoset := parseExtList (p.getD 1 "")
    else if tag == "COSETFOLD_B" then
      cfBetas := parseExtList (p.getD 1 "")
    else if tag == "COSETFOLD_END" then
      steps := steps ++ [
        Step.cosetFold cfCoset cfBetas cfBase cfLi0 cfS cfOff cfON cfN cfExpect
      ]
      st := { st with cosetFolds := st.cosetFolds + 1 }
    else if tag == "PRODUCT_AIR_BIND" then
      pure ()  -- handled above
    else if tag == "END" then
      -- skip non-bundle markers
      if curLabel != "" then
        -- Honest product bundle includes composeCheck in steps (accept kernel)
        let steps' :=
          if curAccept && curLabel == "honest-prod" then
            Step.composeCheck composePack :: steps
          else steps
        let b : Bundle := {
          steps := steps', accept := curAccept, label := curLabel, eligibility := curElig,
          blowup := curB, queries := curQ, grindBits := curG, fold := curF
        }
        st := { st with total := st.total + 1 }
        let leanOk := (verify b).isOk
        if agrees b then st := { st with agree := st.agree + 1 }
        if curAccept then
          st := { st with honestN := st.honestN + 1 }
          if hasComposeCheck b then st := { st with composeChecks := st.composeChecks + 1 }
          if leanOk then st := { st with honestOk := st.honestOk + 1 }
          else
            let why := match verify b with | .ok => "ok" | .err w => w
            IO.eprintln s!"honest lean reject: {curLabel} why={why}"
        else
          st := { st with forgeN := st.forgeN + 1 }
          if leanOk then
            st := { st with leanAccForge := st.leanAccForge + 1 }
            IO.eprintln s!"forge lean ACCEPT: {curLabel}"
          else st := { st with forgeRej := st.forgeRej + 1 }
        curLabel := ""

  IO.println s!"pure_bundles={st.total} honest={st.honestOk}/{st.honestN} forge_reject={st.forgeRej}/{st.forgeN} lean_acc_forge={st.leanAccForge} agree={st.agree}/{st.total} binding={bindingOk} fs_steps={st.fsSteps} pure_qat={st.pureQAt} layout_deep={st.layoutDeep} coset_folds={st.cosetFolds} compose_in_honest=true product_air_fails={airFails}"
  let ok :=
    st.honestN ≥ 1 && st.honestOk == st.honestN && st.leanAccForge == 0 &&
    st.forgeN ≥ 10 && st.forgeRej == st.forgeN && st.agree == st.total &&
    bindingOk && st.fsSteps ≥ 1 && st.pureQAt ≥ 1 && st.layoutDeep ≥ 1 &&
    st.layoutDeep == st.pureQAt && st.cosetFolds ≥ 1 && st.composeChecks ≥ 1 && airFails == 0
  if ok then IO.println "DIFF_PURE_VERIFY_OK"; pure 0
  else IO.println "DIFF_PURE_VERIFY_FAIL"; pure 1
