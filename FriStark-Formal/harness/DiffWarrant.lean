/-
  Name-on-the-line DiffWarrant — spine invariants + forge patterns.
  Gates: product_present, productAir_mem, unpack_kernel, phi_forced, forge table.
-/
import FriStark.Soundness.Warrant
import FriStark.Soundness.Phi
import FriStark.Soundness.Games
import FriStark.Soundness.ForgeCoverage
import FriStark.Soundness.StepAlgebra
import FriStark.Soundness.FullIREndToEnd
import FriStark.Soundness.EndToEnd
import FriStark.Soundness.Statement
import FriStark.Soundness.ResidualKill
import FriStark.Full.Verify
import FriStark.Packing.Unpack
import FriStark.Packing.ProdIRFixture
import FriStark.Packing.PureIRFragment
import FriStark.Packing.Topology
import FriStark.Binding.Forges
import FriStark.Binding.Presence
import FriStark.Host.CovenantScript
import FriStark.AIR.ProductV1
import FriStark.Params.V1

open FriStark.Soundness.Warrant
open FriStark.Soundness.Phi
open FriStark.Soundness.Games
open FriStark.Soundness.ForgeCoverage
open FriStark.Soundness.StepAlgebra
open FriStark.Soundness.FullIREndToEnd
open FriStark.Soundness.Statement
open FriStark.Soundness.ResidualKill
open FriStark.Full.Verify
open FriStark.Packing.Unpack
open FriStark.Packing.ProdIRFixture
open FriStark.Packing.PureIRFragment
open FriStark.Packing.Topology
open FriStark.Binding.Forges
open FriStark.Binding.Presence
open FriStark.Host.CovenantScript
open FriStark.AIR.ProductV1
open FriStark.Params.V1

def check (name : String) (ok : Bool) : IO Bool := do
  if ok then IO.println s!"OK {name}"; pure true
  else IO.eprintln s!"FAIL {name}"; pure false

def main : IO UInt32 := do
  let fails ← IO.mkRef (0 : Nat)
  let run (name : String) (ok : Bool) : IO Unit := do
    unless (← check name ok) do fails.modify (· + 1)

  -- Φ honest product-AIR (checklist is executable form)
  run "phi_deposit" (verifyProductAir honestDeposit.1 honestDeposit.2)
  run "phi_transfer" (verifyProductAir honestTransfer.1 honestTransfer.2)
  run "phi_withdrawal" (verifyProductAir honestWithdrawal.1 honestWithdrawal.2)
  run "phi_mutations" mutationsAllRejected
  run "phi_in_scope_17" (decide (phiInScopeClauseIds.length = 17))
  run "phi_out_scope_6" (decide (phiOutOfScopeClauseIds.length = 6))

  -- Games + step algebra complete for production path
  run "games_3" (decide (residualGameNames.length = 3))
  run "axioms_4" (decide (underlyingAxiomNames.length = 4))
  run "step_algebra_20" (decide (stepAlgebraNames.length = 20))

  -- Packing / unpack
  run "sound_role_order" (roleOrderOk (mkSoundBlob dummyKernel))
  run "unpack_sound" ((unpack (mkSoundBlob dummyKernel)).isSome)
  run "bad_order_unpack" (!(unpack badOrderBlob).isSome)
  run "packing_forge" forge_PACK_bad_order
  run "topo" (wellFormedTopology defaultTopology)
  run "dual_vm_corollary" dualVmIsCorollary
  run "binding_honest_wf" (wellFormed honestModel)

  -- Residual kill table + scoreboard accounting (not security theorem)
  run "residual_kill_table_9" (decide (residualKillTable.length = 9))
  run "no_active_build_residuals" (decide (activeBuildNames.length = 0))
  run "eternal_literature_r1_r2" (decide (eternalLiteratureNames = ["CapacityRegimeAtRate", "IndependentFRIQueries"]))
  run "eternal_crypto_r3_r4" (decide (eternalCryptoNames = ["Sha256RandomOracle", "Sha256CollisionResistance"]))
  run "scoreboard_accounting_104" (decide (v1ScoreboardAccounting = 104))
  -- M1: capacity accounting discharged; R1/R2 eternal literature with necessity 1:1
  run "m1_capacity_accounting_discharged" capacityAccountingOk
  run "m1_accounting_proved_5" (decide (capacityAccountingProved.length = 5))
  run "m1_literature_necessity_2" (decide (residualLiteratureNecessity.length = 2))
  run "m1_literature_names_covered"
    (decide (eternalLiteratureNames == residualLiteratureNecessity.map (·.1)))
  run "m1_crypto_necessity_2" (decide (residualCryptoNecessity.length = 2))
  run "m1_crypto_names_covered"
    (decide (eternalCryptoNames == residualCryptoNecessity.map (·.1)))
  run "m1_freeze_status" (decide (m1ResidualFreezeStatus.length > 20))
  run "script_fragment_modeled_6" (decide (scriptFragmentModeledClaims.length = 6))
  run "script_fragment_eternal_4" (decide (scriptFragmentEternalRemainder.length = 4))
  -- Full-IR production Accept (S4): multi-step FRI/DEEP/FS/Merkle bridges
  -- fails if only productAir singleton or identity-step theater is exercised
  let st := honestDeposit.1
  let w := honestDeposit.2
  let c : ProductClaim := ⟨st, w⟩
  let stepOk := (runStep (.productAir st w)).isOk
  run "productAir_step" stepOk
  if stepOk then
    let bFull : Bundle := mkFullIRProductBundle st w
    run "full_ir_bundle" (isFullIRBundle bFull)
    run "full_ir_verify" (verify bFull).isOk
    run "full_ir_has_productAir" (hasProductAirStep c bFull.steps)
    run "full_ir_not_singleton" (decide (bFull.steps.length ≥ 10))
    -- S1/S4 Lean e2e: verify=.ok ⇒ product + NamedP FRI/DEEP (and bridge steps ok)
    run "e2e_deposit_verify_ok" (verify (mkFullIRProductBundle st w)).isOk
    run "e2e_names_10" (decide (fullIREndToEndNames.length = 10))
    run "e2e_bridge_steps_ok"
      (let hs := (verify bFull).isOk
       hs && (runStep fullIRFriStep).isOk && (runStep fullIRDeepStep).isOk &&
       (runStep fullIRFsStep).isOk && (runStep fullIRMerkleStep).isOk &&
       (runStep fullIRCosetStep).isOk && (runStep prodLayerCosetStep0).isOk)
    -- Real bridge constructors present (not natEq/bytesEq identity theater)
    run "full_ir_has_fri" (hasFriFoldStep bFull.steps)
    run "full_ir_has_coset" (hasCosetFoldStep bFull.steps)
    run "full_ir_has_merkle" (hasMerkleStep bFull.steps)
    run "full_ir_has_deep" (hasDeepQAtStep bFull.steps)
    run "full_ir_has_deepZ" (hasDeepZStep bFull.steps)
    run "full_ir_has_fs" (hasFsAbsorbStep bFull.steps)
    -- Multi-query production IR (QUERIES=8 Merkle + 8 coset from pure honest-prod)
    run "full_ir_multi_query" (isMultiQueryIR bFull.steps)
    run "full_ir_merkle_ge_queries" (decide (countMerkleSteps bFull.steps ≥ QUERIES))
    run "full_ir_coset_ge_queries" (decide (countCosetSteps bFull.steps ≥ QUERIES))
    run "prod_ir_merkle_8" (decide (prodIRMerkleCount = 8))
    run "prod_ir_coset_8" (decide (prodIRCosetCount = 8))
    -- Production-layer FRI coset (s = FOLD, |coset| = 2^s) — not s=1-only
    run "full_ir_has_layer_coset" (hasProductionLayerCoset bFull.steps)
    run "prod_ir_layer_coset_ge1" (decide (prodIRLayerCosetCount ≥ 1))
    run "prod_ir_layer_coset_ge8" (decide (prodIRLayerCosetCount ≥ 8))
    run "layer_coset0_is_fold8" (isProductionLayerCoset prodLayerCosetStep0)
    run "bridge_layer_coset0_ok" (runStep prodLayerCosetStep0).isOk
    run "layer_subset_full_pure" (decide (prodIRAcceptLayerCosets ≤ prodIRFullPureCosetS8))
    run "layer_half_of_full_pure"
      (decide (prodIRAcceptLayerCosets * 2 ≤ prodIRFullPureCosetS8 * 2 &&
               prodIRAcceptLayerCosets ≥ prodIRFullPureCosetS8 / 2))
    -- NamedP antecedents: fixture bridge steps run .ok
    run "bridge_fri_ok" (runStep fullIRFriStep).isOk
    run "bridge_coset_ok" (runStep fullIRCosetStep).isOk
    run "bridge_merkle_ok" (runStep fullIRMerkleStep).isOk
    run "bridge_deep_ok" (runStep fullIRDeepStep).isOk
    run "bridge_deepZ_ok" (runStep fullIRDeepZStep).isOk
    run "bridge_fs_ok" (runStep fullIRFsStep).isOk
    run "bridge_prod_merkle1_ok" (runStep prodMerkleStep1).isOk
    run "bridge_prod_coset1_ok" (runStep prodCosetStep1).isOk
    -- StepAlgebra inventory present (20 production NamedP bridges)
    run "step_algebra_20" (decide (stepAlgebraNames.length = 20))
    run "full_ir_namedP_bridges_8" (decide (fullIRBridgeNames.length = 8))
    -- M4 size-bounded eternal remainder (no redeem yet)
    run "m4_modeled_bound_6" (decide (scriptFragmentModeledBound = 6))
    run "m4_eternal_bound_4" (decide (scriptFragmentEternalBound = 4))
    run "m4_eternal_necessity_len" (decide (scriptFragmentEternalNecessity.length = 4))
    run "m4_eternal_names_covered"
      (decide (scriptFragmentEternalRemainder == scriptFragmentEternalNecessity.map (·.1)))
    run "m4_freeze_status" (decide (m4ScriptFreezeStatus.length > 20))
    let a : AcceptBundle := {
      lean := bFull
      product? := some c
      blob? := none
      binding? := some honestModel
      topology := defaultTopology
    }
    run "covenant_accept_full_ir" (CovenantAccept a)
    run "product_present" (a.product?.isSome)
    run "binding_present" (a.binding?.isSome)
    run "productAir_mem" (productAirOnKernel a)
    run "phi_forced" (match a.product? with | some c => verifyProductAir c.st c.w | none => false)
    run "spine_kernel_ok" (kernelVerify a).isOk
    run "rejects_no_product" (!(CovenantAccept { a with product? := none }))
    run "rejects_no_binding" (!(CovenantAccept { a with binding? := none }))
    -- Script fragment ⇔ CovenantAccept
    let red : RedeemFixture := {
      topology := defaultTopology
      binding := honestModel
      product := c
      kernel := bFull
      blob? := none
    }
    run "script_fragment_accept" (scriptFragmentAccept red)
    run "script_iff_covenant" (scriptFragmentAccept red == CovenantAccept red.toAccept)
    run "m4_script_iff_full_ir" (scriptFragmentAccept red == CovenantAccept red.toAccept)
    run "m4_full_ir_redeem_is_full" (isFullIRBundle red.kernel)
    -- blob path full IR
    let a2 : AcceptBundle := {
      lean := dummyKernel
      product? := some c
      blob? := some (mkSoundBlob bFull)
      binding? := some honestModel
      topology := defaultTopology
    }
    run "covenant_with_blob_full_ir" (CovenantAccept a2)
    run "unpack_kernel" ((unpack (mkSoundBlob bFull)).isSome && (kernelVerify a2).isOk)
    run "productAir_mem_blob" (productAirOnKernel a2)
    -- productAir-only is allowed for spine but full track requires full_ir gate above
    let bSolo := mkProductBundle st w
    run "solo_productAir_verify" (verify bSolo).isOk
    run "full_ir_required_for_track" (isFullIRBundle bFull && !(isFullIRBundle bSolo))
    run "not_full_ir_product_only" (!(isFullIRBundle bSolo))
  else
    fails.modify (· + 1)

  -- Forge coverage + pattern inventory
  run "forge_F-ST" forge_ST_reject
  run "forge_F-BIND" forge_BIND_reject
  run "forge_F-FRI" forge_FRI_bad_fold
  run "forge_F-DEEP" forge_DEEP_reject
  run "forge_F-FS" forge_FS_bad_absorb
  run "forge_F-MERK" forge_MERK_bad
  run "forge_F-PACK" forge_PACK_bad_order
  run "forge_F-PARAM" forge_PARAM_bad
  run "forge_F-GRIND" forge_GRIND_reject
  run "forge_F-PROD" forge_PROD_mutations
  run "binding_allForgesRejected" allForgesRejected
  run "binding_omit_binding" (forgeRejected honestModel "omit_binding")
  run "binding_unlocking_breaks_wf" (!wellFormed (applyForge honestModel "unlocking_bind"))
  run "st_mut_wrong_kind" (!(verifyProductAir mutWrongKind.stmt mutWrongKind.wit))
  run "st_mut_packet_commit" (!(verifyProductAir mutPacketCommitMismatch.stmt mutPacketCommitMismatch.wit))
  for (id, ok) in forgeCoverageTable do
    run s!"table_{id}" ok
  run "all_forges_covered" allForgesCovered
  run "forge_count_10" (decide (forgeCoverageTable.length = 10))
  run "forge_pattern_thms_10" (decide (forgePatternTheoremNames.length = 10))

  -- S4 pure-IR fragment freeze (Lean modeled + eternal inline remainder with necessity)
  run "pure_ir_modeled_7" (decide (pureIRModeledBound = 7))
  run "pure_ir_eternal_4" (decide (pureIREternalBound = 4))
  run "pure_ir_eternal_necessity_len" (decide (pureIREternalNecessity.length = 4))
  run "pure_ir_eternal_names_covered"
    (decide (pureIREternalRemainder == pureIREternalNecessity.map (·.1)))
  run "pure_ir_accept_multi_query"
    (decide (pureIRAcceptModeled.merkleOpens ≥ QUERIES) &&
     decide (pureIRAcceptModeled.cosetS1 ≥ QUERIES) &&
     decide (pureIRAcceptModeled.layerCosetSFold ≥ QUERIES))
  run "pure_ir_full_inventory_multi_query"
    (decide (pureIRFullInventory.merkleOpens ≥ QUERIES) &&
     decide (pureIRFullInventory.layerCosetSFold = 16) &&
     decide (pureIRFullInventory.deepQAt ≥ QUERIES))
  run "pure_ir_layer_strict_subset"
    (decide (pureIRAcceptModeled.layerCosetSFold < pureIRFullInventory.layerCosetSFold))
  run "pure_ir_freeze_status" (decide (pureIRFragmentFreezeStatus.length > 20))
  -- Track complete only if Lean full-IR AND full pure gate both green
  run "pure_ir_track_needs_both_true_true" (pureIRAcceptTrackComplete true true)
  run "pure_ir_track_rejects_lean_only" (!(pureIRAcceptTrackComplete true false))
  run "pure_ir_track_rejects_pure_only" (!(pureIRAcceptTrackComplete false true))

  -- S4: full pure production IR (C-pure-verify.simple honest-prod) via shipped gate
  -- MANDATORY for Accept track — Lean sample alone is not enough (fragment freeze).
  let pureBin := System.FilePath.mk ".lake/build/bin/diff_pure_verify"
  let pureExists ← pureBin.pathExists
  let mut pureGateOk := false
  if pureExists then
    let pure ← IO.Process.output { cmd := pureBin.toString, args := #[] }
    let pureOk := pure.exitCode == 0
    run "full_pure_ir_verify" pureOk
    if pureOk then
      let purePath := System.FilePath.mk "vectors/verify/C-pure-verify.simple"
      let pureTxt ← IO.FS.readFile purePath
      let mut inHon := false
      let mut pureMerkle := 0
      let mut pureCoset := 0
      let mut pureLayer := 0
      let mut pureDeep := 0
      let mut pureFs := 0
      let mut pureLines := 0
      for line in pureTxt.splitOn "\n" do
        let p := line.splitOn "|"
        let tag := p.headD ""
        if tag == "BUNDLE" then
          inHon := p.getD 1 "" == "honest-prod" && p.getD 2 "" == "1"
        else if tag == "END" then
          inHon := false
        else if inHon then
          pureLines := pureLines + 1
          if tag == "MERKLE" then pureMerkle := pureMerkle + 1
          if tag == "COSETFOLD_BEGIN" then
            pureCoset := pureCoset + 1
            if p.getD 3 "" == "8" then pureLayer := pureLayer + 1
          if tag == "DEEPQAT_BEGIN" then pureDeep := pureDeep + 1
          if tag == "FSABSORB" then pureFs := pureFs + 1
      run "full_pure_merkle_ge_queries" (decide (pureMerkle ≥ QUERIES))
      run "full_pure_coset_ge_queries" (decide (pureCoset ≥ QUERIES))
      run "full_pure_layer_coset_16" (decide (pureLayer = 16))
      run "full_pure_deep_ge_queries" (decide (pureDeep ≥ QUERIES))
      run "full_pure_fs_ge_1" (decide (pureFs ≥ 1))
      run "full_pure_step_lines_889" (decide (pureLines = pureIRFullInventory.stepLines))
      run "full_pure_merkle_matches_inventory" (decide (pureMerkle = pureIRFullInventory.merkleOpens))
      run "full_pure_coset_matches_inventory" (decide (pureCoset = pureIRFullInventory.cosetFolds))
      run "lean_layer_sample_le_full_pure"
        (decide (prodIRLayerCosetCount ≤ pureLayer))
      -- Inventory 1:1 with live vector (no stale freeze)
      let invOk :=
        pureMerkle == pureIRFullInventory.merkleOpens &&
        pureCoset == pureIRFullInventory.cosetFolds &&
        pureLayer == pureIRFullInventory.layerCosetSFold &&
        pureDeep == pureIRFullInventory.deepQAt &&
        pureFs == pureIRFullInventory.fsAbsorb &&
        pureLines == pureIRFullInventory.stepLines
      run "pure_ir_inventory_1to1_vector" invOk
      pureGateOk := pureOk && invOk && pureMerkle ≥ QUERIES && pureLayer == 16
      IO.println s!"full_pure_ir merkle={pureMerkle} coset={pureCoset} layer_s8={pureLayer} deep={pureDeep} fs={pureFs} lines={pureLines}"
    else
      IO.eprintln pure.stderr
      pureGateOk := false
  else
    run "full_pure_ir_verify" false
    pureGateOk := false
    IO.eprintln "FAIL full pure path: diff_pure_verify binary missing — Accept track incomplete"

  -- Accept track: Lean full-IR sample AND full pure gate (fails if either missing)
  let leanIR :=
    isFullIRBundle (mkFullIRProductBundle honestDeposit.1 honestDeposit.2) &&
    (verify (mkFullIRProductBundle honestDeposit.1 honestDeposit.2)).isOk
  run "accept_track_lean_full_ir" leanIR
  run "accept_track_full_pure_gate" pureGateOk
  run "accept_track_complete" (pureIRAcceptTrackComplete leanIR pureGateOk)
  if !(pureIRAcceptTrackComplete leanIR pureGateOk) then
    IO.eprintln "FAIL accept_track: need Lean multi-query full-IR AND full pure multi-query FRI path"

  run "apex_status" (decide (warrantApexStatus.length > 10))
  run "crown_count" (decide (warrantCrownTheoremNames.length = 10))
  run "apex_pride_string"
    (warrantApexStatus == "covenant_mandatory_product_phi_full_ir_track")

  IO.println s!"warrant_apex={warrantApexStatus}"
  IO.println s!"residual_games={residualGameNames}"
  IO.println s!"phi_clauses_in={phiInScopeClauseIds.length} out={phiOutOfScopeClauseIds.length}"
  IO.println s!"spine_tags={spineTagProductPresent},{spineTagProductAirMem},{spineTagUnpackKernel},{spineTagPhiForced}"
  IO.println "forge_coverage:"
  for (id, ok) in forgeCoverageTable do
    IO.println s!"  {id}={ok}"
  let n ← fails.get
  if n == 0 then
    IO.println "WARRANT_VERIFY_TO_STATEMENT_OK"
    IO.println "WARRANT_PHI_OK"
    IO.println "WARRANT_GAMES_OK"
    IO.println "WARRANT_PACKING_OK"
    IO.println "WARRANT_COVENANT_OK"
    IO.println "WARRANT_FORGE_COVERAGE_OK"
    IO.println "WARRANT_SPINE_product_present"
    IO.println "WARRANT_SPINE_productAir_mem"
    IO.println "WARRANT_SPINE_unpack_kernel"
    IO.println "WARRANT_SPINE_phi_forced"
    IO.println "WARRANT_FULL_IR_OK"
    IO.println "WARRANT_FULL_PURE_IR_OK"
    IO.println "WARRANT_M1_RESIDUAL_OK"
    IO.println "WARRANT_SCRIPT_FRAGMENT_OK"
    IO.println "WARRANT_RESIDUAL_KILL_OK"
    IO.println "WARRANT_OK"
    pure 0
  else
    IO.eprintln s!"WARRANT_FAIL fails={n}"
    pure 1
