/-
  Meta.Headlines — the declared HEADLINE theorems: the roots from which "load-bearing" is computed.
  A declaration is load-bearing iff it is in the transitive proof-term closure of one of these.
  This is the single human input to the necessity analyzer (Meta.Necessity) and the intent spec:
  everything NOT reachable from here is REFERENCE (kept on purpose, banner'd) or dead.
  Keep in sync with `tools/opt-ci/verify.sh`'s `#print axioms` list.
-/
import Lean

namespace LeanBCH.Meta
open Lean

/-- The theorems the project PROMISES. Any name not found in the env is reported (not fatal). -/
def headlines : List Name :=
  [ -- consensus VM self-hardening + cost certificate
    `LeanBCH.VM.runExt_WF_final,
    `LeanBCH.VM.runScript_fuel_suffices_final,
    `LeanBCH.VM.verifyInput_cost_within_budget,
    -- optimizer: scheduler refinement + whole-program + movement floor + INVOKE/CSE
    `LeanBCH.Opt.schedule_refines,
    `LeanBCH.Opt.schedule_refines_move_cond,   -- promoted: the MOVE-based arrange (justifies MoveArrange/NoNullHome)
    `LeanBCH.Opt.whole_program_end_to_end,
    `LeanBCH.Opt.NlcsFloor.movement_lower_bound_nlcs,
    `LeanBCH.Opt.Providers.invoke_const_provider,
    `LeanBCH.Opt.InvokeCSE.invoke_cse,
    -- generated fold table: one sample per proof shape (a rename/removal fails the gate)
    `LeanBCH.Opt.FoldTable.u_DUP_SWAP__DUP,
    `LeanBCH.Opt.FoldTable.u_2PICK_NIP__DROP_OVER,
    `LeanBCH.Opt.FoldTable.c_4PICK_TWODROP__DROP_k5,
    `LeanBCH.Opt.FoldTable.c_TWODUP_TWODROP__EMPTY_k2,
    -- hand-written peephole catalog (the 17+2 folds FoldTable EXCLUDES to avoid duplication; the
    -- recompiler's peephole actually fires these). Sampled so a silent break is caught by the gate.
    `LeanBCH.Opt.over_over,
    `LeanBCH.Opt.roll2_rot,
    -- decompile faithfulness
    `LeanBCH.Opt.bridge_block,
    `LeanBCH.Opt.decompile_end_to_end,
    -- C1 real-VM optimizer bridge capstones (the actual deliverables)
    `LeanBCH.Opt.emit_ops_typed,
    `LeanBCH.Opt.PushButton.push_button_arith,
    `LeanBCH.Opt.PushButtonFull.push_button,
    `LeanBCH.Opt.PushButtonBytes.push_button_arith_bytes,
    `LeanBCH.Opt.OriginalBytes.push_button_arith_bytes_symmetric,
    -- OP-COST FLOOR-PROVER (Opt/OpCostFloor_SCOPE.md): machine-checked LOWER BOUNDS turning "this op
    -- is at-floor" into a kernel theorem. Piece A: per-OP_MUL op-cost floor (general + BN254 k=32).
    `LeanBCH.Opt.OpMulFloor.opMul_opCost_ge,
    `LeanBCH.Opt.OpMulFloor.opMul_bn254_opCost_ge,
    -- Piece B: Fp2 = F[i]/(i²+1) multiplication has tensor rank EXACTLY 3 (essential-mult count floor).
    `LeanBCH.Opt.BilinearRank.CRing.fp2_rank_ge_three,
    `LeanBCH.Opt.BilinearRank.int_fp2_min_mults,
    -- Piece C: compose A×B into the Fp2 op-cost floor (general + concrete BN254: ≥3372 op / ≥3072 arith).
    `LeanBCH.Opt.Fp12OpCostFloor.fp2_opCost_floor,
    `LeanBCH.Opt.Fp12OpCostFloor.fp2_opCost_floor_bn254,
    `LeanBCH.Opt.Fp12OpCostFloor.fp2_arith_floor_bn254,
    -- TOWER extension of the op-cost floor-prover: the three per-level tensor ranks of the BN254 2-3-2
    -- tower, composed into the fp12Mul essential-Fp-mult + op-cost floor (de Groote rank(deg-n ext) = 2n−1).
    -- Target A: Fp12 = Fp6[w]/(w²−v) degree-2 rank ≥ 3 over Fp6 (+ exact-3 non-vacuity over Int, d=2).
    `LeanBCH.Opt.DegreeExtRank.fp12_over_fp6_rank_ge_three,
    `LeanBCH.Opt.DegreeExtRank.int_degExt_two_min_mults,
    -- Target B: Fp6 = Fp2[v]/(v³−ξ) degree-3 rank ≥ 5 over Fp2 (the crux; + unconditional over 𝔽₇).
    `LeanBCH.Opt.Fp6Rank.fp6_rank_ge_five,
    `LeanBCH.Opt.Fp6Rank.f7_fp6_rank_ge_five,
    -- Target C: the parametric tower-model composition — #essential-Fp-mults ≥ r12·r6·r2.
    `LeanBCH.Opt.TowerRankCompose.fp12_leaves_ge,
    -- Composed at the proven ranks (3,5,3): fp12Mul ≥ 45 essential Fp-mults / ≥ 50580 op-cost (k=32),
    -- grounded unconditionally in a concrete BN254 tower (gFp12) via the actual per-level rank theorems.
    `LeanBCH.Opt.Fp12TowerFloor.fp12Mul_fp_mult_floor,
    `LeanBCH.Opt.Fp12TowerFloor.fp12Mul_opCost_floor,
    `LeanBCH.Opt.Fp12TowerFloor.gFp12_opCost_floor,
    -- BLS12-381 instantiation of that same tower floor at k=48: retain both the generic
    -- essential-multiplication/op-cost promises and the fully grounded concrete tower witness.
    `LeanBCH.Opt.Fp12TowerFloorBLS.fp12Mul_bls_fp_mult_floor,
    `LeanBCH.Opt.Fp12TowerFloorBLS.fp12Mul_bls_opCost_floor,
    `LeanBCH.Opt.Fp12TowerFloorBLS.gFp12Bls_opCost_floor,
    -- value-producing movement floor: #movement-ops ≥ n − LCS(entry,exit) for a body that COMPUTES.
    `LeanBCH.Opt.MovementFloorDag.movement_lower_bound_dag ]

end LeanBCH.Meta
