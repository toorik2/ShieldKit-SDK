/-
  S4 pure-path Accept fragment vs full multi-query production IR remainder.

  Lean Accept (`mkFullIRProductBundle`) carries a multi-query + layer production
  sample with NamedP e2e bridges. The complete pure honest-prod IR
  (vectors/verify/C-pure-verify.simple, 889 step lines, 16 s=FOLD cosets) is
  exercised by the shipped `diff_pure_verify` gate — not fully inlined into the
  Lean Accept constant (compile/size bound).

  This freezes that split as a machine-checked fragment + eternal remainder
  with necessity (same pattern as M4 script fragment), so DiffWarrant cannot
  green on productAir-only / Lean-sample-only without the full pure path.
-/
import FriStark.Packing.ProdIRFixture
import FriStark.Params.V1

namespace FriStark.Packing.PureIRFragment

open FriStark.Packing.ProdIRFixture
open FriStark.Params.V1

/-! ### Modeled Accept fragment (Lean constant path) -/

/-- What the Lean Accept full-IR constant models (counts). -/
structure PureIRAcceptModeled where
  merkleOpens : Nat
  cosetS1 : Nat
  layerCosetSFold : Nat
  fsAbsorbs : Nat
  deepZ : Nat
  friNamedPAnchor : Nat
  deepQAtNamedPAnchor : Nat
  deriving Repr, DecidableEq

def pureIRAcceptModeled : PureIRAcceptModeled where
  merkleOpens := prodIRMerkleCount
  cosetS1 := prodIRCosetCount
  layerCosetSFold := prodIRLayerCosetCount
  fsAbsorbs := prodIRFsCount
  deepZ := 1
  friNamedPAnchor := 1
  deepQAtNamedPAnchor := 1

theorem pureIR_accept_modeled_multi_query :
    pureIRAcceptModeled.merkleOpens ≥ QUERIES ∧
    pureIRAcceptModeled.cosetS1 ≥ QUERIES ∧
    pureIRAcceptModeled.layerCosetSFold ≥ QUERIES := by
  simp only [pureIRAcceptModeled, prodIRMerkleCount, prodIRCosetCount,
    prodIRLayerCosetCount, QUERIES]
  native_decide

/-- Modeled claim names (fragment inventory). -/
def pureIRModeledClaims : List String :=
  [ "lean_accept_merkle_ge_queries"
  , "lean_accept_coset_s1_ge_queries"
  , "lean_accept_layer_coset_s_fold_ge_queries"
  , "lean_accept_fs_absorb_sample"
  , "lean_accept_deepZ_sample"
  , "lean_e2e_verify_implies_fri_deep_namedP"
  , "full_pure_path_gated_by_diff_pure_verify"
  ]

theorem pureIR_modeled_count : pureIRModeledClaims.length = 7 := by native_decide

def pureIRModeledBound : Nat := pureIRModeledClaims.length

/-! ### Full pure production IR (complete multi-query FRI path) -/

/-- Full pure honest-prod inventory (from C-pure-verify.simple). -/
structure PureIRFullInventory where
  stepLines : Nat
  merkleOpens : Nat
  cosetFolds : Nat
  layerCosetSFold : Nat
  deepQAt : Nat
  fsAbsorb : Nat
  deriving Repr, DecidableEq

/--
  Production pure honest-prod counts (Params.V1 2048/8/24/8).
  Must stay 1:1 with vectors/verify/C-pure-verify.simple; DiffWarrant re-counts.
-/
def pureIRFullInventory : PureIRFullInventory where
  stepLines := prodIRFullPureStepLines  -- 889
  merkleOpens := 40
  cosetFolds := 24
  layerCosetSFold := prodIRFullPureCosetS8  -- 16
  deepQAt := 8
  fsAbsorb := 8

theorem pureIR_full_multi_query :
    pureIRFullInventory.merkleOpens ≥ QUERIES ∧
    pureIRFullInventory.cosetFolds ≥ QUERIES ∧
    pureIRFullInventory.layerCosetSFold ≥ QUERIES ∧
    pureIRFullInventory.deepQAt ≥ QUERIES := by
  simp only [pureIRFullInventory, QUERIES, prodIRFullPureCosetS8]
  native_decide

theorem pureIR_full_layer_complete :
    pureIRFullInventory.layerCosetSFold = 16 := by
  simp only [pureIRFullInventory, prodIRFullPureCosetS8]

/-! ### Size remainder: full pure not fully inlined into Lean Accept -/

/--
  Eternal remainder for **Lean inlining** of the full pure IR constant.
  The full path is still required at gate time via `diff_pure_verify`.
-/
def pureIREternalRemainder : List String :=
  [ "full_pure_889_step_lean_inline"
  , "full_pure_layer_coset_remainder_8_of_16"
  , "full_pure_deepQAtLayout_H_rebuild"
  , "full_pure_fs_absorb_int_challenge_stream"
  ]

def pureIREternalBound : Nat := pureIREternalRemainder.length

theorem pureIR_eternal_count : pureIREternalRemainder.length = 4 := by native_decide

/-- Necessity 1:1 with pureIREternalRemainder names. -/
def pureIREternalNecessity : List (String × String) :=
  [ ("full_pure_889_step_lean_inline",
      "Full honest-prod IR is 889 step lines; Lean Accept carries a multi-query+layer sample with NamedP e2e; full path is the diff_pure_verify gate (compile/size bound, not fog).")
  , ("full_pure_layer_coset_remainder_8_of_16",
      "Accept samples 8 of 16 production s=FOLD cosets; remaining 8 are same form and are covered by full pure gate counts, not silent drop.")
  , ("full_pure_deepQAtLayout_H_rebuild",
      "Full pure DEEP uses H-layout rebuild (deepQAtLayout); Lean e2e NamedP uses deepQAt fixture; layout path required on full pure gate.")
  , ("full_pure_fs_absorb_int_challenge_stream",
      "Full pure has hundreds of FS absorbInt/extChallenge steps; Accept models FS absorb sample + multi-query opens; stream completeness is pure-gate, not Lean constant.")
  ]

theorem pureIR_eternal_necessity_len :
    pureIREternalNecessity.length = pureIREternalBound := by native_decide

theorem pureIR_eternal_names_covered :
    pureIREternalRemainder = pureIREternalNecessity.map (·.1) := by
  native_decide

/-- Accept sample is a proper subset of full pure layer cosets. -/
theorem pureIR_accept_layer_strict_subset :
    pureIRAcceptModeled.layerCosetSFold < pureIRFullInventory.layerCosetSFold ∧
    pureIRAcceptModeled.layerCosetSFold ≥ pureIRFullInventory.layerCosetSFold / 2 := by
  simp only [pureIRAcceptModeled, pureIRFullInventory, prodIRLayerCosetCount,
    prodIRFullPureCosetS8]
  native_decide

/-- Freeze status (harness surface). -/
def pureIRFragmentFreezeStatus : String :=
  "lean_accept_multi_query_layer_sample_plus_full_pure_gate_eternal_inline_remainder_4"

theorem pureIR_fragment_freeze_status_nonempty :
    pureIRFragmentFreezeStatus.length > 20 := by native_decide

/--
  Accept track completeness policy:
  Lean fragment (modeled) ∧ full pure gate (complete multi-query FRI IR) ∧
  eternal remainder is only Lean-inline size, not “pure IR not required.”
-/
def pureIRAcceptTrackComplete (leanFullIR : Bool) (fullPureGate : Bool) : Bool :=
  leanFullIR && fullPureGate

theorem pureIR_accept_track_needs_both :
    pureIRAcceptTrackComplete true true = true ∧
    pureIRAcceptTrackComplete true false = false ∧
    pureIRAcceptTrackComplete false true = false := by native_decide

end FriStark.Packing.PureIRFragment
