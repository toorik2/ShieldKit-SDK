/-
  LeanBCH.Opt.Fp12TowerFloorBLS — the BLS12-381 (k = 48) INSTANTIATION of the composed
  `fp12Mul` essential-Fp-multiplication + op-cost FLOOR.  The BN254 (k = 32) tower lives in
  `Opt/Fp12TowerFloor.lean`; this file ports it to the BLS12-381 base-field width.  See
  `Opt/OpCostFloor_SCOPE.md`.

  ────────────────────────────────────────────────────────────────────────────────
  WHY THE PORT IS A WIDTH CHANGE ONLY — the two curves share the 2-3-2 tower.

  BLS12-381 uses the SAME field-extension tower as BN254:
    * Fp2  = Fp[i]/(i²+1)      — BLS12-381's base prime p ≡ 3 (mod 4), so −1 is NOT a square
                                  (the field-defining condition), exactly as for BN254.
    * Fp6  = Fp2[v]/(v³−ξ)     — a cubic extension (ξ = 1+i is a non-cube).
    * Fp12 = Fp6[w]/(w²−v)     — a quadratic extension (v is a non-square).
  The per-level TENSOR-RANK lower bounds are therefore the very same theorems, proven once,
  field-generically, over any admissible base ring:
    * r2  = 3  — `BilinearRank.CRing.fp2_rank_ge_three`  (Winograd; frozen, Piece B)
    * r6  = 5  — `Fp6Rank.fp6_rank_ge_five`              (de Groote 2·3−1; Target B)
    * r12 = 3  — `DegreeExtRank.fp12_over_fp6_rank_ge_three`  (deg-2 Karatsuba; Target A)
  so the composed leaf-count floor `TowerRankCompose.fp12_leaves_ge 3 5 3 = 3·5·3 = 45` is
  IDENTICAL to BN254's.  The ONLY thing that differs is the OPERAND WIDTH fed into Piece A
  (`OpMulFloor`): a reduced BLS12-381 field element is a 381-bit ⇒ 48-byte generic-width VM
  number (k = 48), against BN254's 254-bit ⇒ 32-byte (k = 32).  The op-cost floor scales with
  the per-multiply pre-charge k²:

      fp12Mul_bls_fp_mult_floor  :  a tower-structured BLS `fp12Mul` performs ≥ 45 essential Fp-mults,
      fp12Mul_bls_opCost_floor   :  … bills ≥ 45·(100 + 48²) = 108180 op-cost (BCH_2026_05, k = 48),
      fp12Mul_bls_arith_floor    :  … bills ≥ 45·48²          = 103680 arithmeticCost.

  ## Grounding the 48-byte width in the frozen band (NOT a kernel evaluation of a 380-bit int)

  `bls12381Operand = 2^375` and `bls12381Operand_width : 48 ≤ intByteLen bls12381Operand` are the
  k = 48 analogues of `OpMulFloor.bn254Operand` / `bn254Operand_width`.  The width is discharged by
  the frozen lower band `OpMulFloor.le_intByteLen` at L = 48 (`2^(8·48−9) = 2^375`), exactly as the
  BN254 witness uses L = 32 (`2^(8·32−9) = 2^247`).  No 380-bit magnitude is ever kernel-evaluated.

  ## Non-vacuity — a concrete BLS-width tower with ALL THREE ranks discharged by the theorems

  `gFp12Bls` mirrors `Fp12TowerFloor.gFp12` (3 Fp6-mults, each 9 Fp2-mults = the Fp6 schoolbook
  count, each 3 leaf Fp-mults = the Fp2 Karatsuba count ⇒ 3·9·3 = 81 leaves) but its leaves are the
  48-byte `blsLeaf`.  Its `WF12 3 5 3` is proven by discharging every per-level bridge with a REAL
  computing witness — the SAME witnesses as the BN254 file (they are field-generic):
    * r2 = 3 via `wf2_of_fp2rank` on the Karatsuba program over `Int` (−1-not-a-square);
    * r6 = 5 via `wf6_of_fp6rank` on the `Fp6Rank.schoolbook` 9-gate program over `𝔽₇` (ξ = 2 a
      non-cube, `f7_is_domain`), so `5 ≤ 9`;
    * r12 = 3 via `wf12_of_fp12rank` on the `DegreeExtRank.karatsuba` 3-product program over `Int`
      at the non-square modulus `d = 2` (`int_no_sqrt_two`), so `3 ≤ 3`.
  Hence `gFp12Bls_opCost_floor : 108180 ≤ mulCostSum BCH_2026_05 (gFp12Bls.leaves)` and
  `gFp12Bls_arith_floor : 103680 ≤ mulArithSum (gFp12Bls.leaves)` fire UNCONDITIONALLY.

  ★★ MODEL BOUNDARY (inherited verbatim from `TowerRankCompose` / `Fp12TowerFloor`, restated so it
  is never laundered): 108180 lower-bounds ONE Fp12 multiplication whose computation is STRUCTURED AS
  THE TOWER (each field-extension mult realized by its own child mults one level down — the shipped
  BLS SZ verifier's nested `fp12Mul → fp6Mul → fp2Mul → fpMul` structure), NOT arbitrary straight-line
  programs, a direct Fp12-over-Fp structure tensor, cross-multiplication sharing, or a different
  tower/curve.  It is a floor on the Fp12 ARITHMETIC CORE of ONE full multiply — it is NOT a floor on
  the whole BLS SZ verifier's 162,663 op-cost (that total includes the movement/shuffle half, the many
  restricted maps `fp12Sqr`/`mul034`/the SZ miller line functions, and the covenant/chunking layer —
  all out of scope, exactly as for BN254).  What this file turns from ASSERTED to PROVEN is: the BLS
  Fp12 full-multiplication arithmetic core sits at ≥ 108180 op-cost on the BCH-2026 VM.

  Additive layer over the FROZEN core + `Fp12TowerFloor` (which re-exports the Fp2/Fp6/Fp12 rank
  bridges) + `OpMulFloor` (the `le_intByteLen` band).  Edits nothing.  Lean 4 core, NO mathlib.
  0 sorry, axiom-clean.
-/
import LeanBCH.Opt.Fp12TowerFloor

namespace LeanBCH.Opt.Fp12TowerFloorBLS

open LeanBCH.Opt.OpMulFloor
open LeanBCH.Opt.BilinearRank
open LeanBCH.Opt.Fp12OpCostFloor
open LeanBCH.Opt.TowerRankCompose
open LeanBCH.Opt.Fp12TowerFloor

/-! ## The k = 48 operand-width witness (the ONLY genuinely new ingredient over BN254). -/

/-- A concrete BLS12-381-scale operand: `2^375`, whose libauth VM-number width is (at least) 48
    bytes.  Reduced BLS12-381 field elements are 381-bit ⇒ 48-byte generic-width values; this
    witnesses that the `k = 48` full-width hypotheses are SATISFIABLE (the floors below are
    non-vacuous).  The k = 48 analogue of `OpMulFloor.bn254Operand` (`2^247`). -/
def bls12381Operand : Int := Int.ofNat (2 ^ 375)

/-- The witness IS full-width: `intByteLen (2^375) ≥ 48`.  Discharged by the frozen width band
    `OpMulFloor.le_intByteLen` at L = 48 (`|2^375| = 2^375 = 2^(8·48−9)`), NOT by kernel-evaluating
    the 376-bit magnitude.  The k = 48 analogue of `OpMulFloor.bn254Operand_width`. -/
theorem bls12381Operand_width : 48 ≤ intByteLen bls12381Operand := by
  apply le_intByteLen bls12381Operand 48 (by decide)
  have hnat : bls12381Operand.natAbs = 2 ^ 375 := rfl
  have hexp : 8 * 48 - 9 = 375 := rfl
  rw [hnat, hexp]
  exact Nat.le_refl _

/-! ## ★★ THE COMPOSED BLS fp12Mul FLOORS — the parametric bridge at (3,5,3), width k = 48. -/

/-- ★★ THE BLS fp12Mul ESSENTIAL-Fp-MULT FLOOR.  Curve-independent: a tower-structured `fp12Mul`
    whose per-level sub-multiplications respect the kernel-proven ranks (r2 = 3, r6 = 5, r12 = 3)
    performs ≥ 45 essential Fp-multiplications.  Same statement as BN254 — the count floor does not
    depend on operand width — recorded here for the BLS instantiation's completeness. -/
theorem fp12Mul_bls_fp_mult_floor (a : Fp12Algo) (hwf : WF12 3 5 3 a) :
    45 ≤ (Fp12Algo.leaves a).length :=
  fp12Mul_fp_mult_floor a hwf

/-- ★★ THE BLS fp12Mul OP-COST FLOOR.  The same tower, on full-width (≥ 48-byte) BLS12-381 operands,
    bills ≥ 45·(100 + 48²) = 108180 op-cost under the shipped `BCH_2026_05` epoch. -/
theorem fp12Mul_bls_opCost_floor (a : Fp12Algo) (hwf : WF12 3 5 3 a)
    (hw : ∀ p ∈ Fp12Algo.leaves a, 48 ≤ intByteLen p.1 ∧ 48 ≤ intByteLen p.2) :
    108180 ≤ mulCostSum BCH_2026_05 (Fp12Algo.leaves a) := by
  have h := fp12_opCost_floor BCH_2026_05 48 3 5 3 a hwf hw
  have hb : BCH_2026_05.baseInstructionCost = 100 := rfl
  rw [hb] at h
  omega

/-- ★ THE BLS fp12Mul ARITH FLOOR: the same tower bills ≥ 45·48² = 103680 arithmeticCost. -/
theorem fp12Mul_bls_arith_floor (a : Fp12Algo) (hwf : WF12 3 5 3 a)
    (hw : ∀ p ∈ Fp12Algo.leaves a, 48 ≤ intByteLen p.1 ∧ 48 ≤ intByteLen p.2) :
    103680 ≤ mulArithSum (Fp12Algo.leaves a) := by
  have h := fp12_arith_floor 48 3 5 3 a hwf hw
  omega

/-! ## Non-vacuity: a concrete BLS-width tower with ALL THREE ranks discharged by the theorems.

    `gFp12Bls` = 3 Fp6-mults, each 9 Fp2-mults (Fp6 schoolbook count), each 3 leaf Fp-mults (Fp2
    Karatsuba count) ⇒ 3·9·3 = 81 full-width BLS12-381 leaves.  Structure mirrors
    `Fp12TowerFloor.gFp12`; only the leaf operand changes to the 48-byte `blsLeaf`. -/

/-- One full-width BLS12-381-scale leaf multiply (`2³⁷⁵ · 2³⁷⁵`). -/
def blsLeaf : Int × Int := (bls12381Operand, bls12381Operand)

/-- An Fp2 tower sub-mult with exactly 3 BLS-width leaf Fp-mults (Karatsuba/Winograd count). -/
def blsFp2 : Fp2Algo := ⟨[blsLeaf, blsLeaf, blsLeaf]⟩

/-- The 9 Fp2-sub-multiplications of the concrete Fp6-mult (the Fp6 schoolbook count). -/
def gFp6Bls : Fp6Algo := ⟨List.replicate 9 blsFp2⟩

/-- The concrete Fp12-mult: 3 Fp6-sub-multiplications (the Fp12/Fp6 Karatsuba count). -/
def gFp12Bls : Fp12Algo := ⟨[gFp6Bls, gFp6Bls, gFp6Bls]⟩

/-- `blsFp2` is `WF2 3`, DISCHARGED via the actual Fp2 rank theorem (Karatsuba program over `Int`,
    −1-not-a-square).  Same grounding as `TowerRankCompose.bnFp2_wf`; only the leaves differ. -/
theorem blsFp2_wf : WF2 3 blsFp2 := by
  apply wf2_of_fp2rank (F := Int) blsFp2 CRing.karatsuba
    CRing.karatsuba_rank1 CRing.karatsuba_computes_M0 CRing.karatsuba_computes_M1
    int_no_sqrt_neg_one
  have h1 : (CRing.karatsuba (F := Int)).length = 3 := CRing.karatsuba_length
  have h2 : (Fp2Algo.leaves blsFp2).length = 3 := rfl
  omega

/-- `gFp6Bls` is `WF6 3 5`, DISCHARGED via `Fp6Rank.fp6_rank_ge_five` on `𝔽₇` with the 9-gate
    schoolbook program (`5 ≤ 9`), and each of its 9 Fp2-children `WF2 3` via `blsFp2_wf`. -/
theorem gFp6Bls_wf : WF6 3 5 gFp6Bls := by
  apply wf6_of_fp6rank (F := Fin 7) (xi := (2 : Fin 7)) gFp6Bls
    Fp6Rank.f7_one_ne_zero Fp6Rank.f7_is_domain
    (Fp6Rank.schoolbook (2 : Fin 7)) (Fp6Rank.schoolbook_computes (2 : Fin 7))
  · -- gate count 9 ≤ 9 Fp2-children
    have hg : (Fp6Rank.schoolbook (2 : Fin 7)).length = 9 := Fp6Rank.schoolbook_length (2 : Fin 7)
    have hc : gFp6Bls.fp2Mults.length = 9 := by
      show (List.replicate 9 blsFp2).length = 9
      rw [List.length_replicate]
    omega
  · -- each Fp2-child is WF2 3
    intro s hs
    have hseq : s = blsFp2 := List.eq_of_mem_replicate hs
    subst hseq; exact blsFp2_wf

/-- `gFp12Bls` is `WF12 3 5 3`, DISCHARGED via `DegreeExtRank.fp12_over_fp6_rank_ge_three` on the
    `Int[w]/(w²−2)` degree-2 Karatsuba program (`3 ≤ 3`, non-square `d = 2`), and each of its 3
    Fp6-children `WF6 3 5` via `gFp6Bls_wf`.  Every one of the three tower ranks (3, 5, 3) is thus
    the conclusion of a kernel-checked rank theorem. -/
theorem gFp12Bls_wf : WF12 3 5 3 gFp12Bls := by
  apply wf12_of_fp12rank (F := Int) (2 : Int) gFp12Bls
    CRing.karatsuba CRing.karatsuba_rank1
    (DegreeExtRank.karatsuba_computes_M0d (2 : Int)) CRing.karatsuba_computes_M1
    DegreeExtRank.int_no_sqrt_two
  · -- product count 3 ≤ 3 Fp6-children
    have hp : (CRing.karatsuba (F := Int)).length = 3 := CRing.karatsuba_length
    have hc : gFp12Bls.fp6Mults.length = 3 := rfl
    omega
  · -- each Fp6-child is WF6 3 5
    intro s hs
    have hs' : s ∈ [gFp6Bls, gFp6Bls, gFp6Bls] := hs
    have hseq : s = gFp6Bls := by
      simp only [List.mem_cons, List.not_mem_nil, or_false, or_self] at hs'; exact hs'
    subst hseq; exact gFp6Bls_wf

/-- Every one of `gFp12Bls`'s 81 leaves is full-width (≥ 48-byte), via `bls12381Operand_width` —
    NOT by kernel-evaluating any 376-bit magnitude. -/
theorem gFp12Bls_leaves_width :
    ∀ p ∈ Fp12Algo.leaves gFp12Bls, 48 ≤ intByteLen p.1 ∧ 48 ≤ intByteLen p.2 := by
  intro p hp
  obtain ⟨s, hs, hps⟩ := mem_catMap Fp6Algo.leaves p gFp12Bls.fp6Mults hp
  have hs' : s ∈ [gFp6Bls, gFp6Bls, gFp6Bls] := hs
  have hseq : s = gFp6Bls := by
    simp only [List.mem_cons, List.not_mem_nil, or_false, or_self] at hs'; exact hs'
  subst hseq
  obtain ⟨t, ht, hpt⟩ := mem_catMap Fp2Algo.leaves p gFp6Bls.fp2Mults hps
  have hteq : t = blsFp2 := List.eq_of_mem_replicate ht
  subst hteq
  have hpl : p ∈ [blsLeaf, blsLeaf, blsLeaf] := hpt
  have hpeq : p = blsLeaf := by
    simp only [List.mem_cons, List.not_mem_nil, or_false, or_self] at hpl; exact hpl
  subst hpeq
  exact ⟨bls12381Operand_width, bls12381Operand_width⟩

/-- ★ THE COMPOSED BLS fp12Mul OP-COST FLOOR, UNCONDITIONAL, all ranks grounded: the concrete tower
    `gFp12Bls` bills ≥ 108180 = 45·(100 + 48²) op-cost under `BCH_2026_05`.  Non-vacuous with the
    composed floor 45 = 3·5·3 grounded in `fp2_rank_ge_three` (r2), `fp6_rank_ge_five` (r6), and
    `fp12_over_fp6_rank_ge_three` (r12) — the actual per-level tensor-rank theorems, at BLS width. -/
theorem gFp12Bls_opCost_floor :
    108180 ≤ mulCostSum BCH_2026_05 (Fp12Algo.leaves gFp12Bls) :=
  fp12Mul_bls_opCost_floor gFp12Bls gFp12Bls_wf gFp12Bls_leaves_width

/-- ★ THE COMPOSED BLS fp12Mul ARITH FLOOR, UNCONDITIONAL: `gFp12Bls` bills ≥ 103680 = 45·48²
    arithmeticCost. -/
theorem gFp12Bls_arith_floor :
    103680 ≤ mulArithSum (Fp12Algo.leaves gFp12Bls) :=
  fp12Mul_bls_arith_floor gFp12Bls gFp12Bls_wf gFp12Bls_leaves_width

/-- The composed essential-Fp-mult floor, UNCONDITIONAL: `gFp12Bls` performs ≥ 45 = 3·5·3 essential
    leaf Fp-multiplications. -/
theorem gFp12Bls_fp_mult_floor : 45 ≤ (Fp12Algo.leaves gFp12Bls).length :=
  fp12Mul_bls_fp_mult_floor gFp12Bls gFp12Bls_wf

/-! ## The honest shipped-vs-floor comparison for the BLS SZ verifier.

    The proven BLS Fp12 full-multiplication arithmetic-core floor is 108180 op-cost.  The BLS SZ
    verifier's measured total is 162,663 op-cost — but that total is the WHOLE grouped verifier
    (movement half, restricted maps fp12Sqr/mul034/miller line functions, covenant/chunking), of
    which ONE full fp12Mul arithmetic core is a component.  `108180 ≤ 162663` records only that the
    proven component floor does not exceed the measured whole — NO at-floor claim about the 162,663
    total follows (that would need the movement floor + the restricted-map ranks, all OPEN). -/
theorem bls_fp12Mul_core_floor_le_sz_total : (108180 : Nat) ≤ 162663 := by decide

/-! ## Axiom audit (emitted at build time; expect only propext / Quot.sound / Classical.choice). -/

#print axioms bls12381Operand_width
#print axioms fp12Mul_bls_fp_mult_floor
#print axioms fp12Mul_bls_opCost_floor
#print axioms fp12Mul_bls_arith_floor
#print axioms gFp12Bls_wf
#print axioms gFp12Bls_opCost_floor
#print axioms gFp12Bls_arith_floor
#print axioms gFp12Bls_fp_mult_floor

/-
  ## OPEN (not proven here) — honest boundary, not laundered.

  * 108180 is the op-cost floor of ONE tower-structured BLS `fp12Mul` full multiplication's
    arithmetic core.  It is NOT a floor on the whole BLS SZ verifier's 162,663 op-cost: the
    movement/shuffle half, the restricted maps (`fp12Sqr` squaring, `mul034` sparse, the SZ miller
    line functions), and the covenant/chunking layer are all out of scope — exactly the BN254
    boundary, inherited verbatim.
  * The 45 floor bounds only TOWER-STRUCTURED `fp12Mul` (the shipped nested code's structure), NOT
    arbitrary straight-line programs / a direct Fp12-over-Fp structure tensor / a different tower.
  * r6 = 5 is the de-Groote tensor rank (a valid LOWER bound with slack); a clean Karatsuba-over-Fp6
    tower uses 6.  This file proves the FLOOR (≥ 45 leaves ⇒ ≥ 108180 op-cost), not the achievable
    minimum of the shipped BLS schedule.
  * The count correspondence between abstract tower leaves and executed VM OP_MULs, and the
    full-width (≥ 48-byte) hypothesis, are the same modelling assumptions carried by the frozen
    `Fp12OpCostFloor` / `TowerRankCompose`; only the width constant changes (32 → 48).
-/

end LeanBCH.Opt.Fp12TowerFloorBLS
