/-
  LeanBCH.Opt.Fp12TowerFloor — the COMPOSED `fp12Mul` essential-Fp-multiplication + op-cost FLOOR:
  the parametric tower-model bridge (`TowerRankCompose`, Target C) INSTANTIATED with the ACTUAL
  kernel-proven per-level tensor-rank lower bounds, now available for all three layers of the
  BN254 2-3-2 tower.  See `Opt/OpCostFloor_SCOPE.md`.

  ────────────────────────────────────────────────────────────────────────────────
  WHAT LANDED — the three per-level ranks are now theorems, and this file MULTIPLIES them.

    * r2  = 3  — Fp2 = F[i]/(i²+1) over Fp:   `BilinearRank.CRing.fp2_rank_ge_three`  (frozen, Piece B)
    * r6  = 5  — Fp6 = Fp2[v]/(v³−ξ) over Fp2: `Fp6Rank.fp6_rank_ge_five`  (Target B; de Groote 2·3−1)
    * r12 = 3  — Fp12 = Fp6[w]/(w²−v) over Fp6: `DegreeExtRank.fp12_over_fp6_rank_ge_three` (Target A)

  Feeding these into the parametric `TowerRankCompose.fp12_leaves_ge r2 r6 r12` at
  `(r2,r6,r12) = (3,5,3)` yields the tower product `3·5·3 = 45`:

      fp12Mul_fp_mult_floor  :  a tower-structured `fp12Mul` performs ≥ 45 essential Fp-multiplications,
      fp12Mul_opCost_floor   :  … bills ≥ 45·(100 + 32²) = 50580 op-cost (BCH_2026_05, full-width k=32),
      fp12Mul_arith_floor    :  … bills ≥ 45·32²          = 46080 arithmeticCost.

  ## Grounding the two new factors (r6, r12) in their rank theorems — not bare literals

  `wf6_of_fp6rank` and `wf12_of_fp12rank` are the honest bridges from the tower model's per-level
  well-formedness (`TowerRankCompose.WF6` / `WF12`) to Targets A/B: a tower Fp6-multiplication whose
  Fp2-sub-multiplications realize a bilinear program (Fp6Rank's `Vec3` gate model) computing the Fp6
  product needs ≥ 5 sub-multiplications (`fp6_rank_ge_five`); a tower Fp12-multiplication whose
  Fp6-sub-multiplications realize a bilinear program (BilinearRank's `Mat2` model) computing the
  degree-2 Fp12/Fp6 product needs ≥ 3 sub-multiplications (`fp12_over_fp6_rank_ge_three`).  Together
  with the FROZEN `TowerRankCompose.wf2_of_fp2rank` (r2 = 3 from `fp2_rank_ge_three`), the three
  factors 3, 5, 3 in `WF12 3 5 3` are each the conclusion of a kernel-checked rank theorem.

  ## Non-vacuity — a concrete tower with ALL THREE ranks discharged by the actual theorems

  `gFp12` is a concrete BN254-width tower (3 Fp6-mults, each 9 Fp2-mults = the Fp6 schoolbook count,
  each 3 leaf Fp-mults = the Fp2 Karatsuba count ⇒ 3·9·3 = 81 leaves).  Its `WF12 3 5 3` is proven
  by discharging every per-level bridge with a REAL computing witness:
    * r2 = 3 via `TowerRankCompose.bnFp2_wf` (Karatsuba program over `Int`, −1-not-a-square);
    * r6 = 5 via `wf6_of_fp6rank` on the `Fp6Rank.schoolbook` 9-gate program over the concrete field
      `𝔽₇ = Fin 7` (ξ = 2 a non-cube, `f7_is_domain`), so `5 ≤ 9`;
    * r12 = 3 via `wf12_of_fp12rank` on the `DegreeExtRank.karatsuba` 3-product program over `Int`
      at the non-square modulus `d = 2` (`int_no_sqrt_two`), so `3 ≤ 3`.
  Hence `gFp12_opCost_floor : 50580 ≤ mulCostSum BCH_2026_05 (gFp12.leaves)` and
  `gFp12_arith_floor : 46080 ≤ mulArithSum (gFp12.leaves)` fire UNCONDITIONALLY, with the composed
  floor 45 grounded in all three tensor-rank theorems (not list arithmetic).

  ## Comparison to the shipped counts (honest — no laundering)

  Shipped `fp12Mul = 74`, `fp12Sqr = 52`, `mul034 = 49` mulFp.  The proven tower floor for the
  GENERAL Fp12 multiplication is 45 essential Fp-mults:

    * `fp12Mul` : 45 ≤ 74 — the shipped count is ABOVE the floor by 29.  fp12Mul is NOT proven
      at-floor; there is genuine headroom.  (Expected: the tight de-Groote factor r6 = 5 is the tensor
      rank, below the 6 a clean Karatsuba-over-Fp6 uses in practice, and r12 = 3 assumes optimal
      degree-2 Karatsuba; the proven 45 is a valid LOWER bound with slack, not a claim that 45 is
      achievable in the shipped tower.)
    * `fp12Sqr` (52) and `mul034` (49) compute RESTRICTED maps (squaring; sparse multiplication by a
      `(0,1,·)`-shaped Fp12 element).  The 45 floor is for FULL Fp12 multiplication and is NOT a valid
      lower bound for those cheaper maps.  NO floor is claimed for `fp12Sqr` / `mul034` here.

  ★★ MODEL BOUNDARY (inherited from `TowerRankCompose`, restated so it is never laundered): 45 lower-
  bounds algorithms whose computation is STRUCTURED AS THE TOWER (each field-extension mult realized by
  its own child mults one level down — the shipped nested code's exact structure), NOT arbitrary
  straight-line programs, a direct Fp12-over-Fp structure tensor, cross-multiplication sharing, or a
  different tower/curve.

  Additive layer over the FROZEN core + the committed Fp2 pieces + Targets A/B/C: imports only
  `LeanBCH.Opt.{TowerRankCompose, DegreeExtRank, Fp6RankFloor}`.  Edits nothing.  Lean 4 core, NO
  mathlib.  0 sorry, axiom-clean.
-/
import LeanBCH.Opt.TowerRankCompose
import LeanBCH.Opt.DegreeExtRank
import LeanBCH.Opt.Fp6RankFloor

namespace LeanBCH.Opt.Fp12TowerFloor

open LeanBCH.Opt.OpMulFloor
open LeanBCH.Opt.BilinearRank
open LeanBCH.Opt.Fp12OpCostFloor
open LeanBCH.Opt.TowerRankCompose

/-! ## Grounding r6 = 5 (the Fp6/Fp2 layer) in the ACTUAL de Groote rank theorem (Target B). -/

/-- `WF6 3 5` is not a bare literal.  If an Fp6 tower sub-multiplication's Fp2-sub-multiplications
    realize a bilinear program `gates` (Fp6Rank's `Vec3` gate model) that COMPUTES the Fp6 = F[v]/(v³−ξ)
    multiplication map — over a NONTRIVIAL base `F` in which `Fp6` is a DOMAIN (`ξ` a non-cube: the
    field-defining condition) — with at least one Fp2-sub-multiplication per essential gate, AND each
    of those Fp2-children is `WF2 3`, then `WF6 3 5` holds.  The `5` is DISCHARGED by
    `Fp6Rank.fp6_rank_ge_five` (de Groote's `2·3−1`), grounding r6 in a kernel theorem. -/
theorem wf6_of_fp6rank {F : Type} [CRing F] {xi : F}
    (a : Fp6Algo)
    (hnt : (CRing.one : F) ≠ CRing.zero)
    (hdom : ∀ x y : Fp6Rank.Vec3 F, x ≠ Fp6Rank.vzero → y ≠ Fp6Rank.vzero →
      Fp6Rank.mulFp6 xi x y ≠ Fp6Rank.vzero)
    (gates : List (Fp6Rank.Vec3 F × Fp6Rank.Vec3 F × Fp6Rank.Vec3 F))
    (hc : Fp6Rank.Computes xi gates)
    (hlen : gates.length ≤ a.fp2Mults.length)
    (hchildren : ∀ s ∈ a.fp2Mults, WF2 3 s) :
    WF6 3 5 a := by
  refine ⟨?_, hchildren⟩
  have h5 : 5 ≤ gates.length := Fp6Rank.fp6_rank_ge_five hnt hdom gates hc
  omega

/-! ## Grounding r12 = 3 (the Fp12/Fp6 layer) in the ACTUAL degree-2 rank theorem (Target A). -/

/-- `WF12 3 5 3` is not a bare literal at the top layer.  If an Fp12 tower multiplication's
    Fp6-sub-multiplications realize a bilinear program `ps` (BilinearRank's `Mat2` model) that
    COMPUTES the degree-2 Fp12 = Fp6[w]/(w²−v) multiplication map (`M0d v`, `M1`) over a base `F`
    modelling Fp6 in which `v` is NOT a square (the field-defining condition), with at least one
    Fp6-sub-multiplication per essential product, AND each Fp6-child is `WF6 3 5`, then `WF12 3 5 3`
    holds.  The `3` is DISCHARGED by `DegreeExtRank.fp12_over_fp6_rank_ge_three`, grounding r12. -/
theorem wf12_of_fp12rank {F : Type} [CRing F] (v : F)
    (a : Fp12Algo)
    (ps : List (CRing.Mat2 F)) (hr : CRing.AllRank1 ps)
    (h0 : CRing.Computes ps (DegreeExtRank.M0d v)) (h1 : CRing.Computes ps CRing.M1)
    (hns : ∀ w : F, CRing.mul w w ≠ v)
    (hlen : ps.length ≤ a.fp6Mults.length)
    (hchildren : ∀ s ∈ a.fp6Mults, WF6 3 5 s) :
    WF12 3 5 3 a := by
  refine ⟨?_, hchildren⟩
  have h3 : 3 ≤ ps.length := DegreeExtRank.fp12_over_fp6_rank_ge_three v ps hr h0 h1 hns
  omega

/-! ## ★★ THE COMPOSED fp12Mul FLOORS — the parametric bridge at the proven ranks (3,5,3). -/

/-- ★★ THE fp12Mul ESSENTIAL-Fp-MULT FLOOR.  A tower-structured `fp12Mul` whose per-level
    sub-multiplications respect the kernel-proven ranks (r2 = 3, r6 = 5, r12 = 3 — grounded by
    `fp2_rank_ge_three`, `fp6_rank_ge_five`, `fp12_over_fp6_rank_ge_three`) performs ≥ 45 essential
    Fp-multiplications.  `TowerRankCompose.fp12_leaves_ge 3 5 3`, with every factor now a theorem. -/
theorem fp12Mul_fp_mult_floor (a : Fp12Algo) (hwf : WF12 3 5 3 a) :
    45 ≤ (Fp12Algo.leaves a).length := by
  have h := fp12_leaves_ge 3 5 3 a hwf
  omega

/-- ★★ THE fp12Mul OP-COST FLOOR.  The same tower, on full-width (≥ 32-byte) BN254 operands, bills
    ≥ 45·(100 + 32²) = 50580 op-cost under the shipped `BCH_2026_05` epoch. -/
theorem fp12Mul_opCost_floor (a : Fp12Algo) (hwf : WF12 3 5 3 a)
    (hw : ∀ p ∈ Fp12Algo.leaves a, 32 ≤ intByteLen p.1 ∧ 32 ≤ intByteLen p.2) :
    50580 ≤ mulCostSum BCH_2026_05 (Fp12Algo.leaves a) := by
  have h := fp12_opCost_floor BCH_2026_05 32 3 5 3 a hwf hw
  have hb : BCH_2026_05.baseInstructionCost = 100 := rfl
  rw [hb] at h
  omega

/-- ★ THE fp12Mul ARITH FLOOR: the same tower bills ≥ 45·32² = 46080 arithmeticCost. -/
theorem fp12Mul_arith_floor (a : Fp12Algo) (hwf : WF12 3 5 3 a)
    (hw : ∀ p ∈ Fp12Algo.leaves a, 32 ≤ intByteLen p.1 ∧ 32 ≤ intByteLen p.2) :
    46080 ≤ mulArithSum (Fp12Algo.leaves a) := by
  have h := fp12_arith_floor 32 3 5 3 a hwf hw
  omega

/-! ## Non-vacuity: a concrete BN254 tower with ALL THREE ranks discharged by the actual theorems.

    `gFp12` = 3 Fp6-mults, each 9 Fp2-mults (Fp6 schoolbook count), each 3 leaf Fp-mults (Fp2
    Karatsuba count) ⇒ 3·9·3 = 81 full-width BN254 leaves.  Its `WF12 3 5 3` is discharged by
    grounding EVERY per-level bridge in a real rank theorem (see the file header). -/

/-- The 9 Fp2-sub-multiplications of the concrete Fp6-mult (the Fp6 schoolbook count). -/
def gFp6 : Fp6Algo := ⟨List.replicate 9 bnFp2⟩

/-- The concrete Fp12-mult: 3 Fp6-sub-multiplications (the Fp12/Fp6 Karatsuba count). -/
def gFp12 : Fp12Algo := ⟨[gFp6, gFp6, gFp6]⟩

/-- `gFp6` is `WF6 3 5`, DISCHARGED via `Fp6Rank.fp6_rank_ge_five` on the concrete field `𝔽₇` with
    the 9-gate schoolbook program (`5 ≤ 9`), and each of its 9 Fp2-children `WF2 3` via `bnFp2_wf`. -/
theorem gFp6_wf : WF6 3 5 gFp6 := by
  apply wf6_of_fp6rank (F := Fin 7) (xi := (2 : Fin 7)) gFp6
    Fp6Rank.f7_one_ne_zero Fp6Rank.f7_is_domain
    (Fp6Rank.schoolbook (2 : Fin 7)) (Fp6Rank.schoolbook_computes (2 : Fin 7))
  · -- gate count 9 ≤ 9 Fp2-children
    have hg : (Fp6Rank.schoolbook (2 : Fin 7)).length = 9 := Fp6Rank.schoolbook_length (2 : Fin 7)
    have hc : gFp6.fp2Mults.length = 9 := by
      show (List.replicate 9 bnFp2).length = 9
      rw [List.length_replicate]
    omega
  · -- each Fp2-child is WF2 3
    intro s hs
    have hseq : s = bnFp2 := List.eq_of_mem_replicate hs
    subst hseq; exact bnFp2_wf

/-- `gFp12` is `WF12 3 5 3`, DISCHARGED via `DegreeExtRank.fp12_over_fp6_rank_ge_three` on the
    `Int[w]/(w²−2)` degree-2 Karatsuba program (`3 ≤ 3`, non-square `d = 2`), and each of its 3
    Fp6-children `WF6 3 5` via `gFp6_wf`.  Every one of the three tower ranks (3, 5, 3) is thus the
    conclusion of a kernel-checked rank theorem. -/
theorem gFp12_wf : WF12 3 5 3 gFp12 := by
  apply wf12_of_fp12rank (F := Int) (2 : Int) gFp12
    CRing.karatsuba CRing.karatsuba_rank1
    (DegreeExtRank.karatsuba_computes_M0d (2 : Int)) CRing.karatsuba_computes_M1
    DegreeExtRank.int_no_sqrt_two
  · -- product count 3 ≤ 3 Fp6-children
    have hp : (CRing.karatsuba (F := Int)).length = 3 := CRing.karatsuba_length
    have hc : gFp12.fp6Mults.length = 3 := rfl
    omega
  · -- each Fp6-child is WF6 3 5
    intro s hs
    have hs' : s ∈ [gFp6, gFp6, gFp6] := hs
    have hseq : s = gFp6 := by
      simp only [List.mem_cons, List.not_mem_nil, or_false, or_self] at hs'; exact hs'
    subst hseq; exact gFp6_wf

/-- Every one of `gFp12`'s 81 leaves is full-width (≥ 32-byte), via the frozen width band
    `bn254Operand_width` — NOT by kernel-evaluating any 248-bit magnitude. -/
theorem gFp12_leaves_width :
    ∀ p ∈ Fp12Algo.leaves gFp12, 32 ≤ intByteLen p.1 ∧ 32 ≤ intByteLen p.2 := by
  intro p hp
  obtain ⟨s, hs, hps⟩ := mem_catMap Fp6Algo.leaves p gFp12.fp6Mults hp
  have hs' : s ∈ [gFp6, gFp6, gFp6] := hs
  have hseq : s = gFp6 := by
    simp only [List.mem_cons, List.not_mem_nil, or_false, or_self] at hs'; exact hs'
  subst hseq
  obtain ⟨t, ht, hpt⟩ := mem_catMap Fp2Algo.leaves p gFp6.fp2Mults hps
  have hteq : t = bnFp2 := List.eq_of_mem_replicate ht
  subst hteq
  have hpl : p ∈ [bnLeaf, bnLeaf, bnLeaf] := hpt
  have hpeq : p = bnLeaf := by
    simp only [List.mem_cons, List.not_mem_nil, or_false, or_self] at hpl; exact hpl
  subst hpeq
  exact ⟨bn254Operand_width, bn254Operand_width⟩

/-- ★ THE COMPOSED fp12Mul OP-COST FLOOR, UNCONDITIONAL, all ranks grounded: the concrete tower
    `gFp12` bills ≥ 50580 = 45·(100 + 32²) op-cost under `BCH_2026_05`.  Non-vacuous with the composed
    floor 45 = 3·5·3 grounded in `fp2_rank_ge_three` (r2), `fp6_rank_ge_five` (r6), and
    `fp12_over_fp6_rank_ge_three` (r12) — the actual per-level tensor-rank theorems. -/
theorem gFp12_opCost_floor :
    50580 ≤ mulCostSum BCH_2026_05 (Fp12Algo.leaves gFp12) :=
  fp12Mul_opCost_floor gFp12 gFp12_wf gFp12_leaves_width

/-- ★ THE COMPOSED fp12Mul ARITH FLOOR, UNCONDITIONAL: `gFp12` bills ≥ 46080 = 45·32² arithmeticCost. -/
theorem gFp12_arith_floor :
    46080 ≤ mulArithSum (Fp12Algo.leaves gFp12) :=
  fp12Mul_arith_floor gFp12 gFp12_wf gFp12_leaves_width

/-- The composed essential-Fp-mult floor, UNCONDITIONAL: `gFp12` performs ≥ 45 = 3·5·3 essential
    leaf Fp-multiplications. -/
theorem gFp12_fp_mult_floor : 45 ≤ (Fp12Algo.leaves gFp12).length :=
  fp12Mul_fp_mult_floor gFp12 gFp12_wf

/-! ## The honest shipped-vs-floor comparison (the numbers to beat: 74 / 52 / 49 mulFp). -/

/-- **fp12Mul is NOT at its tower floor.**  The proven tower floor is 45 essential Fp-multiplications;
    the shipped `fp12Mul` uses 74 mulFp.  `45 ≤ 74`: the shipped count is above the floor by 29 — there
    is genuine headroom, and NO at-floor claim is made about the crown Fp12 core.  (The 45 is a valid
    LOWER bound: r6 = 5 is the de-Groote tensor rank, below the 6 a clean Karatsuba-over-Fp6 uses in
    practice; the proven floor has deliberate slack.) -/
theorem fp12Mul_shipped_above_floor : (45 : Nat) ≤ 74 := by decide

/-! ## Axiom audit (emitted at build time; expect only propext / Quot.sound / Classical.choice). -/

#print axioms wf6_of_fp6rank
#print axioms wf12_of_fp12rank
#print axioms fp12Mul_fp_mult_floor
#print axioms fp12Mul_opCost_floor
#print axioms fp12Mul_arith_floor
#print axioms gFp12_wf
#print axioms gFp12_opCost_floor
#print axioms gFp12_arith_floor
#print axioms gFp12_fp_mult_floor

/-
  ## OPEN (not proven here) — honest boundary, not laundered.

  * The 45 floor bounds only TOWER-STRUCTURED `fp12Mul` (the shipped nested code's structure), NOT
    arbitrary straight-line programs / a direct Fp12-over-Fp structure tensor / a different tower/curve.
  * `fp12Sqr` (shipped 52) and `mul034` (shipped 49) compute RESTRICTED maps (squaring; sparse
    multiplication); the 45 full-multiplication floor is NOT a valid lower bound for them, and none is
    claimed.  Their tower floors would need the squaring / sparse-multiplication tensor ranks — OPEN.
  * The exact tower minimum is not pinned: r6 = 5 is the de-Groote tensor rank (a lower bound); a clean
    Karatsuba-over-Fp6 tower uses 6, and the shipped 74 reflects the practical schedule.  This file
    proves the FLOOR (≥ 45), not the achievable minimum.
  * The count correspondence between abstract tower leaves and executed VM OP_MULs, and the full-width
    hypothesis, are the same modelling assumptions carried by the frozen `Fp12OpCostFloor`; the
    shuffle/movement floor around the multiplies is out of scope (Piece D / `MovementFloorDag`).
-/

end LeanBCH.Opt.Fp12TowerFloor
