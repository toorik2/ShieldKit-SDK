/-
  LeanBCH.Opt.DegreeExtRank — the degree-2 field-extension multiplication rank floor,
  GENERALIZING the frozen Fp2 result (`Opt/BilinearRankFloor.lean`) to ANY degree-2
  extension `R[x]/(x²−d)`, and INSTANTIATING it at the top of the BN254 tower to obtain
  the Fp12/Fp6 layer floor.  TARGET A of the tower extension (see `Opt/OpCostFloor_SCOPE.md`).

  ## What this file proves (kernel-checked, 0-sorry, axioms ⊆ {propext,Quot.sound,Classical.choice})

  The frozen file pinned the Fp2 = F[i]/(i²+1) multiplication tensor rank at EXACTLY 3, over any
  commutative ring in which −1 is not a square.  That is the degree-2 extension with modulus
  `x²+1`, i.e. `d = −1`.  Here we lift the SAME substitution/matrix-pencil argument to the general
  degree-2 extension `R[x]/(x²−d)`, whose multiplication map is

      (a0,a1,b0,b1)  ↦  (a0·b0 + d·a1·b1 ,  a0·b1 + a1·b0)

  (from `(a0+a1 x)(b0+b1 x) = a0 b0 + a1 b1 x² + (a0 b1 + a1 b0) x` with `x² = d`).  Encoding the
  two output forms as the coefficient matrices `M0d d = ⟨1,0,0,d⟩` and `M1 = ⟨0,1,1,0⟩` (the latter
  IDENTICAL to Fp2's, hence REUSED from the frozen file), we prove:

    * `degExt_rank_ge_three` : every bilinear algorithm computing this map uses ≥ 3 essential
       scalar multiplications (tensor rank ≥ 3), provided `d` is NOT a square in `R`
       (`∀ w, w*w ≠ d`) — exactly the condition under which `R[x]/(x²−d)` is a FIELD.
    * `degExt_rank_le_three` : Karatsuba/Winograd achieves it with exactly 3 (rank ≤ 3).

  Hence the degree-2 extension multiplication tensor has rank EXACTLY 3 for every non-square `d`.
  The lower bound reuses the frozen substitution engine unchanged: two rank-1 matrices whose span
  contains both `M0d d` and `M1` force `d` to be a square (`scalar_contra_d`), contradiction.

  ## The BN254 tower instance — Fp12/Fp6 (the deliverable named in the task)

  `Fp12 = Fp6[w]/(w²−v)` is the degree-2 extension of `Fp6` with modulus `x²−v`, i.e. `d = v`, the
  designated Fp6 element of the tower.  `fp12_over_fp6_rank_ge_three` is `degExt_rank_ge_three`
  instantiated at `d = v`: for ANY commutative ring `F` modelling `Fp6` and ANY element `v : F` that
  is NOT a square in `F` (the field-defining condition making `Fp12` a proper field extension —
  precisely why the BN254 tower picks `v` a non-square-and-non-cube), computing one Fp12-mult by a
  bilinear algorithm OVER Fp6 needs ≥ 3 essential Fp6-multiplications.  This is the Karatsuba layer
  of the 2-3-2 tower: `w²−v` deg-2 over Fp6, rank ≥ 3.

  ## Faithfulness (why the abstract statement IS the Fp12/Fp6 fact)

  `Fp6` is a commutative ring (a `CRing`), and its tower element `v` is a non-square by construction;
  the Fp12 mult tensor over Fp6 is literally the map above with `R = Fp6`, `d = v`.  So the theorem
  applies to the real Fp6 the instant Fp6 is presented as a `CRing` with `v` non-square — which it is.
  We do not hardcode a concrete `Fp6` (building `Fp2[v]/(v³−ξ)` in Lean core is a separate,
  heavier task); the parametric statement is the honest, reusable form.

  ## Non-vacuity (the hypothesis class is inhabited by concrete machine-checked rings)

  Over `Int`: `d = −1` (reusing the frozen `int_no_sqrt_neg_one`) and, to certify the generalization
  is GENUINE and not a relabelling of Fp2, `d = 2` (`int_no_sqrt_two`, a fresh non-square modulus the
  frozen Fp2 result does NOT cover).  `int_degExt_two_min_mults` states the full hypothesis-free fact
  over `Int` at `d = 2`: the minimum is EXACTLY 3 (achievability ∧ optimality).  Every lower-bound
  theorem's hypotheses are thus demonstrably satisfiable with a real, positive bound.

  ## Honest scope boundary (do not launder)

  This is the deg-2 (Fp12/Fp6, rank ≥ 3) LAYER of the tower.  It is ONE factor of the tower-model
  composition; it does NOT by itself bound the Fp-multiplication count of `fp12Mul` / `fp12Sqr` /
  `mul034`.  The Fp6/Fp2 deg-3 layer (de Groote: rank(deg-3 ext mult) = 2·3−1 = 5, i.e. ≥ 5 over
  Fp2) is NOT proven here and belongs to a separate target; see the OPEN note at the end.  The
  eventual product-of-per-level-ranks bounds only algorithms CONSTRAINED to compute via the tower
  (which the shipped code is), NOT arbitrary algorithms.

  Additive layer over the FROZEN core: imports only `LeanBCH.Opt.BilinearRankFloor` and reuses its
  `CRing`/`Mat2`/`det`/`IsRank1`/`Computes`/`bilK`/`M1`/`karatsuba` machinery verbatim.  Edits
  nothing.  Lean 4 core, NO mathlib.  0 sorry, axiom-clean.
-/
import LeanBCH.Opt.BilinearRankFloor

namespace LeanBCH.Opt.DegreeExtRank

open LeanBCH.Opt.BilinearRank

/-! ## The abstract degree-2 extension floor (over any admissible commutative ring). -/

section Abstract

open LeanBCH.Opt.BilinearRank.CRing

set_option linter.unusedSectionVars false

variable {F : Type} [CRing F]

/-- The real-part coefficient matrix of the `R[x]/(x²−d)` multiplication tensor: the `x·y`
    coefficient table of `a0·b0 + d·a1·b1`, i.e. `⟨1,0,0,d⟩`.  For `d = −1` this is Fp2's `M0`
    (definitionally); for `d = v` this is the Fp12/Fp6 real part.  The imaginary part `⟨0,1,1,0⟩`
    is `d`-independent and REUSED as the frozen `M1`. -/
def M0d (d : F) : Mat2 F := ⟨one, zero, zero, d⟩

/-- `det ⟨1,0,0,d⟩ = d`. -/
theorem det_M0d (d : F) : det (M0d d) = d := by
  simp only [det, M0d]; ring1

/-- `det (⟨1,0,0,d⟩ + ⟨0,1,1,0⟩) = det ⟨1,1,1,d⟩ = d − 1`. -/
theorem det_M0dM1 (d : F) : det (madd (M0d d) M1) = (d + neg one : F) := by
  simp only [det, madd, M0d, M1]; ring1

/-- The scalar heart of the generalized substitution bound.  If a single scalar `K` and weights
    `x0,y0,x1,y1` satisfy the three determinant equations forced by a 2-product bilinear algorithm
    for the `x²−d` extension, then `((x0·y1)·K)² = d`, i.e. `d` is a square — impossible when `hns`
    holds.  (For `d = −1` this is the frozen `scalar_contra`.) -/
theorem scalar_contra_d {d K x0 y0 x1 y1 : F}
    (hns : ∀ w : F, w * w ≠ d)
    (E1 : (x0 * y0) * K = d)
    (E2 : (x1 * y1) * K = neg one)
    (E3 : ((x0 + x1) * (y0 + y1)) * K = (d + neg one : F)) : False := by
  have expand : ((x0 + x1) * (y0 + y1)) * K
      = ((x0 * y0) * K + (x1 * y1) * K) + ((x0 * y1) * K + (x1 * y0) * K) := by ring1
  rw [expand, E1, E2] at E3
  -- E3 : (d + neg one) + ((x0*y1)*K + (x1*y0)*K) = d + neg one
  have hPQ : (x0 * y1) * K + (x1 * y0) * K = zero := add_right_eq_self E3
  have hmul : ((x0 * y1) * K) * ((x1 * y0) * K) = neg d := by
    have e : ((x0 * y1) * K) * ((x1 * y0) * K) = ((x0 * y0) * K) * ((x1 * y1) * K) := by ring1
    rw [e, E1, E2, mul_neg, mul_one]
  have hQ : (x1 * y0) * K = neg ((x0 * y1) * K) := neg_unique hPQ
  rw [hQ, mul_neg] at hmul
  -- hmul : neg (((x0*y1)*K) * ((x0*y1)*K)) = neg d
  have hsq : ((x0 * y1) * K) * ((x0 * y1) * K) = d := by
    rw [← neg_neg (((x0 * y1) * K) * ((x0 * y1) * K)), hmul, neg_neg]
  exact hns ((x0 * y1) * K) hsq

/-- **Two essential products are not enough** (general degree-2 extension).  No pair of rank-1
    matrices `U, V` has both output matrices `M0d d`, `M1` in its span, provided `d` is not a
    square.  Reuses the frozen singular-pencil algebra (`rank1_det_zero`, `det_combo_rank1`,
    `madd_combine`) unchanged. -/
theorem two_not_enough_d {d : F} {U V : Mat2 F} (hU : IsRank1 U) (hV : IsRank1 V)
    (x0 y0 x1 y1 : F)
    (hM0 : (M0d d : Mat2 F) = madd (smul x0 U) (smul y0 V))
    (hM1 : (M1 : Mat2 F) = madd (smul x1 U) (smul y1 V))
    (hns : ∀ w : F, w * w ≠ d) : False := by
  have hUd : det U = zero := rank1_det_zero hU
  have hVd : det V = zero := rank1_det_zero hV
  have E1 : (x0 * y0) * bilK U V = d := by
    have h := det_M0d (F := F) d
    rw [hM0, det_combo_rank1 hUd hVd x0 y0] at h
    exact h
  have E2 : (x1 * y1) * bilK U V = neg one := by
    have h := det_M1 (F := F)
    rw [hM1, det_combo_rank1 hUd hVd x1 y1] at h
    exact h
  have E3 : ((x0 + x1) * (y0 + y1)) * bilK U V = (d + neg one : F) := by
    have h := det_M0dM1 (F := F) d
    rw [hM0, hM1, madd_combine, det_combo_rank1 hUd hVd (x0 + x1) (y0 + y1)] at h
    exact h
  exact scalar_contra_d hns E1 E2 E3

/-- **Degree-2 extension multiplication has tensor rank ≥ 3.**  Every bilinear algorithm (list of
    essential rank-1 products) whose span contains both output matrices `M0d d`, `M1` uses at least
    three products — provided `d` is not a square in `F` (the condition making `F[x]/(x²−d)` a
    field).  A genuine non-existence theorem: no 2-, 1-, or 0-product schedule exists, kernel-checked.
    Generalizes the frozen `fp2_rank_ge_three` (`d = −1`). -/
theorem degExt_rank_ge_three {d : F} (ps : List (Mat2 F)) (hr : AllRank1 ps)
    (h0 : Computes ps (M0d d)) (h1 : Computes ps M1)
    (hns : ∀ w : F, w * w ≠ d) : 3 ≤ ps.length := by
  rcases ps with _ | ⟨u, _ | ⟨v, _ | ⟨w, rest⟩⟩⟩
  · -- ps = [] : the span is {0}, but M0d has (0,0) entry 1 ≠ 0 unless the ring is trivial.
    exfalso
    obtain ⟨ws, hw⟩ := h0
    rw [combo_nil] at hw
    have hone : (one : F) = zero := congrArg Mat2.a hw
    have htriv : ∀ x : F, x = zero := fun x => by rw [← mul_one x, hone, mul_zero]
    exact hns zero (by rw [zero_mul]; exact (htriv d).symm)
  · -- ps = [u] : pad with the zero product; two_not_enough_d with V = mzero.
    exfalso
    have hu : IsRank1 u := hr u (by simp)
    obtain ⟨ws0, hw0⟩ := h0
    obtain ⟨ws1, hw1⟩ := h1
    obtain ⟨a0, ha0⟩ := combo_one ws0 u
    obtain ⟨a1, ha1⟩ := combo_one ws1 u
    rw [ha0] at hw0
    rw [ha1] at hw1
    have hz : (mzero : Mat2 F) = smul zero mzero := (smul_mzero zero).symm
    rw [hz] at hw0 hw1
    exact two_not_enough_d hu rank1_mzero a0 zero a1 zero hw0 hw1 hns
  · -- ps = [u, v] : the crux case, direct two_not_enough_d.
    exfalso
    have hu : IsRank1 u := hr u (by simp)
    have hv : IsRank1 v := hr v (by simp)
    obtain ⟨ws0, hw0⟩ := h0
    obtain ⟨ws1, hw1⟩ := h1
    obtain ⟨a0, b0, ha0⟩ := combo_two ws0 u v
    obtain ⟨a1, b1, ha1⟩ := combo_two ws1 u v
    rw [ha0] at hw0
    rw [ha1] at hw1
    exact two_not_enough_d hu hv a0 b0 a1 b1 hw0 hw1 hns
  · -- ps has length ≥ 3 : the bound holds directly.
    simp only [List.length_cons]
    omega

/-! ## Tightness: Karatsuba/Winograd achieves 3 for the general modulus (rank ≤ 3, hence = 3).
    The products `K1,K2,K3` and their rank-1 witness (`karatsuba_rank1`), the imaginary-part
    schedule (`karatsuba_computes_M1`), and the length are all `d`-independent and REUSED from the
    frozen file; only the real-part combination changes (weights `[1, d, 0]`). -/

/-- Karatsuba computes the real part `M0d d = 1·(a0 b0) + d·(a1 b1)` with weights `[1, d, 0]`. -/
theorem karatsuba_computes_M0d (d : F) : Computes (karatsuba : List (Mat2 F)) (M0d d) := by
  refine ⟨[one, d, zero], ?_⟩
  simp only [karatsuba, combo, List.zipWith_cons_cons,
    List.zipWith_nil_right, List.foldr_cons, List.foldr_nil, smul, madd, mzero, M0d,
    K1, K2, K3, Mat2.mk.injEq]
  refine ⟨?_, ?_, ?_, ?_⟩ <;> ring2

/-- **Degree-2 extension multiplication has tensor rank ≤ 3.**  The frozen 3-product
    Karatsuba/Winograd schedule computes both output matrices for every modulus `d`. -/
theorem degExt_rank_le_three (d : F) :
    ∃ ps : List (Mat2 F), AllRank1 ps ∧ Computes ps (M0d d) ∧ Computes ps M1 ∧ ps.length = 3 :=
  ⟨karatsuba, karatsuba_rank1, karatsuba_computes_M0d d, karatsuba_computes_M1, karatsuba_length⟩

/-! ## Consistency: the generalization SUBSUMES the frozen Fp2 result (`d = −1`). -/

/-- The frozen `fp2_rank_ge_three` is exactly `degExt_rank_ge_three` at `d = −1` (since Fp2's `M0`
    is `M0d (−1)` definitionally).  Re-derived here to certify the generalization is faithful. -/
theorem fp2_rank_ge_three_via_degExt (ps : List (Mat2 F)) (hr : AllRank1 ps)
    (h0 : Computes ps M0) (h1 : Computes ps M1)
    (hns : ∀ w : F, w * w ≠ neg one) : 3 ≤ ps.length := by
  have hM0 : (M0 : Mat2 F) = M0d (neg one) := rfl
  rw [hM0] at h0
  exact degExt_rank_ge_three ps hr h0 h1 hns

/-! ## ★★ THE BN254 TOWER INSTANCE — Fp12 = Fp6[w]/(w²−v), rank ≥ 3 over Fp6 (the deliverable). -/

/-- **Fp12/Fp6 multiplication has tensor rank ≥ 3** (the deg-2 top layer of the BN254 tower).  For
    any commutative ring `F` modelling `Fp6` and any element `v : F` that is NOT a square in `F`
    (the field-defining condition for `Fp12 = Fp6[w]/(w²−v)`; the BN254 tower's non-square `v`),
    every bilinear algorithm OVER Fp6 computing one Fp12-multiplication uses ≥ 3 essential
    Fp6-multiplications.  This is `degExt_rank_ge_three` at `d = v`.  Honest boundary: this is ONE
    tower layer, not the Fp-mult count of `fp12Mul` (which also needs the Fp6/Fp2 rank ≥ 5, OPEN). -/
theorem fp12_over_fp6_rank_ge_three (v : F)
    (ps : List (Mat2 F)) (hr : AllRank1 ps)
    (h0 : Computes ps (M0d v)) (h1 : Computes ps M1)
    (hns : ∀ w : F, w * w ≠ v) : 3 ≤ ps.length :=
  degExt_rank_ge_three ps hr h0 h1 hns

/-- **Fp12/Fp6 multiplication has tensor rank ≤ 3** (Karatsuba over Fp6 achieves it). -/
theorem fp12_over_fp6_rank_le_three (v : F) :
    ∃ ps : List (Mat2 F), AllRank1 ps ∧ Computes ps (M0d v) ∧ Computes ps M1 ∧ ps.length = 3 :=
  degExt_rank_le_three v

#print axioms degExt_rank_ge_three
#print axioms degExt_rank_le_three
#print axioms scalar_contra_d
#print axioms two_not_enough_d
#print axioms karatsuba_computes_M0d
#print axioms fp2_rank_ge_three_via_degExt
#print axioms fp12_over_fp6_rank_ge_three
#print axioms fp12_over_fp6_rank_le_three

end Abstract

/-! ## Concrete non-vacuity over `Int`.  Stated OUTSIDE the `Abstract` section so the scoped
    `+`/`*` are inactive and `Int`'s own arithmetic is used unambiguously (as the frozen file does
    for its `Int` witnesses). -/

/-- `2` is not a square in `Int` (a fresh non-square modulus, distinct from Fp2's `−1`): from
    `(w·w).natAbs = w.natAbs²` and the fact that no natural number squares to `2`
    (`n ≤ 1 ⇒ n² ≤ 1`; `n ≥ 2 ⇒ n² ≥ 4`).  This certifies the degree-2 generalization is GENUINE —
    it fires at a modulus the frozen Fp2 result cannot express. -/
theorem int_no_sqrt_two : ∀ w : Int, w * w ≠ (2 : Int) := by
  intro w h
  have hnat : w.natAbs * w.natAbs = 2 := by
    have e : (w * w).natAbs = w.natAbs * w.natAbs := Int.natAbs_mul w w
    rw [h] at e
    have h2 : (2 : Int).natAbs = 2 := rfl
    rw [h2] at e
    exact e.symm
  rcases Nat.lt_or_ge w.natAbs 2 with hlt | hge
  · have hle : w.natAbs * w.natAbs ≤ 1 * 1 := Nat.mul_le_mul (by omega) (by omega)
    have h11 : (1 : Nat) * 1 = 1 := rfl
    rw [h11] at hle
    omega
  · have hge4 : 2 * 2 ≤ w.natAbs * w.natAbs := Nat.mul_le_mul hge hge
    have h22 : (2 : Nat) * 2 = 4 := rfl
    rw [h22] at hge4
    omega

/-- **The complete, hypothesis-free fact over `Int` at `d = 2`:** the minimum number of essential
    multiplications to compute the `Int[w]/(w²−2)` (degree-2 extension) multiplication tensor is
    EXACTLY 3 — achievability (a 3-product algorithm exists) AND optimality (none uses fewer).
    A concrete, machine-checked instance of `fp12_over_fp6_rank_ge_three` with `v = 2`, proving the
    tower-layer theorem is non-vacuous with a real positive bound. -/
theorem int_degExt_two_min_mults :
    (∃ ps : List (CRing.Mat2 Int),
      CRing.AllRank1 ps ∧ CRing.Computes ps (M0d (2 : Int))
        ∧ CRing.Computes ps CRing.M1 ∧ ps.length = 3)
    ∧ (∀ ps : List (CRing.Mat2 Int),
      CRing.AllRank1 ps → CRing.Computes ps (M0d (2 : Int))
        → CRing.Computes ps CRing.M1 → 3 ≤ ps.length) :=
  ⟨fp12_over_fp6_rank_le_three (2 : Int),
   fun ps hr h0 h1 => fp12_over_fp6_rank_ge_three (2 : Int) ps hr h0 h1 int_no_sqrt_two⟩

/-- The Fp12/Fp6 tower-layer bound, discharged over `Int` at the frozen `−1` witness too (reusing
    `int_no_sqrt_neg_one`), showing the hypothesis class is inhabited by the Fp2-recovering case. -/
theorem int_degExt_neg_one_rank_ge_three (ps : List (CRing.Mat2 Int)) (hr : CRing.AllRank1 ps)
    (h0 : CRing.Computes ps (M0d (CRing.neg CRing.one)))
    (h1 : CRing.Computes ps CRing.M1) : 3 ≤ ps.length :=
  fp12_over_fp6_rank_ge_three (CRing.neg CRing.one) ps hr h0 h1 int_no_sqrt_neg_one

#print axioms int_no_sqrt_two
#print axioms int_degExt_two_min_mults
#print axioms int_degExt_neg_one_rank_ge_three

/-
  ## OPEN (not proven here) — the Fp6/Fp2 degree-3 layer and the full fp12Mul Fp-mult floor.

  This file delivers the deg-2 tower layer: Fp12/Fp6 multiplication has rank EXACTLY 3 over Fp6
  (`fp12_over_fp6_rank_ge_three` / `_le_three`), generalizing the frozen Fp2 = deg-2/Fp result to an
  arbitrary non-square modulus and instantiating it at the tower element `v`.

  Still OPEN (honestly, not scaffolded with placeholder statements):
    * the Fp6 = Fp2[v]/(v³−ξ) deg-3 layer: de Groote's theorem gives rank(deg-n ext mult) = 2n−1, so
      rank(Fp6/Fp2) = 5, i.e. ≥ 5 over Fp2.  This needs the `Mat2` flattening generalized to the
      3-output / degree-3 structure tensor and a Lean-core lower-bound proof for a degree-2-poly
      product modulo a cubic — genuinely harder than the deg-2 substitution argument.
    * the tower-model composition (product of per-level rank lower bounds) down to Fp, yielding the
      essential-Fp-mult floor for `fp12Mul` / `fp12Sqr` / `mul034` to compare against the shipped
      74 / 52 / 49 mulFp.  That composition bounds algorithms CONSTRAINED to the tower (the shipped
      code IS such), NOT arbitrary algorithms — a boundary to state whenever it is cited.

  The reusable deg-2 engine (`M0d`, `det_M0d`, `scalar_contra_d`, `two_not_enough_d`,
  `degExt_rank_ge_three`) plus the frozen `CRing`/`Mat2`/pencil machinery are in place; the deg-3
  layer is the next target's work.
-/

end LeanBCH.Opt.DegreeExtRank
