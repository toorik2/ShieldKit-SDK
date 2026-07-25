/-
  LeanBCH.Opt.BilinearRankFloor — the bilinear-rank (essential-multiplication) FLOOR for
  the Fp2 multiplication tensor.  Piece B of the op-cost floor-prover (see
  `Opt/OpCostFloor_SCOPE.md`).

  ## What this file proves (the CRUX, kernel-checked, 0-sorry, axiom-clean)

  The number of ESSENTIAL field multiplications needed to compute a bilinear map equals its
  tensor rank.  For the Fp2 = F[i]/(i²+1) multiplication map

      (a0,a1,b0,b1) ↦ (a0·b0 − a1·b1 ,  a0·b1 + a1·b0)

  we prove, over ANY commutative ring `F` in which −1 is NOT a square (exactly the condition
  under which F[i]/(i²+1) is a field — e.g. the BN254 base field, p ≡ 3 mod 4), that:

    * `fp2_rank_ge_three` : every straight-line BILINEAR algorithm computing this map uses
       ≥ 3 scalar multiplications (tensor rank ≥ 3);
    * `fp2_rank_le_three` : Karatsuba/Winograd achieves it with exactly 3 (tensor rank ≤ 3).

  Hence the tensor rank is EXACTLY 3 — Winograd's classical "complex multiplication needs 3
  real multiplications", formalized in Lean core with NO mathlib.  The lower bound is the
  substitution / matrix-pencil argument: two rank-1 matrices whose span contains both output
  matrices M0, M1 would force −1 to be a square, contradiction.

  ## Model faithfulness

  A bilinear algorithm computing a bilinear map is a list of ESSENTIAL products
  `p_k = L_k(a)·N_k(b)` (each a product of an input-linear-combination of the a's by one of
  the b's), and each output form is a linear combination of the `p_k`.  Encoding the k-th
  product's coefficient table as the outer-product (hence rank-1) matrix `M[i][j] = coeff of
  a_i·b_j`, "computes M" ⇔ "M is in the F-span of the product matrices".  `IsRank1`,
  `combo`, `Computes` below encode exactly this — nothing weaker, nothing that lets the prover
  cheat: extra weights are ignored (the bound is only strengthened by being generous), the
  product count is the list length (an honest multiplication count).

  ## Non-vacuity

  The hypothesis `∀ w, w*w ≠ neg one` (−1 not a square) is satisfiable: `Int` is a witness
  (`int_no_sqrt_neg_one`) — squares are non-negative, so `w*w ≠ -1`.  Over `Int` the map is
  Gaussian-integer multiplication and `int_fp2_min_mults` states the FULL, hypothesis-free
  fact: the minimum is exactly 3 (achievability ∧ optimality).  The bound `3` is a real
  positive quantity; the hypotheses of every lower-bound theorem are demonstrably satisfiable.

  ## Honest scope boundary (do not launder)

  This audits "the fixed 2-3-2 tower's Fp2 layer is at its multiplication floor", NOT "no
  cheaper algorithm/representation/scheme exists".  The Fp6 (≥6 over Fp2) and Fp12 (≥3 over
  Fp6) tower-composition bounds are NOT proven here — see the OPEN note near the end.  This
  file is deliberately dependency-free (core Lean only); Piece C composition with
  `LeanBCH.Cost.Arith` lives in a separate file.
-/

namespace LeanBCH.Opt.BilinearRank

-- Style-only linters: the `ring1`/`ring2` closers deliberately pass a fixed, robust superset
-- of simp lemmas (some redundant on a given goal), and `Mat2.ext` does not use `[CRing F]`.
set_option linter.unusedSimpArgs false
set_option linter.unusedSectionVars false

/-! ## A minimal commutative-ring interface (Lean core has no `CommRing`) -/

/-- Commutative ring, stated by axioms.  The whole floor needs only the ring structure plus
    the hypothesis "−1 is not a square"; NO field inverses are used anywhere in the proof,
    so the bound holds over any commutative ring with that property (fields included). -/
class CRing (F : Type) where
  add : F → F → F
  mul : F → F → F
  neg : F → F
  zero : F
  one : F
  add_comm : ∀ a b, add a b = add b a
  add_assoc : ∀ a b c, add (add a b) c = add a (add b c)
  add_zero : ∀ a, add a zero = a
  zero_add : ∀ a, add zero a = a
  add_left_neg : ∀ a, add (neg a) a = zero
  mul_comm : ∀ a b, mul a b = mul b a
  mul_assoc : ∀ a b c, mul (mul a b) c = mul a (mul b c)
  mul_one : ∀ a, mul a one = a
  one_mul : ∀ a, mul one a = a
  mul_zero : ∀ a, mul a zero = zero
  zero_mul : ∀ a, mul zero a = zero
  left_distrib : ∀ a b c, mul a (add b c) = add (mul a b) (mul a c)
  right_distrib : ∀ a b c, mul (add a b) c = add (mul a c) (mul b c)

namespace CRing

variable {F : Type} [CRing F]

scoped infixl:65 " + " => CRing.add
scoped infixl:70 " * " => CRing.mul

/-! ## Derived ring lemmas + a `ring`-style normalizer built from them -/

theorem add_left_comm (a b c : F) : a + (b + c) = b + (a + c) := by
  rw [← add_assoc, add_comm a b, add_assoc]

theorem mul_left_comm (a b c : F) : a * (b * c) = b * (a * c) := by
  rw [← mul_assoc, mul_comm a b, mul_assoc]

theorem add_neg (a : F) : a + (neg a) = (zero : F) := by rw [add_comm]; exact add_left_neg a

theorem neg_unique {a b : F} (h : a + b = zero) : b = neg a := by
  calc b = zero + b := (zero_add _).symm
    _ = (neg a + a) + b := by rw [add_left_neg]
    _ = neg a + (a + b) := by rw [add_assoc]
    _ = neg a + zero := by rw [h]
    _ = neg a := add_zero _

theorem neg_mul (a b : F) : (neg a) * b = neg (a * b) :=
  neg_unique (by rw [← right_distrib, add_neg, zero_mul])

theorem mul_neg (a b : F) : a * (neg b) = neg (a * b) :=
  neg_unique (by rw [← left_distrib, add_neg, mul_zero])

theorem neg_zero : neg (zero : F) = zero := (neg_unique (add_zero zero)).symm

theorem neg_neg (a : F) : neg (neg a) = a := (neg_unique (add_left_neg a)).symm

theorem neg_add (a b : F) : neg (a + b) = (neg a) + (neg b) := by
  refine (neg_unique ?_).symm
  calc (a + b) + ((neg a) + (neg b))
      = a + (b + ((neg a) + (neg b))) := by rw [add_assoc]
    _ = a + ((b + (neg a)) + (neg b)) := by rw [add_assoc b (neg a) (neg b)]
    _ = a + (((neg a) + b) + (neg b)) := by rw [add_comm b (neg a)]
    _ = a + ((neg a) + (b + (neg b))) := by rw [add_assoc (neg a) b (neg b)]
    _ = a + ((neg a) + zero) := by rw [add_neg b]
    _ = a + (neg a) := by rw [add_zero]
    _ = zero := add_neg a

theorem add_left_cancel {a b c : F} (h : a + b = a + c) : b = c := by
  calc b = zero + b := (zero_add b).symm
    _ = (neg a + a) + b := by rw [add_left_neg]
    _ = neg a + (a + b) := add_assoc _ _ _
    _ = neg a + (a + c) := by rw [h]
    _ = (neg a + a) + c := (add_assoc _ _ _).symm
    _ = zero + c := by rw [add_left_neg]
    _ = c := zero_add c

theorem add_right_eq_self {a t : F} (h : a + t = a) : t = zero := by
  apply add_left_cancel (a := a); rw [add_zero]; exact h

/-- Commutative-ring polynomial-identity closer (no cancellation): distribute, push
    negations to leaves, AC-normalize.  Proves any identity of equal polynomials. -/
macro "ring1" : tactic => `(tactic|
  simp only [left_distrib, right_distrib, neg_mul, mul_neg, neg_add, neg_neg, neg_zero,
    mul_one, one_mul, mul_zero, zero_mul, add_zero, zero_add,
    mul_assoc, mul_comm, mul_left_comm, add_assoc, add_comm, add_left_comm])

/-- `ring1` plus additive cancellation of inverses (`a + neg a → 0`). -/
macro "ring2" : tactic => `(tactic|
  simp only [left_distrib, right_distrib, neg_mul, mul_neg, neg_add, neg_neg, neg_zero,
    mul_one, one_mul, mul_zero, zero_mul, add_zero, zero_add, add_left_neg, add_neg,
    mul_assoc, mul_comm, mul_left_comm, add_assoc, add_comm, add_left_comm])

/-! ## 2×2 matrices over `F` — the flattening of a 2-input/2-output bilinear form.
    Entry convention: `a = M[0][0]`, `b = M[0][1]`, `c = M[1][0]`, `d = M[1][1]`, where
    `M[i][j]` is the coefficient of the monomial `x_i · y_j`. -/

structure Mat2 (F : Type) where
  a : F
  b : F
  c : F
  d : F

/-- Scale a coefficient matrix (used as a bilinear-form linear combination). -/
def smul (x : F) (m : Mat2 F) : Mat2 F := ⟨x * m.a, x * m.b, x * m.c, x * m.d⟩

/-- Add two coefficient matrices. -/
def madd (m n : Mat2 F) : Mat2 F := ⟨m.a + n.a, m.b + n.b, m.c + n.c, m.d + n.d⟩

/-- The zero matrix. -/
def mzero : Mat2 F := ⟨zero, zero, zero, zero⟩

theorem Mat2.ext {m n : Mat2 F}
    (ha : m.a = n.a) (hb : m.b = n.b) (hc : m.c = n.c) (hd : m.d = n.d) : m = n := by
  cases m; cases n; simp_all

/-- 2×2 determinant `a·d − b·c` (with `−` spelled additively). -/
def det (m : Mat2 F) : F := m.a * m.d + neg (m.b * m.c)

/-- The off-diagonal bilinear pairing of two matrices: the `x·y` coefficient of
    `det (x•U + y•V)` once the pure `x²`, `y²` parts (their own determinants) are removed. -/
def bilK (U V : Mat2 F) : F := (U.a * V.d + V.a * U.d) + neg (U.b * V.c + V.b * U.c)

/-- A coefficient matrix has RANK ≤ 1 iff it is an outer product `p ⊗ q`.  This is EXACTLY
    the matrix of one essential product `(p0·a0 + p1·a1)·(q0·b0 + q1·b1)`. -/
def IsRank1 (m : Mat2 F) : Prop :=
  ∃ p0 p1 q0 q1 : F, m.a = p0 * q0 ∧ m.b = p0 * q1 ∧ m.c = p1 * q0 ∧ m.d = p1 * q1

/-! ## Determinant algebra: rank-1 ⇒ singular, and the pencil determinant identity -/

/-- Every rank-1 (outer-product) matrix is singular. -/
theorem rank1_det_zero {m : Mat2 F} (h : IsRank1 m) : det m = zero := by
  obtain ⟨p0, p1, q0, q1, ha, hb, hc, hd⟩ := h
  simp only [det, ha, hb, hc, hd]
  have e : (p0 * q1) * (p1 * q0) = (p0 * q0) * (p1 * q1) := by ring1
  rw [e]; exact add_neg _

/-- The determinant of a 2×2 pencil `x•U + y•V` expands as
    `x²·det U + y²·det V + x·y·bilK U V`.  (Pure polynomial identity in the 10 scalars.) -/
theorem det_smul_add (x y : F) (U V : Mat2 F) :
    det (madd (smul x U) (smul y V))
      = (x * x) * det U + ((y * y) * det V + (x * y) * bilK U V) := by
  simp only [det, madd, smul, bilK]
  ring1

/-- For rank-1 (singular) `U`, `V`, the pencil determinant collapses to the pure off-diagonal
    term `x·y·bilK U V`. -/
theorem det_combo_rank1 {U V : Mat2 F} (hU : det U = zero) (hV : det V = zero) (x y : F) :
    det (madd (smul x U) (smul y V)) = (x * y) * bilK U V := by
  rw [det_smul_add, hU, hV]
  simp only [mul_zero, zero_add]

/-! ## The Fp2 multiplication tensor as two coefficient matrices -/

/-- Real part `a0·b0 − a1·b1`  ↦  matrix `⟨1,0,0,−1⟩`. -/
def M0 : Mat2 F := ⟨one, zero, zero, neg one⟩

/-- Imaginary part `a0·b1 + a1·b0`  ↦  matrix `⟨0,1,1,0⟩`. -/
def M1 : Mat2 F := ⟨zero, one, one, zero⟩

theorem det_M0 : det (M0 : Mat2 F) = neg one := by
  simp only [det, M0]; ring1

theorem det_M1 : det (M1 : Mat2 F) = neg one := by
  simp only [det, M1]; ring1

theorem det_M0M1 : det (madd (M0 : Mat2 F) M1) = (neg one + neg one : F) := by
  simp only [det, madd, M0, M1]; ring1

/-- Combining the two outputs' pencil representations onto a shared pair of products. -/
theorem madd_combine (x0 y0 x1 y1 : F) (U V : Mat2 F) :
    madd (madd (smul x0 U) (smul y0 V)) (madd (smul x1 U) (smul y1 V))
      = madd (smul (x0 + x1) U) (smul (y0 + y1) V) := by
  apply Mat2.ext <;> · simp only [madd, smul]; ring1

/-! ## The substitution-method contradiction: two products cannot compute Fp2 mult -/

/-- The scalar heart of Winograd's lower bound.  If a single scalar `K` and weights
    `x0,y0,x1,y1` satisfy the three determinant equations forced by a 2-multiplication
    bilinear algorithm for Fp2, then `((x0·y1)·K)² = −1`, i.e. −1 is a square — impossible
    when `hns` holds. -/
theorem scalar_contra {K x0 y0 x1 y1 : F}
    (hns : ∀ w : F, w * w ≠ neg one)
    (E1 : (x0 * y0) * K = neg one)
    (E2 : (x1 * y1) * K = neg one)
    (E3 : ((x0 + x1) * (y0 + y1)) * K = (neg one + neg one : F)) : False := by
  have expand : ((x0 + x1) * (y0 + y1)) * K
      = ((x0 * y0) * K + (x1 * y1) * K) + ((x0 * y1) * K + (x1 * y0) * K) := by ring1
  rw [expand, E1, E2] at E3
  -- E3 : (neg one + neg one) + ((x0*y1)*K + (x1*y0)*K) = neg one + neg one
  have hPQ : (x0 * y1) * K + (x1 * y0) * K = zero := add_right_eq_self E3
  have hmul : ((x0 * y1) * K) * ((x1 * y0) * K) = one := by
    have e : ((x0 * y1) * K) * ((x1 * y0) * K) = ((x0 * y0) * K) * ((x1 * y1) * K) := by ring1
    rw [e, E1, E2]; ring1
  have hQ : (x1 * y0) * K = neg ((x0 * y1) * K) := neg_unique hPQ
  rw [hQ, mul_neg] at hmul
  -- hmul : neg (((x0*y1)*K) * ((x0*y1)*K)) = one
  have hsq : ((x0 * y1) * K) * ((x0 * y1) * K) = neg one := by
    rw [← neg_neg (((x0 * y1) * K) * ((x0 * y1) * K)), hmul]
  exact hns ((x0 * y1) * K) hsq

/-- **Two essential products are not enough.**  No pair of rank-1 matrices `U, V` has both
    Fp2-output matrices `M0`, `M1` in its F-span, provided −1 is not a square. -/
theorem two_not_enough {U V : Mat2 F} (hU : IsRank1 U) (hV : IsRank1 V)
    (x0 y0 x1 y1 : F)
    (hM0 : (M0 : Mat2 F) = madd (smul x0 U) (smul y0 V))
    (hM1 : (M1 : Mat2 F) = madd (smul x1 U) (smul y1 V))
    (hns : ∀ w : F, w * w ≠ neg one) : False := by
  have hUd : det U = zero := rank1_det_zero hU
  have hVd : det V = zero := rank1_det_zero hV
  have E1 : (x0 * y0) * bilK U V = neg one := by
    have h := det_M0 (F := F)
    rw [hM0, det_combo_rank1 hUd hVd x0 y0] at h
    exact h
  have E2 : (x1 * y1) * bilK U V = neg one := by
    have h := det_M1 (F := F)
    rw [hM1, det_combo_rank1 hUd hVd x1 y1] at h
    exact h
  have E3 : ((x0 + x1) * (y0 + y1)) * bilK U V = (neg one + neg one : F) := by
    have h := det_M0M1 (F := F)
    rw [hM0, hM1, madd_combine, det_combo_rank1 hUd hVd (x0 + x1) (y0 + y1)] at h
    exact h
  exact scalar_contra hns E1 E2 E3

/-! ## The bilinear-algorithm model and the rank ≥ 3 lower bound -/

/-- All products of the algorithm are essential (rank-1). -/
def AllRank1 (ps : List (Mat2 F)) : Prop := ∀ m ∈ ps, IsRank1 m

/-- The weighted sum of the products by a coefficient list.  (`zipWith` ignores surplus
    weights/products — this only makes the model MORE generous to the prover, so a lower
    bound proved here is a fortiori valid for the standard model with one weight per product.) -/
def combo (ws : List F) (ps : List (Mat2 F)) : Mat2 F :=
  (List.zipWith smul ws ps).foldr madd mzero

/-- `ps` COMPUTES matrix `M` iff some F-linear combination of its products equals `M`. -/
def Computes (ps : List (Mat2 F)) (M : Mat2 F) : Prop := ∃ ws : List F, M = combo ws ps

theorem combo_nil (ws : List F) : combo ws [] = (mzero : Mat2 F) := by
  simp only [combo, List.zipWith_nil_right, List.foldr_nil]

theorem combo_one (ws : List F) (u : Mat2 F) :
    ∃ x, combo ws [u] = madd (smul x u) mzero := by
  cases ws with
  | nil => exact ⟨zero, by
      simp only [combo, List.zipWith_nil_left, List.foldr_nil, madd, smul, mzero,
        zero_mul, add_zero, Mat2.mk.injEq, and_self]⟩
  | cons w0 ws1 => exact ⟨w0, by
      simp only [combo, List.zipWith_cons_cons, List.zipWith_nil_right,
        List.foldr_cons, List.foldr_nil]⟩

theorem combo_two (ws : List F) (u v : Mat2 F) :
    ∃ x y, combo ws [u, v] = madd (smul x u) (smul y v) := by
  cases ws with
  | nil => exact ⟨zero, zero, by
      simp only [combo, List.zipWith_nil_left, List.foldr_nil, madd, smul, mzero,
        zero_mul, add_zero, Mat2.mk.injEq, and_self]⟩
  | cons w0 ws1 =>
    cases ws1 with
    | nil => exact ⟨w0, zero, by
        simp only [combo, List.zipWith_cons_cons, List.zipWith_nil_left, List.zipWith_nil_right,
          List.foldr_cons, List.foldr_nil, madd, smul, mzero, zero_mul, add_zero,
          Mat2.mk.injEq, and_self]⟩
    | cons w1 ws2 => exact ⟨w0, w1, by
        simp only [combo, List.zipWith_cons_cons, List.zipWith_nil_right,
          List.foldr_cons, List.foldr_nil, madd, smul, mzero, add_zero]⟩

theorem smul_mzero (x : F) : smul x (mzero : Mat2 F) = mzero := by
  apply Mat2.ext <;> simp only [smul, mzero, mul_zero]

theorem rank1_mzero : IsRank1 (mzero : Mat2 F) :=
  ⟨zero, zero, zero, zero,
    (zero_mul zero).symm, (zero_mul zero).symm, (zero_mul zero).symm, (zero_mul zero).symm⟩

/-- **Fp2 multiplication has tensor rank ≥ 3.**  Every bilinear algorithm (list of essential
    rank-1 products) whose F-span contains both Fp2 output matrices `M0`, `M1` uses at least
    three products — provided −1 is not a square in `F` (the condition making `F[i]/(i²+1)` a
    field).  This is a genuine non-existence *theorem*: no 2-, 1-, or 0-product schedule
    exists, kernel-checked. -/
theorem fp2_rank_ge_three (ps : List (Mat2 F)) (hr : AllRank1 ps)
    (h0 : Computes ps M0) (h1 : Computes ps M1)
    (hns : ∀ w : F, w * w ≠ neg one) : 3 ≤ ps.length := by
  rcases ps with _ | ⟨u, _ | ⟨v, _ | ⟨w, rest⟩⟩⟩
  · -- ps = [] : the span is {0}, but M0 ≠ 0 (its (0,0) entry is 1 ≠ 0).
    exfalso
    obtain ⟨ws, hw⟩ := h0
    rw [combo_nil] at hw
    have hone : (one : F) = zero := congrArg Mat2.a hw
    have hn : neg (one : F) = zero := by rw [hone]; exact neg_zero
    exact hns zero (by rw [zero_mul, hn])
  · -- ps = [u] : pad with the zero product; two_not_enough with V = mzero.
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
    exact two_not_enough hu rank1_mzero a0 zero a1 zero hw0 hw1 hns
  · -- ps = [u, v] : the crux case, direct two_not_enough.
    exfalso
    have hu : IsRank1 u := hr u (by simp)
    have hv : IsRank1 v := hr v (by simp)
    obtain ⟨ws0, hw0⟩ := h0
    obtain ⟨ws1, hw1⟩ := h1
    obtain ⟨a0, b0, ha0⟩ := combo_two ws0 u v
    obtain ⟨a1, b1, ha1⟩ := combo_two ws1 u v
    rw [ha0] at hw0
    rw [ha1] at hw1
    exact two_not_enough hu hv a0 b0 a1 b1 hw0 hw1 hns
  · -- ps has length ≥ 3 : the bound holds directly.
    simp only [List.length_cons]
    omega

/-! ## Tightness: Karatsuba/Winograd achieves 3 (tensor rank ≤ 3, hence = 3) -/

/-- Product `a0·b0`  ↦  outer product `(1,0)⊗(1,0)`. -/
def K1 : Mat2 F := ⟨one, zero, zero, zero⟩
/-- Product `a1·b1`  ↦  outer product `(0,1)⊗(0,1)`. -/
def K2 : Mat2 F := ⟨zero, zero, zero, one⟩
/-- Product `(a0+a1)·(b0+b1)`  ↦  outer product `(1,1)⊗(1,1)`. -/
def K3 : Mat2 F := ⟨one, one, one, one⟩

/-- The 3-product Karatsuba/Winograd schedule for Fp2 multiplication. -/
def karatsuba : List (Mat2 F) := [K1, K2, K3]

theorem karatsuba_rank1 : AllRank1 (karatsuba : List (Mat2 F)) := by
  intro m hm
  simp only [karatsuba, List.mem_cons, List.not_mem_nil, or_false] at hm
  rcases hm with h | h | h <;> subst h
  · exact ⟨one, zero, one, zero,
      by simp only [K1]; ring1, by simp only [K1]; ring1,
      by simp only [K1]; ring1, by simp only [K1]; ring1⟩
  · exact ⟨zero, one, zero, one,
      by simp only [K2]; ring1, by simp only [K2]; ring1,
      by simp only [K2]; ring1, by simp only [K2]; ring1⟩
  · exact ⟨one, one, one, one,
      by simp only [K3]; ring1, by simp only [K3]; ring1,
      by simp only [K3]; ring1, by simp only [K3]; ring1⟩

theorem karatsuba_computes_M0 : Computes (karatsuba : List (Mat2 F)) M0 := by
  refine ⟨[one, neg one, zero], ?_⟩
  simp only [karatsuba, combo, List.zipWith_cons_cons, List.zipWith_nil_left,
    List.zipWith_nil_right, List.foldr_cons, List.foldr_nil, smul, madd, mzero, M0,
    K1, K2, K3, Mat2.mk.injEq]
  refine ⟨?_, ?_, ?_, ?_⟩ <;> ring2

theorem karatsuba_computes_M1 : Computes (karatsuba : List (Mat2 F)) M1 := by
  refine ⟨[neg one, neg one, one], ?_⟩
  simp only [karatsuba, combo, List.zipWith_cons_cons, List.zipWith_nil_left,
    List.zipWith_nil_right, List.foldr_cons, List.foldr_nil, smul, madd, mzero, M1,
    K1, K2, K3, Mat2.mk.injEq]
  refine ⟨?_, ?_, ?_, ?_⟩ <;> ring2

theorem karatsuba_length : (karatsuba : List (Mat2 F)).length = 3 := rfl

/-- **Fp2 multiplication has tensor rank ≤ 3.**  An explicit 3-product bilinear algorithm
    (Karatsuba/Winograd) computes both output matrices over any commutative ring. -/
theorem fp2_rank_le_three :
    ∃ ps : List (Mat2 F), AllRank1 ps ∧ Computes ps M0 ∧ Computes ps M1 ∧ ps.length = 3 :=
  ⟨karatsuba, karatsuba_rank1, karatsuba_computes_M0, karatsuba_computes_M1, karatsuba_length⟩

#print axioms fp2_rank_ge_three
#print axioms fp2_rank_le_three
#print axioms two_not_enough
#print axioms karatsuba_computes_M0
#print axioms karatsuba_computes_M1
#print axioms karatsuba_rank1

end CRing

/-! ## Concrete non-vacuity witness: the ring `Int` (Gaussian-integer multiplication).
    Stated OUTSIDE `namespace CRing` so the scoped `+`/`*` are inactive and `Int`'s own
    arithmetic is used unambiguously. -/

instance : CRing Int where
  add := Int.add
  mul := Int.mul
  neg := Int.neg
  zero := 0
  one := 1
  add_comm := Int.add_comm
  add_assoc := Int.add_assoc
  add_zero := Int.add_zero
  zero_add := Int.zero_add
  add_left_neg := Int.add_left_neg
  mul_comm := Int.mul_comm
  mul_assoc := Int.mul_assoc
  mul_one := Int.mul_one
  one_mul := Int.one_mul
  mul_zero := Int.mul_zero
  zero_mul := Int.zero_mul
  left_distrib := Int.mul_add
  right_distrib := Int.add_mul

/-- `Int` satisfies the standing hypothesis: −1 is not a square (every square is ≥ 0).  Hence
    every lower-bound theorem above is NON-VACUOUS — the hypothesis class is inhabited by a
    concrete, machine-checked ring, and the map is genuine (Gaussian-integer multiplication). -/
theorem int_no_sqrt_neg_one : ∀ w : Int, CRing.mul w w ≠ CRing.neg (CRing.one) := by
  intro w hcontra
  have h : w * w = -1 := hcontra
  have hnn : 0 ≤ w * w := by
    rcases Int.le_total 0 w with hw | hw
    · exact Int.mul_nonneg hw hw
    · have hpos : (0 : Int) ≤ (-w) * (-w) := Int.mul_nonneg (by omega) (by omega)
      rw [Int.neg_mul_neg] at hpos; omega
  omega

/-- The rank ≥ 3 bound, discharged over `Int` (no remaining hypothesis). -/
theorem fp2_rank_ge_three_int (ps : List (CRing.Mat2 Int)) (hr : CRing.AllRank1 ps)
    (h0 : CRing.Computes ps CRing.M0) (h1 : CRing.Computes ps CRing.M1) : 3 ≤ ps.length :=
  CRing.fp2_rank_ge_three ps hr h0 h1 int_no_sqrt_neg_one

/-- **The complete, hypothesis-free fact over `Int`:** the minimum number of essential
    multiplications to compute Fp2-style multiplication is EXACTLY 3 — achievability
    (a 3-product algorithm exists) AND optimality (none uses fewer). -/
theorem int_fp2_min_mults :
    (∃ ps : List (CRing.Mat2 Int),
      CRing.AllRank1 ps ∧ CRing.Computes ps CRing.M0 ∧ CRing.Computes ps CRing.M1
        ∧ ps.length = 3)
    ∧ (∀ ps : List (CRing.Mat2 Int),
      CRing.AllRank1 ps → CRing.Computes ps CRing.M0 → CRing.Computes ps CRing.M1
        → 3 ≤ ps.length) :=
  ⟨CRing.fp2_rank_le_three, fp2_rank_ge_three_int⟩

/-
  ## OPEN (not proven here) — tower composition to Fp6 / Fp12

  The scope asks, if tractable, to compose the Fp2 rank to Fp6 (= Fp2[v]/(v³−ξ), rank ≥ 6 over
  Fp2) and Fp12 (= Fp6[w]/(w²−v), rank ≥ 3 over Fp6), then down to Fp via rank
  (super-additivity / sub-multiplicativity) to bound `fp12Mul`/`fp12Sqr`/`mul034`.

  HONEST STATUS: those bounds are NOT established in this file.  Doing so rigorously requires
  (a) generalizing the `Mat2` flattening to n×n / n-output structure tensors, (b) writing the
  Fp6 and Fp12 multiplication tensors from the tower relations, and (c) a Lean-core proof of a
  rank lower bound for a degree-2-poly product modulo a cubic (Fp6) and the composition
  theorem — this is genuine algebraic-complexity formalization beyond the elementary Fp2 case.
  We deliberately do NOT scaffold it with placeholder/vacuous definitions (per the project's
  no-placeholder rule): what is above is exactly what is proven.  The Fp2 result is the
  substitution-method CRUX and the reusable engine (`CRing`, `Mat2`, `det`, `IsRank1`,
  `Computes`, `two_not_enough`) for that future work.
-/

#print axioms int_fp2_min_mults
#print axioms int_no_sqrt_neg_one
#print axioms fp2_rank_ge_three_int

end LeanBCH.Opt.BilinearRank
