/-
  LeanBCH.Opt.Fp6RankFloor — the bilinear-rank (essential-multiplication) FLOOR for the
  Fp6 = Fp2[v]/(v³−ξ) multiplication tensor, as a DEGREE-3 Fp2-algebra.  This is TARGET B
  of the tower floor-prover (see `Opt/OpCostFloor_SCOPE.md`): de Groote's bound
  rank(degree-n field extension) = 2n−1, here n = 3, so rank ≥ 5.

  ## What this file proves (kernel-checked, 0-sorry, axioms ⊆ {propext, Quot.sound,
  ## Classical.choice} — `Classical.choice` only via the `by_cases` in `common_kernel_two`;
  ## `f7_is_domain` is pure `propext`)

  Fp6-multiplication multiplies two degree-≤2 polynomials over Fp2 modulo the cubic v³−ξ:
  a map (Fp2)³ × (Fp2)³ → (Fp2)³,

      c0 = a0·b0 + ξ·(a1·b2 + a2·b1)
      c1 = a0·b1 + a1·b0 + ξ·(a2·b2)
      c2 = a0·b2 + a1·b1 + a2·b0.

  We work over ANY commutative ring `F` (the base Fp2, reusing the `CRing` interface FROZEN in
  `Opt/BilinearRankFloor.lean`), and prove:

    * `fp6_rank_ge_five` : every BILINEAR algorithm (list of essential products
       `p_l = ⟨u_l,a⟩·⟨v_l,b⟩` accumulating `w_l` into the output) that computes this map uses
       ≥ 5 scalar (Fp2-)multiplications — tensor rank ≥ 5 — provided `F` is NONTRIVIAL and the
       algebra Fp6 is a DOMAIN (`a,b ≠ 0 ⟹ a·b ≠ 0`, i.e. v³−ξ is irreducible / ξ is a
       non-cube: exactly the condition making Fp2[v]/(v³−ξ) a field, e.g. the BN254 tower).

  This is the tight de Groote bound 2·3−1 = 5, the CRUX of the tower (harder than the
  degree-2 Fp2 rank-3 result).  It supersedes the SCOPE's provisional "Fp6 ≥ 6" overestimate.

  ## The proof (Fiduccia–Zalcstein / de Groote, in its cleanest form)

  Suppose a bilinear algorithm with r ≤ 4 products computes the map.  The essential idea:
  pick the LEFT input `a` in the common kernel of the first two products' left-forms
  (`⟨u_1,a⟩ = ⟨u_2,a⟩ = 0`), and the RIGHT input `b` in the common kernel of the last two
  products' right-forms (`⟨v_3,b⟩ = ⟨v_4,b⟩ = 0`).  Two linear forms on the 3-dimensional
  space `F³` always have a nonzero common kernel (`common_kernel_two`, the algebraic crux —
  a nonzero vector orthogonal to two given vectors, e.g. their cross product), so `a ≠ 0` and
  `b ≠ 0` exist.  Then EVERY product vanishes (each is killed either by `a` or by `b`), so the
  algorithm outputs `0`.  But `a·b ≠ 0` (Fp6 is a domain), and the algorithm is supposed to
  output `a·b` — contradiction.  Hence r ≥ 5.  No determinants, no norm form: only the
  common-kernel lemma (used twice) and the domain property.  The argument generalizes to
  rank ≥ 2n−1 for any degree-n extension (kill n−1 products via `a`, n−1 via `b`).

  ## Model faithfulness (nothing that lets the prover cheat)

  A bilinear algorithm is a `List` of gates `(u, v, w) : F³ × F³ × F³`, each ONE essential
  product `⟨u,a⟩·⟨v,b⟩` (an input-linear-form of `a` times one of `b`), accumulating `w·p`
  into the 3-vector output.  `Bmap` evaluates it; `Computes` says it equals `mulFp6` on ALL
  inputs.  The multiplication COUNT is the list length — an honest count.  This is exactly the
  tensor-rank model (`t = Σ_l u_l ⊗ v_l ⊗ w_l`), the same modelling philosophy as the FROZEN
  Fp2 file's `IsRank1`/`Computes`.

  ## Non-vacuity (the hypotheses are inhabited by a concrete, machine-checked ring)

  Over `F = 𝔽₇ = Fin 7` with `ξ = 2` (a non-cube mod 7, so `𝔽₇[v]/(v³−2) = 𝔽₇₃₄₃` is a
  field), the domain hypothesis is a finite fact discharged by `decide` (`f7_is_domain`), and
  `f7_fp6_rank_ge_five` states the rank ≥ 5 bound with NO remaining hypotheses.  So every
  lower-bound theorem here is genuinely non-vacuous.

  ## Honest scope boundary (do not launder)

  This audits "the fixed 2-3-2 tower's Fp6 layer is at its multiplication floor over Fp2",
  i.e. any TOWER-STRUCTURED implementation (each Fp6-mult built from Fp2-mults — which the
  shipped code IS) — NOT "no cheaper algorithm/representation/scheme for the whole of fp12Mul
  exists".  Composition down to Fp and the shipped 74/52/49 counts live in the Piece-C file.

  Dependency-free beyond the FROZEN `BilinearRankFloor` (its `CRing` interface + ring lemmas).
-/
import LeanBCH.Opt.BilinearRankFloor

namespace LeanBCH.Opt.Fp6Rank

open LeanBCH.Opt.BilinearRank
open LeanBCH.Opt.BilinearRank.CRing

set_option linter.unusedSimpArgs false
set_option linter.unusedSectionVars false

variable {F : Type} [CRing F]

/-! ## 3-vectors over the base ring `F` (= Fp2), and the algebra operations -/

/-- A 3-vector: the coordinate representation of an Fp6 element in the basis `{1, v, v²}`. -/
structure Vec3 (F : Type) where
  v0 : F
  v1 : F
  v2 : F
  deriving DecidableEq

/-- The zero vector. -/
def vzero : Vec3 F := ⟨zero, zero, zero⟩

/-- The unit `1 = (1,0,0)`. -/
def e0 : Vec3 F := ⟨one, zero, zero⟩

/-- Vector addition. -/
def vadd (x y : Vec3 F) : Vec3 F := ⟨x.v0 + y.v0, x.v1 + y.v1, x.v2 + y.v2⟩

/-- Scalar multiple of a vector. -/
def vsmul (c : F) (x : Vec3 F) : Vec3 F := ⟨c * x.v0, c * x.v1, c * x.v2⟩

/-- The standard bilinear pairing `⟨u,a⟩ = u0·a0 + u1·a1 + u2·a2` (a linear form applied). -/
def dot (u a : Vec3 F) : F := (u.v0 * a.v0 + u.v1 * a.v1) + u.v2 * a.v2

/-- Fp6 multiplication `a·b mod (v³−ξ)` as a map on coordinate 3-vectors, parametric in `ξ`. -/
def mulFp6 (xi : F) (a b : Vec3 F) : Vec3 F :=
  ⟨ a.v0 * b.v0 + xi * (a.v1 * b.v2 + a.v2 * b.v1),
    (a.v0 * b.v1 + a.v1 * b.v0) + xi * (a.v2 * b.v2),
    (a.v0 * b.v2 + a.v1 * b.v1) + a.v2 * b.v0 ⟩

/-! ## Basic vector lemmas -/

theorem Vec3.ext {x y : Vec3 F} (h0 : x.v0 = y.v0) (h1 : x.v1 = y.v1) (h2 : x.v2 = y.v2) :
    x = y := by cases x; cases y; simp_all

/-- A vector with a nonzero first coordinate is nonzero. -/
theorem ne_vzero_of_v0 {a : Vec3 F} (h : a.v0 ≠ zero) : a ≠ (vzero : Vec3 F) := by
  intro heq; subst heq; exact h rfl

theorem ne_vzero_of_v1 {a : Vec3 F} (h : a.v1 ≠ zero) : a ≠ (vzero : Vec3 F) := by
  intro heq; subst heq; exact h rfl

theorem ne_vzero_of_v2 {a : Vec3 F} (h : a.v2 ≠ zero) : a ≠ (vzero : Vec3 F) := by
  intro heq; subst heq; exact h rfl

theorem e0_ne_vzero (hnt : (one : F) ≠ zero) : (e0 : Vec3 F) ≠ vzero :=
  ne_vzero_of_v0 (by simpa only [e0] using hnt)

theorem dot_vzero (a : Vec3 F) : dot (vzero : Vec3 F) a = zero := by
  simp only [dot, vzero, zero_mul, add_zero]

theorem vsmul_zero (x : Vec3 F) : vsmul (zero : F) x = vzero := by
  apply Vec3.ext <;> simp only [vsmul, vzero, zero_mul]

theorem vzero_vadd (x : Vec3 F) : vadd (vzero : Vec3 F) x = x := by
  apply Vec3.ext <;> simp only [vadd, vzero, zero_add]

/-! ## Two ring helpers -/

/-- If `neg x = 0` then `x = 0`. -/
theorem eq_zero_of_neg_eq_zero {x : F} (h : neg x = zero) : x = zero := by
  rw [← neg_neg x, h, neg_zero]

/-- `x + neg y = 0 ⟹ x = y`. -/
theorem eq_of_add_neg_eq_zero {x y : F} (h : x + neg y = zero) : x = y := by
  have h2 : neg y = neg x := neg_unique h
  have h3 : y = x := by rw [← neg_neg y, h2, neg_neg]
  exact h3.symm

/-! ## The additive 6-term canceller (robust closer for the degree-3 cross identities) -/

/-- Any sum of three terms and their negations telescopes to zero. -/
theorem cancel6 (a b c : F) :
    a + (b + (c + (neg a + (neg b + neg c)))) = (zero : F) := by
  have h : a + (b + (c + (neg a + (neg b + neg c))))
         = (a + neg a) + ((b + neg b) + (c + neg c)) := by
    simp only [add_assoc, add_left_comm, add_comm]
  rw [h, add_neg, add_neg, add_neg, add_zero, add_zero]

/-! ## The cross product and its orthogonality (the algebraic heart of `common_kernel_two`) -/

/-- The cross product `u × w`.  Orthogonal to both `u` and `w` over any commutative ring. -/
def cross (u w : Vec3 F) : Vec3 F :=
  ⟨ u.v1 * w.v2 + neg (u.v2 * w.v1),
    u.v2 * w.v0 + neg (u.v0 * w.v2),
    u.v0 * w.v1 + neg (u.v1 * w.v0) ⟩

/-- `⟨u, u × w⟩ = 0` (repeated-row determinant vanishes). -/
theorem dot_cross_left (u w : Vec3 F) : dot u (cross u w) = (zero : F) := by
  simp only [dot, cross, left_distrib, mul_neg, mul_assoc, mul_comm, mul_left_comm]
  rw [← cancel6 (F := F) (w.v0 * (u.v1 * u.v2)) (u.v0 * (u.v1 * w.v2)) (u.v0 * (w.v1 * u.v2))]
  simp only [add_assoc, add_left_comm, add_comm]

/-- `⟨w, u × w⟩ = 0`. -/
theorem dot_cross_right (u w : Vec3 F) : dot w (cross u w) = (zero : F) := by
  simp only [dot, cross, left_distrib, mul_neg, mul_assoc, mul_comm, mul_left_comm]
  rw [← cancel6 (F := F) (w.v0 * (u.v1 * w.v2)) (w.v0 * (w.v1 * u.v2)) (u.v0 * (w.v1 * w.v2))]
  simp only [add_assoc, add_left_comm, add_comm]

/-! ## Degenerate case of the common kernel: coordinate "rotations" (zero-coordinate
    kernel vectors), used when `u × w = 0`.  Each `rot` is orthogonal to its own vector
    (antisymmetry) and, using a vanishing 2×2 minor, to the other. -/

/-- `⟨neg x1, x0, 0⟩` — orthogonal to `x`, nonzero when `(x0,x1) ≠ 0`. -/
def rot01 (x : Vec3 F) : Vec3 F := ⟨neg x.v1, x.v0, zero⟩

/-- `⟨0, neg x2, x1⟩` — orthogonal to `x`, nonzero when `(x1,x2) ≠ 0`. -/
def rot12 (x : Vec3 F) : Vec3 F := ⟨zero, neg x.v2, x.v1⟩

theorem dot_rot01_self (x : Vec3 F) : dot x (rot01 x) = (zero : F) := by
  simp only [dot, rot01, mul_neg, mul_zero, add_zero]
  rw [mul_comm x.v1 x.v0]; exact add_left_neg _

theorem dot_rot12_self (x : Vec3 F) : dot x (rot12 x) = (zero : F) := by
  simp only [dot, rot12, mul_neg, mul_zero, zero_add]
  rw [mul_comm x.v2 x.v1]; exact add_left_neg _

/-- Orthogonality of `rot01 u` to `w`, given the minor `u0·w1 = u1·w0`. -/
theorem dot_rot01_other {u w : Vec3 F} (m2 : u.v0 * w.v1 = u.v1 * w.v0) :
    dot w (rot01 u) = (zero : F) := by
  simp only [dot, rot01, mul_neg, mul_zero, add_zero]
  have e : w.v1 * u.v0 = w.v0 * u.v1 := by
    rw [mul_comm w.v1 u.v0, m2, mul_comm u.v1 w.v0]
  rw [e]; exact add_left_neg _

/-- Orthogonality of `rot12 u` to `w`, given the minor `u1·w2 = u2·w1`. -/
theorem dot_rot12_other {u w : Vec3 F} (m0 : u.v1 * w.v2 = u.v2 * w.v1) :
    dot w (rot12 u) = (zero : F) := by
  simp only [dot, rot12, mul_neg, mul_zero, zero_add]
  have e : w.v2 * u.v1 = w.v1 * u.v2 := by
    rw [mul_comm w.v2 u.v1, m0, mul_comm u.v2 w.v1]
  rw [e]; exact add_left_neg _

theorem rot01_ne_of_v0 {x : Vec3 F} (h : x.v0 ≠ zero) : rot01 x ≠ (vzero : Vec3 F) :=
  ne_vzero_of_v1 (by simpa only [rot01] using h)

theorem rot01_ne_of_v1 {x : Vec3 F} (h : x.v1 ≠ zero) : rot01 x ≠ (vzero : Vec3 F) :=
  ne_vzero_of_v0 (by simpa only [rot01] using fun hc => h (eq_zero_of_neg_eq_zero hc))

theorem rot12_ne_of_v2 {x : Vec3 F} (h : x.v2 ≠ zero) : rot12 x ≠ (vzero : Vec3 F) :=
  ne_vzero_of_v1 (by simpa only [rot12] using fun hc => h (eq_zero_of_neg_eq_zero hc))

/-! ## The crux: two linear forms on `F³` have a nonzero common kernel. -/

/-- **Common kernel of two forms.**  For any `u, w : F³` there is a NONZERO `a : F³` with
    `⟨u,a⟩ = ⟨w,a⟩ = 0`.  (Two homogeneous linear equations in three unknowns always have a
    nonzero solution.)  Constructive: the cross product `u × w` when it is nonzero, else a
    coordinate rotation.  Needs `F` nontrivial only for the fully-degenerate `u = w = 0`. -/
theorem common_kernel_two (hnt : (one : F) ≠ zero) (u w : Vec3 F) :
    ∃ a : Vec3 F, a ≠ vzero ∧ dot u a = zero ∧ dot w a = zero := by
  by_cases hcr : cross u w = vzero
  · -- Degenerate: `u × w = 0`, so the three 2×2 minors vanish.
    have m0 : u.v1 * w.v2 = u.v2 * w.v1 :=
      eq_of_add_neg_eq_zero (by have h := congrArg Vec3.v0 hcr; simpa only [cross, vzero] using h)
    have m2 : u.v0 * w.v1 = u.v1 * w.v0 :=
      eq_of_add_neg_eq_zero (by have h := congrArg Vec3.v2 hcr; simpa only [cross, vzero] using h)
    by_cases hu : u = vzero
    · -- u = 0: need a nonzero kernel of `w` alone.
      by_cases hw : w = vzero
      · -- u = w = 0: any nonzero vector works.
        exact ⟨e0, e0_ne_vzero hnt, by rw [hu]; exact dot_vzero _, by rw [hw]; exact dot_vzero _⟩
      · -- w ≠ 0: use a rotation of `w` (self-orthogonal), trivially ⊥ u = 0.
        by_cases hw0 : w.v0 = zero
        · by_cases hw1 : w.v1 = zero
          · -- w0 = w1 = 0 ⟹ w2 ≠ 0.
            have hw2 : w.v2 ≠ zero := fun h2 => hw (Vec3.ext hw0 hw1 h2)
            exact ⟨rot12 w, rot12_ne_of_v2 hw2, by rw [hu]; exact dot_vzero _, dot_rot12_self w⟩
          · exact ⟨rot01 w, rot01_ne_of_v1 hw1, by rw [hu]; exact dot_vzero _, dot_rot01_self w⟩
        · exact ⟨rot01 w, rot01_ne_of_v0 hw0, by rw [hu]; exact dot_vzero _, dot_rot01_self w⟩
    · -- u ≠ 0: use a rotation of `u`; ⊥ u by antisymmetry, ⊥ w by the minor.
      by_cases hu0 : u.v0 = zero
      · by_cases hu1 : u.v1 = zero
        · -- u0 = u1 = 0 ⟹ u2 ≠ 0; use rot12 u.
          have hu2 : u.v2 ≠ zero := fun h2 => hu (Vec3.ext hu0 hu1 h2)
          exact ⟨rot12 u, rot12_ne_of_v2 hu2, dot_rot12_self u, dot_rot12_other m0⟩
        · exact ⟨rot01 u, rot01_ne_of_v1 hu1, dot_rot01_self u, dot_rot01_other m2⟩
      · exact ⟨rot01 u, rot01_ne_of_v0 hu0, dot_rot01_self u, dot_rot01_other m2⟩
  · -- Nondegenerate: the cross product itself is a nonzero common kernel vector.
    exact ⟨cross u w, hcr, dot_cross_left u w, dot_cross_right u w⟩

/-! ## The bilinear-algorithm model and the rank ≥ 5 lower bound -/

/-- The evaluation of a bilinear algorithm: a `List` of gates `(u, v, w)`, each contributing
    the essential product `⟨u,a⟩·⟨v,b⟩` scaled into `w`, summed into the 3-vector output.
    The list LENGTH is the number of essential (Fp2-)multiplications. -/
def Bmap (gates : List (Vec3 F × Vec3 F × Vec3 F)) (a b : Vec3 F) : Vec3 F :=
  gates.foldr (fun g acc => vadd (vsmul (dot g.1 a * dot g.2.1 b) g.2.2) acc) vzero

/-- `gates` COMPUTES the Fp6(ξ)-multiplication map iff it agrees with `mulFp6 ξ` on ALL
    inputs. -/
def Computes (xi : F) (gates : List (Vec3 F × Vec3 F × Vec3 F)) : Prop :=
  ∀ a b, Bmap gates a b = mulFp6 xi a b

/-- **Fp6 multiplication has tensor rank ≥ 5 (de Groote, `2·3−1`).**  Every bilinear algorithm
    computing the degree-3 extension multiplication map `mulFp6 ξ` uses at least five essential
    scalar multiplications — provided `F` is nontrivial and `Fp6 = F[v]/(v³−ξ)` is a DOMAIN
    (the condition making it a field: `ξ` a non-cube).  A genuine non-existence theorem: no
    4-, 3-, 2-, 1-, or 0-product schedule exists, kernel-checked. -/
theorem fp6_rank_ge_five {xi : F} (hnt : (one : F) ≠ zero)
    (hdom : ∀ a b : Vec3 F, a ≠ vzero → b ≠ vzero → mulFp6 xi a b ≠ vzero)
    (gates : List (Vec3 F × Vec3 F × Vec3 F)) (hc : Computes xi gates) :
    5 ≤ gates.length := by
  rcases gates with _ | ⟨⟨u1, v1, w1⟩, _ | ⟨⟨u2, v2, w2⟩, _ | ⟨⟨u3, v3, w3⟩,
      _ | ⟨⟨u4, v4, w4⟩, _ | ⟨g5, rest⟩⟩⟩⟩⟩
  · -- length 0 : empty algorithm outputs 0, but `1·1 = 1 ≠ 0`.
    exfalso
    have hb := e0_ne_vzero hnt
    have h := hc e0 e0
    simp only [Bmap, List.foldr_nil] at h
    exact hdom e0 e0 hb hb h.symm
  · -- length 1 : kill the one gate via `a`.
    exfalso
    obtain ⟨a, ha, ha1, _⟩ := common_kernel_two hnt u1 u1
    have h := hc a e0
    simp only [Bmap, List.foldr_cons, List.foldr_nil, ha1,
      zero_mul, mul_zero, vsmul_zero, vzero_vadd] at h
    exact hdom a e0 ha (e0_ne_vzero hnt) h.symm
  · -- length 2 : kill both gates via `a`.
    exfalso
    obtain ⟨a, ha, ha1, ha2⟩ := common_kernel_two hnt u1 u2
    have h := hc a e0
    simp only [Bmap, List.foldr_cons, List.foldr_nil, ha1, ha2,
      zero_mul, mul_zero, vsmul_zero, vzero_vadd] at h
    exact hdom a e0 ha (e0_ne_vzero hnt) h.symm
  · -- length 3 : kill g1,g2 via `a`, g3 via `b`.
    exfalso
    obtain ⟨a, ha, ha1, ha2⟩ := common_kernel_two hnt u1 u2
    obtain ⟨b, hb, hb3, _⟩ := common_kernel_two hnt v3 v3
    have h := hc a b
    simp only [Bmap, List.foldr_cons, List.foldr_nil, ha1, ha2, hb3,
      zero_mul, mul_zero, vsmul_zero, vzero_vadd] at h
    exact hdom a b ha hb h.symm
  · -- length 4 : kill g1,g2 via `a`, g3,g4 via `b`.  The crux `4 = 2 + 2` split.
    exfalso
    obtain ⟨a, ha, ha1, ha2⟩ := common_kernel_two hnt u1 u2
    obtain ⟨b, hb, hb3, hb4⟩ := common_kernel_two hnt v3 v4
    have h := hc a b
    simp only [Bmap, List.foldr_cons, List.foldr_nil, ha1, ha2, hb3, hb4,
      zero_mul, mul_zero, vsmul_zero, vzero_vadd] at h
    exact hdom a b ha hb h.symm
  · -- length ≥ 5 : the bound holds directly.
    simp only [List.length_cons]
    omega

/-! ## Achievability: the schoolbook algorithm computes the map with 9 products.
    This proves `Computes` is INHABITED (so `fp6_rank_ge_five`'s `∀`-over-algorithms is not
    vacuous), and bounds the rank: `5 ≤ rank ≤ 9` over any base ring. -/

/-- Basis vector `v = (0,1,0)`. -/
def e1 : Vec3 F := ⟨zero, one, zero⟩
/-- Basis vector `v² = (0,0,1)`. -/
def e2 : Vec3 F := ⟨zero, zero, one⟩

/-- The 9-product "schoolbook" algorithm: one gate per monomial `aᵢ·bⱼ`, routed to the output
    coordinate its reduction lands in (the three `ξ`-weighted ones carry `v³ = ξ`). -/
def schoolbook (xi : F) : List (Vec3 F × Vec3 F × Vec3 F) :=
  [ (e0, e0, e0),
    (e0, e1, e1),
    (e0, e2, e2),
    (e1, e0, e1),
    (e1, e1, e2),
    (e1, e2, ⟨xi, zero, zero⟩),
    (e2, e0, e2),
    (e2, e1, ⟨xi, zero, zero⟩),
    (e2, e2, ⟨zero, xi, zero⟩) ]

theorem schoolbook_length (xi : F) : (schoolbook xi).length = 9 := rfl

/-- The schoolbook algorithm computes `mulFp6 ξ` — hence `Computes ξ` is satisfiable. -/
theorem schoolbook_computes (xi : F) : Computes xi (schoolbook xi) := by
  intro a b
  apply Vec3.ext <;>
    simp only [Bmap, schoolbook, List.foldr_cons, List.foldr_nil, vadd, vsmul, vzero,
      dot, e0, e1, e2, mulFp6, one_mul, zero_mul, mul_zero, zero_add, add_zero] <;>
    ring1

/-- **Fp6 multiplication tensor rank is between 5 and 9** over any nontrivial domain base:
    de Groote's `≥ 2·3−1 = 5` (optimal is exactly 5; the naive schoolbook uses 9). -/
theorem fp6_rank_ge_five_le_nine {xi : F} (hnt : (one : F) ≠ zero)
    (hdom : ∀ a b : Vec3 F, a ≠ vzero → b ≠ vzero → mulFp6 xi a b ≠ vzero) :
    (∀ gates : List (Vec3 F × Vec3 F × Vec3 F), Computes xi gates → 5 ≤ gates.length)
    ∧ (∃ gates : List (Vec3 F × Vec3 F × Vec3 F), Computes xi gates ∧ gates.length = 9) :=
  ⟨fun gates hc => fp6_rank_ge_five hnt hdom gates hc,
   ⟨schoolbook xi, schoolbook_computes xi, schoolbook_length xi⟩⟩

end LeanBCH.Opt.Fp6Rank

/-! ## Concrete non-vacuity witness: the finite field `𝔽₇ = Fin 7`, `ξ = 2`.

    `2` is not a cube mod 7 (cubes are `{0,1,6}`), so `v³−2` is irreducible over `𝔽₇` and
    `𝔽₇[v]/(v³−2) = 𝔽₇₃₄₃` is a field — hence a domain.  Stated OUTSIDE the opened `CRing`
    scope so `Fin 7`'s own arithmetic is used unambiguously (mirrors the FROZEN `Int`
    instance).  All finite facts are discharged by `decide`, so `f7_fp6_rank_ge_five` is a
    complete, hypothesis-free proof that the bound is non-vacuous. -/

namespace LeanBCH.Opt.Fp6Rank

open LeanBCH.Opt.BilinearRank

/-- `𝔽₇` as a commutative ring (every axiom `decide`d). -/
instance instCRingFin7 : CRing (Fin 7) where
  add := (· + ·)
  mul := (· * ·)
  neg := (- ·)
  zero := 0
  one := 1
  add_comm := by decide
  add_assoc := by decide
  add_zero := by decide
  zero_add := by decide
  add_left_neg := by decide
  mul_comm := by decide
  mul_assoc := by decide
  mul_one := by decide
  one_mul := by decide
  mul_zero := by decide
  zero_mul := by decide
  left_distrib := by decide
  right_distrib := by decide

/-- `𝔽₇` is nontrivial. -/
theorem f7_one_ne_zero : (CRing.one : Fin 7) ≠ CRing.zero := by decide

-- The domain property, in unpacked coordinate form — a finite check over all `7⁶` pairs.
set_option maxHeartbeats 4000000 in
theorem f7_domain_coord : ∀ a0 a1 a2 b0 b1 b2 : Fin 7,
    ¬(a0 = 0 ∧ a1 = 0 ∧ a2 = 0) → ¬(b0 = 0 ∧ b1 = 0 ∧ b2 = 0) →
    mulFp6 (2 : Fin 7) ⟨a0, a1, a2⟩ ⟨b0, b1, b2⟩ ≠ vzero := by
  decide

/-- **`𝔽₇[v]/(v³−2)` is a DOMAIN.** -/
theorem f7_is_domain (a b : Vec3 (Fin 7)) (ha : a ≠ vzero) (hb : b ≠ vzero) :
    mulFp6 (2 : Fin 7) a b ≠ vzero := by
  obtain ⟨a0, a1, a2⟩ := a
  obtain ⟨b0, b1, b2⟩ := b
  refine f7_domain_coord a0 a1 a2 b0 b1 b2 ?_ ?_
  · rintro ⟨h0, h1, h2⟩; exact ha (by rw [h0, h1, h2]; rfl)
  · rintro ⟨h0, h1, h2⟩; exact hb (by rw [h0, h1, h2]; rfl)

/-- **The Fp6 rank ≥ 5 bound, discharged UNCONDITIONALLY over `𝔽₇` (no hypotheses).**  Every
    bilinear algorithm computing `𝔽₇[v]/(v³−2)`-multiplication uses ≥ 5 essential
    multiplications — the de Groote bound `2·3−1`, non-vacuously true over a concrete field. -/
theorem f7_fp6_rank_ge_five (gates : List (Vec3 (Fin 7) × Vec3 (Fin 7) × Vec3 (Fin 7)))
    (hc : Computes (2 : Fin 7) gates) : 5 ≤ gates.length :=
  fp6_rank_ge_five f7_one_ne_zero f7_is_domain gates hc

#print axioms fp6_rank_ge_five
#print axioms common_kernel_two
#print axioms f7_fp6_rank_ge_five
#print axioms f7_is_domain

end LeanBCH.Opt.Fp6Rank
