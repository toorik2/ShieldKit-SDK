/-
  LeanBCH.Opt.TowerRankCompose — TARGET C of the op-cost floor-prover: the TOWER-MODEL
  COMPOSITION BRIDGE.  See `Opt/OpCostFloor_SCOPE.md` and the Fp2 pieces
  (`OpMulFloor` = A, `BilinearRankFloor` = B, `Fp12OpCostFloor` = the A×B Fp2 composition).

  ────────────────────────────────────────────────────────────────────────────────
  WHAT THIS PROVES (kernel-checked, 0-sorry, axiom-clean) — and WHAT IT DELIBERATELY DOES NOT.

  The shipped `fp12Mul`/`fp12Sqr`/`mul034` compute the Fp12 product through the 2-3-2 TOWER:
  one Fp12-multiplication is realized by several Fp6-multiplications, each Fp6-multiplication
  by several Fp2-multiplications, each Fp2-multiplication by several Fp-multiplications.  This
  file formalizes exactly that NESTED structure as a value (`Fp12Algo` ▷ `Fp6Algo` ▷ `Fp2Algo`
  ▷ leaf Fp-mults) and proves the composition of the per-level essential-multiplication
  (tensor-rank) lower bounds:

      #essential-Fp-mults(a tower algorithm)  ≥  r12 · r6 · r2

  where `r2, r6, r12` are the per-level rank LOWER BOUNDS carried as PARAMETERS/HYPOTHESES —
  so the bridge composes WHATEVER the per-level rank theorems prove:
    * r2  = rank(Fp2 = Fp[i]/(i²+1)  mult over Fp)      — proved = 3 in `BilinearRankFloor`
            (`CRing.fp2_rank_ge_three`), Winograd's "complex mult needs 3 real mults";
    * r6  = rank(Fp6 = Fp2[v]/(v³−ξ) mult over Fp2)     — de Groote deg-3 ext: ≥ 2·3−1 = 5;
    * r12 = rank(Fp12 = Fp6[w]/(w²−v) mult over Fp6)    — deg-2 ext, same technique as Fp2: ≥ 3.
  The tight tower product is 3·5·3 = 45 essential Fp-mults for `fp12Mul` (cf. shipped 74 mulFp).

  Then, composing with PIECE A (`OpMulFloor`, via `Fp12OpCostFloor.mulCostSum_ge_count`), the
  full-width op-cost of the tower body is

      op-cost  ≥  (r12 · r6 · r2) · (baseInstructionCost + k²)          (`fp12_opCost_floor`)

  and at BN254 width k = 32 with (r2,r6,r12) = (3,5,3) the concrete instance
  `bnFp12_opCost_floor` fires UNCONDITIONALLY at ≥ 45·(100+1024) = 50580 op-cost (and
  `bnFp12_arith_floor` at ≥ 45·1024 = 46080 arithmeticCost).

  ★★ THE MODEL BOUNDARY — STATED, NEVER LAUNDERED.  This lower-bounds algorithms whose
  computation is STRUCTURED AS THE TOWER: a nested tree in which each field-extension
  multiplication is realized by its OWN child multiplications one level down (the shipped
  code's exact structure — `fp12Mul` calls `fp6Mul` calls `fp2Mul` calls `fpMul`).  It does
  NOT bound arbitrary straight-line algorithms: an algorithm that abandons the tower (a direct
  Fp12-over-Fp structure tensor, a different tower, cross-level common-subexpression sharing
  between distinct Fp6-multiplications) is a DIFFERENT computation with its own rank and is out
  of scope.  Concretely, the model has no cross-multiplication sharing — each `Fp6Algo`/`Fp2Algo`
  owns its child list — which is faithful to the shipped nested code but is the reason the bound
  applies to TOWER-STRUCTURED algorithms only.  The per-level `WF*` hypotheses ("this level's
  multiplication uses ≥ rᵢ sub-multiplications") are EXACTLY the conclusion of that level's rank
  theorem applied to each realized sub-multiplication; `wf2_of_fp2rank` discharges the Fp2 base
  case from the ACTUAL proven `CRing.fp2_rank_ge_three`, grounding r2 = 3 in a kernel theorem
  rather than a bare literal.  r6 (de Groote deg-3) and r12 (deg-2) are supplied by the per-level
  rank theorems (Targets A/B); this bridge is parametric so it holds the instant those land.

  Non-vacuity: the r's are positive (`tower_bound_pos`), the model is inhabited by a concrete
  45-leaf full-width BN254 tower (`bnFp12`), and both floors fire with real positive numbers.

  Additive layer over the FROZEN core + the committed Fp2 pieces: imports only
  `LeanBCH.Opt.Fp12OpCostFloor` (which transitively re-exports `OpMulFloor`, `BilinearRankFloor`,
  and the frozen `Cost.Arith`/`Epoch` seam).  Edits nothing.  Lean 4 core, NO mathlib.  0 sorry.
-/
import LeanBCH.Opt.Fp12OpCostFloor

namespace LeanBCH.Opt.TowerRankCompose

open LeanBCH.Opt.OpMulFloor
open LeanBCH.Opt.BilinearRank
open LeanBCH.Opt.Fp12OpCostFloor

/-! ## The tower algorithm, as a nested value.

    A leaf is one essential Fp-multiplication, carrying its two operands (`Int × Int`, exactly
    the operand pair `OpMulFloor`/`Fp12OpCostFloor` price).  Each higher level is the LIST of
    sub-multiplications one level down — the honest "computes X via these sub-mults" structure,
    with no cross-level sharing (see the model boundary above). -/

/-- A tower algorithm for one Fp2-multiplication: the list of essential Fp-multiplications
    (leaf operand pairs) it performs. -/
structure Fp2Algo where
  fpMults : List (Int × Int)

/-- A tower algorithm for one Fp6-multiplication: the list of Fp2-sub-multiplications it
    performs, each itself a tower algorithm. -/
structure Fp6Algo where
  fp2Mults : List Fp2Algo

/-- A tower algorithm for one Fp12-multiplication: the list of Fp6-sub-multiplications. -/
structure Fp12Algo where
  fp6Mults : List Fp6Algo

/-- Concatenating map: the total leaf list produced by applying `f` to each element and
    appending.  (Named locally to avoid any clash with core `List.flatMap`/`List.bind`.) -/
def catMap {α : Type} (f : α → List (Int × Int)) : List α → List (Int × Int)
  | []      => []
  | x :: xs => f x ++ catMap f xs

/-- The flat list of ALL essential Fp-multiplications (leaves) an Fp2 tower algorithm performs. -/
def Fp2Algo.leaves (a : Fp2Algo) : List (Int × Int) := a.fpMults

/-- The flat list of ALL leaf Fp-multiplications an Fp6 tower algorithm performs: the leaves of
    each Fp2 sub-multiplication, concatenated. -/
def Fp6Algo.leaves (a : Fp6Algo) : List (Int × Int) := catMap Fp2Algo.leaves a.fp2Mults

/-- The flat list of ALL leaf Fp-multiplications an Fp12 tower algorithm performs. -/
def Fp12Algo.leaves (a : Fp12Algo) : List (Int × Int) := catMap Fp6Algo.leaves a.fp6Mults

/-! ## Per-level well-formedness = the per-level rank lower bound, applied to each sub-mult. -/

/-- The Fp2 layer respects its rank bound `r2`: this Fp2-multiplication performs ≥ r2 essential
    Fp-multiplications (its tensor rank ≥ r2). -/
def WF2 (r2 : Nat) (a : Fp2Algo) : Prop := r2 ≤ (Fp2Algo.leaves a).length

/-- The Fp6 layer respects rank `r6` and its Fp2 children respect `r2`: this Fp6-multiplication
    performs ≥ r6 Fp2-sub-multiplications, each of which is `WF2 r2`. -/
def WF6 (r2 r6 : Nat) (a : Fp6Algo) : Prop :=
  r6 ≤ a.fp2Mults.length ∧ ∀ s ∈ a.fp2Mults, WF2 r2 s

/-- The Fp12 layer respects rank `r12` and its children respect `r6`/`r2`: this
    Fp12-multiplication performs ≥ r12 Fp6-sub-multiplications, each `WF6 r2 r6`. -/
def WF12 (r2 r6 r12 : Nat) (a : Fp12Algo) : Prop :=
  r12 ≤ a.fp6Mults.length ∧ ∀ s ∈ a.fp6Mults, WF6 r2 r6 s

/-! ## The counting engine: a list whose every element contributes ≥ m leaves has ≥ len·m leaves. -/

/-- If every element `x` of `xs` contributes at least `m` leaves through `f`, then the total
    concatenated leaf list has length ≥ `xs.length · m`.  (Pure list/arithmetic induction —
    the reusable multiplier at every tower level.) -/
theorem catMap_length_ge {α : Type} (f : α → List (Int × Int)) (m : Nat) :
    ∀ (xs : List α), (∀ x ∈ xs, m ≤ (f x).length) → xs.length * m ≤ (catMap f xs).length := by
  intro xs
  induction xs with
  | nil => intro _; simp [catMap]
  | cons x xs ih =>
      intro hall
      have hhead : m ≤ (f x).length := hall x List.mem_cons_self
      have htail : xs.length * m ≤ (catMap f xs).length :=
        ih (fun y hy => hall y (List.mem_cons_of_mem x hy))
      have hexp : (x :: xs).length * m = xs.length * m + m := by
        rw [List.length_cons, Nat.add_mul, Nat.one_mul]
      have hcat : (catMap f (x :: xs)).length = (f x).length + (catMap f xs).length := by
        show (f x ++ catMap f xs).length = _
        rw [List.length_append]
      rw [hexp, hcat]
      omega

/-- Membership through `catMap`: a leaf in the concatenation comes from some element's list.
    (Used only for the concrete non-vacuity instance's full-width discharge.) -/
theorem mem_catMap {α : Type} (f : α → List (Int × Int)) (p : Int × Int) :
    ∀ xs : List α, p ∈ catMap f xs → ∃ x ∈ xs, p ∈ f x := by
  intro xs
  induction xs with
  | nil => intro hp; simp [catMap] at hp
  | cons x xs ih =>
      intro hp
      have hp' : p ∈ f x ++ catMap f xs := hp
      rcases List.mem_append.mp hp' with h | h
      · exact ⟨x, List.mem_cons_self, h⟩
      · obtain ⟨y, hy, hpy⟩ := ih h
        exact ⟨y, List.mem_cons_of_mem x hy, hpy⟩

/-! ## The per-level leaf-count lower bounds — composing rank bottom-up. -/

/-- Fp2 level: a `WF2 r2` algorithm performs ≥ r2 leaf Fp-multiplications (definitional). -/
theorem fp2_leaves_ge (r2 : Nat) (a : Fp2Algo) (h : WF2 r2 a) :
    r2 ≤ (Fp2Algo.leaves a).length := h

/-- Fp6 level: a `WF6 r2 r6` algorithm performs ≥ r6·r2 leaf Fp-multiplications.  (≥ r6 Fp2
    children, each ≥ r2 leaves.) -/
theorem fp6_leaves_ge (r2 r6 : Nat) (a : Fp6Algo) (h : WF6 r2 r6 a) :
    r6 * r2 ≤ (Fp6Algo.leaves a).length := by
  obtain ⟨hlen, hall⟩ := h
  have hsum : a.fp2Mults.length * r2 ≤ (Fp6Algo.leaves a).length :=
    catMap_length_ge Fp2Algo.leaves r2 a.fp2Mults (fun s hs => hall s hs)
  calc r6 * r2 ≤ a.fp2Mults.length * r2 := Nat.mul_le_mul hlen (Nat.le_refl r2)
    _ ≤ (Fp6Algo.leaves a).length := hsum

/-- ★★ Fp12 level — THE TOWER COUNT FLOOR (the headline).  A `WF12 r2 r6 r12` tower algorithm
    for `fp12Mul` performs ≥ r12·r6·r2 essential leaf Fp-multiplications: the product of the
    per-level rank lower bounds.  Parametric in the r's, so it composes whatever the per-level
    rank theorems prove (r2 = 3 from `BilinearRankFloor`; r6 = 5, r12 = 3 from de Groote / the
    deg-2 argument). -/
theorem fp12_leaves_ge (r2 r6 r12 : Nat) (a : Fp12Algo) (h : WF12 r2 r6 r12 a) :
    r12 * r6 * r2 ≤ (Fp12Algo.leaves a).length := by
  obtain ⟨hlen, hall⟩ := h
  have hsub : ∀ s ∈ a.fp6Mults, r6 * r2 ≤ (Fp6Algo.leaves s).length :=
    fun s hs => fp6_leaves_ge r2 r6 s (hall s hs)
  have hsum : a.fp6Mults.length * (r6 * r2) ≤ (Fp12Algo.leaves a).length :=
    catMap_length_ge Fp6Algo.leaves (r6 * r2) a.fp6Mults hsub
  calc r12 * r6 * r2 = r12 * (r6 * r2) := Nat.mul_assoc r12 r6 r2
    _ ≤ a.fp6Mults.length * (r6 * r2) := Nat.mul_le_mul hlen (Nat.le_refl (r6 * r2))
    _ ≤ (Fp12Algo.leaves a).length := hsum

/-! ## Composition with PIECE A (`OpMulFloor`) — the tower op-cost / arith floors. -/

/-- ★★ THE TOWER OP-COST FLOOR.  A `WF12 r2 r6 r12` tower algorithm for `fp12Mul` whose leaf
    Fp-multiplications all act on full-width (≥ k-byte) operands bills at least
    `(r12·r6·r2) · (baseInstructionCost + k²)` op-cost under any epoch.  Composes the tower count
    floor (`fp12_leaves_ge`) with the per-multiply op-cost floor (`OpMulFloor.opMul_opCost_ge`,
    summed by `Fp12OpCostFloor.mulCostSum_ge_count`). -/
theorem fp12_opCost_floor (E : Epoch) (k r2 r6 r12 : Nat) (a : Fp12Algo)
    (hwf : WF12 r2 r6 r12 a)
    (hw : ∀ p ∈ Fp12Algo.leaves a, k ≤ intByteLen p.1 ∧ k ≤ intByteLen p.2) :
    (r12 * r6 * r2) * (E.baseInstructionCost + k * k)
      ≤ mulCostSum E (Fp12Algo.leaves a) := by
  have hcount := fp12_leaves_ge r2 r6 r12 a hwf
  exact mulCostSum_ge_count E k (r12 * r6 * r2) (Fp12Algo.leaves a) hcount hw

/-- ★★ THE TOWER ARITH FLOOR (arithmeticCost form): ≥ `(r12·r6·r2) · k²`. -/
theorem fp12_arith_floor (k r2 r6 r12 : Nat) (a : Fp12Algo)
    (hwf : WF12 r2 r6 r12 a)
    (hw : ∀ p ∈ Fp12Algo.leaves a, k ≤ intByteLen p.1 ∧ k ≤ intByteLen p.2) :
    (r12 * r6 * r2) * (k * k) ≤ mulArithSum (Fp12Algo.leaves a) := by
  have hcount := fp12_leaves_ge r2 r6 r12 a hwf
  exact mulArithSum_ge_count k (r12 * r6 * r2) (Fp12Algo.leaves a) hcount hw

/-! ## Grounding the Fp2 base case in the ACTUAL proven Fp2 rank theorem (r2 = 3 is real). -/

/-- `WF2 3` is not a bare literal: if an Fp2 tower sub-algorithm's leaf Fp-multiplications realize
    a bilinear program `ps` that COMPUTES the Fp2 = F[i]/(i²+1) multiplication map (rank-1 products,
    over a ring where −1 is not a square — the field-defining condition), with at least one leaf per
    essential product, then `WF2 3` holds — DISCHARGED by `CRing.fp2_rank_ge_three`.  This is the
    honest link between the tower model's per-level hypothesis and Piece B's rank theorem. -/
theorem wf2_of_fp2rank {F : Type} [CRing F]
    (a : Fp2Algo) (ps : List (CRing.Mat2 F))
    (hr : CRing.AllRank1 ps)
    (h0 : CRing.Computes ps CRing.M0) (h1 : CRing.Computes ps CRing.M1)
    (hns : ∀ w : F, CRing.mul w w ≠ CRing.neg CRing.one)
    (hlen : ps.length ≤ (Fp2Algo.leaves a).length) :
    WF2 3 a := by
  have hrank : 3 ≤ ps.length := CRing.fp2_rank_ge_three ps hr h0 h1 hns
  exact Nat.le_trans hrank hlen

/-! ## Non-vacuity: a concrete full-width BN254 tower with the tight (3,5,3) ranks.

    The r's are positive and the model is inhabited: three Fp6-mults, each five Fp2-mults, each
    three full-width BN254 leaf Fp-mults ⇒ 45 leaves, all width ≥ 32.  `bnFp2`'s r2 = 3 is
    grounded via `wf2_of_fp2rank` on the Karatsuba program over `Int` (the −1-not-a-square witness). -/

/-- One full-width BN254-scale leaf multiply (`2²⁴⁷ · 2²⁴⁷`). -/
def bnLeaf : Int × Int := (bn254Operand, bn254Operand)

/-- An Fp2 tower sub-mult with exactly 3 leaf Fp-mults (Karatsuba/Winograd count). -/
def bnFp2 : Fp2Algo := ⟨[bnLeaf, bnLeaf, bnLeaf]⟩

/-- An Fp6 tower sub-mult with exactly 5 Fp2-mults (de Groote deg-3 count). -/
def bnFp6 : Fp6Algo := ⟨[bnFp2, bnFp2, bnFp2, bnFp2, bnFp2]⟩

/-- An Fp12 tower mult with exactly 3 Fp6-mults (deg-2 Karatsuba count) ⇒ 3·5·3 = 45 leaves. -/
def bnFp12 : Fp12Algo := ⟨[bnFp6, bnFp6, bnFp6]⟩

/-- `bnFp2` is `WF2 3`, DISCHARGED via the actual Fp2 rank theorem (Karatsuba program over `Int`). -/
theorem bnFp2_wf : WF2 3 bnFp2 := by
  apply wf2_of_fp2rank (F := Int) bnFp2 CRing.karatsuba
    CRing.karatsuba_rank1 CRing.karatsuba_computes_M0 CRing.karatsuba_computes_M1
    int_no_sqrt_neg_one
  have h1 : (CRing.karatsuba (F := Int)).length = 3 := CRing.karatsuba_length
  have h2 : (Fp2Algo.leaves bnFp2).length = 3 := rfl
  omega

/-- `bnFp6` is `WF6 3 5`: 5 Fp2 children, each `WF2 3`. -/
theorem bnFp6_wf : WF6 3 5 bnFp6 := by
  refine ⟨?_, ?_⟩
  · have h : bnFp6.fp2Mults.length = 5 := rfl
    omega
  · intro s hs
    have hs' : s ∈ [bnFp2, bnFp2, bnFp2, bnFp2, bnFp2] := hs
    have hseq : s = bnFp2 := by
      simp only [List.mem_cons, List.not_mem_nil, or_false, or_self] at hs'; exact hs'
    subst hseq; exact bnFp2_wf

/-- `bnFp12` is `WF12 3 5 3`: 3 Fp6 children, each `WF6 3 5`. -/
theorem bnFp12_wf : WF12 3 5 3 bnFp12 := by
  refine ⟨?_, ?_⟩
  · have h : bnFp12.fp6Mults.length = 3 := rfl
    omega
  · intro s hs
    have hs' : s ∈ [bnFp6, bnFp6, bnFp6] := hs
    have hseq : s = bnFp6 := by
      simp only [List.mem_cons, List.not_mem_nil, or_false, or_self] at hs'; exact hs'
    subst hseq; exact bnFp6_wf

/-- Every one of the 45 leaves is full-width (≥ 32-byte), via the frozen width band
    `bn254Operand_width` — NOT by kernel-evaluating any 248-bit magnitude. -/
theorem bnFp12_leaves_width :
    ∀ p ∈ Fp12Algo.leaves bnFp12, 32 ≤ intByteLen p.1 ∧ 32 ≤ intByteLen p.2 := by
  intro p hp
  obtain ⟨s, hs, hps⟩ := mem_catMap Fp6Algo.leaves p bnFp12.fp6Mults hp
  have hs' : s ∈ [bnFp6, bnFp6, bnFp6] := hs
  have hseq : s = bnFp6 := by
    simp only [List.mem_cons, List.not_mem_nil, or_false, or_self] at hs'; exact hs'
  subst hseq
  obtain ⟨t, ht, hpt⟩ := mem_catMap Fp2Algo.leaves p bnFp6.fp2Mults hps
  have ht' : t ∈ [bnFp2, bnFp2, bnFp2, bnFp2, bnFp2] := ht
  have hteq : t = bnFp2 := by
    simp only [List.mem_cons, List.not_mem_nil, or_false, or_self] at ht'; exact ht'
  subst hteq
  have hpl : p ∈ [bnLeaf, bnLeaf, bnLeaf] := hpt
  have hpeq : p = bnLeaf := by
    simp only [List.mem_cons, List.not_mem_nil, or_false, or_self] at hpl; exact hpl
  subst hpeq
  exact ⟨bn254Operand_width, bn254Operand_width⟩

/-- The tower count floor, DISCHARGED for the concrete tower: `bnFp12` performs ≥ 45 = 3·5·3
    essential leaf Fp-multiplications (unconditional). -/
theorem bnFp12_leaves_ge : 45 ≤ (Fp12Algo.leaves bnFp12).length := by
  have h := fp12_leaves_ge 3 5 3 bnFp12 bnFp12_wf
  omega

/-- ★ THE TOWER OP-COST FLOOR at BN254 width, UNCONDITIONAL: any tower-structured `fp12Mul`
    with the (3,5,3) per-level ranks on full-width operands bills ≥ 45·(100+32²) = 50580 op-cost
    under the shipped `BCH_2026_05` epoch.  Non-vacuous — r's positive, model inhabited, r2 = 3
    grounded in `CRing.fp2_rank_ge_three`. -/
theorem bnFp12_opCost_floor :
    50580 ≤ mulCostSum BCH_2026_05 (Fp12Algo.leaves bnFp12) := by
  have h := fp12_opCost_floor BCH_2026_05 32 3 5 3 bnFp12 bnFp12_wf bnFp12_leaves_width
  have hb : BCH_2026_05.baseInstructionCost = 100 := rfl
  rw [hb] at h
  omega

/-- ★ THE TOWER ARITH FLOOR at BN254 width, UNCONDITIONAL: ≥ 45·32² = 46080 arithmeticCost. -/
theorem bnFp12_arith_floor :
    46080 ≤ mulArithSum (Fp12Algo.leaves bnFp12) := by
  have h := fp12_arith_floor 32 3 5 3 bnFp12 bnFp12_wf bnFp12_leaves_width
  omega

/-- Non-vacuity of the bound object itself: the tower product of the tight per-level ranks is a
    genuine positive quantity. -/
theorem tower_bound_pos : 0 < 3 * 5 * 3 := by decide

/-! ## Axiom audit (emitted at build time; expect only propext / Quot.sound / Classical.choice). -/

#print axioms fp12_leaves_ge
#print axioms fp12_opCost_floor
#print axioms fp12_arith_floor
#print axioms wf2_of_fp2rank
#print axioms bnFp12_leaves_ge
#print axioms bnFp12_opCost_floor
#print axioms bnFp12_arith_floor

/-
  ## OPEN (not proven here) — honest boundary, not laundered.

  * This bridge is PARAMETRIC in r2/r6/r12; it does NOT itself prove r6 = 5 (de Groote deg-3
    rank of Fp6 = Fp2[v]/(v³−ξ) over Fp2) nor r12 = 3 (deg-2 rank of Fp12 = Fp6[w]/(w²−v) over
    Fp6).  r2 = 3 IS grounded (`wf2_of_fp2rank` ▷ `CRing.fp2_rank_ge_three`); r6 and r12 are
    supplied as the per-level rank theorems of Targets A/B.  Feeding proven r6/r12 into
    `fp12_leaves_ge`/`fp12_opCost_floor` immediately yields the crown op-cost floor with no change
    here.
  * The `WF*` hypotheses model the tower as a nested tree WITHOUT cross-multiplication sharing —
    faithful to the shipped nested code, but this is a lower bound on TOWER-STRUCTURED algorithms
    ONLY, never on an arbitrary straight-line program, a direct Fp12/Fp structure tensor, or a
    different tower/curve.  No at-floor claim about the shipped 74/52/49 mulFp counts follows from
    this file alone; that comparison needs the proven r6/r12 and is stated OPEN.
-/

end LeanBCH.Opt.TowerRankCompose
