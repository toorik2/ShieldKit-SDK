/-
  LeanBCH.Opt.Fp12OpCostFloor — PIECE C of the op-cost floor-prover: the COMPOSITION of the
  per-multiply op-cost floor (Piece A, `OpMulFloor`) with the essential-multiplication COUNT floor
  (Piece B, `BilinearRankFloor`) into a machine-checked op-cost LOWER BOUND for field-extension
  multiplication on the BCH-2026 VM.  See `Opt/OpCostFloor_SCOPE.md`.

  ────────────────────────────────────────────────────────────────────────────────
  WHAT THIS PROVES — and, precisely, WHAT IT DOES NOT (read before citing).

  The SCOPE's composition target is `op-cost(f) ≥ rank(f) · min-per-mult-cost`.  Both factors are
  now Lean objects:

    * Piece A (`OpMulFloor.opMul_opCost_ge`): an OP_MUL of two operands each of VM-number width ≥ k
      bills ≥ `baseInstructionCost + k²` op-cost (≥ `100 + k²` at `BCH_2026_05`); at the reduced
      BN254 field-element width k = 32 that is ≥ 1124 op-cost (≥ 1024 arithmeticCost) per essential
      multiply — discharged full-width by `OpMulFloor.bn254Operand_width`.
    * Piece B (`BilinearRankFloor.CRing.fp2_rank_ge_three`): computing the Fp2 = F[i]/(i²+1)
      multiplication map needs ≥ 3 essential field multiplications (tensor rank 3), over any ring in
      which −1 is not a square (the field-defining condition; BN254's base field, p ≡ 3 mod 4).

  This file MULTIPLIES them: a straight-line body whose essential OP_MULs realize the Fp2 bilinear
  map, on full-width BN254 operands, bills
        ≥ 3 · 1024 = 3072  arithmeticCost   and   ≥ 3 · 1124 = 3372  op-cost.
  `fp2_opCost_floor_bn254` / `fp2_arith_floor_bn254` are those two as unconditional KERNEL THEOREMS
  (real, positive, non-vacuous — a concrete witness list is exhibited that satisfies every hypothesis).

  ★ THE THREE HONEST CARE-POINTS (carried as EXPLICIT hypotheses — never laundered):
    (1) FULL-WIDTH operands (`hw : ∀ p ∈ mults, k ≤ intByteLen p.1 ∧ k ≤ intByteLen p.2`): Piece A is
        cheatable with small operands, so the width premise is explicit (and discharged, k = 32, by
        `bn254Operand_width` for the concrete instance).
    (2) COUNT CORRESPONDENCE (`hlen : ps.length ≤ mults.length`): the bilinear program `ps` (whose
        rank ≥ 3 is Piece B) is linked to the executed OP_MUL list `mults` by "there is at least one
        OP_MUL per essential product".  This is the Piece A↔B structural bridge; stated as a hypothesis
        (the SCOPE's "the essential multiplications act on ... full-width inputs" link).
    (3) The ADDITIVE cost model `mulCostSum` sums the FROZEN per-op `Cost.operationCost` over the
        essential OP_MULs; it is a genuine lower bound on the whole body's op-cost precisely because
        op-cost is a non-negative linear roll-up (frozen `operationCost`) and these multiplies are a
        SUBSET of the body's ops.  It does not model the shuffle/movement ops around them (Piece D /
        `MovementFloorDag`), so the whole-body floor is ≥ this arithmetic-only floor.

  ❌ SCOPE LEVEL DELIVERED = Fp2 ONLY.  Piece B proved the Fp2 tensor rank (= 3) but left the Fp6
  (rank ≥ 6 over Fp2) and Fp12 (rank ≥ 3 over Fp6) tower-composition ranks OPEN.  Therefore this file
  composes ONLY the Fp2 layer.  It makes NO claim about the shipped `fp12Mul = 74 / fp12Sqr = 52 /
  mul034 = 49` mulFp counts being at-floor: bounding those needs the Fp12 rank (≥ 54 essential Fp-mults
  by the standard tower count), which is NOT a theorem yet.  See the OPEN note at the file's end.  What
  IS a kernel theorem today: the op-cost floor of ONE Fp2 multiplication on this VM.  State that boundary.

  Additive layer over the FROZEN core: imports only the two intra-optimizer floor pieces
  (`LeanBCH.Opt.OpMulFloor`, `LeanBCH.Opt.BilinearRankFloor`), which transitively supply the frozen
  cost model (`Cost.operationCost`/`Epoch`/`intByteLen`) through the allowed `Cost.Arith` seam.  Edits
  nothing.  Lean 4 core, NO mathlib.  0 sorry, axiom-clean.
-/
import LeanBCH.Opt.OpMulFloor
import LeanBCH.Opt.BilinearRankFloor

namespace LeanBCH.Opt.Fp12OpCostFloor

open LeanBCH.Opt.OpMulFloor
open LeanBCH.Opt.BilinearRank

/-! ## The additive cost of a list of essential OP_MULs (over the FROZEN per-op model). -/

/-- Total `arithmeticCost` the VM bills for a list of essential field multiplications: the FROZEN
    `(opMulMetrics a b).arithmeticCost` summed over the operand pairs.  A genuine lower bound on the
    body's total arithmeticCost — these multiplies are a subset of the body's ops. -/
def mulArithSum : List (Int × Int) → Nat
  | []      => 0
  | p :: ps => (opMulMetrics p.1 p.2).arithmeticCost + mulArithSum ps

/-- Total `operationCost` (epoch-parameterized) the VM bills for a list of essential field
    multiplications: the FROZEN `Cost.operationCost E (opMulMetrics a b)` summed over the pairs. -/
def mulCostSum (E : Epoch) : List (Int × Int) → Nat
  | []      => 0
  | p :: ps => Cost.operationCost E (opMulMetrics p.1 p.2) + mulCostSum E ps

/-! ## The summation floors: length·(per-mult floor) ≤ total, from Piece A applied per element. -/

/-- Every full-width essential multiply bills ≥ `k²` arith ⇒ the arith SUM is ≥ `#mults · k²`. -/
theorem mulArithSum_ge_len (k : Nat) :
    ∀ (mults : List (Int × Int)),
      (∀ p ∈ mults, k ≤ intByteLen p.1 ∧ k ≤ intByteLen p.2) →
      mults.length * (k * k) ≤ mulArithSum mults := by
  intro mults
  induction mults with
  | nil => intro _; simp [mulArithSum]
  | cons p ps ih =>
      intro hw
      have hhead : k * k ≤ (opMulMetrics p.1 p.2).arithmeticCost := by
        have hp := hw p List.mem_cons_self
        exact opMul_arith_ge_sq p.1 p.2 k hp.1 hp.2
      have htail : ps.length * (k * k) ≤ mulArithSum ps :=
        ih (fun q hq => hw q (List.mem_cons_of_mem p hq))
      simp only [mulArithSum, List.length_cons]
      rw [Nat.add_mul, Nat.one_mul]
      omega

/-- Every full-width essential multiply bills ≥ `base + k²` op-cost ⇒ the op-cost SUM is ≥
    `#mults · (base + k²)`. -/
theorem mulCostSum_ge_len (E : Epoch) (k : Nat) :
    ∀ (mults : List (Int × Int)),
      (∀ p ∈ mults, k ≤ intByteLen p.1 ∧ k ≤ intByteLen p.2) →
      mults.length * (E.baseInstructionCost + k * k) ≤ mulCostSum E mults := by
  intro mults
  induction mults with
  | nil => intro _; simp [mulCostSum]
  | cons p ps ih =>
      intro hw
      have hhead : E.baseInstructionCost + k * k ≤ Cost.operationCost E (opMulMetrics p.1 p.2) := by
        have hp := hw p List.mem_cons_self
        exact opMul_opCost_ge E p.1 p.2 k hp.1 hp.2
      have htail : ps.length * (E.baseInstructionCost + k * k) ≤ mulCostSum E ps :=
        ih (fun q hq => hw q (List.mem_cons_of_mem p hq))
      simp only [mulCostSum, List.length_cons]
      rw [Nat.add_mul, Nat.one_mul]
      omega

/-- ★ COUNT × PER-MULT (arith).  A count lower bound `n ≤ #mults` on full-width essential multiplies
    gives `n · k² ≤` total arithmeticCost. -/
theorem mulArithSum_ge_count (k n : Nat) (mults : List (Int × Int))
    (hcount : n ≤ mults.length)
    (hw : ∀ p ∈ mults, k ≤ intByteLen p.1 ∧ k ≤ intByteLen p.2) :
    n * (k * k) ≤ mulArithSum mults := by
  have hlen := mulArithSum_ge_len k mults hw
  have hmono : n * (k * k) ≤ mults.length * (k * k) := Nat.mul_le_mul hcount (Nat.le_refl _)
  omega

/-- ★ COUNT × PER-MULT (op-cost).  A count lower bound `n ≤ #mults` on full-width essential multiplies
    gives `n · (base + k²) ≤` total op-cost. -/
theorem mulCostSum_ge_count (E : Epoch) (k n : Nat) (mults : List (Int × Int))
    (hcount : n ≤ mults.length)
    (hw : ∀ p ∈ mults, k ≤ intByteLen p.1 ∧ k ≤ intByteLen p.2) :
    n * (E.baseInstructionCost + k * k) ≤ mulCostSum E mults := by
  have hlen := mulCostSum_ge_len E k mults hw
  have hmono : n * (E.baseInstructionCost + k * k) ≤ mults.length * (E.baseInstructionCost + k * k) :=
    Nat.mul_le_mul hcount (Nat.le_refl _)
  omega

/-! ## Piece A × Piece B — the Fp2 op-cost floor (general form, over any admissible ring). -/

/-- ★★ THE Fp2 OP-COST FLOOR (composition).  If a bilinear program `ps` computes the Fp2 = F[i]/(i²+1)
    multiplication map (rank-1 essential products, over a ring `F` in which −1 is NOT a square — the
    field-defining condition), and its essential multiplications are executed as OP_MULs `mults` with
    at least one OP_MUL per essential product (`ps.length ≤ mults.length`), each on full-width (≥ k-byte)
    operands, then the body bills ≥ `3 · (baseInstructionCost + k²)` op-cost.  Piece B pins the `3`
    (`fp2_rank_ge_three`); Piece A pins each `base + k²` (`opMul_opCost_ge`, via `mulCostSum_ge_count`). -/
theorem fp2_opCost_floor {F : Type} [CRing F] (E : Epoch) (k : Nat)
    (ps : List (CRing.Mat2 F)) (mults : List (Int × Int))
    (hr : CRing.AllRank1 ps)
    (h0 : CRing.Computes ps CRing.M0) (h1 : CRing.Computes ps CRing.M1)
    (hns : ∀ w : F, CRing.mul w w ≠ CRing.neg CRing.one)
    (hlen : ps.length ≤ mults.length)
    (hw : ∀ p ∈ mults, k ≤ intByteLen p.1 ∧ k ≤ intByteLen p.2) :
    3 * (E.baseInstructionCost + k * k) ≤ mulCostSum E mults := by
  have hrank : 3 ≤ ps.length := CRing.fp2_rank_ge_three ps hr h0 h1 hns
  have hcount : 3 ≤ mults.length := Nat.le_trans hrank hlen
  exact mulCostSum_ge_count E k 3 mults hcount hw

/-- ★★ THE Fp2 ARITH FLOOR (composition), same hypotheses, arithmeticCost form: ≥ `3 · k²`. -/
theorem fp2_arith_floor {F : Type} [CRing F] (k : Nat)
    (ps : List (CRing.Mat2 F)) (mults : List (Int × Int))
    (hr : CRing.AllRank1 ps)
    (h0 : CRing.Computes ps CRing.M0) (h1 : CRing.Computes ps CRing.M1)
    (hns : ∀ w : F, CRing.mul w w ≠ CRing.neg CRing.one)
    (hlen : ps.length ≤ mults.length)
    (hw : ∀ p ∈ mults, k ≤ intByteLen p.1 ∧ k ≤ intByteLen p.2) :
    3 * (k * k) ≤ mulArithSum mults := by
  have hrank : 3 ≤ ps.length := CRing.fp2_rank_ge_three ps hr h0 h1 hns
  have hcount : 3 ≤ mults.length := Nat.le_trans hrank hlen
  exact mulArithSum_ge_count k 3 mults hcount hw

/-! ## Non-vacuous concrete instance: full-width BN254 operands, discharged unconditionally.

    The concrete witness list of three BN254-scale (≥ 32-byte) essential multiplies, together with
    the Karatsuba/Winograd 3-product program over `Int` (the field-defining `−1`-not-a-square witness),
    makes both floors fire with real positive numbers and no remaining hypotheses. -/

/-- Three full-width BN254-scale essential multiplies (each `2²⁴⁷ · 2²⁴⁷`). -/
def bn254Mults : List (Int × Int) :=
  [(bn254Operand, bn254Operand), (bn254Operand, bn254Operand), (bn254Operand, bn254Operand)]

/-- The witness list is full-width: every operand has VM-number width ≥ 32 (from `bn254Operand_width`,
    the frozen width band — NOT a kernel evaluation of the 248-bit magnitude). -/
theorem bn254Mults_width :
    ∀ p ∈ bn254Mults, 32 ≤ intByteLen p.1 ∧ 32 ≤ intByteLen p.2 := by
  intro p hp
  simp only [bn254Mults, List.mem_cons, List.not_mem_nil, or_false] at hp
  rcases hp with h | h | h <;> (subst h; exact ⟨bn254Operand_width, bn254Operand_width⟩)

/-- ★ THE Fp2 OP-COST FLOOR at BN254 width, UNCONDITIONAL: any Fp2 multiplication realized by these
    three full-width essential OP_MULs bills ≥ 3372 = 3·(100 + 32²) op-cost under `BCH_2026_05`.
    Non-vacuous: composes Piece B's Karatsuba witness (rank exactly 3) with Piece A's `bn254Operand`. -/
theorem fp2_opCost_floor_bn254 :
    3372 ≤ mulCostSum BCH_2026_05 bn254Mults := by
  have hlen : (CRing.karatsuba (F := Int)).length ≤ bn254Mults.length := by
    have h1 : (CRing.karatsuba (F := Int)).length = 3 := CRing.karatsuba_length
    have h2 : bn254Mults.length = 3 := rfl
    omega
  have h := fp2_opCost_floor (F := Int) BCH_2026_05 32
      CRing.karatsuba bn254Mults
      CRing.karatsuba_rank1 CRing.karatsuba_computes_M0 CRing.karatsuba_computes_M1
      int_no_sqrt_neg_one hlen bn254Mults_width
  have hb : BCH_2026_05.baseInstructionCost = 100 := rfl
  rw [hb] at h
  omega

/-- ★ THE Fp2 ARITH FLOOR at BN254 width, UNCONDITIONAL: ≥ 3072 = 3·32² arithmeticCost. -/
theorem fp2_arith_floor_bn254 :
    3072 ≤ mulArithSum bn254Mults := by
  have hlen : (CRing.karatsuba (F := Int)).length ≤ bn254Mults.length := by
    have h1 : (CRing.karatsuba (F := Int)).length = 3 := CRing.karatsuba_length
    have h2 : bn254Mults.length = 3 := rfl
    omega
  have h := fp2_arith_floor (F := Int) 32
      CRing.karatsuba bn254Mults
      CRing.karatsuba_rank1 CRing.karatsuba_computes_M0 CRing.karatsuba_computes_M1
      int_no_sqrt_neg_one hlen bn254Mults_width
  omega

/-! ## Axiom audit (emitted at build time; expect only propext / Quot.sound / Classical.choice). -/

#print axioms fp2_opCost_floor
#print axioms fp2_arith_floor
#print axioms fp2_opCost_floor_bn254
#print axioms fp2_arith_floor_bn254

/-
  ## OPEN (not proven here) — Fp6 / Fp12 tower composition and the shipped-count comparison.

  This file composes ONLY the Fp2 layer, because Piece B (`BilinearRankFloor`) established ONLY the
  Fp2 tensor rank (= 3).  To reach the SCOPE's `fp12Mul`/`fp12Sqr`/`mul034` op-cost floor and compare
  against the shipped 74 / 52 / 49 mulFp, the following remain OPEN (honestly, not scaffolded with
  placeholder statements):

    * rank(Fp6 = Fp2[v]/(v³−ξ) mul) ≥ 6 over Fp2, and rank(Fp12 = Fp6[w]/(w²−v) mul) ≥ 3 over Fp6;
    * the rank composition (super-multiplicativity) down to Fp giving ≥ 54 essential Fp-mults for
      `fp12Mul` — the number that would then multiply through `mulCostSum_ge_count` to a concrete
      op-cost floor and be compared to the shipped counts (at-floor vs headroom).

  Until those land, NO claim is made or implied that the crown's ~88k Fp12 core is at its op-cost
  floor.  The reusable composition engine (`mulCostSum`, `mulArithSum`, `*_ge_len`, `*_ge_count`,
  `fp2_opCost_floor`) is in place to consume a higher-tower rank theorem the moment Piece B proves one.
-/

end LeanBCH.Opt.Fp12OpCostFloor
