/-
  LeanBCH.Opt.OpMulFloor — PIECE A of the op-cost floor-prover: a machine-checked
  per-OP_MUL op-cost LOWER BOUND, read straight off the FROZEN BCH-2026 cost model.

  ────────────────────────────────────────────────────────────────────────────────
  WHAT THIS PROVES (and what it does NOT — read `Opt/OpCostFloor_SCOPE.md`).

  The frozen `LeanBCH.Cost.arithCost` bills an OP_MUL of operands `a`, `b` (pushing the
  result `a * b`) an `arithmeticCost` of `intByteLen a * intByteLen b + intByteLen (a*b)`
  — the libauth `measureArithmeticCost` operand pre-charge `|a|·|b|` plus the result-byte
  bill (see `LeanBCH/Cost/Arith.lean`, differentially pinned to libauth 3.1.0-next.8).

  Piece A turns that per-op cost into a LOWER BOUND keyed on OPERAND WIDTH:

      any OP_MUL of two operands each of VM-number width ≥ k  bills  ≥ k²  arithmeticCost,
      and hence  ≥ baseInstructionCost + k²  op-cost  (= 100 + k² under BCH_2026_05).

  This is the algebraically-cheap half of the Fp12 floor: it prices ONE essential field
  multiply. Composed (later, Piece B/C) with a bilinear-rank lower bound on the NUMBER of
  essential Fp-mults, it bounds `fp12Mul`/`fp12Sqr`/`mul034`.

  ★ THE ONE HONEST MODELLING CARE-POINT (called out in the SCOPE). The bound is NOT free
  of hypotheses: a prover could "cheat" the |a|·|b| pre-charge with SMALL operands (an
  OP_MUL of two 1-byte numbers bills only 1). So the full-width condition is carried as
  EXPLICIT HYPOTHESES `k ≤ intByteLen a` and `k ≤ intByteLen b`; the bound fires exactly
  when the essential multiplications act on non-degenerate, full-width inputs — which for
  reduced BN254 field elements is the 32-byte generic width. The hypotheses are SATISFIABLE
  (not contradictory): `bn254Operand_width` exhibits a concrete 32-byte operand, so the
  concrete instances (`opMul_bn254_*`) are non-vacuous with a real positive bound (1024 / 1124).

  ❌ This does NOT rule out a different algorithm/representation, a different tower, a
  different curve, nor does it touch the shuffle/movement floor. It audits the COST OF ONE
  MULTIPLY on this VM — nothing more. State that boundary wherever this is cited.

  Additive layer over the FROZEN core: imports only `LeanBCH.Cost.Arith` — the single allowed
  optimizer→VM cost seam — which TRANSITIVELY re-exports everything this file needs
  (`LeanBCH.Number`'s `intByteLen`/`intByteLen_band`, and `LeanBCH.Cost.Metrics`'s
  `operationCost`/`Epoch`/`BCH_2026_05`). Edits nothing. Lean 4 core, NO mathlib. 0 sorry, axiom-clean.
-/
import LeanBCH.Cost.Arith

namespace LeanBCH.Opt.OpMulFloor

/-! ## The per-op cost object: the exact `Metrics` delta of one `OP_MUL a b`. -/

/-- The exact per-op `Metrics` the BCH-2026 VM bills for one `OP_MUL a b`: the FROZEN
    `Cost.arithCost` on kind `.mul`, with the pushed result the FROZEN
    `Cost.arithResult .mul a b` (`= a * b`). This is precisely the delta the cost fold
    (`kappaStep`) accumulates for the multiply — no re-derivation, we bind the frozen model. -/
def opMulMetrics (a b : Int) : Cost.Metrics :=
  Cost.arithCost .mul a b (Cost.arithResult .mul a b)

/-- The `arithmeticCost` of an `OP_MUL` is EXACTLY the operand pre-charge plus the result
    byte-bill: `intByteLen a * intByteLen b + intByteLen (a*b)` (frozen
    `arithCost_mulDivMod_operand`, specialised to MUL). -/
theorem opMul_arith_eq (a b : Int) :
    (opMulMetrics a b).arithmeticCost = intByteLen a * intByteLen b + intByteLen (a * b) := by
  unfold opMulMetrics
  exact Cost.arithCost_mulDivMod_operand .mul rfl a b (a * b)

/-! ## Piece A — the width-keyed LOWER BOUNDS (the two headlines). -/

/-- ★★ THE ARITH FLOOR (monotone form). Any `OP_MUL` of two operands each of VM-number
    width ≥ k bills at least `k²` to `arithmeticCost`. The `intByteLen ≥ k` hypotheses ARE
    the full-width care-point: drop them and the bound is cheatable by small operands. -/
theorem opMul_arith_ge_sq (a b : Int) (k : Nat)
    (ha : k ≤ intByteLen a) (hb : k ≤ intByteLen b) :
    k * k ≤ (opMulMetrics a b).arithmeticCost := by
  rw [opMul_arith_eq]
  calc k * k ≤ intByteLen a * intByteLen b := Nat.mul_le_mul ha hb
    _ ≤ intByteLen a * intByteLen b + intByteLen (a * b) := Nat.le_add_right _ _

/-- The full `operationCost` of an `OP_MUL`, made explicit for ANY epoch: one evaluated
    instruction (`baseInstructionCost`), the operand pre-charge, and the N-byte result
    DOUBLE-billed (once to `arithmeticCost`, once to `stackPushedBytes`). No sig/hash cost. -/
theorem opMul_operationCost_eq (E : Epoch) (a b : Int) :
    Cost.operationCost E (opMulMetrics a b)
      = E.baseInstructionCost + intByteLen a * intByteLen b + 2 * intByteLen (a * b) := by
  have harith : (opMulMetrics a b).arithmeticCost
      = intByteLen a * intByteLen b + intByteLen (a * b) := opMul_arith_eq a b
  have hstack : (opMulMetrics a b).stackPushedBytes = intByteLen (a * b) := rfl
  have heic : (opMulMetrics a b).evaluatedInstructionCount = 1 := rfl
  have hscc : (opMulMetrics a b).signatureCheckCount = 0 := rfl
  have hhdi : (opMulMetrics a b).hashDigestIterations = 0 := rfl
  unfold Cost.operationCost
  rw [harith, hstack, heic, hscc, hhdi]
  omega

/-- ★★ THE OP-COST FLOOR (epoch-general). Composing the arith floor with the cost roll-up:
    an `OP_MUL` of two width-≥ k operands costs at least `baseInstructionCost + k²` op-cost. -/
theorem opMul_opCost_ge (E : Epoch) (a b : Int) (k : Nat)
    (ha : k ≤ intByteLen a) (hb : k ≤ intByteLen b) :
    E.baseInstructionCost + k * k ≤ Cost.operationCost E (opMulMetrics a b) := by
  rw [opMul_operationCost_eq]
  have hsq : k * k ≤ intByteLen a * intByteLen b := Nat.mul_le_mul ha hb
  omega

/-- ★ THE OP-COST FLOOR at the SHIPPED epoch `BCH_2026_05` (base = 100): an `OP_MUL` of two
    width-≥ k operands costs ≥ `100 + k²`. -/
theorem opMul_opCost_ge_2026 (a b : Int) (k : Nat)
    (ha : k ≤ intByteLen a) (hb : k ≤ intByteLen b) :
    100 + k * k ≤ Cost.operationCost BCH_2026_05 (opMulMetrics a b) := by
  have h := opMul_opCost_ge BCH_2026_05 a b k ha hb
  have hb0 : BCH_2026_05.baseInstructionCost = 100 := rfl
  rw [hb0] at h
  exact h

/-! ## Discharging the full-width care-point on CONCRETE BN254-scale operands.

    The bounds above are conditional on `intByteLen ≥ k`. To show they are NON-VACUOUS
    (the hypotheses are satisfiable, the bound a real positive number) we EXHIBIT a concrete
    full-width operand, using the FROZEN band `intByteLen z ≤ M ↔ |z| < 2^(8M-1)`. -/

/-- LOWER bound on `intByteLen` from a magnitude threshold, dual to the frozen upper band
    `intByteLen_band`. For `L ≥ 2`, any value whose magnitude reaches `2^(8L-9)` needs at
    least `L` VM-number bytes. (`2^(8L-9) = 2^(8(L-1)-1)` is the band threshold for width `L-1`.) -/
theorem le_intByteLen (z : Int) (L : Nat) (hL : 2 ≤ L)
    (h : 2 ^ (8 * L - 9) ≤ z.natAbs) : L ≤ intByteLen z := by
  rcases Nat.lt_or_ge (intByteLen z) L with hlt | hge
  · exfalso
    have hle : intByteLen z ≤ L - 1 := by omega
    have hM : 1 ≤ L - 1 := by omega
    have hband := (intByteLen_band z (L - 1) hM).mp hle
    have he : 8 * (L - 1) - 1 = 8 * L - 9 := by omega
    rw [he] at hband
    omega
  · exact hge

/-- A concrete BN254-scale operand: `2^247`, whose libauth VM-number width is (exactly) 32
    bytes. Reduced BN254 field elements are 32-byte generic-width values; this witnesses that
    the `k = 32` hypotheses are SATISFIABLE — the floor instances below are non-vacuous. -/
def bn254Operand : Int := Int.ofNat (2 ^ 247)

/-- The witness IS full-width: `intByteLen (2^247) ≥ 32`. Discharged by the width band
    (`|2^247| = 2^247 = 2^(8·32-9)`), NOT by kernel-evaluating the 248-bit magnitude. -/
theorem bn254Operand_width : 32 ≤ intByteLen bn254Operand := by
  apply le_intByteLen bn254Operand 32 (by decide)
  have hnat : bn254Operand.natAbs = 2 ^ 247 := rfl
  have hexp : 8 * 32 - 9 = 247 := rfl
  rw [hnat, hexp]
  exact Nat.le_refl _

/-- ★ BN254 INSTANCE (arithmeticCost). OP_MUL of two full-width (≥ 32-byte) operands bills
    ≥ 32² = 1024 to `arithmeticCost`. Non-vacuous: `bn254Operand` meets the width hypothesis. -/
theorem opMul_bn254_arith_ge :
    1024 ≤ (opMulMetrics bn254Operand bn254Operand).arithmeticCost := by
  have h := opMul_arith_ge_sq bn254Operand bn254Operand 32 bn254Operand_width bn254Operand_width
  omega

/-- ★ BN254 INSTANCE (op-cost). The SAME OP_MUL costs ≥ 100 + 1024 = 1124 op-cost under the
    shipped `BCH_2026_05` epoch (base 100). This is the "each essential Fp-mult ≥ ~1024 arith
    + 100 base" figure from the SCOPE, now a KERNEL THEOREM. -/
theorem opMul_bn254_opCost_ge :
    1124 ≤ Cost.operationCost BCH_2026_05 (opMulMetrics bn254Operand bn254Operand) := by
  have h := opMul_opCost_ge_2026 bn254Operand bn254Operand 32 bn254Operand_width bn254Operand_width
  omega

/-! ## Axiom audit (emitted at build time; expect only propext / Quot.sound / Classical.choice). -/

#print axioms opMul_arith_ge_sq
#print axioms opMul_opCost_ge
#print axioms opMul_opCost_ge_2026
#print axioms opMul_bn254_arith_ge
#print axioms opMul_bn254_opCost_ge

end LeanBCH.Opt.OpMulFloor
