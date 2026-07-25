/-
  Verified modular exponentiation + Fermat's-little-theorem-for-82 BY COMPUTATION.

  Upgrades the twist-derive (b2 = 3/(9+u), Groth16.Ederive) from CONDITIONAL to
  math-rigorous. b2 = (27/82, −3/82) needs inv82 = 82⁻¹ mod p, which the crown computes via
  its `inverseFp` subroutine — a 254-iter square-and-multiply modexp = Fermat (a^(p-2) mod p).

  The abstract Fermat's little theorem needs mathlib-grade number theory. We instead:
    (1) define a STRUCTURAL (kernel-computable) modexp `powMod` — the inverseFp algorithm;
    (2) prove it correct as modexp: `powMod_correct : powMod a e m = a^e % m` (a clean
        square-and-multiply induction, NO number theory);
    (3) `decide` that `powMod 82 (p-2) p = inv82` and `82·inv82 ≡ 1 mod p` — kernel-running
        the 254-step modexp, so `82^(p-2) mod p` is PROVEN (not assumed) to be 82's inverse.
  ⇒ `fermat_82` : Fermat's little theorem for a=82, discharged by verified computation.

  We ALSO model inverseFp's actual BEGIN/UNTIL loop shape (`modexpLoop`, iterative forward
  square-and-multiply) and prove its LOOP INVARIANT (`modexpLoop_inv`: it maintains
  `result·base^e mod m`) ⇒ the loop computes `a^e mod m` (`modexpLoop_pow`), agreeing with the
  recursive `powMod`. So inverseFp's LOOP ALGORITHM is machine-checked to compute the inverse.

  RESIDUAL (honest, now purely SYNTACTIC): the only thing not in Lean is that the crown's
  bytecode literally IS this loop — verified EMPIRICALLY (`inverseFp(a) = a⁻¹` on random a), the
  same differential/round-trip standard by which the E-derivation's `ederiveOps` matches
  `buildDeriv()`. No modeling/math assumption remains. 0-sorry, [propext, Quot.sound].
-/

namespace Groth16.Fermat

set_option maxRecDepth 10000

/-- Structural (fuel-based) square-and-multiply modular exponentiation — the inverseFp
    algorithm. Fuel bounds the recursion depth (≥ bit-length of the exponent). -/
def powMod : Nat → Nat → Nat → Nat → Nat
  | 0,      _, _, m => 1 % m
  | fuel+1, a, e, m =>
      if e = 0 then 1 % m
      else
        let h := powMod fuel a (e / 2) m
        let sq := (h * h) % m
        if e % 2 = 1 then (sq * a) % m else sq

/-- **`powMod` is genuine modular exponentiation**: `powMod a e m = a^e mod m` (given enough
    fuel). A clean square-and-multiply correctness induction — no number theory. -/
theorem powMod_correct : ∀ (fuel a e m : Nat), e < 2 ^ fuel → powMod fuel a e m = a ^ e % m := by
  intro fuel
  induction fuel with
  | zero =>
    intro a e m he; rw [Nat.pow_zero] at he
    have h0 : e = 0 := by omega
    subst h0; rfl
  | succ n ih =>
    intro a e m he
    have he2 : e / 2 < 2 ^ n := by rw [Nat.pow_succ] at he; omega
    simp only [powMod]
    by_cases h : e = 0
    · subst h; simp
    · rw [if_neg h, ih a (e / 2) m he2]
      have hsq : a ^ (e / 2) % m * (a ^ (e / 2) % m) % m = a ^ (2 * (e / 2)) % m := by
        rw [← Nat.mul_mod, ← Nat.pow_add, show e / 2 + e / 2 = 2 * (e / 2) from by omega]
      by_cases hodd : e % 2 = 1
      · rw [if_pos hodd, hsq, Nat.mod_mul_mod, ← Nat.pow_succ]
        have hE : (2 * (e / 2)).succ = e := by omega
        rw [hE]
      · rw [if_neg hodd, hsq]
        have hE : 2 * (e / 2) = e := by omega
        rw [hE]

/-- **The inverseFp LOOP model**: iterative (forward-accumulating) square-and-multiply modexp —
    the shape of the crown's `inverseFp` BEGIN/UNTIL bytecode loop (state `(result, base, e)`,
    per iteration: conditionally multiply result by base on the low exponent bit, square base,
    halve e). `powMod` above is the recursive form; this is the iterative form the bytecode runs. -/
def modexpLoop : Nat → Nat → Nat → Nat → Nat → Nat
  | 0,      result, _,    _, m => result % m
  | fuel+1, result, base, e, m =>
      if e = 0 then result % m
      else
        modexpLoop fuel (if e % 2 = 1 then result * base % m else result) (base * base % m) (e / 2) m

/-- **The LOOP INVARIANT**: the modexp loop maintains `result · base^e (mod m)`. This is the
    classic square-and-multiply loop-correctness proof — closes "the bytecode loop computes the
    modexp." -/
theorem modexpLoop_inv : ∀ (fuel result base e m : Nat), e < 2 ^ fuel →
    modexpLoop fuel result base e m = result * base ^ e % m := by
  intro fuel
  induction fuel with
  | zero =>
    intro result base e m he; rw [Nat.pow_zero] at he
    have h0 : e = 0 := by omega
    subst h0; simp [modexpLoop]
  | succ n ih =>
    intro result base e m he
    have he2 : e / 2 < 2 ^ n := by rw [Nat.pow_succ] at he; omega
    rw [modexpLoop]
    by_cases h : e = 0
    · subst h; simp
    · rw [if_neg h]
      have hbase : (base * base % m) ^ (e / 2) % m = base ^ (2 * (e / 2)) % m := by
        rw [← Nat.pow_mod, ← Nat.pow_two, ← Nat.pow_mul]
      by_cases hodd : e % 2 = 1
      · rw [if_pos hodd, ih _ _ _ _ he2, Nat.mul_mod, Nat.mod_mod, hbase, ← Nat.mul_mod]
        have hexp : result * base * base ^ (2 * (e / 2)) = result * base ^ e := by
          rw [Nat.mul_assoc, Nat.mul_comm base (base ^ (2 * (e / 2))), ← Nat.pow_succ]
          congr 2; omega
        rw [hexp]
      · rw [if_neg hodd, ih _ _ _ _ he2, Nat.mul_mod, hbase, ← Nat.mul_mod,
            show 2 * (e / 2) = e from by omega]

/-- Started at `result = 1`, the loop computes `a^e mod m` — same as the recursive `powMod`. -/
theorem modexpLoop_pow (fuel a e m : Nat) (he : e < 2 ^ fuel) :
    modexpLoop fuel 1 a e m = a ^ e % m := by
  rw [modexpLoop_inv fuel 1 a e m he, Nat.one_mul]

/-- BN254 base-field prime p. -/
def pNat : Nat := 21888242871839275222246405745257275088696311157297823662689037894645226208583
/-- 82⁻¹ mod p. -/
def inv82Nat : Nat := 7207104360239761353666499452706663748717078063988307791373219794578306190631
/-- Fuel ≥ bit-length of p−2 (≈254). -/
def FUEL : Nat := 260

/-- The Fermat-modexp of 82 is exactly inv82 (kernel computation of the 254-step modexp). -/
theorem inv82_eq_powMod : powMod FUEL 82 (pNat - 2) pNat = inv82Nat := by decide

/-- inv82 is genuinely 82⁻¹ mod p. -/
theorem inv82_is_inverse : (82 * inv82Nat) % pNat = 1 := by decide

/-- **Fermat's little theorem for a = 82, by verified computation**: `82 · (82^(p-2) mod p) ≡ 1
    mod p`. Combines `powMod_correct` (the algorithm IS modexp) with the two `decide`s (its
    value at 82 is inv82, which is 82's inverse) — NO abstract number theory. This is exactly
    what the crown's `inverseFp` subroutine computes, so its output at 82 is the true inverse. -/
theorem fermat_82 : (82 * (82 ^ (pNat - 2) % pNat)) % pNat = 1 := by
  have hbound : pNat - 2 < 2 ^ FUEL := by decide
  rw [← powMod_correct FUEL 82 (pNat - 2) pNat hbound, inv82_eq_powMod]
  exact inv82_is_inverse

/-- **The inverseFp LOOP, run on 82, computes 82⁻¹.** The iterative bytecode-shaped loop
    `modexpLoop` (proven correct by `modexpLoop_inv`), started at `(result=1, base=82, e=p−2)`,
    yields `inv82` = 82's inverse. So inverseFp's LOOP ALGORITHM is machine-checked to compute the
    modular inverse — no longer even an algorithm assumption; the sole residual is the syntactic
    fact that the crown's bytecode IS this loop (checked empirically: `inverseFp(a) = a⁻¹` on
    random a, the same differential standard as the E-derivation's `buildDeriv()` match). -/
theorem inverseFp_loop_at_82 : modexpLoop FUEL 1 82 (pNat - 2) pNat = inv82Nat := by decide

/-- Cross-check: the iterative loop and the recursive `powMod` agree at 82 (both = 82^(p−2) mod p). -/
theorem modexpLoop_eq_powMod_at_82 :
    modexpLoop FUEL 1 82 (pNat - 2) pNat = powMod FUEL 82 (pNat - 2) pNat := by
  rw [inverseFp_loop_at_82, inv82_eq_powMod]

end Groth16.Fermat
