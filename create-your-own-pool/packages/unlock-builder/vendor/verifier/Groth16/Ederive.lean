/-
  E-derivation arithmetic soundness — BN254 final-exponentiation exponent.

  Closes the one machine-checked gap in the crown's lever chain. The crown replaced
  cashc's baked 2790-bit constant E = (p^12 - 1)/r with an ON-CHAIN computation
  (Horner p → r = p - 6x² → p^12 → p^12-1 → ÷r), saving ~300 B. That substitution is
  sound iff the spliced op-sequence really computes E — proven here by KERNEL evaluation.

  The recompiler proofs (`schedule_refines`, ...) are POLYMORPHIC over the value type α:
  they preserve WIRING, not arithmetic meaning, so they say nothing about what the
  arithmetic opcodes compute. Here we do the complementary half — INSTANTIATE α := ℤ,
  give the BCH2026 arithmetic opcodes (MUL/ADD/SUB/DIV) concrete signed-bignum semantics,
  and evaluate the exact sequence `ederive-deriv.mjs::buildDeriv()` splices in.

  Proof discipline: `decide` (kernel reduction, GMP-accelerated Nat/Int literals) —
  NOT `native_decide`, which the stackcert axiom-hygiene gate forbids (Lean.ofReduceBool).
-/
import LeanBCH.Opt.Basic
import Groth16.Fermat

namespace Groth16.Ederive
open LeanBCH.Opt LeanBCH.Opt.Op
set_option linter.unusedSimpArgs false   -- the big twist/tail-derive `simp only` reductions

/-- BCH2026 signed-bignum arithmetic opcodes over ℤ, modeled as value-DAG `CALL 2` nodes.
    `step`'s CALL passes operands bottom→top: `[a, b]` = (second-from-top, top), so `f`
    computes the BCH stack effect `a OP b` (e.g. `OP_SUB` = second − top). -/
def mulOp : Op Int := CALL 2 (fun l => match l with | [a, b] => [a * b] | _ => l)  -- 0x95
def addOp : Op Int := CALL 2 (fun l => match l with | [a, b] => [a + b] | _ => l)  -- 0x93
def subOp : Op Int := CALL 2 (fun l => match l with | [a, b] => [a - b] | _ => l)  -- 0x94
def divOp : Op Int := CALL 2 (fun l => match l with | [a, b] => [a / b] | _ => l)  -- 0x96

/-- The BN254 seed x (baked in the derivation). -/
def X : Int := 4965661367192848881

/-- BN254 base-field prime p(x) = 36x⁴+36x³+24x²+6x+1 (Horner form, as the ops compute it). -/
def pDef : Int := (((36*X + 36)*X + 24)*X + 6)*X + 1
/-- BN254 scalar-field order r = p − 6x² (since p − r = 6x²). -/
def rDef : Int := pDef - 6*X*X
/-- p^12 as the ops build it: p² → p⁴ → p⁸ → p⁸·p⁴. -/
def p2  : Int := pDef * pDef
def p4  : Int := p2 * p2
def p8  : Int := p4 * p4
def p12 : Int := p8 * p4
/-- The BN254 final-exp exponent E = (p^12 − 1)/r (2790-bit; exact — r ∣ p^12−1). -/
def Eval : Int := (p12 - 1) / rDef

/-- The EXACT op-sequence `buildDeriv()` splices into the crown (head = top of stack).
    `OP_2 OP_PICK` (constant index) folds to the static `PICK 2`; `OP_1/OP_6`/data pushes
    map to `PUSH`. Hand-traced stack comments are bottom→top. -/
def ederiveOps : List (Op Int) :=
  [ PUSH X,                       -- [x]
    PUSH 36, OVER, mulOp,         -- [x, 36x]
    PUSH 36, addOp,               -- [x, 36x+36]
    OVER, mulOp,                  -- [x, (36x+36)x]
    PUSH 24, addOp,               -- [x, ((36x+36)x)+24]
    OVER, mulOp,
    PUSH 6, addOp,
    OVER, mulOp,
    PUSH 1, addOp,                -- [x, p]
    DUP, PICK 2,                  -- [x, p, p, x]   (copy x up)
    DUP, mulOp,                   -- [x, p, p, x²]
    PUSH 6, mulOp,                -- [x, p, p, 6x²]
    subOp,                        -- [x, p, p−6x²] = [x, p, r]
    ROT, DROP,                    -- [r, p]          (rotate x to top, drop it)
    SWAP,                         -- [p, r]
    DUP, mulOp,                   -- [p², r]
    DUP, mulOp,                   -- [p⁴, r]
    DUP, DUP, mulOp, mulOp,       -- [p¹², r]
    PUSH 1, subOp,                -- [p¹²−1, r]
    SWAP, divOp ]                 -- [(p¹²−1)/r] = [E]

/-- **The E-derivation is arithmetically sound**: the spliced op-sequence, run on the
    empty stack, leaves exactly the BN254 final-exp exponent E = (p^12−1)/r on top.
    Kernel `decide` — axiom-clean (no `native_decide`/`sorryAx`). -/
theorem ederive_computes_E :
    run ederiveOps (([] : List Int), ([] : List Int)) = some ([Eval], []) := by decide

/-- **Composable soundness**: the derivation is a behavior-preserving rewrite of the baked
    `PUSH E` — on ANY underlying stack it computes E on top and leaves the rest untouched.
    Via `Correct.congr` this licenses splicing the derivation in place of the baked constant
    ANYWHERE in the program, so it composes into whole-program soundness exactly like a fold. -/
theorem ederive_pushes_E : Correct ([PUSH Eval] : List (Op Int)) ederiveOps := by
  intro ⟨s, a⟩
  simp only [ederiveOps, run, step, mulOp, addOp, subOp, divOp,
             List.cons_append, List.nil_append, List.singleton_append,
             List.take_succ_cons, List.take_zero, List.drop_succ_cons, List.drop_zero,
             List.reverse_cons, List.reverse_nil, List.reverseAux, List.append,
             removeNth, List.length_cons, List.length_nil,
             List.getElem?_cons_zero, List.getElem?_cons_succ,
             Option.bind, Option.map,
             Nat.succ_le_succ_iff, Nat.zero_le, decide_true, ite_true,
             Nat.le_add_left, Nat.reduceLeDiff]
  -- goal: some (Eval :: s, a) = some (<inlined E-arithmetic> :: s, a); peel s,a then decide
  refine congrArg (fun v => some (v :: s, a)) ?_
  decide

/-! ### Tail-derive: inv2 = (p+1)/2 — the crown's tail-derive lever (modular inverse of 2). -/

/-- inv2 = (p+1)/2. Since p is odd this is an exact integer, and it is 2⁻¹ mod p
    (2·inv2 ≡ 1 mod p; pinned below). -/
def inv2 : Int := (pDef + 1) / 2

/-- Tail-derive op-sequence: from p, compute (p+1)/2. (In the crown p itself arrives via the
    p-provider — `Providers.invoke_const_provider` — then this arithmetic; here p is the base.) -/
def tailOps : List (Op Int) := [PUSH pDef, PUSH 1, addOp, PUSH 2, divOp]

/-- The tail-derive computes inv2 on the empty stack. -/
theorem tail_computes_inv2 :
    run tailOps (([] : List Int), ([] : List Int)) = some ([inv2], []) := by decide

/-- **Composable soundness (tail-derive)**: computing (p+1)/2 on-chain is a `Correct` rewrite of
    the baked inv2 push, on any stack. -/
theorem tail_pushes_inv2 : Correct ([PUSH inv2] : List (Op Int)) tailOps := by
  intro ⟨s, a⟩
  simp only [tailOps, run, step, addOp, divOp,
             List.cons_append, List.nil_append, List.singleton_append,
             List.take_succ_cons, List.take_zero, List.drop_succ_cons, List.drop_zero,
             List.reverse_cons, List.reverse_nil, List.reverseAux, List.append,
             List.length_cons, List.length_nil, Option.bind, Option.map,
             Nat.succ_le_succ_iff, Nat.zero_le, decide_true, ite_true,
             Nat.le_add_left, Nat.reduceLeDiff]
  refine congrArg (fun v => some (v :: s, a)) ?_
  decide

/-- inv2 really is 2⁻¹ mod p. -/
example : (2 * inv2) % pDef = 1 := by decide

/-! ### Twist-derive: b2 = (27/82, −3/82) ∈ Fp2 — the crown's twist-derive lever.

    b2 needs the MODULAR INVERSE `inv82 = 82⁻¹ mod p`, which the crown computes via its
    `inverseFp` subroutine (254-iter square-and-multiply = Fermat, a^(p−2) mod p). `Groth16.Fermat`
    now discharges the number theory RIGOROUSLY: `powMod_correct` (the modexp algorithm genuinely
    computes a^e mod m) + `fermat_82` (82·(82^(p−2) mod p) ≡ 1 mod p — Fermat's little theorem for
    82, by VERIFIED COMPUTATION, no mathlib) + `inv82_eq_powMod` (82^(p−2) mod p = inv82). So
    inverseFp's OUTPUT at 82 is PROVEN to be 82⁻¹ (linked in `inv82_eq_fermat` below), NOT assumed.
    `Fermat` ALSO models inverseFp's BEGIN/UNTIL loop (`modexpLoop`, iterative square-and-multiply)
    and proves its LOOP INVARIANT (`modexpLoop_inv` ⇒ the loop computes a^e mod m), with
    `inverseFp_loop_at_82` = inv82. So the LOOP ALGORITHM is machine-checked. NO modeling/math
    residual remains — only the empirical fact that the crown's bytecode IS this loop, confirmed
    the same way as every lever: the crown's inverseFp (def#6) computes a⁻¹ on 60/60 field
    elements + exact at 82, and the whole-verifier E2E (4/4+4/4) depends on it. -/

/-- 82⁻¹ mod p — `inverseFp`'s output at 82 (certified below). -/
def inv82 : Int := 7207104360239761353666499452706663748717078063988307791373219794578306190631
/-- BCH mod-p multiplication (mulFp), as a value-DAG CALL. -/
def mulFpOp : Op Int := CALL 2 (fun l => match l with | [a, b] => [(a * b) % pDef] | _ => l)
/-- `inverseFp` evaluated at 82, modeled by its (separately-verified) output inv82. -/
def invFp82 : Op Int := CALL 1 (fun l => match l with | [_] => [inv82] | _ => l)
/-- BN254 G2 twist b-coefficient b2 = 3/(9+u) = (27/82, −3/82) ∈ Fp2 (pinned below).
    Written in the on-chain multiply order (inv82·k) so the derivation reduces to these verbatim. -/
def b2c0 : Int := (inv82 * 27) % pDef
def b2c1 : Int := (inv82 * (pDef - 3)) % pDef

/-- Twist-derive op-sequence: 82 → inv82 (inverseFp), then b2c0 = 27·inv82, b2c1 = (p−3)·inv82 mod p. -/
def twistOps : List (Op Int) :=
  [PUSH 82, invFp82, DUP, PUSH 27, mulFpOp, SWAP, PUSH (pDef - 3), mulFpOp]

/-- The twist-derive computes b2 on the empty stack (top = b2c1, then b2c0). -/
theorem twist_computes_b2 :
    run twistOps (([] : List Int), ([] : List Int)) = some ([b2c1, b2c0], []) := by decide

/-- **Composable soundness (twist-derive, conditional on inverseFp)**: computing b2 on-chain is a
    `Correct` rewrite of the two baked b2 pushes, on any stack. -/
theorem twist_pushes_b2 : Correct ([PUSH b2c0, PUSH b2c1] : List (Op Int)) twistOps := by
  intro ⟨s, a⟩
  simp only [twistOps, run, step, mulFpOp, invFp82, b2c0, b2c1,
             List.cons_append, List.nil_append, List.singleton_append,
             List.take_succ_cons, List.take_zero, List.drop_succ_cons, List.drop_zero,
             List.reverse_cons, List.reverse_nil, List.reverseAux, List.append,
             List.length_cons, List.length_nil, Option.bind, Option.map,
             Nat.succ_le_succ_iff, Nat.zero_le, decide_true, ite_true,
             Nat.le_add_left, Nat.reduceLeDiff]

/-- inv82 is genuinely 82⁻¹ mod p, and b2 = (b2c0, b2c1) is the real BN254 twist coefficient. -/
example : (82 * inv82) % pDef = 1 := by decide

/-- The twist's `inv82` is exactly `Fermat.inv82Nat`, which `Groth16.Fermat` proves equals
    `82^(p−2) mod p` (= what inverseFp computes) and is 82⁻¹ — so the modeled inverseFp output is
    VERIFIED, not assumed. -/
theorem inv82_eq_fermat : inv82 = (Fermat.inv82Nat : Int) := by decide
example : b2c0 = 19485874751759354771024239261021720505790618469301721065564631296452457478373 := by decide
example : b2c1 = 266929791119991161246907387137283842545076965332900288569378510910307636690 := by decide

/-- Sanity pin: p and r are the actual BN254 field prime and scalar order, and E is the
    known 2790-bit exponent — so `ederive_computes_E` is about the real constant. -/
example : pDef = 21888242871839275222246405745257275088696311157297823662689037894645226208583 := by decide
example : rDef = 21888242871839275222246405745257275088548364400416034343698204186575808495617 := by decide
/-- E is the exact 2790-bit BN254 final-exponentiation exponent (the value cashc baked and
    the derivation reconstructs on-chain). -/
example : Eval = 552484233613224096312617126783173147097382103762957654188882734314196910839907541213974502761540629817009608548654680343627701153829446747810907373256841551006201639677726139946029199968412598804882391702273019083653272047566316584365559776493027495458238373902875937659943504873220554161550525926302303331747463515644711876653177129578303191095900909191624817826566688241804408081892785725967931714097716709526092261278071952560171111444072049229123565057483750161460024353346284167282452756217662335528813519139808291170539072125381230815729071544861602750936964829313608137325426383735122175229541155376346436093930287402089517426973178917569713384748081827255472576937471496195752727188261435633271238710131736096299798168852925540549342330775279877006784354801422249722573783561685179618816480037695005515426162362431072245638324744480 := by decide

end Groth16.Ederive
