/-
  LeanBCH.Cost.Metrics — the five-metric BCH-2026 VM cost record + the
  epoch-parameterized `operationCost` roll-up.

  The FIVE primitive metrics libauth's VM accumulates per BCH-2026 consensus
  (`measureOperationCost`, `vm/instruction-sets/bch/2025/bch-2025-consensus.ts`);
  `operationCost` is the DERIVED linear aggregate. Pure Lean 4 core, NO mathlib.

  ONE change from the stackcert original (`stackcert/Stackcert/Cost/Metrics.lean`,
  lines 18-99, transcribed here): the consensus pins (100 / 26000 / 192) were baked
  literals there; here they are read from the `Epoch` record (`E.baseInstructionCost`,
  `E.signatureCheckCost`, `E.hashDigestIterationCost`), so `operationCost` /
  `operationCost_add` hold for ANY epoch and a May repricing is a new `Epoch` value —
  no baked consensus literal survives in this file.

  This is the cost half of the engine's orthogonal axes; it never touches VM
  semantics — cost is a fold *alongside* `step`/`run`, not part of it.
-/
import LeanBCH.Epoch

namespace LeanBCH.Cost

/-- The five primitive BCH-2026 VM cost metrics (libauth `measureOperationCost`). -/
structure Metrics where
  evaluatedInstructionCount : Nat := 0
  signatureCheckCount       : Nat := 0
  hashDigestIterations      : Nat := 0
  arithmeticCost            : Nat := 0
  stackPushedBytes          : Nat := 0
deriving DecidableEq, Repr

namespace Metrics

/-- The additive unit. -/
def zero : Metrics := {}

/-- Componentwise addition — libauth accumulates each metric independently. -/
def add (a b : Metrics) : Metrics where
  evaluatedInstructionCount := a.evaluatedInstructionCount + b.evaluatedInstructionCount
  signatureCheckCount       := a.signatureCheckCount + b.signatureCheckCount
  hashDigestIterations      := a.hashDigestIterations + b.hashDigestIterations
  arithmeticCost            := a.arithmeticCost + b.arithmeticCost
  stackPushedBytes          := a.stackPushedBytes + b.stackPushedBytes

instance : Add Metrics := ⟨add⟩

theorem add_eq (a b : Metrics) : a + b = add a b := rfl

theorem add_zero (a : Metrics) : a + zero = a := by
  simp only [add_eq]; cases a; simp [add, zero]

theorem zero_add (a : Metrics) : zero + a = a := by
  simp only [add_eq]; cases a; simp [add, zero]

theorem add_assoc (a b c : Metrics) : a + b + c = a + (b + c) := by
  simp only [add_eq]; cases a; cases b; cases c
  simp only [add, Nat.add_assoc]

end Metrics

/-- The DERIVED aggregate op-cost, epoch-parameterized. Mirrors libauth
    `measureOperationCost` exactly (a linear functional of the five metrics), but
    reads the three RATE pins from `E : Epoch` rather than baking 100 / 26000 / 192. -/
def operationCost (E : Epoch) (m : Metrics) : Nat :=
  m.evaluatedInstructionCount * E.baseInstructionCost
  + m.signatureCheckCount * E.signatureCheckCost
  + m.hashDigestIterations * E.hashDigestIterationCost
  + m.arithmeticCost
  + m.stackPushedBytes

/-- `operationCost E` is a linear functional ⇒ additive over `Metrics.+`, for ANY epoch. -/
theorem operationCost_add (E : Epoch) (a b : Metrics) :
    operationCost E (a + b) = operationCost E a + operationCost E b := by
  simp only [Metrics.add_eq]; cases a; cases b
  -- pins are now epoch VARIABLES, so `(x+y)*E.pin` is nonlinear for omega;
  -- distribute right-multiplication first, then the rest is linear.
  simp only [Metrics.add, operationCost, Nat.add_mul]
  omega

/-- BCH_2026_05 witness: three evaluated instructions (100 each) + 9 pushed bytes
    = 309 op-cost under the real May-2026 pins. Pins the epoch parameterization end-to-end. -/
theorem operationCost_309 :
    operationCost BCH_2026_05 { evaluatedInstructionCount := 3, stackPushedBytes := 9 } = 309 := by
  decide

/-- The abstract weighted syntactic fold, given ANY per-element weight `κ`. This is the
    α-generic spine of the cost model; concrete weights come from the op-trace layers. -/
def progWeight {α : Type} (κ : α → Metrics) : List α → Metrics :=
  List.foldr (fun a acc => κ a + acc) Metrics.zero

@[simp] theorem progWeight_nil {α} (κ : α → Metrics) :
    progWeight κ [] = Metrics.zero := rfl

@[simp] theorem progWeight_cons {α} (κ : α → Metrics) (a : α) (p : List α) :
    progWeight κ (a :: p) = κ a + progWeight κ p := rfl

/-- Split-invariance of the weighted fold — the pure shadow of `run_append`.
    Cost distributes over program concatenation. -/
theorem cost_append {α} (κ : α → Metrics) (p q : List α) :
    progWeight κ (p ++ q) = progWeight κ p + progWeight κ q := by
  induction p with
  | nil => simp only [List.nil_append, progWeight_nil, Metrics.zero_add]
  | cons a p ih => simp only [List.cons_append, progWeight_cons, ih, Metrics.add_assoc]

end LeanBCH.Cost
