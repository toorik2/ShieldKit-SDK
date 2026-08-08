/-
  BCH-2026 stack sub-VM — verified-by-construction recompiler spike.

  Models the stack-machine sub-VM that the byte-recompiler
  (tools/singleton-recompiler, [[E-singleton-step2-recompiler]]) rewrites.
  Goal: prove the recompiler's rewrite rules are pure stack-function
  equivalences, so each pass is correct for ALL inputs (not just the
  8-random-Fp differential test currently gating the hot loop).

  Lean 4 core only. NO mathlib. Val is a type parameter `α` (opaque): these
  rewrites preserve stack SHAPE / value-positions, not crypto meaning, so the
  element type is irrelevant and left abstract.

  Semantics faithful to libauth BCH2026 / tools/singleton-recompiler/decompile.mjs.
  Convention: a stack is a `List α` with the HEAD = TOP of stack (the reverse of
  decompile.mjs's bottom→top arrays; the two are isomorphic and this convention
  makes the ops pattern-match cleanly). Underflow ⇒ `none` (total, faithful:
  the real VM aborts on underflow, and a correct rewrite must abort on exactly
  the same inputs).
-/

namespace Recompiler

/-- Machine state: (main stack, alt stack), head = top. -/
abbrev State (α : Type) := List α × List α

/-- Remove the element at 0-based depth `n` (0 = top). -/
def removeNth {α : Type} (l : List α) (n : Nat) : List α :=
  l.take n ++ l.drop (n + 1)

/-- The BCH-2026 stack op-subset the recompiler manipulates.
    Opcodes (libauth / BCH2026) noted for grounding. -/
inductive Op (α : Type) where
  | DUP                 -- 0x76
  | DROP                -- 0x75
  | OVER                -- 0x78
  | SWAP                -- 0x7c
  | ROT                 -- 0x7b
  | NIP                 -- 0x77
  | TUCK                -- 0x7d
  | PICK (n : Nat)      -- 0x79  (depth n copied to top)
  | ROLL (n : Nat)      -- 0x7a  (depth n moved to top)
  | TOALT               -- 0x6b  OP_TOALTSTACK
  | FROMALT             -- 0x6c  OP_FROMALTSTACK
  | TWODROP             -- 0x6d  OP_2DROP
  | TWODUP              -- 0x6e  OP_2DUP
  | THREEDUP            -- 0x6f  OP_3DUP
  | TWOOVER             -- 0x70  OP_2OVER
  | TWOROT              -- 0x71  OP_2ROT
  | TWOSWAP             -- 0x72  OP_2SWAP
  | PUSH (v : α)        -- data / small-int push (const)
  -- Abstract value-DAG node op (VALOP / INVOKE): pops `nin` operands off the top
  -- (bottom→top order) and pushes `sem`'s outputs. Uninterpreted `sem` ⇒ only the
  -- WIRING matters, exactly the spike's opaque-α philosophy. Used by the PASS-2
  -- DAG scheduler model (Scheduler.lean). Note: a function field means `Op` can no
  -- longer `deriving Repr`; nothing in the library used that instance.
  | CALL (nin : Nat) (sem : List α → List α)

open Op

/-- Single-step interpreter. `none` = underflow / abort. -/
def step {α : Type} : Op α → State α → Option (State α)
  | DUP,     (x :: s,           a) => some (x :: x :: s, a)
  | DROP,    (_ :: s,           a) => some (s, a)
  | OVER,    (x :: y :: s,      a) => some (y :: x :: y :: s, a)
  | SWAP,    (x :: y :: s,      a) => some (y :: x :: s, a)
  | ROT,     (x :: y :: z :: s, a) => some (z :: x :: y :: s, a)
  | NIP,     (x :: _ :: s,      a) => some (x :: s, a)
  | TUCK,    (x :: y :: s,      a) => some (x :: y :: x :: s, a)
  | PICK n,  (s,                a) => (s[n]?).map (fun v => (v :: s, a))
  | ROLL n,  (s,                a) =>
      match s[n]? with
      | some v => some (v :: removeNth s n, a)
      | none   => none
  | TOALT,   (x :: s,           a) => some (s, x :: a)
  | FROMALT, (s,           x :: a) => some (x :: s, a)
  | TWODROP, (_ :: _ :: s,      a) => some (s, a)
  | TWODUP,  (x :: y :: s,      a) => some (x :: y :: x :: y :: s, a)
  | THREEDUP,(x :: y :: z :: s, a) => some (x :: y :: z :: x :: y :: z :: s, a)
  | TWOOVER, (x :: y :: z :: w :: s, a) => some (z :: w :: x :: y :: z :: w :: s, a)
  | TWOROT,  (x :: y :: z :: w :: u :: v :: s, a) => some (u :: v :: x :: y :: z :: w :: s, a)
  | TWOSWAP, (x :: y :: z :: w :: s, a) => some (z :: w :: x :: y :: s, a)
  | PUSH v,  (s,                a) => some (v :: s, a)
  | CALL nin f, (s,             a) =>
      -- pop top `nin` (= reverse of operand bottom→top order), apply `f` bottom→top,
      -- reverse the result so out[nout-1] lands on top. Underflow ⇒ none.
      if nin ≤ s.length then
        some ((f ((s.take nin).reverse)).reverse ++ s.drop nin, a)
      else none
  | _,       _                     => none   -- any underflow case

/-- Run a program (fold with short-circuit on `none`). -/
def run {α : Type} : List (Op α) → State α → Option (State α)
  | [],      st => some st
  | op :: p, st => match step op st with
                   | some st' => run p st'
                   | none     => none

/-- A rewrite `src ⇒ dst` is CORRECT iff it yields the identical (main,alt)
    result on EVERY input state (including identical failure). This is the
    universally-quantified replacement for the recompiler's 8-input differential test. -/
def Correct {α : Type} (src dst : List (Op α)) : Prop :=
  ∀ st : State α, run src st = run dst st

/-- Sequential composition: `run` distributes over append. -/
theorem run_append {α : Type} (p q : List (Op α)) (st : State α) :
    run (p ++ q) st = (run p st).bind (run q) := by
  induction p generalizing st with
  | nil => rfl
  | cons op p ih =>
      simp only [List.cons_append, run]
      cases step op st with
      | none => rfl
      | some st' => simp [ih]

/-- Congruence: a correct rewrite can be spliced into any context `pre ++ · ++ post`.
    This is the substitution lemma that lets a proven peephole be applied ANYWHERE
    in a block, so per-rule proofs compose into whole-pass correctness. -/
theorem Correct.congr {α : Type} {src dst : List (Op α)}
    (h : Correct src dst) (pre post : List (Op α)) :
    Correct (pre ++ src ++ post) (pre ++ dst ++ post) := by
  intro st
  simp only [run_append]
  cases run pre st with
  | none => rfl
  | some st' =>
      simp only [Option.bind]
      rw [h st']

end Recompiler
