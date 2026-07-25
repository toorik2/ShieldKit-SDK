/-
  INVOKE-transparency — Lean coverage for the marshalling-CSE (global subroutine sharing).

  The crown's marshalling-CSE (−95 B) factors a byte-identical op-subsequence appearing 3× in
  main into ONE shared OP_DEFINE'd body, replacing each site with an OP_INVOKE. Soundness rests
  on OP_INVOKE being STACK-TRANSPARENT: libauth's `opInvoke` looks up the body and runs its
  instructions on the SHARED (main, alt) stack (`pushToControlStack` for the return, then jumps
  in), so invoking a body is behavior-identical to inlining its ops.

  We model a RESOLVED invoke — the body carried directly, i.e. AFTER the id→body table lookup
  (the lookup is a syntactic detail the bytecode round-trip gate checks) — and prove
  transparency + the splice-anywhere congruence. So factoring ANY repeated op-subsequence into a
  shared invoke preserves execution, which is exactly the marshalling-CSE. 0-sorry, [propext].
-/
import LeanBCH.Opt.Basic

namespace LeanBCH.Opt.InvokeCSE
open LeanBCH.Opt
set_option linter.unusedSimpArgs false

/-- Op alphabet with a RESOLVED OP_INVOKE (its body carried post-lookup). `prim` lifts a Basic
    stack op; `invoke b` is OP_INVOKE of the shared body `b`. -/
inductive IOp (α : Type) where
  | prim   (o : Op α)
  | invoke (body : List (IOp α))

open IOp

/-- Execution. `prim o` steps via the Basic `step`; `invoke b` runs `b` on the SHARED stack
    (transparent — libauth OP_INVOKE), then continues. Underflow ⇒ `none`. -/
def irun {α : Type} : List (IOp α) → State α → Option (State α)
  | [],            st => some st
  | prim o :: r,   st => match step o st with | some st' => irun r st' | none => none
  | invoke b :: r, st => match irun b st with | some st' => irun r st' | none => none

/-- `irun` distributes over `++` (sequential composition). -/
theorem irun_append {α} (p q : List (IOp α)) (st : State α) :
    irun (p ++ q) st = (irun p st).bind (irun q) := by
  induction p generalizing st with
  | nil => simp [irun]
  | cons op p ih =>
      cases op with
      | prim o   => simp only [List.cons_append, irun]; cases step o st <;> simp [ih]
      | invoke b => simp only [List.cons_append, irun]; cases irun b st <;> simp [ih]

/-- **INVOKE transparency**: invoking a body is behavior-identical to running its ops inline,
    on EVERY stack. The core of the marshalling-CSE's soundness. -/
theorem invoke_transparent {α} (b : List (IOp α)) (st : State α) :
    irun [invoke b] st = irun b st := by
  simp only [irun]; cases irun b st <;> simp [irun]

/-- **Marshalling-CSE soundness**: in ANY context, an inline op-subsequence `b` and an invoke of
    a shared body containing exactly `b` are behavior-identical. So factoring a repeated
    subsequence into one shared subroutine preserves execution — for any body, at any site. -/
theorem invoke_cse {α} (b pre post : List (IOp α)) (st : State α) :
    irun (pre ++ [invoke b] ++ post) st = irun (pre ++ b ++ post) st := by
  rw [List.append_assoc, List.append_assoc, irun_append, irun_append]
  cases irun pre st with
  | none => rfl
  | some st' =>
      simp only [Option.bind]
      rw [irun_append, invoke_transparent, ← irun_append]

/-- Grounding: an invoke-free program runs exactly like the Basic `run` — so `irun` is a faithful
    conservative extension, and the CSE lemmas above compose with the rest of the recompiler. -/
theorem irun_prim_eq_run {α} (ops : List (Op α)) (st : State α) :
    irun (ops.map prim) st = run ops st := by
  induction ops generalizing st with
  | nil => simp [irun, run]
  | cons o os ih => simp only [List.map_cons, irun, run]; cases step o st <;> simp [ih]

/-- Non-vacuity: a concrete repeated subsequence `[prim DUP, prim DROP]` factored into a shared
    invoke is behavior-identical inline vs invoked. -/
example (st : State Int) :
    irun [invoke [prim DUP, prim DROP]] st = irun [prim DUP, prim DROP] st :=
  invoke_transparent _ st

end LeanBCH.Opt.InvokeCSE
