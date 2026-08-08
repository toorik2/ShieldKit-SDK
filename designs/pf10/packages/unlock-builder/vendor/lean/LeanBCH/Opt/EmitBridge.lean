/-
  LeanBCH.Opt.EmitBridge — the scheduler's emitted program, run on the REAL VM, computes the DAG
  denotation. Composes the acceptance bridge (`run_via_encode_accept`, increment 4c) with the
  scheduler's own refinement theorem (`schedule_refines`).

  `schedule_refines` proves `Opt.run (emit b) (entryState M A) = some (denote b M A)` on the ABSTRACT
  machine (for any valid topological schedule). The acceptance bridge proves `foldStraight (encoded) =
  Opt.run` on LeanBCH's real straight-line `stepInstr` interpreter, given each emitted op is faithful
  under its precondition and that precondition is recoverable from acceptance. Chaining them: the bytes
  the scheduler emits for a `WellFormed` block, run without error on the genuine VM, produce EXACTLY
  the block's value-DAG denotation — the whole PASS-2 pipeline landed on the real machine (still
  parameterized by `enc` + its per-op faithfulness; supplying those concretely is increment 4d).
-/
import LeanBCH.Opt.AcceptBridge
import LeanBCH.Opt.Core

namespace LeanBCH.Opt.Adapter
open LeanBCH LeanBCH.VM LeanBCH.Opt LeanBCH.Opt.Op

/-- ★ THE SCHEDULER, ON THE REAL VM. For a `WellFormed` block `b` and entry value-lists `M`/`A` of the
    right sizes: under any encoder whose every emitted op is faithful on its precondition (`SimOpOn`)
    with that precondition recoverable from acceptance (`hconv`, e.g. the `accept_pre_*` family), the
    bytes `emit b` encodes — run from the entry state on LeanBCH's real `foldStraight`/`stepInstr` VM
    WITHOUT error — compute exactly the DAG denotation `denote b M A`. `run_via_encode_accept` bridges
    to `Opt.run (emit b)`; `schedule_refines` equates that to `some (denote b M A)`. -/
theorem emit_sound_under_VM (enc : Op Bytes → List Instr) (P : Op Bytes → Stack → Stack → Prop)
    (b : Block Bytes) (hwf : WellFormed b) (M A : List Bytes)
    (hM : M.length = b.entryDepth) (hA : A.length = b.entryAlt)
    (hsim : ∀ op ∈ emit b, SimOpOn (P op) op (enc op))
    (hconv : ∀ op ∈ emit b, ∀ st al : Stack, foldStraight (enc op) st al ≠ none → P op st al)
    (hacc : foldStraight ((emit b).flatMap enc) (entryState M A).1 (entryState M A).2 ≠ none) :
    foldStraight ((emit b).flatMap enc) (entryState M A).1 (entryState M A).2 = some (denote b M A) := by
  rw [run_via_encode_accept enc P (emit b) hsim hconv (entryState M A).1 (entryState M A).2 hacc]
  exact schedule_refines b hwf M A hM hA

end LeanBCH.Opt.Adapter
