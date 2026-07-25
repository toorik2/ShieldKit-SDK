/-
  COPY-FLOOR — the combinatorial lower bound on stack-COPY instructions for a value-DAG emitter.

  ★ THE CLAIM: in any straight-line stack program, a value produced ONCE but CONSUMED
  (popped as an operand) `k` times forces ≥ `k - 1` explicit COPY (dup) instructions. This is
  a pure conservation / counting argument, proved here over a minimal 3-instruction machine
  (`push` produces, `dup` is the ONLY copy primitive, `pop` models one operand-consumption).
  It is the rigorous core of the byte lower bound on the PASS-2 DAG scheduler: a value-DAG node
  output with fan-out `k` is a value produced once and demanded `k` times.

  ★ WHAT IT DOES / DOES NOT BOUND (honest): this bounds the COPY floor (how many duplications a
  fan-out forces) — a genuine, tight lower bound (met with equality by the witness below). It
  does NOT bound the MOVEMENT/reordering cost (ROLL/PICK depth, stale-tail deletion): choosing a
  stack layout that minimises total movement is a scheduling problem with no comparable clean
  closed form (bounded-register stack sequencing is NP-hard), and is deliberately OUT OF SCOPE.

  Integrated into the project (`LeanBCH.Opt.Dag` import) as `LeanBCH.Opt/Floor.lean`; the counting
  model lives in the nested `LeanBCH.Opt.Floor` namespace, and `LeanBCH.Opt.fanout` ties the model's
  pop-count to the value-DAG's fan-out (see the bridging note). Lean 4.31 core, NO mathlib.

  ★ STATUS: REFERENCE LEMMA — NOT LOAD-BEARING. `copy_floor` bounds an ABSTRACT 3-instruction
  counting machine, not the scheduler's real `emit`/`emitMove` byte output; the bridge from this
  model to the actual emitted program is the HONEST BRIDGE CAVEAT below, and is not proven. It has
  no downstream proof consumer. Kept as a proven combinatorial reference for the fan-out floor, NOT
  as a live byte-count lower bound on any program the optimizer produces.
-/
import LeanBCH.Opt.Dag

namespace LeanBCH.Opt

/-! ## The isolated copy-floor counting model.
    A minimal stack machine: `push v` produces one occurrence of `v`, `dup` copies the top
    (the sole copy primitive), `pop` consumes the top (one operand-consumption). All counts
    are per-value, and the conservation law is proved by structural induction on the program. -/
namespace Floor

inductive Inst where
  | push (v : Nat)
  | dup
  | pop
deriving DecidableEq

abbrev Stack := List Nat

def step (s : Stack) : Inst → Stack
  | .push v => v :: s
  | .dup    => match s with | []      => []       | x :: xs => x :: x :: xs
  | .pop    => match s with | []      => []       | _ :: xs => xs

def run (s : Stack) : List Inst → Stack
  | []      => s
  | i :: is => run (step s i) is

/-- occurrences of `v` in a stack -/
def cnt (v : Nat) : Stack → Nat
  | []      => 0
  | x :: xs => (if x = v then 1 else 0) + cnt v xs

/-- top-of-stack equals v (0/1) -/
def topEq (v : Nat) : Stack → Nat
  | []     => 0
  | x :: _ => if x = v then 1 else 0

/-- runtime event counters for v: (#push v, #dup-of-v, #pop-of-v) along the real trace -/
def evc (v : Nat) : Stack → List Inst → (Nat × Nat × Nat)
  | _, []      => (0, 0, 0)
  | s, i :: is =>
      let r := evc v (step s i) is
      match i with
      | .push w => ((if w = v then 1 else 0) + r.1, r.2.1, r.2.2)
      | .dup    => (r.1, topEq v s + r.2.1, r.2.2)
      | .pop    => (r.1, r.2.1, topEq v s + r.2.2)

/-- one-step count laws -/
theorem cnt_push (v w : Nat) (s : Stack) :
    cnt v (step s (.push w)) = (if w = v then 1 else 0) + cnt v s := by
  simp [step, cnt]

theorem cnt_dup (v : Nat) (s : Stack) :
    cnt v (step s .dup) = topEq v s + cnt v s := by
  cases s with
  | nil => simp [step, cnt, topEq]
  | cons x xs => by_cases h : x = v <;> simp [step, cnt, topEq, h] <;> omega

theorem cnt_pop (v : Nat) (s : Stack) :
    cnt v s = topEq v (s) + cnt v (step s .pop) := by
  cases s with
  | nil => simp [step, cnt, topEq]
  | cons x xs => simp [step, cnt, topEq]

/-- ★ CONSERVATION LAW (proved by induction on the program):
    occurrences remaining + pops = occurrences initial + pushes + dups (all for v). -/
theorem conserve (v : Nat) (s : Stack) (prog : List Inst) :
    cnt v (run s prog) + (evc v s prog).2.2
      = cnt v s + (evc v s prog).1 + (evc v s prog).2.1 := by
  induction prog generalizing s with
  | nil => simp [run, evc]
  | cons i is ih =>
    cases i with
    | push w =>
      simp only [run, evc]
      have h := ih (step s (.push w))
      have hc := cnt_push v w s
      omega
    | dup =>
      simp only [run, evc]
      have h := ih (step s .dup)
      have hc := cnt_dup v s
      omega
    | pop =>
      simp only [run, evc]
      have h := ih (step s .pop)
      have hc := cnt_pop v s
      omega

/-- ★ THE COPY FLOOR: if v starts absent, ends absent, and is pushed exactly once,
    then the number of dup-of-v events is at least (#pops of v) - 1.
    i.e. serving `k = pops` consumptions of a once-produced value costs ≥ k-1 copies. -/
theorem copy_floor (v : Nat) (prog : List Inst)
    (hstart : cnt v [] = 0)
    (hend   : cnt v (run [] prog) = 0)
    (hpush  : (evc v [] prog).1 = 1) :
    (evc v [] prog).2.1 + 1 ≥ (evc v [] prog).2.2 := by
  have h := conserve v [] prog
  omega

/-- Corollary in the usual direction: dups ≥ pops - 1 (Nat-safe form above).
    Each dup is one instruction, so prog.length ≥ (#pops of v) - 1 for that single v,
    and summing the independent per-value dup events gives prog.length ≥ sum (fanout-1). -/
theorem dups_ge (v : Nat) (prog : List Inst)
    (hend  : cnt v (run [] prog) = 0)
    (hpush : (evc v [] prog).1 = 1) :
    (evc v [] prog).2.2 ≤ (evc v [] prog).2.1 + 1 := by
  have h := conserve v [] prog
  simp [cnt] at h
  omega

/-- ★ NON-VACUITY (model side): a concrete program that pushes v = 7 once and pops it 3 times
    has event counts (#push, #dup, #pop) = (1, 2, 3) and ends with an empty stack. So serving
    fan-out 3 costs exactly 2 dups — the floor is met with EQUALITY, and the model is not
    degenerate (it genuinely tracks pushes/dups/pops and clears the stack). -/
example :
    evc 7 [] [Inst.push 7, Inst.dup, Inst.dup, Inst.pop, Inst.pop, Inst.pop] = (1, 2, 3)
  ∧ run [] [Inst.push 7, Inst.dup, Inst.dup, Inst.pop, Inst.pop, Inst.pop] = ([] : Stack) := by
  decide

/-- ★ The copy-floor lemma FIRES on that witness: its hypotheses hold and it yields dups+1 ≥ pops
    (here 2+1 ≥ 3), a non-vacuous instantiation. -/
example :
    (evc 7 [] [Inst.push 7, Inst.dup, Inst.dup, Inst.pop, Inst.pop, Inst.pop]).2.1 + 1
      ≥ (evc 7 [] [Inst.push 7, Inst.dup, Inst.dup, Inst.pop, Inst.pop, Inst.pop]).2.2 :=
  copy_floor 7 _ rfl rfl rfl

end Floor

/-! ## Bridging the copy-floor to the value-DAG (`LeanBCH.Opt.Dag`).

    In a `Block α`, a value-ref `r` is CONSUMED once per occurrence in the demand multiset
    `nodes.flatMap Node.ins ++ exit ++ exitAlt`; its FAN-OUT is that count (`fanout` below). A
    node output `out nid j` is PRODUCED once — its `CALL` pushes it a single time. The scheduler
    (`LeanBCH.Opt.Scheduler.emitFetch`) serves each consuming edge by exactly one stack primitive:
    a MOVE (ROLL/SWAP/ROT, `moveOps`) on the LAST use, or a COPY (PICK/OVER/DUP, `copyOps`) on
    every EARLIER use. Only the COPYs add duplications. Under the map produce ↦ `push`,
    each COPY ↦ `dup`, each consume ↦ `pop`, a value's emitter sub-trace is exactly a `Floor`
    program with `#push = 1` and `#pop = fanout`; `copy_floor` then gives `#copies ≥ fanout − 1`.

    ★ SCOPE (honest): `fanout` and this correspondence are DEFINED/DOCUMENTED here; the counting
    THEOREM (`copy_floor`) is mechanically proven over the `Floor` model. What is NOT mechanised
    is that `Scheduler.emit` realises exactly this per-value push/pop sub-trace (that needs a
    per-value projection of the full emitter trace). So the bound is a floor on the abstract
    serve model — asserted by construction of the emitter — not yet a proven property of `emit`. -/

/-- Fan-out of a value-ref in a block: how many times it is demanded, as a node operand or an
    exit/exit-alt slot. Uses decidable `Ref`-equality via `countP` (no `BEq` instance needed). -/
def fanout {α : Type} [DecidableEq α] (b : Block α) (r : Ref α) : Nat :=
  (b.nodes.flatMap Node.ins ++ b.exit ++ b.exitAlt).countP (fun x => decide (x = r))

/-- ★ NON-VACUITY (DAG side): a block whose node-0 output is demanded 3 times (fan-out 3) —
    twice as operands of node 1 and once in `exit`. Via the bridge, `copy_floor` says any
    push-once / serve-each-consumer emission of it uses ≥ 2 copies. -/
example :
    fanout
      ({ entryDepth := 0, entryAlt := 0,
         nodes := [⟨0, ⟨0, 1, fun _ => [(0 : Nat)]⟩, []⟩,
                   ⟨1, ⟨2, 1, fun l => [l.headD 0 + l.tail.headD 0]⟩,
                       [Ref.out 0 0, Ref.out 0 0]⟩],
         exit := [Ref.out 0 0], exitAlt := [] } : Block Nat)
      (Ref.out 0 0) = 3 := by decide

end LeanBCH.Opt
