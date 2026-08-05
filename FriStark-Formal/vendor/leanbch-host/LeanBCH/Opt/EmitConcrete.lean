/-
  LeanBCH.Opt.EmitConcrete — INCREMENT 4d: a CONCRETE encoder that makes `emit_sound_under_VM`
  fire on the SCHEDULER'S ACTUAL OUTPUT.

  `EmitBridge.emit_sound_under_VM` is PARAMETERIZED by an encoder `enc : Op Bytes → List Instr`
  plus per-op faithfulness (`hsim`) and an acceptance converse (`hconv`). Increment 4c left `enc`
  abstract because the scheduler emits every compute node as `Op.CALL n.op.nin n.op.sem` with an
  OPAQUE `sem : List Bytes → List Bytes` — and no total function can pattern-match on a function
  value to recover the opcode. This file supplies a CONCRETE `enc` and DISCHARGES the parameters on
  genuine `emit b` output, over the shuffle + arithmetic compute op classes.

  ★ THE ENABLING MOVE (opcode identity by PROBING, additive — no edit to Dag/Scheduler/Op). The
  opaque `sem` cannot be matched on, but it can be APPLIED. `arithProbe` evaluates the node's `sem`
  on the canonical operand pair `[ofNum 6, ofNum 2]`; the five arithmetic kinds yield five DISTINCT
  results (`8/4/12/3/0`), so the output identifies the opcode. `arithProbe (arithSem k) = some k`
  is proven by kernel computation (`decide`), so `enc` recovers the concrete `arithInstr k` for every
  arith `CALL` the scheduler emits — reusing the existing `OpFaithful`/`ComputeBridge`/`AcceptBridge`
  witnesses (`simOpOn_arith`, `arith_accept_pre`) unchanged.

  ★ WHAT IS PROVEN. `enc` faithfully encodes EVERY op the scheduler emits: all 15 direct stack
  shuffles + PUSH/PICK/ROLL (the `Adapter.sim_*` witnesses) and the whole arithmetic class
  (`simOpOn_arith`). `emit_bA_sound` then INSTANTIATES `emit_sound_under_VM` on real scheduler output
  `emit (bA k)` for the FULL arithmetic class `k ∈ {add,sub,mul,div,mod}` (including the PARTIAL
  div/mod, whose precondition is discharged by the run's own acceptance): the bytes the scheduler
  emits for the block, run without error on LeanBCH's real `foldStraight`/`stepInstr` VM, compute
  EXACTLY the DAG denotation. `emit_bDup_sound` does the same for a block whose operand reuse forces a
  real `OP_DUP`, exercising a second shuffle class alongside the compute op.

  SCOPE (honest boundary). The compute coverage here is the arithmetic class (the interesting partial
  seam). The unary-numeric / unary-bool / binary-numeric / binary-bool / hash classes extend by the
  IDENTICAL probe pattern — their `ComputeBridge.simOpOn_*` + `AcceptBridge.accept_pre_*` witnesses
  already exist; only a per-class probe (a few `decide`d output comparisons) is missing. The FULLY
  general theorem (every `WellFormed` arith/shuffle block, not a fixed one) additionally needs a
  characterization of `emit b`'s op multiset (a scheduler-output typing lemma), which does not yet
  exist — see the `MANIFEST`/`README` frontier note. This file closes "no concrete `enc` exists" with
  a concrete one that provably fires on genuine scheduler output.

  Lean 4 core only; NO mathlib.
-/
import LeanBCH.Opt.Core
import LeanBCH.Opt.EmitBridge

namespace LeanBCH.Opt.EmitConcrete
open LeanBCH LeanBCH.VM LeanBCH.Opt LeanBCH.Opt.Op LeanBCH.Opt.OpFaithful LeanBCH.Opt.Adapter

/-! ### The arithmetic-kind probe: recover the opcode from the opaque `sem` by evaluation. -/

/-- Identify the arithmetic kind behind an opaque binary `sem` by evaluating it on the canonical
    operands `[ofNum 6, ofNum 2]` (bottom→top). The five kinds give five DISTINCT outputs
    (`6+2=8`, `6-2=4`, `6*2=12`, `6/2=3`, `6%2=0`), so the result pins the opcode. -/
def arithProbe (sem : List Bytes → List Bytes) : Option ArithKind :=
  let out := sem [ofNum 6, ofNum 2]
  if out = [ofNum 8] then some .add
  else if out = [ofNum 4] then some .sub
  else if out = [ofNum 12] then some .mul
  else if out = [ofNum 3] then some .div
  else if out = [ofNum 0] then some .mod
  else none

/-- The probe recovers exactly the arith kind for every canonical arith node semantics
    (kernel-checked: the five probe outputs are distinct and canonical). -/
theorem arithProbe_arithSem (k : ArithKind) : arithProbe (arithSem k) = some k := by
  cases k <;> decide

/-! ### The concrete BCH byte encoder for the scheduler's op set. -/

/-- ★ THE CONCRETE ENCODER. Every op the PASS-2 scheduler emits mapped to real BCH instructions:
    the 15 direct stack shuffles to their single opcode; `PUSH v` to its minimal push (`pushOf`);
    `PICK n`/`ROLL n` to `[push n, OP_PICK/ROLL]` (the VM pops the index); and a compute `CALL` to
    the arith opcode recovered by `arithProbe`. (Non-arith `CALL`s fall through to `[]`; they never
    occur in the arith/shuffle blocks this file's theorems cover — see the scope note. The unary /
    binary / hash classes extend by the same probe pattern.) -/
def enc : Op Bytes → List Instr
  | .DUP      => [{ opcode := Opcode.OP_DUP, data := [] }]
  | .DROP     => [{ opcode := Opcode.OP_DROP, data := [] }]
  | .OVER     => [{ opcode := Opcode.OP_OVER, data := [] }]
  | .SWAP     => [{ opcode := Opcode.OP_SWAP, data := [] }]
  | .ROT      => [{ opcode := Opcode.OP_ROT, data := [] }]
  | .NIP      => [{ opcode := Opcode.OP_NIP, data := [] }]
  | .TUCK     => [{ opcode := Opcode.OP_TUCK, data := [] }]
  | .PICK n   => [pushOf (bigIntToVmNumber (Int.ofNat n)), { opcode := Opcode.OP_PICK, data := [] }]
  | .ROLL n   => [pushOf (bigIntToVmNumber (Int.ofNat n)), { opcode := Opcode.OP_ROLL, data := [] }]
  | .TOALT    => [{ opcode := Opcode.OP_TOALTSTACK, data := [] }]
  | .FROMALT  => [{ opcode := Opcode.OP_FROMALTSTACK, data := [] }]
  | .TWODROP  => [{ opcode := Opcode.OP_2DROP, data := [] }]
  | .TWODUP   => [{ opcode := Opcode.OP_2DUP, data := [] }]
  | .THREEDUP => [{ opcode := Opcode.OP_3DUP, data := [] }]
  | .TWOOVER  => [{ opcode := Opcode.OP_2OVER, data := [] }]
  | .TWOROT   => [{ opcode := Opcode.OP_2ROT, data := [] }]
  | .TWOSWAP  => [{ opcode := Opcode.OP_2SWAP, data := [] }]
  | .PUSH v   => [pushOf v]
  | .CALL _ sem => match arithProbe sem with
                   | some k => [arithInstr k]
                   | none   => []

/-- `enc` recovers the concrete arith instruction for every arith `CALL` node (via the probe). -/
theorem enc_call_arith (k : ArithKind) : enc (Op.CALL 2 (arithSem k)) = [arithInstr k] := by
  show (match arithProbe (arithSem k) with | some k => [arithInstr k] | none => []) = [arithInstr k]
  rw [arithProbe_arithSem]

/-! ### `enc` is FAITHFUL on every op class — reusable per-constructor witnesses.

    The 15 shuffles are UNCONDITIONAL (`enc .X` is definitionally the instruction of the matching
    `Adapter.sim_X`). PUSH / PICK / ROLL carry the minimal-encoding length side-condition. Each is a
    one-liner because `enc`'s output is defeq to the corresponding `sim_*` lemma's instruction list. -/

theorem enc_sim_DUP      : SimOp Op.DUP      (enc Op.DUP)      := sim_DUP
theorem enc_sim_DROP     : SimOp Op.DROP     (enc Op.DROP)     := sim_DROP
theorem enc_sim_OVER     : SimOp Op.OVER     (enc Op.OVER)     := sim_OVER
theorem enc_sim_SWAP     : SimOp Op.SWAP     (enc Op.SWAP)     := sim_SWAP
theorem enc_sim_ROT      : SimOp Op.ROT      (enc Op.ROT)      := sim_ROT
theorem enc_sim_NIP      : SimOp Op.NIP      (enc Op.NIP)      := sim_NIP
theorem enc_sim_TUCK     : SimOp Op.TUCK     (enc Op.TUCK)     := sim_TUCK
theorem enc_sim_TOALT    : SimOp Op.TOALT    (enc Op.TOALT)    := sim_TOALT
theorem enc_sim_FROMALT  : SimOp Op.FROMALT  (enc Op.FROMALT)  := sim_FROMALT
theorem enc_sim_TWODROP  : SimOp Op.TWODROP  (enc Op.TWODROP)  := sim_TWODROP
theorem enc_sim_TWODUP   : SimOp Op.TWODUP   (enc Op.TWODUP)   := sim_TWODUP
theorem enc_sim_THREEDUP : SimOp Op.THREEDUP (enc Op.THREEDUP) := sim_THREEDUP
theorem enc_sim_TWOOVER  : SimOp Op.TWOOVER  (enc Op.TWOOVER)  := sim_TWOOVER
theorem enc_sim_TWOROT   : SimOp Op.TWOROT   (enc Op.TWOROT)   := sim_TWOROT
theorem enc_sim_TWOSWAP  : SimOp Op.TWOSWAP  (enc Op.TWOSWAP)  := sim_TWOSWAP

theorem enc_sim_PUSH (v : Bytes) (hv : v.length ≤ maxItemLen) :
    SimOp (Op.PUSH v) (enc (Op.PUSH v)) := sim_PUSH v hv
theorem enc_sim_PICK (n : Nat) (hn : (bigIntToVmNumber (Int.ofNat n)).length ≤ maxItemLen) :
    SimOp (Op.PICK n) (enc (Op.PICK n)) := sim_PICK n hn
theorem enc_sim_ROLL (n : Nat) (hn : (bigIntToVmNumber (Int.ofNat n)).length ≤ maxItemLen) :
    SimOp (Op.ROLL n) (enc (Op.ROLL n)) := sim_ROLL n hn

/-- ★ `enc` faithfully encodes an arith compute `CALL` under its precondition (`ArithPre k`):
    the probe recovers `arithInstr k`, and `ComputeBridge.simOpOn_arith` proves that one instruction
    realizes `Op.CALL 2 (arithSem k)` on every `ArithPre k` state. -/
theorem enc_simOpOn_arith (k : ArithKind) :
    SimOpOn (ArithPre k) (Op.CALL 2 (arithSem k)) (enc (Op.CALL 2 (arithSem k))) := by
  rw [enc_call_arith]; exact simOpOn_arith k

/-- ★ The acceptance converse for an arith `CALL`: if its encoded instruction did not error, its
    operands satisfy `ArithPre k` (`AcceptBridge.arith_accept_pre`). -/
theorem enc_accept_arith (k : ArithKind) (st al : Stack)
    (h : foldStraight (enc (Op.CALL 2 (arithSem k))) st al ≠ none) : ArithPre k st al := by
  rw [enc_call_arith] at h; exact arith_accept_pre k st al h

/-! ### The per-op precondition threaded to `emit_sound_under_VM`. -/

/-- The precondition `emit_sound_under_VM` threads per emitted op: an arith `CALL`'s canonical-operand
    precondition `ArithPre k` (recovered via the probe), and the trivially-true precondition for every
    unconditional shuffle/PUSH op. -/
def Pfun : Op Bytes → Stack → Stack → Prop
  | .CALL _ sem => match arithProbe sem with
                   | some k => ArithPre k
                   | none   => fun _ _ => True
  | _ => fun _ _ => True

theorem Pfun_call_arith (k : ArithKind) : Pfun (Op.CALL 2 (arithSem k)) = ArithPre k := by
  show (match arithProbe (arithSem k) with | some k => ArithPre k | none => fun _ _ => True)
        = ArithPre k
  rw [arithProbe_arithSem]

/-! ### ★★ INSTANTIATION 1 — the whole arithmetic class on real scheduler output.

    `bA k` is a 2-input block with one arith node `k`; the scheduler emits
    `[OP_SWAP, OP_SWAP, CALL 2 (arithSem k)]` (`emit_bA`). `emit_bA_sound` runs `emit_sound_under_VM`
    on it for every `k ∈ {add, sub, mul, div, mod}`, discharging faithfulness from `enc_*` above. -/

/-- A 2-input, 1-node arithmetic block, parametric in the arith kind. -/
def bA (k : ArithKind) : Block Bytes :=
  { entryDepth := 2, entryAlt := 0,
    nodes := [⟨0, ⟨2, 1, arithSem k⟩, [Ref.inp 0, Ref.inp 1]⟩],
    exit := [Ref.out 0 0], exitAlt := [] }

/-- The scheduler's actual output for `bA k`: two operand SWAPs then the compute `CALL`. -/
theorem emit_bA (k : ArithKind) : emit (bA k) = [Op.SWAP, Op.SWAP, Op.CALL 2 (arithSem k)] := by
  cases k <;> rfl

/-- `bA k` is genuinely `WellFormed` (so `emit_sound_under_VM`'s hypothesis is non-vacuous). -/
theorem bA_wf (k : ArithKind) : WellFormed (bA k) := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · refine ⟨fun r hr => ?_, trivial⟩
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hr
    rcases hr with rfl | rfl
    · show (0:Nat) < 2; omega
    · show (1:Nat) < 2; omega
  · intro r hr; simp only [bA, List.mem_singleton] at hr; subst hr; show (0:Nat) ∈ [0]; simp
  · intro r hr; simp only [bA, List.not_mem_nil] at hr
  · simp [bA]
  · intro n hn; simp only [bA, List.mem_singleton] at hn; subst hn; rfl
  · intro n hn l hl; simp only [bA, List.mem_singleton] at hn; subst hn
    match l, hl with | [_, _], _ => rfl
  · intro nid j hmem nd hnd hid
    simp only [bA, List.mem_singleton] at hnd; subst hnd
    show j < 1
    simp only [bA, List.flatMap_cons, List.flatMap_nil, List.append_nil, List.mem_append,
      List.mem_cons, List.not_mem_nil, or_false, reduceCtorEq, false_or, Ref.out.injEq] at hmem
    omega

/-- Faithfulness of every op in `emit (bA k)` under `enc` — the `hsim` for `emit_sound_under_VM`. -/
theorem hsim_bA (k : ArithKind) : ∀ op ∈ emit (bA k), SimOpOn (Pfun op) op (enc op) := by
  intro op hop
  rw [emit_bA] at hop
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hop
  rcases hop with rfl | rfl | rfl
  · exact SimOp.toOn enc_sim_SWAP (Pfun Op.SWAP)
  · exact SimOp.toOn enc_sim_SWAP (Pfun Op.SWAP)
  · rw [Pfun_call_arith]; exact enc_simOpOn_arith k

/-- The acceptance converse for every op in `emit (bA k)` — the `hconv` for `emit_sound_under_VM`. -/
theorem hconv_bA (k : ArithKind) : ∀ op ∈ emit (bA k), ∀ st al : Stack,
    foldStraight (enc op) st al ≠ none → Pfun op st al := by
  intro op hop st al hne
  rw [emit_bA] at hop
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hop
  rcases hop with rfl | rfl | rfl
  · trivial
  · trivial
  · rw [Pfun_call_arith]; exact enc_accept_arith k st al hne

/-- ★★★ THE INCREMENT-4d HEADLINE (arithmetic class). For EVERY arith kind `k` and entry mains `M`
    (length 2): the bytes the PASS-2 SCHEDULER actually emits for `bA k` — encoded by the CONCRETE
    `enc`, run from the entry state on LeanBCH's real `foldStraight`/`stepInstr` VM WITHOUT error —
    compute EXACTLY the block's DAG denotation `denote (bA k) M A`. `emit_sound_under_VM` fires on
    genuine scheduler output; the concrete `enc` is no longer a parameter. Covers the PARTIAL div/mod
    (their canonical-operand / nonzero-divisor precondition discharged by the run's own acceptance). -/
theorem emit_bA_sound (k : ArithKind) (M A : List Bytes)
    (hM : M.length = 2) (hA : A.length = 0)
    (hacc : foldStraight ((emit (bA k)).flatMap enc) (entryState M A).1 (entryState M A).2 ≠ none) :
    foldStraight ((emit (bA k)).flatMap enc) (entryState M A).1 (entryState M A).2
      = some (denote (bA k) M A) :=
  emit_sound_under_VM enc Pfun (bA k) (bA_wf k) M A hM hA (hsim_bA k) (hconv_bA k) hacc

/-! ### ★★ INSTANTIATION 2 — operand reuse forces a real `OP_DUP` alongside the compute op.

    `bDup` reuses its single input for both operands of an ADD; the scheduler copies it with
    `OP_DUP` (`copyOps 0`) then `OP_SWAP`, then the `CALL`. Exercises a second shuffle class. -/

/-- A 1-input block whose ADD consumes the input twice (⇒ the scheduler emits a copy). -/
def bDup : Block Bytes :=
  { entryDepth := 1, entryAlt := 0,
    nodes := [⟨0, ⟨2, 1, arithSem .add⟩, [Ref.inp 0, Ref.inp 0]⟩],
    exit := [Ref.out 0 0], exitAlt := [] }

/-- The scheduler's actual output for `bDup`: `OP_DUP` (copy the reused input), `OP_SWAP`, `CALL`. -/
theorem emit_bDup : emit bDup = [Op.DUP, Op.SWAP, Op.CALL 2 (arithSem .add)] := rfl

theorem bDup_wf : WellFormed bDup := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · refine ⟨fun r hr => ?_, trivial⟩
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hr
    rcases hr with rfl | rfl <;> · show (0:Nat) < 1; omega
  · intro r hr; simp only [bDup, List.mem_singleton] at hr; subst hr; show (0:Nat) ∈ [0]; simp
  · intro r hr; simp only [bDup, List.not_mem_nil] at hr
  · simp [bDup]
  · intro n hn; simp only [bDup, List.mem_singleton] at hn; subst hn; rfl
  · intro n hn l hl; simp only [bDup, List.mem_singleton] at hn; subst hn
    match l, hl with | [_, _], _ => rfl
  · intro nid j hmem nd hnd hid
    simp only [bDup, List.mem_singleton] at hnd; subst hnd
    show j < 1
    simp only [bDup, List.flatMap_cons, List.flatMap_nil, List.append_nil, List.mem_append,
      List.mem_cons, List.not_mem_nil, or_false, reduceCtorEq, false_or, Ref.out.injEq] at hmem
    omega

theorem hsim_bDup : ∀ op ∈ emit bDup, SimOpOn (Pfun op) op (enc op) := by
  intro op hop
  simp only [emit_bDup, List.mem_cons, List.not_mem_nil, or_false] at hop
  rcases hop with rfl | rfl | rfl
  · exact SimOp.toOn enc_sim_DUP (Pfun Op.DUP)
  · exact SimOp.toOn enc_sim_SWAP (Pfun Op.SWAP)
  · rw [Pfun_call_arith]; exact enc_simOpOn_arith .add

theorem hconv_bDup : ∀ op ∈ emit bDup, ∀ st al : Stack,
    foldStraight (enc op) st al ≠ none → Pfun op st al := by
  intro op hop st al hne
  simp only [emit_bDup, List.mem_cons, List.not_mem_nil, or_false] at hop
  rcases hop with rfl | rfl | rfl
  · trivial
  · trivial
  · rw [Pfun_call_arith]; exact enc_accept_arith .add st al hne

/-- ★★★ The 4d headline for the operand-reuse block: the scheduler's `[OP_DUP, OP_SWAP, OP_ADD]`,
    encoded by `enc` and run on the real VM without error, computes exactly `denote bDup M A`. -/
theorem emit_bDup_sound (M A : List Bytes) (hM : M.length = 1) (hA : A.length = 0)
    (hacc : foldStraight ((emit bDup).flatMap enc) (entryState M A).1 (entryState M A).2 ≠ none) :
    foldStraight ((emit bDup).flatMap enc) (entryState M A).1 (entryState M A).2
      = some (denote bDup M A) :=
  emit_sound_under_VM enc Pfun bDup bDup_wf M A hM hA hsim_bDup hconv_bDup hacc

end LeanBCH.Opt.EmitConcrete
