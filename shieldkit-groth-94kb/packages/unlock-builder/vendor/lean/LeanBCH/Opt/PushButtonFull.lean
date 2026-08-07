/-
  LeanBCH.Opt.PushButtonFull — TRACK 1: the FULLY-GENERAL byte-level push-button (optimized side).

  `PushButtonBytes.push_button_arith_bytes` closes the optimizer's byte-level soundness for a FIXED
  arithmetic block. `EmitTyped.emit_op_cases` (block-generality) and `EmitConcreteExt.encFull` /
  the `ComputeBridge.simOpOn_*` + `AcceptBridge.accept_pre_*` witnesses (class-coverage) already
  close the two structural axes. This file GLUES them into a single theorem that fires on ANY
  `WellFormed` block, under honest coverage hypotheses:

    • `hcov`   — every compute node is one of the covered (NON-hash) numeric classes: arith (add/sub/
                mul/div/mod), binary-numeric (MIN/MAX), the eight binary-boolean comparisons, the four
                unary-numeric ops, or the two unary-boolean ops — AND at the matching arity (`nin = 2`
                for binary, `nin = 1` for unary). This is `CoveredNode nd.op`. Arity is genuinely part
                of coverage: the emitted op is `CALL nd.op.nin nd.op.sem`, and the real opcode pops a
                FIXED number of operands, so faithfulness needs `nin` pinned (HASH is deferred — see
                `EmitConcreteExt`'s note: probing a hash `sem` forces the kernel to compute SHA-256).
    • `hconst` — every constant the block materialises fits the item-length limit (`≤ maxItemLen`).
    • `hidx`   — every `PICK`/`ROLL` index the scheduler emits encodes within the item-length limit
                (a real stack depth is tiny; the honest wire-format bound).

  ★ THE GLUE. `general_hsim`/`general_hconv` discharge `emit_sound_under_VM`'s per-op hypotheses over
  the whole `emit b` op-set by `rcases emit_op_cases b op hop` into the five shapes:
    shuffles → the unconditional `Adapter.sim_*` (via `SimOp.toOn`);
    PICK/ROLL → `sim_PICK`/`sim_ROLL` under the `hidx` bound;
    PUSH v   → `sim_PUSH` under the `hconst` bound (`v` is a block constant);
    CALL     → `callInstr`'s decode fact + `ComputeBridge.simOpOn_*` + `AcceptBridge.accept_pre_*`.
  The per-op precondition threaded to `emit_sound_under_VM` is the ACCEPTANCE precondition
  (`PacceptFull op st al := foldStraight (encFull op) st al ≠ none`) — recoverable from acceptance
  trivially (`general_hconv` is the identity), with `general_hsim` proving faithfulness-under-that.
  This is exactly the AcceptBridge design: the compute preconditions are threaded backward by the
  run's own acceptance, never assumed.

  ★ DELIVERED.
    • `push_button_foldStraight` — for any covered `WellFormed` block, the emitted ops encoded by
      `encFull` and run on the real `foldStraight`/`stepInstr` VM (no error) compute EXACTLY
      `denote b M A`.
    • `push_button` — the BYTE level: the fully-serialised bytecode `((emit b).flatMap encFull)
      .flatMap encodeInstr` PARSES back to the emitted instructions (`Codec.parse_encode`, every
      emitted instr `WFInstr`) and, RUN on `VM.run`, computes `denote b M A` (main, alt, no error).
    • `push_button_original` — for a block the DECOMPILER produced, additionally re-attaches the
      ORIGINAL program: `Opt.run rawOps (entryState M A) = some (denote b M A)`
      (`schedule_refines` ∘ `DecompileWF.decompile_end_to_end`). So: original program ≡ optimizer's
      output-BYTECODE-on-the-real-VM, for any covered decompiled block.

  Lean 4 core only; NO mathlib. No `sorry`/`admit`/`native_decide`/`partial`. Additive: a NEW file.
-/
import LeanBCH.Opt.EmitTyped
import LeanBCH.Opt.EmitConcreteExt
import LeanBCH.Opt.PushButtonBytes
import LeanBCH.Opt.DecompileWF

namespace LeanBCH.Opt.PushButtonFull
open LeanBCH LeanBCH.VM LeanBCH.Opt LeanBCH.Opt.Op LeanBCH.Opt.OpFaithful LeanBCH.Opt.Adapter
open LeanBCH.Opt.EmitConcrete LeanBCH.Opt.EmitConcreteExt LeanBCH.Opt.PushButtonBytes
open LeanBCH.Opt.Codec

/-! ### 1. The coverage predicate — a node's op is a covered NON-hash compute class at its arity. -/

/-- ★ COVERED COMPUTE NODE. A node's op is one of the classes `encFull`/`callInstr` decodes, PINNED
    at the arity the real opcode pops (binary → `nin = 2`, unary → `nin = 1`). Arity is genuinely
    part of coverage: the emitted op is `CALL nin sem`, and the concrete opcode (`OP_MIN`, …) pops a
    fixed count, so faithfulness needs `nin` to match. HASH is deferred (see the header). -/
def CoveredNode (op : NodeOp Bytes) : Prop :=
  (∃ k : ArithKind, op.nin = 2 ∧ op.sem = arithSem k)
  ∨ (op.nin = 2 ∧ op.sem = binNumSem (fun a b => if a ≤ b then a else b))            -- MIN
  ∨ (op.nin = 2 ∧ op.sem = binNumSem (fun a b => if a ≤ b then b else a))            -- MAX
  ∨ (op.nin = 2 ∧ op.sem = binBoolSem (fun a b => a != 0 && b != 0))                 -- BOOLAND
  ∨ (op.nin = 2 ∧ op.sem = binBoolSem (fun a b => a != 0 || b != 0))                 -- BOOLOR
  ∨ (op.nin = 2 ∧ op.sem = binBoolSem (fun a b => a == b))                           -- NUMEQUAL
  ∨ (op.nin = 2 ∧ op.sem = binBoolSem (fun a b => a != b))                           -- NUMNOTEQUAL
  ∨ (op.nin = 2 ∧ op.sem = binBoolSem (fun a b => decide (a < b)))                   -- LESSTHAN
  ∨ (op.nin = 2 ∧ op.sem = binBoolSem (fun a b => decide (a > b)))                   -- GREATERTHAN
  ∨ (op.nin = 2 ∧ op.sem = binBoolSem (fun a b => decide (a ≤ b)))                   -- LESSTHANOREQUAL
  ∨ (op.nin = 2 ∧ op.sem = binBoolSem (fun a b => decide (a ≥ b)))                   -- GREATERTHANOREQUAL
  ∨ (op.nin = 1 ∧ op.sem = unaryNumSem (· + 1))                                      -- 1ADD
  ∨ (op.nin = 1 ∧ op.sem = unaryNumSem (· - 1))                                      -- 1SUB
  ∨ (op.nin = 1 ∧ op.sem = unaryNumSem (fun x => -x))                                -- NEGATE
  ∨ (op.nin = 1 ∧ op.sem = unaryNumSem (fun x => (x.natAbs : Int)))                  -- ABS
  ∨ (op.nin = 1 ∧ op.sem = unaryBoolSem (· == 0))                                    -- NOT
  ∨ (op.nin = 1 ∧ op.sem = unaryBoolSem (· != 0))                                    -- 0NOTEQUAL

/-- The per-op precondition threaded to `emit_sound_under_VM`: the ACCEPTANCE precondition — this
    op's encoded chunk did not error. Recoverable from acceptance trivially (identity); faithfulness
    under it is `general_hsim`. Mirrors the `AcceptBridge` philosophy (backward-threaded precondition). -/
def PacceptFull (op : Op Bytes) : Stack → Stack → Prop :=
  fun st al => foldStraight (encFull op) st al ≠ none

/-! ### 2. A CALL op faithful-under-acceptance from its decode fact + `simOpOn_*` + `accept_pre_*`. -/

/-- ★ THE CALL GLUE. If `callInstr sem` decodes to `[instr]`, that one instruction realizes
    `CALL nin sem` on every state meeting `Pre` (`hsimOn`), and `Pre` is recoverable from that
    instruction not erroring (`hacc`), then `CALL nin sem`'s `encFull` chunk is faithful whenever it
    accepts — i.e. `SimOpOn (PacceptFull …)`. The precondition is discharged by acceptance. -/
theorem simOpOn_call_covered {nin : Nat} {sem : List Bytes → List Bytes} {instr : Instr}
    {Pre : Stack → Stack → Prop}
    (hsimOn : SimOpOn Pre (Op.CALL nin sem) [instr])
    (hacc : ∀ st al : Stack, foldStraight [instr] st al ≠ none → Pre st al)
    (hdec : callInstr sem = [instr]) :
    SimOpOn (PacceptFull (Op.CALL nin sem)) (Op.CALL nin sem) (encFull (Op.CALL nin sem)) := by
  intro st al hne
  simp only [PacceptFull, encFull_call, hdec] at hne
  rw [encFull_call, hdec]
  exact hsimOn st al (hacc st al hne)

/-! ### 3. `general_hsim` — every emitted op is faithful-under-acceptance under coverage. -/

/-- ★★ THE GENERAL `hsim`. For a `WellFormed`-covered block, EVERY op the scheduler emits is faithful
    on states where its encoded chunk accepts. `rcases emit_op_cases`: shuffles via the unconditional
    `Adapter.sim_*`; PICK/ROLL via `sim_PICK`/`sim_ROLL` under `hidx`; PUSH under `hconst`; CALL via
    `simOpOn_call_covered` picking the class from `CoveredNode`. -/
theorem general_hsim (b : Block Bytes)
    (hcov : ∀ nd ∈ b.nodes, CoveredNode nd.op)
    (hconst : ∀ (v : Bytes) (cse : Bool), Ref.const v cse ∈ blockRefs b → v.length ≤ maxItemLen)
    (hidx : ∀ n : Nat, (Op.PICK n ∈ emit b ∨ Op.ROLL n ∈ emit b) →
        (bigIntToVmNumber (Int.ofNat n)).length ≤ maxItemLen) :
    ∀ op ∈ emit b, SimOpOn (PacceptFull op) op (encFull op) := by
  intro op hop
  rcases emit_op_cases b op hop with hshuf | ⟨n, rfl⟩ | ⟨n, rfl⟩ | ⟨v, cse, rfl, hmem⟩ | ⟨nd, hnd, rfl⟩
  · -- the eight stack shuffles: unconditional `SimOp`, embedded by `SimOp.toOn`
    rcases hshuf with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
    · exact SimOp.toOn enc_sim_DUP _
    · exact SimOp.toOn enc_sim_DROP _
    · exact SimOp.toOn enc_sim_OVER _
    · exact SimOp.toOn enc_sim_SWAP _
    · exact SimOp.toOn enc_sim_ROT _
    · exact SimOp.toOn enc_sim_NIP _
    · exact SimOp.toOn enc_sim_TOALT _
    · exact SimOp.toOn enc_sim_FROMALT _
  · -- PICK n
    exact SimOp.toOn (enc_sim_PICK n (hidx n (Or.inl hop))) _
  · -- ROLL n
    exact SimOp.toOn (enc_sim_ROLL n (hidx n (Or.inr hop))) _
  · -- PUSH v (a constant ref of the block)
    exact SimOp.toOn (enc_sim_PUSH v (hconst v cse hmem)) _
  · -- CALL nd.op.nin nd.op.sem : covered numeric compute class
    rcases hcov nd hnd with
        ⟨k, hnin, hsem⟩ | ⟨hnin, hsem⟩ | ⟨hnin, hsem⟩ | ⟨hnin, hsem⟩ | ⟨hnin, hsem⟩
      | ⟨hnin, hsem⟩ | ⟨hnin, hsem⟩ | ⟨hnin, hsem⟩ | ⟨hnin, hsem⟩ | ⟨hnin, hsem⟩
      | ⟨hnin, hsem⟩ | ⟨hnin, hsem⟩ | ⟨hnin, hsem⟩ | ⟨hnin, hsem⟩ | ⟨hnin, hsem⟩
      | ⟨hnin, hsem⟩ | ⟨hnin, hsem⟩
    · rw [hnin, hsem]; exact simOpOn_call_covered (simOpOn_arith k) (arith_accept_pre k) (callInstr_arith k)
    · rw [hnin, hsem]; exact simOpOn_call_covered simOpOn_MIN accept_pre_MIN (by decide)
    · rw [hnin, hsem]; exact simOpOn_call_covered simOpOn_MAX accept_pre_MAX (by decide)
    · rw [hnin, hsem]; exact simOpOn_call_covered simOpOn_BOOLAND accept_pre_BOOLAND (by decide)
    · rw [hnin, hsem]; exact simOpOn_call_covered simOpOn_BOOLOR accept_pre_BOOLOR (by decide)
    · rw [hnin, hsem]; exact simOpOn_call_covered simOpOn_NUMEQUAL accept_pre_NUMEQUAL (by decide)
    · rw [hnin, hsem]; exact simOpOn_call_covered simOpOn_NUMNOTEQUAL accept_pre_NUMNOTEQUAL (by decide)
    · rw [hnin, hsem]; exact simOpOn_call_covered simOpOn_LESSTHAN accept_pre_LESSTHAN (by decide)
    · rw [hnin, hsem]; exact simOpOn_call_covered simOpOn_GREATERTHAN accept_pre_GREATERTHAN (by decide)
    · rw [hnin, hsem]; exact simOpOn_call_covered simOpOn_LESSTHANOREQUAL accept_pre_LESSTHANOREQUAL (by decide)
    · rw [hnin, hsem]; exact simOpOn_call_covered simOpOn_GREATERTHANOREQUAL accept_pre_GREATERTHANOREQUAL (by decide)
    · rw [hnin, hsem]; exact simOpOn_call_covered simOpOn_1ADD accept_pre_1ADD (by decide)
    · rw [hnin, hsem]; exact simOpOn_call_covered simOpOn_1SUB accept_pre_1SUB (by decide)
    · rw [hnin, hsem]; exact simOpOn_call_covered simOpOn_NEGATE accept_pre_NEGATE (by decide)
    · rw [hnin, hsem]; exact simOpOn_call_covered simOpOn_ABS accept_pre_ABS (by decide)
    · rw [hnin, hsem]; exact simOpOn_call_covered simOpOn_NOT accept_pre_NOT (by decide)
    · rw [hnin, hsem]; exact simOpOn_call_covered simOpOn_0NOTEQUAL accept_pre_0NOTEQUAL (by decide)

/-- ★ THE GENERAL `hconv`. The acceptance precondition IS "this chunk did not error", so recovering it
    from that fact is the identity — no per-op work. (The compute preconditions live inside
    `general_hsim`, discharged there by `accept_pre_*`.) -/
theorem general_hconv (b : Block Bytes) :
    ∀ op ∈ emit b, ∀ st al : Stack, foldStraight (encFull op) st al ≠ none → PacceptFull op st al := by
  intro op _ st al h; exact h

/-! ### 4. The op-list → real-VM headline for ANY covered `WellFormed` block. -/

/-- ★★★ THE GENERAL PUSH-BUTTON (op-list level). For ANY `WellFormed` block whose compute nodes are
    covered (`hcov`), whose constants (`hconst`) and `PICK`/`ROLL` indices (`hidx`) encode within the
    item limit: the ops the PASS-2 scheduler emits, encoded by the CONCRETE `encFull` and run from
    the entry state on LeanBCH's real `foldStraight`/`stepInstr` VM WITHOUT error, compute EXACTLY
    the DAG denotation `denote b M A`. `emit_sound_under_VM` fired on genuine scheduler output, over
    an ARBITRARY block (not a fixed one). -/
theorem push_button_foldStraight (b : Block Bytes) (hwf : WellFormed b) (M A : List Bytes)
    (hM : M.length = b.entryDepth) (hA : A.length = b.entryAlt)
    (hcov : ∀ nd ∈ b.nodes, CoveredNode nd.op)
    (hconst : ∀ (v : Bytes) (cse : Bool), Ref.const v cse ∈ blockRefs b → v.length ≤ maxItemLen)
    (hidx : ∀ n : Nat, (Op.PICK n ∈ emit b ∨ Op.ROLL n ∈ emit b) →
        (bigIntToVmNumber (Int.ofNat n)).length ≤ maxItemLen)
    (hacc : foldStraight ((emit b).flatMap encFull) (entryState M A).1 (entryState M A).2 ≠ none) :
    foldStraight ((emit b).flatMap encFull) (entryState M A).1 (entryState M A).2
      = some (denote b M A) :=
  emit_sound_under_VM encFull PacceptFull b hwf M A hM hA
    (general_hsim b hcov hconst hidx) (general_hconv b) hacc

/-! ### 5. Every emitted instruction is `WFInstr` + straight-line (for the byte codec / real `run`).

    `encFull op`'s instructions are: a plain shuffle opcode; a minimal `pushOf` push (+ `OP_PICK`/
    `OP_ROLL`); or the single decoded compute opcode. Each is `WFInstr` and straight-line. The
    compute case holds for ANY `sem` (the probe RESULTS are the fixed opcodes), so no coverage is
    needed here — only the const / index length bounds for the pushes. -/

/-- A push opcode (`(pushOf v).opcode.toNat ≤ 0x60`) is straight-line: the only non-straight bytes
    are the conditionals (0x63/0x64/0x67/0x68) and BEGIN/UNTIL (0x65/0x66), all `> 0x60`. -/
theorem straightOp_le (op : UInt8) (h : op.toNat ≤ 0x60) : straightOp op = true := by
  have e : ∀ c : UInt8, 0x60 < c.toNat → (op == c) = false := by
    intro c hc; rw [beq_eq_false_iff_ne]; intro heq; rw [heq] at h; omega
  simp only [straightOp, Opcode.isConditional, Opcode.OP_BEGIN, Opcode.OP_UNTIL, bne,
    e 0x63 (by decide), e 0x64 (by decide), e 0x65 (by decide), e 0x66 (by decide),
    e 0x67 (by decide), e 0x68 (by decide),
    Bool.or_self, Bool.not_false, Bool.and_true]

/-- Every opcode `pushOf` can emit is straight-line (`≤ 0x60`, casing exactly as `pushOf_WFInstr`). -/
theorem pushOf_straight (v : Bytes) : straightOp (pushOf v).opcode = true := by
  rcases v with _ | ⟨b, _ | ⟨c, rest⟩⟩
  · decide
  · by_cases hcond : 1 ≤ b.toNat ∧ b.toNat ≤ 16
    · have hpo : pushOf [b] = { opcode := UInt8.ofNat (0x50 + b.toNat), data := [] } := by
        show (if 1 ≤ b.toNat ∧ b.toNat ≤ 16 then _ else _) = _; rw [if_pos hcond]
      have ht : (UInt8.ofNat (0x50 + b.toNat)).toNat = 0x50 + b.toNat :=
        UInt8.toNat_ofNat_of_lt' (by have : UInt8.size = 256 := rfl; omega)
      rw [hpo]; exact straightOp_le _ (by rw [ht]; omega)
    · by_cases hng : b.toNat = 0x81
      · have hb : b = 0x81 := by
          have h' : UInt8.ofNat b.toNat = b := UInt8.ofNat_toNat; rw [hng] at h'; exact h'.symm
        subst hb
        have hpo : pushOf [(0x81 : UInt8)] = { opcode := 0x4f, data := [] } := by decide
        rw [hpo]; decide
      · have hpo : pushOf [b] = { opcode := 0x01, data := [b] } := by
          show (if 1 ≤ b.toNat ∧ b.toNat ≤ 16 then _ else if b.toNat = 0x81 then _ else _) = _
          rw [if_neg hcond, if_neg hng]
        rw [hpo]; show straightOp (0x01 : UInt8) = true; decide
  · by_cases hc1 : (b :: c :: rest).length ≤ 0x4b
    · have hpo : pushOf (b :: c :: rest)
          = { opcode := UInt8.ofNat (b :: c :: rest).length, data := b :: c :: rest } := by
        show (if (b :: c :: rest).length ≤ 0x4b then _ else _) = _; rw [if_pos hc1]
      have ht : (UInt8.ofNat (b :: c :: rest).length).toNat = (b :: c :: rest).length :=
        UInt8.toNat_ofNat_of_lt' (by have : UInt8.size = 256 := rfl; omega)
      rw [hpo]; exact straightOp_le _ (by rw [ht]; omega)
    · by_cases hc2 : (b :: c :: rest).length ≤ 0xff
      · have hpo : pushOf (b :: c :: rest) = { opcode := 0x4c, data := b :: c :: rest } := by
          show (if (b :: c :: rest).length ≤ 0x4b then _
                else if (b :: c :: rest).length ≤ 0xff then _ else _) = _
          rw [if_neg hc1, if_pos hc2]
        rw [hpo]; show straightOp (0x4c : UInt8) = true; decide
      · by_cases hc3 : (b :: c :: rest).length ≤ 0xffff
        · have hpo : pushOf (b :: c :: rest) = { opcode := 0x4d, data := b :: c :: rest } := by
            show (if (b :: c :: rest).length ≤ 0x4b then _
                  else if (b :: c :: rest).length ≤ 0xff then _
                  else if (b :: c :: rest).length ≤ 0xffff then _ else _) = _
            rw [if_neg hc1, if_neg hc2, if_pos hc3]
          rw [hpo]; show straightOp (0x4d : UInt8) = true; decide
        · have hpo : pushOf (b :: c :: rest) = { opcode := 0x4e, data := b :: c :: rest } := by
            show (if (b :: c :: rest).length ≤ 0x4b then _
                  else if (b :: c :: rest).length ≤ 0xff then _
                  else if (b :: c :: rest).length ≤ 0xffff then _ else _) = _
            rw [if_neg hc1, if_neg hc2, if_neg hc3]
          rw [hpo]; show straightOp (0x4e : UInt8) = true; decide

/-- Whatever instruction `binNumProbe` returns (`MIN`/`MAX` opcode) is `WFInstr` + straight-line. -/
theorem binNumProbe_wf {sem : List Bytes → List Bytes} {i : Instr} (h : binNumProbe sem = some i) :
    WFInstr i ∧ straightOp i.opcode = true := by
  simp only [binNumProbe] at h
  (repeat' split at h) <;>
    (first
      | (injection h with h; subst h; exact ⟨WFInstr_plain _ (by decide), by decide⟩)
      | simp at h)

/-- Whatever instruction `binBoolProbe` returns (one of the eight comparisons) is `WFInstr` + straight. -/
theorem binBoolProbe_wf {sem : List Bytes → List Bytes} {i : Instr} (h : binBoolProbe sem = some i) :
    WFInstr i ∧ straightOp i.opcode = true := by
  simp only [binBoolProbe] at h
  (repeat' split at h) <;>
    (first
      | (injection h with h; subst h; exact ⟨WFInstr_plain _ (by decide), by decide⟩)
      | simp at h)

/-- Whatever instruction `unaryNumProbe` returns (1ADD/1SUB/NEGATE/ABS) is `WFInstr` + straight. -/
theorem unaryNumProbe_wf {sem : List Bytes → List Bytes} {i : Instr} (h : unaryNumProbe sem = some i) :
    WFInstr i ∧ straightOp i.opcode = true := by
  simp only [unaryNumProbe] at h
  (repeat' split at h) <;>
    (first
      | (injection h with h; subst h; exact ⟨WFInstr_plain _ (by decide), by decide⟩)
      | simp at h)

/-- Whatever instruction `unaryBoolProbe` returns (NOT/0NOTEQUAL) is `WFInstr` + straight. -/
theorem unaryBoolProbe_wf {sem : List Bytes → List Bytes} {i : Instr} (h : unaryBoolProbe sem = some i) :
    WFInstr i ∧ straightOp i.opcode = true := by
  simp only [unaryBoolProbe] at h
  (repeat' split at h) <;>
    (first
      | (injection h with h; subst h; exact ⟨WFInstr_plain _ (by decide), by decide⟩)
      | simp at h)

/-- Every instruction `callInstr sem` can emit (for ANY `sem`) is `WFInstr` and straight-line: the
    probe RESULTS are the fixed compute opcodes, independent of which `sem` selected them. -/
theorem callInstr_props (sem : List Bytes → List Bytes) :
    ∀ i ∈ callInstr sem, WFInstr i ∧ straightOp i.opcode = true := by
  intro i hi
  unfold callInstr at hi
  cases hA : arithKindProbe sem with
  | some k =>
    simp only [hA, List.mem_singleton] at hi; subst hi
    exact ⟨arithInstr_WFInstr k, by cases k <;> decide⟩
  | none =>
    simp only [hA] at hi
    cases hBN : binNumProbe sem with
    | some j => simp only [hBN, List.mem_singleton] at hi; subst hi; exact binNumProbe_wf hBN
    | none =>
      simp only [hBN] at hi
      cases hBB : binBoolProbe sem with
      | some j => simp only [hBB, List.mem_singleton] at hi; subst hi; exact binBoolProbe_wf hBB
      | none =>
        simp only [hBB] at hi
        cases hUN : unaryNumProbe sem with
        | some j => simp only [hUN, List.mem_singleton] at hi; subst hi; exact unaryNumProbe_wf hUN
        | none =>
          simp only [hUN] at hi
          cases hUB : unaryBoolProbe sem with
          | some j => simp only [hUB, List.mem_singleton] at hi; subst hi; exact unaryBoolProbe_wf hUB
          | none => simp only [hUB] at hi; simp at hi

/-- ★★ Every instruction the scheduler's `encFull`-encoded output contains is `WFInstr` (so
    `Codec.parse_encode` applies) AND straight-line (so `run_straightline`/`run_bytes_eq_fold`
    applies). Constants use `hconst`; `PICK`/`ROLL` indices use `hidx`; the rest is unconditional. -/
theorem emitted_props (b : Block Bytes)
    (hconst : ∀ (v : Bytes) (cse : Bool), Ref.const v cse ∈ blockRefs b → v.length ≤ maxItemLen)
    (hidx : ∀ n : Nat, (Op.PICK n ∈ emit b ∨ Op.ROLL n ∈ emit b) →
        (bigIntToVmNumber (Int.ofNat n)).length ≤ maxItemLen) :
    ∀ i ∈ (emit b).flatMap encFull, WFInstr i ∧ straightOp i.opcode = true := by
  intro i hi
  obtain ⟨op, hop, hi⟩ := List.mem_flatMap.mp hi
  rcases emit_op_cases b op hop with hshuf | ⟨n, rfl⟩ | ⟨n, rfl⟩ | ⟨v, cse, rfl, hmem⟩ | ⟨nd, hnd, rfl⟩
  · -- shuffle: a single plain opcode
    rcases hshuf with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
      · have hii := List.mem_singleton.mp hi; subst hii
        exact ⟨WFInstr_plain _ (by decide), by decide⟩
  · -- PICK n : [pushOf idx, OP_PICK]
    have hlen : (bigIntToVmNumber (Int.ofNat n)).length ≤ maxItemLen := hidx n (Or.inl hop)
    rcases List.mem_cons.mp hi with rfl | hi2
    · exact ⟨pushOf_WFInstr _ (by simp only [maxItemLen] at hlen; omega), pushOf_straight _⟩
    · have hii := List.mem_singleton.mp hi2; subst hii
      exact ⟨WFInstr_plain _ (by decide), by decide⟩
  · -- ROLL n : [pushOf idx, OP_ROLL]
    have hlen : (bigIntToVmNumber (Int.ofNat n)).length ≤ maxItemLen := hidx n (Or.inr hop)
    rcases List.mem_cons.mp hi with rfl | hi2
    · exact ⟨pushOf_WFInstr _ (by simp only [maxItemLen] at hlen; omega), pushOf_straight _⟩
    · have hii := List.mem_singleton.mp hi2; subst hii
      exact ⟨WFInstr_plain _ (by decide), by decide⟩
  · -- PUSH v : [pushOf v]
    have hlen : v.length ≤ maxItemLen := hconst v cse hmem
    have hii := List.mem_singleton.mp hi; subst hii
    exact ⟨pushOf_WFInstr _ (by simp only [maxItemLen] at hlen; omega), pushOf_straight _⟩
  · -- CALL : callInstr of the node's sem (any sem)
    rw [encFull_call] at hi
    exact callInstr_props _ i hi

theorem emitted_WFInstr (b : Block Bytes)
    (hconst : ∀ (v : Bytes) (cse : Bool), Ref.const v cse ∈ blockRefs b → v.length ≤ maxItemLen)
    (hidx : ∀ n : Nat, (Op.PICK n ∈ emit b ∨ Op.ROLL n ∈ emit b) →
        (bigIntToVmNumber (Int.ofNat n)).length ≤ maxItemLen) :
    ∀ i ∈ (emit b).flatMap encFull, WFInstr i :=
  fun i hi => (emitted_props b hconst hidx i hi).1

theorem emitted_straight (b : Block Bytes)
    (hconst : ∀ (v : Bytes) (cse : Bool), Ref.const v cse ∈ blockRefs b → v.length ≤ maxItemLen)
    (hidx : ∀ n : Nat, (Op.PICK n ∈ emit b ∨ Op.ROLL n ∈ emit b) →
        (bigIntToVmNumber (Int.ofNat n)).length ≤ maxItemLen) :
    ∀ i ∈ (emit b).flatMap encFull, straightOp i.opcode = true :=
  fun i hi => (emitted_props b hconst hidx i hi).2

/-! ### 6. ★★★★ THE BYTE-LEVEL PUSH-BUTTON — the whole optimizer on RAW BYTECODE, ANY covered block. -/

/-- ★★★★ THE FULLY-GENERAL BYTE-LEVEL PUSH-BUTTON (optimized side). For ANY `WellFormed` block whose
    compute nodes are covered numeric classes (`hcov`), whose constants (`hconst`) and `PICK`/`ROLL`
    indices (`hidx`) encode within the item limit, the ACTUAL BYTECODE the scheduler emits —
    `((emit b).flatMap encFull).flatMap encodeInstr` —
      • PARSES back to exactly the emitted instruction array (`Codec.parse_encode`, every emitted
        instruction `WFInstr`), and
      • RUN from the entry state on LeanBCH's real fuel-driven `run`/`stepInstr` VM (enough fuel; the
        run accepting), computes EXACTLY the block's DAG denotation `denote b M A` — same main stack,
        same alt stack, no error.
    This lands the optimizer's soundness on genuine consensus BYTECODE for an ARBITRARY covered block,
    not a fixed one and not a `List Instr`. -/
theorem push_button (b : Block Bytes) (hwf : WellFormed b) (M A : List Bytes)
    (hM : M.length = b.entryDepth) (hA : A.length = b.entryAlt)
    (hcov : ∀ nd ∈ b.nodes, CoveredNode nd.op)
    (hconst : ∀ (v : Bytes) (cse : Bool), Ref.const v cse ∈ blockRefs b → v.length ≤ maxItemLen)
    (hidx : ∀ n : Nat, (Op.PICK n ∈ emit b ∨ Op.ROLL n ∈ emit b) →
        (bigIntToVmNumber (Int.ofNat n)).length ≤ maxItemLen)
    (fuel : Nat) (hf : ((emit b).flatMap encFull).length + 1 ≤ fuel)
    (hacc : foldStraight ((emit b).flatMap encFull) (entryState M A).1 (entryState M A).2 ≠ none) :
    parse (((emit b).flatMap encFull).flatMap encodeInstr) = .ok ((emit b).flatMap encFull).toArray
    ∧ (VM.run fuel { instrs := ((emit b).flatMap encFull).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).stack = (denote b M A).1
    ∧ (VM.run fuel { instrs := ((emit b).flatMap encFull).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).alt = (denote b M A).2
    ∧ (VM.run fuel { instrs := ((emit b).flatMap encFull).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).error = none := by
  refine ⟨parse_encode _ (emitted_WFInstr b hconst hidx), ?_⟩
  exact run_bytes_eq_fold _ (emitted_straight b hconst hidx) _ _ _ _ fuel hf
    (push_button_foldStraight b hwf M A hM hA hcov hconst hidx hacc)

/-! ### 7. ★ THE ORIGINAL-PROGRAM ATTACHMENT — for blocks the DECOMPILER produced. -/

/-- ★★★★ THE PUSH-BUTTON WITH THE ORIGINAL RE-ATTACHED. For a covered block the DECOMPILER accepts
    from `rawOps` (`hb : decompileBlock rawOps ed ea = some b`, whose value-ops are output-arity
    uniform, `hops`): the optimizer's actual output BYTECODE, parsed and run on the real VM, computes
    `denote b M A`; AND the ORIGINAL program `rawOps` runs (on the abstract machine) to the SAME
    `denote b M A` (`DecompileWF.decompile_end_to_end` ∘ `schedule_refines`). Hence the original
    program and the optimizer's output-bytes-on-the-real-VM agree, for any covered decompiled block —
    the full analog of `PushButtonBytes.push_button_arith_bytes` over an ARBITRARY block. `WellFormed`
    is PROVEN from acceptance (`DecompileWF`), not assumed. -/
theorem push_button_original (rawOps : List (Op Bytes)) (ed ea : Nat) (M A : List Bytes)
    (hM : M.length = ed) (hA : A.length = ea)
    (b : Block Bytes) (hops : ∀ o ∈ rawOps, OpUniform o)
    (hb : decompileBlock rawOps ed ea = some b)
    (hcov : ∀ nd ∈ b.nodes, CoveredNode nd.op)
    (hconst : ∀ (v : Bytes) (cse : Bool), Ref.const v cse ∈ blockRefs b → v.length ≤ maxItemLen)
    (hidx : ∀ n : Nat, (Op.PICK n ∈ emit b ∨ Op.ROLL n ∈ emit b) →
        (bigIntToVmNumber (Int.ofNat n)).length ≤ maxItemLen)
    (fuel : Nat) (hf : ((emit b).flatMap encFull).length + 1 ≤ fuel)
    (hacc : foldStraight ((emit b).flatMap encFull) (entryState M A).1 (entryState M A).2 ≠ none) :
    (parse (((emit b).flatMap encFull).flatMap encodeInstr) = .ok ((emit b).flatMap encFull).toArray
      ∧ (VM.run fuel { instrs := ((emit b).flatMap encFull).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).stack = (denote b M A).1
      ∧ (VM.run fuel { instrs := ((emit b).flatMap encFull).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).alt = (denote b M A).2
      ∧ (VM.run fuel { instrs := ((emit b).flatMap encFull).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).error = none)
    ∧ LeanBCH.Opt.run rawOps (entryState M A) = some (denote b M A) := by
  have hwf : WellFormed b := decompileBlock_WellFormed rawOps ed ea b hops hb
  obtain ⟨_, _, hde, hea, _, _, _⟩ := decompileBlock_dfin rawOps ed ea b hb
  have hMd : M.length = b.entryDepth := by rw [hM, hde]
  have hAd : A.length = b.entryAlt := by rw [hA, hea]
  refine ⟨push_button b hwf M A hMd hAd hcov hconst hidx fuel hf hacc, ?_⟩
  rw [← decompile_end_to_end rawOps ed ea M A hM hA b hops hb]
  exact schedule_refines b hwf M A hMd hAd

/-- ★ NON-VACUITY of the coverage hypothesis: `CoveredNode` is INHABITED — every arithmetic block's
    node satisfies it (the first disjunct). So `push_button`'s `hcov` premise is genuinely
    satisfiable and the general theorem is not a vacuous-hypothesis trap; a concrete end-to-end firing
    on the arith class ships as `PushButtonBytes.push_button_arith_bytes` /
    `OriginalBytes.push_button_arith_bytes_symmetric`. -/
theorem coveredNode_bA (k : ArithKind) : ∀ nd ∈ (LeanBCH.Opt.EmitConcrete.bA k).nodes, CoveredNode nd.op := by
  intro nd hnd
  simp only [LeanBCH.Opt.EmitConcrete.bA, List.mem_singleton] at hnd
  subst hnd
  exact Or.inl ⟨k, rfl, rfl⟩

end LeanBCH.Opt.PushButtonFull
