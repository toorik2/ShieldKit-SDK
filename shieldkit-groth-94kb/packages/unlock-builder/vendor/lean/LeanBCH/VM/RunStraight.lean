/-
  LeanBCH.VM.RunStraight — the KEYSTONE connecting the ip-machine `run` to the algebraic
  denotation `foldStraight`.

  `Straightline.lean` proved the *algebra* (`foldStraight_append`, `splice_congr`) of the pure
  stack transformer.  This file closes the loop: on a straight-line program (every opcode a
  `straightOp`) the fuel-driven `run` computes EXACTLY `foldStraight` — same stack, same alt,
  and `error = none` iff the fold succeeds.  The corollary `splice_congr_run` lifts the algebraic
  splice congruence to the real `run`: swapping a straight block for a `BlockEquiv` one leaves the
  whole program's `run` observationally unchanged.

  The crux is `stepInstr_local`: on a straight op the `stack`/`alt`/`error` outputs of `stepInstr`
  are a function of the input `stack`/`alt`/`error` alone — never of `ip`/`ctrl`/`instrs`/… .  With
  that, one `step1` on a straight op with empty control stack equals one `stepStk`, and an induction
  over the instruction pointer discharges the whole run.
-/
import LeanBCH.VM.Straightline

namespace LeanBCH.VM
open LeanBCH LeanBCH.VM.State

set_option maxHeartbeats 4000000
set_option maxRecDepth 100000
-- The per-arm closers are uniform over ~16 opcode families, so they deliberately over-specify
-- their `simp` sets; the resulting per-arm "unused simp arg" hints are expected.
set_option linter.unusedSimpArgs false

/-! ## The field-independence crux -/

/- Closer for the `s`-vs-`t` field lemma: resolve the (aligned) stack/alt matches, reduce record
   projections, split any residual value ifs/matches, and close reflexively. -/
set_option hygiene false in
local macro "arm_close" : tactic =>
  `(tactic| (refine ⟨?_, ?_, ?_⟩ <;>
      rcases t.stack with _ | ⟨x0, _ | ⟨x1, _ | ⟨x2, xr⟩⟩⟩ <;>
      rcases t.alt with _ | ⟨y0, yr⟩ <;>
      (repeat' first
        | rfl
        | (simp only [State.advance, State.push, State.setErr, removeNth, hst, hal, herr]; done)
        | split)))

/-- ★ On a straight opcode, the `stack`/`alt`/`error` outputs of `stepInstr` depend ONLY on the
    input `stack`/`alt`/`error` — the control-flow fields `ip`/`ctrl`/`instrs`/… are irrelevant.
    (The six control opcodes are the only ones that would read/write them; `straightOp` excludes
    exactly those, so every reachable arm is a pure stack/alt transformer.) -/
theorem stepInstr_local {op : UInt8} {data : Bytes} {s t : State}
    (hstr : straightOp op = true)
    (hst : s.stack = t.stack) (hal : s.alt = t.alt) (herr : s.error = t.error) :
    (stepInstr op data s).stack = (stepInstr op data t).stack ∧
    (stepInstr op data s).alt = (stepInstr op data t).alt ∧
    (stepInstr op data s).error = (stepInstr op data t).error := by
  simp only [straightOp, Bool.and_eq_true, Bool.not_eq_true', bne_iff_ne] at hstr
  obtain ⟨⟨hcond, hbegin⟩, huntil⟩ := hstr
  unfold Opcode.isConditional at hcond
  simp only [Bool.or_eq_false_iff] at hcond
  have cIF : (op == Opcode.OP_IF) = false := hcond.1.1.1
  have cNOTIF : (op == Opcode.OP_NOTIF) = false := hcond.1.1.2
  have cELSE : (op == Opcode.OP_ELSE) = false := hcond.1.2
  have cENDIF : (op == Opcode.OP_ENDIF) = false := hcond.2
  have cBEGIN : (op == Opcode.OP_BEGIN) = false := by rw [beq_eq_false_iff_ne]; exact hbegin
  have cUNTIL : (op == Opcode.OP_UNTIL) = false := by rw [beq_eq_false_iff_ne]; exact huntil
  simp only [stepInstr, cIF, cNOTIF, cELSE, cENDIF, cBEGIN, cUNTIL, Bool.or_false, Bool.false_or,
             Bool.false_eq_true, if_false]
  rw [hst, hal]
  cases hpush : Opcode.isPushOp op with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hV : (op == Opcode.OP_VERIFY) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hR : (op == Opcode.OP_RETURN) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hDUP : (op == Opcode.OP_DUP) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hDROP : (op == Opcode.OP_DROP) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hOVER : (op == Opcode.OP_OVER) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hSWAP : (op == Opcode.OP_SWAP) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hROT : (op == Opcode.OP_ROT) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hNIP : (op == Opcode.OP_NIP) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hTUCK : (op == Opcode.OP_TUCK) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hTO : (op == Opcode.OP_TOALTSTACK) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hFROM : (op == Opcode.OP_FROMALTSTACK) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hPR : (op == Opcode.OP_PICK || op == Opcode.OP_ROLL) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hK : Opcode.arithKind? op with
  | some k => arm_close
  | none =>
  cases hEQ : (op == Opcode.OP_EQUAL) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hEV : (op == Opcode.OP_EQUALVERIFY) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hUN : unaryNumOp? op with
  | some f => arm_close
  | none =>
  cases hUB : unaryBoolOp? op with
  | some f => arm_close
  | none =>
  cases hBN : binNumOp? op with
  | some f => arm_close
  | none =>
  cases hBB : binBoolOp? op with
  | some f => arm_close
  | none =>
  cases h9d : (op == 0x9d) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases ha5 : (op == 0xa5) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hBW : bitwiseOp? op with
  | some f => arm_close
  | none =>
  cases hH : hashOp? op with
  | some h => arm_close
  | none =>
  cases hDEP : (op == Opcode.OP_DEPTH) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hSIZE : (op == Opcode.OP_SIZE) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hIFD : (op == Opcode.OP_IFDUP) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h2DR : (op == Opcode.OP_2DROP) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h2DU : (op == Opcode.OP_2DUP) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h3DU : (op == Opcode.OP_3DUP) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h2OV : (op == Opcode.OP_2OVER) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h2RO : (op == Opcode.OP_2ROT) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h2SW : (op == Opcode.OP_2SWAP) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h7e : (op == 0x7e) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h7f : (op == 0x7f) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h81 : (op == 0x81) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h80 : (op == 0x80) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hCS : (op == Opcode.OP_CODESEPARATOR) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hNOP : (op == Opcode.OP_NOP || (0xb0 ≤ op.toNat && op.toNat ≤ 0xb9)) with
  | true => simp only [if_true]; arm_close
  | false =>
  simp only [Bool.false_eq_true, if_false]
  arm_close

/- Closer for the single-state metadata lemma. -/
set_option hygiene false in
local macro "arm_self" : tactic =>
  `(tactic| (refine ⟨?_, ?_, ?_⟩ <;>
      (repeat' first
        | rfl
        | exact Or.inl rfl
        | exact Or.inr rfl
        | (simp only [State.advance, State.push, State.setErr, removeNth]; done)
        | split)))

/-- On a straight opcode, `stepInstr` leaves `ctrl` and `instrs` untouched, and advances `ip` by
    exactly one unless it aborts (sets `error`). -/
theorem stepInstr_self {op : UInt8} {data : Bytes} {s : State}
    (hstr : straightOp op = true) :
    (stepInstr op data s).ctrl = s.ctrl ∧ (stepInstr op data s).instrs = s.instrs ∧
      ((stepInstr op data s).ip = s.ip + 1 ∨ (stepInstr op data s).error.isSome = true) := by
  simp only [straightOp, Bool.and_eq_true, Bool.not_eq_true', bne_iff_ne] at hstr
  obtain ⟨⟨hcond, hbegin⟩, huntil⟩ := hstr
  unfold Opcode.isConditional at hcond
  simp only [Bool.or_eq_false_iff] at hcond
  have cIF : (op == Opcode.OP_IF) = false := hcond.1.1.1
  have cNOTIF : (op == Opcode.OP_NOTIF) = false := hcond.1.1.2
  have cELSE : (op == Opcode.OP_ELSE) = false := hcond.1.2
  have cENDIF : (op == Opcode.OP_ENDIF) = false := hcond.2
  have cBEGIN : (op == Opcode.OP_BEGIN) = false := by rw [beq_eq_false_iff_ne]; exact hbegin
  have cUNTIL : (op == Opcode.OP_UNTIL) = false := by rw [beq_eq_false_iff_ne]; exact huntil
  simp only [stepInstr, cIF, cNOTIF, cELSE, cENDIF, cBEGIN, cUNTIL, Bool.or_false, Bool.false_or,
             Bool.false_eq_true, if_false]
  cases hpush : Opcode.isPushOp op with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hV : (op == Opcode.OP_VERIFY) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hR : (op == Opcode.OP_RETURN) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hDUP : (op == Opcode.OP_DUP) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hDROP : (op == Opcode.OP_DROP) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hOVER : (op == Opcode.OP_OVER) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hSWAP : (op == Opcode.OP_SWAP) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hROT : (op == Opcode.OP_ROT) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hNIP : (op == Opcode.OP_NIP) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hTUCK : (op == Opcode.OP_TUCK) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hTO : (op == Opcode.OP_TOALTSTACK) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hFROM : (op == Opcode.OP_FROMALTSTACK) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hPR : (op == Opcode.OP_PICK || op == Opcode.OP_ROLL) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hK : Opcode.arithKind? op with
  | some k => arm_self
  | none =>
  cases hEQ : (op == Opcode.OP_EQUAL) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hEV : (op == Opcode.OP_EQUALVERIFY) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hUN : unaryNumOp? op with
  | some f => arm_self
  | none =>
  cases hUB : unaryBoolOp? op with
  | some f => arm_self
  | none =>
  cases hBN : binNumOp? op with
  | some f => arm_self
  | none =>
  cases hBB : binBoolOp? op with
  | some f => arm_self
  | none =>
  cases h9d : (op == 0x9d) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases ha5 : (op == 0xa5) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hBW : bitwiseOp? op with
  | some f => arm_self
  | none =>
  cases hH : hashOp? op with
  | some h => arm_self
  | none =>
  cases hDEP : (op == Opcode.OP_DEPTH) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hSIZE : (op == Opcode.OP_SIZE) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hIFD : (op == Opcode.OP_IFDUP) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h2DR : (op == Opcode.OP_2DROP) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h2DU : (op == Opcode.OP_2DUP) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h3DU : (op == Opcode.OP_3DUP) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h2OV : (op == Opcode.OP_2OVER) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h2RO : (op == Opcode.OP_2ROT) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h2SW : (op == Opcode.OP_2SWAP) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h7e : (op == 0x7e) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h7f : (op == 0x7f) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h81 : (op == 0x81) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h80 : (op == 0x80) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hCS : (op == Opcode.OP_CODESEPARATOR) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hNOP : (op == Opcode.OP_NOP || (0xb0 ≤ op.toNat && op.toNat ≤ 0xb9)) with
  | true => simp only [if_true]; arm_self
  | false =>
  simp only [Bool.false_eq_true, if_false]
  arm_self

/-! ## One step vs one `stepStk` -/

/-- `stepStk` is exactly the `stack`/`alt`/`error` shadow of one `stepInstr` from a live state
    (empty error). -/
theorem stepInstr_stepStk {i : Instr} {s : State} (hstr : straightOp i.opcode = true)
    (herr : s.error = none) :
    (match stepStk i s.stack s.alt with
     | some (st', al') => (stepInstr i.opcode i.data s).stack = st' ∧
         (stepInstr i.opcode i.data s).alt = al' ∧ (stepInstr i.opcode i.data s).error = none
     | none => (stepInstr i.opcode i.data s).error.isSome = true) := by
  have L := stepInstr_local (op := i.opcode) (data := i.data) (s := s)
    (t := { stack := s.stack, alt := s.alt }) hstr rfl rfl herr
  obtain ⟨Lst, Lal, Lerr⟩ := L
  unfold stepStk
  cases hue : (stepInstr i.opcode i.data { stack := s.stack, alt := s.alt }).error with
  | some e =>
    simp only [hue]
    simp only [Lerr, hue, Option.isSome_some]
  | none =>
    simp only [hue]
    exact ⟨Lst, Lal, by rw [Lerr, hue]⟩

/-- One `step1` with an empty control stack is exactly the raw `stepInstr` (with `ctrl = []` the
    branch is always live, so the op fires whether or not it is conditional). -/
theorem step1_straight {s : State} {i : Instr}
    (hctrl : s.ctrl = []) (hcur : s.current? = some i) :
    step1 s = stepInstr i.opcode i.data s := by
  simp only [step1, hcur, State.executionIsActive, hctrl, List.all_nil, Bool.true_or, if_true]

/-! ## The ip-induction -/

/-- Once finished, `run` is a fixed point. -/
theorem run_finished {s : State} (h : finished s = true) : ∀ f, run f s = s := by
  intro f
  cases f with
  | zero => rfl
  | succ n => show (if finished s then s else run n (step1 s)) = s; rw [if_pos h]

/-- The master induction: from any state whose `instrs = is`, empty control stack, no error, and
    enough fuel to reach the end, `run` matches `foldStraight` over the remaining instructions. -/
theorem run_from (is : Array Instr) (hs : ∀ i ∈ is.toList, straightOp i.opcode = true) :
    ∀ (fuel : Nat) (s : State), s.instrs = is → s.ctrl = [] → s.error = none →
      is.size - s.ip + 1 ≤ fuel →
      (match foldStraight (is.toList.drop s.ip) s.stack s.alt with
       | some (st', al') => (run fuel s).stack = st' ∧ (run fuel s).alt = al' ∧
           (run fuel s).error = none
       | none => (run fuel s).error.isSome = true) := by
  intro fuel
  induction fuel with
  | zero => intro s _ _ _ hfuel; exfalso; omega
  | succ f ih =>
    intro s hins hctrl herr hfuel
    by_cases hend : s.ip < is.size
    · -- a real step
      have hcur : s.current? = some is[s.ip] := by
        simp only [State.current?, hins]
        exact (Array.getElem?_eq_some_getElem_iff is s.ip hend).mpr trivial
      have hmem : is[s.ip] ∈ is.toList := Array.getElem_mem_toList hend
      have hstri : straightOp (is[s.ip]).opcode = true := hs _ hmem
      have hnotfin : finished s = false := by
        simp only [finished, herr, hins, Option.isSome_none, Bool.false_or, decide_eq_false_iff_not]
        omega
      have hstep : run (f + 1) s = run f (step1 s) := by
        show (if finished s then s else run f (step1 s)) = run f (step1 s)
        rw [hnotfin]; rfl
      rw [hstep, step1_straight hctrl hcur]
      have hdrop : is.toList.drop s.ip = is[s.ip] :: is.toList.drop (s.ip + 1) := by
        have h1 : s.ip < is.toList.length := by rw [Array.length_toList]; exact hend
        rw [List.drop_eq_getElem_cons h1, Array.getElem_toList]
      rw [hdrop, foldStraight]
      have hSS := stepInstr_stepStk (i := is[s.ip]) (s := s) hstri herr
      have hself := stepInstr_self (op := (is[s.ip]).opcode) (data := (is[s.ip]).data) (s := s) hstri
      cases hss : stepStk is[s.ip] s.stack s.alt with
      | none =>
        simp only [hss] at hSS
        have hfin1 : finished (stepInstr (is[s.ip]).opcode (is[s.ip]).data s) = true := by
          simp only [finished, hSS, Bool.true_or]
        rw [run_finished hfin1 f]
        exact hSS
      | some p =>
        obtain ⟨st', al'⟩ := p
        simp only [hss] at hSS
        obtain ⟨hSt, hAl, hErr⟩ := hSS
        have hs1ctrl : (stepInstr (is[s.ip]).opcode (is[s.ip]).data s).ctrl = [] := by
          rw [hself.1, hctrl]
        have hs1ins : (stepInstr (is[s.ip]).opcode (is[s.ip]).data s).instrs = is := by
          rw [hself.2.1, hins]
        have hs1ip : (stepInstr (is[s.ip]).opcode (is[s.ip]).data s).ip = s.ip + 1 := by
          rcases hself.2.2 with h | h
          · exact h
          · rw [hErr] at h; simp only [Option.isSome_none, Bool.false_eq_true] at h
        have hfuel1 : is.size - (stepInstr (is[s.ip]).opcode (is[s.ip]).data s).ip + 1 ≤ f := by
          rw [hs1ip]; omega
        have key := ih (stepInstr (is[s.ip]).opcode (is[s.ip]).data s) hs1ins hs1ctrl hErr hfuel1
        rw [hs1ip, hSt, hAl] at key
        exact key
    · -- past the end: nothing left to do
      have hge : is.size ≤ s.ip := by omega
      have hfin : finished s = true := by
        simp only [finished, hins, herr, Option.isSome_none, Bool.false_or, decide_eq_true_eq]
        omega
      rw [run_finished hfin (f + 1)]
      have hdrop : is.toList.drop s.ip = [] := by
        apply List.drop_eq_nil_of_le; rw [Array.length_toList]; exact hge
      rw [hdrop, foldStraight]
      exact ⟨rfl, rfl, herr⟩

/-! ## The keystone -/

/-- ★ RUN = FOLD.  On a straight-line program the ip-machine `run` computes exactly the algebraic
    denotation `foldStraight`: identical `stack` and `alt`, and it errors iff the fold underflows. -/
theorem run_straightline (is : Array Instr)
    (hs : ∀ i ∈ is.toList, straightOp i.opcode = true)
    (st al : Stack) (fuel : Nat) (hf : is.size + 1 ≤ fuel) :
    (match foldStraight is.toList st al with
     | some (st', al') =>
         (run fuel { instrs := is, stack := st, alt := al }).stack = st' ∧
         (run fuel { instrs := is, stack := st, alt := al }).alt = al' ∧
         (run fuel { instrs := is, stack := st, alt := al }).error = none
     | none => (run fuel { instrs := is, stack := st, alt := al }).error.isSome = true) := by
  have key := run_from is hs fuel { instrs := is, stack := st, alt := al } rfl rfl rfl (by simpa using hf)
  simpa using key

/-! ## The splice congruence, lifted to `run` -/

/-- ★ Replacing a straight block `b` by any behaviourally-equal block `b'` leaves the whole
    straight-line program's `run` result unchanged: both runs realise the *same* `foldStraight`
    denotation (equal by `splice_congr`), so they agree on `stack`/`alt`/`error`. -/
theorem splice_congr_run {b b' : List Instr} (h : BlockEquiv b b')
    (pre post : List Instr)
    (hstr : ∀ i ∈ pre ++ b ++ post, straightOp i.opcode = true)
    (hstr' : ∀ i ∈ pre ++ b' ++ post, straightOp i.opcode = true)
    (st al : Stack) (fuel fuel' : Nat)
    (hf : (pre ++ b ++ post).length + 1 ≤ fuel)
    (hf' : (pre ++ b' ++ post).length + 1 ≤ fuel') :
    (match foldStraight (pre ++ b ++ post) st al with
     | some (st', al') =>
         ((run fuel { instrs := (pre ++ b ++ post).toArray, stack := st, alt := al }).stack = st' ∧
          (run fuel { instrs := (pre ++ b ++ post).toArray, stack := st, alt := al }).alt = al' ∧
          (run fuel { instrs := (pre ++ b ++ post).toArray, stack := st, alt := al }).error = none) ∧
         ((run fuel' { instrs := (pre ++ b' ++ post).toArray, stack := st, alt := al }).stack = st' ∧
          (run fuel' { instrs := (pre ++ b' ++ post).toArray, stack := st, alt := al }).alt = al' ∧
          (run fuel' { instrs := (pre ++ b' ++ post).toArray, stack := st, alt := al }).error = none)
     | none =>
         (run fuel { instrs := (pre ++ b ++ post).toArray, stack := st, alt := al }).error.isSome = true ∧
         (run fuel' { instrs := (pre ++ b' ++ post).toArray, stack := st, alt := al }).error.isSome = true) := by
  have hstrA : ∀ i ∈ ((pre ++ b ++ post).toArray).toList, straightOp i.opcode = true := by
    intro i hi; rw [List.toList_toArray] at hi; exact hstr i hi
  have hstrA' : ∀ i ∈ ((pre ++ b' ++ post).toArray).toList, straightOp i.opcode = true := by
    intro i hi; rw [List.toList_toArray] at hi; exact hstr' i hi
  have e1 := run_straightline (pre ++ b ++ post).toArray hstrA st al fuel
    (by rw [List.size_toArray]; exact hf)
  have e2 := run_straightline (pre ++ b' ++ post).toArray hstrA' st al fuel'
    (by rw [List.size_toArray]; exact hf')
  rw [List.toList_toArray] at e1 e2
  have hcong : foldStraight (pre ++ b ++ post) st al = foldStraight (pre ++ b' ++ post) st al :=
    splice_congr h pre post st al
  rw [← hcong] at e2
  cases hf0 : foldStraight (pre ++ b ++ post) st al with
  | some p =>
    obtain ⟨st', al'⟩ := p
    rw [hf0] at e1 e2
    exact ⟨e1, e2⟩
  | none =>
    rw [hf0] at e1 e2
    exact ⟨e1, e2⟩

end LeanBCH.VM
