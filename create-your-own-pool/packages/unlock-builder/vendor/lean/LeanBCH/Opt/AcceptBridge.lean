/-
  LeanBCH.Opt.AcceptBridge — the compute-op bridge closed by ACCEPTANCE (C1 increment 4c).

  The compute-op faithfulness witnesses (`OpFaithful` / `ComputeBridge.simOpOn_*`) are CONDITIONAL:
  each holds only when its operands are canonical numbers (`ArithPre`/`UnaryPre`/`BinPre`). The 4c
  question was "what invariant discharges those preconditions?" — and the answer is that no forward
  invariant is needed. The real `stepInstr` sets an error (`.stackUnderflow`/`.minimalEncoding`/
  `.divByZero`) in EXACTLY the cases where the precondition fails, so `foldStraight [op] st al ≠ none`
  is *definitionally equivalent* to the precondition. Because `foldStraight` short-circuits to `none`
  on the first failing chunk, "the whole encoded program did not error" already asserts that every
  compute op's precondition held when it fired — the precondition is threaded by ACCEPTANCE, backward,
  not by a preserved-forward `Q`. This mirrors the acceptance move the headline `rewrite_sound_under_VM`
  already uses (`Adapter.lean`, `rw [haccept]`), generalized from the unconditional shuffle fragment to
  the conditional compute ops. Additive: no edit to the DAG / scheduler / simulation spine.
-/
import LeanBCH.Opt.ComputeBridge

namespace LeanBCH.Opt.Adapter
open LeanBCH LeanBCH.VM LeanBCH.Opt LeanBCH.Opt.Op LeanBCH.Opt.OpFaithful
-- The converses share one union simp set covering every op-arm decoder; per op most are unused.
set_option linter.unusedSimpArgs false

/-- `readNum?` is total-or-canonical: it is either `some (toNum b)` (when `b` is a short, minimally
    encoded VM number) or `none`. It NEVER returns `some v` for a non-`toNum` value — so recovering
    `readNum? b = some (toNum b)` from "it wasn't `none`" is exact, not a surrogate. -/
theorem readNum?_some_or_none (b : Bytes) : readNum? b = some (toNum b) ∨ readNum? b = none := by
  unfold readNum?
  split
  · exact Or.inl rfl
  · exact Or.inr rfl

/-- ★ THE CONVERSE (arithmetic), the crux of the acceptance bridge: if the one-instruction encoding of
    a binary arithmetic op does NOT error on `st`, then its operands satisfy `ArithPre` — the two top
    items are canonically-encoded numbers and (for div/mod) the divisor is nonzero. The exact mirror
    of `sim_CALL_arith`: the frozen guard chain reduces on the concrete opcode literal, and the arm's
    own `.stackUnderflow`/`.minimalEncoding`/`.divByZero` guards are what force the precondition. -/
theorem arith_accept_pre (k : ArithKind) (st al : Stack)
    (h : foldStraight [arithInstr k] st al ≠ none) : ArithPre k st al := by
  rw [foldStraight_single] at h
  cases st with
  | nil => exact absurd (by cases k <;> rfl) h
  | cons b st1 =>
    cases st1 with
    | nil => exact absurd (by cases k <;> rfl) h
    | cons a rest =>
      rcases readNum?_some_or_none a with ha | ha
      · rcases readNum?_some_or_none b with hb | hb
        · refine ⟨a, b, rest, rfl, ha, hb, fun _ hb0 => ?_⟩
          apply h
          cases k <;>
            simp_all (config := { decide := true }) [stepStk, stepInstr, arithInstr, arithByte,
              Opcode.arithKind?, State.advance, State.setErr]
        · exact absurd (by
            cases k <;>
              simp_all (config := { decide := true }) [stepStk, stepInstr, arithInstr, arithByte,
                Opcode.arithKind?, State.setErr]) h
      · exact absurd (by
          cases k <;>
            simp_all (config := { decide := true }) [stepStk, stepInstr, arithInstr, arithByte,
              Opcode.arithKind?, State.setErr]) h


/-! ### The converse for the remaining compute classes (mirrors of the OpFaithful witnesses).
    Same shape as `arith_accept_pre`: the op's own arm errors on exactly the states where its
    precondition fails, so "did not error" recovers the precondition. Hash ops are total, so the
    converse recovers only operand PRESENCE (`HashPre`). -/

theorem accept_pre_1ADD (st al : Stack) (h : foldStraight [opInstr 0x8b] st al ≠ none) : UnaryPre st al := by
  rw [foldStraight_single] at h
  cases st with
  | nil => exact absurd rfl h
  | cons x rest =>
    rcases readNum?_some_or_none x with hx | hx
    · exact ⟨x, rest, rfl, hx⟩
    · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h

theorem accept_pre_1SUB (st al : Stack) (h : foldStraight [opInstr 0x8c] st al ≠ none) : UnaryPre st al := by
  rw [foldStraight_single] at h
  cases st with
  | nil => exact absurd rfl h
  | cons x rest =>
    rcases readNum?_some_or_none x with hx | hx
    · exact ⟨x, rest, rfl, hx⟩
    · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h

theorem accept_pre_NEGATE (st al : Stack) (h : foldStraight [opInstr 0x8f] st al ≠ none) : UnaryPre st al := by
  rw [foldStraight_single] at h
  cases st with
  | nil => exact absurd rfl h
  | cons x rest =>
    rcases readNum?_some_or_none x with hx | hx
    · exact ⟨x, rest, rfl, hx⟩
    · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h

theorem accept_pre_ABS (st al : Stack) (h : foldStraight [opInstr 0x90] st al ≠ none) : UnaryPre st al := by
  rw [foldStraight_single] at h
  cases st with
  | nil => exact absurd rfl h
  | cons x rest =>
    rcases readNum?_some_or_none x with hx | hx
    · exact ⟨x, rest, rfl, hx⟩
    · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h

theorem accept_pre_NOT (st al : Stack) (h : foldStraight [opInstr 0x91] st al ≠ none) : UnaryPre st al := by
  rw [foldStraight_single] at h
  cases st with
  | nil => exact absurd rfl h
  | cons x rest =>
    rcases readNum?_some_or_none x with hx | hx
    · exact ⟨x, rest, rfl, hx⟩
    · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h

theorem accept_pre_0NOTEQUAL (st al : Stack) (h : foldStraight [opInstr 0x92] st al ≠ none) : UnaryPre st al := by
  rw [foldStraight_single] at h
  cases st with
  | nil => exact absurd rfl h
  | cons x rest =>
    rcases readNum?_some_or_none x with hx | hx
    · exact ⟨x, rest, rfl, hx⟩
    · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h

theorem accept_pre_MIN (st al : Stack) (h : foldStraight [opInstr 0xa3] st al ≠ none) : BinPre st al := by
  rw [foldStraight_single] at h
  cases st with
  | nil => exact absurd rfl h
  | cons b st1 => cases st1 with
    | nil => exact absurd rfl h
    | cons a rest =>
      rcases readNum?_some_or_none a with ha | ha
      · rcases readNum?_some_or_none b with hb | hb
        · exact ⟨a, b, rest, rfl, ha, hb⟩
        · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h
      · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h

theorem accept_pre_MAX (st al : Stack) (h : foldStraight [opInstr 0xa4] st al ≠ none) : BinPre st al := by
  rw [foldStraight_single] at h
  cases st with
  | nil => exact absurd rfl h
  | cons b st1 => cases st1 with
    | nil => exact absurd rfl h
    | cons a rest =>
      rcases readNum?_some_or_none a with ha | ha
      · rcases readNum?_some_or_none b with hb | hb
        · exact ⟨a, b, rest, rfl, ha, hb⟩
        · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h
      · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h

theorem accept_pre_BOOLAND (st al : Stack) (h : foldStraight [opInstr 0x9a] st al ≠ none) : BinPre st al := by
  rw [foldStraight_single] at h
  cases st with
  | nil => exact absurd rfl h
  | cons b st1 => cases st1 with
    | nil => exact absurd rfl h
    | cons a rest =>
      rcases readNum?_some_or_none a with ha | ha
      · rcases readNum?_some_or_none b with hb | hb
        · exact ⟨a, b, rest, rfl, ha, hb⟩
        · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h
      · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h

theorem accept_pre_BOOLOR (st al : Stack) (h : foldStraight [opInstr 0x9b] st al ≠ none) : BinPre st al := by
  rw [foldStraight_single] at h
  cases st with
  | nil => exact absurd rfl h
  | cons b st1 => cases st1 with
    | nil => exact absurd rfl h
    | cons a rest =>
      rcases readNum?_some_or_none a with ha | ha
      · rcases readNum?_some_or_none b with hb | hb
        · exact ⟨a, b, rest, rfl, ha, hb⟩
        · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h
      · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h

theorem accept_pre_NUMEQUAL (st al : Stack) (h : foldStraight [opInstr 0x9c] st al ≠ none) : BinPre st al := by
  rw [foldStraight_single] at h
  cases st with
  | nil => exact absurd rfl h
  | cons b st1 => cases st1 with
    | nil => exact absurd rfl h
    | cons a rest =>
      rcases readNum?_some_or_none a with ha | ha
      · rcases readNum?_some_or_none b with hb | hb
        · exact ⟨a, b, rest, rfl, ha, hb⟩
        · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h
      · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h

theorem accept_pre_NUMNOTEQUAL (st al : Stack) (h : foldStraight [opInstr 0x9e] st al ≠ none) : BinPre st al := by
  rw [foldStraight_single] at h
  cases st with
  | nil => exact absurd rfl h
  | cons b st1 => cases st1 with
    | nil => exact absurd rfl h
    | cons a rest =>
      rcases readNum?_some_or_none a with ha | ha
      · rcases readNum?_some_or_none b with hb | hb
        · exact ⟨a, b, rest, rfl, ha, hb⟩
        · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h
      · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h

theorem accept_pre_LESSTHAN (st al : Stack) (h : foldStraight [opInstr 0x9f] st al ≠ none) : BinPre st al := by
  rw [foldStraight_single] at h
  cases st with
  | nil => exact absurd rfl h
  | cons b st1 => cases st1 with
    | nil => exact absurd rfl h
    | cons a rest =>
      rcases readNum?_some_or_none a with ha | ha
      · rcases readNum?_some_or_none b with hb | hb
        · exact ⟨a, b, rest, rfl, ha, hb⟩
        · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h
      · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h

theorem accept_pre_GREATERTHAN (st al : Stack) (h : foldStraight [opInstr 0xa0] st al ≠ none) : BinPre st al := by
  rw [foldStraight_single] at h
  cases st with
  | nil => exact absurd rfl h
  | cons b st1 => cases st1 with
    | nil => exact absurd rfl h
    | cons a rest =>
      rcases readNum?_some_or_none a with ha | ha
      · rcases readNum?_some_or_none b with hb | hb
        · exact ⟨a, b, rest, rfl, ha, hb⟩
        · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h
      · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h

theorem accept_pre_LESSTHANOREQUAL (st al : Stack) (h : foldStraight [opInstr 0xa1] st al ≠ none) : BinPre st al := by
  rw [foldStraight_single] at h
  cases st with
  | nil => exact absurd rfl h
  | cons b st1 => cases st1 with
    | nil => exact absurd rfl h
    | cons a rest =>
      rcases readNum?_some_or_none a with ha | ha
      · rcases readNum?_some_or_none b with hb | hb
        · exact ⟨a, b, rest, rfl, ha, hb⟩
        · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h
      · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h

theorem accept_pre_GREATERTHANOREQUAL (st al : Stack) (h : foldStraight [opInstr 0xa2] st al ≠ none) : BinPre st al := by
  rw [foldStraight_single] at h
  cases st with
  | nil => exact absurd rfl h
  | cons b st1 => cases st1 with
    | nil => exact absurd rfl h
    | cons a rest =>
      rcases readNum?_some_or_none a with ha | ha
      · rcases readNum?_some_or_none b with hb | hb
        · exact ⟨a, b, rest, rfl, ha, hb⟩
        · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h
      · exact absurd (by simp_all (config := { decide := true }) [stepStk, stepInstr, opInstr, Opcode.arithKind?, unaryNumOp?, unaryBoolOp?, binNumOp?, binBoolOp?, State.setErr]) h

theorem accept_pre_RIPEMD160 (st al : Stack) (h : foldStraight [opInstr 0xa6] st al ≠ none) : HashPre st al := by
  rw [foldStraight_single] at h
  cases st with
  | nil => exact absurd rfl h
  | cons x rest => exact ⟨x, rest, rfl⟩

theorem accept_pre_SHA1 (st al : Stack) (h : foldStraight [opInstr 0xa7] st al ≠ none) : HashPre st al := by
  rw [foldStraight_single] at h
  cases st with
  | nil => exact absurd rfl h
  | cons x rest => exact ⟨x, rest, rfl⟩

theorem accept_pre_SHA256 (st al : Stack) (h : foldStraight [opInstr 0xa8] st al ≠ none) : HashPre st al := by
  rw [foldStraight_single] at h
  cases st with
  | nil => exact absurd rfl h
  | cons x rest => exact ⟨x, rest, rfl⟩

theorem accept_pre_HASH160 (st al : Stack) (h : foldStraight [opInstr 0xa9] st al ≠ none) : HashPre st al := by
  rw [foldStraight_single] at h
  cases st with
  | nil => exact absurd rfl h
  | cons x rest => exact ⟨x, rest, rfl⟩

theorem accept_pre_HASH256 (st al : Stack) (h : foldStraight [opInstr 0xaa] st al ≠ none) : HashPre st al := by
  rw [foldStraight_single] at h
  cases st with
  | nil => exact absurd rfl h
  | cons x rest => exact ⟨x, rest, rfl⟩


/-- ★ THE ACCEPTANCE COMPOSITION — the payoff. Under any encoder whose every op is faithful on states
    meeting its precondition `P op` (`SimOpOn (P op)`) and whose precondition is RECOVERABLE from that
    op's chunk not erroring (`hconv`, e.g. `arith_accept_pre`), the whole encoded program — WHENEVER
    it runs without error — has `foldStraight` equal to the abstract `LeanBCH.Opt.run`. The
    precondition is threaded by acceptance, backward: `foldStraight` short-circuits on the first
    failing chunk, so the whole being `≠ none` forces each op's chunk `≠ none`, hence each `P op`. No
    forward invariant, no `hpres`, no DAG typing. Generalizes `run_via_encode_on` to conditional ops
    with the shuffle/PUSH fragment embedding via `SimOp.toOn` (its `P op` trivially recoverable). -/
theorem run_via_encode_accept (enc : Op Bytes → List Instr) (P : Op Bytes → Stack → Stack → Prop) :
    ∀ (ops : List (Op Bytes)),
      (∀ op ∈ ops, SimOpOn (P op) op (enc op)) →
      (∀ op ∈ ops, ∀ st al : Stack, foldStraight (enc op) st al ≠ none → P op st al) →
      ∀ (st al : Stack), foldStraight (ops.flatMap enc) st al ≠ none →
        foldStraight (ops.flatMap enc) st al = LeanBCH.Opt.run ops (st, al)
  | [],        _,    _,     st, al, _   => by simp [foldStraight, LeanBCH.Opt.run]
  | op :: ops, hsim, hconv, st, al, hne => by
      rw [List.flatMap_cons, foldStraight_append] at hne ⊢
      have hop_ne : foldStraight (enc op) st al ≠ none := by
        intro hnone; apply hne; rw [hnone]; rfl
      have hP : P op st al := hconv op (List.mem_cons.mpr (Or.inl rfl)) st al hop_ne
      rw [hsim op (List.mem_cons.mpr (Or.inl rfl)) st al hP] at hne ⊢
      have hstep_ne : LeanBCH.Opt.step op (st, al) ≠ none := by
        rw [← hsim op (List.mem_cons.mpr (Or.inl rfl)) st al hP]; exact hop_ne
      cases hb : LeanBCH.Opt.step op (st, al) with
      | none   => exact absurd hb hstep_ne
      | some p =>
          rw [hb] at hne
          simp only [Option.bind, LeanBCH.Opt.run, hb]
          simp only [Option.bind] at hne
          exact run_via_encode_accept enc P ops
            (fun o ho => hsim o (List.mem_cons.mpr (Or.inr ho)))
            (fun o ho => hconv o (List.mem_cons.mpr (Or.inr ho))) p.1 p.2 hne

/-- ★★ THE ACCEPTANCE HEADLINE — the optimizer sound under the real VM, for programs WITH compute ops.
    For a `Correct` rewrite `src ⇒ dst` whose emitted (`dst`) ops are faithful-under-precondition
    (`SimOpOn`) with those preconditions recoverable from acceptance (`hconvD`, e.g.
    `arith_accept_pre`): WHENEVER the emitted bytecode runs on LeanBCH's real straight-line
    `stepInstr` interpreter WITHOUT error, it computes EXACTLY the ORIGINAL program's abstract
    semantics `LeanBCH.Opt.run src`. Unlike the unconditional `rewrite_sound_under_VM`, this carries
    the compute ops (arith/…/hash) honestly: the conditional faithfulness is discharged by the run's
    own acceptance, never assumed. `foldStraight` is the real fuel-driven `run` (keystone
    `run_straightline`), so "run the optimized bytecode" IS "compute the original's semantics". -/
theorem rewrite_sound_accept (enc : Op Bytes → List Instr) (P : Op Bytes → Stack → Stack → Prop)
    {src dst : List (Op Bytes)}
    (hsimD : ∀ op ∈ dst, SimOpOn (P op) op (enc op))
    (hconvD : ∀ op ∈ dst, ∀ st al : Stack, foldStraight (enc op) st al ≠ none → P op st al)
    (h : LeanBCH.Opt.Correct src dst) (st al : Stack)
    (hacc : foldStraight (dst.flatMap enc) st al ≠ none) :
    foldStraight (dst.flatMap enc) st al = LeanBCH.Opt.run src (st, al) := by
  rw [run_via_encode_accept enc P dst hsimD hconvD st al hacc]
  exact (h (st, al)).symm

end LeanBCH.Opt.Adapter
