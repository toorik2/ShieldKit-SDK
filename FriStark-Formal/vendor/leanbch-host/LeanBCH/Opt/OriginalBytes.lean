/-
  LeanBCH.Opt.OriginalBytes — TRACK 3: give the ORIGINAL program the SAME byte treatment as the
  optimized one, so the push-button theorem becomes SYMMETRIC on genuine consensus BYTECODE.

  `PushButtonBytes.push_button_arith_bytes` already lands the OPTIMIZED side at the byte level: the
  scheduler's emitted bytes, PARSED and run on the real `run`/`stepInstr` VM, compute `denote (bA k)`.
  But the ORIGINAL program was still only run ABSTRACTLY there (`Opt.run rawOps = denote b` via
  `Decompile.bridge_block`) — never parsed from bytes. That asymmetry is the last open seam: a
  consensus node parses BOTH the original and the optimized script from raw bytes; the theorem should
  therefore treat both the same way.

  This file closes it, composing the three keystones already proven for the optimized side, now on an
  arbitrary abstract op program `rawOps`:

    • `AcceptBridge.run_via_encode_accept` : for a faithfully-encodable program (`SimOpOn`/`hconv`),
      whenever the encoded bytes run without error, `foldStraight (rawOps.flatMap encFull)` equals the
      ORIGINAL program's abstract semantics `Opt.run rawOps`.
    • `PushButtonBytes.run_bytes_eq_fold` : the fuel-driven ip-machine `run` on the instruction array
      reproduces that `foldStraight`.
    • `Codec.parse_encode` : the serialised bytes parse back to exactly the instruction array
      (`WFInstr` discharged per emitted instruction).

  DELIVERED:
    (a) `bytes_run_of_fold` — the reusable byte-lift over ANY straight-line, well-formed `List Instr`
        whose `foldStraight` is known: its serialised bytes parse back and, run on the real VM with
        enough fuel, reproduce that fold. (The optimized-side `emit_bA_bytes_sound` was exactly this
        lift specialised to `enc (emit (bA k))`; here it is factored out and reused on BOTH sides.)
    (b) `run_original_bytes_sound` — THE ORIGINAL-SIDE BYTE LEMMA. For any `rawOps` whose ops are all
        faithfully encodable under `encFull` (the same per-op faithfulness `SimOpOn`/`hconv` the
        optimized side uses) with well-formed, straight-line byte encodings: the ORIGINAL bytecode
        `(rawOps.flatMap encFull).flatMap encodeInstr`, PARSED and run on the real VM without error,
        reproduces EXACTLY the original program's abstract semantics `Opt.run rawOps`. This mirrors
        `emit_bA_bytes_sound` but for the raw program instead of `emit b`.
    (c) `rawA_bytes_sound` / `emit_bA_encFull_bytes_sound` — the arith class specialised, ORIGINAL and
        OPTIMIZED, both through `encFull` and both landed on `denote (bA k)`.
    (d) `push_button_arith_bytes_symmetric` — THE SYMMETRIC HEADLINE. For every arith kind `k`: the
        ORIGINAL bytecode `encFull (rawA k)` and the OPTIMIZED bytecode `encFull (emit (bA k))`, BOTH
        serialised, PARSED and run on the real `run`/`stepInstr` VM (each accepting), compute the SAME
        result — the shared `denote (bA k) M A` (both main stacks equal, both alt stacks equal). The
        `List Instr` intermediary is gone on BOTH sides: original-bytes-on-the-real-VM ≡
        optimized-bytes-on-the-real-VM, for the whole arithmetic class incl. the partial div/mod.

  Lean 4 core only; NO mathlib. Additive: a new file, no edit to any keystone.
-/
import LeanBCH.Opt.EmitConcreteExt
import LeanBCH.Opt.PushButtonBytes
import LeanBCH.Opt.AcceptBridge
import LeanBCH.Opt.Decompile

namespace LeanBCH.Opt.OriginalBytes
open LeanBCH LeanBCH.VM LeanBCH.Opt LeanBCH.Opt.Op LeanBCH.Opt.OpFaithful LeanBCH.Opt.Adapter
  LeanBCH.Opt.EmitConcrete LeanBCH.Opt.Codec LeanBCH.Opt.PushButton LeanBCH.Opt.PushButtonBytes
  LeanBCH.Opt.EmitConcreteExt

/-! ## (a) The reusable byte-lift over a known `foldStraight`.

    Both the optimized and the original sides need the same last step: a straight-line, well-formed
    instruction list whose `foldStraight` is known lifts to "serialise, parse, run on the real VM".
    `emit_bA_bytes_sound` inlined this for `enc (emit (bA k))`; factoring it out lets BOTH sides reuse
    it verbatim (the original side via `run_via_encode_accept`, the optimized side via
    `emit_bA_full_sound`). -/

/-- ★ For a straight-line (`hstr`), round-trippable (`hwf`) instruction list `is` whose `foldStraight`
    from `(st, al)` is `some (r1, r2)`: its serialised bytes `is.flatMap encodeInstr` parse back to
    `is.toArray` (`parse_encode`), and running that array on the real fuel-driven `run`/`stepInstr` VM
    (enough fuel) yields main stack `r1`, alt stack `r2`, and no error (`run_bytes_eq_fold`). -/
theorem bytes_run_of_fold (is : List Instr)
    (hwf : ∀ i ∈ is, WFInstr i)
    (hstr : ∀ i ∈ is, straightOp i.opcode = true)
    (st al r1 r2 : Stack) (fuel : Nat) (hf : is.length + 1 ≤ fuel)
    (hfold : foldStraight is st al = some (r1, r2)) :
    parse (is.flatMap encodeInstr) = .ok is.toArray
    ∧ (VM.run fuel { instrs := is.toArray, stack := st, alt := al }).stack = r1
    ∧ (VM.run fuel { instrs := is.toArray, stack := st, alt := al }).alt = r2
    ∧ (VM.run fuel { instrs := is.toArray, stack := st, alt := al }).error = none :=
  ⟨ parse_encode is hwf,
    run_bytes_eq_fold is hstr st al r1 r2 fuel hf hfold ⟩

/-! ## (b) ★★ THE ORIGINAL-SIDE BYTE LEMMA (fully general over `rawOps`).

    The mirror of the optimized-side `emit_bA_bytes_sound`, but applied to the RAW program instead of
    the scheduler output. The precondition threading is by ACCEPTANCE (`run_via_encode_accept`): no
    forward invariant, no DAG typing — "the encoded bytes did not error" already forces every compute
    op's precondition when it fired, so `foldStraight (rawOps.flatMap encFull) = Opt.run rawOps`. -/

/-- ★★ For an abstract op program `rawOps` whose every op is faithfully encodable under `encFull`
    (`hsim` = `SimOpOn (P op)`; `hconv` = that precondition recoverable from the op's chunk not
    erroring) and whose byte encodings are all well-formed (`hwf`) and straight-line (`hstr`): the
    ORIGINAL bytecode `(rawOps.flatMap encFull).flatMap encodeInstr` PARSES back to the emitted
    instruction array, and — run on LeanBCH's real fuel-driven `run`/`stepInstr` VM WITHOUT error
    (enough fuel, the run accepting) — reproduces EXACTLY the original program's abstract semantics
    `Opt.run rawOps (st, al)`. This gives the ORIGINAL program the SAME byte treatment the optimized
    side already enjoys. -/
theorem run_original_bytes_sound
    (P : Op Bytes → Stack → Stack → Prop) (rawOps : List (Op Bytes))
    (hsim : ∀ op ∈ rawOps, SimOpOn (P op) op (encFull op))
    (hconv : ∀ op ∈ rawOps, ∀ st al : Stack, foldStraight (encFull op) st al ≠ none → P op st al)
    (hwf : ∀ i ∈ rawOps.flatMap encFull, WFInstr i)
    (hstr : ∀ i ∈ rawOps.flatMap encFull, straightOp i.opcode = true)
    (st al : Stack) (fuel : Nat)
    (hf : (rawOps.flatMap encFull).length + 1 ≤ fuel)
    (hacc : foldStraight (rawOps.flatMap encFull) st al ≠ none) :
    parse ((rawOps.flatMap encFull).flatMap encodeInstr) = .ok (rawOps.flatMap encFull).toArray
    ∧ ∃ r1 r2, LeanBCH.Opt.run rawOps (st, al) = some (r1, r2)
      ∧ (VM.run fuel { instrs := (rawOps.flatMap encFull).toArray, stack := st, alt := al }).stack = r1
      ∧ (VM.run fuel { instrs := (rawOps.flatMap encFull).toArray, stack := st, alt := al }).alt = r2
      ∧ (VM.run fuel { instrs := (rawOps.flatMap encFull).toArray, stack := st, alt := al }).error = none := by
  have hrun_eq := run_via_encode_accept encFull P rawOps hsim hconv st al hacc
  cases hfold : foldStraight (rawOps.flatMap encFull) st al with
  | none => exact absurd hfold hacc
  | some p =>
    obtain ⟨r1, r2⟩ := p
    have hopt : LeanBCH.Opt.run rawOps (st, al) = some (r1, r2) := by rw [← hrun_eq]; exact hfold
    obtain ⟨hpar, hst, hal, herr⟩ :=
      bytes_run_of_fold (rawOps.flatMap encFull) hwf hstr st al r1 r2 fuel hf hfold
    exact ⟨hpar, r1, r2, hopt, hst, hal, herr⟩

/-! ## (c) The arith class, ORIGINAL and OPTIMIZED, both through `encFull`, both on `denote (bA k)`.

    The original program is `rawA k = [arith CALL]`; through `encFull` it encodes to the single arith
    instruction `[arithInstr k]`. The optimized program `emit (bA k)` encodes (through `encFull`) to
    `[OP_SWAP, OP_SWAP, arithInstr k]`. Both are straight-line and round-trippable, and both compute
    `denote (bA k)` — the original via the decompile bridge, the optimized via `emit_bA_full_sound`. -/

/-- The ORIGINAL program's `encFull` bytecode is exactly the single arith instruction. -/
theorem encFull_rawA (k : ArithKind) : (rawA k).flatMap encFull = [arithInstr k] := by
  unfold rawA
  rw [List.flatMap_cons, List.flatMap_nil, List.append_nil]
  exact encFull_arith k

/-- The OPTIMIZED program's `encFull` bytecode: two operand `OP_SWAP`s then the arith opcode
    (identical instruction list to the `enc` version `enc_emit_bA`, now under the unified `encFull`). -/
theorem encFull_emit_bA (k : ArithKind) :
    (emit (bA k)).flatMap encFull
      = [{ opcode := Opcode.OP_SWAP, data := [] }, { opcode := Opcode.OP_SWAP, data := [] },
         arithInstr k] := by
  rw [emit_bA, List.flatMap_cons, List.flatMap_cons, List.flatMap_cons, List.flatMap_nil,
      List.append_nil, encFull_arith]
  rfl

/-! ### Well-formedness + straight-line for the two `encFull` byte strings. -/

theorem rawA_bytes_WFInstr (k : ArithKind) : ∀ i ∈ (rawA k).flatMap encFull, WFInstr i := by
  rw [encFull_rawA]
  intro i hi
  simp only [List.mem_singleton] at hi
  subst hi
  exact arithInstr_WFInstr k

theorem rawA_bytes_straight (k : ArithKind) :
    ∀ i ∈ (rawA k).flatMap encFull, straightOp i.opcode = true := by
  rw [encFull_rawA]
  intro i hi
  simp only [List.mem_singleton] at hi
  subst hi
  cases k <;> decide

theorem emit_bA_encFull_WFInstr (k : ArithKind) :
    ∀ i ∈ (emit (bA k)).flatMap encFull, WFInstr i := by
  rw [encFull_emit_bA]
  intro i hi
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hi
  rcases hi with rfl | rfl | rfl
  · exact WFInstr_plain _ (by decide)
  · exact WFInstr_plain _ (by decide)
  · exact arithInstr_WFInstr k

theorem emit_bA_encFull_straight (k : ArithKind) :
    ∀ i ∈ (emit (bA k)).flatMap encFull, straightOp i.opcode = true := by
  rw [encFull_emit_bA]
  intro i hi
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hi
  rcases hi with rfl | rfl | rfl
  · decide
  · decide
  · cases k <;> decide

/-! ### Faithfulness of the single arith op in `rawA k` under `encFull` (the `hsim`/`hconv` the
    original-side lemma consumes — the SAME witnesses the optimized side uses in `hsim_bA_full`). -/

theorem hsim_rawA (k : ArithKind) : ∀ op ∈ rawA k, SimOpOn (Parith k op) op (encFull op) := by
  intro op hop
  unfold rawA at hop
  simp only [List.mem_singleton] at hop
  subst hop
  rw [encFull_arith, Parith_call]
  exact simOpOn_arith k

theorem hconv_rawA (k : ArithKind) : ∀ op ∈ rawA k, ∀ st al : Stack,
    foldStraight (encFull op) st al ≠ none → Parith k op st al := by
  intro op hop st al hne
  unfold rawA at hop
  simp only [List.mem_singleton] at hop
  subst hop
  rw [encFull_arith] at hne
  rw [Parith_call]
  exact arith_accept_pre k st al hne

/-- ★★★ THE ORIGINAL-SIDE BYTE HEADLINE (arithmetic class). The ORIGINAL program's bytecode
    `encFull (rawA k)` — serialised, PARSED, and run on the real `run`/`stepInstr` VM without error —
    computes EXACTLY `denote (bA k) M A`. The abstract original semantics `Opt.run (rawA k)` is
    supplied premise-free by the decompile bridge (`bridge_block`); the acceptance bridge lands it on
    the real VM. Covers the partial div/mod (precondition discharged by the run's own acceptance). -/
theorem rawA_bytes_sound (k : ArithKind) (M A : List Bytes)
    (hM : M.length = 2) (hA : A.length = 0)
    (fuel : Nat) (hf : ((rawA k).flatMap encFull).length + 1 ≤ fuel)
    (hacc : foldStraight ((rawA k).flatMap encFull) (entryState M A).1 (entryState M A).2 ≠ none) :
    parse (((rawA k).flatMap encFull).flatMap encodeInstr) = .ok ((rawA k).flatMap encFull).toArray
    ∧ (VM.run fuel { instrs := ((rawA k).flatMap encFull).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).stack = (denote (bA k) M A).1
    ∧ (VM.run fuel { instrs := ((rawA k).flatMap encFull).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).alt = (denote (bA k) M A).2
    ∧ (VM.run fuel { instrs := ((rawA k).flatMap encFull).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).error = none := by
  -- ORIGINAL abstract run = denote (bA k), premise-free (decompile bridge)
  have hopt : LeanBCH.Opt.run (rawA k) (entryState M A) = some (denote (bA k) M A) :=
    bridge_block (rawA k) 2 0 M A hM hA (bA k) (rawA_decompiles k)
      (decompileBlock_WellFormed (rawA k) 2 0 (bA k) (rawA_uniform k) (rawA_decompiles k))
  -- the encFull bytes' foldStraight = the abstract run (acceptance bridge)
  have hrun_eq := run_via_encode_accept encFull (Parith k) (rawA k)
    (hsim_rawA k) (hconv_rawA k) (entryState M A).1 (entryState M A).2 hacc
  have hfold : foldStraight ((rawA k).flatMap encFull) (entryState M A).1 (entryState M A).2
      = some (denote (bA k) M A) := by rw [hrun_eq]; exact hopt
  exact bytes_run_of_fold ((rawA k).flatMap encFull) (rawA_bytes_WFInstr k) (rawA_bytes_straight k)
    (entryState M A).1 (entryState M A).2 (denote (bA k) M A).1 (denote (bA k) M A).2 fuel hf hfold

/-- ★★★ The OPTIMIZED-side byte headline through `encFull` (the ONE encoder). The scheduler's bytecode
    `encFull (emit (bA k))` — serialised, PARSED, and run on the real VM without error — computes
    EXACTLY `denote (bA k) M A`. (The `enc`-flavoured version is `PushButtonBytes.emit_bA_bytes_sound`;
    this is its `encFull` twin, so the ORIGINAL and OPTIMIZED sides are lifted by the ONE `encFull`.) -/
theorem emit_bA_encFull_bytes_sound (k : ArithKind) (M A : List Bytes)
    (hM : M.length = 2) (hA : A.length = 0)
    (fuel : Nat) (hf : ((emit (bA k)).flatMap encFull).length + 1 ≤ fuel)
    (hacc : foldStraight ((emit (bA k)).flatMap encFull) (entryState M A).1 (entryState M A).2 ≠ none) :
    parse (((emit (bA k)).flatMap encFull).flatMap encodeInstr) = .ok ((emit (bA k)).flatMap encFull).toArray
    ∧ (VM.run fuel { instrs := ((emit (bA k)).flatMap encFull).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).stack = (denote (bA k) M A).1
    ∧ (VM.run fuel { instrs := ((emit (bA k)).flatMap encFull).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).alt = (denote (bA k) M A).2
    ∧ (VM.run fuel { instrs := ((emit (bA k)).flatMap encFull).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).error = none := by
  have hfold := emit_bA_full_sound k M A hM hA hacc
  exact bytes_run_of_fold ((emit (bA k)).flatMap encFull)
    (emit_bA_encFull_WFInstr k) (emit_bA_encFull_straight k)
    (entryState M A).1 (entryState M A).2 (denote (bA k) M A).1 (denote (bA k) M A).2 fuel hf hfold

/-! ## (d) ★★★★ THE SYMMETRIC BYTE-LEVEL PUSH-BUTTON (arithmetic class). -/

/-- ★★★★ ORIGINAL ≡ OPTIMIZED, BOTH ON RAW BYTECODE ON THE REAL VM. For every arith kind `k` on a
    2-input entry, given enough fuel and each run accepting:
      • the ORIGINAL bytecode `encFull (rawA k)`, serialised → parsed → run on the real
        `run`/`stepInstr` VM, computes `denote (bA k) M A`; and
      • the OPTIMIZED bytecode `encFull (emit (bA k))`, serialised → parsed → run on the same real VM,
        computes `denote (bA k) M A`;
    hence the two agree — SAME main stack AND same alt stack — for the whole arithmetic class,
    including the partial div/mod. The `List Instr` intermediary is gone on BOTH sides: this is the
    fully symmetric "original bytes = optimized bytes, both on the real VM" for arith. -/
theorem push_button_arith_bytes_symmetric (k : ArithKind) (M A : List Bytes)
    (hM : M.length = 2) (hA : A.length = 0)
    (fuelO fuelP : Nat)
    (hfO : ((rawA k).flatMap encFull).length + 1 ≤ fuelO)
    (hfP : ((emit (bA k)).flatMap encFull).length + 1 ≤ fuelP)
    (haccO : foldStraight ((rawA k).flatMap encFull) (entryState M A).1 (entryState M A).2 ≠ none)
    (haccP : foldStraight ((emit (bA k)).flatMap encFull) (entryState M A).1 (entryState M A).2 ≠ none) :
    -- ORIGINAL bytecode: parses back and runs to `denote (bA k)` on the real VM
    (parse (((rawA k).flatMap encFull).flatMap encodeInstr) = .ok ((rawA k).flatMap encFull).toArray
      ∧ (VM.run fuelO { instrs := ((rawA k).flatMap encFull).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).stack = (denote (bA k) M A).1
      ∧ (VM.run fuelO { instrs := ((rawA k).flatMap encFull).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).alt = (denote (bA k) M A).2
      ∧ (VM.run fuelO { instrs := ((rawA k).flatMap encFull).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).error = none)
    -- OPTIMIZED bytecode: parses back and runs to `denote (bA k)` on the real VM
    ∧ (parse (((emit (bA k)).flatMap encFull).flatMap encodeInstr) = .ok ((emit (bA k)).flatMap encFull).toArray
      ∧ (VM.run fuelP { instrs := ((emit (bA k)).flatMap encFull).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).stack = (denote (bA k) M A).1
      ∧ (VM.run fuelP { instrs := ((emit (bA k)).flatMap encFull).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).alt = (denote (bA k) M A).2
      ∧ (VM.run fuelP { instrs := ((emit (bA k)).flatMap encFull).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).error = none)
    -- SAME RESULT: the two real-VM runs agree on both stacks
    ∧ ((VM.run fuelO { instrs := ((rawA k).flatMap encFull).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).stack
        = (VM.run fuelP { instrs := ((emit (bA k)).flatMap encFull).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).stack
      ∧ (VM.run fuelO { instrs := ((rawA k).flatMap encFull).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).alt
        = (VM.run fuelP { instrs := ((emit (bA k)).flatMap encFull).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).alt) := by
  have hO := rawA_bytes_sound k M A hM hA fuelO hfO haccO
  have hP := emit_bA_encFull_bytes_sound k M A hM hA fuelP hfP haccP
  exact ⟨hO, hP, by rw [hO.2.1, hP.2.1], by rw [hO.2.2.1, hP.2.2.1]⟩

end LeanBCH.Opt.OriginalBytes
