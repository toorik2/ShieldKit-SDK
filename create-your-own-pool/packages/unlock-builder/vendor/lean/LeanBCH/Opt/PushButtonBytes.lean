/-
  LeanBCH.Opt.PushButtonBytes — TRACK 3: the BYTE-LEVEL closure of the optimizer bridge.

  `EmitConcrete`/`PushButton` land the optimizer's soundness at the `List Instr` level: the scheduler's
  emitted ops, encoded by the concrete `enc`, run on the real `foldStraight`/`stepInstr` VM and compute
  the DAG denotation (`emit_bA_sound`, `push_button_arith`). But a consensus node never sees a
  `List Instr` — it sees raw BYTECODE BYTES, which it must PARSE first. This file lifts the bridge across
  that last seam, composing three machine-checked keystones:

    • `Codec.parse_encode`  : `parse (is.flatMap encodeInstr) = .ok is.toArray` for `WFInstr` instrs —
                              the serialise∘parse round-trip is the identity.
    • `RunStraight.run_straightline` : on a straight-line program the fuel-driven ip-machine `run`
                              computes EXACTLY `foldStraight`.
    • `EmitConcrete.emit_bA_sound` : `foldStraight ((emit (bA k)).flatMap enc) = some (denote (bA k))`.

  DELIVERED:
    (a) `pushOf_WFInstr` / `arithInstr_WFInstr` / `WFInstr_plain` — every instruction SHAPE `enc` emits
        (minimal pushes, the arith opcode, the plain stack-shuffle/2-item ops) is `WFInstr`, so
        `parse_encode` applies; `emitted_bA_WFInstr` / `emitted_bDup_WFInstr` discharge it on the
        genuine scheduler output for the two exhibited blocks.
    (b) `emit_bA_bytes_sound` / `emit_bDup_bytes_sound` / `push_button_arith_bytes` — the actual emitted
        BYTECODE (`((emit b).flatMap enc).flatMap encodeInstr`), PARSED and RUN on LeanBCH's real
        `run`/`stepInstr` VM, computes exactly `denote b`. This closes the op-list→bytes seam on the
        OPTIMIZED side for the whole arithmetic class (incl. the partial div/mod) and the operand-reuse
        (real `OP_DUP`) block. `push_button_arith_bytes` additionally re-attaches the ORIGINAL-program
        run (`push_button_arith.2`), so: original program ≡ optimized BYTECODE-on-the-real-VM.

  Honest boundary (unchanged from EmitConcrete): coverage is the arith/shuffle op set on the two
  exhibited `WellFormed` blocks; the fully-general theorem still needs a scheduler-output typing lemma.
  The ORIGINAL-side byte decode (parsing the raw program's bytes) is the symmetric remaining seam.

  Lean 4 core only; NO mathlib. No `sorry`/`admit`/`native_decide`/`partial`.
-/
import LeanBCH.Opt.EmitConcrete
import LeanBCH.Opt.Codec
import LeanBCH.Opt.PushButton
import LeanBCH.VM.RunStraight

namespace LeanBCH.Opt.PushButtonBytes
open LeanBCH LeanBCH.VM LeanBCH.Opt LeanBCH.Opt.Op LeanBCH.Opt.OpFaithful LeanBCH.Opt.Adapter
  LeanBCH.Opt.EmitConcrete LeanBCH.Opt.Codec LeanBCH.Opt.PushButton

/-! ## (a) Every instruction shape `enc` emits is `WFInstr`.

    `enc` only ever produces three instruction shapes: a plain op with NO immediate data (the 15
    stack shuffles + the 2-item ops + the OP_PICK/OP_ROLL trailer + the arith opcode), and a minimal
    `pushOf` push (for `PUSH v` and the `PICK`/`ROLL` index). Each is `WFInstr`. -/

/-- A plain op with no immediate data whose byte is not a push opcode round-trips: it hits `WFInstr`'s
    value/plain-op disjunct. The 15 shuffles, the six 2-item ops, TOALT/FROMALT and the arith opcode
    (`arithInstr`) all have `pushDataLen? = none`. -/
theorem WFInstr_plain (op : UInt8) (h : Opcode.pushDataLen? op = none) :
    WFInstr { opcode := op, data := [] } := by
  unfold WFInstr
  exact Or.inr (Or.inr (Or.inr (Or.inr ⟨Or.inr h, rfl⟩)))

/-- The arith opcode instruction (`arithInstr k`, opcode `0x93..0x97`) is `WFInstr` (a plain op). -/
theorem arithInstr_WFInstr (k : ArithKind) : WFInstr (arithInstr k) := by
  have h : WFInstr { opcode := arithByte k, data := [] } :=
    WFInstr_plain (arithByte k) (by cases k <;> decide)
  exact h

/-- WFInstr's disjunct-1 shape helper: a direct push whose opcode byte equals its data length. -/
theorem WFInstr_direct (op : UInt8) (d : Bytes) (h1 : op.toNat ≤ 0x4b) (h2 : op.toNat = d.length) :
    WFInstr { opcode := op, data := d } := by unfold WFInstr; exact Or.inl ⟨h1, h2⟩

/-- WFInstr's PUSHDATA1/2/4 shape helpers. -/
theorem WFInstr_pd1 (d : Bytes) (h : d.length < 256) : WFInstr { opcode := 0x4c, data := d } := by
  unfold WFInstr; exact Or.inr (Or.inl ⟨rfl, h⟩)
theorem WFInstr_pd2 (d : Bytes) (h : d.length < 65536) : WFInstr { opcode := 0x4d, data := d } := by
  unfold WFInstr; exact Or.inr (Or.inr (Or.inl ⟨rfl, h⟩))
theorem WFInstr_pd4 (d : Bytes) (h : d.length < 4294967296) :
    WFInstr { opcode := 0x4e, data := d } := by
  unfold WFInstr; exact Or.inr (Or.inr (Or.inr (Or.inl ⟨rfl, h⟩)))

/-- WFInstr's value/plain-op shape helper (a value opcode with no data). -/
theorem WFInstr_value (op : UInt8) (h : Opcode.pushDataLen? op = some .value) :
    WFInstr { opcode := op, data := [] } := by
  unfold WFInstr; exact Or.inr (Or.inr (Or.inr (Or.inr ⟨Or.inl h, rfl⟩)))

/-- A value opcode (`OP_1..OP_16`, i.e. `0x51..0x60`) classifies as a `.value` push. (Mirrors
    `Adapter.isPushOp_value`, extracting the exact `pushDataLen?` result the value disjunct needs.) -/
theorem pushDataLen_value (o : UInt8) (h1 : 0x51 ≤ o.toNat) (h2 : o.toNat ≤ 0x60) :
    Opcode.pushDataLen? o = some .value := by
  simp only [Opcode.pushDataLen?]
  rw [beq_eq_false_iff_ne.mpr (show o.toNat ≠ 0 by omega),
      if_neg (show ¬(1 ≤ o.toNat ∧ o.toNat ≤ 0x4b) by omega),
      beq_eq_false_iff_ne.mpr (show o.toNat ≠ 0x4c by omega),
      beq_eq_false_iff_ne.mpr (show o.toNat ≠ 0x4d by omega),
      beq_eq_false_iff_ne.mpr (show o.toNat ≠ 0x4e by omega),
      beq_eq_false_iff_ne.mpr (show o.toNat ≠ 0x4f by omega),
      if_pos (show 0x51 ≤ o.toNat ∧ o.toNat ≤ 0x60 from ⟨h1, h2⟩)]
  rfl

/-- ★ THE MINIMAL PUSH IS ALWAYS WELL-FORMED. For any payload whose length fits the 4-byte PUSHDATA4
    length field (a hard wire-format bound, always met by verifier pushes), the minimal encoder
    `pushOf v` produces a `WFInstr` instruction — its opcode/length shape is exactly one of the five
    `WFInstr` disjuncts (empty/direct push, value op, or PUSHDATA1/2/4). This is the `pushOf` leg of
    "every instr `enc` emits is `WFInstr`" (feeding PUSH / PICK / ROLL through `parse_encode`). -/
theorem pushOf_WFInstr (v : Bytes) (h : v.length < 4294967296) : WFInstr (pushOf v) := by
  rcases v with _ | ⟨b, _ | ⟨c, rest⟩⟩
  · -- v = []  ⟹  { 0x00, [] } : direct push (opcode.toNat 0 = data length 0)
    exact WFInstr_direct 0x00 [] (by decide) (by decide)
  · -- v = [b]
    by_cases hcond : 1 ≤ b.toNat ∧ b.toNat ≤ 16
    · -- value op OP_1..OP_16
      have hpo : pushOf [b] = { opcode := UInt8.ofNat (0x50 + b.toNat), data := [] } := by
        show (if 1 ≤ b.toNat ∧ b.toNat ≤ 16 then _ else _) = _; rw [if_pos hcond]
      have ht : (UInt8.ofNat (0x50 + b.toNat)).toNat = 0x50 + b.toNat :=
        UInt8.toNat_ofNat_of_lt' (by have : UInt8.size = 256 := rfl; omega)
      rw [hpo]
      exact WFInstr_value _ (pushDataLen_value _ (by rw [ht]; omega) (by rw [ht]; omega))
    · by_cases hng : b.toNat = 0x81
      · -- OP_1NEGATE (0x4f) : value op
        have hb : b = 0x81 := by
          have h' : UInt8.ofNat b.toNat = b := UInt8.ofNat_toNat; rw [hng] at h'; exact h'.symm
        subst hb
        have hpo : pushOf [(0x81 : UInt8)] = { opcode := 0x4f, data := [] } := by decide
        rw [hpo]; exact WFInstr_value 0x4f (by decide)
      · -- { 0x01, [b] } : direct push (length 1)
        have hpo : pushOf [b] = { opcode := 0x01, data := [b] } := by
          show (if 1 ≤ b.toNat ∧ b.toNat ≤ 16 then _ else if b.toNat = 0x81 then _ else _) = _
          rw [if_neg hcond, if_neg hng]
        rw [hpo]; exact WFInstr_direct 0x01 [b] (by decide) rfl
  · -- v = b :: c :: rest  (length ≥ 2)
    by_cases hc1 : (b :: c :: rest).length ≤ 0x4b
    · -- direct push (opcode = length)
      have hpo : pushOf (b :: c :: rest)
          = { opcode := UInt8.ofNat (b :: c :: rest).length, data := b :: c :: rest } := by
        show (if (b :: c :: rest).length ≤ 0x4b then _ else _) = _; rw [if_pos hc1]
      have ht : (UInt8.ofNat (b :: c :: rest).length).toNat = (b :: c :: rest).length :=
        UInt8.toNat_ofNat_of_lt' (by have : UInt8.size = 256 := rfl; omega)
      rw [hpo]
      exact WFInstr_direct (UInt8.ofNat (b :: c :: rest).length) (b :: c :: rest)
        (by rw [ht]; omega) (by rw [ht])
    · by_cases hc2 : (b :: c :: rest).length ≤ 0xff
      · -- PUSHDATA1
        have hpo : pushOf (b :: c :: rest) = { opcode := 0x4c, data := b :: c :: rest } := by
          show (if (b :: c :: rest).length ≤ 0x4b then _
                else if (b :: c :: rest).length ≤ 0xff then _ else _) = _
          rw [if_neg hc1, if_pos hc2]
        rw [hpo]; exact WFInstr_pd1 (b :: c :: rest) (by omega)
      · by_cases hc3 : (b :: c :: rest).length ≤ 0xffff
        · -- PUSHDATA2
          have hpo : pushOf (b :: c :: rest) = { opcode := 0x4d, data := b :: c :: rest } := by
            show (if (b :: c :: rest).length ≤ 0x4b then _
                  else if (b :: c :: rest).length ≤ 0xff then _
                  else if (b :: c :: rest).length ≤ 0xffff then _ else _) = _
            rw [if_neg hc1, if_neg hc2, if_pos hc3]
          rw [hpo]; exact WFInstr_pd2 (b :: c :: rest) (by omega)
        · -- PUSHDATA4
          have hpo : pushOf (b :: c :: rest) = { opcode := 0x4e, data := b :: c :: rest } := by
            show (if (b :: c :: rest).length ≤ 0x4b then _
                  else if (b :: c :: rest).length ≤ 0xff then _
                  else if (b :: c :: rest).length ≤ 0xffff then _ else _) = _
            rw [if_neg hc1, if_neg hc2, if_neg hc3]
          rw [hpo]; exact WFInstr_pd4 (b :: c :: rest) h

/-! ### The instruction list `enc` emits for `bA k` / `bDup`, in explicit form. -/

/-- The concrete instruction list `enc` emits for `bA k`: two `OP_SWAP`s then the arith opcode. -/
theorem enc_emit_bA (k : ArithKind) :
    (emit (bA k)).flatMap enc
      = [{ opcode := Opcode.OP_SWAP, data := [] }, { opcode := Opcode.OP_SWAP, data := [] },
         arithInstr k] := by
  cases k <;> rfl

/-- The concrete instruction list `enc` emits for `bDup`: `OP_DUP`, `OP_SWAP`, then `OP_ADD`. -/
theorem enc_emit_bDup :
    (emit bDup).flatMap enc
      = [{ opcode := Opcode.OP_DUP, data := [] }, { opcode := Opcode.OP_SWAP, data := [] },
         arithInstr .add] := rfl

/-- ★ `emitted_instrs_WFInstr` (arith block). Every instruction the scheduler's `bA k` output encodes
    to is `WFInstr`, so `Codec.parse_encode` applies to the whole emitted byte string. -/
theorem emitted_bA_WFInstr (k : ArithKind) : ∀ i ∈ (emit (bA k)).flatMap enc, WFInstr i := by
  rw [enc_emit_bA]
  intro i hi
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hi
  rcases hi with rfl | rfl | rfl
  · exact WFInstr_plain _ (by decide)
  · exact WFInstr_plain _ (by decide)
  · exact arithInstr_WFInstr k

/-- Every instruction the scheduler's `bDup` output encodes to is `WFInstr`. -/
theorem emitted_bDup_WFInstr : ∀ i ∈ (emit bDup).flatMap enc, WFInstr i := by
  rw [enc_emit_bDup]
  intro i hi
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hi
  rcases hi with rfl | rfl | rfl
  · exact WFInstr_plain _ (by decide)
  · exact WFInstr_plain _ (by decide)
  · exact arithInstr_WFInstr .add

/-! ### The emitted instructions are all straight-line (so `run_straightline` applies). -/

theorem emitted_bA_straight (k : ArithKind) :
    ∀ i ∈ (emit (bA k)).flatMap enc, straightOp i.opcode = true := by
  rw [enc_emit_bA]
  intro i hi
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hi
  rcases hi with rfl | rfl | rfl
  · decide
  · decide
  · cases k <;> decide

theorem emitted_bDup_straight :
    ∀ i ∈ (emit bDup).flatMap enc, straightOp i.opcode = true := by
  rw [enc_emit_bDup]
  intro i hi
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hi
  rcases hi with rfl | rfl | rfl <;> decide

/-! ## (b) The BYTE-LEVEL run: parse the emitted bytes, run them on the real VM, get `denote`.

    `run_bytes_eq_fold` is the reusable adapter: for a straight-line instruction list `is`, running
    its `toArray` on the fuel-driven ip-machine `run` reproduces `foldStraight is`. Chaining
    `Codec.parse_encode` (the bytes parse back to `is.toArray`) with `run_bytes_eq_fold` and the
    op-list soundness (`emit_bA_sound`) closes the seam. -/

/-- The straight-line ip-machine `run` on `is.toArray` equals `foldStraight is`, packaged for a
    known successful fold `= some (r1, r2)`. (A thin wrapper over `RunStraight.run_straightline`.) -/
theorem run_bytes_eq_fold (is : List Instr)
    (hstr : ∀ i ∈ is, straightOp i.opcode = true)
    (st al r1 r2 : Stack) (fuel : Nat) (hf : is.length + 1 ≤ fuel)
    (hfold : foldStraight is st al = some (r1, r2)) :
    (VM.run fuel { instrs := is.toArray, stack := st, alt := al }).stack = r1 ∧
    (VM.run fuel { instrs := is.toArray, stack := st, alt := al }).alt = r2 ∧
    (VM.run fuel { instrs := is.toArray, stack := st, alt := al }).error = none := by
  have hstrA : ∀ i ∈ is.toArray.toList, straightOp i.opcode = true := by
    intro i hi; rw [List.toList_toArray] at hi; exact hstr i hi
  have hf' : is.toArray.size + 1 ≤ fuel := by rw [List.size_toArray]; exact hf
  have key := run_straightline is.toArray hstrA st al fuel hf'
  rw [List.toList_toArray, hfold] at key
  exact key

/-- ★★★ THE BYTE-LEVEL HEADLINE (arithmetic class). For every arith kind `k` and entry mains `M`
    (length 2): the ACTUAL BYTECODE the scheduler emits for `bA k` — the fully serialised bytes
    `((emit (bA k)).flatMap enc).flatMap encodeInstr` —
      • PARSES back to exactly the emitted instruction array (`Codec.parse_encode`, via
        `emitted_bA_WFInstr`), and
      • when that array is RUN from the entry state on LeanBCH's real fuel-driven `run`/`stepInstr`
        VM (enough fuel; the run accepting), computes EXACTLY the block's DAG denotation
        `denote (bA k) M A` — same main stack, same alt stack, no error.
    Covers the PARTIAL div/mod (their precondition discharged by the run's own `foldStraight`
    acceptance). This lands the optimizer's soundness on genuine consensus BYTECODE, not a
    `List Instr`. -/
theorem emit_bA_bytes_sound (k : ArithKind) (M A : List Bytes)
    (hM : M.length = 2) (hA : A.length = 0)
    (fuel : Nat) (hf : ((emit (bA k)).flatMap enc).length + 1 ≤ fuel)
    (hacc : foldStraight ((emit (bA k)).flatMap enc) (entryState M A).1 (entryState M A).2 ≠ none) :
    parse (((emit (bA k)).flatMap enc).flatMap encodeInstr) = .ok ((emit (bA k)).flatMap enc).toArray
    ∧ (VM.run fuel { instrs := ((emit (bA k)).flatMap enc).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).stack = (denote (bA k) M A).1
    ∧ (VM.run fuel { instrs := ((emit (bA k)).flatMap enc).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).alt = (denote (bA k) M A).2
    ∧ (VM.run fuel { instrs := ((emit (bA k)).flatMap enc).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).error = none := by
  refine ⟨parse_encode _ (emitted_bA_WFInstr k), ?_⟩
  exact run_bytes_eq_fold _ (emitted_bA_straight k) _ _ _ _ fuel hf
    (emit_bA_sound k M A hM hA hacc)

/-- ★★★ The byte-level headline for the operand-reuse block `bDup` (a real `OP_DUP` alongside the
    compute op): its emitted BYTECODE parses back to the emitted instructions and, run on the real
    VM, computes exactly `denote bDup M A`. -/
theorem emit_bDup_bytes_sound (M A : List Bytes)
    (hM : M.length = 1) (hA : A.length = 0)
    (fuel : Nat) (hf : ((emit bDup).flatMap enc).length + 1 ≤ fuel)
    (hacc : foldStraight ((emit bDup).flatMap enc) (entryState M A).1 (entryState M A).2 ≠ none) :
    parse (((emit bDup).flatMap enc).flatMap encodeInstr) = .ok ((emit bDup).flatMap enc).toArray
    ∧ (VM.run fuel { instrs := ((emit bDup).flatMap enc).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).stack = (denote bDup M A).1
    ∧ (VM.run fuel { instrs := ((emit bDup).flatMap enc).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).alt = (denote bDup M A).2
    ∧ (VM.run fuel { instrs := ((emit bDup).flatMap enc).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).error = none := by
  refine ⟨parse_encode _ emitted_bDup_WFInstr, ?_⟩
  exact run_bytes_eq_fold _ emitted_bDup_straight _ _ _ _ fuel hf
    (emit_bDup_sound M A hM hA hacc)

/-- ★★★★ THE BYTE-LEVEL PUSH-BUTTON (arithmetic class). Track A meets Track B ON RAW BYTECODE:
      • (optimized, on bytes) the scheduler's emitted BYTECODE for `bA k`, PARSED and RUN on the real
        `run`/`stepInstr` VM, computes `denote (bA k) M A`; and
      • (original, on the abstract machine) the ORIGINAL program `rawA k = [arith CALL]` runs to the
        SAME `denote (bA k) M A` (`push_button_arith.2`).
    Hence: the original program and the optimizer's actual output-bytes-on-the-real-VM agree, for the
    whole arithmetic class including the partial div/mod. The `List Instr` intermediary is gone. -/
theorem push_button_arith_bytes (k : ArithKind) (M A : List Bytes)
    (hM : M.length = 2) (hA : A.length = 0)
    (fuel : Nat) (hf : ((emit (bA k)).flatMap enc).length + 1 ≤ fuel)
    (hacc : foldStraight ((emit (bA k)).flatMap enc) (entryState M A).1 (entryState M A).2 ≠ none) :
    (parse (((emit (bA k)).flatMap enc).flatMap encodeInstr) = .ok ((emit (bA k)).flatMap enc).toArray
      ∧ (VM.run fuel { instrs := ((emit (bA k)).flatMap enc).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).stack = (denote (bA k) M A).1
      ∧ (VM.run fuel { instrs := ((emit (bA k)).flatMap enc).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).alt = (denote (bA k) M A).2
      ∧ (VM.run fuel { instrs := ((emit (bA k)).flatMap enc).toArray, stack := (entryState M A).1, alt := (entryState M A).2 }).error = none)
    ∧ Opt.run (rawA k) (entryState M A) = some (denote (bA k) M A) :=
  ⟨ emit_bA_bytes_sound k M A hM hA fuel hf hacc,
    (push_button_arith k M A hM hA hacc).2 ⟩

end LeanBCH.Opt.PushButtonBytes
