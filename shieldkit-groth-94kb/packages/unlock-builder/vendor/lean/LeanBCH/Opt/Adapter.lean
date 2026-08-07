/-
  LeanBCH.Opt.Adapter — grounding the α-generic optimizer in LeanBCH's REAL VM.

  The optimizer (`LeanBCH.Opt.Basic`) proves `Correct src dst := ∀ st, LeanBCH.Opt.run src st = LeanBCH.Opt.run dst st`
  over its OWN abstract stack machine (`LeanBCH.Opt.step`, `State α = List α × List α`, head = top). This
  module provides the machinery to transfer that guarantee to LeanBCH's frozen `stepInstr`, so a
  proven rewrite is equivalent under the ACTUAL Bitcoin Cash VM — not a look-alike.

  ★ STATUS — the SEMANTIC bridge is CLOSED (see the sibling modules; this file holds the UNCONDITIONAL
  fragment). Direct stack ops (15 shuffles + PUSH/PICK/ROLL) carry unconditional `SimOp` witnesses
  here. The COMPUTE seam — once only the interface `sim_CALL_of_faithful` — is now genuinely
  discharged: `LeanBCH.Opt.OpFaithful` proves per-opcode faithfulness against real `stepInstr` for the
  whole compute surface (arith/unary/comparison/hash), CONDITIONAL on the operands being canonical
  numbers (`stepInstr` is partial where the abstract `Op.CALL` is total). `LeanBCH.Opt.CondBridge`/
  `ComputeBridge` compose those conditional witnesses; `LeanBCH.Opt.AcceptBridge` discharges the
  precondition by ACCEPTANCE (`rewrite_sound_accept`: a clean run ⟹ every op's precondition held);
  and `LeanBCH.Opt.EmitBridge.emit_sound_under_VM` composes with `schedule_refines` so the scheduler's
  emitted bytes, run clean on the real VM, compute `denote b`. `AcceptExample` witnesses the whole
  chain on `[SWAP,ADD]⇒[ADD]`. All parameterized by an encoder `enc` + its per-op faithfulness.
  STILL OPEN (for a push-button end-to-end, NOT part of the semantic result): a CONCRETE `enc` for the
  scheduler's opaque `Op.CALL n.op.nin n.op.sem` output (opcode identity — the emitted CALL discards
  the opcode) and decompile faithfulness (`denote b = Opt.run originalRawOps`, the Dag.lean SPEC).

  ★ THE BRIDGE ALREADY HALF-EXISTS. `LeanBCH.VM.Straightline` defines `stepStk`/`foldStraight` — the
  (main, alt) → `Option (Stack × Stack)` interpreter read straight off `stepInstr`, explicitly "the
  `LeanBCH.Opt.run` shape at LeanBCH's concrete value type" — and the keystone `run_straightline`
  (`[propext, Quot.sound]`) already proves `foldStraight` computes exactly the real fuel-driven `run`.
  So the whole adapter reduces to ONE fact per opcode:

      SimOp op is  :=  ∀ st al, foldStraight is st al = LeanBCH.Opt.step op (st, al)          -- `is` faithfully encodes `op`

  With `α := Bytes` the two interpreters share the type `Option (List Bytes × List Bytes)`, so the
  equalities are literal. This file provides the REUSABLE COMPOSITION (`run_via_encode`,
  `Correct_to_BlockEquiv`): given ANY encoder `enc : Op Bytes → List Instr` and a per-op `SimOp`
  witness, a `LeanBCH.Opt.Correct` rewrite becomes a `BlockEquiv` on the encoded blocks — and `BlockEquiv`
  is exactly what the frozen keystone (`splice_congr_run`) consumes to rewrite the real metered run.
  The per-op `SimOp` proofs (for the concrete BCH encoder) are the discharge frontier:
    • direct single-byte shuffle ops DUP…2SWAP — 1:1 with `stepInstr` (this increment's target);
    • PICK n / ROLL n — index is a `Basic.Op` PARAMETER but LeanBCH POPS it ⇒ encode `[push n, OP_PICK]`;
    • PUSH v — minimal push opcode + the `maxItemLen` guard;
    • CALL nin sem — opaque value-DAG node; faithful iff `sem` matches the real op's stack effect
      (the total-`sem`-vs-partial-VM seam — an explicit faithfulness hypothesis, never assumed).
  No stub, no `sorry`: unproven ops simply have no `SimOp` witness yet.
-/
import LeanBCH.Opt.Basic
import LeanBCH.VM.Straightline
import LeanBCH.VM.RunStraight
import LeanBCH.Opt.Codec

namespace LeanBCH.Opt.Adapter
open LeanBCH LeanBCH.VM LeanBCH.Opt LeanBCH.Opt.Op

/-- `is` faithfully encodes `op`: running its LeanBCH instruction sequence through the straight-line
    stack interpreter (`foldStraight`, read off the frozen `stepInstr`) yields exactly `LeanBCH.Opt.step op`.
    Both sides are `Option (List Bytes × List Bytes)`, so this is a literal equality. -/
def SimOp (op : Op Bytes) (is : List Instr) : Prop :=
  ∀ st al : Stack, foldStraight is st al = LeanBCH.Opt.step op (st, al)

/-- A single straight-line instruction's `foldStraight` IS its `stepStk` (the base case for `SimOp`
    proofs of one-instruction encodings). -/
theorem foldStraight_single (i : Instr) (st al : Stack) :
    foldStraight [i] st al = stepStk i st al := by
  simp only [foldStraight]; cases stepStk i st al <;> rfl

/-- **The run-level bridge.** Under any encoder whose every op satisfies `SimOp`, running the encoded
    program (concatenated per-op encodings) through LeanBCH's `foldStraight` equals `LeanBCH.Opt.run` on the
    abstract machine. Induction on the op-list: `foldStraight` distributes over `++`
    (`foldStraight_append`), each op's chunk collapses via its `SimOp` witness, and the tail is the IH.
    So the optimizer's abstract `run` IS the concrete VM's straight-line denotation of the encoding. -/
theorem run_via_encode (enc : Op Bytes → List Instr) :
    ∀ (ops : List (Op Bytes)), (∀ op ∈ ops, SimOp op (enc op)) → ∀ (st al : Stack),
      foldStraight (ops.flatMap enc) st al = LeanBCH.Opt.run ops (st, al)
  | [],        _,    st, al => by simp [foldStraight, LeanBCH.Opt.run]
  | op :: ops, henc, st, al => by
      rw [List.flatMap_cons, foldStraight_append, henc op (List.mem_cons.mpr (Or.inl rfl)) st al]
      cases hb : LeanBCH.Opt.step op (st, al) with
      | none   => simp [LeanBCH.Opt.run, hb]
      | some p =>
          simp only [Option.bind, LeanBCH.Opt.run, hb]
          rw [run_via_encode enc ops (fun o ho => henc o (List.mem_cons.mpr (Or.inr ho))) p.1 p.2]

/-- **The optimizer's guarantee, transferred to LeanBCH.** A rewrite that is `LeanBCH.Opt.Correct` (same
    result on all inputs of the abstract machine) yields `BlockEquiv` encodings — same
    `foldStraight` denotation on every input of LeanBCH's real straight-line semantics. Only the ops
    ACTUALLY IN `src`/`dst` need a `SimOp` witness (so a rewrite over the shuffle fragment needs only
    the shuffle `SimOp`s). Composed with the frozen keystone `splice_congr_run` below. -/
theorem Correct_to_BlockEquiv (enc : Op Bytes → List Instr) {src dst : List (Op Bytes)}
    (hs : ∀ op ∈ src, SimOp op (enc op)) (hd : ∀ op ∈ dst, SimOp op (enc op))
    (h : LeanBCH.Opt.Correct src dst) :
    BlockEquiv (src.flatMap enc) (dst.flatMap enc) := by
  intro st al
  rw [run_via_encode enc src hs st al, run_via_encode enc dst hd st al]
  exact h (st, al)

/-- ★ **THE HEADLINE — the optimizer is sound under the REAL fuel-driven VM.** For a `Correct` rewrite
    whose ops all satisfy `SimOp` and whose LeanBCH encodings are straight-line (`straightOp`), the
    actual `LeanBCH.VM.run` (the ip-machine over `stepInstr`, whose equivalence to `foldStraight` is
    the frozen keystone `run_straightline`) computes the SAME clean result — stack, altstack, and
    error — on the emitted (`dst`) bytecode as on the original (`src`). This is
    `run (optimize) = run (original)` at LeanBCH's genuine VM, not a look-alike: `Correct_to_BlockEquiv`
    supplies `BlockEquiv`, and `splice_congr_run` (`pre = post = []`) discharges it against `run`. -/
theorem rewrite_sound_under_VM (enc : Op Bytes → List Instr) {src dst : List (Op Bytes)}
    (hs : ∀ op ∈ src, SimOp op (enc op)) (hd : ∀ op ∈ dst, SimOp op (enc op))
    (h : LeanBCH.Opt.Correct src dst)
    (hstr : ∀ i ∈ src.flatMap enc, straightOp i.opcode = true)
    (hstr' : ∀ i ∈ dst.flatMap enc, straightOp i.opcode = true)
    (st al : Stack) (fuel fuel' : Nat)
    (hf : (src.flatMap enc).length + 1 ≤ fuel) (hf' : (dst.flatMap enc).length + 1 ≤ fuel')
    (haccept : (LeanBCH.VM.run fuel { instrs := (src.flatMap enc).toArray, stack := st, alt := al }).error = none) :
    (LeanBCH.VM.run fuel' { instrs := (dst.flatMap enc).toArray, stack := st, alt := al }).stack
      = (LeanBCH.VM.run fuel { instrs := (src.flatMap enc).toArray, stack := st, alt := al }).stack
    ∧ (LeanBCH.VM.run fuel' { instrs := (dst.flatMap enc).toArray, stack := st, alt := al }).alt
      = (LeanBCH.VM.run fuel { instrs := (src.flatMap enc).toArray, stack := st, alt := al }).alt
    ∧ (LeanBCH.VM.run fuel' { instrs := (dst.flatMap enc).toArray, stack := st, alt := al }).error = none := by
  have key := splice_congr_run (Correct_to_BlockEquiv enc hs hd h) [] []
    (by simpa using hstr) (by simpa using hstr') st al fuel fuel' (by simpa using hf) (by simpa using hf')
  simp only [List.nil_append, List.append_nil] at key
  cases hfs : foldStraight (src.flatMap enc) st al with
  | none   => rw [hfs] at key; rw [haccept] at key; simp at key
  | some p =>
      rw [hfs] at key
      exact ⟨key.2.1.trans key.1.1.symm, key.2.2.1.trans key.1.2.1.symm, key.2.2.2⟩


/-! ### Increment 1 — `SimOp` for the direct single-byte stack-shuffle ops (DUP … 2SWAP).
    Each one-instruction encoding: `rw [foldStraight_single]` collapses `foldStraight [i]` to `stepStk i`;
    the opcode is a CONCRETE literal so the frozen `stepInstr`'s whole guard chain reduces in the kernel,
    leaving only the op's `match s.stack`; `cases` the (symbolic) stack to the op's arity and every leaf
    (underflow → `none`; success → the shuffle result) closes by `rfl`. All `[propext, Quot.sound]`. -/

theorem sim_DUP : SimOp .DUP [{ opcode := Opcode.OP_DUP, data := [] }] := by
  intro st al; rw [foldStraight_single]; cases st <;> rfl

theorem sim_DROP : SimOp .DROP [{ opcode := Opcode.OP_DROP, data := [] }] := by
  intro st al; rw [foldStraight_single]; cases st <;> rfl

theorem sim_OVER : SimOp .OVER [{ opcode := Opcode.OP_OVER, data := [] }] := by
  intro st al; rw [foldStraight_single]
  cases st with
  | nil => rfl
  | cons a st => cases st <;> rfl

theorem sim_SWAP : SimOp .SWAP [{ opcode := Opcode.OP_SWAP, data := [] }] := by
  intro st al; rw [foldStraight_single]
  cases st with
  | nil => rfl
  | cons a st => cases st <;> rfl

theorem sim_ROT : SimOp .ROT [{ opcode := Opcode.OP_ROT, data := [] }] := by
  intro st al; rw [foldStraight_single]
  cases st with
  | nil => rfl
  | cons a st => cases st with
    | nil => rfl
    | cons b st => cases st <;> rfl

theorem sim_NIP : SimOp .NIP [{ opcode := Opcode.OP_NIP, data := [] }] := by
  intro st al; rw [foldStraight_single]
  cases st with
  | nil => rfl
  | cons a st => cases st <;> rfl

theorem sim_TUCK : SimOp .TUCK [{ opcode := Opcode.OP_TUCK, data := [] }] := by
  intro st al; rw [foldStraight_single]
  cases st with
  | nil => rfl
  | cons a st => cases st <;> rfl

theorem sim_TOALT : SimOp .TOALT [{ opcode := Opcode.OP_TOALTSTACK, data := [] }] := by
  intro st al; rw [foldStraight_single]; cases st <;> rfl

theorem sim_FROMALT : SimOp .FROMALT [{ opcode := Opcode.OP_FROMALTSTACK, data := [] }] := by
  intro st al; rw [foldStraight_single]; cases al <;> rfl

theorem sim_TWODROP : SimOp .TWODROP [{ opcode := Opcode.OP_2DROP, data := [] }] := by
  intro st al; rw [foldStraight_single]
  cases st with
  | nil => rfl
  | cons a st => cases st <;> rfl

theorem sim_TWODUP : SimOp .TWODUP [{ opcode := Opcode.OP_2DUP, data := [] }] := by
  intro st al; rw [foldStraight_single]
  cases st with
  | nil => rfl
  | cons a st => cases st <;> rfl

theorem sim_THREEDUP : SimOp .THREEDUP [{ opcode := Opcode.OP_3DUP, data := [] }] := by
  intro st al; rw [foldStraight_single]
  cases st with
  | nil => rfl
  | cons a st => cases st with
    | nil => rfl
    | cons b st => cases st <;> rfl

theorem sim_TWOOVER : SimOp .TWOOVER [{ opcode := Opcode.OP_2OVER, data := [] }] := by
  intro st al; rw [foldStraight_single]
  cases st with
  | nil => rfl
  | cons a st => cases st with
    | nil => rfl
    | cons b st => cases st with
      | nil => rfl
      | cons c st => cases st <;> rfl

theorem sim_TWOROT : SimOp .TWOROT [{ opcode := Opcode.OP_2ROT, data := [] }] := by
  intro st al; rw [foldStraight_single]
  cases st with
  | nil => rfl
  | cons a st => cases st with
    | nil => rfl
    | cons b st => cases st with
      | nil => rfl
      | cons c st => cases st with
        | nil => rfl
        | cons d st => cases st with
          | nil => rfl
          | cons e st => cases st <;> rfl

theorem sim_TWOSWAP : SimOp .TWOSWAP [{ opcode := Opcode.OP_2SWAP, data := [] }] := by
  intro st al; rw [foldStraight_single]
  cases st with
  | nil => rfl
  | cons a st => cases st with
    | nil => rfl
    | cons b st => cases st with
      | nil => rfl
      | cons c st => cases st <;> rfl


/-! ### Increment 2 — `SimOp` for the value-parametric ops PUSH / PICK / ROLL.

    Unlike the direct shuffle ops, these carry a VALUE (`PUSH v`) or an INDEX (`PICK n`/`ROLL n`)
    that the real VM reads off the byte stream. PUSH needs the minimal-push ENCODER `pushOf`
    (shortest valid opcode per `isMinimalPush`); PICK/ROLL POP their index off the stack, so they
    encode as `[push n, OP_PICK/ROLL]` and the index survives a `bigIntToVmNumber`/`vmNumberToBigInt`
    round-trip. The `hv : v.length ≤ maxItemLen` / `hn : (bigIntToVmNumber n).length ≤ maxItemLen`
    premises are HONEST (every real push fits the item limit; every real index is tiny). All
    `[propext, Quot.sound]`. -/

/-- `bigIntToVmNumber` of a small positive int is its single little-endian byte. -/
theorem bigIntToVmNumber_small (n : Nat) (h1 : 1 ≤ n) (h2 : n < 128) :
    bigIntToVmNumber (Int.ofNat n) = [UInt8.ofNat n] := by
  unfold bigIntToVmNumber
  have hmag : magBytes n = [n] := by
    rw [magBytes_succ n h1, Nat.mod_eq_of_lt (by omega), Nat.div_eq_of_lt (by omega)]; rfl
  have hnat : (Int.ofNat n).natAbs = n := Int.natAbs_ofNat' n
  have hsign : (decide (Int.ofNat n < 0)) = false := rfl
  rw [hnat, hsign, hmag]
  show (encodeDigits false [n]).map (fun d => UInt8.ofNat d) = [UInt8.ofNat n]
  simp only [encodeDigits]
  rw [if_neg (by omega : ¬ (128 ≤ n))]
  simp

/-- `pushValue` returns its data payload for every opcode that is not a value push. -/
theorem pushValue_data (o : UInt8) (data : Bytes)
    (h1 : o.toNat ≠ 0x4f) (h2 : ¬(0x51 ≤ o.toNat ∧ o.toNat ≤ 0x60)) :
    pushValue o data = data := by
  simp only [pushValue]; rw [if_neg (by simp [h1]), if_neg h2]

/-- `pushValue` of a value opcode (OP_1..OP_16) is the encoded small integer. -/
theorem pushValue_value_op (o : UInt8) (data : Bytes)
    (h1 : 0x51 ≤ o.toNat) (h2 : o.toNat ≤ 0x60) :
    pushValue o data = bigIntToVmNumber (Int.ofNat (o.toNat - 0x50)) := by
  simp only [pushValue]
  rw [if_neg (by rw [beq_eq_false_iff_ne.mpr (show o.toNat ≠ 79 by omega)]; simp),
      if_pos (show 0x51 ≤ o.toNat ∧ o.toNat ≤ 0x60 from ⟨h1, h2⟩)]

/-- A ≥2-byte direct push (opcode = length) is minimally encoded. -/
theorem isMinimalPush_direct (o : UInt8) (data : Bytes)
    (h1 : 2 ≤ o.toNat) (h2 : o.toNat ≤ 0x4b) (h3 : data.length ≠ 1) :
    isMinimalPush o data = true := by
  simp only [isMinimalPush]
  have e1 : (o.toNat == 0) = false := by rw [beq_eq_false_iff_ne]; omega
  have e2 : (o.toNat == 79) = false := by rw [beq_eq_false_iff_ne]; omega
  have e3 : decide (81 ≤ o.toNat) = false := by rw [decide_eq_false_iff_not]; omega
  have e5 : (data.length == 1) = false := by rw [beq_eq_false_iff_ne]; exact h3
  simp only [e1, e2, e3, e5, Bool.false_and, Bool.or_false, Bool.false_eq_true, if_false]
  rw [if_pos (show o.toNat ≤ 75 by omega)]

/-- A value opcode (OP_1..OP_16) always denotes a minimal push. -/
theorem isMinimalPush_value (o : UInt8) (data : Bytes)
    (h1 : 0x51 ≤ o.toNat) (h2 : o.toNat ≤ 0x60) : isMinimalPush o data = true := by
  simp only [isMinimalPush]
  have h81 : decide (81 ≤ o.toNat) = true := decide_eq_true (by omega)
  have h96 : decide (o.toNat ≤ 96) = true := decide_eq_true (by omega)
  have hc : (o.toNat == 0 || o.toNat == 79 || decide (81 ≤ o.toNat) && decide (o.toNat ≤ 96))
      = true := by rw [h81, h96, Bool.and_true, Bool.or_true]
  rw [if_pos hc]

/-- Direct-push opcodes 0x01..0x4b are push opcodes. -/
theorem isPushOp_direct (o : UInt8) (h1 : 1 ≤ o.toNat) (h2 : o.toNat ≤ 0x4b) :
    Opcode.isPushOp o = true := by
  simp only [Opcode.isPushOp, Opcode.pushDataLen?]
  rw [beq_eq_false_iff_ne.mpr (show o.toNat ≠ 0 by omega)]
  rw [if_neg (by simp), if_pos (show 1 ≤ o.toNat ∧ o.toNat ≤ 0x4b from ⟨h1, h2⟩)]; rfl

/-- Value opcodes 0x51..0x60 are push opcodes. -/
theorem isPushOp_value (o : UInt8) (h1 : 0x51 ≤ o.toNat) (h2 : o.toNat ≤ 0x60) :
    Opcode.isPushOp o = true := by
  simp only [Opcode.isPushOp, Opcode.pushDataLen?]
  rw [beq_eq_false_iff_ne.mpr (show o.toNat ≠ 0 by omega),
      if_neg (show ¬(1 ≤ o.toNat ∧ o.toNat ≤ 0x4b) by omega),
      beq_eq_false_iff_ne.mpr (show o.toNat ≠ 0x4c by omega),
      beq_eq_false_iff_ne.mpr (show o.toNat ≠ 0x4d by omega),
      beq_eq_false_iff_ne.mpr (show o.toNat ≠ 0x4e by omega),
      beq_eq_false_iff_ne.mpr (show o.toNat ≠ 0x4f by omega),
      if_pos (show 0x51 ≤ o.toNat ∧ o.toNat ≤ 0x60 from ⟨h1, h2⟩)]; rfl

/-- The minimal-push ENCODER: the shortest valid push of `v` (per `isMinimalPush`) — OP_0 for [],
    a value opcode for a single 1..16 / -1 byte, else the direct push (≤75 bytes) or
    PUSHDATA1/2/4 at their length thresholds. The `data` field is the raw payload; the opcode
    selects the wire form (the parser, not the straight-line semantics, materializes any prefix). -/
def pushOf (v : Bytes) : Instr :=
  match v with
  | [] => { opcode := 0x00, data := [] }
  | [b] =>
      if 1 ≤ b.toNat ∧ b.toNat ≤ 16 then { opcode := UInt8.ofNat (0x50 + b.toNat), data := [] }
      else if b.toNat = 0x81 then { opcode := 0x4f, data := [] }
      else { opcode := 0x01, data := [b] }
  | v =>
      if v.length ≤ 0x4b then { opcode := UInt8.ofNat v.length, data := v }
      else if v.length ≤ 0xff then { opcode := 0x4c, data := v }
      else if v.length ≤ 0xffff then { opcode := 0x4d, data := v }
      else { opcode := 0x4e, data := v }

/-- The three push facts hold simultaneously for the encoder of every `v`: it decodes back to `v`,
    is minimally encoded, and is a push opcode. -/
theorem pushOf_spec (v : Bytes) :
    pushValue (pushOf v).opcode (pushOf v).data = v
    ∧ isMinimalPush (pushOf v).opcode (pushOf v).data = true
    ∧ Opcode.isPushOp (pushOf v).opcode = true := by
  rcases v with _ | ⟨b, _ | ⟨c, rest⟩⟩
  · -- v = []
    refine ⟨by decide, by decide, by decide⟩
  · -- v = [b]
    by_cases hcond : 1 ≤ b.toNat ∧ b.toNat ≤ 16
    · have hpo : pushOf [b] = { opcode := UInt8.ofNat (0x50 + b.toNat), data := [] } := by
        show (if 1 ≤ b.toNat ∧ b.toNat ≤ 16 then _ else _) = _; rw [if_pos hcond]
      have ht : (UInt8.ofNat (0x50 + b.toNat)).toNat = 0x50 + b.toNat :=
        UInt8.toNat_ofNat_of_lt' (by have : UInt8.size = 256 := rfl; omega)
      rw [hpo]
      refine ⟨?_, ?_, ?_⟩
      · rw [pushValue_value_op _ _ (by rw [ht]; omega) (by rw [ht]; omega), ht,
            show 0x50 + b.toNat - 0x50 = b.toNat from by omega,
            bigIntToVmNumber_small b.toNat (by omega) (by omega), UInt8.ofNat_toNat]
      · exact isMinimalPush_value _ _ (by rw [ht]; omega) (by rw [ht]; omega)
      · exact isPushOp_value _ (by rw [ht]; omega) (by rw [ht]; omega)
    · by_cases hng : b.toNat = 0x81
      · have hb : b = 0x81 := by
          have h : UInt8.ofNat b.toNat = b := UInt8.ofNat_toNat; rw [hng] at h; exact h.symm
        subst hb; refine ⟨by decide, by decide, by decide⟩
      · have hpo : pushOf [b] = { opcode := 0x01, data := [b] } := by
          show (if 1 ≤ b.toNat ∧ b.toNat ≤ 16 then _ else if b.toNat = 0x81 then _ else _) = _
          rw [if_neg hcond, if_neg hng]
        rw [hpo]
        refine ⟨pushValue_data 0x01 [b] (by decide) (by decide), ?_, by rfl⟩
        have key : isMinimalPush 0x01 [b]
            = (!(decide (1 ≤ b.toNat) && decide (b.toNat ≤ 16) || b.toNat == 129)) := rfl
        have hb1 : (decide (1 ≤ b.toNat) && decide (b.toNat ≤ 16)) = false := by
          by_cases hp : 1 ≤ b.toNat
          · by_cases hq : b.toNat ≤ 16
            · exact absurd ⟨hp, hq⟩ hcond
            · rw [decide_eq_false hq, Bool.and_false]
          · rw [decide_eq_false hp, Bool.false_and]
        have hb2 : (b.toNat == 129) = false := beq_eq_false_iff_ne.mpr hng
        rw [key, hb1, hb2]; rfl
  · -- v = b :: c :: rest  (length ≥ 2)
    have hlen2 : 2 ≤ (b :: c :: rest).length := by simp only [List.length_cons]; omega
    by_cases hc1 : (b :: c :: rest).length ≤ 0x4b
    · have hpo : pushOf (b :: c :: rest)
          = { opcode := UInt8.ofNat (b :: c :: rest).length, data := b :: c :: rest } := by
        show (if (b :: c :: rest).length ≤ 0x4b then _ else _) = _; rw [if_pos hc1]
      have ht : (UInt8.ofNat (b :: c :: rest).length).toNat = (b :: c :: rest).length :=
        UInt8.toNat_ofNat_of_lt' (by have : UInt8.size = 256 := rfl; omega)
      rw [hpo]
      refine ⟨pushValue_data _ _ (by rw [ht]; omega) (by rw [ht]; omega),
              isMinimalPush_direct _ _ (by rw [ht]; omega) (by rw [ht]; omega)
                (by simp only [List.length_cons]; omega),
              isPushOp_direct _ (by rw [ht]; omega) (by rw [ht]; omega)⟩
    · by_cases hc2 : (b :: c :: rest).length ≤ 0xff
      · have hpo : pushOf (b :: c :: rest) = { opcode := 0x4c, data := b :: c :: rest } := by
          show (if (b :: c :: rest).length ≤ 0x4b then _
                else if (b :: c :: rest).length ≤ 0xff then _ else _) = _
          rw [if_neg hc1, if_pos hc2]
        rw [hpo]
        refine ⟨pushValue_data 0x4c _ (by decide) (by decide), ?_, by rfl⟩
        show isMinimalPush 0x4c (b :: c :: rest) = true
        rw [show isMinimalPush 0x4c (b :: c :: rest) = decide ((b :: c :: rest).length ≥ 76) from rfl]
        simp only [decide_eq_true_eq]; omega
      · by_cases hc3 : (b :: c :: rest).length ≤ 0xffff
        · have hpo : pushOf (b :: c :: rest) = { opcode := 0x4d, data := b :: c :: rest } := by
            show (if (b :: c :: rest).length ≤ 0x4b then _
                  else if (b :: c :: rest).length ≤ 0xff then _
                  else if (b :: c :: rest).length ≤ 0xffff then _ else _) = _
            rw [if_neg hc1, if_neg hc2, if_pos hc3]
          rw [hpo]
          refine ⟨pushValue_data 0x4d _ (by decide) (by decide), ?_, by rfl⟩
          show isMinimalPush 0x4d (b :: c :: rest) = true
          rw [show isMinimalPush 0x4d (b :: c :: rest) = decide ((b :: c :: rest).length ≥ 256) from rfl]
          simp only [decide_eq_true_eq]; omega
        · have hpo : pushOf (b :: c :: rest) = { opcode := 0x4e, data := b :: c :: rest } := by
            show (if (b :: c :: rest).length ≤ 0x4b then _
                  else if (b :: c :: rest).length ≤ 0xff then _
                  else if (b :: c :: rest).length ≤ 0xffff then _ else _) = _
            rw [if_neg hc1, if_neg hc2, if_neg hc3]
          rw [hpo]
          refine ⟨pushValue_data 0x4e _ (by decide) (by decide), ?_, by rfl⟩
          show isMinimalPush 0x4e (b :: c :: rest) = true
          rw [show isMinimalPush 0x4e (b :: c :: rest) = decide ((b :: c :: rest).length ≥ 65536) from rfl]
          simp only [decide_eq_true_eq]; omega

theorem pushOf_value (v : Bytes) : pushValue (pushOf v).opcode (pushOf v).data = v :=
  (pushOf_spec v).1
theorem pushOf_minimal (v : Bytes) : isMinimalPush (pushOf v).opcode (pushOf v).data = true :=
  (pushOf_spec v).2.1
theorem pushOf_isPush (v : Bytes) : Opcode.isPushOp (pushOf v).opcode = true :=
  (pushOf_spec v).2.2

/-- `stepInstr` on a well-formed push (within `maxItemLen`) pushes the value onto the main stack. -/
theorem stepInstr_push (op : UInt8) (data : Bytes) (s : LeanBCH.VM.State)
    (hpush : Opcode.isPushOp op = true) (hmin : isMinimalPush op data = true)
    (hlen : (pushValue op data).length ≤ maxItemLen) :
    stepInstr op data s = s.advance.push (pushValue op data) := by
  unfold stepInstr
  rw [if_pos hpush]
  simp only [hmin, Bool.not_true, Bool.false_eq_true, if_false]
  rw [if_neg (show ¬ (maxItemLen < (pushValue op data).length) by omega)]

/-- **SimOp for PUSH.** The minimal encoding `[pushOf v]` reproduces `LeanBCH.Opt.step (PUSH v)`
    (push `v` onto the main stack) whenever `v` fits the item-length limit. -/
theorem sim_PUSH (v : Bytes) (hv : v.length ≤ maxItemLen) : SimOp (.PUSH v) [pushOf v] := by
  intro st al
  rw [foldStraight_single]
  unfold stepStk
  rw [stepInstr_push (pushOf v).opcode (pushOf v).data { stack := st, alt := al }
       (pushOf_isPush v) (pushOf_minimal v) (by rw [pushOf_value v]; exact hv)]
  rw [pushOf_value v]; rfl

/-- `stepStk` of a within-limit `pushOf` push (the reusable one-step form of `sim_PUSH`). -/
theorem stepStk_pushOf (w : Bytes) (hw : w.length ≤ maxItemLen) (st al : Stack) :
    stepStk (pushOf w) st al = some (w :: st, al) := by
  have h := sim_PUSH w hw st al; rw [foldStraight_single] at h; exact h

/-- `stepInstr` on OP_PICK reduces (opcode literal) to the copy-at-depth arm. -/
theorem stepInstr_pick (s : LeanBCH.VM.State) :
    stepInstr Opcode.OP_PICK [] s
      = (match s.stack with
         | nb :: rest =>
             match rest[(vmNumberToBigInt nb).toNat]? with
             | some v => { s.advance with stack := v :: rest }
             | none => s.setErr .stackUnderflow
         | [] => s.setErr .stackUnderflow) := rfl

/-- `stepStk` of an OP_PICK on a nonempty stack: copy the element at the decoded depth. -/
theorem stepStk_pick (nb : Bytes) (rest al : Stack) :
    stepStk { opcode := Opcode.OP_PICK, data := [] } (nb :: rest) al
      = (rest[(vmNumberToBigInt nb).toNat]?).map (fun v => (v :: rest, al)) := by
  simp only [stepStk, stepInstr_pick]
  cases h : rest[(vmNumberToBigInt nb).toNat]? with
  | none => rfl
  | some v => rfl

/-- **SimOp for PICK.** The index is a `Basic.Op` parameter but the real VM POPS it, so PICK
    encodes as `[push n, OP_PICK]`; the pushed `bigIntToVmNumber n` decodes back to `n`
    (`vmNumber_roundTrip`), matching `LeanBCH.Opt.step (PICK n)` on both the in-range and
    underflow leaves. -/
theorem sim_PICK (n : Nat)
    (hn : (bigIntToVmNumber (Int.ofNat n)).length ≤ maxItemLen) :
    SimOp (.PICK n)
      [pushOf (bigIntToVmNumber (Int.ofNat n)), { opcode := Opcode.OP_PICK, data := [] }] := by
  intro st al
  have e1 : foldStraight [pushOf (bigIntToVmNumber (Int.ofNat n)),
      { opcode := Opcode.OP_PICK, data := [] }] st al
      = (match stepStk (pushOf (bigIntToVmNumber (Int.ofNat n))) st al with
         | none => none
         | some (s', a') => foldStraight [{ opcode := Opcode.OP_PICK, data := [] }] s' a') := rfl
  have hidx : (vmNumberToBigInt (bigIntToVmNumber (Int.ofNat n))).toNat = n := by
    rw [vmNumber_roundTrip]; rfl
  rw [e1, stepStk_pushOf _ hn st al]
  show foldStraight [{ opcode := Opcode.OP_PICK, data := [] }]
        (bigIntToVmNumber (Int.ofNat n) :: st) al = step (PICK n) (st, al)
  rw [foldStraight_single, stepStk_pick, hidx]
  rfl

/-- `stepInstr` on OP_ROLL reduces (opcode literal) to the move-from-depth arm. -/
theorem stepInstr_roll (s : LeanBCH.VM.State) :
    stepInstr Opcode.OP_ROLL [] s
      = (match s.stack with
         | nb :: rest =>
             match rest[(vmNumberToBigInt nb).toNat]? with
             | some v => { s.advance with
                           stack := v :: LeanBCH.VM.removeNth rest (vmNumberToBigInt nb).toNat }
             | none => s.setErr .stackUnderflow
         | [] => s.setErr .stackUnderflow) := rfl

/-- `stepStk` of an OP_ROLL on a nonempty stack: move the element at the decoded depth to the top
    (`LeanBCH.VM.removeNth` here is the SAME `take ++ drop` definition as `LeanBCH.Opt.removeNth`). -/
theorem stepStk_roll (nb : Bytes) (rest al : Stack) :
    stepStk { opcode := Opcode.OP_ROLL, data := [] } (nb :: rest) al
      = (rest[(vmNumberToBigInt nb).toNat]?).map
          (fun v => (v :: LeanBCH.VM.removeNth rest (vmNumberToBigInt nb).toNat, al)) := by
  simp only [stepStk, stepInstr_roll]
  cases h : rest[(vmNumberToBigInt nb).toNat]? with
  | none => rfl
  | some v => rfl

/-- **SimOp for ROLL.** As `sim_PICK`, encoded `[push n, OP_ROLL]`; the move-from-depth result uses
    `LeanBCH.VM.removeNth`, which is definitionally the optimizer's `LeanBCH.Opt.removeNth`. -/
theorem sim_ROLL (n : Nat)
    (hn : (bigIntToVmNumber (Int.ofNat n)).length ≤ maxItemLen) :
    SimOp (.ROLL n)
      [pushOf (bigIntToVmNumber (Int.ofNat n)), { opcode := Opcode.OP_ROLL, data := [] }] := by
  intro st al
  have e1 : foldStraight [pushOf (bigIntToVmNumber (Int.ofNat n)),
      { opcode := Opcode.OP_ROLL, data := [] }] st al
      = (match stepStk (pushOf (bigIntToVmNumber (Int.ofNat n))) st al with
         | none => none
         | some (s', a') => foldStraight [{ opcode := Opcode.OP_ROLL, data := [] }] s' a') := rfl
  have hidx : (vmNumberToBigInt (bigIntToVmNumber (Int.ofNat n))).toNat = n := by
    rw [vmNumber_roundTrip]; rfl
  rw [e1, stepStk_pushOf _ hn st al]
  show foldStraight [{ opcode := Opcode.OP_ROLL, data := [] }]
        (bigIntToVmNumber (Int.ofNat n) :: st) al = step (ROLL n) (st, al)
  rw [foldStraight_single, stepStk_roll, hidx]
  -- LHS uses VM.removeNth, RHS (step ROLL) uses Opt.removeNth; defeq
  rfl


/-! ### Increment 3 — the `CALL` seam, and the FINALE: composing the byte-bridge with the run headline. -/

/-- **The `CALL` seam.** `CALL nin sem` is the opaque value-DAG node (an arithmetic/hash/sig op the
    recompiler never interprets). It has no unconditional encoding — its `SimOp` witness IS the
    statement that a concrete instruction sequence `is` faithfully realizes the node's arity+effect,
    exactly what the DECOMPILER establishes when it builds the `CALL` from `is`. So grounding a `CALL`
    is definitional (`id`): the caller supplies the faithfulness fact. Honest — never assumed, never stubbed. -/
theorem sim_CALL_of_faithful {nin : Nat} {sem : List Bytes → List Bytes} {is : List Instr}
    (hfaithful : ∀ st al : Stack, foldStraight is st al = LeanBCH.Opt.step (.CALL nin sem) (st, al)) :
    SimOp (.CALL nin sem) is := hfaithful

/-- The bytecode the optimizer EMITS for an encoded op-program parses back to EXACTLY the model
    instructions (`Codec.parse_encode`, given the encodings are well-formed) — the byte-bridge that
    closes the recompiler's old JS parse/round-trip gate with a machine-checked one. -/
theorem parse_emit (enc : Op Bytes → List Instr) (ops : List (Op Bytes))
    (hwf : ∀ i ∈ ops.flatMap enc, Codec.WFInstr i) :
    parse ((ops.flatMap enc).flatMap encodeInstr) = .ok (ops.flatMap enc).toArray :=
  Codec.parse_encode (ops.flatMap enc) hwf

/-- ★★ **THE FINALE — the optimizer is sound at the BYTE level, under LeanBCH's real VM.** For a
    `Correct` rewrite whose ops satisfy `SimOp` and whose encodings are straight-line + well-formed:
    the bytes the optimizer EMITS for `dst`, PARSED and RUN on the genuine fuel-driven `stepInstr`
    machine, compute EXACTLY what the emitted bytes for `src` do (identical stack, altstack, accept).
    This is the whole chain closed end to end — `Basic.Correct` ⟶ `SimOp`/`foldStraight` ⟶ keystone
    `splice_congr_run`/`run` (`rewrite_sound_under_VM`) ⟶ `parse ∘ encode = id` (`parse_emit`) — so
    "run the emitted bytecode" is literally "run the original," proven, not JS-differential-tested. -/
theorem rewrite_sound_bytes (enc : Op Bytes → List Instr) {src dst : List (Op Bytes)}
    (hs : ∀ op ∈ src, SimOp op (enc op)) (hd : ∀ op ∈ dst, SimOp op (enc op))
    (h : LeanBCH.Opt.Correct src dst)
    (hstr : ∀ i ∈ src.flatMap enc, straightOp i.opcode = true)
    (hstr' : ∀ i ∈ dst.flatMap enc, straightOp i.opcode = true)
    (hwfs : ∀ i ∈ src.flatMap enc, Codec.WFInstr i) (hwfd : ∀ i ∈ dst.flatMap enc, Codec.WFInstr i)
    (st al : Stack) (fuel fuel' : Nat)
    (hf : (src.flatMap enc).length + 1 ≤ fuel) (hf' : (dst.flatMap enc).length + 1 ≤ fuel')
    {arrS arrD : Array Instr}
    (hps : parse ((src.flatMap enc).flatMap encodeInstr) = .ok arrS)
    (hpd : parse ((dst.flatMap enc).flatMap encodeInstr) = .ok arrD)
    (haccept : (LeanBCH.VM.run fuel { instrs := arrS, stack := st, alt := al }).error = none) :
    (LeanBCH.VM.run fuel' { instrs := arrD, stack := st, alt := al }).stack
      = (LeanBCH.VM.run fuel { instrs := arrS, stack := st, alt := al }).stack
    ∧ (LeanBCH.VM.run fuel' { instrs := arrD, stack := st, alt := al }).alt
      = (LeanBCH.VM.run fuel { instrs := arrS, stack := st, alt := al }).alt
    ∧ (LeanBCH.VM.run fuel' { instrs := arrD, stack := st, alt := al }).error = none := by
  rw [parse_emit enc src hwfs] at hps
  rw [parse_emit enc dst hwfd] at hpd
  injection hps with hps; injection hpd with hpd
  subst hps; subst hpd
  exact rewrite_sound_under_VM enc hs hd h hstr hstr' st al fuel fuel' hf hf' haccept

end LeanBCH.Opt.Adapter
