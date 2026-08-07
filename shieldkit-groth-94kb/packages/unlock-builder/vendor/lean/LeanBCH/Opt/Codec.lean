/-
  LeanBCH.Opt.Codec — the machine-checked byte-codec round-trip that closes the optimizer's
  flat↔structured bridge.

  The optimizer emits its result as a list of `LeanBCH.VM.Instr` (the flat model), then serialises
  it to raw bytes with `encodeInstr` (`LeanBCH.VM.Extended`) and re-`parse`s it (`LeanBCH.VM.Instr`)
  to feed the consensus VM. libauth's harness only ever *checked* that this serialise∘parse loop is
  the identity with a JavaScript round-trip test; here that gate becomes a THEOREM.

  `parse_encode` proves: for a list of WELL-FORMED instructions, the bytes the optimizer emits parse
  back to EXACTLY the model's instructions —
      `parse (is.flatMap encodeInstr) = .ok is.toArray`.

  `WFInstr` is the honest, minimal side condition: an instruction round-trips iff it is a direct push
  whose opcode byte equals its data length (`opcode.toNat = data.length ≤ 0x4b`), a PUSHDATA1/2/4 with
  a data length in the byte-prefix's range (`< 256` / `< 65536` / `< 2^32`), or a value/plain op
  (`pushDataLen? = .value | none`) carrying no data. This is exactly the shape of every instruction the
  optimizer emits (stack shuffles, PICK/ROLL, small pushes, value ops), read straight off the three
  functions `pushDataLen?` / `decode1` / `encodeInstr` — it does NOT assume the conclusion.

  Keystone-frozen: this module only proves theorems ABOUT `Instr`/`Extended`; it edits nothing there.
  No `native_decide`, `sorry`, `admit`, `partial` (`decide` on closed opcode literals only).
-/
import LeanBCH.VM.Instr
import LeanBCH.VM.Extended

namespace LeanBCH.Opt.Codec

open LeanBCH LeanBCH.VM

/-! ## Verbatim data / length helpers

    The bytes `encodeInstr` writes are read back UNCHANGED by `takeData` / `readLE`. -/

/-- `takeData` on the just-encoded data returns it verbatim: splitting `d.length` bytes off
    `d ++ rest` yields `(d, rest)`. -/
theorem takeData_append (d rest : Bytes) : takeData d.length (d ++ rest) = some (d, rest) := by
  induction d with
  | nil => rfl
  | cons b bs ih => simp [takeData, List.length, ih]

/-- The 1-byte little-endian length prefix reads back as the byte's `toNat`. -/
theorem readLE1 (b : UInt8) (rest : Bytes) : readLE 1 (b :: rest) = some (b.toNat, rest) := by
  simp [readLE]

/-- The 2-byte little-endian length prefix. -/
theorem readLE2 (b0 b1 : UInt8) (rest : Bytes) :
    readLE 2 (b0 :: b1 :: rest) = some (b0.toNat + 256 * b1.toNat, rest) := by simp [readLE]

/-- The 4-byte little-endian length prefix. -/
theorem readLE4 (b0 b1 b2 b3 : UInt8) (rest : Bytes) :
    readLE 4 (b0 :: b1 :: b2 :: b3 :: rest)
      = some (b0.toNat + 256 * (b1.toNat + 256 * (b2.toNat + 256 * b3.toNat)), rest) := by
  simp [readLE]

/-! ## Push-classifier facts -/

/-- A byte `≤ 0x4b` classifies as the direct push of its own value. -/
theorem pushDataLen_direct (op : UInt8) (h : op.toNat ≤ 0x4b) :
    Opcode.pushDataLen? op = some (.direct op.toNat) := by
  unfold Opcode.pushDataLen?
  by_cases h0 : op.toNat = 0
  · rw [h0]; rfl
  · have e1 : (op.toNat == 0) = false := by simp [h0]
    have e2 : (1 ≤ op.toNat ∧ op.toNat ≤ 0x4b) := by omega
    simp only [e1, Bool.false_eq_true, if_false]
    rw [if_pos e2]

/-- The PUSHDATA opcode literals classify as `readLen 1/2/4` (closed, `decide`-checked). -/
theorem pd4c : Opcode.pushDataLen? 0x4c = some (.readLen 1) := by decide
theorem pd4d : Opcode.pushDataLen? 0x4d = some (.readLen 2) := by decide
theorem pd4e : Opcode.pushDataLen? 0x4e = some (.readLen 4) := by decide

/-- A `≤ 0x4b` byte is none of the PUSHDATA opcode bytes, so its `==` tests are all `false`. -/
theorem beq_false_of_le (op : UInt8) (h : op.toNat ≤ 0x4b) :
    (op == 0x4c) = false ∧ (op == 0x4d) = false ∧ (op == 0x4e) = false := by
  refine ⟨?_, ?_, ?_⟩ <;>
  · rw [beq_eq_false_iff_ne]; intro hc; subst hc; simp at h

/-- A value/plain-op byte (`pushDataLen? = .value | none`) is none of the PUSHDATA opcode bytes. -/
theorem beq_false_of_pushval (op : UInt8)
    (h : Opcode.pushDataLen? op = some .value ∨ Opcode.pushDataLen? op = none) :
    (op == 0x4c) = false ∧ (op == 0x4d) = false ∧ (op == 0x4e) = false := by
  refine ⟨?_, ?_, ?_⟩ <;>
  · rw [beq_eq_false_iff_ne]; intro hc; subst hc
    rcases h with h | h <;> simp [Opcode.pushDataLen?] at h

/-! ## `encodeInstr` head-forms -/

/-- `encodeInstr` in the non-PUSHDATA (`else`) branch: opcode byte then the data verbatim. -/
theorem encodeInstr_else (i : Instr)
    (h4c : (i.opcode == 0x4c) = false) (h4d : (i.opcode == 0x4d) = false)
    (h4e : (i.opcode == 0x4e) = false) :
    encodeInstr i = i.opcode :: i.data := by
  unfold encodeInstr
  simp only [h4c, h4d, h4e, Bool.false_eq_true, if_false]

theorem encodeInstr_4c (i : Instr) (hop : i.opcode = 0x4c) :
    encodeInstr i = i.opcode :: (UInt8.ofNat (i.data.length % 256) :: i.data) := by
  unfold encodeInstr; rw [hop]; simp

theorem encodeInstr_4d (i : Instr) (hop : i.opcode = 0x4d) :
    encodeInstr i = i.opcode :: (UInt8.ofNat (i.data.length % 256)
        :: UInt8.ofNat (i.data.length / 256 % 256) :: i.data) := by
  unfold encodeInstr; rw [hop]; simp

theorem encodeInstr_4e (i : Instr) (hop : i.opcode = 0x4e) :
    encodeInstr i = i.opcode :: (UInt8.ofNat (i.data.length % 256)
        :: UInt8.ofNat (i.data.length / 256 % 256)
        :: UInt8.ofNat (i.data.length / 65536 % 256)
        :: UInt8.ofNat (i.data.length / 16777216 % 256) :: i.data) := by
  unfold encodeInstr; rw [hop]; simp

/-! ## Well-formed instructions

    Exactly the instructions the optimizer emits: those on which `encodeInstr` then `decode1`
    round-trips. Read directly off `pushDataLen?` / `decode1` / `encodeInstr`. -/

/-- An instruction round-trips through `encodeInstr` / `decode1` iff it is one of these shapes. -/
def WFInstr (i : Instr) : Prop :=
  (i.opcode.toNat ≤ 0x4b ∧ i.opcode.toNat = i.data.length)                    -- direct push
  ∨ (i.opcode = 0x4c ∧ i.data.length < 256)                                    -- PUSHDATA1
  ∨ (i.opcode = 0x4d ∧ i.data.length < 65536)                                  -- PUSHDATA2
  ∨ (i.opcode = 0x4e ∧ i.data.length < 4294967296)                             -- PUSHDATA4
  ∨ ((Opcode.pushDataLen? i.opcode = some .value ∨ Opcode.pushDataLen? i.opcode = none)
        ∧ i.data = [])                                                          -- value / plain op

/-! ## The core round-trip: encode then decode returns the instruction verbatim -/

/-- For a well-formed `i`, `encodeInstr i` is `i.opcode` followed by a body `t` (independent of any
    suffix), and `decode1 i.opcode (t ++ rest)` recovers exactly `(i, rest)`. This is the single fact
    the parse fold consumes, one instruction per step. -/
theorem encode_decode (i : Instr) (h : WFInstr i) :
    ∃ t : Bytes, encodeInstr i = i.opcode :: t
      ∧ ∀ rest, decode1 i.opcode (t ++ rest) = some (i, rest) := by
  rcases h with ⟨h1, h2⟩ | ⟨hop, hlen⟩ | ⟨hop, hlen⟩ | ⟨hop, hlen⟩ | ⟨hpd, hdata⟩
  -- direct push (opcode = length ≤ 0x4b)
  · obtain ⟨e4c, e4d, e4e⟩ := beq_false_of_le i.opcode h1
    refine ⟨i.data, encodeInstr_else i e4c e4d e4e, fun rest => ?_⟩
    unfold decode1
    rw [pushDataLen_direct i.opcode h1]
    simp only [Option.map]
    rw [h2, takeData_append]
  -- PUSHDATA1
  · refine ⟨UInt8.ofNat (i.data.length % 256) :: i.data, encodeInstr_4c i hop, fun rest => ?_⟩
    unfold decode1
    rw [hop]
    simp only [pd4c, List.cons_append, readLE1, Option.bind]
    have hb : (UInt8.ofNat (i.data.length % 256)).toNat = i.data.length := by simp; omega
    rw [hb, takeData_append]
    simp only [Option.map]; rw [← hop]
  -- PUSHDATA2
  · refine ⟨UInt8.ofNat (i.data.length % 256) :: UInt8.ofNat (i.data.length / 256 % 256) :: i.data,
      encodeInstr_4d i hop, fun rest => ?_⟩
    unfold decode1
    rw [hop]
    simp only [pd4d, List.cons_append, readLE2, Option.bind]
    have hb : (UInt8.ofNat (i.data.length % 256)).toNat
                + 256 * (UInt8.ofNat (i.data.length / 256 % 256)).toNat = i.data.length := by
      simp; omega
    rw [hb, takeData_append]
    simp only [Option.map]; rw [← hop]
  -- PUSHDATA4
  · refine ⟨UInt8.ofNat (i.data.length % 256) :: UInt8.ofNat (i.data.length / 256 % 256)
        :: UInt8.ofNat (i.data.length / 65536 % 256) :: UInt8.ofNat (i.data.length / 16777216 % 256) :: i.data,
      encodeInstr_4e i hop, fun rest => ?_⟩
    unfold decode1
    rw [hop]
    simp only [pd4e, List.cons_append, readLE4, Option.bind]
    have hb : (UInt8.ofNat (i.data.length % 256)).toNat
                + 256 * ((UInt8.ofNat (i.data.length / 256 % 256)).toNat
                + 256 * ((UInt8.ofNat (i.data.length / 65536 % 256)).toNat
                + 256 * (UInt8.ofNat (i.data.length / 16777216 % 256)).toNat)) = i.data.length := by
      simp; omega
    rw [hb, takeData_append]
    simp only [Option.map]; rw [← hop]
  -- value / plain op (no data)
  · obtain ⟨e4c, e4d, e4e⟩ := beq_false_of_pushval i.opcode hpd
    refine ⟨i.data, encodeInstr_else i e4c e4d e4e, fun rest => ?_⟩
    unfold decode1
    rcases hpd with hpd | hpd <;>
    · rw [hpd, hdata]
      simp only [List.nil_append]
      -- `some ({opcode := op, data := []}, rest) = some (i, rest)` since `i.data = []`
      rw [← hdata]

/-! ## The fuel-generalised parse fold

    `parseFuel` consumes ONE instruction per fuel unit; `length ≤ fuel` suffices. `parse` supplies
    `bytes.length + 1`, which dominates the instruction count (each `encodeInstr` is ≥ 1 byte). -/

/-- Empty input: the fold returns the accumulator (any fuel). -/
theorem parseFuel_nil (f : Nat) (acc : Array Instr) : parseFuel f acc [] = .ok acc := by
  cases f <;> rfl

/-- One fold step, given a successful `decode1`. -/
theorem parseFuel_step (f : Nat) (acc : Array Instr) (b : UInt8) (bs : Bytes)
    (i : Instr) (rest : Bytes) (hd : decode1 b bs = some (i, rest)) :
    parseFuel (f + 1) acc (b :: bs) = parseFuel f (acc.push i) rest := by
  rw [show parseFuel (f + 1) acc (b :: bs)
        = (match decode1 b bs with
           | some (i, rest) => parseFuel f (acc.push i) rest
           | none => Parsed.malformed (acc.push { opcode := b, data := bs })) from rfl, hd]

/-- Accumulator bookkeeping across one step. -/
theorem push_append_toArray (acc : Array Instr) (i : Instr) (is' : List Instr) :
    (acc.push i) ++ is'.toArray = acc ++ (i :: is').toArray := by
  rw [Array.push_eq_append, Array.append_assoc, ← List.toArray_cons]

/-- The fuel-generalised round-trip: parsing the concatenated encodings, starting from `acc`, with
    enough fuel and all instructions well-formed, appends exactly `is` to `acc`. -/
theorem parseFuel_flatMap :
    ∀ (is : List Instr) (f : Nat) (acc : Array Instr),
      is.length ≤ f → (∀ i ∈ is, WFInstr i) →
      parseFuel f acc (is.flatMap encodeInstr) = .ok (acc ++ is.toArray)
  | [], f, acc, _, _ => by
      rw [List.flatMap_nil]
      cases f <;> simp [parseFuel]
  | i :: is', f, acc, hfuel, hwf => by
      -- fuel is positive: peel it
      obtain ⟨f', rfl⟩ : ∃ f', f = f' + 1 := ⟨f - 1, by simp only [List.length_cons] at hfuel; omega⟩
      obtain ⟨t, henc, hdec⟩ := encode_decode i (hwf i (List.mem_cons_self ..))
      rw [List.flatMap_cons, henc, List.cons_append]
      rw [parseFuel_step f' acc i.opcode (t ++ is'.flatMap encodeInstr) i (is'.flatMap encodeInstr)
            (hdec _)]
      rw [parseFuel_flatMap is' f' (acc.push i)
            (by simp only [List.length_cons] at hfuel; omega)
            (fun j hj => hwf j (List.mem_cons_of_mem i hj))]
      rw [push_append_toArray]

/-- Each encoded instruction is at least one byte, so the total byte length dominates the
    instruction count — giving `parse`'s `bytes.length + 1` fuel plenty of headroom. -/
theorem length_le_flatMap (is : List Instr) : is.length ≤ (is.flatMap encodeInstr).length := by
  induction is with
  | nil => simp
  | cons i is' ih =>
      rw [List.flatMap_cons, List.length_cons, List.length_append]
      -- `encodeInstr i` is a cons, hence length ≥ 1
      have h1 : 1 ≤ (encodeInstr i).length := by
        unfold encodeInstr
        split
        · simp
        · split
          · simp
          · split <;> simp
      omega

/-! ## The headline theorem -/

/-- **Byte-codec round-trip.** The bytes the optimizer emits for a list of well-formed instructions
    parse back to exactly those instructions. This is the machine-checked replacement for libauth's
    JavaScript serialise∘parse round-trip gate. -/
theorem parse_encode (is : List Instr) (hwf : ∀ i ∈ is, WFInstr i) :
    parse (is.flatMap encodeInstr) = .ok is.toArray := by
  unfold parse
  rw [parseFuel_flatMap is ((is.flatMap encodeInstr).length + 1) #[]
        (by have := length_le_flatMap is; omega) hwf]
  rw [Array.empty_append]

#print axioms parse_encode

end LeanBCH.Opt.Codec
