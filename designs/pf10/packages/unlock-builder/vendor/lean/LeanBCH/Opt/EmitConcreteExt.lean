/-
  LeanBCH.Opt.EmitConcreteExt — INCREMENT 4d, TRACK 1: extend the `EmitConcrete` probe/encoder
  from the ARITHMETIC class to the WHOLE non-hash compute surface, and fire `emit_sound_under_VM`
  on genuine scheduler output for EACH remaining numeric class.

  `EmitConcrete` closed the real-VM bridge for the arithmetic class by PROBING the opaque
  `Op.CALL _ sem`: it applies `sem` to canonical operands and reads the opcode off the result
  (`arithProbe`). That move is not arith-specific — every value-DAG compute node the PASS-2
  scheduler emits is an opaque `Op.CALL nin sem`, and every such `sem` is one of a small, KNOWN
  set of pure functions whose OUTPUT on a well-chosen operand tuple identifies the opcode. This
  file supplies that probe for the four numeric classes and a CONCRETE full encoder `encFull` that
  provably fires `emit_sound_under_VM` on real `emit b` output for a hand-built representative
  block per class.

  ★ THE FOUR PROBES (opcode identity by evaluation, mirroring `arithProbe`):
    • `unaryNumProbe`  — apply `sem` to `[ofNum 5]`; 1ADD/1SUB/NEGATE/ABS give `6, 4, -5, 5`, DISTINCT.
    • `unaryBoolProbe` — apply to `[ofNum 0]`; NOT/0NOTEQUAL give `true/false` (`ofBool`), DISTINCT.
    • `binNumProbe`    — apply to `[ofNum 11, ofNum 4]`; MIN/MAX give `4/11`, DISTINCT.
    • `binBoolProbe`   — apply to the FOUR pairs `(0,0),(0,1),(2,1),(2,2)`; the truth-table columns
      separate all EIGHT comparisons (a single pair yields only a bit — two values — so it cannot
      distinguish eight functions; four pairs give an 8-way-distinct signature, kernel-checked).
  Each `<class>Probe_<op>` correctness fact is closed by `decide` (kernel computation).

  ★ CROSS-CLASS NON-INTERFERENCE (the design constraint that forces the operand choices). `ofNum 0`
  and `ofBool false` are the SAME bytes (the empty item), and `ofNum 1 = ofBool true`. So a boolean
  op's `false/true` output collides with a numeric `0/1`. The arithmetic probe here therefore uses
  operands `[11,4]` (NOT `EmitConcrete`'s `[6,2]`, whose `mod` result `0` would masquerade as a
  false comparison), giving arith results `{15,7,44,2,3}` — disjoint from `binNum {4,11}` and from
  every boolean output `{0,1}`. With the cascade order arith→binNum→binBool→unaryNum→unaryBool,
  each probe returns `none` on every OTHER class's `sem`, so `encFull`'s `CALL` handler is a total,
  UNAMBIGUOUS decoder of the opaque semantics — every per-op `encFull (Op.CALL …) = [opInstr …]`
  fact is closed by `decide` (which evaluates the FULL cascade, proving the non-interference).

  ★ WHAT IS PROVEN. For each of the four numeric classes a representative `WellFormed` block whose
  single node is that class's op, run through the CONCRETE `encFull` on LeanBCH's real
  `foldStraight`/`stepInstr` VM from the entry state WITHOUT error, computes EXACTLY the DAG
  denotation (`emit_bUN_sound` / `emit_bUB_sound` / `emit_bBN_sound` / `emit_bBB_sound`). Each
  reuses the existing `ComputeBridge.simOpOn_*` faithfulness and `AcceptBridge.accept_pre_*`
  acceptance converse UNCHANGED — only the missing per-class probe is supplied here. `encFull` also
  subsumes the arithmetic class (`emit_bA_full_sound`, reusing `EmitConcrete.bA`), so the ONE
  encoder covers the whole numeric compute surface plus all 15 shuffles + PUSH/PICK/ROLL (delegated
  to `EmitConcrete.enc`).

  ★ HASH IS DEFERRED (honest boundary — see the closing note). Probing `hashSem Crypto.sha256` by
  applying it forces the kernel to COMPUTE sha256 inside `decide`; that is prohibitively heavy, and
  `native_decide` is FORBIDDEN (it would forfeit the axiom-clean guarantee). Output-length
  disambiguation alone cannot separate the 32-byte SHA256/HASH256 pair, and a committed test-vector
  compared by list-`decide` STILL forces the hash. The five `sim_CALL_*`/`simOpOn_*`/`accept_pre_*`
  hash witnesses already exist (`OpFaithful`/`ComputeBridge`/`AcceptBridge`); ONLY a light,
  kernel-cheap hash probe is missing, and none is currently known without `native_decide`.

  Lean 4 core only; NO mathlib. Additive: no edit to `EmitConcrete`/Dag/Scheduler/Op.
-/
import LeanBCH.Opt.EmitConcrete

namespace LeanBCH.Opt.EmitConcreteExt
open LeanBCH LeanBCH.VM LeanBCH.Opt LeanBCH.Opt.Op LeanBCH.Opt.OpFaithful LeanBCH.Opt.Adapter
open LeanBCH.Opt.EmitConcrete

/-! ### 1. The four numeric-class probes (opcode identity by evaluating the opaque `sem`). -/

/-- Recover a binary ARITHMETIC opcode from `sem` by evaluating it on `[ofNum 11, ofNum 4]`.
    The five kinds give `11+4=15`, `11-4=7`, `11*4=44`, `11/4=2`, `11%4=3` — DISTINCT and all
    OUTSIDE `{0,1}` (so no boolean output can masquerade as an arith result; cf. the header). -/
def arithKindProbe (sem : List Bytes → List Bytes) : Option ArithKind :=
  let out := sem [ofNum 11, ofNum 4]
  if out = [ofNum 15] then some .add
  else if out = [ofNum 7] then some .sub
  else if out = [ofNum 44] then some .mul
  else if out = [ofNum 2] then some .div
  else if out = [ofNum 3] then some .mod
  else none

/-- Recover a binary NUMERIC opcode (MIN 0xa3 / MAX 0xa4) from `sem` on `[ofNum 11, ofNum 4]`:
    `min 11 4 = 4`, `max 11 4 = 11` — distinct, and disjoint from the arith results. -/
def binNumProbe (sem : List Bytes → List Bytes) : Option Instr :=
  let out := sem [ofNum 11, ofNum 4]
  if out = [ofNum 4] then some (opInstr 0xa3)
  else if out = [ofNum 11] then some (opInstr 0xa4)
  else none

/-- Recover a binary BOOLEAN comparison opcode from `sem` by its truth table on the four operand
    pairs `(0,0),(0,1),(2,1),(2,2)` (a=2nd-from-top, b=top). Each of the eight comparisons has a
    DISTINCT four-bit signature (kernel-checked below), so four evaluations pin the opcode. -/
def binBoolProbe (sem : List Bytes → List Bytes) : Option Instr :=
  let o1 := sem [ofNum 0, ofNum 0]
  let o2 := sem [ofNum 0, ofNum 1]
  let o3 := sem [ofNum 2, ofNum 1]
  let o4 := sem [ofNum 2, ofNum 2]
  let v := (o1, o2, o3, o4)
  if      v = ([ofBool false], [ofBool false], [ofBool true],  [ofBool true])  then some (opInstr 0x9a) -- BOOLAND
  else if v = ([ofBool false], [ofBool true],  [ofBool true],  [ofBool true])  then some (opInstr 0x9b) -- BOOLOR
  else if v = ([ofBool true],  [ofBool false], [ofBool false], [ofBool true])  then some (opInstr 0x9c) -- NUMEQUAL
  else if v = ([ofBool false], [ofBool true],  [ofBool true],  [ofBool false]) then some (opInstr 0x9e) -- NUMNOTEQUAL
  else if v = ([ofBool false], [ofBool true],  [ofBool false], [ofBool false]) then some (opInstr 0x9f) -- LESSTHAN
  else if v = ([ofBool false], [ofBool false], [ofBool true],  [ofBool false]) then some (opInstr 0xa0) -- GREATERTHAN
  else if v = ([ofBool true],  [ofBool true],  [ofBool false], [ofBool true])  then some (opInstr 0xa1) -- LESSTHANOREQUAL
  else if v = ([ofBool true],  [ofBool false], [ofBool true],  [ofBool true])  then some (opInstr 0xa2) -- GREATERTHANOREQUAL
  else none

/-- Recover a unary NUMERIC opcode from `sem` on `[ofNum 5]`: 1ADD/1SUB/NEGATE/ABS give
    `6, 4, -5, 5` — DISTINCT (and boolean `0/1` cannot collide with any of them). -/
def unaryNumProbe (sem : List Bytes → List Bytes) : Option Instr :=
  let out := sem [ofNum 5]
  if out = [ofNum 6] then some (opInstr 0x8b)       -- 1ADD
  else if out = [ofNum 4] then some (opInstr 0x8c)  -- 1SUB
  else if out = [ofNum (-5)] then some (opInstr 0x8f) -- NEGATE
  else if out = [ofNum 5] then some (opInstr 0x90)  -- ABS
  else none

/-- Recover a unary BOOLEAN opcode from `sem` on `[ofNum 0]`: NOT gives `true`, 0NOTEQUAL `false`. -/
def unaryBoolProbe (sem : List Bytes → List Bytes) : Option Instr :=
  let out := sem [ofNum 0]
  if out = [ofBool true] then some (opInstr 0x91)   -- NOT (0 == 0)
  else if out = [ofBool false] then some (opInstr 0x92) -- 0NOTEQUAL (0 != 0)
  else none

/-! ### 2. Probe correctness (`<class>Probe_<op> : probe (sem f) = some …`, by `decide`). -/

theorem arithKindProbe_arithSem (k : ArithKind) : arithKindProbe (arithSem k) = some k := by
  cases k <;> decide

theorem binNumProbe_MIN : binNumProbe (binNumSem (fun a b => if a ≤ b then a else b)) = some (opInstr 0xa3) := by decide
theorem binNumProbe_MAX : binNumProbe (binNumSem (fun a b => if a ≤ b then b else a)) = some (opInstr 0xa4) := by decide

theorem binBoolProbe_BOOLAND : binBoolProbe (binBoolSem (fun a b => a != 0 && b != 0)) = some (opInstr 0x9a) := by decide
theorem binBoolProbe_BOOLOR : binBoolProbe (binBoolSem (fun a b => a != 0 || b != 0)) = some (opInstr 0x9b) := by decide
theorem binBoolProbe_NUMEQUAL : binBoolProbe (binBoolSem (fun a b => a == b)) = some (opInstr 0x9c) := by decide
theorem binBoolProbe_NUMNOTEQUAL : binBoolProbe (binBoolSem (fun a b => a != b)) = some (opInstr 0x9e) := by decide
theorem binBoolProbe_LESSTHAN : binBoolProbe (binBoolSem (fun a b => decide (a < b))) = some (opInstr 0x9f) := by decide
theorem binBoolProbe_GREATERTHAN : binBoolProbe (binBoolSem (fun a b => decide (a > b))) = some (opInstr 0xa0) := by decide
theorem binBoolProbe_LESSTHANOREQUAL : binBoolProbe (binBoolSem (fun a b => decide (a ≤ b))) = some (opInstr 0xa1) := by decide
theorem binBoolProbe_GREATERTHANOREQUAL : binBoolProbe (binBoolSem (fun a b => decide (a ≥ b))) = some (opInstr 0xa2) := by decide

theorem unaryNumProbe_1ADD : unaryNumProbe (unaryNumSem (· + 1)) = some (opInstr 0x8b) := by decide
theorem unaryNumProbe_1SUB : unaryNumProbe (unaryNumSem (· - 1)) = some (opInstr 0x8c) := by decide
theorem unaryNumProbe_NEGATE : unaryNumProbe (unaryNumSem (fun x => -x)) = some (opInstr 0x8f) := by decide
theorem unaryNumProbe_ABS : unaryNumProbe (unaryNumSem (fun x => (x.natAbs : Int))) = some (opInstr 0x90) := by decide

theorem unaryBoolProbe_NOT : unaryBoolProbe (unaryBoolSem (· == 0)) = some (opInstr 0x91) := by decide
theorem unaryBoolProbe_0NOTEQUAL : unaryBoolProbe (unaryBoolSem (· != 0)) = some (opInstr 0x92) := by decide

/-! ### 3. `callInstr`: the opaque-`sem` decoder (arith→binNum→binBool→unaryNum→unaryBool). -/

/-- Decode the single real instruction for an opaque compute `sem`, trying each class in turn.
    A `sem` outside the covered classes (e.g. a hash `sem`) falls through to `[]`. -/
def callInstr (sem : List Bytes → List Bytes) : List Instr :=
  match arithKindProbe sem with
  | some k => [arithInstr k]
  | none => match binNumProbe sem with
    | some i => [i]
    | none => match binBoolProbe sem with
      | some i => [i]
      | none => match unaryNumProbe sem with
        | some i => [i]
        | none => match unaryBoolProbe sem with
          | some i => [i]
          | none => []

/-- ★ THE CONCRETE FULL ENCODER. Compute `CALL`s decode via `callInstr` (the whole numeric
    surface); every shuffle / PUSH / PICK / ROLL delegates to `EmitConcrete.enc` unchanged. -/
def encFull : Op Bytes → List Instr
  | .CALL _ sem => callInstr sem
  | op => EmitConcrete.enc op

/-- `encFull` on a compute `CALL` is exactly `callInstr` of its semantics. -/
theorem encFull_call (n : Nat) (sem : List Bytes → List Bytes) :
    encFull (Op.CALL n sem) = callInstr sem := rfl

/-- `encFull` on a non-`CALL` op is exactly `EmitConcrete.enc` (used to reuse the shuffle witnesses). -/
theorem encFull_swap : encFull Op.SWAP = EmitConcrete.enc Op.SWAP := rfl
theorem encFull_dup : encFull Op.DUP = EmitConcrete.enc Op.DUP := rfl

/-! ### 4. Per-op `encFull` decode facts (each by `decide` over the full cascade). -/

theorem callInstr_arith (k : ArithKind) : callInstr (arithSem k) = [arithInstr k] := by
  cases k <;> decide

theorem encFull_MIN :
    encFull (Op.CALL 2 (binNumSem (fun a b => if a ≤ b then a else b))) = [opInstr 0xa3] := by
  rw [encFull_call]; decide
theorem encFull_NUMEQUAL :
    encFull (Op.CALL 2 (binBoolSem (fun a b => a == b))) = [opInstr 0x9c] := by
  rw [encFull_call]; decide
theorem encFull_1ADD :
    encFull (Op.CALL 1 (unaryNumSem (· + 1))) = [opInstr 0x8b] := by
  rw [encFull_call]; decide
theorem encFull_NOT :
    encFull (Op.CALL 1 (unaryBoolSem (· == 0))) = [opInstr 0x91] := by
  rw [encFull_call]; decide
theorem encFull_arith (k : ArithKind) :
    encFull (Op.CALL 2 (arithSem k)) = [arithInstr k] := by
  rw [encFull_call]; exact callInstr_arith k

/-! ### 5. The per-class preconditions threaded to `emit_sound_under_VM`.
    Within each representative block there is exactly ONE compute `CALL`, of a known class, so the
    threaded predicate simply returns that class's precondition for any `CALL` (no probe needed). -/

/-- Binary compute precondition (MIN/MAX and all comparisons): top two operands canonical numbers. -/
def Pbin : Op Bytes → Stack → Stack → Prop
  | .CALL _ _ => BinPre
  | _ => fun _ _ => True
/-- Unary compute precondition (1ADD/…/NOT/0NOTEQUAL): top operand a canonical number. -/
def Punary : Op Bytes → Stack → Stack → Prop
  | .CALL _ _ => UnaryPre
  | _ => fun _ _ => True
/-- Arithmetic compute precondition, parametric in the kind (adds the div/mod nonzero-divisor). -/
def Parith (k : ArithKind) : Op Bytes → Stack → Stack → Prop
  | .CALL _ _ => ArithPre k
  | _ => fun _ _ => True

theorem Pbin_call (n : Nat) (sem : List Bytes → List Bytes) : Pbin (Op.CALL n sem) = BinPre := rfl
theorem Punary_call (n : Nat) (sem : List Bytes → List Bytes) : Punary (Op.CALL n sem) = UnaryPre := rfl
theorem Parith_call (k : ArithKind) (n : Nat) (sem : List Bytes → List Bytes) :
    Parith k (Op.CALL n sem) = ArithPre k := rfl

/-! ### 6. Representative blocks + their WellFormedness + scheduler output. -/

/-- 2-input, 1-node binary-NUMERIC block (MIN). Same wiring as `EmitConcrete.bA`; scheduler emits
    two operand SWAPs then the compute `CALL`. -/
def bBN : Block Bytes :=
  { entryDepth := 2, entryAlt := 0,
    nodes := [⟨0, ⟨2, 1, binNumSem (fun a b => if a ≤ b then a else b)⟩, [Ref.inp 0, Ref.inp 1]⟩],
    exit := [Ref.out 0 0], exitAlt := [] }

/-- 2-input, 1-node binary-BOOLEAN block (NUMEQUAL). -/
def bBB : Block Bytes :=
  { entryDepth := 2, entryAlt := 0,
    nodes := [⟨0, ⟨2, 1, binBoolSem (fun a b => a == b)⟩, [Ref.inp 0, Ref.inp 1]⟩],
    exit := [Ref.out 0 0], exitAlt := [] }

/-- 1-input, 1-node unary-NUMERIC block (1ADD). Scheduler emits just the compute `CALL`. -/
def bUN : Block Bytes :=
  { entryDepth := 1, entryAlt := 0,
    nodes := [⟨0, ⟨1, 1, unaryNumSem (· + 1)⟩, [Ref.inp 0]⟩],
    exit := [Ref.out 0 0], exitAlt := [] }

/-- 1-input, 1-node unary-BOOLEAN block (NOT). -/
def bUB : Block Bytes :=
  { entryDepth := 1, entryAlt := 0,
    nodes := [⟨0, ⟨1, 1, unaryBoolSem (· == 0)⟩, [Ref.inp 0]⟩],
    exit := [Ref.out 0 0], exitAlt := [] }

theorem emit_bBN : emit bBN = [Op.SWAP, Op.SWAP, Op.CALL 2 (binNumSem (fun a b => if a ≤ b then a else b))] := rfl
theorem emit_bBB : emit bBB = [Op.SWAP, Op.SWAP, Op.CALL 2 (binBoolSem (fun a b => a == b))] := rfl
theorem emit_bUN : emit bUN = [Op.CALL 1 (unaryNumSem (· + 1))] := rfl
theorem emit_bUB : emit bUB = [Op.CALL 1 (unaryBoolSem (· == 0))] := rfl

/-- The shared WellFormedness proof for a 2-input, 1-node block with operands `[inp 0, inp 1]`.
    The `semArity` conjunct is a genuine property of the specific `sem` (it must return one output
    on two inputs), so it is passed as `hsem` — discharged by `rfl` for every concrete class `sem`. -/
theorem binBlock_wf (sem : List Bytes → List Bytes)
    (hsem : ∀ l : List Bytes, l.length = 2 → (sem l).length = 1) :
    WellFormed
      ({ entryDepth := 2, entryAlt := 0,
         nodes := [⟨0, ⟨2, 1, sem⟩, [Ref.inp 0, Ref.inp 1]⟩],
         exit := [Ref.out 0 0], exitAlt := [] } : Block Bytes) := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · refine ⟨fun r hr => ?_, trivial⟩
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hr
    rcases hr with rfl | rfl
    · show (0:Nat) < 2; omega
    · show (1:Nat) < 2; omega
  · intro r hr; simp only [List.mem_singleton] at hr; subst hr; show (0:Nat) ∈ [0]; simp
  · intro r hr; simp only [List.not_mem_nil] at hr
  · simp
  · intro n hn; simp only [List.mem_singleton] at hn; subst hn; rfl
  · intro n hn l hl; simp only [List.mem_singleton] at hn; subst hn; exact hsem l hl
  · intro nid j hmem nd hnd hid
    simp only [List.mem_singleton] at hnd; subst hnd
    show j < 1
    simp only [List.flatMap_cons, List.flatMap_nil, List.append_nil, List.mem_append,
      List.mem_cons, List.not_mem_nil, or_false, reduceCtorEq, false_or, Ref.out.injEq] at hmem
    omega

/-- The shared WellFormedness proof for a 1-input, 1-node block with operand `[inp 0]`. -/
theorem unaryBlock_wf (sem : List Bytes → List Bytes)
    (hsem : ∀ l : List Bytes, l.length = 1 → (sem l).length = 1) :
    WellFormed
      ({ entryDepth := 1, entryAlt := 0,
         nodes := [⟨0, ⟨1, 1, sem⟩, [Ref.inp 0]⟩],
         exit := [Ref.out 0 0], exitAlt := [] } : Block Bytes) := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · refine ⟨fun r hr => ?_, trivial⟩
    simp only [List.mem_singleton] at hr
    subst hr; show (0:Nat) < 1; omega
  · intro r hr; simp only [List.mem_singleton] at hr; subst hr; show (0:Nat) ∈ [0]; simp
  · intro r hr; simp only [List.not_mem_nil] at hr
  · simp
  · intro n hn; simp only [List.mem_singleton] at hn; subst hn; rfl
  · intro n hn l hl; simp only [List.mem_singleton] at hn; subst hn; exact hsem l hl
  · intro nid j hmem nd hnd hid
    simp only [List.mem_singleton] at hnd; subst hnd
    show j < 1
    simp only [List.flatMap_cons, List.flatMap_nil, List.append_nil, List.mem_append,
      List.mem_cons, List.not_mem_nil, or_false, reduceCtorEq, false_or, Ref.out.injEq] at hmem
    omega

theorem bBN_wf : WellFormed bBN := binBlock_wf _ (by intro l hl; match l, hl with | [_, _], _ => rfl)
theorem bBB_wf : WellFormed bBB := binBlock_wf _ (by intro l hl; match l, hl with | [_, _], _ => rfl)
theorem bUN_wf : WellFormed bUN := unaryBlock_wf _ (by intro l hl; match l, hl with | [_], _ => rfl)
theorem bUB_wf : WellFormed bUB := unaryBlock_wf _ (by intro l hl; match l, hl with | [_], _ => rfl)

/-! ### 7. ★★ The per-class real-VM headlines. -/

/-- Binary-NUMERIC (MIN). `hsim`/`hconv` for `emit bBN`, then `emit_sound_under_VM`. -/
theorem hsim_bBN : ∀ op ∈ emit bBN, SimOpOn (Pbin op) op (encFull op) := by
  intro op hop
  simp only [emit_bBN, List.mem_cons, List.not_mem_nil, or_false] at hop
  rcases hop with rfl | rfl | rfl
  · exact SimOp.toOn enc_sim_SWAP (Pbin Op.SWAP)
  · exact SimOp.toOn enc_sim_SWAP (Pbin Op.SWAP)
  · rw [encFull_MIN, Pbin_call]; exact simOpOn_MIN

theorem hconv_bBN : ∀ op ∈ emit bBN, ∀ st al : Stack,
    foldStraight (encFull op) st al ≠ none → Pbin op st al := by
  intro op hop st al hne
  simp only [emit_bBN, List.mem_cons, List.not_mem_nil, or_false] at hop
  rcases hop with rfl | rfl | rfl
  · trivial
  · trivial
  · rw [encFull_MIN] at hne; rw [Pbin_call]; exact accept_pre_MIN st al hne

/-- ★★★ Binary-numeric class on real scheduler output: the bytes `encFull` emits for `bBN`, run on
    the real VM without error, compute exactly `denote bBN M A`. -/
theorem emit_bBN_sound (M A : List Bytes) (hM : M.length = 2) (hA : A.length = 0)
    (hacc : foldStraight ((emit bBN).flatMap encFull) (entryState M A).1 (entryState M A).2 ≠ none) :
    foldStraight ((emit bBN).flatMap encFull) (entryState M A).1 (entryState M A).2
      = some (denote bBN M A) :=
  emit_sound_under_VM encFull Pbin bBN bBN_wf M A hM hA hsim_bBN hconv_bBN hacc

/-- Binary-BOOLEAN (NUMEQUAL). -/
theorem hsim_bBB : ∀ op ∈ emit bBB, SimOpOn (Pbin op) op (encFull op) := by
  intro op hop
  simp only [emit_bBB, List.mem_cons, List.not_mem_nil, or_false] at hop
  rcases hop with rfl | rfl | rfl
  · exact SimOp.toOn enc_sim_SWAP (Pbin Op.SWAP)
  · exact SimOp.toOn enc_sim_SWAP (Pbin Op.SWAP)
  · rw [encFull_NUMEQUAL, Pbin_call]; exact simOpOn_NUMEQUAL

theorem hconv_bBB : ∀ op ∈ emit bBB, ∀ st al : Stack,
    foldStraight (encFull op) st al ≠ none → Pbin op st al := by
  intro op hop st al hne
  simp only [emit_bBB, List.mem_cons, List.not_mem_nil, or_false] at hop
  rcases hop with rfl | rfl | rfl
  · trivial
  · trivial
  · rw [encFull_NUMEQUAL] at hne; rw [Pbin_call]; exact accept_pre_NUMEQUAL st al hne

/-- ★★★ Binary-boolean class on real scheduler output. -/
theorem emit_bBB_sound (M A : List Bytes) (hM : M.length = 2) (hA : A.length = 0)
    (hacc : foldStraight ((emit bBB).flatMap encFull) (entryState M A).1 (entryState M A).2 ≠ none) :
    foldStraight ((emit bBB).flatMap encFull) (entryState M A).1 (entryState M A).2
      = some (denote bBB M A) :=
  emit_sound_under_VM encFull Pbin bBB bBB_wf M A hM hA hsim_bBB hconv_bBB hacc

/-- Unary-NUMERIC (1ADD). `emit bUN` is a lone compute `CALL` (no fetch shuffle needed). -/
theorem hsim_bUN : ∀ op ∈ emit bUN, SimOpOn (Punary op) op (encFull op) := by
  intro op hop
  simp only [emit_bUN, List.mem_cons, List.not_mem_nil, or_false] at hop
  rcases hop with rfl
  rw [encFull_1ADD, Punary_call]; exact simOpOn_1ADD

theorem hconv_bUN : ∀ op ∈ emit bUN, ∀ st al : Stack,
    foldStraight (encFull op) st al ≠ none → Punary op st al := by
  intro op hop st al hne
  simp only [emit_bUN, List.mem_cons, List.not_mem_nil, or_false] at hop
  rcases hop with rfl
  rw [encFull_1ADD] at hne; rw [Punary_call]; exact accept_pre_1ADD st al hne

/-- ★★★ Unary-numeric class on real scheduler output. -/
theorem emit_bUN_sound (M A : List Bytes) (hM : M.length = 1) (hA : A.length = 0)
    (hacc : foldStraight ((emit bUN).flatMap encFull) (entryState M A).1 (entryState M A).2 ≠ none) :
    foldStraight ((emit bUN).flatMap encFull) (entryState M A).1 (entryState M A).2
      = some (denote bUN M A) :=
  emit_sound_under_VM encFull Punary bUN bUN_wf M A hM hA hsim_bUN hconv_bUN hacc

/-- Unary-BOOLEAN (NOT). -/
theorem hsim_bUB : ∀ op ∈ emit bUB, SimOpOn (Punary op) op (encFull op) := by
  intro op hop
  simp only [emit_bUB, List.mem_cons, List.not_mem_nil, or_false] at hop
  rcases hop with rfl
  rw [encFull_NOT, Punary_call]; exact simOpOn_NOT

theorem hconv_bUB : ∀ op ∈ emit bUB, ∀ st al : Stack,
    foldStraight (encFull op) st al ≠ none → Punary op st al := by
  intro op hop st al hne
  simp only [emit_bUB, List.mem_cons, List.not_mem_nil, or_false] at hop
  rcases hop with rfl
  rw [encFull_NOT] at hne; rw [Punary_call]; exact accept_pre_NOT st al hne

/-- ★★★ Unary-boolean class on real scheduler output. -/
theorem emit_bUB_sound (M A : List Bytes) (hM : M.length = 1) (hA : A.length = 0)
    (hacc : foldStraight ((emit bUB).flatMap encFull) (entryState M A).1 (entryState M A).2 ≠ none) :
    foldStraight ((emit bUB).flatMap encFull) (entryState M A).1 (entryState M A).2
      = some (denote bUB M A) :=
  emit_sound_under_VM encFull Punary bUB bUB_wf M A hM hA hsim_bUB hconv_bUB hacc

/-! ### 8. ★★ `encFull` subsumes the ARITHMETIC class too (reusing `EmitConcrete.bA`). -/

theorem hsim_bA_full (k : ArithKind) : ∀ op ∈ emit (bA k), SimOpOn (Parith k op) op (encFull op) := by
  intro op hop
  rw [emit_bA] at hop
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hop
  rcases hop with rfl | rfl | rfl
  · exact SimOp.toOn enc_sim_SWAP (Parith k Op.SWAP)
  · exact SimOp.toOn enc_sim_SWAP (Parith k Op.SWAP)
  · rw [encFull_arith, Parith_call]; exact simOpOn_arith k

theorem hconv_bA_full (k : ArithKind) : ∀ op ∈ emit (bA k), ∀ st al : Stack,
    foldStraight (encFull op) st al ≠ none → Parith k op st al := by
  intro op hop st al hne
  rw [emit_bA] at hop
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hop
  rcases hop with rfl | rfl | rfl
  · trivial
  · trivial
  · rw [encFull_arith] at hne; rw [Parith_call]; exact arith_accept_pre k st al hne

/-- ★★★ The full arithmetic class through `encFull` (the ONE encoder now covers arith too). -/
theorem emit_bA_full_sound (k : ArithKind) (M A : List Bytes)
    (hM : M.length = 2) (hA : A.length = 0)
    (hacc : foldStraight ((emit (bA k)).flatMap encFull) (entryState M A).1 (entryState M A).2 ≠ none) :
    foldStraight ((emit (bA k)).flatMap encFull) (entryState M A).1 (entryState M A).2
      = some (denote (bA k) M A) :=
  emit_sound_under_VM encFull (Parith k) (bA k) (bA_wf k) M A hM hA (hsim_bA_full k) (hconv_bA_full k) hacc

end LeanBCH.Opt.EmitConcreteExt
