/-
  LeanBCH.Opt.EmitConcreteHash — TRACK 2, THE HASH GAP: make the five hash `CALL`s
  (`hashSem Crypto.{ripemd160,sha1,sha256,hash160,hash256}`) handleable by the general
  real-VM bridge (`emit_sound_under_VM`) WITHOUT `native_decide`.

  ─────────────────────────────────────────────────────────────────────────────────────
  ★ THE INVESTIGATION — why NO kernel-cheap probe can recover the hash opcode.

  Every value-DAG compute node the PASS-2 scheduler emits is an opaque `Op.CALL nin sem`
  with `sem : List Bytes → List Bytes`. `EmitConcrete`/`EmitConcreteExt` decode the NUMERIC
  classes by PROBING: apply the opaque `sem` to a fixed canonical operand tuple and read the
  opcode off the (kernel-computed) result. Every numeric probe fact is closed by `decide`,
  i.e. by KERNEL REDUCTION — which works precisely because `arithSem`/`unaryNumSem`/…/`binBoolSem`
  are built from pure `Int`/`List`/`ofNum` structural operations that the kernel reduces on the
  small chosen operands.

  The identical move is UNAVAILABLE for hash for a structural, not merely quantitative, reason:

  1. The ONLY handle on an opaque `sem : List Bytes → List Bytes` is APPLICATION. Function values
     carry no `DecidableEq` (there is no `decide`-able test `sem = hashSem Crypto.sha256`), so the
     opcode can only ever be recovered by observing `sem` on some concrete input.

  2. But APPLYING a `hashSem h` forces the kernel to compute `h` on that input, and the hash
     implementations (`Crypto.Sha256.hash`, `Ripemd160.hash`, `Sha1.hash`, and the composed
     `hash160`/`hash256`) are written as imperative `Id.run do` / `for _ in [a:b]` / `Array.getElem!`
     code over `UInt32`. That code is KERNEL-IRREDUCIBLE: the kernel's `whnf` does not unfold the
     `ForIn`/`Id.run`/`Array` machinery to a value. EMPIRICALLY (this environment, Lean core, no
     mathlib):
         example : (Crypto.sha256 []).length = 32 := by decide
     does NOT time out — it REPORTS `reduction got stuck` on `List.length (Crypto.sha256 [])`.
     So even the CHEAPEST conceivable probe — reading only the OUTPUT LENGTH via `(sem [x]).length`
     — cannot make progress in the kernel, because the length still depends on evaluating the whole
     hash. (Under `#eval`, the COMPILED path, the same expressions print `32/20/20/32/20`; the gap is
     exactly kernel-vs-native.)

  3. Even if a hash DID reduce in the kernel, output length could not separate the classes: the
     digests are `ripemd160 = sha1 = hash160 = 20` bytes and `sha256 = hash256 = 32` bytes, so length
     gives only the 3-vs-2 split `{ripemd160,sha1,hash160}` vs `{sha256,hash256}` — never a single
     opcode. Any finer split (a committed test-vector compared by list-`decide`, or byte inspection)
     would compare against `h x` and therefore STILL force the full, kernel-stuck hash computation.

  4. `native_decide` — the one tactic that WOULD force these Booleans (it evaluates by compiled
     code) — is FORBIDDEN here: it injects `Lean.ofReduceBool` into the axiom set, forfeiting the
     clean `[propext, Quot.sound]` guarantee the whole bridge is built to preserve.

  CONCLUSION: there is no kernel-cheap probe of the opaque `hashSem h`. The honest handle on the
  opcode is not the (irreducible) semantics but the ORIGINAL INSTRUCTION the decompiler read — data
  that is available at emit time and is simply not RE-derivable from the closure by any `decide`.

  ─────────────────────────────────────────────────────────────────────────────────────
  ★ THE HONEST FALLBACK — cover hash under an EXPLICIT per-node opcode hypothesis.

  Instead of a probe, a hash node carries its opcode as an explicit hypothesis `HashTag sem i`
  ("`sem` is a specific `hashSem Crypto.<h>` AND its VM instruction is the matching `opInstr 0x<..>`").
  Under that hypothesis we discharge EXACTLY the two obligations the general bridge
  (`run_via_encode_accept` / `emit_sound_under_VM`) consumes for any covered op:

    • FAITHFULNESS   `simOpOn_hashTag  : HashTag sem i → SimOpOn HashPre (Op.CALL 1 sem) [i]`
    • ACCEPTANCE CONVERSE
                     `accept_pre_hashTag : HashTag sem i → foldStraight [i] st al ≠ none → HashPre st al`

  Both simply case on the five tags and reuse the ALREADY-PROVEN, axiom-clean per-op witnesses
  `ComputeBridge.simOpOn_{RIPEMD160,SHA1,SHA256,HASH160,HASH256}` and
  `AcceptBridge.accept_pre_{…}` (themselves built on `OpFaithful.sim_CALL_{…}`). `hashTag_covered`
  bundles the pair — the "hash-under-hypothesis" coverage witness a Track-1 `CoveredClass` consumes.

  We then fire the general bridge end-to-end: for a representative `WellFormed` block whose single
  node is a hash of ANY of the five kinds, `hash_block_sound` shows the bytes the scheduler emits —
  encoded with the honest opcode `i` (`encH i`) and run on LeanBCH's real `foldStraight`/`stepInstr`
  VM WITHOUT error — compute EXACTLY the DAG denotation. Five concrete corollaries
  (`emit_b{RIPEMD160,SHA1,SHA256,HASH160,HASH256}_sound`) instantiate all kinds. The hash CALL is
  thus covered by the SAME machinery as the numeric classes, honestly, under a per-node tag rather
  than an impossible probe.

  Lean 4 core only; NO mathlib. Additive: new file, no edit to
  EmitConcrete/EmitConcreteExt/Dag/Scheduler/Op.
-/
import LeanBCH.Opt.EmitConcreteExt

namespace LeanBCH.Opt.EmitConcreteHash
open LeanBCH LeanBCH.VM LeanBCH.Opt LeanBCH.Opt.Op LeanBCH.Opt.OpFaithful LeanBCH.Opt.Adapter
open LeanBCH.Opt.EmitConcrete LeanBCH.Opt.EmitConcreteExt

/-! ### 1. The honest per-node opcode hypothesis. -/

/-- ★ THE HONEST TAG. `HashTag sem i` asserts the opaque compute semantics `sem` IS one specific hash
    and `i` is its matching VM instruction. This is the datum the decompiler ALREADY knew (which
    `opInstr` it read) but which — per the investigation above — no kernel-cheap `decide` can recover
    from the closure. It is threaded as an explicit hypothesis, never fabricated. -/
def HashTag (sem : List Bytes → List Bytes) (i : Instr) : Prop :=
  (sem = hashSem Crypto.ripemd160 ∧ i = opInstr 0xa6)
  ∨ (sem = hashSem Crypto.sha1     ∧ i = opInstr 0xa7)
  ∨ (sem = hashSem Crypto.sha256   ∧ i = opInstr 0xa8)
  ∨ (sem = hashSem Crypto.hash160  ∧ i = opInstr 0xa9)
  ∨ (sem = hashSem Crypto.hash256  ∧ i = opInstr 0xaa)

/-! ### 2. Faithfulness + acceptance converse UNDER the tag (reusing the existing witnesses). -/

/-- ★ FAITHFULNESS UNDER THE TAG. Given the honest opcode hypothesis, the single instruction `[i]`
    realizes the abstract hash node `Op.CALL 1 sem` on every state meeting `HashPre` (one operand
    present). Case on the five tags → the matching `ComputeBridge.simOpOn_<HASH>`. -/
theorem simOpOn_hashTag {sem : List Bytes → List Bytes} {i : Instr} (h : HashTag sem i) :
    SimOpOn HashPre (Op.CALL 1 sem) [i] := by
  rcases h with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩
  · exact simOpOn_RIPEMD160
  · exact simOpOn_SHA1
  · exact simOpOn_SHA256
  · exact simOpOn_HASH160
  · exact simOpOn_HASH256

/-- ★ ACCEPTANCE CONVERSE UNDER THE TAG. If the tagged instruction `[i]` runs without error, its
    (sole) precondition `HashPre` held. Case on the five tags → the matching
    `AcceptBridge.accept_pre_<HASH>`. -/
theorem accept_pre_hashTag {sem : List Bytes → List Bytes} {i : Instr} (h : HashTag sem i)
    (st al : Stack) (hne : foldStraight [i] st al ≠ none) : HashPre st al := by
  rcases h with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩
  · exact accept_pre_RIPEMD160 st al hne
  · exact accept_pre_SHA1 st al hne
  · exact accept_pre_SHA256 st al hne
  · exact accept_pre_HASH160 st al hne
  · exact accept_pre_HASH256 st al hne

/-- ★ THE HASH-UNDER-HYPOTHESIS COVERAGE WITNESS. A tagged hash `CALL` satisfies BOTH obligations
    the general bridge consumes for any covered op: faithfulness on its precondition, and that
    precondition being recoverable from acceptance. This is the pair a Track-1 `CoveredClass` needs
    in order to admit hash nodes alongside the probe-covered numeric classes. -/
theorem hashTag_covered {sem : List Bytes → List Bytes} {i : Instr} (h : HashTag sem i) :
    SimOpOn HashPre (Op.CALL 1 sem) [i]
    ∧ (∀ st al : Stack, foldStraight [i] st al ≠ none → HashPre st al) :=
  ⟨simOpOn_hashTag h, fun st al hne => accept_pre_hashTag h st al hne⟩

/-! ### 3. The tagged encoder + threaded precondition for a representative hash block. -/

/-- The hash-aware encoder for a block with a single (tagged) hash node: the opaque compute `CALL`
    is emitted as the honest instruction `i`; every other op delegates to `EmitConcrete.enc`
    unchanged. Because the tag supplies `i` explicitly, no probe of the irreducible `sem` is needed. -/
def encH (i : Instr) : Op Bytes → List Instr
  | .CALL _ _ => [i]
  | op        => EmitConcrete.enc op

theorem encH_call (i : Instr) (n : Nat) (sem : List Bytes → List Bytes) :
    encH i (Op.CALL n sem) = [i] := rfl

/-- The per-op precondition threaded to `emit_sound_under_VM`: a hash `CALL`'s `HashPre` (operand
    present), trivially true for any non-`CALL` op. -/
def Phash : Op Bytes → Stack → Stack → Prop
  | .CALL _ _ => HashPre
  | _         => fun _ _ => True

theorem Phash_call (n : Nat) (sem : List Bytes → List Bytes) :
    Phash (Op.CALL n sem) = HashPre := rfl

/-! ### 4. `hsim` / `hconv` / the general hash-block headline, THREADED via the emit-equation.

    We take the scheduler's emitted list as an explicit hypothesis `hemit : emit b = [Op.CALL 1 sem]`
    and rewrite by it, rather than forcing `emit b` to REDUCE symbolically. (Reducing `emit` with an
    ABSTRACT `sem` is possible but costs >1.5M heartbeats — the scheduler explores its movement search
    without the concrete-value shortcuts; with a concrete `sem` the SAME reduction is fast. Threading
    `hemit` lets each concrete instantiation discharge it by a fast `rfl` while the proof body below is
    paid once, abstractly and cheaply.) -/

theorem hsim_of_emit (i : Instr) (sem : List Bytes → List Bytes) (b : Block Bytes)
    (hemit : emit b = [Op.CALL 1 sem]) (htag : HashTag sem i) :
    ∀ op ∈ emit b, SimOpOn (Phash op) op (encH i op) := by
  intro op hop
  rw [hemit] at hop
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hop
  rcases hop with rfl
  rw [encH_call, Phash_call]
  exact simOpOn_hashTag htag

theorem hconv_of_emit (i : Instr) (sem : List Bytes → List Bytes) (b : Block Bytes)
    (hemit : emit b = [Op.CALL 1 sem]) (htag : HashTag sem i) :
    ∀ op ∈ emit b, ∀ st al : Stack,
      foldStraight (encH i op) st al ≠ none → Phash op st al := by
  intro op hop st al hne
  rw [hemit] at hop
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hop
  rcases hop with rfl
  rw [encH_call] at hne
  rw [Phash_call]
  exact accept_pre_hashTag htag st al hne

/-- ★★★ THE GENERAL HASH-BLOCK HEADLINE (UNDER THE HONEST OPCODE TAG). For ANY `WellFormed` block `b`
    whose scheduler output is a lone hash `CALL` (`hemit`), carrying the matching instruction `i`
    (`htag`), and entry mains `M`/`A` of the right sizes: the bytes the scheduler emits for `b`,
    encoded by `encH i` and run from the entry state on LeanBCH's real `foldStraight`/`stepInstr` VM
    WITHOUT error, compute EXACTLY the block's DAG denotation `denote b M A`. `emit_sound_under_VM`
    fires with the tagged faithfulness (`hsim_of_emit`) and acceptance converse (`hconv_of_emit`). -/
theorem hash_block_sound (b : Block Bytes) (hb : WellFormed b) (i : Instr)
    (sem : List Bytes → List Bytes) (hemit : emit b = [Op.CALL 1 sem]) (htag : HashTag sem i)
    (M A : List Bytes) (hM : M.length = b.entryDepth) (hA : A.length = b.entryAlt)
    (hacc : foldStraight ((emit b).flatMap (encH i))
              (entryState M A).1 (entryState M A).2 ≠ none) :
    foldStraight ((emit b).flatMap (encH i)) (entryState M A).1 (entryState M A).2
      = some (denote b M A) :=
  emit_sound_under_VM (encH i) Phash b hb M A hM hA
    (hsim_of_emit i sem b hemit htag) (hconv_of_emit i sem b hemit htag) hacc

/-! ### 5. The representative block + the five concrete instantiations (each `hemit` a fast `rfl`). -/

/-- 1-input, 1-node HASH block, parametric in the hash function `h`. The scheduler emits just the
    lone compute `CALL` (the input already sits at the top of the stack). -/
def bH (h : Bytes → Bytes) : Block Bytes :=
  { entryDepth := 1, entryAlt := 0,
    nodes := [⟨0, ⟨1, 1, hashSem h⟩, [Ref.inp 0]⟩],
    exit := [Ref.out 0 0], exitAlt := [] }

/-- `bH h` is genuinely `WellFormed` (the `semArity` conjunct: `hashSem h` returns one item on one).
    The WellFormedness proof concerns only the block SHAPE and never reduces `emit`, so it is cheap. -/
theorem bH_wf (h : Bytes → Bytes) : WellFormed (bH h) :=
  unaryBlock_wf (hashSem h) (by intro l hl; match l, hl with | [_], _ => rfl)

/-- OP_RIPEMD160 (0xa6) block on the real VM, under its tag. -/
theorem emit_bRIPEMD160_sound (M A : List Bytes) (hM : M.length = 1) (hA : A.length = 0)
    (hacc : foldStraight ((emit (bH Crypto.ripemd160)).flatMap (encH (opInstr 0xa6)))
              (entryState M A).1 (entryState M A).2 ≠ none) :
    foldStraight ((emit (bH Crypto.ripemd160)).flatMap (encH (opInstr 0xa6)))
        (entryState M A).1 (entryState M A).2
      = some (denote (bH Crypto.ripemd160) M A) :=
  hash_block_sound (bH Crypto.ripemd160) (bH_wf Crypto.ripemd160) (opInstr 0xa6)
    (hashSem Crypto.ripemd160) rfl (Or.inl ⟨rfl, rfl⟩) M A hM hA hacc

/-- OP_SHA1 (0xa7) block on the real VM, under its tag. -/
theorem emit_bSHA1_sound (M A : List Bytes) (hM : M.length = 1) (hA : A.length = 0)
    (hacc : foldStraight ((emit (bH Crypto.sha1)).flatMap (encH (opInstr 0xa7)))
              (entryState M A).1 (entryState M A).2 ≠ none) :
    foldStraight ((emit (bH Crypto.sha1)).flatMap (encH (opInstr 0xa7)))
        (entryState M A).1 (entryState M A).2
      = some (denote (bH Crypto.sha1) M A) :=
  hash_block_sound (bH Crypto.sha1) (bH_wf Crypto.sha1) (opInstr 0xa7)
    (hashSem Crypto.sha1) rfl (Or.inr (Or.inl ⟨rfl, rfl⟩)) M A hM hA hacc

/-- OP_SHA256 (0xa8) block on the real VM, under its tag. -/
theorem emit_bSHA256_sound (M A : List Bytes) (hM : M.length = 1) (hA : A.length = 0)
    (hacc : foldStraight ((emit (bH Crypto.sha256)).flatMap (encH (opInstr 0xa8)))
              (entryState M A).1 (entryState M A).2 ≠ none) :
    foldStraight ((emit (bH Crypto.sha256)).flatMap (encH (opInstr 0xa8)))
        (entryState M A).1 (entryState M A).2
      = some (denote (bH Crypto.sha256) M A) :=
  hash_block_sound (bH Crypto.sha256) (bH_wf Crypto.sha256) (opInstr 0xa8)
    (hashSem Crypto.sha256) rfl (Or.inr (Or.inr (Or.inl ⟨rfl, rfl⟩))) M A hM hA hacc

/-- OP_HASH160 (0xa9) block on the real VM, under its tag. -/
theorem emit_bHASH160_sound (M A : List Bytes) (hM : M.length = 1) (hA : A.length = 0)
    (hacc : foldStraight ((emit (bH Crypto.hash160)).flatMap (encH (opInstr 0xa9)))
              (entryState M A).1 (entryState M A).2 ≠ none) :
    foldStraight ((emit (bH Crypto.hash160)).flatMap (encH (opInstr 0xa9)))
        (entryState M A).1 (entryState M A).2
      = some (denote (bH Crypto.hash160) M A) :=
  hash_block_sound (bH Crypto.hash160) (bH_wf Crypto.hash160) (opInstr 0xa9)
    (hashSem Crypto.hash160) rfl (Or.inr (Or.inr (Or.inr (Or.inl ⟨rfl, rfl⟩)))) M A hM hA hacc

/-- OP_HASH256 (0xaa) block on the real VM, under its tag. -/
theorem emit_bHASH256_sound (M A : List Bytes) (hM : M.length = 1) (hA : A.length = 0)
    (hacc : foldStraight ((emit (bH Crypto.hash256)).flatMap (encH (opInstr 0xaa)))
              (entryState M A).1 (entryState M A).2 ≠ none) :
    foldStraight ((emit (bH Crypto.hash256)).flatMap (encH (opInstr 0xaa)))
        (entryState M A).1 (entryState M A).2
      = some (denote (bH Crypto.hash256) M A) :=
  hash_block_sound (bH Crypto.hash256) (bH_wf Crypto.hash256) (opInstr 0xaa)
    (hashSem Crypto.hash256) rfl (Or.inr (Or.inr (Or.inr (Or.inr ⟨rfl, rfl⟩)))) M A hM hA hacc

end LeanBCH.Opt.EmitConcreteHash
