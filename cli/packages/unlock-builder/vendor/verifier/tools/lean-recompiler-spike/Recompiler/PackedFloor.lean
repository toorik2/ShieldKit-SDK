/-
  PACKED COPY-FLOOR — the SOUND lower bound on stack-COPY *instructions* (bytes) for a
  value-DAG emitter, once the copy primitive set includes the MULTI-COPY ops the real
  BCH-2026 VM (and the crown bytecode) actually use: 2DUP / 2OVER (copy 2), 3DUP (copy 3),
  plus the single-copy family DUP / OVER / PICK / TUCK (copy 1).

  ★ WHY THIS FILE EXISTS — a SOUNDNESS FIX to `Floor.copy_floor`.
  `Floor.copy_floor` proves, per value produced once and demanded `k` times, `#dup ≥ k−1`,
  hence charges the whole block `D := Σ_v (fanout_v − 1)` bytes assuming ONE single `DUP`
  per duplication. That is a valid floor over the 1-instruction=1-copy machine, but it is
  **UNSOUND as a byte floor for PACKED bytecode**: a single `2DUP` byte creates TWO new
  occurrences and a single `3DUP` byte creates THREE, so real bytecode can realize FEWER
  copy-bytes than `D`. (The crown floor-characterization observed def#33/block#2 hitting
  `6 < 7 = D`-floor for exactly this reason.) Charging `D` bytes therefore claims a floor
  that valid programs BEAT — worse than no floor at all.

  ★ THE SOUND PACKED FLOOR (proved here, 0-sorry):
      #copy-instructions  ≥  ⌈D / 3⌉         where   D = (total demand) − (total produced).
  It is sound because NO instruction in the VM creates more than 3 new occurrences of stack
  values (`3DUP` is the max; see the adversarial audit note at the bottom). It is TIGHT: the
  `3DUP` witness below meets it with EQUALITY (3 values of fan-out 2 served by ONE 3DUP byte).

  ★ MODEL. We track only the TOTAL occurrence count (stack size) as a `Nat`, because `D`
  is a global count over all values, and the copy floor is a conservation fact about how
  fast total occurrences can grow: `push` and node outputs PRODUCE, the copy family
  DUPLICATES (+1/+2/+3), `pop` CONSUMES. Underflow ⇒ `none` (faithful to `Basic.step`). The
  conservation law is proved by induction over the program, mirroring `Floor.conserve`.

  ★ HONEST SCOPE. (1) This is the SOUND UNIVERSAL byte floor `⌈D/3⌉`. The TIGHT floor lies in
  `[⌈D/3⌉, D]` and is set by ADJACENCY (can the needed copies be lined up as the top-2/top-3
  so a `2DUP`/`3DUP` fires?) — an in-block scheduling quantity with no clean closed form
  (bounded-stack sequencing is NP-hard), left as the documented gap. (2) Same bridge caveat
  as `Floor`/`NlcsFloor`: the correspondence to `Scheduler.emit`'s realized per-op trace is
  asserted-by-construction of the emitter, not a proven property of `emit`.

  Lean 4.31 core, NO mathlib. Reuses the `Recompiler` namespace + the `fanout` bridge.
-/
import Recompiler.Floor

namespace Recompiler
namespace PackedFloor

/-! ## The enriched copy-floor counting model.

    Instruction classes, keyed by their EFFECT on the total occurrence count:
    * `push`  — produce one fresh occurrence (a node output `CALL`, or a data/const push);
    * `dup`   — the SINGLE-copy family: `DUP`/`OVER`/`PICK`/`TUCK` (+1 occurrence);
    * `copy2` — the DOUBLE-copy family: `2DUP`/`2OVER` (+2 occurrences);
    * `copy3` — `3DUP` (+3 occurrences), the maximum any BCH-2026 op creates;
    * `pop`   — consume one occurrence (one operand-consumption);
    * `move`  — occurrence-count-NEUTRAL rearrangers: `SWAP`/`ROT`/`NIP`/`ROLL`/`2SWAP`/`2ROT`.
    Underflow ⇒ `none`, exactly as `Basic.step`. -/
inductive PInst where
  | push
  | dup
  | copy2
  | copy3
  | pop
  | move
deriving DecidableEq

/-  Machine state = total occurrence count (stack size), a plain `Nat`. `D` is a global
    count over all values, so tracking only the total is exactly the invariant the floor
    needs. (Kept as raw `Nat` — not an abbrev — so `omega` reads the arithmetic directly.) -/

/-- Single-step interpreter. `none` = underflow / abort (faithful to `Basic.step`).
    Pattern-matched on the size (no `ite`) so the arithmetic effect is transparent to `omega`. -/
def stepP : PInst → Nat → Option Nat
  | .push,  n       => some (n + 1)
  | .dup,   0       => none
  | .dup,   (n + 1) => some (n + 2)
  | .copy2, 0       => none
  | .copy2, 1       => none
  | .copy2, (n + 2) => some (n + 4)
  | .copy3, 0       => none
  | .copy3, 1       => none
  | .copy3, 2       => none
  | .copy3, (n + 3) => some (n + 6)
  | .pop,   0       => none
  | .pop,   (n + 1) => some n
  | .move,  n       => some n

/-- Run a program (fold with short-circuit on `none`), mirroring `Recompiler.run`. -/
def runP : List PInst → Nat → Option Nat
  | [],      n => some n
  | i :: is, n => match stepP i n with
                  | some n' => runP is n'
                  | none    => none

/-! ## Per-class instruction counters (direct recursion; no `BEq`/`List.count` needed). -/

def npush : List PInst → Nat
  | []            => 0
  | .push :: t    => npush t + 1
  | _ :: t        => npush t

def ndup : List PInst → Nat
  | []            => 0
  | .dup :: t     => ndup t + 1
  | _ :: t        => ndup t

def nc2 : List PInst → Nat
  | []            => 0
  | .copy2 :: t   => nc2 t + 1
  | _ :: t        => nc2 t

def nc3 : List PInst → Nat
  | []            => 0
  | .copy3 :: t   => nc3 t + 1
  | _ :: t        => nc3 t

def npop : List PInst → Nat
  | []            => 0
  | .pop :: t     => npop t + 1
  | _ :: t        => npop t

/-- The quantity the floor bounds: number of COPY-instruction bytes. -/
def copyInstrs (p : List PInst) : Nat := ndup p + nc2 p + nc3 p

/-! ## ★ CONSERVATION LAW (induction on the program).
    For any successful run, final size + #pop = initial size + #push + (weighted copies),
    where a copy of class `k` contributes `k` new occurrences (`dup`↦1, `copy2`↦2, `copy3`↦3). -/
theorem conserveP :
    ∀ (p : List PInst) (n nf : Nat),
      runP p n = some nf →
        nf + npop p = n + npush p + (ndup p + 2 * nc2 p + 3 * nc3 p) := by
  intro p
  induction p with
  | nil => intro n nf h; simp only [runP, Option.some.injEq] at h; subst h
           simp [npush, ndup, nc2, nc3, npop]
  | cons i is ih =>
    intro n nf h
    cases i with
    | push =>
        simp only [runP, stepP] at h
        have hb := ih (n + 1) nf h
        simp only [npush, ndup, nc2, nc3, npop]; omega
    | dup =>
        cases n with
        | zero   => simp [runP, stepP] at h
        | succ m =>
            simp only [runP, stepP] at h
            have hb := ih (m + 2) nf h
            simp only [npush, ndup, nc2, nc3, npop]; omega
    | copy2 =>
        match n, h with
        | 0,     h => simp [runP, stepP] at h
        | 1,     h => simp [runP, stepP] at h
        | m + 2, h =>
            simp only [runP, stepP] at h
            have hb := ih (m + 4) nf h
            simp only [npush, ndup, nc2, nc3, npop]; omega
    | copy3 =>
        match n, h with
        | 0,     h => simp [runP, stepP] at h
        | 1,     h => simp [runP, stepP] at h
        | 2,     h => simp [runP, stepP] at h
        | m + 3, h =>
            simp only [runP, stepP] at h
            have hb := ih (m + 6) nf h
            simp only [npush, ndup, nc2, nc3, npop]; omega
    | pop =>
        cases n with
        | zero   => simp [runP, stepP] at h
        | succ m =>
            simp only [runP, stepP] at h
            have hb := ih m nf h
            simp only [npush, ndup, nc2, nc3, npop]; omega
    | move =>
        simp only [runP, stepP] at h
        have hb := ih n nf h
        simp only [npush, ndup, nc2, nc3, npop]; omega

/-! ## ★★ THE SOUND PACKED COPY FLOOR.
    For a clean run (empty start & empty end — the block clears its scratch), the total
    demand `npop` exceeds the total produced `npush` by exactly the weighted copies, and
    each copy INSTRUCTION contributes ≤ 3, so `3 · copyInstrs ≥ D`. -/
theorem packed_copy_floor (p : List PInst) (h : runP p 0 = some 0) :
    3 * copyInstrs p ≥ npop p - npush p := by
  have hc := conserveP p 0 0 h
  simp only [copyInstrs]
  omega

/-- ★ Ceiling form: `copyInstrs ≥ ⌈D / 3⌉` (Nat ceiling `(D + 2) / 3`). This is the number
    the crown re-measurement uses: `D` duplications cost at least `⌈D/3⌉` copy bytes. -/
theorem packed_copy_floor_ceil (p : List PInst) (h : runP p 0 = some 0) :
    copyInstrs p ≥ (npop p - npush p + 2) / 3 := by
  have hc := conserveP p 0 0 h
  simp only [copyInstrs]
  omega

/-! ## ★ NON-VACUITY — the `3DUP` witness meets `⌈D/3⌉` with EQUALITY (tight, and it BEATS
    the old single-`DUP` floor `D`). Three values, each produced once and consumed twice
    (fan-out 2, so `D = 3`), served by ONE `3DUP` byte then 6 pops. The unsound `Floor`
    charge would be `D = 3` dups; the packed reality is `copyInstrs = 1 = ⌈3/3⌉`. -/
def witness : List PInst :=
  [.push, .push, .push, .copy3, .pop, .pop, .pop, .pop, .pop, .pop]

/-- The witness is a clean run (starts and ends empty). -/
theorem witness_run : runP witness 0 = some 0 := by decide

/-- Its counts: 3 pushes, 6 pops, ONE copy instruction; `D = npop − npush = 3`. -/
theorem witness_counts :
    npush witness = 3 ∧ npop witness = 6 ∧ copyInstrs witness = 1
    ∧ ndup witness = 0 ∧ nc2 witness = 0 ∧ nc3 witness = 1 := by
  decide

/-- ★ The packed floor FIRES on the witness and is MET WITH EQUALITY: `⌈3/3⌉ = 1 = copyInstrs`.
    A non-vacuous instantiation — the bound is not vacuously loose. -/
theorem witness_tight :
    copyInstrs witness ≥ (npop witness - npush witness + 2) / 3 :=
  packed_copy_floor_ceil witness witness_run

example : copyInstrs witness = (npop witness - npush witness + 2) / 3 := by decide

/-- ★ SOUNDNESS DEMONSTRATION — the witness BEATS the old (unsound) `D`-byte charge.
    Old `Floor` floor for this DAG = `D = 3` single dups; packed realizes `1` copy byte.
    `1 < 3`, so charging `D` claims a floor a valid program violates; `⌈D/3⌉ = 1` holds. -/
example : copyInstrs witness < (npop witness - npush witness) := by decide

/-! ## ★ ADVERSARIAL SOUNDNESS AUDIT (machine-checked skeleton).
    The floor is sound iff NO single instruction creates > 3 new occurrences. We check every
    class's size-delta is ≤ 3 (the structural fact underwriting `conserveP`'s `3 * …` bound):
    `push,dup ↦ +1`, `copy2 ↦ +2`, `copy3 ↦ +3`, `pop ↦ −1`, `move ↦ 0`. Every BCH-2026 copy
    op maps into a class with delta ≤ 3 (`2OVER`↦copy2 +2, no op exceeds `3DUP`'s +3), so a
    program creating `D` duplications in `< ⌈D/3⌉` copy bytes is impossible. -/
example :
    stepP .push 5 = some 6 ∧ stepP .dup 5 = some 6 ∧ stepP .copy2 5 = some 7
  ∧ stepP .copy3 5 = some 8 ∧ stepP .pop 5 = some 4 ∧ stepP .move 5 = some 5 := by decide

end PackedFloor

/-! ## Bridge to the value-DAG (`Recompiler.Dag`, reusing `Recompiler.fanout`).

    `D` for a block is `Σ_v (fanout_v − 1)` summed over every value PRODUCED once (each node
    output and each surviving entry slot). Under the emission map produce ↦ `push`, each
    single/double/triple copy ↦ `dup`/`copy2`/`copy3`, and consume ↦ `pop`, a block's emitter
    trace is a `PackedFloor` program with `npush = #produced`, `npop = Σ fanout`, hence
    `npop − npush = Σ(fanout − 1) = D`, and `packed_copy_floor_ceil` gives the SOUND
    `#copy-bytes ≥ ⌈D/3⌉`. (The crown's measured `D = 459` ⇒ sound copy floor `⌈459/3⌉ = 153`
    bytes — replacing the old unsound `D`-byte charge, which valid packed bytecode beats.) -/

/-- ★ NON-VACUITY (DAG side): the same fan-out-3 block as `Floor` — node-0 output demanded 3×.
    Its per-value copy demand is `3 − 1 = 2`; over a whole block these `(fanout−1)` sum to `D`,
    and the packed floor charges `⌈D/3⌉` bytes for them (vs the old, unsound, `D`). -/
example :
    fanout
      ({ entryDepth := 0, entryAlt := 0,
         nodes := [⟨0, ⟨0, 1, fun _ => [(0 : Nat)]⟩, []⟩,
                   ⟨1, ⟨2, 1, fun l => [l.headD 0 + l.tail.headD 0]⟩,
                       [Ref.out 0 0, Ref.out 0 0]⟩],
         exit := [Ref.out 0 0], exitAlt := [] } : Block Nat)
      (Ref.out 0 0) = 3 := by decide

end Recompiler
