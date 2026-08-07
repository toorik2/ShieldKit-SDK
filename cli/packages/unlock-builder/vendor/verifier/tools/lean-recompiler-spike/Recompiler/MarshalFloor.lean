/-
  MARSHALLING FLOOR — a machine-checked LOWER BOUND on stack-MOVEMENT ops forced by the
  CONSUMPTION side of a value-DAG block (the "gathering" the exit-side n-LCS floor credits 0).

  ★ THE GAP THIS ADDRESSES. `NlcsFloor.movement_lower_bound_nlcs` proves the SHARP movement floor
  `#moves ≥ n − LCS(entry, EXIT)` for placing SURVIVORS at the fixed exit layout. It credits ZERO
  for CONSUMED-input gathering, on the (loose) reasoning "consumption order is free ⇒ consume
  top-down at 0 cost". That is NOT zero: the block's nodes fire in a topological order, and a
  DEEP entry input feeding an EARLY node cannot be consumed top-down — it must be dug out. This
  file formalises that as a CONSUMPTION-SEQUENCE movement floor:

      #moves  ≥  n − LCS(entry, σ)        where σ = the pop (consumption) sequence.

  Same untouched-common-subsequence argument as `NlcsFloor`, but the second sequence is the
  ORDER VALUES ARE POPPED (consumed) rather than the exit layout. Values never ROLLed are popped
  top-down (in entry order), so the never-moved set is a common subsequence of the entry AND of σ.

  ★ THE DAG CONSTRAINT (why this is FORCED, not free). σ is not arbitrary: it is a LINEAR
  EXTENSION of the DAG's precedence poset (a node's operands are popped when it fires, and firing
  respects precedence). So the SOUND per-block floor is `n − max_{σ∈LinExt} LCS(entry, σ)` — the
  scheduler may pick the best consumption order, but topology bounds how top-down it can be. When
  topology FORCES a deep input before a shallow one, that pair is order-inverted in EVERY σ, and
  the floor fires with a strictly-positive, computable value (the disjoint-forced-inverted-pair
  count ≤ n − LCS). The non-vacuity witness below has topology forcing one inversion ⇒ floor 1,
  MET WITH EQUALITY by one ROLL.

  ★ MODEL. The consumption phase is a {moveToTop, pop} machine over `MovementFloor.Stack`
  (`List Nat`, head = TOP), REUSING `MovementFloor.moveToTop` (= the main-stack effect of `ROLL`,
  Basic.lean) and `NlcsFloor`'s LCS DP + counting lemmas verbatim. `pop` = `List.tail` (a CALL
  consuming one top operand). A run that EMPTIES the stack (`crun prog s = []`) models a block
  that consumes its whole entry. Lean 4.31 core, NO mathlib; distinct entry values (`s.Nodup`).

  ★ BRIDGE (identical posture to `Floor`/`MovementFloor`/`NlcsFloor`). The scheduler's `emitFetch`
  (Scheduler.lean) delivers a LAST-USE operand to the top via `moveOps` (ROLL/SWAP/ROT) — exactly
  `moveToTop` — and a CALL consumes it (`pop`). So the emitted consumption trace of the fanout-1
  (last-use) inputs IS a `{moveToTop, pop}` program, and this floor lower-bounds its ROLL count.
  What is asserted-by-construction (NOT proven of `emit`): that the emitter realises consumption
  by these ops. See the ADVERSARIAL SOUNDNESS AUDIT at the bottom — a DIFFERENT program CAN beat
  the move-COUNT by PICK-copying a deep value and dropping the original (0 moves), but that route
  costs strictly MORE bytes (PICK+extra DROP = 2 B vs ROLL = 1 B) and the emitter provably does
  not emit it for last uses. Hence this is a sound floor on the emitter's move-discipline, not a
  universal all-programs byte floor (that needs the joint move+copy argument, left OPEN below).
-/
import Recompiler.NlcsFloor

namespace Recompiler
namespace MarshalFloor

open List
open MovementFloor (moveToTop runMoves Stack)
open NlcsFloor (lcsLen lcs_dominates filter_moveToTop_inv filter_len_compl nodup_length_le)

/-! ## The {moveToTop, pop} consumption machine. -/

/-- A consumption instruction: `mv d` = ROLL depth `d` to the top (a reorder), `pop` = a CALL
    consuming the top operand. -/
inductive CInst where
  | mv (d : Nat)
  | pop
deriving DecidableEq

/-- Single step. `pop` on `[]` is a no-op (`List.tail`); out-of-range `mv` is a no-op. -/
def cstep : CInst → Stack → Stack
  | .mv d, s => moveToTop d s
  | .pop,  s => s.tail

/-- Run a consumption program. -/
def crun : List CInst → Stack → Stack
  | [],      s => s
  | i :: is, s => crun is (cstep i s)

/-- The POP (consumption) SEQUENCE σ: the values popped, in order. -/
def popped : List CInst → Stack → List Nat
  | [],           _ => []
  | .mv d :: is,  s => popped is (moveToTop d s)
  | .pop :: is,   s => (match s with | [] => [] | x :: _ => [x]) ++ popped is s.tail

/-- Ordered list of values lifted to the top by a `mv`, one per successful move. -/
def moved : List CInst → Stack → List Nat
  | [],           _ => []
  | .mv d :: is,  s => (match s[d]? with | some v => [v] | none => []) ++ moved is (moveToTop d s)
  | .pop :: is,   s => moved is s.tail

/-- Number of MOVE instructions (the quantity this floor lower-bounds). -/
def nmoves : List CInst → Nat
  | []            => 0
  | .mv _ :: is   => nmoves is + 1
  | .pop :: is    => nmoves is

/-! ## (A) The common-subsequence core: the never-moved values are popped in ENTRY order. -/

/-- ★ FILTER INVARIANCE of the pop-sequence: if the run EMPTIES the stack and every moved value
    fails `p`, then filtering the pop-sequence by `p` recovers filtering the ENTRY by `p`. (The
    consumption analog of `NlcsFloor.filter_runMoves_inv`: never-moved values keep entry order and
    — since the stack empties — are all eventually popped.) -/
theorem filter_popped_inv (p : Nat → Bool) :
    ∀ (prog : List CInst) (s : Stack), crun prog s = [] → (∀ v ∈ moved prog s, p v = false) →
      (popped prog s).filter p = s.filter p := by
  intro prog
  induction prog with
  | nil =>
      intro s hempty _
      simp only [crun] at hempty
      subst hempty
      rfl
  | cons i is ih =>
      intro s hempty h
      cases i with
      | mv d =>
          simp only [crun, cstep] at hempty
          have hmt_empty : crun is (moveToTop d s) = [] := hempty
          simp only [popped]
          cases hd : s[d]? with
          | none =>
              have hmt : moveToTop d s = s := by simp only [moveToTop, hd]
              have htail : ∀ v ∈ moved is (moveToTop d s), p v = false := by
                intro v hv; apply h; simp only [moved, hd, List.nil_append]; exact hv
              rw [ih (moveToTop d s) hmt_empty htail, hmt]
          | some v =>
              have hpv : p v = false := by
                apply h; simp only [moved, hd, List.singleton_append]; exact List.mem_cons_self
              have htail : ∀ w ∈ moved is (moveToTop d s), p w = false := by
                intro w hw; apply h
                simp only [moved, hd, List.singleton_append]; exact List.mem_cons_of_mem v hw
              rw [ih (moveToTop d s) hmt_empty htail, filter_moveToTop_inv p s d v hd hpv]
      | pop =>
          simp only [crun, cstep] at hempty
          have htail_empty : crun is s.tail = [] := hempty
          have htail : ∀ v ∈ moved is s.tail, p v = false := by
            intro v hv; apply h; simp only [moved]; exact hv
          cases s with
          | nil =>
              simp only [popped, List.nil_append, List.tail_nil]
              rw [ih [] htail_empty htail]
          | cons x xs =>
              simp only [popped, List.tail_cons, List.singleton_append, List.filter_cons]
              rw [ih xs htail_empty htail]

/-- Every moved value forces `decide (· ∉ moved) = false`. -/
theorem moved_false (prog : List CInst) (s : Stack) :
    ∀ v ∈ moved prog s, decide (v ∉ moved prog s) = false := by
  intro v hv
  rw [decide_eq_false_iff_not]
  exact fun h => h hv

/-- The never-moved values, IN ENTRY ORDER. -/
def untouched (prog : List CInst) (s : Stack) : Stack :=
  s.filter (fun v => decide (v ∉ moved prog s))

/-- The (distinct) moved values, in entry order. -/
def touched (prog : List CInst) (s : Stack) : Stack :=
  s.filter (fun v => decide (v ∈ moved prog s))

/-- ★ `untouched` is a SUBSEQUENCE of the ENTRY stack. -/
theorem untouched_sub_entry (prog : List CInst) (s : Stack) : untouched prog s <+ s :=
  List.filter_sublist

/-- ★ `untouched` is a SUBSEQUENCE of the CONSUMPTION SEQUENCE (never-moved popped in entry order),
    for a run that empties the stack. -/
theorem untouched_sub_popped (prog : List CInst) (s : Stack) (hempty : crun prog s = []) :
    untouched prog s <+ popped prog s := by
  have he : (popped prog s).filter (fun v => decide (v ∉ moved prog s)) = untouched prog s :=
    filter_popped_inv _ prog s hempty (moved_false prog s)
  rw [← he]
  exact List.filter_sublist

/-! ## (A) The counting: n − |untouched| ≤ #moves. -/

/-- `touched.length + untouched.length = s.length`. -/
theorem len_split (prog : List CInst) (s : Stack) :
    (touched prog s).length + (untouched prog s).length = s.length := by
  have hpu : (fun v => decide (v ∉ moved prog s))
           = (fun v => !(decide (v ∈ moved prog s))) := by
    funext v; rw [decide_not]
  unfold touched untouched
  rw [hpu]
  exact filter_len_compl (fun v => decide (v ∈ moved prog s)) s

/-- Each `mv` lifts ≤ 1 value, `pop` lifts none ⇒ `#moved ≤ #moves`. -/
theorem moved_len_le : ∀ (prog : List CInst) (s : Stack), (moved prog s).length ≤ nmoves prog := by
  intro prog
  induction prog with
  | nil => intro s; simp [moved, nmoves]
  | cons i is ih =>
      intro s
      cases i with
      | mv d =>
          cases hd : s[d]? with
          | none =>
              have he : moved (CInst.mv d :: is) s = moved is (moveToTop d s) := by
                simp only [moved, hd, List.nil_append]
              rw [he]; simp only [nmoves]
              have := ih (moveToTop d s); omega
          | some v =>
              have he : moved (CInst.mv d :: is) s = v :: moved is (moveToTop d s) := by
                simp only [moved, hd, List.singleton_append]
              rw [he, List.length_cons]; simp only [nmoves]
              have := ih (moveToTop d s); omega
      | pop =>
          have he : moved (CInst.pop :: is) s = moved is s.tail := by simp only [moved]
          rw [he]; simp only [nmoves]
          exact ih s.tail

/-- ★★ (A) THE CORE BOUND: `n − |untouched| ≤ #moves`. -/
theorem marshal_lb_untouched (prog : List CInst) (s : Stack) (hnd : s.Nodup) :
    s.length - (untouched prog s).length ≤ nmoves prog := by
  have hsplit := len_split prog s
  have h1 : s.length - (untouched prog s).length = (touched prog s).length := by omega
  rw [h1]
  have hnd_t : (touched prog s).Nodup := List.Nodup.sublist List.filter_sublist hnd
  have hsub : ∀ x ∈ touched prog s, x ∈ moved prog s := by
    intro x hx
    unfold touched at hx
    rw [List.mem_filter] at hx
    exact of_decide_eq_true hx.2
  have hle1 := nodup_length_le (touched prog s) (moved prog s) hnd_t hsub
  have hle2 := moved_len_le prog s
  omega

/-! ## (B)+(C) LCS-packaging: the CONSUMPTION-SEQUENCE movement floor. -/

/-- ★★★ THE MARSHALLING FLOOR: any {moveToTop, pop} program that CONSUMES a Nodup entry to empty
    uses at least `n − LCS(entry, σ)` move ops, where `σ = popped prog s` is the consumption
    (pop) order. Since the DAG constrains `σ` to a topological linear extension, taking the min
    over admissible `σ` gives a sound per-block floor; when topology forces a deep-before-shallow
    consumption the value is strictly positive (see the witness). -/
theorem marshal_move_floor (prog : List CInst) (s : Stack) (hnd : s.Nodup)
    (hempty : crun prog s = []) :
    s.length - lcsLen s (popped prog s) ≤ nmoves prog := by
  have hUL : (untouched prog s).length ≤ lcsLen s (popped prog s) :=
    lcs_dominates s (popped prog s) (untouched prog s)
      (untouched_sub_entry prog s) (untouched_sub_popped prog s hempty)
  have hcore := marshal_lb_untouched prog s hnd
  have hmono : s.length - lcsLen s (popped prog s) ≤ s.length - (untouched prog s).length :=
    Nat.sub_le_sub_left hUL s.length
  omega

/-! ## NON-VACUITY — topology FORCES a deep-before-shallow consumption ⇒ floor 1, MET WITH EQUALITY.

    Entry `[10, 20]` (value 10 on TOP, 20 at depth 1). Suppose node X consumes the DEEP input 20,
    node Y consumes the shallow input 10, and X ≺ Y in the DAG (X must fire first). Then EVERY
    topological consumption order σ pops 20 before 10, so `σ = [20, 10]` and `LCS([10,20],[20,10]) = 1`.
    The floor is `2 − 1 = 1` move — and it is FORCED (independent of schedule, since the single
    admissible σ inverts the pair). The witness program `[mv 1, pop, pop]` (ROLL the deep 20 up,
    then pop both) realises exactly this with ONE move ⇒ TIGHT. -/

/-- The witness consumes `[10,20]` to empty. -/
theorem witness_run : crun [CInst.mv 1, CInst.pop, CInst.pop] [10, 20] = [] := by decide

/-- Its consumption (pop) sequence is `[20, 10]` — the DAG-forced deep-before-shallow order. -/
theorem witness_popped : popped [CInst.mv 1, CInst.pop, CInst.pop] [10, 20] = [20, 10] := by decide

/-- LCS(entry, forced-σ) = 1. -/
example : lcsLen [10, 20] [20, 10] = 1 := by simp [lcsLen]

/-- Entry is Nodup. -/
theorem witness_nodup : ([10, 20] : Stack).Nodup := by decide

/-- ★ THE MARSHALLING FLOOR FIRES and is MET WITH EQUALITY: `2 − 1 = 1 ≤ 1`. -/
theorem witness_bound :
    ([10, 20] : Stack).length - lcsLen [10, 20] (popped [CInst.mv 1, CInst.pop, CInst.pop] [10, 20])
      ≤ nmoves [CInst.mv 1, CInst.pop, CInst.pop] :=
  marshal_move_floor [CInst.mv 1, CInst.pop, CInst.pop] [10, 20] witness_nodup witness_run

/-- Numerically: floor value = achieved move-count = 1 (tight). -/
example :
    ([10, 20] : Stack).length - lcsLen [10, 20] (popped [CInst.mv 1, CInst.pop, CInst.pop] [10, 20]) = 1
  ∧ nmoves [CInst.mv 1, CInst.pop, CInst.pop] = 1 := by
  rw [witness_popped]; refine ⟨?_, by decide⟩; simp [lcsLen]

/-! ## ★ ADVERSARIAL SOUNDNESS AUDIT (machine-checked, over the REAL `Basic.step` VM).

    Is the move-COUNT floor a UNIVERSAL byte floor (does EVERY valid program pay ≥ floor bytes of
    marshalling)? NO — and we prove the exact failure mode, so the scope is honest.

    Take the witness scenario: entry `[10, 20]`, forced consumption order `20`-before-`10` (deep
    first). The `moveToTop` route pays ONE move:
        ROLL 1 ; DROP ; DROP           (1 ROLL, 3 bytes)   ⇒ meets the floor (1 move).
    But a DIFFERENT program CIRCUMVENTS the move-count entirely by PICK-copying the deep value to
    the top, consuming the COPY, then dropping the buried original — ZERO ROLL/SWAP/ROT:
        PICK 1 ; DROP ; DROP ; DROP    (0 moves, 4 bytes)  ⇒ consumes 20 then 10, 0 moves.
    So as an OP-COUNT bound over the FULL VM the move-floor is UNSOUND (this program achieves the
    forced inversion with 0 moves < floor 1). Both machine-checked below to empty the stack. -/

/-- The MOVE route: 1 ROLL, consumes `[10,20]` deep-first, empties the stack. -/
example : run [Op.ROLL 1, Op.DROP, Op.DROP] (([10, 20] : List Nat), ([] : List Nat))
            = some ([], []) := by decide

/-- ★ THE CIRCUMVENTION: PICK-copy the deep `20` to top, consume it, then the shallow `10`, then
    DROP the buried original `20`. ZERO moves — beats the move-count floor of 1. Machine-checked to
    consume `[10,20]` (deep-first) to empty. Syntactically contains NO ROLL/SWAP/ROT. -/
example : run [Op.PICK 1, Op.DROP, Op.DROP, Op.DROP] (([10, 20] : List Nat), ([] : List Nat))
            = some ([], []) := by decide

/-! ★ WHY THIS DOES NOT DETHRONE (byte reading). The circumvention trades the 1-byte ROLL for a
    1-byte PICK **plus an extra 1-byte DROP** of the buried original: 2 marshalling bytes vs 1.
    So the move↔copy substitution NEVER reduces BYTES below the move route — it only reduces the
    move-COUNT. Hence the disjoint-forced-inversion count remains a plausible BYTE lower bound; but
    proving it over the full 18-op VM requires a JOINT argument bounding (moves + marshalling-copies)
    together, because the consumption-order projection is NOT invariant under copies (a PICK can
    invert it). That joint invariant is NOT closed here — it is the exact OPEN obstacle.

    ★ WHAT IS SOUND (this file's claim). The bound is a machine-checked LOWER BOUND on `moveToTop`
    ops in the {move, pop} consumption machine, and — via the SAME asserted-by-construction bridge
    as `Floor`/`MovementFloor`/`NlcsFloor` — a floor on the ROLL count of the EMITTER's consumption
    trace, because `Scheduler.emitFetch` delivers every LAST-USE (fanout-1 consumed) operand via
    `moveOps` (ROLL/SWAP/ROT), never by the PICK-and-drop route. The adversarial program above is
    NOT emitted by the scheduler for last uses; it merely delimits that this is a move-discipline
    floor, not an all-programs byte floor. -/

end MarshalFloor
end Recompiler
