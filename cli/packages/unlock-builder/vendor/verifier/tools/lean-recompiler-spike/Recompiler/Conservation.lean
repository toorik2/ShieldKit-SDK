/-
  GLOBAL-CONSERVATION — the ZERO-SUM SHUFFLE-RELOCATION identity (callee-saves == caller-pays),
  its N-block re-blocking invariance, and the interface-as-wire-order corollary, over an abstract
  per-op byte weight. Plus an HONEST accounting of what this does and does NOT give.

  ★ WHAT THIS UPGRADES. The empirical finding (§6/§9): the aggressive scheduler realised only ~33
  of ~4,073 B of proven per-block slack because "a block's saved exit-shuffle is paid by its
  caller's entry-shuffle" — cross-block scheduling and interface reassignment are ~zero-sum. This
  file turns that from empirics into a THEOREM: relocating a shuffle sub-program across a
  caller/callee boundary is EXACTLY zero-sum in total addressing bytes, with the data-flow
  (denotation) provably preserved. Consequently the total addressing cost is INVARIANT under any
  re-partitioning of a fixed flat op-sequence into blocks (the N-block call-graph result), and
  interface (wire-order) reassignment merely re-splits a fixed composite shuffle — zero-sum.

  ★ THE MODEL (reuses existing machinery verbatim).
    • Addressing cost = a WEIGHTED op-list length `acost w l := (l.map w).sum` for ANY per-op
      byte weight `w`. The ONLY property used is ADDITIVITY (`acost_append`). Concretely w ≡ 1 is
      the move-op-count surrogate (ROLL/SWAP/ROT are 1-byte moveOps ⇒ bytes = count).
    • The flat whole program is `List (Op α)` under `Basic.run`; the faithful structured form is
      `Control.Prog` with real block leaves (`Item.block ops _ _ _` runs `ops` via flat `run`).
    • The interface (wire-order) sub-model reuses `MovementFloor.runMoves` (built on the project's
      real `Recompiler.removeNth`, the deletion `Op.ROLL` uses; `moveToTop_faithful_ROLL`).

  ★ SCOPE / HONEST CAVEATS.
    • The identity is an EXACT accounting equality for RELOCATING A FIXED shuffle program (§8's
      "passthrough / data-flow preserved" sub-component). Create/destroy/dup boundaries are OUT of
      scope (the §8 model-mismatch caveat) — those are the copy dimension (`PackedFloor.copy_floor`,
      immune to PICK/DROP), not the reordering dimension bounded here.
    • This is an INVARIANCE (no relocation/re-blocking/interface-reassignment can reduce the total),
      NOT a positive global BYTE floor. The SECONDARY target (a positive global marshalling byte
      floor) provably DIES to the same PICK/DROP evasion that killed the per-block byte floor
      (`MarshalFloor` adversarial audit) — a machine-checked whole-program witness is included, and
      the honest conclusion is: the only sound positive global bounds are the copy-floor (existing)
      and this conservation INVARIANCE (new). Reported honestly, no overclaim.

  Lean 4.31 core, NO mathlib.
-/
import Recompiler.Control
import Recompiler.MarshalFloor

namespace Recompiler
namespace Conservation

open Op
open MovementFloor (moveToTop runMoves Stack)

/-! ## §1. WEIGHTED ADDRESSING COST + ADDITIVITY (the only algebraic fact used). -/

/-- Weighted addressing cost: sum of a per-element byte weight over an op/move list. Generic in the
    element type `β` (used at `β = Op α` for the flat/structured program and `β = Nat` for the
    move-depth interface model). -/
def acost {β : Type} (w : β → Nat) (l : List β) : Nat := (l.map w).sum

/-- ★ ADDITIVITY — the sole property the conservation identity rests on. -/
theorem acost_append {β : Type} (w : β → Nat) (p q : List β) :
    acost w (p ++ q) = acost w p + acost w q := by
  simp only [acost, List.map_append, List.sum_append]

@[simp] theorem acost_nil {β : Type} (w : β → Nat) : acost w ([] : List β) = 0 := rfl

/-- The move-op-count surrogate: with unit weight, cost is just the op count (bytes = count for the
    1-byte moveOps ROLL/SWAP/ROT). -/
theorem acost_one_eq_length {β : Type} (l : List β) : acost (fun _ => 1) l = l.length := by
  induction l with
  | nil => rfl
  | cons x xs ih =>
      simp only [acost, List.map_cons, List.sum_cons, List.length_cons] at *
      omega

/-! ## §2. THE 2-BLOCK BOUNDARY UNIT. -/

/-- A caller/callee call boundary: `calleeBase` is the callee block's fixed body, `prog` the SHUFFLE
    sub-program sitting AT the boundary (the reorder of passthrough values), `callerBase` the caller
    block's fixed body. Relocating `prog` = moving it from end-of-callee to start-of-caller. -/
structure Boundary (α : Type) where
  calleeBase : List (Op α)
  prog       : List (Op α)
  callerBase : List (Op α)

/-- CALLEE-SIDE placement: the shuffle sits at the END of the callee block. Returns the two block
    bodies (callee, caller). -/
def Boundary.calleeSide (bd : Boundary α) : List (Op α) × List (Op α) :=
  (bd.calleeBase ++ bd.prog, bd.callerBase)

/-- CALLER-SIDE placement: the shuffle sits at the START of the caller block. -/
def Boundary.callerSide (bd : Boundary α) : List (Op α) × List (Op α) :=
  (bd.calleeBase, bd.prog ++ bd.callerBase)

/-- Total addressing cost of a two-block split under weight `w`. -/
def totalCost {α : Type} (w : Op α → Nat) (blk : List (Op α) × List (Op α)) : Nat :=
  acost w blk.1 + acost w blk.2

/-! ## §3. THE CONSERVATION IDENTITY — COST HALF (exact, zero-sum). -/

/-- ★★ THE ZERO-SUM SHUFFLE-RELOCATION IDENTITY. Moving `prog` from end-of-callee to start-of-caller:
    block-A cost changes by −acost prog, block-B by +acost prog, TOTAL invariant. Both sides
    `= acost calleeBase + acost prog + acost callerBase`. -/
theorem shuffle_relocation_cost {β : Type} (w : β → Nat) (calleeBase prog callerBase : List β) :
    acost w (calleeBase ++ prog) + acost w callerBase
      = acost w calleeBase + acost w (prog ++ callerBase) := by
  rw [acost_append, acost_append]; omega

/-- ★ "callee-saves == caller-pays == acost prog": the callee block SAVES exactly `acost prog` by
    shedding the shuffle, and the caller block PAYS exactly `acost prog` by absorbing it — the same
    quantity. An exact accounting equality. -/
theorem callee_saves_eq_caller_pays {β : Type} (w : β → Nat) (calleeBase prog callerBase : List β) :
    acost w (calleeBase ++ prog) - acost w calleeBase = acost w prog
  ∧ acost w (prog ++ callerBase) - acost w callerBase = acost w prog := by
  rw [acost_append, acost_append]; omega

/-- ★ Packaged on the `Boundary`: the two placements have EQUAL total addressing cost. -/
theorem boundary_cost_invariant {α : Type} (w : Op α → Nat) (bd : Boundary α) :
    totalCost w bd.calleeSide = totalCost w bd.callerSide := by
  simp only [totalCost, Boundary.calleeSide, Boundary.callerSide]
  exact shuffle_relocation_cost w bd.calleeBase bd.prog bd.callerBase

/-! ## §4. THE CONSERVATION IDENTITY — SEMANTIC HALF (data-flow preserved). -/

/-- ★ DATA-FLOW PRESERVED (flat model): both placements flatten to the SAME op-sequence
    `calleeBase ++ prog ++ callerBase`, so `run` agrees — literally equal denotation on every
    input state, by `List.append_assoc`. -/
theorem shuffle_relocation_denote {α : Type} (calleeBase prog callerBase : List (Op α))
    (st : State α) :
    run ((calleeBase ++ prog) ++ callerBase) st = run (calleeBase ++ (prog ++ callerBase)) st := by
  rw [List.append_assoc]

/-- ★ Packaged on the `Boundary`: running block-A then block-B agrees between the two placements. -/
theorem boundary_denote_invariant {α : Type} (bd : Boundary α) (st : State α) :
    run (bd.calleeSide.1 ++ bd.calleeSide.2) st = run (bd.callerSide.1 ++ bd.callerSide.2) st := by
  simp only [Boundary.calleeSide, Boundary.callerSide]
  exact shuffle_relocation_denote bd.calleeBase bd.prog bd.callerBase st

/-! ## §5. FAITHFUL STRUCTURED FORM — two real `Control.Item.block` leaves.

    The flat `++` above is faithful because a `Prog` block leaf runs its ops via the flat `run`
    (Control.lean:90). Here we prove the SAME zero-sum relocation over two ADJACENT block leaves in
    a `Prog`, with `prog` appended to leaf-1's ops OR prepended to leaf-2's ops — the real
    block-boundary form. Cost is `acost` of each leaf's ops. -/

/-- A single block leaf reduces to the flat `run` of its ops (any sufficient fuel). -/
theorem runProg_one_block {α : Type} (isT : α → Bool) (n : Nat) (ops : List (Op α))
    (e a : Nat) (b : Block α) (st : State α) :
    runProg isT (n+1) [Item.block ops e a b] st = run ops st := by
  cases h : run ops st with
  | none => rw [rp_none _ _ _ _ _ (by rw [ri_block]; exact h)]
  | some st' => rw [rp_some _ _ _ _ _ _ (by rw [ri_block]; exact h), rp_nil]

/-- Two adjacent block leaves compose by monadic bind of their flat `run`s. -/
theorem runProg_two_blocks {α : Type} (isT : α → Bool) (n : Nat)
    (opsA opsB : List (Op α)) (e1 a1 e2 a2 : Nat) (b1 b2 : Block α) (st : State α) :
    runProg isT (n+2) [Item.block opsA e1 a1 b1, Item.block opsB e2 a2 b2] st
      = (run opsA st).bind (fun st' => run opsB st') := by
  cases h1 : run opsA st with
  | none =>
      have hri : runItem isT (n+1) (Item.block opsA e1 a1 b1) st = none := by rw [ri_block]; exact h1
      rw [rp_none _ _ _ _ _ hri, Option.bind_none]
  | some st' =>
      have hri : runItem isT (n+1) (Item.block opsA e1 a1 b1) st = some st' := by rw [ri_block]; exact h1
      rw [rp_some _ _ _ _ _ _ hri, runProg_one_block, Option.bind_some]

/-- ★ FAITHFUL ZERO-SUM (semantics): relocating `prog` between two real adjacent block leaves
    preserves the whole-program denotation (`runProg` composition over the structured model). -/
theorem structured_boundary_denote_invariant {α : Type} (isT : α → Bool) (n : Nat)
    (calleeBase prog callerBase : List (Op α)) (e1 a1 e2 a2 : Nat) (b1 b2 : Block α) (st : State α) :
    runProg isT (n+2) [Item.block (calleeBase ++ prog) e1 a1 b1, Item.block callerBase e2 a2 b2] st
      = runProg isT (n+2) [Item.block calleeBase e1 a1 b1, Item.block (prog ++ callerBase) e2 a2 b2] st := by
  rw [runProg_two_blocks, runProg_two_blocks, run_append]
  cases run calleeBase st with
  | none => simp only [Option.bind_none]
  | some s => simp only [Option.bind_some]; rw [run_append]

/-- ★ FAITHFUL ZERO-SUM (cost): the two structured placements have equal total leaf cost. -/
theorem structured_boundary_cost_invariant {α : Type} (w : Op α → Nat)
    (calleeBase prog callerBase : List (Op α)) :
    acost w (calleeBase ++ prog) + acost w callerBase
      = acost w calleeBase + acost w (prog ++ callerBase) :=
  shuffle_relocation_cost w calleeBase prog callerBase

/-! ## §6. N-BLOCK GENERALIZATION — total addressing is a function of the FLAT sequence alone.

    The strongest generalization of the 2-block identity to the whole call graph: since `acost` is
    additive, the SUM of per-block costs equals the `acost` of the concatenation. Hence ANY
    re-partitioning of a fixed flat op-sequence into blocks (= ANY assignment of shuffles to block
    boundaries) has the SAME total addressing cost — cross-block scheduling by relocation is
    globally zero-sum, not merely pairwise. -/

/-- Total cost over a list of blocks = `acost` of their concatenation. -/
theorem acost_flatten {β : Type} (w : β → Nat) (blocks : List (List β)) :
    (blocks.map (acost w)).sum = acost w blocks.flatten := by
  induction blocks with
  | nil => rfl
  | cons b bs ih =>
      simp only [List.map_cons, List.sum_cons, List.flatten_cons]
      rw [acost_append, ih]

/-- ★★ N-BLOCK RE-BLOCKING INVARIANCE (COST): any two blockings of the SAME flat op-sequence have
    identical total addressing cost. This is the whole-call-graph statement that relocating shuffles
    across ANY set of boundaries is zero-sum. -/
theorem reblocking_cost_invariant {β : Type} (w : β → Nat) (bs1 bs2 : List (List β))
    (h : bs1.flatten = bs2.flatten) :
    (bs1.map (acost w)).sum = (bs2.map (acost w)).sum := by
  rw [acost_flatten, acost_flatten, h]

/-- ★ N-BLOCK RE-BLOCKING INVARIANCE (SEMANTICS): same flat sequence ⇒ same denotation. -/
theorem reblocking_denote_invariant {α : Type} (bs1 bs2 : List (List (Op α)))
    (h : bs1.flatten = bs2.flatten) (st : State α) :
    run bs1.flatten st = run bs2.flatten st := by
  rw [h]

/-! ## §7. INTERFACE AS A WIRE-ORDER PERMUTATION (the §9 interface-opt, made a theorem).

    A boundary carries `k` passthrough values, cross unchanged, only REORDERED (the "fixed interface
    position / data-flow preserved" condition; create/destroy/dup are OUT of scope). The callee's
    natural exit is `P`; the caller requires consumption order `Q` (a permutation of `P`). An
    interface assignment ι = a WIRE ORDER `W`: the callee shuffles `P → W` (`progC`), the caller
    shuffles `W → Q` (`progK`). Reassigning ι = choosing a different `W` = re-splitting the fixed
    composite shuffle that realizes `P → Q` — zero-sum. Uses the SAME move-to-top machine as the
    movement floors (`moveToTop_faithful_ROLL` grounds it to `Op.ROLL`). -/

/-- `runMoves` distributes over append: running `p` then `q` = running the concatenation. This is
    the move-model analog of `run_append`. -/
theorem runMoves_append (p q : List Nat) (s : Stack) :
    runMoves (p ++ q) s = runMoves q (runMoves p s) := by
  induction p generalizing s with
  | nil => rfl
  | cons d ds ih =>
      simp only [List.cons_append, runMoves, ih]

/-- ★ DATA-FLOW COMPOSITION: whatever wire order `W` the interface picks, the composite
    callee-then-caller shuffle realizes the SAME data-flow `P → Q`. -/
theorem interface_composite_dataflow (progC progK : List Nat) (P W Q : Stack)
    (hC : runMoves progC P = W) (hK : runMoves progK W = Q) :
    runMoves (progC ++ progK) P = Q := by
  rw [runMoves_append, hC, hK]

/-- ★★ INTERFACE REASSIGNMENT IS ZERO-SUM. Fix the composite shuffle `full` realizing `P → Q`. A
    choice of interface wire order `W` is a SPLIT `full = progC ++ progK` (with `W = runMoves progC
    P` the wire order). Then: (a) the split preserves the end-to-end data-flow (`runMoves progK
    (runMoves progC P) = runMoves full P` — the fixed `Q`); and (b) the total addressing cost is
    INVARIANT to the split (`acost progC + acost progK = acost full`). So reassigning the interface
    order merely relocates the shuffle across the boundary — total addressing invariant. -/
theorem interface_reassignment_zero_sum (wm : Nat → Nat) (full progC progK : List Nat) (P : Stack)
    (hsplit : progC ++ progK = full) :
    runMoves progK (runMoves progC P) = runMoves full P
  ∧ acost wm progC + acost wm progK = acost wm full := by
  refine ⟨?_, ?_⟩
  · rw [← hsplit, runMoves_append]
  · rw [← hsplit, acost_append]

/-! ## §8. NON-VACUITY WITNESSES (concrete, machine-checked; bounds met with EQUALITY). -/

-- A concrete boundary with a REAL shuffle to relocate (nonempty `prog`).
private def egCallee : List (Op Nat) := [Op.PUSH 1, Op.PUSH 2, Op.PUSH 3]
private def egProg   : List (Op Nat) := [Op.SWAP, Op.ROT]        -- the boundary shuffle
private def egCaller : List (Op Nat) := [Op.DROP]
private def egBd : Boundary Nat := ⟨egCallee, egProg, egCaller⟩

/-- NON-VACUOUS: there genuinely IS a shuffle to relocate (positive cost). -/
example : acost (fun _ => 1) egProg = 2 := by decide

/-- ★ callee-saves == caller-pays == acost prog, all EXACTLY 2 (the identity fires non-vacuously). -/
example :
    acost (fun _ => 1) (egCallee ++ egProg) - acost (fun _ => 1) egCallee = 2
  ∧ acost (fun _ => 1) (egProg ++ egCaller) - acost (fun _ => 1) egCaller = 2 := by decide

/-- ★ The total cost is invariant across the two placements (the theorem fires on the witness). -/
example : totalCost (fun _ => 1) egBd.calleeSide = totalCost (fun _ => 1) egBd.callerSide :=
  boundary_cost_invariant (fun _ => 1) egBd

/-- ★ Both placements genuinely RUN (not a vacuous none) and agree: entry `[]` ⇒ `some ([2,3], [])`.
    (PUSH 1,2,3 ⇒ [3,2,1]; SWAP ⇒ [2,3,1]; ROT ⇒ [1,2,3]; DROP ⇒ [2,3].) -/
example : run (egBd.calleeSide.1 ++ egBd.calleeSide.2) (([], []) : State Nat) = some ([2, 3], []) := by
  decide
example : run (egBd.callerSide.1 ++ egBd.callerSide.2) (([], []) : State Nat) = some ([2, 3], []) := by
  decide

/-- ★ The denotation invariance theorem fires on the witness. -/
example (st : State Nat) :
    run (egBd.calleeSide.1 ++ egBd.calleeSide.2) st = run (egBd.callerSide.1 ++ egBd.callerSide.2) st :=
  boundary_denote_invariant egBd st

-- N-block: two DIFFERENT blockings of the SAME flat program (shuffle at different boundaries).
private def blocking1 : List (List (Op Nat)) := [[Op.PUSH 1, Op.SWAP], [Op.DROP]]
private def blocking2 : List (List (Op Nat)) := [[Op.PUSH 1], [Op.SWAP, Op.DROP]]

/-- Same flat op-sequence (the SWAP is assigned to a different block). `Op` has a function-typed
    field (CALL) so it lacks `DecidableEq`; the two flattens are DEFINITIONALLY equal (`rfl`). -/
example : blocking1.flatten = blocking2.flatten := by rfl

/-- ★ N-block re-blocking is cost-invariant on the witness (both total 3). -/
example : (blocking1.map (acost (fun _ => 1))).sum = (blocking2.map (acost (fun _ => 1))).sum :=
  reblocking_cost_invariant (fun _ => 1) blocking1 blocking2 (by rfl)

example : (blocking1.map (acost (fun _ => 1))).sum = 3
        ∧ (blocking2.map (acost (fun _ => 1))).sum = 3 := by decide

-- Interface: TWO interface assignments (wire orders) of the SAME data-flow P=[1,2,3,4] → Q=[4,3,2,1].
-- full = [1,2,3] (3 moves) reverses P (NlcsFloor.witness_run). Splits pick different wires W.
/-- Assignment ι₁: W₁ = runMoves [1] P (callee does 1 move, caller does 2). -/
example : runMoves [1] ([1, 2, 3, 4] : Stack) = [2, 1, 3, 4] := by decide
/-- Assignment ι₂: W₂ = runMoves [1,2] P (callee does 2 moves, caller does 1). -/
example : runMoves [1, 2] ([1, 2, 3, 4] : Stack) = [3, 2, 1, 4] := by decide
/-- ★ The two interface assignments genuinely DIFFER (different wire orders) — non-vacuous. -/
example : runMoves [1] ([1, 2, 3, 4] : Stack) ≠ runMoves [1, 2] [1, 2, 3, 4] := by decide

/-- ★ Yet BOTH preserve the SAME data-flow Q = [4,3,2,1] AND cost the SAME total (3) — the
    interface-reassignment zero-sum theorem fires on each. -/
example :
    runMoves [2, 3] (runMoves [1] ([1, 2, 3, 4] : Stack)) = runMoves [1, 2, 3] [1, 2, 3, 4]
  ∧ acost (fun _ => 1) [1] + acost (fun _ => 1) [2, 3] = acost (fun _ => 1) [1, 2, 3] :=
  interface_reassignment_zero_sum (fun _ => 1) [1, 2, 3] [1] [2, 3] [1, 2, 3, 4] rfl
example :
    runMoves [3] (runMoves [1, 2] ([1, 2, 3, 4] : Stack)) = runMoves [1, 2, 3] [1, 2, 3, 4]
  ∧ acost (fun _ => 1) [1, 2] + acost (fun _ => 1) [3] = acost (fun _ => 1) [1, 2, 3] :=
  interface_reassignment_zero_sum (fun _ => 1) [1, 2, 3] [1, 2] [3] [1, 2, 3, 4] rfl

/-- Both assignments realize the same data-flow Q, and both cost 3 (numerically). -/
example :
    runMoves [2, 3] (runMoves [1] ([1, 2, 3, 4] : Stack)) = [4, 3, 2, 1]
  ∧ runMoves [3] (runMoves [1, 2] ([1, 2, 3, 4] : Stack)) = [4, 3, 2, 1] := by decide

/-! ## §9. SECONDARY TARGET — the HONEST NEGATIVE on a positive global BYTE floor.

    Does the total marshalling addressing admit a POSITIVE global byte lower bound (beyond the copy
    floor)? NO — it inherits the exact PICK/DROP evasion that killed the per-block byte floor
    (`MarshalFloor` adversarial audit). The conservation identity above is an INVARIANCE (relocation
    / re-blocking / interface reassignment cannot REDUCE the total), NOT a positive floor: it says
    the total is CONSERVED, not that it is bounded below by a data-flow invariant that every program
    must pay in BYTES.

    Concretely, at a boundary whose data-flow forces a deep-before-shallow consumption (so the
    move-based route pays ≥ 1 move), a WHOLE-VM program can realize the SAME net consumption with
    ZERO move ops by PICK-copying the deep value and dropping the buried original — beating any
    "global move-count floor > 0". Machine-checked over the REAL `Basic.step` VM (this is
    `MarshalFloor`'s audit, re-exhibited here at the whole-program consumption level to certify the
    NEGATIVE for the GLOBAL claim). -/

/-- MOVE route: 1 ROLL delivers the deep operand, then both are consumed — meets the move floor. -/
example : run [Op.ROLL 1, Op.DROP, Op.DROP] (([10, 20] : List Nat), ([] : List Nat)) = some ([], []) := by
  decide

/-- ★ THE EVASION (whole-VM): PICK-copy the deep `20` to top, consume the copy, consume `10`, then
    DROP the buried original — ZERO ROLL/SWAP/ROT. Beats any positive global MOVE-count byte floor.
    Machine-checked to consume `[10,20]` deep-first to empty. -/
example : run [Op.PICK 1, Op.DROP, Op.DROP, Op.DROP] (([10, 20] : List Nat), ([] : List Nat)) = some ([], []) := by
  decide

/-! ## §10. STRONGER NEGATIVE — a COPY can SUBSUME a REORDER ⇒ any ADDITIVE (copy+reorder) global
    byte floor is BEATEN. This closes the "maybe the BYTE floor survives even though the move-COUNT
    floor dies" hope adversarially, over the REAL `Basic.step` VM.

    §9 kills the move-COUNT floor. One might still hope for a BYTE floor of the form
    `copy_floor(D) + reorder_floor(inversions)` — the intuition being that the §9 PICK evasion pays
    an EXTRA `DROP` for the buried original (`MarshalFloor` audit: 2 marshalling bytes vs 1), so per
    forced inversion you always pay ≥ 1 byte. That intuition FAILS whenever the reordered value has
    FANOUT ≥ 2: then the "extra DROP" is NOT extra — it is the value's genuine SECOND consumption —
    so the SAME `PICK` that pays the (mandatory, copy-floor-charged) duplication ALSO delivers the
    value out-of-order for FREE. The reorder byte is absorbed into the copy byte; charging both
    DOUBLE-COUNTS. Hence `copy_floor + reorder_floor` is not a sound global byte floor.

    WITNESS DATA-FLOW. Entry `[10, 20]` (10 TOP, 20 at depth 1). Value `20` has FANOUT 2 (consumed
    twice) and is forced DEEP-FIRST (before `10`). `10` has fanout 1. -/

/-- Marshalling+copy byte weight: 1 for every reorder/duplication op (ROLL/SWAP/ROT/PICK/DUP/…),
    0 for pure consumption (`DROP`/`TWODROP`), constant push (`PUSH`), and node fire (`CALL`).
    These 0-weighted ops are the mandatory node emits / const pushes — NOT marshalling. -/
def wMC {α : Type} : Op α → Nat
  | Op.DROP => 0 | Op.TWODROP => 0 | Op.PUSH _ => 0 | Op.CALL _ _ => 0
  | _ => 1

/-- BASELINE (fanout-1 route): if `20` had fanout 1, the byte-minimal route is the MOVE
    `[ROLL 1, DROP, DROP]` — 1 marshalling byte (the ROLL), the PICK evasion here costs strictly
    MORE (extra DROP). This is the fanout-1 case where the reorder byte is genuinely paid. -/
example : run [Op.ROLL 1, Op.DROP, Op.DROP] (([10, 20] : List Nat), ([] : List Nat)) = some ([], [])
        ∧ acost (wMC (α := Nat)) [Op.ROLL 1, Op.DROP, Op.DROP] = 1 := by decide

/-- ★★ THE SUBSUMPTION WITNESS (fanout-2 route). ONE `PICK 1` copies `20` to the top: it (a) serves
    the MANDATORY fanout-2 duplication of `20` AND (b) delivers `20` out-of-order (deep-first) — the
    forced inversion — in the SAME byte. Consumption trace: `[10,20] →PICK→ [20,10,20] →DROP(20#1)→
    [10,20] →DROP(10)→ [20] →DROP(20#2)→ []`, so `20` is consumed BEFORE `10` (inversion realised)
    and consumed TWICE (fanout-2 realised). Marshalling+copy cost = 1 byte (the single PICK). -/
example :
    run [Op.PICK 1, Op.DROP, Op.DROP, Op.DROP] (([10, 20] : List Nat), ([] : List Nat)) = some ([], [])
  ∧ acost (wMC (α := Nat)) [Op.PICK 1, Op.DROP, Op.DROP, Op.DROP] = 1 := by decide

/-- Intermediate states certify the ORDER: `20` (copy) consumed first, then `10`, then `20` (orig).
    So the deep-before-shallow FORCED INVERSION is realised, AND `20` is consumed twice (fanout 2). -/
example :
    run [Op.PICK 1] (([10, 20] : List Nat), ([] : List Nat)) = some ([20, 10, 20], [])
  ∧ run [Op.PICK 1, Op.DROP] (([10, 20] : List Nat), ([] : List Nat)) = some ([10, 20], [])
  ∧ run [Op.PICK 1, Op.DROP, Op.DROP] (([10, 20] : List Nat), ([] : List Nat)) = some ([20], []) := by
  decide

/-- ★ THE ADDITIVE-FLOOR BEAT (numeric). For this data-flow the two SEPARATE sound bounds are:
    copy_floor = ⌈D/3⌉ with D = 1 duplication (20 fanout-2) ⇒ ⌈1/3⌉ = 1 (`PackedFloor.witness`-style);
    reorder_floor = n − LCS(entry, consumption) = 1 (the forced (10,20) inversion, `MarshalFloor`-style).
    An ADDITIVE global byte floor would charge `1 + 1 = 2`. The witness realises the FULL data-flow
    (duplication + inversion) with `1` marshalling+copy byte. `1 < 2` ⇒ the additive floor is BEATEN:
    a copy SUBSUMES a reorder, so the copy and reorder dimensions are NOT additive over the VM. -/
example : acost (wMC (α := Nat)) [Op.PICK 1, Op.DROP, Op.DROP, Op.DROP]
            < ((1 + 2) / 3 /- copy_floor ⌈1/3⌉ -/ + 1 /- reorder n−LCS -/) := by decide

/-! ★ HONEST CONCLUSION (reported, not overclaimed).
    • POSITIVE, SOUND, this file: the ZERO-SUM conservation identity (cost) + data-flow preservation
      (semantics), 2-block EXACT, generalized to the whole call graph as re-blocking invariance, and
      to interface reassignment as composite re-splitting. This PROVES cross-block scheduling and
      interface reassignment cannot win by RELOCATION — the §6/§9 empirics upgraded to theorem.
    • The only OTHER sound positive global bound is the COPY floor (`PackedFloor.packed_copy_floor`,
      ⌈D/3⌉), which is immune to PICK/DROP (PICK *is* the copy). The reordering/marshalling dimension
      has NO sound positive global BYTE floor: (a) the move-COUNT floor dies to PICK/DROP
      (`MarshalFloor` audit, §9), and (b) even the hoped-for BYTE floor `copy_floor + reorder_floor`
      DIES (§10) — a single PICK can SUBSUME a fanout-≥2 duplication AND an out-of-order delivery in
      ONE byte, so the copy and reorder dimensions are NON-ADDITIVE and the summed floor double-counts.
      No data-flow potential function lower-bounds the marshalling bytes every whole program must pay.
    • NET: un-dethronability of the marshalling remains EMPIRICAL (search-exhausted), now buttressed
      by a THEOREM that relocation/re-blocking/interface reassignment is zero-sum, but NOT by a
      positive global byte floor (which provably does not exist for the reordering dimension: the
      only sound positive global byte bound is the copy floor ⌈D/3⌉, which is DISJOINT from — not
      additive with — the marshalling). -/

end Conservation
end Recompiler
