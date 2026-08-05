/-
  CONTROL COMPOSITION + WHOLE-PROGRAM END-TO-END — the FINAL piece.

  `LeanBCH.Opt.Decompile` closes the PER-BLOCK bridge (`bridge_block`) and the per-block
  end-to-end (`end_to_end`): for one straight-line block accepted by the decompiler,
      run (emit (decompileBlock rawOps)) st = run rawOps st        (on the block's entry state).
  This file COMPOSES those over the `[Block | ctrl]` control structure that
  tools/singleton-recompiler/decompile.mjs produces, yielding the WHOLE-PROGRAM
  end-to-end theorem `run(optimize(program)) = run(program)` for programs the decompiler
  accepts, over an abstract value type `α` and an abstract branch predicate `isT : α → Bool`.

  ★ WHY A STRUCTURED MODEL (faithfulness): the flat `Basic.run` is a straight-line fold with
  NO control flow. decompile.mjs's control opcodes (IF/NOTIF/ELSE/ENDIF/BEGIN/UNTIL/VERIFY) are
  re-emitted VERBATIM between blocks, and the real VM BRANCHES on them. Modelling control ops as
  opaque no-ops in a flat fold would be UNFAITHFUL (it would not branch). So we model the program
  as a structured `Prog = List (Item)` where `Item` carries the nesting the flat bytecode's
  IF/ELSE/ENDIF + BEGIN/UNTIL drive, with a big-step semantics (`runProg`) that BRANCHES. Block
  leaves run their stored op-list via the flat `run`; that is exactly the real VM's behaviour on a
  straight-line segment. This nesting is FAITHFUL because decompile.mjs's reconciliation
  (`beginBlock` relabels the FULL stack as fresh slots at every boundary; branch-shape (a) and
  loop-invariance (b) checks) guarantees the flat control flow matches this structure.

  ★ NO FRAME/PASSTHROUGH GAP: `beginBlock()` sets `entryDepth = main.length` — each block is
  decompiled at the FULL current stack depth (the whole stack is relabeled `in i` / `ain i`), so
  a block CONSUMES and PRODUCES the entire stack. Hence at every block leaf the runtime state is
  EXACTLY `entryState M A` with `|M| = entryDepth`, `|A| = entryAlt`; `end_to_end` applies with no
  passthrough argument. The depth match is carried by the static `Shaped` judgment below (the
  Lean surfacing of decompile.mjs's depth tracking + its (a)/(b) fail-loud checks).

  Lean 4.31 core, NO mathlib.
-/
import LeanBCH.Opt.Decompile

namespace LeanBCH.Opt
open Op

/-- A structured program item — the `[Block | ctrl]` cover of decompile.mjs, with control
    NESTING made explicit (the flat IF/ELSE/ENDIF + BEGIN/UNTIL are re-expressed as the tree
    they delimit). `Prog α := List (Item α)`.
      • `block ops ed ea b` — a straight-line block: `ops` are RUN by the flat `run` (`ops`
        = rawOps for the original, `emit b` for the optimized); `b` is the decompiled DAG; `ed`/`ea`
        the entry depths decompile assigned (= the FULL stack depth at that boundary).
      • `ifte neg t e` — OP_IF/OP_NOTIF … OP_ELSE … OP_ENDIF: pops the top main value as a
        condition, runs the then-arm `t` when `(isT c) != neg` else the else-arm `e` (an
        IF-without-ELSE is `ifte neg t []`). The `neg` POLARITY flag distinguishes the two control
        opcodes: `neg = false` is OP_IF (0x63, then-arm on truthy); `neg = true` is OP_NOTIF (0x64,
        then-arm on FALSY). This is the fidelity fix — the real libauth VM branches OP_NOTIF on
        `!isT c`, so modelling both as `neg = false` computed the OPPOSITE branch for every NOTIF.
      • `loop body` — OP_BEGIN … OP_UNTIL: runs `body`, which leaves a condition on top; pops it,
        exits if truthy, else repeats.
      • `verify` — OP_VERIFY (and NUMEQUALVERIFY/EQUALVERIFY collapse to popping the cond): pops
        the top main value, aborting (`none`) if falsy. -/
inductive Item (α : Type) where
  | block (ops : List (Op α)) (ed ea : Nat) (b : Block α)
  | ifte  (neg : Bool) (thenB elseB : List (Item α))
  | loop  (body : List (Item α))
  | verify

abbrev Prog (α : Type) := List (Item α)

/- ★ THE OPTIMIZER: recompile every block leaf (`ops := emit b`), leave the control structure
   verbatim. Mirror of tools/singleton-recompiler/optimize.mjs: `flattenIdentity` with each
   block's rawOps replaced by its re-scheduled `emit b`. Structural mutual recursion over the
   nested list. -/
mutual
def optItem {α} [DecidableEq α] : Item α → Item α
  | .block _ ed ea b => .block (emit b) ed ea b
  | .ifte neg t e    => .ifte neg (optProg t) (optProg e)
  | .loop body       => .loop (optProg body)
  | .verify          => .verify
def optProg {α} [DecidableEq α] : Prog α → Prog α
  | []        => []
  | it :: rest => optItem it :: optProg rest
end

/- ★ THE STRUCTURED BIG-STEP SEMANTICS (branches on `isT`). Fuel bounds loop iteration (and, as
   an artefact of the single decreasing measure, structural descent); the end-to-end theorem is
   proven for ALL fuel, so terminating runs are fully covered (and non-terminating runs give
   `none = none`). Block leaves run the flat `run` (no fuel needed — straight-line). -/
mutual
def runProg {α} (isT : α → Bool) : Nat → Prog α → State α → Option (State α)
  | _,      [],         st => some st
  | 0,      _ :: _,     _  => none
  | fuel+1, it :: rest, st =>
      match runItem isT fuel it st with
      | some st' => runProg isT fuel rest st'
      | none     => none
  termination_by fuel _ _ => fuel*3 + 1
def runItem {α} (isT : α → Bool) : Nat → Item α → State α → Option (State α)
  | _,    .block ops _ _ _, st => run ops st
  | fuel, .ifte neg t e,    st =>
      match st with
      | (c :: m, a) => if (isT c) != neg then runProg isT fuel t (m, a) else runProg isT fuel e (m, a)
      | ([], _)     => none
  | fuel, .loop body,       st => runLoop isT fuel body st
  | _,    .verify,          st =>
      match st with
      | (c :: m, a) => if isT c then some (m, a) else none
      | ([], _)     => none
  termination_by fuel _ _ => fuel*3 + 2
def runLoop {α} (isT : α → Bool) : Nat → Prog α → State α → Option (State α)
  | 0,      _,    _  => none
  | fuel+1, body, st =>
      match runProg isT fuel body st with
      | some (c :: m, a) => if isT c then some (m, a) else runLoop isT fuel body (m, a)
      | some ([], _)     => none
      | none             => none
  termination_by fuel _ _ => fuel*3 + 0
end

/-! ### ★ THE `Shaped` JUDGMENT — the Lean surfacing of decompile.mjs's depth tracking + its
    fail-loud reconciliation checks. `Shaped prog dm da dm' da'` means: entered with main-depth
    `dm` / alt-depth `da`, `prog` is decompile-ACCEPTED and exits with main-depth `dm'` / alt-depth
    `da'`. Each constructor transcribes one decompile.mjs rule:
      • `nil`      — empty program is depth-neutral.
      • `block`    — `beginBlock` relabels the FULL stack ⇒ `ed = dm`, `ea = da`; the block must
        DECOMPILE (`decompileBlock … = some b`) and be `WellFormed`; its exit depths are
        `|b.exit|` / `|b.exitAlt|` (what `denote` produces), which the rest continues from.
      • `ifte`     — IF/NOTIF pops the cond (`1 ≤ dm`); both arms start at `(dm-1, da)` and — by
        branch-shape consistency (hardening (a)) — must leave the SAME `(tm, ta)`; rest continues
        from `(tm, ta)`. POLARITY-INDEPENDENT: `neg` only selects WHICH arm runs, not the exit
        depth (both arms have equal exit-depth), so the depth judgment is untouched by the flag.
      • `loop`     — BEGIN records `(dm, da)`; the body leaves the cond on top, so it exits at
        `(dm+1, da)`; UNTIL pops it and — by loop-invariance (hardening (b)) — the popped layout
        `(dm, da)` equals the BEGIN layout, so the loop is depth-neutral; rest continues from
        `(dm, da)`.
      • `verify`   — VERIFY pops the cond (`1 ≤ dm`); rest continues from `(dm-1, da)`. -/
inductive Shaped {α} [Inhabited α] : Prog α → Nat → Nat → Nat → Nat → Prop where
  | nil {dm da} : Shaped [] dm da dm da
  | block {raw ed ea b rest dm da dm' da'}
      (hed : ed = dm) (hea : ea = da)
      (hdec : decompileBlock raw ed ea = some b) (hwf : WellFormed b)
      (hrest : Shaped rest b.exit.length b.exitAlt.length dm' da') :
      Shaped (Item.block raw ed ea b :: rest) dm da dm' da'
  | ifte {neg t e rest dm da tm ta dm' da'}
      (hpos : 1 ≤ dm)
      (ht : Shaped t (dm-1) da tm ta)
      (he : Shaped e (dm-1) da tm ta)
      (hrest : Shaped rest tm ta dm' da') :
      Shaped (Item.ifte neg t e :: rest) dm da dm' da'
  | loop {body rest dm da dm' da'}
      (hbody : Shaped body dm da (dm+1) da)
      (hrest : Shaped rest dm da dm' da') :
      Shaped (Item.loop body :: rest) dm da dm' da'
  | verify {rest dm da dm' da'}
      (hpos : 1 ≤ dm)
      (hrest : Shaped rest (dm-1) da dm' da') :
      Shaped (Item.verify :: rest) dm da dm' da'

/-- `denote`'s exit main length is `|b.exit|` (it is `b.exit.map … |>.reverse`). -/
theorem denote_len_main {α} [Inhabited α] (b : Block α) (M A : List α) :
    (denote b M A).1.length = b.exit.length := by simp [denote]

/-- `denote`'s exit alt length is `|b.exitAlt|`. -/
theorem denote_len_alt {α} [Inhabited α] (b : Block α) (M A : List α) :
    (denote b M A).2.length = b.exitAlt.length := by simp [denote]

/-- ★ BLOCK-LEAF EQUALITY — at a `Shaped` block the runtime state IS the block's `entryState`
    (full-stack relabeling), so `end_to_end`/`bridge_block` fire: running the recompiled ops
    `emit b` equals running the original `raw`, both `= some (denote b M A)`. -/
theorem block_leaf {α} [DecidableEq α] [Inhabited α]
    (raw : List (Op α)) (ed ea : Nat) (b : Block α)
    (hdec : decompileBlock raw ed ea = some b) (hwf : WellFormed b)
    (st : State α) (hm : st.1.length = ed) (ha : st.2.length = ea) :
    run (emit b) st = run raw st ∧ run raw st = some (denote b st.1.reverse st.2.reverse) := by
  have hst : st = entryState st.1.reverse st.2.reverse := by
    simp [entryState]
  have hM : (st.1.reverse).length = ed := by rw [List.length_reverse]; exact hm
  have hA : (st.2.reverse).length = ea := by rw [List.length_reverse]; exact ha
  have hbr := bridge_block raw ed ea st.1.reverse st.2.reverse hM hA b hdec hwf
  have he2e := end_to_end raw ed ea st.1.reverse st.2.reverse hM hA b hdec hwf
  rw [← hst] at hbr he2e
  exact ⟨he2e, hbr⟩

/-! ### Targeted unfolding lemmas for the WF-recursive semantics (scrutinee made concrete so the
    internal `match` reduces). -/

theorem rp_nil {α} (isT : α → Bool) (fuel : Nat) (st : State α) :
    runProg isT fuel [] st = some st := by rw [runProg]
theorem rp_zero_cons {α} (isT : α → Bool) (it : Item α) (rest : Prog α) (st : State α) :
    runProg isT 0 (it :: rest) st = none := by rw [runProg]
theorem rp_some {α} (isT : α → Bool) (fuel : Nat) (it : Item α) (rest : Prog α) (st st' : State α)
    (h : runItem isT fuel it st = some st') :
    runProg isT (fuel+1) (it :: rest) st = runProg isT fuel rest st' := by rw [runProg, h]
theorem rp_none {α} (isT : α → Bool) (fuel : Nat) (it : Item α) (rest : Prog α) (st : State α)
    (h : runItem isT fuel it st = none) :
    runProg isT (fuel+1) (it :: rest) st = none := by rw [runProg, h]
theorem ri_block {α} (isT : α → Bool) (fuel : Nat) (ops : List (Op α)) (ed ea : Nat) (b : Block α) (st : State α) :
    runItem isT fuel (Item.block ops ed ea b) st = run ops st := by rw [runItem]
theorem ri_loop {α} (isT : α → Bool) (fuel : Nat) (body : Prog α) (st : State α) :
    runItem isT fuel (Item.loop body) st = runLoop isT fuel body st := by rw [runItem]
theorem ri_ifte {α} (isT : α → Bool) (fuel : Nat) (neg : Bool) (t e : Prog α) (c : α) (m a : List α) :
    runItem isT fuel (Item.ifte neg t e) (c :: m, a)
      = (if (isT c) != neg then runProg isT fuel t (m, a) else runProg isT fuel e (m, a)) := by rw [runItem]
theorem ri_verify {α} (isT : α → Bool) (fuel : Nat) (c : α) (m a : List α) :
    runItem isT fuel (Item.verify) (c :: m, a) = (if isT c then some (m, a) else none) := by rw [runItem]
theorem rl_zero {α} (isT : α → Bool) (body : Prog α) (st : State α) :
    runLoop isT 0 body st = none := by rw [runLoop]
theorem rl_some {α} (isT : α → Bool) (fuel : Nat) (body : Prog α) (st : State α) (c : α) (m a : List α)
    (h : runProg isT fuel body st = some (c :: m, a)) :
    runLoop isT (fuel+1) body st = (if isT c then some (m, a) else runLoop isT fuel body (m, a)) := by
  rw [runLoop, h]
theorem rl_none {α} (isT : α → Bool) (fuel : Nat) (body : Prog α) (st : State α)
    (h : runProg isT fuel body st = none) : runLoop isT (fuel+1) body st = none := by rw [runLoop, h]

theorem optProg_cons {α} [DecidableEq α] (it : Item α) (rest : Prog α) :
    optProg (it :: rest) = optItem it :: optProg rest := by rw [optProg]
theorem optItem_block {α} [DecidableEq α] (ops : List (Op α)) (ed ea : Nat) (b : Block α) :
    optItem (Item.block ops ed ea b) = Item.block (emit b) ed ea b := by rw [optItem]
theorem optItem_ifte {α} [DecidableEq α] (neg : Bool) (t e : Prog α) :
    optItem (Item.ifte neg t e) = Item.ifte neg (optProg t) (optProg e) := by rw [optItem]
theorem optItem_loop {α} [DecidableEq α] (body : Prog α) :
    optItem (Item.loop body) = Item.loop (optProg body) := by rw [optItem]
theorem optItem_verify {α} [DecidableEq α] :
    optItem (Item.verify : Item α) = Item.verify := by rw [optItem]

/-! ### ★★ THE WHOLE-PROGRAM COMPOSITION — one simultaneous induction on fuel proving both the
    program-list statement (QP) and the loop statement (QL). Both carry a run-EQUALITY and a
    depth-PRESERVATION conjunct (the depth is needed to feed the tail / the next iteration). Every
    `fuel+1` case reduces to facts at `fuel` (the induction hypothesis) — block leaves via
    `block_leaf`; `ifte`/`verify` pop the top and branch identically on both sides; `loop` unrolls,
    the body handled by QP-at-`fuel`, the tail iteration by QL-at-`fuel`. -/
theorem compose_all {α} [DecidableEq α] [Inhabited α] (isT : α → Bool) :
    ∀ fuel : Nat,
      (∀ prog dm da dm' da', Shaped prog dm da dm' da' →
        ∀ st : State α, st.1.length = dm → st.2.length = da →
          runProg isT fuel (optProg prog) st = runProg isT fuel prog st ∧
          ∀ st', runProg isT fuel prog st = some st' → st'.1.length = dm' ∧ st'.2.length = da')
    ∧ (∀ body dm da, Shaped body dm da (dm+1) da →
        ∀ st : State α, st.1.length = dm → st.2.length = da →
          runLoop isT fuel (optProg body) st = runLoop isT fuel body st ∧
          ∀ st', runLoop isT fuel body st = some st' → st'.1.length = dm ∧ st'.2.length = da) := by
  intro fuel
  induction fuel with
  | zero =>
    refine ⟨?_, ?_⟩
    · -- QP at fuel 0
      intro prog dm da dm' da' hs st hm ha
      cases hs with
      | nil => exact ⟨rfl, fun st' h => by rw [rp_nil] at h; injection h with h; subst h; exact ⟨hm, ha⟩⟩
      | block _ _ _ _ => exact ⟨by rw [optProg_cons, rp_zero_cons, rp_zero_cons], fun st' h => by rw [rp_zero_cons] at h; exact absurd h (by simp)⟩
      | ifte _ _ _ => exact ⟨by rw [optProg_cons, rp_zero_cons, rp_zero_cons], fun st' h => by rw [rp_zero_cons] at h; exact absurd h (by simp)⟩
      | loop _ _ => exact ⟨by rw [optProg_cons, rp_zero_cons, rp_zero_cons], fun st' h => by rw [rp_zero_cons] at h; exact absurd h (by simp)⟩
      | verify _ _ => exact ⟨by rw [optProg_cons, rp_zero_cons, rp_zero_cons], fun st' h => by rw [rp_zero_cons] at h; exact absurd h (by simp)⟩
    · -- QL at fuel 0
      intro body dm da _ st _ _
      exact ⟨by rw [rl_zero, rl_zero], fun st' h => by rw [rl_zero] at h; exact absurd h (by simp)⟩
  | succ fuel ih =>
    obtain ⟨ihP, ihL⟩ := ih
    refine ⟨?_, ?_⟩
    · -- QP at fuel+1
      intro prog dm da dm' da' hs st hm ha
      cases hs with
      | nil =>
        exact ⟨rfl, fun st' h => by rw [rp_nil] at h; injection h with h; subst h; exact ⟨hm, ha⟩⟩
      | @block raw ed ea b rest _ _ dm' da' hed hea hdec hwf hrest =>
        subst hed hea
        -- both leaves reduce to `some (denote b …)`; continue with `rest` via ihP
        obtain ⟨hEq, hDen⟩ := block_leaf raw ed ea b hdec hwf st hm ha
        have hsdM : (denote b st.1.reverse st.2.reverse).1.length = b.exit.length := denote_len_main b _ _
        have hsdA : (denote b st.1.reverse st.2.reverse).2.length = b.exitAlt.length := denote_len_alt b _ _
        have hriO : runItem isT fuel (Item.block raw ed ea b) st
                  = some (denote b st.1.reverse st.2.reverse) := by rw [ri_block]; exact hDen
        have hriE : runItem isT fuel (Item.block (emit b) ed ea b) st
                  = some (denote b st.1.reverse st.2.reverse) := by rw [ri_block, hEq]; exact hDen
        obtain ⟨hrec, hpres⟩ := ihP rest _ _ dm' da' hrest _ hsdM hsdA
        refine ⟨?_, ?_⟩
        · rw [optProg_cons, optItem_block, rp_some _ _ _ _ _ _ hriE, rp_some _ _ _ _ _ _ hriO, hrec]
        · intro st' h; rw [rp_some _ _ _ _ _ _ hriO] at h; exact hpres st' h
      | @ifte neg t e rest dm da tm ta dm' da' hpos ht he hrest =>
        -- pop the cond: st.1 nonempty since |st.1| = dm ≥ 1
        obtain ⟨s1, s2⟩ := st
        cases s1 with
        | nil => simp only [List.length_nil] at hm; omega
        | cons c m =>
          simp only [List.length_cons] at hm
          have hmlen : m.length = dm - 1 := by omega
          -- item-level equality + depth, for whichever branch `(isT c) != neg` selects.
          -- POLARITY-SYMMETRIC: both arms exit at `(tm, ta)` (`ht`/`he`), so whichever the flag
          -- picks, the recompiler equivalence + depth conjuncts hold — generalized over `neg`.
          have hitem : runItem isT fuel (Item.ifte neg (optProg t) (optProg e)) (c :: m, s2)
                     = runItem isT fuel (Item.ifte neg t e) (c :: m, s2)
                   ∧ ∀ st', runItem isT fuel (Item.ifte neg t e) (c :: m, s2) = some st' →
                       st'.1.length = tm ∧ st'.2.length = ta := by
            rw [ri_ifte, ri_ifte]
            by_cases hcond : ((isT c) != neg) = true
            · simp only [hcond, if_true]
              obtain ⟨hrecT, hpresT⟩ := ihP t _ _ tm ta ht (m, s2) hmlen ha
              exact ⟨hrecT, hpresT⟩
            · simp only [hcond]
              obtain ⟨hrecE, hpresE⟩ := ihP e _ _ tm ta he (m, s2) hmlen ha
              exact ⟨hrecE, hpresE⟩
          obtain ⟨hitemEq, hitemPres⟩ := hitem
          -- now dispatch on whether the item yields some/none
          cases hri : runItem isT fuel (Item.ifte neg t e) (c :: m, s2) with
          | none =>
            refine ⟨?_, ?_⟩
            · rw [optProg_cons, optItem_ifte, rp_none _ _ _ _ _ (by rw [hitemEq]; exact hri), rp_none _ _ _ _ _ hri]
            · intro st' h; rw [rp_none _ _ _ _ _ hri] at h; exact absurd h (by simp)
          | some st2 =>
            obtain ⟨h2m, h2a⟩ := hitemPres st2 hri
            obtain ⟨hrec, hpres⟩ := ihP rest _ _ dm' da' hrest st2 h2m h2a
            refine ⟨?_, ?_⟩
            · rw [optProg_cons, optItem_ifte, rp_some _ _ _ _ _ _ (by rw [hitemEq]; exact hri),
                  rp_some _ _ _ _ _ _ hri, hrec]
            · intro st' h; rw [rp_some _ _ _ _ _ _ hri] at h; exact hpres st' h
      | @loop body rest dm da dm' da' hbody hrest =>
        obtain ⟨hlrec, hlpres⟩ := ihL body _ _ hbody st hm ha
        have hriO : runItem isT fuel (Item.loop body) st = runLoop isT fuel body st := ri_loop _ _ _ _
        have hriE : runItem isT fuel (Item.loop (optProg body)) st = runLoop isT fuel (optProg body) st := ri_loop _ _ _ _
        cases hrl : runLoop isT fuel body st with
        | none =>
          refine ⟨?_, ?_⟩
          · rw [optProg_cons, optItem_loop,
                rp_none _ _ _ _ _ (by rw [hriE, hlrec]; exact hrl), rp_none _ _ _ _ _ (by rw [hriO]; exact hrl)]
          · intro st' h; rw [rp_none _ _ _ _ _ (by rw [hriO]; exact hrl)] at h; exact absurd h (by simp)
        | some st2 =>
          obtain ⟨h2m, h2a⟩ := hlpres st2 hrl
          obtain ⟨hrec, hpres⟩ := ihP rest _ _ dm' da' hrest st2 h2m h2a
          refine ⟨?_, ?_⟩
          · rw [optProg_cons, optItem_loop, rp_some _ _ _ _ _ _ (by rw [hriE, hlrec]; exact hrl),
                rp_some _ _ _ _ _ _ (by rw [hriO]; exact hrl), hrec]
          · intro st' h; rw [rp_some _ _ _ _ _ _ (by rw [hriO]; exact hrl)] at h; exact hpres st' h
      | @verify rest dm da dm' da' hpos hrest =>
        obtain ⟨s1, s2⟩ := st
        cases s1 with
        | nil => simp only [List.length_nil] at hm; omega
        | cons c m =>
          simp only [List.length_cons] at hm
          have hmlen : m.length = dm - 1 := by omega
          have hriE : runItem isT fuel (Item.verify) (c :: m, s2)
                    = (if isT c then some (m, s2) else none) := ri_verify _ _ _ _ _
          by_cases hcond : isT c = true
          · have hri : runItem isT fuel (Item.verify) (c :: m, s2) = some (m, s2) := by
              rw [hriE]; simp only [hcond, if_true]
            obtain ⟨hrec, hpres⟩ := ihP rest _ _ dm' da' hrest (m, s2) hmlen ha
            refine ⟨?_, ?_⟩
            · rw [optProg_cons, optItem_verify, rp_some _ _ _ _ _ _ hri, rp_some _ _ _ _ _ _ hri, hrec]
            · intro st' h; rw [rp_some _ _ _ _ _ _ hri] at h; exact hpres st' h
          · have hri : runItem isT fuel (Item.verify) (c :: m, s2) = none := by
              rw [hriE]; simp only [hcond, Bool.false_eq_true, if_false]
            refine ⟨?_, ?_⟩
            · rw [optProg_cons, optItem_verify, rp_none _ _ _ _ _ hri, rp_none _ _ _ _ _ hri]
            · intro st' h; rw [rp_none _ _ _ _ _ hri] at h; exact absurd h (by simp)
    · -- QL at fuel+1
      intro body dm da hbody st hm ha
      obtain ⟨hbrec, hbpres⟩ := ihP body _ _ (dm+1) da hbody st hm ha
      cases hrp : runProg isT fuel body st with
      | none =>
        refine ⟨?_, ?_⟩
        · rw [rl_none _ _ _ _ (by rw [hbrec]; exact hrp), rl_none _ _ _ _ hrp]
        · intro st' h; rw [rl_none _ _ _ _ hrp] at h; exact absurd h (by simp)
      | some st2 =>
        obtain ⟨h2m, h2a⟩ := hbpres st2 hrp
        -- st2.1 has length dm+1 ≥ 1 ⇒ nonempty
        obtain ⟨p1, p2⟩ := st2
        cases p1 with
        | nil => simp only [List.length_nil] at h2m; omega
        | cons c m =>
          simp only [List.length_cons] at h2m
          have hmlen : m.length = dm := by omega
          have hrpE : runProg isT fuel (optProg body) st = some (c :: m, p2) := by rw [hbrec]; exact hrp
          by_cases hcond : isT c = true
          · refine ⟨?_, ?_⟩
            · rw [rl_some _ _ _ _ _ _ _ hrpE, rl_some _ _ _ _ _ _ _ hrp]
              simp only [hcond, if_true]
            · intro st' h
              rw [rl_some _ _ _ _ _ _ _ hrp] at h
              simp only [hcond, if_true] at h
              injection h with h; subst h; exact ⟨hmlen, h2a⟩
          · obtain ⟨hlrec, hlpres⟩ := ihL body _ _ hbody (m, p2) hmlen h2a
            refine ⟨?_, ?_⟩
            · rw [rl_some _ _ _ _ _ _ _ hrpE, rl_some _ _ _ _ _ _ _ hrp]
              simp only [hcond, Bool.false_eq_true, if_false]
              exact hlrec
            · intro st' h
              rw [rl_some _ _ _ _ _ _ _ hrp] at h
              simp only [hcond, Bool.false_eq_true, if_false] at h
              exact hlpres st' h

/-- ★★★ WHOLE-PROGRAM END-TO-END — for a decompile-accepted (`Shaped`) program entered at the
    matching stack depth, running the RECOMPILED program (`optProg`: every block leaf replaced by
    `emit ∘ decompileBlock`, control re-emitted verbatim) equals running the ORIGINAL program, on
    ALL inputs, ALL fuel, over an abstract value type `α` and abstract branch predicate `isT`.

    This composes the per-block bridge (`Decompile.bridge_block`/`end_to_end`, 0-sorry) over the
    full IF/ELSE/ENDIF + BEGIN/UNTIL + VERIFY control structure, closing the verified byte-recompiler
    correctness chain end-to-end at the whole-program level. -/
theorem whole_program_end_to_end {α} [DecidableEq α] [Inhabited α] (isT : α → Bool)
    (prog : Prog α) (dm da dm' da' : Nat) (hs : Shaped prog dm da dm' da')
    (fuel : Nat) (st : State α) (hm : st.1.length = dm) (ha : st.2.length = da) :
    runProg isT fuel (optProg prog) st = runProg isT fuel prog st :=
  ((compose_all isT fuel).1 prog dm da dm' da' hs st hm ha).1

/-! ### ★ NON-VACUITY WITNESS — a concrete whole PROGRAM (a real CALL block THEN an IF/ELSE) that
    is genuinely `Shaped`, so `whole_program_end_to_end` provably FIRES; plus a witness that the
    semantics genuinely BRANCHES (the two arms of an IF give different results), guarding against a
    trivial/non-branching model. -/

/-- `[a,b] ↦ [a+b]`. -/
private def addSem : List Nat → List Nat := fun l => [l.headD 0 + l.tail.headD 0]
/-- PUSH 3; PUSH 4; CALL 2 addSem. -/
private def egOps : List (Op Nat) := [Op.PUSH 3, Op.PUSH 4, Op.CALL 2 addSem]
/-- The block the decompiler produces for `egOps` (one `addSem` node over two consts). -/
private def egB : Block Nat :=
  { entryDepth := 0, entryAlt := 0,
    nodes := [⟨0, ⟨2, 1, addSem⟩, [Ref.const 3 false, Ref.const 4 false]⟩],
    exit := [Ref.out 0 0], exitAlt := [] }

private theorem egB_dec : decompileBlock egOps 0 0 = some egB := rfl

private theorem egB_wf : WellFormed egB := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · refine ⟨fun r hr => ?_, trivial⟩
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hr
    rcases hr with rfl | rfl <;> trivial
  · intro r hr; simp only [egB, List.mem_singleton] at hr; subst hr; show (0 : Nat) ∈ [0]; simp
  · intro r hr; simp only [egB, List.not_mem_nil] at hr
  · simp [egB]
  · intro n hn; simp only [egB, List.mem_singleton] at hn; subst hn; rfl
  · intro n hn l _; simp only [egB, List.mem_singleton] at hn; subst hn; rfl
  · intro nid j hmem nd hnd hid
    simp only [egB, List.mem_singleton] at hnd; subst hnd; show j < 1
    simp only [egB, List.flatMap_cons, List.flatMap_nil, List.append_nil,
      List.mem_append, List.mem_cons, List.not_mem_nil, or_false,
      reduceCtorEq, false_or, Ref.out.injEq] at hmem
    omega

/-- ★ A whole program: run the CALL block (⇒ `[7]`), then an IF/ELSE (both arms empty, popping the
    `7` cond). Genuinely `Shaped` from `(0,0)` to `(0,0)` — every conjunct discharged. -/
private def egProg : Prog Nat := [Item.block egOps 0 0 egB, Item.ifte false [] []]

private theorem egProg_shaped : Shaped egProg 0 0 0 0 :=
  .block rfl rfl egB_dec egB_wf (.ifte (Nat.le_refl 1) .nil .nil .nil)

/-- ★ CAPSTONE (whole-program): the recompiled program run = the original program run, on the
    concrete `egProg`, for ANY branch predicate and ANY (sufficient) fuel — every hypothesis of
    `whole_program_end_to_end` discharged (non-vacuous). -/
example (isT : Nat → Bool) (fuel : Nat) :
    runProg isT fuel (optProg egProg) ([], []) = runProg isT fuel egProg ([], []) :=
  whole_program_end_to_end isT egProg 0 0 0 0 egProg_shaped fuel ([], []) rfl rfl

/-- ★ THE SEMANTICS GENUINELY BRANCHES: the SAME program yields DIFFERENT results under a cond that
    is true vs false (then-arm empty ⇒ `some`; else-arm `verify` underflows the emptied stack ⇒
    `none`). Guards against a non-branching (hence vacuous) control model. (`runProg` is WF-recursive
    so it does not reduce under `decide`; we drive it with the unfolding lemmas.) -/
private def branchProg : Prog Nat := [Item.ifte false [] [Item.verify]]

example : runProg (· == 1) 4 branchProg ([1, 9], []) = some ([9], []) := by
  have h1 : runItem (· == 1) 3 (Item.ifte false [] [Item.verify]) ([1, 9], []) = some ([9], []) := by
    rw [ri_ifte]
    simp only [beq_self_eq_true, show (true != false) = true from rfl, if_true, rp_nil]
  show runProg (· == 1) (3+1) [Item.ifte false [] [Item.verify]] ([1, 9], []) = some ([9], [])
  rw [rp_some _ _ _ _ _ _ h1, rp_nil]

example : runProg (· == 1) 4 branchProg ([0, 9], []) = none := by
  have hv : runItem (· == 1) 2 Item.verify ([9], []) = none := by
    rw [ri_verify]; simp only [show ((9 : Nat) == 1) = false from rfl, Bool.false_eq_true, if_false]
  have h1 : runItem (· == 1) 3 (Item.ifte false [] [Item.verify]) ([0, 9], []) = none := by
    rw [ri_ifte]
    simp only [show ((0 : Nat) == 1) = false from rfl, show (false != false) = false from rfl,
      Bool.false_eq_true, if_false]
    rw [rp_none _ _ _ _ _ hv]
  show runProg (· == 1) (3+1) [Item.ifte false [] [Item.verify]] ([0, 9], []) = none
  rw [rp_none _ _ _ _ _ h1]

/-- ★ THE POLARITY GENUINELY INVERTS (NOTIF fidelity witness): the SAME condition value drives
    OPPOSITE arms under `neg = false` (OP_IF) vs `neg = true` (OP_NOTIF). Here cond `1` is truthy:
    OP_IF runs the then-arm (empty ⇒ `some`), OP_NOTIF runs the else-arm (`verify` on the emptied
    stack ⇒ `none`). This guards against the pre-fix bug where NOTIF was modelled as IF. -/
private def notifProg : Prog Nat := [Item.ifte true [] [Item.verify]]

example : runProg (· == 1) 4 notifProg ([1, 9], []) = none := by
  have hv : runItem (· == 1) 2 Item.verify ([9], []) = none := by
    rw [ri_verify]; simp only [show ((9 : Nat) == 1) = false from rfl, Bool.false_eq_true, if_false]
  have h1 : runItem (· == 1) 3 (Item.ifte true [] [Item.verify]) ([1, 9], []) = none := by
    rw [ri_ifte]
    simp only [beq_self_eq_true, show (true != true) = false from rfl, Bool.false_eq_true, if_false]
    rw [rp_none _ _ _ _ _ hv]
  show runProg (· == 1) (3+1) [Item.ifte true [] [Item.verify]] ([1, 9], []) = none
  rw [rp_none _ _ _ _ _ h1]

end LeanBCH.Opt
