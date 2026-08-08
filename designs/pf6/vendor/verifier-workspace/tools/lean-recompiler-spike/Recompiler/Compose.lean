/-
  PASS-2 DAG-SCHEDULER — END-TO-END COMPOSITION of the step-lemmas into the top theorem
  `run (emit b) (entryState M A) = some (denote b M A)` (for ANY valid topological order —
  correctness is decoupled from the byte-optimising heuristic, which only reorders nodes).

  ARCHITECTURE (this file). The whole emitter `scheduleBlock` is the composition of FOUR
  phases over the seeded model state:
        seedState → drainPhase → nodesPhase → exitAltPhase → emitExitMain
  Each phase is a `StepOk` one-step-refinement (StepLemmas.lean); `StepOk.trans` folds them
  into `schedule_stepOk : StepOk (seedState b) (scheduleBlock b)`. The base case
  `inv_entry` (Simulation.lean) seeds the invariant; `final_readout` reads the exit layout
  off the invariant at the end. The reduction `schedule_refines` then follows purely.

  ★ WHAT IS MACHINE-CHECKED HERE (0 sorry):
    • the REDUCTION `schedule_refines ⟸ schedule_stepOk + final_readout` (pure plumbing);
    • the COMPOSITION `schedule_stepOk` = `StepOk.trans` over the four phases;
    • the generic `stepOk_foldl` combinator (fold of per-element StepOks);
    • the ENTIRE DRAIN PHASE `drain_stepOk` (FROMALT fold) — `fromalt_stepOk` + `drainFold_stepOk`;
    • `final_readout` reduced to the two exit read-off lemmas;
    • the ALT-STACK STRUCTURAL BOOKKEEPING (`*_Salt` lemmas) closing `final_readout_alt` (F4b):
      main-side primitives leave `Salt`, the DRAIN fold empties it, the EXIT-ALT fold deposits
      exactly the exit-alt tokens — so the final alt stack reads out to the exit-alt DAG layout.
  So the scheduler is CORRECT-BY-CONSTRUCTION modulo a small, named, precisely-stated
  frontier (see the `sorry`s below), each a genuine lemma — NOT the top theorem itself.

  ★ THE RESIDUAL FRONTIER (the honest `sorry`s, each isolated):
    (F1) `nodes_stepOk`   — per-node emission preserves `Inv`. Needs (i) the HOME/DEMAND
         LIVENESS invariant (every still-needed ref has a non-transient home in `S`, and
         `use` counts its remaining uses so MOVE fires only on the last use) threaded across
         the node fold, and (ii) the DENOTATION LINK feeding `emitCall_stepOk.hout`
         (`n.op.sem (n.ins.map dRef) = blockEnv … n.id`, from `denoteNodes` + topo order +
         distinct ids) and the operand-layout `hS` (materialize fold leaves top-k = operands).
    (F2) `exitAlt_stepOk` — exit-alt deposit preserves `Inv` (needs homes for exitAlt refs).
    (F3) `arrange_stepOk` — final main arrange (matchPrefix + build + stale-tail delete)
         preserves `Inv`. ★ THE ARRANGE MACHINERY IS NOW PROVEN 0-sorry OFF THE R4 INVARIANT
         (`emitExitMain_stepOk`, below): the exit-build fold (`buildFold_stepOk`), the stale-tail
         delete fold (`delFold_stepOk`), and the full depth/length arithmetic are machine-checked.
         The step reduces to the SINGLE residual liveness fact `∀ r ∈ b.exit, RefHasHome
         (exitAltPhase b) r` — R4 holding after the (still-open) node + exit-alt phases — which is
         the honest remaining `sorry` (it threads R4 across F1/F2; see `arrange_stepOk`).
    (F4a) `final_readout_main` — the final MAIN stack reads out to the exit DAG layout
         (the matchPrefix / arrange bookkeeping; downstream of the liveness invariant).
    [F4b `final_readout_alt` is now PROVEN — see below; it needed only structural `Salt` tracking.]
  F1–F4a are downstream of ONE invariant (the home/demand liveness map) — getting that
  invariant right (per the doctrine, ~80% of a simulation proof) closes them together.

  Lean 4.31 core, NO mathlib.
-/
import Recompiler.StepLemmas

namespace Recompiler
open Op

/-! ### Phase decomposition of `scheduleBlock` (mirrors Scheduler.lean exactly). -/

/-- The seeded emitter state (entry main/alt slots, empty ops, initial demand map). -/
def seedState [DecidableEq α] (b : Block α) : ModelState α :=
  { ops  := []
  , S    := (List.range b.entryDepth).map (fun i => (⟨Token.inTok i, false⟩ : Entry α))
  , Salt := (List.range b.entryAlt).map   (fun i => (⟨Token.ainTok i, false⟩ : Entry α))
  , use  := demand b (altPassthrough b) }

/-- One entry-alt drain step (FROMALT): pop alt-top `ainTok k`, push it on main. -/
def drainStep (m : ModelState α) (k : Nat) : ModelState α :=
  { m with ops  := m.ops ++ [Op.FROMALT]
         , S    := m.S ++ [⟨Token.ainTok k, false⟩]
         , Salt := m.Salt.dropLast }

/-- Phase 1 — drain entry alt to main (unless passthrough). -/
def drainPhase [DecidableEq α] (b : Block α) : ModelState α :=
  bif altPassthrough b then seedState b
  else (List.range b.entryAlt).reverse.foldl drainStep (seedState b)

/-- Phase 2 — emit nodes in the block's topological order. -/
def nodesPhase [DecidableEq α] (b : Block α) : ModelState α :=
  b.nodes.foldl (fun m n => emitNode n m) (drainPhase b)

/-- One exit-alt deposit step (materialize ref, then TOALT). -/
def exitAltStep [DecidableEq α] (m : ModelState α) (r : Ref α) : ModelState α :=
  let m' := emitFetch r m
  { m' with ops  := m'.ops ++ [Op.TOALT]
          , S    := m'.S.dropLast
          , Salt := m'.Salt ++ [⟨tokenOf r, false⟩] }

/-- Phase 3 — deposit exit-alt refs (unless passthrough). -/
def exitAltPhase [DecidableEq α] (b : Block α) : ModelState α :=
  bif altPassthrough b then nodesPhase b
  else b.exitAlt.foldl exitAltStep (nodesPhase b)

/-- `scheduleBlock` IS the four phases followed by the main arrange (definitional). -/
theorem scheduleBlock_eq [DecidableEq α] (b : Block α) :
    scheduleBlock b = emitExitMain b (exitAltPhase b) := rfl

/-! ### ALT-STACK STRUCTURAL BOOKKEEPING (0 sorry — closes F4b `final_readout_alt`).
    The alt stack `Salt` is threaded through the four phases by a handful of purely STRUCTURAL
    facts (no liveness needed): every main-side primitive (`emitFetch`, `emitNode`,
    `emitBuildRef`, `emitExitMain`) leaves `Salt` untouched; the DRAIN fold empties it; the
    EXIT-ALT fold appends one `⟨tokenOf r, false⟩` per exit-alt ref. Reading that final `Salt`
    out gives exactly the exit-alt DAG layout. -/

/-- A fold whose step function preserves `Salt` preserves `Salt` overall. -/
theorem foldl_Salt_invariant {α β} (g : ModelState α → β → ModelState α)
    (hg : ∀ (m : ModelState α) (x : β), (g m x).Salt = m.Salt) :
    ∀ (l : List β) (ms : ModelState α), (l.foldl g ms).Salt = ms.Salt := by
  intro l
  induction l with
  | nil => intro ms; rfl
  | cons x xs ih => intro ms; rw [List.foldl_cons, ih (g ms x), hg ms x]

/-- `eagerDrop` only DROPs main-stack items; `Salt` is invariant. -/
theorem eagerDrop_Salt {α} [DecidableEq α] (fuel : Nat) (ms : ModelState α) :
    (eagerDrop fuel ms).Salt = ms.Salt := by
  induction fuel generalizing ms with
  | zero => rfl
  | succ fuel ih =>
      unfold eagerDrop
      split
      · rfl
      · split
        · rfl
        · split
          · rw [ih]
          · rfl

/-- `emitFetch` (materialize an operand) touches only `ops`/`S`/`use`; `Salt` is invariant. -/
theorem emitFetch_Salt {α} [DecidableEq α] (r : Ref α) (ms : ModelState α) :
    (emitFetch r ms).Salt = ms.Salt := by
  cases r with
  | inp i =>
      simp only [emitFetch]
      split
      · rfl
      · split <;> rfl
  | ainp i =>
      simp only [emitFetch]
      split
      · rfl
      · split <;> rfl
  | out nid j =>
      simp only [emitFetch]
      split
      · rfl
      · split <;> rfl
  | const v cse =>
      cases cse with
      | false => rfl
      | true =>
          simp only [emitFetch]
          split
          · rfl
          · split <;> rfl

/-- `emitBuildRef` (exit build) touches only `ops`/`S`; `Salt` is invariant. -/
theorem emitBuildRef_Salt {α} [DecidableEq α] (r : Ref α) (ms : ModelState α) :
    (emitBuildRef r ms).Salt = ms.Salt := by
  cases r with
  | inp i => simp only [emitBuildRef]; split <;> rfl
  | ainp i => simp only [emitBuildRef]; split <;> rfl
  | out nid j => simp only [emitBuildRef]; split <;> rfl
  | const v cse =>
      cases cse with
      | false => rfl
      | true => simp only [emitBuildRef]; split <;> rfl

/-- `emitNode` (CSE-setup fold ∘ operand-materialize fold ∘ CALL ∘ eager-drop) leaves `Salt`. -/
theorem emitNode_Salt {α} [DecidableEq α] (n : Node α) (ms : ModelState α) :
    (emitNode n ms).Salt = ms.Salt := by
  unfold emitNode
  rw [eagerDrop_Salt]
  -- (record update over the emitFetch-fold over the CSE-fold).Salt
  change (n.ins.foldl (fun m inp => emitFetch inp m) _).Salt = ms.Salt
  rw [foldl_Salt_invariant (fun m inp => emitFetch inp m) (fun m x => emitFetch_Salt x m)]
  change (n.ins.foldl _ ms).Salt = ms.Salt
  refine foldl_Salt_invariant _ (fun m x => ?_) n.ins ms
  cases x with
  | const v cse =>
      cases cse with
      | true =>
          dsimp only
          split
          · rfl
          · split <;> rfl
      | false => rfl
  | _ => rfl

/-- `emitExitMain` (exit build fold + stale-tail delete fold) leaves `Salt`. -/
theorem emitExitMain_Salt {α} [DecidableEq α] (b : Block α) (ms : ModelState α) :
    (emitExitMain b ms).Salt = ms.Salt := by
  have hdel : ∀ (q : Nat) (l : List Nat) (m : ModelState α),
      (l.foldl (fun (m : ModelState α) (_ : Nat) =>
        { m with ops := m.ops ++ delOps q,
                 S := m.S.eraseIdx (m.S.length - 1 - q) }) m).Salt = m.Salt :=
    fun q l m => foldl_Salt_invariant
      (fun (m : ModelState α) (_ : Nat) =>
        { m with ops := m.ops ++ delOps q, S := m.S.eraseIdx (m.S.length - 1 - q) })
      (fun m _ => rfl) l m
  have hbuild : ∀ (l : List (Ref α)) (m : ModelState α),
      (l.foldl (fun m r => emitBuildRef r m) m).Salt = m.Salt :=
    fun l m => foldl_Salt_invariant _ (fun m x => emitBuildRef_Salt x m) l m
  unfold emitExitMain
  rw [hdel, hbuild]

/-- One exit-alt deposit appends exactly `⟨tokenOf r, false⟩` to `Salt` (main-side is `emitFetch`
    + a top-consume, alt-side is the TOALT push). -/
theorem exitAltStep_Salt {α} [DecidableEq α] (ms : ModelState α) (r : Ref α) :
    (exitAltStep ms r).Salt = ms.Salt ++ [(⟨tokenOf r, false⟩ : Entry α)] := by
  show (emitFetch r ms).Salt ++ [(⟨tokenOf r, false⟩ : Entry α)] = _
  rw [emitFetch_Salt]

/-- The whole exit-alt deposit fold appends `map (⟨tokenOf ·, false⟩)` to `Salt`. -/
theorem exitAltFold_Salt {α} [DecidableEq α] (l : List (Ref α)) (ms : ModelState α) :
    (l.foldl exitAltStep ms).Salt
      = ms.Salt ++ l.map (fun r => (⟨tokenOf r, false⟩ : Entry α)) := by
  induction l generalizing ms with
  | nil => simp
  | cons x xs ih =>
      rw [List.foldl_cons, ih (exitAltStep ms x), exitAltStep_Salt ms x,
          List.map_cons, List.append_assoc, List.cons_append, List.nil_append]

/-- The DRAIN fold empties `Salt` when its length matches the number of FROMALT steps. -/
theorem drainFold_Salt {α} [DecidableEq α] :
    ∀ (l : List Nat) (ms : ModelState α), ms.Salt.length = l.length →
      (l.foldl drainStep ms).Salt = [] := by
  intro l
  induction l with
  | nil =>
      intro ms h
      cases hh : ms.Salt with
      | nil => rw [List.foldl_nil]; exact hh
      | cons x xs => rw [hh] at h; simp at h
  | cons y ys ih =>
      intro ms h
      rw [List.foldl_cons]
      apply ih
      show (ms.Salt.dropLast).length = ys.length
      rw [List.length_dropLast, h]
      simp

/-! ### Generic composition combinator: a fold of per-element StepOks is a StepOk.
    `P` is an emitter-state invariant preserved by each step (e.g. the home/demand liveness
    invariant); this is the reusable engine that turns the per-node and per-ref step-lemmas
    into the whole-phase refinement. -/
theorem stepOk_foldl {α β} [Inhabited α] {M A : List α} {envF : Env α}
    (g : ModelState α → β → ModelState α) (P : ModelState α → Prop)
    (hg : ∀ m x, P m → StepOk M A envF m (g m x) ∧ P (g m x)) :
    ∀ (l : List β) (ms : ModelState α), P ms → StepOk M A envF ms (l.foldl g ms) := by
  intro l
  induction l with
  | nil => intro ms _; exact StepOk.refl M A envF ms
  | cons x xs ih =>
      intro ms hP
      rw [List.foldl_cons]
      obtain ⟨h1, hP1⟩ := hg ms x hP
      exact h1.trans (ih (g ms x) hP1)

/-! ### DRAIN PHASE — fully proven (0 sorry). -/

/-- BUILDER: a FROMALT step. The alt stack is `Sa ++ [e2]` (bottom→top), so its top is `e2`;
    FROMALT pops it and pushes `e` on main (with `e` denoting the same value as `e2`). Preserves
    `Inv` (concrete `FROMALT`, `readStack_append` on both stacks). -/
theorem fromalt_stepOk {α} [Inhabited α] {M A : List α} {envF : Env α}
    {ms ms' : ModelState α} (e e2 : Entry α) (Sa : List (Entry α))
    (hval : valOf M A envF e.tok = valOf M A envF e2.tok)
    (hSalt0 : ms.Salt = Sa ++ [e2])
    (hops : ms'.ops = ms.ops ++ [Op.FROMALT])
    (hS : ms'.S = ms.S ++ [e]) (hSalt : ms'.Salt = Sa) :
    StepOk M A envF ms ms' := by
  refine ⟨[Op.FROMALT], hops, ?_⟩
  intro st hInv
  obtain ⟨m, a⟩ := st
  have h1 : m = readStack M A envF ms.S := hInv.1
  have h2 : a = readStack M A envF ms.Salt := hInv.2
  rw [hSalt0, readStack_append] at h2
  refine ⟨(valOf M A envF e2.tok :: m, readStack M A envF Sa), ?_, ?_, ?_⟩
  · rw [h2]; simp [run, step]
  · show valOf M A envF e2.tok :: m = readStack M A envF ms'.S
    rw [hS, readStack_append, hval, ← h1]
  · show readStack M A envF Sa = readStack M A envF ms'.Salt
    rw [hSalt]

/-- The whole entry-alt drain fold is a `StepOk`, for any state whose alt stack is the seeded
    `ainTok` prefix `(range n)`. Proven by induction on `n` (each step is `fromalt_stepOk`,
    the residual alt stays a shorter `ainTok` prefix). -/
theorem drainFold_stepOk {α} [Inhabited α] (M A : List α) (envF : Env α) :
    ∀ (n : Nat) (ms : ModelState α),
      ms.Salt = (List.range n).map (fun i => (⟨Token.ainTok i, false⟩ : Entry α)) →
      StepOk M A envF ms ((List.range n).reverse.foldl drainStep ms) := by
  intro n
  induction n with
  | zero =>
      intro ms _
      simp only [List.range_zero, List.reverse_nil, List.foldl_nil]
      exact StepOk.refl M A envF ms
  | succ n ih =>
      intro ms hSalt
      have hr : (List.range (n + 1)).reverse = n :: (List.range n).reverse := by
        rw [List.range_succ, List.reverse_append]; rfl
      have hSalt2 : ms.Salt =
          (List.range n).map (fun i => (⟨Token.ainTok i, false⟩ : Entry α))
            ++ [⟨Token.ainTok n, false⟩] := by
        rw [hSalt, List.range_succ, List.map_append]; rfl
      have hSaltStep : (drainStep ms n).Salt =
          (List.range n).map (fun i => (⟨Token.ainTok i, false⟩ : Entry α)) := by
        show ms.Salt.dropLast = _
        rw [hSalt2]; simp
      have step1 : StepOk M A envF ms (drainStep ms n) :=
        fromalt_stepOk (⟨Token.ainTok n, false⟩) (⟨Token.ainTok n, false⟩)
          ((List.range n).map (fun i => (⟨Token.ainTok i, false⟩ : Entry α)))
          rfl hSalt2 rfl rfl hSaltStep
      rw [hr, List.foldl_cons]
      exact step1.trans (ih (drainStep ms n) hSaltStep)

/-- ★ PHASE 1 (PROVEN, 0 sorry): the drain phase refines the DAG. -/
theorem drain_stepOk {α} [DecidableEq α] [Inhabited α] (b : Block α) (M A : List α) :
    StepOk M A (blockEnv b M A) (seedState b) (drainPhase b) := by
  unfold drainPhase
  cases h : altPassthrough b with
  | true  => exact StepOk.refl M A (blockEnv b M A) (seedState b)
  | false => exact drainFold_stepOk M A (blockEnv b M A) b.entryAlt (seedState b) rfl

/-! ### ★ THE R3/R4 LIVENESS INVARIANT (home/demand map) + the ARRANGE machinery.

    R4 (HOME AVAILABILITY): a ref is *available* in a model state iff it is a constant OR its
    token has a live non-transient home in `S` (`depthOfHome … isSome`). This is EXACTLY the
    `hhome` hypothesis of `emitFetch_stepOk`/`emitBuildRef_stepOk`, so R4 is precisely what makes
    materialisation TOTAL (never hits the WF-excluded "no home" branch) and every build a `copy`.
    R3 (DEMAND ACCOUNTING) enters through the `use` map: MOVE fires (consuming the home) only on
    a ref's LAST use (`use = 1`), COPY (non-consuming) while `use > 1`; the two home-preservation
    lemmas below are the R4-maintenance half of the invariant.

    The `emitBuildRef` primitive (exit build) NEVER consumes a home — it only APPENDS a slot — so
    R4 is *monotone* through the exit-build fold (`depthOfHome_isSome_append`). `emitFetch`'s MOVE
    branch DOES erase a home, but only the *last-use* one, and only for its own token; homes for
    every OTHER live token survive (`any_eraseIdx_of_ne` — the A2 erase-bookkeeping crux). -/

/-- Home predicate: `e` is a live (non-transient) home for token `t`. `depthOfHome` = the depth
    of the topmost such entry, so `isSome ↔ S.any (homeP t)`. -/
def homeP [DecidableEq α] (t : Token α) : Entry α → Bool :=
  fun e => (!e.transient) && decide (e.tok = t)

/-- `depthOfHome … isSome` is exactly "`S` has a live home for `t`" (`any homeP`). -/
theorem depthOfHome_isSome_iff [DecidableEq α] (S : List (Entry α)) (t : Token α) :
    (depthOfHome S t).isSome = S.any (homeP t) := by
  unfold depthOfHome homeP; rw [List.findIdx?_isSome, List.any_reverse]

/-- ★ R4 MONOTONE UNDER APPEND: appending any slot preserves every existing home
    (`emitBuildRef`/COPY/PUSH never destroy a home). -/
theorem depthOfHome_isSome_append [DecidableEq α] (S : List (Entry α)) (e : Entry α)
    (t : Token α) (h : (depthOfHome S t).isSome = true) :
    (depthOfHome (S ++ [e]) t).isSome = true := by
  rw [depthOfHome_isSome_iff] at h ⊢; rw [List.any_append, h]; simp

/-- ★ A2 ERASE-BOOKKEEPING (the MOVE-consume crux): erasing an element that does NOT satisfy `p`
    preserves `any p`. Hence the last-use MOVE (which erases the *own*-token home) leaves every
    OTHER live token's home intact. -/
theorem any_eraseIdx_of_ne {α} (l : List α) (p : α → Bool) (i : Nat) (hi : i < l.length)
    (h : l.any p = true) (hpi : p l[i] = false) : (l.eraseIdx i).any p = true := by
  rw [List.any_eq_true] at h ⊢
  obtain ⟨x, hx, hpx⟩ := h
  have hne : x ≠ l[i] := by intro he; rw [he, hpi] at hpx; exact absurd hpx (by simp)
  refine ⟨x, ?_, hpx⟩
  rw [List.eraseIdx_eq_take_drop_succ]
  have hmem : x ∈ List.take i l ++ List.drop i l := by rw [List.take_append_drop]; exact hx
  rw [List.mem_append] at hmem
  rw [List.mem_append]
  rcases hmem with h1 | h2
  · exact Or.inl h1
  · right
    rw [List.drop_eq_getElem_cons hi] at h2
    rcases List.mem_cons.mp h2 with he | ht
    · exact absurd he hne
    · exact ht

/-- The home slot found by `depthOfHome … = some d` sits at model-index `|S|-1-d` and is a live
    home for `t` (`homeP`). The bridge from the abstract lookup to the concrete slot's token. -/
theorem depthOfHome_home_entry {α} [DecidableEq α] (S : List (Entry α)) (t : Token α) (d : Nat)
    (hd : depthOfHome S t = some d) :
    ∃ _ : d < S.length, homeP t (S[S.length - 1 - d]) = true := by
  unfold depthOfHome at hd
  rw [List.findIdx?_eq_some_iff_getElem] at hd
  obtain ⟨hlt, hp, _⟩ := hd
  rw [List.length_reverse] at hlt
  refine ⟨hlt, ?_⟩
  rw [List.getElem_reverse (l := S) (i := d) (by rw [List.length_reverse]; exact hlt)] at hp
  exact hp

/-- ★★ R4 PRESERVATION FOR THE MATERIALISE STEP (the F1/F2 template — the hard, consuming half
    of the liveness invariant). Any `emitFetch r` preserves the home of EVERY OTHER token
    `t ≠ tokenOf r`: PUSH/COPY only append (monotone); the last-use MOVE erases only `r`'s OWN
    home (`homeP (tokenOf r)` at the erased slot), so `any_eraseIdx_of_ne` keeps `any (homeP t)`.
    This is exactly why materialising one operand never strands the homes needed by the rest —
    the R4 half `emitNode`/`exitAltStep` thread across their operand folds. -/
theorem depthOfHome_isSome_emitFetch_of_ne {α} [DecidableEq α] (r : Ref α) (ms : ModelState α)
    (t : Token α) (hne : t ≠ tokenOf r) (h : (depthOfHome ms.S t).isSome = true) :
    (depthOfHome (emitFetch r ms).S t).isSome = true := by
  rw [depthOfHome_isSome_iff] at h ⊢
  -- the MOVE branch, shared by inp/ainp/out/cse-const: erase r's own home, append transient.
  have moveCase : ∀ (tok : Token α) (d : Nat), tok = tokenOf r →
      depthOfHome ms.S tok = some d →
      ((ms.S.eraseIdx (ms.S.length - 1 - d) ++ [(⟨tok, true⟩ : Entry α)]).any (homeP t)) = true := by
    intro tok d htok hdh
    obtain ⟨hlt, hhome⟩ := depthOfHome_home_entry ms.S tok d hdh
    rw [List.any_append]
    have herase : (ms.S.eraseIdx (ms.S.length - 1 - d)).any (homeP t) = true := by
      apply any_eraseIdx_of_ne _ _ _ (by omega) h
      simp only [homeP, Bool.and_eq_false_iff]
      right
      simp only [homeP, Bool.and_eq_true, decide_eq_true_eq] at hhome
      rw [hhome.2, htok]
      simp only [decide_eq_false_iff_not]
      exact fun heq => hne (heq ▸ rfl)
    rw [herase]; simp
  cases r with
  | const v cse =>
      cases cse with
      | false => show ((ms.S ++ [_]).any (homeP t)) = true; rw [List.any_append, h]; simp
      | true =>
          simp only [emitFetch, tokenOf]
          cases hdh : depthOfHome ms.S (Token.cTok v) with
          | none => show ((ms.S ++ [_]).any (homeP t)) = true; rw [List.any_append, h]; simp
          | some d =>
              by_cases hu : ms.use (Token.cTok v) = 1
              · simp only [hu, if_true]; exact moveCase (Token.cTok v) d rfl hdh
              · simp only [hu, if_false]
                show ((ms.S ++ [_]).any (homeP t)) = true; rw [List.any_append, h]; simp
  | inp i =>
      simp only [emitFetch, tokenOf]
      cases hdh : depthOfHome ms.S (Token.inTok i) with
      | none => show ((ms.S ++ [_]).any (homeP t)) = true; rw [List.any_append, h]; simp
      | some d =>
          by_cases hu : ms.use (Token.inTok i) = 1
          · simp only [hu, if_true]; exact moveCase (Token.inTok i) d rfl hdh
          · simp only [hu, if_false]
            show ((ms.S ++ [_]).any (homeP t)) = true; rw [List.any_append, h]; simp
  | ainp i =>
      simp only [emitFetch, tokenOf]
      cases hdh : depthOfHome ms.S (Token.ainTok i) with
      | none => show ((ms.S ++ [_]).any (homeP t)) = true; rw [List.any_append, h]; simp
      | some d =>
          by_cases hu : ms.use (Token.ainTok i) = 1
          · simp only [hu, if_true]; exact moveCase (Token.ainTok i) d rfl hdh
          · simp only [hu, if_false]
            show ((ms.S ++ [_]).any (homeP t)) = true; rw [List.any_append, h]; simp
  | out nid j =>
      simp only [emitFetch, tokenOf]
      cases hdh : depthOfHome ms.S (Token.vTok nid j) with
      | none => show ((ms.S ++ [_]).any (homeP t)) = true; rw [List.any_append, h]; simp
      | some d =>
          by_cases hu : ms.use (Token.vTok nid j) = 1
          · simp only [hu, if_true]; exact moveCase (Token.vTok nid j) d rfl hdh
          · simp only [hu, if_false]
            show ((ms.S ++ [_]).any (homeP t)) = true; rw [List.any_append, h]; simp

/-- ★ R4 for a ref: it is a constant, or its token has a live home. This IS the `hhome`
    hypothesis threaded by the arrange fold; the invariant's R4 half. -/
def RefHasHome [DecidableEq α] (ms : ModelState α) (r : Ref α) : Prop :=
  (∃ v b, r = Ref.const v b) ∨ (depthOfHome ms.S (tokenOf r)).isSome = true

/-- `emitBuildRef` only APPENDS one slot in every branch (it never erases). -/
theorem emitBuildRef_S_append {α} [DecidableEq α] (r : Ref α) (ms : ModelState α) :
    ∃ e, (emitBuildRef r ms).S = ms.S ++ [e] := by
  cases r with
  | inp i => simp only [emitBuildRef]; split <;> exact ⟨_, rfl⟩
  | ainp i => simp only [emitBuildRef]; split <;> exact ⟨_, rfl⟩
  | out nid j => simp only [emitBuildRef]; split <;> exact ⟨_, rfl⟩
  | const v cse =>
      cases cse with
      | false => exact ⟨_, rfl⟩
      | true => simp only [emitBuildRef]; split <;> exact ⟨_, rfl⟩

/-- R4 is preserved by `emitBuildRef` (monotone: it only appends). -/
theorem RefHasHome_emitBuildRef {α} [DecidableEq α] (r x : Ref α) (ms : ModelState α)
    (h : RefHasHome ms r) : RefHasHome (emitBuildRef x ms) r := by
  rcases h with hc | hs
  · exact Or.inl hc
  · right
    obtain ⟨e, he⟩ := emitBuildRef_S_append x ms
    rw [he]; exact depthOfHome_isSome_append ms.S e (tokenOf r) hs

/-- The exit-build fold grows `S` by exactly one slot per ref. -/
theorem buildFold_S_length {α} [DecidableEq α] (l : List (Ref α)) (ms : ModelState α) :
    (l.foldl (fun m r => emitBuildRef r m) ms).S.length = ms.S.length + l.length := by
  induction l generalizing ms with
  | nil => simp
  | cons x xs ih =>
      rw [List.foldl_cons, ih (emitBuildRef x ms)]
      obtain ⟨e, he⟩ := emitBuildRef_S_append x ms
      rw [he]; simp [List.length_append]; omega

/-- ★ THE EXIT-BUILD FOLD REFINES: given R4 for every exit ref (homes available), building the
    differing suffix on top is a `StepOk` (each step = `emitBuildRef_stepOk`; R4 for the tail is
    preserved because the fold only appends). -/
theorem buildFold_stepOk {α} [DecidableEq α] [Inhabited α] {M A : List α} {envF : Env α}
    (l : List (Ref α)) (ms : ModelState α) (h : ∀ r ∈ l, RefHasHome ms r) :
    StepOk M A envF ms (l.foldl (fun m r => emitBuildRef r m) ms) := by
  induction l generalizing ms with
  | nil => exact StepOk.refl M A envF ms
  | cons x xs ih =>
      rw [List.foldl_cons]
      have hx : RefHasHome ms x := h x (List.mem_cons_self ..)
      have step1 : StepOk M A envF ms (emitBuildRef x ms) :=
        emitBuildRef_stepOk M A envF x ms hx
      have hrest : ∀ r ∈ xs, RefHasHome (emitBuildRef x ms) r := fun r hr =>
        RefHasHome_emitBuildRef r x ms (h r (List.mem_cons.mpr (Or.inr hr)))
      exact step1.trans (ih (emitBuildRef x ms) hrest)

/-- ★ THE STALE-TAIL DELETE FOLD REFINES: deleting the element at depth `q`, `nDel` times, is a
    `StepOk` as long as `q + nDel ≤ |S|` (each step = `del_stepOk`, and the length invariant
    `q + (remaining) ≤ |S|` is maintained since each erase drops the length by one). The
    element of `List.range nDel` is ignored (`q` is fixed) so this holds over ANY list. -/
theorem delFold_stepOk {α β} [DecidableEq α] [Inhabited α] {M A : List α} {envF : Env α}
    (q : Nat) (l : List β) (ms : ModelState α) (hbound : q + l.length ≤ ms.S.length) :
    StepOk M A envF ms
      (l.foldl (fun m (_ : β) =>
        { m with ops := m.ops ++ delOps q, S := m.S.eraseIdx (m.S.length - 1 - q) }) ms) := by
  induction l generalizing ms with
  | nil => exact StepOk.refl M A envF ms
  | cons x xs ih =>
      rw [List.foldl_cons]
      have hqlt : q < ms.S.length := by simp only [List.length_cons] at hbound; omega
      let ms1 := { ms with ops := ms.ops ++ delOps q, S := ms.S.eraseIdx (ms.S.length - 1 - q) }
      have step1 : StepOk M A envF ms ms1 := del_stepOk (ms' := ms1) q hqlt rfl rfl rfl
      have hlen1 : ms1.S.length = ms.S.length - 1 := by
        show (ms.S.eraseIdx (ms.S.length - 1 - q)).length = ms.S.length - 1
        rw [List.length_eraseIdx]
        have : ms.S.length - 1 - q < ms.S.length := by omega
        simp [this]
      have hbound1 : q + xs.length ≤ ms1.S.length := by
        rw [hlen1]; simp only [List.length_cons] at hbound; omega
      exact step1.trans (ih ms1 hbound1)

/-- ★★ THE ARRANGE STEP, OFF THE R4 INVARIANT (the genuine content of F3): given R4 — every exit
    ref has a live home — the whole final main arrange (match longest prefix, build the differing
    suffix, delete the stale tail) is a `StepOk`. The build fold (`buildFold_stepOk`) + the
    stale-tail delete fold (`delFold_stepOk`) compose by `StepOk.trans`; the depth/length
    arithmetic (`q = |exit|-L`, `nDel = |S|-L`, `|S_built| = |S| + (|exit|-L)` ⇒ `q + nDel ≤
    |S_built|`) is discharged by `buildFold_S_length` + `omega`. 0 sorry, off the invariant. -/
theorem emitExitMain_stepOk {α} [DecidableEq α] [Inhabited α] (M A : List α) (envF : Env α)
    (b : Block α) (ms : ModelState α) (hhome : ∀ r ∈ b.exit, RefHasHome ms r) :
    StepOk M A envF ms (emitExitMain b ms) := by
  let L := matchPrefixAux ms.S 0 b.exit
  let msB := (b.exit.drop L).foldl (fun m r => emitBuildRef r m) ms
  let q := b.exit.length - L
  let nDel := ms.S.length - L
  have hbuild : StepOk M A envF ms msB := by
    apply buildFold_stepOk
    intro r hr
    exact hhome r (List.mem_of_mem_drop hr)
  have hlenB : msB.S.length = ms.S.length + (b.exit.length - L) := by
    show ((b.exit.drop L).foldl (fun m r => emitBuildRef r m) ms).S.length = _
    rw [buildFold_S_length, List.length_drop]
  have hdel : StepOk M A envF msB
      ((List.range nDel).foldl (fun m (_ : Nat) =>
        { m with ops := m.ops ++ delOps q, S := m.S.eraseIdx (m.S.length - 1 - q) }) msB) := by
    apply delFold_stepOk
    rw [List.length_range]
    show q + nDel ≤ msB.S.length
    rw [hlenB]
    show (b.exit.length - L) + (ms.S.length - L) ≤ ms.S.length + (b.exit.length - L)
    omega
  show StepOk M A envF ms
      ((List.range nDel).foldl (fun m (_ : Nat) =>
        { m with ops := m.ops ++ delOps q, S := m.S.eraseIdx (m.S.length - 1 - q) }) msB)
  exact hbuild.trans hdel

/-! ### ★ THE DENOTATION LINK (DL) — the CALL result equals the DAG denotation.
    Discharges `emitCall_stepOk`'s `hout`. Pure facts about `denoteNodes` + the topological order
    + distinct ids (no model state). The core equality `DL`:
        `blockEnv b M A n.id = n.op.sem (n.ins.map (dRef M A (blockEnv b M A)))`.
    Proven by splitting `b.nodes = pre ++ n :: post`, using DN-append/DN-stable to isolate the
    per-node update, and the topological + distinctness facts to show the operands' `dRef`s are
    stable between the pre-environment and the full environment. -/

/-- DN-append: denoting `pre ++ rest` = denoting `rest` from the pre-environment. -/
theorem denoteNodes_append {α} [Inhabited α] (M A : List α) (pre : List (Node α)) :
    ∀ (rest : List (Node α)) (env : Env α),
      denoteNodes M A (pre ++ rest) env = denoteNodes M A rest (denoteNodes M A pre env) := by
  induction pre with
  | nil => intro rest env; rfl
  | cons n ns ih =>
      intro rest env
      simp only [List.cons_append, denoteNodes]
      exact ih rest _

/-- DN-stable: a node-fold leaves untouched every id not among the folded nodes. -/
theorem denoteNodes_stable {α} [Inhabited α] (M A : List α) (q : Nat) :
    ∀ (nodes : List (Node α)) (env : Env α), q ∉ nodes.map Node.id →
      denoteNodes M A nodes env q = env q := by
  intro nodes
  induction nodes with
  | nil => intro env _; rfl
  | cons n ns ih =>
      intro env hq
      rw [List.map_cons, List.mem_cons] at hq
      have h1 : q ≠ n.id := fun h => hq (Or.inl h)
      have h2 : q ∉ ns.map Node.id := fun h => hq (Or.inr h)
      have hstep : denoteNodes M A (n :: ns) env q
          = denoteNodes M A ns
              (fun q' => if q' = n.id then n.op.sem (n.ins.map (dRef M A env)) else env q') q := rfl
      rw [hstep, ih _ h2]
      simp only [if_neg h1]

/-- The topological guarantee, localised at a split `pre ++ n :: post`: every operand of `n`
    references an entry slot, a constant, or an id in `pre` (the nodes emitted earlier). -/
theorem nodesWF_ins_bounded {α} (ed ea : Nat) (n : Node α) :
    ∀ (pre post : List (Node α)) (seen : List Nat),
      nodesWF ed ea seen (pre ++ n :: post) →
      ∀ r ∈ n.ins, refBounded ed ea (seen ++ pre.map Node.id) r := by
  intro pre
  induction pre with
  | nil =>
      intro post seen hwf r hr
      rw [List.map_nil, List.append_nil]
      exact hwf.1 r hr
  | cons p ps ih =>
      intro post seen hwf r hr
      have hwf2 : nodesWF ed ea (seen ++ [p.id]) (ps ++ n :: post) := hwf.2
      have hb := ih post (seen ++ [p.id]) hwf2 r hr
      rw [List.append_assoc] at hb
      simpa using hb

/-- ★ THE DENOTATION LINK. For a `WellFormed` block, each node's assigned value in the block
    environment is exactly its `sem` applied to its operands' DAG values. -/
theorem denotation_link {α} [Inhabited α] (M A : List α) (b : Block α)
    (hwf : WellFormed b) (n : Node α) (hn : n ∈ b.nodes) :
    (blockEnv b M A) n.id = n.op.sem (n.ins.map (dRef M A (blockEnv b M A))) := by
  obtain ⟨pre, post, hsplit⟩ := List.append_of_mem hn
  have hnd : (b.nodes.map Node.id).Nodup := hwf.2.2.2.1
  rw [hsplit, List.map_append, List.map_cons, List.nodup_append] at hnd
  obtain ⟨_, hcons, hdisj⟩ := hnd
  rw [List.nodup_cons] at hcons
  obtain ⟨hnid_post, _⟩ := hcons
  obtain ⟨envF, henvF⟩ : ∃ e, e = blockEnv b M A := ⟨_, rfl⟩
  obtain ⟨e0, he0⟩ : ∃ e, e = denoteNodes M A pre (fun _ => []) := ⟨_, rfl⟩
  rw [← henvF]
  have henv_eq : envF = denoteNodes M A post
      (fun q => if q = n.id then n.op.sem (n.ins.map (dRef M A e0)) else e0 q) := by
    rw [henvF]; unfold blockEnv
    rw [hsplit, denoteNodes_append M A pre (n :: post), ← he0]
    rfl
  have h_nid : envF n.id = n.op.sem (n.ins.map (dRef M A e0)) := by
    rw [henv_eq, denoteNodes_stable M A n.id post _ hnid_post]
    show (if n.id = n.id then n.op.sem (n.ins.map (dRef M A e0)) else e0 n.id) = _
    rw [if_pos rfl]
  have hins_bound : ∀ r ∈ n.ins, refBounded b.entryDepth b.entryAlt (pre.map Node.id) r := by
    have hwfn : nodesWF b.entryDepth b.entryAlt [] (pre ++ n :: post) := by
      have h := hwf.1; rw [hsplit] at h; exact h
    intro r hr
    have := nodesWF_ins_bounded b.entryDepth b.entryAlt n pre post [] hwfn r hr
    simpa using this
  have hstab : ∀ r ∈ n.ins, dRef M A e0 r = dRef M A envF r := by
    intro r hr
    cases r with
    | inp i => rfl
    | ainp i => rfl
    | const v cse => cases cse <;> rfl
    | out q j =>
        have hqpre : q ∈ pre.map Node.id := hins_bound (Ref.out q j) hr
        have hqne : q ≠ n.id := hdisj q hqpre n.id List.mem_cons_self
        have hqpost : q ∉ post.map Node.id := fun hc =>
          hdisj q hqpre q (List.mem_cons.mpr (Or.inr hc)) rfl
        have hqenv : envF q = e0 q := by
          rw [henv_eq, denoteNodes_stable M A q post _ hqpost]
          show (if q = n.id then n.op.sem (n.ins.map (dRef M A e0)) else e0 q) = e0 q
          rw [if_neg hqne]
        show (e0 q).getD j default = (envF q).getD j default
        rw [hqenv]
  rw [h_nid]
  congr 1
  exact List.map_congr_left hstab

/-! ### ★ R3 DEMAND ACCOUNTING — the `use` map is an exact occurrence count.
    `occ`/`occCount` count how many refs demand a token (const-false refs are untracked, matching
    `bumpUse`). `bumpUse_foldl` characterises `demand` as this count, so `use t = 1` ⟺ exactly one
    remaining occurrence (the crux that makes a MOVE fire only on a genuine last use). -/

/-- Occurrence weight of one ref for token `t` (const-false untracked, per `bumpUse`). -/
def occ {α} [DecidableEq α] (t : Token α) (r : Ref α) : Nat :=
  match r with
  | .const _ false => 0
  | _ => if t = tokenOf r then 1 else 0

/-- Total demand for token `t` over a ref list. -/
def occCount {α} [DecidableEq α] (t : Token α) : List (Ref α) → Nat
  | [] => 0
  | r :: rs => occ t r + occCount t rs

theorem occCount_append {α} [DecidableEq α] (t : Token α) (l1 l2 : List (Ref α)) :
    occCount t (l1 ++ l2) = occCount t l1 + occCount t l2 := by
  induction l1 with
  | nil => simp [occCount]
  | cons r rs ih => simp only [List.cons_append, occCount, ih]; omega

/-- ★ `demand`/`bumpUse` fold = starting value + occurrence count. -/
theorem bumpUse_foldl {α} [DecidableEq α] (t : Token α) :
    ∀ (refs : List (Ref α)) (u0 : Token α → Nat),
      (refs.foldl bumpUse u0) t = u0 t + occCount t refs := by
  intro refs
  induction refs with
  | nil => intro u0; simp [occCount]
  | cons r rs ih =>
      intro u0
      rw [List.foldl_cons, ih (bumpUse u0 r)]
      have hb : (bumpUse u0 r) t = u0 t + occ t r := by
        cases r with
        | const v cse =>
            cases cse with
            | false => simp [bumpUse, occ]
            | true => by_cases h : t = tokenOf (Ref.const v true) <;> simp [bumpUse, occ, h]
        | inp i => by_cases h : t = tokenOf (Ref.inp i) <;> simp [bumpUse, occ, h]
        | ainp i => by_cases h : t = tokenOf (Ref.ainp i) <;> simp [bumpUse, occ, h]
        | out nid j => by_cases h : t = tokenOf (Ref.out nid j) <;> simp [bumpUse, occ, h]
      rw [hb]; simp only [occCount]; omega

/-! ### ★ depthOfHome OVER A TRANSIENT OPERAND BLOCK.
    The operand-materialise fold accumulates transient copies on top; `depthOfHome` skips them, so
    a home lookup through `base ++ blk` (blk all transient) is the base lookup shifted by `|blk|`.
    This keeps the operand block glued on top while MOVE-erasures reach only into the base. -/
theorem depthOfHome_append_transient {α} [DecidableEq α] (B blk : List (Entry α)) (t : Token α)
    (hblk : ∀ e ∈ blk, e.transient = true) :
    depthOfHome (B ++ blk) t = (depthOfHome B t).map (· + blk.length) := by
  unfold depthOfHome
  rw [List.reverse_append, List.findIdx?_append]
  have hnone : blk.reverse.findIdx? (fun e => (!e.transient) && decide (e.tok = t)) = none := by
    rw [List.findIdx?_eq_none_iff]
    intro e he
    have hmem : e ∈ blk := List.mem_reverse.mp he
    rw [hblk e hmem]; simp
  rw [hnone, List.length_reverse]
  simp

/-- ★ emitFetch S-shape: it always appends a transient copy of the ref's token on top; either it
    KEEPS the base (PUSH/COPY) or (last-use MOVE) erases the depth-`d` home first. -/
theorem emitFetch_S {α} [DecidableEq α] (r : Ref α) (ms : ModelState α) :
    (emitFetch r ms).S = ms.S ++ [⟨tokenOf r, true⟩]
    ∨ ∃ d, depthOfHome ms.S (tokenOf r) = some d ∧ ms.use (tokenOf r) = 1
         ∧ (emitFetch r ms).S = ms.S.eraseIdx (ms.S.length - 1 - d) ++ [⟨tokenOf r, true⟩] := by
  cases r with
  | const v cse =>
      cases cse with
      | false => left; rfl
      | true =>
          simp only [emitFetch, tokenOf]
          cases hdh : depthOfHome ms.S (Token.cTok v) with
          | none => left; rfl
          | some d =>
              by_cases hu : ms.use (Token.cTok v) = 1
              · right; exact ⟨d, rfl, hu, by simp [hu]⟩
              · left; simp [hu]
  | inp i =>
      simp only [emitFetch, tokenOf]
      cases hdh : depthOfHome ms.S (Token.inTok i) with
      | none => left; rfl
      | some d =>
          by_cases hu : ms.use (Token.inTok i) = 1
          · right; exact ⟨d, rfl, hu, by simp [hu]⟩
          · left; simp [hu]
  | ainp i =>
      simp only [emitFetch, tokenOf]
      cases hdh : depthOfHome ms.S (Token.ainTok i) with
      | none => left; rfl
      | some d =>
          by_cases hu : ms.use (Token.ainTok i) = 1
          · right; exact ⟨d, rfl, hu, by simp [hu]⟩
          · left; simp [hu]
  | out nid j =>
      simp only [emitFetch, tokenOf]
      cases hdh : depthOfHome ms.S (Token.vTok nid j) with
      | none => left; rfl
      | some d =>
          by_cases hu : ms.use (Token.vTok nid j) = 1
          · right; exact ⟨d, rfl, hu, by simp [hu]⟩
          · left; simp [hu]

/-- ★ THE OPERAND-MATERIALISE LAYOUT FOLD. Folding `emitFetch` over the operand list `is` leaves a
    contiguous transient operand block `is.map ⟨tokenOf ·, true⟩` on top of a base (the MOVE-erasures
    reach only into the base, since `depthOfHome` skips the transient block — `append_transient`).
    Stated over an arbitrary already-materialised transient prefix `blk` so the induction threads. -/
theorem operand_layout {α} [DecidableEq α] (is : List (Ref α)) :
    ∀ (m : ModelState α) (base blk : List (Entry α)),
      m.S = base ++ blk → (∀ e ∈ blk, e.transient = true) →
      ∃ base', (is.foldl (fun mm r => emitFetch r mm) m).S
                 = base' ++ (blk ++ is.map (fun r => ⟨tokenOf r, true⟩)) := by
  induction is with
  | nil => intro m base blk hS _; exact ⟨base, by simpa using hS⟩
  | cons r is' ih =>
      intro m base blk hS hblk
      have hstep : ∃ base'', (emitFetch r m).S = base'' ++ (blk ++ [⟨tokenOf r, true⟩]) := by
        rcases emitFetch_S r m with hk | ⟨d, hdh, _, he⟩
        · exact ⟨base, by rw [hk, hS, List.append_assoc]⟩
        · rw [hS] at hdh he
          rw [depthOfHome_append_transient base blk (tokenOf r) hblk] at hdh
          obtain ⟨d0, hd0, hdeq⟩ :
              ∃ d0, depthOfHome base (tokenOf r) = some d0 ∧ d = d0 + blk.length := by
            cases hb : depthOfHome base (tokenOf r) with
            | none => rw [hb] at hdh; simp at hdh
            | some d0 => rw [hb] at hdh; simp at hdh; exact ⟨d0, rfl, hdh.symm⟩
          have hd0lt : d0 < base.length := (depthOfHome_home_entry base (tokenOf r) d0 hd0).1
          refine ⟨base.eraseIdx (base.length - 1 - d0), ?_⟩
          rw [he]
          have hidx : (base ++ blk).length - 1 - d = base.length - 1 - d0 := by
            rw [List.length_append, hdeq]; omega
          rw [hidx, List.eraseIdx_append_of_lt_length (by omega) blk, List.append_assoc]
      obtain ⟨base'', hb''⟩ := hstep
      have hblk1 : ∀ e ∈ blk ++ [⟨tokenOf r, true⟩], e.transient = true := by
        intro e he; rw [List.mem_append] at he
        rcases he with h | h
        · exact hblk e h
        · rw [List.mem_singleton] at h; rw [h]
      obtain ⟨base', hbf⟩ := ih (emitFetch r m) base'' (blk ++ [⟨tokenOf r, true⟩]) hb'' hblk1
      refine ⟨base', ?_⟩
      rw [List.foldl_cons, hbf, List.map_cons]
      congr 1
      simp [List.append_assoc]

/-- A token that needs a stack home (entry/output slots); consts (`cTok`/`nullTok`) do not. -/
def isSlotTok {α} : Token α → Bool
  | .cTok _   => false
  | .nullTok _ => false
  | _         => true

theorem occ_ne {α} [DecidableEq α] (r : Ref α) (t : Token α) (h : t ≠ tokenOf r) :
    occ t r = 0 := by
  cases r with
  | const v cse => cases cse with
      | false => rfl
      | true => simp only [occ]; rw [if_neg h]
  | inp i => simp only [occ]; rw [if_neg h]
  | ainp i => simp only [occ]; rw [if_neg h]
  | out nid j => simp only [occ]; rw [if_neg h]

theorem occ_self_slot {α} [DecidableEq α] (r : Ref α) (h : isSlotTok (tokenOf r) = true) :
    occ (tokenOf r) r = 1 := by
  cases r with
  | const v cse => cases cse <;> simp [tokenOf, isSlotTok] at h
  | inp i => simp [occ, tokenOf]
  | ainp i => simp [occ, tokenOf]
  | out nid j => simp [occ, tokenOf]

/-- ★ emitFetch DEMAND UPDATE: given `r` is materialisable (const, or a live home), it decrements
    exactly the fetched token's residual — `use' t = use t - occ t r`. This threads R3 exactly. -/
theorem emitFetch_use {α} [DecidableEq α] (r : Ref α) (ms : ModelState α)
    (hh : RefHasHome ms r) : ∀ t, (emitFetch r ms).use t = ms.use t - occ t r := by
  intro t
  cases r with
  | const v cse =>
      cases cse with
      | false => simp [emitFetch, occ]
      | true =>
          have huse : (emitFetch (Ref.const v true) ms).use = decUse ms.use (Token.cTok v) := by
            simp only [emitFetch, tokenOf]
            split <;> first | rfl | (split <;> rfl)
          rw [huse]; simp only [occ, tokenOf, decUse]
          by_cases h : t = Token.cTok v <;> simp [h]
  | inp i =>
      have hs : (depthOfHome ms.S (Token.inTok i)).isSome = true := by
        rcases hh with ⟨_, _, hc⟩ | hs
        · exact absurd hc (by simp)
        · simpa [tokenOf] using hs
      cases hd : depthOfHome ms.S (Token.inTok i) with
      | none => rw [hd] at hs; simp at hs
      | some d =>
          have huse : (emitFetch (Ref.inp i) ms).use = decUse ms.use (Token.inTok i) := by
            simp only [emitFetch, tokenOf, hd]; split <;> rfl
          rw [huse]; simp only [occ, tokenOf, decUse]
          by_cases h : t = Token.inTok i <;> simp [h]
  | ainp i =>
      have hs : (depthOfHome ms.S (Token.ainTok i)).isSome = true := by
        rcases hh with ⟨_, _, hc⟩ | hs
        · exact absurd hc (by simp)
        · simpa [tokenOf] using hs
      cases hd : depthOfHome ms.S (Token.ainTok i) with
      | none => rw [hd] at hs; simp at hs
      | some d =>
          have huse : (emitFetch (Ref.ainp i) ms).use = decUse ms.use (Token.ainTok i) := by
            simp only [emitFetch, tokenOf, hd]; split <;> rfl
          rw [huse]; simp only [occ, tokenOf, decUse]
          by_cases h : t = Token.ainTok i <;> simp [h]
  | out nid j =>
      have hs : (depthOfHome ms.S (Token.vTok nid j)).isSome = true := by
        rcases hh with ⟨_, _, hc⟩ | hs
        · exact absurd hc (by simp)
        · simpa [tokenOf] using hs
      cases hd : depthOfHome ms.S (Token.vTok nid j) with
      | none => rw [hd] at hs; simp at hs
      | some d =>
          have huse : (emitFetch (Ref.out nid j) ms).use = decUse ms.use (Token.vTok nid j) := by
            simp only [emitFetch, tokenOf, hd]; split <;> rfl
          rw [huse]; simp only [occ, tokenOf, decUse]
          by_cases h : t = Token.vTok nid j <;> simp [h]

/-- ★★ THE OPERAND-MATERIALISE SIMULATION FOLD (the R3/R4 crux). Given R3 (`use` = exact residual
    demand over `is ++ REST`) and R4 (every still-demanded slot token has a live home), folding
    `emitFetch` over the operands `is` is a `StepOk`, and re-establishes R3/R4 for the tail `REST`.
    MOVE-safety: R3 makes `use = 1` a genuine last use, so the consumed home is no longer demanded;
    every OTHER home survives (`_emitFetch_of_ne`), and a still-demanded token is COPYed not MOVEd
    (`_isSome_append`). -/
theorem operand_sim {α} [DecidableEq α] [Inhabited α] {M A : List α} {envF : Env α}
    (av : Token α → Prop) (is : List (Ref α)) :
    ∀ (REST : List (Ref α)) (m : ModelState α),
      (∀ t, m.use t = occCount t (is ++ REST)) →
      (∀ t, isSlotTok t = true → av t → 0 < m.use t → (depthOfHome m.S t).isSome = true) →
      (∀ r ∈ is, (∃ v b, r = Ref.const v b) ∨ av (tokenOf r)) →
      StepOk M A envF m (is.foldl (fun mm r => emitFetch r mm) m)
      ∧ (∀ t, (is.foldl (fun mm r => emitFetch r mm) m).use t = occCount t REST)
      ∧ (∀ t, isSlotTok t = true → av t → 0 < occCount t REST →
              (depthOfHome (is.foldl (fun mm r => emitFetch r mm) m).S t).isSome = true) := by
  induction is with
  | nil =>
      intro REST m hR3 hR4 _
      refine ⟨StepOk.refl M A envF m, ?_, ?_⟩
      · intro t; simpa using hR3 t
      · intro t hslot hav hpos; exact hR4 t hslot hav (by rw [hR3 t]; simpa using hpos)
  | cons r is' ih =>
      intro REST m hR3 hR4 havl
      -- home for r (RefHasHome), to fetch it
      have hh_r : RefHasHome m r := by
        cases r with
        | const v cse => exact Or.inl ⟨v, cse, rfl⟩
        | inp i =>
            have hav : av (tokenOf (Ref.inp i)) := by
              rcases havl (Ref.inp i) List.mem_cons_self with ⟨_, _, hc⟩ | ha
              · exact absurd hc (by simp)
              · exact ha
            refine Or.inr (hR4 (tokenOf (Ref.inp i)) rfl hav ?_)
            rw [hR3]; rw [show (Ref.inp i :: is') ++ REST = Ref.inp i :: (is' ++ REST) from rfl]
            simp only [occCount]; rw [occ_self_slot _ rfl]; omega
        | ainp i =>
            have hav : av (tokenOf (Ref.ainp i)) := by
              rcases havl (Ref.ainp i) List.mem_cons_self with ⟨_, _, hc⟩ | ha
              · exact absurd hc (by simp)
              · exact ha
            refine Or.inr (hR4 (tokenOf (Ref.ainp i)) rfl hav ?_)
            rw [hR3]; rw [show (Ref.ainp i :: is') ++ REST = Ref.ainp i :: (is' ++ REST) from rfl]
            simp only [occCount]; rw [occ_self_slot _ rfl]; omega
        | out nid j =>
            have hav : av (tokenOf (Ref.out nid j)) := by
              rcases havl (Ref.out nid j) List.mem_cons_self with ⟨_, _, hc⟩ | ha
              · exact absurd hc (by simp)
              · exact ha
            refine Or.inr (hR4 (tokenOf (Ref.out nid j)) rfl hav ?_)
            rw [hR3]; rw [show (Ref.out nid j :: is') ++ REST = Ref.out nid j :: (is' ++ REST) from rfl]
            simp only [occCount]; rw [occ_self_slot _ rfl]; omega
      -- HR3 for m1 = emitFetch r m
      have hR3' : ∀ t, (emitFetch r m).use t = occCount t (is' ++ REST) := by
        intro t
        rw [emitFetch_use r m hh_r t, hR3 t]
        rw [show (r :: is') ++ REST = r :: (is' ++ REST) from rfl]
        simp only [occCount]; omega
      -- HR4 for m1
      have hR4' : ∀ t, isSlotTok t = true → av t → 0 < (emitFetch r m).use t →
          (depthOfHome (emitFetch r m).S t).isSome = true := by
        intro t hslot hav hpos
        by_cases hne : t = tokenOf r
        · -- t = tokenOf r ; slot ⇒ r non-const ⇒ occ = 1 ⇒ m.use t ≥ 2 ⇒ COPY (append)
          subst hne
          have hocc1 : occ (tokenOf r) r = 1 := occ_self_slot r hslot
          have hm2 : 2 ≤ m.use (tokenOf r) := by
            rw [emitFetch_use r m hh_r (tokenOf r), hocc1] at hpos
            omega
          have hhome : (depthOfHome m.S (tokenOf r)).isSome = true :=
            hR4 (tokenOf r) hslot hav (by omega)
          have hkeep : (emitFetch r m).S = m.S ++ [⟨tokenOf r, true⟩] := by
            rcases emitFetch_S r m with hk | ⟨d, _, hu1, _⟩
            · exact hk
            · exact absurd hu1 (by omega)
          rw [hkeep]; exact depthOfHome_isSome_append m.S _ (tokenOf r) hhome
        · -- t ≠ tokenOf r : use unchanged, home preserved by _emitFetch_of_ne
          have huse : (emitFetch r m).use t = m.use t := by
            rw [emitFetch_use r m hh_r t, occ_ne r t hne]; omega
          rw [huse] at hpos
          exact depthOfHome_isSome_emitFetch_of_ne r m t hne (hR4 t hslot hav hpos)
      -- StepOk for the first fetch, then recurse
      have step1 : StepOk M A envF m (emitFetch r m) := emitFetch_stepOk M A envF r m hh_r
      have havl' : ∀ r' ∈ is', (∃ v b, r' = Ref.const v b) ∨ av (tokenOf r') :=
        fun r' hr' => havl r' (List.mem_cons.mpr (Or.inr hr'))
      obtain ⟨stepRest, huseRest, hR4Rest⟩ := ih REST (emitFetch r m) hR3' hR4' havl'
      refine ⟨?_, ?_, ?_⟩
      · rw [List.foldl_cons]; exact step1.trans stepRest
      · rw [List.foldl_cons]; exact huseRest
      · rw [List.foldl_cons]; exact hR4Rest

/-- R4 monotone under appending a whole list (iterated `depthOfHome_isSome_append`). -/
theorem depthOfHome_isSome_append_list {α} [DecidableEq α] (extra : List (Entry α)) :
    ∀ (S : List (Entry α)) (t : Token α),
      (depthOfHome S t).isSome = true → (depthOfHome (S ++ extra) t).isSome = true := by
  induction extra with
  | nil => intro S t h; simpa using h
  | cons e rest ih =>
      intro S t h
      have h1 : (depthOfHome (S ++ [e]) t).isSome = true := depthOfHome_isSome_append S e t h
      have h2 := ih (S ++ [e]) t h1
      rwa [List.append_assoc] at h2

/-! ### ★ CSE-CONST HOME SETUP FOLD (emitNode step 1). Establishes shared homes for reused CSE
    consts; each step is a `PUSH` (or a no-op). It leaves `use` untouched (R3), only APPENDS
    non-transient `cTok` slots (so R4 for every slot token is monotone), and is a `StepOk`. -/
def cseF {α} [DecidableEq α] (m : ModelState α) (inp : Ref α) : ModelState α :=
  match inp with
  | .const v true =>
      match depthOfHome m.S (Token.cTok v) with
      | some _ => m
      | none => if 1 < m.use (Token.cTok v)
                then { m with ops := m.ops ++ [Op.PUSH v], S := m.S ++ [⟨Token.cTok v, false⟩] }
                else m
  | _ => m

theorem cse_step {α} [DecidableEq α] [Inhabited α] {M A : List α} {envF : Env α}
    (m : ModelState α) (inp : Ref α) :
    StepOk M A envF m (cseF m inp) ∧ (cseF m inp).use = m.use
      ∧ ∃ extra, (cseF m inp).S = m.S ++ extra := by
  have refl_case : StepOk M A envF m m ∧ m.use = m.use ∧ ∃ extra, m.S = m.S ++ extra :=
    ⟨StepOk.refl M A envF m, rfl, ⟨[], by simp⟩⟩
  cases inp with
  | inp i => exact refl_case
  | ainp i => exact refl_case
  | out nid j => exact refl_case
  | const v cse =>
      cases cse with
      | false => exact refl_case
      | true =>
          simp only [cseF]
          cases depthOfHome m.S (Token.cTok v) with
          | some d => exact refl_case
          | none =>
              by_cases hu : 1 < m.use (Token.cTok v)
              · rw [if_pos hu]
                exact ⟨push_stepOk (⟨Token.cTok v, false⟩) v rfl rfl rfl rfl, rfl,
                        ⟨[⟨Token.cTok v, false⟩], rfl⟩⟩
              · rw [if_neg hu]; exact refl_case

/-- The whole CSE-setup fold: a `StepOk`, `use`-preserving, and `S` grows only by appended slots. -/
theorem cse_fold {α} [DecidableEq α] [Inhabited α] {M A : List α} {envF : Env α}
    (ins : List (Ref α)) (ms : ModelState α) :
    StepOk M A envF ms (ins.foldl cseF ms) ∧ (ins.foldl cseF ms).use = ms.use
      ∧ ∃ extra, (ins.foldl cseF ms).S = ms.S ++ extra := by
  induction ins generalizing ms with
  | nil => exact ⟨StepOk.refl M A envF ms, rfl, ⟨[], by simp⟩⟩
  | cons r rs ih =>
      obtain ⟨s1, u1, extra1, hS1⟩ := cse_step (M := M) (A := A) (envF := envF) ms r
      obtain ⟨s2, u2, extra2, hS2⟩ := ih (cseF ms r)
      rw [List.foldl_cons]
      refine ⟨s1.trans s2, by rw [u2, u1], ⟨extra1 ++ extra2, ?_⟩⟩
      rw [hS2, hS1, List.append_assoc]

/-! ### ★ eagerDrop PRESERVES LIVE HOMES. eagerDrop only DROPs a non-transient top slot whose
    residual demand is 0; a home for a still-demanded token (`use > 0`) is never that slot, so it
    survives. `use` is untouched throughout. -/
theorem eagerDrop_use {α} [DecidableEq α] (fuel : Nat) (ms : ModelState α) :
    (eagerDrop fuel ms).use = ms.use := by
  induction fuel generalizing ms with
  | zero => rfl
  | succ fuel ih =>
      unfold eagerDrop
      split
      · rfl
      · split
        · rfl
        · split
          · rw [ih]
          · rfl

theorem eagerDrop_preserves_home {α} [DecidableEq α] (fuel : Nat) (ms : ModelState α) (t : Token α)
    (hu : 0 < ms.use t) (h : (depthOfHome ms.S t).isSome = true) :
    (depthOfHome (eagerDrop fuel ms).S t).isSome = true := by
  induction fuel generalizing ms with
  | zero => exact h
  | succ fuel ih =>
      unfold eagerDrop
      split
      · exact h
      · next e rest heq =>
          split
          · exact h
          · next htr =>
              split
              · next hzero =>
                  have hSeq : ms.S = rest.reverse ++ [e] := by
                    have := congrArg List.reverse heq; simpa using this
                  have hne : homeP t e = false := by
                    simp only [homeP, htr, Bool.not_false, Bool.true_and, decide_eq_false_iff_not]
                    intro heqt; rw [heqt] at hzero; omega
                  have hdrop : (depthOfHome ms.S.dropLast t).isSome = true := by
                    rw [hSeq, List.dropLast_concat, depthOfHome_isSome_iff]
                    rw [hSeq, depthOfHome_isSome_iff, List.any_append] at h
                    simpa [hne] using h
                  exact ih { ms with ops := ms.ops ++ [Op.DROP], S := ms.S.dropLast } hu hdrop
              · exact h

/-- ★ eagerDrop is a `StepOk` (each drop = `del_stepOk` at depth 0 = `DROP`). -/
theorem eagerDrop_stepOk {α} [DecidableEq α] [Inhabited α] {M A : List α} {envF : Env α}
    (fuel : Nat) (ms : ModelState α) : StepOk M A envF ms (eagerDrop fuel ms) := by
  induction fuel generalizing ms with
  | zero => exact StepOk.refl M A envF ms
  | succ fuel ih =>
      unfold eagerDrop
      split
      · exact StepOk.refl M A envF ms
      · next e rest heq =>
          split
          · exact StepOk.refl M A envF ms
          · split
            · have hlen : 0 < ms.S.length := by
                have hh : ms.S.reverse.length = (e :: rest).length := by rw [heq]
                simp at hh; omega
              have hstep : StepOk M A envF ms
                  { ms with ops := ms.ops ++ [Op.DROP], S := ms.S.dropLast } := by
                refine del_stepOk (ms' := { ms with ops := ms.ops ++ [Op.DROP], S := ms.S.dropLast })
                  0 (by omega) rfl ?_ rfl
                show ms.S.dropLast = ms.S.eraseIdx (ms.S.length - 1 - 0)
                rw [Nat.sub_zero, List.eraseIdx_length_sub_one]
              exact hstep.trans (ih _)
            · exact StepOk.refl M A envF ms

/-- If some entry `⟨t, false⟩` sits in `S`, then `t` has a live home. -/
theorem depthOfHome_isSome_of_mem {α} [DecidableEq α] (S : List (Entry α)) (t : Token α)
    (hmem : (⟨t, false⟩ : Entry α) ∈ S) : (depthOfHome S t).isSome = true := by
  rw [depthOfHome_isSome_iff, List.any_eq_true]
  exact ⟨⟨t, false⟩, hmem, by simp [homeP]⟩

/-- `occCount t l > 0` ⇒ some ref in `l` demands `t`. -/
theorem occCount_pos {α} [DecidableEq α] (t : Token α) (l : List (Ref α))
    (h : 0 < occCount t l) : ∃ r ∈ l, occ t r ≠ 0 := by
  induction l with
  | nil => simp [occCount] at h
  | cons r rs ih =>
      by_cases hr : occ t r = 0
      · rw [occCount, hr, Nat.zero_add] at h
        obtain ⟨r', hr', h'⟩ := ih h
        exact ⟨r', List.mem_cons.mpr (Or.inr hr'), h'⟩
      · exact ⟨r, List.mem_cons_self, hr⟩

/-- ★ AVAILABILITY (Avail(done)): the slot tokens that have (or will have) homes after the nodes in
    `done` are emitted — entry slots (in range) and outputs of already-emitted nodes. Future-node
    outputs are NOT available (they carry demand but have no home yet — the prefix-indexed R4). -/
def availTok {α} (b : Block α) (doneIds : List Nat) : Token α → Prop
  | .inTok i   => i < b.entryDepth
  | .ainTok i  => i < b.entryAlt
  | .vTok nid _ => nid ∈ doneIds
  | .cTok _    => False
  | .nullTok _ => False

/-- Residual refs still demanded when `rest` nodes remain: their operands + exit (+ exitAlt). -/
def remRefs {α} [DecidableEq α] (b : Block α) (rest : List (Node α)) : List (Ref α) :=
  rest.flatMap Node.ins ++ b.exit ++ (bif altPassthrough b then [] else b.exitAlt)

/-- ★★ THE R4-ESTABLISHMENT STEP: emitting node `n` (CSE-setup ∘ operand-materialise ∘ CALL ∘
    eager-drop) is a `StepOk`, re-establishes exact demand R3 for the tail, and R4 for
    `Avail(done ++ [n])` — the node's outputs ACQUIRE homes (from the CALL), every still-demanded
    available home survives, and the DENOTATION LINK makes the CALL value-coherent. -/
theorem emitNode_establish {α} [DecidableEq α] [Inhabited α] (b : Block α) (hwf : WellFormed b)
    (M A : List α) (done : List (Node α)) (n : Node α) (rest' : List (Node α))
    (hnodes : b.nodes = done ++ n :: rest') (m : ModelState α)
    (hR3 : ∀ t, m.use t = occCount t (n.ins ++ remRefs b rest'))
    (hR4 : ∀ t, isSlotTok t = true → availTok b (done.map Node.id) t → 0 < m.use t →
              (depthOfHome m.S t).isSome = true) :
    StepOk M A (blockEnv b M A) m (emitNode n m)
    ∧ (∀ t, (emitNode n m).use t = occCount t (remRefs b rest'))
    ∧ (∀ t, isSlotTok t = true → availTok b ((done ++ [n]).map Node.id) t →
              0 < (emitNode n m).use t → (depthOfHome (emitNode n m).S t).isSome = true) := by
  have hn : n ∈ b.nodes := by
    rw [hnodes]; exact List.mem_append_right _ List.mem_cons_self
  -- WF projections
  have harity : n.ins.length = n.op.nin := (hwf.2.2.2.2.1) n hn
  have hsem : ∀ l : List α, l.length = n.op.nin → (n.op.sem l).length = n.op.nout :=
    (hwf.2.2.2.2.2.1) n hn
  -- name the two folds
  obtain ⟨ms1, hms1⟩ : ∃ x, x = n.ins.foldl cseF m := ⟨_, rfl⟩
  obtain ⟨ms2, hms2⟩ : ∃ x, x = n.ins.foldl (fun mm r => emitFetch r mm) ms1 := ⟨_, rfl⟩
  -- (1) CSE-setup fold
  obtain ⟨cseStep, cseUse, extra, cseS⟩ := cse_fold (M := M) (A := A) (envF := blockEnv b M A) n.ins m
  rw [← hms1] at cseStep cseUse cseS
  -- R3, R4, availability for the operand fold on ms1
  have hR3ms1 : ∀ t, ms1.use t = occCount t (n.ins ++ remRefs b rest') := by
    intro t; rw [cseUse]; exact hR3 t
  have hR4ms1 : ∀ t, isSlotTok t = true → availTok b (done.map Node.id) t → 0 < ms1.use t →
      (depthOfHome ms1.S t).isSome = true := by
    intro t hslot hav hpos
    rw [cseUse] at hpos
    rw [cseS]
    exact depthOfHome_isSome_append_list extra m.S t (hR4 t hslot hav hpos)
  -- operand availability (topo/WF)
  have havail : ∀ r ∈ n.ins, (∃ v b, r = Ref.const v b) ∨ availTok b (done.map Node.id) (tokenOf r) := by
    intro r hr
    have hb := nodesWF_ins_bounded b.entryDepth b.entryAlt n done rest' []
      (by have h := hwf.1; rw [hnodes] at h; exact h) r hr
    rw [List.nil_append] at hb
    cases r with
    | inp i => exact Or.inr hb
    | ainp i => exact Or.inr hb
    | const v cse => exact Or.inl ⟨v, cse, rfl⟩
    | out nid j => exact Or.inr hb
  -- (2) operand fold
  obtain ⟨opStep, opUse, opR4⟩ := operand_sim (M := M) (A := A) (envF := blockEnv b M A)
    (av := availTok b (done.map Node.id)) n.ins (remRefs b rest') ms1 hR3ms1 hR4ms1 havail
  rw [← hms2] at opStep opUse opR4
  -- operand layout
  obtain ⟨base', hlay0⟩ := operand_layout n.ins ms1 ms1.S [] (by simp) (by intro e he; simp at he)
  rw [← hms2] at hlay0
  have hlay : ms2.S = base' ++ n.ins.map (fun r => (⟨tokenOf r, true⟩ : Entry α)) := by
    rw [hlay0, List.nil_append]
  have hS3 : ms2.S.take (ms2.S.length - n.ins.length) = base' := by
    rw [hlay, List.length_append, List.length_map]
    rw [show base'.length + n.ins.length - n.ins.length = base'.length from by omega]
    exact List.take_left' rfl
  -- (3) the CALL, via the DENOTATION LINK
  obtain ⟨ms3, hms3⟩ : ∃ x, x = ({ ms2 with
                ops := ms2.ops ++ [Op.CALL n.op.nin n.op.sem],
                S := ms2.S.take (ms2.S.length - n.ins.length)
                     ++ (List.range n.op.nout).map (fun j => (⟨Token.vTok n.id j, false⟩ : Entry α)) }
              : ModelState α) := ⟨_, rfl⟩
  have hDL : blockEnv b M A n.id = n.op.sem (n.ins.map (dRef M A (blockEnv b M A))) :=
    denotation_link M A b hwf n hn
  have hlenEnv : (blockEnv b M A n.id).length = n.op.nout := by
    rw [hDL]; exact hsem _ (by rw [List.length_map]; exact harity)
  have hcall : StepOk M A (blockEnv b M A) ms2 ms3 := by
    rw [hms3]
    refine emitCall_stepOk M A (blockEnv b M A) n.op.nin n.op.nout n.op.sem n.id base'
      (n.ins.map (fun r => (⟨tokenOf r, true⟩ : Entry α))) ?hlen ?hout hlay rfl ?hS' rfl
    case hlen => rw [List.length_map]; exact harity
    case hout =>
      have e1 : (n.ins.map (fun r => (⟨tokenOf r, true⟩ : Entry α))).map
                  (fun e => valOf M A (blockEnv b M A) e.tok)
              = n.ins.map (dRef M A (blockEnv b M A)) := by
        rw [List.map_map]
        exact List.map_congr_left (fun r _ => valOf_tokenOf M A (blockEnv b M A) r)
      rw [e1, ← hDL]
      have e2 : (fun jj => valOf M A (blockEnv b M A) (Token.vTok n.id jj))
              = (fun jj => (blockEnv b M A n.id).getD jj default) := by funext jj; rfl
      rw [e2, ← hlenEnv, map_range_getD]
    case hS' => rw [hS3]
  -- (4) emitNode reduces to eagerDrop over ms3
  have hemit : emitNode n m = eagerDrop ms3.S.length ms3 := by
    rw [hms3, hms2, hms1]; rfl
  have hms3S : ms3.S = base'
      ++ (List.range n.op.nout).map (fun j => (⟨Token.vTok n.id j, false⟩ : Entry α)) := by
    rw [hms3]; show ms2.S.take (ms2.S.length - n.ins.length) ++ _ = _; rw [hS3]
  have hms3use : ∀ t, ms3.use t = occCount t (remRefs b rest') := by
    intro t; rw [hms3]; exact opUse t
  refine ⟨?_, ?_, ?_⟩
  · -- StepOk
    rw [hemit]
    exact (cseStep.trans (opStep.trans (hcall.trans (eagerDrop_stepOk ms3.S.length ms3))))
  · -- R3
    intro t; rw [hemit, eagerDrop_use, hms3]; exact opUse t
  · -- R4 for Avail(done ++ [n])
    intro t hslot hav hpos
    rw [hemit] at hpos ⊢
    rw [eagerDrop_use] at hpos
    have hpos3 : 0 < occCount t (remRefs b rest') := by rw [← hms3use t]; exact hpos
    have hhome3 : (depthOfHome ms3.S t).isSome = true := by
      rw [hms3S]
      by_cases hcase : availTok b (done.map Node.id) t
      · -- available already: home in ms2.S ⇒ in base' ⇒ in base' ++ outs
        have h2 : (depthOfHome ms2.S t).isSome = true := opR4 t hslot hcase hpos3
        have hblkt : ∀ e ∈ n.ins.map (fun r => (⟨tokenOf r, true⟩ : Entry α)), e.transient = true := by
          intro e he; rw [List.mem_map] at he; obtain ⟨r, _, hr⟩ := he; rw [← hr]
        rw [hlay, depthOfHome_append_transient base' _ t hblkt] at h2
        have hbase : (depthOfHome base' t).isSome = true := by
          cases hh : depthOfHome base' t with
          | none => rw [hh] at h2; simp at h2
          | some d => rfl
        exact depthOfHome_isSome_append_list _ base' t hbase
      · -- not yet available: must be a fresh output of `n`, home from the CALL's output slots
        have hj : ∃ j, t = Token.vTok n.id j := by
          cases t with
          | inTok i => exact absurd hav hcase
          | ainTok i => exact absurd hav hcase
          | cTok v => simp [isSlotTok] at hslot
          | nullTok v => simp [isSlotTok] at hslot
          | vTok nid j =>
              rw [show availTok b ((done ++ [n]).map Node.id) (Token.vTok nid j)
                    = (nid ∈ (done ++ [n]).map Node.id) from rfl] at hav
              rw [List.map_append, List.map_cons, List.map_nil, List.mem_append,
                  List.mem_singleton] at hav
              rcases hav with h | h
              · exact absurd h hcase
              · exact ⟨j, by rw [h]⟩
        obtain ⟨j, hj⟩ := hj
        subst hj
        have hjlt : j < n.op.nout := by
          obtain ⟨r, hrmem, hrocc⟩ := occCount_pos (Token.vTok n.id j) (remRefs b rest') hpos3
          have hr : r = Ref.out n.id j := by
            cases r with
            | out nid' j' =>
                simp only [occ, tokenOf] at hrocc
                split at hrocc
                · next he => injection he with h1 h2; rw [h1, h2]
                · exact absurd rfl hrocc
            | inp i => simp [occ, tokenOf] at hrocc
            | ainp i => simp [occ, tokenOf] at hrocc
            | const v cse => cases cse <;> simp [occ, tokenOf] at hrocc
          rw [hr] at hrmem
          have hmemAll : Ref.out n.id j ∈ (b.nodes.flatMap Node.ins ++ b.exit ++ b.exitAlt) := by
            unfold remRefs at hrmem
            rw [List.mem_append, List.mem_append] at hrmem
            rw [List.mem_append, List.mem_append]
            rcases hrmem with (hA | hB) | hC
            · left; left
              rw [List.mem_flatMap] at hA ⊢
              obtain ⟨nd, hnd, hrr⟩ := hA
              exact ⟨nd, by rw [hnodes]; exact List.mem_append_right _ (List.mem_cons_of_mem _ hnd), hrr⟩
            · left; right; exact hB
            · right
              cases hp : altPassthrough b with
              | true => rw [hp] at hC; simp at hC
              | false => rw [hp] at hC; exact hC
          exact (hwf.2.2.2.2.2.2) n.id j hmemAll n hn rfl
        apply depthOfHome_isSome_of_mem
        rw [List.mem_append]; right; rw [List.mem_map]
        exact ⟨j, List.mem_range.mpr hjlt, rfl⟩
    exact eagerDrop_preserves_home ms3.S.length ms3 t (by rw [hms3use t]; exact hpos3) hhome3

/-! ### ★ BASE CASE (Live at the drain phase) + the node-fold that threads it. -/

theorem drainStep_use {α} [DecidableEq α] (m : ModelState α) (k : Nat) :
    (drainStep m k).use = m.use := rfl

theorem drainFold_use {α} [DecidableEq α] (l : List Nat) (m : ModelState α) :
    (l.foldl drainStep m).use = m.use := by
  induction l generalizing m with
  | nil => rfl
  | cons x xs ih => rw [List.foldl_cons, ih]; rfl

theorem drainPhase_use {α} [DecidableEq α] (b : Block α) :
    (drainPhase b).use = (seedState b).use := by
  cases h : altPassthrough b with
  | true => unfold drainPhase; rw [h]; rfl
  | false => unfold drainPhase; rw [h]; exact drainFold_use _ _

theorem drainFold_S {α} [DecidableEq α] (l : List Nat) (m : ModelState α) :
    (l.foldl drainStep m).S = m.S ++ l.map (fun k => (⟨Token.ainTok k, false⟩ : Entry α)) := by
  induction l generalizing m with
  | nil => simp
  | cons x xs ih =>
      rw [List.foldl_cons, ih]
      show m.S ++ [⟨Token.ainTok x, false⟩] ++ _ = _
      rw [List.map_cons, List.append_assoc]; rfl

theorem occCount_eq_zero {α} [DecidableEq α] (t : Token α) (L : List (Ref α))
    (h : ∀ r ∈ L, occ t r = 0) : occCount t L = 0 := by
  induction L with
  | nil => rfl
  | cons r rs ih =>
      rw [occCount, h r List.mem_cons_self, Nat.zero_add]
      exact ih (fun r' hr' => h r' (List.mem_cons.mpr (Or.inr hr')))

theorem remRefs_cons {α} [DecidableEq α] (b : Block α) (n : Node α) (rest' : List (Node α)) :
    remRefs b (n :: rest') = n.ins ++ remRefs b rest' := by
  unfold remRefs
  simp only [List.flatMap_cons, List.append_assoc]

/-- R3 base: the drain-phase `use` map is exactly the residual demand over the whole block. -/
theorem drain_R3 {α} [DecidableEq α] (b : Block α) :
    ∀ t, (drainPhase b).use t = occCount t (remRefs b b.nodes) := by
  intro t
  rw [drainPhase_use]
  show (demand b (altPassthrough b)) t = occCount t (remRefs b b.nodes)
  unfold demand remRefs
  rw [bumpUse_foldl]; simp

/-- The drain-phase main stack = entry mains, then (unless passthrough) the drained entry alts. -/
theorem drainPhase_S {α} [DecidableEq α] (b : Block α) :
    (drainPhase b).S = (seedState b).S
      ++ (bif altPassthrough b then ([] : List (Entry α))
          else (List.range b.entryAlt).reverse.map (fun k => (⟨Token.ainTok k, false⟩ : Entry α))) := by
  cases h : altPassthrough b with
  | true => unfold drainPhase; simp [h]
  | false => unfold drainPhase; simp only [h, cond_false]; rw [drainFold_S]

/-- R4 base: at the drain phase, every available slot token with demand has a home (entry mains
    always; entry alts either drained onto main, or — in passthrough — carry zero demand). -/
theorem drain_R4 {α} [DecidableEq α] [Inhabited α] (b : Block α) :
    ∀ t, isSlotTok t = true → availTok b ([] : List Nat) t → 0 < (drainPhase b).use t →
      (depthOfHome (drainPhase b).S t).isSome = true := by
  intro t hslot hav hpos
  cases t with
  | cTok v => simp [isSlotTok] at hslot
  | nullTok v => simp [isSlotTok] at hslot
  | vTok nid j => simp [availTok] at hav
  | inTok i =>
      have hmem : (⟨Token.inTok i, false⟩ : Entry α) ∈ (seedState b).S := by
        show _ ∈ (List.range b.entryDepth).map (fun i => (⟨Token.inTok i, false⟩ : Entry α))
        rw [List.mem_map]; exact ⟨i, List.mem_range.mpr hav, rfl⟩
      apply depthOfHome_isSome_of_mem
      rw [drainPhase_S]; exact List.mem_append_left _ hmem
  | ainTok i =>
      cases hp : altPassthrough b with
      | true =>
          exfalso
          rw [drain_R3 b] at hpos
          have hnoain : (b.nodes.flatMap Node.ins ++ b.exit).any
              (fun r => match r with | Ref.ainp _ => true | _ => false) = false := by
            have hpass := hp
            unfold altPassthrough at hpass
            generalize hX : (b.nodes.flatMap Node.ins ++ b.exit).any
              (fun r => match r with | Ref.ainp _ => true | _ => false) = X at hpass ⊢
            cases X with
            | false => rfl
            | true => simp at hpass
          have hz : occCount (Token.ainTok i) (remRefs b b.nodes) = 0 := by
            apply occCount_eq_zero
            intro r hr
            cases r with
            | ainp i' =>
                exfalso
                have hrL0 : Ref.ainp i' ∈ (b.nodes.flatMap Node.ins ++ b.exit) := by
                  have hr2 := hr
                  unfold remRefs at hr2
                  rw [hp] at hr2
                  simpa using hr2
                have hcontra := List.any_eq_false.mp hnoain (Ref.ainp i') hrL0
                simp at hcontra
            | inp _ => simp [occ, tokenOf]
            | out _ _ => simp [occ, tokenOf]
            | const v cse => cases cse <;> simp [occ, tokenOf]
          rw [hz] at hpos; exact absurd hpos (by omega)
      | false =>
          have hmem : (⟨Token.ainTok i, false⟩ : Entry α)
              ∈ (List.range b.entryAlt).reverse.map (fun k => (⟨Token.ainTok k, false⟩ : Entry α)) := by
            rw [List.mem_map]
            exact ⟨i, List.mem_reverse.mpr (List.mem_range.mpr hav), rfl⟩
          apply depthOfHome_isSome_of_mem
          rw [drainPhase_S, hp]; simp only [cond_false]
          exact List.mem_append_right _ hmem

/-- ★ THE NODE-FOLD: threads Live (`b.nodes = done ++ rest`, R3 for `rest`, R4 for Avail(done))
    across the node schedule, using `emitNode_establish` at each step. Returns the whole-fold
    `StepOk`, plus the re-established R3 (residual demand `remRefs b []`) and R4
    (Avail over ALL of `done ++ rest`), so the cascade (F2/F3) can reuse them. -/
theorem nodesFold_establish {α} [DecidableEq α] [Inhabited α] (b : Block α) (hwf : WellFormed b)
    (M A : List α) :
    ∀ (rest done : List (Node α)) (m : ModelState α),
      b.nodes = done ++ rest →
      (∀ t, m.use t = occCount t (remRefs b rest)) →
      (∀ t, isSlotTok t = true → availTok b (done.map Node.id) t → 0 < m.use t →
            (depthOfHome m.S t).isSome = true) →
      StepOk M A (blockEnv b M A) m (rest.foldl (fun mm nd => emitNode nd mm) m)
      ∧ (∀ t, (rest.foldl (fun mm nd => emitNode nd mm) m).use t = occCount t (remRefs b []))
      ∧ (∀ t, isSlotTok t = true → availTok b ((done ++ rest).map Node.id) t →
              0 < (rest.foldl (fun mm nd => emitNode nd mm) m).use t →
              (depthOfHome (rest.foldl (fun mm nd => emitNode nd mm) m).S t).isSome = true) := by
  intro rest
  induction rest with
  | nil =>
      intro done m _ hR3 hR4
      refine ⟨StepOk.refl _ _ _ m, ?_, ?_⟩
      · intro t; simpa using hR3 t
      · intro t hslot hav hpos
        simp only [List.append_nil] at hav
        exact hR4 t hslot hav hpos
  | cons n rest' ih =>
      intro done m hnodes hR3 hR4
      have hR3' : ∀ t, m.use t = occCount t (n.ins ++ remRefs b rest') := by
        intro t; rw [hR3 t, remRefs_cons]
      obtain ⟨estep, euse, eR4⟩ := emitNode_establish b hwf M A done n rest' hnodes m hR3' hR4
      have hnodes' : b.nodes = (done ++ [n]) ++ rest' := by rw [hnodes]; simp
      obtain ⟨rstep, ruse, rR4⟩ := ih (done ++ [n]) (emitNode n m) hnodes' euse eR4
      refine ⟨?_, ?_, ?_⟩
      · rw [List.foldl_cons]; exact estep.trans rstep
      · rw [List.foldl_cons]; exact ruse
      · rw [List.foldl_cons]
        intro t hslot hav hpos
        exact rR4 t hslot (by simpa using hav) hpos

/-- ★ FRONTIER (F1) — CLOSED. Per-node emission preserves `Inv`: the node fold is a `StepOk`,
    off the base-case Live at the drain phase (`drain_R3`/`drain_R4`) threaded by
    `nodesFold_establish` / `emitNode_establish` (R4-establishment + the DENOTATION LINK). -/
theorem nodes_stepOk {α} [DecidableEq α] [Inhabited α] (b : Block α) (hwf : WellFormed b)
    (M A : List α) :
    StepOk M A (blockEnv b M A) (drainPhase b) (nodesPhase b) :=
  (nodesFold_establish b hwf M A b.nodes [] (drainPhase b) (by simp) (drain_R3 b) (drain_R4 b)).1

/-- R3 at the node phase: residual demand is exactly `exit (++ exitAlt)`. -/
theorem nodesPhase_R3 {α} [DecidableEq α] [Inhabited α] (b : Block α) (hwf : WellFormed b) :
    ∀ t, (nodesPhase b).use t = occCount t (remRefs b []) :=
  (nodesFold_establish b hwf ([] : List α) ([] : List α)
    b.nodes [] (drainPhase b) (by simp) (drain_R3 b) (drain_R4 b)).2.1

/-- R4 at the node phase: every available slot token still demanded has a live home. -/
theorem nodesPhase_R4 {α} [DecidableEq α] [Inhabited α] (b : Block α) (hwf : WellFormed b) :
    ∀ t, isSlotTok t = true → availTok b (b.nodes.map Node.id) t → 0 < (nodesPhase b).use t →
      (depthOfHome (nodesPhase b).S t).isSome = true := by
  have h := (nodesFold_establish b hwf ([] : List α) ([] : List α)
    b.nodes [] (drainPhase b) (by simp) (drain_R3 b) (drain_R4 b)).2.2
  intro t hslot hav hpos
  exact h t hslot (by simpa using hav) hpos

/-! ### ★ EXIT-ALT DEPOSIT FOLD (F2). Each `exitAltStep` = materialise `emitFetch` + `TOALT`
    (pop the copy off main, push it on alt). It reuses the exact R3/R4 bookkeeping of the operand
    fold: `use` is `emitFetch`'s, and the main-stack HOMES coincide with `emitFetch`'s (the extra
    `dropLast` only removes the transient copy `TOALT` consumed). -/

/-- BUILDER: a TOALT step. Pops the main top `e` (= `Se ++ [e]`), pushes an alt slot `ea` of equal
    value. Preserves `Inv` (concrete `TOALT`, `readStack_append` on both stacks). -/
theorem toalt_stepOk {α} [Inhabited α] {M A : List α} {envF : Env α}
    {ms ms' : ModelState α} (e ea : Entry α) (Se : List (Entry α))
    (hval : valOf M A envF ea.tok = valOf M A envF e.tok)
    (hS0 : ms.S = Se ++ [e])
    (hops : ms'.ops = ms.ops ++ [Op.TOALT])
    (hS : ms'.S = Se) (hSalt : ms'.Salt = ms.Salt ++ [ea]) :
    StepOk M A envF ms ms' := by
  refine ⟨[Op.TOALT], hops, ?_⟩
  intro st hInv
  obtain ⟨mm, aa⟩ := st
  have h1 : mm = readStack M A envF ms.S := hInv.1
  have h2 : aa = readStack M A envF ms.Salt := hInv.2
  rw [hS0, readStack_append] at h1
  refine ⟨(readStack M A envF Se, valOf M A envF e.tok :: aa), ?_, ?_, ?_⟩
  · rw [h1]; simp [run, step]
  · show readStack M A envF Se = readStack M A envF ms'.S; rw [hS]
  · show valOf M A envF e.tok :: aa = readStack M A envF ms'.Salt
    rw [hSalt, readStack_append, hval, h2]

theorem exitAltStep_use {α} [DecidableEq α] (r : Ref α) (ms : ModelState α) :
    (exitAltStep ms r).use = (emitFetch r ms).use := rfl

/-- The exit-alt step's main-stack homes coincide with `emitFetch`'s (only the transient copy the
    `TOALT` consumed is dropped, and `depthOfHome` skips transients). -/
theorem exitAltStep_home {α} [DecidableEq α] (r : Ref α) (ms : ModelState α) (t : Token α) :
    (depthOfHome (exitAltStep ms r).S t).isSome = (depthOfHome (emitFetch r ms).S t).isSome := by
  obtain ⟨C, hC⟩ : ∃ C, (emitFetch r ms).S = C ++ [(⟨tokenOf r, true⟩ : Entry α)] := by
    rcases emitFetch_S r ms with h | ⟨d, _, _, h⟩ <;> exact ⟨_, h⟩
  have hS : (exitAltStep ms r).S = C := by
    show (emitFetch r ms).S.dropLast = C; rw [hC, List.dropLast_concat]
  rw [hS, hC, depthOfHome_append_transient C [⟨tokenOf r, true⟩] t
      (by intro e he; rw [List.mem_singleton] at he; rw [he])]
  cases depthOfHome C t <;> simp

/-- exit-alt step is a `StepOk` (materialise then move-to-alt), given a home for `r`. -/
theorem exitAltStep_stepOk {α} [DecidableEq α] [Inhabited α] {M A : List α} {envF : Env α}
    (r : Ref α) (ms : ModelState α) (hh : RefHasHome ms r) :
    StepOk M A envF ms (exitAltStep ms r) := by
  have hfetch : StepOk M A envF ms (emitFetch r ms) := emitFetch_stepOk M A envF r ms hh
  obtain ⟨C, hC⟩ : ∃ C, (emitFetch r ms).S = C ++ [(⟨tokenOf r, true⟩ : Entry α)] := by
    rcases emitFetch_S r ms with h | ⟨d, _, _, h⟩ <;> exact ⟨_, h⟩
  refine hfetch.trans (toalt_stepOk (⟨tokenOf r, true⟩) (⟨tokenOf r, false⟩) C rfl hC rfl ?_ rfl)
  show (emitFetch r ms).S.dropLast = C; rw [hC, List.dropLast_concat]

/-- ★ THE EXIT-ALT SIMULATION FOLD (F2 crux) — identical R3/R4 bookkeeping to `operand_sim`,
    with `exitAltStep` in place of `emitFetch` (the home behaviour coincides — `exitAltStep_home`). -/
theorem exitAltFold_sim {α} [DecidableEq α] [Inhabited α] {M A : List α} {envF : Env α}
    (av : Token α → Prop) (is : List (Ref α)) :
    ∀ (REST : List (Ref α)) (m : ModelState α),
      (∀ t, m.use t = occCount t (is ++ REST)) →
      (∀ t, isSlotTok t = true → av t → 0 < m.use t → (depthOfHome m.S t).isSome = true) →
      (∀ r ∈ is, (∃ v b, r = Ref.const v b) ∨ av (tokenOf r)) →
      StepOk M A envF m (is.foldl exitAltStep m)
      ∧ (∀ t, isSlotTok t = true → av t → 0 < occCount t REST →
              (depthOfHome (is.foldl exitAltStep m).S t).isSome = true) := by
  induction is with
  | nil =>
      intro REST m hR3 hR4 _
      refine ⟨StepOk.refl M A envF m, ?_⟩
      intro t hslot hav hpos; exact hR4 t hslot hav (by rw [hR3 t]; simpa using hpos)
  | cons r is' ih =>
      intro REST m hR3 hR4 havl
      have hh_r : RefHasHome m r := by
        cases r with
        | const v cse => exact Or.inl ⟨v, cse, rfl⟩
        | inp i =>
            have hav : av (tokenOf (Ref.inp i)) := by
              rcases havl (Ref.inp i) List.mem_cons_self with ⟨_, _, hc⟩ | ha
              · exact absurd hc (by simp)
              · exact ha
            refine Or.inr (hR4 (tokenOf (Ref.inp i)) rfl hav ?_)
            rw [hR3]; rw [show (Ref.inp i :: is') ++ REST = Ref.inp i :: (is' ++ REST) from rfl]
            simp only [occCount]; rw [occ_self_slot _ rfl]; omega
        | ainp i =>
            have hav : av (tokenOf (Ref.ainp i)) := by
              rcases havl (Ref.ainp i) List.mem_cons_self with ⟨_, _, hc⟩ | ha
              · exact absurd hc (by simp)
              · exact ha
            refine Or.inr (hR4 (tokenOf (Ref.ainp i)) rfl hav ?_)
            rw [hR3]; rw [show (Ref.ainp i :: is') ++ REST = Ref.ainp i :: (is' ++ REST) from rfl]
            simp only [occCount]; rw [occ_self_slot _ rfl]; omega
        | out nid j =>
            have hav : av (tokenOf (Ref.out nid j)) := by
              rcases havl (Ref.out nid j) List.mem_cons_self with ⟨_, _, hc⟩ | ha
              · exact absurd hc (by simp)
              · exact ha
            refine Or.inr (hR4 (tokenOf (Ref.out nid j)) rfl hav ?_)
            rw [hR3]; rw [show (Ref.out nid j :: is') ++ REST = Ref.out nid j :: (is' ++ REST) from rfl]
            simp only [occCount]; rw [occ_self_slot _ rfl]; omega
      have hR3' : ∀ t, (exitAltStep m r).use t = occCount t (is' ++ REST) := by
        intro t
        rw [exitAltStep_use, emitFetch_use r m hh_r t, hR3 t]
        rw [show (r :: is') ++ REST = r :: (is' ++ REST) from rfl]
        simp only [occCount]; omega
      have hR4' : ∀ t, isSlotTok t = true → av t → 0 < (exitAltStep m r).use t →
          (depthOfHome (exitAltStep m r).S t).isSome = true := by
        intro t hslot hav hpos
        rw [exitAltStep_use] at hpos
        rw [exitAltStep_home]
        by_cases hne : t = tokenOf r
        · subst hne
          have hocc1 : occ (tokenOf r) r = 1 := occ_self_slot r hslot
          have hm2 : 2 ≤ m.use (tokenOf r) := by
            rw [emitFetch_use r m hh_r (tokenOf r), hocc1] at hpos; omega
          have hhome : (depthOfHome m.S (tokenOf r)).isSome = true :=
            hR4 (tokenOf r) hslot hav (by omega)
          have hkeep : (emitFetch r m).S = m.S ++ [⟨tokenOf r, true⟩] := by
            rcases emitFetch_S r m with hk | ⟨d, _, hu1, _⟩
            · exact hk
            · exact absurd hu1 (by omega)
          rw [hkeep]; exact depthOfHome_isSome_append m.S _ (tokenOf r) hhome
        · have huse : (emitFetch r m).use t = m.use t := by
            rw [emitFetch_use r m hh_r t, occ_ne r t hne]; omega
          rw [huse] at hpos
          exact depthOfHome_isSome_emitFetch_of_ne r m t hne (hR4 t hslot hav hpos)
      have havl' : ∀ r' ∈ is', (∃ v b, r' = Ref.const v b) ∨ av (tokenOf r') :=
        fun r' hr' => havl r' (List.mem_cons.mpr (Or.inr hr'))
      obtain ⟨stepRest, hR4Rest⟩ := ih REST (exitAltStep m r) hR3' hR4' havl'
      refine ⟨?_, ?_⟩
      · rw [List.foldl_cons]; exact (exitAltStep_stepOk r m hh_r).trans stepRest
      · rw [List.foldl_cons]; exact hR4Rest

/-- ★ FRONTIER (F2) — CLOSED. The exit-alt deposit fold refines the DAG. Passthrough: identity.
    Otherwise: the `exitAltFold_sim` over `b.exitAlt`, off R3/R4 at the node phase. -/
theorem exitAlt_stepOk {α} [DecidableEq α] [Inhabited α] (b : Block α) (hwf : WellFormed b)
    (M A : List α) :
    StepOk M A (blockEnv b M A) (nodesPhase b) (exitAltPhase b) := by
  cases hp : altPassthrough b with
  | true =>
      have hea : exitAltPhase b = nodesPhase b := by unfold exitAltPhase; rw [hp]; rfl
      rw [hea]; exact StepOk.refl M A (blockEnv b M A) (nodesPhase b)
  | false =>
      have hea : exitAltPhase b = b.exitAlt.foldl exitAltStep (nodesPhase b) := by
        unfold exitAltPhase; rw [hp]; rfl
      rw [hea]
      have hR3 : ∀ t, (nodesPhase b).use t = occCount t (b.exitAlt ++ b.exit) := by
        intro t
        rw [nodesPhase_R3 b hwf t]
        show occCount t (remRefs b []) = _
        unfold remRefs
        rw [hp]
        simp only [List.flatMap_nil, List.nil_append, cond_false]
        rw [occCount_append, occCount_append]; omega
      have hR4 : ∀ t, isSlotTok t = true → availTok b (b.nodes.map Node.id) t →
          0 < (nodesPhase b).use t → (depthOfHome (nodesPhase b).S t).isSome = true :=
        nodesPhase_R4 b hwf
      have havl : ∀ r ∈ b.exitAlt, (∃ v bb, r = Ref.const v bb) ∨ availTok b (b.nodes.map Node.id) (tokenOf r) := by
        intro r hr
        have hb := hwf.2.2.1 r hr
        cases r with
        | inp i => exact Or.inr hb
        | ainp i => exact Or.inr hb
        | const v cse => exact Or.inl ⟨v, cse, rfl⟩
        | out nid j => exact Or.inr hb
      exact (exitAltFold_sim (av := availTok b (b.nodes.map Node.id)) b.exitAlt b.exit
        (nodesPhase b) hR3 hR4 havl).1

/-- `occ t r ≤ occCount t l` whenever `r ∈ l`. -/
theorem occCount_ge_of_mem {α} [DecidableEq α] (l : List (Ref α)) (t : Token α) (r : Ref α)
    (hr : r ∈ l) : occ t r ≤ occCount t l := by
  induction l with
  | nil => simp at hr
  | cons x xs ih =>
      rw [occCount]
      rcases List.mem_cons.mp hr with h | h
      · rw [h]; omega
      · have := ih h; omega

/-- R4 at the exit-alt phase: every available slot token still demanded by `b.exit` has a home
    (nodes-phase R4 in passthrough; the exit-alt fold's re-established R4 otherwise). -/
theorem exitAltPhase_R4 {α} [DecidableEq α] [Inhabited α] (b : Block α) (hwf : WellFormed b) :
    ∀ t, isSlotTok t = true → availTok b (b.nodes.map Node.id) t → 0 < occCount t b.exit →
      (depthOfHome (exitAltPhase b).S t).isSome = true := by
  intro t hslot hav hpos
  cases hp : altPassthrough b with
  | true =>
      have hea : exitAltPhase b = nodesPhase b := by unfold exitAltPhase; rw [hp]; rfl
      rw [hea]
      apply nodesPhase_R4 b hwf t hslot hav
      rw [nodesPhase_R3 b hwf]
      have hrem : remRefs b [] = b.exit := by unfold remRefs; rw [hp]; simp
      rw [hrem]; exact hpos
  | false =>
      have hea : exitAltPhase b = b.exitAlt.foldl exitAltStep (nodesPhase b) := by
        unfold exitAltPhase; rw [hp]; rfl
      rw [hea]
      have hrem : remRefs b [] = b.exit ++ b.exitAlt := by unfold remRefs; rw [hp]; simp
      have hR3 : ∀ t', (nodesPhase b).use t' = occCount t' (b.exitAlt ++ b.exit) := by
        intro t'
        rw [nodesPhase_R3 b hwf t', hrem, occCount_append, occCount_append]; omega
      have havl : ∀ r ∈ b.exitAlt,
          (∃ v bb, r = Ref.const v bb) ∨ availTok b (b.nodes.map Node.id) (tokenOf r) := by
        intro r hr
        have hb := hwf.2.2.1 r hr
        cases r with
        | inp i => exact Or.inr hb
        | ainp i => exact Or.inr hb
        | const v cse => exact Or.inl ⟨v, cse, rfl⟩
        | out nid j => exact Or.inr hb
      exact (exitAltFold_sim (M := ([] : List α)) (A := ([] : List α)) (envF := fun _ => [])
        (av := availTok b (b.nodes.map Node.id)) b.exitAlt b.exit
        (nodesPhase b) hR3 (nodesPhase_R4 b hwf) havl).2 t hslot hav hpos

/-- ★ FRONTIER (F3) — CLOSED. The final incremental main arrange preserves `Inv`: the arrange
    machinery (`emitExitMain_stepOk`) discharges everything OFF R4, and the residual R4 for the
    exit refs is now supplied by `exitAltPhase_R4` (threaded from F1/F2). -/
theorem arrange_stepOk {α} [DecidableEq α] [Inhabited α] (b : Block α) (hwf : WellFormed b)
    (M A : List α) :
    StepOk M A (blockEnv b M A) (exitAltPhase b) (emitExitMain b (exitAltPhase b)) := by
  apply emitExitMain_stepOk
  intro r hr
  cases r with
  | const v cse => exact Or.inl ⟨v, cse, rfl⟩
  | inp i =>
      right
      apply exitAltPhase_R4 b hwf (Token.inTok i) rfl (hwf.2.1 (Ref.inp i) hr)
      have hle := occCount_ge_of_mem b.exit (Token.inTok i) (Ref.inp i) hr
      simp [occ, tokenOf] at hle; omega
  | ainp i =>
      right
      apply exitAltPhase_R4 b hwf (Token.ainTok i) rfl (hwf.2.1 (Ref.ainp i) hr)
      have hle := occCount_ge_of_mem b.exit (Token.ainTok i) (Ref.ainp i) hr
      simp [occ, tokenOf] at hle; omega
  | out nid j =>
      right
      apply exitAltPhase_R4 b hwf (Token.vTok nid j) rfl (hwf.2.1 (Ref.out nid j) hr)
      have hle := occCount_ge_of_mem b.exit (Token.vTok nid j) (Ref.out nid j) hr
      simp [occ, tokenOf] at hle; omega

/-- ★ COMPOSITION (PROVEN modulo the three frontier phases): the whole emitter refines the DAG,
    by `StepOk.trans` over the four phases. Phase 1 (`drain_stepOk`) is fully proven. -/
theorem schedule_stepOk {α} [DecidableEq α] [Inhabited α] (b : Block α) (hwf : WellFormed b)
    (M A : List α) :
    StepOk M A (blockEnv b M A) (seedState b) (scheduleBlock b) := by
  rw [scheduleBlock_eq]
  exact (drain_stepOk b M A).trans
        ((nodes_stepOk b hwf M A).trans
        ((exitAlt_stepOk b hwf M A).trans (arrange_stepOk b hwf M A)))

/-! ### ★ THE ARRANGE READOUT (F4a). `emitExitMain` keeps the matching bottom prefix of `S`,
    builds the differing exit suffix on top, and deletes the stale tail underneath. Its final `S`
    is exactly `S.take L ++ (exit.drop L).map ⟨tokenOf ·, false⟩`, whose read-out is the exit
    layout (`matchPrefix_map` gives the prefix values coincide with the exit refs). -/

/-- `matchPrefixAux` for a non-const head unfolds to the slot-match body. -/
theorem matchPrefixAux_cons_ne {α} [DecidableEq α] (S : List (Entry α)) (r : Ref α)
    (rest : List (Ref α)) (i : Nat) (hnc : ∀ v c, r ≠ Ref.const v c) :
    matchPrefixAux S i (r :: rest) =
      (match S[i]? with
       | none => i
       | some e => match e.transient with
                   | true => i
                   | false => if e.tok = tokenOf r then matchPrefixAux S (i + 1) rest else i) := by
  cases r with
  | const v c => exact absurd rfl (hnc v c)
  | inp k => rfl
  | ainp k => rfl
  | out nid j => rfl

theorem matchPrefixAux_ge {α} [DecidableEq α] (S : List (Entry α)) :
    ∀ (exit : List (Ref α)) (i : Nat), i ≤ matchPrefixAux S i exit := by
  intro exit
  induction exit with
  | nil => intro i; exact Nat.le_refl i
  | cons r rest ih =>
      intro i
      by_cases hc : ∃ v c, r = Ref.const v c
      · obtain ⟨v, c, rfl⟩ := hc; simp [matchPrefixAux]
      · rw [matchPrefixAux_cons_ne S r rest i (by rintro v c rfl; exact hc ⟨v, c, rfl⟩)]
        split
        · exact Nat.le_refl i
        · split
          · exact Nat.le_refl i
          · split
            · exact Nat.le_trans (Nat.le_succ i) (ih (i + 1))
            · exact Nat.le_refl i

theorem matchPrefixAux_le_exit {α} [DecidableEq α] (S : List (Entry α)) :
    ∀ (exit : List (Ref α)) (i : Nat), matchPrefixAux S i exit ≤ i + exit.length := by
  intro exit
  induction exit with
  | nil => intro i; simp [matchPrefixAux]
  | cons r rest ih =>
      intro i
      by_cases hc : ∃ v c, r = Ref.const v c
      · obtain ⟨v, c, rfl⟩ := hc; simp only [matchPrefixAux, List.length_cons]; omega
      · rw [matchPrefixAux_cons_ne S r rest i (by rintro v c rfl; exact hc ⟨v, c, rfl⟩),
            List.length_cons]
        split
        · omega
        · split
          · omega
          · split
            · have := ih (i + 1); omega
            · omega

theorem matchPrefixAux_le_S {α} [DecidableEq α] (S : List (Entry α)) :
    ∀ (exit : List (Ref α)) (i : Nat), i ≤ S.length → matchPrefixAux S i exit ≤ S.length := by
  intro exit
  induction exit with
  | nil => intro i hi; simp only [matchPrefixAux]; exact hi
  | cons r rest ih =>
      intro i hi
      by_cases hc : ∃ v c, r = Ref.const v c
      · obtain ⟨v, c, rfl⟩ := hc; simp only [matchPrefixAux]; exact hi
      · rw [matchPrefixAux_cons_ne S r rest i (by rintro v c rfl; exact hc ⟨v, c, rfl⟩)]
        split
        · exact hi
        · next heqS =>
            split
            · exact hi
            · split
              · exact ih (i + 1) (by obtain ⟨hlt, _⟩ := List.getElem?_eq_some_iff.mp heqS; omega)
              · exact hi

/-- ★ The matched bottom prefix of `S` reads out (as values) to the exit refs it matched. -/
theorem matchPrefix_map {α} [DecidableEq α] [Inhabited α] (M A : List α) (envF : Env α) :
    ∀ (exit : List (Ref α)) (S : List (Entry α)) (i : Nat),
      (List.take (matchPrefixAux S i exit - i) (S.drop i)).map (fun e => valOf M A envF e.tok)
        = (List.take (matchPrefixAux S i exit - i) exit).map (dRef M A envF) := by
  intro exit
  induction exit with
  | nil => intro S i; simp [matchPrefixAux]
  | cons r rest ih =>
      intro S i
      by_cases hc : ∃ v c, r = Ref.const v c
      · obtain ⟨v, c, rfl⟩ := hc; simp [matchPrefixAux]
      · rw [matchPrefixAux_cons_ne S r rest i (by rintro v c rfl; exact hc ⟨v, c, rfl⟩)]
        split
        · simp
        · next e heqS =>
            split
            · simp
            · split
              · next heq =>
                  obtain ⟨hi2, hSe⟩ := List.getElem?_eq_some_iff.mp heqS
                  have hge : i + 1 ≤ matchPrefixAux S (i + 1) rest := matchPrefixAux_ge S rest (i + 1)
                  have hdrop : S.drop i = e :: S.drop (i + 1) := by
                    rw [List.drop_eq_getElem_cons hi2, hSe]
                  have hsub : matchPrefixAux S (i + 1) rest - i
                      = (matchPrefixAux S (i + 1) rest - (i + 1)) + 1 := by omega
                  rw [hdrop, hsub, List.take_succ_cons, List.take_succ_cons,
                      List.map_cons, List.map_cons, ih S (i + 1)]
                  congr 1
                  rw [heq]; exact valOf_tokenOf M A envF r
              · simp

/-- `emitBuildRef` appends exactly one non-transient slot for the ref's token. -/
theorem emitBuildRef_S {α} [DecidableEq α] (r : Ref α) (ms : ModelState α) :
    (emitBuildRef r ms).S = ms.S ++ [(⟨tokenOf r, false⟩ : Entry α)] := by
  cases r with
  | inp i => simp only [emitBuildRef, tokenOf]; split <;> rfl
  | ainp i => simp only [emitBuildRef, tokenOf]; split <;> rfl
  | out nid j => simp only [emitBuildRef, tokenOf]; split <;> rfl
  | const v cse => cases cse with
      | false => rfl
      | true => simp only [emitBuildRef, tokenOf]; split <;> rfl

theorem buildFold_S {α} [DecidableEq α] (l : List (Ref α)) (ms : ModelState α) :
    (l.foldl (fun m r => emitBuildRef r m) ms).S
      = ms.S ++ l.map (fun r => (⟨tokenOf r, false⟩ : Entry α)) := by
  induction l generalizing ms with
  | nil => simp
  | cons x xs ih =>
      rw [List.foldl_cons, ih, emitBuildRef_S]
      simp [List.append_assoc, List.map_cons]

/-- The stale-tail delete fold removes exactly the `|D|` items sitting between the kept bottom
    prefix `P` and the freshly-built top `B` (`|B| = q`): `P ++ D ++ B ↦ P ++ B`. -/
theorem delFold_S {α} [DecidableEq α] (q : Nat) (P B : List (Entry α)) (hB : B.length = q) :
    ∀ (l : List Nat) (D : List (Entry α)) (ms : ModelState α),
      D.length = l.length → ms.S = P ++ D ++ B →
      (l.foldl (fun m _ => { m with ops := m.ops ++ delOps q,
                                    S := m.S.eraseIdx (m.S.length - 1 - q) }) ms).S = P ++ B := by
  intro l
  induction l with
  | nil =>
      intro D ms hD hS
      have : D = [] := by cases D with | nil => rfl | cons _ _ => simp at hD
      subst this; simpa using hS
  | cons x xs ih =>
      intro D ms hD hS
      have hDlen : 0 < D.length := by cases D with | nil => simp at hD | cons _ _ => simp
      have hDne : D ≠ [] := by cases D with | nil => simp at hD | cons _ _ => simp
      rw [List.foldl_cons]
      apply ih D.dropLast
      · rw [List.length_dropLast, hD]; simp
      · show ms.S.eraseIdx (ms.S.length - 1 - q) = P ++ D.dropLast ++ B
        rw [hS]
        rw [show ((P ++ D) ++ B).length - 1 - q = (P ++ D).length - 1 by
              rw [List.length_append, List.length_append, hB]; omega]
        rw [List.eraseIdx_append_of_lt_length (by rw [List.length_append]; omega) B,
            List.eraseIdx_length_sub_one, List.dropLast_append_of_ne_nil hDne]

/-- ★ The arrange output stack is the kept prefix plus the built exit suffix. -/
theorem emitExitMain_S {α} [DecidableEq α] (b : Block α) (ms : ModelState α)
    (hLS : matchPrefixAux ms.S 0 b.exit ≤ ms.S.length)
    (hLe : matchPrefixAux ms.S 0 b.exit ≤ b.exit.length) :
    (emitExitMain b ms).S = ms.S.take (matchPrefixAux ms.S 0 b.exit)
      ++ (b.exit.drop (matchPrefixAux ms.S 0 b.exit)).map (fun r => (⟨tokenOf r, false⟩ : Entry α)) := by
  unfold emitExitMain
  exact delFold_S (b.exit.length - matchPrefixAux ms.S 0 b.exit)
    (ms.S.take (matchPrefixAux ms.S 0 b.exit))
    ((b.exit.drop (matchPrefixAux ms.S 0 b.exit)).map (fun r => (⟨tokenOf r, false⟩ : Entry α)))
    (by rw [List.length_map, List.length_drop])
    (List.range (ms.S.length - matchPrefixAux ms.S 0 b.exit))
    (ms.S.drop (matchPrefixAux ms.S 0 b.exit))
    ((b.exit.drop (matchPrefixAux ms.S 0 b.exit)).foldl (fun m r => emitBuildRef r m) ms)
    (by rw [List.length_range, List.length_drop])
    (by rw [buildFold_S, List.take_append_drop])

/-- ★ FRONTIER (F4a) — CLOSED. The final MAIN stack reads out to the exit DAG layout: the kept
    prefix matches `b.exit`'s low refs (`matchPrefix_map`), the built suffix is `b.exit`'s high
    refs (`emitBuildRef` slots read via `valOf_tokenOf`), and together they are all of `b.exit`. -/
theorem final_readout_main {α} [DecidableEq α] [Inhabited α] (b : Block α) (_hwf : WellFormed b)
    (M A : List α) :
    readStack M A (blockEnv b M A) (scheduleBlock b).S
      = (b.exit.map (dRef M A (blockEnv b M A))).reverse := by
  rw [scheduleBlock_eq,
      emitExitMain_S b (exitAltPhase b) (matchPrefixAux_le_S _ _ 0 (Nat.zero_le _))
        (by have := matchPrefixAux_le_exit (exitAltPhase b).S b.exit 0; omega)]
  simp only [readStack, List.map_append]
  have h1 : ((exitAltPhase b).S.take (matchPrefixAux (exitAltPhase b).S 0 b.exit)).map
              (fun e => valOf M A (blockEnv b M A) e.tok)
          = (b.exit.take (matchPrefixAux (exitAltPhase b).S 0 b.exit)).map (dRef M A (blockEnv b M A)) := by
    have h := matchPrefix_map M A (blockEnv b M A) b.exit (exitAltPhase b).S 0
    simpa using h
  have h2 : (((b.exit.drop (matchPrefixAux (exitAltPhase b).S 0 b.exit)).map
                (fun r => (⟨tokenOf r, false⟩ : Entry α))).map
              (fun e => valOf M A (blockEnv b M A) e.tok))
          = (b.exit.drop (matchPrefixAux (exitAltPhase b).S 0 b.exit)).map (dRef M A (blockEnv b M A)) := by
    rw [List.map_map]
    exact List.map_congr_left (fun r _ => valOf_tokenOf M A (blockEnv b M A) r)
  rw [h1, h2, ← List.map_append, List.take_append_drop]

/-- ★ (F4b — PROVEN, 0 sorry): the final alt stack reads out to the exit-alt DAG layout.
    Closed by pure STRUCTURAL alt-stack bookkeeping (no liveness needed): the main-side
    primitives leave `Salt`; the DRAIN fold empties it; the EXIT-ALT fold deposits exactly
    `map (⟨tokenOf ·, false⟩)`. Passthrough sub-case: `Salt` untouched = seed, `exitAlt` =
    identity carry ⇒ both sides reduce to `A.reverse`; deposit sub-case tracks the TOALT fold. -/
theorem final_readout_alt {α} [DecidableEq α] [Inhabited α] (b : Block α) (_hwf : WellFormed b)
    (M A : List α) :
    readStack M A (blockEnv b M A) (scheduleBlock b).Salt
      = (b.exitAlt.map (dRef M A (blockEnv b M A))).reverse := by
  -- (scheduleBlock b).Salt = (exitAltPhase b).Salt  (the main arrange leaves Salt)
  have hsb : (scheduleBlock b).Salt = (exitAltPhase b).Salt := by
    rw [scheduleBlock_eq, emitExitMain_Salt]
  -- the node fold leaves Salt as the drain phase leaves it
  have hnodes : (nodesPhase b).Salt = (drainPhase b).Salt :=
    foldl_Salt_invariant (fun m n => emitNode n m) (fun m n => emitNode_Salt n m)
      b.nodes (drainPhase b)
  cases hp : altPassthrough b with
  | true =>
      -- PASSTHROUGH: Salt stays the seeded entry-alt slots; exitAlt = identity carry.
      have hdrain : (drainPhase b).Salt = (seedState b).Salt := by
        unfold drainPhase; simp only [hp, cond_true]
      have hea : (exitAltPhase b).Salt = (seedState b).Salt := by
        unfold exitAltPhase; simp only [hp, cond_true]; rw [hnodes, hdrain]
      have hexit : b.exitAlt = (List.range b.entryAlt).map (fun i => Ref.ainp i) := by
        have h := hp
        unfold altPassthrough at h
        simp only [Bool.and_eq_true, decide_eq_true_eq] at h
        exact h.2
      rw [hsb, hea, hexit]
      simp only [readStack, seedState, List.map_map]
      have hF : ((fun e => valOf M A (blockEnv b M A) e.tok) ∘
                 (fun i => (⟨Token.ainTok i, false⟩ : Entry α)))
              = ((dRef M A (blockEnv b M A)) ∘ (fun i => Ref.ainp i)) := by
        funext i; rfl
      rw [hF]
  | false =>
      -- DEPOSIT: drain empties Salt, then each exit-alt ref deposits its token.
      have hdrain : (drainPhase b).Salt = [] := by
        unfold drainPhase
        simp only [hp, cond_false]
        apply drainFold_Salt
        show ((List.range b.entryAlt).map (fun i => (⟨Token.ainTok i, false⟩ : Entry α))).length
              = (List.range b.entryAlt).reverse.length
        simp
      have hea : (exitAltPhase b).Salt
          = b.exitAlt.map (fun r => (⟨tokenOf r, false⟩ : Entry α)) := by
        unfold exitAltPhase
        simp only [hp, cond_false]
        rw [exitAltFold_Salt, hnodes, hdrain, List.nil_append]
      rw [hsb, hea]
      simp only [readStack, List.map_map]
      have hF : ((fun e => valOf M A (blockEnv b M A) e.tok) ∘
                 (fun r => (⟨tokenOf r, false⟩ : Entry α)))
              = dRef M A (blockEnv b M A) := by
        funext r; exact valOf_tokenOf M A (blockEnv b M A) r
      rw [hF]

/-- The two components of `denote` (definitional; `blockEnv = denoteNodes … (fun _ => [])`). -/
theorem denote_fst {α} [Inhabited α] (b : Block α) (M A : List α) :
    (denote b M A).1 = (b.exit.map (dRef M A (blockEnv b M A))).reverse := rfl
theorem denote_snd {α} [Inhabited α] (b : Block α) (M A : List α) :
    (denote b M A).2 = (b.exitAlt.map (dRef M A (blockEnv b M A))).reverse := rfl

/-- ★ GENERALIZED EXIT READ-OFF (algorithm-agnostic). Given the simulation invariant at ANY
    final model state `ms` together with the TWO terminal layout facts — that `ms.S` / `ms.Salt`
    read out to the exit / exit-alt DAG layouts — the concrete state IS the DAG denotation. This
    is `final_readout` with the two `final_readout_main`/`final_readout_alt` facts factored out as
    hypotheses: nothing about HOW `ms` was arranged is used, only the terminal read-off. Both the
    incremental (`emitExitMain`) and MOVE (`emitExitMove`) arranges feed this same lemma. -/
theorem final_readout_gen {α} [DecidableEq α] [Inhabited α] (b : Block α)
    (M A : List α) (ms : ModelState α) (st : State α)
    (hInv : Inv M A (blockEnv b M A) ms st)
    (hS   : readStack M A (blockEnv b M A) ms.S
              = (b.exit.map (dRef M A (blockEnv b M A))).reverse)
    (hSalt : readStack M A (blockEnv b M A) ms.Salt
              = (b.exitAlt.map (dRef M A (blockEnv b M A))).reverse) :
    st = denote b M A := by
  have e1 : st.1 = (denote b M A).1 := by rw [hInv.1, hS, denote_fst]
  have e2 : st.2 = (denote b M A).2 := by rw [hInv.2, hSalt, denote_snd]
  exact Prod.ext e1 e2

/-- The exit invariant pins the concrete state to the DAG denotation (PROVEN modulo F4).
    Now an INSTANCE of `final_readout_gen` at the incremental arrange (`scheduleBlock`). -/
theorem final_readout {α} [DecidableEq α] [Inhabited α] (b : Block α) (hwf : WellFormed b)
    (M A : List α) (st : State α)
    (hInv : Inv M A (blockEnv b M A) (scheduleBlock b) st) :
    st = denote b M A :=
  final_readout_gen b M A (scheduleBlock b) st hInv
    (final_readout_main b hwf M A) (final_readout_alt b hwf M A)

/-! ### ★ THE TOP THEOREM. -/

/-- ★ END-TO-END REFINEMENT (PROVEN modulo the F1–F4 frontier lemmas above): for every
    `WellFormed` block at matching entry sizes, running the EMITTED ops from the entry state
    reproduces the DAG denotation — the recompiler's PASS-2 output is a drop-in replacement for
    the original block on ALL inputs, for ANY valid topological node order. Combined with the
    (out-of-scope) decompile bridge `run(original) = denote`, this gives `run(emit) =
    run(original)`. The reduction here (seed invariant `inv_entry` → whole-schedule `StepOk`
    → exit read-off) is machine-checked with 0 sorry; only the phase lemmas remain. -/
theorem schedule_refines {α} [DecidableEq α] [Inhabited α] (b : Block α)
    (hwf : WellFormed b) (M A : List α)
    (hM : M.length = b.entryDepth) (hA : A.length = b.entryAlt) :
    run (emit b) (entryState M A) = some (denote b M A) := by
  have hInv0 : Inv M A (blockEnv b M A) (seedState b) (entryState M A) :=
    inv_entry b M A hM hA
  obtain ⟨δ, hδ, hrun⟩ := schedule_stepOk b hwf M A
  obtain ⟨st', hst', hInv'⟩ := hrun (entryState M A) hInv0
  have hδe : emit b = δ := by
    show (scheduleBlock b).ops = δ
    rw [hδ]; rfl
  rw [hδe, hst']
  exact congrArg some (final_readout b hwf M A st' hInv')

/-- ★★ THE GENERAL LAYOUT-REPRODUCTION LEMMA (algorithm-agnostic end-to-end refinement). For ANY
    model state `ms` reached from the seed by a `StepOk` chain (any StepOk-preserving emission,
    ANY arrange algorithm), IF its final main/alt stacks read out to the exit/exit-alt DAG
    layouts, THEN running its emitted ops from the entry state reproduces the DAG denotation.

    This is the precise analog of the theorem already decoupling correctness from NODE ORDER:
    `hstep` abstracts the construction; `hS`/`hSalt` abstract the terminal layout — nothing here
    constrains the arrange PRIMITIVES. `schedule_refines` (incremental arrange) is one instance;
    `schedule_refines_move` (MOVE-based exit arrange) is another, same shape. -/
theorem run_of_stepOk_layout {α} [DecidableEq α] [Inhabited α] (b : Block α)
    (M A : List α) (ms : ModelState α)
    (hstep : StepOk M A (blockEnv b M A) (seedState b) ms)
    (hS   : readStack M A (blockEnv b M A) ms.S
              = (b.exit.map (dRef M A (blockEnv b M A))).reverse)
    (hSalt : readStack M A (blockEnv b M A) ms.Salt
              = (b.exitAlt.map (dRef M A (blockEnv b M A))).reverse)
    (hM : M.length = b.entryDepth) (hA : A.length = b.entryAlt) :
    run ms.ops (entryState M A) = some (denote b M A) := by
  obtain ⟨δ, hδ, hrun⟩ := hstep
  have hInv0 : Inv M A (blockEnv b M A) (seedState b) (entryState M A) :=
    inv_entry b M A hM hA
  obtain ⟨st', hst', hInv'⟩ := hrun (entryState M A) hInv0
  have hops : ms.ops = δ := by rw [hδ]; rfl        -- (seedState b).ops = [] definitionally
  rw [hops, hst']
  exact congrArg some (final_readout_gen b M A ms st' hInv' hS hSalt)

/-- `schedule_refines` re-derived as an INSTANCE of the general lemma (sanity: the incremental
    arrange still goes through, unchanged behaviour). -/
theorem schedule_refines' {α} [DecidableEq α] [Inhabited α] (b : Block α)
    (hwf : WellFormed b) (M A : List α)
    (hM : M.length = b.entryDepth) (hA : A.length = b.entryAlt) :
    run (emit b) (entryState M A) = some (denote b M A) :=
  run_of_stepOk_layout b M A (scheduleBlock b) (schedule_stepOk b hwf M A)
    (final_readout_main b hwf M A) (final_readout_alt b hwf M A) hM hA

end Recompiler
