/-
  PASS-2 MOVE-BASED EXIT ARRANGE — a SECOND, structurally-distinct exit arrange (faithful model
  of tools/singleton-recompiler/scheduler.mjs with `opts.arrange='move'`, L273-346), proven sound
  as an INSTANCE of the general layout-reproduction lemma `run_of_stepOk_layout` (Compose.lean).

  ★ WHY THIS FILE EXISTS. The closed `schedule_refines` (Compose) proves the INCREMENTAL arrange
  (`emitExitMain`: keep prefix, COPY-only build, bulk-delete stale tail) sound. The 6,054-byte
  singleton floor was bought by the MOVE arrange instead: (1) drop dead homes, (2) build exit[L..]
  by MOVING (ROLL) each token on its LAST use / COPYING (PICK) earlier uses, NO bulk-delete. This
  is a DIFFERENT emitter. `run_of_stepOk_layout` decouples correctness from the arrange ALGORITHM
  (any StepOk chain from the seed that reaches the exit/exit-alt layout is sound); this file is the
  MOVE instance.

  ★ WHAT IS MACHINE-CHECKED HERE (0 sorry):
    • the FAITHFUL model (`deadDropPass`, `buildMovePass`, `scheduleBlockMove`) — real ops, real
      depth computations (windowed `depthOfHomeFrom` mirrors the scratch `homeUnplaced`);
    • `deadDropPass_stepOk` — the dead-drop pass is a `StepOk` UNCONDITIONALLY;
    • `moveAt_stepOk` — a generalized MOVE-at-known-depth builder (superset of `move_stepOk`:
      the arrange consumes a specific UNPLACED home while a shallower placed copy may exist);
    • `buildMovePass_stepOk` — the build is a `StepOk` under `BuildHomesOk` (the static analog of
      the scratch self-check), reusing `push`/`copy`/`moveAt` builders;
    • `final_readout_move_alt` — the alt stack reproduces the exit-alt layout (arrange leaves Salt);
    • `schedule_refines_move` — SOUNDNESS as an instance of `run_of_stepOk_layout`, CONDITIONAL on
      the two decidable success conditions (`hHomes`, `hReach`) that the scratch checks at emit time
      (it THROWS on failure — never silently miscompiles), so this is the correct "certified pass
      that may reject" soundness.

  ★ THE HONEST FRONTIER: `hHomes` (build lookups succeed) and `hReach` (arrange reaches the exit
  layout) are left as HYPOTHESES, NOT `sorry`. Discharging them for ALL `WellFormed` blocks is
  FALSE in general (the arrange can mis-place / not-find a home — exactly what the self-check
  catches); a full discharge would need the multiset/permutation home-existence invariant on the
  unplaced region (future work). Stating them as hypotheses (not axioms/sorry) keeps this file
  0-sorry and asserts nothing false.

  Lean 4.31 core, NO mathlib.
-/
import Recompiler.Compose
import Recompiler.NoNullHome

namespace Recompiler
open Op

/-! ### ★ MOVE-BASED EXIT ARRANGE — faithful model of scheduler.mjs `opts.arrange='move'`
    (L273-346). -/

/-- A token is EXIT-NEEDED iff it is (`tokenOf`) an exit ref — the scratch `need` keyset. -/
def neededTok [DecidableEq α] (b : Block α) (t : Token α) : Bool :=
  b.exit.any (fun r => decide (tokenOf r = t))

/-- Windowed home lookup (scratch `homeUnplaced(tok, placed) = depthOfHome(tok, |S|-placed)`):
    the depth-from-top of the topmost live (non-transient) home of `tok` NOT among the top
    `placed` slots (the "unplaced" region). Depth is measured in the FULL stack (for ROLL). -/
def depthOfHomeFrom [DecidableEq α] (S : List (Entry α)) (placed : Nat) (tok : Token α) :
    Option Nat :=
  ((S.reverse.drop placed).findIdx? (fun e => (!e.transient) && decide (e.tok = tok))).map
    (· + placed)

/-- ★ VALUE lemma for the windowed lookup (analog of `depthOfHome_value`): a `some d` windowed
    home lands on concrete depth `d < |S|` holding the token's denoted value. -/
theorem depthOfHomeFrom_value {α} [DecidableEq α] [Inhabited α]
    (M A : List α) (envF : Env α) (S : List (Entry α)) (placed : Nat) (tok : Token α) (d : Nat)
    (hdh : depthOfHomeFrom S placed tok = some d) :
    d < S.length ∧ (readStack M A envF S)[d]? = some (valOf M A envF tok) := by
  unfold depthOfHomeFrom at hdh
  rw [Option.map_eq_some_iff] at hdh
  obtain ⟨j, hj, hd⟩ := hdh
  rw [List.findIdx?_eq_some_iff_getElem] at hj
  obtain ⟨hjlt, hp, _⟩ := hj
  rw [List.length_drop, List.length_reverse] at hjlt
  have hd' : d = placed + j := by omega
  have hdlt : d < S.length := by omega
  refine ⟨hdlt, ?_⟩
  simp only [Bool.and_eq_true, Bool.not_eq_true', decide_eq_true_eq] at hp
  obtain ⟨_, htok⟩ := hp
  rw [List.getElem_drop] at htok
  have hrs : readStack M A envF S = S.reverse.map (fun e => valOf M A envF e.tok) := by
    simp only [readStack]; rw [← List.map_reverse]
  rw [hrs, hd', List.getElem?_map,
      List.getElem?_eq_getElem (show placed + j < S.reverse.length by
        rw [List.length_reverse]; omega)]
  simp only [Option.map_some]
  rw [htok]

/-- ★ GENERALIZED MOVE BUILDER (move a home at a KNOWN depth `d`, not necessarily the topmost:
    the move-arrange consumes a specific unplaced home while a shallower PLACED copy may exist).
    Keyed on the concrete value at depth `d` (via the windowed lookup), reusing `run_moveOps` +
    `readStack_eraseIdx`. Superset of `move_stepOk`. -/
theorem moveAt_stepOk {α} [DecidableEq α] [Inhabited α] {M A : List α} {envF : Env α}
    {ms ms' : ModelState α} (e : Entry α) (d : Nat) (hd : d < ms.S.length)
    (hval : (readStack M A envF ms.S)[d]? = some (valOf M A envF e.tok))
    (hops : ms'.ops = ms.ops ++ moveOps d)
    (hS : ms'.S = ms.S.eraseIdx (ms.S.length - 1 - d) ++ [e]) (hSalt : ms'.Salt = ms.Salt) :
    StepOk M A envF ms ms' := by
  refine ⟨moveOps d, hops, ?_⟩
  intro st hInv
  obtain ⟨m, a⟩ := st
  have h1 : m = readStack M A envF ms.S := hInv.1
  have h2 : a = readStack M A envF ms.Salt := hInv.2
  have hd1 : d < m.length := by rw [h1, readStack_length]; exact hd
  have hmd : m[d] = valOf M A envF e.tok := by
    have hq : m[d]? = some (valOf M A envF e.tok) := by rw [h1]; exact hval
    rw [List.getElem?_eq_getElem hd1] at hq; exact Option.some.inj hq
  refine ⟨(m[d] :: removeNth m d, a), run_moveOps d m a hd1, ?_, ?_⟩
  · show m[d] :: removeNth m d = readStack M A envF ms'.S
    rw [hS, readStack_append, hmd, readStack_eraseIdx M A envF ms.S d hd, h1]
  · show a = readStack M A envF ms'.Salt
    rw [hSalt]; exact h2

/-! ### The two model passes. -/

/-- The index (into `S`) of the SHALLOWEST (largest index) live non-transient dead (non-needed)
    home at index ≥ `L`, or `none`. (Scratch dead-drop selection, L287-299.) -/
def deadIdx [DecidableEq α] (b : Block α) (L : Nat) (S : List (Entry α)) : Option Nat :=
  (List.range S.length).reverse.find? (fun i =>
    decide (L ≤ i) &&
      (match S[i]? with
       | some e => (!e.transient) && (!neededTok b e.tok)
       | none   => false))

/-- (1) DEAD-DROP PASS: repeatedly delete the shallowest dead home ≥ `L` (fuel = |S|). Each
    deletion erases the element at its index `i` (concrete depth `|S|-1-i`) via `delOps`. NO
    bulk-delete of live homes (the whole point vs `emitExitMain`'s `delFold`). -/
def deadDropPass [DecidableEq α] (b : Block α) (L : Nat) : Nat → ModelState α → ModelState α
  | 0,        ms => ms
  | fuel + 1, ms =>
      match deadIdx b L ms.S with
      | none   => ms
      | some i =>
          deadDropPass b L fuel
            { ms with ops := ms.ops ++ delOps (ms.S.length - 1 - i), S := ms.S.eraseIdx i }

/-- (2) BUILD PASS: scan `exit[L..]` left→right, tracking `placed` (count built on top).
    MOVE on last occurrence (window lookup `depthOfHomeFrom`), COPY earlier occurrences
    (`depthOfHome`), fresh-PUSH small consts. (Scratch build, L300-337.) The `none` fallbacks
    mirror the scratch's const-push fallback / are `WellFormed`-excluded for slots. -/
def buildMovePass [DecidableEq α] : List (Ref α) → Nat → ModelState α → ModelState α
  | [],        _,      ms => ms
  | r :: rest, placed, ms =>
      match r with
      | .const v false =>
          buildMovePass rest (placed + 1)
            { ms with ops := ms.ops ++ [Op.PUSH v], S := ms.S ++ [⟨Token.nullTok v, false⟩] }
      | _ =>
          let tok := tokenOf r
          if tok ∈ rest.map tokenOf then
            -- not last occurrence within exit[L..]: COPY from shallowest live home
            match depthOfHome ms.S tok with
            | some d =>
                buildMovePass rest (placed + 1)
                  { ms with ops := ms.ops ++ copyOps d, S := ms.S ++ [⟨tok, false⟩] }
            | none =>
                buildMovePass rest (placed + 1) { ms with S := ms.S ++ [⟨tok, false⟩] }
          else
            -- last occurrence: MOVE the original home from the unplaced region
            match depthOfHomeFrom ms.S placed tok with
            | some d =>
                buildMovePass rest (placed + 1)
                  { ms with ops := ms.ops ++ moveOps d,
                            S := ms.S.eraseIdx (ms.S.length - 1 - d) ++ [⟨tok, false⟩] }
            | none =>
                buildMovePass rest (placed + 1) { ms with S := ms.S ++ [⟨tok, false⟩] }

/-- ★ `scheduleBlockMove` — the whole emitter with the MOVE-based exit arrange substituted for
    the incremental one. First three phases (drain · nodes · exit-alt) are SHARED with
    `scheduleBlock`; only the final arrange differs. -/
def scheduleBlockMove [DecidableEq α] (b : Block α) : ModelState α :=
  let ms := exitAltPhase b
  let L  := matchPrefixAux ms.S 0 b.exit
  let ms1 := deadDropPass b L ms.S.length ms
  buildMovePass (b.exit.drop L) 0 ms1

/-- The emitted op-list for the MOVE arrange. -/
def emitMove [DecidableEq α] (b : Block α) : List (Op α) := (scheduleBlockMove b).ops

/-! ### Salt bookkeeping (structural; both passes leave `Salt`). -/

theorem deadDropPass_Salt {α} [DecidableEq α] (b : Block α) (L : Nat) :
    ∀ (fuel : Nat) (ms : ModelState α), (deadDropPass b L fuel ms).Salt = ms.Salt := by
  intro fuel
  induction fuel with
  | zero => intro ms; rfl
  | succ fuel ih =>
      intro ms
      unfold deadDropPass
      cases deadIdx b L ms.S with
      | none => rfl
      | some i => rw [ih]

theorem buildMovePass_Salt {α} [DecidableEq α] :
    ∀ (l : List (Ref α)) (placed : Nat) (ms : ModelState α),
      (buildMovePass l placed ms).Salt = ms.Salt := by
  intro l
  induction l with
  | nil => intro placed ms; rfl
  | cons r rest ih =>
      intro placed ms
      unfold buildMovePass
      split
      · rw [ih]
      · dsimp only; split <;> split <;> rw [ih]

theorem scheduleBlockMove_Salt {α} [DecidableEq α] (b : Block α) :
    (scheduleBlockMove b).Salt = (exitAltPhase b).Salt := by
  unfold scheduleBlockMove
  rw [buildMovePass_Salt, deadDropPass_Salt]

/-- The MOVE arrange reproduces the exit-alt layout on the alt stack — REUSES `final_readout_alt`
    (the alt stack is untouched by BOTH arranges). 0 sorry. -/
theorem final_readout_move_alt {α} [DecidableEq α] [Inhabited α] (b : Block α) (hwf : WellFormed b)
    (M A : List α) :
    readStack M A (blockEnv b M A) (scheduleBlockMove b).Salt
      = (b.exitAlt.map (dRef M A (blockEnv b M A))).reverse := by
  have h1 : (scheduleBlockMove b).Salt = (exitAltPhase b).Salt := scheduleBlockMove_Salt b
  have h2 : (scheduleBlock b).Salt = (exitAltPhase b).Salt := by
    rw [scheduleBlock_eq, emitExitMain_Salt]
  rw [h1, ← h2]
  exact final_readout_alt b hwf M A

/-! ### Dead-drop pass is a StepOk (0 sorry — deletes only valid indices). -/

theorem deadIdx_lt {α} [DecidableEq α] (b : Block α) (L : Nat) (S : List (Entry α)) (i : Nat)
    (h : deadIdx b L S = some i) : i < S.length := by
  unfold deadIdx at h
  have hmem := List.find?_some h
  have : i ∈ (List.range S.length).reverse := List.mem_of_find?_eq_some h
  rw [List.mem_reverse, List.mem_range] at this
  exact this

theorem deadDropPass_stepOk {α} [DecidableEq α] [Inhabited α] {M A : List α} {envF : Env α}
    (b : Block α) (L : Nat) :
    ∀ (fuel : Nat) (ms : ModelState α), StepOk M A envF ms (deadDropPass b L fuel ms) := by
  intro fuel
  induction fuel with
  | zero => intro ms; exact StepOk.refl M A envF ms
  | succ fuel ih =>
      intro ms
      unfold deadDropPass
      cases hdi : deadIdx b L ms.S with
      | none => exact StepOk.refl M A envF ms
      | some i =>
          have hilt : i < ms.S.length := deadIdx_lt b L ms.S i hdi
          have hd : ms.S.length - 1 - i < ms.S.length := by omega
          have hidx : ms.S.length - 1 - (ms.S.length - 1 - i) = i := by omega
          have step1 : StepOk M A envF ms
              { ms with ops := ms.ops ++ delOps (ms.S.length - 1 - i), S := ms.S.eraseIdx i } :=
            del_stepOk
              (ms' := { ms with ops := ms.ops ++ delOps (ms.S.length - 1 - i),
                                S := ms.S.eraseIdx i })
              (ms.S.length - 1 - i) hd rfl (by rw [hidx]) rfl
          exact step1.trans (ih _)

/-! ### Build pass is a StepOk WHEN every home lookup succeeds (the static analog of the scratch
    self-check / no-throw condition). This discharges ARCHITECT obligation (i) — each emitted op
    is a `StepOk` primitive, reusing `push`/`copy`/`moveAt`-builders — CONDITIONAL on the
    decidable, harness-checkable success predicate `BuildHomesOk`. Non-vacuous: the `none`
    (home-not-found) fallbacks are exactly where the scratch throws. -/

/-- The build succeeds (no home-lookup falls through to a `none` fallback), threaded through the
    SAME recursion / successor states as `buildMovePass`. Mirrors "the move-arrange doesn't throw
    a `home not found`". -/
def BuildHomesOk [DecidableEq α] : List (Ref α) → Nat → ModelState α → Prop
  | [],        _,      _  => True
  | r :: rest, placed, ms =>
      match r with
      | .const v false =>
          BuildHomesOk rest (placed + 1)
            { ms with ops := ms.ops ++ [Op.PUSH v], S := ms.S ++ [⟨Token.nullTok v, false⟩] }
      | _ =>
          let tok := tokenOf r
          if tok ∈ rest.map tokenOf then
            match depthOfHome ms.S tok with
            | some d =>
                BuildHomesOk rest (placed + 1)
                  { ms with ops := ms.ops ++ copyOps d, S := ms.S ++ [⟨tok, false⟩] }
            | none => False
          else
            match depthOfHomeFrom ms.S placed tok with
            | some d =>
                BuildHomesOk rest (placed + 1)
                  { ms with ops := ms.ops ++ moveOps d,
                            S := ms.S.eraseIdx (ms.S.length - 1 - d) ++ [⟨tok, false⟩] }
            | none => False

/-- Equation lemma: for a NON-(const false) ref, `buildMovePass` unfolds to the inner if/match
    keyed on `tokenOf r`. (Const-true is the CSE-home case; all slots the same shape.) -/
theorem buildMovePass_cons_nc {α} [DecidableEq α] (r : Ref α) (rest : List (Ref α))
    (placed : Nat) (ms : ModelState α) (hnc : ∀ v, r ≠ Ref.const v false) :
    buildMovePass (r :: rest) placed ms =
      (if tokenOf r ∈ rest.map tokenOf then
         match depthOfHome ms.S (tokenOf r) with
         | some d =>
             buildMovePass rest (placed + 1)
               { ms with ops := ms.ops ++ copyOps d, S := ms.S ++ [⟨tokenOf r, false⟩] }
         | none => buildMovePass rest (placed + 1) { ms with S := ms.S ++ [⟨tokenOf r, false⟩] }
       else
         match depthOfHomeFrom ms.S placed (tokenOf r) with
         | some d =>
             buildMovePass rest (placed + 1)
               { ms with ops := ms.ops ++ moveOps d,
                         S := ms.S.eraseIdx (ms.S.length - 1 - d) ++ [⟨tokenOf r, false⟩] }
         | none => buildMovePass rest (placed + 1) { ms with S := ms.S ++ [⟨tokenOf r, false⟩] }) := by
  cases r with
  | inp i => rfl
  | ainp i => rfl
  | out nid j => rfl
  | const v cse => cases cse with | false => exact absurd rfl (hnc v) | true => rfl

/-- Equation lemma: `BuildHomesOk` unfolds the same way for a NON-(const false) ref. -/
theorem BuildHomesOk_cons_nc {α} [DecidableEq α] (r : Ref α) (rest : List (Ref α))
    (placed : Nat) (ms : ModelState α) (hnc : ∀ v, r ≠ Ref.const v false) :
    BuildHomesOk (r :: rest) placed ms =
      (if tokenOf r ∈ rest.map tokenOf then
         match depthOfHome ms.S (tokenOf r) with
         | some d =>
             BuildHomesOk rest (placed + 1)
               { ms with ops := ms.ops ++ copyOps d, S := ms.S ++ [⟨tokenOf r, false⟩] }
         | none => False
       else
         match depthOfHomeFrom ms.S placed (tokenOf r) with
         | some d =>
             BuildHomesOk rest (placed + 1)
               { ms with ops := ms.ops ++ moveOps d,
                         S := ms.S.eraseIdx (ms.S.length - 1 - d) ++ [⟨tokenOf r, false⟩] }
         | none => False) := by
  cases r with
  | inp i => rfl
  | ainp i => rfl
  | out nid j => rfl
  | const v cse => cases cse with | false => exact absurd rfl (hnc v) | true => rfl

theorem buildMovePass_stepOk {α} [DecidableEq α] [Inhabited α] {M A : List α} {envF : Env α} :
    ∀ (l : List (Ref α)) (placed : Nat) (ms : ModelState α),
      BuildHomesOk l placed ms → StepOk M A envF ms (buildMovePass l placed ms) := by
  intro l
  induction l with
  | nil => intro placed ms _; exact StepOk.refl M A envF ms
  | cons r rest ih =>
      intro placed ms hHomes
      by_cases hcf : ∃ v, r = Ref.const v false
      · obtain ⟨v, rfl⟩ := hcf
        show StepOk M A envF ms
          (buildMovePass rest (placed + 1)
            { ms with ops := ms.ops ++ [Op.PUSH v], S := ms.S ++ [⟨Token.nullTok v, false⟩] })
        refine (push_stepOk
                  (ms' := { ms with ops := ms.ops ++ [Op.PUSH v],
                                    S := ms.S ++ [⟨Token.nullTok v, false⟩] })
                  (⟨Token.nullTok v, false⟩) v rfl rfl rfl rfl).trans (ih _ _ ?_)
        exact hHomes
      · have hnc : ∀ w, r ≠ Ref.const w false := fun w h => hcf ⟨w, h⟩
        rw [buildMovePass_cons_nc r rest placed ms hnc]
        rw [BuildHomesOk_cons_nc r rest placed ms hnc] at hHomes
        by_cases hmem : tokenOf r ∈ rest.map tokenOf
        · rw [if_pos hmem] at hHomes ⊢
          cases hdh : depthOfHome ms.S (tokenOf r) with
          | none => rw [hdh] at hHomes; exact hHomes.elim
          | some d =>
              rw [hdh] at hHomes
              show StepOk M A envF ms
                (buildMovePass rest (placed + 1)
                  { ms with ops := ms.ops ++ copyOps d, S := ms.S ++ [⟨tokenOf r, false⟩] })
              exact (copy_stepOk
                       (ms' := { ms with ops := ms.ops ++ copyOps d, S := ms.S ++ [⟨tokenOf r, false⟩] })
                       (⟨tokenOf r, false⟩) d hdh rfl rfl rfl).trans (ih _ _ hHomes)
        · rw [if_neg hmem] at hHomes ⊢
          cases hdh : depthOfHomeFrom ms.S placed (tokenOf r) with
          | none => rw [hdh] at hHomes; exact hHomes.elim
          | some d =>
              rw [hdh] at hHomes
              obtain ⟨hdlt, hval⟩ := depthOfHomeFrom_value M A envF ms.S placed (tokenOf r) d hdh
              show StepOk M A envF ms
                (buildMovePass rest (placed + 1)
                  { ms with ops := ms.ops ++ moveOps d,
                            S := ms.S.eraseIdx (ms.S.length - 1 - d) ++ [⟨tokenOf r, false⟩] })
              exact (moveAt_stepOk
                       (ms' := { ms with ops := ms.ops ++ moveOps d,
                                         S := ms.S.eraseIdx (ms.S.length - 1 - d) ++ [⟨tokenOf r, false⟩] })
                       (⟨tokenOf r, false⟩) d hdlt hval rfl rfl rfl).trans (ih _ _ hHomes)

/-! ### ★ INSTANTIATE THE GENERAL LEMMA FOR THE MOVE ARRANGE. -/

/-- The kept-prefix length for the move arrange (same `matchPrefixAux` as the incremental one). -/
def moveL [DecidableEq α] (b : Block α) : Nat := matchPrefixAux (exitAltPhase b).S 0 b.exit

/-- The post-dead-drop model state (fuel = full stack height). -/
def moveDead [DecidableEq α] (b : Block α) : ModelState α :=
  deadDropPass b (moveL b) (exitAltPhase b).S.length (exitAltPhase b)

/-- Seed → exit-alt: the first THREE phases (drain · nodes · exit-alt), SHARED with the
    incremental schedule (extracted from `schedule_stepOk`). -/
theorem toExitAlt_stepOk {α} [DecidableEq α] [Inhabited α] (b : Block α) (hwf : WellFormed b)
    (M A : List α) :
    StepOk M A (blockEnv b M A) (seedState b) (exitAltPhase b) :=
  (drain_stepOk b M A).trans ((nodes_stepOk b hwf M A).trans (exitAlt_stepOk b hwf M A))

/-- ★ THE MOVE ARRANGE IS A `StepOk` (dead-drop · build), CONDITIONAL on the build succeeding
    (`hHomes` — the static analog of the scratch self-check / no-`throw`). Dead-drop is a StepOk
    unconditionally (`deadDropPass_stepOk`); the build is a StepOk under `hHomes`
    (`buildMovePass_stepOk`, reusing `push`/`copy`/`moveAt`-builders). -/
theorem emitExitMove_stepOk {α} [DecidableEq α] [Inhabited α] (b : Block α) (M A : List α)
    (hHomes : BuildHomesOk (b.exit.drop (moveL b)) 0 (moveDead b)) :
    StepOk M A (blockEnv b M A) (exitAltPhase b) (scheduleBlockMove b) := by
  show StepOk M A (blockEnv b M A) (exitAltPhase b)
    (buildMovePass (b.exit.drop (moveL b)) 0 (moveDead b))
  have h1 : StepOk M A (blockEnv b M A) (exitAltPhase b) (moveDead b) :=
    deadDropPass_stepOk b (moveL b) (exitAltPhase b).S.length (exitAltPhase b)
  have h2 : StepOk M A (blockEnv b M A) (moveDead b)
      (buildMovePass (b.exit.drop (moveL b)) 0 (moveDead b)) :=
    buildMovePass_stepOk _ 0 _ hHomes
  exact h1.trans h2

/-- ★★ SOUNDNESS OF THE MOVE ARRANGE (instance of `run_of_stepOk_layout`). Given the two static
    SUCCESS conditions — the build's home lookups succeed (`hHomes`) and the arranged main stack
    reaches the exit layout (`hReach`) — the MOVE-emitted ops reproduce the DAG denotation. These
    two hypotheses ARE the compile-time analog of the scratch's runtime self-check (which
    THROWS if either fails, never silently miscompiling). The alt-stack side (`hSalt`) is
    discharged outright (`final_readout_move_alt`: the arrange leaves `Salt`), and every op is a
    verified `StepOk` primitive. 0 sorry. -/
theorem schedule_refines_move {α} [DecidableEq α] [Inhabited α] (b : Block α)
    (hwf : WellFormed b) (M A : List α)
    (hM : M.length = b.entryDepth) (hA : A.length = b.entryAlt)
    (hHomes : BuildHomesOk (b.exit.drop (moveL b)) 0 (moveDead b))
    (hReach : readStack M A (blockEnv b M A) (scheduleBlockMove b).S
              = (b.exit.map (dRef M A (blockEnv b M A))).reverse) :
    run (emitMove b) (entryState M A) = some (denote b M A) :=
  run_of_stepOk_layout b M A (scheduleBlockMove b)
    ((toExitAlt_stepOk b hwf M A).trans (emitExitMove_stepOk b M A hHomes))
    hReach
    (final_readout_move_alt b hwf M A) hM hA

/-! ### ★ DISCHARGING `hHomes` FROM `WellFormed` (the tractable frontier half — a home-EXISTENCE
    invariant). Every home the build needs exists: exit refs have a home at the exit-alt phase
    (`exit_RefHasHome`, reusing `exitAltPhase_R4`); the dead-drop drops only NON-needed homes so it
    preserves every exit token's home (`deadDropPass_preserves_needed`); and the windowed build
    invariant (`buildMovePass_homes`, keyed on `depthOfHomeFrom_split`) shows each COPY/MOVE lookup
    succeeds because its token still has a home in the current `base` (unplaced) region. The one
    honest CORNER: a use-once CSE `const _ true` exit ref has no `WellFormed`-guaranteed home, so it
    is supplied as a small decidable side condition (`hct`) — NOT vacuous, NOT faked. -/

/-- Windowed lookup over `base ++ built` dropping exactly `|built|` = the `base` lookup shifted by
    `|built|`. The positional bridge that lets the build's MOVE see exactly the unplaced region. -/
theorem depthOfHomeFrom_split {α} [DecidableEq α]
    (base built : List (Entry α)) (tok : Token α) :
    depthOfHomeFrom (base ++ built) built.length tok
      = (depthOfHome base tok).map (· + built.length) := by
  unfold depthOfHomeFrom depthOfHome
  rw [List.reverse_append]
  have hlen : built.length = built.reverse.length := by rw [List.length_reverse]
  rw [hlen, List.drop_left]

/-- ★ THE WINDOWED HOME INVARIANT: if every non-(const false) ref in `l` has a home in `base`, and
    `ms.S = base ++ built` with `built.length = placed`, the build's lookups ALL succeed (no `none`
    fallback). Induction on `l`; PUSH/COPY only append to `built` (base unchanged); the last-use
    MOVE erases only its OWN token's base home (`depthOfHome_home_entry` + `any_eraseIdx_of_ne`),
    which no remaining ref needs (`if_neg hmem`). -/
theorem buildMovePass_homes {α} [DecidableEq α] :
    ∀ (l : List (Ref α)) (placed : Nat) (ms : ModelState α) (base built : List (Entry α)),
      ms.S = base ++ built → built.length = placed →
      (∀ r' ∈ l, (∀ v, r' ≠ Ref.const v false) → (depthOfHome base (tokenOf r')).isSome = true) →
      BuildHomesOk l placed ms := by
  intro l
  induction l with
  | nil => intro placed ms base built _ _ _; exact True.intro
  | cons r rest ih =>
      intro placed ms base built hS hlen hHomes
      by_cases hcf : ∃ v, r = Ref.const v false
      · obtain ⟨v, rfl⟩ := hcf
        show BuildHomesOk rest (placed + 1)
          { ms with ops := ms.ops ++ [Op.PUSH v], S := ms.S ++ [⟨Token.nullTok v, false⟩] }
        apply ih (placed + 1) _ base (built ++ [⟨Token.nullTok v, false⟩])
        · show ms.S ++ [⟨Token.nullTok v, false⟩] = base ++ (built ++ [⟨Token.nullTok v, false⟩])
          rw [hS, List.append_assoc]
        · rw [List.length_append, hlen]; rfl
        · intro r' hr' hnc'
          exact hHomes r' (List.mem_cons.mpr (Or.inr hr')) hnc'
      · have hnc : ∀ w, r ≠ Ref.const w false := fun w h => hcf ⟨w, h⟩
        rw [BuildHomesOk_cons_nc r rest placed ms hnc]
        have hbaseHome : (depthOfHome base (tokenOf r)).isSome = true :=
          hHomes r (List.mem_cons_self ..) (by intro v hv; cases hv; exact (hnc v) rfl)
        by_cases hmem : tokenOf r ∈ rest.map tokenOf
        · rw [if_pos hmem]
          have hmsHome : (depthOfHome ms.S (tokenOf r)).isSome = true := by
            rw [hS]; exact depthOfHome_isSome_append_list built base (tokenOf r) hbaseHome
          cases hdh : depthOfHome ms.S (tokenOf r) with
          | none => rw [hdh] at hmsHome; exact absurd hmsHome (by simp)
          | some d =>
              show BuildHomesOk rest (placed + 1)
                { ms with ops := ms.ops ++ copyOps d, S := ms.S ++ [⟨tokenOf r, false⟩] }
              apply ih (placed + 1) _ base (built ++ [⟨tokenOf r, false⟩])
              · show ms.S ++ [⟨tokenOf r, false⟩] = base ++ (built ++ [⟨tokenOf r, false⟩])
                rw [hS, List.append_assoc]
              · rw [List.length_append, hlen]; rfl
              · intro r' hr' hnc'
                exact hHomes r' (List.mem_cons.mpr (Or.inr hr')) hnc'
        · rw [if_neg hmem]
          obtain ⟨d0, hd0⟩ := Option.isSome_iff_exists.mp hbaseHome
          have hsplit : depthOfHomeFrom ms.S placed (tokenOf r) = some (d0 + placed) := by
            rw [hS, ← hlen, depthOfHomeFrom_split, hd0]; rfl
          rw [hsplit]
          obtain ⟨hd0lt, hhome⟩ := depthOfHome_home_entry base (tokenOf r) d0 hd0
          have hidx : ms.S.length - 1 - (d0 + placed) = base.length - 1 - d0 := by
            rw [hS, List.length_append, ← hlen]; omega
          have hidxlt : base.length - 1 - d0 < base.length := by omega
          have heraseS : ms.S.eraseIdx (ms.S.length - 1 - (d0 + placed)) ++ [⟨tokenOf r, false⟩]
              = (base.eraseIdx (base.length - 1 - d0)) ++ (built ++ [⟨tokenOf r, false⟩]) := by
            rw [hidx, hS, List.eraseIdx_append_of_lt_length hidxlt built, List.append_assoc]
          show BuildHomesOk rest (placed + 1)
            { ms with ops := ms.ops ++ moveOps (d0 + placed),
                      S := ms.S.eraseIdx (ms.S.length - 1 - (d0 + placed)) ++ [⟨tokenOf r, false⟩] }
          apply ih (placed + 1) _ (base.eraseIdx (base.length - 1 - d0))
                   (built ++ [⟨tokenOf r, false⟩])
          · exact heraseS
          · rw [List.length_append, hlen]; rfl
          · intro r' hr' hnc'
            have hne : tokenOf r' ≠ tokenOf r := by
              intro heq; exact hmem (heq ▸ List.mem_map_of_mem hr')
            have hbase' : (depthOfHome base (tokenOf r')).isSome = true :=
              hHomes r' (List.mem_cons.mpr (Or.inr hr')) hnc'
            rw [depthOfHome_isSome_iff] at hbase' ⊢
            apply any_eraseIdx_of_ne _ _ _ hidxlt hbase'
            simp only [homeP, Bool.and_eq_true, decide_eq_true_eq] at hhome
            simp only [homeP, Bool.and_eq_false_iff]
            right
            rw [hhome.2]
            simp only [decide_eq_false_iff_not]
            exact fun h => hne h.symm

/-- The `deadIdx`-selected index holds a live, NON-needed home (extracts the `find?` predicate). -/
theorem deadIdx_spec {α} [DecidableEq α] (b : Block α) (L : Nat) (S : List (Entry α)) (i : Nat)
    (h : deadIdx b L S = some i) :
    ∃ e, S[i]? = some e ∧ e.transient = false ∧ neededTok b e.tok = false := by
  unfold deadIdx at h
  have hp := List.find?_some h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at hp
  obtain ⟨_, hmatch⟩ := hp
  cases hSi : S[i]? with
  | none => rw [hSi] at hmatch; exact absurd hmatch (by simp)
  | some e =>
      rw [hSi] at hmatch
      simp only [Bool.and_eq_true, Bool.not_eq_true'] at hmatch
      exact ⟨e, rfl, by simp_all, by simp_all⟩

/-- Dead-drop preserves the home of any NEEDED (exit) token: it only erases NON-needed homes, whose
    tokens therefore differ from any needed `t` (`any_eraseIdx_of_ne`). -/
theorem deadDropPass_preserves_needed {α} [DecidableEq α] (b : Block α) (L : Nat)
    (t : Token α) (hneed : neededTok b t = true) :
    ∀ (fuel : Nat) (ms : ModelState α), (depthOfHome ms.S t).isSome = true →
      (depthOfHome (deadDropPass b L fuel ms).S t).isSome = true := by
  intro fuel
  induction fuel with
  | zero => intro ms h; exact h
  | succ fuel ih =>
      intro ms h
      unfold deadDropPass
      cases hdi : deadIdx b L ms.S with
      | none => exact h
      | some i =>
          apply ih
          have hilt : i < ms.S.length := deadIdx_lt b L ms.S i hdi
          obtain ⟨e, hSi, _, hne⟩ := deadIdx_spec b L ms.S i hdi
          have hget : ms.S[i] = e := by
            have := List.getElem?_eq_getElem hilt; rw [hSi] at this; exact (Option.some.inj this).symm
          rw [depthOfHome_isSome_iff] at h ⊢
          apply any_eraseIdx_of_ne _ _ _ hilt h
          rw [hget]
          simp only [homeP, Bool.and_eq_false_iff]
          right
          have htne : e.tok ≠ t := by intro heq; rw [heq, hneed] at hne; exact absurd hne (by simp)
          simp only [decide_eq_false_iff_not]; exact htne

/-- Membership in `b.exit` ⇒ the ref's token is exit-needed. -/
theorem neededTok_of_mem {α} [DecidableEq α] (b : Block α) (r : Ref α) (hr : r ∈ b.exit) :
    neededTok b (tokenOf r) = true := by
  unfold neededTok; rw [List.any_eq_true]; exact ⟨r, hr, by simp⟩

/-- A non-const exit ref has a home at the exit-alt phase (the same fact `arrange_stepOk` uses,
    named for reuse — via `exitAltPhase_R4` + `occCount_ge_of_mem` + the `WellFormed` bounds). -/
theorem exit_RefHasHome {α} [DecidableEq α] [Inhabited α] (b : Block α) (hwf : WellFormed b)
    (r : Ref α) (hr : r ∈ b.exit) (hnc : ∀ v c, r ≠ Ref.const v c) :
    (depthOfHome (exitAltPhase b).S (tokenOf r)).isSome = true := by
  cases r with
  | const v c => exact absurd rfl (hnc v c)
  | inp i =>
      apply exitAltPhase_R4 b hwf (Token.inTok i) rfl (hwf.2.1 (Ref.inp i) hr)
      have hle := occCount_ge_of_mem b.exit (Token.inTok i) (Ref.inp i) hr
      simp [occ, tokenOf] at hle; omega
  | ainp i =>
      apply exitAltPhase_R4 b hwf (Token.ainTok i) rfl (hwf.2.1 (Ref.ainp i) hr)
      have hle := occCount_ge_of_mem b.exit (Token.ainTok i) (Ref.ainp i) hr
      simp [occ, tokenOf] at hle; omega
  | out nid j =>
      apply exitAltPhase_R4 b hwf (Token.vTok nid j) rfl (hwf.2.1 (Ref.out nid j) hr)
      have hle := occCount_ge_of_mem b.exit (Token.vTok nid j) (Ref.out nid j) hr
      simp [occ, tokenOf] at hle; omega

/-- A non-const exit ref has a home in `moveDead b` (exit-alt home preserved through dead-drop). -/
theorem exit_home_moveDead {α} [DecidableEq α] [Inhabited α] (b : Block α) (hwf : WellFormed b)
    (r : Ref α) (hr : r ∈ b.exit) (hnc : ∀ v c, r ≠ Ref.const v c) :
    (depthOfHome (moveDead b).S (tokenOf r)).isSome = true := by
  unfold moveDead
  exact deadDropPass_preserves_needed b (moveL b) (tokenOf r) (neededTok_of_mem b r hr)
    _ _ (exit_RefHasHome b hwf r hr hnc)

/-- ★★ `hHomes` DISCHARGED from `WellFormed` + the const-true corner side condition `hct`. Every
    build lookup succeeds: inp/ainp/out exit refs get homes from `exit_home_moveDead`; use-once
    CSE `const _ true` refs (which `WellFormed` does NOT home) are supplied by `hct`. This turns the
    raw `hHomes` hypothesis of `schedule_refines_move` into an honest, decidable, harness-checkable
    side condition (empty whenever `b.exit.drop (moveL b)` has no `const _ true`). -/
theorem emitExitMove_hHomes {α} [DecidableEq α] [Inhabited α] (b : Block α) (hwf : WellFormed b)
    (hct : ∀ v, Ref.const v true ∈ b.exit.drop (moveL b) →
             (depthOfHome (moveDead b).S (Token.cTok v)).isSome = true) :
    BuildHomesOk (b.exit.drop (moveL b)) 0 (moveDead b) := by
  apply buildMovePass_homes (b.exit.drop (moveL b)) 0 (moveDead b) (moveDead b).S []
    (List.append_nil _).symm rfl
  intro r' hr' hnc'
  have hrexit : r' ∈ b.exit := List.mem_of_mem_drop hr'
  cases r' with
  | const v c =>
      cases c with
      | false => exact absurd rfl (hnc' v)
      | true => exact hct v hr'
  | inp i => exact exit_home_moveDead b hwf (Ref.inp i) hrexit (by intro w c h; simp at h)
  | ainp i => exact exit_home_moveDead b hwf (Ref.ainp i) hrexit (by intro w c h; simp at h)
  | out nid j => exact exit_home_moveDead b hwf (Ref.out nid j) hrexit (by intro w c h; simp at h)

/-- ★ SOUNDNESS WITH `hHomes` DISCHARGED: `schedule_refines_move` with its raw `hHomes` hypothesis
    replaced by the honest const-true side condition `hct` (via `emitExitMove_hHomes`). `hReach`
    STILL remains — and CANNOT be discharged unconditionally (see the counterexample below). -/
theorem schedule_refines_move_no_hHomes {α} [DecidableEq α] [Inhabited α] (b : Block α)
    (hwf : WellFormed b) (M A : List α)
    (hM : M.length = b.entryDepth) (hA : A.length = b.entryAlt)
    (hct : ∀ v, Ref.const v true ∈ b.exit.drop (moveL b) →
             (depthOfHome (moveDead b).S (Token.cTok v)).isSome = true)
    (hReach : readStack M A (blockEnv b M A) (scheduleBlockMove b).S
              = (b.exit.map (dRef M A (blockEnv b M A))).reverse) :
    run (emitMove b) (entryState M A) = some (denote b M A) :=
  schedule_refines_move b hwf M A hM hA (emitExitMove_hHomes b hwf hct) hReach

/-! ### ★ WHY `hReach` CANNOT BE DISCHARGED UNCONDITIONALLY — a machine-checked counterexample.

    The plan was to statically PROVE `hReach` for all `WellFormed` blocks and thereby obtain an
    UNCONDITIONAL `schedule_refines_move_uncond`. That is IMPOSSIBLE for the move arrange as
    modelled: there is a `WellFormed` block on which the arranged main stack does NOT reach the
    exit layout, so `hReach` is genuinely FALSE (not merely unproven). The obstruction is the
    move-arrange's last-occurrence MOVE: for `exit = [inp 0, inp 0]` the matched-prefix slot for
    `exit[0]` IS the only home for `inp 0`, and the (windowed) MOVE that builds `exit[1]` STEALS
    that slot instead of COPYing, so the final stack has ONE element where the exit layout has
    TWO. This is exactly the runtime self-check the scratch scheduler THROWS on — hence the move
    arrange is a certified pass that MAY REJECT, not an unconditionally-correct pass. Discharging
    `hReach` would require the multiset/permutation home-existence invariant on the unplaced
    region that separates the kept prefix from the movable region (future work / model fix). -/

/-- The witness block: entry main depth 1, no nodes, `exit = [inp 0, inp 0]`. -/
def ceBlock : Block Nat :=
  { entryDepth := 1, entryAlt := 0, nodes := [],
    exit := [Ref.inp 0, Ref.inp 0], exitAlt := [] }

/-- The witness block is `WellFormed`. -/
theorem ceBlock_wf : WellFormed ceBlock := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · show nodesWF ceBlock.entryDepth ceBlock.entryAlt [] ceBlock.nodes; simp [ceBlock, nodesWF]
  · intro r hr
    have hmem : r ∈ [Ref.inp (0:Nat), Ref.inp 0] := hr
    rcases List.mem_cons.mp hmem with h | h
    · subst h; show (0:Nat) < 1; omega
    · rcases List.mem_cons.mp h with h2 | h2
      · subst h2; show (0:Nat) < 1; omega
      · exact absurd h2 List.not_mem_nil
  · intro r hr; have : r ∈ ([] : List (Ref Nat)) := hr; simp at this
  · show (List.map Node.id ceBlock.nodes).Nodup; simp [ceBlock]
  · intro n hn; have : n ∈ ([] : List (Node Nat)) := hn; simp at this
  · intro n hn; have : n ∈ ([] : List (Node Nat)) := hn; simp at this
  · intro nid j _ nd hnd; have : nd ∈ ([] : List (Node Nat)) := hnd; simp at this

/-- ★★ `hReach` IS FALSE on a `WellFormed` block: with `M = [7]`, the arranged main stack reads
    out to `[7]` (length 1) while the exit layout is `[7, 7]` (length 2). Hence no unconditional
    `schedule_refines_move_uncond` exists for the move arrange as modelled — `hReach` is a genuine,
    honest hypothesis, not a provable consequence of `WellFormed`. -/
theorem hReach_false_on_wf :
    ∃ (b : Block Nat) (M A : List Nat),
      WellFormed b ∧ M.length = b.entryDepth ∧ A.length = b.entryAlt ∧
      readStack M A (blockEnv b M A) (scheduleBlockMove b).S
        ≠ (b.exit.map (dRef M A (blockEnv b M A))).reverse := by
  refine ⟨ceBlock, [7], [], ceBlock_wf, rfl, rfl, ?_⟩
  intro h
  have hl := congrArg List.length h
  rw [show (readStack [7] [] (blockEnv ceBlock [7] []) (scheduleBlockMove ceBlock).S).length = 1
        from rfl,
      show ((ceBlock.exit.map (dRef [7] [] (blockEnv ceBlock [7] []))).reverse).length = 2
        from rfl] at hl
  omega

/-! ### ★★ PATH 2 — DECIDABLE-D SOUNDNESS. The opaque runtime `hReach` is UPGRADED to a decidable,
    artifact-checkable predicate `D` (Dexit ∧ Dtransient ∧ Dhome), and `move_hReach_of_D` proves
    `D b → hReach b` GENUINELY (0 sorry), consuming the machine-checked `NoNull` crux
    (`NoNullHome.lean`). This closes Path 2: `schedule_refines_move_cond` is a real conditional
    soundness theorem, axioms = [propext, Classical.choice, Quot.sound], NO sorryAx. -/

/-! #### Step 0/1 — dead-drop reaches a fixpoint + preserves the matched prefix + preserves NoNull. -/

/-- The `deadIdx`-selected index is `≥ L` (the `L ≤ i` conjunct of the `find?` predicate). -/
theorem deadIdx_ge {α} [DecidableEq α] (b : Block α) (L : Nat) (S : List (Entry α)) (i : Nat)
    (h : deadIdx b L S = some i) : L ≤ i := by
  unfold deadIdx at h
  have hp := List.find?_some h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at hp
  exact hp.1

/-- Erasing an index `≥ L` leaves the bottom-`L` prefix untouched. -/
theorem take_eraseIdx_of_le {α} (l : List α) (L i : Nat) (hi : i < l.length) (h : L ≤ i) :
    (l.eraseIdx i).take L = l.take L := by
  rw [List.eraseIdx_eq_take_drop_succ,
      List.take_append_of_le_length (by rw [List.length_take]; omega),
      List.take_take]
  congr 1; omega

/-- ★ Dead-drop preserves the bottom-`L` matched prefix (it only erases dead homes at index ≥ L). -/
theorem deadDropPass_prefix {α} [DecidableEq α] (b : Block α) (L : Nat) :
    ∀ (fuel : Nat) (ms : ModelState α),
      (deadDropPass b L fuel ms).S.take L = ms.S.take L := by
  intro fuel
  induction fuel with
  | zero => intro ms; rfl
  | succ fuel ih =>
      intro ms
      unfold deadDropPass
      cases hdi : deadIdx b L ms.S with
      | none => rfl
      | some i =>
          rw [ih]
          exact take_eraseIdx_of_le ms.S L i (deadIdx_lt b L ms.S i hdi) (deadIdx_ge b L ms.S i hdi)

/-- ★ Dead-drop with fuel ≥ |S| reaches a FIXPOINT: no dead home ≥ L remains. -/
theorem deadDropPass_fixpoint {α} [DecidableEq α] (b : Block α) (L : Nat) :
    ∀ (fuel : Nat) (ms : ModelState α), ms.S.length ≤ fuel →
      deadIdx b L (deadDropPass b L fuel ms).S = none := by
  intro fuel
  induction fuel with
  | zero =>
      intro ms hlen
      have h0 : ms.S = [] := List.length_eq_zero_iff.mp (Nat.le_zero.mp hlen)
      show deadIdx b L ms.S = none
      rw [h0]; rfl
  | succ fuel ih =>
      intro ms hlen
      unfold deadDropPass
      cases hdi : deadIdx b L ms.S with
      | none => exact hdi
      | some i =>
          apply ih
          have hilt := deadIdx_lt b L ms.S i hdi
          show (ms.S.eraseIdx i).length ≤ fuel
          rw [List.length_eraseIdx, if_pos hilt]; omega

/-- ★ Dead-drop preserves `NoNull` (it only ERASES entries). -/
theorem deadDropPass_NoNull {α} [DecidableEq α] (b : Block α) (L : Nat) :
    ∀ (fuel : Nat) (ms : ModelState α), NoNull ms.S → NoNull (deadDropPass b L fuel ms).S := by
  intro fuel
  induction fuel with
  | zero => intro ms h; exact h
  | succ fuel ih =>
      intro ms h
      unfold deadDropPass
      cases deadIdx b L ms.S with
      | none => exact h
      | some i => exact ih _ (h.eraseIdx i)

/-- ★ THE CRUX CONSUMED: `moveDead b` has no non-transient `nullTok` home. -/
theorem moveDead_NoNull {α} [DecidableEq α] (b : Block α) : NoNull (moveDead b).S :=
  deadDropPass_NoNull b (moveL b) _ _ (exitAltPhase_NoNull b)

/-! #### Step 2a — the matched prefix's tokens (= matched exit-ref tokens) + non-transience. -/

/-- The matched bottom prefix's tokens coincide with the matched exit refs' tokens. -/
theorem matchPrefix_tok {α} [DecidableEq α] :
    ∀ (exit : List (Ref α)) (S : List (Entry α)) (i : Nat),
      (List.take (matchPrefixAux S i exit - i) (S.drop i)).map Entry.tok
        = (List.take (matchPrefixAux S i exit - i) exit).map tokenOf := by
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
                  have hsub : matchPrefixAux S (i + 1) rest - i
                      = (matchPrefixAux S (i + 1) rest - (i + 1)) + 1 := by
                    have := matchPrefixAux_ge S rest (i + 1); omega
                  have hdrop : S.drop i = e :: S.drop (i + 1) := by
                    rw [List.drop_eq_getElem_cons hi2, hSe]
                  rw [hdrop, hsub, List.take_succ_cons, List.take_succ_cons,
                      List.map_cons, List.map_cons, ih S (i + 1), heq]
              · simp

/-- The matched bottom prefix is entirely NON-transient (`matchPrefixAux` stops at a transient). -/
theorem matchPrefix_nonTransient {α} [DecidableEq α] :
    ∀ (exit : List (Ref α)) (S : List (Entry α)) (i : Nat) (e : Entry α),
      e ∈ List.take (matchPrefixAux S i exit - i) (S.drop i) → e.transient = false := by
  intro exit
  induction exit with
  | nil => intro S i e he; simp [matchPrefixAux] at he
  | cons r rest ih =>
      intro S i e he
      by_cases hc : ∃ v c, r = Ref.const v c
      · obtain ⟨v, c, rfl⟩ := hc; simp [matchPrefixAux] at he
      · rw [matchPrefixAux_cons_ne S r rest i (by rintro v c rfl; exact hc ⟨v, c, rfl⟩)] at he
        revert he
        split
        · intro he; simp at he
        · next e0 heqS =>
            split
            · intro he; simp at he
            · next htr =>
                split
                · next _ =>
                    intro he
                    obtain ⟨hi2, hSe⟩ := List.getElem?_eq_some_iff.mp heqS
                    have hsub : matchPrefixAux S (i + 1) rest - i
                        = (matchPrefixAux S (i + 1) rest - (i + 1)) + 1 := by
                      have := matchPrefixAux_ge S rest (i + 1); omega
                    have hdrop : S.drop i = e0 :: S.drop (i + 1) := by
                      rw [List.drop_eq_getElem_cons hi2, hSe]
                    rw [hdrop, hsub, List.take_succ_cons, List.mem_cons] at he
                    rcases he with h | h
                    · subst h; exact htr
                    · exact ih S (i + 1) e h
                · intro he; simp at he

/-! #### Step 2b/3 — the build-readout S-shape machinery (consuming NoNull via the initial-condition
    lemmas below). These are the reverted D-chain lemmas, now closeable because `moveDead_NoNull`
    supplies the missing "no non-transient nullTok home" fact. -/

theorem eraseIdx_map_ne {α β} (f : α → β) (U : List α) (m : Nat) (hm : m < U.length)
    (hnd : (U.map f).Nodup) : ∀ e ∈ U.eraseIdx m, f e ≠ f (U[m]) := by
  intro e he heq
  rw [List.mem_eraseIdx_iff_getElem] at he
  obtain ⟨k, hk, hkm, hke⟩ := he
  apply hkm
  have hmap : (U.map f)[k]'(by rw [List.length_map]; exact hk)
            = (U.map f)[m]'(by rw [List.length_map]; exact hm) := by
    rw [List.getElem_map, List.getElem_map, hke, heq]
  exact (List.getElem_inj hnd).mp hmap

theorem mem_map_eraseIdx {α β} (f : α → β) (U : List α) (m : Nat) (hm : m < U.length)
    (x : β) (hx : x ∈ U.map f) (hxne : x ≠ f (U[m])) : x ∈ (U.eraseIdx m).map f := by
  rw [List.mem_map] at hx
  obtain ⟨u, hu, rfl⟩ := hx
  rw [List.mem_iff_getElem] at hu
  obtain ⟨k, hk, hku⟩ := hu
  have hkm : k ≠ m := by intro h; subst h; exact hxne (by rw [hku])
  have hu' : u ∈ U.eraseIdx m := by rw [List.mem_eraseIdx_iff_getElem]; exact ⟨k, hk, hkm, hku⟩
  exact List.mem_map_of_mem hu'

theorem depthOfHomeFrom_move {α} [DecidableEq α] (P U B : List (Entry α)) (tok : Token α)
    (hUnt : ∀ e ∈ U, e.transient = false)
    (hPno : ∀ e ∈ P, e.transient = false → e.tok ≠ tok)
    (htokU : tok ∈ U.map Entry.tok) :
    ∃ (d m : Nat) (hm : m < U.length),
      depthOfHomeFrom ((P ++ U) ++ B) B.length tok = some d ∧
      (U[m]).tok = tok ∧
      ((P ++ U) ++ B).length - 1 - d = P.length + m := by
  have hBlen : B.length = B.reverse.length := (List.length_reverse).symm
  have hrev : ((P ++ U) ++ B).reverse.drop B.length = U.reverse ++ P.reverse := by
    rw [List.reverse_append, List.reverse_append, hBlen, List.drop_left]
  have hPnone : List.findIdx? (fun e : Entry α => (!e.transient) && decide (e.tok = tok)) P.reverse = none := by
    rw [List.findIdx?_eq_none_iff]
    intro e he
    rw [List.mem_reverse] at he
    cases hte : e.transient with
    | true => simp
    | false =>
        have hne := hPno e he hte
        simp only [Bool.not_false, Bool.true_and]
        exact decide_eq_false hne
  have hne_none : List.findIdx? (fun e : Entry α => (!e.transient) && decide (e.tok = tok)) U.reverse ≠ none := by
    intro h
    rw [List.findIdx?_eq_none_iff] at h
    rw [List.mem_map] at htokU
    obtain ⟨e0, he0, he0tok⟩ := htokU
    have hcontra := h e0 (List.mem_reverse.mpr he0)
    simp [hUnt e0 he0, he0tok] at hcontra
  obtain ⟨j, hj0⟩ := Option.ne_none_iff_exists'.mp hne_none
  have hj := hj0
  rw [List.findIdx?_eq_some_iff_getElem] at hj
  obtain ⟨hjlt, hpj, _⟩ := hj
  rw [List.length_reverse] at hjlt
  have hpj2 := hpj
  simp only [Bool.and_eq_true, decide_eq_true_eq] at hpj2
  rw [List.getElem_reverse (by rw [List.length_reverse]; exact hjlt)] at hpj2
  refine ⟨j + B.length, U.length - 1 - j, by omega, ?_, hpj2.2, ?_⟩
  · unfold depthOfHomeFrom
    rw [hrev, List.findIdx?_append, hj0, hPnone]
    rfl
  · rw [List.length_append, List.length_append]; omega


theorem buildMovePass_S_shape {α} [DecidableEq α] :
    ∀ (l : List (Ref α)) (placed : Nat) (ms : ModelState α) (P U B : List (Entry α)),
      ms.S = (P ++ U) ++ B →
      B.length = placed →
      (∀ e ∈ U, e.transient = false) →
      (U.map Entry.tok).Nodup →
      (∀ e ∈ P, e.transient = false → ∀ r ∈ l, (∀ v, r ≠ Ref.const v false) → e.tok ≠ tokenOf r) →
      (∀ e ∈ U, ∃ r ∈ l, (∀ v, r ≠ Ref.const v false) ∧ e.tok = tokenOf r) →
      (∀ r ∈ l, (∀ v, r ≠ Ref.const v false) → tokenOf r ∈ U.map Entry.tok) →
      (l.map tokenOf).Nodup →
      (buildMovePass l placed ms).S
        = P ++ (B ++ l.map (fun r => (⟨tokenOf r, false⟩ : Entry α))) := by
  intro l
  induction l with
  | nil =>
      intro placed ms P U B hS _ _ _ _ hUcorr _ _
      have hUnil : U = [] := by
        rcases U with _ | ⟨u, us⟩
        · rfl
        · obtain ⟨r, hr, _⟩ := hUcorr u (List.mem_cons_self ..); simp at hr
      subst hUnil
      change ms.S = P ++ (B ++ [])
      rw [hS]; simp
  | cons r rest ih =>
      intro placed ms P U B hS hB hUnt hUnd hPno hUcorr hlhome hlnd
      by_cases hcf : ∃ v, r = Ref.const v false
      · obtain ⟨v, rfl⟩ := hcf
        have hlnd' : (rest.map tokenOf).Nodup := by
          have h := hlnd; rw [List.map_cons] at h; exact (List.nodup_cons.mp h).2
        show (buildMovePass rest (placed + 1)
                { ms with ops := ms.ops ++ [Op.PUSH v],
                          S := ms.S ++ [(⟨Token.nullTok v, false⟩ : Entry α)] }).S = _
        rw [ih (placed + 1) _ P U (B ++ [(⟨Token.nullTok v, false⟩ : Entry α)])
              (by rw [hS]; simp [List.append_assoc])
              (by rw [List.length_append, hB]; rfl)
              hUnt hUnd
              (fun e he hnt r' hr' hnc' => hPno e he hnt r' (List.mem_cons_of_mem _ hr') hnc')
              (fun e he => by
                obtain ⟨r'', hr'', hnc'', htok''⟩ := hUcorr e he
                refine ⟨r'', ?_, hnc'', htok''⟩
                rcases List.mem_cons.mp hr'' with h | h
                · exact absurd h (by subst h; exact fun hh => (hnc'' v) hh)
                · exact h)
              (fun r' hr' hnc' => hlhome r' (List.mem_cons_of_mem _ hr') hnc')
              hlnd']
        simp [List.append_assoc, tokenOf]
      · have hnc : ∀ v, r ≠ Ref.const v false := fun v h => hcf ⟨v, h⟩
        obtain ⟨hnotmem, hlnd'⟩ := List.nodup_cons.mp hlnd
        rw [buildMovePass_cons_nc r rest placed ms hnc, if_neg hnotmem]
        have htokU : tokenOf r ∈ U.map Entry.tok := hlhome r (List.mem_cons_self ..) hnc
        have hPno_tok : ∀ e ∈ P, e.transient = false → e.tok ≠ tokenOf r :=
          fun e he hnt => hPno e he hnt r (List.mem_cons_self ..) hnc
        obtain ⟨d, m, hm, hdep, hUmtok, herase⟩ :=
          depthOfHomeFrom_move P U B (tokenOf r) hUnt hPno_tok htokU
        have hdep' : depthOfHomeFrom ms.S placed (tokenOf r) = some d := by
          rw [hS, ← hB]; exact hdep
        rw [hdep']
        have hSlen : ms.S.length - 1 - d = P.length + m := by rw [hS]; exact herase
        have he1 : ms.S.eraseIdx (ms.S.length - 1 - d) = (P ++ U.eraseIdx m) ++ B := by
          rw [hSlen, hS,
              List.eraseIdx_append_of_lt_length (by rw [List.length_append]; omega),
              List.eraseIdx_append_of_length_le (Nat.le_add_right _ _)]
          simp
        have hUmtok' : Entry.tok (U[m]) = tokenOf r := hUmtok
        rw [ih (placed + 1)
              { ms with ops := ms.ops ++ moveOps d,
                        S := ms.S.eraseIdx (ms.S.length - 1 - d) ++ [(⟨tokenOf r, false⟩ : Entry α)] }
              P (U.eraseIdx m) (B ++ [(⟨tokenOf r, false⟩ : Entry α)])
              (by show ms.S.eraseIdx (ms.S.length - 1 - d) ++ _ = _
                  rw [he1, List.append_assoc])
              (by rw [List.length_append, hB]; rfl)
              (fun e he => hUnt e (List.mem_of_mem_eraseIdx he))
              (((List.eraseIdx_sublist U m).map Entry.tok).nodup hUnd)
              (fun e he hnt r' hr' hnc' => hPno e he hnt r' (List.mem_cons_of_mem _ hr') hnc')
              (fun e he => by
                obtain ⟨r'', hr'', hnc'', htok''⟩ := hUcorr e (List.mem_of_mem_eraseIdx he)
                refine ⟨r'', ?_, hnc'', htok''⟩
                rcases List.mem_cons.mp hr'' with h | h
                · exfalso
                  have := eraseIdx_map_ne Entry.tok U m hm hUnd e he
                  rw [htok'', hUmtok'] at this
                  exact this (by rw [h])
                · exact h)
              (fun r' hr' hnc' => by
                have hne : tokenOf r' ≠ tokenOf r := fun heq =>
                  hnotmem (heq ▸ List.mem_map_of_mem hr')
                apply mem_map_eraseIdx Entry.tok U m hm (tokenOf r')
                  (hlhome r' (List.mem_cons_of_mem _ hr') hnc')
                rw [hUmtok']; exact hne)
              hlnd']
        simp [List.append_assoc]


/-! #### Step 3/4 — the DECIDABLE predicate `D` and the `D → hReach → soundness` chain.
    `move_hReach_of_D` closes GENUINELY (0 sorry) by consuming `moveDead_NoNull` + the fixpoint
    + matched-prefix lemmas + the build-readout S-shape. `schedule_refines_move_cond` is then a
    real conditional soundness theorem (axioms = [propext, Classical.choice, Quot.sound]). -/

section PathTwo
open List
variable {α : Type} [DecidableEq α]

def Dexit (b : Block α) : Prop := (b.exit.map tokenOf).Nodup
def Dtransient (b : Block α) : Prop := ∀ e ∈ (moveDead b).S.drop (moveL b), e.transient = false
def Dhome (b : Block α) : Prop :=
  (((moveDead b).S.filter (fun e => !e.transient)).map Entry.tok).Nodup
def D (b : Block α) : Prop := Dexit b ∧ Dtransient b ∧ Dhome b

instance (b : Block α) : Decidable (Dexit b) := by unfold Dexit; infer_instance
instance (b : Block α) : Decidable (Dtransient b) := by unfold Dtransient; infer_instance
instance (b : Block α) : Decidable (Dhome b) := by unfold Dhome; infer_instance
instance (b : Block α) : Decidable (D b) := by unfold D; infer_instance

theorem move_hReach_of_D [Inhabited α] (b : Block α) (hwf : WellFormed b)
    (hct : ∀ v, Ref.const v true ∈ b.exit.drop (moveL b) →
             (depthOfHome (moveDead b).S (Token.cTok v)).isSome = true)
    (hD : D b) (M A : List α) :
    readStack M A (blockEnv b M A) (scheduleBlockMove b).S
      = (b.exit.map (dRef M A (blockEnv b M A))).reverse := by
  obtain ⟨hDexit, hDtrans, hDhome⟩ := hD
  have hprefix : (moveDead b).S.take (moveL b) = (exitAltPhase b).S.take (moveL b) := by
    unfold moveDead
    exact deadDropPass_prefix b (moveL b) (exitAltPhase b).S.length (exitAltPhase b)
  have hPtok : ((moveDead b).S.take (moveL b)).map Entry.tok
             = (b.exit.take (moveL b)).map tokenOf := by
    rw [hprefix]; simpa [moveL] using matchPrefix_tok b.exit (exitAltPhase b).S 0
  have hPnt : ∀ e ∈ (moveDead b).S.take (moveL b), e.transient = false := by
    intro e he
    rw [hprefix] at he
    exact matchPrefix_nonTransient b.exit (exitAltPhase b).S 0 e (by simpa [moveL] using he)
  have hdisj : ∀ r ∈ b.exit.drop (moveL b), tokenOf r ∉ (b.exit.take (moveL b)).map tokenOf := by
    intro r hr hmem
    have hnd : (b.exit.map tokenOf).Nodup := hDexit
    rw [← List.take_append_drop (moveL b) b.exit, List.map_append, List.nodup_append] at hnd
    exact hnd.2.2 (tokenOf r) hmem (tokenOf r) (List.mem_map_of_mem hr) rfl
  have hfilterPU : (moveDead b).S.filter (fun e => !e.transient)
      = (moveDead b).S.take (moveL b) ++ (moveDead b).S.drop (moveL b) := by
    have hfa := List.filter_append (p := fun e : Entry α => !e.transient)
      ((moveDead b).S.take (moveL b)) ((moveDead b).S.drop (moveL b))
    rw [List.take_append_drop] at hfa
    rw [hfa]
    congr 1
    · apply List.filter_eq_self.mpr; intro e he; rw [hPnt e he]; rfl
    · apply List.filter_eq_self.mpr; intro e he; rw [hDtrans e he]; rfl
  have hdisjPU : ∀ t, t ∈ ((moveDead b).S.take (moveL b)).map Entry.tok →
      t ∈ ((moveDead b).S.drop (moveL b)).map Entry.tok → False := by
    have h : (((moveDead b).S.filter (fun e => !e.transient)).map Entry.tok).Nodup := hDhome
    rw [hfilterPU, List.map_append, List.nodup_append] at h
    intro t h1 h2
    exact h.2.2 t h1 t h2 rfl
  have hUnd : (((moveDead b).S.drop (moveL b)).map Entry.tok).Nodup := by
    have hsub : (moveDead b).S.drop (moveL b) <+ (moveDead b).S.filter (fun e => !e.transient) := by
      have h1 : ((moveDead b).S.drop (moveL b)).filter (fun e => !e.transient)
              = (moveDead b).S.drop (moveL b) := by
        apply List.filter_eq_self.mpr; intro e he; rw [hDtrans e he]; rfl
      rw [← h1]; exact (List.drop_sublist _ _).filter _
    exact (hsub.map Entry.tok).nodup hDhome
  have hPno : ∀ e ∈ (moveDead b).S.take (moveL b), e.transient = false →
      ∀ r ∈ b.exit.drop (moveL b), (∀ v, r ≠ Ref.const v false) → e.tok ≠ tokenOf r := by
    intro e he _ r hr _ heq
    refine hdisj r hr ?_
    rw [← heq, ← hPtok]; exact List.mem_map_of_mem he
  have hlnd : ((b.exit.drop (moveL b)).map tokenOf).Nodup :=
    ((List.drop_sublist _ _).map tokenOf).nodup hDexit
  have hhomeU : ∀ (t : Token α), ((moveDead b).S.any (homeP t)) = true →
      t ∉ (b.exit.take (moveL b)).map tokenOf → t ∈ ((moveDead b).S.drop (moveL b)).map Entry.tok := by
    intro t hany hnotP
    rw [List.any_eq_true] at hany
    obtain ⟨e, he, hpe⟩ := hany
    simp only [homeP, Bool.and_eq_true, decide_eq_true_eq, Bool.not_eq_true'] at hpe
    obtain ⟨hent, hetok⟩ := hpe
    rw [← List.take_append_drop (moveL b) (moveDead b).S] at he
    rcases List.mem_append.mp he with hP | hU
    · exfalso; apply hnotP; rw [← hetok, ← hPtok]; exact List.mem_map_of_mem hP
    · rw [← hetok]; exact List.mem_map_of_mem hU
  have hlhome : ∀ r ∈ b.exit.drop (moveL b), (∀ v, r ≠ Ref.const v false) →
      tokenOf r ∈ ((moveDead b).S.drop (moveL b)).map Entry.tok := by
    intro r hr hnc
    have hrexit : r ∈ b.exit := List.mem_of_mem_drop hr
    apply hhomeU (tokenOf r) _ (hdisj r hr)
    rw [← depthOfHome_isSome_iff]
    cases r with
    | const v c =>
        cases c with
        | false => exact absurd rfl (hnc v)
        | true => exact hct v hr
    | inp i => exact exit_home_moveDead b hwf (Ref.inp i) hrexit (by intro w c h; simp at h)
    | ainp i => exact exit_home_moveDead b hwf (Ref.ainp i) hrexit (by intro w c h; simp at h)
    | out nid j => exact exit_home_moveDead b hwf (Ref.out nid j) hrexit (by intro w c h; simp at h)
  have hfix : deadIdx b (moveL b) (moveDead b).S = none := by
    unfold moveDead
    exact deadDropPass_fixpoint b (moveL b) (exitAltPhase b).S.length (exitAltPhase b) (Nat.le_refl _)
  have hUcorr : ∀ e ∈ (moveDead b).S.drop (moveL b), ∃ r ∈ b.exit.drop (moveL b),
      (∀ v, r ≠ Ref.const v false) ∧ e.tok = tokenOf r := by
    intro e he
    have hent : e.transient = false := hDtrans e he
    have hneed : neededTok b e.tok = true := by
      rw [List.mem_iff_getElem] at he
      obtain ⟨k, hk, hke⟩ := he
      rw [List.length_drop] at hk
      have hidx : (moveDead b).S[moveL b + k]? = some e := by
        rw [List.getElem?_eq_getElem (by omega), ← hke, List.getElem_drop]
      unfold deadIdx at hfix
      rw [List.find?_eq_none] at hfix
      have hi_mem : (moveL b + k) ∈ (List.range (moveDead b).S.length).reverse := by
        rw [List.mem_reverse, List.mem_range]; omega
      have hp := hfix _ hi_mem
      have hle : decide (moveL b ≤ moveL b + k) = true := by rw [decide_eq_true_eq]; omega
      simp only [hidx, hent, hle, Bool.not_false, Bool.true_and] at hp
      cases hnv : neededTok b e.tok with
      | true => rfl
      | false => simp [hnv] at hp
    rw [neededTok, List.any_eq_true] at hneed
    obtain ⟨r, hrex, hrtok⟩ := hneed
    rw [decide_eq_true_eq] at hrtok
    have hnc : ∀ v, r ≠ Ref.const v false := by
      intro v hv
      apply moveDead_NoNull b e (List.mem_of_mem_drop he) hent v
      rw [← hrtok, hv]; rfl
    have hrdrop : r ∈ b.exit.drop (moveL b) := by
      rw [← List.take_append_drop (moveL b) b.exit] at hrex
      rcases List.mem_append.mp hrex with h | h
      · exfalso
        apply hdisjPU (tokenOf r)
        · rw [hPtok]; exact List.mem_map_of_mem h
        · rw [hrtok]; exact List.mem_map_of_mem he
      · exact h
    exact ⟨r, hrdrop, hnc, hrtok.symm⟩
  have hS0 : (moveDead b).S
      = (((moveDead b).S.take (moveL b)) ++ ((moveDead b).S.drop (moveL b))) ++ [] := by
    rw [List.append_nil, List.take_append_drop]
  have hSshape : (scheduleBlockMove b).S
      = ((moveDead b).S.take (moveL b))
        ++ ([] ++ (b.exit.drop (moveL b)).map (fun r => (⟨tokenOf r, false⟩ : Entry α))) := by
    show (buildMovePass (b.exit.drop (moveL b)) 0 (moveDead b)).S = _
    exact buildMovePass_S_shape (b.exit.drop (moveL b)) 0 (moveDead b)
      ((moveDead b).S.take (moveL b)) ((moveDead b).S.drop (moveL b)) []
      hS0 rfl hDtrans hUnd hPno hUcorr hlhome hlnd
  rw [hSshape, List.nil_append,
      show (b.exit.map (dRef M A (blockEnv b M A)))
        = (b.exit.take (moveL b)).map (dRef M A (blockEnv b M A))
          ++ (b.exit.drop (moveL b)).map (dRef M A (blockEnv b M A)) by
        rw [← List.map_append, List.take_append_drop]]
  simp only [readStack, List.map_append, List.reverse_append]
  congr 1
  · rw [List.map_map]
    exact congrArg List.reverse (List.map_congr_left (fun r _ => valOf_tokenOf M A (blockEnv b M A) r))
  · rw [hprefix]
    exact congrArg List.reverse (by simpa [moveL] using matchPrefix_map M A (blockEnv b M A) b.exit (exitAltPhase b).S 0)

theorem schedule_refines_move_cond [Inhabited α] (b : Block α)
    (hwf : WellFormed b) (M A : List α)
    (hM : M.length = b.entryDepth) (hA : A.length = b.entryAlt)
    (hct : ∀ v, Ref.const v true ∈ b.exit.drop (moveL b) →
             (depthOfHome (moveDead b).S (Token.cTok v)).isSome = true)
    (hD : D b) :
    run (emitMove b) (entryState M A) = some (denote b M A) :=
  schedule_refines_move_no_hHomes b hwf M A hM hA hct (move_hReach_of_D b hwf hct hD M A)

/-- ★ NON-VACUITY (excludes the Part-3 counterexample). The `WellFormed` `[inp 0, inp 0]` block
    that made `hReach` FALSE genuinely FAILS `D` (duplicate exit token ⇒ ¬Dexit). -/
theorem D_excludes_ce : ¬ D ceBlock := by decide

/-- A real reordering block (distinct exit tokens): `entryDepth 2`, `exit = [inp 1, inp 0]`. -/
def realBlock : Block Nat :=
  { entryDepth := 2, entryAlt := 0, nodes := [],
    exit := [Ref.inp 1, Ref.inp 0], exitAlt := [] }

theorem realBlock_wf : WellFormed realBlock := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · show nodesWF realBlock.entryDepth realBlock.entryAlt [] realBlock.nodes; simp [realBlock, nodesWF]
  · intro r hr
    have hmem : r ∈ [Ref.inp (1:Nat), Ref.inp 0] := hr
    rcases List.mem_cons.mp hmem with h | h
    · subst h; show (1:Nat) < 2; omega
    · rcases List.mem_cons.mp h with h2 | h2
      · subst h2; show (0:Nat) < 2; omega
      · exact absurd h2 (by simp)
  · intro r hr; have : r ∈ ([] : List (Ref Nat)) := hr; simp at this
  · show (List.map Node.id realBlock.nodes).Nodup; simp [realBlock]
  · intro n hn; have : n ∈ ([] : List (Node Nat)) := hn; simp at this
  · intro n hn; have : n ∈ ([] : List (Node Nat)) := hn; simp at this
  · intro nid j _ nd hnd; have : nd ∈ ([] : List (Node Nat)) := hnd; simp at this

/-- ★ NON-VACUITY (satisfiable). `realBlock` genuinely satisfies `D`, so `D` is NOT vacuously
    false — `schedule_refines_move_cond` has real content. -/
theorem D_realBlock : D realBlock := by decide

end PathTwo


end Recompiler
