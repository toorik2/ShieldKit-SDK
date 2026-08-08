/-
  ★ NO-NULL-HOME — the REFINED, machine-checked crux invariant for Path 2 (decidable-D
  MOVE-arrange soundness). Unconditional (no `WellFormed` needed), 0 sorry,
  axioms = [propext, Quot.sound].

  CONTEXT. The Path-2 blocker (`buildMove_final_S`, the build-readout S-shape lemma) needs the
  movable region `U` of `moveDead` to be emptied EXACTLY by the build's MOVEs, i.e.
  `|U| = #(non-const-false refs in exit.drop L)`. This FAILS iff `exit.drop L` has a
  `Ref.const v false` whose `nullTok v` also occurs as a NON-TRANSIENT home in `U` (const-false
  PUSHes fresh, never consumes from `U` ⇒ a leftover strands the S-shape).

  ★ CORRECTION of the prior diagnosis. The deferred next-step was stated as
  `SlotInv := ∀ non-transient e ∈ (exitAltPhase b).S, isSlotTok e.tok` (isSlotTok = inTok/ainTok/
  vTok). That statement is FALSE: `emitNode`'s CSE-const setup (Scheduler.lean:172-174) pushes a
  NON-TRANSIENT `⟨cTok v, false⟩` home, and a `const v true` exit ref keeps that `cTok` home into
  `exitAltPhase.S` (the case the existing `hct` side-condition covers). So `cTok` homes provably
  exist ⇒ no `isSlotTok`-invariant holds.

  ★ WHAT ACTUALLY CLOSES. `buildMove_final_S` does NOT need `isSlotTok`; it only needs the WEAKER
  `NoNull`: no NON-TRANSIENT `nullTok` home. That IS true and is proved here by threading through
  every phase step: seed (inTok) · drain (ainTok) · nodes (emitFetch pushes const-false as
  TRANSIENT [Scheduler.lean:124]; CSE-setup pushes cTok NON-transient — still ≠ nullTok; CALL
  pushes vTok NON-transient; MOVE/COPY/drop only erase) · exit-alt (emitFetch + dropLast). Since
  `deadDropPass` only removes entries, `NoNull (exitAltPhase b).S ⇒ NoNull (moveDead b).S`, hence
  `U` has no non-transient `nullTok` — the exact fact `buildMove_final_S` was missing.

  STATUS: this invariant is CLOSED; the remaining Path-2 work is to rebuild the reverted D infra
  (`D`/Steps 0–2a/`buildMove_final_S`/`move_hReach_of_D`) and consume `NoNull` there. Lean 4.31.
-/
import Recompiler.Compose

namespace Recompiler
open Op

/-- The REFINED crux invariant: every NON-transient entry of a modelled main stack has a token
    that is NOT a `nullTok`. (Weaker than the FALSE `isSlotTok`-invariant — `cTok` homes exist —
    but exactly what the MOVE-arrange build-readout needs: no un-moved const-false leftover.) -/
def NoNull {α} (S : List (Entry α)) : Prop :=
  ∀ e ∈ S, e.transient = false → ∀ v, e.tok ≠ Token.nullTok v

theorem NoNull.mono {α} {S S' : List (Entry α)} (h : ∀ e, e ∈ S' → e ∈ S)
    (hS : NoNull S) : NoNull S' := fun e he => hS e (h e he)

theorem NoNull.nil {α} : NoNull ([] : List (Entry α)) := by intro e he; simp at he

theorem NoNull.append_slot {α} {S : List (Entry α)} (hS : NoNull S) (e : Entry α)
    (he : e.transient = false → ∀ v, e.tok ≠ Token.nullTok v) : NoNull (S ++ [e]) := by
  intro x hx
  rcases List.mem_append.mp hx with h | h
  · exact hS x h
  · rw [List.mem_singleton] at h; subst h; exact he

theorem NoNull.append {α} {S T : List (Entry α)} (hS : NoNull S) (hT : NoNull T) :
    NoNull (S ++ T) := by
  intro x hx
  rcases List.mem_append.mp hx with h | h
  · exact hS x h
  · exact hT x h

theorem NoNull.eraseIdx {α} {S : List (Entry α)} (hS : NoNull S) (i : Nat) :
    NoNull (S.eraseIdx i) := hS.mono (fun _ he => List.mem_of_mem_eraseIdx he)

theorem NoNull.dropLast {α} {S : List (Entry α)} (hS : NoNull S) : NoNull S.dropLast :=
  hS.mono (fun _ he => List.dropLast_subset _ he)

theorem NoNull.take {α} {S : List (Entry α)} (hS : NoNull S) (n : Nat) : NoNull (S.take n) :=
  hS.mono (fun _ he => List.mem_of_mem_take he)

/-! Generic foldl preservation. -/
theorem foldl_NoNull {α β} (g : ModelState α → β → ModelState α)
    (hg : ∀ (m : ModelState α) (x : β), NoNull m.S → NoNull (g m x).S) :
    ∀ (l : List β) (ms : ModelState α), NoNull ms.S → NoNull (l.foldl g ms).S := by
  intro l
  induction l with
  | nil => intro ms h; exact h
  | cons x xs ih => intro ms h; rw [List.foldl_cons]; exact ih (g ms x) (hg ms x h)

/-! ### Phase-step preservation. -/

theorem seedState_NoNull {α} [DecidableEq α] (b : Block α) : NoNull (seedState b).S := by
  intro e he
  simp only [seedState] at he
  rw [List.mem_map] at he
  obtain ⟨i, _, rfl⟩ := he
  intro _ v h; nomatch h

theorem drainStep_NoNull {α} (m : ModelState α) (k : Nat) (hS : NoNull m.S) :
    NoNull (drainStep m k).S := by
  show NoNull (m.S ++ [⟨Token.ainTok k, false⟩])
  exact hS.append_slot _ (fun _ v h => by nomatch h)

theorem drainPhase_NoNull {α} [DecidableEq α] (b : Block α) : NoNull (drainPhase b).S := by
  unfold drainPhase
  cases altPassthrough b with
  | true => exact seedState_NoNull b
  | false =>
      exact foldl_NoNull drainStep (fun m k h => drainStep_NoNull m k h) _ _ (seedState_NoNull b)

theorem emitFetch_NoNull {α} [DecidableEq α] (r : Ref α) (ms : ModelState α)
    (hS : NoNull ms.S) : NoNull (emitFetch r ms).S := by
  have nc : ∀ (t : Token α), (⟨t, true⟩ : Entry α).transient = false → ∀ v, (⟨t, true⟩ : Entry α).tok ≠ Token.nullTok v :=
    fun t h => Bool.noConfusion h
  cases r with
  | inp i =>
      simp only [emitFetch]
      split
      · exact hS.append_slot _ (nc _)
      · split
        · exact (hS.eraseIdx _).append_slot _ (nc _)
        · exact hS.append_slot _ (nc _)
  | ainp i =>
      simp only [emitFetch]
      split
      · exact hS.append_slot _ (nc _)
      · split
        · exact (hS.eraseIdx _).append_slot _ (nc _)
        · exact hS.append_slot _ (nc _)
  | out nid j =>
      simp only [emitFetch]
      split
      · exact hS.append_slot _ (nc _)
      · split
        · exact (hS.eraseIdx _).append_slot _ (nc _)
        · exact hS.append_slot _ (nc _)
  | const v cse =>
      cases cse with
      | false =>
          simp only [emitFetch]
          exact hS.append_slot _ (nc _)
      | true =>
          simp only [emitFetch]
          split
          · exact hS.append_slot _ (nc _)
          · split
            · exact (hS.eraseIdx _).append_slot _ (nc _)
            · exact hS.append_slot _ (nc _)

theorem cseSetupStep_NoNull {α} [DecidableEq α] (m : ModelState α)
    (inp : Ref α) (hS : NoNull m.S) :
    NoNull ((match inp with
      | .const v true =>
          let t := Token.cTok v
          match depthOfHome m.S t with
          | some _ => m
          | none   => if 1 < m.use t
                      then { m with ops := m.ops ++ [Op.PUSH v], S := m.S ++ [⟨t, false⟩] }
                      else m
      | _ => m) : ModelState α).S := by
  cases inp with
  | inp i => exact hS
  | ainp i => exact hS
  | out nid j => exact hS
  | const v cse =>
      cases cse with
      | false => exact hS
      | true =>
          dsimp only
          cases depthOfHome m.S (Token.cTok v) with
          | some _ => exact hS
          | none =>
              by_cases hu : 1 < m.use (Token.cTok v)
              · simp only [hu, if_true]
                exact hS.append_slot _ (fun _ w h => by nomatch h)
              · simp only [hu, if_false]; exact hS

theorem eagerDrop_NoNull {α} [DecidableEq α] (fuel : Nat) (ms : ModelState α)
    (hS : NoNull ms.S) : NoNull (eagerDrop fuel ms).S := by
  induction fuel generalizing ms with
  | zero => exact hS
  | succ fuel ih =>
      unfold eagerDrop
      split
      · exact hS
      · split
        · exact hS
        · split
          · exact ih _ hS.dropLast
          · exact hS

theorem emitNode_NoNull {α} [DecidableEq α] (n : Node α) (ms : ModelState α)
    (hS : NoNull ms.S) : NoNull (emitNode n ms).S := by
  unfold emitNode
  apply eagerDrop_NoNull
  -- goal: NoNull of the ms3 state's S = S3 ++ outs
  show NoNull (_ ++ _)
  apply NoNull.append
  · -- S3 = ms2.S.take _, and ms2 = foldl emitFetch (ms1); ms1 = foldl cse-setup ms
    apply NoNull.take
    apply foldl_NoNull (fun m inp => emitFetch inp m) (fun m inp h => emitFetch_NoNull inp m h)
    apply foldl_NoNull _ (fun m inp h => cseSetupStep_NoNull m inp h)
    exact hS
  · -- outs = (range nout).map (⟨vTok n.id j, false⟩)
    intro e he
    rw [List.mem_map] at he
    obtain ⟨j, _, rfl⟩ := he
    intro _ v h; nomatch h

theorem nodesPhase_NoNull {α} [DecidableEq α] (b : Block α) : NoNull (nodesPhase b).S := by
  unfold nodesPhase
  exact foldl_NoNull (fun m n => emitNode n m) (fun m n h => emitNode_NoNull n m h) _ _
    (drainPhase_NoNull b)

theorem exitAltStep_NoNull {α} [DecidableEq α] (m : ModelState α) (r : Ref α)
    (hS : NoNull m.S) : NoNull (exitAltStep m r).S := by
  show NoNull (emitFetch r m).S.dropLast
  exact (emitFetch_NoNull r m hS).dropLast

/-- ★★ THE REFINED CRUX: `exitAltPhase.S` has NO non-transient `nullTok` home. Unconditional
    (no `WellFormed` needed) — purely structural: every non-transient push in the four phases is
    an `inTok`/`ainTok`/`vTok`/`cTok` slot; the ONLY `nullTok` pushes (emitFetch const-false,
    Scheduler.lean:124) are TRANSIENT. -/
theorem exitAltPhase_NoNull {α} [DecidableEq α] (b : Block α) : NoNull (exitAltPhase b).S := by
  unfold exitAltPhase
  cases altPassthrough b with
  | true => exact nodesPhase_NoNull b
  | false =>
      exact foldl_NoNull exitAltStep (fun m r h => exitAltStep_NoNull m r h) _ _
        (nodesPhase_NoNull b)

end Recompiler
