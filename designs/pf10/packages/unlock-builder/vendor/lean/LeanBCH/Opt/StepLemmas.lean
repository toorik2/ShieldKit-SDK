/-
  PASS-2 DAG-SCHEDULER — STEP-LEMMAS (each emitter primitive preserves the simulation `Inv`).

  This file discharges the "hard simulation core" flagged in Simulation.lean:
    (A) CONCRETE OP SEMANTICS — the index-arithmetic crux: the depth→op shortcut folds
        (`copyOps`/`moveOps`/`delOps`, = the spike's proven peepholes) do EXACTLY
        copy-at-depth / move-at-depth / delete-at-depth on the concrete stack.
    (B) readStack ALGEBRA — the model↔concrete bridge: appending to the (bottom→top) model
        stack = pushing on the (head=top) concrete stack; `eraseIdx (len-1-d)` on the model
        = `removeNth d` on the concrete stack (the MOVE bookkeeping).
    (C) depthOfHome VALUE — a `some d` home lookup lands on a concrete slot holding the
        token's denoted value (the map from liveRefs to concrete-index is value-faithful).
    (D) emitFetch — MOVE(ROLL) / COPY(PICK) preserve `Inv` and land the ref's value on top.
    (E) const-CSE (emitBuildRef) — push-once + COPY-reuse preserve `Inv`.
    (F) emitNode CALL — operands-on-top ⇒ node output(s) on top, `Inv` extended.

  Machine-checked, Lean 4.31 core, NO mathlib. Every theorem here is `sorry`-free — as is the
  end-to-end composition `schedule_refines` (Compose.lean), which these step-lemmas feed. (An
  earlier draft of this header noted a remaining `sorry` in that composition; it is discharged.)
-/
import LeanBCH.Opt.Dag
import LeanBCH.Opt.Scheduler
import LeanBCH.Opt.Simulation

namespace LeanBCH.Opt
open Op

/-! ### (A) CONCRETE OP SEMANTICS — depth→op folds do copy/move/delete at depth. -/

/-- COPY: `copyOps d` (DUP / OVER / PICK d) copies the element at concrete depth `d` to top. -/
theorem run_copyOps {α} (d : Nat) (m a : List α) (h : d < m.length) :
    run (copyOps d) (m, a) = some (m[d] :: m, a) := by
  match d, h with
  | 0, h =>
      cases m with
      | nil => simp at h
      | cons x s => rfl
  | 1, h =>
      cases m with
      | nil => simp at h
      | cons x t =>
          cases t with
          | nil => simp at h
          | cons y s => rfl
  | n + 2, h =>
      show run [Op.PICK (n + 2)] (m, a) = some (m[n + 2] :: m, a)
      simp [run, step, List.getElem?_eq_getElem h]

/-- MOVE: `moveOps d` (nothing / SWAP / ROT / ROLL d) moves the depth-`d` element to top,
    removing it from its old slot (`removeNth`). -/
theorem run_moveOps {α} (d : Nat) (m a : List α) (h : d < m.length) :
    run (moveOps d) (m, a) = some (m[d] :: removeNth m d, a) := by
  match d, h with
  | 0, h =>
      cases m with
      | nil => simp at h
      | cons x s => simp [moveOps, run, removeNth]
  | 1, h =>
      cases m with
      | nil => simp at h
      | cons x t =>
          cases t with
          | nil => simp at h
          | cons y s => simp [moveOps, run, step, removeNth]
  | 2, h =>
      cases m with
      | nil => simp at h
      | cons x t =>
          cases t with
          | nil => simp at h
          | cons y u =>
              cases u with
              | nil => simp at h
              | cons z s => simp [moveOps, run, step, removeNth]
  | n + 3, h =>
      show run [Op.ROLL (n + 3)] (m, a) = some (m[n + 3] :: removeNth m (n + 3), a)
      simp [run, step, List.getElem?_eq_getElem h]

/-- DELETE: `delOps q` (DROP / NIP / ROLL q;DROP) erases the element at concrete depth `q`. -/
theorem run_delOps {α} (q : Nat) (m a : List α) (h : q < m.length) :
    run (delOps q) (m, a) = some (removeNth m q, a) := by
  match q, h with
  | 0, h =>
      cases m with
      | nil => simp at h
      | cons x s => simp [delOps, run, step, removeNth]
  | 1, h =>
      cases m with
      | nil => simp at h
      | cons x t =>
          cases t with
          | nil => simp at h
          | cons y s => simp [delOps, run, step, removeNth]
  | n + 2, h =>
      show run [Op.ROLL (n + 2), Op.DROP] (m, a) = some (removeNth m (n + 2), a)
      simp [run, step, List.getElem?_eq_getElem h]

/-! ### (B) readStack ALGEBRA — the model (bottom→top) ↔ concrete (head=top) bridge. -/

/-- The concrete stack read from a model stack has the model stack's length (1:1). -/
theorem readStack_length {α} [Inhabited α] (M A : List α) (envF : Env α) (S : List (Entry α)) :
    (readStack M A envF S).length = S.length := by
  simp [readStack]

/-- ★ APPEND = PUSH: appending an entry to the (bottom→top) model stack is consing its value
    on top of the (head=top) concrete read-out. This is why every `emitFetch`/`emitBuildRef`
    that appends a slot corresponds to a top-push on the concrete stack. -/
theorem readStack_append {α} [Inhabited α] (M A : List α) (envF : Env α)
    (S : List (Entry α)) (e : Entry α) :
    readStack M A envF (S ++ [e]) = valOf M A envF e.tok :: readStack M A envF S := by
  simp [readStack]

/-- Helper: `map` commutes with `eraseIdx`. -/
theorem map_eraseIdx {α β} (f : α → β) : ∀ (l : List α) (i : Nat),
    (l.map f).eraseIdx i = (l.eraseIdx i).map f
  | [],      _     => rfl
  | _ :: _,  0     => rfl
  | x :: xs, i + 1 => by
      simp only [List.map_cons, List.eraseIdx_cons_succ, map_eraseIdx f xs i]

/-- Helper: erasing the (bottom→top) index `len-1-d` mirrors erasing the (head=top) index `d`
    after reversing. The index-arithmetic core of the MOVE bookkeeping. -/
theorem reverse_eraseIdx {α} (l : List α) (d : Nat) (h : d < l.length) :
    (l.eraseIdx (l.length - 1 - d)).reverse = l.reverse.eraseIdx d := by
  rw [List.eraseIdx_eq_take_drop_succ l, List.eraseIdx_eq_take_drop_succ l.reverse,
      List.reverse_append, List.take_reverse, List.drop_reverse]
  have e1 : l.length - 1 - d + 1 = l.length - d := by omega
  have e2 : l.length - 1 - d = l.length - (d + 1) := by omega
  rw [e1, e2]

/-- `removeNth` (the spike's take/drop delete) IS `List.eraseIdx`. -/
theorem removeNth_eq_eraseIdx {α} (l : List α) (n : Nat) : removeNth l n = l.eraseIdx n :=
  (List.eraseIdx_eq_take_drop_succ l n).symm

/-- ★ MOVE bookkeeping: reading the model stack after erasing home `len-1-d` equals
    `removeNth d` of the original concrete read-out. Combined with `readStack_append`, this
    shows the MOVE branch of `emitFetch` (erase old slot, push on top) preserves `Inv`. -/
theorem readStack_eraseIdx {α} [Inhabited α] (M A : List α) (envF : Env α)
    (S : List (Entry α)) (d : Nat) (h : d < S.length) :
    readStack M A envF (S.eraseIdx (S.length - 1 - d)) = removeNth (readStack M A envF S) d := by
  rw [removeNth_eq_eraseIdx]
  simp only [readStack]
  rw [← map_eraseIdx]
  have h' : d < (S.map (fun e => valOf M A envF e.tok)).length := by simpa using h
  rw [show S.length - 1 - d = (S.map (fun e => valOf M A envF e.tok)).length - 1 - d by simp]
  rw [reverse_eraseIdx _ d h']

/-! ### (C) depthOfHome VALUE — the liveRef ↦ concrete-index map is value-faithful. -/

/-- ★ A `some d` home lookup lands on the concrete slot at depth `d`, and that slot holds
    exactly the token's denoted value. This is the crux that turns a home DEPTH into a
    guarantee about the concrete stack CONTENTS. -/
theorem depthOfHome_value {α} [DecidableEq α] [Inhabited α]
    (M A : List α) (envF : Env α) (S : List (Entry α)) (tok : Token α) (d : Nat)
    (hd : depthOfHome S tok = some d) :
    d < S.length ∧ (readStack M A envF S)[d]? = some (valOf M A envF tok) := by
  unfold depthOfHome at hd
  rw [List.findIdx?_eq_some_iff_getElem] at hd
  obtain ⟨hlt, hp, _⟩ := hd
  rw [List.length_reverse] at hlt
  refine ⟨hlt, ?_⟩
  simp only [Bool.and_eq_true, Bool.not_eq_true', decide_eq_true_eq] at hp
  obtain ⟨_, htok⟩ := hp
  have hrs : readStack M A envF S = S.reverse.map (fun e => valOf M A envF e.tok) := by
    simp only [readStack]; rw [← List.map_reverse]
  rw [hrs, List.getElem?_map,
      List.getElem?_eq_getElem (by rw [List.length_reverse]; exact hlt)]
  simp only [Option.map_some]
  rw [htok]

/-! ### (D) StepOk — the composable one-step refinement, and the emitFetch step-lemma.

    `StepOk ms ms'` = "the transition `ms → ms'` only APPENDS ops, and running exactly those
    appended ops from any `Inv`-related concrete state reaches an `Inv`-related concrete state."
    This is the CompCert-style one-step simulation diagram, packaged so that whole-block
    composition is just `StepOk.trans` folded over the schedule (`run_append` does the gluing). -/
def StepOk {α} [Inhabited α] (M A : List α) (envF : Env α)
    (ms ms' : ModelState α) : Prop :=
  ∃ δ : List (Op α), ms'.ops = ms.ops ++ δ ∧
    ∀ st, Inv M A envF ms st → ∃ st', run δ st = some st' ∧ Inv M A envF ms' st'

/-- Reflexivity (a no-op emitter step). -/
theorem StepOk.refl {α} [Inhabited α] (M A : List α) (envF : Env α) (ms : ModelState α) :
    StepOk M A envF ms ms :=
  ⟨[], (List.append_nil _).symm, fun st h => ⟨st, rfl, h⟩⟩

/-- ★ TRANSITIVITY — the composition law. Chaining two invariant-preserving steps gives one;
    the concrete run is the append of the two deltas (`run_append`). Folding this over the
    node schedule is the entire whole-block simulation argument. -/
theorem StepOk.trans {α} [Inhabited α] {M A : List α} {envF : Env α}
    {ms₁ ms₂ ms₃ : ModelState α}
    (h12 : StepOk M A envF ms₁ ms₂) (h23 : StepOk M A envF ms₂ ms₃) :
    StepOk M A envF ms₁ ms₃ := by
  obtain ⟨δ₁, ho1, hr1⟩ := h12
  obtain ⟨δ₂, ho2, hr2⟩ := h23
  refine ⟨δ₁ ++ δ₂, by rw [ho2, ho1, List.append_assoc], ?_⟩
  intro st hInv
  obtain ⟨st', hrun1, hInv'⟩ := hr1 st hInv
  obtain ⟨st'', hrun2, hInv''⟩ := hr2 st' hInv'
  exact ⟨st'', by rw [run_append, hrun1]; simpa using hrun2, hInv''⟩

/-- BUILDER: a PUSH step (fresh const / CSE-home establishment). Emits `[PUSH v]`, appends a
    slot whose token denotes `v`. Preserves `Inv` (append=push, `readStack_append`). -/
theorem push_stepOk {α} [Inhabited α] {M A : List α} {envF : Env α}
    {ms ms' : ModelState α} (e : Entry α) (v : α)
    (hv : valOf M A envF e.tok = v)
    (hops : ms'.ops = ms.ops ++ [Op.PUSH v])
    (hS : ms'.S = ms.S ++ [e]) (hSalt : ms'.Salt = ms.Salt) :
    StepOk M A envF ms ms' := by
  refine ⟨[Op.PUSH v], hops, ?_⟩
  intro st hInv
  obtain ⟨m, a⟩ := st
  have h1 : m = readStack M A envF ms.S := hInv.1
  have h2 : a = readStack M A envF ms.Salt := hInv.2
  refine ⟨(v :: m, a), by simp [run, step], ?_, ?_⟩
  · show v :: m = readStack M A envF ms'.S
    rw [hS, readStack_append, hv, h1]
  · show a = readStack M A envF ms'.Salt
    rw [hSalt]; exact h2

/-- BUILDER: a COPY step (`emitFetch` reuse / `emitBuildRef` copy). Emits `copyOps d` from a
    home at depth `d`; appends a slot with the same token. Preserves `Inv`
    (`run_copyOps` + `depthOfHome_value` + `readStack_append`). -/
theorem copy_stepOk {α} [DecidableEq α] [Inhabited α] {M A : List α} {envF : Env α}
    {ms ms' : ModelState α} (e : Entry α) (d : Nat)
    (hdh : depthOfHome ms.S e.tok = some d)
    (hops : ms'.ops = ms.ops ++ copyOps d)
    (hS : ms'.S = ms.S ++ [e]) (hSalt : ms'.Salt = ms.Salt) :
    StepOk M A envF ms ms' := by
  refine ⟨copyOps d, hops, ?_⟩
  intro st hInv
  obtain ⟨hlt, hval⟩ := depthOfHome_value M A envF ms.S e.tok d hdh
  obtain ⟨m, a⟩ := st
  have h1 : m = readStack M A envF ms.S := hInv.1
  have h2 : a = readStack M A envF ms.Salt := hInv.2
  have hd1 : d < m.length := by rw [h1, readStack_length]; exact hlt
  have hq : m[d]? = some (valOf M A envF e.tok) := by rw [h1]; exact hval
  have hmd : m[d] = valOf M A envF e.tok := by
    rw [List.getElem?_eq_getElem hd1] at hq; exact Option.some.inj hq
  refine ⟨(m[d] :: m, a), run_copyOps d m a hd1, ?_, ?_⟩
  · show m[d] :: m = readStack M A envF ms'.S
    rw [hS, readStack_append, hmd, h1]
  · show a = readStack M A envF ms'.Salt
    rw [hSalt]; exact h2

/-- BUILDER: a MOVE step (`emitFetch` last-use). Emits `moveOps d`, erases the depth-`d` home
    and appends the moved slot on top. Preserves `Inv` (`run_moveOps` + `readStack_eraseIdx`). -/
theorem move_stepOk {α} [DecidableEq α] [Inhabited α] {M A : List α} {envF : Env α}
    {ms ms' : ModelState α} (e : Entry α) (d : Nat)
    (hdh : depthOfHome ms.S e.tok = some d)
    (hops : ms'.ops = ms.ops ++ moveOps d)
    (hS : ms'.S = ms.S.eraseIdx (ms.S.length - 1 - d) ++ [e]) (hSalt : ms'.Salt = ms.Salt) :
    StepOk M A envF ms ms' := by
  refine ⟨moveOps d, hops, ?_⟩
  intro st hInv
  obtain ⟨hlt, hval⟩ := depthOfHome_value M A envF ms.S e.tok d hdh
  obtain ⟨m, a⟩ := st
  have h1 : m = readStack M A envF ms.S := hInv.1
  have h2 : a = readStack M A envF ms.Salt := hInv.2
  have hd1 : d < m.length := by rw [h1, readStack_length]; exact hlt
  have hq : m[d]? = some (valOf M A envF e.tok) := by rw [h1]; exact hval
  have hmd : m[d] = valOf M A envF e.tok := by
    rw [List.getElem?_eq_getElem hd1] at hq; exact Option.some.inj hq
  refine ⟨(m[d] :: removeNth m d, a), run_moveOps d m a hd1, ?_, ?_⟩
  · show m[d] :: removeNth m d = readStack M A envF ms'.S
    rw [hS, readStack_append, hmd, readStack_eraseIdx M A envF ms.S d hlt, h1]
  · show a = readStack M A envF ms'.Salt
    rw [hSalt]; exact h2

/-- ★ STEP-LEMMA (1) — emitFetch preserves `Inv`. For a ref that is a constant OR has a live
    home (the `WellFormed`-guaranteed case for `in/ain/out` refs), materializing it to the top
    is a valid one-step refinement. MOVE (last use) / COPY (reuse) / fresh-PUSH are each one of
    the three builders; the `none`-home non-const branch is `WellFormed`-excluded (ruled out by
    `hhome`). This is the index-arithmetic crux, now composable via `StepOk`. -/
theorem emitFetch_stepOk {α} [DecidableEq α] [Inhabited α]
    (M A : List α) (envF : Env α) (r : Ref α) (ms : ModelState α)
    (hhome : (∃ v b, r = Ref.const v b) ∨ (depthOfHome ms.S (tokenOf r)).isSome = true) :
    StepOk M A envF ms (emitFetch r ms) := by
  -- helper for the three non-const, live-home refs (in / ain / out): they share the emitFetch
  -- `else` branch shape; only the token differs.
  rcases r with i | i | ⟨v, cse⟩ | ⟨nid, j⟩
  · -- inp i
    have hsome : (depthOfHome ms.S (Token.inTok i)).isSome = true := by
      rcases hhome with ⟨_, _, hc⟩ | hs
      · simp at hc
      · exact hs
    cases hdh : depthOfHome ms.S (Token.inTok i) with
    | none => rw [hdh] at hsome; simp at hsome
    | some d =>
        by_cases huse : ms.use (Token.inTok i) = 1
        · apply move_stepOk (⟨Token.inTok i, true⟩) d hdh <;> simp [emitFetch, tokenOf, hdh, huse]
        · apply copy_stepOk (⟨Token.inTok i, true⟩) d hdh <;> simp [emitFetch, tokenOf, hdh, huse]
  · -- ainp i
    have hsome : (depthOfHome ms.S (Token.ainTok i)).isSome = true := by
      rcases hhome with ⟨_, _, hc⟩ | hs
      · simp at hc
      · exact hs
    cases hdh : depthOfHome ms.S (Token.ainTok i) with
    | none => rw [hdh] at hsome; simp at hsome
    | some d =>
        by_cases huse : ms.use (Token.ainTok i) = 1
        · apply move_stepOk (⟨Token.ainTok i, true⟩) d hdh <;> simp [emitFetch, tokenOf, hdh, huse]
        · apply copy_stepOk (⟨Token.ainTok i, true⟩) d hdh <;> simp [emitFetch, tokenOf, hdh, huse]
  · -- const v cse
    cases cse with
    | false =>
        apply push_stepOk (⟨Token.nullTok v, true⟩) v rfl <;> simp [emitFetch]
    | true =>
        cases hdh : depthOfHome ms.S (Token.cTok v) with
        | none =>
            apply push_stepOk (⟨Token.cTok v, true⟩) v rfl <;> simp [emitFetch, tokenOf, hdh]
        | some d =>
            by_cases huse : ms.use (Token.cTok v) = 1
            · apply move_stepOk (⟨Token.cTok v, true⟩) d hdh <;> simp [emitFetch, tokenOf, hdh, huse]
            · apply copy_stepOk (⟨Token.cTok v, true⟩) d hdh <;> simp [emitFetch, tokenOf, hdh, huse]
  · -- out nid j
    have hsome : (depthOfHome ms.S (Token.vTok nid j)).isSome = true := by
      rcases hhome with ⟨_, _, hc⟩ | hs
      · simp at hc
      · exact hs
    cases hdh : depthOfHome ms.S (Token.vTok nid j) with
    | none => rw [hdh] at hsome; simp at hsome
    | some d =>
        by_cases huse : ms.use (Token.vTok nid j) = 1
        · apply move_stepOk (⟨Token.vTok nid j, true⟩) d hdh <;> simp [emitFetch, tokenOf, hdh, huse]
        · apply copy_stepOk (⟨Token.vTok nid j, true⟩) d hdh <;> simp [emitFetch, tokenOf, hdh, huse]

/-! ### (E) const-CSE (`emitBuildRef`) + the DELETE builder (eager-drop / stale-tail). -/

/-- BUILDER: a DELETE step (`eagerDrop` dead top / `emitExitMain` stale tail). Emits `delOps d`,
    erases the depth-`d` model home; NO append. Preserves `Inv` (`run_delOps` + `readStack_eraseIdx`). -/
theorem del_stepOk {α} [DecidableEq α] [Inhabited α] {M A : List α} {envF : Env α}
    {ms ms' : ModelState α} (d : Nat) (hdlt : d < ms.S.length)
    (hops : ms'.ops = ms.ops ++ delOps d)
    (hS : ms'.S = ms.S.eraseIdx (ms.S.length - 1 - d)) (hSalt : ms'.Salt = ms.Salt) :
    StepOk M A envF ms ms' := by
  refine ⟨delOps d, hops, ?_⟩
  intro st hInv
  obtain ⟨m, a⟩ := st
  have h1 : m = readStack M A envF ms.S := hInv.1
  have h2 : a = readStack M A envF ms.Salt := hInv.2
  have hd1 : d < m.length := by rw [h1, readStack_length]; exact hdlt
  refine ⟨(removeNth m d, a), run_delOps d m a hd1, ?_, ?_⟩
  · show removeNth m d = readStack M A envF ms'.S
    rw [hS, readStack_eraseIdx M A envF ms.S d hdlt, h1]
  · show a = readStack M A envF ms'.Salt
    rw [hSalt]; exact h2

/-- ★ STEP-LEMMA (4) — const-CSE + exit-ref build (`emitBuildRef`). A CSE const with a live
    home is COPY-reused (push-once, then PICK); with no home yet it is PUSHed; a small const is
    freshly PUSHed; a slot ref is COPYied from its home. Every case is a `push`/`copy` builder,
    recording a NON-transient exit slot. (No MOVE — exit build never consumes a home.) -/
theorem emitBuildRef_stepOk {α} [DecidableEq α] [Inhabited α]
    (M A : List α) (envF : Env α) (r : Ref α) (ms : ModelState α)
    (hhome : (∃ v b, r = Ref.const v b) ∨ (depthOfHome ms.S (tokenOf r)).isSome = true) :
    StepOk M A envF ms (emitBuildRef r ms) := by
  rcases r with i | i | ⟨v, cse⟩ | ⟨nid, j⟩
  · have hsome : (depthOfHome ms.S (Token.inTok i)).isSome = true := by
      rcases hhome with ⟨_, _, hc⟩ | hs
      · simp at hc
      · exact hs
    cases hdh : depthOfHome ms.S (Token.inTok i) with
    | none => rw [hdh] at hsome; simp at hsome
    | some d => apply copy_stepOk (⟨Token.inTok i, false⟩) d hdh <;> simp [emitBuildRef, tokenOf, hdh]
  · have hsome : (depthOfHome ms.S (Token.ainTok i)).isSome = true := by
      rcases hhome with ⟨_, _, hc⟩ | hs
      · simp at hc
      · exact hs
    cases hdh : depthOfHome ms.S (Token.ainTok i) with
    | none => rw [hdh] at hsome; simp at hsome
    | some d => apply copy_stepOk (⟨Token.ainTok i, false⟩) d hdh <;> simp [emitBuildRef, tokenOf, hdh]
  · cases cse with
    | false => apply push_stepOk (⟨Token.nullTok v, false⟩) v rfl <;> simp [emitBuildRef]
    | true =>
        cases hdh : depthOfHome ms.S (Token.cTok v) with
        | none => apply push_stepOk (⟨Token.cTok v, false⟩) v rfl <;> simp [emitBuildRef, hdh]
        | some d => apply copy_stepOk (⟨Token.cTok v, false⟩) d hdh <;> simp [emitBuildRef, hdh]
  · have hsome : (depthOfHome ms.S (Token.vTok nid j)).isSome = true := by
      rcases hhome with ⟨_, _, hc⟩ | hs
      · simp at hc
      · exact hs
    cases hdh : depthOfHome ms.S (Token.vTok nid j) with
    | none => rw [hdh] at hsome; simp at hsome
    | some d => apply copy_stepOk (⟨Token.vTok nid j, false⟩) d hdh <;> simp [emitBuildRef, tokenOf, hdh]

/-! ### (F) emitNode CALL — operands-on-top ⇒ node output(s) on top. -/

/-- `valOf ∘ tokenOf = dRef`: a token's denoted value is exactly its ref's DAG value. Hence a
    materialized operand slot holds precisely `dRef` of that operand. -/
theorem valOf_tokenOf {α} [Inhabited α] (M A : List α) (envF : Env α) (r : Ref α) :
    valOf M A envF (tokenOf r) = dRef M A envF r := by
  cases r with
  | inp i => rfl
  | ainp i => rfl
  | out nid j => rfl
  | const v cse => cases cse <;> rfl

/-- `readStack` splits over append (top part first, since head=top). -/
theorem readStack_append_gen {α} [Inhabited α] (M A : List α) (envF : Env α)
    (X Y : List (Entry α)) :
    readStack M A envF (X ++ Y) = readStack M A envF Y ++ readStack M A envF X := by
  simp [readStack]

/-- Concrete CALL semantics: pop the top `nin`, apply `f` bottom→top, push its reversed result. -/
theorem run_call {α} (nin : Nat) (f : List α → List α) (s a : List α) (h : nin ≤ s.length) :
    run [Op.CALL nin f] (s, a) = some ((f ((s.take nin).reverse)).reverse ++ s.drop nin, a) := by
  simp [run, step, h]

/-- ★ STEP-LEMMA (2) — the emitNode CALL step. When the model stack is `base ++ ops` (the `nin`
    operands sitting contiguously on top) and the outputs' denoted values are exactly
    `f (operand values)` (the DENOTATION LINK `hout` — discharged from `denoteNodes`/topo-order
    for a `WellFormed` block; see the frontier note), emitting `CALL nin f` and replacing the
    operands by the output slots `base ++ outs` preserves `Inv`. This is "operands-on-top then op
    ⇒ output on top, invariant extended", with the stack-wiring fully machine-checked. -/
theorem emitCall_stepOk {α} [Inhabited α] (M A : List α) (envF : Env α)
    {ms ms' : ModelState α} (nin nout : Nat) (f : List α → List α) (id : Nat)
    (base ops : List (Entry α))
    (hlen : ops.length = nin)
    (hout : (List.range nout).map (fun jj => valOf M A envF (Token.vTok id jj))
            = f (ops.map (fun e => valOf M A envF e.tok)))
    (hS : ms.S = base ++ ops)
    (hops : ms'.ops = ms.ops ++ [Op.CALL nin f])
    (hS' : ms'.S = base ++ (List.range nout).map (fun jj => (⟨Token.vTok id jj, false⟩ : Entry α)))
    (hSalt : ms'.Salt = ms.Salt) :
    StepOk M A envF ms ms' := by
  refine ⟨[Op.CALL nin f], hops, ?_⟩
  intro st hInv
  obtain ⟨m, a⟩ := st
  have h1 : m = readStack M A envF ms.S := hInv.1
  have h2 : a = readStack M A envF ms.Salt := hInv.2
  have hro : (readStack M A envF ops).length = nin := by rw [readStack_length]; exact hlen
  have hm : m = readStack M A envF ops ++ readStack M A envF base := by
    rw [h1, hS, readStack_append_gen]
  have hnin : nin ≤ m.length := by rw [hm, List.length_append, hro]; omega
  refine ⟨((f ((m.take nin).reverse)).reverse ++ m.drop nin, a), run_call nin f m a hnin, ?_, ?_⟩
  · show (f ((m.take nin).reverse)).reverse ++ m.drop nin = readStack M A envF ms'.S
    rw [hm, List.take_left' hro, List.drop_left' hro, hS', readStack_append_gen]
    have hopsrev : (readStack M A envF ops).reverse = ops.map (fun e => valOf M A envF e.tok) := by
      simp [readStack]
    rw [hopsrev]
    congr 1
    rw [readStack, List.map_map, ← hout]
    rfl
  · show a = readStack M A envF ms'.Salt
    rw [hSalt]; exact h2

end LeanBCH.Opt
