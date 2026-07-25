/-
  PASS-2 DAG-SCHEDULER — THE GENERAL EMIT OP-TYPING LEMMA.

  `emit_ops_typed`: EVERY op the scheduler emits for a `Block α` has one of exactly four shapes,
  each recoverable from the block itself:
    • a stack SHUFFLE the emitter uses — one of {DUP, DROP, OVER, SWAP, ROT, NIP, TOALT, FROMALT}
      (the only shuffles the depth→op folds `copyOps`/`moveOps`/`delOps` and the alt drain/deposit
      ever produce);
    • a PICK n or ROLL n (index folds for depth ≥ 2 copies / ≥ 3 moves / ≥ 2 deletes);
    • a PUSH v where `Ref.const v cse` is a CONSTANT REF OF THE BLOCK (appears in some node's
      inputs, the exit, or the exitAlt) — the emitter only ever pushes constants it was asked to
      materialize;
    • a CALL nd.op.nin nd.op.sem for some `nd ∈ b.nodes` — the emitter's `emitNode` appends
      EXACTLY the node's own `NodeOp` as the compute call.

  ★ WHY THIS MATTERS. `EmitConcrete.emit_bA_sound`/`emit_bDup_sound` fire the real-VM bridge on
  FIXED hand-built blocks by `rfl`-computing `emit b` to a literal op list and typing each op by
  hand. To upgrade `PushButton.push_button_arith` to an ARBITRARY WellFormed block, the encoder
  `enc` must be shown faithful on every op the scheduler CAN emit — i.e. we need a structural
  characterization of `emit b`'s op set that holds for ALL blocks, not a per-block `rfl`. That is
  exactly `emit_ops_typed`: it is the missing "scheduler-output typing lemma" the `EmitConcrete`
  scope note names as the one piece the fully-general theorem still needs.

  ★ PROOF SHAPE — structural induction through `scheduleBlock`'s phases. The emitter is a pipeline
  of folds over `ModelState`; each phase only ever APPENDS ops to `ms.ops`, and every appended op
  is of an allowed shape. We prove one `*_typed` lemma per primitive (`copyOps`/`moveOps`/`delOps`
  shape lemmas; then `emitFetch`/`eagerDrop`/`emitNode`/`emitBuildRef`/`emitExitMain`), each of the
  form "OpsTyped ms → (side conditions) → OpsTyped (phase ms)", and compose them along the exact
  fold structure of `scheduleBlock`. The CALL and PUSH shapes are the load-bearing cases: `emitNode`
  is applied inside `b.nodes.foldl`, so its node argument is a genuine member of `b.nodes`; and
  every `emitFetch`/`emitBuildRef` is applied to a ref drawn from `b`'s own operand/exit lists, so
  any constant it pushes is a constant ref of `b`.

  Lean 4 core only; NO mathlib. Additive: a NEW file; nothing existing is edited.
-/
import LeanBCH.Opt.Scheduler

namespace LeanBCH.Opt

open Op

/-! ### The block's constant refs, and the `EmitOp` typing predicate. -/

/-- All refs syntactically occurring in a block: every node's inputs, the exit, the exitAlt.
    Every constant the emitter pushes and every node whose `CALL` it emits is drawn from here. -/
def blockRefs (b : Block α) : List (Ref α) :=
  b.nodes.flatMap Node.ins ++ b.exit ++ b.exitAlt

/-- ★ THE EMIT-TYPING PREDICATE. An op is EMITTABLE-FROM-`b` iff it is one of:
    * a stack shuffle the emitter's depth-folds / alt-drain produce
      ({DUP, DROP, OVER, SWAP, ROT, NIP, TOALT, FROMALT});
    * a `PICK n` or `ROLL n`;
    * a `PUSH v` whose value is a CONSTANT REF of the block (`Ref.const v cse ∈ blockRefs b`);
    * a `CALL nd.op.nin nd.op.sem` for some node `nd ∈ b.nodes`. -/
def EmitOp (b : Block α) : Op α → Prop
  | .DUP | .DROP | .OVER | .SWAP | .ROT | .NIP | .TOALT | .FROMALT => True
  | .PICK _ | .ROLL _ => True
  | .PUSH v => ∃ cse, Ref.const v cse ∈ blockRefs b
  | .CALL nin sem => ∃ nd ∈ b.nodes, nin = nd.op.nin ∧ sem = nd.op.sem
  -- the remaining shuffles the emitter never produces:
  | .TUCK | .TWODROP | .TWODUP | .THREEDUP | .TWOOVER | .TWOROT | .TWOSWAP => False

/-- Every op emitted so far in a model state is emittable-from-`b`. -/
def OpsTyped (b : Block α) (ms : ModelState α) : Prop := ∀ op ∈ ms.ops, EmitOp b op

/-- Appending a list of emittable ops preserves typedness. -/
theorem opsTyped_append {b : Block α} {L extra : List (Op α)}
    (h : ∀ op ∈ L, EmitOp b op) (hextra : ∀ op ∈ extra, EmitOp b op) :
    ∀ op ∈ L ++ extra, EmitOp b op := by
  intro op hop
  rcases List.mem_append.mp hop with h1 | h2
  · exact h op h1
  · exact hextra op h2

/-! ### Shape lemmas for the three depth→op folds. Each produces only allowed shuffles/PICK/ROLL. -/

theorem copyOps_typed (b : Block α) (d : Nat) : ∀ op ∈ (copyOps d : List (Op α)), EmitOp b op := by
  intro op hop
  match d with
  | 0 => simp only [copyOps, List.mem_singleton] at hop; subst hop; trivial
  | 1 => simp only [copyOps, List.mem_singleton] at hop; subst hop; trivial
  | n + 2 => simp only [copyOps, List.mem_singleton] at hop; subst hop; trivial

theorem moveOps_typed (b : Block α) (d : Nat) : ∀ op ∈ (moveOps d : List (Op α)), EmitOp b op := by
  intro op hop
  match d with
  | 0 => simp only [moveOps, List.not_mem_nil] at hop
  | 1 => simp only [moveOps, List.mem_singleton] at hop; subst hop; trivial
  | 2 => simp only [moveOps, List.mem_singleton] at hop; subst hop; trivial
  | n + 3 => simp only [moveOps, List.mem_singleton] at hop; subst hop; trivial

theorem delOps_typed (b : Block α) (q : Nat) : ∀ op ∈ (delOps q : List (Op α)), EmitOp b op := by
  intro op hop
  match q with
  | 0 => simp only [delOps, List.mem_singleton] at hop; subst hop; trivial
  | 1 => simp only [delOps, List.mem_singleton] at hop; subst hop; trivial
  | n + 2 =>
      simp only [delOps, List.mem_cons, List.not_mem_nil, or_false] at hop
      rcases hop with rfl | rfl <;> trivial

/-! ### Ref-membership helpers: a node input / exit / exitAlt ref is a block ref. -/

theorem ins_mem_blockRefs {b : Block α} {n : Node α} (hn : n ∈ b.nodes) {r : Ref α}
    (hr : r ∈ n.ins) : r ∈ blockRefs b := by
  unfold blockRefs
  apply List.mem_append_left
  apply List.mem_append_left
  exact List.mem_flatMap.mpr ⟨n, hn, hr⟩

theorem exit_mem_blockRefs {b : Block α} {r : Ref α} (hr : r ∈ b.exit) : r ∈ blockRefs b := by
  unfold blockRefs
  exact List.mem_append_left _ (List.mem_append_right _ hr)

theorem exitAlt_mem_blockRefs {b : Block α} {r : Ref α} (hr : r ∈ b.exitAlt) : r ∈ blockRefs b :=
  List.mem_append_right _ hr

/-! ### Generic `foldl` preservation: folding a typedness-preserving step over any list stays typed. -/

theorem foldl_typed {β : Type} {b : Block α} (f : ModelState α → β → ModelState α) :
    ∀ (L : List β) {ms : ModelState α},
      (∀ (m : ModelState α) (x : β), x ∈ L → OpsTyped b m → OpsTyped b (f m x)) →
      OpsTyped b ms → OpsTyped b (L.foldl f ms)
  | [],      _, _,  h => h
  | x :: xs, _, hf, h => by
      simp only [List.foldl_cons]
      exact foldl_typed f xs
        (fun m y hy hm => hf m y (List.mem_cons.mpr (Or.inr hy)) hm)
        (hf _ x (List.mem_cons.mpr (Or.inl rfl)) h)

/-! ### Phase lemma: `emitFetch` only appends PUSH (of the ref, when const) / MOVE / COPY ops. -/

/-- `emitFetch r` preserves typedness provided any constant it might push (when `r` is a
    constant ref) is a constant ref of the block. All call sites supply `r ∈ blockRefs b`. -/
theorem emitFetch_typed [DecidableEq α] {b : Block α} {r : Ref α} {ms : ModelState α}
    (h : OpsTyped b ms) (hr : r ∈ blockRefs b) : OpsTyped b (emitFetch r ms) := by
  intro op hop
  rcases r with i | i | ⟨v, cse⟩ | ⟨nid, j⟩
  case inp | ainp | out =>
    all_goals {
      simp only [emitFetch] at hop
      split at hop
      · exact h op hop
      · split at hop
        · exact opsTyped_append h (moveOps_typed b _) op hop
        · exact opsTyped_append h (copyOps_typed b _) op hop }
  case const =>
    cases cse
    · -- .const v false : always freshly pushed
      simp only [emitFetch] at hop
      rcases List.mem_append.mp hop with h1 | h2
      · exact h op h1
      · simp only [List.mem_singleton] at h2; subst h2; exact ⟨false, hr⟩
    · -- .const v true : CSE const
      simp only [emitFetch] at hop
      split at hop
      · -- none: pushed a lone transient PUSH v
        rcases List.mem_append.mp hop with h1 | h2
        · exact h op h1
        · simp only [List.mem_singleton] at h2; subst h2; exact ⟨true, hr⟩
      · split at hop
        · exact opsTyped_append h (moveOps_typed b _) op hop
        · exact opsTyped_append h (copyOps_typed b _) op hop

/-! ### Phase lemma: `eagerDrop` only ever appends `DROP`. -/

theorem eagerDrop_typed [DecidableEq α] {b : Block α} (fuel : Nat) {ms : ModelState α}
    (h : OpsTyped b ms) : OpsTyped b (eagerDrop fuel ms) := by
  induction fuel generalizing ms with
  | zero => exact h
  | succ fuel ih =>
      unfold eagerDrop
      split
      · exact h
      · split
        · exact h
        · split
          · refine ih ?_
            exact opsTyped_append h (by intro op hop; simp only [List.mem_singleton] at hop;
                                        subst hop; trivial)
          · exact h

/-! ### Phase lemma: `emitNode` appends CSE-const PUSHes, operand MOVE/COPY/PUSHes, then the
    node's own `CALL`, then eager DROPs — all emittable-from-`b` when `n ∈ b.nodes`. -/

/-- The CSE-const home-setup step (stage 1 of `emitNode`), factored out so its typedness is
    referable. Definitionally equal to the inline lambda in `emitNode`. -/
def cseSetupStep [DecidableEq α] (m : ModelState α) (inp : Ref α) : ModelState α :=
  match inp with
  | .const v true =>
      match depthOfHome m.S (Token.cTok v) with
      | some _ => m
      | none   => if 1 < m.use (Token.cTok v)
                  then { m with ops := m.ops ++ [Op.PUSH v], S := m.S ++ [⟨Token.cTok v, false⟩] }
                  else m
  | _ => m

theorem cseSetupStep_typed [DecidableEq α] {b : Block α} {n : Node α} (hn : n ∈ b.nodes)
    (m : ModelState α) (inp : Ref α) (hinp : inp ∈ n.ins) (hm : OpsTyped b m) :
    OpsTyped b (cseSetupStep m inp) := by
  unfold cseSetupStep
  split
  · -- inp = .const v true
    rename_i v
    split
    · exact hm
    · split
      · intro op hop
        rcases List.mem_append.mp hop with hh | hh
        · exact hm op hh
        · simp only [List.mem_singleton] at hh; subst hh
          exact ⟨true, ins_mem_blockRefs hn hinp⟩
      · exact hm
  · exact hm

theorem emitNode_typed [DecidableEq α] {b : Block α} {n : Node α} {ms : ModelState α}
    (hn : n ∈ b.nodes) (h : OpsTyped b ms) : OpsTyped b (emitNode n ms) := by
  -- stage 1: CSE-const home setup
  have h1 : OpsTyped b (n.ins.foldl cseSetupStep ms) :=
    foldl_typed cseSetupStep n.ins
      (fun m inp hinp hm => cseSetupStep_typed hn m inp hinp hm) h
  -- stage 2: materialize operands (emitFetch)
  have h2 : OpsTyped b (n.ins.foldl (fun m inp => emitFetch inp m) (n.ins.foldl cseSetupStep ms)) :=
    foldl_typed (fun m inp => emitFetch inp m) n.ins
      (fun m inp hinp hm => emitFetch_typed hm (ins_mem_blockRefs hn hinp)) h1
  -- stage 3: emit the node's CALL; stage 4: eager-drop.  Assemble by unfolding.
  unfold emitNode
  apply eagerDrop_typed
  intro op hop
  rcases List.mem_append.mp hop with hh | hh
  · exact h2 op hh
  · simp only [List.mem_singleton] at hh; subst hh
    exact ⟨n, hn, rfl, rfl⟩

/-! ### Phase lemma: `emitBuildRef` appends PUSH (of the ref, when const) / COPY. -/

theorem emitBuildRef_typed [DecidableEq α] {b : Block α} {r : Ref α} {ms : ModelState α}
    (h : OpsTyped b ms) (hr : r ∈ blockRefs b) : OpsTyped b (emitBuildRef r ms) := by
  intro op hop
  rcases r with i | i | ⟨v, cse⟩ | ⟨nid, j⟩
  case inp | ainp | out =>
    all_goals {
      simp only [emitBuildRef] at hop
      split at hop
      · exact opsTyped_append h (copyOps_typed b _) op hop
      · exact h op hop }
  case const =>
    cases cse
    · simp only [emitBuildRef] at hop
      rcases List.mem_append.mp hop with hh | hh
      · exact h op hh
      · simp only [List.mem_singleton] at hh; subst hh; exact ⟨false, hr⟩
    · simp only [emitBuildRef] at hop
      split at hop
      · exact opsTyped_append h (copyOps_typed b _) op hop
      · rcases List.mem_append.mp hop with hh | hh
        · exact h op hh
        · simp only [List.mem_singleton] at hh; subst hh; exact ⟨true, hr⟩

/-! ### Phase lemma: `emitExitMain` builds exit refs (COPY/PUSH) then appends stale-tail deletes. -/

theorem emitExitMain_typed [DecidableEq α] {b : Block α} {ms : ModelState α}
    (h : OpsTyped b ms) : OpsTyped b (emitExitMain b ms) := by
  have hmsB : OpsTyped b ((b.exit.drop (matchPrefixAux ms.S 0 b.exit)).foldl
      (fun m r => emitBuildRef r m) ms) :=
    foldl_typed (fun m r => emitBuildRef r m) _
      (fun m r hr hm => emitBuildRef_typed hm (exit_mem_blockRefs (List.mem_of_mem_drop hr))) h
  unfold emitExitMain
  apply foldl_typed
  · intro m _ _ hm op hop
    rcases List.mem_append.mp hop with hh | hh
    · exact hm op hh
    · exact delOps_typed b _ op hh
  · exact hmsB

/-! ### ★★★ THE HEADLINE — every op the scheduler emits for ANY block is emittable-from-that-block.

    `scheduleBlock` is: seed entry slots (empty `ops`) → (alt-drain FROMALTs, unless passthrough)
    → emit each node (`emitNode`, over `b.nodes`) → (alt-deposit TOALTs, unless passthrough) →
    incremental main arrange (`emitExitMain`). Each stage is a fold whose step preserves
    typedness (`*_typed` above); the two `bif`-guarded stages are typed on both branches; and the
    node/deposit steps hit refs drawn from `b`. Composing along that exact structure discharges it. -/

theorem scheduleBlock_typed [DecidableEq α] (b : Block α) : OpsTyped b (scheduleBlock b) := by
  unfold scheduleBlock
  apply emitExitMain_typed
  cases hpass : altPassthrough b
  · -- passthrough = false: alt-deposit ∘ node-fold ∘ alt-drain, all over `ms0` (ops = [])
    apply foldl_typed         -- alt-deposit (TOALT after emitFetch)
    · intro m r hr hm op hop
      rcases List.mem_append.mp hop with hh | hh
      · exact emitFetch_typed hm (exitAlt_mem_blockRefs hr) op hh
      · simp only [List.mem_singleton] at hh; subst hh; trivial
    · apply foldl_typed       -- node-fold
      · intro m n hn hm; exact emitNode_typed hn hm
      · apply foldl_typed     -- alt-drain (FROMALT)
        · intro m k _ hm op hop
          rcases List.mem_append.mp hop with hh | hh
          · exact hm op hh
          · simp only [List.mem_singleton] at hh; subst hh; trivial
        · intro op hop; cases hop
  · -- passthrough = true: just the node-fold over `ms0` (both alt stages are identities)
    apply foldl_typed         -- node-fold
    · intro m n hn hm; exact emitNode_typed hn hm
    · intro op hop; cases hop

/-- ★★★ THE GENERAL EMIT OP-TYPING LEMMA. For EVERY block `b` and EVERY op the PASS-2 scheduler
    emits (`op ∈ emit b`), `op` is emittable-from-`b`: it is one of the eight stack shuffles the
    emitter uses, a `PICK`/`ROLL`, a `PUSH` of one of `b`'s own constant refs, or the `CALL` of one
    of `b`'s own nodes. This is the structural characterization of `emit b`'s op set that the
    fully-general real-VM bridge needs (the `EmitConcrete` scope note's missing piece): it upgrades
    the per-op `enc`-faithfulness discharge from FIXED blocks to ANY block. -/
theorem emit_ops_typed [DecidableEq α] (b : Block α) : ∀ op ∈ emit b, EmitOp b op :=
  scheduleBlock_typed b

/-- ★ THE SAME FACT AS AN EXPLICIT FIVE-WAY DISJUNCTION — the downstream-friendly interface.
    Any op the scheduler emits is: one of the eight shuffles the emitter uses; a `PICK n`; a
    `ROLL n`; a `PUSH v` of a constant ref of `b`; or the `CALL` of one of `b`'s nodes. A caller
    (e.g. a general `enc`-faithfulness discharge) does `rcases emit_op_cases …` and handles exactly
    these five shapes, with the never-emitted shuffles (`TUCK`/`2DROP`/`2DUP`/`3DUP`/`2OVER`/`2ROT`/
    `2SWAP`) provably absent. -/
theorem emit_op_cases [DecidableEq α] (b : Block α) (op : Op α) (hop : op ∈ emit b) :
    (op = .DUP ∨ op = .DROP ∨ op = .OVER ∨ op = .SWAP ∨ op = .ROT ∨ op = .NIP
        ∨ op = .TOALT ∨ op = .FROMALT)
    ∨ (∃ n, op = .PICK n)
    ∨ (∃ n, op = .ROLL n)
    ∨ (∃ v cse, op = .PUSH v ∧ Ref.const v cse ∈ blockRefs b)
    ∨ (∃ nd ∈ b.nodes, op = .CALL nd.op.nin nd.op.sem) := by
  have h := emit_ops_typed b op hop
  cases op with
  | DUP     => exact Or.inl (Or.inl rfl)
  | DROP    => exact Or.inl (Or.inr (Or.inl rfl))
  | OVER    => exact Or.inl (Or.inr (Or.inr (Or.inl rfl)))
  | SWAP    => exact Or.inl (Or.inr (Or.inr (Or.inr (Or.inl rfl))))
  | ROT     => exact Or.inl (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl rfl)))))
  | NIP     => exact Or.inl (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl rfl))))))
  | TOALT   => exact Or.inl (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl rfl)))))))
  | FROMALT => exact Or.inl (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr rfl)))))))
  | PICK n  => exact Or.inr (Or.inl ⟨n, rfl⟩)
  | ROLL n  => exact Or.inr (Or.inr (Or.inl ⟨n, rfl⟩))
  | PUSH v  =>
      obtain ⟨cse, hc⟩ := h
      exact Or.inr (Or.inr (Or.inr (Or.inl ⟨v, cse, rfl, hc⟩)))
  | CALL nin sem =>
      obtain ⟨nd, hnd, hnin, hsem⟩ := h
      subst hnin; subst hsem
      exact Or.inr (Or.inr (Or.inr (Or.inr ⟨nd, hnd, rfl⟩)))
  | TUCK | TWODROP | TWODUP | THREEDUP | TWOOVER | TWOROT | TWOSWAP => exact h.elim

end LeanBCH.Opt
