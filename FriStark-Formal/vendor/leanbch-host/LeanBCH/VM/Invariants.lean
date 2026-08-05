/-
  LeanBCH.VM.Invariants — the SELF-HARDENING layer (see `SELF_HARDENING.md`).

  Converts LeanBCH's *differential* trust into *deductive* trust: theorems ABOUT the verifier
  itself, so whole classes of bug (a missing guard, a non-monotone meter, an un-sticky reject)
  become unprovable-if-present rather than caught vector-by-vector.

  A STRICT LEAF: imports `Verify` (⇒ `Extended`/`Eval`) and is imported by nothing (added last
  in `LeanBCH.lean`). It proves theorems about the FROZEN keystone without touching it — the
  freeze forbids changing the definitions, not reasoning about them. Pure Lean 4, no mathlib.

  === Increment 1: the order & metering substrate ===
  Axis B (metering monotonicity) + Axis D (error stickiness) from the design doc: the
  componentwise `Metrics` order, `stepOpCost`/`operationCost` monotonicity, per-step and
  per-run cost monotonicity, and the errored-state fixpoint. The reusable algebra every
  higher-axis theorem stands on.
-/
import LeanBCH.VM.Verify

namespace LeanBCH.Cost
namespace Metrics

/-! ### The componentwise order on the five metrics
    `Nat`-valued and accumulated additively, so the natural order is componentwise `≤`; it makes
    the cost meter a monotone object (nothing the VM does can *decrease* accumulated work). -/

/-- Componentwise order: every one of the five primitive metrics is `≤`. -/
def le (a b : Metrics) : Prop :=
  a.evaluatedInstructionCount ≤ b.evaluatedInstructionCount ∧
  a.signatureCheckCount       ≤ b.signatureCheckCount ∧
  a.hashDigestIterations      ≤ b.hashDigestIterations ∧
  a.arithmeticCost            ≤ b.arithmeticCost ∧
  a.stackPushedBytes          ≤ b.stackPushedBytes

instance : LE Metrics := ⟨le⟩

/-- Unfolding lemma: `≤` on `Metrics` IS the five-way componentwise conjunction (definitional). -/
theorem le_def (a b : Metrics) :
    a ≤ b ↔
      a.evaluatedInstructionCount ≤ b.evaluatedInstructionCount ∧
      a.signatureCheckCount       ≤ b.signatureCheckCount ∧
      a.hashDigestIterations      ≤ b.hashDigestIterations ∧
      a.arithmeticCost            ≤ b.arithmeticCost ∧
      a.stackPushedBytes          ≤ b.stackPushedBytes := Iff.rfl

@[refl] theorem le_refl (a : Metrics) : a ≤ a := by
  simp only [le_def]; omega

theorem le_trans {a b c : Metrics} (h1 : a ≤ b) (h2 : b ≤ c) : a ≤ c := by
  simp only [le_def] at h1 h2 ⊢; omega

/-- `Nat` has no negatives, so adding metrics can only grow the total: `a ≤ a + b`. -/
theorem le_add_right (a b : Metrics) : a ≤ a + b := by
  simp only [le_def, add_eq, add]; omega

/-- Symmetric form: `b ≤ a + b`. -/
theorem le_add_left (a b : Metrics) : b ≤ a + b := by
  simp only [le_def, add_eq, add]; omega

/-- Addition is monotone in both arguments — the meter's accumulation preserves order. -/
theorem add_le_add {a b c d : Metrics} (h1 : a ≤ b) (h2 : c ≤ d) : a + c ≤ b + d := by
  simp only [le_def, add_eq, add] at h1 h2 ⊢; omega

end Metrics

/-- The DERIVED aggregate op-cost is a monotone linear functional of the metrics, for ANY epoch.
    `m.field * E.rate` is nonlinear for `omega` (the epoch rate is a variable), so bound each
    weighted term with `Nat.mul_le_mul` and re-assemble. -/
theorem operationCost_mono (E : Epoch) {m m' : Metrics} (h : m ≤ m') :
    operationCost E m ≤ operationCost E m' := by
  obtain ⟨h1, h2, h3, h4, h5⟩ := h
  simp only [operationCost]
  exact Nat.add_le_add (Nat.add_le_add (Nat.add_le_add (Nat.add_le_add
    (Nat.mul_le_mul h1 (Nat.le_refl _))
    (Nat.mul_le_mul h2 (Nat.le_refl _)))
    (Nat.mul_le_mul h3 (Nat.le_refl _)))
    h4) h5

end LeanBCH.Cost

namespace LeanBCH.VM
open LeanBCH.Cost LeanBCH.Tx LeanBCH.Crypto

/-! ### Axis B — the `stepMeterExt`-pinned aggregate is monotone
    `stepOpCost` bakes the CONSENSUS pins (100 / 26000 / 64 / 1 / 1); the coefficients are
    literals, so `omega` handles the monotonicity directly. -/

/-- The `stepMeterExt` op-cost aggregate is monotone in the metrics. -/
theorem stepOpCost_mono {m m' : Metrics} (h : m ≤ m') : stepOpCost m ≤ stepOpCost m' := by
  simp only [Metrics.le_def] at h
  simp only [stepOpCost]
  omega

/-! ### Axis B — one metered step never decreases accumulated cost
    `stepMeterExt` sets `metrics := s.metrics + kappa s + Δ` BEFORE the error/limit branches, and
    every branch returns that state or a `setErr` of it (metrics-preserving). So the result's
    metrics are `s.metrics + (something ≥ 0)`, hence `≥ s.metrics` — for whatever `Δ` the sig /
    introspection corrections contribute. -/

/-- The post-step limit gate only ever sets `error`, so it preserves accumulated metrics. A one-line
    proof over the plain variable `t` (no `let`s, no huge body) — precisely why `enforceStepLimits`
    was factored out of `stepMeterExt`. -/
theorem enforceStepLimits_metrics (t : State) : (enforceStepLimits t).metrics = t.metrics := by
  unfold enforceStepLimits
  split
  · rfl
  · split
    · rfl
    · split
      · rfl
      · split
        · rfl
        · rfl

/-- A metered step's accumulated metrics dominate the pre-state's, componentwise. `stepMeterExt`
    writes `metrics := s.metrics + kappa s + Δ` and then applies `enforceStepLimits` (metrics-
    preserving), so the result's metrics are `s.metrics + kappa s + Δ ≥ s.metrics` — for whatever
    correction `Δ` the sig / introspection layer contributes. -/
theorem stepMeterExt_metrics_ge (p : Tx.Program) (crypto : Secp256k1) (s : State) :
    s.metrics ≤ (stepMeterExt p crypto s).metrics := by
  unfold stepMeterExt
  rw [enforceStepLimits_metrics]
  exact Metrics.le_trans (Metrics.le_add_right _ _) (Metrics.le_add_right _ _)

/-- The `stepOpCost` aggregate never decreases across one metered step. -/
theorem stepMeterExt_opCost_ge (p : Tx.Program) (crypto : Secp256k1) (s : State) :
    stepOpCost s.metrics ≤ stepOpCost (stepMeterExt p crypto s).metrics :=
  stepOpCost_mono (stepMeterExt_metrics_ge p crypto s)

/-! ### Axis D — an errored state is a fixpoint of the run loop ("reject is final") -/

/-- Once `error` is set, `runExt` returns the state unchanged: no state ever un-rejects. -/
theorem runExt_error_fix (p : Tx.Program) (crypto : Secp256k1) (f : Nat) (s : State)
    (h : s.error.isSome = true) : runExt p crypto f s = s := by
  cases f with
  | zero => rfl
  | succ f => simp [runExt, h]

/-! ### Axis B — the whole metered run never decreases accumulated cost
    Fuel induction: the error and finished branches return the state (cost unchanged); the step
    branch composes `stepMeterExt_metrics_ge` with the IH; the frame-return branch only rewrites
    `instrs`/`ip`/`ctrl` (metrics untouched). -/

/-- Across an entire metered run, accumulated metrics only grow. -/
theorem runExt_metrics_ge (p : Tx.Program) (crypto : Secp256k1) :
    ∀ (f : Nat) (s : State), s.metrics ≤ (runExt p crypto f s).metrics
  | 0,     s => Metrics.le_refl _
  | f + 1, s => by
      -- `runExt`'s body has no lets, so `unfold` exposes the `error` / `ip<size` ifs + the `ctrl`
      -- match; `split` is one-level, so nest explicitly (then-branch first at each level).
      unfold runExt
      split
      · exact Metrics.le_refl _                                            -- error → s (unchanged)
      · split
        · exact Metrics.le_trans (stepMeterExt_metrics_ge p crypto s)
                  (runExt_metrics_ge p crypto f _)                         -- ip<size → step then IH
        · split
          · -- frame return: name the pattern vars and hand the IH the EXPLICIT frame state, so its
            -- `?m` is pinned from the state (not mis-unified `:= s` off the `?m.metrics ≡ s.metrics`
            -- LHS). `{frame}.metrics` is literally `s.metrics`, so the IH closes the goal by defeq.
            rename_i retInstrs retIp rest _heq   -- 4th: the `s.ctrl = frame …` match equation
            exact runExt_metrics_ge p crypto f { s with instrs := retInstrs, ip := retIp, ctrl := rest }
          · exact Metrics.le_refl _                                        -- finished → s (unchanged)

/-- The `stepOpCost` aggregate never decreases across an entire metered run — the monotone
    backbone of abort soundness (once over budget, always over budget). -/
theorem runExt_opCost_ge (p : Tx.Program) (crypto : Secp256k1) (f : Nat) (s : State) :
    stepOpCost s.metrics ≤ stepOpCost (runExt p crypto f s).metrics :=
  stepOpCost_mono (runExt_metrics_ge p crypto f s)

/-! ### Increment 2 — Axis A (resource safety), the EASY half: slot/depth well-formedness
    The design's `WF` predicate (`SELF_HARDENING.md §3.A`) has three limits: item-length
    (`≤ maxItemLen`), memory slots (`stack+alt+funcs ≤ maxMemorySlots`) and control depth
    (`ctrl ≤ maxCtrlDepth`). The item-length conjunct is the DEEP guard-completeness proof over the
    frozen `stepInstr` (Increment 3); here we DEFINE the full predicate and discharge the two limit
    conjuncts — they fall straight out of `enforceStepLimits`'s own post-step `setErr` guards. -/

/-- Item-length well-formedness (the DEEP half — Increment 3): every stack/alt item is within the
    10 000-byte cap `maxItemLen`. Defined now; its preservation is the mechanized guard-completeness
    proof that would have caught the audit's CAT-overflow. -/
def WFlen (s : State) : Prop :=
  (∀ i ∈ s.stack, i.length ≤ maxItemLen) ∧ (∀ i ∈ s.alt, i.length ≤ maxItemLen)

/-- Slot/depth well-formedness (the EASY half — this increment): the memory-slot count
    (`stack + alt + functionTable`, libauth's `functionCount` term) and the control-stack depth are
    within their consensus caps. Exactly the two conjuncts `enforceStepLimits` enforces by `setErr`. -/
def WFmem (s : State) : Prop :=
  s.stack.length + s.alt.length + s.functionTable.length ≤ maxMemorySlots ∧
  s.ctrl.length ≤ maxCtrlDepth

/-- Full Axis-A resource-safety well-formedness: item-length AND slot/depth. -/
def WF (s : State) : Prop := WFlen s ∧ WFmem s

/-- `setErr` writes `error := some e`, so the result's `error.isSome` is `true` (definitional). The
    reusable "this branch aborted" leaf for the gate case-splits below. -/
theorem setErr_isSome (s : State) (e : Err) : (s.setErr e).error.isSome = true := rfl

/-- The post-step gate ESTABLISHES slot/depth well-formedness on every non-errored output: for any
    `t`, either `enforceStepLimits t` is `WFmem` or it has errored. **Unconditional** (needs no `WFmem`
    hypothesis on the input) — the gate's own `setErr` guards are what force `WFmem` in the
    fall-through branch. One `split` per `if` (this Lean's `split` is one-level); the errored leaves
    close by `setErr_isSome`/the `error` hypothesis, the fall-through by the two negated guards. -/
theorem enforceStepLimits_WFmem (t : State) :
    WFmem (enforceStepLimits t) ∨ (enforceStepLimits t).error.isSome = true := by
  unfold enforceStepLimits
  split
  · exact Or.inr (by assumption)                       -- error already set → still set
  · split
    · exact Or.inr (setErr_isSome _ _)                 -- over-budget abort
    · split
      · exact Or.inr (setErr_isSome _ _)               -- ctrl-depth abort
      · split
        · exact Or.inr (setErr_isSome _ _)             -- memory-slot abort
        · exact Or.inl (by unfold WFmem; omega)        -- fall-through: both guards passed

/-- One metered step lands in a `WFmem` state or an errored one — because `stepMeterExt` ends in
    `enforceStepLimits`. `unfold` keeps `kappa`/`widthAt`/the sig corrections opaque (do NOT
    `simp only [stepMeterExt]` — it whnf's the huge body and blows the 200 000-heartbeat budget). -/
theorem stepMeterExt_WFmem (p : Tx.Program) (crypto : Secp256k1) (s : State) :
    WFmem (stepMeterExt p crypto s) ∨ (stepMeterExt p crypto s).error.isSome = true := by
  unfold stepMeterExt
  exact enforceStepLimits_WFmem _

/-- Across a whole metered run, slot/depth well-formedness is preserved-or-errored: from a `WFmem`
    start, every reachable state is `WFmem` or has aborted. Fuel induction mirroring
    `runExt_metrics_ge`: the error/finished branches return the (WF) state; the step branch threads
    `stepMeterExt_WFmem` (falling to `runExt_error_fix` when the step itself errors); the
    frame-return branch only SHRINKS `ctrl` and leaves `stack`/`alt`/`functionTable` untouched, so
    `WFmem` is preserved into the recursive call. -/
theorem runExt_WFmem (p : Tx.Program) (crypto : Secp256k1) :
    ∀ (f : Nat) (s : State), WFmem s →
      WFmem (runExt p crypto f s) ∨ (runExt p crypto f s).error.isSome = true
  | 0,     s, hwf => Or.inl hwf
  | f + 1, s, hwf => by
      unfold runExt
      split
      · exact Or.inr (by assumption)                                   -- error → s (WF hyp unused)
      · split
        · -- ip < size: metered step, then recurse on the stepped state
          rcases stepMeterExt_WFmem p crypto s with hstep | herr
          · exact runExt_WFmem p crypto f _ hstep
          · rw [runExt_error_fix p crypto f _ herr]; exact Or.inr herr -- stepped errored, run is fixed
        · split
          · -- frame return: pop `Ctrl.frame retInstrs retIp`, resume caller with `ctrl := rest`
            rename_i retInstrs retIp rest heq        -- heq : s.ctrl = Ctrl.frame retInstrs retIp :: rest
            refine runExt_WFmem p crypto f
              { s with instrs := retInstrs, ip := retIp, ctrl := rest } ?_
            unfold WFmem at hwf ⊢
            have hlen : s.ctrl.length = rest.length + 1 := by rw [heq, List.length_cons]
            refine ⟨hwf.1, ?_⟩                        -- stack/alt/funcs untouched ⇒ slots unchanged
            show rest.length ≤ maxCtrlDepth
            omega                                     -- rest.length < s.ctrl.length ≤ maxCtrlDepth
          · exact Or.inl hwf                                            -- finished → s (WF hyp)

/-! ### Increment 4 — Axis B headline: the deductive FITS-CONSENSUS cost certificate
    (`SELF_HARDENING.md §3.B`). `enforceStepLimits` sets `error` the instant `stepOpCost metrics >
    budget`; error is sticky (`runExt_error_fix`, Increment 1/Axis D) and cost is monotone
    (`runExt_opCost_ge`, Increment 1/Axis B). Consequence: a metered run that ACCEPTS (ends
    non-errored) never exceeded its budget — and, with monotonicity, not at any intermediate step
    either. Acceptance is a machine-checked *certificate of bounded work*: the mid-run abort cannot
    be bypassed by a later under-billed / non-monotone step. This is what upgrades a
    `verifyInput`-based "this input fits the per-input op-cost density budget" claim from
    executable-checked to theorem-backed — the property a real-oracle fits-BCH verifier and the
    CHIP cost-authority role both rest on. -/

/-- The post-step gate, whenever it OUTPUTS a non-errored state, has certified `stepOpCost ≤ budget`:
    the only non-errored exit is the fall-through `else`, reached only once the budget guard
    `stepOpCost s'.metrics > s'.budget` was FALSE. `∨` form (errored OR within budget) so it threads
    through the run induction with no unfoldable premise. Mirrors `enforceStepLimits_WFmem`. -/
theorem enforceStepLimits_bounded (t : State) :
    (enforceStepLimits t).error.isSome = true ∨
      stepOpCost (enforceStepLimits t).metrics ≤ (enforceStepLimits t).budget := by
  unfold enforceStepLimits
  split
  · exact Or.inl (by assumption)                       -- error already set
  · split
    · exact Or.inl (setErr_isSome _ _)                 -- budget abort
    · split
      · exact Or.inl (setErr_isSome _ _)               -- ctrl-depth abort
      · split
        · exact Or.inl (setErr_isSome _ _)             -- memory-slot abort
        · exact Or.inr (by omega)                      -- fall-through: budget guard was false

/-- One metered step is errored OR has certified `stepOpCost ≤ budget` (it ends in the gate). -/
theorem stepMeterExt_bounded (p : Tx.Program) (crypto : Secp256k1) (s : State) :
    (stepMeterExt p crypto s).error.isSome = true ∨
      stepOpCost (stepMeterExt p crypto s).metrics ≤ (stepMeterExt p crypto s).budget := by
  unfold stepMeterExt
  exact enforceStepLimits_bounded _

/-- **Bounded-work backbone.** A metered run STARTED within budget is errored OR ENDS within budget.
    Fuel induction (mirrors `runExt_metrics_ge`): error/finished branches carry the hypothesis
    unchanged; the frame-return branch leaves `metrics`/`budget` untouched (so the hypothesis still
    holds); the step branch takes `stepMeterExt_bounded` — if the step errored, `runExt_error_fix`
    fixes the whole run to that errored state (left disjunct); else the step is within budget and
    feeds the IH. -/
theorem runExt_bounded (p : Tx.Program) (crypto : Secp256k1) :
    ∀ (f : Nat) (s : State), stepOpCost s.metrics ≤ s.budget →
      (runExt p crypto f s).error.isSome = true ∨
        stepOpCost (runExt p crypto f s).metrics ≤ (runExt p crypto f s).budget
  | 0,     s, hin => Or.inr hin
  | f + 1, s, hin => by
      unfold runExt
      split
      · exact Or.inl (by assumption)                                   -- error → s
      · split
        · rcases stepMeterExt_bounded p crypto s with herr | hb        -- ip < size: step then recurse
          · rw [runExt_error_fix p crypto f _ herr]; exact Or.inl herr -- step errored ⇒ run fixed
          · exact runExt_bounded p crypto f (stepMeterExt p crypto s) hb
        · split
          · rename_i retInstrs retIp rest _heq                         -- frame return: metrics/budget kept
            exact runExt_bounded p crypto f
              { s with instrs := retInstrs, ip := retIp, ctrl := rest } hin
          · exact Or.inr hin                                           -- finished → s

/-- A freshly-loaded script state has zero accumulated metrics (both `parse` branches default). -/
theorem loadFrom_metrics (stk : Stack) (bs : Bytes) : (loadFrom stk bs).metrics = {} := by
  unfold loadFrom; split <;> rfl

/-- A metered `runScript` is errored OR ends within the budget it was given: the fresh `loadFrom`
    starts at zero cost (`stepOpCost {} = 0 ≤ budget`), discharging `runExt_bounded`'s hypothesis. -/
theorem runScript_bounded (crypto : Secp256k1) (p : Tx.Program) (stk : Stack) (bs : Bytes)
    (budget : Nat) :
    (runScript crypto p stk bs budget).error.isSome = true ∨
      stepOpCost (runScript crypto p stk bs budget).metrics
        ≤ (runScript crypto p stk bs budget).budget := by
  unfold runScript
  apply runExt_bounded
  show stepOpCost (loadFrom stk bs).metrics ≤ budget
  rw [loadFrom_metrics]
  exact Nat.zero_le _

/-- The accept-side post-check's op-cost (`operationCost BCH_2026_05_CONSENSUS`) IS the per-step
    meter aggregate `stepOpCost` — both bake the consensus pins 100 / 26000 / 64 / 1 / 1. This
    bridges the density-budget certificate to the mid-run abort's units. -/
theorem operationCost_consensus_eq (m : Cost.Metrics) :
    operationCost BCH_2026_05_CONSENSUS m = stepOpCost m := by
  simp only [operationCost, stepOpCost, BCH_2026_05_CONSENSUS, BCH_2026_05]

/-- **The fits-consensus certificate.** If `verifyInput` ACCEPTS, the input's accounted consensus
    op-cost (unlocking + locking, `operationCost BCH_2026_05_CONSENSUS`) is ≤ the per-input density
    budget `opBudget |unlocking|`. Extracted from `verifyInput`'s own final `&&` post-check: the
    non-P2SH branch asserts `cost12 ≤ budget` directly; the P2SH branch asserts
    `cost12 + redeemCost ≤ budget`, whence `cost12 ≤ budget` (`redeemCost ≥ 0`, `omega`). So
    acceptance is a machine-checked "this input fits the op-cost wall" certificate — the exact claim
    the verifier.cash BCH-native track and the CHIP cost-authority role need theorem-backed. -/
theorem verifyInput_cost_within_budget (crypto : Secp256k1) (p : Tx.Program)
    (inp : Tx.Input) (src : Tx.Output)
    (hi : p.currentInput = some inp) (ho : p.currentSourceOutput = some src)
    (h : verifyInput crypto p = true) :
    operationCost BCH_2026_05_CONSENSUS
        (runScript crypto p [] inp.unlockingBytecode (opBudget inp.unlockingBytecode.length)).metrics
      + operationCost BCH_2026_05_CONSENSUS
        (runScript crypto p
          (runScript crypto p [] inp.unlockingBytecode (opBudget inp.unlockingBytecode.length)).stack
          src.lockingBytecode (opBudget inp.unlockingBytecode.length)).metrics
      ≤ opBudget inp.unlockingBytecode.length := by
  simp only [verifyInput, hi, ho] at h
  split at h; · simp at h                            -- reject: bytecode length limit
  split at h; · simp at h                            -- reject: not push-only
  split at h; · simp at h                            -- reject: unlocking run errored
  split at h; · simp at h                            -- reject: locking run errored
  split at h
  · -- P2SH: match on the redeem item, then the joint (cost12 + redeemCost ≤ budget) post-check
    split at h
    · split at h; · simp at h                        -- reject: redeem length limit
      simp only [Bool.and_eq_true, decide_eq_true_eq] at h
      omega
    · simp at h                                      -- reject: empty stack under P2SH
  · -- non-P2SH: the (cost12 ≤ budget) post-check is a direct conjunct
    simp only [Bool.and_eq_true, decide_eq_true_eq] at h
    omega


/-! ### Increment 3 — Axis A (resource safety), the DEEP half: item-length `WFlen` preservation
    The guard-completeness proof `SELF_HARDENING.md §3.A` promised: the item-length conjunct of `WF`
    is preserved-or-errored across the metered run. Mirrors the Increment-2 `WFmem` chain, but the
    item-length cap is NOT a single `enforceStepLimits` gate — it is enforced op-by-op inside the
    frozen `stepInstrExt` (the CAT / arithmetic / shift / NUM2BIN / introspection guards). So the run
    reduction is DECOUPLED from the per-step guard audit: the metering wrapper (`stepMeterExt`) and the
    run loop (`runExt`) preserve `WFlen` GIVEN a per-step `step1Ext`-level guarantee `Hstep`, and the
    per-step obligation is discharged group-by-group with the reusable `WFlen` primitives below. The
    run machinery is thus complete and re-usable; the per-step lemma is parametrized so it can be
    strengthened opcode-class by opcode-class without touching the induction. -/

/-- The post-step gate preserves the main stack: every branch either returns the state or `setErr`s
    it (which rewrites only `error`). Companion to `enforceStepLimits_metrics`. -/
theorem enforceStepLimits_stack (t : State) : (enforceStepLimits t).stack = t.stack := by
  unfold enforceStepLimits
  split
  · rfl
  · split
    · rfl
    · split
      · rfl
      · split
        · rfl
        · rfl

/-- The post-step gate preserves the alt stack (same reasoning as `enforceStepLimits_stack`). -/
theorem enforceStepLimits_alt (t : State) : (enforceStepLimits t).alt = t.alt := by
  unfold enforceStepLimits
  split
  · rfl
  · split
    · rfl
    · split
      · rfl
      · split
        · rfl
        · rfl

/-- The post-step gate preserves item-length well-formedness UNCONDITIONALLY: it only ever `setErr`s
    or returns the state, and `WFlen` reads only `stack`/`alt` — both fixed by the two lemmas above. -/
theorem enforceStepLimits_WFlen (t : State) (h : WFlen t) : WFlen (enforceStepLimits t) := by
  unfold WFlen at h ⊢
  rw [enforceStepLimits_stack, enforceStepLimits_alt]
  exact h

/-- The post-step gate is error-sticky: a pre-set error survives it (the `s'.error.isSome` guard is
    the gate's FIRST branch, returning the state as-is). The `WFlen`-side analogue of Axis D. -/
theorem enforceStepLimits_preserves_error (t : State) (h : t.error.isSome = true) :
    (enforceStepLimits t).error.isSome = true := by
  unfold enforceStepLimits
  split
  · exact h
  · exact absurd h (by assumption)

/-- **The metering bridge.** One metered step preserves-or-errors `WFlen` AS SOON AS its pure core
    `step1Ext` does. `stepMeterExt` wraps `step1Ext` in a metrics-only `{· with metrics := …}` update
    (`stack`/`alt`/`error` untouched) then `enforceStepLimits`; the `WFlen` disjunct threads through
    `enforceStepLimits_WFlen` and the error disjunct through `enforceStepLimits_preserves_error`
    (both after the metrics update, which is transparent to `WFlen`/`error` — closed here by defeq
    through the `stepMeterExt` `let`-chain, so the huge `kappa`/sig-correction bodies never unfold).
    This is exactly what reduces the DEEP per-step audit from `stepMeterExt` down to `step1Ext`. -/
theorem stepMeterExt_WFlen_of (p : Tx.Program) (crypto : Secp256k1) (s : State)
    (h : WFlen (step1Ext p crypto s) ∨ (step1Ext p crypto s).error.isSome = true) :
    WFlen (stepMeterExt p crypto s) ∨ (stepMeterExt p crypto s).error.isSome = true := by
  rcases h with hwf | herr
  · left
    unfold stepMeterExt
    apply enforceStepLimits_WFlen
    exact hwf
  · right
    unfold stepMeterExt
    apply enforceStepLimits_preserves_error
    exact herr

/-- **The `WFlen` run reduction.** From any `step1Ext`-level guard-completeness guarantee `Hstep`
    (item-length preserved-or-errored by every pure step), a whole metered run preserves-or-errors
    `WFlen`. Fuel induction mirroring `runExt_WFmem`: error/finished branches return the state; the
    step branch threads `stepMeterExt_WFlen_of ∘ Hstep`, falling to `runExt_error_fix` when the step
    itself errors; the frame-return branch only rewrites `instrs`/`ip`/`ctrl` (stack/alt fixed, so
    `WFlen` passes straight into the recursive call). `Hstep` is the ONLY remaining obligation. -/
theorem runExt_WFlen (p : Tx.Program) (crypto : Secp256k1)
    (Hstep : ∀ (s : State), WFlen s →
      WFlen (step1Ext p crypto s) ∨ (step1Ext p crypto s).error.isSome = true) :
    ∀ (f : Nat) (s : State), WFlen s →
      WFlen (runExt p crypto f s) ∨ (runExt p crypto f s).error.isSome = true
  | 0,     s, hwf => Or.inl hwf
  | f + 1, s, hwf => by
      unfold runExt
      split
      · exact Or.inr (by assumption)                                   -- error → s
      · split
        · rcases stepMeterExt_WFlen_of p crypto s (Hstep s hwf) with hstep | herr
          · exact runExt_WFlen p crypto Hstep f _ hstep               -- ip<size: step then IH
          · rw [runExt_error_fix p crypto f _ herr]; exact Or.inr herr -- step errored ⇒ run fixed
        · split
          · rename_i retInstrs retIp rest heq                          -- frame return: stack/alt kept
            refine runExt_WFlen p crypto Hstep f
              { s with instrs := retInstrs, ip := retIp, ctrl := rest } ?_
            unfold WFlen at hwf ⊢
            exact hwf
          · exact Or.inl hwf                                           -- finished → s

/-- **The full Axis-A resource-safety headline** (`WF = WFlen ∧ WFmem`). Given the `WFlen` per-step
    guarantee `Hstep`, a metered run from a `WF` start stays `WF` or aborts — combining this
    increment's `runExt_WFlen` with Increment 2's (unconditional) `runExt_WFmem`. Once `Hstep` is
    discharged for the full opcode dispatch, this is the closed statement that every reachable VM
    state respects the three consensus resource caps or has already rejected. -/
theorem runExt_WF (p : Tx.Program) (crypto : Secp256k1)
    (Hstep : ∀ (s : State), WFlen s →
      WFlen (step1Ext p crypto s) ∨ (step1Ext p crypto s).error.isSome = true)
    (f : Nat) (s : State) (hwf : WF s) :
    WF (runExt p crypto f s) ∨ (runExt p crypto f s).error.isSome = true := by
  rcases hwf with ⟨hlen, hmem⟩
  rcases runExt_WFlen p crypto Hstep f s hlen with hl | he
  · rcases runExt_WFmem p crypto f s hmem with hm | he2
    · exact Or.inl ⟨hl, hm⟩
    · exact Or.inr he2
  · exact Or.inr he

/-! ### Per-step `WFlen` primitives — the reusable toolkit for discharging `Hstep` group-by-group
    `WFlen` reads only `stack`/`alt`, so each `stepInstrExt` arm is one of: an existing-item
    rearrangement (`WFlen_of_subset`), an `ip`-only bump (`WFlen_advance`), a length-bounded push
    (`WFlen_push`), a length-checked introspection push (`introspectIndexed_WFlen_checked`/`_bounded`),
    or a `setErr` (the error disjunct). These are the leaves the parent stitches into the full
    `step1Ext_WFlen` opcode by opcode. -/

/-- OP_INVERT is a byte-wise `xor 0xff` map, so it preserves item length exactly — the INVERT arm
    pushes an item no longer than the (≤`maxItemLen`) operand it consumed. -/
theorem opInvert_length (x : Bytes) : (opInvert x).length = x.length := by
  unfold opInvert
  rw [List.length_map]

/-- `ofNum 0 = []` fits the cap — the LSHIFTNUM `value = 0` short-circuit result. -/
theorem ofNum_zero_length : (ofNum 0).length ≤ maxItemLen := by decide

/-- `ofNum (-1) = [0x81]` fits the cap — the RSHIFTNUM over-shift collapse-to-`-1` result. -/
theorem ofNum_negOne_length : (ofNum (-1)).length ≤ maxItemLen := by decide

/-- Any state whose stack/alt items are each drawn (as members) from a `WFlen` state's stack/alt is
    itself `WFlen`. The workhorse for the pop / relocate / duplicate arms (DROP/DUP/SWAP/ROT/NIP/…,
    the DEFINE/INVOKE stack tails): every resulting item is an EXISTING ≤`maxItemLen` item. -/
theorem WFlen_of_subset (s s' : State)
    (hstk : ∀ x ∈ s'.stack, x ∈ s.stack) (halt : ∀ x ∈ s'.alt, x ∈ s.alt)
    (h : WFlen s) : WFlen s' := by
  unfold WFlen at h ⊢
  exact ⟨fun x hx => h.1 x (hstk x hx), fun x hx => h.2 x (halt x hx)⟩

/-- `advance` only bumps `ip`; stack/alt are untouched, so `WFlen` is preserved definitionally. -/
theorem WFlen_advance (s : State) (h : WFlen s) : WFlen s.advance := h

/-- Pushing one within-cap item onto a `WFlen` stack keeps the state `WFlen` (the guarded-result
    and bounded-nullary-introspection arms, once their pushed item is shown ≤`maxItemLen`). -/
theorem WFlen_push (s : State) (b : Bytes) (h : WFlen s) (hb : b.length ≤ maxItemLen) :
    WFlen (s.push b) := by
  unfold WFlen at h ⊢
  refine ⟨fun x hx => ?_, h.2⟩
  rcases List.mem_cons.mp hx with hh | hh
  · cases hh; exact hb
  · exact h.1 x hh

/-- The length-CHECKED introspection shell preserves-or-errors `WFlen` with NO side condition on the
    looked-up bytes: `introspectIndexed … checkLen := true` either `setErr`s (negative/out-of-range
    index, or the `bytes.length > maxItemLen` guard fires) or pushes `bytes :: rest` with the guard
    having certified `bytes.length ≤ maxItemLen`. Covers OP_UTXOBYTECODE / OP_INPUTBYTECODE /
    OP_OUTPUTBYTECODE and the token-commitment variants — the ops libauth marks `pushToStackChecked`. -/
theorem introspectIndexed_WFlen_checked (base : State) (rest : Stack) (i : Int)
    (lookup : Nat → Option Bytes)
    (hbase : WFlen base) (hrest : ∀ x ∈ rest, x.length ≤ maxItemLen) :
    WFlen (introspectIndexed base rest i lookup true) ∨
      (introspectIndexed base rest i lookup true).error.isSome = true := by
  unfold introspectIndexed
  split
  · exact Or.inr rfl                                   -- i < 0 → invalidTxIndex
  · split
    · rename_i bytes heq
      split
      · exact Or.inr rfl                               -- oversize push → itemTooLarge
      · rename_i hguard
        left
        unfold WFlen
        refine ⟨?_, hbase.2⟩
        intro x hx
        rcases List.mem_cons.mp hx with h | h
        · subst h
          simp only [Bool.true_and, decide_eq_true_eq] at hguard
          omega
        · exact hrest x h
    · exact Or.inr rfl                                 -- lookup none → invalidTxIndex

/-- The introspection shell preserves-or-errors `WFlen` for EITHER `checkLen` under a static bound on
    the lookup (`hlk` — every looked-up payload fits the cap). This is the form the UNCHECKED numeric
    introspection ops (OP_UTXOVALUE / OP_OUTPOINTTXHASH / token category/amount, libauth's plain
    `pushToStack`) need: their payloads are consensus-bounded by transaction well-formedness, which
    the model's unbounded `Program` fields do NOT witness, so `hlk` makes that assumption EXPLICIT. -/
theorem introspectIndexed_WFlen_bounded (base : State) (rest : Stack) (i : Int)
    (lookup : Nat → Option Bytes) (checkLen : Bool)
    (hbase : WFlen base) (hrest : ∀ x ∈ rest, x.length ≤ maxItemLen)
    (hlk : ∀ n b, lookup n = some b → b.length ≤ maxItemLen) :
    WFlen (introspectIndexed base rest i lookup checkLen) ∨
      (introspectIndexed base rest i lookup checkLen).error.isSome = true := by
  unfold introspectIndexed
  split
  · exact Or.inr rfl
  · split
    · rename_i bytes heq
      split
      · exact Or.inr rfl
      · left
        unfold WFlen
        refine ⟨?_, hbase.2⟩
        intro x hx
        rcases List.mem_cons.mp hx with h | h
        · cases h; exact hlk _ _ heq
        · exact hrest x h
    · exact Or.inr rfl

/-! ### Increment 5 — Axis C: termination & totality (`SELF_HARDENING.md §3.C`)
    The keystone interpreter is FUEL-DRIVEN, so it is a plain total `def` (never a diverging/untrusted
    loop) — Lean's own termination checker accepts it, making TOTALITY true by construction. We (1) make that
    totality machine-checkable, (2) prove the rigorous stabilization core (an errored/finished state
    is a run fixpoint, fuel is additive, and extra fuel never un-does a converged result), and (3)
    prove the strongest honest termination MILESTONE: once the fuel-indexed run stops changing it has
    converged permanently. Full fuel-SUFFICIENCY (`instrs.size + evalFuelSlack` always reaches a
    fixpoint on a within-budget run) needs a decreasing measure and is scoped out below. -/

/-- **Totality-by-construction (`stepMeterExt`).** A total function: it elaborated as a plain total
    `def` with no unproven holes, so it returns on every input. The `∃`-statement is trivially true —
    that is exactly the point: it documents that the metered step cannot diverge or get stuck. -/
theorem stepMeterExt_total (p : Tx.Program) (crypto : Secp256k1) (s : State) :
    ∃ s', stepMeterExt p crypto s = s' := ⟨_, rfl⟩

/-- **Totality-by-construction (`runExt`).** The fuel-driven run loop is total for every fuel/state:
    fuel structurally decreases, so Lean accepts it as a total `def` (not a diverging loop). Contrast a
    fuel-free interpreter, whose loop can diverge and would need a divergence marker (untrusted) — this
    one cannot. -/
theorem runExt_total (p : Tx.Program) (crypto : Secp256k1) (f : Nat) (s : State) :
    ∃ s', runExt p crypto f s = s' := ⟨_, rfl⟩

/-- **Totality-by-construction (`runScript`).** The per-script entry point is total. -/
theorem runScript_total (crypto : Secp256k1) (p : Tx.Program) (stk : Stack) (bs : Bytes)
    (budget : Nat) : ∃ s', runScript crypto p stk bs budget = s' := ⟨_, rfl⟩

/-- **Totality-by-construction (`verifyInput`).** The consensus predicate is a total `Bool` function
    — it always returns a definite accept/reject, never diverges. -/
theorem verifyInput_total (crypto : Secp256k1) (p : Tx.Program) :
    ∃ b, verifyInput crypto p = b := ⟨_, rfl⟩

/-! ### Stabilization: the run loop has a fixpoint that extra fuel cannot escape -/

/-- A `runExt` fixpoint (a "halted" configuration): the state has ERRORED, or its instruction pointer
    is exhausted (`instrs.size ≤ ip`) with NO return frame left on the control stack to pop. These are
    exactly the two `runExt` branches that return the input state unchanged for `f+1` fuel. -/
def Halted (s : State) : Prop :=
  s.error.isSome = true ∨
    (s.instrs.size ≤ s.ip ∧
      ∀ (ri : Array Instr) (rp : Nat) (rest : List Ctrl), s.ctrl ≠ Ctrl.frame ri rp :: rest)

/-- A halted state is a fixpoint of the run loop for ANY fuel: `runExt … s = s`. Errored states go
    through `runExt_error_fix`; finished states (ip exhausted, no frame) hit the `_ => s` branch. The
    unification of the two "reject is final" (Axis D) and "accept is stable" facts into one fixpoint. -/
theorem runExt_fixed (p : Tx.Program) (crypto : Secp256k1) (f : Nat) (s : State)
    (h : Halted s) : runExt p crypto f s = s := by
  rcases h with herr | ⟨hip, hctrl⟩
  · exact runExt_error_fix p crypto f s herr
  · cases f with
    | zero => rfl
    | succ f =>
      unfold runExt
      split
      · rfl                                   -- error branch returns s
      · split
        · omega                               -- ip < size contradicts `instrs.size ≤ ip`
        · split
          · rename_i ri rp rest heq           -- frame return contradicts the no-frame hypothesis
            exact absurd heq (hctrl ri rp rest)
          · rfl                               -- finished: `_ => s`

/-- **Fuel is additive.** Running `a + b` fuel equals running `b` fuel on the result of running `a`
    fuel — the run loop composes, so fuel splits at any point. Structural induction on `a`: the error
    and finished branches use the fixpoint (`runExt_error_fix` / `runExt_fixed`) to absorb the trailing
    `b` fuel; the step and frame-return branches recurse on the shared successor state via the IH. -/
theorem runExt_add (p : Tx.Program) (crypto : Secp256k1) :
    ∀ (a b : Nat) (s : State),
      runExt p crypto (a + b) s = runExt p crypto b (runExt p crypto a s)
  | 0,     b, s => by rw [Nat.zero_add]; rfl
  | a + 1, b, s => by
      rw [show a + 1 + b = (a + b) + 1 from by omega]
      -- one-step unfoldings of the two successor occurrences (each defeq to its `runExt` body); this
      -- avoids `unfold runExt`, which would also rewrite the outer `runExt b` into a `match b`.
      have hL : runExt p crypto ((a + b) + 1) s =
          (if s.error.isSome then s
           else if s.ip < s.instrs.size then runExt p crypto (a + b) (stepMeterExt p crypto s)
           else match s.ctrl with
             | Ctrl.frame ri rp :: rest =>
                 runExt p crypto (a + b) { s with instrs := ri, ip := rp, ctrl := rest }
             | _ => s) := rfl
      have hR : runExt p crypto (a + 1) s =
          (if s.error.isSome then s
           else if s.ip < s.instrs.size then runExt p crypto a (stepMeterExt p crypto s)
           else match s.ctrl with
             | Ctrl.frame ri rp :: rest =>
                 runExt p crypto a { s with instrs := ri, ip := rp, ctrl := rest }
             | _ => s) := rfl
      rw [hL, hR]
      by_cases herr : s.error.isSome = true
      · rw [if_pos herr, if_pos herr, runExt_error_fix p crypto b s herr]
      · rw [if_neg herr, if_neg herr]
        by_cases hip : s.ip < s.instrs.size
        · rw [if_pos hip, if_pos hip]
          exact runExt_add p crypto a b (stepMeterExt p crypto s)
        · rw [if_neg hip, if_neg hip]
          -- generalize `s.ctrl` so BOTH `match`es reduce on the same discriminant
          generalize hc : s.ctrl = c
          match c with
          | Ctrl.frame ri rp :: rest =>
              exact runExt_add p crypto a b { s with instrs := ri, ip := rp, ctrl := rest }
          | [] =>
              exact (runExt_fixed p crypto b s (Or.inr ⟨by omega, by simp [hc]⟩)).symm
          | Ctrl.cond cb :: cs =>
              exact (runExt_fixed p crypto b s (Or.inr ⟨by omega, by simp [hc]⟩)).symm
          | Ctrl.mark mn :: cs =>
              exact (runExt_fixed p crypto b s (Or.inr ⟨by omega, by simp [hc]⟩)).symm

/-- **Extra fuel is inert once halted (additive form).** If `a` fuel already reached a halted
    (errored/finished) result, any additional `c` fuel changes nothing: `runExt (a+c) = runExt a`.
    Fuel-monotonicity's core — more fuel never un-does a reached verdict. -/
theorem runExt_fuel_stable (p : Tx.Program) (crypto : Secp256k1) (a c : Nat) (s : State)
    (h : Halted (runExt p crypto a s)) :
    runExt p crypto (a + c) s = runExt p crypto a s := by
  rw [runExt_add p crypto a c s]
  exact runExt_fixed p crypto c (runExt p crypto a s) h

/-- **Fuel-monotonicity (`≤` form).** If a small budget `a` already halted the run, then every larger
    fuel `b ≥ a` yields the SAME state. So the verdict is fuel-monotone: giving the interpreter more
    fuel can never flip a settled accept/reject — the property that lets `runScript`'s fixed fuel
    formula be an implementation detail rather than a soundness parameter. -/
theorem runExt_fuel_mono (p : Tx.Program) (crypto : Secp256k1) {a b : Nat} (s : State)
    (hab : a ≤ b) (h : Halted (runExt p crypto a s)) :
    runExt p crypto b s = runExt p crypto a s := by
  obtain ⟨c, rfl⟩ := Nat.le.dest hab
  exact runExt_fuel_stable p crypto a c s h

/-- If a state is a fixpoint of ONE fuel unit, it is a fixpoint of ALL fuel — even without knowing it
    is `Halted` (a genuine no-op step would qualify too). Induction on `n` via `runExt_add`: peel one
    unit off the front and collapse it with the hypothesis. The measure-free half of stabilization. -/
theorem runExt_one_fixed (p : Tx.Program) (crypto : Secp256k1) (t : State)
    (h : runExt p crypto 1 t = t) (n : Nat) : runExt p crypto n t = t := by
  induction n with
  | zero => rfl
  | succ n ih => rw [show n + 1 = 1 + n from by omega, runExt_add p crypto 1 n t, h, ih]

/-- **Convergence is permanent.** The termination milestone reachable with NO decreasing measure: if
    ONE extra fuel unit leaves the `f`-fuel run unchanged (`runExt (f+1) s = runExt f s`), then the
    fuel-indexed sequence has converged for good — every larger fuel `f+n` gives the same state. So
    "the run stopped making progress" is a stable, machine-checkable stopping condition; a caller can
    detect convergence by a single extra step and trust it will not later resume. -/
theorem runExt_stabilizes (p : Tx.Program) (crypto : Secp256k1) (f n : Nat) (s : State)
    (h : runExt p crypto (f + 1) s = runExt p crypto f s) :
    runExt p crypto (f + n) s = runExt p crypto f s := by
  have h1 : runExt p crypto 1 (runExt p crypto f s) = runExt p crypto f s := by
    rw [← runExt_add p crypto f 1 s]; exact h
  rw [runExt_add p crypto f n s]
  exact runExt_one_fixed p crypto (runExt p crypto f s) h1 n

/-! ### Increment 4 (THROUGHOUT refinement) — bounded work at EVERY step, not just at the end
    The Increment-4 headline (`runExt_bounded`/`runScript_bounded`) certifies an accepting run ENDS
    within budget. This refinement strengthens that to "within budget at every intermediate step",
    resting on the reusable fuel-composition law `runExt_add` (`runExt` is a truncation of iterated
    one-tick application, so fuel splits additively). Two throughout routes are delivered: the direct
    universal form (route (a), every prefix errored-or-within-budget from `runExt_bounded`) and the
    monotone form (route (b), every prefix's op-cost ≤ the accepting state's final budget). -/

/-- Defining equation of `runExt` on positive fuel (the `f+1` arm), as an explicit rewrite target:
    the run loop's one-tick dispatch (error → stop; `ip < size` → metered step; else pop a return
    frame or finish). Definitional (`rfl`); lets a proof unfold exactly ONE tick without `unfold`
    whnf-ing the whole recursion / step body. -/
theorem runExt_succ (p : Tx.Program) (crypto : Secp256k1) (f : Nat) (s : State) :
    runExt p crypto (f + 1) s =
      (if s.error.isSome then s
       else if s.ip < s.instrs.size then runExt p crypto f (stepMeterExt p crypto s)
       else match s.ctrl with
         | Ctrl.frame retInstrs retIp :: rest =>
             runExt p crypto f { s with instrs := retInstrs, ip := retIp, ctrl := rest }
         | _ => s) := rfl

/-- **Monotone prefix.** Extending a run by extra fuel never lowers the accumulated op-cost aggregate:
    `stepOpCost` at any prefix `a` is ≤ its value after `a + b` more-fuel steps. Immediate from
    `runExt_add` (split the run at `a`) + `runExt_opCost_ge` (the suffix only grows cost). -/
theorem runExt_opCost_prefix (p : Tx.Program) (crypto : Secp256k1) (a b : Nat) (s : State) :
    stepOpCost (runExt p crypto a s).metrics
      ≤ stepOpCost (runExt p crypto (a + b) s).metrics := by
  rw [runExt_add]
  exact runExt_opCost_ge p crypto b (runExt p crypto a s)

/-- **Monotone prefix, ≤-form.** For any `a ≤ f`, the `a`-fuel prefix's op-cost is ≤ the full
    `f`-fuel run's op-cost. Just `runExt_opCost_prefix` after writing `f = a + d`. -/
theorem runExt_prefix_le_final (p : Tx.Program) (crypto : Secp256k1) (f : Nat) (s : State) :
    ∀ (a : Nat), a ≤ f →
      stepOpCost (runExt p crypto a s).metrics ≤ stepOpCost (runExt p crypto f s).metrics := by
  intro a ha
  obtain ⟨d, hd⟩ := Nat.le.dest ha
  rw [← hd]
  exact runExt_opCost_prefix p crypto a d s

/-- **Bounded work THROUGHOUT (universal / route (a)).** At EVERY prefix length `a`, a run that
    STARTED within budget is errored OR still within budget — i.e. it never sat over-budget at any
    reachable step without having aborted. Each prefix is itself a `runExt`, so this is just
    `runExt_bounded` (Increment 4) instantiated at every `a`. The direct "at every intermediate step"
    strengthening of the ENDS-within-budget certificate. -/
theorem runExt_throughout (p : Tx.Program) (crypto : Secp256k1) (s : State)
    (h : stepOpCost s.metrics ≤ s.budget) :
    ∀ (a : Nat),
      (runExt p crypto a s).error.isSome = true ∨
        stepOpCost (runExt p crypto a s).metrics ≤ (runExt p crypto a s).budget :=
  fun a => runExt_bounded p crypto a s h

/-- **Bounded work THROUGHOUT (monotone / route (b)).** If the full `f`-fuel run ENDS within its
    final budget, then EVERY prefix's op-cost is ≤ that same final budget — the abort ceiling the
    accepting state cleared dominates the whole trajectory. Bounds by the FINAL budget (not the
    initial `s.budget`) to avoid step-level budget-invariance over the full `step1Ext` dispatch
    (intractable within heartbeats — see the increment note). Monotone backbone:
    `runExt_prefix_le_final` then transitivity through the final bound. -/
theorem runExt_prefix_within_budget (p : Tx.Program) (crypto : Secp256k1) (f : Nat) (s : State)
    (hbud : stepOpCost (runExt p crypto f s).metrics ≤ (runExt p crypto f s).budget) :
    ∀ (a : Nat), a ≤ f →
      stepOpCost (runExt p crypto a s).metrics ≤ (runExt p crypto f s).budget :=
  fun a ha => Nat.le_trans (runExt_prefix_le_final p crypto f s a ha) hbud

/-- **Accepting run is bounded throughout.** The headline: a run that STARTED within budget and
    ACCEPTS (ends non-errored) at fuel `f` had op-cost ≤ its final budget at EVERY prefix `a ≤ f`.
    Acceptance discharges `runExt_bounded`'s right disjunct (error is `false`, so not the left), and
    monotonicity (`runExt_prefix_within_budget`) spreads the final bound backward over the whole run.
    Machine-checked "the accepting run never exceeded budget at any step". -/
theorem runExt_accept_throughout (p : Tx.Program) (crypto : Secp256k1) (f : Nat) (s : State)
    (hstart : stepOpCost s.metrics ≤ s.budget)
    (haccept : (runExt p crypto f s).error.isSome = false) :
    ∀ (a : Nat), a ≤ f →
      stepOpCost (runExt p crypto a s).metrics ≤ (runExt p crypto f s).budget := by
  have hbud : stepOpCost (runExt p crypto f s).metrics ≤ (runExt p crypto f s).budget := by
    rcases runExt_bounded p crypto f s hstart with herr | hb
    · simp [haccept] at herr
    · exact hb
  exact runExt_prefix_within_budget p crypto f s hbud


/-! ### Increment 3 helpers — bounding pushed VM-number lengths.
    A `bigIntToVmNumber` push fits `maxItemLen` once its value's magnitude is below the width band
    `2^(8·maxItemLen−1)` (`intByteLen_band` ∘ `intByteLen_eq_encodedLength`). Every UInt32/UInt64/
    int32 field is `< 2^64 ≪ 2^(8·maxItemLen−1)`, so the TYPE-BOUNDED introspection ops need NO
    program premise. -/
/-- Any integer whose magnitude is below the `maxItemLen` width band encodes within the item cap. -/
theorem bigIntToVmNumber_length_le (z : Int) (h : z.natAbs < 2 ^ (8 * maxItemLen - 1)) :
    (bigIntToVmNumber z).length ≤ maxItemLen := by
  rw [← intByteLen_eq_encodedLength]
  exact (intByteLen_band z maxItemLen (by decide)).mpr h

theorem bigIntToVmNumber_length_le_uint64 (z : Int) (h : z.natAbs < 2 ^ 64) :
    (bigIntToVmNumber z).length ≤ maxItemLen := by
  apply bigIntToVmNumber_length_le
  exact Nat.lt_of_lt_of_le h (Nat.pow_le_pow_right (by decide) (by decide))

theorem bigIntToVmNumber_ofNat_length (n : Nat) (h : n < 2 ^ 64) :
    (bigIntToVmNumber (Int.ofNat n)).length ≤ maxItemLen := by
  apply bigIntToVmNumber_length_le_uint64; exact h

theorem int32Signed_natAbs_lt (x : UInt32) : (int32Signed x).natAbs < 2 ^ 64 := by
  have hx : x.toNat < 2 ^ 32 := x.toNat_lt
  have h32 : (2:Nat) ^ 32 = 4294967296 := by decide
  have h64 : (2:Nat) ^ 64 = 18446744073709551616 := by decide
  rw [h32] at hx; rw [h64]
  unfold int32Signed
  simp only [Int.ofNat_eq_natCast]
  split <;> omega

theorem bigIntToVmNumber_uint32_length (x : UInt32) :
    (bigIntToVmNumber (Int.ofNat x.toNat)).length ≤ maxItemLen := by
  apply bigIntToVmNumber_ofNat_length
  exact Nat.lt_of_lt_of_le x.toNat_lt (by decide)

theorem bigIntToVmNumber_uint64_length (x : UInt64) :
    (bigIntToVmNumber (Int.ofNat x.toNat)).length ≤ maxItemLen := by
  apply bigIntToVmNumber_ofNat_length; exact x.toNat_lt

theorem bigIntToVmNumber_int32Signed_length (x : UInt32) :
    (bigIntToVmNumber (int32Signed x)).length ≤ maxItemLen :=
  bigIntToVmNumber_length_le_uint64 _ (int32Signed_natAbs_lt x)

/-- **The honest transaction well-formedness premise.** Bounds EXACTLY the genuinely-unbounded
    `Program`/`Bytes`/`Nat` fields the UNCHECKED introspection ops push verbatim: the evaluated input
    index, the varint-bounded input/output counts, each input's 32-byte outpoint hash, and each
    output / source-output token category+amount. A decoded, consensus-valid transaction satisfies
    every conjunct (32-byte hashes/categories, amount < 2^63, varint-bounded counts); the model's
    unbounded fields do not witness it, so it is stated as an explicit premise. -/
def WFProgram (p : Tx.Program) : Prop :=
  (bigIntToVmNumber (Int.ofNat p.inputIndex)).length ≤ maxItemLen ∧
  (bigIntToVmNumber (Int.ofNat p.inputCount)).length ≤ maxItemLen ∧
  (bigIntToVmNumber (Int.ofNat p.outputCount)).length ≤ maxItemLen ∧
  (∀ inp ∈ p.transaction.inputs, inp.outpointTransactionHash.length ≤ maxItemLen) ∧
  (∀ o ∈ p.transaction.outputs,
      (tokenCategoryBytes o.token).length ≤ maxItemLen ∧ (tokenAmountBytes o.token).length ≤ maxItemLen) ∧
  (∀ u ∈ p.sourceOutputs,
      (tokenCategoryBytes u.token).length ≤ maxItemLen ∧ (tokenAmountBytes u.token).length ≤ maxItemLen)

/-! ### `hlk` builders — turn a per-array length bound into the `introspectIndexed_WFlen_bounded`
    side condition `∀ n b, lookup n = some b → b.length ≤ maxItemLen`, via `arr[n]? = some x → x ∈ arr`. -/
/-- Type-bounded UInt64 value lookups (OP_UTXOVALUE / OP_OUTPUTVALUE) — no program premise. -/
theorem hlk_uint64_value {α} (arr : Array α) (g : α → UInt64) :
    ∀ (n : Nat) (b : Bytes), (arr[n]?).map (fun u => bigIntToVmNumber (Int.ofNat (g u).toNat)) = some b →
      b.length ≤ maxItemLen := by
  intro n b hb; obtain ⟨u, _, rfl⟩ := Option.map_eq_some_iff.mp hb
  exact bigIntToVmNumber_uint64_length (g u)

theorem hlk_uint32_value {α} (arr : Array α) (g : α → UInt32) :
    ∀ (n : Nat) (b : Bytes), (arr[n]?).map (fun u => bigIntToVmNumber (Int.ofNat (g u).toNat)) = some b →
      b.length ≤ maxItemLen := by
  intro n b hb; obtain ⟨u, _, rfl⟩ := Option.map_eq_some_iff.mp hb
  exact bigIntToVmNumber_uint32_length (g u)

theorem hlk_bounded_map {α} (arr : Array α) (g : α → Bytes)
    (hg : ∀ u ∈ arr, (g u).length ≤ maxItemLen) :
    ∀ (n : Nat) (b : Bytes), (arr[n]?).map g = some b → b.length ≤ maxItemLen := by
  intro n b hb; obtain ⟨u, hu, rfl⟩ := Option.map_eq_some_iff.mp hb
  exact hg u (Array.mem_of_getElem? hu)

/-! ### Per-branch closure toolkit: `WFlenOrErr t := WFlen t ∨ t.error.isSome` (single-occurrence so
    the `stepInstrExt` dispatch can be peeled one `if`/`match` at a time without a huge two-copy split). -/
/-- Item-length well-formed OR already errored — the disjunction preserved by every step. -/
def WFlenOrErr (t : State) : Prop := WFlen t ∨ t.error.isSome = true
theorem wfle_err {t : State} (h : t.error.isSome = true) : WFlenOrErr t := Or.inr h
theorem wfle_cons {s t : State} {b : Bytes} {rest : Stack}
    (hb : b.length ≤ maxItemLen) (hrest : ∀ y ∈ rest, y.length ≤ maxItemLen)
    (hs : WFlen s) (hstk : t.stack = b :: rest) (halt : t.alt = s.alt) : WFlenOrErr t := by
  refine Or.inl ⟨?_, ?_⟩
  · rw [hstk]; intro y hy
    rcases List.mem_cons.mp hy with h | h
    · subst h; exact hb
    · exact hrest y h
  · rw [halt]; exact hs.2
theorem wfle_stack (s : State) {t : State} (hrest : ∀ y ∈ t.stack, y.length ≤ maxItemLen)
    (halt : t.alt = s.alt) (hs : WFlen s) : WFlenOrErr t :=
  Or.inl ⟨hrest, by rw [halt]; exact hs.2⟩
theorem wfle_push {s : State} {v : Bytes} (hv : v.length ≤ maxItemLen) (hs : WFlen s) :
    WFlenOrErr (s.advance.push v) := wfle_cons hv hs.1 hs rfl rfl
theorem ofBool_length (b : Bool) : (ofBool b).length ≤ maxItemLen := by cases b <;> decide
theorem wfle_guarded_push {s : State} (v : Bytes) (hs : WFlen s) :
    WFlenOrErr (if v.length > maxItemLen then s.setErr .itemTooLarge else s.advance.push v) := by
  by_cases h : v.length > maxItemLen
  · rw [if_pos h]; exact wfle_err rfl
  · rw [if_neg h]; exact wfle_push (by omega) hs

/-! ### Signature-op closures — each pushes only `ofBool _` (≤1 byte) onto a stack suffix, or errors. -/
set_option maxHeartbeats 400000 in
/-- OP_CHECKSIG preserves-or-errors item length (pushes `ofBool _`; NULLFAIL errors). -/
theorem opCheckSig_WFlen (crypto : Secp256k1) (p : Program) (s : State) (hs : WFlen s) :
    WFlenOrErr (opCheckSig crypto p s) := by
  unfold opCheckSig
  split
  · rename_i pubkey sig rest heq
    have hr : ∀ y ∈ rest, y.length ≤ maxItemLen :=
      fun y hy => hs.1 y (by rw [heq]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hy))
    by_cases he : sig.isEmpty = true
    · rw [if_pos he]; exact wfle_cons (ofBool_length _) hr hs rfl rfl
    · rw [if_neg he]
      by_cases hok : (if sig.dropLast.length == 64 then crypto.verifySchnorr sig.dropLast pubkey (Tx.sighashDigest p (coveredBytecode s) (UInt32.ofNat (sig.getLast?.getD 0).toNat)) else crypto.verifyDERLowS sig.dropLast pubkey (Tx.sighashDigest p (coveredBytecode s) (UInt32.ofNat (sig.getLast?.getD 0).toNat))) = true
      · rw [if_pos hok]; exact wfle_cons (ofBool_length _) hr hs rfl rfl
      · rw [if_neg hok]; exact wfle_err rfl
  · exact wfle_err rfl

set_option maxHeartbeats 400000 in
theorem opCheckDataSig_WFlen (crypto : Secp256k1) (s : State) (hs : WFlen s) :
    WFlenOrErr (opCheckDataSig crypto s) := by
  unfold opCheckDataSig
  split
  · rename_i pubkey message sig rest heq
    have hr : ∀ y ∈ rest, y.length ≤ maxItemLen :=
      fun y hy => hs.1 y (by rw [heq]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hy)))
    by_cases he : sig.isEmpty = true
    · rw [if_pos he]; exact wfle_cons (ofBool_length _) hr hs rfl rfl
    · rw [if_neg he]
      by_cases hok : (if sig.length == 64 then crypto.verifySchnorr sig pubkey (Crypto.sha256 message) else crypto.verifyDERLowS sig pubkey (Crypto.sha256 message)) = true
      · rw [if_pos hok]; exact wfle_cons (ofBool_length _) hr hs rfl rfl
      · rw [if_neg hok]; exact wfle_err rfl
  · exact wfle_err rfl

set_option maxHeartbeats 400000 in
theorem opCheckMultiSig_WFlen (crypto : Secp256k1) (p : Program) (s : State) (hs : WFlen s) :
    WFlenOrErr (opCheckMultiSig crypto p s) := by
  unfold opCheckMultiSig
  split
  · rename_i nItem rest0 heq0
    split
    · exact wfle_err rfl
    · rename_i nI hnI
      by_cases hb1 : (nI < 0 ∨ nI > 20)
      · rw [if_pos hb1]; exact wfle_err rfl
      · rw [if_neg hb1]
        by_cases hb2 : (rest0.length < nI.toNat)
        · rw [if_pos hb2]; exact wfle_err rfl
        · rw [if_neg hb2]
          split
          · rename_i mItem rest2 heqd
            split
            · exact wfle_err rfl
            · rename_i mI hmI
              by_cases hb3 : (mI < 0 ∨ mI > nI)
              · rw [if_pos hb3]; exact wfle_err rfl
              · rw [if_neg hb3]
                by_cases hb4 : (rest2.length < mI.toNat)
                · rw [if_pos hb4]; exact wfle_err rfl
                · rw [if_neg hb4]
                  split
                  · rename_i dummy rest heqd2
                    by_cases hb5 : (!dummy.isEmpty) = true
                    · rw [if_pos hb5]; exact wfle_err rfl
                    · rw [if_neg hb5]
                      split
                      · exact wfle_err rfl
                      · rename_i approving happ
                        by_cases hb6 : (!(((rest2.take mI.toNat).reverse).toArray.all (·.isEmpty)) ∧ !(approving == mI.toNat))
                        · rw [if_pos hb6]; exact wfle_err rfl
                        · rw [if_neg hb6]
                          refine wfle_cons (ofBool_length _) ?_ hs rfl rfl
                          intro y hy
                          have m1 : y ∈ rest2.drop mI.toNat := by
                            rw [heqd2]; exact List.mem_cons_of_mem _ hy
                          have m2 : y ∈ rest2 := List.mem_of_mem_drop m1
                          have m3 : y ∈ rest0.drop nI.toNat := by
                            rw [heqd]; exact List.mem_cons_of_mem _ m2
                          have m4 : y ∈ rest0 := List.mem_of_mem_drop m3
                          exact hs.1 y (by rw [heq0]; exact List.mem_cons_of_mem _ m4)
                  · exact wfle_err rfl
          · exact wfle_err rfl
  · exact wfle_err rfl

theorem verifyTopInPlace_WFlen {s : State} (hs : WFlen s) :
    WFlenOrErr (verifyTopInPlace s) := by
  unfold verifyTopInPlace
  split
  · rename_i x xs heq
    by_cases ht : isTruthy x = true
    · rw [if_pos ht]
      exact wfle_stack s (fun y hy => hs.1 y (by rw [heq]; exact List.mem_cons_of_mem _ hy)) rfl hs
    · rw [if_neg ht]; exact wfle_err rfl
  · exact wfle_err rfl

-- verify-variant combiner: (op ; if err then s' else verifyTopInPlace s')
theorem wfle_verify_combine {s' : State} (h : WFlenOrErr s') :
    WFlenOrErr (if s'.error.isSome then s' else verifyTopInPlace s') := by
  by_cases he : s'.error.isSome = true
  · rw [if_pos he]; exact wfle_err he
  · rw [if_neg he]
    have hw : WFlen s' := by rcases h with hh | hh; exact hh; exact absurd hh he
    exact verifyTopInPlace_WFlen hw

/-- **The remaining frozen-keystone-core obligation** (Increment 3's harder half, scoped out here).
    Four TRUE facts about the frozen primitives, stated over the FULL resource context `WF`
    (item-length AND memory-slots — the latter is what OP_DEPTH's `ofNum stack.length` push needs,
    so item-length is NOT inductive on its own):
    • `core`  — the pure keystone `stepInstr`, on every op `stepInstrExt` delegates verbatim (the
      `else` default + PICK/ROLL/SPLIT), preserves-or-errors item length (pushes are parse-bounded,
      hashes ≤32, NUM2BIN self-guarded, DEPTH bounded by the slot cap);
    • `wrap`  — for the CAT/arithmetic wrapper ops, the core leaves the alt stack and the
      stack-below-top within the cap (the wrapper's own guard handles the possibly-oversize top);
    • `rshiftnum`/`shiftbin` — the Shift2026 numeric/binary results fit the cap (magnitude only
      shrinks / fixed-length buffer). All four are provable in principle; deferred, not assumed-false. -/
structure FrozenCore (crypto : Secp256k1) : Prop where
  core : ∀ (op : UInt8) (data : Bytes) (s : State), WF s →
      (op == 0x7e || (decide (0x93 ≤ op.toNat) && decide (op.toNat ≤ 0x97)) || op == 0x8b || op == 0x8c
        || op == 0x8f || op == 0x90 || op == 0xa3 || op == 0xa4) = false →
      WFlenOrErr (stepInstr op data s)
  wrap : ∀ (op : UInt8) (data : Bytes) (s : State), WF s →
      (∀ y ∈ (stepInstr op data s).alt, y.length ≤ maxItemLen) ∧
      (∀ (r : Bytes) (rest : Stack), (stepInstr op data s).stack = r :: rest →
          ∀ y ∈ rest, y.length ≤ maxItemLen)
  rshiftnum : ∀ (v : Int) (cn : Nat) (val : Bytes), readNum? val = some v →
      (ofNum (rshiftNum v cn)).length ≤ maxItemLen
  shiftbin : ∀ (dat : Bytes) (n : Nat), dat.length ≤ maxItemLen →
      (lshiftBin dat n).length ≤ maxItemLen ∧ (rshiftBin dat n).length ≤ maxItemLen


set_option linter.unusedSimpArgs false in
set_option maxHeartbeats 400000 in
/-- **The item-length guard-completeness theorem (`SELF_HARDENING.md §3.A`, deep half).** Group-by-group
    over the FROZEN `stepInstrExt` opcode dispatch, every arm preserves-or-errors item-length `WFlen`.
    The INTROSPECTION classes are FULLY discharged here (the actual Increment-3 finding): the guarded
    ops (0xc1 explicit >maxItemLen guard; 0xc7/ca/cd/cf/d2 `pushToStackChecked`) via
    `introspectIndexed_WFlen_checked`; the type-bounded value ops (0xc2/c5/c6/c9/cb/cc) via
    `bigIntToVmNumber_*_length` with NO premise; the premise ops (0xc0/c3/c4/c8/ce/d0/d1/d3) via
    `introspectIndexed_WFlen_bounded` + the matching `WFProgram` conjunct. The bitwise INVERT/
    REVERSEBYTES, the FUNCTIONS chip (DEFINE/INVOKE), the signature ops, CLTV/CSV and CODESEPARATOR
    are closed outright; the frozen keystone-core residue (default `stepInstr`, the CAT/arith wrapper,
    PICK/ROLL/SPLIT, the Shift2026 numeric/binary shifts) is discharged from `FrozenCore`. -/
theorem stepInstrExt_WFlen (p : Program) (crypto : Secp256k1) (hwf : WFProgram p)
    (Hfc : FrozenCore crypto) (op : UInt8) (data : Bytes) (s : State) (hs : WF s) :
    WFlenOrErr (stepInstrExt p crypto op data s) := by
  have hw : WFlen s := hs.1
  rw [stepInstrExt]
  by_cases h0 : (op == 0x83) = true
  · rw [if_pos h0]
    rcases hstk : s.stack with _ | ⟨x, rest⟩
    · simp only [hstk]; exact wfle_err rfl
    · simp only [hstk]
      refine wfle_cons (b := opInvert x) ?_ (fun y hy => hw.1 y (by rw [hstk]; exact List.mem_cons_of_mem _ hy)) hw rfl rfl
      rw [opInvert_length]; exact hw.1 x (by rw [hstk]; exact List.mem_cons_self)
  · rw [if_neg h0]
    by_cases h1 : (op == 0x8d || op == 0x8e) = true
    · rw [if_pos h1]
      rcases hstk : s.stack with _ | ⟨cnt, tl⟩
      · simp only [hstk]; exact wfle_err rfl
      · rcases tl with _ | ⟨val, rest⟩
        · simp only [hstk]; exact wfle_err rfl
        · simp only [hstk]
          rcases hc : readNum? cnt with _ | c
          · simp only [hc]; exact wfle_err rfl
          · rcases hv : readNum? val with _ | v
            · simp only [hc, hv]; exact wfle_err rfl
            · simp only [hc, hv]
              have hrest : ∀ y ∈ rest, y.length ≤ maxItemLen :=
                fun y hy => hw.1 y (by rw [hstk]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hy))
              by_cases hcneg : c < 0
              · rw [if_pos hcneg]; exact wfle_err rfl
              · rw [if_neg hcneg]
                by_cases hv0 : v == 0
                · rw [if_pos hv0]; exact wfle_cons ofNum_zero_length hrest hw rfl rfl
                · rw [if_neg hv0]
                  by_cases hop : op == 0x8d
                  · rw [if_pos hop]
                    by_cases hcn : c.toNat > maxItemLen * 8
                    · rw [if_pos hcn]; exact wfle_err rfl
                    · rw [if_neg hcn]
                      by_cases hlr : (ofNum (lshiftNum v c.toNat)).length > maxItemLen
                      · rw [if_pos hlr]; exact wfle_err rfl
                      · rw [if_neg hlr]; exact wfle_cons (by omega) hrest hw rfl rfl
                  · rw [if_neg hop]
                    by_cases hovr : c.toNat > val.length * 8
                    · rw [if_pos hovr]
                      refine wfle_cons ?_ hrest hw rfl rfl
                      by_cases hvneg : v < 0
                      · rw [if_pos hvneg]; exact ofNum_negOne_length
                      · rw [if_neg hvneg]; exact ofNum_zero_length
                    · rw [if_neg hovr]
                      exact wfle_cons (Hfc.rshiftnum v c.toNat val hv) hrest hw rfl rfl
    · rw [if_neg h1]
      by_cases h2 : (op == 0x98 || op == 0x99) = true
      · rw [if_pos h2]
        rcases hstk : s.stack with _ | ⟨cnt, tl⟩
        · simp only [hstk]; exact wfle_err rfl
        · rcases tl with _ | ⟨dat, rest⟩
          · simp only [hstk]; exact wfle_err rfl
          · simp only [hstk]
            rcases hc : readNum? cnt with _ | c
            · simp only [hc]; exact wfle_err rfl
            · simp only [hc]
              have hrest : ∀ y ∈ rest, y.length ≤ maxItemLen :=
                fun y hy => hw.1 y (by rw [hstk]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hy))
              have hdat : dat.length ≤ maxItemLen := hw.1 dat (by rw [hstk]; exact List.mem_cons_of_mem _ List.mem_cons_self)
              by_cases hcneg : c < 0
              · rw [if_pos hcneg]; exact wfle_err rfl
              · rw [if_neg hcneg]
                by_cases hop : op == 0x98
                · rw [if_pos hop]; exact wfle_cons (Hfc.shiftbin dat c.toNat hdat).1 hrest hw rfl rfl
                · rw [if_neg hop]; exact wfle_cons (Hfc.shiftbin dat c.toNat hdat).2 hrest hw rfl rfl
      · rw [if_neg h2]
        by_cases h3 : (op == 0x89) = true
        · rw [if_pos h3]
          rcases hstk : s.stack with _ | ⟨fnId, rest⟩
          · simp only [hstk]; exact wfle_err rfl
          · simp only [hstk]
            by_cases he1 : fnId.length > maxFunctionIdLen
            · rw [if_pos he1]; exact wfle_err rfl
            · rw [if_neg he1]
              by_cases he2 : (s.functionTable.find? (fun q => q.1 == fnId)).isSome = true
              · rw [if_pos he2]; exact wfle_err rfl
              · rw [if_neg he2]
                rcases hrest : rest with _ | ⟨body, rest2⟩
                · simp only [hrest]; exact wfle_err rfl
                · simp only [hrest]
                  refine wfle_stack s ?_ rfl hw
                  intro y hy
                  exact hw.1 y (by rw [hstk]; refine List.mem_cons_of_mem _ ?_; rw [hrest]; exact List.mem_cons_of_mem _ hy)
        · rw [if_neg h3]
          by_cases h4 : (op == 0x8a) = true
          · rw [if_pos h4]
            rcases hstk : s.stack with _ | ⟨fnId, rest⟩
            · simp only [hstk]; exact wfle_err rfl
            · simp only [hstk]
              rcases hlk : lookupFn s.functionTable fnId with _ | body
              · simp only [hlk]; exact wfle_err rfl
              · simp only [hlk]
                split <;>
                  first
                  | exact wfle_err rfl
                  | (refine wfle_stack s ?_ rfl hw; intro y hy; exact hw.1 y (by rw [hstk]; exact List.mem_cons_of_mem _ hy))
          · rw [if_neg h4]
            by_cases h5 : (op == 0xc0) = true
            · rw [if_pos h5]
              exact wfle_push hwf.1 hw
            · rw [if_neg h5]
              by_cases h6 : (op == 0xc1) = true
              · rw [if_pos h6]
                simp only []
                exact wfle_guarded_push _ hw
              · rw [if_neg h6]
                by_cases h7 : (op == 0xc2) = true
                · rw [if_pos h7]
                  exact wfle_push (bigIntToVmNumber_int32Signed_length p.version) hw
                · rw [if_neg h7]
                  by_cases h8 : (op == 0xc3) = true
                  · rw [if_pos h8]
                    exact wfle_push hwf.2.1 hw
                  · rw [if_neg h8]
                    by_cases h9 : (op == 0xc4) = true
                    · rw [if_pos h9]
                      exact wfle_push hwf.2.2.1 hw
                    · rw [if_neg h9]
                      by_cases h10 : (op == 0xc5) = true
                      · rw [if_pos h10]
                        exact wfle_push (bigIntToVmNumber_uint32_length p.locktime) hw
                      · rw [if_neg h10]
                        by_cases h11 : (op == 0xc6) = true
                        · rw [if_pos h11]
                          rcases hstk : s.stack with _ | ⟨idx, rest⟩
                          · simp only [hstk]; exact wfle_err rfl
                          · simp only [hstk]
                            rcases hrn : readNum? idx with _ | i
                            · simp only [hrn]; exact wfle_err rfl
                            · simp only [hrn]
                              exact introspectIndexed_WFlen_bounded s rest i _ false hw
                                      (fun y hy => hw.1 y (by rw [hstk]; exact List.mem_cons_of_mem _ hy))
                                      (hlk_uint64_value p.sourceOutputs (fun u => u.valueSatoshis))
                        · rw [if_neg h11]
                          by_cases h12 : (op == 0xc7) = true
                          · rw [if_pos h12]
                            rcases hstk : s.stack with _ | ⟨idx, rest⟩
                            · simp only [hstk]; exact wfle_err rfl
                            · simp only [hstk]
                              rcases hrn : readNum? idx with _ | i
                              · simp only [hrn]; exact wfle_err rfl
                              · simp only [hrn]
                                exact introspectIndexed_WFlen_checked s rest i _ hw
                                        (fun y hy => hw.1 y (by rw [hstk]; exact List.mem_cons_of_mem _ hy))
                          · rw [if_neg h12]
                            by_cases h13 : (op == 0xc8) = true
                            · rw [if_pos h13]
                              rcases hstk : s.stack with _ | ⟨idx, rest⟩
                              · simp only [hstk]; exact wfle_err rfl
                              · simp only [hstk]
                                rcases hrn : readNum? idx with _ | i
                                · simp only [hrn]; exact wfle_err rfl
                                · simp only [hrn]
                                  exact introspectIndexed_WFlen_bounded s rest i _ false hw
                                          (fun y hy => hw.1 y (by rw [hstk]; exact List.mem_cons_of_mem _ hy))
                                          (hlk_bounded_map p.transaction.inputs (fun inp => inp.outpointTransactionHash.reverse) (fun inp hinp => by rw [List.length_reverse]; exact hwf.2.2.2.1 inp hinp))
                            · rw [if_neg h13]
                              by_cases h14 : (op == 0xc9) = true
                              · rw [if_pos h14]
                                rcases hstk : s.stack with _ | ⟨idx, rest⟩
                                · simp only [hstk]; exact wfle_err rfl
                                · simp only [hstk]
                                  rcases hrn : readNum? idx with _ | i
                                  · simp only [hrn]; exact wfle_err rfl
                                  · simp only [hrn]
                                    exact introspectIndexed_WFlen_bounded s rest i _ false hw
                                            (fun y hy => hw.1 y (by rw [hstk]; exact List.mem_cons_of_mem _ hy))
                                            (hlk_uint32_value p.transaction.inputs (fun inp => inp.outpointIndex))
                              · rw [if_neg h14]
                                by_cases h15 : (op == 0xca) = true
                                · rw [if_pos h15]
                                  rcases hstk : s.stack with _ | ⟨idx, rest⟩
                                  · simp only [hstk]; exact wfle_err rfl
                                  · simp only [hstk]
                                    rcases hrn : readNum? idx with _ | i
                                    · simp only [hrn]; exact wfle_err rfl
                                    · simp only [hrn]
                                      exact introspectIndexed_WFlen_checked s rest i _ hw
                                              (fun y hy => hw.1 y (by rw [hstk]; exact List.mem_cons_of_mem _ hy))
                                · rw [if_neg h15]
                                  by_cases h16 : (op == 0xcb) = true
                                  · rw [if_pos h16]
                                    rcases hstk : s.stack with _ | ⟨idx, rest⟩
                                    · simp only [hstk]; exact wfle_err rfl
                                    · simp only [hstk]
                                      rcases hrn : readNum? idx with _ | i
                                      · simp only [hrn]; exact wfle_err rfl
                                      · simp only [hrn]
                                        exact introspectIndexed_WFlen_bounded s rest i _ false hw
                                                (fun y hy => hw.1 y (by rw [hstk]; exact List.mem_cons_of_mem _ hy))
                                                (hlk_uint32_value p.transaction.inputs (fun inp => inp.sequenceNumber))
                                  · rw [if_neg h16]
                                    by_cases h17 : (op == 0xcc) = true
                                    · rw [if_pos h17]
                                      rcases hstk : s.stack with _ | ⟨idx, rest⟩
                                      · simp only [hstk]; exact wfle_err rfl
                                      · simp only [hstk]
                                        rcases hrn : readNum? idx with _ | i
                                        · simp only [hrn]; exact wfle_err rfl
                                        · simp only [hrn]
                                          exact introspectIndexed_WFlen_bounded s rest i _ false hw
                                                  (fun y hy => hw.1 y (by rw [hstk]; exact List.mem_cons_of_mem _ hy))
                                                  (hlk_uint64_value p.transaction.outputs (fun o => o.valueSatoshis))
                                    · rw [if_neg h17]
                                      by_cases h18 : (op == 0xcd) = true
                                      · rw [if_pos h18]
                                        rcases hstk : s.stack with _ | ⟨idx, rest⟩
                                        · simp only [hstk]; exact wfle_err rfl
                                        · simp only [hstk]
                                          rcases hrn : readNum? idx with _ | i
                                          · simp only [hrn]; exact wfle_err rfl
                                          · simp only [hrn]
                                            exact introspectIndexed_WFlen_checked s rest i _ hw
                                                    (fun y hy => hw.1 y (by rw [hstk]; exact List.mem_cons_of_mem _ hy))
                                      · rw [if_neg h18]
                                        by_cases h19 : (op == 0xce) = true
                                        · rw [if_pos h19]
                                          rcases hstk : s.stack with _ | ⟨idx, rest⟩
                                          · simp only [hstk]; exact wfle_err rfl
                                          · simp only [hstk]
                                            rcases hrn : readNum? idx with _ | i
                                            · simp only [hrn]; exact wfle_err rfl
                                            · simp only [hrn]
                                              exact introspectIndexed_WFlen_bounded s rest i _ false hw
                                                      (fun y hy => hw.1 y (by rw [hstk]; exact List.mem_cons_of_mem _ hy))
                                                      (hlk_bounded_map p.sourceOutputs (fun u => tokenCategoryBytes u.token) (fun u hu => (hwf.2.2.2.2.2 u hu).1))
                                        · rw [if_neg h19]
                                          by_cases h20 : (op == 0xcf) = true
                                          · rw [if_pos h20]
                                            rcases hstk : s.stack with _ | ⟨idx, rest⟩
                                            · simp only [hstk]; exact wfle_err rfl
                                            · simp only [hstk]
                                              rcases hrn : readNum? idx with _ | i
                                              · simp only [hrn]; exact wfle_err rfl
                                              · simp only [hrn]
                                                exact introspectIndexed_WFlen_checked s rest i _ hw
                                                        (fun y hy => hw.1 y (by rw [hstk]; exact List.mem_cons_of_mem _ hy))
                                          · rw [if_neg h20]
                                            by_cases h21 : (op == 0xd0) = true
                                            · rw [if_pos h21]
                                              rcases hstk : s.stack with _ | ⟨idx, rest⟩
                                              · simp only [hstk]; exact wfle_err rfl
                                              · simp only [hstk]
                                                rcases hrn : readNum? idx with _ | i
                                                · simp only [hrn]; exact wfle_err rfl
                                                · simp only [hrn]
                                                  exact introspectIndexed_WFlen_bounded s rest i _ false hw
                                                          (fun y hy => hw.1 y (by rw [hstk]; exact List.mem_cons_of_mem _ hy))
                                                          (hlk_bounded_map p.sourceOutputs (fun u => tokenAmountBytes u.token) (fun u hu => (hwf.2.2.2.2.2 u hu).2))
                                            · rw [if_neg h21]
                                              by_cases h22 : (op == 0xd1) = true
                                              · rw [if_pos h22]
                                                rcases hstk : s.stack with _ | ⟨idx, rest⟩
                                                · simp only [hstk]; exact wfle_err rfl
                                                · simp only [hstk]
                                                  rcases hrn : readNum? idx with _ | i
                                                  · simp only [hrn]; exact wfle_err rfl
                                                  · simp only [hrn]
                                                    exact introspectIndexed_WFlen_bounded s rest i _ false hw
                                                            (fun y hy => hw.1 y (by rw [hstk]; exact List.mem_cons_of_mem _ hy))
                                                            (hlk_bounded_map p.transaction.outputs (fun o => tokenCategoryBytes o.token) (fun o ho => (hwf.2.2.2.2.1 o ho).1))
                                              · rw [if_neg h22]
                                                by_cases h23 : (op == 0xd2) = true
                                                · rw [if_pos h23]
                                                  rcases hstk : s.stack with _ | ⟨idx, rest⟩
                                                  · simp only [hstk]; exact wfle_err rfl
                                                  · simp only [hstk]
                                                    rcases hrn : readNum? idx with _ | i
                                                    · simp only [hrn]; exact wfle_err rfl
                                                    · simp only [hrn]
                                                      exact introspectIndexed_WFlen_checked s rest i _ hw
                                                              (fun y hy => hw.1 y (by rw [hstk]; exact List.mem_cons_of_mem _ hy))
                                                · rw [if_neg h23]
                                                  by_cases h24 : (op == 0xd3) = true
                                                  · rw [if_pos h24]
                                                    rcases hstk : s.stack with _ | ⟨idx, rest⟩
                                                    · simp only [hstk]; exact wfle_err rfl
                                                    · simp only [hstk]
                                                      rcases hrn : readNum? idx with _ | i
                                                      · simp only [hrn]; exact wfle_err rfl
                                                      · simp only [hrn]
                                                        exact introspectIndexed_WFlen_bounded s rest i _ false hw
                                                                (fun y hy => hw.1 y (by rw [hstk]; exact List.mem_cons_of_mem _ hy))
                                                                (hlk_bounded_map p.transaction.outputs (fun o => tokenAmountBytes o.token) (fun o ho => (hwf.2.2.2.2.1 o ho).2))
                                                  · rw [if_neg h24]
                                                    by_cases h25 : (op == 0xac) = true
                                                    · rw [if_pos h25]
                                                      exact opCheckSig_WFlen crypto p s hw
                                                    · rw [if_neg h25]
                                                      by_cases h26 : (op == 0xad) = true
                                                      · rw [if_pos h26]
                                                        exact wfle_verify_combine (opCheckSig_WFlen crypto p s hw)
                                                      · rw [if_neg h26]
                                                        by_cases h27 : (op == 0xba) = true
                                                        · rw [if_pos h27]
                                                          exact opCheckDataSig_WFlen crypto s hw
                                                        · rw [if_neg h27]
                                                          by_cases h28 : (op == 0xbb) = true
                                                          · rw [if_pos h28]
                                                            exact wfle_verify_combine (opCheckDataSig_WFlen crypto s hw)
                                                          · rw [if_neg h28]
                                                            by_cases h29 : (op == 0xae) = true
                                                            · rw [if_pos h29]
                                                              exact opCheckMultiSig_WFlen crypto p s hw
                                                            · rw [if_neg h29]
                                                              by_cases h30 : (op == 0xaf) = true
                                                              · rw [if_pos h30]
                                                                exact wfle_verify_combine (opCheckMultiSig_WFlen crypto p s hw)
                                                              · rw [if_neg h30]
                                                                by_cases h31 : (op == 0xbc) = true
                                                                · rw [if_pos h31]
                                                                  rcases hstk : s.stack with _ | ⟨x, rest⟩
                                                                  · simp only [hstk]; exact wfle_err rfl
                                                                  · simp only [hstk]
                                                                    refine wfle_cons (b := x.reverse) ?_ (fun y hy => hw.1 y (by rw [hstk]; exact List.mem_cons_of_mem _ hy)) hw rfl rfl
                                                                    rw [List.length_reverse]; exact hw.1 x (by rw [hstk]; exact List.mem_cons_self)
                                                                · rw [if_neg h31]
                                                                  by_cases h32 : (op == 0xb1) = true
                                                                  · rw [if_pos h32]
                                                                    rcases hstk : s.stack with _ | ⟨item, tl⟩
                                                                    · simp only [hstk]; exact wfle_err rfl
                                                                    · simp only [hstk]
                                                                      rcases hlt : readLocktime? item with _ | required
                                                                      · simp only [hlt]; exact wfle_err rfl
                                                                      · simp only [hlt]
                                                                        split
                                                                        · exact wfle_err rfl
                                                                        · split
                                                                          · exact wfle_err rfl
                                                                          · split
                                                                            · exact wfle_err rfl
                                                                            · exact Or.inl (WFlen_advance s hw)
                                                                  · rw [if_neg h32]
                                                                    by_cases h33 : (op == 0xb2) = true
                                                                    · rw [if_pos h33]
                                                                      rcases hstk : s.stack with _ | ⟨item, tl⟩
                                                                      · simp only [hstk]; exact wfle_err rfl
                                                                      · simp only [hstk]
                                                                        rcases hlt : readLocktime? item with _ | required
                                                                        · simp only [hlt]; exact wfle_err rfl
                                                                        · simp only [hlt]
                                                                          split
                                                                          · exact Or.inl (WFlen_advance s hw)
                                                                          · split
                                                                            · exact wfle_err rfl
                                                                            · split
                                                                              · exact wfle_err rfl
                                                                              · split
                                                                                · exact wfle_err rfl
                                                                                · split
                                                                                  · exact wfle_err rfl
                                                                                  · exact Or.inl (WFlen_advance s hw)
                                                                    · rw [if_neg h33]
                                                                      by_cases h34 : (op == 0xab) = true
                                                                      · rw [if_pos h34]
                                                                        exact Or.inl hw
                                                                      · rw [if_neg h34]
                                                                        by_cases h35 : (op == 0x7e || (0x93 ≤ op.toNat && op.toNat ≤ 0x97) || op == 0x8b || op == 0x8c || op == 0x8f || op == 0x90 || op == 0xa3 || op == 0xa4) = true
                                                                        · rw [if_pos h35]
                                                                          have halt := (Hfc.wrap op data s hs).1
                                                                          have htail := (Hfc.wrap op data s hs).2
                                                                          rcases herr : (stepInstr op data s).error with _ | e
                                                                          · rcases hstk2 : (stepInstr op data s).stack with _ | ⟨r, restv⟩
                                                                            · simp only [herr, hstk2]
                                                                              refine Or.inl ⟨?_, halt⟩
                                                                              intro y hy; rw [hstk2] at hy; simp at hy
                                                                            · simp only [herr, hstk2]
                                                                              by_cases hg : r.length > maxItemLen
                                                                              · rw [if_pos hg]; exact wfle_err rfl
                                                                              · rw [if_neg hg]
                                                                                refine Or.inl ⟨?_, halt⟩
                                                                                intro y hy; rw [hstk2] at hy
                                                                                rcases List.mem_cons.mp hy with h | h
                                                                                · subst h; omega
                                                                                · exact htail r restv hstk2 y h
                                                                          · simp only [herr]
                                                                            exact wfle_err (by rw [herr]; rfl)
                                                                        · rw [if_neg h35]
                                                                          by_cases h36 : (op == 0x79 || op == 0x7a || op == 0x7f) = true
                                                                          · rw [if_pos h36]
                                                                            rcases hstk : s.stack with _ | ⟨idx, rest⟩
                                                                            · simp only [hstk]; exact wfle_err rfl
                                                                            · simp only [hstk]
                                                                              rcases hrn : readNum? idx with _ | n
                                                                              · simp only [hrn]; exact wfle_err rfl
                                                                              · simp only [hrn]
                                                                                by_cases hneg : n < 0
                                                                                · rw [if_pos hneg]; exact wfle_err rfl
                                                                                · rw [if_neg hneg]
                                                                                  exact Hfc.core op data s hs (by simpa using h35)
                                                                          · rw [if_neg h36]
                                                                            exact Hfc.core op data s hs (by simpa using h35)

/-- One pure extended step preserves-or-errors item length (dispatch: skip⇒`advance`, else the arm). -/
theorem step1Ext_WFlen (p : Program) (crypto : Secp256k1) (hwf : WFProgram p) (Hfc : FrozenCore crypto)
    (s : State) (hs : WF s) : WFlenOrErr (step1Ext p crypto s) := by
  rw [step1Ext]
  split
  · exact Or.inl hs.1
  · split
    · exact stepInstrExt_WFlen p crypto hwf Hfc _ _ s hs
    · exact Or.inl (WFlen_advance s hs.1)
/-- **The Axis-A resource-safety headline for the metered run.** From `WFProgram p` and the frozen-core
    residual `FrozenCore`, a whole metered run from a `WF` start stays `WF` (all three consensus caps:
    item-length, memory-slots, control-depth) or has already rejected. Threads the FULL `WF` invariant
    per step (item-length via `step1Ext_WFlen`∘`stepMeterExt_WFlen_of`, memory-slots via the
    unconditional `stepMeterExt_WFmem`) — the coupling `runExt_WFlen` could not carry, since
    item-length is not inductive without the slot bound (OP_DEPTH). -/
theorem runExt_WF_of (p : Program) (crypto : Secp256k1) (hwf : WFProgram p) (Hfc : FrozenCore crypto) :
    ∀ (f : Nat) (s : State), WF s →
      WF (runExt p crypto f s) ∨ (runExt p crypto f s).error.isSome = true
  | 0, s, hwfs => Or.inl hwfs
  | f+1, s, hwfs => by
      unfold runExt
      split
      · exact Or.inr (by assumption)
      · split
        · have hlen := stepMeterExt_WFlen_of p crypto s (step1Ext_WFlen p crypto hwf Hfc s hwfs)
          have hmem := stepMeterExt_WFmem p crypto s
          rcases hlen with hl | he
          · rcases hmem with hm | he2
            · exact runExt_WF_of p crypto hwf Hfc f (stepMeterExt p crypto s) ⟨hl, hm⟩
            · rw [runExt_error_fix p crypto f _ he2]; exact Or.inr he2
          · rw [runExt_error_fix p crypto f _ he]; exact Or.inr he
        · split
          · rename_i retInstrs retIp rest heq
            refine runExt_WF_of p crypto hwf Hfc f
              { s with instrs := retInstrs, ip := retIp, ctrl := rest } ?_
            refine ⟨hwfs.1, ?_⟩
            have hm := hwfs.2
            unfold WFmem at hm ⊢
            have hlen2 : s.ctrl.length = rest.length + 1 := by rw [heq, List.length_cons]
            refine ⟨hm.1, ?_⟩
            show rest.length ≤ maxCtrlDepth
            omega
          · exact Or.inl hwfs

/-! ### Increment 5 (Axis C, cont.) — the fuel-sufficiency STEP-COUNT bound (`SELF_HARDENING.md §3.C`)
    The stabilization core (above) proves convergence is permanent but not that `runScript`'s FIXED
    fuel `instrs.size + evalFuelSlack` (`evalFuelSlack = 200 000`) is enough to reach it. This block
    closes that gap. The spine: every metered step over a present instruction bills ≥1
    `evaluatedInstructionCount` (`kappa`'s `base`), so a real (in-range) step raises `stepOpCost` by
    ≥100 (`baseInstructionCost`); the within-budget invariant (`runExt_bounded`, Increment 4) then
    caps the number of real steps at `budget/100 ≤ 80 328`. Frame returns are matched to OP_INVOKE
    real steps by a conservation invariant, bounding TOTAL iterations by `2·budget/100 ≤ 160 656`,
    which the 200 000 slack covers — so a within-budget run halts within its fuel. The two per-step
    obligations `Hframe`/`Hbudget` (no step pushes >1 return frame / alters the budget field) are
    left PARAMETRIZED, exactly like the `WFlen` `Hstep` — the run machinery is complete and reusable. -/

/-- Every metered step over a present instruction bills exactly one instruction tick in
    `evaluatedInstructionCount`: `kappa`'s `base := { evaluatedInstructionCount := 1 }` is the
    `evaluatedInstructionCount` field on EVERY branch (the skipped-instruction tick, the push, the
    `arithCost`/`hashCost`/`sigCost`/`multiSigCost` deltas, and the copy/bool/byte tails all set it
    to 1). `unfold` + structural split keeps the huge `widthAt (step1 s)` arms opaque — only the
    first field is forced. -/
theorem kappa_evalCount (s : State) (i : Instr) (h : s.current? = some i) :
    (kappa s).evaluatedInstructionCount = 1 := by
  unfold kappa
  split
  · rename_i heq; rw [h] at heq; exact absurd heq (by simp)
  · repeat' (first | rfl | dsimp only | split)

/-- **One real step bills exactly one tick.** A metered step over a present instruction adds EXACTLY
    one to `evaluatedInstructionCount`: `stepMeterExt` writes `metrics := s.metrics + kappa s + Δ`
    (`Δ` the introspection/sig correction, `evaluatedInstructionCount = 0`), then the metrics-
    preserving gate. So the tick is `(kappa s).evaluatedInstructionCount = 1`. -/
theorem stepMeterExt_evalCount (p : Tx.Program) (crypto : Secp256k1) (s : State) (i : Instr)
    (h : s.current? = some i) :
    (stepMeterExt p crypto s).metrics.evaluatedInstructionCount
      = s.metrics.evaluatedInstructionCount + 1 := by
  unfold stepMeterExt
  rw [enforceStepLimits_metrics]
  simp only [Metrics.add_eq, Metrics.add]
  rw [kappa_evalCount s i h]

/-- An in-range instruction pointer means the current instruction is present (`current? = some …`) —
    the bridge from `runExt`'s `ip < size` guard to the `current? = some _` hypotheses above. -/
theorem current?_of_lt (s : State) (h : s.ip < s.instrs.size) :
    s.current? = some s.instrs[s.ip] := by
  simp only [State.current?]
  exact (Array.getElem?_eq_some_getElem_iff s.instrs s.ip h).mpr trivial

/-- **A real step raises op-cost by ≥100.** Combining the exact `+1` instruction tick
    (`stepMeterExt_evalCount`) with the componentwise metrics monotonicity (`stepMeterExt_metrics_ge`,
    Increment 1): `evaluatedInstructionCount` is billed at 100 each and the other four metrics only
    grow, so `stepOpCost` rises by at least `baseInstructionCost = 100`. This is the per-step floor
    that turns the op-cost budget into a step-count wall. -/
theorem stepOpCost_step_ge (p : Tx.Program) (crypto : Secp256k1) (s : State) (i : Instr)
    (h : s.current? = some i) :
    stepOpCost s.metrics + 100 ≤ stepOpCost (stepMeterExt p crypto s).metrics := by
  have hle := stepMeterExt_metrics_ge p crypto s
  have heic := stepMeterExt_evalCount p crypto s i h
  simp only [Metrics.le_def] at hle
  simp only [stepOpCost]
  omega

/-- The trivial op-cost floor: `evaluatedInstructionCount` is billed at 100 each and every other
    metric is non-negative, so `eic·100 ≤ stepOpCost`. Lets an `eic` bound become an op-cost bound. -/
theorem stepOpCost_ge_eic (m : Cost.Metrics) :
    m.evaluatedInstructionCount * 100 ≤ stepOpCost m := by
  simp only [stepOpCost]; omega

/-- **The real-step counter.** The number of in-range (`ip < size`) metered steps a `runExt` takes
    before halting, mirroring `runExt`'s own recursion: the frame-return branch is NOT counted (it
    bills no `kappa`), and the error / finished branches stop. The rigorous count-object the budget
    then bounds. -/
def realStepCount (p : Tx.Program) (crypto : Secp256k1) : Nat → State → Nat
  | 0,   _ => 0
  | f+1, s =>
      if s.error.isSome then 0
      else if s.ip < s.instrs.size then realStepCount p crypto f (stepMeterExt p crypto s) + 1
      else match s.ctrl with
        | Ctrl.frame retInstrs retIp :: rest =>
            realStepCount p crypto f { s with instrs := retInstrs, ip := retIp, ctrl := rest }
        | _ => 0

/-- Defining equation of `realStepCount` at positive fuel (definitional; unfolds one tick without
    whnf-ing the recursion). -/
theorem realStepCount_succ (p : Tx.Program) (crypto : Secp256k1) (f : Nat) (s : State) :
    realStepCount p crypto (f+1) s =
      (if s.error.isSome then 0
       else if s.ip < s.instrs.size then realStepCount p crypto f (stepMeterExt p crypto s) + 1
       else match s.ctrl with
         | Ctrl.frame retInstrs retIp :: rest =>
             realStepCount p crypto f { s with instrs := retInstrs, ip := retIp, ctrl := rest }
         | _ => 0) := rfl

/-- **Real steps are billed.** A metered run's final `evaluatedInstructionCount` dominates the
    start's plus the number of real (in-range) steps it took. Fuel induction mirroring `runExt`: the
    in-range branch bills exactly one tick (`stepMeterExt_evalCount`, via `current?_of_lt`) and
    recurses; the frame-return branch preserves metrics AND the count (frame state has `s.metrics`);
    the error/finished branches count zero. -/
theorem runExt_eic_ge_realSteps (p : Tx.Program) (crypto : Secp256k1) :
    ∀ (f : Nat) (s : State),
      s.metrics.evaluatedInstructionCount + realStepCount p crypto f s
        ≤ (runExt p crypto f s).metrics.evaluatedInstructionCount
  | 0,   s => by simp only [realStepCount, runExt, Nat.add_zero]; omega
  | f+1, s => by
      rw [realStepCount_succ, runExt_succ]
      by_cases herr : s.error.isSome = true
      · rw [if_pos herr, if_pos herr]; omega
      · rw [if_neg herr, if_neg herr]
        by_cases hlt : s.ip < s.instrs.size
        · rw [if_pos hlt, if_pos hlt]
          have hcur := current?_of_lt s hlt
          have hstep := stepMeterExt_evalCount p crypto s _ hcur
          have ih := runExt_eic_ge_realSteps p crypto f (stepMeterExt p crypto s)
          omega
        · rw [if_neg hlt, if_neg hlt]
          generalize hc : s.ctrl = c
          match c with
          | Ctrl.frame ri rp :: rest =>
              exact runExt_eic_ge_realSteps p crypto f { s with instrs := ri, ip := rp, ctrl := rest }
          | [] =>
              show s.metrics.evaluatedInstructionCount + 0 ≤ s.metrics.evaluatedInstructionCount
              omega
          | Ctrl.cond cb :: cs =>
              show s.metrics.evaluatedInstructionCount + 0 ≤ s.metrics.evaluatedInstructionCount
              omega
          | Ctrl.mark mn :: cs =>
              show s.metrics.evaluatedInstructionCount + 0 ≤ s.metrics.evaluatedInstructionCount
              omega

/-- **Real-step count is capped by the op-cost budget.** From a within-budget start, a run is
    errored OR its real-step count times 100 stays within the (final) budget — each real step bills
    ≥100 op-cost (`stepOpCost_ge_eic` on the run-accumulated tick), all of it kept within budget by
    `runExt_bounded` (Increment 4). So `realStepCount ≤ budget/100 ≤ 80 328` on any consensus run. -/
theorem runExt_realSteps_le_budget (p : Tx.Program) (crypto : Secp256k1) (f : Nat) (s : State)
    (hstart : stepOpCost s.metrics ≤ s.budget) :
    (runExt p crypto f s).error.isSome = true ∨
      realStepCount p crypto f s * 100 ≤ (runExt p crypto f s).budget := by
  rcases runExt_bounded p crypto f s hstart with herr | hb
  · exact Or.inl herr
  · refine Or.inr ?_
    have h1 := runExt_eic_ge_realSteps p crypto f s
    have h2 := stepOpCost_ge_eic (runExt p crypto f s).metrics
    omega

/-- **Total iteration count.** Every non-halting `runExt` iteration — real step AND frame return
    (the frame branch is `+1` here, unlike `realStepCount`). This is the quantity `runScript`'s fuel
    must exceed to reach a fixpoint. -/
def runIters (p : Tx.Program) (crypto : Secp256k1) : Nat → State → Nat
  | 0,   _ => 0
  | f+1, s =>
      if s.error.isSome then 0
      else if s.ip < s.instrs.size then runIters p crypto f (stepMeterExt p crypto s) + 1
      else match s.ctrl with
        | Ctrl.frame retInstrs retIp :: rest =>
            runIters p crypto f { s with instrs := retInstrs, ip := retIp, ctrl := rest } + 1
        | _ => 0

/-- Defining equation of `runIters` at positive fuel (definitional). -/
theorem runIters_succ (p : Tx.Program) (crypto : Secp256k1) (f : Nat) (s : State) :
    runIters p crypto (f+1) s =
      (if s.error.isSome then 0
       else if s.ip < s.instrs.size then runIters p crypto f (stepMeterExt p crypto s) + 1
       else match s.ctrl with
         | Ctrl.frame retInstrs retIp :: rest =>
             runIters p crypto f { s with instrs := retInstrs, ip := retIp, ctrl := rest } + 1
         | _ => 0) := rfl

/-- **Enough fuel ⇒ halted.** If the loop stopped iterating strictly before exhausting its fuel
    (`runIters f s < f`), the fuel was more than sufficient and the `f`-fuel run is at a `Halted`
    fixpoint. Fuel induction: the real-step / frame-return branches recurse on the successor with
    strictly less spare fuel; the error branch is `Halted` by its error; the finished branch (`ip ≥
    size`, `ctrl` not a `frame`) is `Halted` by exhaustion. The rigorous, audit-free bridge from an
    iteration-count bound to actual termination. -/
theorem runIters_lt_imp_halted (p : Tx.Program) (crypto : Secp256k1) :
    ∀ (f : Nat) (s : State), runIters p crypto f s < f → Halted (runExt p crypto f s)
  | 0,   s, h => absurd h (Nat.not_lt_zero _)
  | f+1, s, h => by
      rw [runExt_succ]
      rw [runIters_succ] at h
      by_cases herr : s.error.isSome = true
      · rw [if_pos herr]; exact Or.inl herr
      · rw [if_neg herr]; rw [if_neg herr] at h
        by_cases hlt : s.ip < s.instrs.size
        · rw [if_pos hlt]; rw [if_pos hlt] at h
          exact runIters_lt_imp_halted p crypto f (stepMeterExt p crypto s) (by omega)
        · rw [if_neg hlt]; rw [if_neg hlt] at h
          generalize hc : s.ctrl = c at h ⊢
          match c with
          | Ctrl.frame ri rp :: rest =>
              dsimp only at h
              exact runIters_lt_imp_halted p crypto f
                { s with instrs := ri, ip := rp, ctrl := rest } (by omega)
          | [] =>
              show Halted s
              exact Or.inr ⟨by omega, by rw [hc]; simp⟩
          | Ctrl.cond cb :: cs =>
              show Halted s
              exact Or.inr ⟨by omega, by rw [hc]; simp⟩
          | Ctrl.mark mn :: cs =>
              show Halted s
              exact Or.inr ⟨by omega, by rw [hc]; simp⟩

/-- The number of `Ctrl.frame` (OP_INVOKE return-frame) entries on a control stack. -/
def frameCount : List Ctrl → Nat
  | [] => 0
  | Ctrl.frame _ _ :: rest => frameCount rest + 1
  | _ :: rest => frameCount rest

/-- Popping (or pushing) one return frame changes `frameCount` by exactly one. -/
theorem frameCount_frame (ri : Array Instr) (rp : Nat) (rest : List Ctrl) :
    frameCount (Ctrl.frame ri rp :: rest) = frameCount rest + 1 := rfl

/-- **Frame-return conservation.** Parametrized on the per-step frame-push bound `Hframe` (no single
    metered step adds more than one return frame — true because only OP_INVOKE pushes a `Ctrl.frame`):
    total iterations plus the frames still open at the end are ≤ twice the real-step count plus the
    frames open at the start. So each frame RETURN is charged to a distinct (INVOKE) real step. Fuel
    induction: the real-step branch pays `Hframe`'s `+1` frame against its `+2` on `2·realStepCount`;
    the frame-return branch trades its `+1` iteration against the popped frame (`frameCount_frame`);
    halting is trivial. With an empty start `ctrl`, `runIters ≤ 2·realStepCount`. -/
theorem runIters_le_two_realSteps (p : Tx.Program) (crypto : Secp256k1)
    (Hframe : ∀ t : State, frameCount (stepMeterExt p crypto t).ctrl ≤ frameCount t.ctrl + 1) :
    ∀ (f : Nat) (s : State),
      runIters p crypto f s + frameCount (runExt p crypto f s).ctrl
        ≤ 2 * realStepCount p crypto f s + frameCount s.ctrl
  | 0,   s => by simp only [runIters, realStepCount, runExt, Nat.mul_zero, Nat.zero_add]; omega
  | f+1, s => by
      rw [runIters_succ, runExt_succ, realStepCount_succ]
      by_cases herr : s.error.isSome = true
      · rw [if_pos herr, if_pos herr, if_pos herr]; omega
      · rw [if_neg herr, if_neg herr, if_neg herr]
        by_cases hlt : s.ip < s.instrs.size
        · rw [if_pos hlt, if_pos hlt, if_pos hlt]
          have ih := runIters_le_two_realSteps p crypto Hframe f (stepMeterExt p crypto s)
          have hf := Hframe s
          omega
        · rw [if_neg hlt, if_neg hlt, if_neg hlt]
          generalize hc : s.ctrl = c
          match c with
          | Ctrl.frame ri rp :: rest =>
              have ih := runIters_le_two_realSteps p crypto Hframe f
                { s with instrs := ri, ip := rp, ctrl := rest }
              dsimp only at ih ⊢
              rw [frameCount_frame]
              omega
          | [] => dsimp only; rw [hc]; omega
          | Ctrl.cond cb :: cs => dsimp only; rw [hc]; omega
          | Ctrl.mark mn :: cs => dsimp only; rw [hc]; omega

/-- **Budget is a run invariant** (parametrized on the per-step obligation `Hbudget`: no metered
    step alters the `budget` field — true because no opcode arm writes it). Fuel induction: the
    real-step branch uses `Hbudget`, the frame-return branch preserves it (only `instrs`/`ip`/`ctrl`
    change), error/finished return `s`. -/
theorem runExt_budget (p : Tx.Program) (crypto : Secp256k1)
    (Hbudget : ∀ t : State, (stepMeterExt p crypto t).budget = t.budget) :
    ∀ (f : Nat) (s : State), (runExt p crypto f s).budget = s.budget
  | 0,   s => rfl
  | f+1, s => by
      rw [runExt_succ]
      by_cases herr : s.error.isSome = true
      · rw [if_pos herr]
      · rw [if_neg herr]
        by_cases hlt : s.ip < s.instrs.size
        · rw [if_pos hlt, runExt_budget p crypto Hbudget f (stepMeterExt p crypto s), Hbudget s]
        · rw [if_neg hlt]
          generalize hc : s.ctrl = c
          match c with
          | Ctrl.frame ri rp :: rest =>
              dsimp only
              rw [runExt_budget p crypto Hbudget f { s with instrs := ri, ip := rp, ctrl := rest }]
          | [] => rfl
          | Ctrl.cond cb :: cs => rfl
          | Ctrl.mark mn :: cs => rfl

/-- **Fuel sufficiency (`runExt` level).** Given the two per-step obligations — no metered step
    pushes more than one return frame (`Hframe`) and none alters the budget field (`Hbudget`) — a run
    from an empty control stack within a consensus-scale budget reaches a `Halted` fixpoint as soon
    as its fuel exceeds `2·maxOpCostCeiling/100 = 160 656`. Chains: `runExt_realSteps_le_budget`
    (errored, or `realStepCount·100 ≤ budget ≤ ceiling`), `runIters_le_two_realSteps` (total
    iters ≤ `2·realStepCount`), `runIters_lt_imp_halted` (`runIters < fuel ⇒ Halted`). -/
theorem runExt_fuel_suffices (p : Tx.Program) (crypto : Secp256k1)
    (Hframe : ∀ t : State, frameCount (stepMeterExt p crypto t).ctrl ≤ frameCount t.ctrl + 1)
    (Hbudget : ∀ t : State, (stepMeterExt p crypto t).budget = t.budget)
    (s : State) (N : Nat)
    (hctrl : s.ctrl = [])
    (hbud : s.budget ≤ maxOpCostCeiling)
    (hstart : stepOpCost s.metrics ≤ s.budget)
    (hN : 2 * maxOpCostCeiling / 100 < N) :
    Halted (runExt p crypto N s) := by
  rcases runExt_realSteps_le_budget p crypto N s hstart with herr | hb
  · exact Or.inl herr
  · apply runIters_lt_imp_halted
    have hcons := runIters_le_two_realSteps p crypto Hframe N s
    rw [runExt_budget p crypto Hbudget N s] at hb
    rw [hctrl] at hcons
    simp only [frameCount] at hcons
    unfold maxOpCostCeiling at hbud hN
    omega

/-- The freshly-loaded script state starts with an empty control stack (both `parse` branches). -/
theorem loadFrom_ctrl (stk : Stack) (bs : Bytes) : (loadFrom stk bs).ctrl = [] := by
  unfold loadFrom; split <;> rfl

/-- **Fuel sufficiency (`runScript` level).** Under the two per-step obligations `Hframe`/`Hbudget`
    and a consensus-scale budget, `runScript`'s fixed fuel `instrs.size + evalFuelSlack`
    (`evalFuelSlack = 200 000`) always reaches a `Halted` fixpoint: the 200 000 slack exceeds the
    worst-case iteration count `2·budget/100 ≤ 160 656`, so a within-budget metered run never
    exhausts its fuel. This certifies the fixed fuel FORMULA as sufficient — an implementation
    detail, not a tunable soundness parameter. `Hframe`/`Hbudget` are the remaining per-step audits
    (the Axis-C analogue of the `WFlen` per-step `Hstep`). -/
theorem runScript_fuel_suffices (crypto : Secp256k1) (p : Tx.Program) (stk : Stack) (bs : Bytes)
    (budget : Nat)
    (Hframe : ∀ t : State, frameCount (stepMeterExt p crypto t).ctrl ≤ frameCount t.ctrl + 1)
    (Hbudget : ∀ t : State, (stepMeterExt p crypto t).budget = t.budget)
    (hbud : budget ≤ maxOpCostCeiling) :
    Halted (runScript crypto p stk bs budget) := by
  unfold runScript
  refine runExt_fuel_suffices p crypto Hframe Hbudget _ _ ?_ ?_ ?_ ?_
  · show (loadFrom stk bs).ctrl = []
    exact loadFrom_ctrl stk bs
  · exact hbud
  · show stepOpCost (loadFrom stk bs).metrics ≤ budget
    rw [loadFrom_metrics]; exact Nat.zero_le _
  · show 2 * maxOpCostCeiling / 100 < (loadFrom stk bs).instrs.size + evalFuelSlack
    unfold maxOpCostCeiling evalFuelSlack; omega


/-! ### Generic fold length helpers (first-projection consing / appending). -/

/-- A `foldr` whose step conses exactly one element to the first component (seeded `([], z)`)
    yields a first component of length `l.length`. -/
theorem foldr_fst_length_nil {β : Type} (f : UInt8 → (Bytes × β) → (Bytes × β)) (z : β)
    (hf : ∀ v p, (f v p).1.length = p.1.length + 1) :
    ∀ (l : Bytes), (l.foldr f ([], z)).1.length = l.length := by
  intro l
  induction l with
  | nil => rfl
  | cons a as ih =>
    rw [List.foldr_cons, hf a (List.foldr f ([], z) as), ih, List.length_cons]

/-- A `foldl` whose step appends exactly one element to the first component grows the first
    component's length by `l.length`. -/
theorem foldl_fst_length_gen {β : Type} (f : (Bytes × β) → UInt8 → (Bytes × β))
    (hf : ∀ p v, (f p v).1.length = p.1.length + 1) :
    ∀ (l : Bytes) (acc : Bytes × β), (l.foldl f acc).1.length = acc.1.length + l.length := by
  intro l
  induction l with
  | nil => intro acc; rfl
  | cons a as ih =>
    intro acc
    rw [List.foldl_cons, ih (f acc a), hf acc a, List.length_cons]
    omega

/-! ### residualLeft / residualRight are length-preserving. -/

theorem frozenCore_residualLeft_length (bitShift : Nat) (data : Bytes) :
    (residualLeft bitShift data).length = data.length := by
  unfold residualLeft
  split
  · rfl
  · exact foldr_fst_length_nil
      (fun v (p : Bytes × UInt8) =>
        ((v <<< UInt8.ofNat bitShift ||| p.2) :: p.1, v >>> UInt8.ofNat (8 - bitShift)))
      (0 : UInt8) (by intro v p; rfl) data

theorem frozenCore_residualRight_length (bitShift : Nat) (data : Bytes) :
    (residualRight bitShift data).length = data.length := by
  unfold residualRight
  split
  · rfl
  · have h := foldl_fst_length_gen
      (fun (p : Bytes × UInt8) v =>
        (p.1 ++ [v >>> UInt8.ofNat bitShift ||| p.2], v <<< UInt8.ofNat (8 - bitShift)))
      (by
        intro p v
        show (p.1 ++ [v >>> UInt8.ofNat bitShift ||| p.2]).length = p.1.length + 1
        simp)
      data ([], 0)
    rw [h]
    show (0 : Nat) + data.length = data.length
    exact Nat.zero_add _

/-! ### lshiftBin / rshiftBin length ≤ input length. -/

theorem frozenCore_lshiftBin_len (dat : Bytes) (n : Nat) :
    (lshiftBin dat n).length ≤ dat.length := by
  unfold lshiftBin
  rw [frozenCore_residualLeft_length, List.length_append, List.length_drop, List.length_replicate]
  have h1 : min (n / 8) dat.length ≤ dat.length := Nat.min_le_right _ _
  have h2 : min (n / 8) dat.length ≤ n / 8 := Nat.min_le_left _ _
  omega

theorem frozenCore_rshiftBin_len (dat : Bytes) (n : Nat) :
    (rshiftBin dat n).length ≤ dat.length := by
  unfold rshiftBin
  rw [frozenCore_residualRight_length, List.length_append, List.length_replicate, List.length_take]
  have h1 : min (n / 8) dat.length ≤ dat.length := Nat.min_le_right _ _
  have h2 : min (dat.length - n / 8) dat.length ≤ dat.length := Nat.min_le_right _ _
  omega

/-! ### The `shiftbin` field. -/

theorem frozenCore_shiftbin : ∀ (dat : Bytes) (n : Nat), dat.length ≤ maxItemLen →
    (lshiftBin dat n).length ≤ maxItemLen ∧ (rshiftBin dat n).length ≤ maxItemLen := by
  intro dat n hdat
  exact ⟨Nat.le_trans (frozenCore_lshiftBin_len dat n) hdat,
         Nat.le_trans (frozenCore_rshiftBin_len dat n) hdat⟩

/-! ### The `rshiftnum` field. -/

/-- The magnitude of a decoded VM number is below the `8·length − 1` width band: the top byte's
    high bit is the sign, so it contributes < 128 to the magnitude. -/
theorem decodeDigits_fst_lt : ∀ (ds : List Nat), (∀ d ∈ ds, d < 256) →
    (decodeDigits ds).1 < 2 ^ (8 * ds.length - 1) := by
  intro ds
  induction ds with
  | nil => intro _; decide
  | cons x rest ih =>
    intro hlt
    have hx : x < 256 := hlt x List.mem_cons_self
    cases rest with
    | nil =>
      rcases Nat.lt_or_ge x 128 with hc | hc
      · have e : decodeDigits [x] = (x, false) := by
          show (if 128 ≤ x then ((x - 128 : Nat), true) else (x, false)) = (x, false)
          rw [if_neg (by omega)]
        rw [e]
        show x < 2 ^ (8 * 1 - 1)
        have h128 : (2 : Nat) ^ (8 * 1 - 1) = 128 := by decide
        omega
      · have e : decodeDigits [x] = (x - 128, true) := by
          show (if 128 ≤ x then ((x - 128 : Nat), true) else (x, false)) = (x - 128, true)
          rw [if_pos hc]
        rw [e]
        show x - 128 < 2 ^ (8 * 1 - 1)
        have h128 : (2 : Nat) ^ (8 * 1 - 1) = 128 := by decide
        omega
    | cons y rest' =>
      have ih' := ih (fun d hd => hlt d (List.mem_cons_of_mem _ hd))
      have hrec : (decodeDigits (x :: y :: rest')).1
                = x + 256 * (decodeDigits (y :: rest')).1 := rfl
      have hlen : (x :: y :: rest').length = (y :: rest').length + 1 := rfl
      have hpow : (2 : Nat) ^ (8 * ((y :: rest').length + 1) - 1)
                = 256 * 2 ^ (8 * (y :: rest').length - 1) := by
        have h1 : 1 ≤ (y :: rest').length := by rw [List.length_cons]; omega
        rw [show (256 : Nat) = 2 ^ 8 from by decide, ← Nat.pow_add]
        congr 1
        omega
      rw [hrec, hlen, hpow]
      omega

/-- The magnitude of a decoded VM number is exactly the first component of `decodeDigits`. -/
theorem vmNumberToBigInt_natAbs (b : Bytes) :
    (vmNumberToBigInt b).natAbs = (decodeDigits (b.map (fun w => w.toNat))).1 := by
  have hb : vmNumberToBigInt b
      = if (decodeDigits (b.map (fun w => w.toNat))).2
        then -(Int.ofNat (decodeDigits (b.map (fun w => w.toNat))).1)
        else Int.ofNat (decodeDigits (b.map (fun w => w.toNat))).1 := rfl
  rw [hb]
  cases hs : (decodeDigits (b.map (fun w => w.toNat))).2
  · rw [if_neg (by decide)]; rfl
  · rw [if_pos (by decide), Int.natAbs_neg]; rfl

/-- A `readNum?`-accepted operand has magnitude below the `maxItemLen` width band. -/
theorem readNum?_natAbs_lt (val : Bytes) (v : Int) (h : readNum? val = some v) :
    v.natAbs < 2 ^ (8 * maxItemLen - 1) := by
  unfold readNum? at h
  split at h
  · rename_i hcond
    have hv : vmNumberToBigInt val = v := Option.some.inj h
    simp only [Bool.and_eq_true, decide_eq_true_eq] at hcond
    have hlen : val.length ≤ maxNumLen := hcond.1
    have hle : val.length ≤ maxItemLen := by
      have hmn : maxNumLen = maxItemLen := rfl
      omega
    have hbound := decodeDigits_fst_lt (val.map (fun w => w.toNat)) (by
      intro d hd
      obtain ⟨w, _, rfl⟩ := List.mem_map.mp hd
      exact Nat.lt_of_lt_of_le w.toNat_lt (by decide))
    rw [List.length_map] at hbound
    have hpow : (2 : Nat) ^ (8 * val.length - 1) ≤ 2 ^ (8 * maxItemLen - 1) :=
      Nat.pow_le_pow_right (by decide) (by omega)
    rw [← hv, vmNumberToBigInt_natAbs]
    omega
  · exact absurd h (by simp)

theorem frozenCore_rshiftnum : ∀ (v : Int) (cn : Nat) (val : Bytes), readNum? val = some v →
    (ofNum (rshiftNum v cn)).length ≤ maxItemLen := by
  intro v cn val hread
  unfold ofNum
  apply bigIntToVmNumber_length_le
  have hv : v.natAbs < 2 ^ (8 * maxItemLen - 1) := readNum?_natAbs_lt val v hread
  have hle : (rshiftNum v cn).natAbs ≤ v.natAbs := by
    unfold rshiftNum
    exact Int.natAbs_fdiv_le_natAbs v _
  omega

/-! ### Group-2 helper lemmas (frozen-core `stepInstr` item-length preservation). -/

/-- A `forIn` over a `List` in the `Id` monad whose body always yields a size-`k` array
    produces a size-`k` array (crypto digest-array size invariant). -/
theorem fc_forIn_id_size {α β : Type} (k : Nat)
    (L : List α) (init : Array β) (F : α → Array β → Id (ForInStep (Array β)))
    (hinit : init.size = k)
    (hF : ∀ a acc, ∃ arr, F a acc = ForInStep.yield arr ∧ arr.size = k) :
    (forIn L init F).size = k := by
  induction L generalizing init with
  | nil => rw [List.forIn_nil]; exact hinit
  | cons a as ih =>
    obtain ⟨arr, hEq, hSz⟩ := hF a init
    rw [List.forIn_cons, hEq]; exact ih arr hSz

set_option maxHeartbeats 1000000 in
theorem fc_sha256_hp_size (padded : Array UInt8) : (Sha256.hashPadded padded).size = 8 := by
  unfold Sha256.hashPadded
  simp only [Id.run, Std.Legacy.Range.forIn_eq_forIn_range']
  exact fc_forIn_id_size 8 _ _ _ rfl (fun a acc => ⟨_, rfl, rfl⟩)
set_option maxHeartbeats 1000000 in
theorem fc_sha1_hp_size (padded : Array UInt8) : (Sha1.hashPadded padded).size = 5 := by
  unfold Sha1.hashPadded
  simp only [Id.run, Std.Legacy.Range.forIn_eq_forIn_range']
  exact fc_forIn_id_size 5 _ _ _ rfl (fun a acc => ⟨_, rfl, rfl⟩)
set_option maxHeartbeats 1000000 in
theorem fc_ripemd_hp_size (padded : Array UInt8) : (Ripemd160.hashPadded padded).size = 5 := by
  unfold Ripemd160.hashPadded
  simp only [Id.run, Std.Legacy.Range.forIn_eq_forIn_range']
  exact fc_forIn_id_size 5 _ _ _ rfl (fun a acc => ⟨_, rfl, rfl⟩)

theorem fc_word4BE_len (x : UInt32) : (word4BE x).length = 4 := rfl
theorem fc_word4LE_len (x : UInt32) : (word4LE x).length = 4 := rfl
theorem fc_flatten_word4BE (L : List UInt32) : ((L.map word4BE).flatten).length = 4 * L.length := by
  induction L with
  | nil => rfl
  | cons x xs ih => rw [List.map_cons, List.flatten_cons, List.length_append, fc_word4BE_len, ih, List.length_cons]; omega
theorem fc_flatten_word4LE (L : List UInt32) : ((L.map word4LE).flatten).length = 4 * L.length := by
  induction L with
  | nil => rfl
  | cons x xs ih => rw [List.map_cons, List.flatten_cons, List.length_append, fc_word4LE_len, ih, List.length_cons]; omega

theorem fc_sha256_len (x : Bytes) : (Crypto.sha256 x).length = 32 := by
  unfold Crypto.sha256 Sha256.hash
  rw [fc_flatten_word4BE, Array.length_toList, fc_sha256_hp_size]
theorem fc_sha1_len (x : Bytes) : (Crypto.sha1 x).length = 20 := by
  unfold Crypto.sha1 Sha1.hash
  rw [fc_flatten_word4BE, Array.length_toList, fc_sha1_hp_size]
theorem fc_ripemd160_len (x : Bytes) : (Crypto.ripemd160 x).length = 20 := by
  unfold Crypto.ripemd160 Ripemd160.hash
  rw [fc_flatten_word4LE, Array.length_toList, fc_ripemd_hp_size]
theorem fc_hash256_len (x : Bytes) : (Crypto.hash256 x).length = 32 := by
  unfold Crypto.hash256; exact fc_sha256_len _
theorem fc_hash160_len (x : Bytes) : (Crypto.hash160 x).length = 20 := by
  unfold Crypto.hash160; exact fc_ripemd160_len _

theorem fc_hashOp_len {op : UInt8} {h : Bytes → Bytes} (hh : hashOp? op = some h) (x : Bytes) :
    (h x).length ≤ maxItemLen := by
  unfold hashOp? at hh
  split at hh
  · injection hh with hh; subst hh; rw [fc_ripemd160_len]; decide
  · split at hh
    · injection hh with hh; subst hh; rw [fc_sha1_len]; decide
    · split at hh
      · injection hh with hh; subst hh; rw [fc_sha256_len]; decide
      · split at hh
        · injection hh with hh; subst hh; rw [fc_hash160_len]; decide
        · split at hh
          · injection hh with hh; subst hh; rw [fc_hash256_len]; decide
          · exact absurd hh (by simp)

theorem fc_zipBytewise_len (f : UInt8 → UInt8 → UInt8) :
    ∀ (a b r : Bytes), zipBytewise f a b = some r → r.length = a.length := by
  intro a
  induction a with
  | nil => intro b r h; cases b with
    | nil => simp only [zipBytewise, Option.some.injEq] at h; subst h; rfl
    | cons y ys => simp [zipBytewise] at h
  | cons x xs ih => intro b r h; cases b with
    | nil => simp [zipBytewise] at h
    | cons y ys =>
      simp only [zipBytewise, Option.map_eq_some_iff] at h
      obtain ⟨r', hr', rfl⟩ := h
      rw [List.length_cons, List.length_cons, ih ys r' hr']

theorem fc_unaryNumOp_none {op : UInt8}
    (h8b : (op == 0x8b) = false) (h8c : (op == 0x8c) = false)
    (h8f : (op == 0x8f) = false) (h90 : (op == 0x90) = false) :
    unaryNumOp? op = none := by
  unfold unaryNumOp?
  rw [if_neg (by simp [h8b]), if_neg (by simp [h8c]), if_neg (by simp [h8f]), if_neg (by simp [h90])]

theorem fc_binNumOp_none {op : UInt8}
    (ha3 : (op == 0xa3) = false) (ha4 : (op == 0xa4) = false) :
    binNumOp? op = none := by
  unfold binNumOp?
  rw [if_neg (by simp [ha3]), if_neg (by simp [ha4])]

theorem fc_arithKind_none {op : UInt8}
    (h : (decide (0x93 ≤ op.toNat) && decide (op.toNat ≤ 0x97)) = false) :
    Opcode.arithKind? op = none := by
  rcases hk : Opcode.arithKind? op with _ | k
  · rfl
  · exfalso
    unfold Opcode.arithKind? at hk
    split at hk <;> simp_all <;> omega

theorem fc_decodeDigits_lt :
    ∀ (L : List Nat), (∀ d ∈ L, d < 256) → (decodeDigits L).1 < 2 ^ (8 * L.length - 1) := by
  intro L
  induction L with
  | nil => intro _; decide
  | cons x rest ih =>
    intro hmem
    have hx : x < 256 := hmem x (by simp)
    cases rest with
    | nil =>
      show (decodeDigits [x]).1 < 2 ^ (8 * 1 - 1)
      simp only [decodeDigits]
      by_cases hc : 128 ≤ x
      · rw [if_pos hc]; show x - 128 < 2^7; omega
      · rw [if_neg hc]; show x < 2^7; omega
    | cons y rest' =>
      have hmem' : ∀ d ∈ (y :: rest'), d < 256 := fun d hd => hmem d (List.mem_cons_of_mem _ hd)
      have hM := ih hmem'
      have hrec : (decodeDigits (x :: y :: rest')).1 = x + 256 * (decodeDigits (y :: rest')).1 := rfl
      have hlen1 : (y :: rest').length = rest'.length + 1 := rfl
      have hlen2 : (x :: y :: rest').length = rest'.length + 2 := rfl
      rw [hrec, hlen2]; rw [hlen1] at hM
      have he : 8 * (rest'.length + 2) - 1 = (8 * (rest'.length + 1) - 1) + 8 := by omega
      rw [he, Nat.pow_add, show (2:Nat)^8 = 256 from by decide]
      omega

theorem fc_vmNum_natAbs_lt (x : Bytes) :
    (vmNumberToBigInt x).natAbs < 2 ^ (8 * x.length - 1) := by
  have hmem : ∀ d ∈ x.map (fun w => w.toNat), d < 256 := by
    intro d hd; rw [List.mem_map] at hd; obtain ⟨w, _, rfl⟩ := hd; exact w.toNat_lt
  have hlen : (x.map (fun w => w.toNat)).length = x.length := List.length_map ..
  have hb := fc_decodeDigits_lt (x.map (fun w => w.toNat)) hmem
  rw [hlen] at hb
  have hna : (vmNumberToBigInt x).natAbs = (decodeDigits (x.map (fun w => w.toNat))).1 := by
    unfold vmNumberToBigInt
    rcases hp : decodeDigits (x.map (fun w => w.toNat)) with ⟨mag, sgn⟩
    simp only [hp]
    cases sgn <;> simp [Int.natAbs_neg]
  rw [hna]; exact hb

theorem fc_bin2num_len (x : Bytes) :
    (bigIntToVmNumber (vmNumberToBigInt x)).length ≤ x.length := by
  rw [← intByteLen_eq_encodedLength]
  cases hx : x.length with
  | zero =>
    have he : x = [] := by cases x with | nil => rfl | cons a l => simp at hx
    subst he; decide
  | succ n =>
    rw [intByteLen_band _ (n+1) (by omega)]
    have h := fc_vmNum_natAbs_lt x
    rw [hx] at h; exact h


theorem fc_stk {s t : State} (hw : WFlen s) (halt : t.alt = s.alt)
    (hsub : ∀ z ∈ t.stack, z ∈ s.stack) : WFlenOrErr t :=
  wfle_stack s (fun z hz => hw.1 z (hsub z hz)) halt hw

set_option linter.unusedSimpArgs false in
set_option maxHeartbeats 1600000 in
theorem frozenCore_core : ∀ (op : UInt8) (data : Bytes) (s : State), WF s →
    (op == 0x7e || (decide (0x93 ≤ op.toNat) && decide (op.toNat ≤ 0x97)) || op == 0x8b || op == 0x8c
      || op == 0x8f || op == 0x90 || op == 0xa3 || op == 0xa4) = false →
    WFlenOrErr (stepInstr op data s) := by
  intro op data s hs hexcl
  have hw : WFlen s := hs.1
  have hmem : WFmem s := hs.2
  simp only [Bool.or_eq_false_iff] at hexcl
  obtain ⟨⟨⟨⟨⟨⟨⟨hcat, harith⟩, h8b⟩, h8c⟩, h8f⟩, h90⟩, ha3⟩, ha4⟩ := hexcl
  unfold stepInstr
  -- arm 1: pushes
  by_cases h1 : Opcode.isPushOp op = true
  · rw [if_pos h1]
    by_cases hmn : (!isMinimalPush op data) = true
    · rw [if_pos hmn]; exact wfle_err rfl
    rw [if_neg hmn]
    by_cases hln : List.length (pushValue op data) > maxItemLen
    · rw [if_pos hln]; exact wfle_err rfl
    rw [if_neg hln]; exact wfle_push (by omega) hw
  rw [if_neg h1]
  -- arm 2: IF/NOTIF
  by_cases h2 : (op == Opcode.OP_IF || op == Opcode.OP_NOTIF) = true
  · rw [if_pos h2]
    by_cases hact : s.executionIsActive = true
    · rw [if_pos hact]
      rcases hstk : s.stack with _ | ⟨x, xs⟩
      · exact wfle_err rfl
      simp only [hstk]
      exact fc_stk hw rfl (fun z hz => by rw [hstk]; exact List.mem_cons_of_mem _ hz)
    rw [if_neg hact]; exact Or.inl hw
  rw [if_neg h2]
  -- arm 3: ELSE
  by_cases h3 : (op == Opcode.OP_ELSE) = true
  · rw [if_pos h3]
    rcases hc : s.ctrl with _ | ⟨c0, crest⟩
    · exact wfle_err rfl
    cases c0 with
    | cond b => simp only [hc]; exact Or.inl hw
    | mark m => exact wfle_err rfl
    | frame a n => exact wfle_err rfl
  rw [if_neg h3]
  -- arm 4: ENDIF
  by_cases h4 : (op == Opcode.OP_ENDIF) = true
  · rw [if_pos h4]
    rcases hc : s.ctrl with _ | ⟨c0, crest⟩
    · exact wfle_err rfl
    cases c0 with
    | cond b => simp only [hc]; exact Or.inl hw
    | mark m => exact wfle_err rfl
    | frame a n => exact wfle_err rfl
  rw [if_neg h4]
  -- arm 5: VERIFY
  by_cases h5 : (op == Opcode.OP_VERIFY) = true
  · rw [if_pos h5]
    rcases hstk : s.stack with _ | ⟨x, xs⟩
    · exact wfle_err rfl
    simp only [hstk]
    by_cases ht : isTruthy x = true
    · rw [if_pos ht]; exact fc_stk hw rfl (fun z hz => by rw [hstk]; exact List.mem_cons_of_mem _ hz)
    rw [if_neg ht]; exact wfle_err rfl
  rw [if_neg h5]
  -- arm 6: RETURN
  by_cases h6 : (op == Opcode.OP_RETURN) = true
  · rw [if_pos h6]; exact wfle_err rfl
  rw [if_neg h6]
  -- arm 7: BEGIN
  by_cases h7 : (op == Opcode.OP_BEGIN) = true
  · rw [if_pos h7]; exact Or.inl hw
  rw [if_neg h7]
  -- arm 8: UNTIL
  by_cases h8 : (op == Opcode.OP_UNTIL) = true
  · rw [if_pos h8]
    rcases hctrl : s.ctrl with _ | ⟨c0, crest⟩
    · exact wfle_err rfl
    cases c0 with
    | cond b => exact wfle_err rfl
    | frame a n => exact wfle_err rfl
    | mark m =>
      rcases hstk : s.stack with _ | ⟨x, xs⟩
      · exact wfle_err rfl
      simp only [hctrl, hstk]
      by_cases ht : isTruthy x = true
      · rw [if_pos ht]
        exact fc_stk hw rfl (fun z hz => by rw [hstk]; exact List.mem_cons_of_mem _ hz)
      rw [if_neg ht]
      exact fc_stk hw rfl (fun z hz => by rw [hstk]; exact List.mem_cons_of_mem _ hz)
  rw [if_neg h8]
  -- arm 9: DUP
  by_cases h9 : (op == Opcode.OP_DUP) = true
  · rw [if_pos h9]
    rcases hstk : s.stack with _ | ⟨x, xs⟩
    · exact wfle_err rfl
    simp only [hstk]
    exact wfle_push (hw.1 x (by rw [hstk]; exact List.mem_cons_self)) hw
  rw [if_neg h9]
  -- arm 10: DROP
  by_cases h10 : (op == Opcode.OP_DROP) = true
  · rw [if_pos h10]
    rcases hstk : s.stack with _ | ⟨x, xs⟩
    · exact wfle_err rfl
    simp only [hstk]
    exact fc_stk hw rfl (fun z hz => by rw [hstk]; exact List.mem_cons_of_mem _ hz)
  rw [if_neg h10]
  -- arm 11: OVER
  by_cases h11 : (op == Opcode.OP_OVER) = true
  · rw [if_pos h11]
    rcases hstk : s.stack with _ | ⟨x, tl⟩
    · exact wfle_err rfl
    rcases tl with _ | ⟨y, xs⟩
    · exact wfle_err rfl
    simp only [hstk]
    refine fc_stk hw rfl (fun z hz => ?_)
    rw [hstk]; simp only [List.mem_cons] at hz ⊢; rcases hz with h|h|h|h <;> simp_all
  rw [if_neg h11]
  -- arm 12: SWAP
  by_cases h12 : (op == Opcode.OP_SWAP) = true
  · rw [if_pos h12]
    rcases hstk : s.stack with _ | ⟨x, tl⟩
    · exact wfle_err rfl
    rcases tl with _ | ⟨y, xs⟩
    · exact wfle_err rfl
    simp only [hstk]
    refine fc_stk hw rfl (fun z hz => ?_)
    rw [hstk]; simp only [List.mem_cons] at hz ⊢; rcases hz with h|h|h <;> simp_all
  rw [if_neg h12]
  -- arm 13: ROT
  by_cases h13 : (op == Opcode.OP_ROT) = true
  · rw [if_pos h13]
    rcases hstk : s.stack with _ | ⟨x, tl⟩
    · exact wfle_err rfl
    rcases tl with _ | ⟨y, tl2⟩
    · exact wfle_err rfl
    rcases tl2 with _ | ⟨zz, xs⟩
    · exact wfle_err rfl
    simp only [hstk]
    refine fc_stk hw rfl (fun z hz => ?_)
    rw [hstk]; simp only [List.mem_cons] at hz ⊢; rcases hz with h|h|h|h <;> simp_all
  rw [if_neg h13]
  -- arm 14: NIP
  by_cases h14 : (op == Opcode.OP_NIP) = true
  · rw [if_pos h14]
    rcases hstk : s.stack with _ | ⟨x, tl⟩
    · exact wfle_err rfl
    rcases tl with _ | ⟨y, xs⟩
    · exact wfle_err rfl
    simp only [hstk]
    refine fc_stk hw rfl (fun z hz => ?_)
    rw [hstk]; simp only [List.mem_cons] at hz ⊢; rcases hz with h|h <;> simp_all
  rw [if_neg h14]
  -- arm 15: TUCK
  by_cases h15 : (op == Opcode.OP_TUCK) = true
  · rw [if_pos h15]
    rcases hstk : s.stack with _ | ⟨x, tl⟩
    · exact wfle_err rfl
    rcases tl with _ | ⟨y, xs⟩
    · exact wfle_err rfl
    simp only [hstk]
    refine fc_stk hw rfl (fun z hz => ?_)
    rw [hstk]; simp only [List.mem_cons] at hz ⊢; rcases hz with h|h|h|h <;> simp_all
  rw [if_neg h15]
  -- arm 16: TOALTSTACK
  by_cases h16 : (op == Opcode.OP_TOALTSTACK) = true
  · rw [if_pos h16]
    rcases hstk : s.stack with _ | ⟨x, xs⟩
    · exact wfle_err rfl
    simp only [hstk]
    refine Or.inl ⟨?_, ?_⟩
    · intro z hz; exact hw.1 z (by rw [hstk]; exact List.mem_cons_of_mem _ hz)
    intro z hz
    rcases List.mem_cons.mp hz with heq | hz
    · rw [heq]; exact hw.1 x (by rw [hstk]; exact List.mem_cons_self)
    exact hw.2 z hz
  rw [if_neg h16]
  -- arm 17: FROMALTSTACK
  by_cases h17 : (op == Opcode.OP_FROMALTSTACK) = true
  · rw [if_pos h17]
    rcases hal : s.alt with _ | ⟨x, a⟩
    · exact wfle_err rfl
    simp only [hal]
    refine Or.inl ⟨?_, ?_⟩
    · intro z hz
      rcases List.mem_cons.mp hz with heq | hz
      · rw [heq]; exact hw.2 x (by rw [hal]; exact List.mem_cons_self)
      exact hw.1 z hz
    intro z hz; exact hw.2 z (by rw [hal]; exact List.mem_cons_of_mem _ hz)
  rw [if_neg h17]
  -- arm 18: PICK / ROLL
  by_cases h18 : (op == Opcode.OP_PICK || op == Opcode.OP_ROLL) = true
  · rw [if_pos h18]
    rcases hstk : s.stack with _ | ⟨nb, rest⟩
    · exact wfle_err rfl
    simp only [hstk]
    have hrest : ∀ z ∈ rest, z.length ≤ maxItemLen :=
      fun z hz => hw.1 z (by rw [hstk]; exact List.mem_cons_of_mem _ hz)
    rcases hv : rest[(vmNumberToBigInt nb).toNat]? with _ | v
    · exact wfle_err rfl
    simp only [hv]
    have hvmem : v.length ≤ maxItemLen := hrest v (List.mem_of_getElem? hv)
    by_cases hp : op == Opcode.OP_PICK
    · rw [if_pos hp]
      refine wfle_stack s ?_ rfl hw
      intro z hz
      rcases List.mem_cons.mp hz with rfl | hz
      · exact hvmem
      exact hrest z hz
    rw [if_neg hp]
    refine wfle_stack s ?_ rfl hw
    intro z hz
    rcases List.mem_cons.mp hz with rfl | hz
    · exact hvmem
    unfold removeNth at hz
    rcases List.mem_append.mp hz with h | h
    · exact hrest z (List.mem_of_mem_take h)
    exact hrest z (List.mem_of_mem_drop h)
  rw [if_neg h18]
  -- arm 19: arith (EXCLUDED)
  simp only [fc_arithKind_none harith]
  -- arm 20: EQUAL
  by_cases h20 : (op == Opcode.OP_EQUAL) = true
  · rw [if_pos h20]
    rcases hstk : s.stack with _ | ⟨x, tl⟩
    · exact wfle_err rfl
    rcases tl with _ | ⟨y, rest⟩
    · exact wfle_err rfl
    simp only [hstk]
    refine wfle_cons (b := if x == y then [1] else []) ?_
      (fun z hz => hw.1 z (by rw [hstk]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hz))) hw rfl rfl
    split <;> decide
  rw [if_neg h20]
  -- arm 21: EQUALVERIFY
  by_cases h21 : (op == Opcode.OP_EQUALVERIFY) = true
  · rw [if_pos h21]
    rcases hstk : s.stack with _ | ⟨x, tl⟩
    · exact wfle_err rfl
    rcases tl with _ | ⟨y, rest⟩
    · exact wfle_err rfl
    simp only [hstk]
    by_cases hxy : (x == y) = true
    · rw [if_pos hxy]
      exact fc_stk hw rfl (fun z hz => by rw [hstk]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hz))
    rw [if_neg hxy]; exact wfle_err rfl
  rw [if_neg h21]
  -- arm 22: unaryNumOp (EXCLUDED)
  simp only [fc_unaryNumOp_none h8b h8c h8f h90]
  -- arm 23: unaryBoolOp
  rcases hub : unaryBoolOp? op with _ | fub
  rotate_left
  · simp only [hub]
    rcases hstk : s.stack with _ | ⟨x, rest⟩
    · exact wfle_err rfl
    simp only [hstk]
    rcases hrn : readNum? x with _ | xv
    · exact wfle_err rfl
    simp only [hrn]
    exact wfle_cons (ofBool_length _) (fun z hz => hw.1 z (by rw [hstk]; exact List.mem_cons_of_mem _ hz)) hw rfl rfl
  simp only [hub]
  -- arm 24: binNumOp (EXCLUDED)
  simp only [fc_binNumOp_none ha3 ha4]
  -- arm 25: binBoolOp
  rcases hbb : binBoolOp? op with _ | fbb
  rotate_left
  · simp only [hbb]
    rcases hstk : s.stack with _ | ⟨b, tl⟩
    · exact wfle_err rfl
    rcases tl with _ | ⟨a, rest⟩
    · exact wfle_err rfl
    have hrest : ∀ z ∈ rest, z.length ≤ maxItemLen :=
      fun z hz => hw.1 z (by rw [hstk]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hz))
    simp only [hstk]
    rcases hra : readNum? a with _ | av
    · exact wfle_err rfl
    rcases hrb : readNum? b with _ | bv
    · exact wfle_err rfl
    simp only [hra, hrb]
    exact wfle_cons (ofBool_length _) hrest hw rfl rfl
  simp only [hbb]
  -- arm 26: NUMEQUALVERIFY
  by_cases h26 : (op == 0x9d) = true
  · rw [if_pos h26]
    rcases hstk : s.stack with _ | ⟨b, tl⟩
    · exact wfle_err rfl
    rcases tl with _ | ⟨a, rest⟩
    · exact wfle_err rfl
    simp only [hstk]
    rcases hra : readNum? a with _ | av
    · exact wfle_err rfl
    rcases hrb : readNum? b with _ | bv
    · exact wfle_err rfl
    simp only [hra, hrb]
    by_cases hab : (av == bv) = true
    · rw [if_pos hab]
      exact fc_stk hw rfl (fun z hz => by rw [hstk]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hz))
    rw [if_neg hab]; exact wfle_err rfl
  rw [if_neg h26]
  -- arm 27: WITHIN
  by_cases h27 : (op == 0xa5) = true
  · rw [if_pos h27]
    rcases hstk : s.stack with _ | ⟨mx, tl⟩
    · exact wfle_err rfl
    rcases tl with _ | ⟨mn, tl2⟩
    · exact wfle_err rfl
    rcases tl2 with _ | ⟨x, rest⟩
    · exact wfle_err rfl
    simp only [hstk]
    rcases hrx : readNum? x with _ | xv
    · exact wfle_err rfl
    rcases hrmn : readNum? mn with _ | mnv
    · exact wfle_err rfl
    rcases hrmx : readNum? mx with _ | mxv
    · exact wfle_err rfl
    simp only [hrx, hrmn, hrmx]
    exact wfle_cons (ofBool_length _)
      (fun z hz => hw.1 z (by rw [hstk]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hz)))) hw rfl rfl
  rw [if_neg h27]
  -- arm 28: bitwise AND/OR/XOR
  rcases hbo : bitwiseOp? op with _ | fbo
  rotate_left
  · simp only [hbo]
    rcases hstk : s.stack with _ | ⟨b, tl⟩
    · exact wfle_err rfl
    rcases tl with _ | ⟨a, rest⟩
    · exact wfle_err rfl
    have hrest : ∀ z ∈ rest, z.length ≤ maxItemLen :=
      fun z hz => hw.1 z (by rw [hstk]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hz))
    have ha : a.length ≤ maxItemLen := hw.1 a (by rw [hstk]; exact List.mem_cons_of_mem _ List.mem_cons_self)
    simp only [hstk]
    rcases hzip : zipBytewise fbo a b with _ | r
    · exact wfle_err rfl
    simp only [hzip]
    refine wfle_cons (b := r) ?_ hrest hw rfl rfl
    rw [fc_zipBytewise_len fbo a b r hzip]; exact ha
  simp only [hbo]
  -- arm 29: hashes
  rcases hho : hashOp? op with _ | hf
  rotate_left
  · simp only [hho]
    rcases hstk : s.stack with _ | ⟨x, rest⟩
    · exact wfle_err rfl
    simp only [hstk]
    exact wfle_cons (b := hf x) (fc_hashOp_len hho x)
      (fun z hz => hw.1 z (by rw [hstk]; exact List.mem_cons_of_mem _ hz)) hw rfl rfl
  simp only [hho]
  -- arm 30: DEPTH
  by_cases h30 : (op == Opcode.OP_DEPTH) = true
  · rw [if_pos h30]
    exact wfle_push (bigIntToVmNumber_ofNat_length s.stack.length
      (by have hb := hmem.1; simp only [maxMemorySlots] at hb; omega)) hw
  rw [if_neg h30]
  -- arm 31: SIZE
  by_cases h31 : (op == Opcode.OP_SIZE) = true
  · rw [if_pos h31]
    rcases hstk : s.stack with _ | ⟨x, rest⟩
    · exact wfle_err rfl
    simp only [hstk]
    refine wfle_cons (b := ofNum (Int.ofNat x.length)) ?_
      (fun z hz => hw.1 z (by rw [hstk]; exact hz)) hw rfl rfl
    apply bigIntToVmNumber_ofNat_length
    have hxlen : x.length ≤ maxItemLen := hw.1 x (by rw [hstk]; exact List.mem_cons_self)
    simp only [maxItemLen] at hxlen; omega
  rw [if_neg h31]
  -- arm 32: IFDUP
  by_cases h32 : (op == Opcode.OP_IFDUP) = true
  · rw [if_pos h32]
    rcases hstk : s.stack with _ | ⟨x, rest⟩
    · exact wfle_err rfl
    simp only [hstk]
    by_cases ht : isTruthy x = true
    · rw [if_pos ht]
      refine fc_stk hw rfl (fun z hz => ?_)
      rw [hstk]; simp only [List.mem_cons] at hz ⊢; rcases hz with h|h|h <;> simp_all
    rw [if_neg ht]; exact Or.inl (WFlen_advance s hw)
  rw [if_neg h32]
  -- arm 33: 2DROP
  by_cases h33 : (op == Opcode.OP_2DROP) = true
  · rw [if_pos h33]
    rcases hstk : s.stack with _ | ⟨x, tl⟩
    · exact wfle_err rfl
    rcases tl with _ | ⟨y, rest⟩
    · exact wfle_err rfl
    simp only [hstk]
    exact fc_stk hw rfl (fun z hz => by rw [hstk]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hz))
  rw [if_neg h33]
  -- arm 34: 2DUP
  by_cases h34 : (op == Opcode.OP_2DUP) = true
  · rw [if_pos h34]
    rcases hstk : s.stack with _ | ⟨a, tl⟩
    · exact wfle_err rfl
    rcases tl with _ | ⟨b, rest⟩
    · exact wfle_err rfl
    simp only [hstk]
    refine fc_stk hw rfl (fun z hz => ?_)
    rw [hstk]; simp only [List.mem_cons] at hz ⊢; rcases hz with h|h|h|h|h <;> simp_all
  rw [if_neg h34]
  -- arm 35: 3DUP
  by_cases h35 : (op == Opcode.OP_3DUP) = true
  · rw [if_pos h35]
    rcases hstk : s.stack with _ | ⟨a, tl⟩
    · exact wfle_err rfl
    rcases tl with _ | ⟨b, tl2⟩
    · exact wfle_err rfl
    rcases tl2 with _ | ⟨c, rest⟩
    · exact wfle_err rfl
    simp only [hstk]
    refine fc_stk hw rfl (fun z hz => ?_)
    rw [hstk]; simp only [List.mem_cons] at hz ⊢; rcases hz with h|h|h|h|h|h|h <;> simp_all
  rw [if_neg h35]
  -- arm 36: 2OVER
  by_cases h36 : (op == Opcode.OP_2OVER) = true
  · rw [if_pos h36]
    rcases hstk : s.stack with _ | ⟨a, tl⟩
    · exact wfle_err rfl
    rcases tl with _ | ⟨b, tl2⟩
    · exact wfle_err rfl
    rcases tl2 with _ | ⟨c, tl3⟩
    · exact wfle_err rfl
    rcases tl3 with _ | ⟨d, rest⟩
    · exact wfle_err rfl
    simp only [hstk]
    refine fc_stk hw rfl (fun z hz => ?_)
    rw [hstk]; simp only [List.mem_cons] at hz ⊢; rcases hz with h|h|h|h|h|h|h <;> simp_all
  rw [if_neg h36]
  -- arm 37: 2ROT
  by_cases h37 : (op == Opcode.OP_2ROT) = true
  · rw [if_pos h37]
    rcases hstk : s.stack with _ | ⟨a, tl⟩
    · exact wfle_err rfl
    rcases tl with _ | ⟨b, tl2⟩
    · exact wfle_err rfl
    rcases tl2 with _ | ⟨c, tl3⟩
    · exact wfle_err rfl
    rcases tl3 with _ | ⟨d, tl4⟩
    · exact wfle_err rfl
    rcases tl4 with _ | ⟨e, tl5⟩
    · exact wfle_err rfl
    rcases tl5 with _ | ⟨ff, rest⟩
    · exact wfle_err rfl
    simp only [hstk]
    refine fc_stk hw rfl (fun z hz => ?_)
    rw [hstk]; simp only [List.mem_cons] at hz ⊢; rcases hz with h|h|h|h|h|h|h <;> simp_all
  rw [if_neg h37]
  -- arm 38: 2SWAP
  by_cases h38 : (op == Opcode.OP_2SWAP) = true
  · rw [if_pos h38]
    rcases hstk : s.stack with _ | ⟨a, tl⟩
    · exact wfle_err rfl
    rcases tl with _ | ⟨b, tl2⟩
    · exact wfle_err rfl
    rcases tl2 with _ | ⟨c, tl3⟩
    · exact wfle_err rfl
    rcases tl3 with _ | ⟨d, rest⟩
    · exact wfle_err rfl
    simp only [hstk]
    refine fc_stk hw rfl (fun z hz => ?_)
    rw [hstk]; simp only [List.mem_cons] at hz ⊢; rcases hz with h|h|h|h|h <;> simp_all
  rw [if_neg h38]
  -- arm 39: CAT (EXCLUDED)
  rw [if_neg (by simp [hcat])]
  -- arm 40: SPLIT
  by_cases h40 : (op == 0x7f) = true
  · rw [if_pos h40]
    rcases hstk : s.stack with _ | ⟨n, tl⟩
    · exact wfle_err rfl
    rcases tl with _ | ⟨x, rest⟩
    · exact wfle_err rfl
    simp only [hstk]
    have hrest : ∀ z ∈ rest, z.length ≤ maxItemLen :=
      fun z hz => hw.1 z (by rw [hstk]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hz))
    have hx : x.length ≤ maxItemLen := hw.1 x (by rw [hstk]; exact List.mem_cons_of_mem _ List.mem_cons_self)
    by_cases hi : (toNum n).toNat ≤ x.length
    · rw [if_pos hi]
      refine wfle_cons (b := x.drop (toNum n).toNat) ?_ ?_ hw rfl rfl
      · rw [List.length_drop]; omega
      intro z hz
      rcases List.mem_cons.mp hz with rfl | hz
      · rw [List.length_take]; omega
      exact hrest z hz
    rw [if_neg hi]; exact wfle_err rfl
  rw [if_neg h40]
  -- arm 41: BIN2NUM
  by_cases h41 : (op == 0x81) = true
  · rw [if_pos h41]
    rcases hstk : s.stack with _ | ⟨x, rest⟩
    · exact wfle_err rfl
    simp only [hstk]
    refine wfle_cons (b := ofNum (toNum x)) ?_
      (fun z hz => hw.1 z (by rw [hstk]; exact List.mem_cons_of_mem _ hz)) hw rfl rfl
    have hx : x.length ≤ maxItemLen := hw.1 x (by rw [hstk]; exact List.mem_cons_self)
    exact Nat.le_trans (fc_bin2num_len x) hx
  rw [if_neg h41]
  -- arm 42: NUM2BIN
  by_cases h42 : (op == 0x80) = true
  · rw [if_pos h42]
    rcases hstk : s.stack with _ | ⟨sz, tl⟩
    · exact wfle_err rfl
    rcases tl with _ | ⟨n, rest⟩
    · exact wfle_err rfl
    have hrest : ∀ z ∈ rest, z.length ≤ maxItemLen :=
      fun z hz => hw.1 z (by rw [hstk]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hz))
    simp only [hstk]
    rcases hsz : readNum? sz with _ | szv
    · exact wfle_err rfl
    simp only [hsz]
    split
    · exact wfle_err rfl
    rcases hnb : num2bin (toNum n) szv.toNat with _ | r
    · exact wfle_err rfl
    simp only [hnb]
    split
    · rename_i hr
      refine wfle_cons (b := r) ?_ hrest hw rfl rfl
      simp only [maxItemLen, maxNumLen] at hr ⊢; omega
    exact wfle_err rfl
  rw [if_neg h42]
  -- arm 43: CODESEPARATOR
  by_cases h43 : (op == Opcode.OP_CODESEPARATOR) = true
  · rw [if_pos h43]; exact Or.inl hw
  rw [if_neg h43]
  -- arm 44: NOP / NOP1..10
  by_cases h44 : (op == Opcode.OP_NOP || (0xb0 ≤ op.toNat && op.toNat ≤ 0xb9)) = true
  · rw [if_pos h44]; exact Or.inl (WFlen_advance s hw)
  rw [if_neg h44]
  -- arm 45: else (unimplemented)
  exact wfle_err rfl

/-- Tail-bound when the whole result stack's members are drawn from `s.stack`. -/
theorem fcw_tail_sub {s : State} (hs : ∀ i ∈ s.stack, i.length ≤ maxItemLen)
    {L : Stack} (hL : ∀ y ∈ L, y ∈ s.stack) :
    ∀ (r : Bytes) (rest : Stack), L = r :: rest → ∀ y ∈ rest, y.length ≤ maxItemLen := by
  intro r rest heq y hy
  exact hs y (hL y (by rw [heq]; exact List.mem_cons_of_mem _ hy))

/-- Tail-bound when the result stack is `top :: tail` with `tail` already bounded. -/
theorem fcw_tail_cons {top : Bytes} {tail : Stack}
    (h : ∀ y ∈ tail, y.length ≤ maxItemLen) :
    ∀ (r : Bytes) (rest : Stack), (top :: tail) = r :: rest → ∀ y ∈ rest, y.length ≤ maxItemLen := by
  intro r rest heq
  rw [List.cons.injEq] at heq
  obtain ⟨-, rfl⟩ := heq
  exact h

set_option linter.unusedSimpArgs false in
set_option maxHeartbeats 800000 in
theorem frozenCore_wrap : ∀ (op : UInt8) (data : Bytes) (s : State), WF s →
    (∀ y ∈ (stepInstr op data s).alt, y.length ≤ maxItemLen) ∧
    (∀ (r : Bytes) (rest : Stack), (stepInstr op data s).stack = r :: rest →
        ∀ y ∈ rest, y.length ≤ maxItemLen) := by
  intro op data s hwf
  have hstk : ∀ i ∈ s.stack, i.length ≤ maxItemLen := hwf.1.1
  have halt : ∀ i ∈ s.alt, i.length ≤ maxItemLen := hwf.1.2
  unfold stepInstr
  -- 1. pushes
  by_cases hpush : Opcode.isPushOp op = true
  · rw [if_pos hpush]
    by_cases hmin : (!isMinimalPush op data) = true
    · rw [if_pos hmin]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
    · rw [if_neg hmin]
      by_cases hlen : (pushValue op data).length > maxItemLen
      · rw [if_pos hlen]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
      · rw [if_neg hlen]; exact ⟨halt, fcw_tail_cons (fun y hy => hstk y hy)⟩
  rw [if_neg hpush]
  -- 2. IF / NOTIF
  by_cases hif : (op == Opcode.OP_IF || op == Opcode.OP_NOTIF) = true
  · rw [if_pos hif]
    by_cases hact : s.executionIsActive = true
    · rw [if_pos hact]
      rcases hs2 : s.stack with _ | ⟨x, xs⟩
      · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
      · simp only [hs2]
        refine ⟨halt, fcw_tail_sub hstk ?_⟩
        intro y hy; rw [hs2]; exact List.mem_cons_of_mem _ hy
    · rw [if_neg hact]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
  rw [if_neg hif]
  -- 3. ELSE
  by_cases hels : (op == Opcode.OP_ELSE) = true
  · rw [if_pos hels]
    rcases hc : s.ctrl with _ | ⟨c, crest⟩
    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
    · rcases c with b | m | ⟨ar, n⟩ <;> exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
  rw [if_neg hels]
  -- 4. ENDIF
  by_cases hend : (op == Opcode.OP_ENDIF) = true
  · rw [if_pos hend]
    rcases hc : s.ctrl with _ | ⟨c, crest⟩
    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
    · rcases c with b | m | ⟨ar, n⟩ <;> exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
  rw [if_neg hend]
  -- 5. VERIFY
  by_cases hver : (op == Opcode.OP_VERIFY) = true
  · rw [if_pos hver]
    rcases hs2 : s.stack with _ | ⟨x, xs⟩
    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
    · simp only [hs2]
      by_cases hit : isTruthy x = true
      · rw [if_pos hit]
        refine ⟨halt, fcw_tail_sub hstk ?_⟩
        intro y hy; rw [hs2]; exact List.mem_cons_of_mem _ hy
      · rw [if_neg hit]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
  rw [if_neg hver]
  -- 6. RETURN
  by_cases hret : (op == Opcode.OP_RETURN) = true
  · rw [if_pos hret]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
  rw [if_neg hret]
  -- 7. BEGIN
  by_cases hbeg : (op == Opcode.OP_BEGIN) = true
  · rw [if_pos hbeg]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
  rw [if_neg hbeg]
  -- 8. UNTIL
  by_cases hunt : (op == Opcode.OP_UNTIL) = true
  · rw [if_pos hunt]
    rcases hc : s.ctrl with _ | ⟨c, crest⟩
    · simp only [hc]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
    · rcases hcc : c with b | m | ⟨ar, n⟩
      · simp only [hc, hcc]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
      · rcases hse : s.stack with _ | ⟨x, xs⟩
        · simp only [hc, hcc, hse]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
        · simp only [hc, hcc, hse]
          by_cases hit : isTruthy x = true
          · rw [if_pos hit]
            exact ⟨halt, fcw_tail_sub hstk (fun y hy => by rw [hse]; exact List.mem_cons_of_mem _ hy)⟩
          · rw [if_neg hit]
            exact ⟨halt, fcw_tail_sub hstk (fun y hy => by rw [hse]; exact List.mem_cons_of_mem _ hy)⟩
      · simp only [hc, hcc]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
  rw [if_neg hunt]
  -- 9. DUP
  by_cases hdup : (op == Opcode.OP_DUP) = true
  · rw [if_pos hdup]
    rcases hs2 : s.stack with _ | ⟨x, xs⟩
    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
    · exact ⟨halt, fcw_tail_cons (fun y hy => hstk y hy)⟩
  rw [if_neg hdup]
  -- 10. DROP
  by_cases hdrop : (op == Opcode.OP_DROP) = true
  · rw [if_pos hdrop]
    rcases hs2 : s.stack with _ | ⟨x, xs⟩
    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
    · refine ⟨halt, fcw_tail_sub hstk ?_⟩
      intro y hy; rw [hs2]; exact List.mem_cons_of_mem _ hy
  rw [if_neg hdrop]
  -- 11. OVER
  by_cases hover : (op == Opcode.OP_OVER) = true
  · rw [if_pos hover]
    rcases hs2 : s.stack with _ | ⟨x, tl⟩
    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
    · rcases tl with _ | ⟨y, xs⟩
      · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
      · refine ⟨halt, fcw_tail_sub hstk ?_⟩
        intro w hw; rw [hs2]; simp only [List.mem_cons] at hw ⊢
        rcases hw with h|h|h|h <;> simp [h]
  rw [if_neg hover]
  -- 12. SWAP
  by_cases hswap : (op == Opcode.OP_SWAP) = true
  · rw [if_pos hswap]
    rcases hs2 : s.stack with _ | ⟨x, tl⟩
    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
    · rcases tl with _ | ⟨y, xs⟩
      · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
      · refine ⟨halt, fcw_tail_sub hstk ?_⟩
        intro w hw; rw [hs2]; simp only [List.mem_cons] at hw ⊢
        rcases hw with h|h|h <;> simp [h]
  rw [if_neg hswap]
  -- 13. ROT
  by_cases hrot : (op == Opcode.OP_ROT) = true
  · rw [if_pos hrot]
    rcases hs2 : s.stack with _ | ⟨x, tl⟩
    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
    · rcases tl with _ | ⟨y, tl2⟩
      · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
      · rcases tl2 with _ | ⟨z, xs⟩
        · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
        · refine ⟨halt, fcw_tail_sub hstk ?_⟩
          intro w hw; rw [hs2]; simp only [List.mem_cons] at hw ⊢
          rcases hw with h|h|h|h <;> simp [h]
  rw [if_neg hrot]
  -- 14. NIP
  by_cases hnip : (op == Opcode.OP_NIP) = true
  · rw [if_pos hnip]
    rcases hs2 : s.stack with _ | ⟨x, tl⟩
    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
    · rcases tl with _ | ⟨y, xs⟩
      · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
      · refine ⟨halt, fcw_tail_sub hstk ?_⟩
        intro w hw; rw [hs2]; simp only [List.mem_cons] at hw ⊢
        rcases hw with h|h <;> simp [h]
  rw [if_neg hnip]
  -- 15. TUCK
  by_cases htuck : (op == Opcode.OP_TUCK) = true
  · rw [if_pos htuck]
    rcases hs2 : s.stack with _ | ⟨x, tl⟩
    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
    · rcases tl with _ | ⟨y, xs⟩
      · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
      · refine ⟨halt, fcw_tail_sub hstk ?_⟩
        intro w hw; rw [hs2]; simp only [List.mem_cons] at hw ⊢
        rcases hw with h|h|h|h <;> simp [h]
  rw [if_neg htuck]
  -- 16. TOALTSTACK
  by_cases htoalt : (op == Opcode.OP_TOALTSTACK) = true
  · rw [if_pos htoalt]
    rcases hs2 : s.stack with _ | ⟨x, xs⟩
    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
    · simp only [hs2]
      refine ⟨?_, fcw_tail_sub hstk ?_⟩
      · intro y hy
        rcases List.mem_cons.mp hy with h | h
        · rw [h]; exact hstk x (by rw [hs2]; exact List.mem_cons_self)
        · exact halt y h
      · intro w hw; rw [hs2]; exact List.mem_cons_of_mem _ hw
  rw [if_neg htoalt]
  -- 17. FROMALTSTACK
  by_cases hfromalt : (op == Opcode.OP_FROMALTSTACK) = true
  · rw [if_pos hfromalt]
    rcases ha2 : s.alt with _ | ⟨x, a⟩
    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
    · refine ⟨?_, fcw_tail_cons (fun y hy => hstk y hy)⟩
      intro y hy; exact halt y (by rw [ha2]; exact List.mem_cons_of_mem _ hy)
  rw [if_neg hfromalt]
  -- 18. PICK / ROLL
  by_cases hpick : (op == Opcode.OP_PICK || op == Opcode.OP_ROLL) = true
  · rw [if_pos hpick]
    rcases hs2 : s.stack with _ | ⟨nb, rest⟩
    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
    · simp only [hs2]
      rcases hrn : rest[(vmNumberToBigInt nb).toNat]? with _ | v
      · simp only [hrn]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
      · simp only [hrn]
        by_cases hpp : (op == Opcode.OP_PICK) = true
        · rw [if_pos hpp]
          refine ⟨halt, fcw_tail_cons ?_⟩
          intro y hy; exact hstk y (by rw [hs2]; exact List.mem_cons_of_mem _ hy)
        · rw [if_neg hpp]
          refine ⟨halt, fcw_tail_cons ?_⟩
          intro y hy
          unfold removeNth at hy
          rcases List.mem_append.mp hy with h | h
          · exact hstk y (by rw [hs2]; exact List.mem_cons_of_mem _ (List.mem_of_mem_take h))
          · exact hstk y (by rw [hs2]; exact List.mem_cons_of_mem _ (List.mem_of_mem_drop h))
  rw [if_neg hpick]
  -- 19. arithmetic (if-let)
  rcases hK : Opcode.arithKind? op with _ | k
  · simp only [hK]
    -- 20. EQUAL
    by_cases heq : (op == Opcode.OP_EQUAL) = true
    · rw [if_pos heq]
      rcases hs2 : s.stack with _ | ⟨x, tl⟩
      · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
      · rcases tl with _ | ⟨y, rest⟩
        · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
        · refine ⟨halt, fcw_tail_cons ?_⟩
          intro z hz; exact hstk z (by rw [hs2]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hz))
    rw [if_neg heq]
    -- 21. EQUALVERIFY
    by_cases heqv : (op == Opcode.OP_EQUALVERIFY) = true
    · rw [if_pos heqv]
      rcases hs2 : s.stack with _ | ⟨x, tl⟩
      · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
      · rcases tl with _ | ⟨y, rest⟩
        · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
        · simp only [hs2]
          by_cases hxy : (x == y) = true
          · rw [if_pos hxy]
            refine ⟨halt, fcw_tail_sub hstk ?_⟩
            intro z hz; rw [hs2]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hz)
          · rw [if_neg hxy]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
    rw [if_neg heqv]
    -- 22. unaryNumOp (if-let)
    rcases hUN : unaryNumOp? op with _ | f
    · simp only [hUN]
      -- 23. unaryBoolOp (if-let)
      rcases hUB : unaryBoolOp? op with _ | f
      · simp only [hUB]
        -- 24. binNumOp (if-let)
        rcases hBN : binNumOp? op with _ | f
        · simp only [hBN]
          -- 25. binBoolOp (if-let)
          rcases hBB : binBoolOp? op with _ | f
          · simp only [hBB]
            -- 26. NUMEQUALVERIFY 0x9d
            by_cases h9d : (op == 0x9d) = true
            · rw [if_pos h9d]
              rcases hs2 : s.stack with _ | ⟨b, tl⟩
              · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
              · rcases tl with _ | ⟨a, rest⟩
                · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                · rcases hra : readNum? a with _ | av
                  · simp only [hra]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                  · rcases hrb : readNum? b with _ | bv
                    · simp only [hra, hrb]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                    · simp only [hra, hrb]
                      by_cases hab : (av == bv) = true
                      · rw [if_pos hab]
                        refine ⟨halt, fcw_tail_sub hstk ?_⟩
                        intro z hz; rw [hs2]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hz)
                      · rw [if_neg hab]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
            rw [if_neg h9d]
            -- 27. WITHIN 0xa5
            by_cases ha5 : (op == 0xa5) = true
            · rw [if_pos ha5]
              rcases hs2 : s.stack with _ | ⟨mx, tl⟩
              · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
              · rcases tl with _ | ⟨mn, tl2⟩
                · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                · rcases tl2 with _ | ⟨x, rest⟩
                  · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                  · rcases hrx : readNum? x with _ | xv
                    · simp only [hrx]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                    · rcases hrn : readNum? mn with _ | mnv
                      · simp only [hrx, hrn]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                      · rcases hrmx : readNum? mx with _ | mxv
                        · simp only [hrx, hrn, hrmx]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                        · simp only [hrx, hrn, hrmx]
                          refine ⟨halt, fcw_tail_cons ?_⟩
                          intro z hz; exact hstk z (by rw [hs2]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hz)))
            rw [if_neg ha5]
            -- 28. bitwise (if-let)
            rcases hBI : bitwiseOp? op with _ | fb
            · simp only [hBI]
              -- 29. hash (if-let)
              rcases hHA : hashOp? op with _ | hh
              · simp only [hHA]
                -- 30. DEPTH
                by_cases hdep : (op == Opcode.OP_DEPTH) = true
                · rw [if_pos hdep]; exact ⟨halt, fcw_tail_cons (fun y hy => hstk y hy)⟩
                rw [if_neg hdep]
                -- 31. SIZE
                by_cases hsz : (op == Opcode.OP_SIZE) = true
                · rw [if_pos hsz]
                  rcases hs2 : s.stack with _ | ⟨x, rest⟩
                  · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                  · refine ⟨halt, fcw_tail_cons ?_⟩
                    intro y hy; exact hstk y (by rw [hs2]; exact hy)
                rw [if_neg hsz]
                -- 32. IFDUP
                by_cases hifd : (op == Opcode.OP_IFDUP) = true
                · rw [if_pos hifd]
                  rcases hs2 : s.stack with _ | ⟨x, rest⟩
                  · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                  · simp only [hs2]
                    by_cases hit : isTruthy x = true
                    · rw [if_pos hit]
                      refine ⟨halt, fcw_tail_cons ?_⟩
                      intro y hy; exact hstk y (by rw [hs2]; exact hy)
                    · rw [if_neg hit]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                rw [if_neg hifd]
                -- 33. 2DROP
                by_cases h2drop : (op == Opcode.OP_2DROP) = true
                · rw [if_pos h2drop]
                  rcases hs2 : s.stack with _ | ⟨a, tl⟩
                  · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                  · rcases tl with _ | ⟨b, rest⟩
                    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                    · refine ⟨halt, fcw_tail_sub hstk ?_⟩
                      intro y hy; rw [hs2]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hy)
                rw [if_neg h2drop]
                -- 34. 2DUP
                by_cases h2dup : (op == Opcode.OP_2DUP) = true
                · rw [if_pos h2dup]
                  rcases hs2 : s.stack with _ | ⟨a, tl⟩
                  · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                  · rcases tl with _ | ⟨b, rest⟩
                    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                    · refine ⟨halt, fcw_tail_sub hstk ?_⟩
                      intro w hw; rw [hs2]; simp only [List.mem_cons] at hw ⊢
                      rcases hw with h|h|h|h|h <;> simp [h]
                rw [if_neg h2dup]
                -- 35. 3DUP
                by_cases h3dup : (op == Opcode.OP_3DUP) = true
                · rw [if_pos h3dup]
                  rcases hs2 : s.stack with _ | ⟨a, tl⟩
                  · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                  · rcases tl with _ | ⟨b, tl2⟩
                    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                    · rcases tl2 with _ | ⟨c, rest⟩
                      · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                      · refine ⟨halt, fcw_tail_sub hstk ?_⟩
                        intro w hw; rw [hs2]; simp only [List.mem_cons] at hw ⊢
                        rcases hw with h|h|h|h|h|h|h <;> simp [h]
                rw [if_neg h3dup]
                -- 36. 2OVER
                by_cases h2over : (op == Opcode.OP_2OVER) = true
                · rw [if_pos h2over]
                  rcases hs2 : s.stack with _ | ⟨a, tl⟩
                  · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                  · rcases tl with _ | ⟨b, tl2⟩
                    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                    · rcases tl2 with _ | ⟨c, tl3⟩
                      · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                      · rcases tl3 with _ | ⟨d, rest⟩
                        · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                        · refine ⟨halt, fcw_tail_sub hstk ?_⟩
                          intro w hw; rw [hs2]; simp only [List.mem_cons] at hw ⊢
                          rcases hw with h|h|h|h|h|h|h <;> simp [h]
                rw [if_neg h2over]
                -- 37. 2ROT
                by_cases h2rot : (op == Opcode.OP_2ROT) = true
                · rw [if_pos h2rot]
                  rcases hs2 : s.stack with _ | ⟨a, tl⟩
                  · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                  · rcases tl with _ | ⟨b, tl2⟩
                    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                    · rcases tl2 with _ | ⟨c, tl3⟩
                      · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                      · rcases tl3 with _ | ⟨d, tl4⟩
                        · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                        · rcases tl4 with _ | ⟨e, tl5⟩
                          · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                          · rcases tl5 with _ | ⟨ff, rest⟩
                            · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                            · refine ⟨halt, fcw_tail_sub hstk ?_⟩
                              intro w hw; rw [hs2]; simp only [List.mem_cons] at hw ⊢
                              rcases hw with h|h|h|h|h|h|h <;> simp [h]
                rw [if_neg h2rot]
                -- 38. 2SWAP
                by_cases h2swap : (op == Opcode.OP_2SWAP) = true
                · rw [if_pos h2swap]
                  rcases hs2 : s.stack with _ | ⟨a, tl⟩
                  · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                  · rcases tl with _ | ⟨b, tl2⟩
                    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                    · rcases tl2 with _ | ⟨c, tl3⟩
                      · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                      · rcases tl3 with _ | ⟨d, rest⟩
                        · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                        · refine ⟨halt, fcw_tail_sub hstk ?_⟩
                          intro w hw; rw [hs2]; simp only [List.mem_cons] at hw ⊢
                          rcases hw with h|h|h|h|h <;> simp [h]
                rw [if_neg h2swap]
                -- 39. CAT 0x7e
                by_cases hcat : (op == 0x7e) = true
                · rw [if_pos hcat]
                  rcases hs2 : s.stack with _ | ⟨b, tl⟩
                  · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                  · rcases tl with _ | ⟨a, rest⟩
                    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                    · refine ⟨halt, fcw_tail_cons ?_⟩
                      intro y hy; exact hstk y (by rw [hs2]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hy))
                rw [if_neg hcat]
                -- 40. SPLIT 0x7f
                by_cases hspl : (op == 0x7f) = true
                · rw [if_pos hspl]
                  rcases hs2 : s.stack with _ | ⟨n, tl⟩
                  · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                  · rcases tl with _ | ⟨x, rest⟩
                    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                    · simp only [hs2]
                      by_cases hle : (toNum n).toNat ≤ x.length
                      · rw [if_pos hle]
                        refine ⟨halt, fcw_tail_cons ?_⟩
                        intro y hy
                        rcases List.mem_cons.mp hy with h | h
                        · rw [h]
                          exact Nat.le_trans (List.length_take_le' _ _)
                            (hstk x (by rw [hs2]; exact List.mem_cons_of_mem _ List.mem_cons_self))
                        · exact hstk y (by rw [hs2]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ h))
                      · rw [if_neg hle]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                rw [if_neg hspl]
                -- 41. BIN2NUM 0x81
                by_cases hb2n : (op == 0x81) = true
                · rw [if_pos hb2n]
                  rcases hs2 : s.stack with _ | ⟨x, rest⟩
                  · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                  · refine ⟨halt, fcw_tail_cons ?_⟩
                    intro y hy; exact hstk y (by rw [hs2]; exact List.mem_cons_of_mem _ hy)
                rw [if_neg hb2n]
                -- 42. NUM2BIN 0x80
                by_cases hn2b : (op == 0x80) = true
                · rw [if_pos hn2b]
                  rcases hs2 : s.stack with _ | ⟨sz, tl⟩
                  · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                  · rcases tl with _ | ⟨nn, rest⟩
                    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                    · rcases hsz2 : readNum? sz with _ | szv
                      · simp only [hsz2]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                      · simp only [hsz2]
                        by_cases hg : (nn.length > maxNumLen || szv < 0) = true
                        · rw [if_pos hg]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                        · rw [if_neg hg]
                          rcases hnb : num2bin (toNum nn) szv.toNat with _ | rr
                          · simp only [hnb]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                          · simp only [hnb]
                            by_cases hrl : rr.length ≤ maxNumLen
                            · rw [if_pos hrl]
                              refine ⟨halt, fcw_tail_cons ?_⟩
                              intro y hy; exact hstk y (by rw [hs2]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hy))
                            · rw [if_neg hrl]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                rw [if_neg hn2b]
                -- 43. CODESEPARATOR
                by_cases hcs : (op == Opcode.OP_CODESEPARATOR) = true
                · rw [if_pos hcs]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                rw [if_neg hcs]
                -- 44. NOP / 0xb0..0xb9
                by_cases hnop : (op == Opcode.OP_NOP || (0xb0 ≤ op.toNat && op.toNat ≤ 0xb9)) = true
                · rw [if_pos hnop]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                rw [if_neg hnop]
                -- 45. else
                exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
              · -- 29. hash arm
                rcases hs2 : s.stack with _ | ⟨x, rest⟩
                · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                · refine ⟨halt, fcw_tail_cons ?_⟩
                  intro y hy; exact hstk y (by rw [hs2]; exact List.mem_cons_of_mem _ hy)
            · -- 28. bitwise arm
              rcases hs2 : s.stack with _ | ⟨b, tl⟩
              · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
              · rcases tl with _ | ⟨a, rest⟩
                · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                · rcases hz : zipBytewise fb a b with _ | rr
                  · simp only [hz]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                  · simp only [hz]
                    refine ⟨halt, fcw_tail_cons ?_⟩
                    intro y hy; exact hstk y (by rw [hs2]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hy))
          · -- 25. binBoolOp arm
            rcases hs2 : s.stack with _ | ⟨b, tl⟩
            · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
            · rcases tl with _ | ⟨a, rest⟩
              · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
              · rcases hra : readNum? a with _ | av
                · simp only [hra]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                · rcases hrb : readNum? b with _ | bv
                  · simp only [hra, hrb]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                  · simp only [hra, hrb]
                    refine ⟨halt, fcw_tail_cons ?_⟩
                    intro y hy; exact hstk y (by rw [hs2]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hy))
        · -- 24. binNumOp arm
          rcases hs2 : s.stack with _ | ⟨b, tl⟩
          · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
          · rcases tl with _ | ⟨a, rest⟩
            · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
            · rcases hra : readNum? a with _ | av
              · simp only [hra]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
              · rcases hrb : readNum? b with _ | bv
                · simp only [hra, hrb]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
                · simp only [hra, hrb]
                  refine ⟨halt, fcw_tail_cons ?_⟩
                  intro y hy; exact hstk y (by rw [hs2]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hy))
      · -- 23. unaryBoolOp arm
        rcases hs2 : s.stack with _ | ⟨x, rest⟩
        · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
        · rcases hrx : readNum? x with _ | xv
          · simp only [hrx]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
          · simp only [hrx]
            refine ⟨halt, fcw_tail_cons ?_⟩
            intro y hy; exact hstk y (by rw [hs2]; exact List.mem_cons_of_mem _ hy)
    · -- 22. unaryNumOp arm
      rcases hs2 : s.stack with _ | ⟨x, rest⟩
      · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
      · rcases hrx : readNum? x with _ | xv
        · simp only [hrx]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
        · simp only [hrx]
          refine ⟨halt, fcw_tail_cons ?_⟩
          intro y hy; exact hstk y (by rw [hs2]; exact List.mem_cons_of_mem _ hy)
  · -- 19. arithmetic arm
    clear hK
    rcases hs2 : s.stack with _ | ⟨b, tl⟩
    · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
    · rcases tl with _ | ⟨a, rest⟩
      · exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
      · rcases hra : readNum? a with _ | av
        · simp only [hra]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
        · rcases hrb : readNum? b with _ | bv
          · simp only [hra, hrb]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
          · simp only [hra, hrb]
            cases k
            · exact ⟨halt, fcw_tail_cons (fun y hy => hstk y (by rw [hs2]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hy)))⟩
            · by_cases hbv : (bv == 0) = true
              · rw [if_pos hbv]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
              · rw [if_neg hbv]
                refine ⟨halt, fcw_tail_cons ?_⟩
                intro y hy; exact hstk y (by rw [hs2]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hy))
            · by_cases hbv : (bv == 0) = true
              · rw [if_pos hbv]; exact ⟨halt, fcw_tail_sub hstk (fun _ h => h)⟩
              · rw [if_neg hbv]
                refine ⟨halt, fcw_tail_cons ?_⟩
                intro y hy; exact hstk y (by rw [hs2]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hy))
            · exact ⟨halt, fcw_tail_cons (fun y hy => hstk y (by rw [hs2]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hy)))⟩
            · exact ⟨halt, fcw_tail_cons (fun y hy => hstk y (by rw [hs2]; exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hy)))⟩

/-! ================= Group 4: Hbudget & Hframe over the wrapper dispatch ================= -/

/-! ### Per-arm closers (walking the frozen `stepInstr`/`stepInstrExt` opcode dispatch). -/

set_option hygiene false in
/-- Budget-arm closer: split residual matches/ifs, reduce record projections, close by `rfl`. -/
local macro "g4bc" : tactic =>
  `(tactic| (repeat' (first
      | rfl
      | (simp only [State.advance, State.push, State.setErr]; done)
      | split)))

set_option hygiene false in
/-- Frame-arm closer: `frameCount` of the result ctrl is ≤ `frameCount s.ctrl + 1` in every arm
    (unchanged for cond/mark pushes and pops; `+1` only for an OP_INVOKE frame push). -/
local macro "g4fc" : tactic =>
  `(tactic| (repeat' (first
      | exact Nat.le_succ _
      | exact Nat.le_refl _
      | split
      | (simp_all only [frameCount, State.advance, State.push, State.setErr]; omega))))

/-! ### `enforceStepLimits` preserves budget and ctrl (mirrors `enforceStepLimits_metrics`). -/

theorem enforceStepLimits_budget (t : State) : (enforceStepLimits t).budget = t.budget := by
  unfold enforceStepLimits
  split
  · rfl
  · split
    · rfl
    · split
      · rfl
      · split
        · rfl
        · rfl

theorem enforceStepLimits_ctrl (t : State) : (enforceStepLimits t).ctrl = t.ctrl := by
  unfold enforceStepLimits
  split
  · rfl
  · split
    · rfl
    · split
      · rfl
      · split
        · rfl
        · rfl

/-! ### Helper transitions preserve budget and ctrl (they never write those fields). -/

set_option maxHeartbeats 800000 in
theorem introspectIndexed_budget (base : State) (rest : Stack) (i : Int)
    (lookup : Nat → Option Bytes) (cl : Bool) :
    (introspectIndexed base rest i lookup cl).budget = base.budget := by
  unfold introspectIndexed; repeat' (first | rfl | split)

set_option maxHeartbeats 800000 in
theorem introspectIndexed_ctrl (base : State) (rest : Stack) (i : Int)
    (lookup : Nat → Option Bytes) (cl : Bool) :
    (introspectIndexed base rest i lookup cl).ctrl = base.ctrl := by
  unfold introspectIndexed; repeat' (first | rfl | split)

theorem introspectIndexed_frameCount (base : State) (rest : Stack) (i : Int)
    (lookup : Nat → Option Bytes) (cl : Bool) :
    frameCount (introspectIndexed base rest i lookup cl).ctrl ≤ frameCount base.ctrl + 1 := by
  rw [introspectIndexed_ctrl]; exact Nat.le_succ _

set_option maxHeartbeats 800000 in
theorem verifyTopInPlace_budget (s : State) : (verifyTopInPlace s).budget = s.budget := by
  unfold verifyTopInPlace; repeat' (first | rfl | split)

set_option maxHeartbeats 800000 in
theorem verifyTopInPlace_ctrl (s : State) : (verifyTopInPlace s).ctrl = s.ctrl := by
  unfold verifyTopInPlace; repeat' (first | rfl | split)

theorem verifyTopInPlace_frameCount (s : State) :
    frameCount (verifyTopInPlace s).ctrl ≤ frameCount s.ctrl + 1 := by
  rw [verifyTopInPlace_ctrl]; exact Nat.le_succ _

set_option maxHeartbeats 800000 in
theorem opCheckSig_budget (crypto : Secp256k1) (p : Program) (s : State) :
    (opCheckSig crypto p s).budget = s.budget := by
  unfold opCheckSig; simp only []; repeat' (first | rfl | split)

set_option maxHeartbeats 800000 in
theorem opCheckSig_ctrl (crypto : Secp256k1) (p : Program) (s : State) :
    (opCheckSig crypto p s).ctrl = s.ctrl := by
  unfold opCheckSig; simp only []; repeat' (first | rfl | split)

theorem opCheckSig_frameCount (crypto : Secp256k1) (p : Program) (s : State) :
    frameCount (opCheckSig crypto p s).ctrl ≤ frameCount s.ctrl + 1 := by
  rw [opCheckSig_ctrl]; exact Nat.le_succ _

set_option maxHeartbeats 800000 in
theorem opCheckDataSig_budget (crypto : Secp256k1) (s : State) :
    (opCheckDataSig crypto s).budget = s.budget := by
  unfold opCheckDataSig; simp only []; repeat' (first | rfl | split)

set_option maxHeartbeats 800000 in
theorem opCheckDataSig_ctrl (crypto : Secp256k1) (s : State) :
    (opCheckDataSig crypto s).ctrl = s.ctrl := by
  unfold opCheckDataSig; simp only []; repeat' (first | rfl | split)

theorem opCheckDataSig_frameCount (crypto : Secp256k1) (s : State) :
    frameCount (opCheckDataSig crypto s).ctrl ≤ frameCount s.ctrl + 1 := by
  rw [opCheckDataSig_ctrl]; exact Nat.le_succ _

set_option maxHeartbeats 800000 in
theorem opCheckMultiSig_budget (crypto : Secp256k1) (p : Program) (s : State) :
    (opCheckMultiSig crypto p s).budget = s.budget := by
  unfold opCheckMultiSig; simp only []; repeat' (first | rfl | split)

set_option maxHeartbeats 800000 in
theorem opCheckMultiSig_ctrl (crypto : Secp256k1) (p : Program) (s : State) :
    (opCheckMultiSig crypto p s).ctrl = s.ctrl := by
  unfold opCheckMultiSig; simp only []; repeat' (first | rfl | split)

theorem opCheckMultiSig_frameCount (crypto : Secp256k1) (p : Program) (s : State) :
    frameCount (opCheckMultiSig crypto p s).ctrl ≤ frameCount s.ctrl + 1 := by
  rw [opCheckMultiSig_ctrl]; exact Nat.le_succ _

/-! ### The frozen keystone core `stepInstr`: budget invariant + frame bound (full dispatch walk). -/

set_option maxHeartbeats 1600000 in
theorem stepInstr_budget (op : UInt8) (data : Bytes) (s : State) :
    (stepInstr op data s).budget = s.budget := by
  unfold stepInstr
  cases hpush : Opcode.isPushOp op with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hIF : (op == Opcode.OP_IF || op == Opcode.OP_NOTIF) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hELSE : (op == Opcode.OP_ELSE) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hENDIF : (op == Opcode.OP_ENDIF) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hV : (op == Opcode.OP_VERIFY) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hR : (op == Opcode.OP_RETURN) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hBEGIN : (op == Opcode.OP_BEGIN) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hUNTIL : (op == Opcode.OP_UNTIL) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hDUP : (op == Opcode.OP_DUP) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hDROP : (op == Opcode.OP_DROP) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hOVER : (op == Opcode.OP_OVER) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hSWAP : (op == Opcode.OP_SWAP) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hROT : (op == Opcode.OP_ROT) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hNIP : (op == Opcode.OP_NIP) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hTUCK : (op == Opcode.OP_TUCK) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hTO : (op == Opcode.OP_TOALTSTACK) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hFROM : (op == Opcode.OP_FROMALTSTACK) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hPR : (op == Opcode.OP_PICK || op == Opcode.OP_ROLL) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hK : Opcode.arithKind? op with
  | some k => g4bc
  | none =>
  cases hEQ : (op == Opcode.OP_EQUAL) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hEV : (op == Opcode.OP_EQUALVERIFY) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hUN : unaryNumOp? op with
  | some f => g4bc
  | none =>
  cases hUB : unaryBoolOp? op with
  | some f => g4bc
  | none =>
  cases hBN : binNumOp? op with
  | some f => g4bc
  | none =>
  cases hBB : binBoolOp? op with
  | some f => g4bc
  | none =>
  cases h9d : (op == 0x9d) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases ha5 : (op == 0xa5) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hBW : bitwiseOp? op with
  | some f => g4bc
  | none =>
  cases hH : hashOp? op with
  | some h => g4bc
  | none =>
  cases hDEP : (op == Opcode.OP_DEPTH) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hSIZE : (op == Opcode.OP_SIZE) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hIFD : (op == Opcode.OP_IFDUP) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h2DR : (op == Opcode.OP_2DROP) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h2DU : (op == Opcode.OP_2DUP) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h3DU : (op == Opcode.OP_3DUP) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h2OV : (op == Opcode.OP_2OVER) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h2RO : (op == Opcode.OP_2ROT) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h2SW : (op == Opcode.OP_2SWAP) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h7e : (op == 0x7e) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h7f : (op == 0x7f) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h81 : (op == 0x81) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h80 : (op == 0x80) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hCS : (op == Opcode.OP_CODESEPARATOR) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hNOP : (op == Opcode.OP_NOP || (0xb0 ≤ op.toNat && op.toNat ≤ 0xb9)) with
  | true => simp only [if_true]; g4bc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  g4bc

set_option maxHeartbeats 1600000 in
theorem stepInstr_frameCount_le (op : UInt8) (data : Bytes) (s : State) :
    frameCount (stepInstr op data s).ctrl ≤ frameCount s.ctrl + 1 := by
  unfold stepInstr
  cases hpush : Opcode.isPushOp op with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hIF : (op == Opcode.OP_IF || op == Opcode.OP_NOTIF) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hELSE : (op == Opcode.OP_ELSE) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hENDIF : (op == Opcode.OP_ENDIF) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hV : (op == Opcode.OP_VERIFY) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hR : (op == Opcode.OP_RETURN) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hBEGIN : (op == Opcode.OP_BEGIN) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hUNTIL : (op == Opcode.OP_UNTIL) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hDUP : (op == Opcode.OP_DUP) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hDROP : (op == Opcode.OP_DROP) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hOVER : (op == Opcode.OP_OVER) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hSWAP : (op == Opcode.OP_SWAP) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hROT : (op == Opcode.OP_ROT) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hNIP : (op == Opcode.OP_NIP) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hTUCK : (op == Opcode.OP_TUCK) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hTO : (op == Opcode.OP_TOALTSTACK) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hFROM : (op == Opcode.OP_FROMALTSTACK) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hPR : (op == Opcode.OP_PICK || op == Opcode.OP_ROLL) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hK : Opcode.arithKind? op with
  | some k => g4fc
  | none =>
  cases hEQ : (op == Opcode.OP_EQUAL) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hEV : (op == Opcode.OP_EQUALVERIFY) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hUN : unaryNumOp? op with
  | some f => g4fc
  | none =>
  cases hUB : unaryBoolOp? op with
  | some f => g4fc
  | none =>
  cases hBN : binNumOp? op with
  | some f => g4fc
  | none =>
  cases hBB : binBoolOp? op with
  | some f => g4fc
  | none =>
  cases h9d : (op == 0x9d) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases ha5 : (op == 0xa5) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hBW : bitwiseOp? op with
  | some f => g4fc
  | none =>
  cases hH : hashOp? op with
  | some h => g4fc
  | none =>
  cases hDEP : (op == Opcode.OP_DEPTH) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hSIZE : (op == Opcode.OP_SIZE) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hIFD : (op == Opcode.OP_IFDUP) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h2DR : (op == Opcode.OP_2DROP) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h2DU : (op == Opcode.OP_2DUP) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h3DU : (op == Opcode.OP_3DUP) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h2OV : (op == Opcode.OP_2OVER) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h2RO : (op == Opcode.OP_2ROT) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h2SW : (op == Opcode.OP_2SWAP) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h7e : (op == 0x7e) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h7f : (op == 0x7f) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h81 : (op == 0x81) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h80 : (op == 0x80) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hCS : (op == Opcode.OP_CODESEPARATOR) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases hNOP : (op == Opcode.OP_NOP || (0xb0 ≤ op.toNat && op.toNat ≤ 0xb9)) with
  | true => simp only [if_true]; g4fc
  | false =>
  simp only [Bool.false_eq_true, if_false]
  g4fc

/-! ### The extended dispatch `stepInstrExt`: budget invariant + frame bound (full opcode walk). -/

set_option hygiene false in
/-- Budget-arm closer for the extended dispatch (adds the helper-delegation exacts). -/
local macro "g4ec" : tactic =>
  `(tactic| (repeat' (first
      | rfl
      | exact stepInstr_budget _ _ _
      | exact introspectIndexed_budget _ _ _ _ _
      | exact opCheckSig_budget _ _ _
      | exact opCheckDataSig_budget _ _
      | exact opCheckMultiSig_budget _ _ _
      | (rw [verifyTopInPlace_budget])
      | (simp only [State.advance, State.push, State.setErr]; done)
      | split)))

set_option hygiene false in
/-- Frame-arm closer for the extended dispatch. -/
local macro "g4ef" : tactic =>
  `(tactic| (repeat' (first
      | exact Nat.le_succ _
      | exact Nat.le_refl _
      | exact stepInstr_frameCount_le _ _ _
      | exact introspectIndexed_frameCount _ _ _ _ _
      | exact opCheckSig_frameCount _ _ _
      | exact opCheckDataSig_frameCount _ _
      | exact opCheckMultiSig_frameCount _ _ _
      | (rw [verifyTopInPlace_ctrl])
      | split
      | (simp_all only [frameCount, State.advance, State.push, State.setErr]; omega))))

set_option maxHeartbeats 1600000 in
theorem stepInstrExt_budget (p : Program) (crypto : Secp256k1) (op : UInt8) (data : Bytes) (s : State) :
    (stepInstrExt p crypto op data s).budget = s.budget := by
  unfold stepInstrExt
  cases h0 : (op == 0x83) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h1 : (op == 0x8d || op == 0x8e) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h2 : (op == 0x98 || op == 0x99) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h3 : (op == 0x89) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h4 : (op == 0x8a) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h5 : (op == 0xc0) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h6 : (op == 0xc1) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h7 : (op == 0xc2) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h8 : (op == 0xc3) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h9 : (op == 0xc4) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h10 : (op == 0xc5) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h11 : (op == 0xc6) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h12 : (op == 0xc7) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h13 : (op == 0xc8) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h14 : (op == 0xc9) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h15 : (op == 0xca) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h16 : (op == 0xcb) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h17 : (op == 0xcc) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h18 : (op == 0xcd) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h19 : (op == 0xce) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h20 : (op == 0xcf) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h21 : (op == 0xd0) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h22 : (op == 0xd1) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h23 : (op == 0xd2) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h24 : (op == 0xd3) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h25 : (op == 0xac) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h26 : (op == 0xad) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h27 : (op == 0xba) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h28 : (op == 0xbb) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h29 : (op == 0xae) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h30 : (op == 0xaf) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h31 : (op == 0xbc) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h32 : (op == 0xb1) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h33 : (op == 0xb2) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h34 : (op == 0xab) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h35 : (op == 0x7e || (0x93 ≤ op.toNat && op.toNat ≤ 0x97) || op == 0x8b || op == 0x8c || op == 0x8f || op == 0x90 || op == 0xa3 || op == 0xa4) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h36 : (op == 0x79 || op == 0x7a || op == 0x7f) with
  | true => simp only [if_true]; g4ec
  | false =>
  simp only [Bool.false_eq_true, if_false]
  g4ec

set_option maxHeartbeats 1600000 in
theorem stepInstrExt_frameCount_le (p : Program) (crypto : Secp256k1) (op : UInt8) (data : Bytes) (s : State) :
    frameCount (stepInstrExt p crypto op data s).ctrl ≤ frameCount s.ctrl + 1 := by
  unfold stepInstrExt
  cases h0 : (op == 0x83) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h1 : (op == 0x8d || op == 0x8e) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h2 : (op == 0x98 || op == 0x99) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h3 : (op == 0x89) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h4 : (op == 0x8a) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h5 : (op == 0xc0) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h6 : (op == 0xc1) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h7 : (op == 0xc2) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h8 : (op == 0xc3) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h9 : (op == 0xc4) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h10 : (op == 0xc5) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h11 : (op == 0xc6) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h12 : (op == 0xc7) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h13 : (op == 0xc8) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h14 : (op == 0xc9) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h15 : (op == 0xca) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h16 : (op == 0xcb) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h17 : (op == 0xcc) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h18 : (op == 0xcd) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h19 : (op == 0xce) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h20 : (op == 0xcf) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h21 : (op == 0xd0) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h22 : (op == 0xd1) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h23 : (op == 0xd2) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h24 : (op == 0xd3) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h25 : (op == 0xac) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h26 : (op == 0xad) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h27 : (op == 0xba) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h28 : (op == 0xbb) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h29 : (op == 0xae) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h30 : (op == 0xaf) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h31 : (op == 0xbc) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h32 : (op == 0xb1) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h33 : (op == 0xb2) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h34 : (op == 0xab) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h35 : (op == 0x7e || (0x93 ≤ op.toNat && op.toNat ≤ 0x97) || op == 0x8b || op == 0x8c || op == 0x8f || op == 0x90 || op == 0xa3 || op == 0xa4) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  cases h36 : (op == 0x79 || op == 0x7a || op == 0x7f) with
  | true => simp only [if_true]; g4ef
  | false =>
  simp only [Bool.false_eq_true, if_false]
  g4ef

/-! ### One pure extended step: budget invariant + frame bound. -/

theorem step1Ext_budget (p : Program) (crypto : Secp256k1) (s : State) :
    (step1Ext p crypto s).budget = s.budget := by
  rw [step1Ext]
  split
  · rfl
  · split
    · exact stepInstrExt_budget _ _ _ _ _
    · rfl

theorem step1Ext_frameCount (p : Program) (crypto : Secp256k1) (s : State) :
    frameCount (step1Ext p crypto s).ctrl ≤ frameCount s.ctrl + 1 := by
  rw [step1Ext]
  split
  · exact Nat.le_succ _
  · split
    · exact stepInstrExt_frameCount_le _ _ _ _ _
    · exact Nat.le_succ _

/-! ### The Group-4 headline obligations (become `runScript_fuel_suffices`'s `Hbudget`/`Hframe`). -/

theorem stepMeterExt_budget_eq (p : Tx.Program) (crypto : Secp256k1) :
    ∀ t : State, (stepMeterExt p crypto t).budget = t.budget := by
  intro t
  unfold stepMeterExt
  rw [enforceStepLimits_budget]
  exact step1Ext_budget p crypto t

theorem stepMeterExt_frameCount_le (p : Tx.Program) (crypto : Secp256k1) :
    ∀ t : State, frameCount (stepMeterExt p crypto t).ctrl ≤ frameCount t.ctrl + 1 := by
  intro t
  unfold stepMeterExt
  rw [enforceStepLimits_ctrl]
  exact step1Ext_frameCount p crypto t

/-! ### Audit complete — `FrozenCore` discharged; the parametrized headlines become unconditional.
    Groups 1–4 of the per-opcode audit: the frozen `stepInstr` core/wrap walks + the Number/Shift
    length lemmas + the `stepInstrExt` budget/frame walk. All four `FrozenCore` fields and both
    fuel hypotheses (`Hframe`/`Hbudget`) are now THEOREMS. -/

/-- **`FrozenCore` is satisfied** — its four conjuncts are the audit theorems `frozenCore_core`
    (every non-excluded `stepInstr` arm preserves-or-errors item length, given `WF`), `frozenCore_wrap`
    (the excluded CAT/arith arms leave altstack + stack-tail bounded), `frozenCore_rshiftnum`,
    `frozenCore_shiftbin`. So it is NOT a vacuous premise: an inhabitant exists for every `crypto`
    (the fields are crypto-independent). This closes the risk that `runExt_WF_of` was secretly vacuous. -/
theorem frozenCore_holds (crypto : Secp256k1) : FrozenCore crypto :=
  ⟨frozenCore_core, frozenCore_wrap, frozenCore_rshiftnum, frozenCore_shiftbin⟩

/-- **Resource-safety preservation, unconditional in `FrozenCore`.** With the audit discharged,
    `runExt_WF_of`'s only remaining premise is the honest tx-well-formedness `WFProgram p` (the genuine
    real-world precondition, established by the wire decoder). Every reachable state of a metered run
    from a `WF` start is `WF` (all stack/alt items ≤ `maxItemLen`, slots ≤ `maxMemorySlots`, ctrl ≤
    `maxCtrlDepth`) or has aborted — the mechanized guard-completeness guarantee (Axis A). -/
theorem runExt_WF_final (p : Program) (crypto : Secp256k1) (hwf : WFProgram p)
    (f : Nat) (s : State) (hs : WF s) :
    WF (runExt p crypto f s) ∨ (runExt p crypto f s).error.isSome = true :=
  runExt_WF_of p crypto hwf (frozenCore_holds crypto) f s hs

/-- **Fuel-sufficiency, unconditional in `Hframe`/`Hbudget`.** The per-step frame/budget audit
    (`stepMeterExt_frameCount_le`, `stepMeterExt_budget_eq`) discharges both hypotheses, leaving only
    the true consensus budget bound `budget ≤ maxOpCostCeiling` (= `(10000+41)·800`). So `runScript`
    ALWAYS reaches a `Halted` fixpoint within its `instrs.size + evalFuelSlack` fuel — the fuel bound
    can never mask a false accept/reject verdict (Axis C). -/
theorem runScript_fuel_suffices_final (crypto : Secp256k1) (p : Tx.Program) (stk : Stack) (bs : Bytes)
    (budget : Nat) (hbud : budget ≤ maxOpCostCeiling) :
    Halted (runScript crypto p stk bs budget) :=
  runScript_fuel_suffices crypto p stk bs budget
    (stepMeterExt_frameCount_le p crypto) (stepMeterExt_budget_eq p crypto) hbud



/-! ### Group A — wire-reader length/bound lemmas + the input/output-count `< 2^64` facts
    (backing `WFProgram` conjuncts (2) & (3)). All are simple structural inductions on the
    reader's `Nat` argument; `Option`-bind reasoning via `Option.bind_eq_some_iff` /
    `Option.map_eq_some_iff`. Do-notation readers (`readN`, `decodeTransaction`) desugar to a
    `match`-form of `Option.bind`, so their bodies are first coerced to explicit `Option.bind`
    applications via a defeq `have` before `Option.bind_eq_some_iff` fires. -/

/-- `takeBytes n` returns exactly `n` bytes when it succeeds. -/
theorem takeBytes_length : ∀ (n : Nat) (bs d r : Bytes), takeBytes n bs = some (d, r) → d.length = n
  | 0, bs, d, r, h => by
      rw [takeBytes] at h
      injection h with h
      injection h with h1 h2
      subst h1; rfl
  | n+1, [], d, r, h => by rw [takeBytes] at h; simp at h
  | n+1, b :: bs, d, r, h => by
      rw [takeBytes, Option.map_eq_some_iff] at h
      obtain ⟨⟨d', r'⟩, hrec, heq⟩ := h
      simp only [Prod.mk.injEq] at heq
      obtain ⟨hd, hr⟩ := heq
      subst hd
      simp only [List.length_cons]
      rw [takeBytes_length n bs d' r' hrec]

/-- `readN rd n` returns exactly `n` items when it succeeds. -/
theorem readN_length {α : Type} (rd : Bytes → Option (α × Bytes)) :
    ∀ (n : Nat) (bs : Bytes) (xs : List α) (r : Bytes), readN rd n bs = some (xs, r) → xs.length = n
  | 0, bs, xs, r, h => by
      have h' : some (([] : List α), bs) = some (xs, r) := h
      simp only [Option.some.injEq, Prod.mk.injEq] at h'
      obtain ⟨h1, _⟩ := h'; subst h1; rfl
  | n+1, bs, xs, r, h => by
      have h' : (rd bs).bind (fun p => (readN rd n p.2).bind (fun q => some (p.1 :: q.1, q.2))) = some (xs, r) := h
      rw [Option.bind_eq_some_iff] at h'
      obtain ⟨⟨x, bs1⟩, _hrd, h2⟩ := h'
      dsimp only at h2
      rw [Option.bind_eq_some_iff] at h2
      obtain ⟨⟨xs', bs2⟩, hrec, hfin⟩ := h2
      simp only [Option.some.injEq, Prod.mk.injEq] at hfin
      obtain ⟨hx, _⟩ := hfin
      subst hx
      simp only [List.length_cons]
      rw [readN_length rd n bs1 xs' bs2 hrec]

/-- A `k`-byte little-endian read yields a value `< 256 ^ k`. -/
theorem readNatLE_lt : ∀ (k : Nat) (bs : Bytes) (v : Nat) (r : Bytes), readNatLE k bs = some (v, r) → v < 256 ^ k
  | 0, bs, v, r, h => by
      rw [readNatLE] at h
      injection h with h
      injection h with h1 h2
      subst h1
      decide
  | k+1, [], v, r, h => by rw [readNatLE] at h; simp at h
  | k+1, b :: bs, v, r, h => by
      rw [readNatLE, Option.map_eq_some_iff] at h
      obtain ⟨⟨n', r'⟩, hrec, heq⟩ := h
      simp only [Prod.mk.injEq] at heq
      obtain ⟨hv, _⟩ := heq
      have hn : n' < 256 ^ k := readNatLE_lt k bs n' r' hrec
      have hb : b.toNat < 256 := b.toNat_lt
      have hp : (256:Nat) ^ (k + 1) = 256 ^ k * 256 := Nat.pow_succ 256 k
      subst hv
      omega

/-- A compact-uint (varint) always decodes to a value `< 2^64`: the `≤252` inline branch is
    `< 253`; the `0xfd/0xfe/else` branches are `readNatLE 2/4/8`, bounded by `256^2/256^4/256^8`,
    all `≤ 2^64`. -/
theorem readCompactUint_lt : ∀ (bs : Bytes) (n : Nat) (r : Bytes), readCompactUint bs = some (n, r) → n < 2 ^ 64 := by
  intro bs n r h
  unfold readCompactUint at h
  cases bs with
  | nil => simp at h
  | cons b rest =>
      simp only [] at h
      split at h
      · -- b.toNat ≤ 252
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨hn, _⟩ := h
        subst hn
        exact Nat.lt_of_lt_of_le b.toNat_lt (by decide)
      · split at h
        · -- 0xfd branch : readNatLE 2
          simp only [Option.bind_eq_some_iff] at h
          obtain ⟨⟨v, r'⟩, hv, hif⟩ := h
          split at hif
          · simp only [Option.some.injEq, Prod.mk.injEq] at hif
            obtain ⟨hn, _⟩ := hif
            subst hn
            exact Nat.lt_of_lt_of_le (readNatLE_lt 2 rest v r' hv) (by decide)
          · simp at hif
        · split at h
          · -- 0xfe branch : readNatLE 4
            simp only [Option.bind_eq_some_iff] at h
            obtain ⟨⟨v, r'⟩, hv, hif⟩ := h
            split at hif
            · simp only [Option.some.injEq, Prod.mk.injEq] at hif
              obtain ⟨hn, _⟩ := hif
              subst hn
              exact Nat.lt_of_lt_of_le (readNatLE_lt 4 rest v r' hv) (by decide)
            · simp at hif
          · -- else branch : readNatLE 8
            simp only [Option.bind_eq_some_iff] at h
            obtain ⟨⟨v, r'⟩, hv, hif⟩ := h
            split at hif
            · simp only [Option.some.injEq, Prod.mk.injEq] at hif
              obtain ⟨hn, _⟩ := hif
              subst hn
              exact Nat.lt_of_lt_of_le (readNatLE_lt 8 rest v r' hv) (by decide)
            · simp at hif

/-- A decoded transaction has `inputs.size < 2^64` (the compact-uint count is `< 2^64`, and
    `readN readInput nIn` produces exactly `nIn` inputs). Backs `WFProgram` conjunct (2). -/
theorem decodeTransaction_inputCount_lt : ∀ (bs : Bytes) (tx : Transaction), decodeTransaction bs = some tx → tx.inputs.size < 2 ^ 64 := by
  intro bs tx h
  have h' : Option.bind (readU32 bs) (fun p1 =>
      Option.bind (readCompactUint p1.2) (fun p2 =>
        Option.bind (readN readInput p2.1 p2.2) (fun p3 =>
          Option.bind (readCompactUint p3.2) (fun p4 =>
            Option.bind (readN readOutput p4.1 p4.2) (fun p5 =>
              Option.bind (readU32 p5.2) (fun p6 =>
                some { version := p1.1, inputs := p3.1.toArray,
                       outputs := p5.1.toArray, locktime := p6.1 })))))) = some tx := h
  simp only [Option.bind_eq_some_iff, Prod.exists] at h'
  obtain ⟨ver, bs1, _hver, nIn, bs2, hnIn, ins, bs3, hins, nOut, bs4, _hnOut,
          outs, bs5, _houts, lock, bs6, _hlock, hfin⟩ := h'
  simp only [Option.some.injEq] at hfin
  subst hfin
  show (ins.toArray).size < 2 ^ 64
  rw [List.size_toArray, readN_length readInput nIn bs2 ins bs3 hins]
  exact readCompactUint_lt bs1 nIn bs2 hnIn

/-- A decoded transaction has `outputs.size < 2^64` (same argument via the second count).
    Backs `WFProgram` conjunct (3). -/
theorem decodeTransaction_outputCount_lt : ∀ (bs : Bytes) (tx : Transaction), decodeTransaction bs = some tx → tx.outputs.size < 2 ^ 64 := by
  intro bs tx h
  have h' : Option.bind (readU32 bs) (fun p1 =>
      Option.bind (readCompactUint p1.2) (fun p2 =>
        Option.bind (readN readInput p2.1 p2.2) (fun p3 =>
          Option.bind (readCompactUint p3.2) (fun p4 =>
            Option.bind (readN readOutput p4.1 p4.2) (fun p5 =>
              Option.bind (readU32 p5.2) (fun p6 =>
                some { version := p1.1, inputs := p3.1.toArray,
                       outputs := p5.1.toArray, locktime := p6.1 })))))) = some tx := h
  simp only [Option.bind_eq_some_iff, Prod.exists] at h'
  obtain ⟨ver, bs1, _hver, nIn, bs2, _hnIn, ins, bs3, _hins, nOut, bs4, hnOut,
          outs, bs5, houts, lock, bs6, _hlock, hfin⟩ := h'
  simp only [Option.some.injEq] at hfin
  subst hfin
  show (outs.toArray).size < 2 ^ 64
  rw [List.size_toArray, readN_length readOutput nOut bs4 outs bs5 houts]
  exact readCompactUint_lt bs3 nOut bs4 hnOut

theorem readN_forall {α : Type} {P : α → Prop} (rd : Bytes → Option (α × Bytes))
    (hrd : ∀ bs x r, rd bs = some (x, r) → P x) :
    ∀ (n : Nat) (bs : Bytes) (xs : List α) (r : Bytes), readN rd n bs = some (xs, r) → ∀ x ∈ xs, P x
  | 0, bs, xs, r, h => by
      simp only [readN, Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, _⟩ := h
      intro x hx
      simp at hx
  | n+1, bs, xs, r, h => by
      simp only [readN, Option.bind_eq_bind, Option.bind_eq_some_iff, Prod.exists,
        Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨x, bs', hrd', xs', bs'', hreadN, hxs, _⟩ := h
      subst hxs
      intro y hy
      rcases List.mem_cons.mp hy with hh | hh
      · subst hh; exact hrd _ _ _ hrd'
      · exact readN_forall rd hrd n bs' xs' bs'' hreadN y hh

theorem readInput_hashLen : ∀ (bs : Bytes) (inp : Input) (r : Bytes), readInput bs = some (inp, r) →
    inp.outpointTransactionHash.length ≤ maxItemLen := by
  intro bs inp r h
  unfold readInput at h
  simp only [Option.bind_eq_bind, Option.bind_eq_some_iff, Prod.exists,
    Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨hashWire, bs1, hhash, idx, bs2, hidx, slen, bs3, hslen, script, bs4, hscript,
    seqn, bs5, hseqn, hinp, _⟩ := h
  subst hinp
  simp only [List.length_reverse]
  rw [takeBytes_length 32 bs hashWire bs1 hhash]
  decide

/-- The token-category push (WIRE-order category + ≤1-byte capability suffix) is at most
    `category.length + 1` bytes. -/
theorem tokenCategoryBytes_some_length (td : TokenData) :
    (tokenCategoryBytes (some td)).length ≤ td.category.length + 1 := by
  simp only [tokenCategoryBytes, List.length_append, List.length_reverse]
  split
  · split <;> simp only [List.length_cons, List.length_nil] <;> omega
  · simp only [List.length_nil]; omega

set_option linter.unusedSimpArgs false in  -- `Prod.exists` IS consumed by the downstream `obtain`
theorem decodeField_tokenOk : ∀ (field : Bytes) (t : Option TokenData) (r : Bytes), decodeField field = some (t, r) →
    (tokenCategoryBytes t).length ≤ maxItemLen ∧ (tokenAmountBytes t).length ≤ maxItemLen := by
  intro field t r h
  unfold decodeField at h
  split at h
  · -- token present: field = 0xef :: rest
    rename_i rest
    simp only [Option.bind_eq_bind, Option.bind_eq_some_iff, Prod.exists] at h
    obtain ⟨catRev, bs0, hcat, bf, bs1, hbf, h⟩ := h
    split at h
    · simp at h
    split at h
    · simp at h
    split at h
    · simp at h
    split at h
    · simp at h
    simp only [Option.bind_eq_bind, Option.bind_eq_some_iff, Prod.exists] at h
    obtain ⟨commitment, bs2, hcommit, amount, bs3, hamount, h⟩ := h
    split at h
    · simp at h
    split at h
    · simp at h
    split at h
    · simp at h
    rename_i hg7
    split at h
    · simp at h
    simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨ht, _⟩ := h
    subst ht
    refine ⟨?_, ?_⟩
    · -- category
      refine Nat.le_trans (tokenCategoryBytes_some_length _) ?_
      have hlen : catRev.length = 32 := takeBytes_length 32 rest catRev bs0 hcat
      simp only [List.length_reverse, hlen]
      decide
    · -- amount
      simp only [tokenAmountBytes]
      apply bigIntToVmNumber_ofNat_length
      exact Nat.lt_of_le_of_lt (show amount ≤ 9223372036854775807 by omega) (by decide)
  · -- no token
    simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨ht, _⟩ := h
    subst ht
    exact ⟨by decide, by decide⟩

theorem readOutput_tokenOk : ∀ (bs : Bytes) (o : Output) (r : Bytes), readOutput bs = some (o, r) →
    (tokenCategoryBytes o.token).length ≤ maxItemLen ∧ (tokenAmountBytes o.token).length ≤ maxItemLen := by
  intro bs o r h
  unfold readOutput at h
  simp only [Option.bind_eq_bind, Option.bind_eq_some_iff, Prod.exists,
    Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨val, bs1, hval, flen, bs2, hflen, field, bs3, hfield, token, locking, hdf, ho, _⟩ := h
  subst ho
  exact decodeField_tokenOk field token locking hdf

theorem decodeTransaction_inputsHashOk : ∀ (bs : Bytes) (tx : Transaction), decodeTransaction bs = some tx →
    ∀ inp ∈ tx.inputs, inp.outpointTransactionHash.length ≤ maxItemLen := by
  intro bs tx h
  unfold decodeTransaction at h
  simp only [Option.bind_eq_bind, Option.bind_eq_some_iff, Prod.exists, Option.some.injEq] at h
  obtain ⟨ver, bs1, hver, nIn, bs2, hnin, ins, bs3, hins, nOut, bs4, hnout, outs, bs5, houts,
    lock, bs6, hlock, htx⟩ := h
  subst htx
  intro inp hinp
  exact readN_forall readInput readInput_hashLen nIn bs2 ins bs3 hins inp (List.mem_toArray.mp hinp)

theorem decodeTransaction_outputsTokenOk : ∀ (bs : Bytes) (tx : Transaction), decodeTransaction bs = some tx →
    ∀ o ∈ tx.outputs, (tokenCategoryBytes o.token).length ≤ maxItemLen ∧ (tokenAmountBytes o.token).length ≤ maxItemLen := by
  intro bs tx h
  unfold decodeTransaction at h
  simp only [Option.bind_eq_bind, Option.bind_eq_some_iff, Prod.exists, Option.some.injEq] at h
  obtain ⟨ver, bs1, hver, nIn, bs2, hnin, ins, bs3, hins, nOut, bs4, hnout, outs, bs5, houts,
    lock, bs6, hlock, htx⟩ := h
  subst htx
  intro o ho
  exact readN_forall readOutput readOutput_tokenOk nOut bs4 outs bs5 houts o (List.mem_toArray.mp ho)

theorem decodeOutputList_tokenOk : ∀ (bs : Bytes) (sos : Array Output), decodeOutputList bs = some sos →
    ∀ u ∈ sos, (tokenCategoryBytes u.token).length ≤ maxItemLen ∧ (tokenAmountBytes u.token).length ≤ maxItemLen := by
  intro bs sos h
  unfold decodeOutputList at h
  simp only [Option.bind_eq_bind, Option.bind_eq_some_iff, Prod.exists, Option.some.injEq] at h
  obtain ⟨n, bs1, hn, os, bs2, hos, hsos⟩ := h
  subst hsos
  intro u hu
  exact readN_forall readOutput readOutput_tokenOk n bs1 os bs2 hos u (List.mem_toArray.mp hu)

/-! ### Grounding `WFProgram` in the wire decoder — the tx-well-formedness premise is an INVARIANT
    of any successfully-decoded transaction (Groups A+B: the reader length/count/field lemmas above).
    This closes the loop: item-length safety (`runExt_WF_final`) traces all the way back to "the bytes
    parsed". The lone caller precondition `inputIndex < 2^64` is genuine and unavoidable —
    `decodeProgram` does not validate the caller's input selector, and no transaction has ≥ 2^64 inputs. -/

/-- **`WFProgram` is established by the wire decoder.** A program obtained from `decodeProgram` (with a
    sane input index) satisfies every `WFProgram` conjunct: `inputIndex < 2^64` (the premise); the
    input/output counts are compact-uint-bounded `< 2^64` (`decodeTransaction_{input,output}Count_lt`);
    every input carries a 32-byte outpoint hash (`decodeTransaction_inputsHashOk`); every output /
    source-output token category (32 B) + amount (< 2^63) fit (`decode{Transaction_outputs,OutputList}_tokenOk`). -/
theorem decodeProgram_WFProgram (txHex soHex : Bytes) (i : Nat) (p : Program)
    (hd : decodeProgram txHex soHex i = some p) (hi : i < 2 ^ 64) : WFProgram p := by
  unfold decodeProgram at hd
  simp only [Option.bind_eq_bind, Option.bind_eq_some_iff, Option.some.injEq] at hd
  obtain ⟨tx, hdt, sos, hds, hp⟩ := hd
  subst hp
  exact ⟨bigIntToVmNumber_ofNat_length i hi,
         bigIntToVmNumber_ofNat_length _ (decodeTransaction_inputCount_lt txHex tx hdt),
         bigIntToVmNumber_ofNat_length _ (decodeTransaction_outputCount_lt txHex tx hdt),
         decodeTransaction_inputsHashOk txHex tx hdt,
         decodeTransaction_outputsTokenOk txHex tx hdt,
         decodeOutputList_tokenOk soHex sos hds⟩

/-- The empty-stack ENTRY state is `WF`: `loadFrom [] bs` has empty stack/alt/ctrl/functionTable
    (whether or not `bs` parsed), so `WFlen` is vacuous and `WFmem` is `0 ≤` the caps. This is the
    base case that DISCHARGES the `WF s` start premise of `decoded_runExt_WF` for a run begun from a
    freshly-loaded script — the missing "premise-free" leaf of Axis A. -/
theorem WF_loadFrom_nil (bs : Bytes) : WF (loadFrom [] bs) := by
  unfold WF WFlen WFmem loadFrom
  cases parse bs <;> simp

/-- **End-to-end resource safety — bounded execution from any `WF` start.** If `p` decodes from
    `txHex`/`soHex` at a sane input index, then every reachable state of a metered run from a `WF`
    start `s` is `WF` (all stack/alt items ≤ `maxItemLen`, slots ≤ `maxMemorySlots`, ctrl ≤
    `maxCtrlDepth`) or has aborted. The tx-parse and `inputIndex < 2^64` premises are discharged from
    the wire; the START state carries the explicit `WF s` premise, which `WF_loadFrom_nil` discharges
    for the empty-stack entry state (so a run begun from `loadFrom [] bs` is premise-free). Axis A:
    `decodeProgram` ⟹ `WFProgram` ⟹ `runExt_WF_final`. -/
theorem decoded_runExt_WF (txHex soHex : Bytes) (i : Nat) (p : Program) (crypto : Secp256k1)
    (hd : decodeProgram txHex soHex i = some p) (hi : i < 2 ^ 64)
    (f : Nat) (s : State) (hs : WF s) :
    WF (runExt p crypto f s) ∨ (runExt p crypto f s).error.isSome = true :=
  runExt_WF_final p crypto (decodeProgram_WFProgram txHex soHex i p hd hi) f s hs

/-- **Premise-free corollary**: a metered run begun from the empty-stack load of `bs` (the genuine
    entry state) is resource-safe — `WF` at every reachable state, or aborted — with NO well-formedness
    premise on the start, only "the transaction parsed" (+ `inputIndex < 2^64`). Closes the honest tail
    of Axis A the header of `decoded_runExt_WF` used to overclaim. -/
theorem decoded_runExt_WF_init (txHex soHex : Bytes) (i : Nat) (p : Program) (crypto : Secp256k1)
    (hd : decodeProgram txHex soHex i = some p) (hi : i < 2 ^ 64) (f : Nat) (bs : Bytes) :
    WF (runExt p crypto f (loadFrom [] bs)) ∨ (runExt p crypto f (loadFrom [] bs)).error.isSome = true :=
  decoded_runExt_WF txHex soHex i p crypto hd hi f (loadFrom [] bs) (WF_loadFrom_nil bs)


end LeanBCH.VM
