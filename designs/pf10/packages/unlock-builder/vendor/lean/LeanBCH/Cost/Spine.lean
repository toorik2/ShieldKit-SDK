/-
  LeanBCH.Cost.Spine — the proven 800:1 op→byte inversion, epoch-relative.

  Exact, self-contained arithmetic from the BCH-2026 density-control budget — no model, no
  quantifier over algorithms. Any on-chain op-cost that must be hosted converts to unlocking bytes
  at a fixed `operationCostBudgetPerByte` op/byte; a single input's op-budget is capped at
  `(densityControlBaseLength+maximumBytecodeLength) · operationCostBudgetPerByte`.

  ★ STATUS: REFERENCE LEMMA — NOT LOAD-BEARING. Nothing in the VM or the optimizer imports
  `Cost.Spine`; `chunks_ge`/`chunks_tight`/`n_chunks_lb`/`cost_split_invariance` have no downstream
  proof consumer, and `chunks_ge`/`chunks_tight` carry a positivity hypothesis never instantiated at
  `BCH_2026_05`. `runMeter` is a fuel recursion (not a fold over `progWeight`), and no lemma bridges
  the two, so `cost_split_invariance` does not apply to a live run. Kept as the proven arithmetic of
  the 800:1 inversion for reference — NOT a guarantee about any executing program. (Making it live
  would need a `runMeter = progWeight kappa` lemma; see the audit recommendation.)

  Transcribed from `stackcert/Stackcert/Cost/Spine.lean` (whole file), with the ONE change the
  LeanBCH design mandates: the BAKED consensus pins (41 / 800 / 10000 / 8032800) become reads of
  `E : Epoch`. `LeanBCH.Epoch` already provides `densityControlLength E ulen` and
  `maxOperationCost E ulen := densityControlLength · operationCostBudgetPerByte`, so the ceiling
  is `f(E)`, re-audited on any VM-version bump; the 41/800/10000 pins survive only inside
  `BCH_2026_05` and appear here only as `decide`-checked witnesses.

  Pure Nat / omega, NO mathlib. Because the budget-per-byte and the max budget are now epoch
  VARIABLES (not the literal 800 / 8032800 stackcert baked), the ceiling proofs carry a positivity
  hypothesis and factor through `Nat.div_add_mod` / `Nat.mod_lt` (omega alone cannot reason about
  division by a variable).
-/
import LeanBCH.Epoch
import LeanBCH.Cost.Metrics

namespace LeanBCH.Cost
open LeanBCH

/-- Ceiling soundness, generic over the (positive) divisor: `d ·⌈O/d⌉ ≥ O`. The one nonlinear
    fact the whole file rests on; `omega` closes it once `div_add_mod` + `mod_lt` are on hand
    (it treats `d * ((O+(d-1))/d)` as a single atom, exactly the atom `Nat.div_add_mod` names). -/
theorem ceil_mul_ge (d O : Nat) (hd : 0 < d) :
    d * ((O + (d - 1)) / d) ≥ O := by
  have h1 := Nat.div_add_mod (O + (d - 1)) d
  have h2 := Nat.mod_lt (O + (d - 1)) hd
  omega

/-- (a) SINGLE-INPUT CEILING — no input can buy more op-budget than the max-length input.
    The epoch-relative form of the baked 8,032,800 ceiling: it is just monotonicity of the
    per-input budget in the unlocking length (`Epoch.maxOperationCost_mono`). -/
theorem single_input_ceiling (E : Epoch) (ulen : Nat)
    (h : ulen ≤ E.maximumBytecodeLength) :
    E.maxOperationCost ulen ≤ E.maxOperationCost E.maximumBytecodeLength :=
  Epoch.maxOperationCost_mono E h

/-- …and the ceiling is TIGHT, hit exactly at the max-bytecode-length cap: at BCH_2026_05
    `maxOperationCost 10000 = (41+10000)·800 = 8,032,800`. -/
theorem ceiling_tight : Epoch.maxOperationCost BCH_2026_05 10000 = 8032800 := by
  decide

/-- (b) O → ⌈O/operationCostBudgetPerByte⌉ : the bytes needed to HOST an irreducible op-cost `O`
    (= ⌈O/800⌉ at BCH_2026_05). -/
def chunks (E : Epoch) (O : Nat) : Nat :=
  (O + (E.operationCostBudgetPerByte - 1)) / E.operationCostBudgetPerByte

/-- The hosting is SOUND: `chunks E O` bytes buy at least `O` op-budget (⌈·⌉ upper bound).
    Epoch-relative — carries `operationCostBudgetPerByte > 0` (baked 800 > 0 in stackcert). -/
theorem chunks_ge (E : Epoch) (O : Nat) (hb : 0 < E.operationCostBudgetPerByte) :
    E.operationCostBudgetPerByte * chunks E O ≥ O := by
  unfold chunks
  exact ceil_mul_ge _ O hb

/-- …and TIGHT: one fewer chunk-byte would not cover `O` (unless O = 0). The tightness half of
    the pair. `omega` needs the product `b·(c-1)` related to `b·c` explicitly (nonlinear), so we
    hand it `b·c = b·(c-1) + b` alongside `div_add_mod` / `mod_lt`. -/
theorem chunks_tight (E : Epoch) (O : Nat) (hb : 0 < E.operationCostBudgetPerByte) :
    chunks E O = 0 ∨ E.operationCostBudgetPerByte * (chunks E O - 1) < O := by
  -- `Nat.core` has no mathlib `set`; generalize the budget + the ceiling by hand, then
  -- case-split the ceiling so `Nat.mul_succ` gives omega the `b·c = b·(c-1)+b` bridge it
  -- needs (omega cannot distribute a variable-by-variable product on its own).
  unfold chunks
  generalize hbeq : E.operationCostBudgetPerByte = b at hb ⊢
  have h1 := Nat.div_add_mod (O + (b - 1)) b
  have h2 := Nat.mod_lt (O + (b - 1)) hb
  generalize hc : (O + (b - 1)) / b = c at h1 ⊢
  cases c with
  | zero => exact Or.inl rfl
  | succ k =>
    refine Or.inr ?_
    have hbc : b * (k + 1) = b * k + b := Nat.mul_succ b k
    simp only [Nat.add_sub_cancel]
    omega

/-- (c) n_chunks LOWER BOUND — hosting op-cost `O` needs at least this many single-input
    transactions, each maxing at the max-length ceiling `maxOperationCost(maximumBytecodeLength)`
    (= 8,032,800 at BCH_2026_05). -/
def nChunks (E : Epoch) (O : Nat) : Nat :=
  (O + (E.maxOperationCost E.maximumBytecodeLength - 1)) / E.maxOperationCost E.maximumBytecodeLength

theorem n_chunks_lb (E : Epoch) (O : Nat)
    (hM : 0 < E.maxOperationCost E.maximumBytecodeLength) :
    O ≤ nChunks E O * E.maxOperationCost E.maximumBytecodeLength := by
  unfold nChunks
  rw [Nat.mul_comm]
  exact ceil_mul_ge _ O hM

/-- (d) COST SPLIT-INVARIANCE at the operationCost level — the aggregate op-cost of a
    concatenated program is the sum, so op-cost is compositional over chunks (any epoch). -/
theorem cost_split_invariance {α} (E : Epoch) (κ : α → Metrics) (p q : List α) :
    operationCost E (progWeight κ (p ++ q))
      = operationCost E (progWeight κ p) + operationCost E (progWeight κ q) := by
  rw [cost_append, operationCost_add]

/-- BCH_2026_05 decide-witnesses — the baked stackcert literals, now pins inside the epoch. -/
theorem maxOperationCost_witness : Epoch.maxOperationCost BCH_2026_05 10000 = 8032800 := by
  decide

theorem chunks_witness : chunks BCH_2026_05 116000000 = 145000 := by
  decide

end LeanBCH.Cost
