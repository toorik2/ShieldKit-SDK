/-
  DECOMPILE ⇒ WELL-FORMED — discharging the last open hypothesis of `bridge_block`/`end_to_end`.

  `bridge_block`/`end_to_end` (Decompile.lean) both take `hwf : WellFormed b` as a hypothesis.
  This file PROVES that hypothesis FROM the fact that `decompileBlock` accepted: the decompiler
  ENFORCES `WellFormed` by construction (decompile.mjs THROWS on any violation — Dag.lean:92).

  ★ THE WALK-STATE INVARIANT `DWF` (mirror of the decompiler's structural bookkeeping):
    • `ids`   — the created node ids are exactly `0,1,…,nextId-1` (`.map id = range nextId`);
                each CALL uses the fresh `nextId` and bumps it. Gives `distinctIds` (`nodup_range`).
    • `topo`  — `nodesWF` holds for the accumulated node list (topological order): each node's
                inputs reference entry slots / constants / EARLIER node ids.
    • `arity` — every created node lists exactly `op.nin` operands (built as `(take nin).reverse`).
    • `vmain`/`valt` — every ref on the main/alt ref-stacks is `RefValid` (in-bounds entry slot,
                constant, or an `out nid j` of an already-created node with `j < nout`).
    • `vins`  — every node's input refs are likewise `RefValid`.
  `DWF` is seeded by `seed_DWF`, preserved by `decStep_DWF` (stack ops: refs only get shuffled /
  duplicated / a fresh const is pushed — `decStep_noncall_mem`; the sole CALL: creates the fresh
  node, its operands are `RefValid` prior refs, its output refs are `RefValid` against itself), and
  folded to the final walk-state by `decFold_DWF`. Closing the block reads the six non-`semArity`
  WellFormed conjuncts straight off `DWF`.

  ★ `semArity` (the 7th conjunct) is the ONE conjunct NOT provable from `decompileBlock` alone: a
  node stores `nout := |sem (replicate nin default)|`, but `semArity` demands `|sem l| = nout` for
  EVERY `l` of length `nin` — a property of `sem` itself (a genuine invariant of real value-ops:
  fixed output arity), NOT enforced by the walk. It is discharged under the minimal, real premise
  `OpUniform` on the raw ops (`decFold_SemWF`). Everything else is UNCONDITIONAL.

  Lean 4.31 core, NO mathlib.
-/
import LeanBCH.Opt.Decompile

namespace LeanBCH.Opt
open Op

/-! ### `RefValid` — a ref is fully valid against a node list (the strong form of `refBounded`
    that ALSO pins the output-index bound needed for `outIdx`). -/

/-- A ref is valid against `nodes`: entry slots in-bounds, constants free, and every `out nid j`
    names a node in `nodes` with `j < nout`. -/
def RefValid {α} (ed ea : Nat) (nodes : List (Node α)) : Ref α → Prop
  | .inp i     => i < ed
  | .ainp i    => i < ea
  | .const _ _ => True
  | .out nid j => ∃ nd ∈ nodes, nd.id = nid ∧ j < nd.op.nout

/-- `RefValid` is monotone under adding nodes (an out-ref stays valid; the `∃` only grows). -/
theorem RefValid_mono {α} (ed ea : Nat) (nodes extra : List (Node α)) (r : Ref α)
    (h : RefValid ed ea nodes r) : RefValid ed ea (nodes ++ extra) r := by
  cases r with
  | inp i => exact h
  | ainp i => exact h
  | const v b => exact h
  | out nid j =>
      obtain ⟨nd, hmem, hid, hj⟩ := h
      exact ⟨nd, List.mem_append_left _ hmem, hid, hj⟩

/-- `RefValid` ⟹ `refBounded` (drop the output-index bound; keep the id-membership). -/
theorem RefValid_refBounded {α} (ed ea : Nat) (nodes : List (Node α)) (r : Ref α)
    (h : RefValid ed ea nodes r) : refBounded ed ea (nodes.map Node.id) r := by
  cases r with
  | inp i => exact h
  | ainp i => exact h
  | const v b => exact trivial
  | out nid j =>
      obtain ⟨nd, hmem, hid, _⟩ := h
      show nid ∈ nodes.map Node.id
      rw [← hid]; exact List.mem_map_of_mem hmem

/-- Distinct ids ⟹ the `id`-map is injective on the node list (needed to promote the `RefValid`
    witness to the `∀ nd` shape `outIdx` demands). -/
theorem nodes_id_inj {α} :
    ∀ (l : List (Node α)), (l.map Node.id).Nodup →
      ∀ a ∈ l, ∀ b ∈ l, a.id = b.id → a = b := by
  intro l
  induction l with
  | nil => intro _ a ha; exact absurd ha (List.not_mem_nil)
  | cons c cs ih =>
      intro hnd a ha b hb hid
      rw [List.map_cons, List.nodup_cons] at hnd
      obtain ⟨hnotin, hcs⟩ := hnd
      rcases List.mem_cons.mp ha with rfl | ha'
      · rcases List.mem_cons.mp hb with rfl | hb'
        · rfl
        · exact absurd (hid ▸ List.mem_map_of_mem hb') hnotin
      · rcases List.mem_cons.mp hb with rfl | hb'
        · exact absurd (hid ▸ List.mem_map_of_mem ha') hnotin
        · exact ih hcs a ha' b hb' hid

/-- Appending one node at the END of a `nodesWF` list, given its inputs are bounded by all prior
    ids: the topological invariant is preserved (each earlier node's check is unchanged). -/
theorem nodesWF_snoc {α} (ed ea : Nat) :
    ∀ (ns : List (Node α)) (n : Node α) (seen : List Nat),
      nodesWF ed ea seen ns →
      (∀ r ∈ n.ins, refBounded ed ea (seen ++ ns.map Node.id) r) →
      nodesWF ed ea seen (ns ++ [n]) := by
  intro ns
  induction ns with
  | nil =>
      intro n seen _ hb
      refine ⟨?_, trivial⟩
      intro r hr
      have := hb r hr
      simpa using this
  | cons m ms ih =>
      intro n seen hwf hb
      obtain ⟨hm, hrest⟩ := hwf
      refine ⟨hm, ?_⟩
      apply ih n (seen ++ [m.id]) hrest
      intro r hr
      have := hb r hr
      rw [List.map_cons] at this
      rw [List.append_assoc, List.cons_append, List.nil_append]
      exact this

/-! ### Per-op stack-membership (non-CALL): a step only shuffles/duplicates existing refs or pushes
    a fresh `const _ false`. This single lemma discharges all 18 stack ops for `RefValid`-transfer. -/

/-- The membership target: `r` is an old-main ref, an old-alt ref, or a fresh const-false. -/
def Qm {α} (main alt : List (Ref α)) (r : Ref α) : Prop :=
  r ∈ main ∨ r ∈ alt ∨ ∃ v, r = Ref.const v false

private theorem subQ {α} (main alt l : List (Ref α)) (h : l ⊆ main) :
    ∀ r ∈ l, Qm main alt r := fun _ hr => Or.inl (h hr)

/-- Every ref produced by a NON-CALL `decStep` is an old main/alt ref or a fresh const-false; and
    the node list and next-id are untouched. -/
theorem decStep_noncall_mem {α} [Inhabited α] (o : Op α) (main alt : List (Ref α))
    (nd : List (Node α)) (id : Nat) (d' : DState α)
    (hne : ∀ nin sem, o ≠ CALL nin sem)
    (hstep : decStep o ⟨main, alt, nd, id⟩ = some d') :
    d'.nodes = nd ∧ d'.nextId = id ∧
    (∀ r ∈ d'.main, Qm main alt r) ∧ (∀ r ∈ d'.alt, Qm main alt r) := by
  cases o with
  | DUP =>
      rcases main with _ | ⟨x, s⟩ <;> simp only [decStep] at hstep <;> (try contradiction)
      obtain rfl := (Option.some.inj hstep).symm
      refine ⟨rfl, rfl, subQ _ _ _ ?_, fun r hr => Or.inr (Or.inl hr)⟩
      intro r hr; simp only [List.mem_cons] at hr ⊢; rcases hr with rfl|rfl|h <;> simp_all
  | DROP =>
      rcases main with _ | ⟨x, s⟩ <;> simp only [decStep] at hstep <;> (try contradiction)
      obtain rfl := (Option.some.inj hstep).symm
      refine ⟨rfl, rfl, subQ _ _ _ ?_, fun r hr => Or.inr (Or.inl hr)⟩
      intro r hr; simp only [List.mem_cons] at hr ⊢; simp_all
  | OVER =>
      rcases main with _ | ⟨x, _ | ⟨y, s⟩⟩ <;> simp only [decStep] at hstep <;> (try contradiction)
      obtain rfl := (Option.some.inj hstep).symm
      refine ⟨rfl, rfl, subQ _ _ _ ?_, fun r hr => Or.inr (Or.inl hr)⟩
      intro r hr; simp only [List.mem_cons] at hr ⊢; rcases hr with rfl|rfl|rfl|h <;> simp_all
  | SWAP =>
      rcases main with _ | ⟨x, _ | ⟨y, s⟩⟩ <;> simp only [decStep] at hstep <;> (try contradiction)
      obtain rfl := (Option.some.inj hstep).symm
      refine ⟨rfl, rfl, subQ _ _ _ ?_, fun r hr => Or.inr (Or.inl hr)⟩
      intro r hr; simp only [List.mem_cons] at hr ⊢; rcases hr with rfl|rfl|h <;> simp_all
  | ROT =>
      rcases main with _ | ⟨x, _ | ⟨y, _ | ⟨z, s⟩⟩⟩ <;>
        simp only [decStep] at hstep <;> (try contradiction)
      obtain rfl := (Option.some.inj hstep).symm
      refine ⟨rfl, rfl, subQ _ _ _ ?_, fun r hr => Or.inr (Or.inl hr)⟩
      intro r hr; simp only [List.mem_cons] at hr ⊢; rcases hr with rfl|rfl|rfl|h <;> simp_all
  | NIP =>
      rcases main with _ | ⟨x, _ | ⟨y, s⟩⟩ <;> simp only [decStep] at hstep <;> (try contradiction)
      obtain rfl := (Option.some.inj hstep).symm
      refine ⟨rfl, rfl, subQ _ _ _ ?_, fun r hr => Or.inr (Or.inl hr)⟩
      intro r hr; simp only [List.mem_cons] at hr ⊢; rcases hr with rfl|h <;> simp_all
  | TUCK =>
      rcases main with _ | ⟨x, _ | ⟨y, s⟩⟩ <;> simp only [decStep] at hstep <;> (try contradiction)
      obtain rfl := (Option.some.inj hstep).symm
      refine ⟨rfl, rfl, subQ _ _ _ ?_, fun r hr => Or.inr (Or.inl hr)⟩
      intro r hr; simp only [List.mem_cons] at hr ⊢; rcases hr with rfl|rfl|rfl|h <;> simp_all
  | TWODROP =>
      rcases main with _ | ⟨x, _ | ⟨y, s⟩⟩ <;> simp only [decStep] at hstep <;> (try contradiction)
      obtain rfl := (Option.some.inj hstep).symm
      refine ⟨rfl, rfl, subQ _ _ _ ?_, fun r hr => Or.inr (Or.inl hr)⟩
      intro r hr; simp only [List.mem_cons] at hr ⊢; simp_all
  | TWODUP =>
      rcases main with _ | ⟨x, _ | ⟨y, s⟩⟩ <;> simp only [decStep] at hstep <;> (try contradiction)
      obtain rfl := (Option.some.inj hstep).symm
      refine ⟨rfl, rfl, subQ _ _ _ ?_, fun r hr => Or.inr (Or.inl hr)⟩
      intro r hr; simp only [List.mem_cons] at hr ⊢
      rcases hr with rfl|rfl|rfl|rfl|h <;> simp_all
  | THREEDUP =>
      rcases main with _ | ⟨x, _ | ⟨y, _ | ⟨z, s⟩⟩⟩ <;>
        simp only [decStep] at hstep <;> (try contradiction)
      obtain rfl := (Option.some.inj hstep).symm
      refine ⟨rfl, rfl, subQ _ _ _ ?_, fun r hr => Or.inr (Or.inl hr)⟩
      intro r hr; simp only [List.mem_cons] at hr ⊢
      rcases hr with rfl|rfl|rfl|rfl|rfl|rfl|h <;> simp_all
  | TWOOVER =>
      rcases main with _ | ⟨x, _ | ⟨y, _ | ⟨z, _ | ⟨w, s⟩⟩⟩⟩ <;>
        simp only [decStep] at hstep <;> (try contradiction)
      obtain rfl := (Option.some.inj hstep).symm
      refine ⟨rfl, rfl, subQ _ _ _ ?_, fun r hr => Or.inr (Or.inl hr)⟩
      intro r hr; simp only [List.mem_cons] at hr ⊢
      rcases hr with rfl|rfl|rfl|rfl|rfl|rfl|h <;> simp_all
  | TWOROT =>
      rcases main with _ | ⟨x, _ | ⟨y, _ | ⟨z, _ | ⟨w, _ | ⟨u, _ | ⟨v, s⟩⟩⟩⟩⟩⟩ <;>
        simp only [decStep] at hstep <;> (try contradiction)
      obtain rfl := (Option.some.inj hstep).symm
      refine ⟨rfl, rfl, subQ _ _ _ ?_, fun r hr => Or.inr (Or.inl hr)⟩
      intro r hr; simp only [List.mem_cons] at hr ⊢
      rcases hr with rfl|rfl|rfl|rfl|rfl|rfl|h <;> simp_all
  | TWOSWAP =>
      rcases main with _ | ⟨x, _ | ⟨y, _ | ⟨z, _ | ⟨w, s⟩⟩⟩⟩ <;>
        simp only [decStep] at hstep <;> (try contradiction)
      obtain rfl := (Option.some.inj hstep).symm
      refine ⟨rfl, rfl, subQ _ _ _ ?_, fun r hr => Or.inr (Or.inl hr)⟩
      intro r hr; simp only [List.mem_cons] at hr ⊢
      rcases hr with rfl|rfl|rfl|rfl|h <;> simp_all
  | TOALT =>
      rcases main with _ | ⟨x, s⟩ <;> simp only [decStep] at hstep <;> (try contradiction)
      obtain rfl := (Option.some.inj hstep).symm
      refine ⟨rfl, rfl, ?_, ?_⟩
      · intro r hr; exact Or.inl (List.mem_cons_of_mem _ hr)
      · intro r hr; simp only [List.mem_cons] at hr
        rcases hr with rfl | h
        · exact Or.inl (List.mem_cons_self ..)
        · exact Or.inr (Or.inl h)
  | FROMALT =>
      rcases alt with _ | ⟨x, a⟩ <;> simp only [decStep] at hstep <;> (try contradiction)
      obtain rfl := (Option.some.inj hstep).symm
      refine ⟨rfl, rfl, ?_, ?_⟩
      · intro r hr; simp only [List.mem_cons] at hr
        rcases hr with rfl | h
        · exact Or.inr (Or.inl (List.mem_cons_self ..))
        · exact Or.inl h
      · intro r hr; exact Or.inr (Or.inl (List.mem_cons_of_mem _ hr))
  | PUSH v0 =>
      simp only [decStep] at hstep
      obtain rfl := (Option.some.inj hstep).symm
      refine ⟨rfl, rfl, ?_, fun r hr => Or.inr (Or.inl hr)⟩
      intro r hr; simp only [List.mem_cons] at hr
      rcases hr with rfl | h
      · exact Or.inr (Or.inr ⟨v0, rfl⟩)
      · exact Or.inl h
  | PICK n =>
      simp only [decStep] at hstep
      rcases hpk : main[n]? with _ | v <;> rw [hpk] at hstep
      · simp at hstep
      · simp only [Option.map_some] at hstep
        obtain rfl := (Option.some.inj hstep).symm
        refine ⟨rfl, rfl, ?_, fun r hr => Or.inr (Or.inl hr)⟩
        intro r hr; simp only [List.mem_cons] at hr
        rcases hr with rfl | h
        · exact Or.inl (List.mem_of_getElem? hpk)
        · exact Or.inl h
  | ROLL n =>
      simp only [decStep] at hstep
      rcases hpk : main[n]? with _ | v <;> rw [hpk] at hstep
      · simp at hstep
      · obtain rfl := (Option.some.inj hstep).symm
        refine ⟨rfl, rfl, ?_, fun r hr => Or.inr (Or.inl hr)⟩
        intro r hr; simp only [List.mem_cons] at hr
        rcases hr with rfl | h
        · exact Or.inl (List.mem_of_getElem? hpk)
        · refine Or.inl ?_
          rw [removeNth, List.mem_append] at h
          rcases h with h | h
          · exact List.mem_of_mem_take h
          · exact List.mem_of_mem_drop h
  | CALL nin sem => exact absurd rfl (hne nin sem)

/-- `Qm` transfers to `RefValid` given the old stacks are `RefValid` (const-false is trivially so). -/
theorem RefValid_of_Qm {α} (ed ea : Nat) (nodes : List (Node α)) (main alt : List (Ref α))
    (hm : ∀ r ∈ main, RefValid ed ea nodes r) (ha : ∀ r ∈ alt, RefValid ed ea nodes r)
    (r : Ref α) (hq : Qm main alt r) : RefValid ed ea nodes r := by
  rcases hq with h | h | ⟨v, rfl⟩
  · exact hm r h
  · exact ha r h
  · exact trivial

/-! ### The walk-state invariant `DWF` and its preservation. -/

/-- The decompiler walk-state invariant (six clauses, all decompile.mjs invariants by
    construction). -/
structure DWF {α} (ed ea : Nat) (d : DState α) : Prop where
  ids   : d.nodes.map Node.id = List.range d.nextId
  topo  : nodesWF ed ea [] d.nodes
  arity : ∀ n ∈ d.nodes, n.ins.length = n.op.nin
  vmain : ∀ r ∈ d.main, RefValid ed ea d.nodes r
  valt  : ∀ r ∈ d.alt,  RefValid ed ea d.nodes r
  vins  : ∀ n ∈ d.nodes, ∀ r ∈ n.ins, RefValid ed ea d.nodes r

/-- ★ `DWF` preservation under one `decStep`. Non-CALL: refs shuffle (`decStep_noncall_mem`),
    nodes untouched. CALL: append the fresh node; its operands are `RefValid` prior refs, its
    output refs are `RefValid` against the extended list, ids extend by `range_succ`. -/
theorem decStep_DWF {α} [Inhabited α] (ed ea : Nat) {o : Op α} {d d' : DState α}
    (hwf : DWF ed ea d) (hstep : decStep o d = some d') : DWF ed ea d' := by
  obtain ⟨main, alt, nd, id⟩ := d
  by_cases hc : ∃ nin sem, o = CALL nin sem
  · -- CALL
    obtain ⟨nin, sem, rfl⟩ := hc
    simp only [decStep] at hstep
    split at hstep
    · next hle =>
        obtain rfl := (Option.some.inj hstep).symm
        -- name the output-arity so the fresh node/out-refs share one atom (no mathlib `set`)
        generalize hg : (sem (List.replicate nin (default : α))).length = nout
        -- operands of the fresh node are `RefValid` prior refs
        have hins_valid : ∀ r ∈ (main.take nin).reverse, RefValid ed ea nd r := by
          intro r hr
          exact hwf.vmain r (List.mem_of_mem_take (List.mem_reverse.mp hr))
        refine ⟨?ids, ?topo, ?arity, ?vmain, ?valt, ?vins⟩
        · -- ids : (nd ++ [newnode]).map id = range (id+1)
          rw [List.map_append, List.map_cons, List.map_nil, hwf.ids]
          show List.range id ++ [id] = List.range (id + 1)
          rw [List.range_succ]
        · -- topo
          refine nodesWF_snoc ed ea nd ⟨id, ⟨nin, nout, sem⟩, (main.take nin).reverse⟩ []
            hwf.topo ?_
          intro r hr
          rw [List.nil_append]
          exact RefValid_refBounded ed ea nd r (hins_valid r hr)
        · -- arity
          intro n hn
          rw [List.mem_append, List.mem_singleton] at hn
          rcases hn with hn | rfl
          · exact hwf.arity n hn
          · show (main.take nin).reverse.length = nin
            rw [List.length_reverse, List.length_take]; omega
        · -- vmain
          intro r hr
          show RefValid ed ea (nd ++ [(⟨id, ⟨nin, nout, sem⟩, (main.take nin).reverse⟩ : Node α)]) r
          rw [List.mem_append] at hr
          rcases hr with hr | hr
          · -- fresh output refs
            rw [List.mem_reverse, List.mem_map] at hr
            obtain ⟨j, hjmem, rfl⟩ := hr
            rw [List.mem_range] at hjmem
            exact ⟨⟨id, ⟨nin, nout, sem⟩, (main.take nin).reverse⟩,
              List.mem_append_right _ (List.mem_singleton.mpr rfl), rfl, hjmem⟩
          · -- carried-over refs from main.drop
            exact RefValid_mono ed ea nd _ r (hwf.vmain r (List.mem_of_mem_drop hr))
        · -- valt (unchanged)
          intro r hr
          exact RefValid_mono ed ea nd _ r (hwf.valt r hr)
        · -- vins
          intro n hn r hr
          rw [List.mem_append, List.mem_singleton] at hn
          rcases hn with hn | rfl
          · exact RefValid_mono ed ea nd _ r (hwf.vins n hn r hr)
          · exact RefValid_mono ed ea nd _ r (hins_valid r hr)
    · next hle => exact absurd hstep (by simp)
  · -- non-CALL
    have hne : ∀ nin sem, o ≠ CALL nin sem := fun nin sem h => hc ⟨nin, sem, h⟩
    obtain ⟨hn, hi, hqm, hqa⟩ := decStep_noncall_mem o main alt nd id d' hne hstep
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
    · rw [hn, hi]; exact hwf.ids
    · rw [hn]; exact hwf.topo
    · rw [hn]; exact hwf.arity
    · intro r hr
      rw [hn]
      exact RefValid_of_Qm ed ea nd main alt hwf.vmain hwf.valt r (hqm r hr)
    · intro r hr
      rw [hn]
      exact RefValid_of_Qm ed ea nd main alt hwf.vmain hwf.valt r (hqa r hr)
    · rw [hn]; exact hwf.vins

/-- ★ `DWF` preservation across the whole op-fold. -/
theorem decFold_DWF {α} [Inhabited α] (ed ea : Nat) :
    ∀ (os : List (Op α)) (d dfin : DState α),
      decFold os d = some dfin → DWF ed ea d → DWF ed ea dfin := by
  intro os
  induction os with
  | nil =>
      intro d dfin h hwf
      simp only [decFold] at h; injection h with h; subst h; exact hwf
  | cons o os ih =>
      intro d dfin h hwf
      simp only [decFold] at h
      cases hstep : decStep o d with
      | none => rw [hstep] at h; exact absurd h (by simp)
      | some d1 =>
          rw [hstep] at h
          exact ih d1 dfin h (decStep_DWF ed ea hwf hstep)

/-- The seeded walk-state satisfies `DWF` (entry `inp`/`ainp` slots are in-bounds; no nodes yet). -/
theorem seed_DWF {α} [Inhabited α] (ed ea : Nat) :
    DWF ed ea (⟨((List.range ed).map Ref.inp).reverse,
               ((List.range ea).map Ref.ainp).reverse, [], 0⟩ : DState α) := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · rfl
  · exact trivial
  · intro n hn; exact absurd hn (List.not_mem_nil)
  · intro r hr
    rw [List.mem_reverse, List.mem_map] at hr
    obtain ⟨i, hi, rfl⟩ := hr
    rw [List.mem_range] at hi
    exact hi
  · intro r hr
    rw [List.mem_reverse, List.mem_map] at hr
    obtain ⟨i, hi, rfl⟩ := hr
    rw [List.mem_range] at hi
    exact hi
  · intro n hn; exact absurd hn (List.not_mem_nil)

/-! ### Extracting the block from an accepting walk. -/

/-- `decompileBlock` accepted ⟹ a final walk-state `dfin`, with `b` its close-up. -/
theorem decompileBlock_dfin {α} [Inhabited α] (rawOps : List (Op α)) (ed ea : Nat) (b : Block α)
    (hb : decompileBlock rawOps ed ea = some b) :
    ∃ dfin, decFold rawOps
        (⟨((List.range ed).map Ref.inp).reverse,
          ((List.range ea).map Ref.ainp).reverse, [], 0⟩ : DState α) = some dfin ∧
      b.entryDepth = ed ∧ b.entryAlt = ea ∧ b.nodes = dfin.nodes ∧
      b.exit = dfin.main.reverse ∧ b.exitAlt = dfin.alt.reverse := by
  rw [decompileBlock, Option.map_eq_some_iff] at hb
  obtain ⟨dfin, hfold, hbeq⟩ := hb
  exact ⟨dfin, hfold, by rw [← hbeq], by rw [← hbeq], by rw [← hbeq], by rw [← hbeq], by rw [← hbeq]⟩

/-! ### ★★ THE SIX UNCONDITIONAL WellFormed CONJUNCTS (everything except `semArity`). -/

/-- ★ Six of the seven WellFormed conjuncts hold for ANY block the decompiler accepts, with NO
    hypothesis on the raw ops. (Conjuncts, in `WellFormed` order: `nodesWF`, exit-bounded,
    exitAlt-bounded, `distinctIds`, `arity`, `outIdx`.) -/
theorem decompileBlock_WF_noSem {α} [Inhabited α] (rawOps : List (Op α)) (ed ea : Nat) (b : Block α)
    (hb : decompileBlock rawOps ed ea = some b) :
    nodesWF b.entryDepth b.entryAlt [] b.nodes ∧
    (∀ r ∈ b.exit,    refBounded b.entryDepth b.entryAlt (b.nodes.map Node.id) r) ∧
    (∀ r ∈ b.exitAlt, refBounded b.entryDepth b.entryAlt (b.nodes.map Node.id) r) ∧
    (b.nodes.map Node.id).Nodup ∧
    (∀ n ∈ b.nodes, n.ins.length = n.op.nin) ∧
    (∀ nid j, Ref.out nid j ∈ (b.nodes.flatMap Node.ins ++ b.exit ++ b.exitAlt) →
       ∀ nd ∈ b.nodes, nd.id = nid → j < nd.op.nout) := by
  obtain ⟨dfin, hfold, hed, hea, hnodes, hexit, hexitAlt⟩ :=
    decompileBlock_dfin rawOps ed ea b hb
  have hwf : DWF ed ea dfin := decFold_DWF ed ea rawOps _ dfin hfold (seed_DWF ed ea)
  -- rewrite b's fields
  have hnd_nodup : (b.nodes.map Node.id).Nodup := by
    rw [hnodes, hwf.ids]; exact List.nodup_range
  refine ⟨?_, ?_, ?_, hnd_nodup, ?_, ?_⟩
  · rw [hed, hea, hnodes]; exact hwf.topo
  · -- exit bounded
    intro r hr
    rw [hexit, List.mem_reverse] at hr
    rw [hed, hea, hnodes]
    exact RefValid_refBounded ed ea dfin.nodes r (hwf.vmain r hr)
  · -- exitAlt bounded
    intro r hr
    rw [hexitAlt, List.mem_reverse] at hr
    rw [hed, hea, hnodes]
    exact RefValid_refBounded ed ea dfin.nodes r (hwf.valt r hr)
  · -- arity
    rw [hnodes]; exact hwf.arity
  · -- outIdx
    intro nid j hmem ndd hndmem hid
    -- the ref is RefValid against dfin.nodes
    have hrv : RefValid ed ea dfin.nodes (Ref.out nid j) := by
      rw [hnodes, hexit, hexitAlt] at hmem
      rw [List.mem_append, List.mem_append] at hmem
      rcases hmem with (hmem | hmem) | hmem
      · -- in node ins
        rw [List.mem_flatMap] at hmem
        obtain ⟨n, hnmem, hrmem⟩ := hmem
        exact hwf.vins n hnmem (Ref.out nid j) hrmem
      · -- in exit
        rw [List.mem_reverse] at hmem
        exact hwf.vmain (Ref.out nid j) hmem
      · -- in exitAlt
        rw [List.mem_reverse] at hmem
        exact hwf.valt (Ref.out nid j) hmem
    obtain ⟨nd0, hnd0mem, hnd0id, hj⟩ := hrv
    -- nd0 = ndd by injectivity on ids
    have hnd_nodup' : (dfin.nodes.map Node.id).Nodup := by rw [hwf.ids]; exact List.nodup_range
    rw [hnodes] at hndmem
    have heq : ndd = nd0 :=
      nodes_id_inj dfin.nodes hnd_nodup' ndd hndmem nd0 hnd0mem (by rw [hid, hnd0id])
    rw [heq]; exact hj

/-! ### `semArity` (the 7th conjunct) — the ONE clause that needs a premise on the raw ops. -/

/-- A raw op is uniform-arity: a CALL's `sem` returns the SAME length on every `nin`-length input
    (so the stored `nout = |sem (replicate nin default)|` is the arity for ALL inputs). This is a
    genuine property of real value-ops (fixed output count) and the ONLY thing `decompileBlock`
    does not itself enforce. Non-CALL ops are trivially uniform. -/
def OpUniform {α} [Inhabited α] (o : Op α) : Prop :=
  ∀ nin sem, o = CALL nin sem →
    ∀ l : List α, l.length = nin → (sem l).length = (sem (List.replicate nin default)).length

/-- The walk-state `semArity` invariant. -/
def SemWF {α} (d : DState α) : Prop :=
  ∀ n ∈ d.nodes, ∀ l : List α, l.length = n.op.nin → (n.op.sem l).length = n.op.nout

/-- `SemWF` preservation under one `decStep`, given the op is uniform. -/
theorem decStep_SemWF {α} [Inhabited α] {o : Op α} {d d' : DState α}
    (hop : OpUniform o) (hstep : decStep o d = some d') (hsem : SemWF d) : SemWF d' := by
  obtain ⟨main, alt, nd, id⟩ := d
  by_cases hc : ∃ nin sem, o = CALL nin sem
  · obtain ⟨nin, sem, rfl⟩ := hc
    simp only [decStep] at hstep
    split at hstep
    · next hle =>
        obtain rfl := (Option.some.inj hstep).symm
        intro n hn l hl
        rw [List.mem_append, List.mem_singleton] at hn
        rcases hn with hn | rfl
        · exact hsem n hn l hl
        · -- the fresh node: uniform arity from `hop`
          show (sem l).length = (sem (List.replicate nin (default : α))).length
          exact hop nin sem rfl l hl
    · next hle => exact absurd hstep (by simp)
  · have hne : ∀ nin sem, o ≠ CALL nin sem := fun nin sem h => hc ⟨nin, sem, h⟩
    obtain ⟨hn, _, _, _⟩ := decStep_noncall_mem o main alt nd id d' hne hstep
    intro n hn' l hl
    rw [hn] at hn'
    exact hsem n hn' l hl

/-- `SemWF` preservation across the fold, given every op is uniform. -/
theorem decFold_SemWF {α} [Inhabited α] :
    ∀ (os : List (Op α)) (d dfin : DState α),
      (∀ o ∈ os, OpUniform o) → decFold os d = some dfin → SemWF d → SemWF dfin := by
  intro os
  induction os with
  | nil =>
      intro d dfin _ h hsem
      simp only [decFold] at h; injection h with h; subst h; exact hsem
  | cons o os ih =>
      intro d dfin hops h hsem
      simp only [decFold] at h
      cases hstep : decStep o d with
      | none => rw [hstep] at h; exact absurd h (by simp)
      | some d1 =>
          rw [hstep] at h
          have hop : OpUniform o := hops o (List.mem_cons_self ..)
          have hops' : ∀ o' ∈ os, OpUniform o' := fun o' ho' => hops o' (List.mem_cons_of_mem _ ho')
          exact ih d1 dfin hops' h (decStep_SemWF hop hstep hsem)

/-- The seed trivially satisfies `SemWF` (no nodes). -/
theorem seed_SemWF {α} [Inhabited α] (ed ea : Nat) :
    SemWF (⟨((List.range ed).map Ref.inp).reverse,
           ((List.range ea).map Ref.ainp).reverse, [], 0⟩ : DState α) := by
  intro n hn; exact absurd hn (List.not_mem_nil)

/-! ### ★★★ THE HEADLINE: decompile ⇒ WellFormed, and the discharged end-to-end corollary. -/

/-- ★ THE FULL WellFormed, given the (unavoidable, minimal) `OpUniform` premise on the raw ops.
    Six conjuncts are unconditional (`decompileBlock_WF_noSem`); `semArity` is the seventh. -/
theorem decompileBlock_WellFormed {α} [Inhabited α] (rawOps : List (Op α)) (ed ea : Nat)
    (b : Block α) (hops : ∀ o ∈ rawOps, OpUniform o)
    (hb : decompileBlock rawOps ed ea = some b) : WellFormed b := by
  obtain ⟨h1, h2, h3, h4, h5, h7⟩ := decompileBlock_WF_noSem rawOps ed ea b hb
  refine ⟨h1, h2, h3, h4, h5, ?_, h7⟩
  -- semArity
  obtain ⟨dfin, hfold, _, _, hnodes, _, _⟩ := decompileBlock_dfin rawOps ed ea b hb
  have hsem : SemWF dfin := decFold_SemWF rawOps _ dfin hops hfold (seed_SemWF ed ea)
  rw [hnodes]; exact hsem

/-- ★★ THE DISCHARGED END-TO-END: for a straight-line block the decompiler accepts (whose value-ops
    have fixed output arity), the RECOMPILED bytes run identically to the ORIGINAL ops on ALL
    inputs — with NO `WellFormed` hypothesis (it is now PROVEN from acceptance). -/
theorem decompile_end_to_end {α} [DecidableEq α] [Inhabited α]
    (rawOps : List (Op α)) (ed ea : Nat) (M A : List α)
    (hM : M.length = ed) (hA : A.length = ea)
    (b : Block α) (hops : ∀ o ∈ rawOps, OpUniform o)
    (hb : decompileBlock rawOps ed ea = some b) :
    run (emit b) (entryState M A) = run rawOps (entryState M A) :=
  end_to_end rawOps ed ea M A hM hA b hb
    (decompileBlock_WellFormed rawOps ed ea b hops hb)

/-! ### ★ NON-VACUITY WITNESS — the discharged theorems FIRE on a concrete program with a genuine
    CALL (guards against a trivialising / vacuous `WellFormed` proof, matching Decompile.lean's
    `egBlock` culture). `[a,b] ↦ [a+b]` is a real length-uniform value-op. -/

/-- A real binary value-op: `nin = 2`, always `nout = 1` (hence `OpUniform`). -/
private def wSem : List Nat → List Nat := fun l => [l.headD 0 + l.tail.headD 0]

/-- Program `PUSH 3; PUSH 4; CALL 2 wSem`. -/
private def wOps : List (Op Nat) := [Op.PUSH 3, Op.PUSH 4, Op.CALL 2 wSem]

/-- Its ops are `OpUniform` (the CALL's `sem` is fixed-arity; the PUSHes vacuously). -/
private theorem wOps_uniform : ∀ o ∈ wOps, OpUniform o := by
  intro o ho
  simp only [wOps, List.mem_cons, List.not_mem_nil, or_false] at ho
  rcases ho with rfl | rfl | rfl
  · intro nin sem h; exact absurd h (by simp)
  · intro nin sem h; exact absurd h (by simp)
  · intro nin sem h
    injection h with hnin hsem
    subst hnin; subst hsem
    intro l hl; rfl

/-- ★ CAPSTONE: `decompileBlock_WellFormed` FIRES — the decompiled block is provably `WellFormed`,
    every hypothesis discharged, no `hwf` assumed. -/
example : ∃ b, decompileBlock wOps 0 0 = some b ∧ WellFormed b :=
  ⟨_, rfl, decompileBlock_WellFormed wOps 0 0 _ wOps_uniform rfl⟩

/-- ★ CAPSTONE (end-to-end, premise-free of `WellFormed`): recompiled run = original run, PROVEN
    for the concrete program straight from acceptance. -/
example : ∃ b, decompileBlock wOps 0 0 = some b ∧
    run (emit b) (entryState ([] : List Nat) []) = run wOps (entryState [] []) :=
  ⟨_, rfl, decompile_end_to_end wOps 0 0 [] [] rfl rfl _ wOps_uniform rfl⟩

end LeanBCH.Opt
