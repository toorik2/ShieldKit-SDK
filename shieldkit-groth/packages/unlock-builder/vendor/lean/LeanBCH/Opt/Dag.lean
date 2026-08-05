/-
  PASS-2 DAG-SCHEDULER — the value-DAG type + its DENOTATION.

  Models the straight-line `Block` produced by tools/singleton-recompiler/decompile.mjs:
  a pure mapping of an entry stack (`entryDepth` opaque main slots + `entryAlt` alt slots)
  to an exit main+alt layout of value-DAGs over those slots.

  ★ OPAQUE-OPERATOR ABSTRACTION (the enabling move): a node's op (prim VALOP / INVOKE) is
  NOT interpreted — it is an uninterpreted `NodeOp` (nin ↦ nout, `sem : List α → List α`,
  bottom→top ↦ bottom→top). `denote` and the emitter (Scheduler.lean) reference the SAME
  `NodeOp` per node, so the executed arithmetic is irrelevant to correctness: only the
  WIRING matters. This is why the scheduler theorem holds over an abstract `α`.

  Convention inherited from the spike (Basic.lean): `State α = List α × List α`, HEAD = TOP
  (the reverse of decompile.mjs's bottom→top arrays; isomorphic, pattern-matches cleanly).
  `Ref`/`Node.ins`/`Block.exit`/`Block.exitAlt` are all in decompile's bottom→top order.

  BRIDGE (out of scope for THIS theorem, documented): `run(original_block_bytecode) =
  denote(block)` is the decompile round-trip / `flattenIdentity` faithfulness primitive
  (the spike's territory), taken here as the SPEC. This layer proves `run(emit) = denote`.

  Lean 4 core only; NO mathlib. Denotation needs a fallback value for out-of-range indices
  (all discharged by `WellFormed` below), hence `[Inhabited α]` on the denotation defs only.
-/
import LeanBCH.Opt.Basic

namespace LeanBCH.Opt

/-- An uninterpreted DAG-node operator: pops `nin` operands (bottom→top), pushes `nout`
    results (bottom→top). `sem` is the abstract value function; never inspected by the
    correctness proof (only wiring matters). -/
structure NodeOp (α : Type) where
  nin  : Nat
  nout : Nat
  sem  : List α → List α

/-- A DAG value reference (decompile ref kinds `{in, ain, const, out}`). `const`'s `cse`
    flag marks a CSE-eligible constant (encoded length ≥ 3 in scheduler.mjs: pushed once,
    reused by copy); `cse = false` is a small constant that is always freshly re-pushed. -/
inductive Ref (α : Type) where
  | inp   (i : Nat)              -- entry main slot i           (in:i)
  | ainp  (i : Nat)              -- entry alt slot i            (ain:i)
  | const (v : α) (cse : Bool)   -- constant value              (const)
  | out   (nid : Nat) (j : Nat)  -- j-th output of node `nid`   (out)
  deriving DecidableEq

/-- A DAG node: unique `id`, its op, and its inputs in bottom→top order
    (decompile `popN`/`unshift` ⇒ `ins[k-1]` is the top operand). -/
structure Node (α : Type) where
  id  : Nat
  op  : NodeOp α
  ins : List (Ref α)

/-- A straight-line block = pure entry→exit stack mapping. `nodes` is a valid TOPOLOGICAL
    order (each node's `out`-inputs have ids appearing earlier). `exit`/`exitAlt` in
    bottom→top order. -/
structure Block (α : Type) where
  entryDepth : Nat
  entryAlt   : Nat
  nodes      : List (Node α)
  exit       : List (Ref α)
  exitAlt    : List (Ref α)

/-- Node-output environment: `env nid = ` the (bottom→top) output list of node `nid`
    (default `[]` for not-yet / never computed). -/
abbrev Env (α : Type) := Nat → List α

/-- Denote one ref to its value, given entry mains `M`, entry alts `A` (bottom→top), and the
    node-output environment `env`. Out-of-range = `default` (excluded by `WellFormed`). -/
def dRef [Inhabited α] (M A : List α) (env : Env α) : Ref α → α
  | .inp i       => M.getD i default
  | .ainp i      => A.getD i default
  | .const v _   => v
  | .out nid j   => (env nid).getD j default

/-- Fold the (topologically ordered) node list into the output environment. Because the
    order is topological, every node's `out`-inputs are already resolved in `env` when it
    is folded, so this straight structural fold (no well-founded recursion) is faithful. -/
def denoteNodes [Inhabited α] (M A : List α) : List (Node α) → Env α → Env α
  | [],      env => env
  | n :: ns, env =>
      denoteNodes M A ns (fun q => if q = n.id then n.op.sem (n.ins.map (dRef M A env)) else env q)

/-- ★ DENOTATION: the block's exit `State α` (head = top) as a function of the entry
    value-lists `M A` (bottom→top). This is the SPEC the emitter must refine. -/
def denote [Inhabited α] (b : Block α) (M A : List α) : State α :=
  let envF := denoteNodes M A b.nodes (fun _ => [])
  ( (b.exit.map    (dRef M A envF)).reverse,
    (b.exitAlt.map (dRef M A envF)).reverse )

/-! ### WellFormed — the decompile-invariant surfaced as a Lean predicate.
    decompile.mjs THROWS on any violation, so blocks reaching the scheduler satisfy this. -/

/-- A ref is in-bounds given entry sizes and the ids declared SO FAR (for the topo check). -/
def refBounded (ed ea : Nat) (priorIds : List Nat) : Ref α → Prop
  | .inp i     => i < ed
  | .ainp i    => i < ea
  | .const _ _ => True
  | .out nid _ => nid ∈ priorIds

/-- Node list is a valid topological order: each node's inputs reference only entry slots,
    constants, or outputs of nodes appearing EARLIER (`seen`). -/
def nodesWF (ed ea : Nat) : List Nat → List (Node α) → Prop
  | _,    []      => True
  | seen, n :: ns => (∀ r ∈ n.ins, refBounded ed ea seen r) ∧ nodesWF ed ea (seen ++ [n.id]) ns

/-- WellFormed block: (topo-ordered acyclic nodes with in-bounds inputs) ∧ (exit/exitAlt refs
    reference declared node ids and in-range entry slots).

    ★ FAITHFULNESS CONJUNCTS (added for the PASS-2 wiring proof; each is a genuine decompile
    invariant, NOT a vacuous restriction — decompile.mjs enforces all three):
      • `distinctIds` — node ids are pairwise distinct (`Dag.lean`: "unique id"). REQUIRED by the
        DENOTATION LINK: `denoteNodes` overwrites by id, so an out-ref reads a *stable* value only
        if no later node reuses the id.
      • `arity`      — `n.ins.length = n.op.nin`: a node lists exactly `nin` operands (decompile
        builds `ins` by `popN a.in`). REQUIRED so the materialised operand block equals the `nin`
        the `CALL` consumes.
      • `semArity`   — `sem` returns exactly `nout` values on `nin`-length input (decompile builds
        each `out node j` with `j < a.out`, i.e. the op produces `nout` outputs). REQUIRED so the
        concrete `CALL` push count matches the model's `nout` output slots (the `Inv` at the CALL).
      • `outIdx`     — every `out nid j` referenced anywhere has `j < nout` of node `nid` (decompile
        creates `out node j` with `j < a.out`). REQUIRED so a demanded node output has a home slot
        among the `nout` outputs the `CALL` pushes (the R4-establishment).
    (These replace the elided "output-index bound" remark: the wiring proof needs the output
    COUNT and the index bound.) -/
def WellFormed (b : Block α) : Prop :=
  nodesWF b.entryDepth b.entryAlt [] b.nodes ∧
  (∀ r ∈ b.exit,    refBounded b.entryDepth b.entryAlt (b.nodes.map Node.id) r) ∧
  (∀ r ∈ b.exitAlt, refBounded b.entryDepth b.entryAlt (b.nodes.map Node.id) r) ∧
  (b.nodes.map Node.id).Nodup ∧
  (∀ n ∈ b.nodes, n.ins.length = n.op.nin) ∧
  (∀ n ∈ b.nodes, ∀ l : List α, l.length = n.op.nin → (n.op.sem l).length = n.op.nout) ∧
  (∀ nid j, Ref.out nid j ∈ (b.nodes.flatMap Node.ins ++ b.exit ++ b.exitAlt) →
     ∀ nd ∈ b.nodes, nd.id = nid → j < nd.op.nout)

end LeanBCH.Opt
