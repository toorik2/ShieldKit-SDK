/-
  PASS-2 DAG-SCHEDULER — the faithful EMITTER MODEL of tools/singleton-recompiler/scheduler.mjs
  (`scheduleBlock`). Produces a `List (Op α)` from a `Block`; correctness (run(emit) = denote)
  is proven in Simulation.lean.

  ★ KEY DECOMPOSITION (makes it tractable): verify the EMITTER, NOT the SEARCH. The scheduler's
  heuristics (ready-list node order, shallow-operand selection) only affect BYTES; correctness
  only needs that WHATEVER topological order it emits REFINES the DAG. So this model emits nodes
  in `block.nodes` order (itself a valid topological order under `WellFormed`) — the greedy
  reordering is an unverified byte optimisation, deliberately decoupled.

  Faithful to scheduler.mjs:
    * entry-alt DRAIN (FROMALT×entryAlt) unless `altPassthrough`; exit-alt DEPOSIT (…TOALT).
    * per node: CSE-const home setup → materialize each operand to top (MOVE via ROLL/SWAP/ROT
      if last use, else COPY via PICK/OVER/DUP from shallowest home) → CALL (the NodeOp) →
      push outputs → eager-drop dead top outputs.
    * final incremental main arrange: keep the longest matching bottom prefix; build the
      differing suffix on top; delete the stale tail underneath (DROP / NIP / ROLL;DROP).
    * const-CSE: eligible consts get a shared stack home (token `cTok v`); small consts
      (token `nullTok v`) are always freshly re-pushed.

  Depth→op folds mirror scheduler.mjs's `pushIntOps` shortcuts and are exactly the spike's
  proven peepholes (Peephole.lean: pick0_dup, pick1_over, roll1_swap, roll2_rot).

  Requires `[DecidableEq α]`: the model's residual-demand map and CSE home lookups key on
  tokens (scheduler.mjs keys CSE consts by their byte encoding — i.e. value equality).
-/
import Recompiler.Dag

namespace Recompiler

/-- Stack-slot identity. `nullTok` = a small (non-CSE) constant, always freshly re-pushed
    (never a shared home). -/
inductive Token (α : Type) where
  | inTok  (k : Nat)          -- entry main slot        (scheduler 'i'+k)
  | ainTok (k : Nat)          -- entry alt slot         ('a'+k)
  | vTok   (id : Nat) (j : Nat) -- node output          ('v'+id+'_'+j)
  | cTok   (v : α)            -- CSE-eligible const     ('c'+hex(enc))
  | nullTok (v : α)           -- small const (fresh)    (null)
  deriving DecidableEq

/-- A modelled main/alt-stack slot, 1:1 with the concrete stack. `transient` copies are
    operand scratch pushed for the current node; home lookups skip them. -/
structure Entry (α : Type) where
  tok       : Token α
  transient : Bool

/-- Emitter state: emitted ops (forward order), the modelled main stack `S` and alt stack
    `Salt` (both bottom→top, 1:1 with the concrete stacks INCLUDING transients), and the
    residual-demand map `use`. -/
structure ModelState (α : Type) where
  ops  : List (Op α)
  S    : List (Entry α)
  Salt : List (Entry α)
  use  : Token α → Nat

/-- The scheduler's token for a ref (`tokenOf`). Small consts ⇒ `nullTok` (always fresh). -/
def tokenOf : Ref α → Token α
  | .inp i       => .inTok i
  | .ainp i      => .ainTok i
  | .out nid j   => .vTok nid j
  | .const v true  => .cTok v
  | .const v false => .nullTok v

/-- COPY shortcut (scheduler `pushIntOps`+PICK folds): depth d ↦ DUP / OVER / PICK d. -/
def copyOps (d : Nat) : List (Op α) :=
  match d with
  | 0     => [Op.DUP]
  | 1     => [Op.OVER]
  | n + 2 => [Op.PICK (n + 2)]

/-- MOVE shortcut (ROLL folds): depth d ↦ (nothing) / SWAP / ROT / ROLL d. -/
def moveOps (d : Nat) : List (Op α) :=
  match d with
  | 0     => []
  | 1     => [Op.SWAP]
  | 2     => [Op.ROT]
  | n + 3 => [Op.ROLL (n + 3)]

/-- Stale-tail deletion op (final arrange), for `q` freshly-built items sitting on top:
    q=0 ⇒ DROP the top stale item; q=1 ⇒ NIP; q≥2 ⇒ ROLL the stale item up then DROP.
    In every case the net stack effect is erasing the element at depth `q`. -/
def delOps (q : Nat) : List (Op α) :=
  match q with
  | 0     => [Op.DROP]
  | 1     => [Op.NIP]
  | n + 2 => [Op.ROLL (n + 2), Op.DROP]

/-- `depthOfHome tok S` (scheduler.mjs): the depth-from-top of the topmost NON-transient
    entry whose token is `tok` (counts transients ⇒ equals concrete depth), or `none`. -/
def depthOfHome [DecidableEq α] (S : List (Entry α)) (tok : Token α) : Option Nat :=
  S.reverse.findIdx? (fun e => (!e.transient) && decide (e.tok = tok))

/-- Demand-map update (`use.set(t, use(t)+1)`); small consts (`nullTok`) are untracked. -/
def bumpUse [DecidableEq α] (u : Token α → Nat) (r : Ref α) : Token α → Nat :=
  match r with
  | .const _ false => u
  | _ => let t := tokenOf r; fun t' => if t' = t then u t' + 1 else u t'

/-- Demand-map decrement (`use.set(t, use(t)-1)`). -/
def decUse [DecidableEq α] (u : Token α → Nat) (t : Token α) : Token α → Nat :=
  fun t' => if t' = t then u t' - 1 else u t'

/-- Residual-demand over all needed nodes' `ins` + `exit` (+ `exitAlt` unless passthrough). -/
def demand [DecidableEq α] (b : Block α) (pass : Bool) : Token α → Nat :=
  let insRefs := b.nodes.flatMap (fun n => n.ins)
  let refs    := insRefs ++ b.exit ++ (bif pass then [] else b.exitAlt)
  refs.foldl bumpUse (fun _ => 0)

/-- Alt-passthrough test (`altPassthrough`): no entry-alt slot is pulled to main, and exitAlt
    is the exact identity carry of entryAlt ⇒ leave the altstack completely untouched. -/
def altPassthrough [DecidableEq α] (b : Block α) : Bool :=
  let ainRef := (b.nodes.flatMap (fun n => n.ins) ++ b.exit).any
    (fun r => match r with | .ainp _ => true | _ => false)
  (!ainRef) && decide (b.exitAlt = (List.range b.entryAlt).map (fun i => Ref.ainp i))

/-- ★ emitFetch / `materialize` — bring one operand ref to the top as a transient, updating
    demand. Last use ⇒ MOVE (ROLL, home removed); reuse ⇒ COPY (PICK) from shallowest home.
    Small const ⇒ freshly pushed. (The `none`-home non-const case is unreachable under
    `WellFormed`; modelled as a trivial top-push so the function is total.) -/
def emitFetch [DecidableEq α] (r : Ref α) (ms : ModelState α) : ModelState α :=
  match r with
  | .const v false =>
      { ms with ops := ms.ops ++ [Op.PUSH v], S := ms.S ++ [⟨.nullTok v, true⟩] }
  | _ =>
      let tok := tokenOf r
      match depthOfHome ms.S tok with
      | none =>
          match r with
          | .const v _ =>   -- CSE const with no live home yet: push a lone transient
              { ms with ops := ms.ops ++ [Op.PUSH v], S := ms.S ++ [⟨tok, true⟩],
                        use := decUse ms.use tok }
          | _ =>            -- unreachable under WellFormed
              { ms with S := ms.S ++ [⟨tok, true⟩] }
      | some d =>
          if ms.use tok = 1 then            -- MOVE (last use)
            let idx := ms.S.length - 1 - d
            { ms with ops := ms.ops ++ moveOps d,
                      S := (ms.S.eraseIdx idx) ++ [⟨tok, true⟩],
                      use := decUse ms.use tok }
          else                              -- COPY (reused)
            { ms with ops := ms.ops ++ copyOps d,
                      S := ms.S ++ [⟨tok, true⟩],
                      use := decUse ms.use tok }

/-- Eager-drop dead top outputs (`while eagerDrop`): pop+DROP each non-transient top slot
    whose residual demand is 0. Fuel = current stack height (strictly decreasing). -/
def eagerDrop [DecidableEq α] : Nat → ModelState α → ModelState α
  | 0,        ms => ms
  | fuel + 1, ms =>
      match ms.S.reverse with
      | [] => ms
      | e :: _ =>
          match e.transient with
          | true  => ms
          | false =>
              if ms.use e.tok = 0 then
                eagerDrop fuel { ms with ops := ms.ops ++ [Op.DROP], S := ms.S.dropLast }
              else ms

/-- ★ emitNode / `emitOne` — CSE-const home setup for reused const operands lacking a home,
    then materialize all operands contiguously on top, consume them, apply the `CALL` (the
    node's `NodeOp`), push its outputs (non-transient homes), then eager-drop dead outputs. -/
def emitNode [DecidableEq α] (n : Node α) (ms : ModelState α) : ModelState α :=
  -- (1) CSE home setup (BEFORE the operand loop, so operands land contiguously on top)
  let ms1 := n.ins.foldl (fun m inp =>
      match inp with
      | .const v true =>
          let t := Token.cTok v
          match depthOfHome m.S t with
          | some _ => m
          | none   => if 1 < m.use t
                      then { m with ops := m.ops ++ [Op.PUSH v], S := m.S ++ [⟨t, false⟩] }
                      else m
      | _ => m) ms
  -- (2) materialize operands (bottom→top) to the top as transients
  let ms2 := n.ins.foldl (fun m inp => emitFetch inp m) ms1
  -- (3) consume top-k operands, emit the node op, push outputs (bottom→top)
  let k    := n.ins.length
  let S3   := ms2.S.take (ms2.S.length - k)
  let outs := (List.range n.op.nout).map (fun j => (⟨Token.vTok n.id j, false⟩ : Entry α))
  let ms3  := { ms2 with ops := ms2.ops ++ [Op.CALL n.op.nin n.op.sem], S := S3 ++ outs }
  -- (4) eager-drop dead top outputs
  eagerDrop ms3.S.length ms3

/-- Build one exit ref onto the top in the final arrange: copy from a live home (DUP/OVER/PICK)
    or push a fresh const, recording a NON-transient slot (it becomes the exit position). -/
def emitBuildRef [DecidableEq α] (r : Ref α) (ms : ModelState α) : ModelState α :=
  match r with
  | .const v false =>
      { ms with ops := ms.ops ++ [Op.PUSH v], S := ms.S ++ [⟨.nullTok v, false⟩] }
  | .const v true =>
      let t := Token.cTok v
      match depthOfHome ms.S t with
      | some d => { ms with ops := ms.ops ++ copyOps d, S := ms.S ++ [⟨t, false⟩] }
      | none   => { ms with ops := ms.ops ++ [Op.PUSH v], S := ms.S ++ [⟨t, false⟩] }
  | _ =>
      let t := tokenOf r
      match depthOfHome ms.S t with
      | some d => { ms with ops := ms.ops ++ copyOps d, S := ms.S ++ [⟨t, false⟩] }
      | none   => { ms with S := ms.S ++ [⟨t, false⟩] }  -- WF-excluded

/-- Longest matching bottom prefix (final arrange): largest `L` with `exit[L]` a non-const
    whose token equals the non-transient home currently at bottom index `L`. -/
def matchPrefixAux [DecidableEq α] (S : List (Entry α)) (i : Nat) : List (Ref α) → Nat
  | []       => i
  | r :: rest =>
      match r with
      | .const _ _ => i
      | _ =>
          match S[i]? with
          | none   => i
          | some e =>
              match e.transient with
              | true  => i
              | false => if e.tok = tokenOf r then matchPrefixAux S (i + 1) rest else i

/-- ★ emitExit (main) — incremental arrange: keep the matching prefix, build `exit[L..]` on
    top, then delete the `origLen-L` stale items now sitting beneath the `q = exit.len-L`
    freshly built ones. Each deletion erases the element at depth `q`. -/
def emitExitMain [DecidableEq α] (b : Block α) (ms : ModelState α) : ModelState α :=
  let L       := matchPrefixAux ms.S 0 b.exit
  let origLen := ms.S.length
  let msB     := (b.exit.drop L).foldl (fun m r => emitBuildRef r m) ms
  let q       := b.exit.length - L
  let nDel    := origLen - L
  (List.range nDel).foldl
    (fun m _ => { m with ops := m.ops ++ delOps q, S := m.S.eraseIdx (m.S.length - 1 - q) }) msB

/-- ★ scheduleBlock — the whole emitter. Seeds entry main+alt slots, drains entry alt (unless
    passthrough), emits nodes in the block's topological order, deposits exit-alt, then does
    the incremental main arrange. Returns the final `ModelState`; `.ops` is the emitted block.

    NOTE (faithful divergences, documented): (i) nodes are emitted in `block.nodes` order, not
    the greedy shallow-operand ready-list order — a byte-only heuristic, decoupled from
    correctness by design; (ii) exit-alt operands are brought up with `emitFetch` rather than
    scheduler.mjs's near-identical `materializeCopyToTop` (they differ only in the CSE-const
    home-establishment BYTES; the wiring effect — value to top — is identical). -/
def scheduleBlock [DecidableEq α] (b : Block α) : ModelState α :=
  let pass := altPassthrough b
  let ms0 : ModelState α :=
    { ops  := []
    , S    := (List.range b.entryDepth).map (fun i => (⟨Token.inTok i, false⟩ : Entry α))
    , Salt := (List.range b.entryAlt).map   (fun i => (⟨Token.ainTok i, false⟩ : Entry α))
    , use  := demand b pass }
  -- drain entry alt to main (FROMALT pops alt-top = ainTok (entryAlt-1) first), unless passthrough
  let ms1 :=
    bif pass then ms0
    else (List.range b.entryAlt).reverse.foldl
      (fun m k => { m with ops  := m.ops ++ [Op.FROMALT]
                         , S    := m.S ++ [⟨Token.ainTok k, false⟩]
                         , Salt := m.Salt.dropLast }) ms0
  -- emit nodes in topological order
  let ms2 := b.nodes.foldl (fun m n => emitNode n m) ms1
  -- deposit exit-alt: bring each to top then TOALT (alt bottom→top == exitAlt), unless passthrough
  let ms3 :=
    bif pass then ms2
    else b.exitAlt.foldl
      (fun m r =>
        let m' := emitFetch r m
        { m' with ops  := m'.ops ++ [Op.TOALT]
                , S    := m'.S.dropLast
                , Salt := m'.Salt ++ [⟨tokenOf r, false⟩] }) ms2
  -- incremental main arrange
  emitExitMain b ms3

/-- The emitted op-list for a block (the recompiler's PASS-2 output for this block). -/
def emit [DecidableEq α] (b : Block α) : List (Op α) := (scheduleBlock b).ops

end Recompiler
