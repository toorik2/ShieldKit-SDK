// scheduler.mjs -- the crown jewel. Re-emit a block's value-DAG to bytecode.
//
// A Block (from decompile.mjs) is a PURE mapping:
//   entry:  main = [in:0 .. in:(entryDepth-1)] (bottom->top), alt = [ain:0 .. ain:(entryAlt-1)]
//   exit:   main = exit[] (refs, bottom->top),  alt = exitAlt[] (refs, bottom->top)
//   nodes:  prim/invoke DAG referenced by the exit refs.
// scheduleBlock emits a straight-line op sequence achieving that mapping with:
//   (PASS 1) NO interior altstack use  -- entry-alt is drained to main once, exit-alt
//            re-parked once; the cashc TOALT/FROMALT park/restore churn is gone.
//   (PASS 2) shallow ROLL/PICK         -- last-use operands are MOVED (ROLL) not copied,
//            reused operands are COPIED (PICK) from their shallowest live instance; small
//            depths fold to OVER/DUP/SWAP/ROT (which subsumes PASS 3 for the common cases).
// Correctness is by construction: every VALOP/INVOKE re-emits the identical opcode with
// operands in the identical bottom->top order, so the executed arithmetic is bit-identical.
// The emitted block reproduces the EXACT entry->exit main+alt layout, so it is a drop-in
// replacement regardless of the surrounding control ops. Guarded per-subroutine by the
// differential tester.
import { serialize } from './asm.mjs';

const OP = {
  DUP: 0x76, DROP: 0x75, OVER: 0x78, SWAP: 0x7c, ROT: 0x7b,
  PICK: 0x79, ROLL: 0x7a, TOALT: 0x6b, FROMALT: 0x6c, INVOKE: 0x8a,
};

// minimal push of a non-negative small integer (used for PICK/ROLL depth and invoke id)
function pushIntOps(n) {
  if (n === 0) return [{ op: 0x00 }];
  if (n >= 1 && n <= 16) return [{ op: 0x50 + n }];
  // encode as minimal little-endian VM number (n<128 -> 1 byte)
  const bytes = [];
  let v = n;
  while (v > 0) { bytes.push(v & 0xff); v >>= 8; }
  if (bytes[bytes.length - 1] & 0x80) bytes.push(0x00); // positive sign pad
  return [{ op: 0, data: Uint8Array.from(bytes) }];
}

// CONSTANT-CSE: a const push of encoded length >= CSE_MIN is worth pushing ONCE and
// reusing via DUP/OVER/PICK (1-2 B) instead of re-emitting the full push every use. The
// 32-byte field elements (enc len 33) dominate; small ints (enc len 1-2) are cheaper to
// re-push than to copy, so they stay on the always-fresh path (token=null). Copies are
// bit-identical to the original push, so this is sound by construction (guarded by the
// per-subroutine differential + E2E multiproof).
const CSE_MIN = 3;
const hexOf = (u8) => { let s = ''; for (let k = 0; k < u8.length; k++) s += (u8[k] < 16 ? '0' : '') + u8[k].toString(16); return s; };
function constEncBytes(ref) {
  if (ref.enc) return ref.enc;
  return serialize([{ op: 0, data: ref.data }]);
}
function cseEligible(ref) { return ref.k === 'const' && constEncBytes(ref).length >= CSE_MIN; }

// token id for a value-producing ref. A CSE-eligible const gets a value-derived token
// ('c'+hex(enc)) so identical pushes share a stack home; small consts keep token=null
// (always freshly pushed, exactly as before).
function tokenOf(ref) {
  if (ref.k === 'in') return 'i' + ref.i;
  if (ref.k === 'ain') return 'a' + ref.i;
  if (ref.k === 'out') return 'v' + ref.node.id + '_' + ref.j;
  if (ref.k === 'const') return cseEligible(ref) ? 'c' + hexOf(constEncBytes(ref)) : null;
  return null;
}

// collect needed nodes in dependency order from a set of root refs
function topoNodes(roots) {
  const order = [];
  const seen = new Set();
  const visit = (ref) => {
    if (ref.k !== 'out') return;
    const node = ref.node;
    if (seen.has(node.id)) return;
    seen.add(node.id);
    for (const inp of node.ins) visit(inp);
    order.push(node);
  };
  for (const r of roots) visit(r);
  return order;
}

// Emit ops implementing the block. Returns { ops, alt: false }.
// arity: id -> {in,out} for invoke output counts.
export function scheduleBlock(block, arity, opts = {}) {
  const readyOrder = opts.readyOrder !== false; // default: shallow-operand ready-list
  const eagerDrop = opts.eagerDrop !== false;    // default: drop dead top outputs
  const { entryDepth, entryAlt, exit, exitAlt } = block;
  const ops = [];

  // ---- model of the main stack: array of entries {tok} bottom->top. transient copies
  //      pushed for an operand are flagged so home lookups skip them. ----
  const S = []; // each: { tok, t?:true }
  const emit = (o) => ops.push(o);
  const depthOfHome = (tok, limit = S.length) => {
    for (let idx = Math.min(limit, S.length) - 1; idx >= 0; idx--) {
      if (!S[idx].t && S[idx].tok === tok) return S.length - 1 - idx;
    }
    return -1;
  };

  // ---- demand counting over all needed nodes' ins + exit + exitAlt ----
  const nodes = topoNodes([...exit, ...exitAlt]);

  // entry main slots
  for (let i = 0; i < entryDepth; i++) S.push({ tok: 'i' + i });
  // Is any entry-alt slot actually needed on main (referenced by a node input or by exit)?
  let ainReferenced = false;
  const scanAin = (ref) => { if (ref.k === 'ain') ainReferenced = true; };
  for (const n of nodes) for (const inp of n.ins) scanAin(inp);
  for (const r of exit) scanAin(r);
  // alt passthrough: alt untouched (exitAlt is the identity carry of entryAlt) and no ain
  // value is pulled to main -> leave the altstack completely alone (no FROMALT/TOALT churn).
  const altPassthrough = !ainReferenced && exitAlt.length === entryAlt &&
    exitAlt.every((r, i) => r.k === 'ain' && r.i === i);
  if (!altPassthrough) {
    // drain entry alt to main: FROMALT pops alt-top (ain:entryAlt-1) first
    for (let k = entryAlt - 1; k >= 0; k--) { emit({ op: OP.FROMALT }); S.push({ tok: 'a' + k }); }
  }

  const use = new Map();
  const bump = (ref) => { const t = tokenOf(ref); if (t) use.set(t, (use.get(t) || 0) + 1); };
  for (const n of nodes) for (const inp of n.ins) bump(inp);
  for (const r of exit) bump(r);
  if (!altPassthrough) for (const r of exitAlt) bump(r);

  // emit ops to bring one operand ref to the top (transient), decrementing demand
  const materialize = (ref) => {
    const tok = tokenOf(ref);
    // small (non-CSE) const: always freshly pushed as a one-shot transient (as before)
    if (ref.k === 'const' && tok === null) { for (const b of encConst(ref)) emit(b); S.push({ tok: null, t: true }); return; }
    const remaining = use.get(tok);
    const d = depthOfHome(tok);
    if (d < 0) {
      // No home. A reused const has its home pre-established at emitOne start (on a clean
      // stack -- see below), so d<0 here means a single-use const: push a lone transient.
      // (Never create a home mid-operand-sequence: that would break operand contiguity for
      // the enclosing node's S.splice.)
      if (ref.k === 'const') { for (const b of encConst(ref)) emit(b); S.push({ tok, t: true }); use.set(tok, remaining - 1); return; }
      throw new Error('scheduler: home not found for ' + tok);
    }
    if (remaining === 1) {
      // last use -> MOVE (ROLL). remove the home, push transient copy on top.
      const idx = S.length - 1 - d;
      S.splice(idx, 1);
      if (d === 0) { /* already on top */ }
      else if (d === 1) emit({ op: OP.SWAP });
      else if (d === 2) emit({ op: OP.ROT });
      else { for (const b of pushIntOps(d)) emit(b); emit({ op: OP.ROLL }); }
      S.push({ tok, t: true });
    } else {
      // reused -> COPY (PICK) from shallowest home
      if (d === 0) emit({ op: OP.DUP });
      else if (d === 1) emit({ op: OP.OVER });
      else { for (const b of pushIntOps(d)) emit(b); emit({ op: OP.PICK }); }
      S.push({ tok, t: true });
    }
    use.set(tok, remaining - 1);
  };

  // ---- emit nodes via a ready-list, greedily picking the node whose operands are
  //      currently SHALLOWEST (PASS 2: keep the hot working set near the top so ROLL/PICK
  //      depths -- hence depth-push bytes -- stay small). Reordering is safe: each node
  //      computes the same value from the same operands; only byte count changes. ----
  const emitOne = (node) => {
    const k = node.ins.length;
    // CONST-CSE home setup: on the currently-clean stack top, push a persistent home for
    // each reused CSE const operand that lacks one. Done BEFORE the operand loop so all k
    // operands land contiguously on top (the S.splice below relies on that); a home pushed
    // mid-sequence would sit between operands and corrupt the removal.
    for (const inp of node.ins) {
      const t = tokenOf(inp);
      if (inp.k === 'const' && t !== null && depthOfHome(t) < 0 && (use.get(t) || 0) > 1) {
        for (const b of encConst(inp)) emit(b); S.push({ tok: t });
      }
    }
    for (const inp of node.ins) materialize(inp);
    S.splice(S.length - k, k);
    if (node.k === 'prim') { emit({ op: node.code }); }
    else { for (const b of pushIntOps(node.invId)) emit(b); emit({ op: OP.INVOKE }); }
    const outN = node.k === 'prim' ? 1 : arity[node.invId].out;
    for (let j = 0; j < outN; j++) S.push({ tok: 'v' + node.id + '_' + j });
    // eager drop of dead top outputs (unused invoke results) to keep the stack shallow
    while (eagerDrop && S.length && !S[S.length - 1].t) {
      const t = S[S.length - 1].tok;
      if ((use.get(t) || 0) === 0) { emit({ op: OP.DROP }); S.pop(); } else break;
    }
  };
  const depNodes = (node) => node.ins.filter((r) => r.k === 'out').map((r) => r.node);
  const emitted = new Set();
  const remaining = new Set(nodes.map((n) => n.id));
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const ready = () => nodes.filter((n) => remaining.has(n.id) && depNodes(n).every((p) => emitted.has(p.id)));
  const operandDepthScore = (node) => {
    let s = 0;
    for (const r of node.ins) { const t = tokenOf(r); if (t) { const dd = depthOfHome(t); s += dd < 0 ? 0 : dd; } }
    return s;
  };
  const maxOperandDepth = (node) => {
    let m = 0;
    for (const r of node.ins) { const t = tokenOf(r); if (t) { const dd = depthOfHome(t); if (dd > m) m = dd; } }
    return m;
  };
  const netEffect = (node) => {
    const outN = node.k === 'prim' ? 1 : arity[node.invId].out;
    return outN - node.ins.length; // >0 grows the stack, <0 shrinks it
  };
  // SHALLOW-LAYOUT tie-breaks (opts.tieBreak). All are pure re-orderings of the ready
  // list: every node still recomputes the identical value from identical operands and the
  // block still lands on the identical exit layout, so every variant is sound by
  // construction (guarded per-body by the differential + E2E). optimize.mjs tries all and
  // keeps the byte-smallest winner. The goal is to keep the hot working set shallow so
  // ROLL/PICK depth pushes (esp. the 2-byte depth>16 ones) shrink.
  const tieBreak = opts.tieBreak || 'shallow';
  const cmp = {
    // default: minimize the summed operand depth of the node emitted next.
    shallow: (a, b) => operandDepthScore(a) - operandDepthScore(b) || a.id - b.id,
    // minimize the single DEEPEST operand access next (caps the worst-case depth push).
    shallowmax: (a, b) => maxOperandDepth(a) - maxOperandDepth(b) || operandDepthScore(a) - operandDepthScore(b) || a.id - b.id,
    // prefer stack-shrinking nodes first (consume deep values, keep the stack short), then shallow.
    netpop: (a, b) => netEffect(a) - netEffect(b) || operandDepthScore(a) - operandDepthScore(b) || a.id - b.id,
    // prefer emitting the node that touches the CURRENTLY-deepest live operand, to clear
    // deep values out of the way early (last-use ROLL removes the home).
    deepfirst: (a, b) => maxOperandDepth(b) - maxOperandDepth(a) || operandDepthScore(a) - operandDepthScore(b) || a.id - b.id,
  }[tieBreak] || ((a, b) => a.id - b.id);
  if (opts.nodeOrder) {
    for (const nid of opts.nodeOrder) { const node = byId.get(nid); if (!node) throw new Error('bad nodeOrder id '+nid); emitOne(node); emitted.add(node.id); remaining.delete(node.id); }
  } else if (opts.pickFn) {
    while (remaining.size) {
      const rs = ready();
      if (!rs.length) throw new Error('scheduler: dependency cycle / unready');
      rs.sort(cmp);
      const node = opts.pickFn(rs);
      emitOne(node);
      emitted.add(node.id); remaining.delete(node.id);
    }
  } else if (readyOrder) {
    while (remaining.size) {
      const rs = ready();
      if (!rs.length) throw new Error('scheduler: dependency cycle / unready');
      rs.sort(cmp);
      const node = rs[0];
      emitOne(node);
      emitted.add(node.id); remaining.delete(node.id);
    }
  } else {
    for (const node of nodes) emitOne(node); // fixed topo order
  }

  // ---- final assembly ----
  // (a) deposit exit-alt (unless the altstack is an untouched passthrough) in order:
  //     copy each to top then TOALT so alt bottom->top == exitAlt[].
  if (!altPassthrough) {
    for (const ref of exitAlt) {
      materializeCopyToTop(ref);
      emit({ op: OP.TOALT });
      S.pop();
    }
  }

  // (b) INCREMENTAL main arrange. Keep the longest matching bottom prefix in place; only
  //     build the differing suffix on top and delete the stale tail underneath it. This is
  //     what makes near-passthrough / append-only blocks (the bulk of `main`) cheap instead
  //     of rebuilding the whole 12-18 deep stack.
  const tokenAt = (i) => (i < S.length && !S[i].t ? S[i].tok : null);
  let L = 0;
  while (L < exit.length && L < S.length) {
    const r = exit[L];
    if (r.k === 'const') break;
    if (tokenAt(L) !== tokenOf(r)) break;
    L++;
  }
  const origLen = S.length;            // items currently on the stack (all homes)
  // build exit[L..] on top (copy shallowest home / push const)
  for (let e = L; e < exit.length; e++) {
    const ref = exit[e];
    const tok = tokenOf(ref);
    if (ref.k === 'const') {
      if (tok !== null) {
        // CSE const: copy from a live home if present, else push fresh (becomes a home for
        // any later identical exit const).
        const dc = depthOfHome(tok);
        if (dc >= 0) {
          if (dc === 0) emit({ op: OP.DUP });
          else if (dc === 1) emit({ op: OP.OVER });
          else { for (const b of pushIntOps(dc)) emit(b); emit({ op: OP.PICK }); }
          S.push({ tok }); continue;
        }
        for (const b of encConst(ref)) emit(b); S.push({ tok }); continue;
      }
      for (const b of encConst(ref)) emit(b); S.push({ tok: null }); continue;
    }
    const d = depthOfHome(tok);
    if (d < 0) throw new Error('scheduler(final): home not found for ' + tok);
    if (d === 0) emit({ op: OP.DUP });
    else if (d === 1) emit({ op: OP.OVER });
    else { for (const b of pushIntOps(d)) emit(b); emit({ op: OP.PICK }); }
    S.push({ tok });
  }
  // delete the stale tail S[L..origLen-1] now sitting beneath the freshly built block.
  const q = exit.length - L;           // built items on top
  const m = origLen - L;               // stale items to remove
  for (let k = 0; k < m; k++) {
    if (q === 0) { emit({ op: OP.DROP }); }
    else if (q === 1) { emit({ op: 0x77 }); }            // NIP: remove 2nd-from-top
    else { for (const b of pushIntOps(q)) emit(b); emit({ op: OP.ROLL }); emit({ op: OP.DROP }); }
  }

  return { ops };

  // ---- helpers closing over S/emit/use ----
  function materializeCopyToTop(ref) {
    const tok = tokenOf(ref);
    if (ref.k === 'const' && tok === null) { for (const b of encConst(ref)) emit(b); S.push({ tok: null, t: true }); return; }
    const remaining = use.get(tok) || 0;
    const d = depthOfHome(tok);
    if (d < 0) {
      if (ref.k === 'const') {
        for (const b of encConst(ref)) emit(b);
        if (remaining > 1) { S.push({ tok }); emit({ op: OP.DUP }); S.push({ tok, t: true }); }
        else { S.push({ tok, t: true }); }
        use.set(tok, Math.max(0, remaining - 1));
        return;
      }
      throw new Error('scheduler(alt): home not found for ' + tok);
    }
    if (remaining <= 1) { // last use -> move
      const idx = S.length - 1 - d;
      S.splice(idx, 1);
      if (d === 1) emit({ op: OP.SWAP });
      else if (d === 2) emit({ op: OP.ROT });
      else if (d > 2) { for (const b of pushIntOps(d)) emit(b); emit({ op: OP.ROLL }); }
      S.push({ tok, t: true });
    } else {
      if (d === 0) emit({ op: OP.DUP });
      else if (d === 1) emit({ op: OP.OVER });
      else { for (const b of pushIntOps(d)) emit(b); emit({ op: OP.PICK }); }
      S.push({ tok, t: true });
    }
    use.set(tok, Math.max(0, remaining - 1));
  }
}

function depthOfHomeIn(S, tok, limit) {
  for (let idx = Math.min(limit, S.length) - 1; idx >= 0; idx--) {
    if (!S[idx].t && S[idx].tok === tok) return S.length - 1 - idx;
  }
  return -1;
}

// re-emit a constant byte-for-byte using the encoding cashc used (ref.enc)
function encConst(ref) {
  if (ref.enc) return [{ _raw: ref.enc }];
  return [{ op: 0, data: ref.data }]; // fallback: minimal data push
}

// serialize with support for _raw (exact preserved const encoding)
export function serializeOps(ops) {
  const flat = [];
  for (const o of ops) {
    if (o._raw) flat.push(...o._raw);
    else if (o.data !== undefined && o.data !== null) { const s = serialize([o]); flat.push(...s); }
    else flat.push(o.op);
  }
  return Uint8Array.from(flat);
}
