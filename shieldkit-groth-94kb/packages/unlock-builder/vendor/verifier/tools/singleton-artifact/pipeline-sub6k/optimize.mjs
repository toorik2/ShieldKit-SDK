// optimize.mjs -- COMPOSED (sub6k): merges all sound+positive node-emission-order angles
// (search-anneal randomized-restart, handcraft-main exhaustive/sampled node-order search,
// handcraft-def30 fixed node-order overrides) into ONE per-block candidate pool. The pipeline
// keeps the per-block MINIMUM across {orig, greedy CONFIGS, node-order search, fixed overrides},
// so the merge is MONOTONE (never worse than the crown 5695) and auto-dedupes overlapping wins
// (all three angles hit the SAME lever -> per-block min counts each win at most once). Every
// candidate recomputes the identical value DAG onto the identical exit layout (sound by
// construction); the scheduler self-check/materialize can only THROW on a bad order (never
// silently miscompile), and the per-subroutine differential + artifact E2E remain the hard gates.
import { serialize } from './asm.mjs';
import { decompile } from './decompile.mjs';
import { scheduleBlock, serializeOps } from './scheduler.mjs';
import { peephole } from './peephole.mjs';

// UNION of the arrange/tie-break configs the two search angles used. handcraft-main searched
// move-only variants; search-anneal also searched non-move variants -> combining covers more.
const SEARCH_CONFIGS = [
  { readyOrder: true, eagerDrop: true, arrange: 'move' },
  { readyOrder: true, eagerDrop: false, arrange: 'move' },
  { readyOrder: true, eagerDrop: true, tieBreak: 'shallowmax', arrange: 'move' },
  { readyOrder: true, eagerDrop: true, tieBreak: 'netpop', arrange: 'move' },
  { readyOrder: true, eagerDrop: true, tieBreak: 'deepfirst', arrange: 'move' },
  { readyOrder: true, eagerDrop: true },
  { readyOrder: true, eagerDrop: false },
  { readyOrder: true, eagerDrop: true, tieBreak: 'shallowmax' },
];
function blockNodes(b) {
  const order = [], seen = new Set();
  const visit = (ref) => { if (ref.k !== 'out') return; const n = ref.node; if (seen.has(n.id)) return; seen.add(n.id); for (const inp of n.ins) visit(inp); order.push(n); };
  for (const r of b.exit) visit(r); for (const r of b.exitAlt) visit(r);
  return order;
}
// Search the byte-minimal node emission order for one block. Returns {ops, by} or null.
// EXHAUSTIVE if the block's #linear-extensions <= cap (guaranteed optimal for that block over the
// searched configs); otherwise RANDOM-SAMPLE `trials` valid topo orders (UID-seeded, deterministic).
function searchBlock(b, arity, fold, opts) {
  const cap = opts.cap ?? 50000;
  const trials = opts.trials ?? 4000;
  const nodes = blockNodes(b);
  if (nodes.length < 3 || nodes.length > 31) return null;
  const ids = nodes.map((n) => n.id);
  const idset = new Set(ids);
  const idx = new Map(ids.map((id, i) => [id, i]));
  const deps = new Map(nodes.map((n) => [n.id, [...new Set(n.ins.filter((r) => r.k === 'out').map((r) => r.node.id))].filter((x) => idset.has(x))]));
  const predMask = ids.map((id) => { let m = 0; for (const p of deps.get(id)) m |= (1 << idx.get(p)); return m; });
  const FULL = (1 << ids.length) - 1;
  const memo = new Map();
  const count = (done) => {
    if (done === FULL) return 1;
    if (memo.has(done)) return memo.get(done);
    let c = 0;
    for (let i = 0; i < ids.length; i++) { if (done & (1 << i)) continue; if ((predMask[i] & done) === predMask[i]) { c += count(done | (1 << i)); if (c > cap) break; } }
    memo.set(done, c); return c;
  };
  const nExt = count(0);
  let best = null;
  const tryOrder = (nodeOrder) => {
    for (const cfg of SEARCH_CONFIGS) {
      try { const ops = fold(scheduleBlock(b, arity, { ...cfg, nodeOrder }).ops); const by = serializeOps(ops); if (!best || by.length < best.by.length) best = { ops, by }; }
      catch (e) { /* invalid/unschedulable order -> skip */ }
    }
  };
  if (nExt <= cap) {
    const order = [];
    const rec = (done) => {
      if (done === FULL) { tryOrder(order.map((i) => ids[i])); return; }
      for (let i = 0; i < ids.length; i++) { if (done & (1 << i)) continue; if ((predMask[i] & done) === predMask[i]) { order.push(i); rec(done | (1 << i)); order.pop(); } }
    };
    rec(0);
  } else {
    const adj = new Map(ids.map((id) => [id, []]));
    for (const id of ids) for (const p of deps.get(id)) adj.get(p).push(id);
    let x = 0x9e3779b9 ^ (ids[0] * 2654435761);
    const rng = () => { x = (Math.imul(x, 1103515245) + 12345) & 0x7fffffff; return x / 0x7fffffff; };
    for (let t = 0; t < trials; t++) {
      const indeg = new Map(ids.map((id) => [id, deps.get(id).length]));
      let ready = ids.filter((id) => indeg.get(id) === 0);
      const ord = [];
      while (ready.length) { const k = Math.floor(rng() * ready.length); const id = ready[k]; ready.splice(k, 1); ord.push(id); for (const c of adj.get(id)) { indeg.set(c, indeg.get(c) - 1); if (indeg.get(c) === 0) ready.push(c); } }
      tryOrder(ord);
    }
  }
  return best;
}

// Optimize one decompiled body (list of {block}|{ctrl}) -> { bytes, chosen, dbg }.
// mode: 'sched' (per-block min sched/orig) or 'identity'.  opts.peephole applies PASS 3.
export function optimizeItems(items, arity, mode = 'sched', opts = {}) {
  const fold = opts.peephole ? peephole : (x) => x;
  const outOps = [];
  const chosen = { sched: 0, orig: 0, blocks: 0 };
  const nodeOrders = opts.nodeOrders || null; // def30 fixed overrides: 'label|itemIdx' -> {order:[...]}
  const label = opts.label || '?';
  let itemIdx = -1;
  for (const it of items) {
    itemIdx++;
    if (it.ctrl !== undefined) { outOps.push({ op: it.ctrl }); continue; }
    const b = it.block;
    chosen.blocks++;
    const origBytes = serialize(fold(b.rawOps));
    if (mode === 'identity') { for (const x of fold(b.rawOps)) outOps.push(x); chosen.orig++; continue; }
    const CONFIGS = [
      { readyOrder: true, eagerDrop: true },
      { readyOrder: false, eagerDrop: false },
      { readyOrder: true, eagerDrop: false },
      { readyOrder: false, eagerDrop: true },
      { readyOrder: true, eagerDrop: true, tieBreak: 'shallowmax' },
      { readyOrder: true, eagerDrop: false, tieBreak: 'shallowmax' },
      { readyOrder: true, eagerDrop: true, tieBreak: 'netpop' },
      { readyOrder: true, eagerDrop: false, tieBreak: 'netpop' },
      { readyOrder: true, eagerDrop: true, tieBreak: 'deepfirst' },
      { readyOrder: true, eagerDrop: false, tieBreak: 'deepfirst' },
      { readyOrder: true, eagerDrop: true, arrange: 'move' },
      { readyOrder: true, eagerDrop: false, arrange: 'move' },
      { readyOrder: true, eagerDrop: true, tieBreak: 'shallowmax', arrange: 'move' },
      { readyOrder: true, eagerDrop: true, tieBreak: 'netpop', arrange: 'move' },
      { readyOrder: true, eagerDrop: true, tieBreak: 'deepfirst', arrange: 'move' },
      { readyOrder: false, eagerDrop: false, arrange: 'move' },
    ];
    let best = null;
    for (const cfg of CONFIGS) {
      try { const ops = fold(scheduleBlock(b, arity, cfg).ops); const by = serializeOps(ops); if (!best || by.length < best.by.length) best = { ops, by }; }
      catch (e) { /* skip failing config */ }
    }
    // (A) node-order search (search-anneal + handcraft-main lever): enumerated/sampled orders.
    if (opts.search) {
      const s = searchBlock(b, arity, fold, opts.search === true ? {} : opts.search);
      if (s && (!best || s.by.length < best.by.length)) best = s;
    }
    // (B) fixed node-order overrides (handcraft-def30): guaranteed candidates from offline search.
    const key = label + '|' + itemIdx;
    const ov = nodeOrders && nodeOrders[key] ? (nodeOrders[key].order || nodeOrders[key]) : null;
    if (ov) {
      for (const arr of [undefined, 'move']) for (const ro of [true, false]) {
        try { const ops = fold(scheduleBlock(b, arity, { readyOrder: ro, eagerDrop: true, arrange: arr, nodeOrder: ov }).ops); const by = serializeOps(ops); if (!best || by.length < best.by.length) best = { ops, by }; }
        catch (e) { /* stale/invalid override -> skip */ }
      }
    }
    if (best && best.by.length < origBytes.length) {
      for (const x of best.ops) outOps.push(x);
      chosen.sched++;
      continue;
    }
    for (const x of fold(b.rawOps)) outOps.push(x);
    chosen.orig++;
  }
  return { bytes: serializeOps(outOps), chosen };
}
