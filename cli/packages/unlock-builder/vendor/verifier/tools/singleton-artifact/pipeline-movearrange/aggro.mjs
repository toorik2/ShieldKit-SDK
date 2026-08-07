// Aggressive topo-order search over a block's node DAG. For each block: enumerate all
// linear extensions (capped), schedule via explicit nodeOrder, keep byte-min. Falls back
// to beam search when the DAG has too many extensions.
import { serializeOps } from './scheduler.mjs';
import { scheduleBlock } from './scheduler.mjs';
import { serialize } from './asm.mjs';
import { peephole } from './peephole.mjs';

// collect nodes (same as scheduler.topoNodes) + adjacency
export function blockNodes(block) {
  const order = []; const seen = new Set();
  const visit = (ref) => {
    if (ref.k !== 'out') return; const node = ref.node;
    if (seen.has(node.id)) return; seen.add(node.id);
    for (const inp of node.ins) visit(inp);
    order.push(node);
  };
  for (const r of [...block.exit, ...block.exitAlt]) visit(r);
  return order;
}

// enumerate linear extensions of the DAG over `nodes`, capped at LIMIT; returns array of
// id-arrays. deps: id -> set of prereq ids (that are in the node set).
function linExtensions(nodes, LIMIT = 20000) {
  const ids = nodes.map(n => n.id);
  const idset = new Set(ids);
  const preds = new Map(ids.map(id => [id, new Set()]));
  const byId = new Map(nodes.map(n => [n.id, n]));
  for (const n of nodes) for (const inp of n.ins) if (inp.k === 'out' && idset.has(inp.node.id)) preds.get(n.id).add(inp.node.id);
  const indeg = new Map(ids.map(id => [id, preds.get(id).size]));
  const succ = new Map(ids.map(id => [id, []]));
  for (const n of nodes) for (const p of preds.get(n.id)) succ.get(p).push(n.id);
  const out = [];
  const cur = [];
  const deg = new Map(indeg);
  let truncated = false;
  const rec = () => {
    if (out.length >= LIMIT) { truncated = true; return; }
    if (cur.length === ids.length) { out.push(cur.slice()); return; }
    const rdy = ids.filter(id => deg.get(id) === 0 && !cur.includes(id));
    for (const id of rdy) {
      cur.push(id);
      for (const s of succ.get(id)) deg.set(s, deg.get(s) - 1);
      rec();
      for (const s of succ.get(id)) deg.set(s, deg.get(s) + 1);
      cur.pop();
      if (truncated) break;
    }
  };
  rec();
  return { orders: out, truncated };
}

const BASE_CONFIGS = [
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
];

export function bestBaseline(block, arity) {
  let best = { by: serialize(peephole(block.rawOps)).length, tag: 'orig' };
  for (const cfg of BASE_CONFIGS) {
    try { const by = serializeOps(peephole(scheduleBlock(block, arity, cfg).ops)).length; if (by < best.by) best = { by, tag: JSON.stringify(cfg) }; } catch (e) {}
  }
  return best;
}

// aggressive: search topo orders (x eagerDrop true/false), keep min bytes
export function bestAggressive(block, arity, LIMIT = 20000) {
  const nodes = blockNodes(block);
  const { orders, truncated } = linExtensions(nodes, LIMIT);
  let best = { by: Infinity, order: null, eager: null };
  for (const order of orders) {
    for (const eager of [true, false]) {
      try {
        const by = serializeOps(peephole(scheduleBlock(block, arity, { nodeOrder: order, eagerDrop: eager }).ops)).length;
        if (by < best.by) best = { by, order, eager };
      } catch (e) {}
    }
  }
  return { best, nExt: orders.length, truncated, nNodes: nodes.length };
}
