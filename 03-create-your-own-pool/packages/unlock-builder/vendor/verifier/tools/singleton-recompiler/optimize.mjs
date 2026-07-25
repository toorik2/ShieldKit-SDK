// optimize.mjs -- assemble an optimized body per subroutine by scheduling each block,
// choosing per-block the smaller of {scheduled, original rawOps} (both reproduce the
// exact entry->exit main+alt layout, so any mix is sound). Emits the same OP_DEFINE
// framing so bytes can be spliced back and the full artifact re-measured.
import { serialize } from './asm.mjs';
import { decompile } from './decompile.mjs';
import { scheduleBlock, serializeOps } from './scheduler.mjs';
import { peephole } from './peephole.mjs';

// Optimize one decompiled body (list of {block}|{ctrl}) -> { bytes, chosen, dbg }.
// mode: 'sched' (per-block min sched/orig) or 'identity'.  opts.peephole applies PASS 3.
export function optimizeItems(items, arity, mode = 'sched', opts = {}) {
  const fold = opts.peephole ? peephole : (x) => x;
  const outOps = []; // op records ({op}|{op,data}|{_raw}) for serializeOps
  const chosen = { sched: 0, orig: 0, blocks: 0 };
  for (const it of items) {
    if (it.ctrl !== undefined) { outOps.push({ op: it.ctrl }); continue; }
    const b = it.block;
    chosen.blocks++;
    const origBytes = serialize(fold(b.rawOps));
    if (mode === 'identity') { for (const x of fold(b.rawOps)) outOps.push(x); chosen.orig++; continue; }
    // try several scheduler configs; keep the smallest (all are semantically equivalent,
    // guarded by the per-subroutine differential test).
    const CONFIGS = [
      { readyOrder: true, eagerDrop: true },
      { readyOrder: false, eagerDrop: false },
      { readyOrder: true, eagerDrop: false },
      { readyOrder: false, eagerDrop: true },
      // SHALLOW-LAYOUT tie-break variants (sound re-orderings; keep byte-smallest).
      { readyOrder: true, eagerDrop: true, tieBreak: 'shallowmax' },
      { readyOrder: true, eagerDrop: false, tieBreak: 'shallowmax' },
      { readyOrder: true, eagerDrop: true, tieBreak: 'netpop' },
      { readyOrder: true, eagerDrop: false, tieBreak: 'netpop' },
      { readyOrder: true, eagerDrop: true, tieBreak: 'deepfirst' },
      { readyOrder: true, eagerDrop: false, tieBreak: 'deepfirst' },
    ];
    let best = null;
    for (const cfg of CONFIGS) {
      try { const ops = fold(scheduleBlock(b, arity, cfg).ops); const by = serializeOps(ops); if (!best || by.length < best.by.length) best = { ops, by }; }
      catch (e) { /* skip failing config */ }
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
