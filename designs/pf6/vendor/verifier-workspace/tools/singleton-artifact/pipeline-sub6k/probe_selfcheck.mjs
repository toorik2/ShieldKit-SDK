// Per-block selection probe: for the flagged dup-input bodies, replicate optimize.mjs's
// CONFIG loop and report, per block, which config won and whether the MOVE-arrange threw
// (self-check firing) vs emitted a self-check-passing result. Also flags blocks whose exit
// has a DUPLICATE value token (in/ain/out) -- the ceBlock-dangerous class the scout warned about.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { serialize } from './asm.mjs';
import { decompile } from './decompile.mjs';
import { scheduleBlock, serializeOps } from './scheduler.mjs';
import { peephole } from './peephole.mjs';
import { dissect } from './program.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const raw = JSON.parse(readFileSync(join(here, 'baseline.json'), 'utf8'));
const baseline = Uint8Array.from(Buffer.from(raw.debug?.bytecode || raw.bytecodeHex || raw.hex, 'hex'));
const d = dissect(baseline);
const arity = JSON.parse(readFileSync(join(here, 'arity.json'), 'utf8'));

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
const isMove = (c) => c.arrange === 'move';
const tokv = (r) => (r.k === 'in' ? 'i' + r.i : r.k === 'ain' ? 'a' + r.i : r.k === 'out' ? 'v' + r.node.id + '_' + r.j : null);
function dupValTok(exit) { const s = new Set(); for (const r of exit) { const t = tokv(r); if (t === null) continue; if (s.has(t)) return t; s.add(t); } return null; }

for (const ID of [30, 32, 35]) {
  const items = decompile(d.bodies.get(ID), arity, arity[ID].in, { label: 'def#' + ID });
  let bi = 0;
  console.log(`\n===== def#${ID} =====`);
  for (const it of items) {
    if (it.ctrl !== undefined) { bi++; continue; }
    const b = it.block;
    const origBytes = serialize(peephole(b.rawOps)).length;
    let best = null, bestCfg = null;
    let moveThrew = 0, moveOK = 0, moveBest = Infinity;
    for (const cfg of CONFIGS) {
      let ok = false, len = Infinity;
      try { const ops = peephole(scheduleBlock(b, arity, cfg).ops); len = serializeOps(ops).length; ok = true; }
      catch (e) { if (isMove(cfg)) moveThrew++; }
      if (isMove(cfg)) { if (ok) { moveOK++; moveBest = Math.min(moveBest, len); } }
      if (ok && (best === null || len < best)) { best = len; bestCfg = cfg; }
    }
    const chosen = best !== null && best < origBytes ? `sched[${JSON.stringify(bestCfg)}]=${best}` : `ORIG=${origBytes}`;
    const dup = dupValTok(b.exit);
    console.log(`  block#${bi}: exitLen=${b.exit.length} dupValTok=${dup || '-'} | move: ok=${moveOK} threw=${moveThrew} bestMove=${moveBest === Infinity ? 'x' : moveBest} | orig=${origBytes} chosen=${chosen} chosenIsMove=${bestCfg ? !!bestCfg.arrange : false}`);
    bi++;
  }
}
