import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { serialize } from './asm.mjs';
import { decompile } from './decompile.mjs';
import { dissect } from './program.mjs';
import { scheduleBlock, serializeOps } from './scheduler.mjs';
import { peephole } from './peephole.mjs';

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
const fold = peephole;
const mainItems = decompile(serialize(d.mainOps), arity, 10, { label: 'main' });
let bi = 0;
let totOrig=0, totBest=0;
for (const it of mainItems) {
  if (it.ctrl !== undefined) continue;
  const b = it.block;
  const orig = serialize(fold(b.rawOps)).length;
  let best = orig, bestcfg='orig';
  for (let ci=0; ci<CONFIGS.length; ci++) {
    try { const by = serializeOps(fold(scheduleBlock(b, arity, CONFIGS[ci]).ops)).length; if (by<best){best=by;bestcfg='c'+ci;} } catch(e){}
  }
  const nodes = b.exit; // count nodes via topo
  totOrig+=orig; totBest+=best;
  console.log(`blk#${bi} entryD=${b.entryDepth} entryAlt=${b.entryAlt} exit=${b.exit.length} exitAlt=${b.exitAlt.length} rawOps=${b.rawOps.length} orig=${orig} best=${best} (${bestcfg})`);
  bi++;
}
console.log(`MAIN blocks=${bi} totOrig=${totOrig} totBest=${totBest}`);
