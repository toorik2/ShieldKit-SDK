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

const ID = Number(process.argv[2] || 30);
const items = decompile(d.bodies.get(ID), arity, arity[ID].in, { label: 'def#'+ID });
console.log(`def#${ID} body ${d.bodies.get(ID).length} B, arity in=${arity[ID].in} out=${arity[ID].out}, items=${items.length}`);

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
];
let bi=0, totOrig=0, totBest=0;
for (const it of items) {
  if (it.ctrl !== undefined) { totOrig+=1; totBest+=1; continue; }
  const b = it.block;
  const orig = serialize(peephole(b.rawOps)).length;
  let best=orig, bestcfg='orig';
  for (const cfg of CONFIGS) {
    try { const by = serializeOps(peephole(scheduleBlock(b, arity, cfg).ops)).length; if (by<best){best=by;bestcfg=JSON.stringify(cfg);} } catch(e){}
  }
  totOrig+=orig; totBest+=best;
  const nNodes = (function(){ const s=new Set(); const vis=(r)=>{if(r.k!=='out')return; if(s.has(r.node.id))return; s.add(r.node.id); for(const x of r.node.ins)vis(x);}; for(const r of [...b.exit,...b.exitAlt])vis(r); return s.size;})();
  if (orig>=30 || best>=30) console.log(`  block#${bi} entryD=${b.entryDepth} entryAlt=${b.entryAlt} exit=${b.exit.length} exitAlt=${b.exitAlt.length} nodes=${nNodes} orig=${orig} best=${best} via=${bestcfg}`);
  bi++;
}
console.log(`TOTAL orig(peephole)=${totOrig} best=${totBest}`);
