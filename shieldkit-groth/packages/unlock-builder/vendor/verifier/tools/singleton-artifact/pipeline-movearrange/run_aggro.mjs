import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { serialize } from './asm.mjs';
import { decompile } from './decompile.mjs';
import { dissect } from './program.mjs';
import { bestBaseline, bestAggressive } from './aggro.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const raw = JSON.parse(readFileSync(join(here, 'baseline.json'), 'utf8'));
const baseline = Uint8Array.from(Buffer.from(raw.debug?.bytecode || raw.bytecodeHex || raw.hex, 'hex'));
const d = dissect(baseline);
const arity = JSON.parse(readFileSync(join(here, 'arity.json'), 'utf8'));
const ID = Number(process.argv[2] || 30);
const items = decompile(d.bodies.get(ID), arity, arity[ID].in, { label:'def#'+ID });
let bi=0, totBase=0, totAggro=0;
for (const it of items) {
  if (it.ctrl !== undefined) { totBase+=1; totAggro+=1; bi++; continue; }
  const b = it.block;
  const base = bestBaseline(b, arity);
  const agg = bestAggressive(b, arity);
  const aggBy = Math.min(base.by, agg.best.by);
  totBase += base.by; totAggro += aggBy;
  if (base.by>=25 || agg.best.by>=25)
    console.log(`block#${bi} nodes=${agg.nNodes} ext=${agg.nExt}${agg.truncated?'+':''}  base=${base.by}  aggro=${agg.best.by}  min=${aggBy}  delta=${base.by-aggBy}`);
  bi++;
}
console.log(`def#${ID}  BASE total=${totBase}  AGGRO total=${totAggro}  delta=${totBase-totAggro}`);
