import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { serialize } from './asm.mjs';
import { decompile } from './decompile.mjs';
import { dissect, rebuild } from './program.mjs';
import { optimizeItems } from './optimize.mjs';
const here = dirname(fileURLToPath(import.meta.url));
const raw = JSON.parse(readFileSync(join(here, 'baseline.json'), 'utf8'));
const baseline = Uint8Array.from(Buffer.from(raw.debug?.bytecode || raw.bytecodeHex || raw.hex, 'hex'));
const d = dissect(baseline);
const arity = JSON.parse(readFileSync(join(here, 'arity.json'), 'utf8'));
const NODEORDERS = JSON.parse(readFileSync(join(here, 'nodeorders.json'), 'utf8'));
const CAP_MAIN = +(process.env.CAP_MAIN||50000), TRIALS_MAIN = +(process.env.TRIALS_MAIN||16000);
const CAP_BODY = +(process.env.CAP_BODY||30000), TRIALS_BODY = +(process.env.TRIALS_BODY||8000);
console.log(`[buildonly] CAP_MAIN=${CAP_MAIN} TRIALS_MAIN=${TRIALS_MAIN} CAP_BODY=${CAP_BODY} TRIALS_BODY=${TRIALS_BODY}`);
const override = new Map(); let bodyOpt=0;
for (const id of d.order) {
  const items = decompile(d.bodies.get(id), arity, arity[id].in, { label:'def#'+id });
  const { bytes } = optimizeItems(items, arity, 'sched', { peephole:true, label:'def#'+id, nodeOrders:NODEORDERS, search:{cap:CAP_BODY,trials:TRIALS_BODY} });
  override.set(id, bytes); bodyOpt += bytes.length;
}
const mainItems = decompile(serialize(d.mainOps), arity, 10, { label:'main' });
const { bytes: mainOpt } = optimizeItems(mainItems, arity, 'sched', { peephole:true, label:'main', nodeOrders:NODEORDERS, search:{cap:CAP_MAIN,trials:TRIALS_MAIN} });
const optBytes = rebuild(d, override, mainOpt);
writeFileSync(join(here,'optimized_hi.hex'), Buffer.from(optBytes).toString('hex'));
console.log(`bodies -> ${bodyOpt} B ; main -> ${mainOpt.length} B ; LOCKING ${optBytes.length} B ; score ${optBytes.length+272+87}`);
