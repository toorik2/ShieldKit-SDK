import { readFileSync } from 'node:fs';
import { dissect } from './program.mjs';
import { serialize } from './asm.mjs';
const rd = p => Uint8Array.from(Buffer.from(readFileSync(p,'utf8').trim(),'hex'));
const CROWN=process.argv[2], SR=process.argv[3];
const c=dissect(rd(CROWN)), s=dissect(rd(SR));
let tc=0,ts=0;
for(const id of c.order){const a=c.bodies.get(id).length,b=s.bodies.get(id).length;tc+=a;ts+=b;if(a!==b)console.log(`def#${id} ${a} -> ${b} (${b-a})`);}
const mc=serialize(c.mainOps).length, ms=serialize(s.mainOps).length;
console.log(`BODIES ${tc} -> ${ts} (${ts-tc})`);
console.log(`MAIN   ${mc} -> ${ms} (${ms-mc})`);
console.log(`TOTAL  ${rd(CROWN).length} -> ${rd(SR).length} (${rd(SR).length-rd(CROWN).length})`);
