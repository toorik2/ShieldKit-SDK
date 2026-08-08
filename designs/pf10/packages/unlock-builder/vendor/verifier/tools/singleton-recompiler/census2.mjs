import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parse, serialize } from './asm.mjs';
import { dissect } from './program.mjs';
const here = dirname(fileURLToPath(import.meta.url));
const raw = JSON.parse(readFileSync(join(here,'baseline.json'),'utf8'));
const hex = raw.debug?.bytecode || raw.bytecodeHex || raw.hex;
const baseline = Uint8Array.from(Buffer.from(hex,'hex'));
const d = dissect(baseline);
// classify bytes across ALL bodies + main
const CAT = {};
const add=(k,n)=>CAT[k]=(CAT[k]||0)+n;
const STACKOPS = new Set([0x6b,0x6c,0x6d,0x6e,0x70,0x71,0x72,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x75,0x76]);
const CTRLB = new Set([0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x9d,0x88]);
function classify(ops){
  for(const o of ops){
    const sz = o.data!==undefined ? (serialize([o]).length) : 1;
    if(o.data!==undefined){
      if(o.data.length>=20) add('const_big(>=20B)',sz);
      else add('const_small',sz);
    } else if(o.op===0x8a) add('INVOKE',sz);
    else if(o.op===0x89) add('DEFINE',sz);
    else if(STACKOPS.has(o.op)) add('stackop:'+o.op.toString(16),sz);
    else if(CTRLB.has(o.op)) add('ctrl',sz);
    else add('other:'+o.op.toString(16),sz);
  }
}
let bodyBytes=0;
for(const id of d.order){ const ops=parse(d.bodies.get(id)); classify(ops); bodyBytes+=d.bodies.get(id).length; }
classify(d.mainOps);
// total incl body-push headers + id + define overhead
console.log('total baseline',baseline.length,'B; sum body blobs',bodyBytes,'B; main',serialize(d.mainOps).length,'B');
const ents=Object.entries(CAT).sort((a,b)=>b[1]-a[1]);
let stacktot=0;
for(const [k,v] of ents){ if(k.startsWith('stackop:')) stacktot+=v; }
console.log('--- byte categories (inside bodies+main, excl push headers/id/define frame) ---');
for(const [k,v] of ents) console.log(v.toString().padStart(7), k);
console.log('TOTAL stackops bytes:', stacktot);
// name the stackops
const NM={0x6b:'TOALT',0x6c:'FROMALT',0x6d:'2DROP',0x6e:'2DUP',0x70:'2OVER',0x71:'2ROT',0x72:'2SWAP',0x77:'NIP',0x78:'OVER',0x79:'PICK',0x7a:'ROLL',0x7b:'ROT',0x7c:'SWAP',0x7d:'TUCK',0x75:'DROP',0x76:'DUP'};
console.log('--- named stackops ---');
for(const [k,v] of ents) if(k.startsWith('stackop:')){ const c=parseInt(k.split(':')[1],16); console.log(v.toString().padStart(6), NM[c]); }
