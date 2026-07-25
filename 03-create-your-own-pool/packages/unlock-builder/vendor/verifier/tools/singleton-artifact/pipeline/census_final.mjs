import { readFileSync } from 'node:fs';
import { parse, serialize } from './asm.mjs';
import { dissect } from './program.mjs';
const hex = readFileSync('optimized-full-5728.hex','utf8').trim();
const bytes = Uint8Array.from(Buffer.from(hex,'hex'));
const d = dissect(bytes);
console.log('TOTAL', bytes.length, 'defines', d.order.length);
let rows=[];
for(const id of d.order){
  const blob=d.bodies.get(id);
  rows.push([id, blob.length]);
}
rows.sort((a,b)=>b[1]-a[1]);
let sum=0;
for(const [id,len] of rows){ sum+=len; }
console.log('sum body blobs', sum, 'main', serialize(d.mainOps).length);
console.log('--- per-block body bytes (sorted) ---');
for(const [id,len] of rows) console.log(String(len).padStart(6), 'def#'+id);
// category classification across all
const CAT={}; const add=(k,n)=>CAT[k]=(CAT[k]||0)+n;
const STACKOPS=new Set([0x6b,0x6c,0x6d,0x6e,0x70,0x71,0x72,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x75,0x76]);
function classify(ops){
  for(const o of ops){
    const sz=o.data!==undefined?serialize([o]).length:1;
    if(o.data!==undefined){ if(o.data.length>=20) add('const_big(>=20B)',sz); else add('const_small',sz);}
    else if(o.op===0x8a) add('INVOKE',sz);
    else if(o.op===0x89) add('DEFINE',sz);
    else if(STACKOPS.has(o.op)) add('stackop',sz);
    else add('arith/other:'+o.op.toString(16),sz);
  }
}
for(const id of d.order){ classify(parse(d.bodies.get(id))); }
classify(d.mainOps);
console.log('--- categories ---');
for(const [k,v] of Object.entries(CAT).sort((a,b)=>b[1]-a[1])) console.log(String(v).padStart(6),k);
