import { readFileSync } from 'node:fs';
import { parse, serialize } from './asm.mjs';
import { dissect } from './program.mjs';
const hex=readFileSync('optimized-full-5728.hex','utf8').trim();
const d=dissect(Uint8Array.from(Buffer.from(hex,'hex')));
const STACK=new Set([0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x75,0x76]);
function cats(ops){ let s=0,cbig=0,csmall=0,inv=0,id=0,arith=0;
  for(const o of ops){ const sz=o.data!==undefined?serialize([o]).length:1;
    if(o.data!==undefined){ if(o.data.length>=20)cbig+=sz; else csmall+=sz; }
    else if(o.op===0x8a) inv+=sz;
    else if(o.op>=0x51&&o.op<=0x60) id+=sz;   // small int pushes = invoke-ids / small consts
    else if(o.op===0x00||o.op===0x4f) id+=sz;
    else if(STACK.has(o.op)) s+=sz;
    else arith+=sz; }
  return {stack:s,cbig,csmall,inv,id,arith}; }
const big=['30','32','33','35','24','23','27','26','21','MAIN'];
for(const id of d.order){ if(!big.includes(String(id)))continue; const c=cats(parse(d.bodies.get(id)));
  console.log('def#'+String(id).padStart(3), 'len',String(d.bodies.get(id).length).padStart(4),'stack',String(c.stack).padStart(4),'inv',c.inv,'id/int',c.id,'cbig',c.cbig,'csmall',c.csmall,'arith',c.arith); }
const cm=cats(d.mainOps);
console.log('MAIN   ', 'len',String(serialize(d.mainOps).length).padStart(4),'stack',String(cm.stack).padStart(4),'inv',cm.inv,'id/int',cm.id,'cbig',cm.cbig,'csmall',cm.csmall,'arith',cm.arith);
