import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { decompile } from './decompile.mjs';
import { dissect } from './program.mjs';
import { scheduleBlock } from './scheduler.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const raw = JSON.parse(readFileSync(join(here, 'baseline.json'), 'utf8'));
const baseline = Uint8Array.from(Buffer.from(raw.debug?.bytecode || raw.bytecodeHex || raw.hex, 'hex'));
const d = dissect(baseline);
const arity = JSON.parse(readFileSync(join(here, 'arity.json'), 'utf8'));
const ID=30, target=Number(process.argv[2]||10);
const items = decompile(d.bodies.get(ID), arity, arity[ID].in, { label:'def#'+ID });
let bi=0;
for (const it of items){ if(it.ctrl!==undefined){bi++;continue;} if(bi===target){
  const b=it.block;
  let cap=null;
  scheduleBlock(b, arity, { readyOrder:true, eagerDrop:true, _probe:(x)=>{cap=x;} });
  console.log('pre-arrange S (bottom->top), len', cap.S.length);
  console.log(cap.S.map((s,i)=>`${i}:${s.tok}${s.t?'*':''}`).join(' '));
  console.log('\nexit target (bottom->top), len', cap.exit.length);
  console.log(cap.exit.map((e,i)=>`${i}:${e.tok||('const'+(e.enc?e.enc.length:'?'))}`).join(' '));
  // analyze: for each exit item, where is its home in S and how many uses
  const homes = new Map(); cap.S.forEach((s,i)=>{ if(!s.t) homes.set(s.tok, i); });
  console.log('\nexit->home depth (from top):');
  const line=[];
  for(const e of cap.exit){ if(e.tok===null||e.tok===undefined){line.push('K');continue;} const idx=homes.get(e.tok); line.push(idx===undefined?'?':(cap.S.length-1-idx)); }
  console.log(line.join(' '));
}
  bi++;
}
