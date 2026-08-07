import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { decompile } from './decompile.mjs';
import { dissect } from './program.mjs';
import { scheduleBlock } from './scheduler.mjs';
import { strat_rollmove, strat_pickdel } from './router.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const raw = JSON.parse(readFileSync(join(here, 'baseline.json'), 'utf8'));
const baseline = Uint8Array.from(Buffer.from(raw.debug?.bytecode || raw.bytecodeHex || raw.hex, 'hex'));
const d = dissect(baseline);
const arity = JSON.parse(readFileSync(join(here, 'arity.json'), 'utf8'));
const ID=30;
const items = decompile(d.bodies.get(ID), arity, arity[ID].in, { label:'def#'+ID });
const encLen=(e)=> e.enc? e.enc.length : 1;
let bi=0;
for (const it of items){ if(it.ctrl!==undefined){bi++;continue;} 
  const b=it.block; let cap=null;
  try { scheduleBlock(b, arity, { readyOrder:true, eagerDrop:true, _probe:(x)=>{cap=x;} }); } catch(e){ bi++; continue; }
  if(!cap){bi++;continue;}
  const S = cap.S.filter(s=>!s.t).map(s=>s.tok); // homes only (transients shouldn't exist pre-arrange)
  const hasT = cap.S.some(s=>s.t);
  const pd = strat_pickdel(S, cap.exit, encLen);
  const rm = strat_rollmove(S, cap.exit, encLen);
  if(cap.S.length>=15)
    console.log(`block#${bi} Slen=${cap.S.length} exit=${cap.exit.length} transients=${hasT} | pickdel=${pd.bytes} rollmove=${rm.bytes}${rm.note?(' ('+rm.note+')'):''}`);
  bi++;
}
