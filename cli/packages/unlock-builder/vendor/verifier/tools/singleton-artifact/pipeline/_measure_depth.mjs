import { repoPath as vcRepoPath } from '#repo-paths';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { serialize, parse } from './asm.mjs';
import { decompile } from './decompile.mjs';
import { dissect } from './program.mjs';
import { scheduleBlock, serializeOps } from './scheduler.mjs';
import { peephole } from './peephole.mjs';

const here = vcRepoPath('tools/singleton-recompiler');
const raw = JSON.parse(readFileSync(join(here,'baseline.json'),'utf8'));
const baseline = Uint8Array.from(Buffer.from(raw.debug?.bytecode||raw.hex,'hex'));
const d = dissect(baseline);
const arity = JSON.parse(readFileSync(join(here,'arity.json'),'utf8'));

// Count, over the chosen (scheduled) bodies, how many depth-push bytes are spent on
// ROLL/PICK at depth>2 (2-byte access d<=16, 3-byte d>16) and the deep-op histogram.
const CONFIGS=[{readyOrder:true,eagerDrop:true},{readyOrder:false,eagerDrop:false},{readyOrder:true,eagerDrop:false},{readyOrder:false,eagerDrop:true}];
let pickroll=0, deep16=0, hist={};
let totalBodyBytes=0;
const analyzeOps=(ops)=>{
  // ops is array of records; re-derive depth pushes preceding PICK(0x79)/ROLL(0x7a)
  for(let i=0;i<ops.length;i++){
    const o=ops[i];
    const code=o._raw? o._raw[0] : o.op;
    if(code===0x79||code===0x7a){
      // preceding op is depth push
      const p=ops[i-1];
      let d=null;
      if(p){ if(p.op>=0x51&&p.op<=0x60)d=p.op-0x50; else if(p.op===0&&p.data)d=p.data[0]; }
      if(d!==null){ pickroll++; hist[d]=(hist[d]||0)+1; if(d>16)deep16++; }
    }
  }
};
for(const id of d.order){
  const items=decompile(d.bodies.get(id),arity,arity[id].in,{label:'d'+id});
  for(const it of items){
    if(it.ctrl!==undefined)continue;
    let best=null;
    for(const cfg of CONFIGS){ try{ const ops=peephole(scheduleBlock(it.block,arity,cfg).ops); const by=serializeOps(ops); if(!best||by.length<best.by.length)best={ops,by}; }catch(e){} }
    const origBy=serialize(peephole(it.block.rawOps));
    if(best&&best.by.length<origBy.length){ analyzeOps(best.ops); totalBodyBytes+=best.by.length; }
    else totalBodyBytes+=origBy.length;
  }
}
console.log('scheduled-body PICK/ROLL depth pushes:', pickroll);
console.log('of which depth>16 (3-byte access):', deep16);
const keys=Object.keys(hist).map(Number).sort((a,b)=>a-b);
console.log('depth histogram:', keys.map(k=>`${k}:${hist[k]}`).join(' '));
// bytes spent on depth pushes: d in 3..16 -> 1 byte push; d>16 -> ~2 byte push
let pushBytes=0; for(const k of keys){ pushBytes += hist[k]*(k>16?2:1); }
console.log('total depth-push bytes (excl the PICK/ROLL op itself):', pushBytes);
