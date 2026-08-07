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
const mainItems = decompile(serialize(d.mainOps), arity, 10, { label: 'main' });
const blocks = mainItems.filter(it=>it.block).map(it=>it.block);
const b = blocks[Number(process.argv[2]??14)];
function topoNodes(roots){const order=[];const seen=new Set();const visit=(ref)=>{if(ref.k!=='out')return;const n=ref.node;if(seen.has(n.id))return;seen.add(n.id);for(const inp of n.ins)visit(inp);order.push(n);};for(const r of roots)visit(r);return order;}
const nodes=topoNodes([...b.exit,...b.exitAlt]);
const ids=nodes.map(n=>n.id);
const idset=new Set(ids);
const idx=new Map(ids.map((id,i)=>[id,i]));
const deps=new Map(nodes.map(n=>[n.id,[...new Set(n.ins.filter(r=>r.k==='out').map(r=>r.node.id))].filter(x=>idset.has(x))]));
const predMask=ids.map(id=>{let m=0;for(const p of deps.get(id))m|=(1<<idx.get(p));return m;});
const CONFIGS=[{readyOrder:true,eagerDrop:true,arrange:'move'},{readyOrder:true,eagerDrop:false,arrange:'move'},{readyOrder:true,eagerDrop:true,tieBreak:'shallowmax',arrange:'move'},{readyOrder:true,eagerDrop:true,tieBreak:'netpop',arrange:'move'},{readyOrder:true,eagerDrop:true,tieBreak:'deepfirst',arrange:'move'},{readyOrder:true,eagerDrop:true},{readyOrder:true,eagerDrop:true,tieBreak:'shallowmax'}];
let best=Infinity,bestO=null,bestC=null,cnt=0;
const order=[];
function rec(done){
  if(done===(1<<ids.length)-1){ cnt++;
    const nodeOrder=order.map(i=>ids[i]);
    for(const cfg of CONFIGS){ try{const s=serializeOps(peephole(scheduleBlock(b,arity,{...cfg,nodeOrder}).ops)).length; if(s<best){best=s;bestO=nodeOrder.slice();bestC=cfg;}}catch(e){} }
    return;
  }
  for(let i=0;i<ids.length;i++){ if(done&(1<<i))continue; if((predMask[i]&done)===predMask[i]){ order.push(i); rec(done|(1<<i)); order.pop(); } }
}
rec(0);
const orig=serialize(peephole(b.rawOps)).length;
console.log(`blk exhaustive: extensions=${cnt} orig=${orig} BEST=${best} save=${orig-best}`);
console.log('bestCfg=',JSON.stringify(bestC));
console.log('bestOrder=',JSON.stringify(bestO));
