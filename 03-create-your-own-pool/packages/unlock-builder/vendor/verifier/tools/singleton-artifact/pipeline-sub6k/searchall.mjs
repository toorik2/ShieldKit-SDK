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
const CONFIGS=[{readyOrder:true,eagerDrop:true},{readyOrder:true,eagerDrop:false},{readyOrder:true,eagerDrop:true,tieBreak:'shallowmax'},{readyOrder:true,eagerDrop:true,arrange:'move'},{readyOrder:true,eagerDrop:false,arrange:'move'},{readyOrder:true,eagerDrop:true,tieBreak:'shallowmax',arrange:'move'},{readyOrder:true,eagerDrop:true,tieBreak:'netpop',arrange:'move'},{readyOrder:true,eagerDrop:true,tieBreak:'deepfirst',arrange:'move'}];
function topoNodes(roots){const order=[];const seen=new Set();const visit=(ref)=>{if(ref.k!=='out')return;const n=ref.node;if(seen.has(n.id))return;seen.add(n.id);for(const inp of n.ins)visit(inp);order.push(n);};for(const r of roots)visit(r);return order;}
const TRIALS = Number(process.argv[2] ?? 20000);
let totHeur=0, totSearch=0, totOrig=0;
for(let bidx=0;bidx<blocks.length;bidx++){
  const b=blocks[bidx];
  const nodes=topoNodes([...b.exit,...b.exitAlt]);
  const orig=serialize(peephole(b.rawOps)).length;
  let heur=orig; for(const cfg of CONFIGS){ try{const by=serializeOps(peephole(scheduleBlock(b,arity,cfg).ops)).length; if(by<heur)heur=by;}catch(e){} }
  totOrig+=orig; totHeur+=heur;
  if(nodes.length<2){ totSearch+=heur; continue; }
  const ids=nodes.map(n=>n.id);
  const deps=new Map(nodes.map(n=>[n.id,n.ins.filter(r=>r.k==='out').map(r=>r.node.id)]));
  const adj=new Map(ids.map(id=>[id,[]])); for(const id of ids) for(const p of deps.get(id)) adj.get(p).push(id);
  let x=99991+bidx*7; const rng=()=>{x=(x*1103515245+12345)&0x7fffffff;return x/0x7fffffff;};
  function randTopo(){const indeg=new Map(ids.map(id=>[id,deps.get(id).length]));let ready=ids.filter(id=>indeg.get(id)===0);const order=[];while(ready.length){const k=Math.floor(rng()*ready.length);const id=ready[k];ready.splice(k,1);order.push(id);for(const c of adj.get(id)){indeg.set(c,indeg.get(c)-1);if(indeg.get(c)===0)ready.push(c);}}return order;}
  let best=heur, bestO=null, bestC=null;
  const nt = Math.min(TRIALS, nodes.length<=3?200:TRIALS);
  for(let t=0;t<nt;t++){const o=randTopo();for(const cfg of CONFIGS){try{const s=serializeOps(peephole(scheduleBlock(b,arity,{...cfg,nodeOrder:o}).ops)).length;if(s<best){best=s;bestO=o.slice();bestC=cfg;}}catch(e){}}}
  totSearch+=best;
  if(best<heur) console.log(`blk#${bidx} nodes=${nodes.length} orig=${orig} heur=${heur} SEARCH=${best} save=${heur-best} cfg=${JSON.stringify(bestC)}`);
}
console.log(`MAIN totOrig=${totOrig} totHeur=${totHeur} totSearch=${totSearch}  search-vs-heur save=${totHeur-totSearch}`);
