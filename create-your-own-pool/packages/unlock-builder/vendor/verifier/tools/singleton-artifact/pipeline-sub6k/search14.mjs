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
const N = Number(process.argv[2] ?? 14);
const arrangeMove = process.argv[3]==='move';
const b = blocks[N];

function topoNodes(roots){const order=[];const seen=new Set();const visit=(ref)=>{if(ref.k!=='out')return;const n=ref.node;if(seen.has(n.id))return;seen.add(n.id);for(const inp of n.ins)visit(inp);order.push(n);};for(const r of roots)visit(r);return order;}
const nodes = topoNodes([...b.exit, ...b.exitAlt]);
const ids = nodes.map(n=>n.id);
const byId = new Map(nodes.map(n=>[n.id,n]));
const deps = new Map(nodes.map(n=>[n.id, n.ins.filter(r=>r.k==='out').map(r=>r.node.id)]));

function score(order, cfg){ try { return serializeOps(peephole(scheduleBlock(b, arity, {...cfg, nodeOrder: order}).ops)).length; } catch(e){ return Infinity; } }

// random topological orders
function randTopo(rng){
  const indeg = new Map(ids.map(id=>[id,0]));
  const adj = new Map(ids.map(id=>[id,[]]));
  for(const id of ids) for(const p of deps.get(id)){ adj.get(p).push(id); indeg.set(id, indeg.get(id)); }
  for(const id of ids) indeg.set(id, deps.get(id).length);
  let ready = ids.filter(id=>indeg.get(id)===0);
  const order=[];
  while(ready.length){ const k=Math.floor(rng()*ready.length); const id=ready[k]; ready.splice(k,1); order.push(id);
    for(const c of adj.get(id)){ indeg.set(c,indeg.get(c)-1); if(indeg.get(c)===0) ready.push(c); } }
  return order;
}
let x=12345; const rng=()=>{x=(x*1103515245+12345)&0x7fffffff; return x/0x7fffffff;};
const cfgs = arrangeMove ? [{readyOrder:true,eagerDrop:true,arrange:'move'},{readyOrder:true,eagerDrop:true,tieBreak:'shallowmax',arrange:'move'}] : [{readyOrder:true,eagerDrop:true},{readyOrder:true,eagerDrop:true,tieBreak:'shallowmax'}];
let best=Infinity, bestOrder=null, bestCfg=null;
const TRIALS = Number(process.argv[4] ?? 20000);
for(let t=0;t<TRIALS;t++){ const o=randTopo(rng); for(const cfg of cfgs){ const s=score(o,cfg); if(s<best){best=s;bestOrder=o.slice();bestCfg=cfg;} } }
console.log(`blk#${N} nodes=${nodes.length} orig=${serialize(peephole(b.rawOps)).length} randsearch(${TRIALS}, move=${arrangeMove}) best=${best} cfg=${JSON.stringify(bestCfg)}`);
