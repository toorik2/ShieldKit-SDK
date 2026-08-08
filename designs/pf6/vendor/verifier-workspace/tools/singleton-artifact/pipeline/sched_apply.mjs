// SCHED-SEARCH pass: exhaustively reschedule the small blocks that BEAT greedy
// on the canonical 6055 program (measured: def#23 -13, def#24 -9; both VM-sound 40/40).
// Pure topological reorder (same op multiset) => orthogonal to the constant passes.
import { readFileSync } from 'node:fs';
import { serialize } from './asm.mjs';
import { decompile } from './decompile.mjs';
import { dissect } from './program.mjs';
import { scheduleBlock, serializeOps } from './scheduler.mjs';
import { peephole } from './peephole.mjs';
const DEFINE=0x89;
const arity=JSON.parse(readFileSync(new URL('./arity.json',import.meta.url),'utf8'));
const idPushOp=(id)=>(id>=1&&id<=16)?{op:0x50+id}:{op:0,data:Uint8Array.from([id])};
function nodesOf(block){const order=[],seen=new Set();const visit=(rf)=>{if(rf.k!=='out')return;const n=rf.node;if(seen.has(n.id))return;seen.add(n.id);for(const inp of n.ins)visit(inp);order.push(n);};for(const rf of[...block.exit,...block.exitAlt])visit(rf);return order;}
function exhBestOrder(block,nodes){const ids=nodes.map(n=>n.id);const deps=new Map(nodes.map(n=>[n.id,n.ins.filter(r=>r.k==='out').map(r=>r.node.id)]));const idset=new Set(ids);let best=Infinity,bestOrder=null;const done=new Set(),cur=[];const rec=()=>{if(done.size===ids.length){const by=serializeOps(peephole(scheduleBlock(block,arity,{eagerDrop:true,nodeOrder:cur.slice()}).ops)).length;if(by<best){best=by;bestOrder=cur.slice();}return;}for(const id of ids){if(done.has(id))continue;if(deps.get(id).every(p=>!idset.has(p)||done.has(p))){done.add(id);cur.push(id);rec();cur.pop();done.delete(id);}}};rec();return bestOrder;}

export function schedApply(bytes,{ids=[23,24]}={}){
  const d=dissect(bytes);
  const newBody=new Map();
  let hits=0;
  for(const id of ids){
    const items=decompile(d.bodies.get(id),arity,arity[String(id)].in,{label:''+id});
    const blk=items.find(it=>it.block).block;
    const nodes=nodesOf(blk);
    const bestOrder=exhBestOrder(blk,nodes);
    const optBytes=serializeOps(peephole(scheduleBlock(blk,arity,{eagerDrop:true,nodeOrder:bestOrder}).ops));
    if(optBytes.length < d.bodies.get(id).length){ newBody.set(id,optBytes); hits++; }
  }
  const ops=[];
  for(const id of d.order){
    const body=newBody.get(id)||d.bodies.get(id);
    ops.push({op:0,data:body}); ops.push(idPushOp(id)); ops.push({op:DEFINE});
  }
  for(const o of d.mainOps) ops.push(o);
  return {bytes:serialize(ops), hits};
}
