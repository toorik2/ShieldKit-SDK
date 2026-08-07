// Measure the TRUE sched-search delta on the CANONICAL 6055 program's own (greedy-scheduled)
// bodies, then (if sound+positive) emit a rescheduled 6055' and re-check byte length.
import { readFileSync } from 'node:fs';
import { serialize } from './asm.mjs';
import { decompile } from './decompile.mjs';
import { dissect, runSubroutine } from './program.mjs';
import { scheduleBlock, serializeOps } from './scheduler.mjs';
import { peephole } from './peephole.mjs';
const CANON='/tmp/claude-1000/-home-toorik-Projects-verifier-cash/fa6e3d58-5aaa-4eaf-bef3-80ed05b22fa9/scratchpad/expderiv-blob/optimized.hex';
const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const arity=JSON.parse(readFileSync('./arity.json','utf8'));
const canon=Uint8Array.from(Buffer.from(readFileSync(CANON,'utf8').trim(),'hex'));
const d=dissect(canon);
function mkrng(seed){let x=BigInt(seed)*6364136223846793005n+1n;return()=>{x=(x*6364136223846793005n+1442695040888963407n)&((1n<<64n)-1n);let z=x;z=(z^(z>>30n))*0xbf58476d1ce4e5b9n&((1n<<64n)-1n);z=(z^(z>>27n))*0x94d049bb133111ebn&((1n<<64n)-1n);return(z^(z>>31n))&((1n<<64n)-1n);};}
function randFp(r){let v=0n;for(let i=0;i<4;i++)v=(v<<64n)|r();return v%P;}
function nodesOf(block){const order=[],seen=new Set();const visit=(rf)=>{if(rf.k!=='out')return;const n=rf.node;if(seen.has(n.id))return;seen.add(n.id);for(const inp of n.ins)visit(inp);order.push(n);};for(const rf of[...block.exit,...block.exitAlt])visit(rf);return order;}
function exhBestOrder(block,nodes){const ids=nodes.map(n=>n.id);const deps=new Map(nodes.map(n=>[n.id,n.ins.filter(r=>r.k==='out').map(r=>r.node.id)]));const idset=new Set(ids);let best=Infinity,bestOrder=null,perms=0;const done=new Set(),cur=[];const rec=()=>{if(done.size===ids.length){perms++;const by=serializeOps(peephole(scheduleBlock(block,arity,{eagerDrop:true,nodeOrder:cur.slice()}).ops)).length;if(by<best){best=by;bestOrder=cur.slice();}return;}for(const id of ids){if(done.has(id))continue;if(deps.get(id).every(p=>!idset.has(p)||done.has(p))){done.add(id);cur.push(id);rec();cur.pop();done.delete(id);}}};rec();return{best,bestOrder,perms};}

// scan all bodies; report node count + greedy vs exhaustive body size (only attempt <=11 nodes)
const results=[];
for(const id of d.order){
  let items;
  try{ items=decompile(d.bodies.get(id),arity,arity[String(id)]?.in??0,{label:''+id}); }catch(e){ continue; }
  const blkItem=items.find(it=>it.block); if(!blkItem)continue;
  const blk=blkItem.block; const nodes=nodesOf(blk);
  const greedyLen=d.bodies.get(id).length;
  if(nodes.length>11){ results.push({id,nodes:nodes.length,greedyLen,skip:'>11 nodes'}); continue; }
  const {best,bestOrder,perms}=exhBestOrder(blk,nodes);
  const optOps=peephole(scheduleBlock(blk,arity,{eagerDrop:true,nodeOrder:bestOrder}).ops);
  const optBytes=serializeOps(optOps);
  // soundness: bit-identical vs canonical on 40 random Fp inputs
  const override=new Map([[id,optBytes]]);
  let match=0,clean=0,mismatch=0;
  for(let s=0;s<40;s++){const rng=mkrng(s*1009+id*7+1);const inputs=Array.from({length:arity[String(id)].in},()=>randFp(rng));const ro=runSubroutine(d,id,inputs);if(ro.error)continue;clean++;const rs=runSubroutine(d,id,inputs,override);if(!rs.error&&ro.stack.length===rs.stack.length&&ro.stack.every((x,i)=>x===rs.stack[i]))match++;else mismatch++;}
  results.push({id,nodes:nodes.length,greedyLen,exhLen:optBytes.length,delta:greedyLen-optBytes.length,perms,sound:mismatch===0&&clean>0,diff:`${match}/${clean}`});
}
let totalWin=0;
for(const r of results.sort((a,b)=>(b.delta||0)-(a.delta||0))){
  if(r.skip){ continue; }
  const win=(r.sound&&r.delta>0)?r.delta:0; totalWin+=win;
  console.log(`def#${r.id}: nodes ${r.nodes} greedy ${r.greedyLen}B exh ${r.exhLen}B delta ${r.delta>=0?'-':'+'}${Math.abs(r.delta)} perms ${r.perms} sound ${r.sound} diff ${r.diff}${win>0?'  <== WIN':''}`);
}
console.log('--- skipped (>11 nodes) ---');
for(const r of results) if(r.skip) console.log(`def#${r.id}: nodes ${r.nodes} greedy ${r.greedyLen}B (skipped)`);
console.log('TOTAL realizable sched-search win on 6055 (sound, delta>0):', totalWin, 'B');
