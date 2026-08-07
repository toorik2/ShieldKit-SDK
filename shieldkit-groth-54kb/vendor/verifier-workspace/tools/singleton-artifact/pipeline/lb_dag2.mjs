import { readFileSync } from 'node:fs';
import { parse, serialize } from './asm.mjs';
import { dissect, decompileProgram } from './program.mjs';
const hex = readFileSync('optimized-full-5728.hex','utf8').trim();
const bytes = Uint8Array.from(Buffer.from(hex,'hex'));
const d = dissect(bytes);
const arity = JSON.parse(readFileSync("arity.json","utf8")); arity["13"]={in:0,out:1}; arity["16"]=arity["16"]||{in:2,out:2};
const ir = decompileProgram(d, arity, 10);

function primOut(){ return 1; }
function analyzeItems(items){
  let nodesPrim=0,nodesInvoke=0,invokeIdBytes=0,copyExcess=0,dead=0,valCount=0;
  for(const it of items){
    if(!it.block) continue;
    const b=it.block;
    const uses=new Map();
    const keyOf=(r)=> r.k==='in'?'in'+r.i : r.k==='ain'?'ain'+r.i : r.k==='out'?'n'+r.node.id+'.'+r.j : null;
    const allNodes=new Map();
    function collect(r){ if(r.k==='out'){ const nd=r.node; if(!allNodes.has(nd.id)){ allNodes.set(nd.id,nd); for(const inr of nd.ins) collect(inr);} } }
    for(const r of b.exit) collect(r);
    for(const r of b.exitAlt) collect(r);
    const bump=(r)=>{ const k=keyOf(r); if(k!==null) uses.set(k,(uses.get(k)||0)+1); };
    for(const nd of allNodes.values()){
      for(const inr of nd.ins) bump(inr);
      if(nd.k==='prim') nodesPrim++;
      else { nodesInvoke++; const id=nd.invId; invokeIdBytes += (id>=1&&id<=16)?1:serialize([{data:Uint8Array.from([id])}]).length; }
    }
    for(const r of b.exit) bump(r);
    for(const r of b.exitAlt) bump(r);
    for(let i=0;i<b.entryDepth;i++){ const u=uses.get('in'+i)||0; valCount++; if(u===0)dead++; else copyExcess+=(u-1); }
    for(let i=0;i<b.entryAlt;i++){ const u=uses.get('ain'+i)||0; valCount++; if(u===0)dead++; else copyExcess+=(u-1); }
    for(const nd of allNodes.values()){
      const outc = nd.k==='invoke'? arity[nd.invId].out : primOut();
      for(let j=0;j<outc;j++){ const u=uses.get('n'+nd.id+'.'+j)||0; valCount++; if(u===0)dead++; else copyExcess+=(u-1); }
    }
  }
  return {nodesPrim,nodesInvoke,invokeIdBytes,copyExcess,dead,valCount};
}
let T={nodesPrim:0,nodesInvoke:0,invokeIdBytes:0,copyExcess:0,dead:0,valCount:0};
const rows=[];
for(const id of d.order){ const r=analyzeItems(ir.bodies.get(id)); for(const k in T)T[k]+=r[k]; rows.push([id,r]); }
const rm=analyzeItems(ir.mainItems); for(const k in T)T[k]+=rm[k]; rows.push(['MAIN',rm]);
console.log('=== per body: nP nI copyX dead vals ===');
for(const [id,r] of rows) console.log(String(id).padStart(6), `nP=${r.nodesPrim} nI=${r.nodesInvoke} copyX=${r.copyExcess} dead=${r.dead} vals=${r.valCount}`);
console.log('=== TOTALS ===',JSON.stringify(T));
const opsLB=T.nodesPrim + T.nodesInvoke + T.invokeIdBytes;
const copyLB3=Math.ceil(T.copyExcess/3), copyLB1=T.copyExcess;
const deadLB2=Math.ceil(T.dead/2), deadLB1=T.dead;
console.log(`ops(prim ${T.nodesPrim} + invoke ${T.nodesInvoke} + idBytes ${T.invokeIdBytes}) = ${opsLB}`);
console.log(`LB(loose,copies/3,dead/2) = ${opsLB+copyLB3+deadLB2} B`);
console.log(`LB(tight,copies*1,dead*1) = ${opsLB+copyLB1+deadLB1} B`);
