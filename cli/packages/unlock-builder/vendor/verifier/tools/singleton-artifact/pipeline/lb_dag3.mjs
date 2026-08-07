import { readFileSync } from 'node:fs';
import { serialize } from './asm.mjs';
import { dissect } from './program.mjs';
import { decompile } from './decompile.mjs';
const hex = readFileSync('optimized-full-5728.hex','utf8').trim();
const bytes = Uint8Array.from(Buffer.from(hex,'hex'));
const d = dissect(bytes);
const arity = JSON.parse(readFileSync('arity.json','utf8'));
arity["13"]={in:0,out:1};
// brute-force fix arity for bodies that fail: try in 0..30 until decompile succeeds
function tryDecompile(body,inAr,label){ return decompile(body, arity, inAr, {label}); }
function bestArity(id){
  const body=d.bodies.get(id);
  // try declared first, then search
  const cands=[]; if(arity[id]) cands.push(arity[id].in);
  for(let k=0;k<=30;k++) cands.push(k);
  for(const k of cands){ try{ tryDecompile(body,k,'def#'+id); return k; }catch(e){} }
  return null;
}
function primOut(){return 1;}
function analyzeItems(items){
  let nodesPrim=0,nodesInvoke=0,invokeIdBytes=0,copyExcess=0,dead=0,valCount=0;
  for(const it of items){ if(!it.block) continue; const b=it.block;
    const uses=new Map();
    const keyOf=(r)=> r.k==='in'?'in'+r.i : r.k==='ain'?'ain'+r.i : r.k==='out'?'n'+r.node.id+'.'+r.j : null;
    const allNodes=new Map();
    function collect(r){ if(r.k==='out'){ const nd=r.node; if(!allNodes.has(nd.id)){ allNodes.set(nd.id,nd); for(const inr of nd.ins) collect(inr);} } }
    for(const r of b.exit) collect(r); for(const r of b.exitAlt) collect(r);
    const bump=(r)=>{ const k=keyOf(r); if(k!==null) uses.set(k,(uses.get(k)||0)+1); };
    for(const nd of allNodes.values()){ for(const inr of nd.ins) bump(inr);
      if(nd.k==='prim') nodesPrim++; else { nodesInvoke++; const id=nd.invId; const a=arity[id]; invokeIdBytes += (id>=1&&id<=16)?1:2; } }
    for(const r of b.exit) bump(r); for(const r of b.exitAlt) bump(r);
    for(let i=0;i<b.entryDepth;i++){ const u=uses.get('in'+i)||0; valCount++; if(u===0)dead++; else copyExcess+=(u-1); }
    for(let i=0;i<b.entryAlt;i++){ const u=uses.get('ain'+i)||0; valCount++; if(u===0)dead++; else copyExcess+=(u-1); }
    for(const nd of allNodes.values()){ const outc = nd.k==='invoke'?(arity[nd.invId]?arity[nd.invId].out:1):primOut();
      for(let j=0;j<outc;j++){ const u=uses.get('n'+nd.id+'.'+j)||0; valCount++; if(u===0)dead++; else copyExcess+=(u-1); } }
  }
  return {nodesPrim,nodesInvoke,invokeIdBytes,copyExcess,dead,valCount};
}
let T={nodesPrim:0,nodesInvoke:0,invokeIdBytes:0,copyExcess:0,dead:0,valCount:0};
const rows=[]; let covered=0, skipped=[];
for(const id of d.order){
  const inAr=bestArity(id);
  if(inAr===null){ skipped.push('def#'+id); continue; }
  const items=tryDecompile(d.bodies.get(id),inAr,'def#'+id);
  const r=analyzeItems(items); for(const k in T)T[k]+=r[k]; rows.push([id,r]); covered++;
}
// main
let mainItems=null;
for(const k of [10,9,11,8,12,7,13,6,14,5,15,4,16]){ try{ mainItems=decompile(serialize(d.mainOps),arity,k,{label:'main'}); rows.push(['MAIN(in'+k+')',null]); break; }catch(e){} }
if(mainItems){ const r=analyzeItems(mainItems); for(const k in T)T[k]+=r[k]; rows[rows.length-1][1]=r; } else skipped.push('MAIN');
console.log('covered bodies',covered,'of',d.order.length,'skipped:',skipped.join(',')||'none');
for(const [id,r] of rows) if(r) console.log(String(id).padStart(9), `nP=${r.nodesPrim} nI=${r.nodesInvoke} copyX=${r.copyExcess} dead=${r.dead} vals=${r.valCount}`);
console.log('=== TOTALS ===',JSON.stringify(T));
const opsLB=T.nodesPrim + T.nodesInvoke + T.invokeIdBytes;
console.log(`ops(prim ${T.nodesPrim} + invoke-opcode ${T.nodesInvoke} + invoke-id ${T.invokeIdBytes}) = ${opsLB} B`);
console.log(`copyExcess=${T.copyExcess} dead=${T.dead}`);
console.log(`LB(loose: copies/3, dead/2) = ${opsLB+Math.ceil(T.copyExcess/3)+Math.ceil(T.dead/2)} B`);
console.log(`LB(mid:   copies/2, dead/2) = ${opsLB+Math.ceil(T.copyExcess/2)+Math.ceil(T.dead/2)} B`);
console.log(`LB(tight: copies*1, dead*1) = ${opsLB+T.copyExcess+T.dead} B`);
