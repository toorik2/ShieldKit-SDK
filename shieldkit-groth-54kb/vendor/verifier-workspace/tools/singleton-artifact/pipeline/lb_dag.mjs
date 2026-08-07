import { readFileSync } from 'node:fs';
import { parse, serialize } from './asm.mjs';
import { dissect } from './program.mjs';
import { decompile } from './decompile.mjs';
const arity = JSON.parse(readFileSync('arity.json','utf8'));
const hex = readFileSync('optimized-full-5728.hex','utf8').trim();
const bytes = Uint8Array.from(Buffer.from(hex,'hex'));
const d = dissect(bytes);

// analyze one body's items (blocks)
function analyzeBody(body, ar, inAr, label){
  let items;
  try { items = decompile(body, arity, inAr, {label}); }
  catch(e){ return {err:e.message}; }
  let nodesPrim=0, nodesInvoke=0, invokeIdBytes=0;
  let copyExcess=0, dead=0, valCount=0;
  let exitPos=0;
  for(const it of items){
    if(!it.block) continue;
    const b=it.block;
    // gather all values produced in this block: entry slots (k:in / k:ain) + node outputs
    // build a use-count map keyed by identity
    const uses = new Map(); // key -> count
    const keyOf=(r)=>{
      if(r.k==='in') return 'in'+r.i;
      if(r.k==='ain') return 'ain'+r.i;
      if(r.k==='const') return null; // consts are re-pushed, not copied from a slot; treat separately
      if(r.k==='out') return 'n'+r.node.id+'.'+r.j;
      return null;
    };
    // walk rawOps to find nodes and their operand refs — easier: re-decompile is opaque.
    // Instead: nodes are embedded in exit refs and in node.ins chains. Collect all nodes reachable.
    const allNodes = new Map();
    const seen=new Set();
    function collect(r){
      if(r.k==='out'){ const nd=r.node; if(!allNodes.has(nd.id)){ allNodes.set(nd.id,nd); for(const inr of nd.ins) collect(inr);} }
    }
    for(const r of b.exit) collect(r);
    for(const r of b.exitAlt) collect(r);
    // count uses: each node.ins ref is a consumption; each exit/exitAlt ref is a consumption
    const bump=(r)=>{ const k=keyOf(r); if(k===null) return; uses.set(k,(uses.get(k)||0)+1); };
    for(const nd of allNodes.values()){
      for(const inr of nd.ins) bump(inr);
      if(nd.k==='prim') nodesPrim++;
      else { nodesInvoke++; const id=nd.invId; invokeIdBytes += (id>=1&&id<=16)?1:(serialize([{data:Uint8Array.from([id])}]).length); }
    }
    for(const r of b.exit){ bump(r); exitPos++; }
    for(const r of b.exitAlt){ bump(r); }
    // supplies: entry slots + node outputs. use-count per supplied value.
    // entry slots
    for(let i=0;i<b.entryDepth;i++){ const k='in'+i; const u=uses.get(k)||0; valCount++; if(u===0) dead++; else copyExcess += (u-1); }
    for(let i=0;i<b.entryAlt;i++){ const k='ain'+i; const u=uses.get(k)||0; valCount++; if(u===0) dead++; else copyExcess += (u-1); }
    // node outputs
    for(const nd of allNodes.values()){
      const outc = nd.k==='invoke' ? arity[nd.invId].out : primOut(nd.code);
      for(let j=0;j<outc;j++){ const k='n'+nd.id+'.'+j; const u=uses.get(k)||0; valCount++; if(u===0) dead++; else copyExcess += (u-1); }
    }
  }
  return {nodesPrim,nodesInvoke,invokeIdBytes,copyExcess,dead,valCount};
}
function primOut(code){ // VALOP outputs are all 1
  return 1;
}
let T={nodesPrim:0,nodesInvoke:0,invokeIdBytes:0,copyExcess:0,dead:0,valCount:0,errs:0};
const perBody=[];
for(const id of d.order){
  const ar=arity[id];
  const r=analyzeBody(d.bodies.get(id), ar, ar?ar.in:0, 'def#'+id);
  if(r.err){ T.errs++; perBody.push([id,'ERR:'+r.err]); continue; }
  for(const k of Object.keys(T)) if(k!=='errs') T[k]+=r[k];
  perBody.push([id, `nP=${r.nodesPrim} nI=${r.nodesInvoke} copyX=${r.copyExcess} dead=${r.dead} vals=${r.valCount}`]);
}
// main
{
  const r=analyzeBody(serialize(d.mainOps), null, 10, 'MAIN');
  if(r.err){ T.errs++; perBody.push(['MAIN','ERR:'+r.err]); }
  else { for(const k of Object.keys(T)) if(k!=='errs') T[k]+=r[k]; perBody.push(['MAIN',`nP=${r.nodesPrim} nI=${r.nodesInvoke} copyX=${r.copyExcess} dead=${r.dead} vals=${r.valCount}`]); }
}
console.log('=== per body ===');
for(const [id,s] of perBody) console.log(String(id).padStart(6), s);
console.log('=== TOTALS ===', JSON.stringify(T));
// LOWER BOUND (bytes):
// ops: prim >=1B, invoke >= 1B(INVOKE)+idBytes
// copies: >= ceil(copyExcess/3)  (3DUP max 3 vals/byte) -- conservative
// dead: >= ceil(dead/2) (2DROP)  -- conservative
const opsLB = T.nodesPrim*1 + T.nodesInvoke*1 + T.invokeIdBytes;
const copyLB = Math.ceil(T.copyExcess/3);
const deadLB = Math.ceil(T.dead/2);
console.log('LB ops(prim+invoke+id) =',opsLB,' copyLB(/3)=',copyLB,' deadLB(/2)=',deadLB);
console.log('COMBINATORIAL LOWER BOUND (program, excl consts/define-frame) =', opsLB+copyLB+deadLB,'B');
