// TAIL free-rider pass (applied on top of the p-pooled + twist-derived program).
// Two SOUND, GENERAL curve-constant derivations (no vk_x/statement baking):
//  [A] inv2 = (p+1)/2  (the modular inverse of 2). Baked ONCE (def#17, 33 B push).
//      Derive from the already-hoisted p (id 13): OP_13 INVOKE OP_1ADD OP_2 OP_DIV
//      -> [ (p+1)/2 ]  (5 B). Net -28 B. (p+1 is even, integer div is exact & == inv2.)
//  [B] 6x^2 subgroup scalar. Baked ONCE (MAIN, 17 B push). Derive inline from the
//      BN254 seed x: push x; DUP; MUL; OP_6; MUL  (13 B). Net -4 B. x is the universal
//      curve seed (same class as p / the b2 coeffs), not a statement constant.
import { parse, serialize } from './asm.mjs';
import { dissect } from './program.mjs';
const DEFINE=0x89, INVOKE=0x8a;
export const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
export const X=4965661367192848881n;
export const INV2=(P+1n)/2n;
export const SIXX2=6n*X*X;
const toLE=(x,n)=>{const o=new Uint8Array(n);let v=x;for(let i=0;i<n;i++){o[i]=Number(v&0xffn);v>>=8n;}return o;};
const minLE=(x)=>{const b=[];let v=x;while(v>0n){b.push(Number(v&0xffn));v>>=8n;}if(b.length===0)b.push(0);if(b[b.length-1]&0x80)b.push(0);return Uint8Array.from(b);};
const eq=(a,b)=>Buffer.from(a).equals(Buffer.from(b));
const idPushOp=(id)=>(id>=1&&id<=16)?{op:0x50+id}:{op:0,data:Uint8Array.from([id])};

const inv2LE=toLE(INV2,32);
const sixx2LE=minLE(SIXX2);
const xLE=minLE(X);

// inv2 derive-from-p op sequence: OP_13 INVOKE OP_1ADD OP_2 OP_DIV
const inv2Seq=(poolId)=>[idPushOp(poolId),{op:INVOKE},{op:0x8b}/*1ADD*/,{op:0x52}/*OP_2*/,{op:0x96}/*DIV*/];
// 6x^2 inline derive: push x ; DUP ; MUL ; OP_6 ; MUL
const sixx2Seq=()=>[{op:0,data:xLE},{op:0x76}/*DUP*/,{op:0x95}/*MUL*/,{op:0x56}/*OP_6*/,{op:0x95}/*MUL*/];

function rewriteOps(ops,{poolId,doInv2,do6x2}){
  const out=[]; let inv2Hits=0, sixHits=0;
  for(const o of ops){
    if(doInv2 && o.data && o.data.length===32 && eq(o.data,inv2LE)){ out.push(...inv2Seq(poolId)); inv2Hits++; continue; }
    if(do6x2 && o.data && eq(o.data,sixx2LE)){ out.push(...sixx2Seq()); sixHits++; continue; }
    out.push(o);
  }
  return {out,inv2Hits,sixHits};
}

export function tailDerive(bytes,{poolId=13,doInv2=true,do6x2=true}={}){
  const d=dissect(bytes);
  let inv2Hits=0, sixHits=0;
  const recs=[];
  for(const id of d.order){
    const r=rewriteOps(parse(d.bodies.get(id)),{poolId,doInv2,do6x2});
    inv2Hits+=r.inv2Hits; sixHits+=r.sixHits;
    recs.push({id, body:serialize(r.out)});
  }
  const mr=rewriteOps(d.mainOps,{poolId,doInv2,do6x2});
  inv2Hits+=mr.inv2Hits; sixHits+=mr.sixHits;
  const ops=[];
  for(const r of recs){ ops.push({op:0,data:r.body}); ops.push(idPushOp(r.id)); ops.push({op:DEFINE}); }
  for(const o of mr.out) ops.push(o);
  return {bytes:serialize(ops), inv2Hits, sixHits};
}
