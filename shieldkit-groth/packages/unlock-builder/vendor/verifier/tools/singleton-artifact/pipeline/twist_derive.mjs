// TWIST-DERIVE pass (applied on top of the p-pooled program).
// The G2 twist b = 3/(9+u) coeffs b2c1=-3*82^-1, b2c0=27*82^-1 (=-9*b2c1) are baked as
// two adjacent 32-byte pushes [b2c1, b2c0] in def#16 and in main (4 pushes, 132 B).
// Derive them on-chain from p via the live inverseFp(def#6), mulFp(def#3), negate(def#5),
// as a single nullary define (id 15, freed by the phase-1 dedup) that leaves [b2c1, b2c0]
// on the stack -- byte-identical order to the literals it replaces (1-for-2 substitution).
import { parse, serialize } from './asm.mjs';
import { dissect } from './program.mjs';
const DEFINE=0x89, INVOKE=0x8a;
const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
function inv(a,m){let[or,r]=[((a%m)+m)%m,m];let[os,s]=[1n,0n];while(r){const q=or/r;[or,r]=[r,or-q*r];[os,s]=[s,os-q*s];}return((os%m)+m)%m;}
const toLE=(x,n)=>{const o=new Uint8Array(n);for(let i=0;i<n;i++){o[i]=Number(x&0xffn);x>>=8n;}return o;};
const I82=inv(82n,P);
export const B2C0=(27n*I82)%P, B2C1=((P-3n)*I82)%P;
const b2c0LE=toLE(B2C0,32), b2c1LE=toLE(B2C1,32);
const eq=(a,b)=>Buffer.from(a).equals(Buffer.from(b));
const idPushOp=(id)=>(id>=1&&id<=16)?{op:0x50+id}:{op:0,data:Uint8Array.from([id])};

// derive-define body: push82; inverseFp; *3; negate(=b2c1); DUP; *9; negate(=b2c0)
function deriveBody(){
  const ops=[
    {op:0,data:Uint8Array.from([0x52])},   // push 82
    idPushOp(6),{op:INVOKE},                // inverseFp -> i82
    {op:0x53},                              // push 3
    idPushOp(3),{op:INVOKE},                // mulFp -> 3*i82
    idPushOp(5),{op:INVOKE},                // negate -> b2c1
    {op:0x76},                              // DUP b2c1
    {op:0x59},                              // push 9
    idPushOp(3),{op:INVOKE},                // mulFp -> 9*b2c1
    idPushOp(5),{op:INVOKE},                // negate -> -9*b2c1 = b2c0
  ];
  return serialize(ops);
}

// replace consecutive [PUSH32 b2c1, PUSH32 b2c0] with [idPush(deriveId), INVOKE]
function rewriteOps(ops, deriveId){
  const out=[]; let hits=0;
  for(let i=0;i<ops.length;i++){
    const o=ops[i], n=ops[i+1];
    if(o.data&&o.data.length===32&&eq(o.data,b2c1LE)&&n&&n.data&&n.data.length===32&&eq(n.data,b2c0LE)){
      out.push(idPushOp(deriveId),{op:INVOKE}); i++; hits++; continue;
    }
    out.push(o);
  }
  return {out,hits};
}

export function twistDerive(bytes,{deriveId=15}={}){
  const d=dissect(bytes);
  if(d.order.includes(deriveId)) throw new Error(`deriveId ${deriveId} already defined`);
  let totalHits=0;
  const newBodies=new Map();
  for(const id of d.order){ const {out,hits}=rewriteOps(parse(d.bodies.get(id)),deriveId); newBodies.set(id,serialize(out)); totalHits+=hits; }
  const {out:mainOut,hits:mainHits}=rewriteOps(d.mainOps,deriveId); totalHits+=mainHits;
  // reassemble: keep p-pool define first (it is d.order[0]=13), then insert derive define, then rest.
  const recs=[];
  const body=deriveBody();
  // place derive define right after the first existing define (the p-pool)
  recs.push({id:d.order[0], body:newBodies.get(d.order[0])});
  recs.push({id:deriveId, body});
  for(let k=1;k<d.order.length;k++){ const id=d.order[k]; recs.push({id, body:newBodies.get(id)}); }
  const ops=[];
  for(const r of recs){ ops.push({op:0,data:r.body}); ops.push(idPushOp(r.id)); ops.push({op:DEFINE}); }
  for(const o of mainOut) ops.push(o);
  return {bytes:serialize(ops), deriveId, hits:totalHits, bodyLen:body.length};
}
