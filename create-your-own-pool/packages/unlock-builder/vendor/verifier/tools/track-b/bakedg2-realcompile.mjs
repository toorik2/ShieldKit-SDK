import { repoPath as vcRepoPath } from '#repo-paths';
// Compile the FULL split-blob proto (hash-bind + split + line() references) for real chunks
// and measure the EXACT locking byte delta vs base (the line() coeff literals fully removed).
import {
  Fp2, ATE_NAF, pairsFor, vec, pointDouble, pointAdd, psi, postPrecompute, lineFn,
  chunkLockingBytes,
} from '../../build/chunked/pairing/_millermath.mjs';
import { readFileSync } from 'node:fs';
import crypto from 'node:crypto';
const sha256d=(b)=>crypto.createHash('sha256').update(crypto.createHash('sha256').update(b).digest()).digest();
const GEN=vcRepoPath('build/chunked/pairing/generated');
const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n;const mod=(x)=>((x%P)+P)%P;
const { bn254 }=await import(vcRepoPath('node_modules/@noble/curves/esm/bn254.js'));const Fp12=bn254.fields.Fp12;
function batchOps3(pairs){const pds=pairs.map(p=>{const Qa=p.Q.toAffine(),Pa=p.P.toAffine();return{Qx:Qa.x,Qy:Qa.y,negQy:Fp2.neg(Qa.y),Px:Pa.x,Py:Pa.y};});
  const ops=[];for(let k=0;k<ATE_NAF.length;k++){ops.push({t:'sqr'});for(let j=0;j<pairs.length;j++){ops.push({t:'dl',j});if(ATE_NAF[k])ops.push({t:'al',j,neg:ATE_NAF[k]===-1});}}for(let j=0;j<pairs.length;j++)ops.push({t:'pp',j});
  const states=[];let f=Fp12.ONE;const Rs=pds.map(pd=>({x:pd.Qx,y:pd.Qy,z:Fp2.ONE}));
  for(const op of ops){states.push({f,Rs:Rs.slice()});if(op.t==='sqr')f=Fp12.sqr(f);else if(op.t==='dl'){const d=pointDouble(Rs[op.j].x,Rs[op.j].y,Rs[op.j].z);Rs[op.j]=d.R;f=lineFn(f,d.coeffs[0],d.coeffs[1],d.coeffs[2],pds[op.j].Px,pds[op.j].Py);}else if(op.t==='al'){const pd=pds[op.j];const a=pointAdd(Rs[op.j].x,Rs[op.j].y,Rs[op.j].z,pd.Qx,op.neg?pd.negQy:pd.Qy);Rs[op.j]=a.R;f=lineFn(f,a.coeffs[0],a.coeffs[1],a.coeffs[2],pds[op.j].Px,pds[op.j].Py);}else{const pd=pds[op.j];const res=postPrecompute(f,Rs[op.j],pd.Qx,pd.Qy,pd.Px,pd.Py);f=res.f;Rs[op.j]=res.R;}}
  states.push({f,Rs:Rs.slice()});return {ops,states};}
const PAIRS4=pairsFor(vec.publicInputs);const pairs3=[PAIRS4[0],PAIRS4[2],PAIRS4[3]];const BAKED3=[false,true,true];
const {ops,states}=batchOps3(pairs3);
const pds3=pairs3.map(p=>{const Qa=p.Q.toAffine(),Pa=p.P.toAffine();return{Qx:Qa.x,Qy:Qa.y,negQy:Fp2.neg(Qa.y),Px:Pa.x,Py:Pa.y};});
const opCoeffs=ops.map(()=>null);
for(let i=0;i<ops.length;i++){const op=ops[i];if(op.t==='sqr'||!BAKED3[op.j])continue;const R=states[i].Rs[op.j],pd=pds3[op.j];
  if(op.t==='dl')opCoeffs[i]=[pointDouble(R.x,R.y,R.z).coeffs];else if(op.t==='al')opCoeffs[i]=[pointAdd(R.x,R.y,R.z,pd.Qx,op.neg?pd.negQy:pd.Qy).coeffs];
  else{const q1=psi(pd.Qx,pd.Qy);const a1=pointAdd(R.x,R.y,R.z,q1[0],q1[1]);const q2=psi(q1[0],q1[1]);const a2=pointAdd(a1.R.x,a1.R.y,a1.R.z,q2[0],Fp2.neg(q2[1]));opCoeffs[i]=[a1.coeffs,a2.coeffs];}}
const man=JSON.parse(readFileSync(`${GEN}/manifest_miller_baked.json`,'utf8'));
const setLimbs=(cf)=>[cf[0].c0,cf[0].c1,cf[1].c0,cf[1].c1,cf[2].c0,cf[2].c1].map(mod);
const toLE32=(x)=>{const b=Buffer.alloc(32);let n=mod(x);for(let i=0;i<32;i++){b[i]=Number(n&0xffn);n>>=8n;}return b;};
let T={base:0,proto:0,np:0};
console.log('chunk  np  lockBase lockProto  Δ      Δ/coeff');
for(const c of man.chunks){
  const ci=c.idx,lo=c.opLo,hi=c.opHi;
  const coeffSets=[];for(let i=lo;i<hi;i++){const op=ops[i];if(op.t==='sqr'||!BAKED3[op.j])continue;for(const cf of opCoeffs[i])coeffSets.push(setLimbs(cf));}
  const allCoeffs=coeffSets.flat();const nC=allCoeffs.length;
  const blob=Buffer.concat(allCoeffs.map(toLE32));const H=sha256d(blob).toString('hex');
  const base=readFileSync(`${GEN}/miller_baked_${String(ci).padStart(2,'0')}.cash`,'utf8');
  let proto=base.replace(/function spend\(([^)]*)\)/s,(m,a)=>`function spend(${a}, bytes blob)`);
  let split=[`        require(hash256(blob) == 0x${H});`];const qn=[];let pv='blob';
  for(let k=0;k<nC;k++){if(k<nC-1){split.push(`        bytes bc${k}, bytes br${k} = ${pv}.split(32);`);split.push(`        int q${k} = int(bc${k});`);pv='br'+k;}else split.push(`        int q${k} = int(${pv});`);qn.push(`q${k}`);}
  proto=proto.replace(/(int P = 21888242871839275222246405745257275088696311157297823662689037894645226208583;)/,`$1\n${split.join('\n')}`);
  let ck=0;proto=proto.replace(/line\(([^)]*)\)/g,(m,inner)=>{const parts=inner.split(',').map(s=>s.trim());if(parts.length!==20)return m;const isNum=s=>/^\d+$/.test(s);if([12,13,14,15,16,17].every(k=>isNum(parts[k]))){for(let k=0;k<6;k++)parts[12+k]=qn[ck++];return `line(${parts.join(',')})`;}return m;});
  let lb,lp;try{lb=chunkLockingBytes(base).length;lp=chunkLockingBytes(proto).length;}catch(e){console.log(`${ci} ERR ${String(e.message).slice(0,60)}`);continue;}
  T.base+=lb;T.proto+=lp;T.np+=nC;
  console.log(`${String(ci).padStart(2)}    ${String(nC).padStart(2)}  ${String(lb).padStart(7)} ${String(lp).padStart(8)}  ${String(lp-lb).padStart(5)}  ${((lp-lb)/nC).toFixed(2)}`);
}
console.log(`\nΣ lockBase=${T.base} lockProto=${T.proto} Δ=${T.proto-T.base} (saving ${T.base-T.proto} B) over ${T.np} coeffs`);
console.log(`real measured saving/coeff = ${((T.base-T.proto)/T.np).toFixed(2)} B`);
