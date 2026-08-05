import { writeFileSync } from 'node:fs';
import { bn254, proof, decl, covIn, covOut, commitBin, CATEGORY, TARGET_UNLOCK, compileFileBytecodeRaw } from './_millermath.mjs';
import { affDoubleJS, affAddJS } from './_affmath.mjs';
import { createVirtualMachineBch2026, encodeDataPush, bigIntToVmNumber, numberToBinUint16LE } from '@bitauth/libauth';
const { Fp, Fp2 } = bn254.fields;
const vm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n, red=(x)=>((x%P)+P)%P;
const BN_X=4965661367192848881n, NBITS=63, bit=(k)=>(BN_X>>BigInt(NBITS-1-k))&1n;
const B2=[19485874751759354771024239261021720505790618469301721065564631296452457478373n,266929791119991161246907387137283842545076965332900288569378510910307636690n];
const b2f=Fp2.fromBigTuple(B2);
const conj=(x)=>Fp2.fromBigTuple([x.c0,(Fp.ORDER-x.c1)%Fp.ORDER]);
const PX=Fp2.pow(Fp2.NONRESIDUE,(Fp.ORDER-1n)/3n), PY=Fp2.pow(Fp2.NONRESIDUE,(Fp.ORDER-1n)/2n);
const psi=(x,y)=>[Fp2.mul(conj(x),PX),Fp2.mul(conj(y),PY)];
const eq=(a,b)=>a.c0===b.c0&&a.c1===b.c1;
// build ladder trace for given affine B
function trace(B){
  const Rafter=new Array(NBITS),lamDbl={},lamAdd={};
  let R={x:B.x,y:B.y};Rafter[0]={x:B.x,y:B.y};
  for(let k=1;k<NBITS;k++){const d=affDoubleJS(R.x,R.y);lamDbl[k]=d.lam;R=d.R;if(bit(k)){const a=affAddJS(R.x,R.y,B.x,B.y);lamAdd[k]=a.lam;R=a.R;}Rafter[k]={x:R.x,y:R.y};}
  const a0=Rafter[NBITS-1],b=psi(a0.x,a0.y),c=psi(b[0],b[1]),d=psi(c[0],c[1]);
  const l1=affAddJS(a0.x,a0.y,B.x,B.y),l2=affAddJS(l1.R.x,l1.R.y,b[0],b[1]),l3=affAddJS(l2.R.x,l2.R.y,c[0],c[1]),rr=affDoubleJS(d[0],d[1]);
  return {Rafter,lamDbl,lamAdd,endoLams:[l1.lam,l2.lam,l3.lam,rr.lam],endoOK:eq(l3.R.x,rr.R.x)&&eq(l3.R.y,rr.R.y)};
}
// emit the FINAL g2 chunk [lo,63) (endo) exactly as unified_affine does
const G2LIBA='../../../singleton/bn254/lib/Miller_aff.cash';
const RN4=['RXa','RXb','RYa','RYb'],BNM=['Bxa','Bxb','Bya','Byb'],PASS=['nAx','nAy','Cx','Cy','input0','input1'];
const G2STA=[...RN4,...BNM,...PASS],SEAM1=['nAx','nAy',...BNM,'Cx','Cy','input0','input1'];
function lastChunk(lo){
  const hi=63; const lamP=[];
  for(let k=Math.max(lo,1);k<hi;k++){lamP.push(`ld${k}a`,`ld${k}b`);if(bit(k))lamP.push(`la${k}a`,`la${k}b`);}
  lamP.push('le1a','le1b','le2a','le2b','le3a','le3b','lera','lerb');
  const L=[];L.push('pragma cashscript ^0.14.0;');L.push(`import "${G2LIBA}";`);L.push('contract G2CheckAff() {');
  L.push(`    function spend(${decl([...G2STA,...lamP])}, bytes unused zeroPadding) {`);
  L.push(covIn(G2STA));
  let r=RN4.slice(),uid=0;const fresh=()=>Array.from({length:4},()=>`v${uid++}`);
  for(let k=Math.max(lo,1);k<hi;k++){const d=fresh();L.push(`        (${decl(d)}) = g2AffDbl(${r.join(',')}, ld${k}a, ld${k}b);`);r=d;if(bit(k)){const a=fresh();L.push(`        (${decl(a)}) = g2AffAdd(${r.join(',')}, ${BNM.join(',')}, la${k}a, la${k}b);`);r=a;}}
  const [Rxa,Rxb,Rya,Ryb]=r;
  L.push(`        (int bxa,int bxb,int bya,int byb) = psi(${Rxa}, ${Rxb}, ${Rya}, ${Ryb});`);
  L.push('        (int cxa,int cxb,int cya,int cyb) = psi(bxa, bxb, bya, byb);');
  L.push('        (int dxa,int dxb,int dya,int dyb) = psi(cxa, cxb, cya, cyb);');
  L.push(`        (int l1xa,int l1xb,int l1ya,int l1yb) = g2AffAdd(${Rxa}, ${Rxb}, ${Rya}, ${Ryb}, Bxa, Bxb, Bya, Byb, le1a, le1b);`);
  L.push('        (int l2xa,int l2xb,int l2ya,int l2yb) = g2AffAdd(l1xa, l1xb, l1ya, l1yb, bxa, bxb, bya, byb, le2a, le2b);');
  L.push('        (int l3xa,int l3xb,int l3ya,int l3yb) = g2AffAdd(l2xa, l2xb, l2ya, l2yb, cxa, cxb, cya, cyb, le3a, le3b);');
  L.push('        (int rxa,int rxb,int rya,int ryb) = g2AffDbl(dxa, dxb, dya, dyb, lera, lerb);');
  L.push('        require(l3xa == rxa); require(l3xb == rxb); require(l3ya == rya); require(l3yb == ryb);');
  L.push(covOut(SEAM1,null));L.push('    }');L.push('}');return L.join('\n')+'\n';
}
const r4=(R)=>[red(R.x.c0),red(R.x.c1),red(R.y.c0),red(R.y.c1)];
const nAx=red(proof.a.negate().toAffine().x),nAy=red(proof.a.negate().toAffine().y),Cx=red(proof.c.toAffine().x),Cy=red(proof.c.toAffine().y);
const in0=5n,in1=7n;
function evalLast(B,forgeLam){
  const lo=50,hi=63; const tr=trace(B);
  const src=lastChunk(lo); writeFileSync('generated/_g2forge.cash',src);
  let raw; try{raw=compileFileBytecodeRaw('generated/_g2forge.cash');}catch(e){return{err:String(e?.message??e).slice(0,80)};}
  const locking=Uint8Array.from([...raw]);
  const stateIn=[...r4(tr.Rafter[lo-1]),red(B.x.c0),red(B.x.c1),red(B.y.c0),red(B.y.c1),nAx,nAy,Cx,Cy,in0,in1];
  const seamOut=[nAx,nAy,red(B.x.c0),red(B.x.c1),red(B.y.c0),red(B.y.c1),Cx,Cy,in0,in1];
  let lams=[]; for(let k=Math.max(lo,1);k<hi;k++){const d=tr.lamDbl[k];lams.push(red(d.c0),red(d.c1));if(bit(k)){const a=tr.lamAdd[k];lams.push(red(a.c0),red(a.c1));}}
  for(const lm of tr.endoLams) lams.push(red(lm.c0),red(lm.c1));
  if(forgeLam!==undefined){const idx=forgeLam<0?lams.length+forgeLam:forgeLam; lams[idx]=red(lams[idx]+1n);}
  const pushed=[...stateIn,...lams];
  const pushInt=(n)=>encodeDataPush(bigIntToVmNumber(BigInt(n)));
  const padPush=(al,t)=>{const N=t-al-3;return Uint8Array.from([0x4d,...numberToBinUint16LE(N),...new Uint8Array(N)]);};
  const argBytes=Uint8Array.from([...pushed].reverse().flatMap(c=>[...pushInt(c)]));
  const unlocking=Uint8Array.from([...padPush(argBytes.length,TARGET_UNLOCK),...argBytes]);
  const tok=(c)=>({amount:0n,category:CATEGORY,nft:{capability:'mutable',commitment:c}});
  const prog={inputIndex:0,sourceOutputs:[{lockingBytecode:locking,valueSatoshis:1000n,token:tok(commitBin(stateIn.map(BigInt)))}],
    transaction:{version:2,inputs:[{outpointTransactionHash:new Uint8Array(32),outpointIndex:0,sequenceNumber:0,unlockingBytecode:unlocking}],outputs:[{lockingBytecode:locking,valueSatoshis:1000n,token:tok(commitBin(seamOut.map(BigInt)))}],locktime:0}};
  const st=vm.evaluate(prog);const top=st.stack[st.stack.length-1];
  return {accepted:st.error===undefined&&st.stack.length===1&&top!==undefined&&top.length===1&&top[0]===1, endoOK:tr.endoOK};
}
// honest subgroup B
const Bg=proof.b.toAffine();
console.log('honest g2 final chunk ACCEPTS:', evalLast(Bg).accepted);
// forge a ladder lambda -> reject
console.log('forged ladder-lambda REJECTS:', !evalLast(Bg,0).accepted);
// forge an endo lambda -> reject
console.log('forged endo-lambda REJECTS:', !evalLast(Bg,-1).accepted);
// non-subgroup on-curve B -> reject
function onCurve(seed){for(let s=seed;;s++){const x=Fp2.fromBigTuple([BigInt(s),3n]);const rhs=Fp2.add(Fp2.mul(Fp2.sqr(x),x),b2f);try{const y=Fp2.sqrt(rhs);if(eq(Fp2.sqr(y),rhs))return{x,y};}catch(e){}}}
const Bns=onCurve(7);
const r=evalLast(Bns);
console.log('non-subgroup B: endoOK(JS)=',r.endoOK,' chunk ACCEPTS=',r.accepted,'=> REJECTS:', !r.accepted);
