import { readFileSync } from 'node:fs';
import { compileString, utils } from 'cashc';
import { createTestAuthenticationProgramBch, encodeDataPush, bigIntToVmNumber, createVirtualMachineBch2026, numberToBinUint16LE } from '@bitauth/libauth';
import { bn254, Fp2, pairsFor, vec, Fp2B } from './_millermath.mjs';
const { asmToBytecode } = utils;
const { Fp } = bn254.fields;
const vm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const lib = readFileSync('variants/V3_millerres_lib.cash','utf8');
function extract(name){ const src=lib.split('\n'); const out=[]; let p=false,depth=0;
  for(const ln of src){ if(!p && ln.startsWith(`function ${name}(`)) p=true;
    if(p){ out.push(ln); depth += (ln.match(/\{/g)||[]).length-(ln.match(/\}/g)||[]).length; if(depth===0&&ln.includes('}')) break; } } return out.join('\n'); }
const need=['addFp','subFp','mulFp','fp2Add','fp2Sub','fp2Neg','fp2Mul','fp2Sqr','fp2Scale'];
const libtext=need.map(extract).join('\n\n')+'\n'+readFileSync('_afflib.cash','utf8');
const OP_PUSHDATA2=0x4d;
function run(body, argvals){
  const nargs=argvals.length;
  const src=`pragma cashscript ^0.14.0;\ncontract T(){function f(${Array.from({length:nargs},(_,i)=>`int a${i}`).join(',')}, bytes unused pad){\n${body}\n}}\n${libtext}`;
  const raw=asmToBytecode(compileString(src,{rescheduleStacks:true}).bytecode);
  const locking=Uint8Array.from(raw);
  const pushInt=(n)=>encodeDataPush(bigIntToVmNumber(n));
  const padN=9000,pad=Uint8Array.from([OP_PUSHDATA2,...numberToBinUint16LE(padN),...new Uint8Array(padN)]);
  const argBytes=Uint8Array.from([...argvals].reverse().flatMap(c=>[...pushInt(c)]));
  const st=vm.evaluate(createTestAuthenticationProgramBch({lockingBytecode:locking,unlockingBytecode:Uint8Array.from([...pad,...argBytes]),valueSatoshis:1000n}));
  return {accepted: st.error===undefined && st.stack.length===1 && st.stack[0].length===1 && st.stack[0][0]===1, err:st.error?String(st.error).slice(0,120):undefined};
}
// JS affine (reference)
const A=(x,y)=>Fp2.add(x,y),S=(x,y)=>Fp2.sub(x,y),M=(x,y)=>Fp2.mul(x,y),SQ=(x)=>Fp2.sqr(x),N=(x)=>Fp2.neg(x),SC=(x,k)=>Fp2.fromBigTuple([Fp.mul(x.c0,k),Fp.mul(x.c1,k)]);
function jsDbl(x,y){ const l3=SC(SQ(x),3n),lam=M(l3,Fp2.inv(A(y,y)));
  const xn=S(SQ(lam),A(x,x)),yn=S(M(lam,S(x,xn)),y);
  const c0=S(SC(Fp2B,3n),SQ(y)),c1=l3,c2=N(A(y,y));
  return {lam,xn,yn,c0,c1,c2}; }
function jsAdd(Rx,Ry,Qx,Qy){ const t1=S(Rx,Qx),t0=S(Ry,Qy),lam=M(t0,Fp2.inv(t1));
  const xn=S(S(SQ(lam),Rx),Qx),yn=S(M(lam,S(Rx,xn)),Ry);
  const c0=S(M(t0,Qx),M(t1,Qy)),c1=N(t0),c2=t1;
  return {lam,xn,yn,c0,c1,c2}; }
const r=(x)=>((x%P)+P)%P;
// test on several points along the real trajectory
const Q=pairsFor(vec.publicInputs)[0].Q.toAffine();
let Rx=Q.x,Ry=Q.y, okD=true, okA=true;
for(let step=0; step<5; step++){
  const d=jsDbl(Rx,Ry);
  // cash affDbl: require outputs == expected (reduced)
  const body=`(int c0a,int c0b,int c1a,int c1b,int c2a,int c2b,int nxa,int nxb,int nya,int nyb)=affDbl(a0,a1,a2,a3,a4,a5);
    require(nxa==${r(d.xn.c0)}); require(nxb==${r(d.xn.c1)}); require(nya==${r(d.yn.c0)}); require(nyb==${r(d.yn.c1)});
    require(c1a % ${P}==${r(d.c1.c0)}); require(c1b % ${P}==${r(d.c1.c1)});
    require(mulFp(c2a, 7)==mulFp(${r(d.c2.c0)}, 7)); require(mulFp(c2b, 7)==mulFp(${r(d.c2.c1)}, 7));
    require(mulFp(c0a,7)==mulFp(${r(d.c0.c0)},7)); require(mulFp(c0b,7)==mulFp(${r(d.c0.c1)},7)); require(mulFp(c1b % ${P},1)==mulFp(${r(d.c1.c1)},1));`;
  const res=run(body,[Rx.c0,Rx.c1,Ry.c0,Ry.c1,d.lam.c0,d.lam.c1]);
  if(!res.accepted){okD=false; console.log('DBL step',step,'FAIL',res.err);}
  Rx=d.xn; Ry=d.yn;
  // then an add with Q
  const a=jsAdd(Rx,Ry,Q.x,Q.y);
  const bodyA=`(int c0a,int c0b,int c1a,int c1b,int c2a,int c2b,int nxa,int nxb,int nya,int nyb)=affAdd(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9);
    require(nxa==${r(a.xn.c0)}); require(nxb==${r(a.xn.c1)}); require(nya==${r(a.yn.c0)}); require(nyb==${r(a.yn.c1)});
    require(mulFp(c0a,7)==mulFp(${r(a.c0.c0)},7)); require(mulFp(c0b,7)==mulFp(${r(a.c0.c1)},7));
    require(mulFp(c1a,7)==mulFp(${r(a.c1.c0)},7)); require(mulFp(c1b,7)==mulFp(${r(a.c1.c1)},7));
    require(mulFp(c2a,7)==mulFp(${r(a.c2.c0)},7)); require(mulFp(c2b,7)==mulFp(${r(a.c2.c1)},7));`;
  const resA=run(bodyA,[Rx.c0,Rx.c1,Ry.c0,Ry.c1,Q.x.c0,Q.x.c1,Q.y.c0,Q.y.c1,a.lam.c0,a.lam.c1]);
  if(!resA.accepted){okA=false; console.log('ADD step',step,'FAIL',resA.err);}
  Rx=a.xn; Ry=a.yn;
}
console.log('affDbl VM==JS:', okD, '| affAdd VM==JS:', okA);
// negative test: wrong lambda must REJECT
const dbad=jsDbl(Q.x,Q.y);
const badBody=`(int c0a,int c0b,int c1a,int c1b,int c2a,int c2b,int nxa,int nxb,int nya,int nyb)=affDbl(a0,a1,a2,a3,a4,a5); require(nxa>=0);`;
const badRes=run(badBody,[Q.x.c0,Q.x.c1,Q.y.c0,Q.y.c1, (dbad.lam.c0+1n)%P, dbad.lam.c1]); // wrong lam
console.log('wrong-lambda REJECTS:', !badRes.accepted, '(', badRes.err?'errored':'accepted', ')');
