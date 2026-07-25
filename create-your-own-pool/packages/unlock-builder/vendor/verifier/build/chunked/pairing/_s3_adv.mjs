import { readFileSync } from 'node:fs';
import { compileString, utils } from 'cashc';
import { createTestAuthenticationProgramBch, encodeDataPush, bigIntToVmNumber, createVirtualMachineBch2026, numberToBinUint16LE } from '@bitauth/libauth';
import { bn254, Fp2, pairsFor, vec } from './_millermath.mjs';
const { asmToBytecode } = utils; const { Fp } = bn254.fields;
const vm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const lib = readFileSync('variants/V3_millerres_lib.cash','utf8');
function extract(name){ const s=lib.split('\n'),o=[];let p=false,d=0;for(const l of s){if(!p&&l.startsWith(`function ${name}(`))p=true;if(p){o.push(l);d+=(l.match(/\{/g)||[]).length-(l.match(/\}/g)||[]).length;if(d===0&&l.includes('}'))break;}}return o.join('\n');}
const need=['addFp','subFp','mulFp','fp2Add','fp2Sub','fp2Neg','fp2Mul','fp2Sqr','fp2Scale'];
const libtext=need.map(extract).join('\n')+'\n'+readFileSync('_afflib.cash','utf8');
const OP_PUSHDATA2=0x4d, r=(x)=>((x%P)+P)%P;
function run(nargs,body,args){
  const src=`pragma cashscript ^0.14.0;\ncontract T(){function f(${Array.from({length:nargs},(_,i)=>`int a${i}`).join(',')}, bytes unused pad){\n${body}\n}}\n${libtext}`;
  let raw; try{raw=asmToBytecode(compileString(src,{rescheduleStacks:true}).bytecode);}catch(e){return{err:String(e?.message??e).slice(0,80)};}
  const locking=Uint8Array.from(raw),pushInt=(n)=>encodeDataPush(bigIntToVmNumber(n));
  const pad=Uint8Array.from([OP_PUSHDATA2,...numberToBinUint16LE(9000),...new Uint8Array(9000)]);
  const argBytes=Uint8Array.from([...args].reverse().flatMap(c=>[...pushInt(c)]));
  const st=vm.evaluate(createTestAuthenticationProgramBch({lockingBytecode:locking,unlockingBytecode:Uint8Array.from([...pad,...argBytes]),valueSatoshis:1000n}));
  return{accepted:st.error===undefined&&st.stack.length===1&&st.stack[0].length===1&&st.stack[0][0]===1,err:st.error?String(st.error).slice(0,60):undefined};
}
const A=(x,y)=>Fp2.add(x,y),S=(x,y)=>Fp2.sub(x,y),M=(x,y)=>Fp2.mul(x,y),SQ=(x)=>Fp2.sqr(x),SC=(x,k)=>Fp2.fromBigTuple([Fp.mul(x.c0,k),Fp.mul(x.c1,k)]);
const Q=pairsFor(vec.publicInputs)[0].Q.toAffine();
const l3=SC(SQ(Q.x),3n),lam=M(l3,Fp2.inv(A(Q.y,Q.y)));
const consume=`require(within(mulFp(c0a,0)+mulFp(c0b,0)+mulFp(c1a,0)+mulFp(c1b,0)+mulFp(c2a,0)+mulFp(c2b,0)+mulFp(nxa,0)+mulFp(nxb,0)+mulFp(nya,0)+mulFp(nyb,0), 0, 2));`;
const bodyD=`(int c0a,int c0b,int c1a,int c1b,int c2a,int c2b,int nxa,int nxb,int nya,int nyb)=affDbl(a0,a1,a2,a3,a4,a5);\n ${consume}`;
// 1. honest lambda -> accept
console.log('DBL honest accepts:', run(6,bodyD,[Q.x.c0,Q.x.c1,Q.y.c0,Q.y.c1,lam.c0,lam.c1]).accepted);
// 2. wrong lambda (off by 1) -> reject
console.log('DBL wrong-lam rejects:', !run(6,bodyD,[Q.x.c0,Q.x.c1,Q.y.c0,Q.y.c1,r(lam.c0+1n),lam.c1]).accepted);
// 3. wrong lambda (arbitrary) -> reject
console.log('DBL bogus-lam rejects:', !run(6,bodyD,[Q.x.c0,Q.x.c1,Q.y.c0,Q.y.c1,12345n,67890n]).accepted);
// affAdd R=2Q, Q
const twoQ=pairsFor(vec.publicInputs)[0].Q.double().toAffine();
const t1=S(twoQ.x,Q.x),t0=S(twoQ.y,Q.y),lamA=M(t0,Fp2.inv(t1));
const bodyA=`(int c0a,int c0b,int c1a,int c1b,int c2a,int c2b,int nxa,int nxb,int nya,int nyb)=affAdd(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9);\n ${consume}`;
console.log('ADD honest accepts:', run(10,bodyA,[twoQ.x.c0,twoQ.x.c1,twoQ.y.c0,twoQ.y.c1,Q.x.c0,Q.x.c1,Q.y.c0,Q.y.c1,lamA.c0,lamA.c1]).accepted);
console.log('ADD wrong-lam rejects:', !run(10,bodyA,[twoQ.x.c0,twoQ.x.c1,twoQ.y.c0,twoQ.y.c1,Q.x.c0,Q.x.c1,Q.y.c0,Q.y.c1,r(lamA.c0+1n),lamA.c1]).accepted);
// 4. R == Q (exceptional R=+Q): Rx=Qx,Ry=Qy -> must reject (guard Rx!=Qx)
console.log('ADD R==Q rejects:', !run(10,bodyA,[Q.x.c0,Q.x.c1,Q.y.c0,Q.y.c1,Q.x.c0,Q.x.c1,Q.y.c0,Q.y.c1,12n,34n]).accepted);
// 5. R == -Q (R+Q=O, point at infinity): Rx=Qx, Ry=-Qy -> reject
const nQy=Fp2.neg(Q.y);
console.log('ADD R==-Q(=>O) rejects:', !run(10,bodyA,[Q.x.c0,Q.x.c1,nQy.c0,nQy.c1,Q.x.c0,Q.x.c1,Q.y.c0,Q.y.c1,12n,34n]).accepted);
// 6. doubling with y=0 (2-torsion-like): x s.t. on curve? just test y=0 -> slope check 0==3x^2 fails
console.log('DBL y=0 rejects (any lam):', !run(6,bodyD,[Q.x.c0,Q.x.c1,0n,0n,lam.c0,lam.c1]).accepted);
