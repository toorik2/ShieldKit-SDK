import { readFileSync } from 'node:fs';
import { compileString, utils } from 'cashc';
import { createTestAuthenticationProgramBch, encodeDataPush, bigIntToVmNumber, createVirtualMachineBch2026, numberToBinUint16LE } from '@bitauth/libauth';
import { bn254, Fp2, pairsFor, vec, Fp2B } from './_millermath.mjs';
const { asmToBytecode } = utils;
const { Fp } = bn254.fields;
const vm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const lib = readFileSync('variants/V3_millerres_lib.cash','utf8');
function extract(name){ const s=lib.split('\n'),o=[];let p=false,d=0;for(const l of s){if(!p&&l.startsWith(`function ${name}(`))p=true;if(p){o.push(l);d+=(l.match(/\{/g)||[]).length-(l.match(/\}/g)||[]).length;if(d===0&&l.includes('}'))break;}}return o.join('\n');}
const need=['addFp','subFp','mulFp','fp2Add','fp2Sub','fp2Neg','fp2Mul','fp2Sqr','fp2Scale'];
const libtext=need.map(extract).join('\n')+'\n'+readFileSync('_afflib.cash','utf8');
const OP_PUSHDATA2=0x4d, r=(x)=>((x%P)+P)%P;
function run(nargs,body,args){
  const src=`pragma cashscript ^0.14.0;\ncontract T(){function f(${Array.from({length:nargs},(_,i)=>`int a${i}`).join(',')}, bytes unused pad){\n${body}\n}}\n${libtext}`;
  let raw; try{raw=asmToBytecode(compileString(src,{rescheduleStacks:true}).bytecode);}catch(e){return{err:String(e?.message??e).slice(0,90)};}
  const locking=Uint8Array.from(raw),pushInt=(n)=>encodeDataPush(bigIntToVmNumber(n));
  const pad=Uint8Array.from([OP_PUSHDATA2,...numberToBinUint16LE(9000),...new Uint8Array(9000)]);
  const argBytes=Uint8Array.from([...args].reverse().flatMap(c=>[...pushInt(c)]));
  const st=vm.evaluate(createTestAuthenticationProgramBch({lockingBytecode:locking,unlockingBytecode:Uint8Array.from([...pad,...argBytes]),valueSatoshis:1000n}));
  return{accepted:st.error===undefined&&st.stack.length===1&&st.stack[0].length===1&&st.stack[0][0]===1,err:st.error?String(st.error).slice(0,90):undefined};
}
const A=(x,y)=>Fp2.add(x,y),S=(x,y)=>Fp2.sub(x,y),M=(x,y)=>Fp2.mul(x,y),SQ=(x)=>Fp2.sqr(x),N=(x)=>Fp2.neg(x),SC=(x,k)=>Fp2.fromBigTuple([Fp.mul(x.c0,k),Fp.mul(x.c1,k)]);
const Q=pairsFor(vec.publicInputs)[0].Q.toAffine();
const l3=SC(SQ(Q.x),3n),lam=M(l3,Fp2.inv(A(Q.y,Q.y)));
const xn=S(SQ(lam),A(Q.x,Q.x)),yn=S(M(lam,S(Q.x,xn)),Q.y);
const c0=S(SC(Fp2B,3n),SQ(Q.y)),c1=l3,c2=N(A(Q.y,Q.y));
const P_=P.toString();
// test each output individually
const outs=['c0a','c0b','c1a','c1b','c2a','c2b','nxa','nxb','nya','nyb'];
for(const [k,E] of [['nxa',r(xn.c0)],['nxb',r(xn.c1)],['nya',r(yn.c0)],['nyb',r(yn.c1)],['c0a',r(c0.c0)],['c0b',r(c0.c1)],['c1a',r(c1.c0)],['c1b',r(c1.c1)],['c2a',r(c2.c0)],['c2b',r(c2.c1)]]){
  const zeros=outs.filter(v=>v!==k).map(v=>`mulFp(${v},0)`).join('+');
  const body=`(int c0a,int c0b,int c1a,int c1b,int c2a,int c2b,int nxa,int nxb,int nya,int nyb)=affDbl(a0,a1,a2,a3,a4,a5);\n require((${k}+${zeros})%${P_}==${E});`;
  const res=run(6,body,[Q.x.c0,Q.x.c1,Q.y.c0,Q.y.c1,lam.c0,lam.c1]);
  console.log('DBL',k, res.err?('ERR '+res.err):(res.accepted?'OK':'MISMATCH'));
}
// affAdd on R=2Q
const twoQ=pairsFor(vec.publicInputs)[0].Q.double().toAffine();
const t1=S(twoQ.x,Q.x),t0=S(twoQ.y,Q.y),lamA=M(t0,Fp2.inv(t1));
const xnA=S(S(SQ(lamA),twoQ.x),Q.x),ynA=S(M(lamA,S(twoQ.x,xnA)),twoQ.y);
const c0A=S(M(t0,Q.x),M(t1,Q.y)),c1A=N(t0),c2A=t1;
for(const [k,E] of [['nxa',r(xnA.c0)],['nxb',r(xnA.c1)],['nya',r(ynA.c0)],['nyb',r(ynA.c1)],['c0a',r(c0A.c0)],['c1a',r(c1A.c0)],['c2a',r(c2A.c0)]]){
  const zeros=outs.filter(v=>v!==k).map(v=>`mulFp(${v},0)`).join('+');
  const body=`(int c0a,int c0b,int c1a,int c1b,int c2a,int c2b,int nxa,int nxb,int nya,int nyb)=affAdd(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9);\n require((${k}+${zeros})%${P_}==${E});`;
  const res=run(10,body,[twoQ.x.c0,twoQ.x.c1,twoQ.y.c0,twoQ.y.c1,Q.x.c0,Q.x.c1,Q.y.c0,Q.y.c1,lamA.c0,lamA.c1]);
  console.log('ADD',k, res.err?('ERR '+res.err):(res.accepted?'OK':'MISMATCH'));
}
