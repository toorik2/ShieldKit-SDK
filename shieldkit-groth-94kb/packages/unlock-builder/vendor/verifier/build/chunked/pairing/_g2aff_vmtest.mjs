import { compileFile, utils } from 'cashc';
import { writeFileSync } from 'node:fs';
import { createTestAuthenticationProgramBch, encodeDataPush, bigIntToVmNumber, createVirtualMachineBch2026, numberToBinUint16LE } from '@bitauth/libauth';
import { bn254, Fp2, proof } from './_millermath.mjs';
import { affDoubleJS, affAddJS } from './_affmath.mjs';
const { asmToBytecode } = utils; const { Fp } = bn254.fields;
const vm=createVirtualMachineBch2026(false);
const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n, r=(x)=>((x%P)+P)%P;
const OP_PUSHDATA2=0x4d;
function run(nargs,body,args){
  const src=`pragma cashscript ^0.14.0;\nimport "../../../singleton/bn254/lib/Miller_aff.cash";\ncontract T(){function f(${Array.from({length:nargs},(_,i)=>`int a${i}`).join(',')}, bytes unused pad){\n${body}\n}}\n`;
  writeFileSync('generated/_g2vt.cash',src);
  let raw; try{raw=asmToBytecode(compileFile('generated/_g2vt.cash').bytecode);}catch(e){return{err:String(e?.message??e).slice(0,90)};}
  const locking=Uint8Array.from(raw),pushInt=(n)=>encodeDataPush(bigIntToVmNumber(n));
  const pad=Uint8Array.from([OP_PUSHDATA2,...numberToBinUint16LE(9000),...new Uint8Array(9000)]);
  const st=vm.evaluate(createTestAuthenticationProgramBch({lockingBytecode:locking,unlockingBytecode:Uint8Array.from([...pad,...Uint8Array.from([...args].reverse().flatMap(c=>[...pushInt(c)]))]),valueSatoshis:1000n}));
  return{accepted:st.error===undefined&&st.stack.length===1&&st.stack[0].length===1&&st.stack[0][0]===1,err:st.error?String(st.error).slice(0,90):undefined};
}
const B=proof.b.toAffine();
const d=affDoubleJS(B.x,B.y);
const bodyD=`(int nxa,int nxb,int nya,int nyb)=g2AffDbl(a0,a1,a2,a3,a4,a5);\n require(nxa==${r(d.R.x.c0)} && nxb==${r(d.R.x.c1)} && nya==${r(d.R.y.c0)} && nyb==${r(d.R.y.c1)});`;
console.log('g2AffDbl VM==noble:', run(6,bodyD,[B.x.c0,B.x.c1,B.y.c0,B.y.c1,d.lam.c0,d.lam.c1]).accepted);
const twoB=proof.b.double().toAffine();
const a=affAddJS(twoB.x,twoB.y,B.x,B.y);
const bodyA=`(int nxa,int nxb,int nya,int nyb)=g2AffAdd(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9);\n require(nxa==${r(a.R.x.c0)} && nxb==${r(a.R.x.c1)} && nya==${r(a.R.y.c0)} && nyb==${r(a.R.y.c1)});`;
console.log('g2AffAdd VM==noble:', run(10,bodyA,[twoB.x.c0,twoB.x.c1,twoB.y.c0,twoB.y.c1,B.x.c0,B.x.c1,B.y.c0,B.y.c1,a.lam.c0,a.lam.c1]).accepted);
console.log('g2AffDbl wrong-lam rejects:', !run(6,bodyD,[B.x.c0,B.x.c1,B.y.c0,B.y.c1,r(d.lam.c0+1n),d.lam.c1]).accepted);
console.log('g2AffAdd R==Q rejects:', !run(10,bodyA,[B.x.c0,B.x.c1,B.y.c0,B.y.c1,B.x.c0,B.x.c1,B.y.c0,B.y.c1,5n,6n]).accepted);
