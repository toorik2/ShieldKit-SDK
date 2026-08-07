// Run the ACTUAL compiled V2 .cash in the loose VM over many inputs (random + corners),
// checking every output limb === noble Fp12.sqr mod p. Catches any transcription mismatch
// between the JS bound-mirror and the real .cash, and confirms in-VM soundness.
import { compileFile, utils } from 'cashc';
import { bigIntToVmNumber } from '@bitauth/libauth';
import { writeFileSync } from 'node:fs';
import { measureRun } from '/home/toorik/Projects/LeanBCH/optimizer/cost.mjs';
import { Fp12, Fp } from './_millermath.mjs';
const P = Fp.ORDER;
const importPath = '../variants/V2_delayed.cash';
const mk2=(a,b)=>({c0:a,c1:b});
const toF12=(L)=>({c0:{c0:mk2(L[0],L[1]),c1:mk2(L[2],L[3]),c2:mk2(L[4],L[5])},c1:{c0:mk2(L[6],L[7]),c1:mk2(L[8],L[9]),c2:mk2(L[10],L[11])}});
const flat=(f)=>[f.c0.c0.c0,f.c0.c0.c1,f.c0.c1.c0,f.c0.c1.c1,f.c0.c2.c0,f.c0.c2.c1,f.c1.c0.c0,f.c1.c0.c1,f.c1.c1.c0,f.c1.c1.c1,f.c1.c2.c0,f.c1.c2.c1];
const nobleSqr=(L)=>flat(Fp12.sqr(toF12(L.map(x=>((x%P)+P)%P))));
const push=(n)=>{const d=bigIntToVmNumber(n);
  if(d.length===0) return Uint8Array.from([0x00]);                       // OP_0
  if(d.length===1&&d[0]>=1&&d[0]<=16) return Uint8Array.from([0x50+d[0]]); // OP_1..OP_16
  if(d.length===1&&d[0]===0x81) return Uint8Array.from([0x4f]);          // OP_1NEGATE
  return Uint8Array.from([d.length,...d]);};
const unlockFor=(a)=>Uint8Array.from([...a].reverse().flatMap(x=>[...push(x)]));
const RESCHED={rescheduleStacks:true};
function src(L){
  const exp=nobleSqr(L);
  const checks=exp.map((e,i)=>`(b${i} % ${P}) == ${e}`).join(' && ');
  return `pragma cashscript ^0.14.0;\nimport "${importPath}";\ncontract Bench(){function run(int a0,int a1,int a2,int a3,int a4,int a5,int a6,int a7,int a8,int a9,int a10,int a11){int b0,int b1,int b2,int b3,int b4,int b5,int b6,int b7,int b8,int b9,int b10,int b11=fp12Sqr(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11);require(${checks});}}`;
}
let s=99194853094755497n;
const rnd=()=>{s^=s<<13n;s&=(1n<<64n)-1n;s^=s>>7n;s^=s<<17n;s&=(1n<<64n)-1n;return s;};
const rndFull=()=>{let x=0n;for(let k=0;k<4;k++)x=(x<<64n)|rnd();return x%P;};
const corners=[0n,1n,2n,P-1n,P-2n];
const cases=[];
for(let t=0;t<20;t++) cases.push(Array.from({length:12},()=>rndFull()));
for(let t=0;t<15;t++) cases.push(Array.from({length:12},()=>corners[Number(rnd()%5n)]));
cases.push(Array.from({length:12},()=>P-1n));
cases.push(Array.from({length:12},()=>0n));
cases.push(Array.from({length:12},(_,i)=>i%2?P-1n:0n));
let ok=0,bad=0;
for(const L of cases){
  writeFileSync('generated/_vmck.cash',src(L));
  const bc=utils.asmToBytecode(compileFile('generated/_vmck.cash',RESCHED).bytecode);
  const r=measureRun(bc,unlockFor(L));
  if(r.ok) ok++; else { bad++; console.log('  REJECT for input', L.slice(0,3).map(String).join(','),'...', r.error||''); }
}
console.log(`VM-level correctness: ${ok}/${cases.length} accepted, ${bad} rejected`);
console.log(bad===0?'ALL VM CASES SOUND (real compiled .cash output === noble mod p)':'UNSOUND -- INVESTIGATE');
