import { compileString, utils } from 'cashc';
import { readFileSync } from 'node:fs';
import { measureRun } from '/home/toorik/Projects/LeanBCH/optimizer/cost.mjs';
import { bigIntToVmNumber, binToHex } from '@bitauth/libauth';
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const BIAS = 202944716560641436058426135953785114602563281282574308384079289034824091685549821404793712422553157789241740953812104359610149043919352694135649979132063988983n;
const mod=(x)=>((x%P)+P)%P;
const f2mW=(a0,a1,b0,b1)=>{const w0=a0*b0,w1=a1*b1;return[w0-w1,(a0+a1)*(b0+b1)-w0-w1];};
const f2xW=(a0,a1)=>[9n*a0-a1,9n*a1+a0];
const f6vW=(a)=>{const[n0,n1]=f2xW(a[4],a[5]);return[n0,n1,a[0],a[1],a[2],a[3]];};
function f6mW(a,b){const[t0a,t0b]=f2mW(a[0],a[1],b[0],b[1]);const[t1a,t1b]=f2mW(a[2],a[3],b[2],b[3]);const[t2a,t2b]=f2mW(a[4],a[5],b[4],b[5]);
const[p1a,p1b]=f2mW(a[2]+a[4],a[3]+a[5],b[2]+b[4],b[3]+b[5]);const[x1a,x1b]=f2xW(p1a-t1a-t2a,p1b-t1b-t2b);const c0a=t0a+x1a,c0b=t0b+x1b;
const[p2a,p2b]=f2mW(a[0]+a[2],a[1]+a[3],b[0]+b[2],b[1]+b[3]);const[x2a,x2b]=f2xW(t2a,t2b);const c1a=p2a-t0a-t1a+x2a,c1b=p2b-t0b-t1b+x2b;
const[p3a,p3b]=f2mW(a[0]+a[4],a[1]+a[5],b[0]+b[4],b[1]+b[5]);const c2a=p3a-t0a-t2a+t1a,c2b=p3b-t0b-t2b+t1b;return[c0a,c0b,c1a,c1b,c2a,c2b];}
function pre(A){const lo=A.slice(0,6),hi=A.slice(6);const t0=f6mW(lo,hi);const vc=f6vW(hi);const u=lo.map((x,i)=>x+vc[i]);const s=lo.map((x,i)=>x+hi[i]);const t1=f6mW(s,u);const vt=f6vW(t0);
return[...[0,1,2,3,4,5].map(i=>t1[i]-t0[i]-vt[i]),...[0,1,2,3,4,5].map(i=>t0[i]+t0[i])];}
const lazy=(A)=>pre(A).map(x=>(x+BIAS)%P);
const LIB=readFileSync('./variants/V2_miller_lib.cash','utf8');
const push=(n)=>{const d=bigIntToVmNumber(n);return Uint8Array.from([d.length,...d]);};
const unlockFor=(a)=>Uint8Array.from([...a].reverse().flatMap(x=>[...push(x)]));
// case: alt 21p/0 (near-max input) -> tests large-input regime through the independent VM
const L=Array.from({length:12},(_,i)=>i%2?21n*P-1n:0n);
const mine=lazy(L);
const checks=mine.map((e,i)=>`b${i} == ${e}`).join(' &&\n      ');
const src=`pragma cashscript ^0.14.0;\n${LIB}\ncontract B(){function run(int a0,int a1,int a2,int a3,int a4,int a5,int a6,int a7,int a8,int a9,int a10,int a11){int b0,int b1,int b2,int b3,int b4,int b5,int b6,int b7,int b8,int b9,int b10,int b11=fp12Sqr(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11);require(\n      ${checks});}}`;
const redeem=utils.asmToBytecode(compileString(src,{rescheduleStacks:true}).bytecode);
const unlock=unlockFor(L);
const r=measureRun(redeem,unlock);
// full program bytecode = unlock ++ redeem (bare-contract evaluation, mirrors libauth measureRun)
const prog=Uint8Array.from([...unlock,...redeem]);
console.log(JSON.stringify({
  case:'alt 21p/0', libauthAccepted:r.ok, libauthOpCost:r.opCost, libauthInstr:r.instr,
  redeemBytes:redeem.length, unlockBytes:unlock.length,
  progHex: binToHex(prog),
}));
