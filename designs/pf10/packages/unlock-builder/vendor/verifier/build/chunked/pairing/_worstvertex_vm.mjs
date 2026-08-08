// Find the EXACT worst-negativity vertex (2^18 enumeration, o4<=6p) and run THAT adversarial input
// through the real compiled lazy mul034 in the VM with the proper stack-accept gate; compare to noble.
import { compileFile, utils } from 'cashc';
import { bigIntToVmNumber, createTestAuthenticationProgramBch } from '@bitauth/libauth';
import { looseVm } from '/home/toorik/Projects/LeanBCH/optimizer/core/program.mjs';
import { Fp2, Fp6, Fp12, Fp } from './_millermath.mjs';
import { writeFileSync } from 'node:fs';
const P=Fp.ORDER, Pm=P-1n;
const BIAS=473346033904423368332684188674078595909661288732727612567210428627021252562119744690866504404556704362571480480121380658603450849396234800254307144706265583n;
const f2mW=(a0,a1,b0,b1)=>{const w0=a0*b0,w1=a1*b1;return[w0-w1,(a0+a1)*(b0+b1)-w0-w1];};
const f2xW=(a0,a1)=>[9n*a0-a1,9n*a1+a0];
const f6vW=(a)=>{const[n0a,n0b]=f2xW(a[4],a[5]);return[n0a,n0b,a[0],a[1],a[2],a[3]];};
function f6m01(c,b0a,b0b,b1a,b1b){const[t0a,t0b]=f2mW(c[0],c[1],b0a,b0b),[t1a,t1b]=f2mW(c[2],c[3],b1a,b1b);
 const[m12a,m12b]=f2mW(c[2]+c[4],c[3]+c[5],b1a,b1b),[xu0a,xu0b]=f2xW(m12a-t1a,m12b-t1b);const r0a=xu0a+t0a,r0b=xu0b+t0b;
 const[m1a,m1b]=f2mW(b0a+b1a,b0b+b1b,c[0]+c[2],c[1]+c[3]);const r1a=m1a-t0a-t1a,r1b=m1b-t0b-t1b;
 const[m2a,m2b]=f2mW(c[0]+c[4],c[1]+c[5],b0a,b0b);const r2a=m2a-t0a+t1a,r2b=m2b-t0b+t1b;return[r0a,r0b,r1a,r1b,r2a,r2b];}
function preM034(F,o0a,o0b,o3a,o3b,o4a,o4b){const A0=f2mW(F[0],F[1],o0a,o0b),A2=f2mW(F[2],F[3],o0a,o0b),A4=f2mW(F[4],F[5],o0a,o0b);
 const Aa=[A0[0],A0[1],A2[0],A2[1],A4[0],A4[1]];const B=f6m01(F.slice(6,12),o3a,o3b,o4a,o4b);
 const S=[0,1,2,3,4,5].map(i=>F[i]+F[6+i]);const G=f6m01(S,o0a+o3a,o0b+o3b,o4a,o4b);const VB=f6vW(B);
 const lo=[0,1,2,3,4,5].map(i=>VB[i]+Aa[i]),hi=[0,1,2,3,4,5].map(i=>G[i]-Aa[i]-B[i]);return[...lo,...hi];}
// exhaustive worst vertex for o4<=6p
const o4max=6n*P; const oVals=[[0n,Pm],[0n,Pm],[0n,Pm],[0n,Pm],[0n,o4max],[0n,o4max]];
let worst=null, worstNeg=0n; const F=new Array(12);
for(let om=0;om<64;om++){const o=[0,1,2,3,4,5].map(b=>oVals[b][(om>>b)&1]);
  for(let fm=0;fm<4096;fm++){for(let b=0;b<12;b++)F[b]=(fm>>b)&1?Pm:0n;
    const pre=preM034(F,o[0],o[1],o[2],o[3],o[4],o[5]);
    for(let i=0;i<12;i++){const neg=pre[i]<0n?-pre[i]:0n; if(neg>worstNeg){worstNeg=neg; worst={F:[...F],o:[...o],limb:i};}}}}
console.log('worst |neg| =', (worstNeg/(P*P)), 'p^2   at limb', worst.limb, '  minDividend =', ((BIAS-worstNeg)/(P*P)), 'p^2', (BIAS-worstNeg>=0n?'(>=0 SOUND)':'(<0 UNSOUND)'));
// noble ref
const mk2=(a,b)=>({c0:((a%P)+P)%P,c1:((b%P)+P)%P});
const toF12=(L)=>({c0:{c0:mk2(L[0],L[1]),c1:mk2(L[2],L[3]),c2:mk2(L[4],L[5])},c1:{c0:mk2(L[6],L[7]),c1:mk2(L[8],L[9]),c2:mk2(L[10],L[11])}});
const flat=(f)=>[f.c0.c0.c0,f.c0.c0.c1,f.c0.c1.c0,f.c0.c1.c1,f.c0.c2.c0,f.c0.c2.c1,f.c1.c0.c0,f.c1.c0.c1,f.c1.c1.c0,f.c1.c1.c1,f.c1.c2.c0,f.c1.c2.c1];
function nobleMul034(Fl,o){const f=toF12(Fl),o0=mk2(o[0],o[1]),o3=mk2(o[2],o[3]),o4=mk2(o[4],o[5]);
 const A=Fp6.create({c0:Fp2.mul(f.c0.c0,o0),c1:Fp2.mul(f.c0.c1,o0),c2:Fp2.mul(f.c0.c2,o0)});
 const B=Fp6.mul01(f.c1,o3,o4);const E=Fp6.mul01(Fp6.add(f.c0,f.c1),Fp2.add(o0,o3),o4);
 return flat(Fp12.create({c0:Fp6.add(Fp6.mulByNonresidue(B),A),c1:Fp6.sub(E,Fp6.add(A,B))}));}
const push=(n)=>{const d=bigIntToVmNumber(n);if(d.length===0)return Uint8Array.from([0]);if(d.length===1&&d[0]>=1&&d[0]<=16)return Uint8Array.from([0x50+d[0]]);if(d.length===1&&d[0]===0x81)return Uint8Array.from([0x4f]);return Uint8Array.from([d.length,...d]);};
const unlockFor=(a)=>Uint8Array.from([...a].reverse().flatMap(x=>[...push(x)]));
const decl='int f0,int f1,int f2,int f3,int f4,int f5,int f6,int f7,int f8,int f9,int f10,int f11,int o0a,int o0b,int o3a,int o3b,int o4a,int o4b';
const args='f0,f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11,o0a,o0b,o3a,o3b,o4a,o4b';
const OUT=Array.from({length:12},(_,i)=>'int c'+i).join(',');
const e=nobleMul034(worst.F,worst.o);
const chk=e.map((v,i)=>'c'+i+' == '+v).join(' && ');
writeFileSync('generated/_wv.cash','pragma cashscript ^0.14.0;\nimport "../variants/V3_mul_delayed.cash";\ncontract C(){function r('+decl+'){'+OUT+' = mul034('+args+');require('+chk+');}}');
const bc=utils.asmToBytecode(compileFile('generated/_wv.cash',{rescheduleStacks:true}).bytecode);
const st=looseVm.evaluate(createTestAuthenticationProgramBch({lockingBytecode:bc,unlockingBytecode:unlockFor([...worst.F,...worst.o]),valueSatoshis:1000n}));
const top=st.stack[st.stack.length-1];
const accept=st.error===undefined&&st.stack.length===1&&top!==undefined&&top.length===1&&top[0]===1;
console.log('WORST-VERTEX through real compiled mul034 (proper gate):', accept?'ACCEPT (output == noble canonical)':'REJECT', ' top='+JSON.stringify(top?[...top]:null));
