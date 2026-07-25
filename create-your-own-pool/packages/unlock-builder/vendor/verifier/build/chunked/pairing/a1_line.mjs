// A1 SKEPTIC part 2 — pin down the TRUE line/mul034 output bound (fp12Sqr Miller input),
// verify my mirror against noble, and determine exactly which input regime CONST_MILLER supports.
import { Fp12, Fp6, Fp2, Fp } from './_millermath.mjs';
const P = Fp.ORDER;
const CONST_MILLER = 202944716560641436058426135953785114602563281282574308384079289034824091685549821404793712422553157789241740953812104359610149043919352694135649979132063988983n;

// ---- exact fractional interval maxHi/minLo for line/mul034 (same model as a1_skeptic (2)) ----
const I=(lo,hi)=>({lo,hi});
const iadd=(a,b)=>I(a.lo+b.lo,a.hi+b.hi);
const RED=()=>I(0n,P-1n);
const subFp=(a,b,k)=>I(a.lo-b.hi+BigInt(k)*P, a.hi-b.lo+BigInt(k)*P);
const f2add=(a,b)=>[iadd(a[0],b[0]),iadd(a[1],b[1])];
const f2sub=(a,b,k)=>[subFp(a[0],b[0],k),subFp(a[1],b[1],k)];
const f2mul=()=>[subFp(RED(),RED(),1), subFp(RED(),iadd(RED(),RED()),2)];
const f2xi=(a,k)=>[subFp(RED(),a[1],k), iadd(RED(),a[0])];
const f6add=(a,b)=>[f2add(a[0],b[0]),f2add(a[1],b[1]),f2add(a[2],b[2])];
const f6sub=(a,b,k)=>[f2sub(a[0],b[0],k),f2sub(a[1],b[1],k),f2sub(a[2],b[2],k)];
const f6vb=(a,k)=>[f2xi(a[2],k),a[0],a[1]];
function f6mul01(){const t0=f2mul(),t1=f2mul(),m12=f2mul();
  const u0=[subFp(m12[0],t1[0],3),subFp(m12[1],t1[1],3)];const xu0=f2xi(u0,6);const r0=f2add(xu0,t0);
  const m1=f2mul();const u1=[subFp(m1[0],t0[0],3),subFp(m1[1],t0[1],3)];const r1=[subFp(u1[0],t1[0],3),subFp(u1[1],t1[1],3)];
  const m2=f2mul();const u2=[subFp(m2[0],t0[0],3),subFp(m2[1],t0[1],3)];const r2=f2add(u2,t1);
  return[r0,r1,r2];}
function mul034I(){const A=[f2mul(),f2mul(),f2mul()];const B=f6mul01();const G=f6mul01();
  const VB=f6vb(B,9);const C_lo=f6add(VB,A);const AB=f6add(A,B);const C_hi=f6sub(G,AB,12);
  const flat=(f)=>[f[0][0],f[0][1],f[1][0],f[1][1],f[2][0],f[2][1]];return[...flat(C_lo),...flat(C_hi)];}
const out=mul034I();let maxHi=0n,minLo=0n;out.forEach(o=>{if(o.hi>maxHi)maxHi=o.hi;if(o.lo<minLo)minLo=o.lo;});
console.log('=== corrected interval bound on line/mul034 output ===');
console.log(`  maxHi = ${(Number(maxHi)/Number(P)).toFixed(4)}·p   minLo = ${(Number(minLo)/Number(P)).toFixed(4)}·p   (exact maxHi = ${maxHi})`);
console.log(`  ceil(maxHi/p) = ${maxHi/P + (maxHi%P===0n?0n:1n)}`);

// ---- what input regime does CONST_MILLER support?  maxNeg(k·p)=1059·k²·p² ----
const BIGm = CONST_MILLER / P;                 // in units of p
// maxNeg(k)=1059 k^2 ; supported iff 1059 k^2 <= BIGm  => k <= sqrt(BIGm/1059)
const kSupported = (() => { let k=0n; while (1059n*(k+1n)*(k+1n) <= BIGm) k++; return k; })();
console.log(`\n=== which input regime does the 66-byte CONST_MILLER cover? ===`);
console.log(`  CONST_MILLER/p = ${BIGm}  = 1059·(${(Number(BIGm)/1059)**0.5}?)... exact: covers inputs ≤ ${kSupported}·p`);
console.log(`  interval maxNeg at 21p = ${1059n*21n*21n}·p²  vs bias ${BIGm}·p² → covered@21p? ${1059n*21n*21n <= BIGm}`);
console.log(`  needed BIG for 21p = ${1059n*21n*21n} p² (byteLen of that·p = ${(()=>{let n=1059n*441n*P;let b=1;while(n>=128n){n>>=8n;b++;}return b;})()})`);

// ---- verify my exact line mirror residues == noble lineFn, then search reachable max magnitude ----
const p=P;
const mod=(x)=>((x%p)+p)%p;
const mulFp=(x,y)=>mod(x*y);
const addFpx=(x,y)=>x+y;
const subFpx=(x,y,k)=>x-y+BigInt(k)*p;
const f2mulx=(a0,a1,b0,b1)=>{const v0=mulFp(a0,b0),v1=mulFp(a1,b1);return[subFpx(v0,v1,1),subFpx(mulFp(addFpx(a0,a1),addFpx(b0,b1)),addFpx(v0,v1),2)];};
const f2addx=(a0,a1,b0,b1)=>[addFpx(a0,b0),addFpx(a1,b1)];
const f2subx=(a0,a1,b0,b1,k)=>[subFpx(a0,b0,k),subFpx(a1,b1,k)];
const f2xix=(a0,a1,k)=>[subFpx(mulFp(9n,a0),a1,k),addFpx(mulFp(9n,a1),a0)];
function f6mul01x(c0a,c0b,c1a,c1b,c2a,c2b,b0a,b0b,b1a,b1b){
  const[t0a,t0b]=f2mulx(c0a,c0b,b0a,b0b);const[t1a,t1b]=f2mulx(c1a,c1b,b1a,b1b);
  const[s12a,s12b]=f2addx(c1a,c1b,c2a,c2b);const[m12a,m12b]=f2mulx(s12a,s12b,b1a,b1b);
  const[u0a,u0b]=f2subx(m12a,m12b,t1a,t1b,3);const[xu0a,xu0b]=f2xix(u0a,u0b,6);const[r0a,r0b]=f2addx(xu0a,xu0b,t0a,t0b);
  const[sba,sbb]=f2addx(b0a,b0b,b1a,b1b);const[sca,scb]=f2addx(c0a,c0b,c1a,c1b);const[m1a,m1b]=f2mulx(sba,sbb,sca,scb);
  const[u1a,u1b]=f2subx(m1a,m1b,t0a,t0b,3);const[r1a,r1b]=f2subx(u1a,u1b,t1a,t1b,3);
  const[s02a,s02b]=f2addx(c0a,c0b,c2a,c2b);const[m2a,m2b]=f2mulx(s02a,s02b,b0a,b0b);
  const[u2a,u2b]=f2subx(m2a,m2b,t0a,t0b,3);const[r2a,r2b]=f2addx(u2a,u2b,t1a,t1b);
  return[r0a,r0b,r1a,r1b,r2a,r2b];}
function mul034x(F,o0a,o0b,o3a,o3b,o4a,o4b){
  const[A0,A1]=f2mulx(F[0],F[1],o0a,o0b);const[A2,A3]=f2mulx(F[2],F[3],o0a,o0b);const[A4,A5]=f2mulx(F[4],F[5],o0a,o0b);
  const[B0,B1,B2,B3,B4,B5]=f6mul01x(F[6],F[7],F[8],F[9],F[10],F[11],o3a,o3b,o4a,o4b);
  const[S0,S1,S2,S3,S4,S5]=[addFpx(F[0],F[6]),addFpx(F[1],F[7]),addFpx(F[2],F[8]),addFpx(F[3],F[9]),addFpx(F[4],F[10]),addFpx(F[5],F[11])];
  const[qa,qb]=f2addx(o0a,o0b,o3a,o3b);
  const[G0,G1,G2,G3,G4,G5]=f6mul01x(S0,S1,S2,S3,S4,S5,qa,qb,o4a,o4b);
  const[VB0,VB1]=f2xix(B4,B5,9);const VB=[VB0,VB1,B0,B1,B2,B3];
  const C0=addFpx(VB[0],A0),C1=addFpx(VB[1],A1),C2=addFpx(VB[2],A2),C3=addFpx(VB[3],A3),C4=addFpx(VB[4],A4),C5=addFpx(VB[5],A5);
  const AB=[addFpx(A0,B0),addFpx(A1,B1),addFpx(A2,B2),addFpx(A3,B3),addFpx(A4,B4),addFpx(A5,B5)];
  const C6=subFpx(G0,AB[0],12),C7=subFpx(G1,AB[1],12),C8=subFpx(G2,AB[2],12),C9=subFpx(G3,AB[3],12),C10=subFpx(G4,AB[4],12),C11=subFpx(G5,AB[5],12);
  return[C0,C1,C2,C3,C4,C5,C6,C7,C8,C9,C10,C11];}
// line(): o0=mulFp(c2,Py), o3=mulFp(c1,Px), o4=c0
function linex(F,c0a,c0b,c1a,c1b,c2a,c2b,Px,Py){
  const o0a=mulFp(c2a,Py),o0b=mulFp(c2b,Py),o3a=mulFp(c1a,Px),o3b=mulFp(c1b,Px);
  return mul034x(F,o0a,o0b,o3a,o3b,c0a,c0b);}

// noble reference for residue check
const mk2=(a,b)=>Fp2.fromBigTuple([mod(a),mod(b)]);
const toF12=(L)=>Fp12.fromBigTuple? null : ({c0:Fp6.create({c0:mk2(L[0],L[1]),c1:mk2(L[2],L[3]),c2:mk2(L[4],L[5])}),c1:Fp6.create({c0:mk2(L[6],L[7]),c1:mk2(L[8],L[9]),c2:mk2(L[10],L[11])})});
const scalarFp2=(x,k)=>Fp2.fromBigTuple([mod(x.c0*k),mod(x.c1*k)]);
function nobleLine(L,c0,c1,c2,Px,Py){
  const f=toF12(L);
  const o0=scalarFp2(Fp2.fromBigTuple([mod(c2[0]),mod(c2[1])]),Py);
  const o3=scalarFp2(Fp2.fromBigTuple([mod(c1[0]),mod(c1[1])]),Px);
  const o4=Fp2.fromBigTuple([mod(c0[0]),mod(c0[1])]);
  const A=Fp6.create({c0:Fp2.mul(f.c0.c0,o0),c1:Fp2.mul(f.c0.c1,o0),c2:Fp2.mul(f.c0.c2,o0)});
  const B=Fp6.mul01(f.c1,o3,o4);
  const E=Fp6.mul01(Fp6.add(f.c0,f.c1),Fp2.add(o0,o3),o4);
  const r=Fp12.create({c0:Fp6.add(Fp6.mulByNonresidue(B),A),c1:Fp6.sub(E,Fp6.add(A,B))});
  return[r.c0.c0.c0,r.c0.c0.c1,r.c0.c1.c0,r.c0.c1.c1,r.c0.c2.c0,r.c0.c2.c1,r.c1.c0.c0,r.c1.c0.c1,r.c1.c1.c0,r.c1.c1.c1,r.c1.c2.c0,r.c1.c2.c1];}

let s=0xabcdef123456n;const rnd=()=>{s^=s<<13n;s&=(1n<<64n)-1n;s^=s>>7n;s^=s<<17n;s&=(1n<<64n)-1n;return s;};
const rF=()=>{let x=0n;for(let k=0;k<4;k++)x=(x<<64n)|rnd();return x%p;};
// verify mirror == noble, and track reachable output magnitude
let mism=0, reachMax=0n, reachMin=0n;
for(let t=0;t<4000;t++){
  const F=Array.from({length:12},()=>rF());
  const c0=[rF(),rF()],c1=[rF(),rF()],c2=[rF(),rF()],Px=rF(),Py=rF();
  const mine=linex(F,c0[0],c0[1],c1[0],c1[1],c2[0],c2[1],Px,Py);
  const ref=nobleLine(F,c0,c1,c2,Px,Py);
  for(let i=0;i<12;i++){ if(mod(mine[i])!==ref[i])mism++; if(mine[i]>reachMax)reachMax=mine[i]; if(mine[i]<reachMin)reachMin=mine[i]; }
}
console.log(`\n=== exact line mirror: residue match vs noble ===`);
console.log(`  residue mismatches: ${mism}  (0 == mirror is faithful to real algebra)`);
console.log(`  reachable output over 4000 random (reduced F, reduced coeffs): [ ${(Number(reachMin)/Number(p)).toFixed(3)}·p , ${(Number(reachMax)/Number(p)).toFixed(3)}·p ]`);

// greedy corner search to push a chosen output limb as HIGH as possible (max magnitude reachable)
// free inputs: F(12), c0(2),c1(2),c2(2),Px,Py = 19 field vars; corners at 0 and p-1 plus a few random
const corners=[0n,1n,p-1n,(p-1n)/2n];
function evalMax(vars){ // vars: [F0..F11,c0a,c0b,c1a,c1b,c2a,c2b,Px,Py]
  const F=vars.slice(0,12);const o=linex(F,vars[12],vars[13],vars[14],vars[15],vars[16],vars[17],vars[18],vars[19]);
  return o;}
let bestReach=reachMax, bestReachMin=reachMin;
for(let target=0;target<12;target++){
  for(let dir of [1n,-1n]){
    let vars=Array.from({length:20},()=>0n);
    for(let iter=0;iter<3;iter++)for(let v=0;v<20;v++){
      let best=vars[v], bestVal=dir*evalMax(vars)[target];
      for(const c of corners){const t=[...vars];t[v]=c;const val=dir*evalMax(t)[target];if(val>bestVal){bestVal=val;best=c;}}
      // also try a few randoms
      for(let r=0;r<8;r++){const t=[...vars];t[v]=rF();const val=dir*evalMax(t)[target];if(val>bestVal){bestVal=val;best=t[v];}}
      vars[v]=best;
    }
    const o=evalMax(vars);
    for(const val of o){ if(val>bestReach)bestReach=val; if(val<bestReachMin)bestReachMin=val; }
  }
}
console.log(`  greedy-searched reachable output range: [ ${(Number(bestReachMin)/Number(p)).toFixed(3)}·p , ${(Number(bestReach)/Number(p)).toFixed(3)}·p ]`);
console.log(`  → exceeds 20p (bias regime)? ${bestReach>20n*p}   exceeds 19p (claim)? ${bestReach>19n*p}`);
