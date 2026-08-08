// A1 SKEPTIC part 2 (fixed) — verify exact line mirror vs noble, search reachable output magnitude.
import { Fp12, Fp6, Fp2, Fp } from './_millermath.mjs';
const p = Fp.ORDER;
const CONST_MILLER = 202944716560641436058426135953785114602563281282574308384079289034824091685549821404793712422553157789241740953812104359610149043919352694135649979132063988983n;
const BIGm = CONST_MILLER / p;   // = 423600·p ; covers maxNeg up to BIGm/p = 423600 p²  = maxNeg(20p)
console.log(`CONST_MILLER/p = ${BIGm}  ; /p again = ${BIGm/p}  (this is 1059·k² with k=${((BIGm/p)/1059n)**(1n)}; k²=${(BIGm/p)/1059n})`);
console.log(`covered input k where 1059·k² ≤ ${BIGm/p}:  k ≤ ${(()=>{let k=1n;while(1059n*(k+1n)*(k+1n)<=BIGm/p)k++;return k;})()}·p`);
console.log(`maxNeg(21p)=${1059n*441n} p²  > bias ${BIGm/p} p² ? ${1059n*441n > BIGm/p}\n`);

const mod=(x)=>((x%p)+p)%p;
const mulFp=(x,y)=>mod(x*y);
const subFpx=(x,y,k)=>x-y+BigInt(k)*p;
const f2mulx=(a0,a1,b0,b1)=>{const v0=mulFp(a0,b0),v1=mulFp(a1,b1);return[subFpx(v0,v1,1),subFpx(mulFp(a0+a1,b0+b1),v0+v1,2)];};
const f2addx=(a0,a1,b0,b1)=>[a0+b0,a1+b1];
const f2subx=(a0,a1,b0,b1,k)=>[subFpx(a0,b0,k),subFpx(a1,b1,k)];
const f2xix=(a0,a1,k)=>[subFpx(mulFp(9n,a0),a1,k),mulFp(9n,a1)+a0];
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
  const[S0,S1,S2,S3,S4,S5]=[F[0]+F[6],F[1]+F[7],F[2]+F[8],F[3]+F[9],F[4]+F[10],F[5]+F[11]];
  const[qa,qb]=f2addx(o0a,o0b,o3a,o3b);
  const[G0,G1,G2,G3,G4,G5]=f6mul01x(S0,S1,S2,S3,S4,S5,qa,qb,o4a,o4b);
  const[VB0,VB1]=f2xix(B4,B5,9);const VB=[VB0,VB1,B0,B1,B2,B3];
  const C0=VB[0]+A0,C1=VB[1]+A1,C2=VB[2]+A2,C3=VB[3]+A3,C4=VB[4]+A4,C5=VB[5]+A5;
  const AB=[A0+B0,A1+B1,A2+B2,A3+B3,A4+B4,A5+B5];
  const C6=subFpx(G0,AB[0],12),C7=subFpx(G1,AB[1],12),C8=subFpx(G2,AB[2],12),C9=subFpx(G3,AB[3],12),C10=subFpx(G4,AB[4],12),C11=subFpx(G5,AB[5],12);
  return[C0,C1,C2,C3,C4,C5,C6,C7,C8,C9,C10,C11];}
function linex(F,c0a,c0b,c1a,c1b,c2a,c2b,Px,Py){
  const o0a=mulFp(c2a,Py),o0b=mulFp(c2b,Py),o3a=mulFp(c1a,Px),o3b=mulFp(c1b,Px);
  return mul034x(F,o0a,o0b,o3a,o3b,c0a,c0b);}

const mk2=(a,b)=>Fp2.fromBigTuple([mod(a),mod(b)]);
const toF12=(L)=>({c0:Fp6.create({c0:mk2(L[0],L[1]),c1:mk2(L[2],L[3]),c2:mk2(L[4],L[5])}),c1:Fp6.create({c0:mk2(L[6],L[7]),c1:mk2(L[8],L[9]),c2:mk2(L[10],L[11])})});
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
let mism=0,reachMax=0n,reachMin=0n;
for(let t=0;t<3000;t++){
  const F=Array.from({length:12},()=>rF());
  const mine=linex(F,rF(),rF(),rF(),rF(),rF(),rF(),rF(),rF());
  // rebuild with same coeffs for noble
}
// redo with captured coeffs for residue check
s=0xabcdef123456n;
for(let t=0;t<3000;t++){
  const F=Array.from({length:12},()=>rF());
  const c0=[rF(),rF()],c1=[rF(),rF()],c2=[rF(),rF()],Px=rF(),Py=rF();
  const mine=linex(F,c0[0],c0[1],c1[0],c1[1],c2[0],c2[1],Px,Py);
  const ref=nobleLine(F,c0,c1,c2,Px,Py);
  for(let i=0;i<12;i++){if(mod(mine[i])!==ref[i])mism++;if(mine[i]>reachMax)reachMax=mine[i];if(mine[i]<reachMin)reachMin=mine[i];}
}
console.log(`residue mismatches vs noble: ${mism}  (0 = mirror faithful)`);
console.log(`random reachable output: [ ${(Number(reachMin)/Number(p)).toFixed(3)}·p , ${(Number(reachMax)/Number(p)).toFixed(3)}·p ]`);

// coordinate-ascent to push each output limb high; free vars = F(12)+c0,c1,c2(6)+Px,Py(2)=20
const corners=[0n,1n,p-1n,(p-1n)/2n,(p-1n)/3n,2n*(p-1n)/3n];
const ev=(v)=>linex(v.slice(0,12),v[12],v[13],v[14],v[15],v[16],v[17],v[18],v[19]);
let gMax=reachMax,gMin=reachMin;
for(let target=0;target<12;target++)for(const dir of [1n,-1n]){
  let v=Array.from({length:20},()=>rF());
  for(let iter=0;iter<4;iter++)for(let idx=0;idx<20;idx++){
    let best=v[idx],bv=dir*ev(v)[target];
    const cand=[...corners];for(let r=0;r<6;r++)cand.push(rF());
    for(const c of cand){const t=[...v];t[idx]=c;const val=dir*ev(t)[target];if(val>bv){bv=val;best=c;}}
    v[idx]=best;
  }
  const o=ev(v);for(const val of o){if(val>gMax)gMax=val;if(val<gMin)gMin=val;}
}
console.log(`greedy-searched reachable output: [ ${(Number(gMin)/Number(p)).toFixed(3)}·p , ${(Number(gMax)/Number(p)).toFixed(3)}·p ]`);
console.log(`reachable max exceeds 20p (bias regime)? ${gMax>20n*p}   exceeds 19p (claim)? ${gMax>19n*p}   min<0? ${gMin<0n}`);
