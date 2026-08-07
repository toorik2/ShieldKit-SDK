// EXACT end-to-end stress: REAL mul034 output (eager lazy ops, coupled data) -> fp12Sqr wide tree.
// Validates: (1) mul034 output limbs fall inside the interval model used to size the bias;
// (2) fp12Sqr reduceOut dividend (x+bias) is ALWAYS >= 0 (no OP_MOD negativity); (3) the reduced
// residue matches noble Fp12.sqr on the residue class. Adversarial corner search maximises negativity.
import { Fp12 } from './_millermath.mjs';
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const BIAS = 202944716560641436058426135953785114602563281282574308384079289034824091685549821404793712422553157789241740953812104359610149043919352694135649979132063988983n;
const byteLen = (x)=>{let n=x<0n?-x:x,b=1;while(n>=128n){n>>=8n;b++;}return b;};
const mod = (x)=>((x%P)+P)%P;

// ---- exact eager lazy ops (mirror V2_miller_lib.cash) ----
const mulFp=(x,y)=>mod(x*y);
const subFp=(x,y,k)=>x-y+BigInt(k)*P;
const addFp=(x,y)=>x+y;
const f2Mul=(a0,a1,b0,b1)=>{const v0=mulFp(a0,b0),v1=mulFp(a1,b1);return [subFp(v0,v1,1),subFp(mulFp(addFp(a0,a1),addFp(b0,b1)),addFp(v0,v1),2)];};
const f2Add=(a0,a1,b0,b1)=>[addFp(a0,b0),addFp(a1,b1)];
const f2Sub=(a0,a1,b0,b1,k)=>[subFp(a0,b0,k),subFp(a1,b1,k)];
const f2MulXi=(a0,a1,k)=>[subFp(mulFp(9n,a0),a1,k),addFp(mulFp(9n,a1),a0)];
const f6Add=(a,b)=>{const r=[];for(let i=0;i<6;i+=2){const [x,y]=f2Add(a[i],a[i+1],b[i],b[i+1]);r.push(x,y);}return r;};
const f6Sub=(a,b,k)=>{const r=[];for(let i=0;i<6;i+=2){const [x,y]=f2Sub(a[i],a[i+1],b[i],b[i+1],k);r.push(x,y);}return r;};
const f6MulByV=(a,k)=>{const [n0,n1]=f2MulXi(a[4],a[5],k);return [n0,n1,a[0],a[1],a[2],a[3]];};
function f6Mul01(c,b0a,b0b,b1a,b1b){
  const [c0a,c0b,c1a,c1b,c2a,c2b]=c;
  const [t0a,t0b]=f2Mul(c0a,c0b,b0a,b0b),[t1a,t1b]=f2Mul(c1a,c1b,b1a,b1b);
  const [s12a,s12b]=f2Add(c1a,c1b,c2a,c2b);
  const [m12a,m12b]=f2Mul(s12a,s12b,b1a,b1b);
  const [u0a,u0b]=f2Sub(m12a,m12b,t1a,t1b,3);
  const [xu0a,xu0b]=f2MulXi(u0a,u0b,6);
  const [r0a,r0b]=f2Add(xu0a,xu0b,t0a,t0b);
  const [sba,sbb]=f2Add(b0a,b0b,b1a,b1b);
  const [sca,scb]=f2Add(c0a,c0b,c1a,c1b);
  const [m1a,m1b]=f2Mul(sba,sbb,sca,scb);
  const [u1a,u1b]=f2Sub(m1a,m1b,t0a,t0b,3);
  const [r1a,r1b]=f2Sub(u1a,u1b,t1a,t1b,3);
  const [s02a,s02b]=f2Add(c0a,c0b,c2a,c2b);
  const [m2a,m2b]=f2Mul(s02a,s02b,b0a,b0b);
  const [u2a,u2b]=f2Sub(m2a,m2b,t0a,t0b,3);
  const [r2a,r2b]=f2Add(u2a,u2b,t1a,t1b);
  return [r0a,r0b,r1a,r1b,r2a,r2b];
}
function mul034(F,o0a,o0b,o3a,o3b,o4a,o4b){
  const [A0,A1]=f2Mul(F[0],F[1],o0a,o0b);
  const [A2,A3]=f2Mul(F[2],F[3],o0a,o0b);
  const [A4,A5]=f2Mul(F[4],F[5],o0a,o0b);
  const A=[A0,A1,A2,A3,A4,A5];
  const B=f6Mul01(F.slice(6,12),o3a,o3b,o4a,o4b);
  const S=[0,1,2,3,4,5].map(i=>addFp(F[i],F[6+i]));
  const [qa,qb]=f2Add(o0a,o0b,o3a,o3b);
  const G=f6Mul01(S,qa,qb,o4a,o4b);
  const VB=f6MulByV(B,9);
  const Clo=f6Add(VB,A);
  const AB=f6Add(A,B);
  const Chi=f6Sub(G,AB,12);
  return [...Clo,...Chi];
}
// ---- exact wide fp12Sqr pre-reduce (mirror V2 fp12Sqr) ----
const f2mulW=(a0,a1,b0,b1)=>{const w0=a0*b0,w1=a1*b1;return [w0-w1,(a0+a1)*(b0+b1)-w0-w1];};
const f2xiW=(a0,a1)=>[9n*a0-a1,9n*a1+a0];
function f6mulW(a,b){const [a0,a1,a2,a3,a4,a5]=a,[b0,b1,b2,b3,b4,b5]=b;
  const [t0,t1]=f2mulW(a0,a1,b0,b1),[u0,u1]=f2mulW(a2,a3,b2,b3),[v0,v1]=f2mulW(a4,a5,b4,b5);
  const [p1,p2]=f2mulW(a2+a4,a3+a5,b2+b4,b3+b5),[x1,x2]=f2xiW(p1-u0-v0,p2-u1-v1);
  const c0=t0+x1,c1=t1+x2;
  const [q1,q2]=f2mulW(a0+a2,a1+a3,b0+b2,b1+b3),[y1,y2]=f2xiW(v0,v1);
  const c2=q1-t0-u0+y1,c3=q2-t1-u1+y2;
  const [r1,r2]=f2mulW(a0+a4,a1+a5,b0+b4,b1+b5);
  const c4=r1-t0-v0+u0,c5=r2-t1-v1+u1;
  return [c0,c1,c2,c3,c4,c5];}
const f6vW=(a)=>{const [n0,n1]=f2xiW(a[4],a[5]);return [n0,n1,a[0],a[1],a[2],a[3]];};
function fp12SqrPre(A){
  const lo=A.slice(0,6),hi=A.slice(6,12);
  const t0=f6mulW(lo,hi);
  const vc=f6vW(hi);
  const s=lo.map((x,i)=>x+hi[i]);
  const u=lo.map((x,i)=>x+vc[i]);
  const t1=f6mulW(s,u);
  const vt0=f6vW(t0);
  const Clo=[0,1,2,3,4,5].map(i=>t1[i]-t0[i]-vt0[i]);
  const Chi=[0,1,2,3,4,5].map(i=>t0[i]+t0[i]);
  return [...Clo,...Chi];
}
// noble reference
const mk2=(a,b)=>({c0:a,c1:b});
const toF12=(L)=>({c0:{c0:mk2(L[0],L[1]),c1:mk2(L[2],L[3]),c2:mk2(L[4],L[5])},c1:{c0:mk2(L[6],L[7]),c1:mk2(L[8],L[9]),c2:mk2(L[10],L[11])}});
const flat=(f)=>[f.c0.c0.c0,f.c0.c0.c1,f.c0.c1.c0,f.c0.c1.c1,f.c0.c2.c0,f.c0.c2.c1,f.c1.c0.c0,f.c1.c0.c1,f.c1.c1.c0,f.c1.c1.c1,f.c1.c2.c0,f.c1.c2.c1];
const nobleSqr=(L)=>flat(Fp12.sqr(toF12(L.map(mod))));

// my interval-model per-limb bounds for mul034 output (from skeptic_fp12sqr_overflow.mjs)
const LIM=[[0n,12n],[1n,11n],[0n,11n],[1n,12n],[2n,10n],[0n,12n],[1n,21n],[1n,20n],[4n,18n],[0n,21n],[4n,18n],[0n,21n]];

let seed=0xC0FFEEBABEn;
const rnd=()=>{seed^=seed<<13n;seed&=(1n<<64n)-1n;seed^=seed>>7n;seed^=seed<<17n;seed&=(1n<<64n)-1n;return seed;};
const rndBelow=(hi)=>{let x=0n;for(let k=0;k<6;k++)x=(x<<64n)|rnd();return x%hi;};

// draw a realistic line-coeff set: o0,o3 = mulFp results in [0,p); o4 (=c0 of a possibly-lazy line coeff) in [0,6p)
function drawO(){ return [rndBelow(P),rndBelow(P),rndBelow(P),rndBelow(P),rndBelow(6n*P),rndBelow(6n*P)]; }
// draw F: a prior accumulator, itself a mul034 output => in [0,21p) per-limb; use the widest reachable
function drawF(){ return Array.from({length:12},(_,i)=>rndBelow((LIM[i][1]+1n)*P)); }

let worstNeg=0n, minDiv=1n<<900n, divFail=0, resFail=0, rangeFail=0, n=0, maxDivW=0, maxHiSeen=0n;
function test(F,o){
  n++;
  const out=mul034(F,o[0],o[1],o[2],o[3],o[4],o[5]);
  // (1) range check vs interval model
  for(let i=0;i<12;i++){ if(out[i]<LIM[i][0]*P||out[i]>LIM[i][1]*P){rangeFail++;} if(out[i]>maxHiSeen)maxHiSeen=out[i]; }
  // (2)+(3) fp12Sqr pre-reduce, dividend>=0, residue==noble
  const pre=fp12SqrPre(out);
  const exp=nobleSqr(out);
  for(let i=0;i<12;i++){
    const div=pre[i]+BIAS;
    if(pre[i]<0n&&-pre[i]>worstNeg)worstNeg=-pre[i];
    if(div<minDiv)minDiv=div;
    const dw=byteLen(div); if(dw>maxDivW)maxDivW=dw;
    if(div<0n)divFail++;
    if(mod(div)!==exp[i])resFail++;
  }
}
// random coupled draws
for(let t=0;t<20000;t++) test(drawF(),drawO());
// structured extremes: F all high, o all high
test(Array.from({length:12},(_,i)=>(LIM[i][1])*P), [P-1n,P-1n,P-1n,P-1n,6n*P-1n,6n*P-1n]);
test(new Array(12).fill(0n), [0n,0n,0n,0n,0n,0n]);
// greedy corner search to MAXIMISE fp12Sqr negativity: perturb F & o limbs among corners
{
  const Fcorn=(i)=>[0n,(LIM[i][1])*P,LIM[i][0]*P];
  const Ocorn=[0n,P-1n,6n*P-1n];
  let F=drawF(), o=drawO();
  for(let iter=0;iter<6;iter++){
    for(let v=0;v<12;v++){ let best=F[v],bn=Math.max(...fp12SqrPre(mul034(F,...o)).map(x=>x<0n?Number(-x):0));
      for(const c of Fcorn(v)){const t=[...F];t[v]=c; const neg=Math.max(...fp12SqrPre(mul034(t,...o)).map(x=>x<0n?Number(-x):0)); if(neg>bn){bn=neg;best=c;}} F[v]=best; }
    for(let v=0;v<6;v++){ let best=o[v],bn=Math.max(...fp12SqrPre(mul034(F,...o)).map(x=>x<0n?Number(-x):0));
      for(const c of Ocorn){const t=[...o];t[v]=c; const neg=Math.max(...fp12SqrPre(mul034(F,...t)).map(x=>x<0n?Number(-x):0)); if(neg>bn){bn=neg;best=c;}} o[v]=best; }
    test(F,o);
  }
}

console.log('=== EXACT end-to-end stress: real mul034 -> fp12Sqr ===');
console.log(`  vectors tested: ${n}`);
console.log(`  mul034 out-of-interval-model failures: ${rangeFail}   (0 => interval model is a valid enclosure on all draws)`);
console.log(`  max mul034 output limb seen: ${(Number(maxHiSeen)/Number(P)).toFixed(3)} p`);
console.log(`  worst fp12Sqr |neg pre-reduce|: ${(Number(worstNeg)/Number(P*P)).toFixed(1)} p^2   (bias = ${(Number(BIAS)/Number(P*P)).toFixed(0)} p^2)`);
console.log(`  min dividend (x+bias): ${minDiv<0n?minDiv+'  *** NEGATIVE ***':'>= 0'}   maxDividend byteLen=${maxDivW}`);
console.log(`  dividend<0 failures: ${divFail}    residue != noble failures: ${resFail}`);
console.log(`  VERDICT: ${rangeFail===0&&divFail===0&&resFail===0?'SOUND on all tested vectors':'*** FAILURE DETECTED ***'}`);
