// A1 SKEPTIC — independent re-derivation of the lazy fp12Sqr soundness bounds.
// Translated DIRECTLY from variants/V2_delayed.cash and variants/V2_miller_lib.cash.
// Does NOT reuse the prior bound harnesses' code. Cross-checks against @noble Fp12.sqr.
import { Fp12, Fp } from './_millermath.mjs';
const P = Fp.ORDER;

// The two hardcoded bias constants, copied verbatim from the .cash sources:
const CONST_STANDALONE = 507361791401603590146065339884462786506408203206435770960198222587060229213828216047103990131139210776525628370024303086564595223859909885393566267333524240n;
const CONST_MILLER     = 202944716560641436058426135953785114602563281282574308384079289034824091685549821404793712422553157789241740953812104359610149043919352694135649979132063988983n;

const byteLen = (x) => { let n = x < 0n ? -x : x; let b = 1; while (n >= 128n) { n >>= 8n; b++; } return b; };

console.log('=== (C) BIAS-CONSTANT INTEGRITY (forgery vector: constant must be ≡ 0 mod p) ===');
for (const [name, c] of [['standalone', CONST_STANDALONE], ['miller', CONST_MILLER]]) {
  const rem = c % P;
  console.log(`  ${name}: byteLen=${byteLen(c)}  const%p=${rem}  (multiple-of-p: ${rem === 0n})  const/p=${c / P}`);
}

// ---------------------------------------------------------------------------
// (1) Interval arithmetic, translated straight from the .cash wide fp12Sqr tree
// ---------------------------------------------------------------------------
const I = (lo, hi) => ({ lo, hi });
const iadd = (a, b) => I(a.lo + b.lo, a.hi + b.hi);
const isub = (a, b) => I(a.lo - b.hi, a.hi - b.lo);
const imul = (a, b) => { const c = [a.lo*b.lo, a.lo*b.hi, a.hi*b.lo, a.hi*b.hi]; return I(c.reduce((m,x)=>x<m?x:m), c.reduce((m,x)=>x>m?x:m)); };
const ismul = (k, a) => k >= 0n ? I(k*a.lo, k*a.hi) : I(k*a.hi, k*a.lo);

// wide fp2/fp6 (NO reduction) — mirror of fp2MulW / fp2MulXiW / fp6MulW / fp6MulByVW
const f2mulW = (a, b) => { const w0=imul(a[0],b[0]), w1=imul(a[1],b[1]); return [isub(w0,w1), isub(imul(iadd(a[0],a[1]),iadd(b[0],b[1])), iadd(w0,w1))]; };
const f2xiW  = (a) => [isub(ismul(9n,a[0]), a[1]), iadd(ismul(9n,a[1]), a[0])];
const f6mulW = (a, b) => {
  const t0=f2mulW([a[0],a[1]],[b[0],b[1]]), t1=f2mulW([a[2],a[3]],[b[2],b[3]]), t2=f2mulW([a[4],a[5]],[b[4],b[5]]);
  const p1=f2mulW([iadd(a[2],a[4]),iadd(a[3],a[5])],[iadd(b[2],b[4]),iadd(b[3],b[5])]);
  const x1=f2xiW([isub(isub(p1[0],t1[0]),t2[0]), isub(isub(p1[1],t1[1]),t2[1])]);
  const c0a=iadd(t0[0],x1[0]), c0b=iadd(t0[1],x1[1]);
  const p2=f2mulW([iadd(a[0],a[2]),iadd(a[1],a[3])],[iadd(b[0],b[2]),iadd(b[1],b[3])]);
  const x2=f2xiW([t2[0],t2[1]]);
  const c1a=iadd(isub(isub(p2[0],t0[0]),t1[0]),x2[0]), c1b=iadd(isub(isub(p2[1],t0[1]),t1[1]),x2[1]);
  const p3=f2mulW([iadd(a[0],a[4]),iadd(a[1],a[5])],[iadd(b[0],b[4]),iadd(b[1],b[5])]);
  const c2a=iadd(isub(isub(p3[0],t0[0]),t2[0]),t1[0]), c2b=iadd(isub(isub(p3[1],t0[1]),t2[1]),t1[1]);
  return [c0a,c0b,c1a,c1b,c2a,c2b];
};
const f6vW = (a) => { const n=f2xiW([a[4],a[5]]); return [n[0],n[1],a[0],a[1],a[2],a[3]]; };
function fp12SqrIntervals(A) { // A: 12 intervals
  const lo=A.slice(0,6), hi=A.slice(6,12);
  const t0=f6mulW(lo,hi);
  const vc=f6vW(hi);
  const s=lo.map((x,i)=>iadd(x,hi[i]));
  const u=lo.map((x,i)=>iadd(x,vc[i]));
  const t1=f6mulW(s,u);
  const vt0=f6vW(t0);
  const Clo=[0,1,2,3,4,5].map(i=>isub(isub(t1[i],t0[i]),vt0[i]));
  const Chi=[0,1,2,3,4,5].map(i=>iadd(t0[i],t0[i]));
  return [...Clo,...Chi];
}
function deriveBias(hiInputBound, label) {
  const inp = I(0n, hiInputBound);
  const A = Array.from({length:12}, ()=>inp);
  const outs = fp12SqrIntervals(A);
  let maxNeg=0n, maxAbs=0n;
  outs.forEach(o=>{ const neg=o.lo<0n?-o.lo:0n; if(neg>maxNeg)maxNeg=neg; const m=(o.hi>0n?o.hi:0n)>((o.lo<0n?-o.lo:0n))?(o.hi>0n?o.hi:0n):(o.lo<0n?-o.lo:0n); if(m>maxAbs)maxAbs=m; });
  const BIG = maxNeg/P + 1n;
  const dividendMax = maxAbs + BIG*P;
  console.log(`  [${label}] input≤ ${hiInputBound/P}·p : maxNeg=${(Number(maxNeg)/Number(P*P)).toFixed(1)}·p²  BIG=${BIG}  BIG·p byteLen=${byteLen(BIG*P)}  maxDividend byteLen=${byteLen(dividendMax)}`);
  return { maxNeg, BIG, BIGxP: BIG*P, maxAbs, dividendMax };
}

console.log('\n=== (1) INDEPENDENT fp12Sqr NEGATIVITY BOUND (interval arithmetic on the wide tree) ===');
const stand = deriveBias(P - 1n, 'standalone [0,p)');
const m19 = deriveBias(19n*P, 'miller 19p');
const m20 = deriveBias(20n*P, 'miller 20p (regime used)');

console.log('\n  Compare derived BIG·p to the hardcoded constants:');
console.log(`  standalone: my BIG·p == CONST_STANDALONE ? ${stand.BIGxP === CONST_STANDALONE}   CONST_STANDALONE ≥ my maxNeg ? ${CONST_STANDALONE >= stand.maxNeg}`);
console.log(`  miller(20p): my BIG·p == CONST_MILLER ? ${m20.BIGxP === CONST_MILLER}   CONST_MILLER ≥ my maxNeg@20p ? ${CONST_MILLER >= m20.maxNeg}   ≥ maxNeg@19p ? ${CONST_MILLER >= m19.maxNeg}`);

// ---------------------------------------------------------------------------
// (2) CORRECT line/mul034 output bound — faithful to V2_miller_lib.cash lazy ops,
//     with fp2Mul/fp2MulXi outputs at their TRUE (k·p-biased) ranges, mulFp→[0,p).
// ---------------------------------------------------------------------------
const RED = () => I(0n, P - 1n);                              // mulFp reduces (needs non-neg inputs)
const subFp = (a, b, k) => I(a.lo - b.hi + BigInt(k)*P, a.hi - b.lo + BigInt(k)*P);
const addFp = (a, b) => iadd(a, b);
const f2add = (a,b) => [addFp(a[0],b[0]), addFp(a[1],b[1])];
const f2sub = (a,b,k) => [subFp(a[0],b[0],k), subFp(a[1],b[1],k)];
const f2mul = () => [ subFp(RED(),RED(),1), subFp(RED(), addFp(RED(),RED()), 2) ];   // fp2Mul: r0=subFp(v0,v1,1); r1=subFp(mulFp, v0+v1, 2)
const f2xi  = (a,k) => [ subFp(RED(), a[1], k), addFp(RED(), a[0]) ];                 // fp2MulXi: subFp(mulFp(9,a0),a1,k), addFp(mulFp(9,a1),a0)
const f6add = (a,b) => [f2add(a[0],b[0]), f2add(a[1],b[1]), f2add(a[2],b[2])];
const f6sub = (a,b,k) => [f2sub(a[0],b[0],k), f2sub(a[1],b[1],k), f2sub(a[2],b[2],k)];
const f6vb  = (a,k) => [ f2xi(a[2],k), a[0], a[1] ];
function f6mul01() {           // fp6Mul01(c, b0, b1) — inputs irrelevant (all through mulFp); structure only
  const t0=f2mul(), t1=f2mul();
  const m12=f2mul();                                  // <-- fp2Mul OUTPUT (not [0,p)!): [ [1,2p), [2,3p) ]
  const u0=[subFp(m12[0],t1[0],3), subFp(m12[1],t1[1],3)];
  const xu0=f2xi(u0,6);
  const r0=f2add(xu0,t0);
  const m1=f2mul();
  const u1=[subFp(m1[0],t0[0],3), subFp(m1[1],t0[1],3)];
  const r1=[subFp(u1[0],t1[0],3), subFp(u1[1],t1[1],3)];
  const m2=f2mul();
  const u2=[subFp(m2[0],t0[0],3), subFp(m2[1],t0[1],3)];
  const r2=f2add(u2,t1);
  return [r0,r1,r2];
}
function mul034() {
  const A=[f2mul(), f2mul(), f2mul()];        // A0..A5
  const B=f6mul01();                          // B0..B5
  const G=f6mul01();                          // G0..G5
  const VB=f6vb(B,9);                         // fp6MulByV(B,9)
  const C_lo=f6add(VB,A);                     // fp6Add(VB,A)
  const AB=f6add(A,B);                        // fp6Add(A,B)
  const C_hi=f6sub(G,AB,12);                  // fp6Sub(G,AB,12)
  const flat=(f)=>[f[0][0],f[0][1],f[1][0],f[1][1],f[2][0],f[2][1]];
  return [...flat(C_lo), ...flat(C_hi)];
}
console.log('\n=== (2) CORRECT line/mul034 OUTPUT BOUND (fp12Sqr Miller input) ===');
const out = mul034();
let maxHi=0n, minLo=0n;
out.forEach((o,i)=>{ if(o.hi>maxHi)maxHi=o.hi; if(o.lo<minLo)minLo=o.lo; });
console.log(`  output limb range: [ ${(Number(minLo)/Number(P)).toFixed(3)}·p , ${(Number(maxHi)/Number(P)).toFixed(3)}·p ]`);
console.log(`  all outputs ≥ 0 (non-neg induction base): ${minLo >= 0n}`);
console.log(`  ceil(maxHi/p) = ${maxHi/P + (maxHi%P===0n?0n:1n)}   → claim "≤19p": ${maxHi <= 19n*P}   "≤20p regime": ${maxHi <= 20n*P}`);
console.log(`  (line_bound.mjs modeled the inner m12 as [0,p) instead of the true fp2Mul [0,2p)/[0,3p) — this recomputes it correctly.)`);

// ---------------------------------------------------------------------------
// (3) EXACT-VALUE STRESS — signed BigInt mirror, adversarial corners, vs noble.
// ---------------------------------------------------------------------------
const f2mulWx=(a0,a1,b0,b1)=>{const w0=a0*b0,w1=a1*b1;return [w0-w1,(a0+a1)*(b0+b1)-w0-w1];};
const f2xiWx=(a0,a1)=>[9n*a0-a1,9n*a1+a0];
function f6mulWx(a,b){const[a0a,a0b,a1a,a1b,a2a,a2b]=a,[b0a,b0b,b1a,b1b,b2a,b2b]=b;
  const[t0a,t0b]=f2mulWx(a0a,a0b,b0a,b0b),[t1a,t1b]=f2mulWx(a1a,a1b,b1a,b1b),[t2a,t2b]=f2mulWx(a2a,a2b,b2a,b2b);
  const[p1a,p1b]=f2mulWx(a1a+a2a,a1b+a2b,b1a+b2a,b1b+b2b);
  const[x1a,x1b]=f2xiWx(p1a-t1a-t2a,p1b-t1b-t2b);
  const c0a=t0a+x1a,c0b=t0b+x1b;
  const[p2a,p2b]=f2mulWx(a0a+a1a,a0b+a1b,b0a+b1a,b0b+b1b);
  const[x2a,x2b]=f2xiWx(t2a,t2b);
  const c1a=p2a-t0a-t1a+x2a,c1b=p2b-t0b-t1b+x2b;
  const[p3a,p3b]=f2mulWx(a0a+a2a,a0b+a2b,b0a+b2a,b0b+b2b);
  const c2a=p3a-t0a-t2a+t1a,c2b=p3b-t0b-t2b+t1b;
  return[c0a,c0b,c1a,c1b,c2a,c2b];}
const f6vWx=(a)=>{const[n0a,n0b]=f2xiWx(a[4],a[5]);return[n0a,n0b,a[0],a[1],a[2],a[3]];};
function preReduce(A){const lo=A.slice(0,6),hi=A.slice(6,12);
  const t0=f6mulWx(lo,hi),vc=f6vWx(hi);
  const s=lo.map((x,i)=>x+hi[i]),u=lo.map((x,i)=>x+vc[i]);
  const t1=f6mulWx(s,u),vt0=f6vWx(t0);
  const Clo=[0,1,2,3,4,5].map(i=>t1[i]-t0[i]-vt0[i]);
  const Chi=[0,1,2,3,4,5].map(i=>t0[i]+t0[i]);
  return[...Clo,...Chi];}
const mk2=(a,b)=>({c0:a,c1:b});
const toF12=(L)=>({c0:{c0:mk2(L[0],L[1]),c1:mk2(L[2],L[3]),c2:mk2(L[4],L[5])},c1:{c0:mk2(L[6],L[7]),c1:mk2(L[8],L[9]),c2:mk2(L[10],L[11])}});
const flat=(f)=>[f.c0.c0.c0,f.c0.c0.c1,f.c0.c1.c0,f.c0.c1.c1,f.c0.c2.c0,f.c0.c2.c1,f.c1.c0.c0,f.c1.c0.c1,f.c1.c1.c0,f.c1.c1.c1,f.c1.c2.c0,f.c1.c2.c1];
const nobleSqr=(L)=>flat(Fp12.sqr(toF12(L.map(x=>((x%P)+P)%P))));   // reduce inputs mod p first (residue class)

let s=0x1234567deadbeefn;
const rnd=()=>{s^=s<<13n;s&=(1n<<64n)-1n;s^=s>>7n;s^=s<<17n;s&=(1n<<64n)-1n;return s;};
const rndBelow=(hi)=>{let x=0n;for(let k=0;k<6;k++)x=(x<<64n)|rnd();return x%(hi+1n);};

function stress(label, hiBound, BIASxP, corners, nRand, nCorner) {
  let worstNeg=0n, minDiv=1n<<800n, divFail=0, formFail=0, n=0, maxDivWidth=0;
  const test=(L)=>{ n++; const pre=preReduce(L); const exp=nobleSqr(L);
    for(let i=0;i<12;i++){ const div=pre[i]+BIASxP; if(div<minDiv)minDiv=div;
      const w=byteLen(pre[i]>0n?pre[i]:-pre[i]); const dw=byteLen(div); if(dw>maxDivWidth)maxDivWidth=dw;
      if(pre[i]<0n&&-pre[i]>worstNeg)worstNeg=-pre[i];
      if(div<0n)divFail++;
      const red=((div%P)+P)%P; if(red!==exp[i])formFail++; } };
  for(let t=0;t<nRand;t++) test(Array.from({length:12},()=>rndBelow(hiBound)));
  for(let t=0;t<nCorner;t++) test(Array.from({length:12},()=>corners[Number(rnd()%BigInt(corners.length))]));
  // structured extremes
  test(Array.from({length:12},()=>hiBound));
  test(Array.from({length:12},()=>0n));
  test(Array.from({length:12},(_,i)=>i%2?hiBound:0n));
  test(Array.from({length:12},(_,i)=>i<6?hiBound:0n));
  // greedy per-limb corner search to MAXIMIZE negativity of each output
  for(let out=0; out<12; out++){
    let base=Array.from({length:12},()=>0n);
    for(let iter=0; iter<3; iter++) for(let v=0; v<12; v++){
      let best=base[v], bestNeg=-(preReduce(base)[out]);
      for(const cand of corners){ const t=[...base]; t[v]=cand; const neg=-(preReduce(t)[out]); if(neg>bestNeg){bestNeg=neg;best=cand;} }
      base[v]=best;
    }
    test(base);
  }
  console.log(`  [${label}] inputs≤${hiBound/P}·p, ${n} vectors:`);
  console.log(`     worst |neg pre| = ${(Number(worstNeg)/Number(P*P)).toFixed(1)}·p²   min dividend = ${minDiv<0n?minDiv:'≥0'}   maxDividend byteLen=${maxDivWidth}`);
  console.log(`     dividend<0 failures = ${divFail}    residue≠noble failures = ${formFail}   → ${divFail===0&&formFail===0?'SOUND':'*** UNSOUND ***'}`);
  return { worstNeg, minDiv, divFail, formFail };
}

console.log('\n=== (3) EXACT STRESS vs noble (residue) + dividend≥0 (bias sufficiency) ===');
const cStd=[0n,1n,2n,P-2n,P-1n];
stress('standalone [0,p)', P-1n, CONST_STANDALONE, cStd, 3000, 500);
const cMil=[0n,1n,P-1n,P,19n*P-1n,19n*P,20n*P];   // include out-of-claim corner 20p
stress('miller ≤19p',  19n*P, CONST_MILLER, [0n,1n,P-1n,P,19n*P], 3000, 500);
stress('miller ≤20p (regime edge)', 20n*P, CONST_MILLER, cMil, 3000, 500);
// deliberately OVER the regime to locate the breaking point
stress('miller ≤21p (OVER regime — expect break?)', 21n*P, CONST_MILLER, [0n,1n,21n*P], 1500, 300);

console.log('\nDONE.');
