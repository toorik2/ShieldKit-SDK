// OVERFLOW-BOUND SKEPTIC AUDIT of lazy fp12Sqr (V2_miller_lib.cash).
// Composes the ACTUAL mul034 per-limb output interval (the real fp12Sqr input regime in the
// Miller loop, since fp12Sqr consumes a line/mul034 output) into the fp12Sqr wide-tree interval
// analysis, and checks max|neg| < bias for the TRUE per-limb regime (NOT a loose uniform 20p box).
// Also computes the max intermediate wide-int byte-width vs the VM number cap (10000 B).
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const BIAS_MILLER = 202944716560641436058426135953785114602563281282574308384079289034824091685549821404793712422553157789241740953812104359610149043919352694135649979132063988983n;
const byteLen = (x) => { let n = x < 0n ? -x : x; let b = 1; while (n >= 128n) { n >>= 8n; b++; } return b; };

const I = (lo, hi) => ({ lo, hi });
const iadd = (a, b) => I(a.lo + b.lo, a.hi + b.hi);
const isub = (a, b) => I(a.lo - b.hi, a.hi - b.lo);
const imul = (a, b) => { const c = [a.lo*b.lo, a.lo*b.hi, a.hi*b.lo, a.hi*b.hi]; return I(c.reduce((m,x)=>x<m?x:m), c.reduce((m,x)=>x>m?x:m)); };
const ismul = (k, a) => k >= 0n ? I(k*a.lo, k*a.hi) : I(k*a.hi, k*a.lo);
const absHi = (o) => { const a = o.hi>0n?o.hi:-o.hi, b = o.lo>0n?o.lo:-o.lo; return a>b?a:b; };

// ---- (A) mul034 per-limb OUTPUT interval (faithful to V2_miller_lib.cash lazy ops) ----
const RED  = () => I(0n, P - 1n);                          // mulFp result in [0,p)
const subFp = (a, b, k) => I(a.lo - b.hi + BigInt(k)*P, a.hi - b.lo + BigInt(k)*P);
const addFp = (a, b) => iadd(a, b);
const f2add = (a,b) => [addFp(a[0],b[0]), addFp(a[1],b[1])];
const f2subI = (a,b,k) => [subFp(a[0],b[0],k), subFp(a[1],b[1],k)];
const f2mul = () => { const v0=RED(), v1=RED(); return [ subFp(v0,v1,1), subFp(RED(), addFp(v0,v1), 2) ]; };
const f2xi  = (a,k) => [ subFp(RED(), a[1], k), addFp(RED(), a[0]) ];
const f6add = (a,b) => [f2add(a[0],b[0]), f2add(a[1],b[1]), f2add(a[2],b[2])];
const f6sub = (a,b,k) => [f2subI(a[0],b[0],k), f2subI(a[1],b[1],k), f2subI(a[2],b[2],k)];
const f6vb  = (a,k) => [ f2xi(a[2],k), a[0], a[1] ];
function f6mul01() {
  const t0=f2mul(), t1=f2mul();
  const m12=f2mul();
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
  const A=[f2mul(), f2mul(), f2mul()];
  const B=f6mul01();
  const G=f6mul01();
  const VB=f6vb(B,9);
  const C_lo=f6add(VB,A);
  const AB=f6add(A,B);
  const C_hi=f6sub(G,AB,12);
  const flat=(f)=>[f[0][0],f[0][1],f[1][0],f[1][1],f[2][0],f[2][1]];
  return [...flat(C_lo), ...flat(C_hi)];
}
const mulOut = mul034();
console.log('=== (A) mul034 per-limb OUTPUT interval (fp12Sqr Miller input regime) ===');
mulOut.forEach((o,i)=>console.log(`  limb ${String(i).padStart(2)}: [ ${(Number(o.lo)/Number(P)).toFixed(3)} , ${(Number(o.hi)/Number(P)).toFixed(3)} ]p  lo>=0:${o.lo>=0n}`));
const maxHi = mulOut.reduce((m,o)=>o.hi>m?o.hi:m, 0n);
const minLo = mulOut.reduce((m,o)=>o.lo<m?o.lo:m, 0n);
console.log(`  overall minLo=${(Number(minLo)/Number(P)).toFixed(3)}p  maxHi=${(Number(maxHi)/Number(P)).toFixed(3)}p`);

// ---- (B) fp12Sqr wide-tree intervals, mirror of V2_miller_lib.cash fp12Sqr ----
const f2mulW = (a, b) => { const w0=imul(a[0],b[0]), w1=imul(a[1],b[1]); return [isub(w0,w1), isub(imul(iadd(a[0],a[1]),iadd(b[0],b[1])), iadd(w0,w1))]; };
const f2xiW  = (a) => [isub(ismul(9n,a[0]), a[1]), iadd(ismul(9n,a[1]), a[0])];
function f6mulW(a, b) {
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
}
const f6vW = (a) => { const n=f2xiW([a[4],a[5]]); return [n[0],n[1],a[0],a[1],a[2],a[3]]; };
function fp12SqrIntervals(A) {
  const lo=A.slice(0,6), hi=A.slice(6,12);
  const t0=f6mulW(lo,hi);
  const vc=f6vW(hi);
  const s=lo.map((x,i)=>iadd(x,hi[i]));
  const u=lo.map((x,i)=>iadd(x,vc[i]));
  const t1=f6mulW(s,u);
  const vt0=f6vW(t0);
  const Clo=[0,1,2,3,4,5].map(i=>isub(isub(t1[i],t0[i]),vt0[i]));
  const Chi=[0,1,2,3,4,5].map(i=>iadd(t0[i],t0[i]));
  const pre=[...Clo,...Chi];
  const allInter=[...t0,...vc,...s,...u,...t1,...vt0,...pre];
  return { pre, allInter };
}
function analyze(label, inputs) {
  const { pre, allInter } = fp12SqrIntervals(inputs);
  let maxNeg=0n, maxAbs=0n, maxInterW=0;
  pre.forEach(o=>{ const neg=o.lo<0n?-o.lo:0n; if(neg>maxNeg)maxNeg=neg; const m=absHi(o); if(m>maxAbs)maxAbs=m; });
  allInter.forEach(o=>{ const w=Math.max(byteLen(o.lo), byteLen(o.hi)); if(w>maxInterW)maxInterW=w; });
  const minDividend = BIAS_MILLER - maxNeg;
  const maxDividend = maxAbs + BIAS_MILLER;
  console.log(`\n[${label}]`);
  console.log(`  max|neg| pre-reduce = ${(Number(maxNeg)/Number(P*P)).toFixed(1)} p^2   bias = ${(Number(BIAS_MILLER)/Number(P*P)).toFixed(1)} p^2`);
  console.log(`  bias - max|neg|     = ${(Number(minDividend)/Number(P*P)).toFixed(1)} p^2   => ${minDividend >= 0n ? 'dividend always >=0  SOUND' : '*** UNSOUND: dividend<0 -> forgery ***'}`);
  console.log(`  max dividend byteLen = ${byteLen(maxDividend)}   widest intermediate wide-int byteLen = ${maxInterW}   (cap 10000)`);
  return { maxNeg, minDividend };
}
console.log('\n=== (B) fp12Sqr pre-reduce negativity vs bias, per input regime ===');
analyze('COMPOSED mul034->fp12Sqr (TRUE per-limb regime)', mulOut);
analyze('uniform [0,20p]^12 (bias-sizing box)', Array.from({length:12},()=>I(0n,20n*P)));
analyze('uniform [0,21p]^12 (loose interval box)', Array.from({length:12},()=>I(0n,21n*P)));
analyze('uniform [0,p)^12 (canonical boundary)', Array.from({length:12},()=>I(0n,P-1n)));
