// B2 AUDIT (independent): derive the TRUE Miller-regime input bound for the lazy mul034/fp12Mul,
// re-derive the required BIG*p bias from first principles, and adversarially test whether the
// deployed V3 bias covers it. Everything mirrors the eager Bn254Lazy.cash ops EXACTLY.
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

// ---------- interval arithmetic ----------
const I = (lo, hi) => ({ lo, hi });
const add = (a, b) => I(a.lo + b.lo, a.hi + b.hi);
const sub = (a, b) => I(a.lo - b.hi, a.hi - b.lo);
const kmul = (k, a) => k >= 0n ? I(k * a.lo, k * a.hi) : I(k * a.hi, k * a.lo);
const mulI = (a, b) => { const c = [a.lo*b.lo, a.lo*b.hi, a.hi*b.lo, a.hi*b.hi]; return I(c.reduce((m,x)=>x<m?x:m), c.reduce((m,x)=>x>m?x:m)); };
const byteLen = (x) => { let n = x<0n?-x:x, b=1; while (n>=128n){n>>=8n;b++;} return b; };

// ===================================================================================
// PART 1 — EAGER lazy-lib interval mirror to bound o4 = line c0 (pointDouble / pointAdd)
// mulFp reduces to [0,p); addFp = +, subFp(x,y,k) = x-y+kp. Model output intervals of each op.
// ===================================================================================
const RED = I(0n, P - 1n);                 // mulFp output: always [0,p)
const mulFp = () => RED;                    // reduces
// fp2Mul output interval (independent of input magnitude, provided inputs >=0):
//   r0 = v0 - v1 + p  in [0,2p) ; r1 = M - (v0+v1) + 2p in [0,3p)
const fp2MulOut = () => [I(0n, 2n*P), I(0n, 3n*P)];
const fp2SqrOut = () => [RED, RED];        // mulFp(...) both limbs
const fp2ScaleOut = () => [RED, RED];      // mulFp(a,k)
const fp2MulByBOut = () => fp2MulOut();    // it's an fp2Mul
const fp2HalfOut = () => [RED, RED];       // mulFp
const fp2AddOut = (a, b) => [add(a[0], b[0]), add(a[1], b[1])];
// Note: subFp adds EXACTLY k*p (a constant), so model as +[kp,kp].
const kp = (k) => { const kk = BigInt(k); return I(kk*P, kk*P); };
const fp2Sub = (a, b, k) => [add(add(sub(a[0], b[0]), kp(k)), I(0n,0n)), add(sub(a[1], b[1]), kp(k))];
const fp2Neg = (a, k) => [add(sub(I(0n,0n), a[0]), kp(k)), add(sub(I(0n,0n), a[1]), kp(k))];

// pointDouble c0 interval. Inputs X,Y,Z are reduced fp2 in [0,p) (committed state limbs).
function pointDoubleC0() {
  const t0 = fp2SqrOut();                   // sqr(Y)   [0,p)x[0,p)
  const t2 = fp2MulByBOut();                // fp2Mul   [0,2p)x[0,3p)
  const c0 = fp2Sub(t2, t0, 1);             // t2 - t0 + 1p
  return c0;
}
// pointAdd c0 interval. Inputs X,Y,Z (reduced [0,p)); Qx,Qy reduced-ish (>=0) — magnitude irrelevant
// because every use of Qx/Qy passes through fp2Mul which reduces.
function pointAddC0() {
  const t0qx = fp2MulOut();                 // fp2Mul(t0,Qx)  [0,2p)x[0,3p)
  const t1qy = fp2MulOut();                 // fp2Mul(t1,Qy)  [0,2p)x[0,3p)
  const c0 = fp2Sub(t0qx, t1qy, 3);         // t0qx - t1qy + 3p
  return c0;
}
const showC0 = (name, c0) => {
  const a = c0[0], b = c0[1];
  console.log(`  ${name}: c0a in [${(Number(a.lo)/Number(P)).toFixed(2)}p, ${(Number(a.hi)/Number(P)).toFixed(2)}p]  c0b in [${(Number(b.lo)/Number(P)).toFixed(2)}p, ${(Number(b.hi)/Number(P)).toFixed(2)}p]`);
  return [a, b];
};
console.log('=== PART 1: o4 = line c0 range (eager lazy pointDouble/pointAdd) ===');
const dC0 = showC0('pointDouble', pointDoubleC0());
const aC0 = showC0('pointAdd   ', pointAddC0());
const o4hiA = [dC0[0].hi, aC0[0].hi].reduce((m,x)=>x>m?x:m);
const o4hiB = [dC0[1].hi, aC0[1].hi].reduce((m,x)=>x>m?x:m);
const o4loA = [dC0[0].lo, aC0[0].lo, 0n].reduce((m,x)=>x<m?x:m);
console.log(`  => o4 max hi: c0a ~${(Number(o4hiA)/Number(P)).toFixed(3)}p , c0b ~${(Number(o4hiB)/Number(P)).toFixed(3)}p   (min lo ${o4loA})`);
const O4HI = o4hiB > o4hiA ? o4hiB : o4hiA;
console.log(`  => worst o4 component upper bound = ${(Number(O4HI)/Number(P)).toFixed(3)}p  (use ceil = ${(O4HI+P-1n)/P}p)`);

// ===================================================================================
// PART 2 — lazy mul034 wide-int interval tree (EXACT mirror of V3_mul_delayed.cash)
// ===================================================================================
const f2mulW = (a, b) => { const w0 = mulI(a[0],b[0]), w1 = mulI(a[1],b[1]); return [sub(w0,w1), sub(mulI(add(a[0],a[1]),add(b[0],b[1])), add(w0,w1))]; };
const f2xiW = (a) => [sub(kmul(9n,a[0]),a[1]), add(kmul(9n,a[1]),a[0])];
const f2add = (a,b) => [add(a[0],b[0]), add(a[1],b[1])];
const f2sub = (a,b) => [sub(a[0],b[0]), sub(a[1],b[1])];
const f6add = (a,b) => [f2add(a[0],b[0]), f2add(a[1],b[1]), f2add(a[2],b[2])];
const f6sub = (a,b) => [f2sub(a[0],b[0]), f2sub(a[1],b[1]), f2sub(a[2],b[2])];
const f6vW = (a) => [f2xiW(a[2]), a[0], a[1]];
function f6mulW(a, b) {
  const t0=f2mulW(a[0],b[0]), t1=f2mulW(a[1],b[1]), t2=f2mulW(a[2],b[2]);
  const p1=f2mulW(f2add(a[1],a[2]), f2add(b[1],b[2]));
  const x1=f2xiW(f2sub(f2sub(p1,t1),t2));
  const c0=f2add(t0,x1);
  const p2=f2mulW(f2add(a[0],a[1]), f2add(b[0],b[1]));
  const x2=f2xiW(t2);
  const c1=f2add(f2sub(f2sub(p2,t0),t1), x2);
  const p3=f2mulW(f2add(a[0],a[2]), f2add(b[0],b[2]));
  const c2=f2add(f2sub(f2sub(p3,t0),t2), t1);
  return [c0,c1,c2];
}
function f6mul01W(c, b0, b1) {
  const t0=f2mulW(c[0],b0), t1=f2mulW(c[1],b1);
  const m12=f2mulW(f2add(c[1],c[2]), b1);
  const r0=f2add(f2xiW(f2sub(m12,t1)), t0);
  const m1=f2mulW(f2add(b0,b1), f2add(c[0],c[1]));
  const r1=f2sub(f2sub(m1,t0), t1);
  const m2=f2mulW(f2add(c[0],c[2]), b0);
  const r2=f2add(f2sub(m2,t0), t1);
  return [r0,r1,r2];
}
const flat6 = (f) => [f[0][0],f[0][1],f[1][0],f[1][1],f[2][0],f[2][1]];
function fp12MulLazy(A, B) {
  const Alo=A.slice(0,3), Ahi=A.slice(3,6), Blo=B.slice(0,3), Bhi=B.slice(3,6);
  const t0=f6mulW(Alo,Blo), t1=f6mulW(Ahi,Bhi), vt=f6vW(t1);
  const Clo=f6add(t0,vt);
  const pr=f6mulW(f6add(Alo,Ahi), f6add(Blo,Bhi));
  const Chi=f6sub(f6sub(pr,t0), t1);
  return [...flat6(Clo), ...flat6(Chi)];
}
function mul034Lazy(F, o0, o3, o4) {
  const Flo=F.slice(0,3), Fhi=F.slice(3,6);
  const A=[f2mulW(F[0],o0), f2mulW(F[1],o0), f2mulW(F[2],o0)];
  const B=f6mul01W(Fhi, o3, o4);
  const G=f6mul01W(f6add(Flo,Fhi), f2add(o0,o3), o4);
  const VB=f6vW(B);
  const Clo=f6add(VB,A);
  const Chi=f6sub(G, f6add(A,B));
  return [...flat6(Clo), ...flat6(Chi)];
}
function maxNegOf(outs) { let mn=0n; outs.forEach(o=>{ const neg=o.lo<0n?-o.lo:0n; if(neg>mn)mn=neg; }); return mn; }
function maxAbsOf(outs) { let m=0n; outs.forEach(o=>{ const a=o.hi>0n?o.hi:0n, b=o.lo<0n?-o.lo:0n, x=a>b?a:b; if(x>m)m=x; }); return m; }

// deployed V3 bias
const BIAS = 473346033904423368332684188674078595909661288732727612567210428627021252562119744690866504404556704362571480480121380658603450849396234800254307144706265583n;
const BIG = BIAS / P;
console.log('\n=== PART 3: deployed V3 bias ===');
console.log(`  bias = ${BIAS}`);
console.log(`  bias % p == 0 ? ${BIAS % P === 0n}   BIG = bias/p = ${BIG}   byteLen(bias) = ${byteLen(BIAS)}`);
console.log(`  bias / p^2 ~= ${(Number(BIAS)/Number(P*P)).toFixed(1)}`);

const inpP = I(0n, P - 1n);
console.log('\n=== PART 4: max|neg| pre-reduce vs deployed bias, per input regime ===');
function assess(name, outs) {
  const mn = maxNegOf(outs), ab = maxAbsOf(outs);
  const covered = BIAS >= mn;
  const div0 = mn <= BIAS;          // min dividend = BIG*p - mn >= 0 ?
  const maxDiv = ab + BIAS;
  console.log(`  ${name}`);
  console.log(`      max|neg| = ${mn}  (~${(Number(mn)/Number(P*P)).toFixed(1)} p^2)`);
  console.log(`      bias-maxNeg (min dividend) = ${BIAS - mn}  ${BIAS>=mn?'>=0 OK':'<0 *** UNSOUND ***'}   marginP=${((BIAS-mn)/P).toString()}`);
  console.log(`      max dividend byteLen = ${byteLen(maxDiv)}`);
  return { mn, covered: BIAS >= mn };
}

const A6 = Array.from({length:6}, () => [inpP, inpP]);
const B6 = Array.from({length:6}, () => [inpP, inpP]);
assess('fp12Mul  A,B in [0,p)                 :', fp12MulLazy(A6, B6));

const F6 = Array.from({length:6}, () => [inpP, inpP]);
for (const k of [1n,4n,5n,6n,7n,8n]) {
  const o4 = [I(0n, k*P), I(0n, k*P)];
  assess(`mul034   F,o0,o3 in [0,p), o4 in [0,${k}p]:`, mul034Lazy(F6, [inpP,inpP], [inpP,inpP], o4));
}

// ===================================================================================
// PART 5 — RANDOM adversarial numeric stress at TRUE bound (o4 up to 6p, with exact
// pointAdd-style extremes), mirroring the signed wide ops, checking dividend>=0 & mod==noble.
// (uses BigInt exact mirror, not intervals)
// ===================================================================================
console.log('\n=== PART 5: numeric adversarial stress (exact signed mirror) ===');
const f2mW = (a0,a1,b0,b1) => { const w0=a0*b0, w1=a1*b1; return [w0-w1,(a0+a1)*(b0+b1)-w0-w1]; };
const f2xW = (a0,a1) => [9n*a0-a1, 9n*a1+a0];
function f6mW(a,b){const[a0a,a0b,a1a,a1b,a2a,a2b]=a,[b0a,b0b,b1a,b1b,b2a,b2b]=b;
  const[t0a,t0b]=f2mW(a0a,a0b,b0a,b0b),[t1a,t1b]=f2mW(a1a,a1b,b1a,b1b),[t2a,t2b]=f2mW(a2a,a2b,b2a,b2b);
  const[p1a,p1b]=f2mW(a1a+a2a,a1b+a2b,b1a+b2a,b1b+b2b),[x1a,x1b]=f2xW(p1a-t1a-t2a,p1b-t1b-t2b);
  const c0a=t0a+x1a,c0b=t0b+x1b;
  const[p2a,p2b]=f2mW(a0a+a1a,a0b+a1b,b0a+b1a,b0b+b1b),[x2a,x2b]=f2xW(t2a,t2b);
  const c1a=p2a-t0a-t1a+x2a,c1b=p2b-t0b-t1b+x2b;
  const[p3a,p3b]=f2mW(a0a+a2a,a0b+a2b,b0a+b2a,b0b+b2b);
  const c2a=p3a-t0a-t2a+t1a,c2b=p3b-t0b-t2b+t1b;
  return[c0a,c0b,c1a,c1b,c2a,c2b];}
const f6vWn=(a)=>{const[n0a,n0b]=f2xW(a[4],a[5]);return[n0a,n0b,a[0],a[1],a[2],a[3]];};
function f6m01(c,b0a,b0b,b1a,b1b){const[c0a,c0b,c1a,c1b,c2a,c2b]=c;
  const[t0a,t0b]=f2mW(c0a,c0b,b0a,b0b),[t1a,t1b]=f2mW(c1a,c1b,b1a,b1b);
  const[m12a,m12b]=f2mW(c1a+c2a,c1b+c2b,b1a,b1b),[xu0a,xu0b]=f2xW(m12a-t1a,m12b-t1b);
  const r0a=xu0a+t0a,r0b=xu0b+t0b;
  const[m1a,m1b]=f2mW(b0a+b1a,b0b+b1b,c0a+c1a,c0b+c1b);
  const r1a=m1a-t0a-t1a,r1b=m1b-t0b-t1b;
  const[m2a,m2b]=f2mW(c0a+c2a,c0b+c2b,b0a,b0b);
  const r2a=m2a-t0a+t1a,r2b=m2b-t0b+t1b;
  return[r0a,r0b,r1a,r1b,r2a,r2b];}
function pre034(F,o0a,o0b,o3a,o3b,o4a,o4b){
  const A0=f2mW(F[0],F[1],o0a,o0b),A2=f2mW(F[2],F[3],o0a,o0b),A4=f2mW(F[4],F[5],o0a,o0b);
  const A=[A0[0],A0[1],A2[0],A2[1],A4[0],A4[1]];
  const B=f6m01(F.slice(6,12),o3a,o3b,o4a,o4b);
  const S=[0,1,2,3,4,5].map(i=>F[i]+F[6+i]);
  const G=f6m01(S,o0a+o3a,o0b+o3b,o4a,o4b);
  const VB=f6vWn(B);
  const Clo=[0,1,2,3,4,5].map(i=>VB[i]+A[i]);
  const Chi=[0,1,2,3,4,5].map(i=>G[i]-A[i]-B[i]);
  return[...Clo,...Chi];
}
// noble-free reference: reduce each pre limb mod p and compare to a direct fp12 mul034 done in reduced field
const mod=(x)=>((x%P)+P)%P;
const F2m=(a0,a1,b0,b1)=>[mod(a0*b0-a1*b1),mod(a0*b1+a1*b0)];
const F2a=(a0,a1,b0,b1)=>[mod(a0+b0),mod(a1+b1)];
const F2xi=(a0,a1)=>[mod(9n*a0-a1),mod(9n*a1+a0)];
function F6m01(c,b0a,b0b,b1a,b1b){const[c0a,c0b,c1a,c1b,c2a,c2b]=c.map(mod);
  const t0=F2m(c0a,c0b,b0a,b0b),t1=F2m(c1a,c1b,b1a,b1b);
  const m12=F2m(mod(c1a+c2a),mod(c1b+c2b),b1a,b1b);
  const r0=F2a(...F2xi(mod(m12[0]-t1[0]),mod(m12[1]-t1[1])),t0[0],t0[1]);
  const m1=F2m(mod(b0a+b1a),mod(b0b+b1b),mod(c0a+c1a),mod(c0b+c1b));
  const r1=[mod(m1[0]-t0[0]-t1[0]),mod(m1[1]-t0[1]-t1[1])];
  const m2=F2m(mod(c0a+c2a),mod(c0b+c2b),b0a,b0b);
  const r2=[mod(m2[0]-t0[0]+t1[0]),mod(m2[1]-t0[1]+t1[1])];
  return[...r0,...r1,...r2];}
function refMul034(F,o0a,o0b,o3a,o3b,o4a,o4b){
  const Fr=F.map(mod), oo0a=mod(o0a),oo0b=mod(o0b),oo3a=mod(o3a),oo3b=mod(o3b),oo4a=mod(o4a),oo4b=mod(o4b);
  const A=[...F2m(Fr[0],Fr[1],oo0a,oo0b),...F2m(Fr[2],Fr[3],oo0a,oo0b),...F2m(Fr[4],Fr[5],oo0a,oo0b)];
  const B=F6m01(Fr.slice(6,12),oo3a,oo3b,oo4a,oo4b);
  const S=[0,1,2,3,4,5].map(i=>mod(Fr[i]+Fr[6+i]));
  const G=F6m01(S,mod(oo0a+oo3a),mod(oo0b+oo3b),oo4a,oo4b);
  const VB=[...F2xi(B[4],B[5]),B[0],B[1],B[2],B[3]];
  const Clo=[0,1,2,3,4,5].map(i=>mod(VB[i]+A[i]));
  const Chi=[0,1,2,3,4,5].map(i=>mod(G[i]-A[i]-B[i]));
  return[...Clo,...Chi];
}
let s=88172645463325252n;
const rnd=()=>{s^=s<<13n;s&=(1n<<64n)-1n;s^=s>>7n;s^=s<<17n;s&=(1n<<64n)-1n;return s;};
const rndFull=()=>{let x=0n;for(let k=0;k<4;k++)x=(x<<64n)|rnd();return x%P;};
let worstNeg=0n, minDiv=1n<<600n, divFail=0, fFail=0, N=0;
function check(pre,exp){N++;for(let i=0;i<12;i++){const d=pre[i]+BIAS;if(d<minDiv)minDiv=d;if(pre[i]<0n&&-pre[i]>worstNeg)worstNeg=-pre[i];if(d<0n)divFail++;if(mod(d)!==exp[i])fFail++;}}
// o4 pushed to the TRUE pointAdd extreme: up to 6p (both components), F in [0,p), o0,o3 in [0,p)
for(let t=0;t<200000;t++){
  const F=Array.from({length:12},()=>rndFull());
  const o0a=rndFull(),o0b=rndFull(),o3a=rndFull(),o3b=rndFull();
  // o4 in [0,6p): rndFull()+{0..5}p, plus occasional exact 6p-epsilon corners
  const o4a=rndFull()+(rnd()%6n)*P, o4b=rndFull()+(rnd()%6n)*P;
  check(pre034(F,o0a,o0b,o3a,o3b,o4a,o4b), refMul034(F,o0a,o0b,o3a,o3b,o4a,o4b));
}
// hard corners: F all (p-1), o0/o3 (p-1), o4 = 6p-1 (max) and exactly 6p
for(const o4 of [6n*P-1n, 6n*P, 5n*P+(P-1n)]){
  check(pre034(Array(12).fill(P-1n),P-1n,P-1n,P-1n,P-1n,o4,o4), refMul034(Array(12).fill(P-1n),P-1n,P-1n,P-1n,P-1n,o4,o4));
  check(pre034(Array(12).fill(P-1n),0n,0n,0n,0n,o4,o4), refMul034(Array(12).fill(P-1n),0n,0n,0n,0n,o4,o4));
}
console.log(`  stressed ${N} mul034 inputs (${N*12} limbs), o4 in [0,6p]`);
console.log(`  worst |neg| = ${worstNeg} (~${(Number(worstNeg)/Number(P*P)).toFixed(1)} p^2)`);
console.log(`  min dividend (pre+bias) = ${minDiv}  ${minDiv>=0n?'>=0 OK':'<0 UNSOUND'}`);
console.log(`  dividend<0 fails = ${divFail}   mod!=ref fails = ${fFail}`);
console.log(divFail===0&&fFail===0 ? '  RESULT: SOUND at o4<=6p under deployed bias' : '  RESULT: *** UNSOUND ***');
