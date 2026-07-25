// Sound interval-bound pass for FULLY-DELAYED-REDUCTION fp12Mul and mul034.
// Carries signed wide values (no per-op reduction/bias); computes, for each of the 12 output
// limbs, the exact integer interval [lo,hi]. The needed pre-mod bias is BIG*p with
// BIG*p >= -min(lo) so (x + BIG*p) is always >= 0 => reduceOut lands in [0,p). All arithmetic
// mirrors the V3 .cash ops EXACTLY (same Karatsuba fp6MulW, fp6Mul01W, complex fp12Mul / mul034).
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

const I = (lo, hi) => ({ lo, hi });
const add = (a, b) => I(a.lo + b.lo, a.hi + b.hi);
const sub = (a, b) => I(a.lo - b.hi, a.hi - b.lo);
const mul = (a, b) => { const c = [a.lo * b.lo, a.lo * b.hi, a.hi * b.lo, a.hi * b.hi]; return I(c.reduce((m, x) => x < m ? x : m), c.reduce((m, x) => x > m ? x : m)); };
const smul = (k, a) => k >= 0n ? I(k * a.lo, k * a.hi) : I(k * a.hi, k * a.lo);

// fp2 as [c0,c1] of intervals
const f2add = (a, b) => [add(a[0], b[0]), add(a[1], b[1])];
const f2sub = (a, b) => [sub(a[0], b[0]), sub(a[1], b[1])];
const f2mulW = (a, b) => {
  const w0 = mul(a[0], b[0]), w1 = mul(a[1], b[1]);
  const r0 = sub(w0, w1);
  const r1 = sub(mul(add(a[0], a[1]), add(b[0], b[1])), add(w0, w1));
  return [r0, r1];
};
const f2xiW = (a) => [sub(smul(9n, a[0]), a[1]), add(smul(9n, a[1]), a[0])]; // (9+u)*a

// fp6 as [c0,c1,c2] of fp2
const f6add = (a, b) => [f2add(a[0], b[0]), f2add(a[1], b[1]), f2add(a[2], b[2])];
const f6sub = (a, b) => [f2sub(a[0], b[0]), f2sub(a[1], b[1]), f2sub(a[2], b[2])];
const f6mulbyvW = (a) => [f2xiW(a[2]), a[0], a[1]];
const f6mulW = (a, b) => {
  const t0 = f2mulW(a[0], b[0]), t1 = f2mulW(a[1], b[1]), t2 = f2mulW(a[2], b[2]);
  const s1 = f2add(a[1], a[2]), s2 = f2add(b[1], b[2]);
  const p1 = f2mulW(s1, s2);
  const d2 = f2sub(f2sub(p1, t1), t2);
  const x1 = f2xiW(d2);
  const c0 = f2add(t0, x1);
  const s3 = f2add(a[0], a[1]), s4 = f2add(b[0], b[1]);
  const p2 = f2mulW(s3, s4);
  const d4 = f2sub(f2sub(p2, t0), t1);
  const x2 = f2xiW(t2);
  const c1 = f2add(d4, x2);
  const s5 = f2add(a[0], a[2]), s6 = f2add(b[0], b[2]);
  const p3 = f2mulW(s5, s6);
  const d6 = f2sub(f2sub(p3, t0), t2);
  const c2 = f2add(d6, t1);
  return [c0, c1, c2];
};
// wide fp6Mul01: c is fp6 [c0,c1,c2], b0/b1 are fp2
const f6mul01W = (c, b0, b1) => {
  const t0 = f2mulW(c[0], b0);
  const t1 = f2mulW(c[1], b1);
  const s12 = f2add(c[1], c[2]);
  const m12 = f2mulW(s12, b1);
  const u0 = f2sub(m12, t1);
  const xu0 = f2xiW(u0);
  const r0 = f2add(xu0, t0);
  const sb = f2add(b0, b1);
  const sc = f2add(c[0], c[1]);
  const m1 = f2mulW(sb, sc);
  const u1 = f2sub(m1, t0);
  const r1 = f2sub(u1, t1);
  const s02 = f2add(c[0], c[2]);
  const m2 = f2mulW(s02, b0);
  const u2 = f2sub(m2, t0);
  const r2 = f2add(u2, t1);
  return [r0, r1, r2];
};

const flat6 = (f) => [f[0][0], f[0][1], f[1][0], f[1][1], f[2][0], f[2][1]];
const pair = (fp6) => [[fp6[0], fp6[1]], [fp6[2], fp6[3]], [fp6[4], fp6[5]]];

function fp12MulLazy(A, B) { // A,B: 6 fp2 each (12 limbs)
  const Alo = A.slice(0, 3), Ahi = A.slice(3, 6);
  const Blo = B.slice(0, 3), Bhi = B.slice(3, 6);
  const t0 = f6mulW(Alo, Blo);
  const t1 = f6mulW(Ahi, Bhi);
  const vt = f6mulbyvW(t1);
  const Clo = f6add(t0, vt);
  const sa = f6add(Alo, Ahi);
  const sb = f6add(Blo, Bhi);
  const pr = f6mulW(sa, sb);
  const qq = f6sub(pr, t0);
  const Chi = f6sub(qq, t1);
  return [...flat6(Clo), ...flat6(Chi)];
}

function mul034Lazy(F, o0, o3, o4) { // F: 6 fp2 (12 limbs); o0,o3,o4: fp2
  const Flo = F.slice(0, 3), Fhi = F.slice(3, 6);
  const A0 = f2mulW(F[0], o0), A1 = f2mulW(F[1], o0), A2 = f2mulW(F[2], o0);
  const A = [A0, A1, A2];
  const B = f6mul01W(Fhi, o3, o4);
  const S = f6add(Flo, Fhi);
  const qa = f2add(o0, o3);
  const G = f6mul01W(S, qa, o4);
  const VB = f6mulbyvW(B);
  const Clo = f6add(VB, A);
  const AB = f6add(A, B);
  const Chi = f6sub(G, AB);
  return [...flat6(Clo), ...flat6(Chi)];
}

const byteLen = (x) => { let n = x < 0n ? -x : x; let b = 1; while (n >= 128n) { n >>= 8n; b++; } return b; };
function report(name, outs) {
  let maxNeg = 0n, maxAbs = 0n;
  outs.forEach((o) => {
    const neg = o.lo < 0n ? -o.lo : 0n;
    if (neg > maxNeg) maxNeg = neg;
    const a = o.hi > 0n ? o.hi : 0n;
    const b = o.lo < 0n ? -o.lo : 0n;
    const m = a > b ? a : b;
    if (m > maxAbs) maxAbs = m;
  });
  const BIG = maxNeg / P + 1n;
  const dividendMax = maxAbs + BIG * P;
  console.log(`\n=== ${name} ===`);
  console.log('max |neg| pre-reduce =', maxNeg.toString(), `(~${(Number(maxNeg) / Number(P * P)).toFixed(1)} p^2)`);
  console.log('BIG (units of p)    =', BIG.toString(), `(byteLen BIG*p = ${byteLen(BIG * P)})`);
  console.log('max dividend byteLen=', byteLen(dividendMax));
  console.log('BIGxP constant      =', (BIG * P).toString());
  return BIG;
}

// --- fp12Mul : both inputs fully reduced in [0,p) ---
const inpP = I(0n, P - 1n);
const A = Array.from({ length: 6 }, () => [inpP, inpP]);
const B = Array.from({ length: 6 }, () => [inpP, inpP]);
report('fp12Mul  (A,B in [0,p))', fp12MulLazy(A, B));

// --- mul034 (noble-comparison contract): all inputs reduced [0,p) ---
const F = Array.from({ length: 6 }, () => [inpP, inpP]);
report('mul034   (F,o0,o3,o4 in [0,p))', mul034Lazy(F, [inpP, inpP], [inpP, inpP], [inpP, inpP]));

// --- mul034 (SOUND Miller drop-in contract): F,o0,o3 in [0,p); o4 in [0,4p] (raw line c0) ---
const inp4 = I(0n, 4n * P);
report('mul034   Miller drop-in (o4 in [0,4p])', mul034Lazy(F, [inpP, inpP], [inpP, inpP], [inp4, inp4]));
