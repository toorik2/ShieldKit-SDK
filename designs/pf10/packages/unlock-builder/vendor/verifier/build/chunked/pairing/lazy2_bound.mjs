// Sound interval-bound pass for a FULLY-DELAYED-REDUCTION fp12Sqr.
// Carries signed wide values (no per-op reduction/bias); computes, for each of the 12 output
// limbs, the exact integer interval [lo,hi] over inputs in [0,p). The needed pre-mod bias is
// BIG*p with BIG*p >= -min(lo) so (x + BIG*p) is always >= 0. Prints BIG (units of p) and the
// max dividend byte-width so we can size the constant. All arithmetic mirrors the .cash ops
// EXACTLY (same Karatsuba fp6Mul, same complex fp12Sqr schedule).
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

// interval helpers (BigInt)
const I = (lo, hi) => ({ lo, hi });
const add = (a, b) => I(a.lo + b.lo, a.hi + b.hi);
const sub = (a, b) => I(a.lo - b.hi, a.hi - b.lo);
const mul = (a, b) => { const c = [a.lo * b.lo, a.lo * b.hi, a.hi * b.lo, a.hi * b.hi]; return I(c.reduce((m, x) => x < m ? x : m), c.reduce((m, x) => x > m ? x : m)); };
const smul = (k, a) => k >= 0n ? I(k * a.lo, k * a.hi) : I(k * a.hi, k * a.lo);

// fp2 as [c0,c1] of intervals
const f2add = (a, b) => [add(a[0], b[0]), add(a[1], b[1])];
const f2sub = (a, b) => [sub(a[0], b[0]), sub(a[1], b[1])];
const f2mul = (a, b) => {
  const w0 = mul(a[0], b[0]), w1 = mul(a[1], b[1]);
  const r0 = sub(w0, w1);
  const r1 = sub(mul(add(a[0], a[1]), add(b[0], b[1])), add(w0, w1));
  return [r0, r1];
};
const f2mulxi = (a) => [sub(smul(9n, a[0]), a[1]), add(smul(9n, a[1]), a[0])]; // (9+u)*a

// fp6 as [c0,c1,c2] of fp2
const f6add = (a, b) => [f2add(a[0], b[0]), f2add(a[1], b[1]), f2add(a[2], b[2])];
const f6sub = (a, b) => [f2sub(a[0], b[0]), f2sub(a[1], b[1]), f2sub(a[2], b[2])];
const f6mulbyv = (a) => [f2mulxi(a[2]), a[0], a[1]];
const f6mul = (a, b) => {
  const t0 = f2mul(a[0], b[0]), t1 = f2mul(a[1], b[1]), t2 = f2mul(a[2], b[2]);
  const s1 = f2add(a[1], a[2]), s2 = f2add(b[1], b[2]);
  const p1 = f2mul(s1, s2);
  const d2 = f2sub(f2sub(p1, t1), t2);
  const x1 = f2mulxi(d2);
  const c0 = f2add(t0, x1);
  const s3 = f2add(a[0], a[1]), s4 = f2add(b[0], b[1]);
  const p2 = f2mul(s3, s4);
  const d4 = f2sub(f2sub(p2, t0), t1);
  const x2 = f2mulxi(t2);
  const c1 = f2add(d4, x2);
  const s5 = f2add(a[0], a[2]), s6 = f2add(b[0], b[2]);
  const p3 = f2mul(s5, s6);
  const d6 = f2sub(f2sub(p3, t0), t2);
  const c2 = f2add(d6, t1);
  return [c0, c1, c2];
};

// fp12 = [lo(fp6), hi(fp6)], complex squaring (matches current fp12Sqr)
function fp12SqrLazy(A) {
  const lo = [A[0], A[1], A[2]], hi = [A[3], A[4], A[5]];
  const t0 = f6mul(lo, hi);
  const s = f6add(lo, hi);
  const vc = f6mulbyv(hi);
  const u = f6add(lo, vc);
  const t1 = f6mul(s, u);
  const Chi = f6add(t0, t0);           // C6..11
  const vt0 = f6mulbyv(t0);
  const d = f6sub(t1, t0);
  const Clo = f6sub(d, vt0);           // C0..5
  // flatten to 12 limbs
  const flat6 = (f) => [f[0][0], f[0][1], f[1][0], f[1][1], f[2][0], f[2][1]];
  return [...flat6(Clo), ...flat6(Chi)];
}

const inp = I(0n, P - 1n);
const A = [[inp, inp], [inp, inp], [inp, inp], [inp, inp], [inp, inp], [inp, inp]]; // 6 fp2 = 12 limbs
const outs = fp12SqrLazy(A);
let maxNeg = 0n, maxAbs = 0n;
outs.forEach((o, i) => {
  const neg = o.lo < 0n ? -o.lo : 0n;
  if (neg > maxNeg) maxNeg = neg;
  const a = o.hi > 0n ? o.hi : 0n;
  const b = o.lo < 0n ? -o.lo : 0n;
  const m = a > b ? a : b;
  if (m > maxAbs) maxAbs = m;
});
const BIG = maxNeg / P + 1n;                 // BIG*p >= maxNeg
const dividendMax = maxAbs + BIG * P;
const byteLen = (x) => { let n = x < 0n ? -x : x; let b = 1; while (n >= 128n) { n >>= 8n; b++; } return b; };
console.log('max |neg| pre-reduce =', maxNeg.toString(), `(~${(Number(maxNeg) / Number(P * P)).toFixed(1)} p^2)`);
console.log('BIG (units of p)    =', BIG.toString(), `(byteLen BIG*p = ${byteLen(BIG * P)})`);
console.log('max dividend byteLen=', byteLen(dividendMax));
console.log('BIGxP constant      =', (BIG * P).toString());
