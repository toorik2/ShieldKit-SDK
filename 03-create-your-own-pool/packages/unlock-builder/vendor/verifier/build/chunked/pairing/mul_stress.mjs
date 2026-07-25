// Soundness stress for V3 delayed-reduction fp12Mul and mul034.
// 1) Independently compute the SIGNED pre-reduction limb values (exact BigInt mirror of the .cash)
//    over many inputs (random + adversarial corners) and confirm none is below -BIG*p  => the mod
//    dividend (x+BIG*p) is always >= 0 => reduceOut lands in [0,p). Non-forgery gate.
// 2) Confirm reduceOut(pre) === noble reference (Fp12.mul / mul034) mod p for every case.
import { Fp2, Fp6, Fp12, Fp } from './_millermath.mjs';
const P = Fp.ORDER;
const BIGxP = 473346033904423368332684188674078595909661288732727612567210428627021252562119744690866504404556704362571480480121380658603450849396234800254307144706265583n;

// --- exact signed BigInt mirror of the V3 wide ops ---
const f2mulW = (a0, a1, b0, b1) => { const w0 = a0 * b0, w1 = a1 * b1; return [w0 - w1, (a0 + a1) * (b0 + b1) - w0 - w1]; };
const f2xiW = (a0, a1) => [9n * a0 - a1, 9n * a1 + a0];
function f6mulW(a, b) {
  const [a0a, a0b, a1a, a1b, a2a, a2b] = a, [b0a, b0b, b1a, b1b, b2a, b2b] = b;
  const [t0a, t0b] = f2mulW(a0a, a0b, b0a, b0b);
  const [t1a, t1b] = f2mulW(a1a, a1b, b1a, b1b);
  const [t2a, t2b] = f2mulW(a2a, a2b, b2a, b2b);
  const [p1a, p1b] = f2mulW(a1a + a2a, a1b + a2b, b1a + b2a, b1b + b2b);
  const [x1a, x1b] = f2xiW(p1a - t1a - t2a, p1b - t1b - t2b);
  const c0a = t0a + x1a, c0b = t0b + x1b;
  const [p2a, p2b] = f2mulW(a0a + a1a, a0b + a1b, b0a + b1a, b0b + b1b);
  const [x2a, x2b] = f2xiW(t2a, t2b);
  const c1a = p2a - t0a - t1a + x2a, c1b = p2b - t0b - t1b + x2b;
  const [p3a, p3b] = f2mulW(a0a + a2a, a0b + a2b, b0a + b2a, b0b + b2b);
  const c2a = p3a - t0a - t2a + t1a, c2b = p3b - t0b - t2b + t1b;
  return [c0a, c0b, c1a, c1b, c2a, c2b];
}
const f6vW = (a) => { const [n0a, n0b] = f2xiW(a[4], a[5]); return [n0a, n0b, a[0], a[1], a[2], a[3]]; };
function f6mul01W(c, b0a, b0b, b1a, b1b) {
  const [c0a, c0b, c1a, c1b, c2a, c2b] = c;
  const [t0a, t0b] = f2mulW(c0a, c0b, b0a, b0b);
  const [t1a, t1b] = f2mulW(c1a, c1b, b1a, b1b);
  const [m12a, m12b] = f2mulW(c1a + c2a, c1b + c2b, b1a, b1b);
  const [xu0a, xu0b] = f2xiW(m12a - t1a, m12b - t1b);
  const r0a = xu0a + t0a, r0b = xu0b + t0b;
  const [m1a, m1b] = f2mulW(b0a + b1a, b0b + b1b, c0a + c1a, c0b + c1b);
  const r1a = m1a - t0a - t1a, r1b = m1b - t0b - t1b;
  const [m2a, m2b] = f2mulW(c0a + c2a, c0b + c2b, b0a, b0b);
  const r2a = m2a - t0a + t1a, r2b = m2b - t0b + t1b;
  return [r0a, r0b, r1a, r1b, r2a, r2b];
}
function preMul(A, B) {
  const Alo = A.slice(0, 6), Ahi = A.slice(6, 12), Blo = B.slice(0, 6), Bhi = B.slice(6, 12);
  const t0 = f6mulW(Alo, Blo), t1 = f6mulW(Ahi, Bhi), vt = f6vW(t1);
  const sa = Alo.map((x, i) => x + Ahi[i]), sb = Blo.map((x, i) => x + Bhi[i]);
  const pr = f6mulW(sa, sb);
  const Clo = [0, 1, 2, 3, 4, 5].map(i => t0[i] + vt[i]);
  const Chi = [0, 1, 2, 3, 4, 5].map(i => pr[i] - t0[i] - t1[i]);
  return [...Clo, ...Chi];
}
function pre034(F, o0a, o0b, o3a, o3b, o4a, o4b) {
  const A0 = f2mulW(F[0], F[1], o0a, o0b), A2 = f2mulW(F[2], F[3], o0a, o0b), A4 = f2mulW(F[4], F[5], o0a, o0b);
  const A = [A0[0], A0[1], A2[0], A2[1], A4[0], A4[1]];
  const B = f6mul01W(F.slice(6, 12), o3a, o3b, o4a, o4b);
  const S = [0, 1, 2, 3, 4, 5].map(i => F[i] + F[6 + i]);
  const G = f6mul01W(S, o0a + o3a, o0b + o3b, o4a, o4b);
  const VB = f6vW(B);
  const Clo = [0, 1, 2, 3, 4, 5].map(i => VB[i] + A[i]);
  const Chi = [0, 1, 2, 3, 4, 5].map(i => G[i] - A[i] - B[i]);
  return [...Clo, ...Chi];
}

// --- noble references ---
const mk2 = (a, b) => ({ c0: ((a % P) + P) % P, c1: ((b % P) + P) % P });
const toF12 = (L) => ({ c0: { c0: mk2(L[0], L[1]), c1: mk2(L[2], L[3]), c2: mk2(L[4], L[5]) }, c1: { c0: mk2(L[6], L[7]), c1: mk2(L[8], L[9]), c2: mk2(L[10], L[11]) } });
const flat = (f) => [f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0, f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1];
const nobleMul = (A, B) => flat(Fp12.mul(toF12(A), toF12(B)));
function nobleMul034(F, o0a, o0b, o3a, o3b, o4a, o4b) {
  const f = toF12(F);
  const o0 = mk2(o0a, o0b), o3 = mk2(o3a, o3b), o4 = mk2(o4a, o4b);
  const A = Fp6.create({ c0: Fp2.mul(f.c0.c0, o0), c1: Fp2.mul(f.c0.c1, o0), c2: Fp2.mul(f.c0.c2, o0) });
  const B = Fp6.mul01(f.c1, o3, o4);
  const E = Fp6.mul01(Fp6.add(f.c0, f.c1), Fp2.add(o0, o3), o4);
  const res = Fp12.create({ c0: Fp6.add(Fp6.mulByNonresidue(B), A), c1: Fp6.sub(E, Fp6.add(A, B)) });
  return flat(res);
}

// --- rng ---
let s = 88172645463325252n;
const rnd = () => { s ^= s << 13n; s &= (1n << 64n) - 1n; s ^= s >> 7n; s ^= s << 17n; s &= (1n << 64n) - 1n; return s; };
const rndFull = () => { let x = 0n; for (let k = 0; k < 4; k++) x = (x << 64n) | rnd(); return x % P; };
const corners = [0n, 1n, 2n, P - 1n, P - 2n];
const rndCorner = () => corners[Number(rnd() % 5n)];

let minDiv = 1n << 600n, worstNeg = 0n, formulaFails = 0, divFails = 0, n = 0;
function checkLimbs(pre, exp) {
  n++;
  for (let i = 0; i < 12; i++) {
    const div = pre[i] + BIGxP;
    if (div < minDiv) minDiv = div;
    if (pre[i] < 0n && -pre[i] > worstNeg) worstNeg = -pre[i];
    if (div < 0n) divFails++;
    const red = ((div % P) + P) % P;
    if (red !== exp[i]) formulaFails++;
  }
}

// === fp12Mul battery: A,B in [0,p), random + corners ===
for (let t = 0; t < 3000; t++) {
  const A = Array.from({ length: 12 }, () => rndFull()), B = Array.from({ length: 12 }, () => rndFull());
  checkLimbs(preMul(A, B), nobleMul(A, B));
}
for (let t = 0; t < 800; t++) {
  const A = Array.from({ length: 12 }, () => rndCorner()), B = Array.from({ length: 12 }, () => rndCorner());
  checkLimbs(preMul(A, B), nobleMul(A, B));
}
// structured corners
checkLimbs(preMul(Array(12).fill(P - 1n), Array(12).fill(P - 1n)), nobleMul(Array(12).fill(P - 1n), Array(12).fill(P - 1n)));
checkLimbs(preMul(Array(12).fill(0n), Array(12).fill(P - 1n)), nobleMul(Array(12).fill(0n), Array(12).fill(P - 1n)));
const altHi = Array.from({ length: 12 }, (_, i) => i % 2 ? P - 1n : 0n);
checkLimbs(preMul(altHi, altHi), nobleMul(altHi, altHi));
const mulCases = n;
console.log(`fp12Mul: ${n} inputs (${n * 12} limbs) tested vs noble Fp12.mul`);

// === mul034 battery A: all inputs in [0,p) ===
const nMulSnap = n;
for (let t = 0; t < 3000; t++) {
  const F = Array.from({ length: 12 }, () => rndFull());
  const o = Array.from({ length: 6 }, () => rndFull());
  checkLimbs(pre034(F, ...o), nobleMul034(F, ...o));
}
for (let t = 0; t < 800; t++) {
  const F = Array.from({ length: 12 }, () => rndCorner());
  const o = Array.from({ length: 6 }, () => rndCorner());
  checkLimbs(pre034(F, ...o), nobleMul034(F, ...o));
}
// === mul034 battery B: SOUND Miller drop-in — o4 unreduced up to 4p (raw line c0) ===
for (let t = 0; t < 3000; t++) {
  const F = Array.from({ length: 12 }, () => rndFull());
  const o0a = rndFull(), o0b = rndFull(), o3a = rndFull(), o3b = rndFull();
  const o4a = rndFull() + (rnd() % 5n) * P, o4b = rndFull() + (rnd() % 5n) * P; // 0..~5p
  checkLimbs(pre034(F, o0a, o0b, o3a, o3b, o4a, o4b), nobleMul034(F, o0a, o0b, o3a, o3b, o4a, o4b));
}
// corner: o4 exactly 4p-ish with extremal F
checkLimbs(pre034(Array(12).fill(P - 1n), P - 1n, P - 1n, P - 1n, P - 1n, 4n * P, 4n * P),
           nobleMul034(Array(12).fill(P - 1n), P - 1n, P - 1n, P - 1n, P - 1n, 4n * P, 4n * P));
console.log(`mul034 : ${n - mulCases} inputs (${(n - mulCases) * 12} limbs) tested vs noble mul034 (incl. o4 up to ~5p Miller range)`);

console.log(`\ntotal cases: ${n * 12} limbs across ${n} inputs`);
console.log(`worst observed |neg pre-reduce| = ${worstNeg} (~${(Number(worstNeg) / Number(P * P)).toFixed(1)} p^2)`);
console.log(`min dividend (pre+BIGxP)        = ${minDiv}  (>=0 required)`);
console.log(`dividend<0 failures = ${divFails}   formula(mod p mismatch vs noble) failures = ${formulaFails}`);
console.log(divFails === 0 && formulaFails === 0 ? 'SOUND: all dividends >=0 AND all limbs match noble mod p' : 'UNSOUND -- INVESTIGATE');
