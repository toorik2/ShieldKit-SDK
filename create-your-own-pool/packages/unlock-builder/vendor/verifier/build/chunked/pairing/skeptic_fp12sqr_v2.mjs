// FRESH adversarial verification of lazy fp12Sqr (V2_miller_lib.cash), correctness lens.
//  P1: JS wide-mirror == COMPILED .cash fp12Sqr (raw output identity, incl. large inputs) -> op is BUILT.
//  P2: residue differential lazy vs NOBLE at random/corner/Miller-regime/beyond  (mismatch => refuted).
//  P3: REAL lazy Miller loop (4 committed + random pairs): actual fp12Sqr input magnitudes + canonical/residue.
//  P4: HARD adversarial coordinate-ascent for a REACHABLE non-canonical output (fp12Sqr input = mul034 out).
import { compileString, utils } from 'cashc';
import { readFileSync } from 'node:fs';
import { measureRun } from '/home/toorik/Projects/LeanBCH/optimizer/cost.mjs';
import { bigIntToVmNumber } from '@bitauth/libauth';
import { Fp12, Fp2, Fp6, Fp, bn254, ATE_NAF, pointDouble, pointAdd } from './_millermath.mjs';

const P = Fp.ORDER;
const BIAS = 202944716560641436058426135953785114602563281282574308384079289034824091685549821404793712422553157789241740953812104359610149043919352694135649979132063988983n;
const mod = (x) => ((x % P) + P) % P;

// ---- EXACT wide lazy mirror of V2_miller_lib.cash fp12Sqr (pre-reduction 12 wide limbs) ----
const f2mW = (a0, a1, b0, b1) => { const w0 = a0 * b0, w1 = a1 * b1; return [w0 - w1, (a0 + a1) * (b0 + b1) - w0 - w1]; };
const f2xW = (a0, a1) => [9n * a0 - a1, 9n * a1 + a0];
const f6vW = (a) => { const [n0, n1] = f2xW(a[4], a[5]); return [n0, n1, a[0], a[1], a[2], a[3]]; };
function f6mW(a, b) {
  const [t0a, t0b] = f2mW(a[0], a[1], b[0], b[1]);
  const [t1a, t1b] = f2mW(a[2], a[3], b[2], b[3]);
  const [t2a, t2b] = f2mW(a[4], a[5], b[4], b[5]);
  const [p1a, p1b] = f2mW(a[2] + a[4], a[3] + a[5], b[2] + b[4], b[3] + b[5]);
  const [x1a, x1b] = f2xW(p1a - t1a - t2a, p1b - t1b - t2b);
  const c0a = t0a + x1a, c0b = t0b + x1b;
  const [p2a, p2b] = f2mW(a[0] + a[2], a[1] + a[3], b[0] + b[2], b[1] + b[3]);
  const [x2a, x2b] = f2xW(t2a, t2b);
  const c1a = p2a - t0a - t1a + x2a, c1b = p2b - t0b - t1b + x2b;
  const [p3a, p3b] = f2mW(a[0] + a[4], a[1] + a[5], b[0] + b[4], b[1] + b[5]);
  const c2a = p3a - t0a - t2a + t1a, c2b = p3b - t0b - t2b + t1b;
  return [c0a, c0b, c1a, c1b, c2a, c2b];
}
function fp12SqrPre(A) {
  const lo = [A[0], A[1], A[2], A[3], A[4], A[5]], hi = [A[6], A[7], A[8], A[9], A[10], A[11]];
  const t0 = f6mW(lo, hi);
  const vc = f6vW(hi);
  const u = lo.map((x, i) => x + vc[i]);
  const s = lo.map((x, i) => x + hi[i]);
  const t1 = f6mW(s, u);
  const vt0 = f6vW(t0);
  const Clo = [0, 1, 2, 3, 4, 5].map((i) => t1[i] - t0[i] - vt0[i]);
  const Chi = [0, 1, 2, 3, 4, 5].map((i) => t0[i] + t0[i]);
  return [...Clo, ...Chi];
}
const reduceOut = (x) => (x + BIAS) % P; // JS % = truncated mod = BCH OP_MOD sign-of-dividend
const fp12SqrLazy = (A) => fp12SqrPre(A).map(reduceOut);

// ---- noble reference ----
const mk2 = (a, b) => Fp2.fromBigTuple([mod(a), mod(b)]);
const toF12 = (L) => Fp12.create({
  c0: Fp6.create({ c0: mk2(L[0], L[1]), c1: mk2(L[2], L[3]), c2: mk2(L[4], L[5]) }),
  c1: Fp6.create({ c0: mk2(L[6], L[7]), c1: mk2(L[8], L[9]), c2: mk2(L[10], L[11]) }),
});
const limbsOf = (f) => [f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0, f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1];
const nobleSqr = (L) => limbsOf(Fp12.sqr(toF12(L)));

// ---- EXACT wide lazy mirror of mul034/line (V2_miller_lib.cash; = a1_line.mjs, 0 residue mismatch) ----
const mulFp = (x, y) => mod(x * y);
const sub = (x, y, k) => x - y + BigInt(k) * P;
const f2mul = (a0, a1, b0, b1) => { const v0 = mulFp(a0, b0), v1 = mulFp(a1, b1); return [sub(v0, v1, 1), sub(mulFp(a0 + a1, b0 + b1), v0 + v1, 2)]; };
const f2xi = (a0, a1, k) => [sub(mulFp(9n, a0), a1, k), mulFp(9n, a1) + a0];
function f6mul01(c0a, c0b, c1a, c1b, c2a, c2b, b0a, b0b, b1a, b1b) {
  const [t0a, t0b] = f2mul(c0a, c0b, b0a, b0b), [t1a, t1b] = f2mul(c1a, c1b, b1a, b1b);
  const [m12a, m12b] = f2mul(c1a + c2a, c1b + c2b, b1a, b1b);
  const [xu0a, xu0b] = f2xi(sub(m12a, t1a, 3), sub(m12b, t1b, 3), 6);
  const r0a = xu0a + t0a, r0b = xu0b + t0b;
  const [m1a, m1b] = f2mul(b0a + b1a, b0b + b1b, c0a + c1a, c0b + c1b);
  const r1a = sub(sub(m1a, t0a, 3), t1a, 3), r1b = sub(sub(m1b, t0b, 3), t1b, 3);
  const [m2a, m2b] = f2mul(c0a + c2a, c0b + c2b, b0a, b0b);
  const r2a = sub(m2a, t0a, 3) + t1a, r2b = sub(m2b, t0b, 3) + t1b;
  return [r0a, r0b, r1a, r1b, r2a, r2b];
}
function mul034(F, o0a, o0b, o3a, o3b, o4a, o4b) {
  const [A0, A1] = f2mul(F[0], F[1], o0a, o0b), [A2, A3] = f2mul(F[2], F[3], o0a, o0b), [A4, A5] = f2mul(F[4], F[5], o0a, o0b);
  const B = f6mul01(F[6], F[7], F[8], F[9], F[10], F[11], o3a, o3b, o4a, o4b);
  const S = [F[0] + F[6], F[1] + F[7], F[2] + F[8], F[3] + F[9], F[4] + F[10], F[5] + F[11]];
  const G = f6mul01(S[0], S[1], S[2], S[3], S[4], S[5], o0a + o3a, o0b + o3b, o4a, o4b);
  const [VB0, VB1] = f2xi(B[4], B[5], 9); const VB = [VB0, VB1, B[0], B[1], B[2], B[3]];
  const A = [A0, A1, A2, A3, A4, A5];
  const C = VB.map((v, i) => v + A[i]);
  const AB = A.map((v, i) => v + B[i]);
  const Chi = [0, 1, 2, 3, 4, 5].map((i) => sub(G[i], AB[i], 12));
  return [...C, ...Chi];
}
// noble mul034 for residue-of-line check
function nobleMul034(fL, o0, o3, o4) {
  const f = toF12(fL);
  const A = Fp6.create({ c0: Fp2.mul(f.c0.c0, o0), c1: Fp2.mul(f.c0.c1, o0), c2: Fp2.mul(f.c0.c2, o0) });
  const B = Fp6.mul01(f.c1, o3, o4);
  const E = Fp6.mul01(Fp6.add(f.c0, f.c1), Fp2.add(o0, o3), o4);
  const r = Fp12.create({ c0: Fp6.add(Fp6.mulByNonresidue(B), A), c1: Fp6.sub(E, Fp6.add(A, B)) });
  return limbsOf(r);
}

// PRNG
let s = 0xDEADBEEF12345n;
const rnd = () => { s ^= s << 13n; s &= (1n << 64n) - 1n; s ^= s >> 7n; s ^= s << 17n; s &= (1n << 64n) - 1n; return s; };
const rBig = () => { let x = 0n; for (let k = 0; k < 4; k++) x = (x << 64n) | rnd(); return x; };
const rRange = (M) => rBig() % (M + 1n); // in [0,M]

// =============================================================================
console.log('=== P1: JS mirror vs COMPILED V2_miller_lib.cash fp12Sqr (RAW output identity) ===');
const LIB = readFileSync('./variants/V2_miller_lib.cash', 'utf8');
const push = (n) => { const d = bigIntToVmNumber(n); return Uint8Array.from([d.length, ...d]); };
const unlockFor = (a) => Uint8Array.from([...a].reverse().flatMap((x) => [...push(x)]));
const RESCHED = { rescheduleStacks: true };
function compiledEqualsMirror(L) {
  const mine = fp12SqrLazy(L);
  const checks = mine.map((e, i) => `b${i} == ${e}`).join(' &&\n      ');
  const src = `pragma cashscript ^0.14.0;\n${LIB}\ncontract B(){function run(int a0,int a1,int a2,int a3,int a4,int a5,int a6,int a7,int a8,int a9,int a10,int a11){int b0,int b1,int b2,int b3,int b4,int b5,int b6,int b7,int b8,int b9,int b10,int b11=fp12Sqr(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11);require(\n      ${checks});}}`;
  const bc = utils.asmToBytecode(compileString(src, RESCHED).bytecode);
  return { ok: measureRun(bc, unlockFor(L)).ok, mine };
}
const cases = [];
for (let i = 0; i < 5; i++) cases.push([`rand[0,p)#${i}`, Array.from({ length: 12 }, () => rBig() % P)]);
cases.push(['all(p-1)', Array.from({ length: 12 }, () => P - 1n)]);
cases.push(['all 0', Array.from({ length: 12 }, () => 0n)]);
for (const k of [17, 18, 19, 20, 21, 22]) cases.push([`rand[0,${k}p)`, Array.from({ length: 12 }, () => rRange(BigInt(k) * P))]);
cases.push(['alt 21p/0', Array.from({ length: 12 }, (_, i) => i % 2 ? 21n * P - 1n : 0n)]);
let p1fail = 0;
for (const [tag, L] of cases) {
  const { ok, mine } = compiledEqualsMirror(L);
  if (!ok) p1fail++;
  const canonical = mine.every((v) => v >= 0n && v < P);
  const inMax = L.reduce((m, v) => v > m ? v : m, 0n);
  console.log(`  ${ok ? 'OK ' : 'MISMATCH'} ${tag.padEnd(12)} inMax=${(Number(inMax) / Number(P)).toFixed(2)}p compiled==mirror=${ok} canonical=${canonical}`);
}
console.log(`P1: mirror-vs-compiled mismatches=${p1fail} => ${p1fail === 0 ? 'FAITHFUL (op really built & compiled)' : 'DIVERGENCE'}`);

// =============================================================================
console.log('\n=== P2: residue differential lazy fp12Sqr vs NOBLE (mod p) ===');
let p2mism = 0, p2n = 0, p2noncanon = 0;
function residCheck(L) {
  p2n++;
  const lazy = fp12SqrLazy(L), ref = nobleSqr(L);
  if (!lazy.every((v, i) => mod(v) === ref[i])) { p2mism++; return false; }
  if (!lazy.every((v) => v >= 0n && v < P)) p2noncanon++;
  return true;
}
for (let i = 0; i < 30000; i++) residCheck(Array.from({ length: 12 }, () => rBig() % P));              // [0,p)
for (const k of [5, 10, 15, 17, 18, 19, 20]) for (let i = 0; i < 8000; i++) residCheck(Array.from({ length: 12 }, () => rRange(BigInt(k) * P)));
// corners
for (let v = 0; v < 4096; v++) residCheck(Array.from({ length: 12 }, (_, i) => (v >> i) & 1 ? P - 1n : 0n));
for (let v = 0; v < 4096; v++) residCheck(Array.from({ length: 12 }, (_, i) => (v >> i) & 1 ? 19n * P - 1n : 0n));
console.log(`P2: ${p2n} cases  residue-mismatches=${p2mism}  non-canonical-outputs=${p2noncanon}  => ${p2mism === 0 ? 'RESIDUE ALWAYS CORRECT (congruence preserved)' : '*** RESIDUE FORGERY ***'}`);

// =============================================================================
console.log('\n=== P3: REAL lazy Miller loop — actual fp12Sqr input magnitudes + canonical/residue ===');
// Drive the ATE_NAF loop with LAZY arithmetic (wide mul034 + reduceOut fp12Sqr). Line coeffs from
// noble pointDouble/pointAdd (baked-coeff regime; o4=c0 reduced -> LOWER-bound on magnitude).
const scalarFp2 = (x, k) => Fp2.fromBigTuple([Fp.mul(x.c0, k), Fp.mul(x.c1, k)]);
function lazyLine(fL, c0, c1, c2, Px, Py) {
  const o0a = mulFp(c2.c0, Py), o0b = mulFp(c2.c1, Py), o3a = mulFp(c1.c0, Px), o3b = mulFp(c1.c1, Px);
  return mul034(fL, o0a, o0b, o3a, o3b, c0.c0, c0.c1); // o4 = c0 (noble-reduced here)
}
function runLazyMiller(pair, rec) {
  const Qa = pair.Q.toAffine(), Pa = pair.P.toAffine(), negQy = Fp2.neg(Qa.y);
  let fL = [1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n];
  let R = { x: Qa.x, y: Qa.y, z: Fp2.ONE };
  for (let k = 0; k < ATE_NAF.length; k++) {
    rec(fL);                                     // fL is the fp12Sqr INPUT this step
    fL = fp12SqrLazy(fL);
    let d = pointDouble(R.x, R.y, R.z); R = d.R; fL = lazyLine(fL, d.coeffs[0], d.coeffs[1], d.coeffs[2], Pa.x, Pa.y);
    if (ATE_NAF[k]) { let a = pointAdd(R.x, R.y, R.z, Qa.x, ATE_NAF[k] === -1 ? negQy : Qa.y); R = a.R; fL = lazyLine(fL, a.coeffs[0], a.coeffs[1], a.coeffs[2], Pa.x, Pa.y); }
  }
}
// random valid pairs
const randPair = () => {
  const a = BigInt(Math.floor(Math.random() * 1e15)) + 1n, b = BigInt(Math.floor(Math.random() * 1e15)) + 1n;
  return { P: bn254.G1.Point.BASE.multiply(a), Q: bn254.G2.Point.BASE.multiply(b) };
};
let p3maxIn = 0n, p3nonCanon = 0, p3residFail = 0, p3squares = 0, p3worstNeg = 0n;
const recFor = () => (fL) => {
  p3squares++;
  const inMax = fL.reduce((m, v) => (v < 0n ? -v : v) > m ? (v < 0n ? -v : v) : m, 0n);
  if (inMax > p3maxIn) p3maxIn = inMax;
  const pre = fp12SqrPre(fL);
  for (const x of pre) { const neg = x < 0n ? -x : 0n; if (neg > p3worstNeg) p3worstNeg = neg; }
  const out = fp12SqrLazy(fL), ref = nobleSqr(fL);
  if (!out.every((v, i) => mod(v) === ref[i])) p3residFail++;
  if (!out.every((v) => v >= 0n && v < P)) p3nonCanon++;
};
for (let t = 0; t < 12; t++) runLazyMiller(randPair(), recFor());
console.log(`  squares sampled=${p3squares}  max fp12Sqr input=${(Number(p3maxIn) / Number(P)).toFixed(3)}p  worst pre|neg|=${(Number(p3worstNeg) / Number(P * P)).toFixed(1)} p^2`);
console.log(`  non-canonical outputs=${p3nonCanon}  residue-fails=${p3residFail}  bias=${Number(BIAS) / Number(P * P)} p^2  => ${p3nonCanon === 0 && p3residFail === 0 ? 'ALL CANONICAL & RESIDUE-CORRECT' : '*** ISSUE ***'}`);

// =============================================================================
console.log('\n=== P4: HARD adversarial coordinate-ascent — REACHABLE non-canonicity? ===');
// The fp12Sqr input is a mul034 OUTPUT. Search (F in [0,p), o0,o3 in [0,p), o4 in [0,5p]) to MAXIMIZE
// fp12Sqr negativity (min pre-limb). Also directly search fp12Sqr's 12-limb box for the min pre-limb.
const corners = [0n, 1n, P - 1n, (P - 1n) / 2n, P >> 2n, (3n * P) >> 2n];
function mul034out(vars) { // vars: F0..11(12), o0a,o0b(2), o3a,o3b(2), o4a,o4b(2)
  return mul034(vars.slice(0, 12), vars[12], vars[13], vars[14], vars[15], vars[16], vars[17]);
}
function minPreOf(A) { const pre = fp12SqrPre(A); return pre.reduce((m, x) => x < m ? x : m, 1n << 800n); }
// coordinate ascent to MINIMIZE the min pre-limb of fp12Sqr(mul034(vars))
let bestMin = 1n << 800n, bestVars = null, bestMul034Max = 0n;
const o4hi = 5n * P;
for (let restart = 0; restart < 40; restart++) {
  let vars = Array.from({ length: 18 }, (_, i) => i < 16 ? rBig() % P : rRange(o4hi));
  for (let sweep = 0; sweep < 4; sweep++) {
    for (let v = 0; v < 18; v++) {
      const hi = v < 16 ? P - 1n : o4hi;
      let bestC = vars[v], bestVal = minPreOf(mul034out(vars));
      const trials = [...corners.filter((c) => c <= hi), ...Array.from({ length: 12 }, () => rRange(hi))];
      if (v >= 16) trials.push(o4hi, 4n * P, 3n * P, 2n * P);
      for (const c of trials) { const t = vars.slice(); t[v] = c; const val = minPreOf(mul034out(t)); if (val < bestVal) { bestVal = val; bestC = c; } }
      vars[v] = bestC;
    }
  }
  const mo = mul034out(vars); const mm = minPreOf(mo);
  const molMax = mo.reduce((m, v) => (v < 0n ? -v : v) > m ? (v < 0n ? -v : v) : m, 0n);
  if (mm < bestMin) { bestMin = mm; bestVars = vars.slice(); }
  if (molMax > bestMul034Max) bestMul034Max = molMax;
}
const worstDividend = bestMin + BIAS;
console.log(`  reachable mul034 output max limb (over search) = ${(Number(bestMul034Max) / Number(P)).toFixed(3)}p`);
console.log(`  worst reachable fp12Sqr min pre-limb = ${(Number(bestMin) / Number(P * P)).toFixed(1)} p^2  (|neg|=${(Number(-bestMin) / Number(P * P)).toFixed(1)} p^2)`);
console.log(`  worst reachable dividend (pre+BIAS)  = ${(Number(worstDividend) / Number(P * P)).toFixed(1)} p^2  ${worstDividend >= 0n ? '>=0 CANONICAL (no underflow reachable)' : '*** <0 NON-CANONICAL REACHABLE ***'}`);
// verify residue on the worst-found input, and canonicity of its output
if (bestVars) {
  const A = mul034out(bestVars);
  const out = fp12SqrLazy(A), ref = nobleSqr(A);
  console.log(`  worst-case output: residue==noble=${out.every((v, i) => mod(v) === ref[i])}  canonical=${out.every((v) => v >= 0n && v < P)}`);
}

// Also: direct box search — min pre-limb over fp12Sqr input box [0,Mp]^12 via coordinate ascent.
console.log('\n  direct box search: worst fp12Sqr |neg| over input box [0,Mp]^12 (coordinate ascent):');
for (const kM of [17, 18, 19, 20, 21]) {
  const M = BigInt(kM) * P;
  let best = 1n << 800n;
  for (let restart = 0; restart < 30; restart++) {
    let A = Array.from({ length: 12 }, () => rRange(M));
    for (let sweep = 0; sweep < 3; sweep++) for (let v = 0; v < 12; v++) {
      let bc = A[v], bv = minPreOf(A);
      for (const c of [0n, M, M / 2n, M >> 2n, (3n * M) >> 2n, rRange(M), rRange(M)]) { const t = A.slice(); t[v] = c; const val = minPreOf(t); if (val < bv) { bv = val; bc = c; } }
      A[v] = bc;
    }
    const m = minPreOf(A); if (m < best) best = m;
  }
  const div = best + BIAS;
  console.log(`    M=${kM}p: worst |neg|=${(Number(-best) / Number(P * P)).toFixed(0)} p^2  dividend=${(Number(div) / Number(P * P)).toFixed(0)} p^2  ${div >= 0n ? 'canonical' : '*** NON-CANONICAL ***'}`);
}
