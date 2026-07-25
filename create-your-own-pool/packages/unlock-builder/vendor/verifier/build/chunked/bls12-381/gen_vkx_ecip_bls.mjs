// gen_vkx_ecip_bls.mjs — BLS12-381 G1 port of the BN254 T3-2 ECIP vk_x certificate
// (chunked/pairing/gen_vkx_ecip.mjs). Replaces the 6-chunk GLV vk_x MSM with a SINGLE
// Liam-Eagen principal-divisor / Weil-reciprocity certificate (garaga ePrint 2022/596)
// binding  vk_x = IC0 + in0*IC1 + in1*IC2. Validated for BLS in projection (garaga
// zk_ecip_hint, 22-coeff SumDlogDiv FunctionFelt) — this file is the self-contained JS
// port of that hint (no garaga at build time), specialized to BLS12-381 G1: a=0, b=4,
// 381-bit base field p, 255-bit scalar field r, p ≡ 3 mod 4.
//
// The polynomial / divisor machinery is field-generic and identical to the BN254 port;
// only the curve constants change (P, R, b, the fixed non-residue g, the base(-3) loop
// length, and the 48-byte FS serialization). Point arithmetic uses @noble/curves
// bls12_381 G1 (the same instance the singleton/chunked builds verify).
//
// SEAM (grouped-residue): this chunk is the pipeline GENESIS (reads public inputs in0,in1
// as its committed state) AND the vkx->miller cross handoff (emits vkxX=Qx, vkxY=Qy, the
// point the fused-Miller genesis consumes at pair2). Body is Pmod-FREE (inline prime
// literals) so intratx/transform.mjs's grouped epilogue rewrite applies (only the covOut
// helper declares Pmod).
//
//   node gen_vkx_ecip_bls.mjs   -> generated/vkxecip_00.cash + manifest_vkxecip.json,
//                                  then isolated measureCovenant sanity (accept + forge rejects).
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import { vmNumberToBigInt, bigIntToVmNumber, encodeDataPush, numberToBinUint16LE, createVirtualMachineBch2026 } from '@bitauth/libauth';
import { P, covIn, covOut, vk, computeVkx, bls12_381, commitBin, CATEGORY, compileBytecodeRaw, TARGET_UNLOCK } from './_vkxmath.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const G1 = bls12_381.G1.Point;

// ---- BLS12-381 curve constants ----
export const Pbls = P; // base field prime (381-bit)
export const Rbls = 52435875175126190479447740508185965837690552500527637822603658699938581184513n; // scalar order
const R = Rbls;
const CURVE_B = 4n;        // y^2 = x^3 + 4
const NONRES = 2n;         // fixed quadratic NON-residue in Fp (p ≡ 3 mod 4; 2 is a non-residue)
const W = 48;              // BLS limb width (bytes)

// base(-3) loop length: every k in [0,R) has <= LOOP balanced base(-3) digits, since the
// max magnitude representable with n digits {-1,0,1} is (3^n-1)/2. Pick the smallest such n.
export const NEG3_LOOP = (() => { let n = 1, p = 3n; while ((p - 1n) / 2n < R - 1n) { n++; p *= 3n; } return n; })();

// ---- Fp ----
const fp = (x) => ((x % P) + P) % P;
const fadd = (a, b) => fp(a + b), fsub = (a, b) => fp(a - b), fmul = (a, b) => fp(a * b), fneg = (a) => fp(-a);
const fpow = (b, e) => { let r = 1n; b = fp(b); while (e > 0n) { if (e & 1n) r = fmul(r, b); b = fmul(b, b); e >>= 1n; } return r; };
const finv = (a) => fpow(fp(a), P - 2n);
const fdiv = (a, b) => fmul(a, finv(b));

// ---- Polynomial over Fp: array of BigInt (Fp), LSB-first, canonical (no trailing zeros; zero = [0n]) ----
const trim = (c) => { let i = c.length - 1; while (i > 0 && c[i] === 0n) i--; return c.slice(0, i + 1); };
const mk = (c) => trim(c.map(fp));
const PZERO = [0n], PONE = [1n];
const pdeg = (a) => { let i = a.length - 1; while (i > 0 && a[i] === 0n) i--; return a[i] === 0n ? -1 : i; };
const piszero = (a) => pdeg(a) === -1;
const padd = (a, b) => { const n = Math.max(a.length, b.length); const r = []; for (let i = 0; i < n; i++) r.push(fadd(a[i] ?? 0n, b[i] ?? 0n)); return trim(r); };
const psub = (a, b) => { const n = Math.max(a.length, b.length); const r = []; for (let i = 0; i < n; i++) r.push(fsub(a[i] ?? 0n, b[i] ?? 0n)); return trim(r); };
const pneg = (a) => a.map(fneg);
const pscale = (a, s) => trim(a.map((c) => fmul(c, s)));
const pmul = (a, b) => { if (piszero(a) || piszero(b)) return PZERO.slice(); const r = new Array(a.length + b.length - 1).fill(0n); for (let i = 0; i < a.length; i++) { if (a[i] === 0n) continue; for (let j = 0; j < b.length; j++) r[i + j] = fadd(r[i + j], fmul(a[i], b[j])); } return trim(r); };
const pdiff = (a) => { if (a.length <= 1) return PZERO.slice(); const r = []; for (let i = 1; i < a.length; i++) r.push(fmul(a[i], BigInt(i))); return trim(r); };
const plead = (a) => a[pdeg(a)];
function pdivmod(num, den) {
  const dd = pdeg(den); if (dd === -1) throw new Error('div by zero poly');
  let nd = pdeg(num); if (nd < dd) return [PZERO.slice(), num.slice()];
  let rem = num.slice(); const quo = new Array(nd - dd + 1).fill(0n);
  const dlinv = finv(den[dd]);
  while (nd >= dd) {
    const shift = nd - dd; const co = fmul(rem[nd], dlinv); quo[shift] = co;
    for (let i = 0; i <= dd; i++) rem[shift + i] = fsub(rem[shift + i] ?? 0n, fmul(co, den[i]));
    nd = pdeg(rem);
  }
  return [trim(quo), trim(rem)];
}
const pfloordiv = (a, b) => pdivmod(a, b)[0];
function pxgcd_gcd(x, y) {
  let old_r = x.slice(), r = y.slice();
  while (!piszero(r)) { const q = pfloordiv(old_r, r); const nr = psub(old_r, pmul(q, r)); old_r = r; r = nr; }
  const lcinv = finv(plead(old_r));
  return pscale(old_r, lcinv);
}
const peval = (a, x) => { let v = 0n, xi = 1n; for (const c of a) { v = fadd(v, fmul(c, xi)); xi = fmul(xi, x); } return v; };

// ---- FF: list of Polynomials (coeffs in y). y2 = x^3 + b (a=0). ----
const Y2 = [CURVE_B, 0n, 0n, 1n]; // b, a(=0), 0, 1
function ffAdd(A, B) { const n = Math.max(A.length, B.length); const r = []; for (let i = 0; i < n; i++) r.push(padd(A[i] ?? PZERO, B[i] ?? PZERO)); return r; }
function ffMul(A, B) { const buf = new Array(A.length + B.length - 1).fill(0).map(() => PZERO.slice()); for (let i = 0; i < A.length; i++) { if (piszero(A[i])) continue; for (let j = 0; j < B.length; j++) buf[i + j] = padd(buf[i + j], pmul(A[i], B[j])); } return buf; }
function ffNegY(A) { if (A.length < 2) return A.map((c) => c.slice()); const c = A.map((x) => x.slice()); c[1] = pneg(c[1]); return c; }
function ffReduce(A) {
  if (A.length <= 2) { const c = A.map((x) => x.slice()); while (c.length < 2) c.push(PZERO.slice()); return c; }
  let y2 = Y2.slice(); let d0 = A[0].slice(), d1 = A[1].slice();
  for (let i = 2; i < A.length; i++) { if (i % 2 === 0) d0 = padd(d0, pmul(A[i], y2)); else { d1 = padd(d1, pmul(A[i], y2)); y2 = pmul(y2, y2); } }
  return [d0, d1];
}
const ffToPoly = (A) => { if (A.length !== 1) throw new Error('to_poly len!=1'); return A[0]; };
const ffDivByPoly = (A, poly) => A.map((c) => pfloordiv(c, poly));
function ffNormalize(A) { const inv = finv(A[0][0] ?? 0n); return A.map((c) => pscale(c, inv)); }

// ---- points ----
const smul = (pt, k) => { k = BigInt(k); if (pt.is0() || k === 0n) return G1.ZERO; const kk = k < 0n ? -k : k; const R2 = pt.multiplyUnsafe(kk); return k < 0n ? R2.negate() : R2; };
const isInf = (pt) => pt.is0();
const aff = (pt) => pt.toAffine();

// line(P,Q) -> FF (garaga hints/ecip.py line(); a=0)
function line(Pp, Qp) {
  if (isInf(Pp)) {
    if (isInf(Qp)) return [PONE.slice()];
    const qx = fp(aff(Qp).x); return [mk([fneg(qx), 1n])];
  }
  if (isInf(Qp)) { const px = fp(aff(Pp).x); return [mk([fneg(px), 1n])]; }
  const pa = aff(Pp), px = fp(pa.x), py = fp(pa.y);
  if (Pp.equals(Qp)) {
    const m = fdiv(fmul(3n, fmul(px, px)), fmul(2n, py)); // a=0
    const b = fsub(py, fmul(m, px));
    return [mk([fneg(b), fneg(m)]), PONE.slice()];
  }
  if (Pp.equals(Qp.negate())) { return [mk([fneg(px), 1n])]; }
  const qa = aff(Qp), qx = fp(qa.x), qy = fp(qa.y);
  const m = fdiv(fsub(py, qy), fsub(px, qx));
  const b = fsub(qy, fmul(m, qx));
  return [mk([fneg(b), fneg(m)]), PONE.slice()];
}

function constructFunction(Ps) {
  if (Ps.length === 0) throw new Error('EMPTY');
  let xs = Ps.map((Pp) => [Pp, line(Pp, Pp.negate())]);
  while (xs.length !== 1) {
    const xs2 = []; let x0 = null;
    if (xs.length & 1) { x0 = xs[0]; xs = xs.slice(1); }
    for (let n = 0; n < (xs.length >> 1); n++) {
      const [A, aNum] = xs[2 * n], [B, bNum] = xs[2 * n + 1];
      const aNum_bNum = ffMul(aNum, bNum);
      const lineAB = line(A, B);
      const product = ffMul(aNum_bNum, lineAB);
      const num = ffReduce(product);
      const den = ffToPoly(ffMul(line(A, A.negate()), line(B, B.negate())));
      const D = ffDivByPoly(num, den);
      xs2.push([A.add(B), D]);
    }
    if (x0 !== null) xs2.push(x0);
    xs = xs2;
  }
  if (!isInf(xs[0][0])) throw new Error('construct_function: not infinity');
  return ffNormalize(xs[xs.length - 1][1]);
}

function rowFunction(ds, Ps, Q) {
  const inf = G1.ZERO;
  const digitsPoints = ds.map((d, i) => d === 1 ? Ps[i] : d === -1 ? Ps[i].negate() : inf);
  const sumDigits = digitsPoints.reduce((x, y) => x.add(y), inf);
  const Q2 = smul(Q, -3n).add(sumDigits);
  const Qneg = Q.negate();
  const div_ = [Qneg, Qneg, Qneg, Q2.negate(), ...digitsPoints];
  const div = div_.filter((Pp) => !isInf(Pp));
  let D;
  try { D = constructFunction(div); }
  catch (e) { if (String(e.message).includes('EMPTY')) D = [PONE.slice()]; else throw e; }
  return [D, Q2];
}

// neg_3 base decomposition (garaga hints/neg_3.py)
const fdivInt = (a, b) => (a - (((a % b) + b) % b)) / b; // floor division
export function neg3(scalar) { if (scalar === 0n) return [0]; const d = []; while (scalar !== 0n) { let r = ((scalar % 3n) + 3n) % 3n; if (r === 2n) { r = -1n; scalar += 1n; } d.push(Number(r)); scalar = -fdivInt(scalar, 3n); } return d; }
export function epen(scalar) { const dg = neg3(scalar); let ep = 0n, en = 0n, pw = 1n; for (let i = 0; i < dg.length; i++) { if (dg[i] === 1) ep += pw; if (dg[i] === -1) en += pw; pw = pw * -3n; } return [ep, en]; }
function constructDigitVectors(es) { const dss_ = es.map(neg3); const maxLen = Math.max(...dss_.map((d) => d.length)); const padded = dss_.map((d) => [...d, ...new Array(maxLen - d.length).fill(0)]); const dss = []; for (let col = 0; col < maxLen; col++) dss.push(padded.map((row) => row[col])); return dss; }

function ecipFunctions(Bs, dss) {
  dss = dss.slice().reverse();
  let Q = G1.ZERO; const Ds = [];
  for (const ds of dss) { const [D, nQ] = rowFunction(ds, Bs, Q); Q = nQ; Ds.push(D); }
  Ds.reverse();
  return [Q, Ds];
}

function dlog(dIn) {
  const d = ffReduce(dIn); // [A(x), B(x)]
  const Dx = [pdiff(d[0]), pdiff(d[1])];
  const Dy = d[1];
  const TWO_Y = [PZERO.slice(), [2n]];
  // U = Dx*2y + FF([ Dy*(3x^2+a), 0 ])   (a=0)
  const U = ffAdd(ffMul(Dx, TWO_Y), [pmul(Dy, [0n, 0n, 3n]), PZERO.slice()]);
  const V = ffMul(TWO_Y, d);
  const Num = ffReduce(ffMul(U, ffNegY(V)));
  const DenFF = ffReduce(ffMul(V, ffNegY(V)));
  if (!piszero(DenFF[1])) throw new Error('Den[1] != 0');
  const Den = DenFF[0];
  const gcd0 = pxgcd_gcd(Num[0], Den);
  const gcd1 = pxgcd_gcd(Num[1], Den);
  const a_num = pfloordiv(Num[0], gcd0);
  const a_den = pfloordiv(Den, gcd0);
  const b_num = pfloordiv(Num[1], gcd1);
  const b_den = pfloordiv(Den, gcd1);
  const lcinv = finv(plead(Den));
  return {
    a_num: pscale(a_num, lcinv), a_den: pscale(a_den, finv(plead(a_den))),
    b_num: pscale(b_num, lcinv), b_den: pscale(b_den, finv(plead(b_den))),
  };
}

// main hint: returns {Q,Qx,Qy, a_num,a_den,b_num,b_den} (BigInt arrays / values)
export function zkEcipHint(Bs, scalars) {
  const dss = constructDigitVectors(scalars);
  const [Q, Ds] = ecipFunctions(Bs, dss);
  const dlogs = Ds.map(dlog);
  let acc = dlogs[0];
  let f = 1n;
  for (let i = 1; i < dlogs.length; i++) { f = f * -3n; acc = rfSum(acc, scaleDlog(dlogs[i], fp(f))); }
  const qa = aff(Q);
  return { Q, Qx: fp(qa.x), Qy: fp(qa.y), a_num: acc.a_num, a_den: acc.a_den, b_num: acc.b_num, b_den: acc.b_den };
}
function scaleDlog(dl, s) { return { a_num: pscale(dl.a_num, s), a_den: dl.a_den, b_num: pscale(dl.b_num, s), b_den: dl.b_den }; }
function rfAddSimplify(n1, d1, n2, d2) {
  let num = padd(pmul(n1, d2), pmul(n2, d1));
  let den = pmul(d1, d2);
  const g = pxgcd_gcd(num, den);
  num = pfloordiv(num, g); den = pfloordiv(den, g);
  num = pscale(num, finv(plead(den)));
  den = pscale(den, finv(plead(den)));
  return [num, den];
}
function rfSum(A, B) {
  const [an, ad] = rfAddSimplify(A.a_num, A.a_den, B.a_num, B.a_den);
  const [bn, bd] = rfAddSimplify(A.b_num, A.b_den, B.b_num, B.b_den);
  return { a_num: an, a_den: ad, b_num: bn, b_den: bd };
}

// ================= ON-CHAIN VERIFIER REFERENCE (mirrors the .cash exactly) =================
// 48-byte little-endian serialization (matches cash toPaddedBytes(., 48)).
const le48 = (x) => { const b = Buffer.alloc(48); let v = fp(x); for (let i = 0; i < 48; i++) { b[i] = Number(v & 0xffn); v >>= 8n; } return b; };
// mirror the VM `int(bytes.split(31)[0])`: sign-magnitude decode of the low 31 bytes, then mod P.
const vmInt31 = (digest) => fp(vmNumberToBigInt(digest.subarray(0, 31), { maximumVmNumberByteLength: 32, requireMinimalEncoding: false }));
const sqrtFp = (a) => fpow(fp(a), (P + 1n) / 4n); // P ≡ 3 mod 4
const isQR = (a) => { a = fp(a); if (a === 0n) return true; return fpow(a, (P - 1n) / 2n) === 1n; };

// Fiat–Shamir preimage: le48 of [in0,in1,Qx,Qy] ++ 22 coeffs (a_num4,a_den5,b_num5,b_den8).
// x_seed = VM int() of the low 31 bytes of sha256(preimage), reduced mod P.
export function fsChallenge(in0, in1, Qx, Qy, h) {
  const parts = [in0, in1, Qx, Qy, ...h.a_num, ...h.a_den, ...h.b_num, ...h.b_den].map(le48);
  return vmInt31(createHash('sha256').update(Buffer.concat(parts)).digest());
}

// try-and-increment bound. The verifier loops MAXTRY times reading sqrt-witnesses from a
// single `bytes grblob` (nfail*48 B) — so the REDEEM size is O(1) in MAXTRY (only the loop
// body, not MAXTRY unrolled blocks), and MAXTRY can be large for universality (P(honest
// instance needs > MAXTRY rehashes) = 2^-(MAXTRY+1)) at only a per-iteration op-cost.
export const MAXTRY = Number(process.env.ECIP_MAXTRY ?? 48);
const nextX = (x) => vmInt31(createHash('sha256').update(le48(x)).digest());
const rhsOf = (x) => fadd(fmul(fmul(x, x), x), CURVE_B); // x^3 + b
export function ecipVerify(IC, scalars, h) {
  const Qx = h.Qx, Qy = h.Qy;
  const xseed = fsChallenge(scalars[1], scalars[2], Qx, Qy, h);
  // try-and-increment: advance while rhs(x) is a non-residue; each FAILED attempt records
  // gRoot = sqrt(g*rhs) (proves rhs non-residue, g a fixed non-residue). Bounded at MAXTRY.
  let x = xseed, nfail = 0; const gRoots = [];
  while (!isQR(rhsOf(x))) { gRoots.push(sqrtFp(fmul(NONRES, rhsOf(x)))); x = nextX(x); nfail++; if (nfail > MAXTRY) throw new Error('MAXTRY exceeded'); }
  const xA0 = x;
  const yA0 = sqrtFp(rhsOf(xA0));
  // A2 = -2*A0 via tangent-doubling (a=0):
  const mA0 = fdiv(fmul(3n, fmul(xA0, xA0)), fmul(2n, yA0));
  const bA0 = fsub(yA0, fmul(mA0, xA0));
  const x2d = fsub(fmul(mA0, mA0), fmul(2n, xA0));
  const y2d = fsub(fmul(mA0, fsub(xA0, x2d)), yA0);
  const xA2 = x2d, yA2 = fneg(y2d);
  const mA0A2 = fdiv(fsub(yA2, yA0), fsub(xA2, xA0));
  const c2den = fsub(fmul(3n, fmul(xA2, xA2)), fmul(2n, fmul(mA0A2, yA2)));
  const coeff2 = fdiv(fmul(2n, fmul(yA2, fsub(xA0, xA2))), c2den);
  const coeff0 = fadd(coeff2, fmul(2n, mA0A2));
  const EPN = scalars.map((s) => epen(BigInt(s)));
  const chalTerm = (Px, Py, mult) => { const den = fsub(fsub(Py, fmul(mA0, Px)), bA0); const num = fmul(fp(mult), fsub(xA0, Px)); return { term: den === 0n ? 0n : fdiv(num, den), den, num }; };
  const pts = IC.map((pt) => { const a = aff(pt); return [fp(a.x), fp(a.y)]; });
  let basis = 0n; const chalWit = [];
  for (let i = 0; i < 3; i++) {
    const [Px, Py] = pts[i]; const [ep, en] = EPN[i];
    const tp = chalTerm(Px, Py, ep); const tn = chalTerm(Px, fneg(Py), en);
    basis = fadd(basis, fadd(tp.term, tn.term));
    chalWit.push({ Px, Py, epMod: fp(ep), enMod: fp(en), termP: tp.term, termN: tn.term });
  }
  const tQ = chalTerm(Qx, fneg(Qy), 1n); // eval_point_challenge(-Q, 1): Pt=(Qx,-Qy)
  const RHS = fadd(tQ.term, basis);
  const adenA0 = peval(h.a_den, xA0), bdenA0 = peval(h.b_den, xA0);
  const adenA2 = peval(h.a_den, xA2), bdenA2 = peval(h.b_den, xA2);
  const fEval = (x, y, iad, ibd) => fadd(fmul(peval(h.a_num, x), iad), fmul(y, fmul(peval(h.b_num, x), ibd)));
  const fA0 = fEval(xA0, yA0, finv(adenA0), finv(bdenA0));
  const fA2 = fEval(xA2, yA2, finv(adenA2), finv(bdenA2));
  const LHS = fsub(fmul(coeff0, fA0), fmul(coeff2, fA2));
  const ok = LHS === RHS;
  return { ok, nfail, gRoots, xseed, yA0, xA0, yA2, xA2, mA0, bA0, mA0A2, coeff0, coeff2, c2den, RHS, LHS,
    invAdenA0: finv(adenA0), invBdenA0: finv(bdenA0), invAdenA2: finv(adenA2), invBdenA2: finv(bdenA2),
    fA0, fA2, chalWit, tQterm: tQ.term, EPN };
}

// ================= SINGLE-CHUNK .cash VERIFIER GENERATOR =================
// SEAM1 committed state (covIn) = the genesis public inputs.
export const SEAM1 = ['in0', 'in1'];
// SEAM2 emitted (covOut) — vkxX/vkxY carry Q to the fused-Miller genesis (pair2 P).
export const SEAM2 = ['vkxX', 'vkxY'];
const AN = ['an0', 'an1', 'an2', 'an3'], AD = ['ad0', 'ad1', 'ad2', 'ad3', 'ad4'];
const BNs = ['bn0', 'bn1', 'bn2', 'bn3', 'bn4'], BD = ['bd0', 'bd1', 'bd2', 'bd3', 'bd4', 'bd5', 'bd6', 'bd7'];
// witness param order (after SEAM1). `grblob` is a BYTES witness (nfail*48 B) carrying the
// non-residue sqrt certificates for the skipped x's; every other slot is an int. WIT_BYTES
// marks which slots are bytes so the assembler/measurer push them as data, not as VM ints.
export const WIT = [
  'Qx', 'Qy', ...AN, ...AD, ...BNs, ...BD, 'yA0', 'nfail', 'grblob',
  'mA0', 'mA0A2', 'coeff2', 'iad0', 'ibd0', 'iad2', 'ibd2',
  't0p', 't0n', 't1p', 't1n', 't2p', 't2n', 'tQ',
];
export const WIT_BYTES = new Set(['grblob']);
const PSTR = P.toString();
const RSTR = R.toString();
const horner = (names, X) => { let e = names[names.length - 1]; for (let i = names.length - 2; i >= 0; i--) e = `addFp(mulFp(${e},${X}),${names[i]})`; return e; };

// emit the single-chunk BLS ECIP vk_x verifier .cash source. Body is Pmod-FREE (inline
// prime literals): only the covOut helper declares Pmod, so transform.mjs's grouped
// epilogue rewrite (which re-adds Pmod for the % reductions) applies cleanly.
export function emitCashVerifier(IC) {
  const [[i0x, i0y], [i1x, i1y], [i2x, i2y]] = IC.map((pt) => { const a = aff(pt); return [fp(a.x).toString(), fp(a.y).toString()]; });
  const cb = CURVE_B.toString();
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`function addFp(int x,int y) returns(int){return (x+y)%${PSTR};}`);
  L.push(`function subFp(int x,int y) returns(int){return (x-y+${PSTR})%${PSTR};}`);
  L.push(`function mulFp(int x,int y) returns(int){return (x*y)%${PSTR};}`);
  L.push('contract VkxEcipBls() {');
  const decl = (n) => `${WIT_BYTES.has(n) ? 'bytes' : 'int'} ${n}`;
  L.push(`    function spend(${[...SEAM1, ...WIT].map(decl).join(',')}, bytes unused zeroPadding) {`);
  // covIn(SEAM1): the covenant ROOT / pipeline genesis (transform peels in0,in1 from inBlob).
  L.push(covIn(SEAM1));
  // ---- in0/in1 canonicality (0 <= in < r): unique scalar representative preserved from GLV genesis ----
  L.push(`        require(in0 >= 0); require(in0 < ${RSTR});`);
  L.push(`        require(in1 >= 0); require(in1 < ${RSTR});`);
  // ---- canonicality of FS-hashed witnesses (unique serialization; 0 <= v < p) ----
  for (const n of ['Qx', 'Qy', ...AN, ...AD, ...BNs, ...BD]) L.push(`        require(${n} >= 0); require(${n} < ${PSTR});`);
  // ---- Fiat-Shamir challenge over ALL committed scalars + Q + hint coeffs ----
  const pre = ['in0', 'in1', 'Qx', 'Qy', ...AN, ...AD, ...BNs, ...BD].map((n) => `toPaddedBytes(${n}, 48)`).join(' + ');
  L.push(`        int cseed = int(bytes(sha256(${pre}).split(31)[0]));`);
  L.push(`        int x = cseed % ${PSTR}; if (x < 0) { x = x + ${PSTR}; }`);
  // ---- derive A0: bounded try-and-increment via a counted loop over grblob. For each of the
  // first `nfail` challenge x's the prover supplies gr = sqrt(g*(x^3+b)) (g a fixed non-residue),
  // proving x^3+b is a NON-residue so skipping that x is forced; then x is rehashed. After nfail
  // steps x = xA0 must be a residue (yA0^2 == xA0^3+b below). This forces A0 = the FIRST rehash
  // with a point, unpredictable to the prover (the FS seed commits to every hint coeff). ----
  L.push(`        require(nfail >= 0); require(nfail <= ${MAXTRY});`);
  L.push(`        for (int t = 0; t < ${MAXTRY}; t = t + 1) {`);
  L.push('            if (t < nfail) {');
  L.push(`                int grt = int(grblob.split(t * 48)[1].split(48)[0]);`);
  L.push(`                require(mulFp(grt, grt) == mulFp(${NONRES}, addFp(mulFp(mulFp(x,x),x), ${cb})));`);
  L.push(`                int hct = int(bytes(sha256(toPaddedBytes(x, 48)).split(31)[0])); x = hct % ${PSTR}; if (x < 0) { x = x + ${PSTR}; }`);
  L.push('            }');
  L.push('        }');
  L.push('        int xA0 = x;');
  L.push(`        require(mulFp(yA0, yA0) == addFp(mulFp(mulFp(xA0,xA0),xA0), ${cb}));`); // A0 on curve
  // ---- A2 = -2*A0, slopes, coeffs ----
  L.push('        require(mulFp(mulFp(2, yA0), mA0) == mulFp(3, mulFp(xA0, xA0)));'); // tangent slope (a=0)
  L.push('        int bA0 = subFp(yA0, mulFp(mA0, xA0));');
  L.push('        int x2d = subFp(mulFp(mA0, mA0), mulFp(2, xA0));');
  L.push('        int y2d = subFp(mulFp(mA0, subFp(xA0, x2d)), yA0);');
  L.push('        int xA2 = x2d; int yA2 = subFp(0, y2d);');
  L.push('        require(mulFp(mA0A2, subFp(xA2, xA0)) == subFp(yA2, yA0));'); // slope A2->A0
  L.push('        require(mulFp(coeff2, subFp(mulFp(3, mulFp(xA2, xA2)), mulFp(2, mulFp(mA0A2, yA2)))) == mulFp(2, mulFp(yA2, subFp(xA0, xA2))));');
  L.push('        int coeff0 = addFp(coeff2, mulFp(2, mA0A2));');
  // ---- base(-3) multiplicities ep/en for in0, in1 (scalar 1 => ep=1,en=0) ----
  L.push('        int s0 = in0; int ep0 = 0; int en0 = 0; int s1 = in1; int ep1 = 0; int en1 = 0; int pw = 1;');
  L.push(`        for (int k = 0; k < ${NEG3_LOOP}; k = k + 1) { if (s0 != 0 || s1 != 0) {`);
  L.push('            int r0 = s0 % 3; if (r0 < 0) { r0 = r0 + 3; } int d0 = 0; if (r0 == 2) { d0 = -1; } else { d0 = r0; }');
  L.push('            if (d0 == 1) { ep0 = ep0 + pw; } if (d0 == -1) { en0 = en0 + pw; } s0 = (d0 - s0) / 3;');
  L.push('            int r1 = s1 % 3; if (r1 < 0) { r1 = r1 + 3; } int d1 = 0; if (r1 == 2) { d1 = -1; } else { d1 = r1; }');
  L.push('            if (d1 == 1) { ep1 = ep1 + pw; } if (d1 == -1) { en1 = en1 + pw; } s1 = (d1 - s1) / 3; pw = 0 - (3 * pw); } }');
  L.push('        require(s0 == 0); require(s1 == 0);');
  L.push(`        int ep0m = ep0 % ${PSTR}; if (ep0m < 0) { ep0m = ep0m + ${PSTR}; } int en0m = en0 % ${PSTR}; if (en0m < 0) { en0m = en0m + ${PSTR}; }`);
  L.push(`        int ep1m = ep1 % ${PSTR}; if (ep1m < 0) { ep1m = ep1m + ${PSTR}; } int en1m = en1 % ${PSTR}; if (en1m < 0) { en1m = en1m + ${PSTR}; }`);
  // ---- point-challenge terms (witnessed, checked term*den == mult*(xA0-Px)) ----
  const chal = (tp, tn, Px, Py, epv, env) => {
    L.push(`        int mx${tp} = mulFp(mA0, ${Px});`);
    L.push(`        require(mulFp(${tp}, subFp(subFp(${Py}, mx${tp}), bA0)) == mulFp(${epv}, subFp(xA0, ${Px})));`);
    L.push(`        require(mulFp(${tn}, subFp(subFp(subFp(0, ${Py}), mx${tp}), bA0)) == mulFp(${env}, subFp(xA0, ${Px})));`);
  };
  chal('t0p', 't0n', i0x, i0y, '1', '0');           // IC0, scalar 1
  chal('t1p', 't1n', i1x, i1y, 'ep0m', 'en0m');      // IC1, scalar in0
  chal('t2p', 't2n', i2x, i2y, 'ep1m', 'en1m');      // IC2, scalar in1
  L.push('        int mxQ = mulFp(mA0, Qx);');
  L.push('        require(mulFp(tQ, subFp(subFp(subFp(0, Qy), mxQ), bA0)) == subFp(xA0, Qx));'); // -Q term, mult 1
  L.push('        int RHS = addFp(tQ, addFp(addFp(t0p, t0n), addFp(addFp(t1p, t1n), addFp(t2p, t2n))));');
  // ---- f(xA0), f(xA2); denominator inverses witnessed ----
  L.push(`        int adA0 = ${horner(AD, 'xA0')}; require(mulFp(adA0, iad0) == 1);`);
  L.push(`        int bdA0 = ${horner(BD, 'xA0')}; require(mulFp(bdA0, ibd0) == 1);`);
  L.push(`        int adA2 = ${horner(AD, 'xA2')}; require(mulFp(adA2, iad2) == 1);`);
  L.push(`        int bdA2 = ${horner(BD, 'xA2')}; require(mulFp(bdA2, ibd2) == 1);`);
  L.push(`        int fA0 = addFp(mulFp(${horner(AN, 'xA0')}, iad0), mulFp(yA0, mulFp(${horner(BNs, 'xA0')}, ibd0)));`);
  L.push(`        int fA2 = addFp(mulFp(${horner(AN, 'xA2')}, iad2), mulFp(yA2, mulFp(${horner(BNs, 'xA2')}, ibd2)));`);
  L.push('        int LHS = subFp(mulFp(coeff0, fA0), mulFp(coeff2, fA2));');
  L.push('        require(LHS == RHS);');
  // ---- emit SEAM2 (vkxX=Qx, vkxY=Qy). covOut helper declares the ONLY Pmod. ----
  L.push('        int vkxX = Qx; int vkxY = Qy;');
  L.push(covOut(SEAM2));
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// assemble the witness VALUES in WIT order (after the 2 SEAM1 limbs). Returns a mixed array
// of BigInt (int limbs) and one Uint8Array (`grblob`, the nfail*48-B sqrt-cert blob).
export function emitWitness(IC, scalars, h, v) {
  const red = (x) => ((x % P) + P) % P;
  const grblob = Buffer.concat(v.gRoots.map((g) => le48(g))); // nfail * 48 bytes (empty if nfail==0)
  const cw = v.chalWit; // [{termP,termN} for IC0,IC1,IC2]
  const ints = (arr) => arr.map(red);
  return [
    ...ints([h.Qx, h.Qy, ...h.a_num, ...h.a_den, ...h.b_num, ...h.b_den, v.yA0, BigInt(v.nfail)]),
    Uint8Array.from(grblob),
    ...ints([v.mA0, v.mA0A2, v.coeff2, v.invAdenA0, v.invBdenA0, v.invAdenA2, v.invBdenA2,
      cw[0].termP, cw[0].termN, cw[1].termP, cw[1].termN, cw[2].termP, cw[2].termN, v.tQterm]),
  ];
}

// build the single grouped-residue spec-fields for a given instance's inputs (used by the
// assembler). Returns { inLimbs, outLimbs, extras } with the .cash pre-emitted at GEN.
export function ecipSpecData(inst_in0, inst_in1) {
  const in0 = BigInt(inst_in0), in1 = BigInt(inst_in1);
  const IC = vk.ic;
  const scalars = [1n, in0, in1];
  const h = zkEcipHint(IC, scalars);
  if (!(h.a_num.length === 4 && h.a_den.length === 5 && h.b_num.length === 5 && h.b_den.length === 8))
    throw new Error(`ECIP coeff counts != (4,5,5,8): got (${h.a_num.length},${h.a_den.length},${h.b_num.length},${h.b_den.length})`);
  const v = ecipVerify(IC, scalars, h);
  if (!v.ok) throw new Error('ECIP LHS != RHS for instance');
  const vkxAff = computeVkx([in0, in1]).toAffine();
  if (h.Qx !== fp(vkxAff.x) || h.Qy !== fp(vkxAff.y)) throw new Error('ECIP Q != computeVkx(in0,in1)');
  return { inLimbs: [in0, in1], outLimbs: [fp(vkxAff.x), fp(vkxAff.y)], extras: emitWitness(IC, scalars, h, v) };
}

// ---------- emit + isolated self-test (measureCovenant accept + forge rejects) ----------
if (process.argv[1] && process.argv[1].endsWith('gen_vkx_ecip_bls.mjs')) {
  mkdirSync(GEN, { recursive: true });
  const IC = vk.ic;
  const src = emitCashVerifier(IC);
  writeFileSync(join(GEN, 'vkxecip_00.cash'), src);
  writeFileSync(join(GEN, 'manifest_vkxecip.json'), JSON.stringify({
    curve: 'BLS12-381', method: 'ecip-divisor-cert', numChunks: 1, iters: NEG3_LOOP, maxtry: MAXTRY,
    coeffCounts: { a_num: 4, a_den: 5, b_num: 5, b_den: 8 }, chunks: [{ idx: 0, role: 'cross', final: true, checkpoint: 'vk_x' }],
  }, null, 2));
  console.error(`emitted vkxecip_00.cash (NEG3_LOOP=${NEG3_LOOP}, MAXTRY=${MAXTRY}, nonres=${NONRES}, b=${CURVE_B})`);

  // ---- mixed-args covenant measurer (the shared measureCovenant handles int args only; our
  // grblob is a bytes witness). Drives the RAW covenant form (covIn hash of [in0,in1], covOut
  // hash of [vkxX,vkxY]) through a synthetic mutable-token tx — isolated compile-sanity + forge
  // gate, NOT the full pipeline. Mirrors _vkxmath.measureCovenantRaw for the mixed push. ----
  const realVm = createVirtualMachineBch2026(false);
  const pushArg = (a) => (a instanceof Uint8Array ? encodeDataPush(a) : encodeDataPush(bigIntToVmNumber(BigInt(a))));
  const tok = (commitment) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment } });
  const OP_PUSHDATA2 = 0x4d;
  const padPush = (argLen, target) => { const N = target - argLen - 3; return Uint8Array.from([OP_PUSHDATA2, ...numberToBinUint16LE(N), ...new Uint8Array(N)]); };
  let raw; try { raw = compileBytecodeRaw(src); } catch (e) { console.error('COMPILE ERROR:', String(e?.message ?? e)); process.exit(1); }
  // measure(stateArgs decl-order, commitInts incoming, outLimbs outgoing) -> {accepted,operationCost,lockingBytes,error}
  const measureRaw = (stateArgs, commitInts, outLimbs) => {
    const locking = Uint8Array.from([...raw]);
    const argBytes = Uint8Array.from([...stateArgs].reverse().flatMap((a) => [...pushArg(a)]));
    const unlocking = Uint8Array.from([...padPush(argBytes.length, TARGET_UNLOCK), ...argBytes]);
    const st = realVm.evaluate({
      inputIndex: 0,
      sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(commitInts.map(BigInt))) }],
      transaction: {
        version: 2,
        inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
        outputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(outLimbs.map(BigInt))) }],
        locktime: 0,
      },
    });
    const top = st.stack[st.stack.length - 1];
    const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
    return { lockingBytes: locking.length, unlockingBytes: unlocking.length, operationCost: st.metrics.operationCost, accepted, error: st.error ?? null };
  };
  const measure = (in0, in1, mutate) => {
    const d = ecipSpecData(in0, in1);
    let stateArgs = [in0, in1, ...d.extras];
    let outLimbs = d.outLimbs.slice();
    let commit = [in0, in1];
    if (mutate) ({ stateArgs, outLimbs, commit } = { commit, ...mutate(stateArgs.slice(), outLimbs.slice()) });
    return measureRaw(stateArgs, commit, outLimbs);
  };
  const idx = (name) => 2 + WIT.indexOf(name); // position in stateArgs (after in0,in1)
  const bump = (s, name) => { s[idx(name)] = fp(BigInt(s[idx(name)]) + 1n); };

  const cases = [
    { tag: 'committed(123,456)', in: [123n, 456n] },
    { tag: 'proof1(135208,67633)', in: [135208n, 67633n] },
    { tag: 'dense(r-12345,r-6789)', in: [R - 12345n, R - 6789n] },
  ];
  let allok = true;
  for (const c of cases) {
    const [in0, in1] = c.in;
    const m = measure(in0, in1, null);
    const okAcc = m.accepted;
    // FORGE A: fake divisor (perturb a_num[0]) -> FS challenge shifts / identity fails -> reject
    const fDiv = measure(in0, in1, (s, o) => { bump(s, 'an0'); return { stateArgs: s, outLimbs: o }; });
    // FORGE B: wrong Q (perturb Qx in witness AND covOut out-limb, self-consistent) -> identity fails
    const fQ = measure(in0, in1, (s, o) => { const bad = fp(BigInt(s[idx('Qx')]) + 1n); s[idx('Qx')] = bad; o[0] = bad; return { stateArgs: s, outLimbs: o }; });
    // FORGE C: FS-grind attempt (perturb hint coeff b_den[0]) -> challenge shifts -> reject
    const fFS = measure(in0, in1, (s, o) => { bump(s, 'bd0'); return { stateArgs: s, outLimbs: o }; });
    // FORGE D: tamper a point-challenge term tQ -> RHS wrong -> reject
    const ftQ = measure(in0, in1, (s, o) => { bump(s, 'tQ'); return { stateArgs: s, outLimbs: o }; });
    // FORGE E: non-canonical in0 = in0 + r (same residue mod r, but >= r) -> canonicality reject
    const fCanon = (() => { const d = ecipSpecData(in0, in1); return measureRaw([in0 + R, in1, ...d.extras], [in0 + R, in1], d.outLimbs); })();
    // FORGE F: tamper a sqrt cert in grblob (only meaningful when nfail>0) -> non-residue proof fails
    let fGr = { accepted: false };
    if (c.in[0] === 123n) fGr = measure(in0, in1, (s, o) => { const g = Uint8Array.from(s[idx('grblob')]); if (g.length) g[0] ^= 0x01; s[idx('grblob')] = g; return { stateArgs: s, outLimbs: o }; });
    const forgesReject = !fDiv.accepted && !fQ.accepted && !fFS.accepted && !ftQ.accepted && !fCanon.accepted && !fGr.accepted;
    if (!okAcc || !forgesReject) allok = false;
    console.error(`case ${c.tag}: redeem=${m.lockingBytes}B unlock=${m.unlockingBytes}B op=${m.operationCost.toLocaleString()} accept=${okAcc}` +
      ` | forge fakeDivisor=${!fDiv.accepted} wrongQ=${!fQ.accepted} fsGrind=${!fFS.accepted} tamperTerm=${!ftQ.accepted} nonCanon=${!fCanon.accepted} tamperSqrt=${!fGr.accepted}` +
      (okAcc ? '' : `  ACCEPT-ERR=${m.error}`));
  }
  console.error(allok ? 'ECIP ISOLATED SANITY: ALL PASS (accept + all forges reject)' : 'ECIP ISOLATED SANITY: FAIL');
  process.exit(allok ? 0 : 1);
}
