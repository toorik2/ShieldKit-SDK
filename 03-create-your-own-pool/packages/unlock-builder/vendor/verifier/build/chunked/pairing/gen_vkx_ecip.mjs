// gen_vkx_ecip.mjs — port of garaga's zk_ecip_hint (pure-python, non-batched, use_rust=False)
// to JS for the T3-2 ECIP vk_x certificate. Emits the 22-coeff SumDlogDiv FunctionFelt hint that
// binds  vk_x = IC0 + in0*IC1 + in1*IC2  via Liam Eagen's principal-divisor / Weil-reciprocity
// check (ePrint 2022/596). BCH bigint => no low/high felt split (garaga's Cairo-only concern).
//
// Faithful port of garaga v1.1.0 hints/ecip.py + algebra.py (Polynomial / RationalFunction /
// FunctionFelt / FF) restricted to BN254 G1 (a=0, b=3). Validated coefficient-for-coefficient
// against garaga's own audited output (generated/_ecip_golden.json) for the real, worst-case and
// dense-2^253 instances. Point arithmetic uses @noble/curves bn254 G1 (same curve, canonical
// affine coordinates); the polynomial/divisor machinery is ported directly.
import { bn254 } from '@noble/curves/bn254.js';
const G1 = bn254.G1.Point;
export const Pbn = 21888242871839275222246405745257275088696311157297823662689037894645226208583n; // base field
export const Rbn = 21888242871839275222246405745257275088548364400416034343698204186575808495617n; // scalar order
const P = Pbn;

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
// polynomial divmod -> [quotient, remainder]
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
const pdivexact = (a, b) => { const [q, r] = pdivmod(a, b); if (!piszero(r)) throw new Error('inexact poly div'); return q; };
// extended gcd -> returns gcd only (garaga uses gcd_0/gcd_1)
function pxgcd_gcd(x, y) {
  let old_r = x.slice(), r = y.slice();
  while (!piszero(r)) { const q = pfloordiv(old_r, r); const nr = psub(old_r, pmul(q, r)); old_r = r; r = nr; }
  const lcinv = finv(plead(old_r));
  return pscale(old_r, lcinv);
}
const peval = (a, x) => { let v = 0n, xi = 1n; for (const c of a) { v = fadd(v, fmul(c, xi)); xi = fmul(xi, x); } return v; };

// ---- FF: list of Polynomials (coeffs in y). y2 = x^3 + 3 (a=0,b=3). ----
const Y2 = [3n, 0n, 0n, 1n]; // b, a, 0, 1
function ffAdd(A, B) { const n = Math.max(A.length, B.length); const r = []; for (let i = 0; i < n; i++) r.push(padd(A[i] ?? PZERO, B[i] ?? PZERO)); return r; }
function ffMulPoly(A, poly) { return A.map((c) => pmul(c, poly)); }
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
const smul = (pt, k) => { k = BigInt(k); if (pt.is0() || k === 0n) return G1.ZERO; const kk = k < 0n ? -k : k; let R = pt.multiplyUnsafe(kk); return k < 0n ? R.negate() : R; };
const isInf = (pt) => pt.is0();
const aff = (pt) => pt.toAffine();

// line(P,Q) -> FF (garaga hints/ecip.py line())
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

// main hint: returns {Qx,Qy, a_num,a_den,b_num,b_den} (all BigInt arrays / values)
export function zkEcipHint(Bs, scalars) {
  const dss = constructDigitVectors(scalars);
  const [Q, Ds] = ecipFunctions(Bs, dss);
  const dlogs = Ds.map(dlog);
  // sum_dlog = dlogs[0] + sum_{i>=1} (-3)^i * dlogs[i]   (RationalFunction add w/ simplify)
  let acc = dlogs[0];
  let f = 1n;
  for (let i = 1; i < dlogs.length; i++) { f = f * -3n; acc = rfSum(acc, scaleDlog(dlogs[i], fp(f))); }
  const qa = aff(Q);
  return { Q, Qx: fp(qa.x), Qy: fp(qa.y), a_num: acc.a_num, a_den: acc.a_den, b_num: acc.b_num, b_den: acc.b_den };
}
// scale a FunctionFelt by scalar: multiply numerators
function scaleDlog(dl, s) { return { a_num: pscale(dl.a_num, s), a_den: dl.a_den, b_num: pscale(dl.b_num, s), b_den: dl.b_den }; }
// RationalFunction add + simplify (garaga RationalFunction.__add__ then .simplify)
function rfAddSimplify(n1, d1, n2, d2) {
  let num = padd(pmul(n1, d2), pmul(n2, d1));
  let den = pmul(d1, d2);
  const g = pxgcd_gcd(num, den);
  num = pfloordiv(num, g); den = pfloordiv(den, g);
  // normalize: num * den.lead^{-1}... garaga: num_s * self.den.lead_inv? Actually simplify does
  // num_simplified * self.denominator.leading_coefficient().__inv__(); den_simplified * den_simplified.lead_inv
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
import { createHash } from 'node:crypto';
import { vmNumberToBigInt } from '@bitauth/libauth';
const le32 = (x) => { const b = Buffer.alloc(32); let v = fp(x); for (let i = 0; i < 32; i++) { b[i] = Number(v & 0xffn); v >>= 8n; } return b; };
// mirror the VM `int(bytes.split(31)[0])`: sign-magnitude decode of the low 31 bytes, then mod P.
const vmInt31 = (digest) => fp(vmNumberToBigInt(digest.subarray(0, 31), { maximumVmNumberByteLength: 32, requireMinimalEncoding: false }));
const sqrtFp = (a) => fpow(fp(a), (P + 1n) / 4n); // P ≡ 3 mod 4
const isQR = (a) => { a = fp(a); if (a === 0n) return true; return fpow(a, (P - 1n) / 2n) === 1n; };

// Fiat–Shamir preimage: le32 of [in0,in1,Qx,Qy] ++ 22 coeffs (a_num4,a_den5,b_num5,b_den8).
// x_seed = VM int() of the low 31 bytes of sha256(preimage), reduced mod P.
export function fsChallenge(in0, in1, Qx, Qy, h) {
  const parts = [in0, in1, Qx, Qy, ...h.a_num, ...h.a_den, ...h.b_num, ...h.b_den].map(le32);
  return vmInt31(createHash('sha256').update(Buffer.concat(parts)).digest());
}

// Full ECIP verification + witness extraction. Mirrors the on-chain algebra step-for-step and
// returns every value the .cash consumes as witness (batch inverses / slopes / challenge terms).
// Throws if the identity does not hold (should never for an honest hint on a QR x_seed).
export const MAXTRY = 8;
const nextX = (x) => vmInt31(createHash('sha256').update(le32(x)).digest());
const rhsOf = (x) => fadd(fmul(fmul(x, x), x), 3n);
/**
 * Measure ECIP nfail from affine IC + public scalars using *this module's* G1.
 * Avoids the cross-instance `@noble/curves` ProjectivePoint bug when callers
 * construct points from a differently resolved bn254 package copy.
 *
 * @param {{ x: string|bigint, y: string|bigint }[]} icAffine length-3
 * @param {bigint[]} scalars [1n, in0, in1]
 * @returns {ReturnType<typeof ecipVerify>}
 */
export function measureEcipNfailFromAffine(icAffine, scalars) {
  if (!Array.isArray(icAffine) || icAffine.length !== 3) {
    throw new Error('measureEcipNfailFromAffine: icAffine must be length-3');
  }
  if (!Array.isArray(scalars) || scalars.length !== 3) {
    throw new Error('measureEcipNfailFromAffine: scalars must be [1, in0, in1]');
  }
  const IC = icAffine.map((p, i) => {
    const x = BigInt(p.x);
    const y = BigInt(p.y);
    // snarkjs infinity encoding for optional IC0
    if (x === 0n && y === 1n) return G1.ZERO;
    return G1.fromAffine({ x, y });
  });
  const scal = scalars.map((s) => BigInt(s));
  const h = zkEcipHint(IC, scal);
  return ecipVerify(IC, scal, h);
}

export function ecipVerify(IC, scalars, h) {
  const Qx = h.Qx, Qy = h.Qy;
  const xseed = fsChallenge(scalars[1], scalars[2], Qx, Qy, h);
  // try-and-increment (garaga derive_ec_point_from_X): advance while rhs(x) is a non-residue.
  // For each FAILED attempt record gRoot = sqrt(3*rhs) (proves rhs non-residue, since 3 is a
  // non-residue). Accepted A0 = (x, yA0=sqrt(rhs)). Bounded at MAXTRY.
  let x = xseed, nfail = 0; const gRoots = [];
  while (!isQR(rhsOf(x))) { gRoots.push(sqrtFp(fmul(3n, rhsOf(x)))); x = nextX(x); nfail++; if (nfail > MAXTRY) throw new Error('MAXTRY exceeded'); }
  const retry0 = nfail === 0;
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
  // ep/en per scalar (base -3)
  const epns = scalars.map((s) => epen(fp(s) === 0n ? 0n : s));
  // Note: for the on-chain loop the scalar is the raw integer; epen wants integer. scalars are ints.
  const EPN = scalars.map((s) => epen(BigInt(s)));
  // point challenge term: mult*(xA0 - Px)/(Py - mA0*Px - bA0)
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
  // f(x,y) = a_num(x)/a_den(x) + y*b_num(x)/b_den(x)
  const adenA0 = peval(h.a_den, xA0), bdenA0 = peval(h.b_den, xA0);
  const adenA2 = peval(h.a_den, xA2), bdenA2 = peval(h.b_den, xA2);
  const fEval = (x, y, iad, ibd) => fadd(fmul(peval(h.a_num, x), iad), fmul(y, fmul(peval(h.b_num, x), ibd)));
  const fA0 = fEval(xA0, yA0, finv(adenA0), finv(bdenA0));
  const fA2 = fEval(xA2, yA2, finv(adenA2), finv(bdenA2));
  const LHS = fsub(fmul(coeff0, fA0), fmul(coeff2, fA2));
  const ok = LHS === RHS;
  return { ok, retry0, nfail, gRoots, xseed, yA0, xA0, yA2, xA2, mA0, bA0, mA0A2, coeff0, coeff2, c2den, RHS, LHS,
    invAdenA0: finv(adenA0), invBdenA0: finv(bdenA0), invAdenA2: finv(adenA2), invBdenA2: finv(bdenA2),
    fA0, fA2, chalWit, tQterm: tQ.term, EPN };
}

// ================= SINGLE-CHUNK .cash VERIFIER GENERATOR =================
// SEAM1 committed state (covIn, decl order) — must equal unified_affine's vkx genesis SEAM1.
export const SEAM1 = ['nAx', 'nAy', 'Bxa', 'Bxb', 'Bya', 'Byb', 'Cx', 'Cy', 'in0', 'in1'];
// SEAM2 emitted (covOut, ptParams order) — vkxX/vkxY carry Q to the miller genesis.
export const SEAM2 = ['nAx', 'nAy', 'Bxa', 'Bxb', 'Bya', 'Byb', 'vkxX', 'vkxY', 'Cx', 'Cy'];
const AN = ['an0', 'an1', 'an2', 'an3'], AD = ['ad0', 'ad1', 'ad2', 'ad3', 'ad4'];
const BN = ['bn0', 'bn1', 'bn2', 'bn3', 'bn4'], BD = ['bd0', 'bd1', 'bd2', 'bd3', 'bd4', 'bd5', 'bd6', 'bd7'];
const GR = Array.from({ length: MAXTRY }, (_, i) => `gr${i}`);
// full witness param order (after SEAM1). emitWitness must produce values in this order.
export const WIT = [
  'Qx', 'Qy', ...AN, ...AD, ...BN, ...BD, 'yA0', 'nfail', ...GR,
  'mA0', 'mA0A2', 'coeff2', 'iad0', 'ibd0', 'iad2', 'ibd2',
  't0p', 't0n', 't1p', 't1n', 't2p', 't2n', 'tQ',
];
const B2 = ['19485874751759354771024239261021720505790618469301721065564631296452457478373',
            '266929791119991161246907387137283842545076965332900288569378510910307636690'];
const FR = '21888242871839275222246405745257275088548364400416034343698204186575808495617';
const PSTR = P.toString();
const horner = (names, X) => { // names LSB-first; returns nested addFp/mulFp expr
  let e = names[names.length - 1];
  for (let i = names.length - 2; i >= 0; i--) e = `addFp(mulFp(${e},${X}),${names[i]})`;
  return e;
};
// emit the single-chunk ECIP vk_x verifier .cash source. `succSpk` = successor (miller genesis) P2SH32 spk hex or null.
export function emitCashVerifier(IC, succSpk, crossPinIdx = null, liteChecks = false, liteB = false) {
  const [[i0x, i0y], [i1x, i1y], [i2x, i2y]] = IC.map((pt) => { const a = aff(pt); return [fp(a.x).toString(), fp(a.y).toString()]; });
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`function addFp(int x,int y) returns(int){return (x+y)%${PSTR};}`);
  L.push(`function subFp(int x,int y) returns(int){return (x-y+${PSTR})%${PSTR};}`);
  L.push(`function mulFp(int x,int y) returns(int){return (x*y)%${PSTR};}`);
  L.push(`function fp2Mul(int a0,int a1,int b0,int b1) returns(int,int){int v0=mulFp(a0,b0);int v1=mulFp(a1,b1);return subFp(v0,v1),subFp(mulFp(addFp(a0,a1),addFp(b0,b1)),addFp(v0,v1));}`);
  L.push(`function fp2Add(int a0,int a1,int b0,int b1) returns(int,int){return addFp(a0,b0),addFp(a1,b1);}`);
  L.push('contract VkxEcip() {');
  L.push(`    function spend(${[...SEAM1, ...WIT].map((n) => `int ${n}`).join(',')}, bytes unused zeroPadding) {`);
  L.push(`        int Pmod = ${PSTR};`);
  // covIn(SEAM1): the covenant ROOT. DIRECT-PORT (channel A): genesis is the ROOT — the root statement
  // (nAx..in1) simply IS its witnessed public input, so the self-NFT covIn is redundant with the scored
  // witness. Drop it (fully tokenless): soundness ("accept iff valid Groth16 on THIS witnessed statement")
  // is unchanged; the ecip MSM below still binds vk_x=Q to in0/in1, and the FS transcript absorbs A/B/C.
  if (process.env.DP !== '1') L.push(`        require(tx.inputs[this.activeInputIndex].nftCommitment == hash256(${SEAM1.map((n) => `toPaddedBytes(${n}, 40)`).join(' + ')}));`);
  // ---- T5-1 relocated input validation ----
  if (process.env.VKX_NOFR !== '1') L.push(`        require(in0 >= 0); require(in1 >= 0); require(in0 < ${FR}); require(in1 < ${FR});`);
  // sr-reconstruct-sz63: liteChecks moves the A(=nA)/C on-curve validations to genesis (which is byte-bound
  // with op headroom and commits the same PT via the vkx cross-pin), shaving ~30 op so the op-tight 2-input
  // ecip fits under the per-input density ceiling. B(twist) validation stays here (needs fp2).
  if (!liteChecks) {
    L.push('        require(mulFp(nAy, nAy) == addFp(mulFp(mulFp(nAx, nAx), nAx), 3));');
    L.push('        require(mulFp(Cy, Cy) == addFp(mulFp(mulFp(Cx, Cx), Cx), 3));');
  }
  {
    L.push('        (int oxa,int oxb) = fp2Mul(Bxa, Bxb, Bxa, Bxb);');
    L.push('        (int oya,int oyb) = fp2Mul(oxa, oxb, Bxa, Bxb);');
    L.push(`        (int ora,int orb) = fp2Add(oya, oyb, ${B2[0]}, ${B2[1]});`);
    L.push('        (int oba,int obb) = fp2Mul(Bya, Byb, Bya, Byb);');
    L.push('        require(oba == ora); require(obb == orb);');
  }
  // ---- canonicality of FS-hashed witnesses (unique serialization) ----
  // liteChecks: Qx/Qy(=vkxX/vkxY) canonicality is enforced in genesis (they are cross-pinned into genesis's
  // PT token, so the identical committed values are range-checked there) — op-offload for the density fit.
  for (const n of ['Qx', 'Qy', ...AN, ...AD, ...BN, ...BD]) L.push(`        require(${n} >= 0); require(${n} < Pmod);`);
  // ---- Fiat-Shamir challenge ----
  const pre = ['in0', 'in1', 'Qx', 'Qy', ...AN, ...AD, ...BN, ...BD].map((n) => `toPaddedBytes(${n}, 32)`).join(' + ');
  L.push(`        int cseed = int(bytes(sha256(${pre}).split(31)[0]));`);
  L.push('        int x = cseed % Pmod; if (x < 0) { x = x + Pmod; }');
  // ---- derive A0: bounded try-and-increment (nfail advances, gRoot proves non-residue) ----
  L.push('        require(nfail >= 0); require(nfail <= ' + MAXTRY + ');');
  for (let t = 0; t < MAXTRY; t++) {
    L.push(`        if (nfail > ${t}) { require(mulFp(${GR[t]}, ${GR[t]}) == mulFp(3, addFp(mulFp(mulFp(x,x),x), 3)));`);
    L.push(`            int hc${t} = int(bytes(sha256(toPaddedBytes(x, 32)).split(31)[0])); x = hc${t} % Pmod; if (x < 0) { x = x + Pmod; } } else { require(${GR[t]} == 0); }`);
  }
  L.push('        int xA0 = x;');
  L.push('        require(mulFp(yA0, yA0) == addFp(mulFp(mulFp(xA0,xA0),xA0), 3));'); // A0 on curve
  // ---- A2 = -2*A0, slopes, coeffs (witness mA0/mA0A2/coeff2, verify) ----
  L.push('        require(mulFp(mulFp(2, yA0), mA0) == mulFp(3, mulFp(xA0, xA0)));'); // tangent slope
  L.push('        int bA0 = subFp(yA0, mulFp(mA0, xA0));');
  L.push('        int x2d = subFp(mulFp(mA0, mA0), mulFp(2, xA0));');
  L.push('        int y2d = subFp(mulFp(mA0, subFp(xA0, x2d)), yA0);');
  L.push('        int xA2 = x2d; int yA2 = subFp(0, y2d);');
  L.push('        require(mulFp(mA0A2, subFp(xA2, xA0)) == subFp(yA2, yA0));'); // slope A2->A0
  L.push('        require(mulFp(coeff2, subFp(mulFp(3, mulFp(xA2, xA2)), mulFp(2, mulFp(mA0A2, yA2)))) == mulFp(2, mulFp(yA2, subFp(xA0, xA2))));');
  L.push('        int coeff0 = addFp(coeff2, mulFp(2, mA0A2));');
  // ---- base(-3) multiplicities ep/en for in0, in1 (scalar 1 => ep=1,en=0) ----
  L.push('        int s0 = in0; int ep0 = 0; int en0 = 0; int s1 = in1; int ep1 = 0; int en1 = 0; int pw = 1;');
  L.push('        for (int k = 0; k < 161; k = k + 1) { if (s0 != 0 || s1 != 0) {');
  L.push('            int r0 = s0 % 3; if (r0 < 0) { r0 = r0 + 3; } int d0 = 0; if (r0 == 2) { d0 = -1; } else { d0 = r0; }');
  L.push('            if (d0 == 1) { ep0 = ep0 + pw; } if (d0 == -1) { en0 = en0 + pw; } s0 = (d0 - s0) / 3;');
  L.push('            int r1 = s1 % 3; if (r1 < 0) { r1 = r1 + 3; } int d1 = 0; if (r1 == 2) { d1 = -1; } else { d1 = r1; }');
  L.push('            if (d1 == 1) { ep1 = ep1 + pw; } if (d1 == -1) { en1 = en1 + pw; } s1 = (d1 - s1) / 3; pw = 0 - (3 * pw); } }');
  L.push('        require(s0 == 0); require(s1 == 0);');
  L.push('        int ep0m = ep0 % Pmod; if (ep0m < 0) { ep0m = ep0m + Pmod; } int en0m = en0 % Pmod; if (en0m < 0) { en0m = en0m + Pmod; }');
  L.push('        int ep1m = ep1 % Pmod; if (ep1m < 0) { ep1m = ep1m + Pmod; } int en1m = en1 % Pmod; if (en1m < 0) { en1m = en1m + Pmod; }');
  // ---- point-challenge terms (witnessed, checked term*den == mult*(xA0-Px)) ----
  // IC0 (scalar 1: ep=1,en=0), IC1 (ep1,en1), IC2 (ep... wait scalars=[1,in0,in1] -> IC1 uses in0, IC2 uses in1
  const chal = (tp, tn, Px, Py, epv, env) => {
    L.push(`        int mx${tp} = mulFp(mA0, ${Px});`);
    L.push(`        require(mulFp(${tp}, subFp(subFp(${Py}, mx${tp}), bA0)) == mulFp(${epv}, subFp(xA0, ${Px})));`);
    L.push(`        require(mulFp(${tn}, subFp(subFp(subFp(0, ${Py}), mx${tp}), bA0)) == mulFp(${env}, subFp(xA0, ${Px})));`);
  };
  chal('t0p', 't0n', i0x, i0y, '1', '0');           // IC0, scalar 1
  chal('t1p', 't1n', i1x, i1y, 'ep0m', 'en0m');      // IC1, scalar in0
  chal('t2p', 't2n', i2x, i2y, 'ep1m', 'en1m');      // IC2, scalar in1
  // -Q term: point (Qx, -Qy), mult 1
  L.push('        int mxQ = mulFp(mA0, Qx);');
  L.push('        require(mulFp(tQ, subFp(subFp(subFp(0, Qy), mxQ), bA0)) == subFp(xA0, Qx));');
  L.push('        int RHS = addFp(tQ, addFp(addFp(t0p, t0n), addFp(addFp(t1p, t1n), addFp(t2p, t2n))));');
  // ---- f(xA0), f(xA2); inverses witnessed ----
  L.push(`        int adA0 = ${horner(AD, 'xA0')}; require(mulFp(adA0, iad0) == 1);`);
  L.push(`        int bdA0 = ${horner(BD, 'xA0')}; require(mulFp(bdA0, ibd0) == 1);`);
  L.push(`        int adA2 = ${horner(AD, 'xA2')}; require(mulFp(adA2, iad2) == 1);`);
  L.push(`        int bdA2 = ${horner(BD, 'xA2')}; require(mulFp(bdA2, ibd2) == 1);`);
  L.push(`        int fA0 = addFp(mulFp(${horner(AN, 'xA0')}, iad0), mulFp(yA0, mulFp(${horner(BN, 'xA0')}, ibd0)));`);
  L.push(`        int fA2 = addFp(mulFp(${horner(AN, 'xA2')}, iad2), mulFp(yA2, mulFp(${horner(BN, 'xA2')}, ibd2)));`);
  L.push('        int LHS = subFp(mulFp(coeff0, fA0), mulFp(coeff2, fA2));');
  L.push('        require(LHS == RHS);');
  // ---- emit SEAM2 (vkxX=Qx, vkxY=Qy) + pin miller genesis ----
  const _SR = process.env.SIBLING_READ === '1';
  // sr-reconstruct-sz63: cross-pin genesis@crossPinIdx (input[crossPinIdx].nft == commit(seam2)) so the
  // verified full vkx point Q = IC0 + in0·IC1 + in1·IC2 binds genesis's PT token (== PT@0's vkxX/vkxY).
  const _tgt = crossPinIdx !== null ? `tx.inputs[${crossPinIdx}]` : (_SR ? 'tx.inputs[this.activeInputIndex + 1]' : 'tx.outputs[0]');
  L.push('        int vkxX = Qx; int vkxY = Qy;');
  // vkxX/vkxY (=Qx/Qy) are already canonicality-validated (>=0, < Pmod) above, so their % Pmod here is dead —
  // drop it (saves 2 big-int OP_MODs, shaving the op-tight 2-input density fit). Other seam2 limbs keep % Pmod
  // (their canonicality is FORCED by this cross-pin match against genesis's raw-committed PT token).
  const extra = (process.env.SR_DROP ?? '').split(',').filter(Boolean);
  const seam2Canon = new Set(['vkxX', 'vkxY', ...extra]);
  L.push(`        require(${_tgt}.nftCommitment == hash256(${SEAM2.map((n) => `toPaddedBytes(${seam2Canon.has(n) ? n : `${n} % Pmod`}, 40)`).join(' + ')}));`);
  L.push(`        require(${_tgt}.tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);`);
  if (succSpk !== null && succSpk !== undefined) {
    const hex = typeof succSpk === 'string' ? succSpk : Buffer.from(succSpk).toString('hex');
    if (!_SR) L.push('        require(tx.outputs.length == 1);');
    L.push(`        require(${_tgt}.lockingBytecode == 0x${hex});`);
  }
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// assemble the witness VALUES in WIT order (after the 10 SEAM1 limbs). Returns BigInt[].
export function emitWitness(IC, scalars, h, v) {
  const gr = Array.from({ length: MAXTRY }, (_, i) => (i < v.gRoots.length ? v.gRoots[i] : 0n));
  const cw = v.chalWit; // [{termP,termN} for IC0,IC1,IC2]
  return [
    h.Qx, h.Qy, ...h.a_num, ...h.a_den, ...h.b_num, ...h.b_den, v.yA0, BigInt(v.nfail), ...gr,
    v.mA0, v.mA0A2, v.coeff2, v.invAdenA0, v.invBdenA0, v.invAdenA2, v.invBdenA2,
    cw[0].termP, cw[0].termN, cw[1].termP, cw[1].termN, cw[2].termP, cw[2].termN, v.tQterm,
  ].map((x) => ((x % P) + P) % P);
}

// ---------- self-test vs golden ----------
if (process.argv[1] && process.argv[1].endsWith('gen_vkx_ecip.mjs')) {
  const { readFileSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const { dirname, join } = await import('node:path');
  const here = dirname(fileURLToPath(import.meta.url));
  // garaga-audited golden reference (tracked at intel/validation/T3-2/; regenerate via that dir's
  // setup_and_run.sh + dump_golden.py). Used ONLY by this self-test — the build never reads it.
  const goldPath = join(here, '../../../intel/validation/T3-2/ecip_golden.json');
  const gold = JSON.parse(readFileSync(goldPath, 'utf8'));
  const IC = gold.IC.map(([x, y]) => G1.fromAffine({ x: BigInt(x), y: BigInt(y) }));
  let allok = true;
  for (const c of gold.cases) {
    const scal = c.scalars.map(BigInt);
    const h = zkEcipHint(IC, scal);
    const cmp = (name, got, exp) => { const e = exp.map(BigInt); const ok = got.length === e.length && got.every((v, i) => v === e[i]); if (!ok) { allok = false; console.log(`  ${c.tag} ${name} MISMATCH got_len=${got.length} exp_len=${e.length}`); } return ok; };
    const okQ = h.Qx === BigInt(c.Qx) && h.Qy === BigInt(c.Qy);
    if (!okQ) { allok = false; console.log(`  ${c.tag} Q MISMATCH`); }
    const oks = [cmp('a_num', h.a_num, c.a_num), cmp('a_den', h.a_den, c.a_den), cmp('b_num', h.b_num, c.b_num), cmp('b_den', h.b_den, c.b_den)];
    console.log(`case ${c.tag}: Q=${okQ} coeffs=${oks.every(Boolean)} counts=(${h.a_num.length},${h.a_den.length},${h.b_num.length},${h.b_den.length})`);
  }
  console.log(allok ? 'ALL GOLDEN MATCH' : 'GOLDEN MISMATCH');
  process.exit(allok ? 0 : 1);
}
