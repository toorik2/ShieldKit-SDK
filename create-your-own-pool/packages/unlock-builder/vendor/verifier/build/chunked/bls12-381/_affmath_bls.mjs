// L10 AFFINE pair0 Miller trajectory (witnessed-slope) for BLS12-381. BLS analog of bn254's
// chunked/pairing/_affmath.mjs. Mirrors _pairingmath.millerBatchOps / _residuemath.millerFusedOps
// EXACTLY, except pair0 (the ONLY runtime-point pair) rides AFFINE coords: its point ops produce a
// witnessed slope `lam`, the affine next point, and line coeffs that equal the projective
// pointDouble/pointAdd at Z=1. Pairs 2,3 keep the projective math (their coeffs are baked / their R
// never rides on-chain); pair 1 is skipped (baked fAB). The folded f differs from the all-projective
// f only by an Fp* factor (dies under ^h in finalExp), so the residue witness is recomputed from THIS
// affine boundary. R[0] is stored AFFINE (4 limbs) instead of projective (6).
import {
  Fp, Fp2, Fp6, Fp12, ATE_NAF, pointDouble, pointAdd, singlePairMiller,
} from './_pairingmath.mjs';
import { conj } from './_residuemath.mjs';

const p = Fp.ORDER;
const SC = (x, k) => Fp2.fromBigTuple([Fp.mul(x.c0, k), Fp.mul(x.c1, k)]);
const B_TWIST = Fp2.fromBigTuple([4n, 4n]); // BLS G2 twist b' = 4 + 4u

// ---- affine pair0 point ops (return coeffs [c0,c1,c2] + affine R{x,y} + witnessed slope lam) ----
export function affDoubleJS(x, y) {
  const c1 = SC(Fp2.sqr(x), 3n);                 // c1 = 3x^2
  const lam = Fp2.mul(c1, Fp2.inv(Fp2.add(y, y))); // lam = 3x^2 / 2y
  const xn = Fp2.sub(Fp2.sqr(lam), Fp2.add(x, x));
  const yn = Fp2.sub(Fp2.mul(lam, Fp2.sub(x, xn)), y);
  const c0 = Fp2.sub(SC(B_TWIST, 3n), Fp2.sqr(y)); // c0 = 3b' - y^2 = (12+12u) - y^2
  const c2 = Fp2.neg(Fp2.add(y, y));               // c2 = -2y
  return { coeffs: [c0, c1, c2], R: { x: xn, y: yn }, lam };
}
export function affAddJS(Rx, Ry, Qx, Qy) {
  const t1 = Fp2.sub(Rx, Qx), t0 = Fp2.sub(Ry, Qy);
  const lam = Fp2.mul(t0, Fp2.inv(t1));            // lam = (Ry-Qy)/(Rx-Qx)
  const xn = Fp2.sub(Fp2.sub(Fp2.sqr(lam), Rx), Qx);
  const yn = Fp2.sub(Fp2.mul(lam, Fp2.sub(Rx, xn)), Ry);
  const c0 = Fp2.sub(Fp2.mul(t0, Qx), Fp2.mul(t1, Qy)), c1 = Fp2.neg(t0), c2 = t1;
  return { coeffs: [c0, c1, c2], R: { x: xn, y: yn }, lam };
}

// ---- BLS line fold (mul014, identical to _pairingmath.lineFn) ----
const fp6Mul1 = (x, b1) => Fp6.create({ c0: Fp2.mulByNonresidue(Fp2.mul(x.c2, b1)), c1: Fp2.mul(x.c0, b1), c2: Fp2.mul(x.c1, b1) });
function mul014(f, o0, o1, o4) {
  const t0 = Fp6.mul01(f.c0, o0, o1);
  const t1 = fp6Mul1(f.c1, o4);
  return Fp12.create({
    c0: Fp6.add(Fp6.mulByNonresidue(t1), t0),
    c1: Fp6.sub(Fp6.sub(Fp6.mul01(Fp6.add(f.c1, f.c0), o0, Fp2.add(o1, o4)), t0), t1),
  });
}
const lineFn = (f, c0, c1, c2, Px, Py) => mul014(f, c0, SC(c1, Px), SC(c2, Py));

// ---- batched Miller, pair0 AFFINE. Same op list / f-fold order as millerBatchOps. Each pair0
// point op records op.lam. states carry pair0 R AFFINE ({x,y}); pairs 1..3 ride projective. ----
export function millerBatchOpsAffine(pairs, opts = {}) {
  const skip = opts.skipPairs ?? new Set();
  const pds = pairs.map((pr) => { const Qa = pr.Q.toAffine(), Pa = pr.P.toAffine(); return { Qx: Qa.x, Qy: Qa.y, negQy: Fp2.neg(Qa.y), Px: Pa.x, Py: Pa.y }; });
  const ops = [];
  for (let k = 0; k < ATE_NAF.length; k++) {
    ops.push({ t: 'sqr' });
    for (let j = 0; j < 4; j++) { if (skip.has(j)) continue; ops.push({ t: 'dl', j }); if (ATE_NAF[k]) ops.push({ t: 'al', j, neg: ATE_NAF[k] === -1 }); }
  }
  const states = [];
  let f = Fp12.ONE;
  const Rs = pds.map((pd, j) => j === 0 ? { x: pd.Qx, y: pd.Qy } : { x: pd.Qx, y: pd.Qy, z: Fp2.ONE });
  for (const op of ops) {
    states.push({ f, Rs: Rs.map((R) => ({ ...R })) });
    if (op.t === 'sqr') { f = Fp12.sqr(f); continue; }
    const pd = pds[op.j];
    if (op.j === 0) { // AFFINE pair0
      if (op.t === 'dl') { const d = affDoubleJS(Rs[0].x, Rs[0].y); Rs[0] = d.R; op.coeffs = d.coeffs; op.lam = d.lam; f = lineFn(f, d.coeffs[0], d.coeffs[1], d.coeffs[2], pd.Px, pd.Py); }
      else { const a = affAddJS(Rs[0].x, Rs[0].y, pd.Qx, op.neg ? pd.negQy : pd.Qy); Rs[0] = a.R; op.coeffs = a.coeffs; op.lam = a.lam; f = lineFn(f, a.coeffs[0], a.coeffs[1], a.coeffs[2], pd.Px, pd.Py); }
    } else { // projective pairs 1..3 (unchanged; baked)
      if (op.t === 'dl') { const d = pointDouble(Rs[op.j].x, Rs[op.j].y, Rs[op.j].z); Rs[op.j] = d.R; op.coeffs = d.coeffs; f = lineFn(f, d.coeffs[0], d.coeffs[1], d.coeffs[2], pd.Px, pd.Py); }
      else { const a = pointAdd(Rs[op.j].x, Rs[op.j].y, Rs[op.j].z, pd.Qx, op.neg ? pd.negQy : pd.Qy); Rs[op.j] = a.R; op.coeffs = a.coeffs; f = lineFn(f, a.coeffs[0], a.coeffs[1], a.coeffs[2], pd.Px, pd.Py); }
    }
  }
  states.push({ f, Rs: Rs.map((R) => ({ ...R })) });
  return { ops, states, boundary: f, finalF: Fp12.conjugate(f) };
}

// ---- c^-|x|-FUSED affine Miller (mirrors _residuemath.millerFusedOps: skip pair1, bake conj(fAB),
// fold c^-|x| across the NAF squarings). pair0 rides AFFINE. ----
const mul = (a, b) => Fp12.mul(a, b), sqr = (a) => Fp12.sqr(a);
export function millerFusedOpsAffine(pairs, c, cInv) {
  const base = millerBatchOpsAffine(pairs, { skipPairs: new Set([1]) });
  const fAB = conj(singlePairMiller(pairs[1]).f); // baked UNCONJUGATED e(alpha,beta) (x<0 -> conj)
  const ops = []; const states = [];
  let cpow = cInv; let k = 0;
  for (let bi = 0; bi < base.ops.length; bi++) {
    const op = base.ops[bi];
    states.push({ f: mul(base.states[bi].f, cpow), Rs: base.states[bi].Rs.map((R) => ({ ...R })), c, cInv });
    ops.push(op.t === 'sqr' ? { t: 'sqr' } : op);
    if (op.t === 'sqr') {
      cpow = sqr(cpow);
      const digit = ATE_NAF[k] ?? 0;
      if (digit !== 0) {
        states.push({ f: mul(base.states[bi + 1].f, cpow), Rs: base.states[bi + 1].Rs.map((R) => ({ ...R })), c, cInv });
        ops.push({ t: 'cf', neg: digit === -1 });
        cpow = mul(cpow, digit === 1 ? cInv : c);
      }
      k++;
    }
  }
  const preF1 = mul(base.boundary, cpow);
  states.push({ f: preF1, Rs: base.states[base.states.length - 1].Rs.map((R) => ({ ...R })), c, cInv });
  ops.push({ t: 'cmul1' });
  const boundary = mul(preF1, fAB);
  states.push({ f: boundary, Rs: base.states[base.states.length - 1].Rs.map((R) => ({ ...R })), c, cInv });
  return { ops, states, boundary, baseBoundary: mul(base.boundary, fAB), cpowFinal: cpow, fAB };
}

// self-test parity when run directly: affine boundary is a valid residue boundary (g_aff^h == 1).
if (process.argv[1] && process.argv[1].endsWith('_affmath_bls.mjs')) {
  const { pairsFor, millerBatchOps } = await import('./_pairingmath.mjs');
  const { residueWitness, eq12 } = await import('./_residuemath.mjs');
  const { PUBLIC_INPUTS } = await import('../../singleton/bls12-381/bls_instance.mjs');
  const r = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
  const h = (p ** 12n - 1n) / r;
  const powE = (a, e) => { let R = Fp12.ONE, b = a; while (e > 0n) { if (e & 1n) R = mul(R, b); b = sqr(b); e >>= 1n; } return R; };
  const pairs = pairsFor(PUBLIC_INPUTS);
  const { boundary: gProj } = millerBatchOps(pairs);
  const { boundary: gAff } = millerBatchOpsAffine(pairs);
  console.log('proj boundary^h == 1 ?', eq12(powE(gProj, h), Fp12.ONE));
  console.log('aff  boundary^h == 1 ?', eq12(powE(gAff, h), Fp12.ONE));
  const ratio = mul(gAff, Fp12.inv(gProj));
  console.log('gAff/gProj in Fp* (c1==0 & c0.c1,c0.c2 zero) ?', ratio.c1.c0.c0 === 0n && ratio.c1.c0.c1 === 0n && ratio.c0.c1.c0 === 0n && ratio.c0.c2.c0 === 0n);
  // residue witness recomputes cleanly from the affine boundary
  const { c, cInv, w } = residueWitness(gAff);
  const fused = millerFusedOpsAffine(pairs, c, cInv);
  console.log('fused affine boundary == gAff*c^-|x| ?', eq12(fused.boundary, mul(gAff, powE(cInv, 0xd201000000010000n))));
  console.log('TAIL gF*w == frob(c,1) ?', eq12(mul(fused.boundary, w), Fp12.frobeniusMap(c, 1)));
  console.log('num fused ops =', fused.ops.length);
}
