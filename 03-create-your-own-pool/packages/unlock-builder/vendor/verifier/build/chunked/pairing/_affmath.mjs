// S3 AFFINE pair0 Miller trajectory (witnessed-slope). Mirrors _millermath.millerBatchOps /
// _residuemath.millerFusedOps EXACTLY, except pair0's (the ONLY runtime-point pair) point ops
// run in AFFINE coords producing a witnessed slope `lam`, the affine next point, and line coeffs
// that equal pointDouble/pointAdd at Z=1 (proven vs noble). Pairs 1,2,3 keep the Jacobian math
// (their coeffs are baked / their R never rides on-chain), so the folded f differs from the
// all-Jacobian f only by an Fp* factor (dies in finalExp) and the residue witness is recomputed
// from THIS boundary. R[0] is stored AFFINE (4 limbs) instead of Jacobian (6).
import {
  bn254, Fp2, Fp6, Fp12, Fp2B, ATE_NAF, pointDouble, pointAdd,
} from './_millermath.mjs';
const { Fp } = bn254.fields;
const SC = (x, k) => Fp2.fromBigTuple([Fp.mul(x.c0, k), Fp.mul(x.c1, k)]);
const PSI_X = Fp2.pow(Fp2.NONRESIDUE, (Fp.ORDER - 1n) / 3n);
const PSI_Y = Fp2.pow(Fp2.NONRESIDUE, (Fp.ORDER - 1n) / 2n);

// ---- affine pair0 point ops (return coeffs + affine R + witnessed slope lam) ----
export function affDoubleJS(x, y) {
  const l3 = SC(Fp2.sqr(x), 3n), lam = Fp2.mul(l3, Fp2.inv(Fp2.add(y, y)));
  const xn = Fp2.sub(Fp2.sqr(lam), Fp2.add(x, x));
  const yn = Fp2.sub(Fp2.mul(lam, Fp2.sub(x, xn)), y);
  const c0 = Fp2.sub(SC(Fp2B, 3n), Fp2.sqr(y)), c1 = l3, c2 = Fp2.neg(Fp2.add(y, y));
  return { coeffs: [c0, c1, c2], R: { x: xn, y: yn }, lam };
}
export function affAddJS(Rx, Ry, Qx, Qy) {
  const t1 = Fp2.sub(Rx, Qx), t0 = Fp2.sub(Ry, Qy), lam = Fp2.mul(t0, Fp2.inv(t1));
  const xn = Fp2.sub(Fp2.sub(Fp2.sqr(lam), Rx), Qx);
  const yn = Fp2.sub(Fp2.mul(lam, Fp2.sub(Rx, xn)), Ry);
  const c0 = Fp2.sub(Fp2.mul(t0, Qx), Fp2.mul(t1, Qy)), c1 = Fp2.neg(t0), c2 = t1;
  return { coeffs: [c0, c1, c2], R: { x: xn, y: yn }, lam };
}

// ---- line fold (identical convention to _millermath.lineFn: mul034(f, c2*Py, c1*Px, c0)) ----
function mul034(f, o0, o3, o4) {
  const A = Fp6.create({ c0: Fp2.mul(f.c0.c0, o0), c1: Fp2.mul(f.c0.c1, o0), c2: Fp2.mul(f.c0.c2, o0) });
  const B = Fp6.mul01(f.c1, o3, o4);
  const E = Fp6.mul01(Fp6.add(f.c0, f.c1), Fp2.add(o0, o3), o4);
  return Fp12.create({ c0: Fp6.add(Fp6.mulByNonresidue(B), A), c1: Fp6.sub(E, Fp6.add(A, B)) });
}
const lineFn = (f, c0, c1, c2, Px, Py) => mul034(f, SC(c2, Py), SC(c1, Px), c0);
const psi = (x, y) => [Fp2.mul(Fp2.frobeniusMap(x, 1), PSI_X), Fp2.mul(Fp2.frobeniusMap(y, 1), PSI_Y)];

// ---- batched Miller, pair0 AFFINE. Same op list / f-fold order as millerBatchOps. Each pair0
// point op records op.lam (dl/al) or op.lams (pp's two psi-adds). states carry pair0 R AFFINE. ----
export function millerBatchOpsAffine(pairs, opts = {}) {
  const skip = opts.skipPairs ?? new Set();
  const affSet = opts.affPairs ?? new Set([0]);
  const pds = pairs.map((p) => { const Qa = p.Q.toAffine(), Pa = p.P.toAffine(); return { Qx: Qa.x, Qy: Qa.y, negQy: Fp2.neg(Qa.y), Px: Pa.x, Py: Pa.y }; });
  const ops = [];
  for (let k = 0; k < ATE_NAF.length; k++) {
    ops.push({ t: 'sqr' });
    for (let j = 0; j < 4; j++) { if (skip.has(j)) continue; ops.push({ t: 'dl', j }); if (ATE_NAF[k]) ops.push({ t: 'al', j, neg: ATE_NAF[k] === -1 }); }
  }
  for (let j = 0; j < 4; j++) { if (skip.has(j)) continue; ops.push({ t: 'pp', j }); }
  const states = [];
  let f = Fp12.ONE;
  // affSet rides AFFINE {x,y}; remaining pairs ride Jacobian {x,y,z}.
  const Rs = pds.map((pd, j) => affSet.has(j) ? { x: pd.Qx, y: pd.Qy } : { x: pd.Qx, y: pd.Qy, z: Fp2.ONE });
  for (const op of ops) {
    states.push({ f, Rs: Rs.map((R) => ({ ...R })) });
    if (op.t === 'sqr') { f = Fp12.sqr(f); continue; }
    const pd = pds[op.j], j = op.j;
    if (affSet.has(j)) {
      if (op.t === 'dl') { const d = affDoubleJS(Rs[j].x, Rs[j].y); Rs[j] = d.R; op.coeffs = d.coeffs; op.lam = d.lam; f = lineFn(f, d.coeffs[0], d.coeffs[1], d.coeffs[2], pd.Px, pd.Py); }
      else if (op.t === 'al') { const a = affAddJS(Rs[j].x, Rs[j].y, pd.Qx, op.neg ? pd.negQy : pd.Qy); Rs[j] = a.R; op.coeffs = a.coeffs; op.lam = a.lam; f = lineFn(f, a.coeffs[0], a.coeffs[1], a.coeffs[2], pd.Px, pd.Py); }
      else {                                            // pp: two psi-adds
        const q1 = psi(pd.Qx, pd.Qy);
        const a1 = affAddJS(Rs[j].x, Rs[j].y, q1[0], q1[1]); Rs[j] = a1.R; f = lineFn(f, a1.coeffs[0], a1.coeffs[1], a1.coeffs[2], pd.Px, pd.Py);
        const q2 = psi(q1[0], q1[1]); const q2ny = Fp2.neg(q2[1]);
        const a2 = affAddJS(Rs[j].x, Rs[j].y, q2[0], q2ny); Rs[j] = a2.R; f = lineFn(f, a2.coeffs[0], a2.coeffs[1], a2.coeffs[2], pd.Px, pd.Py);
        op.coeffs = [a1.coeffs, a2.coeffs]; op.lams = [a1.lam, a2.lam]; op.q1 = q1; op.q2 = q2; op.q2ny = q2ny;
      }
    } else {                                            // Jacobian pairs 1..3 (unchanged)
      if (op.t === 'dl') { const d = pointDouble(Rs[op.j].x, Rs[op.j].y, Rs[op.j].z); Rs[op.j] = d.R; op.coeffs = d.coeffs; f = lineFn(f, d.coeffs[0], d.coeffs[1], d.coeffs[2], pd.Px, pd.Py); }
      else if (op.t === 'al') { const a = pointAdd(Rs[op.j].x, Rs[op.j].y, Rs[op.j].z, pd.Qx, op.neg ? pd.negQy : pd.Qy); Rs[op.j] = a.R; op.coeffs = a.coeffs; f = lineFn(f, a.coeffs[0], a.coeffs[1], a.coeffs[2], pd.Px, pd.Py); }
      else {
        const q1 = psi(pd.Qx, pd.Qy);
        let a1 = pointAdd(Rs[op.j].x, Rs[op.j].y, Rs[op.j].z, q1[0], q1[1]); Rs[op.j] = a1.R; f = lineFn(f, a1.coeffs[0], a1.coeffs[1], a1.coeffs[2], pd.Px, pd.Py);
        const q2 = psi(q1[0], q1[1]);
        let a2 = pointAdd(Rs[op.j].x, Rs[op.j].y, Rs[op.j].z, q2[0], Fp2.neg(q2[1])); Rs[op.j] = a2.R; f = lineFn(f, a2.coeffs[0], a2.coeffs[1], a2.coeffs[2], pd.Px, pd.Py);
        op.coeffs = [a1.coeffs, a2.coeffs];
      }
    }
  }
  states.push({ f, Rs: Rs.map((R) => ({ ...R })) });
  return { ops, states, boundary: f };
}

// ---- c^-(6x+2)-FUSED affine Miller (mirrors _residuemath.millerFusedOps) ----
const mul = (a, b) => Fp12.mul(a, b), sqr = (a) => Fp12.sqr(a);
export function millerFusedOpsAffine(pairs, c, cInv, singlePairMiller, opts = {}) {
  const base = millerBatchOpsAffine(pairs, { skipPairs: new Set([1]), affPairs: opts.affPairs });
  const fAB = singlePairMiller(pairs[1]).f;
  const ops = []; const states = [];
  let cpow = cInv; let k = 0;
  for (let bi = 0; bi < base.ops.length; bi++) {
    const op = base.ops[bi];
    states.push({ f: mul(base.states[bi].f, cpow), Rs: base.states[bi].Rs.map((R) => ({ ...R })), c, cInv });
    ops.push(op);
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
  if (process.env.T7 === '1') return { ops, states, boundary: preF1, fAB };
  ops.push({ t: 'cmul1' });
  const boundary = mul(preF1, fAB);
  states.push({ f: boundary, Rs: base.states[base.states.length - 1].Rs.map((R) => ({ ...R })), c, cInv });
  return { ops, states, boundary, fAB };
}
