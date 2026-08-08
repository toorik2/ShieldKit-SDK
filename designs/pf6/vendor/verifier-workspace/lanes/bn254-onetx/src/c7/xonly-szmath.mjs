// Lossless S-Z quotient for the uniform x/slope fixed-G2 table. The selected
// tangent coefficients are multiplied by 4m^2, while addition lines use the
// already-proven c2-normalized form. Both are nonzero Fp2 scales, so final
// exponentiation preserves the pairing result; all dependent S-Z values are
// nevertheless regenerated from the exact scaled trajectory.
import * as base from '../../../../build/chunked/pairing/_szmath.mjs';
import { Fp12, Fp2, f12limbs } from '../../../../build/chunked/pairing/_millermath.mjs';
import { residueWitness } from '../../../../build/chunked/pairing/_residuemath.mjs';
import { isXOnlyFixedDoubleStep } from './xonly-fixed-g2-plan.mjs';

export * from '../../../../build/chunked/pairing/_szmath.mjs';

const FOUR = Fp2.fromBigTuple([4n, 0n]);
const normalizedFixedAdd = (op) => (op.t === 'al' || op.t === 'pp') && (op.j === 2 || op.j === 3);
const normalizedTerminalFixedDouble = (op, opIndex, original) => (
  op.t === 'dl'
  && (op.j === 2 || op.j === 3)
  && opIndex >= original.fused.ops.length - 6
);
const normalizeCoeffs = (coeffs) => {
  const inverseC2 = Fp2.inv(coeffs[2]);
  return coeffs.map((coefficient) => Fp2.mul(coefficient, inverseC2));
};
const xOnlyDoubleCoeffs = (coeffs) => {
  const slope = Fp2.mul(coeffs[1], Fp2.inv(coeffs[2]));
  const scale = Fp2.mul(FOUR, Fp2.sqr(slope));
  return coeffs.map((coefficient) => Fp2.mul(coefficient, scale));
};
const stepForOperation = (original, opIndex) => {
  let step = 0;
  for (let index = 0; index <= opIndex; index += 1) if (original.fused.ops[index].t === 'sqr') step += 1;
  return step;
};
const xOnlyFixedDouble = (op, opIndex, original) => (
  op.t === 'dl'
  && (op.j === 2 || op.j === 3)
  && isXOnlyFixedDoubleStep(stepForOperation(original, opIndex))
);
const pointAt = (t, pair) => {
  if (pair === 0) return [base.mod(t.nA.x), base.mod(t.nA.y)];
  if (pair === 2) return [base.mod(t.vkxAff.x), base.mod(t.vkxAff.y)];
  if (pair === 3) return [base.mod(t.Caf.x), base.mod(t.Caf.y)];
  throw new Error(`unexpected Miller pair ${pair}`);
};
const lineCoeffs = (op, opIndex, original, coeffs) => {
  if (xOnlyFixedDouble(op, opIndex, original)) return xOnlyDoubleCoeffs(coeffs);
  if (normalizedFixedAdd(op) || normalizedTerminalFixedDouble(op, opIndex, original)) return normalizeCoeffs(coeffs);
  return coeffs;
};
const lineFactors = (t, op, opIndex, c, cInv, rawStates) => {
  if (op.t === 'cf') return [op.neg ? c : cInv];
  if (op.t === 'cmul1') return [Fp12.mul(rawStates[opIndex + 1].f, Fp12.inv(rawStates[opIndex].f))];
  const [px, py] = pointAt(t, op.j);
  const records = op.t === 'pp' ? op.coeffs : [op.coeffs];
  return records.map((coeffs) => base.lineFp12(lineCoeffs(op, opIndex, t, coeffs), px, py));
};
const run = (original, c, cInv) => {
  let f = cInv;
  const states = [{ ...original.fused.states[0], f, c, cInv }];
  for (let index = 0; index < original.fused.ops.length; index += 1) {
    const op = original.fused.ops[index];
    if (op.t === 'sqr') f = Fp12.sqr(f);
    else for (const factor of lineFactors(original, op, index, c, cInv, original.fused.states)) f = Fp12.mul(f, factor);
    states.push({ ...original.fused.states[index + 1], f, c, cInv });
  }
  return { ...original.fused, states, boundary: f };
};
const rebuildSteps = (original, fused, c, cInv) => {
  const steps = [];
  let current = null;
  for (let index = 0; index < fused.ops.length; index += 1) {
    const op = fused.ops[index];
    if (op.t === 'sqr') {
      if (current) steps.push(current);
      current = { fin: fused.states[index].f, factors: [], fout: fused.states[index + 1].f, ops: [] };
      continue;
    }
    current.fout = fused.states[index + 1].f;
    for (const [line, factor] of lineFactors(original, op, index, c, cInv, original.fused.states).entries()) {
      current.factors.push(factor);
      current.ops.push({ op, kindOp: op.t, ...(op.t === 'pp' ? { line } : {}), factor });
    }
  }
  if (current) steps.push(current);
  return steps;
};

let cached = null;
export function trajectory() {
  if (cached) return cached;
  if (process.env.SZ_ALLAFF !== '1') throw new Error('x/slope fixed-G2 trajectory requires the all-affine C7 path');
  const original = base.trajectory();
  const raw = run(original, Fp12.ONE, Fp12.ONE);
  const { c, cInv, w } = residueWitness(raw.boundary);
  const fused = run(original, c, cInv);
  const steps = rebuildSteps(original, fused, c, cInv);
  const chain = base.honestChain(steps, fused.boundary);
  const statementFactors = steps.map((step) => step.factors.map(base.towerToPoly));
  const stmtLimbs = base.deployedStatementLimbs(original.nA, original.Baf, original.Caf, original.vkxAff, c, cInv, w);
  const rolling = base.rollGamma(stmtLimbs, chain);
  const bigQ = base.honestBigQ(statementFactors, chain, rolling.gamma);
  const challenge = base.rollZ(rolling.gamma, bigQ);
  const finZ = chain.map((value) => base.peval(base.towerToPoly(value), challenge.z));
  const prodFactorZ = steps.map((step) => step.factors.reduce(
    (product, factor) => base.mmul(product, base.peval(base.towerToPoly(factor), challenge.z)),
    1n,
  ));
  const bigQz = base.peval(bigQ, challenge.z);
  const id = base.aggregatedIdentity(statementFactors, chain, bigQ, rolling.gamma, challenge.z);
  const canonical = base.canonical(c, cInv, w, chain[0]);
  if (!id.holds || !canonical.all) {
    throw new Error(`x/slope S-Z trajectory invariant failed: ${JSON.stringify({ identity: id.holds, canonical: canonical.all })}`);
  }
  cached = {
    ...original, c, cInv, w, fused, steps, chain, statementFactors, stmtLimbs,
    seamH: rolling.hs, blockCount: rolling.blockCount, blockSizes: rolling.blockSizes,
    gamma: rolling.gamma, z: challenge.z, bigQ, bigQz, finZ, prodFactorZ, id,
    fAB: original.fused.fAB, boundary: fused.boundary, xOnlyFixedDoubles: true,
  };
  return cached;
}

export function stepFactorSpec(t, index) {
  return base.stepFactorSpec(t, index).map((factor) => {
    if (factor.kind === 'fixline' && factor.op === 'dl' && isXOnlyFixedDoubleStep(index)) {
      return { ...factor, coeffs: xOnlyDoubleCoeffs(factor.coeffs) };
    }
    if ((factor.kind === 'fixline' && (factor.op === 'al' || (factor.op === 'dl' && index === t.steps.length - 1))) || factor.kind === 'fixpp') {
      return { ...factor, coeffs: normalizeCoeffs(factor.coeffs) };
    }
    return factor;
  });
}

export function prodFactorZfromSpec(t, index, z) {
  const spec = stepFactorSpec(t, index);
  const evaluation = base.ezCols.map((column) => base.peval(column, z));
  const cLimbs = f12limbs(t.c).map(base.mod);
  const cInvLimbs = f12limbs(t.cInv).map(base.mod);
  const fAbLimbs = f12limbs(t.fAB).map(base.mod);
  const dot = (limbs) => limbs.reduce((sum, value, limb) => base.madd(sum, base.mmul(value, evaluation[limb])), 0n);
  let product = 1n;
  for (const factor of spec) {
    if (factor.kind === 'cfold') product = base.mmul(product, dot(factor.useC ? cLimbs : cInvLimbs));
    else if (factor.kind === 'fab') product = base.mmul(product, dot(fAbLimbs));
    else product = base.mmul(product, base.lineFactorZ(factor.coeffs, factor.Px, factor.Py, z));
  }
  return product;
}
