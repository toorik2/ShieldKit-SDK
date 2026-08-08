import { createHash } from 'node:crypto';

import { bn254 } from '../vendor/verifier/build/chunked/pairing/_millermath.mjs';
import {
  ATE_NAF,
  Fp12,
  f12limbs,
  singlePairMiller,
} from '../vendor/verifier/build/chunked/pairing/_millermath.mjs';
import {
  affDoubleJS,
  millerBatchOpsAffine,
} from '../vendor/verifier/build/chunked/pairing/_affmath.mjs';
import {
  canonical,
  e6col,
  ezCols,
  hash256,
  honestChain,
  lineFp12,
  mod,
  mmul,
  madd,
  peval,
  tailHolds,
  towerToPoly,
  wselOf,
} from '../vendor/verifier/build/chunked/pairing/_szmath.mjs';
import {
  residueWitness,
} from '../vendor/verifier/build/chunked/pairing/_residuemath.mjs';
import {
  aggregatedIdentityV2,
  composeMixedGenesisWindows,
  honestBigQV2,
  TAG_GAMMA_FIN_MIXED_V2,
  TAG_GAMMA_MIXED_V2,
  TAG_Z_MIXED_V2,
} from '../vendor/verifier/lanes/bn254-onetx/src/c7/composed-window-szmath.mjs';

export const DIRECT_V2_MILLER_CONTEXT_BYTES = 448;
export const DIRECT_V2_MILLER_SIGNAL_BYTES = 480;
export const DIRECT_V2_MILLER_HEAD_BYTES = 296;
export const DIRECT_V2_MILLER_RESIDUE_BYTES = 1_152;
export const DIRECT_V2_MILLER_ENDPOINT_BYTES = 384;
export const DIRECT_V2_MILLER_SLOPE_BYTES = 64;
export const DIRECT_V2_MILLER_BIGQ_COEFFICIENTS = 190;
export const DIRECT_V2_MILLER_BIGQ_BYTES =
  DIRECT_V2_MILLER_BIGQ_COEFFICIENTS * 32;
export const DIRECT_V2_MILLER_GENESIS_RANGE = Object.freeze([0, 1]);

const { Fp, Fp2 } = bn254.fields;
const P = Fp.ORDER;
const DECIMAL = /^(0|[1-9][0-9]*)$/;

export class DirectV2IdentityAwareMillerError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DirectV2IdentityAwareMillerError';
  }
}

const fail = (message) => {
  throw new DirectV2IdentityAwareMillerError(message);
};

const jsonValue = (value, label) => {
  if (value !== null && typeof value === 'object' && !Buffer.isBuffer(value)) {
    return value;
  }
  try {
    return JSON.parse(Buffer.from(value).toString('utf8'));
  } catch (error) {
    fail(`${label} is not JSON: ${error.message}`);
  }
};

const field = (value, label) => {
  if (
    (typeof value !== 'string' || !DECIMAL.test(value))
    && typeof value !== 'bigint'
    && !(typeof value === 'number' && Number.isSafeInteger(value))
  ) {
    fail(`${label} must be a canonical nonnegative integer`);
  }
  const parsed = BigInt(value);
  if (parsed < 0n || parsed >= P) fail(`${label} is outside the BN254 base field`);
  return parsed;
};

const g1Affine = (value, label, { allowIdentity = false } = {}) => {
  let x;
  let y;
  let identity = false;
  if (Array.isArray(value)) {
    if (value.length !== 3) fail(`${label} must be [x,y,z]`);
    const z = field(value[2], `${label}[2]`);
    if (z === 0n) {
      if (!allowIdentity || BigInt(value[0]) !== 0n || BigInt(value[1]) !== 1n) {
        fail(`${label} has a forbidden or noncanonical identity encoding`);
      }
      identity = true;
      x = 0n;
      y = 0n;
    } else {
      if (z !== 1n) fail(`${label} must be affine`);
      x = field(value[0], `${label}[0]`);
      y = field(value[1], `${label}[1]`);
    }
  } else if (value && typeof value === 'object') {
    if (!Object.hasOwn(value, 'x') || !Object.hasOwn(value, 'y')) {
      fail(`${label} must contain affine x and y coordinates`);
    }
    const rawX = field(value.x, `${label}.x`);
    const rawY = field(value.y, `${label}.y`);
    identity = rawX === 0n && rawY === 0n;
    if (value.infinity === true && !identity) {
      fail(`${label} has conflicting nonzero coordinates and infinity metadata`);
    }
    if (identity) {
      if (!allowIdentity) fail(`${label} must be finite`);
      x = 0n;
      y = 0n;
    } else {
      x = rawX;
      y = rawY;
    }
  } else {
    fail(`${label} must be a G1 point`);
  }
  if (identity) {
    return Object.freeze({
      affine: Object.freeze({ x: 0n, y: 0n }),
      point: bn254.G1.Point.ZERO,
      infinity: true,
    });
  }
  try {
    const point = bn254.G1.Point.fromAffine({ x, y });
    point.assertValidity();
    if (point.equals(bn254.G1.Point.ZERO)) fail(`${label} must be finite`);
    return Object.freeze({
      affine: Object.freeze({ x, y }),
      point,
      infinity: false,
    });
  } catch (error) {
    if (error instanceof DirectV2IdentityAwareMillerError) throw error;
    fail(`${label} is not a valid prime-order BN254 G1 point`);
  }
};

const g2Affine = (value, label) => {
  let x0;
  let x1;
  let y0;
  let y1;
  if (Array.isArray(value)) {
    if (
      value.length !== 3
      || value.some((entry) => !Array.isArray(entry) || entry.length !== 2)
    ) {
      fail(`${label} must be [[x0,x1],[y0,y1],[1,0]]`);
    }
    x0 = field(value[0][0], `${label}[0][0]`);
    x1 = field(value[0][1], `${label}[0][1]`);
    y0 = field(value[1][0], `${label}[1][0]`);
    y1 = field(value[1][1], `${label}[1][1]`);
    if (BigInt(value[2][0]) !== 1n || BigInt(value[2][1]) !== 0n) {
      fail(`${label} must be affine`);
    }
  } else if (value && typeof value === 'object') {
    x0 = field(value.x0 ?? value.x?.c0, `${label}.x0`);
    x1 = field(value.x1 ?? value.x?.c1, `${label}.x1`);
    y0 = field(value.y0 ?? value.y?.c0, `${label}.y0`);
    y1 = field(value.y1 ?? value.y?.c1, `${label}.y1`);
  } else {
    fail(`${label} must be a G2 point`);
  }
  try {
    const point = bn254.G2.Point.fromAffine({
      x: Fp2.fromBigTuple([x0, x1]),
      y: Fp2.fromBigTuple([y0, y1]),
    });
    point.assertValidity();
    if (point.equals(bn254.G2.Point.ZERO)) fail(`${label} must be finite`);
    return Object.freeze({
      affine: Object.freeze({
        x: Object.freeze({ c0: x0, c1: x1 }),
        y: Object.freeze({ c0: y0, c1: y1 }),
      }),
      point,
    });
  } catch (error) {
    if (error instanceof DirectV2IdentityAwareMillerError) throw error;
    fail(`${label} is not a valid prime-order BN254 G2 point`);
  }
};

export function parseDirectV2MillerVerificationKey(value) {
  const raw = jsonValue(value, 'verification key');
  if (
    raw.protocol !== 'groth16'
    || raw.curve !== 'bn128'
    || raw.nPublic !== 2
    || !Array.isArray(raw.IC)
    || raw.IC.length !== 3
  ) {
    fail('verification key must be a two-public-input snarkjs BN254 Groth16 key');
  }
  return Object.freeze({
    raw,
    alpha: g1Affine(raw.vk_alpha_1, 'verification key alpha').point,
    beta: g2Affine(raw.vk_beta_2, 'verification key beta').point,
    gamma: g2Affine(raw.vk_gamma_2, 'verification key gamma').point,
    delta: g2Affine(raw.vk_delta_2, 'verification key delta').point,
    ic: Object.freeze(raw.IC.map((point, index) =>
      g1Affine(point, `verification key IC[${index}]`, {
        allowIdentity: index === 0,
      }).point)),
  });
}

export function parseDirectV2MillerProof(value) {
  if (value?.a && value?.b && value?.c) {
    return Object.freeze({
      a: g1Affine(value.a, 'proof A').point,
      b: g2Affine(value.b, 'proof B').point,
      c: g1Affine(value.c, 'proof C').point,
    });
  }
  const raw = jsonValue(value, 'proof');
  if (raw.protocol !== 'groth16' || raw.curve !== 'bn128') {
    fail('proof must be a snarkjs BN254 Groth16 proof');
  }
  return Object.freeze({
    a: g1Affine(raw.pi_a, 'proof A').point,
    b: g2Affine(raw.pi_b, 'proof B').point,
    c: g1Affine(raw.pi_c, 'proof C').point,
  });
}

const affineG1Object = (point) => {
  const affine = point.toAffine();
  return Object.freeze({ x: mod(affine.x), y: mod(affine.y) });
};

const affineG2Object = (point) => {
  const affine = point.toAffine();
  return Object.freeze({
    x: Object.freeze({ c0: mod(affine.x.c0), c1: mod(affine.x.c1) }),
    y: Object.freeze({ c0: mod(affine.y.c0), c1: mod(affine.y.c1) }),
  });
};

export function createDirectV2IdentityReferenceProof(verificationKey) {
  const key = verificationKey?.alpha
    ? verificationKey
    : parseDirectV2MillerVerificationKey(verificationKey);
  return Object.freeze({
    a: key.alpha,
    b: key.beta.add(key.delta),
    c: key.alpha,
  });
}

const normalizeQ = (value) => {
  if (value === null) {
    return Object.freeze({
      point: bn254.G1.Point.ZERO,
      affine: Object.freeze({ x: 0n, y: 0n }),
      infinity: true,
    });
  }
  return g1Affine(value, 'MSM output Q', { allowIdentity: true });
};

const cloneStates = (states) => states.map((state) => ({
  ...state,
  Rs: state.Rs.map((entry) => ({ ...entry })),
}));

const fusedWithIdentityBranch = (pairs, qInf, c, cInv) => {
  const skipPairs = new Set([1]);
  const base = millerBatchOpsAffine(pairs, {
    skipPairs,
    affPairs: new Set([0, 2, 3]),
  });
  const fAB = singlePairMiller(pairs[1]).f;
  const ops = [];
  const states = [];
  let cpow = cInv;
  let step = 0;
  for (let index = 0; index < base.ops.length; index += 1) {
    const op = base.ops[index];
    states.push({
      f: Fp12.mul(base.states[index].f, cpow),
      Rs: base.states[index].Rs.map((entry) => ({ ...entry })),
      c,
      cInv,
    });
    ops.push(op);
    if (op.t === 'sqr') {
      cpow = Fp12.sqr(cpow);
      const digit = ATE_NAF[step] ?? 0;
      if (digit !== 0) {
        states.push({
          f: Fp12.mul(base.states[index + 1].f, cpow),
          Rs: base.states[index + 1].Rs.map((entry) => ({ ...entry })),
          c,
          cInv,
        });
        ops.push({ t: 'cf', neg: digit === -1 });
        cpow = Fp12.mul(cpow, digit === 1 ? cInv : c);
      }
      step += 1;
    }
  }
  const beforeConstantPair = Fp12.mul(base.boundary, cpow);
  states.push({
    f: beforeConstantPair,
    Rs: base.states.at(-1).Rs.map((entry) => ({ ...entry })),
    c,
    cInv,
  });
  ops.push({ t: 'cmul1' });
  const boundary = Fp12.mul(beforeConstantPair, fAB);
  states.push({
    f: boundary,
    Rs: base.states.at(-1).Rs.map((entry) => ({ ...entry })),
    c,
    cInv,
  });
  return Object.freeze({
    ops,
    states: cloneStates(states),
    boundary,
    fAB,
  });
};

const normalizeCoefficients = (coefficients) => {
  const inverse = Fp2.inv(coefficients[2]);
  return coefficients.map((coefficient) => Fp2.mul(coefficient, inverse));
};

const xOnlyDoubleCoefficients = (coefficients) => {
  const slope = Fp2.mul(coefficients[1], Fp2.inv(coefficients[2]));
  const scale = Fp2.mul(
    Fp2.fromBigTuple([4n, 0n]),
    Fp2.sqr(slope),
  );
  return coefficients.map((coefficient) => Fp2.mul(coefficient, scale));
};

const stepForOperation = (operations, opIndex) => {
  let step = -1;
  for (let index = 0; index <= opIndex; index += 1) {
    if (operations[index].t === 'sqr') step += 1;
  }
  return step;
};

/**
 * Apply the exact fixed-G2 projective representation consumed by the deployed
 * x/slope kernel.
 *
 * Step 0 remains unscaled because the dedicated Miller-genesis lock evaluates
 * its ordinary affine tangent. Interior doubles [1,64) use the x-only
 * 4*m^2-scaled tangent, including the terminal step-64 double, and fixed
 * additions are c2-normalized. These nonzero Fp2 scalings preserve the pairing
 * result after final exponentiation, but the S-Z trajectory and quotient below
 * must (and does) bind the scaled factors.
 */
const fixedLineCoefficients = (
  operations,
  op,
  opIndex,
  coefficients,
) => {
  if (op.j !== 2 && op.j !== 3) return coefficients;
  if (op.t === 'al' || op.t === 'pp') {
    return normalizeCoefficients(coefficients);
  }
  if (op.t !== 'dl') return coefficients;
  const step = stepForOperation(operations, opIndex);
  if (step >= 1 && step <= 64) {
    return xOnlyDoubleCoefficients(coefficients);
  }
  return coefficients;
};

const pointForPair = (trace, pairIndex) => {
  if (pairIndex === 0) return [trace.nA.x, trace.nA.y];
  if (pairIndex === 2) return [trace.q.x, trace.q.y];
  if (pairIndex === 3) return [trace.C.x, trace.C.y];
  fail(`unexpected live Miller pair ${pairIndex}`);
};

const factorsForOperation = (trace, op, opIndex, c, cInv) => {
  if (op.t === 'cf') return [op.neg ? c : cInv];
  if (op.t === 'cmul1') return [trace.fused.fAB];
  // Keep the fixed gamma trajectory in the operation schedule on both
  // branches, but make Q=O algebraically total by omitting every pair-2
  // factor. This gives the executors one fixed witness/table shape without
  // ever evaluating a line at the non-point (0,0).
  if (trace.qInf && op.j === 2) return [];
  const [px, py] = pointForPair(trace, op.j);
  const records = op.t === 'pp' ? op.coeffs : [op.coeffs];
  return records.map((coefficients) => lineFp12(
    fixedLineCoefficients(
      trace.fused.ops,
      op,
      opIndex,
      coefficients,
    ),
    px,
    py,
  ));
};

const runNormalizedQuotient = (trace, c, cInv) => {
  let f = cInv;
  const states = [{ ...trace.fused.states[0], f, c, cInv }];
  for (let index = 0; index < trace.fused.ops.length; index += 1) {
    const op = trace.fused.ops[index];
    if (op.t === 'sqr') {
      f = Fp12.sqr(f);
    } else {
      for (const factorValue of factorsForOperation(trace, op, index, c, cInv)) {
        f = Fp12.mul(f, factorValue);
      }
    }
    states.push({ ...trace.fused.states[index + 1], f, c, cInv });
  }
  return Object.freeze({
    ...trace.fused,
    states,
    boundary: f,
  });
};

const rebuildNormalizedSteps = (trace, fused, c, cInv) => {
  const steps = [];
  let current;
  for (let index = 0; index < fused.ops.length; index += 1) {
    const op = fused.ops[index];
    if (op.t === 'sqr') {
      if (current) steps.push(current);
      current = {
        fin: fused.states[index].f,
        factors: [],
        fout: fused.states[index + 1].f,
        ops: [],
      };
      continue;
    }
    current.fout = fused.states[index + 1].f;
    for (const [line, factorValue] of factorsForOperation(
      trace,
      op,
      index,
      c,
      cInv,
    ).entries()) {
      current.factors.push(factorValue);
      current.ops.push({
        op,
        kindOp: op.t,
        ...(op.t === 'pp' ? { line } : {}),
        factor: factorValue,
      });
    }
  }
  if (current) steps.push(current);
  return steps;
};

const be32 = (value) => {
  const hex = mod(BigInt(value)).toString(16).padStart(64, '0');
  return Buffer.from(hex, 'hex');
};

const be4 = (value) => {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value >>> 0);
  return out;
};

const serializeLimbs = (values) => Buffer.concat(values.map(be32));

const directV2StatementLimbs = ({
  key,
  nA,
  B,
  C,
  q,
  c,
  cInv,
  w,
}) => {
  const g1 = (point) => {
    const affine = point.toAffine();
    return [affine.x, affine.y];
  };
  const g2 = (point) => {
    const affine = point.toAffine();
    return [
      affine.x.c0,
      affine.x.c1,
      affine.y.c0,
      affine.y.c1,
    ];
  };
  return [
    nA.x,
    mod(P - nA.y),
    B.x.c0,
    B.x.c1,
    B.y.c0,
    B.y.c1,
    C.x,
    C.y,
    q.x,
    q.y,
    ...g1(key.alpha),
    ...g2(key.beta),
    ...g2(key.gamma),
    ...g2(key.delta),
    ...f12limbs(c),
    ...f12limbs(cInv),
    ...f12limbs(w),
  ].map(mod);
};

const rollGammaMixed = (statement, anchors) => {
  const blocks = [serializeLimbs(statement), ...anchors.map(serializeLimbs)];
  let h = hash256(TAG_GAMMA_MIXED_V2);
  const hs = [h];
  for (let index = 0; index < blocks.length; index += 1) {
    h = hash256(Buffer.concat([
      h,
      be4(index),
      be4(blocks[index].length),
      blocks[index],
    ]));
    hs.push(h);
  }
  h = hash256(Buffer.concat([
    h,
    TAG_GAMMA_FIN_MIXED_V2,
    be4(blocks.length),
  ]));
  hs.push(h);
  return Object.freeze({
    gamma: mod(BigInt(`0x${h.toString('hex')}`)),
    hs,
    blockCount: blocks.length,
    blockSizes: blocks.map((block) => block.length),
  });
};

const rollZMixed = (gamma, bigQ) => {
  const payload = Buffer.concat([
    TAG_Z_MIXED_V2,
    be32(gamma),
    serializeLimbs(bigQ),
  ]);
  return mod(BigInt(`0x${hash256(payload).toString('hex')}`));
};

export const directV2MillerStepFactorSpec = (trace, index) => {
  const step = trace.steps[index];
  if (!step) fail(`missing Miller step ${index}`);
  const points = {
    0: [trace.nA.x, trace.nA.y],
    2: [trace.q.x, trace.q.y],
    3: [trace.C.x, trace.C.y],
  };
  const out = [];
  for (const entry of step.ops) {
    const op = entry.op;
    if (entry.kindOp === 'cf') {
      out.push(Object.freeze({ kind: 'cfold', useC: Boolean(op.neg) }));
      continue;
    }
    if (entry.kindOp === 'cmul1') {
      out.push(Object.freeze({ kind: 'fab' }));
      continue;
    }
    const [px, py] = points[op.j];
    const rawCoefficients = op.t === 'pp'
      ? op.coeffs[entry.line]
      : op.coeffs;
    const coefficients = fixedLineCoefficients(
      trace.fused.ops,
      op,
      trace.operationIndex.get(op),
      rawCoefficients,
    );
    const variable = op.j === 0;
    out.push(Object.freeze({
      kind: op.t === 'pp'
        ? (variable ? 'varpp' : 'fixpp')
        : (variable ? 'varline' : 'fixline'),
      pair: op.j,
      op: op.t,
      neg: Boolean(op.neg),
      Px: px,
      Py: py,
      coeffs: coefficients,
      lam: variable
        ? (op.t === 'pp' ? op.lams[entry.line] : op.lam)
        : op.lam,
    }));
  }
  return Object.freeze(out);
};

/**
 * Return the fixed-shape operation schedule for one Miller step.
 *
 * Unlike `directV2MillerStepFactorSpec`, this includes the shadow gamma
 * trajectory in the Q=O branch. Entries carry an `active` bit; pair 2 is
 * inactive exactly when the canonical context coordinates are Q=(0,0).
 * This is transport metadata only: `trace.steps[index].factors` remains the
 * authoritative algebraic factor list used by the S-Z relation.
 */
export const directV2MillerShadowStepFactorSpec = (trace, index) => {
  if (!Number.isInteger(index) || index < 0 || index >= trace.steps.length) {
    fail(`missing Miller step ${index}`);
  }
  let step = -1;
  const operations = [];
  for (const op of trace.fused.ops) {
    if (op.t === 'sqr') {
      step += 1;
      continue;
    }
    if (step !== index) continue;
    if (op.t === 'cf') {
      operations.push(Object.freeze({
        kind: 'cfold',
        useC: Boolean(op.neg),
        active: true,
      }));
      continue;
    }
    if (op.t === 'cmul1') {
      operations.push(Object.freeze({ kind: 'fab', active: true }));
      continue;
    }
    const rawRecords = op.t === 'pp' ? op.coeffs : [op.coeffs];
    rawRecords.forEach((rawCoefficients, line) => {
      const coefficients = fixedLineCoefficients(
        trace.fused.ops,
        op,
        trace.operationIndex.get(op),
        rawCoefficients,
      );
      const variable = op.j === 0;
      const point = op.j === 0
        ? [trace.nA.x, trace.nA.y]
        : op.j === 2
          ? [trace.q.x, trace.q.y]
          : [trace.C.x, trace.C.y];
      operations.push(Object.freeze({
        kind: op.t === 'pp'
          ? (variable ? 'varpp' : 'fixpp')
          : (variable ? 'varline' : 'fixline'),
        pair: op.j,
        op: op.t,
        neg: Boolean(op.neg),
        active: !(trace.qInf && op.j === 2),
        Px: point[0],
        Py: point[1],
        coeffs: coefficients,
        lam: op.t === 'pp' ? op.lams[line] : op.lam,
      }));
    });
  }
  return Object.freeze(operations);
};

const rawHashInt = (bytes) => {
  let result = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    result = (result << 8n) | BigInt(bytes[index]);
  }
  return result;
};

const millerBoundaryState = (trace, chainIndex) => {
  const position = trace.anchorIndices.indexOf(chainIndex);
  if (position < 0) fail(`step ${chainIndex} is not a mixed-transcript boundary`);
  let aggL = 0n;
  let aggF = 0n;
  let gp = 1n;
  for (let index = 0; index < position; index += 1) {
    aggL = madd(aggL, mmul(gp, trace.windowProducts[index]));
    aggF = madd(aggF, mmul(gp, trace.anchorZ[index + 1]));
    gp = mmul(gp, trace.gamma);
  }
  const squareStateIndexes = [];
  trace.fused.ops.forEach((op, index) => {
    if (op.t === 'sqr') squareStateIndexes.push(index);
  });
  const r = trace.fused.states[squareStateIndexes[chainIndex]].Rs[0];
  return Object.freeze({
    chainIndex,
    position,
    h: trace.seamH[position + 2],
    hInt: rawHashInt(trace.seamH[position + 2]),
    aggL,
    aggF,
    gp,
    fC: trace.anchorZ[position],
    R: Object.freeze({
      xa: mod(r.x.c0),
      xb: mod(r.x.c1),
      ya: mod(r.y.c0),
      yb: mod(r.y.c1),
    }),
  });
};

export const directV2MillerBoundaryState = (trace, chainIndex) =>
  millerBoundaryState(trace, chainIndex);

export function encodeDirectV2MillerBoundaryState(trace, chainIndex) {
  const state = millerBoundaryState(trace, chainIndex);
  const encoded = Buffer.concat([
    leUnsigned(state.hInt, 40, 'Miller running hash'),
    leUnsigned(state.aggL, 32, 'Miller aggL', { reduce: true }),
    leUnsigned(state.aggF, 32, 'Miller aggF', { reduce: true }),
    leUnsigned(state.gp, 32, 'Miller gamma power', { reduce: true }),
    leUnsigned(state.fC, 32, 'Miller endpoint evaluation', { reduce: true }),
    leUnsigned(state.R.xa, 32, 'Miller R.x.c0', { reduce: true }),
    leUnsigned(state.R.xb, 32, 'Miller R.x.c1', { reduce: true }),
    leUnsigned(state.R.ya, 32, 'Miller R.y.c0', { reduce: true }),
    leUnsigned(state.R.yb, 32, 'Miller R.y.c1', { reduce: true }),
  ]);
  if (encoded.length !== DIRECT_V2_MILLER_HEAD_BYTES) {
    fail('internal Miller boundary width mismatch');
  }
  return encoded;
}

export function computeDirectV2IdentityAwareMiller({
  verificationKey,
  proof,
  q,
}) {
  const key = verificationKey?.alpha
    ? verificationKey
    : parseDirectV2MillerVerificationKey(verificationKey);
  const parsedProof = proof?.a?.toAffine
    ? proof
    : parseDirectV2MillerProof(proof);
  const normalizedQ = normalizeQ(q);
  const nA = affineG1Object(parsedProof.a.negate());
  const B = affineG2Object(parsedProof.b);
  const C = affineG1Object(parsedProof.c);
  const qAffine = normalizedQ.affine;
  const pairs = Object.freeze([
    Object.freeze({ name: 'negA_B', P: parsedProof.a.negate(), Q: parsedProof.b }),
    Object.freeze({ name: 'alpha_beta', P: key.alpha, Q: key.beta }),
    Object.freeze({ name: 'vkx_gamma', P: normalizedQ.point, Q: key.gamma }),
    Object.freeze({ name: 'C_delta', P: parsedProof.c, Q: key.delta }),
  ]);
  const baseFused = fusedWithIdentityBranch(
    pairs,
    normalizedQ.infinity,
    Fp12.ONE,
    Fp12.ONE,
  );
  const baseTrace = {
    key,
    proof: parsedProof,
    pairs,
    qInf: normalizedQ.infinity,
    q: qAffine,
    nA,
    B,
    C,
    fused: baseFused,
  };
  const rawNormalized = runNormalizedQuotient(baseTrace, Fp12.ONE, Fp12.ONE);
  const { c, cInv, w } = residueWitness(rawNormalized.boundary);
  const fused = runNormalizedQuotient(baseTrace, c, cInv);
  const normalizedBase = { ...baseTrace, fused };
  const steps = rebuildNormalizedSteps(baseTrace, fused, c, cInv);
  const chain = honestChain(steps, fused.boundary);
  const statementFactors = steps.map((step) =>
    step.factors.map((factorValue) => towerToPoly(factorValue)));
  const stmtLimbs = directV2StatementLimbs({
    key,
    nA,
    B,
    C,
    q: qAffine,
    c,
    cInv,
    w,
  });
  const v1 = {
    ...normalizedBase,
    c,
    cInv,
    w,
    steps,
    chain,
    statementFactors,
    stmtLimbs,
    fAB: fused.fAB,
    boundary: fused.boundary,
  };
  const windows = composeMixedGenesisWindows(v1, 2);
  const anchorIndices = [
    ...windows.map((window) => window.start),
    steps.length,
  ];
  const anchors = anchorIndices.map((index) => towerToPoly(chain[index]));
  const transcriptAnchors = anchorIndices.map((index) =>
    f12limbs(chain[index]).map(mod));
  const rolling = rollGammaMixed(stmtLimbs, transcriptAnchors);
  const { bigQ: unpaddedBigQ, quotients } = honestBigQV2(
    windows,
    rolling.gamma,
  );
  if (unpaddedBigQ.length > DIRECT_V2_MILLER_BIGQ_COEFFICIENTS) {
    fail(
      `identity-aware quotient has ${unpaddedBigQ.length} coefficients, `
      + `exceeding the fixed ${DIRECT_V2_MILLER_BIGQ_COEFFICIENTS}-coefficient carrier`,
    );
  }
  // The finite four-pair branch has the maximum quotient degree. Canonically
  // append zero high coefficients in the three-pair Q=O branch so z commits
  // to one proof-independent 6,080-byte shape and every verifier unlock has a
  // fixed layout. Appending high zero coefficients preserves Q(z) exactly.
  const bigQ = Object.freeze([
    ...unpaddedBigQ,
    ...Array(
      DIRECT_V2_MILLER_BIGQ_COEFFICIENTS - unpaddedBigQ.length,
    ).fill(0n),
  ]);
  const z = rollZMixed(rolling.gamma, bigQ);
  const identity = aggregatedIdentityV2(
    windows,
    anchors,
    bigQ,
    rolling.gamma,
    z,
  );
  if (!identity.holds) fail('identity-aware mixed S-Z invariant failed');
  if (!canonical(c, cInv, w, chain[0]).all) {
    fail('identity-aware residue witness is noncanonical');
  }
  if (!tailHolds(chain.at(-1), c, cInv, w)) {
    fail(`identity-aware residue tail does not hold (chain-boundary=${Fp12.eql(chain.at(-1), fused.boundary)}, normalized-raw=${Fp12.eql(rawNormalized.boundary, fused.boundary)})`);
  }
  const operationIndex = new Map(fused.ops.map((op, index) => [op, index]));
  const trace = {
    ...v1,
    v1,
    windows,
    anchors,
    transcriptAnchors,
    anchorIndices,
    quotients,
    seamH: rolling.hs,
    blockCount: rolling.blockCount,
    blockSizes: rolling.blockSizes,
    gamma: rolling.gamma,
    z,
    bigQ,
    bigQz: peval(bigQ, z),
    anchorZ: identity.anchorZ,
    windowProducts: identity.products,
    id: identity,
    operationIndex,
    activePairNames: Object.freeze(
      pairs.filter((_, index) => index !== 2 || !normalizedQ.infinity)
        .map((pair) => pair.name),
    ),
    transcriptVersion: normalizedQ.infinity
      ? '2-mixed-genesis-identity-3pair'
      : '2-mixed-genesis-affine-4pair',
    gammaTag: TAG_GAMMA_MIXED_V2,
    gammaFinTag: TAG_GAMMA_FIN_MIXED_V2,
    zTag: TAG_Z_MIXED_V2,
    scalarEndpoint: false,
  };
  trace.genesisState = millerBoundaryState(trace, 1);
  return Object.freeze(trace);
}

const encodeUnsigned = (value, bytes, label, { reduce = false } = {}) => {
  const parsed = reduce ? mod(BigInt(value)) : BigInt(value);
  if (parsed < 0n || parsed >= (1n << BigInt(bytes * 8))) {
    fail(`${label} does not fit ${bytes} bytes`);
  }
  return Buffer.from(parsed.toString(16).padStart(bytes * 2, '0'), 'hex');
};

const leUnsigned = (value, bytes, label, options) =>
  Buffer.from(encodeUnsigned(value, bytes, label, options)).reverse();

export function encodeDirectV2MillerProjectionContext(trace) {
  const ez = ezCols.map((column) => peval(column, trace.z));
  const dot = (tower) => f12limbs(tower).reduce(
    (sum, value, index) => madd(sum, mmul(mod(value), ez[index])),
    0n,
  );
  const values = [
    trace.gamma,
    trace.z,
    trace.nA.x,
    trace.nA.y,
    trace.q.x,
    trace.q.y,
    trace.C.x,
    trace.C.y,
    trace.B.x.c0,
    trace.B.x.c1,
    trace.B.y.c0,
    trace.B.y.c1,
    dot(trace.c),
    dot(trace.cInv),
  ];
  const encoded = Buffer.concat(values.map((value, index) =>
    leUnsigned(value, 32, `Miller context limb ${index}`, { reduce: true })));
  if (encoded.length !== DIRECT_V2_MILLER_CONTEXT_BYTES) {
    fail('internal Miller context width mismatch');
  }
  return encoded;
}

export function encodeDirectV2MillerProjectionSignal(trace, actionDigest) {
  if (!(actionDigest instanceof Uint8Array) || actionDigest.length !== 32) {
    fail('action digest must contain exactly 32 bytes');
  }
  return Buffer.concat([
    encodeDirectV2MillerProjectionContext(trace),
    Buffer.from(actionDigest),
  ]);
}

export function encodeDirectV2MillerGenesisHead(trace) {
  const state = trace.genesisState ?? millerBoundaryState(trace, 1);
  const encoded = Buffer.concat([
    leUnsigned(state.hInt, 40, 'Miller running hash'),
    leUnsigned(state.aggL, 32, 'Miller aggL', { reduce: true }),
    leUnsigned(state.aggF, 32, 'Miller aggF', { reduce: true }),
    leUnsigned(state.gp, 32, 'Miller gamma power', { reduce: true }),
    leUnsigned(state.fC, 32, 'Miller endpoint evaluation', { reduce: true }),
    leUnsigned(state.R.xa, 32, 'Miller R.x.c0', { reduce: true }),
    leUnsigned(state.R.xb, 32, 'Miller R.x.c1', { reduce: true }),
    leUnsigned(state.R.ya, 32, 'Miller R.y.c0', { reduce: true }),
    leUnsigned(state.R.yb, 32, 'Miller R.y.c1', { reduce: true }),
  ]);
  if (encoded.length !== DIRECT_V2_MILLER_HEAD_BYTES) {
    fail('internal Miller head width mismatch');
  }
  return encoded;
}

export function encodeDirectV2MillerGenesisWitness(trace) {
  const step = directV2MillerStepFactorSpec(trace, 0);
  const slopes = step
    .filter((factorValue) => factorValue.kind === 'varline')
    .flatMap((factorValue) => [
      mod(factorValue.lam.c0),
      mod(factorValue.lam.c1),
    ]);
  if (slopes.length !== 2) {
    fail(`singleton genesis expected two affine-slope limbs, got ${slopes.length}`);
  }
  const residue = Buffer.concat([
    ...f12limbs(trace.c),
    ...f12limbs(trace.cInv),
    ...f12limbs(trace.w),
  ].map((value, index) =>
    encodeUnsigned(mod(value), 32, `residue limb ${index}`)));
  const endpoint = Buffer.concat(f12limbs(trace.chain[1]).map((value, index) =>
    encodeUnsigned(mod(value), 32, `step-1 endpoint limb ${index}`)));
  const slope = Buffer.concat(slopes.map((value, index) =>
    encodeUnsigned(value, 32, `step-0 slope limb ${index}`)));
  if (
    residue.length !== DIRECT_V2_MILLER_RESIDUE_BYTES
    || endpoint.length !== DIRECT_V2_MILLER_ENDPOINT_BYTES
    || slope.length !== DIRECT_V2_MILLER_SLOPE_BYTES
  ) {
    fail('internal Miller witness width mismatch');
  }
  return Object.freeze({ residue, endpoint, slope });
}

export function directV2MillerFixedStep0(verificationKey) {
  const key = verificationKey?.alpha
    ? verificationKey
    : parseDirectV2MillerVerificationKey(verificationKey);
  const gamma = key.gamma.toAffine();
  const delta = key.delta.toAffine();
  return Object.freeze({
    key,
    gamma: Object.freeze({
      point: affineG2Object(key.gamma),
      coefficients: affDoubleJS(gamma.x, gamma.y).coeffs,
    }),
    delta: Object.freeze({
      point: affineG2Object(key.delta),
      coefficients: affDoubleJS(delta.x, delta.y).coeffs,
    }),
  });
}

export function directV2MillerPairingReference(trace) {
  const activePairs = trace.pairs.filter(
    (_, index) => index !== 2 || !trace.qInf,
  );
  return bn254.pairingBatch(
    activePairs.map((pair) => ({ g1: pair.P, g2: pair.Q })),
    true,
  );
}

export const directV2MillerPairingReferenceIsOne = (trace) =>
  Fp12.eql(directV2MillerPairingReference(trace), Fp12.ONE);

export function directV2MillerWitnessDigest(trace) {
  const witness = encodeDirectV2MillerGenesisWitness(trace);
  return createHash('sha256')
    .update(witness.residue)
    .update(witness.endpoint)
    .update(witness.slope)
    .digest('hex');
}

export const DIRECT_V2_MILLER_EZ_COLUMNS = ezCols;
export const DIRECT_V2_MILLER_E6_COLUMNS = e6col;
export const DIRECT_V2_MILLER_TAG_GAMMA = TAG_GAMMA_MIXED_V2;
export const DIRECT_V2_MILLER_TAG_GAMMA_FINAL = TAG_GAMMA_FIN_MIXED_V2;
export const DIRECT_V2_MILLER_TAG_Z = TAG_Z_MIXED_V2;
export const DIRECT_V2_MILLER_WSEL = wselOf;
