// Deterministic fixed-G2 Miller-line table for the K=13 research topology.
//
// This is not a verifier path and is deliberately not selected by a candidate
// profile. It exposes the actual gamma/delta line coefficients already present
// in the live affine trajectory, in the exact record shape a future locking
// bytecode carrier would need. A carrier decoder must bind these window digests
// and retain the normal verification-key/deployment binding; this module alone
// supplies neither.
import { createHash } from 'node:crypto';
import { trajectory, stepFactorSpec, P, mod } from '../../../../build/chunked/pairing/_szmath.mjs';
import { Fp2, vk } from '../../../../build/chunked/pairing/_millermath.mjs';

export const FP_BYTES = 32;
export const LINE_PAIR_LIMBS = 12; // gamma triple + delta triple, each 3 x Fp2
export const LINE_PAIR_BYTES = LINE_PAIR_LIMBS * FP_BYTES;
// A compact record retains c1,c2 for each fixed pair. c0 is reconstructed
// from the curve equation (doubling) or from the fixed addend (addition).
// This is deliberately an extractor/invariant, not a candidate transport.
export const COMPACT_LINE_PAIR_LIMBS = 8;
export const COMPACT_LINE_PAIR_BYTES = COMPACT_LINE_PAIR_LIMBS * FP_BYTES;
// Addition lines are projective: divide their three Fp2 coefficients by c2,
// retain c1/c2, and reconstruct c0/c2 from the fixed addend.  The quotient is
// an Fp2 factor, which is killed by the final exponentiation; the companion
// normalized S-Z trajectory binds the changed intermediate chain exactly.
export const NORMALIZED_ADD_PAIR_LIMBS = 4;
export const NORMALIZED_ADD_PAIR_BYTES = NORMALIZED_ADD_PAIR_LIMBS * FP_BYTES;

const C3B = Object.freeze({
  c0: 14681138511599513868579906292550611339979233093309515871315818100066920017953n,
  c1: 800789373359973483740722161411851527635230895998700865708135532730922910070n,
});
const INV4 = (P + 1n) / 4n;

const sha256d = (bytes) => {
  const once = createHash('sha256').update(bytes).digest();
  return Uint8Array.from(createHash('sha256').update(once).digest());
};
const cat = (...parts) => {
  const bytes = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(bytes);
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
};
const leFp = (value) => {
  let current = mod(BigInt(value));
  const out = new Uint8Array(FP_BYTES);
  for (let i = 0; i < FP_BYTES; i++) { out[i] = Number(current & 0xffn); current >>= 8n; }
  return out;
};
const fromLeFp = (bytes) => {
  if (!(bytes instanceof Uint8Array) || bytes.length !== FP_BYTES) throw new Error('fixed line limb must be 32 B');
  let value = 0n;
  for (let i = FP_BYTES - 1; i >= 0; i--) value = (value << 8n) | BigInt(bytes[i]);
  return value;
};
const flattenCoeffs = (coeffs) => coeffs.flatMap((fp2) => [mod(fp2.c0), mod(fp2.c1)]);
const bytesEq = (a, b) => a.length === b.length && a.every((value, i) => value === b[i]);
const fp2 = (c0, c1) => ({ c0: mod(c0), c1: mod(c1) });
const fp2Eq = (a, b) => mod(a.c0) === mod(b.c0) && mod(a.c1) === mod(b.c1);
const fp2Add = (a, b) => fp2(a.c0 + b.c0, a.c1 + b.c1);
const fp2Neg = (a) => fp2(-a.c0, -a.c1);
const fp2Sub = (a, b) => fp2(a.c0 - b.c0, a.c1 - b.c1);
const fp2Mul = (a, b) => fp2(a.c0 * b.c0 - a.c1 * b.c1, a.c0 * b.c1 + a.c1 * b.c0);
const fp2Scale = (a, scalar) => fp2(a.c0 * scalar, a.c1 * scalar);
const pointFp2 = (point) => {
  const affine = point.toAffine();
  return { x: fp2(affine.x.c0, affine.x.c1), y: fp2(affine.y.c0, affine.y.c1) };
};
const FIXED_ADDENDS = Object.freeze({ gamma: pointFp2(vk.gamma), delta: pointFp2(vk.delta) });

const compactPair = (coeffs) => [coeffs[1], coeffs[2]];
const compactLimbs = (gamma, delta) => [...flattenCoeffs(compactPair(gamma)), ...flattenCoeffs(compactPair(delta))];
const normalizedAddSlope = (coeffs) => {
  const c1 = Fp2.fromBigTuple([coeffs[1].c0, coeffs[1].c1]);
  const c2 = Fp2.fromBigTuple([coeffs[2].c0, coeffs[2].c1]);
  const slope = Fp2.mul(c1, Fp2.inv(c2));
  return fp2(slope.c0, slope.c1);
};
const normalizedAddLimbs = (gamma, delta) => [...flattenCoeffs([normalizedAddSlope(gamma)]), ...flattenCoeffs([normalizedAddSlope(delta)])];
const reconstructC0 = (line, pair) => {
  const [, c1, c2] = line;
  if (pair.op === 'dl') return fp2Sub(C3B, fp2Scale(fp2Mul(c2, c2), INV4));
  if (pair.op === 'al') {
    const base = pair.pair === 2 ? FIXED_ADDENDS.gamma : FIXED_ADDENDS.delta;
    const qy = pair.neg ? fp2Neg(base.y) : base.y;
    return fp2Neg(fp2Add(fp2Mul(c1, base.x), fp2Mul(c2, qy)));
  }
  throw new Error(`cannot compact fixed-G2 line op ${pair.op}`);
};

function fixedForStep(step) {
  const fixed = stepFactorSpec(trajectory(), step).filter((factor) => factor.kind === 'fixline');
  const events = [];
  for (const op of ['dl', 'al']) {
    const gamma = fixed.find((factor) => factor.pair === 2 && factor.op === op);
    const delta = fixed.find((factor) => factor.pair === 3 && factor.op === op);
    if (!gamma && !delta) continue;
    if (!gamma || !delta) throw new Error(`fixed-G2 table step ${step} has unpaired ${op} line`);
    const limbs = [...flattenCoeffs(gamma.coeffs), ...flattenCoeffs(delta.coeffs)];
    if (limbs.length !== LINE_PAIR_LIMBS) throw new Error(`fixed-G2 table step ${step} has ${limbs.length} limbs`);
    const compact = compactLimbs(gamma.coeffs, delta.coeffs);
    const normalizedAdd = op === 'al' ? normalizedAddLimbs(gamma.coeffs, delta.coeffs) : null;
    events.push({
      step,
      op,
      gamma,
      delta,
      limbs,
      bytes: cat(...limbs.map(leFp)),
      compactLimbs: compact,
      compactBytes: cat(...compact.map(leFp)),
      normalizedAddLimbs: normalizedAdd,
      normalizedAddBytes: normalizedAdd ? cat(...normalizedAdd.map(leFp)) : null,
    });
  }
  return events;
}

export const fixedLineEvents = () => {
  const steps = trajectory().steps.length;
  const events = [];
  for (let step = 1; step < steps - 1; step++) events.push(...fixedForStep(step));
  return events;
};

export const fixedLineWindow = (lo, hi) => {
  if (!Number.isInteger(lo) || !Number.isInteger(hi) || lo < 1 || hi <= lo || hi > trajectory().steps.length - 1) {
    throw new Error(`invalid fixed-G2 window [${lo}, ${hi})`);
  }
  const events = [];
  for (let step = lo; step < hi; step++) events.push(...fixedForStep(step));
  const bytes = cat(...events.map((event) => event.bytes));
  return {
    lo,
    hi,
    events,
    bytes,
    digest: sha256d(bytes),
    digestHex: Buffer.from(sha256d(bytes)).toString('hex'),
  };
};

export const compactFixedLineWindow = (lo, hi) => {
  const full = fixedLineWindow(lo, hi);
  const bytes = cat(...full.events.map((event) => event.compactBytes));
  return {
    ...full,
    bytes,
    digest: sha256d(bytes),
    digestHex: Buffer.from(sha256d(bytes)).toString('hex'),
  };
};

export const normalizedFixedLineWindow = (lo, hi) => {
  const full = fixedLineWindow(lo, hi);
  const bytes = cat(...full.events.map((event) => event.op === 'al' ? event.normalizedAddBytes : event.compactBytes));
  return {
    ...full,
    bytes,
    digest: sha256d(bytes),
    digestHex: Buffer.from(sha256d(bytes)).toString('hex'),
  };
};

export const decodeLinePairRecord = (bytes) => {
  if (!(bytes instanceof Uint8Array) || bytes.length !== LINE_PAIR_BYTES) throw new Error(`fixed-G2 record must be ${LINE_PAIR_BYTES} B`);
  const limbs = Array.from({ length: LINE_PAIR_LIMBS }, (_, i) => fromLeFp(bytes.slice(i * FP_BYTES, (i + 1) * FP_BYTES)));
  const triple = (offset) => [
    { c0: limbs[offset], c1: limbs[offset + 1] },
    { c0: limbs[offset + 2], c1: limbs[offset + 3] },
    { c0: limbs[offset + 4], c1: limbs[offset + 5] },
  ];
  return { gamma: triple(0), delta: triple(6) };
};

export const decodeCompactLinePairRecord = (bytes) => {
  if (!(bytes instanceof Uint8Array) || bytes.length !== COMPACT_LINE_PAIR_BYTES) {
    throw new Error(`compact fixed-G2 record must be ${COMPACT_LINE_PAIR_BYTES} B`);
  }
  const limbs = Array.from({ length: COMPACT_LINE_PAIR_LIMBS }, (_, i) => fromLeFp(bytes.slice(i * FP_BYTES, (i + 1) * FP_BYTES)));
  const pair = (offset) => [
    fp2(limbs[offset], limbs[offset + 1]),
    fp2(limbs[offset + 2], limbs[offset + 3]),
  ];
  return { gamma: pair(0), delta: pair(4) };
};

export const reconstructCompactLinePair = (event, compact = decodeCompactLinePairRecord(event.compactBytes)) => {
  const rebuild = (pair, values) => {
    const [c1, c2] = values;
    return [reconstructC0([null, c1, c2], pair), c1, c2];
  };
  return { gamma: rebuild(event.gamma, compact.gamma), delta: rebuild(event.delta, compact.delta) };
};

// Kept as a callable invariant so candidate codegen can fail closed before it
// emits a table. It checks table shape, round-trip serialization, exact factor
// ordering, and the 63-double/21-add event count.
export const assertFixedLineTable = () => {
  const events = fixedLineEvents();
  const doubles = events.filter((event) => event.op === 'dl').length;
  const adds = events.filter((event) => event.op === 'al').length;
  if (doubles !== 63 || adds !== 21 || events.length !== 84) {
    throw new Error(`unexpected fixed-G2 event census ${JSON.stringify({ doubles, adds, total: events.length })}`);
  }
  for (const event of events) {
    if (event.bytes.length !== LINE_PAIR_BYTES) throw new Error(`fixed-G2 event ${event.step}/${event.op} has bad byte length`);
    const decoded = decodeLinePairRecord(event.bytes);
    const rebuilt = cat(
      ...flattenCoeffs(decoded.gamma).map(leFp),
      ...flattenCoeffs(decoded.delta).map(leFp),
    );
    if (!bytesEq(event.bytes, rebuilt)) throw new Error(`fixed-G2 event ${event.step}/${event.op} failed serialization round trip`);
    const expected = [...flattenCoeffs(event.gamma.coeffs), ...flattenCoeffs(event.delta.coeffs)];
    const actual = [...flattenCoeffs(decoded.gamma), ...flattenCoeffs(decoded.delta)];
    if (expected.length !== actual.length || expected.some((value, i) => value !== actual[i])) {
      throw new Error(`fixed-G2 event ${event.step}/${event.op} differs from live trajectory`);
    }
  }
  return { doubles, adds, events: events.length, bytes: events.length * LINE_PAIR_BYTES };
};

// This proves only the algebraic compression identity for the pinned all-affine
// trajectory. It does not establish a BCH carrier, table authentication, or a
// candidate verifier. Any transport must still bind the compact bytes and use
// the exact add-sign schedule before it can inherit this invariant.
export const assertCompactFixedLineTable = () => {
  if (process.env.SZ_ALLAFF !== '1') {
    throw new Error('compact fixed-G2 table requires the all-affine C7 trajectory (SZ_ALLAFF=1)');
  }
  const events = fixedLineEvents();
  for (const event of events) {
    if (event.compactBytes.length !== COMPACT_LINE_PAIR_BYTES) {
      throw new Error(`compact fixed-G2 event ${event.step}/${event.op} has bad byte length`);
    }
    const compact = decodeCompactLinePairRecord(event.compactBytes);
    const rebuilt = reconstructCompactLinePair(event, compact);
    for (const [label, expected, actual] of [
      ['gamma', event.gamma.coeffs, rebuilt.gamma],
      ['delta', event.delta.coeffs, rebuilt.delta],
    ]) {
      if (expected.length !== actual.length || expected.some((value, index) => !fp2Eq(value, actual[index]))) {
        throw new Error(`compact fixed-G2 event ${event.step}/${event.op}/${label} differs from live trajectory`);
      }
    }
    const roundTrip = compactLimbs(rebuilt.gamma, rebuilt.delta);
    if (!bytesEq(event.compactBytes, cat(...roundTrip.map(leFp)))) {
      throw new Error(`compact fixed-G2 event ${event.step}/${event.op} failed serialization round trip`);
    }
  }
  return { events: events.length, bytes: events.length * COMPACT_LINE_PAIR_BYTES };
};

export const assertNormalizedFixedAddTable = () => {
  if (process.env.SZ_ALLAFF !== '1') throw new Error('normalized fixed-G2 additions require the all-affine C7 trajectory');
  const events = fixedLineEvents();
  for (const event of events) {
    if (event.op === 'dl') {
      if (event.compactBytes.length !== COMPACT_LINE_PAIR_BYTES) throw new Error(`normalized fixed-G2 double ${event.step} has bad byte length`);
      continue;
    }
    if (event.normalizedAddBytes?.length !== NORMALIZED_ADD_PAIR_BYTES) throw new Error(`normalized fixed-G2 add ${event.step} has bad byte length`);
    for (const [label, factor, slope] of [
      ['gamma', event.gamma, event.normalizedAddLimbs.slice(0, 2)],
      ['delta', event.delta, event.normalizedAddLimbs.slice(2, 4)],
    ]) {
      const actual = fp2Mul(fp2(slope[0], slope[1]), factor.coeffs[2]);
      if (!fp2Eq(actual, factor.coeffs[1])) throw new Error(`normalized fixed-G2 add ${event.step}/${label} slope mismatch`);
    }
  }
  const doubles = events.filter((event) => event.op === 'dl').length;
  const adds = events.filter((event) => event.op === 'al').length;
  return {
    doubles,
    adds,
    bytes: doubles * COMPACT_LINE_PAIR_BYTES + adds * NORMALIZED_ADD_PAIR_BYTES,
  };
};
