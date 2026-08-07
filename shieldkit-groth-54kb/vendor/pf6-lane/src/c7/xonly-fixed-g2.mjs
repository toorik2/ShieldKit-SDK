// Fixed-G2 x/slope representation for the all-affine C7 Miller trajectory.
//
// A tangent line has coefficient triple (c0,c1,c2), but final exponentiation
// kills a non-zero Fp2 scale.  With m=c1/c2 and the current x-coordinate, the
// tangent can therefore be represented without y:
//
//   4m^2 * (c0,c1,c2)
//     = (12 B m^2 - 9 x^4, 12 m^2 x^2, 12 m x^2),
//   x([2]R) = m^2 - 2x(R).
//
// Addition already has the one-Fp2 projective form
//   (-(m Qx + Qy), m, 1), x(R+Q)=m^2-x(R)-x(Q).
//
// Thus each fixed gamma/delta line needs one Fp2 slope instead of two Fp2
// coefficients, while only x is threaded.  This module is an algebraic model
// and table census, not a candidate emitter: callers must regenerate the full
// scaled SZ trajectory and its quotient witness before using it in a verifier.
import { Fp2, vk } from '../../../../build/chunked/pairing/_millermath.mjs';
import { P, mod, trajectory } from '../../../../build/chunked/pairing/_szmath.mjs';
import { fixedLineEvents } from './fixed-g2-lines.mjs';

const asFp2 = (value) => Fp2.fromBigTuple([mod(value.c0), mod(value.c1)]);
const eq = (left, right) => Fp2.eql(left, right);
const add = (left, right) => Fp2.add(left, right);
const sub = (left, right) => Fp2.sub(left, right);
const mul = (left, right) => Fp2.mul(left, right);
const sqr = (value) => Fp2.sqr(value);
const scale = (value, factor) => Fp2.mul(value, factor);
const inv3 = (P * 2n + 1n) / 3n;
// The deployed affine tangent has c0 = 3B-y^2.  Its baked C3B value is
// represented by this first live tangent identity rather than duplicated here.
const curveB = (() => {
  const first = fixedLineEvents().find((event) => event.op === 'dl');
  if (first === undefined) throw new Error('fixed-G2 trajectory has no doubling event');
  const c2 = asFp2(first.gamma.coeffs[2]);
  const c0 = asFp2(first.gamma.coeffs[0]);
  return scale(add(c0, scale(sqr(c2), (P + 1n) / 4n)), inv3);
})();

const affine = (point) => {
  const out = point.toAffine();
  return { x: asFp2(out.x), y: asFp2(out.y) };
};

const addends = Object.freeze({ gamma: affine(vk.gamma), delta: affine(vk.delta) });

export const slopeOf = (coeffs) => mul(asFp2(coeffs[1]), Fp2.inv(asFp2(coeffs[2])));

export const doubleFromXAndSlope = (x, m) => {
  const x2 = sqr(x);
  const m2 = sqr(m);
  const x4 = sqr(x2);
  return {
    coeffs: [
      sub(scale(mul(curveB, m2), 12n), scale(x4, 9n)),
      scale(mul(m2, x2), 12n),
      scale(mul(m, x2), 12n),
    ],
    scale: scale(m2, 4n),
    nextX: sub(m2, scale(x, 2n)),
  };
};

export const addFromXAndSlope = (x, m, Qx, Qy) => ({
  coeffs: [Fp2.neg(add(mul(m, Qx), Qy)), m, Fp2.ONE],
  nextX: sub(sub(sqr(m), x), Qx),
});

export const xOnlyInitialStates = () => {
  const trace = trajectory();
  const firstStep = trace.steps[1];
  if (firstStep === undefined) throw new Error('missing first fixed-G2 window');
  const seed = (pair) => {
    const entry = firstStep.ops.find((item) => item.kindOp === 'dl' && item.op.j === pair);
    if (entry === undefined) throw new Error(`missing first fixed-G2 double for pair ${pair}`);
    const index = trace.fused.ops.indexOf(entry.op);
    if (index < 0) throw new Error(`fixed-G2 op for pair ${pair} is absent from fused trace`);
    const state = trace.fused.states[index]?.Rs[pair];
    if (state === undefined || (state.z !== undefined && !eq(state.z, Fp2.ONE))) {
      throw new Error(`fixed-G2 seed ${pair} is not affine`);
    }
    return { x: state.x };
  };
  return { gamma: seed(2), delta: seed(3) };
};

const scaled = (coeffs, by) => coeffs.map((value) => mul(asFp2(value), by));
const assertCoeffs = (actual, expected, label) => {
  for (let limb = 0; limb < 3; limb++) {
    if (!eq(actual[limb], expected[limb])) throw new Error(`${label}: coefficient ${limb} mismatch`);
  }
};

const update = (state, factor, base, label) => {
  const m = slopeOf(factor.coeffs);
  if (factor.op === 'dl') {
    const reconstructed = doubleFromXAndSlope(state.x, m);
    assertCoeffs(reconstructed.coeffs, scaled(factor.coeffs, reconstructed.scale), label);
    return { state: { x: reconstructed.nextX }, slope: m, coeffs: reconstructed.coeffs, scale: reconstructed.scale };
  }
  if (factor.op === 'al') {
    const Qy = factor.neg ? Fp2.neg(base.y) : base.y;
    const reconstructed = addFromXAndSlope(state.x, m, base.x, Qy);
    assertCoeffs(reconstructed.coeffs, scaled(factor.coeffs, Fp2.inv(asFp2(factor.coeffs[2]))), label);
    return { state: { x: reconstructed.nextX }, slope: m, coeffs: reconstructed.coeffs, scale: Fp2.inv(asFp2(factor.coeffs[2])) };
  }
  throw new Error(`${label}: unknown fixed-G2 operation ${factor.op}`);
};

export const xOnlyFixedLineEvents = () => {
  const states = xOnlyInitialStates();
  const out = [];
  for (const event of fixedLineEvents()) {
    const gamma = update(states.gamma, event.gamma, addends.gamma, `gamma/${event.step}/${event.op}`);
    const delta = update(states.delta, event.delta, addends.delta, `delta/${event.step}/${event.op}`);
    states.gamma = gamma.state;
    states.delta = delta.state;
    out.push({ step: event.step, op: event.op, gamma, delta });
  }
  return { events: out, finalStates: states };
};

export const xOnlyStateBeforeStep = (step) => {
  if (!Number.isInteger(step) || step < 1 || step >= trajectory().steps.length - 1) {
    throw new Error(`invalid fixed-G2 x/slope seed step ${step}`);
  }
  if (step === 1) return xOnlyInitialStates();
  const prior = xOnlyFixedLineEvents().events.filter((event) => event.step === step - 1).at(-1);
  if (prior === undefined) throw new Error(`missing fixed-G2 x/slope state before step ${step}`);
  return { gamma: prior.gamma.state, delta: prior.delta.state };
};

export const xOnlyFixedLineCensus = () => {
  const events = xOnlyFixedLineEvents().events;
  const doubles = events.filter((event) => event.op === 'dl').length;
  const adds = events.filter((event) => event.op === 'al').length;
  // One Fp2 slope for each of gamma/delta => four Fp limbs/event.  The first
  // executor also needs two Fp2 x-coordinate seeds.
  const tableBytes = (doubles + adds) * 4 * 32;
  const seedBytes = 4 * 32;
  return { doubles, adds, events: events.length, tableBytes, seedBytes, bytes: tableBytes + seedBytes };
};
