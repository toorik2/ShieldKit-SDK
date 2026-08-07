// Executable state plan for the mixed singleton/w=2 PairFold routes.
//
// It deliberately contains no BCH emitter. Its role is to make the exact
// ownership boundary explicit before source generation.
import { P } from '../../../../build/chunked/pairing/_szmath.mjs';
import { mixedGenesisTrajectory } from './composed-window-szmath.mjs';

// Seven-input route: five executors (roles 0..4) + genesis + terminal.
export const MIXED_EXECUTOR_RANGES_7 = Object.freeze([
  [1, 14],
  [14, 26],
  [26, 38],
  [38, 50],
  [50, 64],
]);

// Six-input route: four pure-pair executors. Genesis owns [0,2).
export const MIXED_EXECUTOR_RANGES_6 = Object.freeze([
  [2, 16],
  [16, 32],
  [32, 48],
  [48, 64],
]);
// dens-rich PF6: singleton genesis [0,1) + mixed role0 head (like PF7) so genHi=1 dens-rich genesis stays thin.
// Covers [1,64) with 4 roles: [1,16)=15, pure-16×2, [48,64)=16.
export const MIXED_EXECUTOR_RANGES_6_DENSE = Object.freeze([
  [1, 16],
  [16, 32],
  [32, 48],
  [48, 64],
]);

// Eight-input spike: six executors + genesis [0,1) + terminal.
// Even pure-pair body after singleton [1,2) owned by role0 (same mixed head as PF7).
// Pairs ≈ [5,5,5,5,5,6] modes [11,10,10,10,10,12] covering [1,64).
export const MIXED_EXECUTOR_RANGES_8 = Object.freeze([
  [1, 12],
  [12, 22],
  [22, 32],
  [32, 42],
  [42, 52],
  [52, 64],
]);

// Deployable gen-absorb (genHi=4 / Ideal genP=2): gen6-4exec
export const MIXED_EXECUTOR_RANGES_GEN6_4 = Object.freeze([
  [4, 18],
  [18, 34],
  [34, 50],
  [50, 64],
]);
export const MIXED_GENESIS_RANGE_GEN6_4 = Object.freeze([0, 4]);

// short-04: gen-absorb reorder pairs [8,8,7,7]
export const MIXED_EXECUTOR_RANGES_6IN_GEN2_8877 = Object.freeze([
  [4, 20],
  [20, 36],
  [36, 50],
  [50, 64],
]);

// short-02: 7-in gen-absorb pure-pair [7,7,7,7,2] — no pure-8 density cliff
export const MIXED_EXECUTOR_RANGES_7IN_GEN2_FLAT = Object.freeze([
  [4, 18],
  [18, 32],
  [32, 46],
  [46, 60],
  [60, 64],
]);

// short-03: 7-in head-heavy reorder [7,6,6,6,6] with PF7-style singleton role0
// role0: [1,16) = 15 modes (singleton + 7 pairs); then four pure-6.
export const MIXED_EXECUTOR_RANGES_7IN_HEAD7 = Object.freeze([
  [1, 16],
  [16, 28],
  [28, 40],
  [40, 52],
  [52, 64],
]);

// Aspirational Ideal genP=6 (density-blocked on genChunk genesis).
export const MIXED_EXECUTOR_RANGES_GEN6_4_IDEAL = Object.freeze([
  [12, 28],
  [28, 44],
  [44, 60],
  [60, 64],
]);
export const MIXED_GENESIS_RANGE_GEN6_4_IDEAL = Object.freeze([0, 12]);

/**
 * idealVariant → { genesisRange, executorRanges, singletonHeadEnd, absorb }
 * singletonHeadEnd drives mixed transcript window construction (even, pure-pair body).
 */
export const IDEAL_VARIANT_PLANS = Object.freeze({
  'gen6-4exec': {
    genesisRange: MIXED_GENESIS_RANGE_GEN6_4,
    executorRanges: MIXED_EXECUTOR_RANGES_GEN6_4,
    singletonHeadEnd: 4,
    absorb: true,
  },
  '6in-gen2-8877': {
    genesisRange: MIXED_GENESIS_RANGE_GEN6_4,
    executorRanges: MIXED_EXECUTOR_RANGES_6IN_GEN2_8877,
    singletonHeadEnd: 4,
    absorb: true,
  },
  '7in-gen2-flat': {
    genesisRange: MIXED_GENESIS_RANGE_GEN6_4,
    executorRanges: MIXED_EXECUTOR_RANGES_7IN_GEN2_FLAT,
    singletonHeadEnd: 4,
    absorb: true,
  },
  '7in-head7': {
    genesisRange: Object.freeze([0, 1]),
    executorRanges: MIXED_EXECUTOR_RANGES_7IN_HEAD7,
    singletonHeadEnd: 2, // stock mixed head [0,1]+[1,2) then pairs — role0 still owns singleton [1,2)
    absorb: false,
  },
});

const idealVariant = process.env.C7_IDEAL_VARIANT || '';
const disableIdealWindows = process.env.C7_FORCE_IDEAL_WINDOWS === '0';
const variantPlan = (!disableIdealWindows && IDEAL_VARIANT_PLANS[idealVariant])
  ? IDEAL_VARIANT_PLANS[idealVariant]
  : null;

// Export for mixedGenesisTrajectory (via env mirror set by adapter/build).
if (variantPlan?.absorb) {
  process.env.C7_SINGLETON_HEAD_END = String(variantPlan.singletonHeadEnd);
} else if (!process.env.C7_SINGLETON_HEAD_END) {
  // default stock mixed head ends at 2
  process.env.C7_SINGLETON_HEAD_END = '2';
}

export const MIXED_EXECUTOR_RANGES = variantPlan
  ? variantPlan.executorRanges
  : process.env.C7_PAIRFOLD_TOPOLOGY === '6'
    ? (process.env.C7_SCALAR_ENDPOINT === '1' ? MIXED_EXECUTOR_RANGES_6_DENSE : MIXED_EXECUTOR_RANGES_6)
    : process.env.C7_PAIRFOLD_TOPOLOGY === '8'
      ? MIXED_EXECUTOR_RANGES_8
      : MIXED_EXECUTOR_RANGES_7;

export const MIXED_GENESIS_RANGE = variantPlan
  ? variantPlan.genesisRange
  : process.env.C7_PAIRFOLD_TOPOLOGY === '6'
    ? (process.env.C7_SCALAR_ENDPOINT === '1' ? Object.freeze([0, 1]) : Object.freeze([0, 2]))
    : Object.freeze([0, 1]); // PF7 and PF8 spike both use singleton genesis [0,1)

const rawHashInt = (hash) => {
  let out = 0n;
  for (let index = hash.length - 1; index >= 0; index -= 1) out = (out << 8n) | BigInt(hash[index]);
  return out;
};

const rangeWindows = (windows, [start, end], role) => {
  const selected = windows.filter((window) => window.start >= start && window.end <= end);
  if (!selected.length || selected[0].start !== start || selected.at(-1).end !== end) {
    throw new Error(`${role} does not own a complete composed-window range [${start},${end})`);
  }
  return selected;
};

export const mixedRoute = (trace = mixedGenesisTrajectory(), ranges = MIXED_EXECUTOR_RANGES) => {
  const roles = [
    { role: 'genesis', range: [...MIXED_GENESIS_RANGE] },
    ...ranges.map((range, index) => ({ role: `executor-${index}`, range })),
    { role: 'terminal', range: [trace.steps.length - 1, trace.steps.length] },
  ].map((entry) => ({ ...entry, windows: rangeWindows(trace.windows, entry.range, entry.role) }));
  const covered = roles.flatMap((entry) => entry.windows.flatMap((window) => [window.start, window.end]));
  if (covered[0] !== 0 || covered.at(-1) !== trace.steps.length) throw new Error('mixed route does not cover the full Miller path');
  for (let index = 1; index < covered.length - 1; index += 2) {
    if (covered[index] !== covered[index + 1]) throw new Error(`mixed route has a gap at step ${covered[index]}`);
  }
  return roles;
};

export const boundaryState = (trace, chainIndex) => {
  const position = trace.anchorIndices.indexOf(chainIndex);
  if (position < 0) throw new Error(`chain ${chainIndex} is not a mixed transcript boundary`);
  let aggL = 0n;
  let aggF = 0n;
  let gp = 1n;
  for (let index = 0; index < position; index += 1) {
    aggL = (aggL + gp * trace.windowProducts[index]) % P;
    aggF = (aggF + gp * trace.anchorZ[index + 1]) % P;
    gp = (gp * trace.gamma) % P;
  }
  return {
    chainIndex,
    position,
    gamma: trace.gamma,
    z: trace.z,
    h: trace.seamH[position + 2],
    hInt: rawHashInt(trace.seamH[position + 2]),
    aggL,
    aggF,
    gp,
    fC: trace.anchorZ[position],
  };
};

export const mixedRoutePlan = (trace = mixedGenesisTrajectory()) => {
  const roles = mixedRoute(trace);
  return roles.map((entry) => {
    const [start, end] = entry.range;
    const before = boundaryState(trace, start);
    const after = boundaryState(trace, end);
    return {
      ...entry,
      before,
      after,
      singletonWindows: entry.windows.filter((window) => window.end - window.start === 1).length,
      composedWindows: entry.windows.filter((window) => window.end - window.start === 2).length,
    };
  });
};

export const mixedByteEconomics = (trace = mixedGenesisTrajectory()) => {
  const anchorBytesSaved = (trace.v1.chain.length - trace.anchors.length) * 12 * 32;
  const bigQBytesAdded = (trace.bigQ.length - trace.v1.bigQ.length) * 32;
  return {
    v1Anchors: trace.v1.chain.length,
    mixedAnchors: trace.anchors.length,
    v1BigQ: trace.v1.bigQ.length,
    mixedBigQ: trace.bigQ.length,
    anchorBytesSaved,
    bigQBytesAdded,
    netHintBytes: anchorBytesSaved - bigQBytesAdded,
  };
};
