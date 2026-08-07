import { createHash } from 'node:crypto';

import {
  bn254,
  f12limbs,
  singlePairMiller,
} from '../vendor/verifier/build/chunked/pairing/_millermath.mjs';
import {
  directV2MillerShadowStepFactorSpec,
  encodeDirectV2MillerBoundaryState,
} from './identity-aware-miller.mjs';

export const DIRECT_V2_PAIRFOLD_RANGES = Object.freeze([
  Object.freeze([1, 14]),
  Object.freeze([14, 26]),
  Object.freeze([26, 38]),
  Object.freeze([38, 50]),
  Object.freeze([50, 64]),
]);

export const DIRECT_V2_PAIRFOLD_STATE_BYTES = 296;
export const DIRECT_V2_PAIRFOLD_ENDPOINT_BYTES = 384;
export const DIRECT_V2_PAIRFOLD_TERMINAL_STEP = 64;

const { Fp, Fp2 } = bn254.fields;
const P = Fp.ORDER;

export class DirectV2TotalPairFoldError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DirectV2TotalPairFoldError';
  }
}

const fail = (message) => {
  throw new DirectV2TotalPairFoldError(message);
};

const mod = (value) => {
  const reduced = BigInt(value) % P;
  return reduced < 0n ? reduced + P : reduced;
};

const le32 = (value) => Buffer.from(
  mod(value).toString(16).padStart(64, '0'),
  'hex',
).reverse();

const be32 = (value) => Buffer.from(
  mod(value).toString(16).padStart(64, '0'),
  'hex',
);

const catFieldsLe = (values) => Buffer.concat(values.map(le32));
const catFieldsBe = (values) => Buffer.concat(values.map(be32));

const sha256d = (value) => {
  const once = createHash('sha256').update(value).digest();
  return createHash('sha256').update(once).digest('hex');
};

const fp2Tuple = (value) => [mod(value.c0), mod(value.c1)];
const fp2Slope = (entry) =>
  Fp2.mul(entry.coeffs[1], Fp2.inv(entry.coeffs[2]));

const fp2Sub = (left, right) => Fp2.sub(left, right);
const fp2Sqr = (value) => Fp2.sqr(value);
const fp2Scale = (value, scalar) =>
  Fp2.fromBigTuple([
    Fp.mul(value.c0, scalar),
    Fp.mul(value.c1, scalar),
  ]);

const nextFixedX = (current, entry, baseX) => {
  const slope2 = fp2Sqr(entry.lam);
  if (entry.op === 'dl') {
    return fp2Sub(slope2, fp2Scale(current, 2n));
  }
  if (entry.op === 'al') {
    return fp2Sub(fp2Sub(slope2, current), baseX);
  }
  fail(`fixed x-only trajectory cannot advance ${entry.op}`);
};

const byPairAndOp = (spec, pair, op) =>
  spec.filter((entry) => entry.pair === pair && entry.op === op);

const modeOf = (spec) => {
  const folds = spec.filter((entry) => entry.kind === 'cfold');
  if (folds.length > 1) fail('Miller step contains multiple c-folds');
  if (folds.length === 0) return 0;
  return folds[0].useC ? 1 : 2;
};

const variableSlopeFields = (spec, expectedOperation = null) => {
  const entries = spec.filter((entry) =>
    (entry.kind === 'varline' || entry.kind === 'varpp')
    && (expectedOperation === null || entry.op === expectedOperation));
  return entries.flatMap((entry) => fp2Tuple(entry.lam));
};

const endpointFields = (trace, chainIndex) =>
  f12limbs(trace.chain[chainIndex]).map(mod);

const fixedSchedule = (trace) => {
  const gamma = trace.key.gamma.toAffine();
  const delta = trace.key.delta.toAffine();
  let gammaX = gamma.x;
  let deltaX = delta.x;
  const starts = [];
  const steps = [];
  for (let step = 0; step <= DIRECT_V2_PAIRFOLD_TERMINAL_STEP; step += 1) {
    starts.push(Object.freeze({
      gammaX: Object.freeze(fp2Tuple(gammaX)),
      deltaX: Object.freeze(fp2Tuple(deltaX)),
    }));
    const spec = directV2MillerShadowStepFactorSpec(trace, step);
    const gammaDouble = byPairAndOp(spec, 2, 'dl');
    const deltaDouble = byPairAndOp(spec, 3, 'dl');
    if (gammaDouble.length !== 1 || deltaDouble.length !== 1) {
      fail(`Miller step ${step} lacks one fixed double per trajectory`);
    }
    const gammaAdds = [
      ...byPairAndOp(spec, 2, 'al'),
      ...byPairAndOp(spec, 2, 'pp'),
    ];
    const deltaAdds = [
      ...byPairAndOp(spec, 3, 'al'),
      ...byPairAndOp(spec, 3, 'pp'),
    ];
    if (gammaAdds.length !== deltaAdds.length) {
      fail(`Miller step ${step} fixed add schedules differ`);
    }
    steps.push(Object.freeze({
      spec,
      mode: modeOf(spec),
      gammaDouble: gammaDouble[0],
      deltaDouble: deltaDouble[0],
      gammaAdds: Object.freeze(gammaAdds),
      deltaAdds: Object.freeze(deltaAdds),
    }));
    // No executor consumes a fixed-x seed after the terminal post-precompute
    // step. Its two `pp` addends are psi(Q) and -psi²(Q), not the deployment
    // base point used by the ordinary NAF additions below.
    if (step === DIRECT_V2_PAIRFOLD_TERMINAL_STEP) continue;
    gammaX = nextFixedX(gammaX, gammaDouble[0], gamma.x);
    deltaX = nextFixedX(deltaX, deltaDouble[0], delta.x);
    for (const entry of gammaAdds) {
      gammaX = nextFixedX(gammaX, entry, gamma.x);
    }
    for (const entry of deltaAdds) {
      deltaX = nextFixedX(deltaX, entry, delta.x);
    }
  }
  return Object.freeze({
    gamma: Object.freeze({
      x: Object.freeze(fp2Tuple(gamma.x)),
      y: Object.freeze(fp2Tuple(gamma.y)),
    }),
    delta: Object.freeze({
      x: Object.freeze(fp2Tuple(delta.x)),
      y: Object.freeze(fp2Tuple(delta.y)),
    }),
    starts: Object.freeze(starts),
    steps: Object.freeze(steps),
  });
};

const executorFixedStepFields = (step) => {
  if (step.gammaAdds.length > 1 || step.deltaAdds.length > 1) {
    fail('interior PairFold step has a post-precompute fixed schedule');
  }
  const fields = [
    // The x-only tangent formula consumes m=c1/c2. For the affine update
    // convention this is the negative of op.lam; derive it from the exact
    // scaled line so table transport cannot silently flip the factor.
    ...fp2Tuple(fp2Slope(step.gammaDouble)),
    ...fp2Tuple(fp2Slope(step.deltaDouble)),
  ];
  if (step.gammaAdds.length === 1) {
    // The x-only fixed-add kernel consumes normalized c1, not the affine
    // slope. c2 is normalized to one and c0 follows from Q on chain.
    fields.push(
      ...fp2Tuple(step.gammaAdds[0].coeffs[1]),
      ...fp2Tuple(step.deltaAdds[0].coeffs[1]),
    );
  }
  return fields;
};

const lineFields = (entry) =>
  entry.coeffs.flatMap((coefficient) => fp2Tuple(coefficient));

const executorPrecomputedFixedStepFields = (step) => {
  if (step.gammaAdds.length > 1 || step.deltaAdds.length > 1) {
    fail('interior PairFold step has a post-precompute fixed schedule');
  }
  return [
    ...lineFields(step.gammaDouble),
    ...lineFields(step.deltaDouble),
    ...(step.gammaAdds.length === 0
      ? []
      : [
        ...lineFields(step.gammaAdds[0]),
        ...lineFields(step.deltaAdds[0]),
      ]),
  ];
};

const executorRecords = (trace, start, end, role) => {
  const chunks = [];
  const appendStep = (step, includeEndpoint) => {
    const spec = directV2MillerShadowStepFactorSpec(trace, step);
    chunks.push(catFieldsLe(variableSlopeFields(spec)));
    if (includeEndpoint) {
      chunks.push(catFieldsLe(endpointFields(trace, step + 1)));
    }
  };
  if (role === 0) appendStep(start, true);
  for (
    let step = role === 0 ? start + 1 : start;
    step < end;
    step += 2
  ) {
    appendStep(step, false);
    appendStep(step + 1, true);
  }
  return Buffer.concat(chunks);
};

const executorTable = (schedule, start, end) => {
  const seed = schedule.starts[start];
  return catFieldsLe([
    ...seed.gammaX,
    ...seed.deltaX,
    ...schedule.steps.slice(start, end).flatMap(executorFixedStepFields),
  ]);
};

const executorPrecomputedFixedTable = (schedule, start, end) => {
  return catFieldsLe([
    ...schedule.steps
      .slice(start, end)
      .flatMap(executorPrecomputedFixedStepFields),
  ]);
};

const blockIndexForAnchor = (trace, chainIndex) => {
  const position = trace.anchorIndices.indexOf(chainIndex);
  if (position < 0) fail(`chain ${chainIndex} is not a transcript anchor`);
  // Block zero is the statement; anchors begin at block one.
  return position + 1;
};

const executorEndpointBlocks = (trace, start, end, role) => {
  const blocks = [];
  if (role === 0) blocks.push(blockIndexForAnchor(trace, start + 1));
  for (
    let step = role === 0 ? start + 1 : start;
    step < end;
    step += 2
  ) {
    blocks.push(blockIndexForAnchor(trace, step + 2));
  }
  return Object.freeze(blocks);
};

const normalizedFixedPpFields = (entry) => [
  ...fp2Tuple(entry.coeffs[0]),
  ...fp2Tuple(entry.coeffs[1]),
];

const terminalTable = (schedule) => {
  const step = schedule.steps[DIRECT_V2_PAIRFOLD_TERMINAL_STEP];
  if (step.gammaAdds.length !== 2 || step.deltaAdds.length !== 2) {
    fail('terminal step must contain two fixed post-precompute lines per pair');
  }
  const seed = schedule.starts[DIRECT_V2_PAIRFOLD_TERMINAL_STEP];
  return catFieldsLe([
    ...seed.gammaX,
    ...seed.deltaX,
    ...fp2Tuple(fp2Slope(step.gammaDouble)),
    ...fp2Tuple(fp2Slope(step.deltaDouble)),
    ...step.gammaAdds.flatMap(normalizedFixedPpFields),
    ...step.deltaAdds.flatMap(normalizedFixedPpFields),
  ]);
};

const terminalRecords = (trace) => {
  const spec = directV2MillerShadowStepFactorSpec(
    trace,
    DIRECT_V2_PAIRFOLD_TERMINAL_STEP,
  );
  const doubleSlopes = variableSlopeFields(spec, 'dl');
  const ppSlopes = variableSlopeFields(spec, 'pp');
  if (doubleSlopes.length !== 2 || ppSlopes.length !== 4) {
    fail('terminal variable slope schedule is not one double plus two adds');
  }
  return Buffer.concat([
    catFieldsLe([...doubleSlopes, ...ppSlopes]),
    catFieldsLe(endpointFields(trace, trace.steps.length)),
  ]);
};

function assertCompleteTrace(trace) {
  if (
    trace === null
    || typeof trace !== 'object'
    || trace.steps?.length !== 65
    || trace.anchorIndices?.at(-1) !== 65
  ) {
    fail('total PairFold witness requires one complete 65-step direct-V2 trace');
  }
}

function terminalWitness(trace, schedule) {
  const finalTable = terminalTable(schedule);
  const finalRecords = terminalRecords(trace);
  const bigQ = catFieldsBe(trace.bigQ);
  const fAB = singlePairMiller({
    P: trace.key.alpha,
    Q: trace.key.beta,
  }).f;
  return Object.freeze({
    state: encodeDirectV2MillerBoundaryState(
      trace,
      DIRECT_V2_PAIRFOLD_TERMINAL_STEP,
    ),
    records: finalRecords,
    table: finalTable,
    tableHash256: sha256d(finalTable),
    bigQ,
    finalEndpointBlock: blockIndexForAnchor(trace, 65),
    fAB: Object.freeze(f12limbs(fAB).map(mod)),
  });
}

function roleWitness(trace, schedule, start, end, role, precomputedFixedLines) {
  const compactTable = executorTable(schedule, start, end);
  const fullTable = precomputedFixedLines
    ? executorPrecomputedFixedTable(schedule, start, end)
    : compactTable;
  return Object.freeze({
    role,
    range: Object.freeze([start, end]),
    modes: Object.freeze(schedule.steps.slice(start, end).map(
      (step) => step.mode,
    )),
    state: encodeDirectV2MillerBoundaryState(trace, start),
    expectedOut: encodeDirectV2MillerBoundaryState(trace, end),
    records: executorRecords(trace, start, end, role),
    table: fullTable.subarray(0, compactTable.length),
    remoteTable: fullTable.subarray(compactTable.length),
    fullTableBytes: fullTable.length,
    tableHash256: sha256d(fullTable),
    endpointBlocks: executorEndpointBlocks(trace, start, end, role),
  });
}

function witnessFromSchedule(trace, schedule, precomputedFixedLines) {
  const roles = DIRECT_V2_PAIRFOLD_RANGES.map(([start, end], role) =>
    roleWitness(trace, schedule, start, end, role, precomputedFixedLines));
  return Object.freeze({
    trace,
    schedule,
    fixedLineFormat: precomputedFixedLines
      ? 'precomputed-full'
      : 'xonly-slopes',
    roles: Object.freeze(roles),
    terminal: terminalWitness(trace, schedule),
  });
}

/**
 * Produce both PairFold table encodings from one trace traversal. The compact
 * and precomputed forms differ only in their per-role fixed tables; their
 * schedule, records, boundary states, and terminal witness are identical.
 */
export function buildDirectV2TotalPairFoldWitnessPair(trace) {
  assertCompleteTrace(trace);
  const schedule = fixedSchedule(trace);
  const terminal = terminalWitness(trace, schedule);
  const compactRoles = [];
  const precomputedRoles = [];
  for (const [role, [start, end]] of DIRECT_V2_PAIRFOLD_RANGES.entries()) {
    const compactTable = executorTable(schedule, start, end);
    const fullTable = executorPrecomputedFixedTable(schedule, start, end);
    const modes = Object.freeze(schedule.steps.slice(start, end).map(
      (step) => step.mode,
    ));
    const range = Object.freeze([start, end]);
    const state = encodeDirectV2MillerBoundaryState(trace, start);
    const expectedOut = encodeDirectV2MillerBoundaryState(trace, end);
    const records = executorRecords(trace, start, end, role);
    const endpointBlocks = executorEndpointBlocks(trace, start, end, role);
    const common = { role, range, modes, state, expectedOut, records, endpointBlocks };
    compactRoles.push(Object.freeze({
      ...common,
      table: compactTable.subarray(0, compactTable.length),
      remoteTable: compactTable.subarray(compactTable.length),
      fullTableBytes: compactTable.length,
      tableHash256: sha256d(compactTable),
    }));
    precomputedRoles.push(Object.freeze({
      ...common,
      table: fullTable.subarray(0, compactTable.length),
      remoteTable: fullTable.subarray(compactTable.length),
      fullTableBytes: fullTable.length,
      tableHash256: sha256d(fullTable),
    }));
  }
  return Object.freeze({
    compact: Object.freeze({
      trace,
      schedule,
      fixedLineFormat: 'xonly-slopes',
      roles: Object.freeze(compactRoles),
      terminal,
    }),
    precomputed: Object.freeze({
      trace,
      schedule,
      fixedLineFormat: 'precomputed-full',
      roles: Object.freeze(precomputedRoles),
      terminal,
    }),
  });
}

export function buildDirectV2TotalPairFoldWitness(
  trace,
  { precomputedFixedLines = false } = {},
) {
  assertCompleteTrace(trace);
  const schedule = fixedSchedule(trace);
  if (typeof precomputedFixedLines !== 'boolean') {
    fail('precomputedFixedLines must be boolean');
  }
  return witnessFromSchedule(trace, schedule, precomputedFixedLines);
}
