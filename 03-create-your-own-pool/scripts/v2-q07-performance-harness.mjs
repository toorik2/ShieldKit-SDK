/*
 * Q-07 performance evidence has five intentionally non-interchangeable
 * measurements.  This module is a small-fixture harness only: it records the
 * shape and local counters needed by a later published-machine run, but it
 * cannot turn a fixture run into a 100k qualification result.
 */
import { createHash } from 'node:crypto';
import { lstatSync } from 'node:fs';
import os from 'node:os';
import { resolve } from 'node:path';
import { performance } from 'node:perf_hooks';

export const V2_Q07_PERFORMANCE_SCHEMA =
  'shieldkit-v2-direct/q07-performance-small-fixture/v1';
export const V2_Q07_REFERENCE_MACHINE_SCHEMA =
  'shieldkit-v2-direct/q07-reference-machine-manifest/v1';
export const V2_Q07_SMALL_FIXTURE_MAX_HISTORY_ACTIONS = 64;
export const V2_Q07_OPERATION_KINDS = Object.freeze([
  'bottom-up-snapshot-authentication',
  'raw-fallback',
  'suffix-replay',
  'warm-fixed-depth-update',
  'cold-sqlite-io',
]);

// These are the production-side counters emitted by the Q-04 history runner.
// Keeping the same keys avoids replacing fixed-depth work with an opaque time.
export const V2_Q07_FIXED_DEPTH_COUNTER_KEYS = Object.freeze([
  'productionLeafHashCalls',
  'productionLogicalPathSiblingLookups',
  'productionMutationLeafHashCalls',
  'productionMutationNodeHashCalls',
  'productionLeafReads',
  'productionOrderLookups',
  'productionPathAdapterNodeReads',
  'productionPathOverrideHits',
  'productionPredecessorValidationLeafHashCalls',
  'productionPostMembershipNodeHashCalls',
  'productionPostMembershipNodeReads',
  'productionRootAdapterNodeReads',
  'productionTotalAdapterNodeReads',
]);

export class V2Q07PerformanceHarnessError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2Q07PerformanceHarnessError';
  }
}

const fail = (message) => { throw new V2Q07PerformanceHarnessError(message); };
const isSafeCount = (value) => Number.isSafeInteger(value) && value >= 0;

export function emptyQ07FixedDepthOperationCounts() {
  return Object.freeze(Object.fromEntries(
    V2_Q07_FIXED_DEPTH_COUNTER_KEYS.map((key) => [key, 0]),
  ));
}

function exactKeys(value, keys, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} has unexpected keys`);
  }
}

export function validateQ07FixedDepthOperationCounts(value) {
  exactKeys(value, V2_Q07_FIXED_DEPTH_COUNTER_KEYS, 'fixed-depth operation counts');
  for (const key of V2_Q07_FIXED_DEPTH_COUNTER_KEYS) {
    if (!isSafeCount(value[key])) fail(`fixed-depth operation count ${key} is invalid`);
  }
  return Object.freeze({ ...value });
}

function resourceUsageSnapshot() {
  const usage = process.resourceUsage();
  return Object.freeze({
    fsRead: usage.fsRead,
    fsWrite: usage.fsWrite,
    involuntaryContextSwitches: usage.involuntaryContextSwitches,
    maxRss: usage.maxRSS,
    systemCPUTime: usage.systemCPUTime,
    userCPUTime: usage.userCPUTime,
    voluntaryContextSwitches: usage.voluntaryContextSwitches,
  });
}

function resourceDelta(before, after) {
  const delta = {
    fsReadOps: after.fsRead - before.fsRead,
    fsWriteOps: after.fsWrite - before.fsWrite,
    involuntaryContextSwitches: after.involuntaryContextSwitches - before.involuntaryContextSwitches,
    systemCpuMicros: after.systemCPUTime - before.systemCPUTime,
    userCpuMicros: after.userCPUTime - before.userCPUTime,
    voluntaryContextSwitches: after.voluntaryContextSwitches - before.voluntaryContextSwitches,
  };
  if (!Object.values(delta).every(isSafeCount)) fail('resource usage counters regressed or overflowed');
  return Object.freeze(delta);
}

function peakRss(after) {
  if (!isSafeCount(after.maxRss)) {
    return Object.freeze({
      available: false,
      qualifiesOperationPeak: false,
      reason: 'process.resourceUsage().maxRSS is unavailable',
    });
  }
  return Object.freeze({
    available: true,
    bytes: after.maxRss * 1024,
    qualifiesOperationPeak: false,
    scope: 'process-lifetime-through-operation-end',
    source: 'process.resourceUsage().maxRSS-kibibytes',
  });
}

export function measureQ07StoreSize(paths = []) {
  if (!Array.isArray(paths)) fail('store paths must be an array');
  if (paths.length === 0) {
    return Object.freeze({ available: false, reason: 'workload supplied no SQLite store paths' });
  }
  const files = paths.map((path) => {
    if (typeof path !== 'string' || path.length === 0) fail('store path must be a nonempty string');
    const resolved = resolve(path);
    const observed = lstatSync(resolved);
    if (!observed.isFile() || observed.isSymbolicLink()) {
      fail(`store path must be a direct regular file: ${resolved}`);
    }
    return Object.freeze({ path: resolved, bytes: observed.size });
  });
  const unique = new Set(files.map((file) => file.path));
  if (unique.size !== files.length) fail('store paths must be unique');
  return Object.freeze({
    available: true,
    files: Object.freeze(files),
    bytes: files.reduce((total, file) => total + file.bytes, 0),
  });
}

export function createQ07ReferenceMachineManifest() {
  const cpuModels = [...new Set(os.cpus().map((cpu) => cpu.model))].sort();
  const value = {
    schema: V2_Q07_REFERENCE_MACHINE_SCHEMA,
    attestation: 'local-unattested',
    hostName: os.hostname(),
    runtime: {
      node: process.version,
      v8: process.versions.v8,
      sqlite: process.versions.sqlite ?? null,
    },
    operatingSystem: {
      architecture: process.arch,
      platform: process.platform,
      release: os.release(),
    },
    hardware: {
      cpuModels,
      logicalCores: os.availableParallelism(),
      totalMemoryBytes: os.totalmem(),
    },
  };
  return Object.freeze({
    ...value,
    sha256: createHash('sha256').update(JSON.stringify(value)).digest('hex'),
  });
}

function validateOperationKind(kind) {
  if (!V2_Q07_OPERATION_KINDS.includes(kind)) fail(`unknown Q-07 operation kind: ${String(kind)}`);
}

/**
 * Measures one real workload invocation. The workload itself must return the
 * counters it observed; this harness never fabricates tree work from timing.
 */
export async function measureQ07Operation({
  kind,
  historyActions,
  run,
  storePaths = [],
  coldIoMode = undefined,
}) {
  validateOperationKind(kind);
  if (!isSafeCount(historyActions) || historyActions === 0) {
    fail('historyActions must be a positive safe integer');
  }
  if (typeof run !== 'function') fail('Q-07 workload run must be a function');
  if (kind === 'cold-sqlite-io') {
    if (!['reopened-handle-no-cache-eviction', 'fresh-process', 'cache-evicted'].includes(coldIoMode)) {
      fail('cold SQLite I/O requires an explicit coldIoMode');
    }
  } else if (coldIoMode !== undefined) {
    fail('only cold SQLite I/O may declare coldIoMode');
  }
  const before = resourceUsageSnapshot();
  const started = performance.now();
  const outcome = await run();
  const elapsedMs = performance.now() - started;
  const after = resourceUsageSnapshot();
  if (!Number.isFinite(elapsedMs) || elapsedMs < 0) fail('Q-07 wall-clock measurement is invalid');
  if (outcome === null || typeof outcome !== 'object' || Array.isArray(outcome)) {
    fail('Q-07 workload must return an object');
  }
  exactKeys(outcome, ['fixedDepthOperationCounts'], 'Q-07 workload result');
  const result = {
    kind,
    historyActions,
    wallMs: elapsedMs,
    resourceDelta: resourceDelta(before, after),
    peakRss: peakRss(after),
    storeSize: measureQ07StoreSize(storePaths),
    fixedDepthOperationCounts: validateQ07FixedDepthOperationCounts(outcome.fixedDepthOperationCounts),
  };
  if (kind === 'cold-sqlite-io') result.coldIoMode = coldIoMode;
  return Object.freeze(result);
}

function validateReferenceMachine(value) {
  exactKeys(value, [
    'schema', 'attestation', 'hostName', 'runtime', 'operatingSystem', 'hardware', 'sha256',
  ], 'reference-machine manifest');
  if (value.schema !== V2_Q07_REFERENCE_MACHINE_SCHEMA || value.attestation !== 'local-unattested') {
    fail('reference-machine manifest is not a local unattested manifest');
  }
  if (typeof value.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(value.sha256)) {
    fail('reference-machine manifest digest is invalid');
  }
  exactKeys(value.runtime, ['node', 'v8', 'sqlite'], 'reference-machine runtime');
  exactKeys(value.operatingSystem, ['architecture', 'platform', 'release'], 'reference-machine operating system');
  exactKeys(value.hardware, ['cpuModels', 'logicalCores', 'totalMemoryBytes'], 'reference-machine hardware');
  if (
    typeof value.hostName !== 'string' ||
    typeof value.runtime.node !== 'string' ||
    typeof value.runtime.v8 !== 'string' ||
    (value.runtime.sqlite !== null && typeof value.runtime.sqlite !== 'string') ||
    !Array.isArray(value.hardware.cpuModels) ||
    !value.hardware.cpuModels.every((model) => typeof model === 'string') ||
    !isSafeCount(value.hardware.logicalCores) || value.hardware.logicalCores === 0 ||
    !isSafeCount(value.hardware.totalMemoryBytes) || value.hardware.totalMemoryBytes === 0
  ) fail('reference-machine manifest fields are invalid');
  const unsigned = {
    schema: value.schema,
    attestation: value.attestation,
    hostName: value.hostName,
    runtime: value.runtime,
    operatingSystem: value.operatingSystem,
    hardware: value.hardware,
  };
  const expected = createHash('sha256').update(JSON.stringify(unsigned)).digest('hex');
  if (value.sha256 !== expected) fail('reference-machine manifest digest does not bind its fields');
}

function validateResourceDelta(value) {
  exactKeys(value, [
    'fsReadOps', 'fsWriteOps', 'involuntaryContextSwitches', 'systemCpuMicros',
    'userCpuMicros', 'voluntaryContextSwitches',
  ], 'Q-07 resource delta');
  if (!Object.values(value).every(isSafeCount)) fail('Q-07 resource delta fields are invalid');
}

function validatePeakRss(value) {
  if (value?.available === true) {
    exactKeys(
      value,
      ['available', 'bytes', 'qualifiesOperationPeak', 'scope', 'source'],
      'Q-07 process-lifetime peak RSS',
    );
    if (
      !isSafeCount(value.bytes) ||
      value.qualifiesOperationPeak !== false ||
      value.scope !== 'process-lifetime-through-operation-end' ||
      value.source !== 'process.resourceUsage().maxRSS-kibibytes'
    ) {
      fail('Q-07 peak RSS evidence is invalid');
    }
    return;
  }
  exactKeys(
    value,
    ['available', 'qualifiesOperationPeak', 'reason'],
    'Q-07 unavailable peak RSS',
  );
  if (
    value.available !== false ||
    value.qualifiesOperationPeak !== false ||
    typeof value.reason !== 'string'
  ) fail('Q-07 unavailable peak RSS is invalid');
}

function validateStoreSize(value) {
  if (value?.available === true) {
    exactKeys(value, ['available', 'files', 'bytes'], 'Q-07 store size');
    if (!Array.isArray(value.files) || !isSafeCount(value.bytes)) fail('Q-07 store size is invalid');
    let total = 0;
    const paths = new Set();
    for (const file of value.files) {
      exactKeys(file, ['path', 'bytes'], 'Q-07 store file');
      if (typeof file.path !== 'string' || !isSafeCount(file.bytes) || paths.has(file.path)) {
        fail('Q-07 store file is invalid');
      }
      paths.add(file.path);
      total += file.bytes;
    }
    if (total !== value.bytes) fail('Q-07 store size total does not match its files');
    return;
  }
  exactKeys(value, ['available', 'reason'], 'Q-07 unavailable store size');
  if (value.available !== false || typeof value.reason !== 'string') fail('Q-07 unavailable store size is invalid');
}

function validateOperationMeasurement(operation) {
  validateOperationKind(operation.kind);
  const expectedKeys = [
    'kind', 'historyActions', 'wallMs', 'resourceDelta', 'peakRss', 'storeSize',
    'fixedDepthOperationCounts',
  ];
  if (operation.kind === 'cold-sqlite-io') expectedKeys.push('coldIoMode');
  exactKeys(operation, expectedKeys, `Q-07 ${operation.kind} measurement`);
  if (!isSafeCount(operation.historyActions) || operation.historyActions === 0 || operation.historyActions > V2_Q07_SMALL_FIXTURE_MAX_HISTORY_ACTIONS) {
    fail('small-fixture historyActions must be in the bounded small-fixture range');
  }
  if (!Number.isFinite(operation.wallMs) || operation.wallMs < 0) fail('Q-07 operation wallMs is invalid');
  validateResourceDelta(operation.resourceDelta);
  validatePeakRss(operation.peakRss);
  validateStoreSize(operation.storeSize);
  validateQ07FixedDepthOperationCounts(operation.fixedDepthOperationCounts);
  if (operation.kind === 'cold-sqlite-io' && !['reopened-handle-no-cache-eviction', 'fresh-process', 'cache-evicted'].includes(operation.coldIoMode)) {
    fail('Q-07 cold SQLite I/O mode is invalid');
  }
}

export function createQ07SmallFixtureManifest({ fixtureId, referenceMachine, operations }) {
  if (typeof fixtureId !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(fixtureId)) {
    fail('fixtureId must be a lowercase deterministic identifier');
  }
  validateReferenceMachine(referenceMachine);
  if (!Array.isArray(operations) || operations.length !== V2_Q07_OPERATION_KINDS.length) {
    fail('Q-07 small fixture must contain every operation exactly once');
  }
  const byKind = new Map();
  for (const operation of operations) {
    if (operation === null || typeof operation !== 'object' || Array.isArray(operation)) {
      fail('Q-07 operation measurement must be an object');
    }
    validateOperationKind(operation.kind);
    if (byKind.has(operation.kind)) fail(`Q-07 operation is duplicated: ${operation.kind}`);
    validateOperationMeasurement(operation);
    byKind.set(operation.kind, operation);
  }
  for (const kind of V2_Q07_OPERATION_KINDS) {
    if (!byKind.has(kind)) fail(`Q-07 operation is missing: ${kind}`);
  }
  return Object.freeze({
    schema: V2_Q07_PERFORMANCE_SCHEMA,
    evidenceClass: 'local-small-fixture-performance-harness',
    claims: Object.freeze({
      q04Campaign: 'not-run',
      q07PerformanceTargets: 'not-qualified',
      publishedReferenceMachine: 'not-attested',
      required100kRecovery: 'not-run',
    }),
    fixture: Object.freeze({
      id: fixtureId,
      maximumHistoryActions: V2_Q07_SMALL_FIXTURE_MAX_HISTORY_ACTIONS,
    }),
    referenceMachine,
    operations: Object.freeze(V2_Q07_OPERATION_KINDS.map((kind) => byKind.get(kind))),
  });
}

/** Runs exactly the supplied small fixtures, in a fixed operation order. */
export async function runQ07SmallFixtureHarness({ fixtureId, workloads, referenceMachine = createQ07ReferenceMachineManifest() }) {
  exactKeys(workloads, V2_Q07_OPERATION_KINDS, 'Q-07 workloads');
  // Reject before invoking any workload. This entry point is deliberately not
  // a convenient way to run a reduced-looking 100k campaign.
  for (const kind of V2_Q07_OPERATION_KINDS) {
    const workload = workloads[kind];
    if (workload === null || typeof workload !== 'object' || Array.isArray(workload)) {
      fail(`Q-07 workload ${kind} must be an object`);
    }
    if (!isSafeCount(workload.historyActions) || workload.historyActions === 0 || workload.historyActions > V2_Q07_SMALL_FIXTURE_MAX_HISTORY_ACTIONS) {
      fail('small-fixture historyActions must be in the bounded small-fixture range');
    }
  }
  const operations = [];
  for (const kind of V2_Q07_OPERATION_KINDS) {
    const workload = workloads[kind];
    operations.push(await measureQ07Operation({ kind, ...workload }));
  }
  return createQ07SmallFixtureManifest({ fixtureId, referenceMachine, operations });
}
