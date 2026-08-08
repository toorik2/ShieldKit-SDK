/*
 * Pure Q-07 blocked/development evidence contract. This module deliberately
 * cannot authorize qualification: a final verifier must open, hash, and replay
 * the complete artifact bundle before emitting a qualifying result.
 */
import {
  V2_Q07_FIXED_DEPTH_COUNTER_KEYS as FIXED_DEPTH_COUNTER_KEYS,
} from './v2-q07-performance-harness.mjs';

export const V2_Q07_FIXED_DEPTH_COUNTER_KEYS = FIXED_DEPTH_COUNTER_KEYS;
export const V2_Q07_EVIDENCE_SCHEMA =
  'shieldkit-v2-direct/q07-performance-qualification/v1';
export const V2_Q07_RESULT_SCHEMA =
  'shieldkit-v2-direct/q07-performance-verification-result/v1';
export const V2_Q07_SAMPLE_COUNT = 32;
export const V2_Q07_HISTORY_ACTIONS = 100_000;
export const V2_Q07_ACTION_KIND_COUNTS = Object.freeze({
  deposit: 1,
  transfer: 99_998,
  withdrawal: 1,
});
export const V2_Q07_THRESHOLDS = Object.freeze({
  proofP95Ms: 60_000,
  proverPeakRssBytes: 4 * 1024 ** 3,
  stateApplyP95Ms: 250,
  fullRecoveryMs: 900_000,
  recoveryPeakRssBytes: 2 * 1024 ** 3,
  storeBytes: Math.floor(2.5 * 1024 ** 3),
  warmRatio: 1.10,
  transactionBytes: 100_000,
  unlockBytes: 10_000,
});

export const V2_Q07_PHASES = Object.freeze([
  'bottom-up-snapshot-authentication',
  'raw-fallback',
  'suffix-replay',
  'warm-fixed-depth-update',
  'cold-sqlite-io',
]);

const HASH = /^[0-9a-f]{64}$/;
const GIT_OBJECT = /^[0-9a-f]{40}$/;
const FINAL_ACTIONS = Object.freeze(['deposit', 'transfer', 'withdrawal']);
const QUALIFIED = 'qualified';
const BLOCKED = 'blocked-external-prerequisites';

export class V2Q07EvidenceError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2Q07EvidenceError';
  }
}

const fail = (message) => { throw new V2Q07EvidenceError(message); };
const plain = (value, label) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`);
  return value;
};
const exactKeys = (value, keys, label) => {
  plain(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} has missing or unknown fields`);
  }
  return value;
};
const integer = (value, label, { minimum = 0 } = {}) => {
  if (!Number.isSafeInteger(value) || value < minimum) fail(`${label} is invalid`);
  return value;
};
const number = (value, label, { minimum = 0 } = {}) => {
  if (!Number.isFinite(value) || value < minimum) fail(`${label} is invalid`);
  return value;
};
const hash = (value, label) => {
  if (typeof value !== 'string' || !HASH.test(value)) fail(`${label} must be lowercase SHA-256`);
  return value;
};
const gitObject = (value, label) => {
  if (typeof value !== 'string' || !GIT_OBJECT.test(value)) fail(`${label} must be lowercase 40-hex Git object`);
  return value;
};
const freeze = (value) => Object.freeze(value);

function validateCounters(value, label) {
  exactKeys(value, V2_Q07_FIXED_DEPTH_COUNTER_KEYS, label);
  for (const key of V2_Q07_FIXED_DEPTH_COUNTER_KEYS) integer(value[key], `${label}.${key}`);
  return freeze({ ...value });
}

function validateRss(value, label) {
  if (value === null) fail(`${label} must be measured by cgroup-v2 memory.peak`);
  exactKeys(value, ['bytes', 'provenance'], label);
  integer(value.bytes, `${label}.bytes`, { minimum: 1 });
  exactKeys(value.provenance, ['kind', 'path', 'source'], `${label}.provenance`);
  if (
    value.provenance.kind !== 'cgroup-v2'
    || value.provenance.source !== 'memory.peak'
    || typeof value.provenance.path !== 'string'
    || !value.provenance.path.startsWith('/sys/fs/cgroup/')
  ) fail(`${label} must be measured by cgroup-v2 memory.peak`);
  return freeze({ bytes: value.bytes, provenance: freeze({ ...value.provenance }) });
}

function validateStateBinding(value, label, { startCount, endCount }) {
  exactKeys(value, ['end', 'start'], label);
  const validateEndpoint = (endpoint, endpointLabel, count) => {
    exactKeys(endpoint, ['count', 'logicalDigestSha256', 'stateBytesLength', 'stateCommitmentSha256'], endpointLabel);
    integer(endpoint.count, `${endpointLabel}.count`);
    if (endpoint.count !== count) fail(`${endpointLabel}.count does not bind the phase state`);
    if (endpoint.stateBytesLength !== 128) fail(`${endpointLabel}.stateBytesLength must bind 128 canonical state bytes`);
    // The artifact verifier authenticates canonical bytes; this is a SHA-256
    // state commitment, not a tree root, because Q-07 may bind full V2 state.
    hash(endpoint.stateCommitmentSha256, `${endpointLabel}.stateCommitmentSha256`);
    hash(endpoint.logicalDigestSha256, `${endpointLabel}.logicalDigestSha256`);
    return freeze({ ...endpoint });
  };
  return freeze({
    start: validateEndpoint(value.start, `${label}.start`, startCount),
    end: validateEndpoint(value.end, `${label}.end`, endCount),
  });
}

function validateSample(value, label, stateSpec) {
  exactKeys(value, ['artifactSha256', 'fixedDepthOperationCounts', 'rss', 'state', 'wallMs'], label);
  return freeze({
    artifactSha256: hash(value.artifactSha256, `${label}.artifactSha256`),
    wallMs: number(value.wallMs, `${label}.wallMs`),
    rss: validateRss(value.rss, `${label}.rss`),
    fixedDepthOperationCounts: validateCounters(value.fixedDepthOperationCounts, `${label}.fixedDepthOperationCounts`),
    state: validateStateBinding(value.state, `${label}.state`, stateSpec),
  });
}

export function nearestRankP95(values) {
  if (!Array.isArray(values) || values.length !== V2_Q07_SAMPLE_COUNT) fail(`p95 requires exactly ${V2_Q07_SAMPLE_COUNT} samples`);
  const sorted = values.map((value, index) => number(value, `p95 sample ${index}`)).sort((left, right) => left - right);
  return sorted[Math.ceil(sorted.length * 0.95) - 1];
}

function validateSampleSet(value, label, stateSpec) {
  exactKeys(value, ['p95Ms', 'samples'], label);
  if (!Array.isArray(value.samples) || value.samples.length !== V2_Q07_SAMPLE_COUNT) fail(`${label}.samples must contain exactly ${V2_Q07_SAMPLE_COUNT} entries`);
  const samples = value.samples.map((sample, index) => validateSample(sample, `${label}.samples[${index}]`, stateSpec));
  const p95Ms = nearestRankP95(samples.map((sample) => sample.wallMs));
  if (value.p95Ms !== p95Ms) fail(`${label}.p95Ms does not match nearest-rank p95`);
  return freeze({ p95Ms, samples: freeze(samples) });
}

function validateMeasurement(value, label, { qualifying, validateEvidence }) {
  exactKeys(value, ['evidence', 'reason', 'status'], label);
  if (value.status === 'measured') {
    if (value.reason !== null || value.evidence === null) fail(`${label} measured record is invalid`);
    return freeze({ status: 'measured', reason: null, evidence: validateEvidence(value.evidence) });
  }
  if (value.status === 'unavailable') {
    if (typeof value.reason !== 'string' || value.reason.length === 0 || value.evidence !== null) {
      fail(`${label} unavailable record is invalid`);
    }
    if (qualifying) fail(`${label} must be measured for qualified evidence`);
    return freeze({ status: 'unavailable', reason: value.reason, evidence: null });
  }
  fail(`${label}.status is invalid`);
}

function validateSingletonPhase(value, label, kind, historyActions, stateSpec) {
  exactKeys(value, ['historyActions', 'kind', 'sample'], label);
  if (value.kind !== kind || value.historyActions !== historyActions) fail(`${label} has the wrong phase identity or history count`);
  return freeze({ kind, historyActions, sample: validateSample(value.sample, `${label}.sample`, stateSpec) });
}

function validateWarm(value) {
  exactKeys(value, ['at100k', 'baseline1k', 'kind', 'ratio'], 'warmUpdate');
  if (value.kind !== 'warm-fixed-depth-update') fail('warmUpdate.kind is invalid');
  const baseline1k = validateSampleSet(value.baseline1k, 'warmUpdate.baseline1k', { startCount: 1_000, endCount: 1_001 });
  const at100k = validateSampleSet(value.at100k, 'warmUpdate.at100k', { startCount: V2_Q07_HISTORY_ACTIONS, endCount: V2_Q07_HISTORY_ACTIONS + 1 });
  if (baseline1k.p95Ms === 0) fail('warmUpdate baseline p95 must be positive');
  const ratio = at100k.p95Ms / baseline1k.p95Ms;
  if (value.ratio !== ratio) fail('warmUpdate.ratio does not bind the two p95 values');
  if (baseline1k.p95Ms > V2_Q07_THRESHOLDS.stateApplyP95Ms || at100k.p95Ms > V2_Q07_THRESHOLDS.stateApplyP95Ms) fail('warmUpdate p95 exceeds the state-application target');
  if (ratio > V2_Q07_THRESHOLDS.warmRatio) fail('warmUpdate 100k/1k ratio exceeds 1.10');
  return freeze({ kind: value.kind, baseline1k, at100k, ratio });
}

function validateProof(value) {
  const result = validateSampleSet(value, 'proofGeneration', { startCount: V2_Q07_HISTORY_ACTIONS, endCount: V2_Q07_HISTORY_ACTIONS });
  if (result.p95Ms > V2_Q07_THRESHOLDS.proofP95Ms) fail('proofGeneration p95 exceeds 60000ms');
  for (const sample of result.samples) {
    if (sample.rss.bytes > V2_Q07_THRESHOLDS.proverPeakRssBytes) fail('proofGeneration RSS exceeds 4GiB');
  }
  return result;
}

function validateStore(value) {
  exactKeys(value, ['artifactSha256', 'authenticated', 'bytes', 'kind', 'terminalState'], 'store');
  if (value.kind !== 'full-v2-authenticated-store') fail('store.kind must identify the full V2 store');
  if (value.authenticated !== true) fail('store must be authenticated');
  integer(value.bytes, 'store.bytes', { minimum: 1 });
  hash(value.artifactSha256, 'store.artifactSha256');
  if (value.bytes > V2_Q07_THRESHOLDS.storeBytes) fail('store exceeds 2.5GiB');
  const terminalState = validateStateBinding(
    { start: value.terminalState, end: value.terminalState },
    'store.terminalState',
    { startCount: V2_Q07_HISTORY_ACTIONS, endCount: V2_Q07_HISTORY_ACTIONS },
  ).end;
  return freeze({ artifactSha256: value.artifactSha256, authenticated: true, bytes: value.bytes, kind: value.kind, terminalState });
}

function validateReference(value, label) {
  exactKeys(value, ['reason', 'sha256', 'status'], label);
  if (value.status === 'verified') {
    if (value.reason !== null) fail(`${label}.reason must be null when verified`);
    hash(value.sha256, `${label}.sha256`);
  } else if (value.status === 'unavailable') {
    if (value.sha256 !== null || typeof value.reason !== 'string' || value.reason.length === 0) fail(`${label} unavailable reference is invalid`);
  } else fail(`${label}.status is invalid`);
  return freeze({ ...value });
}

function validatePrerequisites(value) {
  exactKeys(value, ['finalCeremony', 'finalKey', 'finalPf10', 'finalProfile', 'q04Verification'], 'prerequisites');
  return freeze(Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, validateReference(entry, `prerequisites.${key}`)])));
}

function validateSubject(value) {
  exactKeys(value, ['eligibility', 'gitCommit', 'gitTree', 'instanceId', 'profileId', 'runtimeMaterialSha256', 'sourceSetSha256'], 'subject');
  if (!['development-only', 'final'].includes(value.eligibility)) fail('subject.eligibility is invalid');
  for (const key of ['profileId', 'instanceId', 'runtimeMaterialSha256', 'sourceSetSha256']) hash(value[key], `subject.${key}`);
  gitObject(value.gitCommit, 'subject.gitCommit');
  gitObject(value.gitTree, 'subject.gitTree');
  return freeze({ ...value });
}

function validateDataset(value) {
  exactKeys(value, ['frMinusOneEdgeOrdinal', 'historyActions', 'historyCount', 'keyCount', 'mainCount', 'q04GatePass', 'q04VerificationArtifactSha256', 'q04VerificationStatus', 'rawKeyStreamSha256', 'transcriptSha256', 'verificationArtifactSha256', 'warmSampleOrdinal', 'zeroEdgeOrdinal'], 'dataset');
  if (
    value.historyCount !== 1
    || value.historyActions !== V2_Q07_HISTORY_ACTIONS
    || value.mainCount !== V2_Q07_HISTORY_ACTIONS
    || value.keyCount !== V2_Q07_HISTORY_ACTIONS + 1
    || value.warmSampleOrdinal !== V2_Q07_HISTORY_ACTIONS + 1
    || value.zeroEdgeOrdinal !== 1
    || value.frMinusOneEdgeOrdinal !== 2
  ) {
    fail('dataset must bind one 100000-action history and its 100001-key file truth');
  }
  for (const key of ['rawKeyStreamSha256', 'transcriptSha256', 'q04VerificationArtifactSha256', 'verificationArtifactSha256']) hash(value[key], `dataset.${key}`);
  if (value.q04VerificationStatus !== 'verified') fail('dataset Q04 verifier evidence must be verified');
  if (value.q04GatePass !== true) fail('dataset Q04 gate must pass');
  return freeze({ ...value });
}

function validateActionAnchor(value, label, actionSequence) {
  exactKeys(value, ['actionSequence', 'blockHash', 'height', 'stateCommitmentSha256', 'txid', 'vout'], label);
  if (value.actionSequence !== actionSequence) fail(`${label}.actionSequence does not bind the canonical action boundary`);
  integer(value.vout, `${label}.vout`);
  integer(value.height, `${label}.height`);
  for (const key of ['stateCommitmentSha256', 'txid', 'blockHash']) hash(value[key], `${label}.${key}`);
  return freeze({ ...value });
}

function validateActionHistory(value, subject, qualifying) {
  exactKeys(value, ['evidence', 'reason', 'status'], 'actionHistory');
  if (value.status === 'unavailable') {
    if (typeof value.reason !== 'string' || value.reason.length === 0 || value.evidence !== null) fail('actionHistory unavailable record is invalid');
    if (qualifying) fail('actionHistory must be verified for qualified evidence');
    return freeze({ status: 'unavailable', reason: value.reason, evidence: null });
  }
  if (value.status !== 'verified' || value.reason !== null || value.evidence === null) fail('actionHistory verified record is invalid');
  const evidence = value.evidence;
  exactKeys(evidence, ['actionCount', 'actionKindCounts', 'artifactSha256', 'descriptorSha256', 'genesisAnchor', 'instanceId', 'profileId', 'rawTransactionBytes', 'runtimeMaterialSha256', 'terminalAnchor', 'verificationArtifactSha256'], 'actionHistory.evidence');
  if (evidence.actionCount !== V2_Q07_HISTORY_ACTIONS) fail('actionHistory.actionCount must be exactly 100000');
  integer(evidence.rawTransactionBytes, 'actionHistory.rawTransactionBytes', { minimum: 1 });
  for (const key of ['artifactSha256', 'verificationArtifactSha256', 'descriptorSha256']) hash(evidence[key], `actionHistory.${key}`);
  for (const key of ['profileId', 'instanceId', 'runtimeMaterialSha256']) {
    hash(evidence[key], `actionHistory.${key}`);
    if (evidence[key] !== subject[key]) fail(`actionHistory.${key} differs from subject`);
  }
  exactKeys(evidence.actionKindCounts, FINAL_ACTIONS, 'actionHistory.actionKindCounts');
  const actionKindCounts = {};
  let countSum = 0;
  for (const kind of FINAL_ACTIONS) {
    actionKindCounts[kind] = integer(evidence.actionKindCounts[kind], `actionHistory.actionKindCounts.${kind}`);
    countSum += actionKindCounts[kind];
    if (actionKindCounts[kind] !== V2_Q07_ACTION_KIND_COUNTS[kind]) {
      fail(`actionHistory.actionKindCounts.${kind} differs from the frozen Q07 workload`);
    }
  }
  if (countSum !== V2_Q07_HISTORY_ACTIONS) fail('actionHistory action-kind counts must sum to 100000');
  return freeze({
    status: 'verified',
    reason: null,
    evidence: freeze({
      actionCount: evidence.actionCount,
      actionKindCounts: freeze(actionKindCounts),
      artifactSha256: evidence.artifactSha256,
      verificationArtifactSha256: evidence.verificationArtifactSha256,
      descriptorSha256: evidence.descriptorSha256,
      rawTransactionBytes: evidence.rawTransactionBytes,
      profileId: evidence.profileId,
      instanceId: evidence.instanceId,
      runtimeMaterialSha256: evidence.runtimeMaterialSha256,
      genesisAnchor: validateActionAnchor(evidence.genesisAnchor, 'actionHistory.genesisAnchor', 0),
      terminalAnchor: validateActionAnchor(evidence.terminalAnchor, 'actionHistory.terminalAnchor', V2_Q07_HISTORY_ACTIONS),
    }),
  });
}

function validateFinalPf10(value, subject, qualifying) {
  exactKeys(value, ['actions', 'eligibility', 'evidenceArtifactSha256', 'gitCommit', 'gitTree', 'instanceId', 'profileId', 'runtimeMaterialSha256', 'sourceSetSha256'], 'finalPf10');
  if (!['development-only', 'final'].includes(value.eligibility)) fail('finalPf10.eligibility is invalid');
  for (const key of ['profileId', 'instanceId', 'runtimeMaterialSha256', 'sourceSetSha256']) hash(value[key], `finalPf10.${key}`);
  gitObject(value.gitCommit, 'finalPf10.gitCommit');
  gitObject(value.gitTree, 'finalPf10.gitTree');
  for (const key of ['profileId', 'instanceId', 'runtimeMaterialSha256']) {
    if (value[key] !== subject[key]) fail(`finalPf10.${key} differs from subject`);
  }
  if (qualifying) {
    for (const key of ['sourceSetSha256', 'gitCommit', 'gitTree']) {
      if (value[key] !== subject[key]) fail(`finalPf10.${key} differs from subject`);
    }
  }
  hash(value.evidenceArtifactSha256, 'finalPf10.evidenceArtifactSha256');
  if (!Array.isArray(value.actions) || value.actions.length !== FINAL_ACTIONS.length) fail('finalPf10.actions must contain each final action exactly once');
  const actions = value.actions.map((action, index) => {
    exactKeys(action, ['inputCount', 'inputs', 'kind', 'transactionBytes'], `finalPf10.actions[${index}]`);
    if (action.kind !== FINAL_ACTIONS[index]) fail(`finalPf10 action ${index} is invalid`);
    integer(action.transactionBytes, `finalPf10 ${action.kind}.transactionBytes`);
    if (action.transactionBytes > V2_Q07_THRESHOLDS.transactionBytes) fail('final PF10 transaction exceeds 100000 bytes');
    if (action.inputCount !== 13 || !Array.isArray(action.inputs) || action.inputs.length !== 13) {
      fail(`finalPf10 ${action.kind} must bind exactly 13 canonical inputs`);
    }
    const inputs = action.inputs.map((input, inputIndex) => {
      const label = `finalPf10 ${action.kind}.inputs[${inputIndex}]`;
      exactKeys(input, ['accepted', 'hashDigestIterations', 'inputIndex', 'maximumHashDigestIterations', 'maximumOperationCost', 'maximumSignatureChecks', 'operationCost', 'signatureCheckCount', 'unlockBytes'], label);
      if (input.inputIndex !== inputIndex) fail(`${label}.inputIndex is not in canonical order`);
      if (input.accepted !== true) fail(`${label}.accepted must be true`);
      integer(input.unlockBytes, `${label}.unlockBytes`);
      if (input.unlockBytes > V2_Q07_THRESHOLDS.unlockBytes) fail('final PF10 unlock exceeds 10000 bytes');
      for (const [observed, maximum] of [
        ['operationCost', 'maximumOperationCost'],
        ['hashDigestIterations', 'maximumHashDigestIterations'],
        ['signatureCheckCount', 'maximumSignatureChecks'],
      ]) {
        integer(input[observed], `${label}.${observed}`);
        integer(input[maximum], `${label}.${maximum}`, { minimum: 1 });
        if (input[observed] > input[maximum]) fail(`${label}.${observed} exceeds ${maximum}`);
      }
      return freeze({ ...input });
    });
    return freeze({ kind: action.kind, transactionBytes: action.transactionBytes, inputCount: action.inputCount, inputs: freeze(inputs) });
  });
  if (qualifying && value.eligibility !== 'final') fail('development-only PF10 evidence cannot qualify');
  return freeze({ ...value, actions: freeze(actions) });
}

function validateReferenceMachine(value, qualifying) {
  exactKeys(value, ['attestation', 'cgroupV2', 'manifestSha256'], 'referenceMachine');
  hash(value.manifestSha256, 'referenceMachine.manifestSha256');
  if (!['local-unattested', 'published-reference-machine'].includes(value.attestation)) fail('referenceMachine.attestation is invalid');
  if (value.cgroupV2 !== true && value.cgroupV2 !== false) fail('referenceMachine.cgroupV2 is invalid');
  if (qualifying && (value.attestation !== 'published-reference-machine' || value.cgroupV2 !== true)) fail('qualified evidence requires an attested cgroup-v2 reference machine');
  return freeze({ ...value });
}

const allVerified = (prerequisites) => Object.values(prerequisites).every((entry) => entry.status === 'verified');
const measuredMetric = (record, metric) => (record.status === 'measured' ? metric(record.evidence) : null);

/** Validate an evidence document without executing any workload. */
export function validateQ07Evidence(value) {
  exactKeys(value, ['actionHistory', 'dataset', 'finalPf10', 'phases', 'proofGeneration', 'prerequisites', 'referenceMachine', 'schema', 'store', 'subject', 'verdict'], 'Q-07 evidence');
  if (value.schema !== V2_Q07_EVIDENCE_SCHEMA) fail('Q-07 evidence schema is unsupported');
  exactKeys(value.verdict, ['reasons', 'status'], 'verdict');
  if (![QUALIFIED, BLOCKED].includes(value.verdict.status) || !Array.isArray(value.verdict.reasons)) fail('Q-07 verdict is invalid');
  if (value.verdict.status === QUALIFIED && value.verdict.reasons.length !== 0) fail('qualified verdict must not include blocking reasons');
  if (value.verdict.status === BLOCKED && value.verdict.reasons.length === 0) fail('blocked verdict must include a reason');
  if (!value.verdict.reasons.every((reason) => typeof reason === 'string' && reason.length > 0)) fail('Q-07 verdict reasons are invalid');
  const qualifying = value.verdict.status === QUALIFIED;
  const subject = validateSubject(value.subject);
  const prerequisites = validatePrerequisites(value.prerequisites);
  const referenceMachine = validateReferenceMachine(value.referenceMachine, qualifying);
  const dataset = validateDataset(value.dataset);
  const actionHistory = validateActionHistory(value.actionHistory, subject, qualifying);
  if (prerequisites.q04Verification.status !== 'verified') fail('Q04 verifier reference must be verified');
  if (prerequisites.q04Verification.sha256 !== dataset.q04VerificationArtifactSha256) {
    fail('dataset Q04 verifier artifact does not bind the verified Q04 reference');
  }
  const proofGeneration = validateMeasurement(value.proofGeneration, 'proofGeneration', { qualifying, validateEvidence: validateProof });
  exactKeys(value.phases, ['bottomUpSnapshotAuthentication', 'coldIo', 'rawFallback', 'suffixReplay', 'warmUpdate'], 'phases');
  const phases = freeze({
    bottomUpSnapshotAuthentication: validateMeasurement(value.phases.bottomUpSnapshotAuthentication, 'phases.bottomUpSnapshotAuthentication', {
      qualifying,
      validateEvidence: (entry) => validateSingletonPhase(entry, 'phases.bottomUpSnapshotAuthentication.evidence', 'bottom-up-snapshot-authentication', V2_Q07_HISTORY_ACTIONS, { startCount: 0, endCount: V2_Q07_HISTORY_ACTIONS }),
    }),
    rawFallback: validateMeasurement(value.phases.rawFallback, 'phases.rawFallback', {
      qualifying,
      validateEvidence: (entry) => validateSingletonPhase(entry, 'phases.rawFallback.evidence', 'raw-fallback', V2_Q07_HISTORY_ACTIONS, { startCount: 0, endCount: V2_Q07_HISTORY_ACTIONS }),
    }),
    suffixReplay: validateMeasurement(value.phases.suffixReplay, 'phases.suffixReplay', {
      qualifying,
      validateEvidence: (entry) => validateSingletonPhase(entry, 'phases.suffixReplay.evidence', 'suffix-replay', 1_000, { startCount: V2_Q07_HISTORY_ACTIONS - 1_000, endCount: V2_Q07_HISTORY_ACTIONS }),
    }),
    warmUpdate: validateMeasurement(value.phases.warmUpdate, 'phases.warmUpdate', { qualifying, validateEvidence: validateWarm }),
    coldIo: validateMeasurement(value.phases.coldIo, 'phases.coldIo', {
      qualifying,
      validateEvidence: (entry) => {
        exactKeys(entry, ['historyActions', 'kind', 'samples'], 'phases.coldIo.evidence');
        if (entry.kind !== 'cold-sqlite-io' || entry.historyActions !== V2_Q07_HISTORY_ACTIONS) fail('phases.coldIo has the wrong phase identity or history count');
        return freeze({ kind: entry.kind, historyActions: entry.historyActions, samples: validateSampleSet(entry.samples, 'phases.coldIo.evidence.samples', { startCount: V2_Q07_HISTORY_ACTIONS, endCount: V2_Q07_HISTORY_ACTIONS }) });
      },
    }),
  });
  if (phases.rawFallback.status === 'measured' && phases.rawFallback.evidence.sample.wallMs > V2_Q07_THRESHOLDS.fullRecoveryMs) fail('raw-fallback full recovery exceeds 900000ms');
  for (const phase of [phases.bottomUpSnapshotAuthentication, phases.rawFallback, phases.suffixReplay]) {
    if (phase.status === 'measured' && phase.evidence.sample.rss.bytes > V2_Q07_THRESHOLDS.recoveryPeakRssBytes) fail('recovery RSS exceeds 2GiB');
  }
  const store = validateMeasurement(value.store, 'store', { qualifying, validateEvidence: validateStore });
  const hasMeasuredFullV2Evidence = proofGeneration.status === 'measured'
    || store.status === 'measured'
    || Object.values(phases).some((phase) => phase.status === 'measured');
  if (hasMeasuredFullV2Evidence && actionHistory.status !== 'verified') {
    fail('measured full-V2 evidence requires a verified actionHistory corpus');
  }
  const finalPf10 = validateFinalPf10(value.finalPf10, subject, qualifying);
  if (qualifying && (subject.eligibility !== 'final' || !allVerified(prerequisites) || finalPf10.eligibility !== 'final' || !referenceMachine.cgroupV2)) fail('qualified evidence is missing final external prerequisites');
  if (!qualifying && (subject.eligibility === 'final' && allVerified(prerequisites) && finalPf10.eligibility === 'final')) fail('final verified evidence must use a qualified verdict');
  if (qualifying) {
    fail('qualified Q07 evidence requires authoritative artifact-bundle verification; this pure evidence validator is blocked-only');
  }
  return freeze({ schema: value.schema, verdict: freeze({ status: value.verdict.status, reasons: freeze([...value.verdict.reasons]) }), subject, prerequisites, referenceMachine, dataset, actionHistory, proofGeneration, phases, store, finalPf10 });
}

/** Builder alias for blocked/development orchestrators constructing a canonical in-memory record. */
export const buildQ07Evidence = (value) => validateQ07Evidence(value);

/** Return a small, machine-consumable blocked/development result. */
export function verifyQ07Evidence(value) {
  const evidence = validateQ07Evidence(value);
  return freeze({
    schema: V2_Q07_RESULT_SCHEMA,
    status: evidence.verdict.status,
    q07Qualified: false,
    profileId: evidence.subject.profileId,
    instanceId: evidence.subject.instanceId,
    historyActions: evidence.dataset.historyActions,
    proofP95Ms: measuredMetric(evidence.proofGeneration, (entry) => entry.p95Ms),
    warmBaselineP95Ms: measuredMetric(evidence.phases.warmUpdate, (entry) => entry.baseline1k.p95Ms),
    warm100kP95Ms: measuredMetric(evidence.phases.warmUpdate, (entry) => entry.at100k.p95Ms),
    fullRecoveryMs: measuredMetric(evidence.phases.rawFallback, (entry) => entry.sample.wallMs),
    storeBytes: measuredMetric(evidence.store, (entry) => entry.bytes),
  });
}
