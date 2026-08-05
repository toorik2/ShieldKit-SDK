import { availableParallelism } from 'node:os';

import { CHIPNET_GENESIS_HASH, isBchnChipnetBackend } from '../packages/kit/chipnet-rpc.mjs';
import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import { V2_BETA_RUNTIME_WORK_OBSERVATION_SCHEMA } from '../packages/profile/v2/beta-runtime-work-observer.mjs';

const HASH = /^[0-9a-f]{64}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
const VM_METRICS = Object.freeze([
  'arithmeticCost',
  'definedFunctions',
  'densityControlLength',
  'evaluatedInstructionCount',
  'hashDigestIterations',
  'maximumHashDigestIterations',
  'maximumOperationCost',
  'maximumSignatureCheckCount',
  'operationCost',
  'signatureCheckCount',
  'stackPushedBytes',
]);
const RPC_METHODS = Object.freeze([
  'getblockhash',
  'getrawtransaction',
  'gettxout',
  'scantxoutset',
  'sendrawtransaction',
  'testmempoolaccept',
]);
const PUBLIC_ELECTRUM_METHODS = Object.freeze([
  'server.features', 'server.version', 'blockchain.transaction.broadcast',
  'blockchain.transaction.get', 'blockchain.utxo.get_info',
  'blockchain.scripthash.listunspent',
]);
// The logical action route is deliberately transport-neutral. For the actual
// end-user product, retain the literal requests made by Fulcrum as well. A
// negotiated 1.4 provider must use listunspent; 1.5+ uses get_info. Both
// profiles are exact, rather than accepting an unbounded provider counter.
const PUBLIC_FULCRUM_ACTION_PHYSICAL_PROFILES = Object.freeze({
  'fresh-single-pass': Object.freeze([
    Object.freeze({
      'server.features': 0, 'server.version': 0,
      'blockchain.transaction.broadcast': 1,
      'blockchain.transaction.get': 1,
      'blockchain.utxo.get_info': 1,
      'blockchain.scripthash.listunspent': 0,
    }),
    Object.freeze({
      'server.features': 0, 'server.version': 0,
      'blockchain.transaction.broadcast': 1,
      'blockchain.transaction.get': 1,
      'blockchain.utxo.get_info': 0,
      'blockchain.scripthash.listunspent': 1,
    }),
  ]),
});
const RUNTIME_WORK_TYPES = Object.freeze([
  'linked-runtime-cache-load',
  'cold-runtime-build',
  'full-runtime-verification',
  'compiler-child-spawn',
  'instance-specialization',
]);
const ACTION_TIMINGS = Object.freeze([
  'admission',
  'commit',
  'fundingRead',
  'localVm',
  'proofGeneration',
  'proofTotal',
  'proofVerification',
  'signingAndVm',
  'stateRead',
  'total',
  'treeAndPreparation',
  'witnessAssembly',
  'witnessCalculation',
]);
const FORBIDDEN_FIELD_NAME = /(?:secret|private(?:key)?|mnemonic|seed|spend|view|witness|circuitinput|membership|funding.*key|change.*key|note(?:record|material))/iu;

export class V2BetaLiveActionEvidenceError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'V2BetaLiveActionEvidenceError';
    this.code = code;
  }
}

const fail = (code, message) => {
  throw new V2BetaLiveActionEvidenceError(code, message);
};

function record(value, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('LIVE_ACTION_EVIDENCE_INVALID', `${label} must be a plain object`);
  }
  return value;
}

function exact(value, keys, label) {
  record(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])) {
    fail('LIVE_ACTION_EVIDENCE_INVALID', `${label} has missing or unknown fields`);
  }
  return value;
}

function rejectSecretFields(value, label = 'command result') {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => rejectSecretFields(entry, `${label}[${index}]`));
    return;
  }
  if (value === null || typeof value !== 'object') return;
  for (const [key, entry] of Object.entries(value)) {
    // These are timing labels, never witness bytes or private input material.
    const timingLabel = label === 'command result.action.timingsMs'
      && (key === 'witnessAssembly' || key === 'witnessCalculation');
    if (!timingLabel && FORBIDDEN_FIELD_NAME.test(key)) {
      fail('LIVE_ACTION_SECRET_FIELD', `${label}.${key} is forbidden in public action evidence`);
    }
    rejectSecretFields(entry, `${label}.${key}`);
  }
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail('LIVE_ACTION_EVIDENCE_INVALID', `${label} must be lowercase 32-byte hexadecimal`);
  }
  return value;
}

function decimal(value, label) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) {
    fail('LIVE_ACTION_EVIDENCE_INVALID', `${label} must be a canonical unsigned decimal`);
  }
  return value;
}

function integer(value, label, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    fail('LIVE_ACTION_EVIDENCE_INVALID', `${label} must be a safe integer at least ${minimum}`);
  }
  return value;
}

function duration(value, label) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    fail('LIVE_ACTION_EVIDENCE_INVALID', `${label} must be a finite nonnegative duration`);
  }
  return value;
}

function betaClaims(value, label) {
  exact(value, ['broadcasted', 'confirmed', 'mined', 'productionQualified'], label);
  if (value.broadcasted !== true || value.confirmed !== false
    || value.mined !== false || value.productionQualified !== false) {
    fail('LIVE_ACTION_EVIDENCE_INVALID', `${label} must remain broadcast zero-conf and explicitly unqualified`);
  }
  return Object.freeze({ ...value });
}

function runtimeWork(value, { instanceSpecializations = 0 } = {}) {
  exact(value, ['counts', 'events', 'schema'], 'command.runtimeWork');
  if (value.schema !== V2_BETA_RUNTIME_WORK_OBSERVATION_SCHEMA
    || !Array.isArray(value.events)) {
    fail('LIVE_ACTION_RUNTIME_WORK_INVALID', 'runtime-work observation schema or events are invalid');
  }
  exact(value.counts, RUNTIME_WORK_TYPES, 'command.runtimeWork.counts');
  const observed = Object.fromEntries(RUNTIME_WORK_TYPES.map((type) => [type, 0]));
  for (const [index, event] of value.events.entries()) {
    exact(event, ['type'], `command.runtimeWork.events[${index}]`);
    if (!RUNTIME_WORK_TYPES.includes(event.type)) {
      fail('LIVE_ACTION_RUNTIME_WORK_INVALID', `unknown runtime-work event ${event.type}`);
    }
    observed[event.type] += 1;
  }
  for (const type of RUNTIME_WORK_TYPES) {
    integer(value.counts[type], `command.runtimeWork.counts.${type}`);
    if (value.counts[type] !== observed[type]) {
      fail('LIVE_ACTION_RUNTIME_WORK_INVALID', `runtime-work count ${type} differs from its events`);
    }
  }
  const expectedEvents = instanceSpecializations === 1
    ? ['instance-specialization', 'linked-runtime-cache-load']
    : ['linked-runtime-cache-load'];
  if (![0, 1].includes(instanceSpecializations)
    || value.counts['linked-runtime-cache-load'] !== 1
    || value.counts['cold-runtime-build'] !== 0
    || value.counts['full-runtime-verification'] !== 0
    || value.counts['compiler-child-spawn'] !== 0
    || value.counts['instance-specialization'] !== instanceSpecializations
    || value.events.length !== expectedEvents.length
    || value.events.some((event, index) => event.type !== expectedEvents[index])) {
    fail('LIVE_ACTION_RUNTIME_WORK_INVALID', 'operation must relocate once before its linked cache load only when explicitly permitted, and otherwise perform one cache load with zero build, verification, or compiler work');
  }
  return Object.freeze({
    schema: value.schema,
    counts: Object.freeze({ ...value.counts }),
    events: Object.freeze(value.events.map((event) => Object.freeze({ ...event }))),
  });
}

/** Independently inspect the measured pool-create linker/cache boundary. */
export function inspectV2BetaLivePoolRuntimeWork(value, linkedDuringCommand) {
  if (typeof linkedDuringCommand !== 'boolean') {
    fail('LIVE_ACTION_RUNTIME_WORK_INVALID', 'linkedDuringCommand must be boolean');
  }
  return runtimeWork(value, {
    instanceSpecializations: linkedDuringCommand ? 1 : 0,
  });
}

function proofTelemetry(value, actionProof, availableCores, actionTimings) {
  exact(value, [
    'activeCpuThreads', 'containment', 'cpuTicksPerWallMillisecond', 'observedThreads', 'ompThreads',
    'peakRssKiB', 'proofGenerationMs', 'systemTicks', 'totalTicks',
    'userTicks',
  ], 'action.telemetry.proof');
  for (const name of [
    'activeCpuThreads', 'observedThreads', 'ompThreads', 'peakRssKiB', 'systemTicks',
    'totalTicks', 'userTicks',
  ]) integer(value[name], `action.telemetry.proof.${name}`);
  duration(value.proofGenerationMs, 'action.telemetry.proof.proofGenerationMs');
  exact(value.containment, ['backend', 'memoryMaxBytes', 'memoryPeakBytes', 'memorySwapMaxBytes', 'oomDelta', 'oomKillDelta', 'terminatedSuccessfully'], 'action.telemetry.proof.containment');
  if (value.ompThreads !== availableCores || value.activeCpuThreads < availableCores || value.observedThreads < value.ompThreads
    || value.peakRssKiB <= 0 || value.totalTicks <= 0
    || value.totalTicks !== value.userTicks + value.systemTicks
    || value.proofGenerationMs <= 0
    || typeof value.cpuTicksPerWallMillisecond !== 'number'
    || !Number.isFinite(value.cpuTicksPerWallMillisecond)
    || value.cpuTicksPerWallMillisecond <= 0
    || value.cpuTicksPerWallMillisecond !== value.totalTicks / value.proofGenerationMs
    || value.proofGenerationMs !== actionTimings.proofGeneration) {
    fail('LIVE_ACTION_PROOF_TELEMETRY_INVALID', 'native proof telemetry does not prove an all-core measured proof generation');
  }
  if (actionProof.ompThreads !== value.ompThreads
    || actionProof.activeCpuThreads !== value.activeCpuThreads
    || actionProof.observedThreads !== value.observedThreads
    || actionProof.peakRssKiB !== value.peakRssKiB
    || actionProof.userCpuTicks !== value.userTicks
    || actionProof.systemCpuTicks !== value.systemTicks
    || actionProof.totalCpuTicks !== value.totalTicks
    || actionProof.cpuTicksPerWallMillisecond !== value.cpuTicksPerWallMillisecond
    || canonicalizeJcs(actionProof.containment) !== canonicalizeJcs(value.containment)) {
    fail('LIVE_ACTION_PROOF_TELEMETRY_INVALID', 'public proof summary differs from its measured telemetry');
  }
  return Object.freeze({ ...value });
}

function vmTelemetry(value, inputCount) {
  exact(value, ['allInputsAccepted', 'inputs', 'schema'], 'action.telemetry.vm');
  if (value.schema !== 'shieldkit-v2-local-vm-telemetry-v1'
    || value.allInputsAccepted !== true || !Array.isArray(value.inputs)
    || value.inputs.length !== inputCount) {
    fail('LIVE_ACTION_VM_TELEMETRY_INVALID', 'VM telemetry must cover every transaction input');
  }
  const inputs = value.inputs.map((entry, index) => {
    exact(entry, ['accepted', 'index', 'metrics'], `action.telemetry.vm.inputs[${index}]`);
    exact(entry.metrics, VM_METRICS, `action.telemetry.vm.inputs[${index}].metrics`);
    if (entry.index !== index || entry.accepted !== true) {
      fail('LIVE_ACTION_VM_TELEMETRY_INVALID', `VM input ${index} is missing an exact accepted verdict`);
    }
    const metrics = Object.fromEntries(VM_METRICS.map((name) => [
      name,
      decimal(entry.metrics[name], `action.telemetry.vm.inputs[${index}].metrics.${name}`),
    ]));
    if (BigInt(metrics.operationCost) > BigInt(metrics.maximumOperationCost)
      || BigInt(metrics.hashDigestIterations) > BigInt(metrics.maximumHashDigestIterations)
      || BigInt(metrics.signatureCheckCount) > BigInt(metrics.maximumSignatureCheckCount)) {
      fail('LIVE_ACTION_VM_TELEMETRY_INVALID', `VM input ${index} exceeds an exact resource ceiling`);
    }
    return Object.freeze({ index, accepted: true, metrics: Object.freeze(metrics) });
  });
  return Object.freeze({ schema: value.schema, allInputsAccepted: true, inputs: Object.freeze(inputs) });
}

function storeSnapshot(value, label) {
  exact(value, [
    'databaseBytes', 'liveCount', 'noteCount', 'nullifierCount', 'schema',
    'walBytes',
  ], label);
  if (value.schema !== 'shieldkit-v2-beta-incremental-store-telemetry-v1') {
    fail('LIVE_ACTION_STORE_TELEMETRY_INVALID', `${label} has an unsupported schema`);
  }
  for (const name of ['databaseBytes', 'liveCount', 'noteCount', 'nullifierCount', 'walBytes']) {
    integer(value[name], `${label}.${name}`);
  }
  if (value.databaseBytes <= 0 || value.liveCount !== value.noteCount - value.nullifierCount) {
    fail('LIVE_ACTION_STORE_TELEMETRY_INVALID', `${label} counters or measured database bytes are inconsistent`);
  }
  return Object.freeze({ ...value });
}

function storeTelemetry(value, kind) {
  exact(value, ['delta', 'post', 'pre'], 'action.telemetry.store');
  const pre = storeSnapshot(value.pre, 'action.telemetry.store.pre');
  const post = storeSnapshot(value.post, 'action.telemetry.store.post');
  exact(value.delta, [
    'databaseBytes', 'liveCount', 'noteCount', 'nullifierCount', 'walBytes',
  ], 'action.telemetry.store.delta');
  for (const name of ['databaseBytes', 'liveCount', 'noteCount', 'nullifierCount', 'walBytes']) {
    if (!Number.isSafeInteger(value.delta[name])
      || value.delta[name] !== post[name] - pre[name]) {
      fail('LIVE_ACTION_STORE_TELEMETRY_INVALID', `store delta ${name} differs from post minus pre`);
    }
  }
  const expected = kind === 'deposit'
    ? { noteCount: 1, nullifierCount: 0, liveCount: 1 }
    : { noteCount: 0, nullifierCount: 1, liveCount: -1 };
  if (Object.entries(expected).some(([name, amount]) => value.delta[name] !== amount)) {
    fail('LIVE_ACTION_STORE_TELEMETRY_INVALID', `${kind} store-count delta is not the exact protocol transition`);
  }
  return Object.freeze({ pre, post, delta: Object.freeze({ ...value.delta }) });
}

function rpcObservation(value, admissionRoute) {
  const hasPhysicalCounts = Object.hasOwn(value ?? {}, 'physicalMethodCounts');
  exact(value, hasPhysicalCounts
    ? ['backend', 'genesis', 'methodCounts', 'physicalMethodCounts']
    : ['backend', 'genesis', 'methodCounts'], 'action.rpcObservation');
  exact(value.methodCounts, RPC_METHODS, 'action.rpcObservation.methodCounts');
  if (!isBchnChipnetBackend(value.backend) || value.genesis !== CHIPNET_GENESIS_HASH) {
    fail('LIVE_ACTION_RPC_OBSERVATION_INVALID', 'action RPC backend is not the authenticated Chipnet capability');
  }
  const routeProfiles = Object.freeze({
    'fresh-single-pass': Object.freeze({ getrawtransaction: 1, gettxout: 1, sendrawtransaction: 1 }),
    'fresh-reconciled-after-indeterminate-send': Object.freeze({ getrawtransaction: 2, gettxout: 2, sendrawtransaction: 1 }),
    'read-only-reconciliation': Object.freeze({ getrawtransaction: 1, gettxout: 1, sendrawtransaction: 0 }),
    'explicit-rebroadcast-precheck-visible': Object.freeze({ getrawtransaction: 1, gettxout: 1, sendrawtransaction: 0 }),
    'explicit-rebroadcast-single-pass': Object.freeze({ getrawtransaction: 2, gettxout: 1, sendrawtransaction: 1 }),
    'explicit-rebroadcast-reconciled-after-indeterminate-send': Object.freeze({ getrawtransaction: 3, gettxout: 2, sendrawtransaction: 1 }),
  });
  const route = routeProfiles[admissionRoute];
  if (route === undefined) {
    fail('LIVE_ACTION_RPC_OBSERVATION_INVALID', 'action admission route is unsupported');
  }
  const expected = {
    getblockhash: 0,
    getrawtransaction: route.getrawtransaction,
    gettxout: route.gettxout,
    scantxoutset: 0,
    sendrawtransaction: route.sendrawtransaction,
    testmempoolaccept: 0,
  };
  for (const name of RPC_METHODS) {
    if (value.methodCounts[name] !== expected[name]) {
      fail('LIVE_ACTION_RPC_OBSERVATION_INVALID', `action RPC count ${name} is not exactly ${expected[name]}`);
    }
  }
  if (hasPhysicalCounts) {
    if (value.backend !== 'public-chipnet-fulcrum-tls') {
      fail('LIVE_ACTION_RPC_OBSERVATION_INVALID', 'public provider method counts require the public Fulcrum backend');
    }
    exact(value.physicalMethodCounts, PUBLIC_ELECTRUM_METHODS, 'action.rpcObservation.physicalMethodCounts');
    for (const name of PUBLIC_ELECTRUM_METHODS) {
      if (!Number.isSafeInteger(value.physicalMethodCounts[name])
        || value.physicalMethodCounts[name] < 0) {
        fail('LIVE_ACTION_RPC_OBSERVATION_INVALID', `public provider count ${name} is invalid`);
      }
    }
    const physicalProfiles = PUBLIC_FULCRUM_ACTION_PHYSICAL_PROFILES[admissionRoute];
    if (physicalProfiles === undefined || !physicalProfiles.some((profile) =>
      PUBLIC_ELECTRUM_METHODS.every((name) => value.physicalMethodCounts[name] === profile[name]))) {
      fail('LIVE_ACTION_RPC_OBSERVATION_INVALID', 'public Fulcrum method counts do not match the exact declared admission route');
    }
  }
  return Object.freeze({
    backend: value.backend,
    genesis: value.genesis,
    methodCounts: Object.freeze({ ...value.methodCounts }),
    ...(hasPhysicalCounts
      ? { physicalMethodCounts: Object.freeze({ ...value.physicalMethodCounts }) }
      : {}),
  });
}

/**
 * Independently inspect one literal public deposit/withdraw command result.
 * The projection contains only secret-free measurements needed by live gates.
 */
export function inspectV2BetaLiveActionEvidence(result, {
  command,
  operationId,
  // Deliberately test-only. Live callers always compare against the host
  // scheduler's actual availableParallelism(), not a supplied evidence claim.
  testAvailableCores = undefined,
} = {}) {
  const availableCores = testAvailableCores ?? availableParallelism();
  if (!['deposit', 'withdraw'].includes(command)
    || typeof operationId !== 'string' || operationId.length === 0
    || !Number.isSafeInteger(availableCores) || availableCores < 1) {
    fail('LIVE_ACTION_EVIDENCE_INVALID', 'action evidence expectation is invalid');
  }
  rejectSecretFields(result);
  exact(result, [
    'action', 'claims', 'command', 'operationId', 'runtimeWork', 'schema',
    'status', 'telemetry', 'timingsMs', 'transactionId',
  ], 'command result');
  exact(result.timingsMs, ['action', 'commandTotal', 'sessionOpen'], 'command.timingsMs');
  for (const name of ['action', 'commandTotal', 'sessionOpen']) {
    duration(result.timingsMs[name], `command.timingsMs.${name}`);
  }
  if (result.schema !== 'shieldkit-v2-beta-product-command-result-v3'
    || result.status !== 'accepted-zero-conf-beta-unqualified'
    || result.command !== command || result.operationId !== operationId
    || !HASH.test(result.transactionId)) {
    fail('LIVE_ACTION_EVIDENCE_INVALID', 'command result identity is invalid');
  }
  const commandClaims = betaClaims(result.claims, 'command.claims');
  const work = runtimeWork(result.runtimeWork);
  const action = result.action;
  exact(action, [
    'admissionRoute', 'cache', 'claims', 'kind', 'operationId', 'proof', 'readback',
    'rpcObservation', 'schema', 'status', 'telemetry', 'timingsMs',
    'transaction', 'transactionId', 'vm',
  ], 'action');
  const actionKind = command === 'deposit' ? 'deposit' : 'withdrawal';
  if (action.schema !== 'shieldkit-v2-beta-product-action-result-v3'
    || action.status !== result.status || action.kind !== actionKind
    || action.operationId !== operationId
    || action.transactionId !== result.transactionId) {
    fail('LIVE_ACTION_EVIDENCE_INVALID', 'action identity differs from its command result');
  }
  const actionClaims = betaClaims(action.claims, 'action.claims');
  if (canonicalizeJcs(commandClaims) !== canonicalizeJcs(actionClaims)) {
    fail('LIVE_ACTION_EVIDENCE_INVALID', 'command and action claims differ');
  }

  exact(action.cache, ['runtimeManifestSha256', 'runtimeMaterialSha256'], 'action.cache');
  hash(action.cache.runtimeManifestSha256, 'action.cache.runtimeManifestSha256');
  hash(action.cache.runtimeMaterialSha256, 'action.cache.runtimeMaterialSha256');
  exact(action.timingsMs, ACTION_TIMINGS, 'action.timingsMs');
  for (const name of ACTION_TIMINGS) duration(action.timingsMs[name], `action.timingsMs.${name}`);
  if (result.timingsMs.action !== action.timingsMs.total
    || result.timingsMs.commandTotal
      < result.timingsMs.sessionOpen + result.timingsMs.action
    || action.timingsMs.proofTotal < action.timingsMs.proofGeneration
    || action.timingsMs.proofTotal < action.timingsMs.proofVerification
    || action.timingsMs.total < Math.max(...ACTION_TIMINGS
      .filter((name) => name !== 'total')
      .map((name) => action.timingsMs[name]))) {
    fail('LIVE_ACTION_EVIDENCE_INVALID', 'command and action total timings are inconsistent');
  }

  exact(action.proof, [
    'activeCpuThreads', 'containment', 'cpuTicksPerWallMillisecond', 'nativeBackend', 'nativeProverSha256',
    'observedThreads', 'ompThreads', 'peakRssKiB', 'resultSha256',
    'systemCpuTicks', 'totalCpuTicks', 'userCpuTicks', 'verified',
  ], 'action.proof');
  if (action.proof.verified !== true || action.proof.nativeBackend !== 'rapidsnark') {
    fail('LIVE_ACTION_PROOF_TELEMETRY_INVALID', 'action proof is not a locally verified native Rapidsnark proof');
  }
  hash(action.proof.resultSha256, 'action.proof.resultSha256');
  hash(action.proof.nativeProverSha256, 'action.proof.nativeProverSha256');

  exact(action.vm, [
    'acceptedInputCount', 'allInputsAccepted', 'evidenceHash', 'inputCount',
  ], 'action.vm');
  hash(action.vm.evidenceHash, 'action.vm.evidenceHash');
  integer(action.vm.inputCount, 'action.vm.inputCount', 1);
  if (action.vm.allInputsAccepted !== true
    || action.vm.acceptedInputCount !== action.vm.inputCount) {
    fail('LIVE_ACTION_VM_TELEMETRY_INVALID', 'action VM summary does not accept every input');
  }

  exact(action.telemetry, ['proof', 'schema', 'store', 'vm'], 'action.telemetry');
  if (action.telemetry.schema !== 'shieldkit-v2-beta-product-action-telemetry-v1'
    || canonicalizeJcs(result.telemetry) !== canonicalizeJcs(action.telemetry)) {
    fail('LIVE_ACTION_EVIDENCE_INVALID', 'command telemetry differs from the exact action telemetry');
  }
  const proof = proofTelemetry(
    action.telemetry.proof,
    action.proof,
    availableCores,
    action.timingsMs,
  );
  const vm = vmTelemetry(action.telemetry.vm, action.vm.inputCount);
  const store = storeTelemetry(action.telemetry.store, command);

  exact(action.transaction, [
    'bytes', 'changeValueSats', 'changeVout', 'feeRateSatsPerByte', 'feeSats',
  ], 'action.transaction');
  integer(action.transaction.bytes, 'action.transaction.bytes', 1);
  integer(action.transaction.changeVout, 'action.transaction.changeVout');
  decimal(action.transaction.changeValueSats, 'action.transaction.changeValueSats');
  decimal(action.transaction.feeSats, 'action.transaction.feeSats');
  decimal(action.transaction.feeRateSatsPerByte, 'action.transaction.feeRateSatsPerByte');
  if (BigInt(action.transaction.feeSats)
    !== BigInt(action.transaction.bytes) * BigInt(action.transaction.feeRateSatsPerByte)) {
    fail('LIVE_ACTION_EVIDENCE_INVALID', 'transaction fee does not equal its exact byte size and fee rate');
  }

  exact(action.readback, [
    'rawTransactionSha256', 'stateCategoryWire', 'stateCommitmentSha256',
    'stateOutpoint',
  ], 'action.readback');
  exact(action.readback.stateOutpoint, ['txid', 'vout'], 'action.readback.stateOutpoint');
  hash(action.readback.rawTransactionSha256, 'action.readback.rawTransactionSha256');
  hash(action.readback.stateCategoryWire, 'action.readback.stateCategoryWire');
  hash(action.readback.stateCommitmentSha256, 'action.readback.stateCommitmentSha256');
  if (action.readback.stateOutpoint.txid !== result.transactionId
    || action.readback.stateOutpoint.vout !== 0) {
    fail('LIVE_ACTION_EVIDENCE_INVALID', 'state-NFT readback does not bind the accepted transaction output zero');
  }
  const rpc = rpcObservation(action.rpcObservation, action.admissionRoute);

  return Object.freeze({
    operationId,
    admissionRoute: action.admissionRoute,
    transactionId: result.transactionId,
    commandTotalMs: result.timingsMs.commandTotal,
    actionTotalMs: action.timingsMs.total,
    bytes: action.transaction.bytes,
    feeSats: action.transaction.feeSats,
    feeRateSatsPerByte: action.transaction.feeRateSatsPerByte,
    proof: Object.freeze({
      resultSha256: action.proof.resultSha256,
      nativeProverSha256: action.proof.nativeProverSha256,
      backend: action.proof.nativeBackend,
      verified: true,
      ...proof,
    }),
    vm: Object.freeze({
      evidenceHash: action.vm.evidenceHash,
      inputCount: action.vm.inputCount,
      allInputsAccepted: true,
      inputs: vm.inputs,
    }),
    store,
    runtimeWork: work,
    readback: Object.freeze({
      ...action.readback,
      stateOutpoint: Object.freeze({ ...action.readback.stateOutpoint }),
    }),
    cache: Object.freeze({ ...action.cache }),
    rpcObservation: rpc,
    timingsMs: Object.freeze({ ...action.timingsMs }),
    claims: actionClaims,
  });
}
