/**
 * Canonical, offline verifier for a completed V2 beta semantic/performance
 * evidence pair. It deliberately consumes only secret-free projections: raw
 * transactions, witnesses, circuit inputs, paths, and wallet material are not
 * part of this boundary.
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import { parseStrictJson } from '../packages/profile/load.mjs';
import { CHIPNET_GENESIS_HASH } from '../packages/kit/chipnet-rpc.mjs';

export const V2_BETA_LIVE_EVIDENCE_BUNDLE_MANIFEST_SCHEMA =
  'shieldkit-v2-beta-live-evidence-bundle-manifest-v1';
export const V2_BETA_LIVE_SEMANTIC_SCHEMA = 'shieldkit-v2-beta-live-qualification-v2';
export const V2_BETA_LIVE_PERFORMANCE_SCHEMA = 'shieldkit-v2-beta-live-performance-v1';
export const V2_BETA_LIVE_POOL_CREATE_PERFORMANCE_SCHEMA =
  'shieldkit-v2-beta-live-pool-create-performance-v2';

const HASH = /^[0-9a-f]{64}$/u;
const GIT_ID = /^[0-9a-f]{40}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
const RUNTIME_TYPES = Object.freeze([
  'linked-runtime-cache-load', 'cold-runtime-build',
  'full-runtime-verification', 'compiler-child-spawn', 'instance-specialization',
]);
const VM_METRICS = Object.freeze([
  'arithmeticCost', 'definedFunctions', 'densityControlLength',
  'evaluatedInstructionCount', 'hashDigestIterations',
  'maximumHashDigestIterations', 'maximumOperationCost',
  'maximumSignatureCheckCount', 'operationCost', 'signatureCheckCount',
  'stackPushedBytes',
]);
const RPC_METHODS = Object.freeze([
  'getblockhash', 'getrawtransaction', 'gettxout', 'scantxoutset',
  'sendrawtransaction', 'testmempoolaccept',
]);
const ACTION_TIMINGS = Object.freeze([
  'admission', 'commit', 'fundingRead', 'localVm', 'proofGeneration',
  'proofTotal', 'proofVerification', 'signingAndVm', 'stateRead', 'total',
  'treeAndPreparation', 'witnessAssembly', 'witnessCalculation',
]);
const POOL_TIMINGS = Object.freeze([
  'actionStoreBootstrap', 'admissionAndBroadcast', 'artifactLoad', 'atomicCommit',
  'commandTotal', 'durableStage', 'exactReadback', 'funding', 'genesis',
  'instanceSpecialization', 'runtimeCacheInstall', 'runtimeLoad', 'templateLoad',
  'templateReceiptAttestation',
]);
function forbiddenKey(key) {
  const folded = key.toLowerCase();
  return ['path', 'directory', 'datahome', 'datadirectory', 'evidencedirectory',
    'workspacedirectory', 'rawtransaction', 'rawtransactionhex', 'witness',
    'witnessbytes', 'circuitinput', 'membershippath', 'noterecord', 'notematerial']
    .includes(folded)
    || /(?:secret|private|mnemonic|seed|spend|view)/iu.test(key)
    || /(?:funding|change).*key/iu.test(key)
    || /^circuit(?:input|material|witness)?$/iu.test(key);
}

export class V2BetaLiveEvidenceBundleError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'V2BetaLiveEvidenceBundleError';
    this.code = code;
  }
}

const fail = (code, message, options = undefined) => {
  throw new V2BetaLiveEvidenceBundleError(code, message, options);
};
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const clone = (value) => JSON.parse(JSON.stringify(value));

function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('BUNDLE_INVALID', `${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail('BUNDLE_UNKNOWN_FIELD', `${label} has missing or unknown fields`);
  }
  return value;
}
function hash(value, label) { if (typeof value !== 'string' || !HASH.test(value)) fail('BUNDLE_INVALID', `${label} must be lowercase SHA-256`); return value; }
function git(value, label) { if (typeof value !== 'string' || !GIT_ID.test(value)) fail('BUNDLE_INVALID', `${label} must be a lowercase Git object id`); return value; }
function decimal(value, label) { if (typeof value !== 'string' || !DECIMAL.test(value)) fail('BUNDLE_INVALID', `${label} must be canonical unsigned decimal`); return value; }
function integer(value, label, minimum = 0) { if (!Number.isSafeInteger(value) || value < minimum) fail('BUNDLE_INVALID', `${label} must be a safe integer at least ${minimum}`); return value; }
function duration(value, label) { if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) fail('BUNDLE_INVALID', `${label} must be finite and nonnegative`); return value; }

function rejectSecretsAndPaths(value, label = '$') {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => rejectSecretsAndPaths(entry, `${label}[${index}]`));
    return;
  }
  if (value === null || typeof value !== 'object') return;
  for (const [key, entry] of Object.entries(value)) {
    if (forbiddenKey(key)) fail('BUNDLE_SECRET_OR_PATH', `${label}.${key} is forbidden in public evidence`);
    rejectSecretsAndPaths(entry, `${label}.${key}`);
  }
}

function claims(value, label, { broadcasted = false } = {}) {
  exact(value, broadcasted
    ? ['broadcasted', 'confirmed', 'mined', 'productionQualified']
    : ['confirmed', 'mined', 'productionQualified'], label);
  if ((broadcasted && value.broadcasted !== true) || value.confirmed !== false
    || value.mined !== false || value.productionQualified !== false) {
    fail('BUNDLE_PROMOTION_REJECTED', `${label} is not explicitly unqualified BCHN zero-conf evidence`);
  }
  return clone(value);
}

function runtimeWork(value, linkedDuringCommand = false) {
  exact(value, ['counts', 'events', 'schema'], 'action.runtimeWork');
  if (value.schema !== 'shieldkit-v2-beta-runtime-work-observation-v1' || !Array.isArray(value.events)) {
    fail('BUNDLE_RUNTIME_WORK_INVALID', 'runtimeWork has an unsupported schema');
  }
  exact(value.counts, RUNTIME_TYPES, 'action.runtimeWork.counts');
  const counted = Object.fromEntries(RUNTIME_TYPES.map((type) => [type, 0]));
  for (const event of value.events) {
    exact(event, ['type'], 'action.runtimeWork.events[]');
    if (!RUNTIME_TYPES.includes(event.type)) fail('BUNDLE_RUNTIME_WORK_INVALID', 'runtimeWork contains an unknown event');
    counted[event.type] += 1;
  }
  for (const type of RUNTIME_TYPES) {
    integer(value.counts[type], `action.runtimeWork.counts.${type}`);
    if (value.counts[type] !== counted[type]) fail('BUNDLE_RUNTIME_WORK_INVALID', `runtimeWork count ${type} differs from events`);
  }
  if (value.counts['linked-runtime-cache-load'] !== 1
    || value.counts['cold-runtime-build'] !== 0
    || value.counts['full-runtime-verification'] !== 0
    || value.counts['compiler-child-spawn'] !== 0
    || value.counts['instance-specialization'] !== (linkedDuringCommand ? 1 : 0)) {
    fail('BUNDLE_RUNTIME_WORK_INVALID', 'runtimeWork does not prove the allowed cache-only operation');
  }
  return clone(value);
}

function validateVm(value) {
  exact(value, ['allInputsAccepted', 'evidenceHash', 'inputCount', 'inputs'], 'action.vm');
  if (value.allInputsAccepted !== true || !Array.isArray(value.inputs)) fail('BUNDLE_VM_INVALID', 'all action inputs must be accepted');
  hash(value.evidenceHash, 'action.vm.evidenceHash'); integer(value.inputCount, 'action.vm.inputCount', 1);
  if (value.inputs.length !== value.inputCount) fail('BUNDLE_VM_INVALID', 'VM evidence does not retain every input');
  value.inputs.forEach((input, index) => {
    exact(input, ['accepted', 'index', 'metrics'], `action.vm.inputs[${index}]`);
    if (input.index !== index || input.accepted !== true) fail('BUNDLE_VM_INVALID', 'VM input verdict is not canonical accepted evidence');
    exact(input.metrics, VM_METRICS, `action.vm.inputs[${index}].metrics`);
    for (const name of VM_METRICS) decimal(input.metrics[name], `action.vm.inputs[${index}].metrics.${name}`);
    if (BigInt(input.metrics.operationCost) > BigInt(input.metrics.maximumOperationCost)
      || BigInt(input.metrics.hashDigestIterations) > BigInt(input.metrics.maximumHashDigestIterations)
      || BigInt(input.metrics.signatureCheckCount) > BigInt(input.metrics.maximumSignatureCheckCount)) {
      fail('BUNDLE_VM_INVALID', 'VM resource metric exceeds its retained ceiling');
    }
  });
}

function validateStore(value, kind) {
  exact(value, ['delta', 'post', 'pre'], 'action.store');
  const snapshot = (entry, label) => {
    exact(entry, ['databaseBytes', 'liveCount', 'noteCount', 'nullifierCount', 'schema', 'walBytes'], label);
    if (entry.schema !== 'shieldkit-v2-beta-incremental-store-telemetry-v1') fail('BUNDLE_STORE_INVALID', `${label} schema is invalid`);
    for (const name of ['databaseBytes', 'liveCount', 'noteCount', 'nullifierCount', 'walBytes']) integer(entry[name], `${label}.${name}`);
    if (entry.databaseBytes <= 0 || entry.liveCount !== entry.noteCount - entry.nullifierCount) fail('BUNDLE_STORE_INVALID', `${label} counters are inconsistent`);
  };
  snapshot(value.pre, 'action.store.pre'); snapshot(value.post, 'action.store.post');
  exact(value.delta, ['databaseBytes', 'liveCount', 'noteCount', 'nullifierCount', 'walBytes'], 'action.store.delta');
  for (const name of Object.keys(value.delta)) {
    if (!Number.isSafeInteger(value.delta[name]) || value.delta[name] !== value.post[name] - value.pre[name]) fail('BUNDLE_STORE_INVALID', `action.store.delta.${name} differs from post minus pre`);
  }
  const expected = kind === 'deposit'
    ? { liveCount: 1, noteCount: 1, nullifierCount: 0 }
    : { liveCount: -1, noteCount: 0, nullifierCount: 1 };
  for (const [name, amount] of Object.entries(expected)) if (value.delta[name] !== amount) fail('BUNDLE_STORE_INVALID', `store ${name} delta is not the ${kind} transition`);
}

function validateRpc(value, multiplier = 1) {
  exact(value, ['backend', 'genesis', 'methodCounts'], 'rpcObservation');
  exact(value.methodCounts, RPC_METHODS, 'rpcObservation.methodCounts');
  if (value.backend !== 'layer1-bchn-chipnet' || value.genesis !== CHIPNET_GENESIS_HASH) fail('BUNDLE_RPC_INVALID', 'evidence is not bound to BCHN Chipnet');
  const expected = { getblockhash: 0, getrawtransaction: multiplier, gettxout: 1, scantxoutset: 0, sendrawtransaction: multiplier, testmempoolaccept: multiplier };
  for (const name of RPC_METHODS) if (value.methodCounts[name] !== expected[name]) fail('BUNDLE_RPC_INVALID', `RPC count ${name} is not exact`);
}

function validateAction(value, kind, ordinal, cores, { performance = false } = {}) {
  const prefix = performance
    ? ['actionTotalMs', 'bytes', 'cache', 'claims', 'commandTotalMs', 'feeRateSatsPerByte', 'feeSats', 'kind', 'operationId', 'ordinal', 'poolOrdinal', 'proof', 'readback', 'rpcObservation', 'runtimeWork', 'state', 'store', 'timingsMs', 'transactionId', 'vm']
    : ['actionTotalMs', 'bytes', 'cache', 'claims', 'commandTotalMs', 'feeRateSatsPerByte', 'feeSats', 'kind', 'operationId', 'ordinal', 'proof', 'readback', 'rpcObservation', 'runtimeWork', 'store', 'timingsMs', 'transactionId', 'vm'];
  exact(value, prefix, 'action evidence');
  if (value.kind !== kind || value.ordinal !== ordinal || typeof value.operationId !== 'string' || value.operationId.length === 0) fail('BUNDLE_ACTION_IDENTITY_INVALID', 'action kind, ordinal, or operation id differs');
  if (performance && (!Number.isSafeInteger(value.poolOrdinal) || value.poolOrdinal < 0 || value.state !== 'accepted')) fail('BUNDLE_ACTION_IDENTITY_INVALID', 'performance sample is not an accepted planned action');
  hash(value.transactionId, 'action.transactionId'); duration(value.commandTotalMs, 'action.commandTotalMs'); duration(value.actionTotalMs, 'action.actionTotalMs');
  integer(value.bytes, 'action.bytes', 1); decimal(value.feeSats, 'action.feeSats'); decimal(value.feeRateSatsPerByte, 'action.feeRateSatsPerByte');
  if (BigInt(value.feeSats) !== BigInt(value.bytes) * BigInt(value.feeRateSatsPerByte)) fail('BUNDLE_ACTION_INVALID', 'action fee differs from bytes times fee rate');
  claims(value.claims, 'action.claims', { broadcasted: true });
  exact(value.cache, ['runtimeManifestSha256', 'runtimeMaterialSha256'], 'action.cache'); hash(value.cache.runtimeManifestSha256, 'action.cache.runtimeManifestSha256'); hash(value.cache.runtimeMaterialSha256, 'action.cache.runtimeMaterialSha256');
  runtimeWork(value.runtimeWork);
  exact(value.proof, ['activeCpuThreads', 'backend', 'containment', 'cpuTicksPerWallMillisecond', 'nativeProverSha256', 'observedThreads', 'ompThreads', 'peakRssKiB', 'proofGenerationMs', 'resultSha256', 'systemTicks', 'totalTicks', 'userTicks', 'verified'], 'action.proof');
  if (value.proof.backend !== 'rapidsnark' || value.proof.verified !== true) fail('BUNDLE_PROOF_INVALID', 'proof is not a locally verified native Rapidsnark proof');
  hash(value.proof.resultSha256, 'action.proof.resultSha256'); hash(value.proof.nativeProverSha256, 'action.proof.nativeProverSha256');
  for (const name of ['activeCpuThreads', 'observedThreads', 'ompThreads', 'peakRssKiB', 'systemTicks', 'totalTicks', 'userTicks']) integer(value.proof[name], `action.proof.${name}`);
  duration(value.proof.proofGenerationMs, 'action.proof.proofGenerationMs');
  exact(value.proof.containment, ['backend', 'memoryMaxBytes', 'memoryPeakBytes', 'memorySwapMaxBytes', 'oomDelta', 'oomKillDelta', 'terminatedSuccessfully'], 'action.proof.containment');
  if (value.proof.containment.backend !== 'linux-systemd-cgroup-v2' || value.proof.containment.terminatedSuccessfully !== true || !['memoryMaxBytes', 'memoryPeakBytes', 'memorySwapMaxBytes'].every((name) => DECIMAL.test(value.proof.containment[name] ?? '')) || !['oomDelta', 'oomKillDelta'].every((name) => Number.isSafeInteger(value.proof.containment[name]) && value.proof.containment[name] >= 0) || value.proof.ompThreads !== cores || value.proof.activeCpuThreads < cores || value.proof.activeCpuThreads > value.proof.observedThreads || value.proof.observedThreads < cores || value.proof.peakRssKiB <= 0 || value.proof.totalTicks <= 0 || value.proof.totalTicks !== value.proof.userTicks + value.proof.systemTicks || value.proof.proofGenerationMs <= 0 || typeof value.proof.cpuTicksPerWallMillisecond !== 'number' || !Number.isFinite(value.proof.cpuTicksPerWallMillisecond) || value.proof.cpuTicksPerWallMillisecond <= 0 || value.proof.cpuTicksPerWallMillisecond !== value.proof.totalTicks / value.proof.proofGenerationMs) fail('BUNDLE_PROOF_INVALID', 'proof telemetry does not establish a measured all-core contained proof');
  validateVm(value.vm); validateStore(value.store, kind); validateRpc(value.rpcObservation);
  exact(value.readback, ['rawTransactionSha256', 'stateCategoryWire', 'stateCommitmentSha256', 'stateOutpoint'], 'action.readback');
  hash(value.readback.rawTransactionSha256, 'action.readback.rawTransactionSha256'); hash(value.readback.stateCategoryWire, 'action.readback.stateCategoryWire'); hash(value.readback.stateCommitmentSha256, 'action.readback.stateCommitmentSha256'); exact(value.readback.stateOutpoint, ['txid', 'vout'], 'action.readback.stateOutpoint');
  if (value.readback.stateOutpoint.txid !== value.transactionId || value.readback.stateOutpoint.vout !== 0) fail('BUNDLE_READBACK_INVALID', 'state readback does not bind output zero of the accepted action');
  exact(value.timingsMs, ACTION_TIMINGS, 'action.timingsMs'); for (const name of ACTION_TIMINGS) duration(value.timingsMs[name], `action.timingsMs.${name}`);
  if (value.timingsMs.total !== value.actionTotalMs || value.timingsMs.proofGeneration !== value.proof.proofGenerationMs) fail('BUNDLE_ACTION_INVALID', 'action timing summary differs from retained stage telemetry');
}

function validatePool(value) {
  exact(value, ['acceptance', 'actionFundingOutputs', 'actionFundingSetSha256', 'claims', 'genesisTransactionId', 'instanceId', 'rpcObservation', 'runtime', 'sourceTransactionId', 'timingsMs', 'transactions', 'zeroConfEvidenceSha256'], 'semantic.pool');
  hash(value.instanceId, 'semantic.pool.instanceId'); hash(value.sourceTransactionId, 'semantic.pool.sourceTransactionId'); hash(value.genesisTransactionId, 'semantic.pool.genesisTransactionId'); hash(value.zeroConfEvidenceSha256, 'semantic.pool.zeroConfEvidenceSha256'); hash(value.actionFundingSetSha256, 'semantic.pool.actionFundingSetSha256');
  if (value.sourceTransactionId === value.genesisTransactionId || value.actionFundingOutputs !== 10) fail('BUNDLE_POOL_INVALID', 'pool bootstrap topology or action funding set is invalid');
  claims(value.claims, 'semantic.pool.claims', { broadcasted: true }); validateRpc(value.rpcObservation, 2);
  exact(value.runtime, ['linkedDuringCommand', 'runtimeManifestSha256', 'runtimeMaterialSha256', 'work'], 'semantic.pool.runtime');
  if (typeof value.runtime.linkedDuringCommand !== 'boolean') fail('BUNDLE_POOL_INVALID', 'pool runtime link state is invalid');
  hash(value.runtime.runtimeManifestSha256, 'semantic.pool.runtime.runtimeManifestSha256'); hash(value.runtime.runtimeMaterialSha256, 'semantic.pool.runtime.runtimeMaterialSha256'); runtimeWork(value.runtime.work, value.runtime.linkedDuringCommand);
  exact(value.acceptance, ['accepted', 'evidence', 'status'], 'semantic.pool.acceptance'); exact(value.acceptance.evidence, ['claims', 'status'], 'semantic.pool.acceptance.evidence');
  if (value.acceptance.accepted !== true || value.acceptance.status !== 'accepted-zero-conf' || value.acceptance.evidence.status !== 'accepted-zero-conf-beta-unqualified') fail('BUNDLE_POOL_INVALID', 'pool is not accepted zero-conf');
  claims(value.acceptance.evidence.claims, 'semantic.pool.acceptance.evidence.claims', { broadcasted: true });
  exact(value.transactions, ['genesis', 'source'], 'semantic.pool.transactions');
  exact(value.transactions.source, ['rawTransactionSha256', 'serializedBytes', 'transactionId'], 'semantic.pool.transactions.source'); hash(value.transactions.source.rawTransactionSha256, 'semantic.pool.transactions.source.rawTransactionSha256'); integer(value.transactions.source.serializedBytes, 'semantic.pool.transactions.source.serializedBytes', 1);
  if (value.transactions.source.transactionId !== value.sourceTransactionId) fail('BUNDLE_POOL_INVALID', 'pool source transaction id differs');
  exact(value.transactions.genesis, ['bch2026StandardVmAccepted', 'feeRateSatsPerByte', 'feeSats', 'inputMetrics', 'serializedBytes', 'transactionId'], 'semantic.pool.transactions.genesis');
  if (value.transactions.genesis.transactionId !== value.genesisTransactionId || value.transactions.genesis.bch2026StandardVmAccepted !== true || !Array.isArray(value.transactions.genesis.inputMetrics)) fail('BUNDLE_POOL_INVALID', 'pool genesis evidence is incomplete');
  integer(value.transactions.genesis.serializedBytes, 'semantic.pool.transactions.genesis.serializedBytes', 1); decimal(value.transactions.genesis.feeSats, 'semantic.pool.transactions.genesis.feeSats'); decimal(value.transactions.genesis.feeRateSatsPerByte, 'semantic.pool.transactions.genesis.feeRateSatsPerByte');
  if (BigInt(value.transactions.genesis.feeSats) !== BigInt(value.transactions.genesis.serializedBytes) * BigInt(value.transactions.genesis.feeRateSatsPerByte)) fail('BUNDLE_POOL_INVALID', 'pool genesis fee differs from bytes times fee rate');
  exact(value.timingsMs, POOL_TIMINGS, 'semantic.pool.timingsMs'); for (const name of POOL_TIMINGS) duration(value.timingsMs[name], `semantic.pool.timingsMs.${name}`);
}

function validateSemantic(value, cores) {
  exact(value, ['capacity', 'claims', 'deposits', 'install', 'pool', 'poolCreate', 'schema', 'scope', 'timingMs', 'withdrawals'], 'semantic evidence');
  if (value.schema !== V2_BETA_LIVE_SEMANTIC_SCHEMA || value.scope !== 'semantic-five-by-five-only-not-performance-qualification' || value.capacity !== '100000') fail('BUNDLE_SEMANTIC_INVALID', 'semantic evidence is not a completed fresh 100000-note semantic run');
  claims(value.claims, 'semantic.claims'); duration(value.timingMs, 'semantic.timingMs');
  exact(value.install, ['receiptSha256', 'releaseId', 'releaseManifestSha256'], 'semantic.install'); hash(value.install.receiptSha256, 'semantic.install.receiptSha256'); hash(value.install.releaseManifestSha256, 'semantic.install.releaseManifestSha256'); if (typeof value.install.releaseId !== 'string' || value.install.releaseId.length === 0) fail('BUNDLE_SEMANTIC_INVALID', 'semantic install release id is invalid');
  exact(value.poolCreate, ['commandDurationMs', 'sourceOutpointProvenanceSha256'], 'semantic.poolCreate'); duration(value.poolCreate.commandDurationMs, 'semantic.poolCreate.commandDurationMs'); hash(value.poolCreate.sourceOutpointProvenanceSha256, 'semantic.poolCreate.sourceOutpointProvenanceSha256');
  validatePool(value.pool);
  for (const [kind, entries] of [['deposit', value.deposits], ['withdraw', value.withdrawals]]) {
    if (!Array.isArray(entries) || entries.length !== 5) fail('BUNDLE_SEMANTIC_INVALID', `semantic evidence requires exactly five ${kind} actions`);
    const ordinals = new Set(); const ids = new Set(); const txids = new Set();
    entries.forEach((entry) => { validateAction(entry, kind, entry?.ordinal, cores); ordinals.add(entry.ordinal); ids.add(entry.operationId); txids.add(entry.transactionId); });
    if (ordinals.size !== 5 || ids.size !== 5 || txids.size !== 5 || [...ordinals].some((ordinal) => ![1, 2, 3, 4, 5].includes(ordinal))) fail('BUNDLE_SEMANTIC_INVALID', `semantic ${kind} identities are not five distinct canonical actions`);
  }
  const all = [...value.deposits, ...value.withdrawals];
  if (new Set(all.map((entry) => entry.operationId)).size !== 10 || new Set(all.map((entry) => entry.transactionId)).size !== 10) fail('BUNDLE_SEMANTIC_INVALID', 'semantic action identities are duplicated');
  return clone(value);
}

function percentile(values, probability) { const sorted = [...values].sort((left, right) => left - right); return sorted[Math.ceil(sorted.length * probability) - 1]; }
function validateMetrics(value, entries, label) {
  exact(value, ['actionTotalMs', 'commandTotalMs', 'sampleCount'], `performance.metrics.${label}`);
  if (value.sampleCount !== entries.length) fail('BUNDLE_PERFORMANCE_INVALID', `${label} metric sample count differs`);
  for (const [key, field] of [['commandTotalMs', 'commandTotalMs'], ['actionTotalMs', 'actionTotalMs']]) {
    exact(value[key], ['p50', 'p95'], `performance.metrics.${label}.${key}`);
    const expected = { p50: percentile(entries.map((entry) => entry[field]), 0.5), p95: percentile(entries.map((entry) => entry[field]), 0.95) };
    if (value[key].p50 !== expected.p50 || value[key].p95 !== expected.p95 || expected.p50 > 5000 || expected.p95 > 10000) fail('BUNDLE_PERFORMANCE_INVALID', `${label} ${key} percentile is inconsistent or exceeds the warm limit`);
  }
}

function validatePerformance(value, cores, installReceiptSha256, disallowedTxids) {
  exact(value, ['claims', 'elapsedMs', 'metrics', 'pools', 'samples', 'schema', 'scope'], 'performance evidence');
  if (value.schema !== V2_BETA_LIVE_PERFORMANCE_SCHEMA || value.scope !== 'warm-performance-only-explicitly-unqualified') fail('BUNDLE_PERFORMANCE_INVALID', 'performance evidence has an unsupported schema or scope');
  claims(value.claims, 'performance.claims'); duration(value.elapsedMs, 'performance.elapsedMs');
  if (!Array.isArray(value.pools) || value.pools.length < 4) fail('BUNDLE_PERFORMANCE_INVALID', 'performance evidence requires four installed pools');
  value.pools.forEach((pool, index) => { exact(pool, ['receiptSha256'], `performance.pools[${index}]`); hash(pool.receiptSha256, `performance.pools[${index}].receiptSha256`); if (pool.receiptSha256 !== installReceiptSha256) fail('BUNDLE_PERFORMANCE_INVALID', 'performance pool receipt differs from the semantic pinned install'); });
  exact(value.samples, ['deposits', 'withdrawals'], 'performance.samples'); exact(value.metrics, ['deposits', 'withdrawals'], 'performance.metrics');
  const identities = new Set();
  for (const [kind, entries, metric] of [['deposit', value.samples.deposits, value.metrics.deposits], ['withdraw', value.samples.withdrawals, value.metrics.withdrawals]]) {
    if (!Array.isArray(entries) || entries.length < 20) fail('BUNDLE_PERFORMANCE_INVALID', `performance evidence requires at least twenty ${kind} actions`);
    const txids = new Set(); const operationIds = new Set();
    entries.forEach((entry) => { validateAction(entry, kind, entry?.ordinal, cores, { performance: true }); txids.add(entry.transactionId); operationIds.add(entry.operationId); identities.add(entry.transactionId); });
    if (txids.size !== entries.length || operationIds.size !== entries.length) fail('BUNDLE_PERFORMANCE_INVALID', `performance ${kind} identities are duplicated`);
    validateMetrics(metric, entries, kind === 'deposit' ? 'deposits' : 'withdrawals');
  }
  if (identities.size !== value.samples.deposits.length + value.samples.withdrawals.length || [...identities].some((txid) => disallowedTxids.has(txid))) fail('BUNDLE_PERFORMANCE_INVALID', 'performance transactions duplicate another submitted action');
  return clone(value);
}

function poolCreateRuntimeWork(value) {
  runtimeWork(value, true);
  const expected = ['instance-specialization', 'linked-runtime-cache-load'];
  if (value.events.length !== expected.length
    || value.events.some((event, index) => event.type !== expected[index])) {
    fail('BUNDLE_POOL_CREATE_RUNTIME_WORK_INVALID', 'fresh pool create must specialize exactly once before its linked-runtime cache load');
  }
}

function validatePoolCreateMetrics(value, samples) {
  exact(value, ['commandDurationMs', 'sampleCount'], 'pool-create.metrics');
  if (value.sampleCount !== samples.length) fail('BUNDLE_POOL_CREATE_PERFORMANCE_INVALID', 'pool-create metric sample count differs');
  for (const field of ['commandDurationMs']) {
    exact(value[field], ['max', 'p50', 'p95'], `pool-create.metrics.${field}`);
    const values = samples.map((sample) => sample[field]);
    const expected = { p50: percentile(values, 0.5), p95: percentile(values, 0.95), max: Math.max(...values) };
    if (value[field].p50 !== expected.p50 || value[field].p95 !== expected.p95 || value[field].max !== expected.max) {
      fail('BUNDLE_POOL_CREATE_PERFORMANCE_INVALID', `pool-create ${field} distribution differs from canonical samples`);
    }
  }
  for (const field of ['commandDurationMs']) {
    if (value[field].p50 > 5000 || value[field].p95 > 10000) {
      fail('BUNDLE_POOL_CREATE_PERFORMANCE_INVALID', `pool-create ${field} exceeds p50 <= 5000ms or p95 <= 10000ms`);
    }
  }
}

function validatePoolCreatePerformance(value, disallowedIds, installReceiptSha256) {
  exact(value, ['claims', 'elapsedMs', 'metrics', 'pools', 'receiptSha256', 'schema', 'scope'], 'pool-create performance evidence');
  if (value.schema !== V2_BETA_LIVE_POOL_CREATE_PERFORMANCE_SCHEMA
    || value.scope !== 'fresh-pool-create-performance-explicitly-unqualified') {
    fail('BUNDLE_POOL_CREATE_PERFORMANCE_INVALID', 'pool-create performance schema or scope is unsupported');
  }
  hash(value.receiptSha256, 'pool-create performance.receiptSha256');
  if (value.receiptSha256 !== installReceiptSha256) fail('BUNDLE_POOL_CREATE_PERFORMANCE_INVALID', 'pool-create performance receipt differs from the semantic pinned install');
  claims(value.claims, 'pool-create performance.claims'); duration(value.elapsedMs, 'pool-create performance.elapsedMs');
  if (!Array.isArray(value.pools) || value.pools.length < 20) {
    fail('BUNDLE_POOL_CREATE_PERFORMANCE_INVALID', 'at least twenty fresh pool-create samples are required');
  }
  const ordinals = new Set(); const ids = new Set(disallowedIds);
  for (const [index, sample] of value.pools.entries()) {
    exact(sample, ['actionFundingSetSha256', 'claims', 'commandDurationMs', 'genesisTransactionId', 'instanceId', 'ordinal', 'runtimeWork', 'sourceOutpointProvenanceSha256', 'sourceTransactionId'], `pool-create.pools[${index}]`);
    integer(sample.ordinal, `pool-create.pools[${index}].ordinal`, 1);
    if (ordinals.has(sample.ordinal)) fail('BUNDLE_POOL_CREATE_PERFORMANCE_INVALID', 'pool-create sample ordinal is duplicated');
    ordinals.add(sample.ordinal);
    claims(sample.claims, `pool-create.pools[${index}].claims`, { broadcasted: true });
    duration(sample.commandDurationMs, `pool-create.pools[${index}].commandDurationMs`);
    poolCreateRuntimeWork(sample.runtimeWork);
    const sampleIds = [sample.sourceOutpointProvenanceSha256, sample.sourceTransactionId, sample.genesisTransactionId, sample.instanceId, sample.actionFundingSetSha256];
    sampleIds.forEach((identifier, identifierIndex) => hash(identifier, `pool-create.pools[${index}].id[${identifierIndex}]`));
    if (new Set(sampleIds).size !== sampleIds.length || sampleIds.some((identifier) => ids.has(identifier))) {
      fail('BUNDLE_POOL_CREATE_PERFORMANCE_INVALID', 'pool-create source provenance, source, genesis, instance, or action-funding identity is reused');
    }
    sampleIds.forEach((identifier) => ids.add(identifier));
  }
  if (ordinals.size !== value.pools.length || [...ordinals].some((ordinal) => ordinal > value.pools.length)) {
    fail('BUNDLE_POOL_CREATE_PERFORMANCE_INVALID', 'pool-create ordinals must be contiguous from one');
  }
  validatePoolCreateMetrics(value.metrics, value.pools);
  return clone(value);
}

function facts(value) {
  exact(value, ['host', 'repository'], 'verification facts');
  exact(value.repository, ['cleanWorktree', 'head', 'packageLockSha256', 'releasePinSha256', 'releasePinTracked', 'tree'], 'verification facts.repository');
  if (value.repository.cleanWorktree !== true || value.repository.releasePinTracked !== true) fail('BUNDLE_DIRTY_TREE', 'a clean tracked worktree attestation is required');
  git(value.repository.head, 'verification facts.repository.head'); git(value.repository.tree, 'verification facts.repository.tree'); hash(value.repository.packageLockSha256, 'verification facts.repository.packageLockSha256'); hash(value.repository.releasePinSha256, 'verification facts.repository.releasePinSha256');
  exact(value.host, ['architecture', 'availableCores', 'nodeVersion', 'platform'], 'verification facts.host');
  if (value.host.nodeVersion !== 'v22.23.1' || typeof value.host.platform !== 'string' || value.host.platform.length === 0 || typeof value.host.architecture !== 'string' || value.host.architecture.length === 0) fail('BUNDLE_HOST_INVALID', 'host Node/platform/architecture attestation is invalid');
  integer(value.host.availableCores, 'verification facts.host.availableCores', 20);
  return clone(value);
}

function canonicalFile(bytes, label) {
  if (!(bytes instanceof Uint8Array) && !Buffer.isBuffer(bytes)) fail('BUNDLE_FILE_INVALID', `${label} must be bytes`);
  const buffer = Buffer.from(bytes); let value;
  try { value = parseStrictJson(buffer, label); } catch (error) { fail('BUNDLE_FILE_INVALID', `${label} is not strict JSON`, { cause: error }); }
  // parseStrictJson deliberately uses null-prototype records. Normalize only
  // after strict parsing so duplicate-key rejection remains at the file edge.
  value = clone(value);
  const expected = Buffer.from(`${canonicalizeJcs(value)}\n`, 'utf8');
  if (!buffer.equals(expected)) fail('BUNDLE_FILE_NONCANONICAL', `${label} is not exact canonical JCS with one terminal newline`);
  rejectSecretsAndPaths(value, label);
  return Object.freeze({ bytes: buffer, sha256: sha256(buffer), value });
}

function manifestCore({ semantic, performance, poolCreatePerformance, facts: factValue }) {
  return Object.freeze({
    schema: V2_BETA_LIVE_EVIDENCE_BUNDLE_MANIFEST_SCHEMA,
    claims: Object.freeze({ confirmed: false, mined: false, productionQualified: false }),
    semantic: Object.freeze({ schema: semantic.schema, sha256: semantic.sha256 }),
    performance: Object.freeze({ schema: performance.schema, sha256: performance.sha256 }),
    poolCreatePerformance: Object.freeze({ schema: poolCreatePerformance.schema, sha256: poolCreatePerformance.sha256 }),
    repository: Object.freeze({ ...factValue.repository }),
    host: Object.freeze({ ...factValue.host }),
  });
}

/** Verify a canonical semantic/warm-action/pool-create evidence triple against Git/host facts. */
export function createV2BetaLiveEvidenceBundleManifest({ semanticBytes, performanceBytes, poolCreatePerformanceBytes }, verificationFacts) {
  const semanticFile = canonicalFile(semanticBytes, 'semantic evidence');
  const performanceFile = canonicalFile(performanceBytes, 'performance evidence');
  const poolCreatePerformanceFile = canonicalFile(poolCreatePerformanceBytes, 'pool-create performance evidence');
  const factValue = facts(verificationFacts);
  const semantic = validateSemantic(semanticFile.value, factValue.host.availableCores);
  const forbiddenTxids = new Set([...semantic.deposits, ...semantic.withdrawals].map((entry) => entry.transactionId));
  const performance = validatePerformance(performanceFile.value, factValue.host.availableCores, semantic.install.receiptSha256, forbiddenTxids);
  const disallowedPoolIds = new Set([
    semantic.poolCreate.sourceOutpointProvenanceSha256, semantic.pool.sourceTransactionId,
    semantic.pool.genesisTransactionId, semantic.pool.instanceId,
    semantic.pool.actionFundingSetSha256,
    ...performance.samples.deposits.map((entry) => entry.transactionId),
    ...performance.samples.withdrawals.map((entry) => entry.transactionId),
  ]);
  const poolCreatePerformance = validatePoolCreatePerformance(poolCreatePerformanceFile.value, disallowedPoolIds, semantic.install.receiptSha256);
  const core = manifestCore({ semantic: { schema: semantic.schema, sha256: semanticFile.sha256 }, performance: { schema: performance.schema, sha256: performanceFile.sha256 }, poolCreatePerformance: { schema: poolCreatePerformance.schema, sha256: poolCreatePerformanceFile.sha256 }, facts: factValue });
  return Object.freeze({ ...core, manifestSha256: sha256(Buffer.from(canonicalizeJcs(core), 'utf8')) });
}

/** Recompute every field and the canonical manifest hash; reject stale facts or tampering. */
export function verifyV2BetaLiveEvidenceBundleManifest(manifest, files, verificationFacts) {
  exact(manifest, ['claims', 'host', 'manifestSha256', 'performance', 'poolCreatePerformance', 'repository', 'schema', 'semantic'], 'evidence manifest');
  if (manifest.schema !== V2_BETA_LIVE_EVIDENCE_BUNDLE_MANIFEST_SCHEMA) fail('BUNDLE_MANIFEST_INVALID', 'manifest schema is unsupported');
  claims(manifest.claims, 'manifest.claims'); hash(manifest.manifestSha256, 'manifest.manifestSha256');
  const actual = createV2BetaLiveEvidenceBundleManifest(files, verificationFacts);
  if (canonicalizeJcs(manifest) !== canonicalizeJcs(actual)) fail('BUNDLE_MANIFEST_MISMATCH', 'manifest differs from revalidated evidence, Git, or host facts');
  return actual;
}

/** Local fact collector, kept separate from the pure verifier for test injection. */
export function collectV2BetaLiveEvidenceBundleFacts({ repositoryRoot = path.resolve(import.meta.dirname, '../..') } = {}) {
  const runGit = (args) => execFileSync('git', ['-C', repositoryRoot, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  const pin = '03-create-your-own-pool/pins/v2-beta-product-offline-r3.pin.json';
  const status = runGit(['status', '--porcelain=v1', '--untracked-files=all']);
  const tracked = (() => { try { runGit(['ls-files', '--error-unmatch', pin]); return true; } catch { return false; } })();
  return Object.freeze({
    repository: Object.freeze({
      cleanWorktree: status === '', head: runGit(['rev-parse', 'HEAD']), tree: runGit(['rev-parse', 'HEAD^{tree}']),
      packageLockSha256: sha256(readFileSync(path.join(repositoryRoot, 'package-lock.json'))),
      releasePinSha256: sha256(readFileSync(path.join(repositoryRoot, pin))), releasePinTracked: tracked,
    }),
    host: Object.freeze({ nodeVersion: process.version, platform: process.platform, architecture: process.arch, availableCores: availableParallelism() }),
  });
}

function cliUsage() {
  throw new Error('usage: v2-beta-live-evidence-bundle-verify.mjs --create --semantic <canonical-semantic.json> --performance <canonical-performance.json> --pool-create-performance <canonical-pool-create-performance.json> | --verify --semantic <canonical-semantic.json> --performance <canonical-performance.json> --pool-create-performance <canonical-pool-create-performance.json> --manifest <canonical-manifest.json>');
}

function cliArguments(tokens) {
  const mode = tokens[0];
  if (!['--create', '--verify'].includes(mode)) cliUsage();
  const expected = mode === '--create' ? ['performance', 'pool-create-performance', 'semantic'] : ['manifest', 'performance', 'pool-create-performance', 'semantic'];
  const values = Object.create(null);
  for (let index = 1; index < tokens.length; index += 2) {
    const name = tokens[index]; const value = tokens[index + 1];
    if (!['--semantic', '--performance', '--pool-create-performance', '--manifest'].includes(name) || value === undefined || Object.hasOwn(values, name)) cliUsage();
    values[name] = value;
  }
  if (Object.keys(values).length !== expected.length || expected.some((name) => values[`--${name}`] === undefined)) cliUsage();
  return Object.freeze({ mode, semantic: values['--semantic'], performance: values['--performance'], poolCreatePerformance: values['--pool-create-performance'], ...(mode === '--verify' ? { manifest: values['--manifest'] } : {}) });
}

function canonicalManifestBytes(bytes) {
  const parsed = canonicalFile(bytes, 'evidence manifest');
  return parsed.value;
}

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = cliArguments(process.argv.slice(2));
  const files = Object.freeze({ semanticBytes: readFileSync(args.semantic), performanceBytes: readFileSync(args.performance), poolCreatePerformanceBytes: readFileSync(args.poolCreatePerformance) });
  const localFacts = collectV2BetaLiveEvidenceBundleFacts();
  const result = args.mode === '--create'
    ? createV2BetaLiveEvidenceBundleManifest(files, localFacts)
    : verifyV2BetaLiveEvidenceBundleManifest(canonicalManifestBytes(readFileSync(args.manifest)), files, localFacts);
  process.stdout.write(`${canonicalizeJcs(result)}\n`);
}
