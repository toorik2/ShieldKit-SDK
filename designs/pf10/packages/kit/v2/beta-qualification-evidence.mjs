/**
 * Canonical, secret-free evidence for the explicitly unqualified V2 beta
 * Chipnet product lane. This is an evidence boundary only: callers must obtain
 * every observation from the real local runtime and BCHN capability.
 */
import { createHash } from 'node:crypto';

import { transactionIdFromHex } from '../transaction-coordinator.mjs';

export const V2_BETA_PRODUCT_QUALIFICATION_EVIDENCE_SCHEMA =
  'shieldkit-v2-beta-product-qualification-evidence-v1';

const HASH = /^[0-9a-f]{64}$/u;
const GIT_ID = /^[0-9a-f]{40}$/u;
const HEX = /^(?:[0-9a-f]{2})+$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
const STAGE_NAMES = Object.freeze([
  'stateRead', 'treePath', 'witness', 'proofGenerate', 'proofVerify',
  'assemble', 'sign', 'vm', 'bchnAdmission', 'rawReadback',
  'stateReadback', 'sqliteCommit', 'total',
]);
const VM_METRICS = Object.freeze([
  'arithmeticCost', 'definedFunctions', 'densityControlLength',
  'evaluatedInstructionCount', 'hashDigestIterations',
  'maximumHashDigestIterations', 'maximumOperationCost',
  'maximumSignatureCheckCount', 'operationCost', 'signatureCheckCount',
  'stackPushedBytes',
]);
const RPC_METHODS = Object.freeze([
  'getblockcount', 'getblockhash', 'getrawtransaction', 'gettxout',
  'sendrawtransaction', 'testmempoolaccept',
]);
const FORBIDDEN_FIELD_NAME = /(?:secret|private(?:key)?|mnemonic|seed|spend|view|witness|circuitinput|membership|funding.*key|change.*key|note(?:record|material))/iu;

export class V2BetaProductQualificationEvidenceError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'V2BetaProductQualificationEvidenceError';
    this.code = code;
  }
}

const fail = (code, message) => {
  throw new V2BetaProductQualificationEvidenceError(code, message);
};
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

export function canonicalizeV2BetaProductQualificationEvidence(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalizeV2BetaProductQualificationEvidence).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalizeV2BetaProductQualificationEvidence(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function plain(value, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('EVIDENCE_INVALID', `${label} must be a plain object`);
  }
  return value;
}

function exact(value, keys, label) {
  plain(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail('EVIDENCE_UNKNOWN_FIELD', `${label} has missing or unknown fields`);
  }
  return value;
}

function string(value, label) {
  if (typeof value !== 'string' || value.length === 0) fail('EVIDENCE_INVALID', `${label} must be a nonempty string`);
  return value;
}
function hash(value, label) { if (typeof value !== 'string' || !HASH.test(value)) fail('EVIDENCE_INVALID', `${label} must be lowercase SHA-256`); return value; }
function gitId(value, label) { if (typeof value !== 'string' || !GIT_ID.test(value)) fail('EVIDENCE_INVALID', `${label} must be a lowercase 40-hex Git ID`); return value; }
function hex(value, label, { bytes = undefined } = {}) {
  if (typeof value !== 'string' || !HEX.test(value) || (bytes !== undefined && value.length !== bytes * 2)) fail('EVIDENCE_INVALID', `${label} must be lowercase hexadecimal${bytes === undefined ? '' : ` of ${bytes} bytes`}`);
  return value;
}
function decimal(value, label) { if (typeof value !== 'string' || !DECIMAL.test(value)) fail('EVIDENCE_INVALID', `${label} must be a canonical unsigned decimal string`); return value; }
function integer(value, label, { minimum = 0, maximum = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail('EVIDENCE_INVALID', `${label} is outside its supported integer range`);
  return value;
}
function finite(value, label, { minimum = 0, maximum = Number.MAX_VALUE } = {}) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < minimum || value > maximum) fail('EVIDENCE_INVALID', `${label} must be finite and in range`);
  return value;
}

function rejectSecretFields(value, path = '$') {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => rejectSecretFields(entry, `${path}[${index}]`));
    return;
  }
  if (value === null || typeof value !== 'object') return;
  for (const [key, entry] of Object.entries(value)) {
    // `stages.witness` is a duration label, not witness material. All other
    // witness-named fields remain forbidden from the public evidence boundary.
    const allowedStageLabel = path === '$.stages' && key === 'witness';
    if (!allowedStageLabel && FORBIDDEN_FIELD_NAME.test(key)) fail('EVIDENCE_SECRET_FIELD', `${path}.${key} is forbidden in secret-free evidence`);
    rejectSecretFields(entry, `${path}.${key}`);
  }
}

function validateRun(value) {
  exact(value, ['cleanWorktree', 'gitCommit', 'gitTree', 'host', 'lockfileSha256', 'toolPins'], 'run');
  if (value.cleanWorktree !== true) fail('EVIDENCE_CLEAN_WORKTREE_REQUIRED', 'run.cleanWorktree must attest an empty worktree');
  gitId(value.gitCommit, 'run.gitCommit'); gitId(value.gitTree, 'run.gitTree'); hash(value.lockfileSha256, 'run.lockfileSha256');
  exact(value.host, ['architecture', 'machineIdSha256', 'platform'], 'run.host');
  string(value.host.architecture, 'run.host.architecture'); string(value.host.platform, 'run.host.platform'); hash(value.host.machineIdSha256, 'run.host.machineIdSha256');
  exact(value.toolPins, ['bchn', 'libauth', 'node'], 'run.toolPins');
  for (const [key, pin] of Object.entries(value.toolPins)) string(pin, `run.toolPins.${key}`);
}

function validateOperation(value) {
  exact(value, ['cache', 'cacheReceiptSha256', 'command', 'kind', 'ordinal'], 'operation');
  if (!['cold', 'warm'].includes(value.cache)) fail('EVIDENCE_INVALID', 'operation.cache must be cold or warm');
  hash(value.cacheReceiptSha256, 'operation.cacheReceiptSha256');
  if (!['pool.create', 'deposit', 'withdraw'].includes(value.command)) fail('EVIDENCE_INVALID', 'operation.command is unsupported');
  if (!['genesis', 'deposit', 'withdrawal'].includes(value.kind)) fail('EVIDENCE_INVALID', 'operation.kind is unsupported');
  if ((value.command === 'pool.create') !== (value.kind === 'genesis')
    || (value.command === 'withdraw') !== (value.kind === 'withdrawal')) fail('EVIDENCE_INVALID', 'operation command/kind mismatch');
  integer(value.ordinal, 'operation.ordinal', { minimum: 0, maximum: 0xffff_ffff });
}

function validateStages(value) {
  exact(value, STAGE_NAMES, 'stages');
  let priorFinished = 0;
  for (const name of STAGE_NAMES.filter((name) => name !== 'total')) {
    const stage = value[name];
    exact(stage, ['durationMs', 'finishedAtMs', 'startedAtMs'], `stages.${name}`);
    finite(stage.startedAtMs, `stages.${name}.startedAtMs`);
    finite(stage.finishedAtMs, `stages.${name}.finishedAtMs`);
    finite(stage.durationMs, `stages.${name}.durationMs`);
    if (stage.startedAtMs < priorFinished || stage.finishedAtMs < stage.startedAtMs
      || Math.abs((stage.finishedAtMs - stage.startedAtMs) - stage.durationMs) > 0.001) {
      fail('EVIDENCE_STAGE_TIMING_INVALID', `stages.${name} is not monotonic or self-consistent`);
    }
    priorFinished = stage.finishedAtMs;
  }
  const total = value.total;
  exact(total, ['durationMs', 'finishedAtMs', 'startedAtMs'], 'stages.total');
  finite(total.startedAtMs, 'stages.total.startedAtMs'); finite(total.finishedAtMs, 'stages.total.finishedAtMs'); finite(total.durationMs, 'stages.total.durationMs');
  if (total.startedAtMs !== 0 || total.finishedAtMs !== priorFinished
    || Math.abs((total.finishedAtMs - total.startedAtMs) - total.durationMs) > 0.001) fail('EVIDENCE_STAGE_TIMING_INVALID', 'stages.total must span the full ordered operation');
}

function validateProof(value) {
  exact(value, ['artifactHashes', 'cpuUtilizationPercent', 'peakRssBytes', 'system', 'verified', 'workerThreads', 'workspacePeakBytes'], 'proof');
  if (value.system !== 'groth16-bn254' || value.verified !== true) fail('EVIDENCE_PROOF_INVALID', 'proof must be a verified Groth16 BN254 result');
  exact(value.artifactHashes, ['provingKey', 'r1cs', 'verificationKey', 'wasm'], 'proof.artifactHashes');
  Object.entries(value.artifactHashes).forEach(([key, item]) => hash(item, `proof.artifactHashes.${key}`));
  integer(value.workerThreads, 'proof.workerThreads', { minimum: 1, maximum: 1_000_000 });
  finite(value.cpuUtilizationPercent, 'proof.cpuUtilizationPercent', { maximum: 100 });
  integer(value.peakRssBytes, 'proof.peakRssBytes'); integer(value.workspacePeakBytes, 'proof.workspacePeakBytes');
}

function validateTransaction(value) {
  exact(value, ['bytes', 'feeRateSatsPerByte', 'feeSats', 'rawTransactionHex', 'rawTransactionSha256', 'txid', 'unlockBytesByInput'], 'transaction');
  const raw = hex(value.rawTransactionHex, 'transaction.rawTransactionHex');
  if (value.bytes !== raw.length / 2 || hash(sha256(Buffer.from(raw, 'hex')), 'transaction.rawTransactionSha256') !== value.rawTransactionSha256) fail('EVIDENCE_TRANSACTION_MISMATCH', 'transaction bytes or SHA-256 differ from raw bytes');
  const txid = transactionIdFromHex(raw);
  if (value.txid !== txid) fail('EVIDENCE_TRANSACTION_MISMATCH', 'transaction txid differs from raw bytes');
  decimal(value.feeSats, 'transaction.feeSats'); decimal(value.feeRateSatsPerByte, 'transaction.feeRateSatsPerByte');
  if (BigInt(value.feeSats) !== BigInt(value.bytes) * BigInt(value.feeRateSatsPerByte)) fail('EVIDENCE_TRANSACTION_MISMATCH', 'transaction fee must equal exact bytes times fee rate');
  if (!Array.isArray(value.unlockBytesByInput) || value.unlockBytesByInput.length === 0) fail('EVIDENCE_INVALID', 'transaction.unlockBytesByInput must be nonempty');
  value.unlockBytesByInput.forEach((entry, index) => {
    exact(entry, ['bytes', 'index'], `transaction.unlockBytesByInput[${index}]`);
    if (entry.index !== index) fail('EVIDENCE_INVALID', 'transaction unlocking-bytecode indexes must be contiguous');
    integer(entry.bytes, `transaction.unlockBytesByInput[${index}].bytes`, { maximum: 10_000 });
  });
}

function validateVm(value, transaction) {
  exact(value, ['allInputsAccepted', 'inputs', 'profile'], 'vm');
  if (value.profile !== 'BCH_2026_STANDARD' || value.allInputsAccepted !== true || !Array.isArray(value.inputs)
    || value.inputs.length !== transaction.unlockBytesByInput.length) fail('EVIDENCE_VM_INVALID', 'VM evidence must cover every transaction input under BCH_2026_STANDARD');
  value.inputs.forEach((entry, index) => {
    exact(entry, ['accepted', 'index', 'metrics', 'role', 'sourceOutputSha256', 'unlockingBytecodeBytes', 'unlockingBytecodeSha256'], `vm.inputs[${index}]`);
    if (entry.index !== index || entry.accepted !== true || entry.unlockingBytecodeBytes !== transaction.unlockBytesByInput[index].bytes) fail('EVIDENCE_VM_INVALID', `VM input ${index} verdict or unlock size is inconsistent`);
    string(entry.role, `vm.inputs[${index}].role`); hash(entry.sourceOutputSha256, `vm.inputs[${index}].sourceOutputSha256`); hash(entry.unlockingBytecodeSha256, `vm.inputs[${index}].unlockingBytecodeSha256`);
    exact(entry.metrics, VM_METRICS, `vm.inputs[${index}].metrics`);
    VM_METRICS.forEach((name) => decimal(entry.metrics[name], `vm.inputs[${index}].metrics.${name}`));
  });
}

function validateBchn(value, transaction, identity) {
  exact(value, ['admission', 'backend', 'genesis', 'initialHeight', 'methodCounts', 'rawReadback', 'stateReadback'], 'bchn');
  if (value.backend !== 'layer1-bchn-chipnet') fail('EVIDENCE_BCHN_INVALID', 'BCHN backend must be the fixed layer1 Chipnet capability');
  hash(value.genesis, 'bchn.genesis'); integer(value.initialHeight, 'bchn.initialHeight');
  exact(value.methodCounts, RPC_METHODS, 'bchn.methodCounts');
  RPC_METHODS.forEach((name) => integer(value.methodCounts[name], `bchn.methodCounts.${name}`));
  exact(value.admission, ['sendTransactionId', 'testMempoolAccept'], 'bchn.admission');
  if (value.admission.testMempoolAccept !== true || value.admission.sendTransactionId !== transaction.txid
    || value.methodCounts.testmempoolaccept !== 1 || value.methodCounts.sendrawtransaction !== 1) fail('EVIDENCE_BCHN_ADMISSION_INVALID', 'BCHN admission must record exactly one accepted preflight and send');
  if (value.methodCounts.getrawtransaction < 1 || value.methodCounts.gettxout < 1) fail('EVIDENCE_BCHN_READBACK_INVALID', 'BCHN evidence must include raw-transaction and state-NFT readback calls');
  exact(value.rawReadback, ['exact', 'rawTransactionHex', 'rawTransactionSha256', 'transactionId'], 'bchn.rawReadback');
  if (value.rawReadback.exact !== true || value.rawReadback.transactionId !== transaction.txid
    || value.rawReadback.rawTransactionHex !== transaction.rawTransactionHex
    || value.rawReadback.rawTransactionSha256 !== transaction.rawTransactionSha256) fail('EVIDENCE_BCHN_READBACK_INVALID', 'BCHN raw readback differs from the exact signed transaction');
  exact(value.stateReadback, ['capability', 'category', 'commitment', 'commitmentSha256', 'outpoint', 'tokenAmount', 'valueSatoshis'], 'bchn.stateReadback');
  exact(value.stateReadback.outpoint, ['txid', 'vout'], 'bchn.stateReadback.outpoint');
  const expectedCategory = Buffer.from(identity.instanceId, 'hex').reverse().toString('hex');
  if (value.stateReadback.outpoint.txid !== transaction.txid || value.stateReadback.outpoint.vout !== 0
    || value.stateReadback.category !== expectedCategory || value.stateReadback.capability !== 'mutable'
    || value.stateReadback.tokenAmount !== '0') fail('EVIDENCE_BCHN_READBACK_INVALID', 'BCHN state NFT outpoint or token identity is inconsistent');
  const commitment = hex(value.stateReadback.commitment, 'bchn.stateReadback.commitment', { bytes: 128 });
  if (sha256(Buffer.from(commitment, 'hex')) !== value.stateReadback.commitmentSha256) fail('EVIDENCE_BCHN_READBACK_INVALID', 'BCHN state commitment hash differs from returned commitment');
  decimal(value.stateReadback.valueSatoshis, 'bchn.stateReadback.valueSatoshis');
}

function validateStore(value) {
  exact(value, ['databaseBytes', 'noteCount', 'nullifierCount', 'walBytes'], 'store');
  integer(value.databaseBytes, 'store.databaseBytes'); integer(value.walBytes, 'store.walBytes');
  integer(value.noteCount, 'store.noteCount'); integer(value.nullifierCount, 'store.nullifierCount');
}

function validateCore(value) {
  rejectSecretFields(value);
  exact(value, ['bchn', 'claims', 'identity', 'operation', 'proof', 'run', 'schema', 'stages', 'status', 'store', 'transaction', 'vm'], 'beta product qualification evidence');
  if (value.schema !== V2_BETA_PRODUCT_QUALIFICATION_EVIDENCE_SCHEMA
    || value.status !== 'accepted-zero-conf-beta-unqualified') fail('EVIDENCE_STATUS_INVALID', 'evidence must remain explicitly accepted-zero-conf beta-unqualified');
  exact(value.claims, ['broadcasted', 'confirmed', 'mined', 'productionQualified'], 'claims');
  if (value.claims.broadcasted !== true || value.claims.confirmed !== false || value.claims.mined !== false || value.claims.productionQualified !== false) fail('EVIDENCE_CLAIMS_INVALID', 'beta evidence claims must remain zero-conf and unqualified');
  validateRun(value.run); validateOperation(value.operation);
  exact(value.identity, ['instanceId', 'maximumLiveNotes', 'profileId'], 'identity');
  hash(value.identity.profileId, 'identity.profileId'); hash(value.identity.instanceId, 'identity.instanceId');
  if (value.identity.maximumLiveNotes !== '100000') fail('EVIDENCE_CAPACITY_INVALID', 'identity.maximumLiveNotes must be the exact 100000 beta capacity');
  validateStages(value.stages); validateProof(value.proof); validateTransaction(value.transaction); validateVm(value.vm, value.transaction); validateBchn(value.bchn, value.transaction, value.identity); validateStore(value.store);
  return value;
}

/** Create canonical evidence from a real observation; input must not include an evidence hash. */
export function createV2BetaProductQualificationEvidence(value) {
  validateCore(value);
  const canonical = canonicalizeV2BetaProductQualificationEvidence(value);
  return Object.freeze({ ...value, evidenceSha256: sha256(Buffer.from(canonical, 'utf8')) });
}

/** Independently validate the complete canonical evidence record and its hash. */
export function verifyV2BetaProductQualificationEvidence(value) {
  exact(value, ['bchn', 'claims', 'evidenceSha256', 'identity', 'operation', 'proof', 'run', 'schema', 'stages', 'status', 'store', 'transaction', 'vm'], 'beta product qualification evidence');
  const { evidenceSha256, ...core } = value;
  validateCore(core);
  if (hash(evidenceSha256, 'evidenceSha256') !== sha256(Buffer.from(canonicalizeV2BetaProductQualificationEvidence(core), 'utf8'))) fail('EVIDENCE_HASH_MISMATCH', 'evidenceSha256 does not bind the canonical evidence core');
  return Object.freeze({ ...core, evidenceSha256 });
}
