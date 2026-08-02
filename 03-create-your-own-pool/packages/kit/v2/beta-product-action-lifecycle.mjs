import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { availableParallelism } from 'node:os';
import { performance } from 'node:perf_hooks';

import {
  assembleV2DirectSettlement,
  prepareV2DirectSettlement,
  signV2DirectSettlement,
} from '../../action/v2/settlement.mjs';
import {
  buildDirectV2CircuitInput,
} from '../../action/v2/circuit-witness.mjs';
import {
  decodeStateNftCommitment,
  encodeStateNftCommitment,
} from '../../action/v2/state.mjs';
import {
  actionPacketPublicLimbs,
  decodeActionPacket,
} from '../../action/v2/packet.mjs';
import {
  directV2VerifierTopologyById,
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
} from '../../action/v2/topology.mjs';
import {
  canonicalizeJcs,
  deriveProfileId,
  validateProfileCore,
} from '../../profile/v2/profile-core.mjs';
import {
  proveV2DirectNativeGroth16Default,
} from '../../prove/v2/native-groth16-proof-worker.mjs';
import {
  consumeV2NativeGroth16ProverInstallation,
} from '../../prove/v2/native-groth16-prover-installation.mjs';
import {
  V2_NATIVE_GROTH16_PROOF_RESULT_SCHEMA,
} from '../../prove/v2/native-groth16-proof-child.mjs';
import {
  assertV2BetaChipnetRuntimeResolution,
  assertV2BetaChipnetNativeProofArtifacts,
  deriveV2BetaChipnetNativeProofArtifacts,
  V2_BETA_CHIPNET_RUNTIME_RESOLUTION_SCHEMA,
} from '../../profile/v2/beta-chipnet-runtime.mjs';
import {
  V2_BETA_LOCAL_ELIGIBILITY,
  V2_BETA_LOCAL_FALSE_CLAIMS,
} from '../../profile/v2/beta-local-profile.mjs';
import {
  buildDirectV2Pf10BetaActionWitness,
  DIRECT_V2_PF10_STATE_UNLOCK_BYTES,
  DIRECT_V2_PF10_VERIFIER_UNLOCK_BYTES,
} from '../../unlock-builder/v2/pf10-action-witness.mjs';
import {
  assertLayer1BchnChipnetRpc,
  observeLayer1BchnChipnetRpc,
} from '../chipnet-rpc.mjs';
import {
  assertV2BetaProductWallet,
} from './beta-product-wallet.mjs';
import {
  rebroadcastV2BetaZeroConfAdmission,
  reconcileV2BetaZeroConfAdmission,
  submitV2BetaZeroConfAdmission,
  V2_BETA_ZERO_CONF_ADMISSION_SCHEMA,
} from './beta-zero-conf-admission.mjs';
import {
  assertV2DeliveryJournal,
} from './delivery-journal.mjs';
import {
  createV2LocalVmEvidence,
  inspectV2LocalVmEvidence,
  projectV2LocalVmEvidenceTelemetry,
  V2_VM_PROFILE,
} from './vm-evidence.mjs';
import {
  parseSerializedSourceOutput,
  parseV2RawTransaction,
} from './transaction-policy.mjs';

export const V2_BETA_PRODUCT_ACTION_ARTIFACT_SCHEMA =
  'shieldkit-v2-beta-product-action-artifact-v1';
export const V2_BETA_PRODUCT_ACTION_RESULT_SCHEMA =
  'shieldkit-v2-beta-product-action-result-v1';
export const V2_BETA_PRODUCT_ACTION_TELEMETRY_SCHEMA =
  'shieldkit-v2-beta-product-action-telemetry-v1';
export const V2_BETA_PRODUCT_RECOVERY_STATUS_SCHEMA =
  'shieldkit-v2-beta-product-recovery-status-v1';

const HASH = /^[0-9a-f]{64}$/u;
const HEX = /^(?:[0-9a-f]{2})+$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
const OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const require = createRequire(import.meta.url);
const LIBAUTH_VERSION = require('@bitauth/libauth/package.json').version;
const TOPOLOGY = directV2VerifierTopologyById(
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
);

export class V2BetaProductActionLifecycleError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined
      ? undefined
      : { cause: options.cause });
    this.name = 'V2BetaProductActionLifecycleError';
    this.code = code;
    this.recoverable = options?.recoverable === true;
  }
}

const fail = (code, message, options = undefined) => {
  throw new V2BetaProductActionLifecycleError(code, message, options);
};

function exact(value, keys, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('BETA_ACTION_INVALID', `${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    fail('BETA_ACTION_INVALID', `${label} has missing or unknown properties`);
  }
  return value;
}

function exactOptional(value, allowed, required, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('BETA_ACTION_INVALID', `${label} must be a plain object`);
  }
  const keys = Object.keys(value);
  if (
    keys.some((key) => !allowed.includes(key))
    || required.some((key) => !Object.hasOwn(value, key))
  ) {
    fail('BETA_ACTION_INVALID', `${label} has missing or unknown properties`);
  }
  return value;
}

function operationId(value) {
  if (typeof value !== 'string' || !OPERATION_ID.test(value)) {
    fail('BETA_ACTION_INVALID', 'operationId is invalid');
  }
  return value;
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail('BETA_ACTION_INVALID', `${label} must be lowercase 32-byte hex`);
  }
  return value;
}

function decimal(value, label) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) {
    fail('BETA_ACTION_INVALID', `${label} must be canonical unsigned decimal text`);
  }
  return value;
}

function safeInteger(value, minimum, label) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    fail('BETA_ACTION_INVALID', `${label} must be a safe integer >= ${minimum}`);
  }
  return value;
}

function finiteDuration(value, label) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    fail('BETA_ACTION_INVALID', `${label} must be a finite nonnegative duration`);
  }
  return value;
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalBytes(value) {
  return Buffer.from(canonicalizeJcs(value), 'utf8');
}

function copyJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function now() {
  return performance.now();
}

function elapsed(started) {
  return Math.round((performance.now() - started) * 1000) / 1000;
}

function claims() {
  return Object.freeze({
    confirmed: false,
    mined: false,
    productionQualified: false,
  });
}

const OBSERVED_RPC_METHODS = Object.freeze([
  'getblockhash', 'getrawtransaction', 'gettxout', 'scantxoutset',
  'sendrawtransaction', 'testmempoolaccept',
]);

function observedRpc(value, label) {
  exact(value, ['backend', 'genesis', 'methodCounts'], label);
  if (value.backend !== 'layer1-bchn-chipnet' || !HASH.test(value.genesis)) {
    fail('BETA_RPC_OBSERVATION_REJECTED', `${label} backend or genesis is invalid`);
  }
  exact(value.methodCounts, OBSERVED_RPC_METHODS, `${label} method counts`);
  for (const method of OBSERVED_RPC_METHODS) {
    if (!Number.isSafeInteger(value.methodCounts[method]) || value.methodCounts[method] < 0) {
      fail('BETA_RPC_OBSERVATION_REJECTED', `${label} count ${method} is invalid`);
    }
  }
  return Object.freeze({
    backend: value.backend,
    genesis: value.genesis,
    methodCounts: Object.freeze({ ...value.methodCounts }),
  });
}

function assertOneShotAdmissionObservation(before, after) {
  const prior = observedRpc(before, 'pre-admission BCHN observation');
  const current = observedRpc(after, 'post-admission BCHN observation');
  if (prior.backend !== current.backend || prior.genesis !== current.genesis) {
    fail('BETA_RPC_OBSERVATION_REJECTED', 'BCHN backend or genesis changed during admission');
  }
  const delta = Object.fromEntries(OBSERVED_RPC_METHODS.map((method) => [
    method, current.methodCounts[method] - prior.methodCounts[method],
  ]));
  if (delta.getblockhash !== 0 || delta.scantxoutset !== 0
    || delta.getrawtransaction !== 1 || delta.gettxout !== 1
    || delta.testmempoolaccept !== 1 || delta.sendrawtransaction !== 1) {
    fail('BETA_RPC_OBSERVATION_REJECTED', 'one action admission requires exactly one testmempoolaccept/send and one raw/gettxout readback');
  }
  return Object.freeze({
    backend: current.backend,
    genesis: current.genesis,
    methodCounts: Object.freeze(delta),
  });
}

/** Unit-test seam for the admission-only RPC evidence projection. */
export function deriveV2BetaOneShotAdmissionRpcObservationForTest(before, after) {
  return assertOneShotAdmissionObservation(before, after);
}

function observedSatoshis(value, label) {
  if (
    typeof value?.valueSatoshis === 'string'
    && DECIMAL.test(value.valueSatoshis)
  ) {
    return value.valueSatoshis;
  }
  if (
    typeof value?.value === 'number'
    && Number.isFinite(value.value)
    && value.value >= 0
  ) {
    const satoshis = Math.round(value.value * 100_000_000);
    if (Number.isSafeInteger(satoshis) && satoshis / 100_000_000 === value.value) {
      return String(satoshis);
    }
  }
  fail('BETA_CHAIN_READ_REJECTED', `${label} has no exact safe satoshi value`);
}

function assertStore(value) {
  if (
    value === null
    || typeof value !== 'object'
    || typeof value.binding !== 'function'
    || typeof value.optimisticTip !== 'function'
    || typeof value.availableFundingUtxos !== 'function'
    || typeof value.activeOperation !== 'function'
    || typeof value.telemetry !== 'function'
    || typeof value.putEncryptedRecord !== 'function'
    || typeof value.reserveOperation !== 'function'
    || typeof value.deriveProvingSuccessor !== 'function'
    || typeof value.finalizeProvingTransition !== 'function'
    || typeof value.stageOperationArtifacts !== 'function'
    || typeof value.applyAcceptedZeroConfSuccessor !== 'function'
    || typeof value.markLocalWalletCommitComplete !== 'function'
    || typeof value.rollbackActiveSuffix !== 'function'
    || typeof value.markSafePreSendAbort !== 'function'
    || typeof value.safePreSendAbortMarker !== 'function'
    || typeof value.finalizeSafePreSendAbort !== 'function'
    || typeof value.stagedOperation !== 'function'
  ) {
    fail(
      'BETA_STORE_REQUIRED',
      'a V2 beta incremental store capability is required',
    );
  }
  return value;
}

function storeTelemetry(value, label) {
  let telemetry;
  try { telemetry = value.telemetry(); }
  catch (error) {
    fail('BETA_STORE_TELEMETRY_UNAVAILABLE', `${label} beta store telemetry is unavailable`, { cause: error });
  }
  exact(telemetry, [
    'databaseBytes', 'liveCount', 'noteCount', 'nullifierCount', 'schema',
    'walBytes',
  ], `${label} beta store telemetry`);
  if (telemetry.schema !== 'shieldkit-v2-beta-incremental-store-telemetry-v1'
    || !['databaseBytes', 'walBytes', 'noteCount', 'nullifierCount', 'liveCount']
      .every((name) => Number.isSafeInteger(telemetry[name]) && telemetry[name] >= 0)
    || telemetry.liveCount !== telemetry.noteCount - telemetry.nullifierCount) {
    fail('BETA_STORE_TELEMETRY_UNAVAILABLE', `${label} beta store telemetry is invalid`);
  }
  return Object.freeze({ ...telemetry });
}

function storeTelemetryDelta(before, after) {
  return Object.freeze({
    databaseBytes: after.databaseBytes - before.databaseBytes,
    walBytes: after.walBytes - before.walBytes,
    noteCount: after.noteCount - before.noteCount,
    nullifierCount: after.nullifierCount - before.nullifierCount,
    liveCount: after.liveCount - before.liveCount,
  });
}

export function validateV2BetaPersistedProofContainment(containment) {
  exact(containment, [
    'backend', 'memoryMaxBytes', 'memoryPeakBytes', 'memorySwapMaxBytes',
    'oomDelta', 'oomKillDelta', 'terminatedSuccessfully',
  ], 'persisted native proof containment');
  if (containment.backend !== 'linux-systemd-cgroup-v2'
    || containment.terminatedSuccessfully !== true
    || !['memoryMaxBytes', 'memorySwapMaxBytes', 'memoryPeakBytes'].every((name) => typeof containment[name] === 'string' && DECIMAL.test(containment[name]))
    || containment.memoryMaxBytes !== '4294967296'
    || containment.memorySwapMaxBytes !== '0'
    || BigInt(containment.memoryPeakBytes) <= 0n
    || BigInt(containment.memoryPeakBytes) > BigInt(containment.memoryMaxBytes)
    || containment.oomDelta !== 0
    || containment.oomKillDelta !== 0) {
    fail('BETA_PROOF_TELEMETRY_UNAVAILABLE', 'native proof containment telemetry is unavailable');
  }
  return Object.freeze({ ...containment });
}

function proofTelemetry(value, containment) {
  const userTicks = value.nativeProver.userTicks;
  const systemTicks = value.nativeProver.systemTicks;
  const totalTicks = userTicks + systemTicks;
  const proofGenerationMs = value.timingsMs.proofGeneration;
  const cores = availableParallelism();
  if (!Number.isSafeInteger(totalTicks) || totalTicks <= 0
    || !Number.isFinite(proofGenerationMs) || proofGenerationMs <= 0
    || value.nativeProver.ompThreads !== cores
    || value.nativeProver.threads < value.nativeProver.ompThreads
    || value.nativeProver.activeCpuThreads < value.nativeProver.ompThreads
    || value.nativeProver.activeCpuThreads > value.nativeProver.threads
    || value.nativeProver.peakRssKiB <= 0) {
    fail('BETA_PROOF_TELEMETRY_UNAVAILABLE', 'native proof telemetry is unavailable');
  }
  return Object.freeze({
    userTicks,
    systemTicks,
    totalTicks,
    observedThreads: value.nativeProver.threads,
    activeCpuThreads: value.nativeProver.activeCpuThreads,
    ompThreads: value.nativeProver.ompThreads,
    peakRssKiB: value.nativeProver.peakRssKiB,
    proofGenerationMs,
    // A clock-tick rate is platform-specific. This ratio remains a directly
    // observed CPU-ticks-per-wall-time metric without asserting a percentage.
    cpuTicksPerWallMillisecond: proofGenerationMs === 0 ? null : totalTicks / proofGenerationMs,
    containment: validateV2BetaPersistedProofContainment(containment),
  });
}

function assertRuntimeCache(
  value,
  profileCore,
  store,
  wallet,
  assertCapability,
) {
  try {
    assertCapability(value);
  } catch (error) {
    fail(
      'BETA_RUNTIME_CAPABILITY_REJECTED',
      'runtime cache was not issued by the verified warm-cache loader',
      { cause: error },
    );
  }
  exact(
    value,
    [
      'claims',
      'descriptorSha256',
      'eligibility',
      'identity',
      'manifestSha256',
      'proofArtifacts',
      'runtimeManifestSha256',
      'runtimeMaterial',
      'runtimeMaterialSha256',
      'schema',
      'settlementPins',
    ],
    'runtime cache',
  );
  const profileId = deriveProfileId(profileCore);
  const binding = store.binding();
  const walletSummary = wallet.publicSummary();
  const roles = value.runtimeMaterial?.verifierRoles;
  if (
    value.identity?.profileId !== profileId
    || value.identity?.instanceId !== binding.instanceId.toString('hex')
    || value.identity?.instanceId !== walletSummary.instanceId
    || value.identity?.profileId !== walletSummary.profileId
    || value.identity?.denominationSats !== profileCore.denominationSats
    || value.runtimeMaterial?.profileId !== profileId
    || value.runtimeMaterial?.instanceId !== value.identity.instanceId
    || value.runtimeMaterial?.topologyId
      !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
    || !Array.isArray(roles)
    || roles.length !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length
    || roles.some(
      (role, index) => role !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES[index],
    )
    || value.runtimeMaterial?.materialSha256
      !== value.runtimeMaterialSha256
    || value.schema !== V2_BETA_CHIPNET_RUNTIME_RESOLUTION_SCHEMA
    || value.eligibility !== V2_BETA_LOCAL_ELIGIBILITY
    || canonicalizeJcs(value.claims)
      !== canonicalizeJcs(V2_BETA_LOCAL_FALSE_CLAIMS)
    || !HASH.test(value.runtimeManifestSha256)
    || !HASH.test(value.descriptorSha256)
    || value.manifestSha256 !== value.runtimeManifestSha256
  ) {
    fail(
      'BETA_RUNTIME_BINDING_REJECTED',
      'runtime cache, profile, incremental store, and wallet identities differ',
    );
  }
  return Object.freeze({ profileId, instanceId: value.identity.instanceId });
}

function assertTestNativeProverInstallation(value) {
  exact(value, ['binary'], 'test native prover installation');
  if (
    value.binary === null
    || typeof value.binary !== 'object'
    || typeof value.binary.sha256 !== 'string'
    || !HASH.test(value.binary.sha256)
  ) {
    fail('BETA_NATIVE_PROVER_REJECTED', 'test native prover installation is invalid');
  }
  return Object.freeze({ binarySha256: value.binary.sha256 });
}

function assertProofWorkspace(value) {
  if (typeof value !== 'string' || value.length === 0) {
    fail('BETA_PROOF_WORKSPACE_REQUIRED', 'proof workspace is required');
  }
  return value;
}

function inspectRawRead(value, expectedTxid, label) {
  const raw = typeof value === 'string' ? value : value?.hex;
  const claimed = typeof value === 'object' && value !== null
    ? value.txid
    : expectedTxid;
  if (
    typeof raw !== 'string'
    || !HEX.test(raw)
    || claimed !== expectedTxid
  ) {
    fail('BETA_CHAIN_READ_REJECTED', `${label} raw transaction read is invalid`);
  }
  const parsed = parseV2RawTransaction(raw);
  if (parsed.txid !== expectedTxid) {
    fail('BETA_CHAIN_READ_REJECTED', `${label} bytes do not match the txid`);
  }
  return Object.freeze({ raw, parsed });
}

function outputValueSats(output) {
  return output.valueSatoshis.toString();
}

function inspectArtifactMeasurements(value, transaction) {
  exact(value, [
    'acceptancePercent', 'acceptedInputCount', 'changeSats',
    'feeRateSatsPerByte', 'feeSats', 'inputCount',
    'maximumTransactionBytes', 'maximumUnlockingBytecodeBytes',
    'outputCount', 'sizeBytes',
  ], 'persisted transaction measurements');
  decimal(value.changeSats, 'transaction changeSats');
  decimal(value.feeRateSatsPerByte, 'transaction feeRateSatsPerByte');
  decimal(value.feeSats, 'transaction feeSats');
  for (const name of [
    'acceptedInputCount', 'inputCount', 'maximumTransactionBytes',
    'maximumUnlockingBytecodeBytes', 'outputCount', 'sizeBytes',
  ]) safeInteger(value[name], 1, `transaction ${name}`);
  if (
    value.inputCount !== transaction.inputs.length
    || value.outputCount !== transaction.outputs.length
    || value.sizeBytes !== transaction.sizeBytes
    || value.acceptedInputCount !== value.inputCount
    || value.acceptancePercent !== 100
    || BigInt(value.feeSats)
      !== BigInt(value.feeRateSatsPerByte) * BigInt(value.sizeBytes)
  ) {
    fail(
      'BETA_ACTION_ARTIFACT_REJECTED',
      'persisted transaction measurements differ from the exact signed bytes or fee contract',
    );
  }
  return value;
}

function inspectArtifactTimings(value) {
  exact(value, [
    'fundingRead', 'localVm', 'proofGeneration', 'proofTotal',
    'proofVerification', 'signingAndVm', 'stateRead', 'treeAndPreparation',
    'witnessAssembly', 'witnessCalculation',
  ], 'persisted action timings');
  for (const [name, duration] of Object.entries(value)) {
    finiteDuration(duration, `action timing ${name}`);
  }
  return value;
}

function parseArtifact(bytesValue) {
  let value;
  try {
    value = JSON.parse(Buffer.from(bytesValue).toString('utf8'));
  } catch (error) {
    fail('BETA_ACTION_ARTIFACT_REJECTED', 'persisted action artifact is not JSON', {
      cause: error,
    });
  }
  if (!Buffer.from(bytesValue).equals(canonicalBytes(value))) {
    fail(
      'BETA_ACTION_ARTIFACT_REJECTED',
      'persisted action artifact is not exact canonical JCS',
    );
  }
  exact(
    value,
    [
      'change',
      'claims',
      'expectedState',
      'funding',
      'instanceId',
      'kind',
      'localVmEvidenceHex',
      'measurements',
      'operationId',
      'outputNote',
      'packetHex',
      'profileId',
      'proofContainment',
      'proofResultSha256',
      'rawTransactionHex',
      'schema',
      'timingsMs',
      'transactionId',
    ],
    'persisted action artifact',
  );
  if (
    value.schema !== V2_BETA_PRODUCT_ACTION_ARTIFACT_SCHEMA
    || !['deposit', 'withdrawal'].includes(value.kind)
    || value.claims?.confirmed !== false
    || value.claims?.mined !== false
    || value.claims?.productionQualified !== false
    || !HEX.test(value.localVmEvidenceHex)
    || !HEX.test(value.packetHex)
    || !HASH.test(value.proofResultSha256)
    || !HASH.test(value.profileId)
    || !HASH.test(value.instanceId)
    || !HASH.test(value.transactionId)
    || !OPERATION_ID.test(value.operationId)
  ) {
    fail('BETA_ACTION_ARTIFACT_REJECTED', 'persisted action artifact is invalid');
  }
  const parsed = parseV2RawTransaction(value.rawTransactionHex);
  if (parsed.txid !== value.transactionId) {
    fail('BETA_ACTION_ARTIFACT_REJECTED', 'persisted action txid differs from bytes');
  }
  inspectArtifactMeasurements(value.measurements, parsed);
  inspectArtifactTimings(value.timingsMs);
  return Object.freeze({ value, transaction: parsed });
}

function transactionArtifact({
  change,
  expectedState,
  funding,
  identity,
  kind,
  operation,
  outputNote,
  proofResult,
  signed,
  timingsMs,
}) {
  const value = Object.freeze({
    schema: V2_BETA_PRODUCT_ACTION_ARTIFACT_SCHEMA,
    operationId: operation,
    kind,
    profileId: identity.profileId,
    instanceId: identity.instanceId,
    packetHex: signed.actionPacketHex,
    proofResultSha256: proofResult.resultSha256,
    proofContainment: proofResult.containment,
    rawTransactionHex: signed.rawTransactionHex,
    transactionId: signed.txid,
    localVmEvidenceHex: signed.localVmEvidenceHex,
    measurements: copyJson(signed.measurements),
    expectedState,
    funding,
    change,
    outputNote,
    timingsMs,
    claims: claims(),
  });
  return Object.freeze({ value, bytes: canonicalBytes(value) });
}

function canonicalNativeProofResult(value) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail('BETA_PROOF_ARTIFACT_REJECTED', 'native proof result is not an object');
  }
  for (const name of [
    'claims', 'inputSha256', 'nativeProver', 'proof', 'publicInputs',
    'resultSha256', 'schema', 'sourceHashes', 'timingsMs',
  ]) {
    if (!Object.hasOwn(value, name)) {
      fail('BETA_PROOF_ARTIFACT_REJECTED', `native proof result is missing ${name}`);
    }
  }
  if (
    value.claims === null || typeof value.claims !== 'object'
    || value.sourceHashes === null || typeof value.sourceHashes !== 'object'
    || value.timingsMs === null || typeof value.timingsMs !== 'object'
    || value.nativeProver === null || typeof value.nativeProver !== 'object'
    || !Array.isArray(value.publicInputs)
  ) {
    fail('BETA_PROOF_ARTIFACT_REJECTED', 'native proof result has malformed provenance fields');
  }
  const resultSha256 = value.resultSha256;
  const persisted = Object.freeze({
    schema: value.schema,
    claims: copyJson(value.claims),
    inputSha256: value.inputSha256,
    proof: copyJson(value.proof),
    publicInputs: [...value.publicInputs],
    sourceHashes: copyJson(value.sourceHashes),
    timingsMs: copyJson(value.timingsMs),
    nativeProver: copyJson(value.nativeProver),
  });
  exact(persisted, [
    'claims', 'inputSha256', 'nativeProver', 'proof', 'publicInputs',
    'schema', 'sourceHashes', 'timingsMs',
  ], 'persisted native proof result');
  exact(persisted.claims, [
    'proofVerified', 'witnessCalculated', 'witnessR1csChecked',
  ], 'persisted proof claims');
  exact(persisted.sourceHashes, [
    'provingKey', 'r1cs', 'verificationKey', 'wasm',
  ], 'persisted proof source hashes');
  exact(persisted.nativeProver, [
    'activeCpuThreads', 'backend', 'ompThreads', 'peakRssKiB', 'sha256', 'systemTicks',
    'threads', 'userTicks',
  ], 'persisted native prover metrics');
  exact(persisted.timingsMs, [
    'proofGeneration', 'proofVerification', 'total', 'witnessCalculation',
  ], 'persisted proof timings');
  if (
    persisted.schema !== V2_NATIVE_GROTH16_PROOF_RESULT_SCHEMA
    || !HASH.test(persisted.inputSha256)
    || !HASH.test(resultSha256)
    || persisted.claims.proofVerified !== true
    || persisted.claims.witnessCalculated !== true
    || persisted.claims.witnessR1csChecked !== false
    || !Array.isArray(persisted.publicInputs)
    || persisted.publicInputs.some((input) => typeof input !== 'string' || !DECIMAL.test(input))
    || persisted.nativeProver.backend !== 'rapidsnark'
    || !HASH.test(persisted.nativeProver.sha256)
    || !Number.isSafeInteger(persisted.nativeProver.ompThreads)
    || persisted.nativeProver.ompThreads < 1
    || !['activeCpuThreads', 'peakRssKiB', 'systemTicks', 'threads', 'userTicks'].every(
      (name) => Number.isSafeInteger(persisted.nativeProver[name])
        && persisted.nativeProver[name] >= 0,
    )
    || persisted.nativeProver.ompThreads !== availableParallelism()
    || persisted.nativeProver.threads < persisted.nativeProver.ompThreads
    || persisted.nativeProver.activeCpuThreads < persisted.nativeProver.ompThreads
    || persisted.nativeProver.activeCpuThreads > persisted.nativeProver.threads
    || persisted.nativeProver.peakRssKiB <= 0
    || persisted.nativeProver.userTicks + persisted.nativeProver.systemTicks <= 0
    || persisted.proof === null
    || Array.isArray(persisted.proof)
    || typeof persisted.proof !== 'object'
  ) {
    fail('BETA_PROOF_ARTIFACT_REJECTED', 'native proof result provenance is invalid');
  }
  for (const duration of Object.values(persisted.timingsMs)) {
    finiteDuration(duration, 'native proof timing');
  }
  if (persisted.timingsMs.proofGeneration <= 0) {
    fail('BETA_PROOF_ARTIFACT_REJECTED', 'native proof generation must contain measured positive work');
  }
  const bytes = canonicalBytes(persisted);
  if (sha256(bytes) !== resultSha256) {
    fail('BETA_PROOF_ARTIFACT_REJECTED', 'native proof result hash does not match its exact canonical bytes');
  }
  return Object.freeze({ value: persisted, bytes, resultSha256 });
}

function proofArtifact(proofResult) {
  return canonicalNativeProofResult(proofResult).bytes;
}

function inspectProofArtifact(bytesValue, {
  actionArtifact,
  nativeProverSha256,
  packet,
  runtime,
}) {
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(bytesValue).toString('utf8'));
  } catch (error) {
    fail('BETA_PROOF_ARTIFACT_REJECTED', 'persisted proof artifact is not JSON', {
      cause: error,
    });
  }
  if (!Buffer.from(bytesValue).equals(canonicalBytes(parsed))) {
    fail(
      'BETA_PROOF_ARTIFACT_REJECTED',
      'persisted proof artifact is not exact canonical JCS',
    );
  }
  const { value, bytes, resultSha256 } = canonicalNativeProofResult({
    ...parsed,
    resultSha256: sha256(Buffer.from(bytesValue)),
  });
  if (!Buffer.from(bytesValue).equals(bytes)) {
    fail('BETA_PROOF_ARTIFACT_REJECTED', 'persisted proof artifact canonical bytes differ after parsing');
  }
  const expectedInputs = actionPacketPublicLimbs(packet, {
    denominationSats: runtime.identity.denominationSats,
  });
  if (
    resultSha256 !== actionArtifact.proofResultSha256
    || value.publicInputs.length !== expectedInputs.length
    || value.publicInputs.some((input, index) => input !== expectedInputs[index])
    || value.nativeProver.sha256 !== nativeProverSha256
  ) {
    fail(
      'BETA_PROOF_ARTIFACT_REJECTED',
      'persisted proof artifact is not the exact verified native proof for this packet',
    );
  }
  for (const [name, expected] of Object.entries(runtime.proofArtifacts)) {
    if (value.sourceHashes[name] !== expected.sha256) {
      fail(
        'BETA_PROOF_ARTIFACT_REJECTED',
        `persisted proof source ${name} differs from the warm-cache pin`,
      );
    }
  }
  return Object.freeze(value);
}

function inspectFundingArtifact(value, staged, transaction) {
  exact(value, ['txid', 'valueSats', 'vout', 'walletId'], 'funding artifact');
  hash(value.txid, 'funding txid');
  hash(value.walletId, 'funding wallet id');
  safeInteger(value.vout, 0, 'funding vout');
  decimal(value.valueSats, 'funding valueSats');
  const reserved = staged.resources.funding;
  const input = transaction.inputs[TOPOLOGY.fundingInputIndex];
  if (
    reserved === null
    || reserved.txid.toString('hex') !== value.txid
    || reserved.vout !== value.vout
    || reserved.valueSats !== value.valueSats
    || input?.outpoint.txid !== value.txid
    || input?.outpoint.vout !== value.vout
  ) {
    fail(
      'BETA_FUNDING_BINDING_REJECTED',
      'signed funding input differs from the exact persisted funding reservation',
    );
  }
  return value;
}

function inspectAdmissionResult(value, {
  expectedState,
  journal,
  operation,
  rpc,
  transaction,
}) {
  exact(value, [
    'admission', 'backend', 'claims', 'journal', 'operationId', 'readback',
    'schema', 'status', 'txid',
  ], 'beta admission result');
  exact(value.claims, ['confirmed', 'mined', 'productionQualified'], 'admission claims');
  exact(value.admission, ['allowed', 'txid'], 'admission preflight result');
  exact(value.journal, [
    'attemptCount', 'attemptToken', 'metadataHash', 'roleLayoutHash', 'state',
    'vmEvidenceHash',
  ], 'admission journal result');
  exact(value.readback, [
    'rawTransactionSha256', 'stateCategoryWire', 'stateCommitmentSha256',
    'stateOutpoint',
  ], 'admission readback');
  exact(value.readback.stateOutpoint, ['txid', 'vout'], 'admission state outpoint');
  const durable = journal.record(operation);
  if (
    value.schema !== V2_BETA_ZERO_CONF_ADMISSION_SCHEMA
    || value.status !== 'locally-reconciled-zero-conf-beta-unqualified'
    || value.operationId !== operation
    || value.txid !== transaction.txid
    || value.backend !== rpc.backend
    || value.claims.confirmed !== false
    || value.claims.mined !== false
    || value.claims.productionQualified !== false
    || ![true, null].includes(value.admission.allowed)
    || value.admission.txid !== transaction.txid
    || value.journal.state !== 'locally_reconciled'
    || durable?.state !== 'locally_reconciled'
    || durable?.txid !== transaction.txid
    || durable?.metadataHash !== value.journal.metadataHash
    || value.readback.rawTransactionSha256 !== sha256(transaction.bytes)
    || value.readback.stateOutpoint.txid !== transaction.txid
    || value.readback.stateOutpoint.vout !== 0
    || value.readback.stateCategoryWire !== Buffer.from(expectedState.category, 'hex').reverse().toString('hex')
    || value.readback.stateCommitmentSha256 !== sha256(Buffer.from(expectedState.commitment, 'hex'))
  ) {
    fail(
      'BETA_ADMISSION_RESULT_REJECTED',
      'admission result is not durably bound to this exact zero-conf transaction and readback',
    );
  }
  for (const name of [
    'metadataHash', 'roleLayoutHash', 'vmEvidenceHash',
  ]) hash(value.journal[name], `admission journal ${name}`);
  hash(value.readback.rawTransactionSha256, 'admission raw transaction hash');
  hash(value.readback.stateCommitmentSha256, 'admission state commitment hash');
  return value;
}

function fundingProjection(wallets, lockingBytecodeHex, txid, vout) {
  const candidates = wallets.filter((entry) => {
    if (entry.lockingBytecodeHex !== lockingBytecodeHex) return false;
    if (entry.attachedOutpoint === null) return true;
    return entry.attachedOutpoint.txid === txid
      && entry.attachedOutpoint.vout === vout;
  });
  if (candidates.length !== 1) {
    fail(
      'BETA_FUNDING_KEY_REJECTED',
      'funding source does not match exactly one spendable wallet key',
    );
  }
  return candidates[0];
}

function selectChangeOutput(transaction, stagedChange) {
  const matches = transaction.outputs.filter((output) =>
    output.lockingBytecode.toString('hex') === stagedChange.lockingBytecodeHex);
  if (matches.length !== 1) {
    fail(
      'BETA_CHANGE_OUTPUT_REJECTED',
      'signed transaction does not contain exactly one fresh staged change output',
    );
  }
  return Object.freeze({
    walletId: stagedChange.walletId,
    lockingBytecodeHex: stagedChange.lockingBytecodeHex,
    txid: transaction.txid,
    vout: matches[0].index,
    valueSats: outputValueSats(matches[0]),
  });
}

function expectedState(identity, transition, transaction) {
  const commitment = encodeStateNftCommitment(transition.state, {
    denominationSats: identity.denominationSats,
  }).toString('hex');
  return Object.freeze({
    category: identity.instanceId,
    capability: 'mutable',
    commitment,
    tokenAmount: '0',
    valueSatoshis: outputValueSats(transaction.outputs[0]),
  });
}

function outputNoteArtifact(kind, material) {
  if (kind === 'withdrawal') return null;
  return Object.freeze({
    noteId: material.noteId,
    recordId: material.recordId,
  });
}

function inspectOutputNote(value, kind) {
  if (kind === 'withdrawal') {
    if (value !== null) {
      fail('BETA_ACTION_ARTIFACT_REJECTED', 'withdrawal artifact has an output note');
    }
    return null;
  }
  exact(value, ['noteId', 'recordId'], 'output note artifact');
  hash(value.noteId, 'output note id');
  hash(value.recordId, 'output note record id');
  return value;
}

function inspectChange(value, transaction) {
  exact(
    value,
    ['lockingBytecodeHex', 'txid', 'valueSats', 'vout', 'walletId'],
    'change artifact',
  );
  if (
    value.txid !== transaction.txid
    || !Number.isSafeInteger(value.vout)
    || value.vout < 0
    || transaction.outputs[value.vout]?.lockingBytecode.toString('hex')
      !== value.lockingBytecodeHex
    || outputValueSats(transaction.outputs[value.vout]) !== value.valueSats
  ) {
    fail('BETA_ACTION_ARTIFACT_REJECTED', 'change artifact differs from transaction');
  }
  return value;
}

const TEST_DEPENDENCY_FACTORY = Symbol('V2BetaProductActionLifecycle test dependency factory');
const PRODUCTION_FACTORY = Symbol('V2BetaProductActionLifecycle production factory');

function productionDependencies() {
  return Object.freeze({
    assertRuntimeCacheCapability: assertV2BetaChipnetRuntimeResolution,
    assertNativeProofArtifacts: assertV2BetaChipnetNativeProofArtifacts,
    deriveNativeProofArtifacts: deriveV2BetaChipnetNativeProofArtifacts,
    prove: proveV2DirectNativeGroth16Default,
    createVmEvidence: createV2LocalVmEvidence,
    submitAdmission: submitV2BetaZeroConfAdmission,
    rebroadcastAdmission: rebroadcastV2BetaZeroConfAdmission,
    reconcileAdmission: reconcileV2BetaZeroConfAdmission,
    afterSafePreSendWalletAbort: undefined,
  });
}

function testDependencies(value) {
  exact(
    value,
    [
      'afterSafePreSendWalletAbort', 'assertNativeProofArtifacts',
      'assertRuntimeCacheCapability', 'createVmEvidence',
      'deriveNativeProofArtifacts', 'prove', 'rebroadcastAdmission', 'reconcileAdmission',
      'submitAdmission',
    ],
    'beta action dependencies',
  );
  for (const [name, fn] of Object.entries(value)) {
    if (name === 'afterSafePreSendWalletAbort' && fn === undefined) continue;
    if (typeof fn !== 'function') {
      fail('BETA_ACTION_INVALID', `${name} dependency must be a function`);
    }
  }
  return Object.freeze({ ...value });
}

export class V2BetaProductActionLifecycle {
  #profileCore;
  #runtime;
  #nativeProverInstallation;
  #nativeProverSha256;
  #store;
  #wallet;
  #journal;
  #rpc;
  #proofWorkspace;
  #proofArtifacts;
  #identity;
  #dependencies;

  constructor(options, injectedDependencies = undefined, factory = undefined, installedNativeProver = undefined) {
    if (![TEST_DEPENDENCY_FACTORY, PRODUCTION_FACTORY].includes(factory)) {
      fail('BETA_ACTION_CONSTRUCTION_REJECTED', 'use the production or explicit test lifecycle factory');
    }
    if (injectedDependencies !== undefined && factory !== TEST_DEPENDENCY_FACTORY) {
      fail(
        'BETA_ACTION_INJECTION_REJECTED',
        'production lifecycle construction does not accept injected dependencies',
      );
    }
    exact(
      options,
      [
        'journal',
        'nativeProverInstallation',
        'profileCore',
        'proofWorkspaceDirectory',
        'rpc',
        'runtimeCache',
        'store',
        'wallet',
      ],
      'beta product action lifecycle options',
    );
    validateProfileCore(options.profileCore);
    if (
      options.profileCore.network?.id !== 2
      || options.profileCore.network?.name !== 'chipnet'
    ) {
      fail('BETA_PROFILE_REJECTED', 'the beta product action lane is Chipnet-only');
    }
    this.#store = assertStore(options.store);
    this.#wallet = assertV2BetaProductWallet(options.wallet);
    this.#dependencies = injectedDependencies === undefined
      ? productionDependencies()
      : testDependencies(injectedDependencies);
    this.#identity = Object.freeze({
      ...assertRuntimeCache(
        options.runtimeCache,
        options.profileCore,
        this.#store,
        this.#wallet,
        this.#dependencies.assertRuntimeCacheCapability,
      ),
      denominationSats: options.profileCore.denominationSats,
    });
    try {
      this.#proofArtifacts = this.#dependencies.assertNativeProofArtifacts(
        this.#dependencies.deriveNativeProofArtifacts(options.runtimeCache),
      );
    } catch (error) {
      fail(
        'BETA_PROOF_ARTIFACT_REJECTED',
        'native proof artifacts were not issued from this exact branded runtime resolution',
        { cause: error },
      );
    }
    this.#journal = assertV2DeliveryJournal(options.journal);
    try {
      this.#rpc = assertLayer1BchnChipnetRpc(options.rpc);
    } catch (error) {
      fail('BETA_RPC_REJECTED', 'a branded BCHN Chipnet RPC is required', {
        cause: error,
      });
    }
    this.#profileCore = options.profileCore;
    this.#runtime = options.runtimeCache;
    this.#nativeProverInstallation = options.nativeProverInstallation;
    this.#nativeProverSha256 = factory === PRODUCTION_FACTORY
      ? installedNativeProver?.sha256
      : assertTestNativeProverInstallation(options.nativeProverInstallation).binarySha256;
    if (!HASH.test(this.#nativeProverSha256)) {
      fail('BETA_NATIVE_PROVER_REJECTED', 'native prover installation did not yield an exact binary hash');
    }
    this.#proofWorkspace = assertProofWorkspace(options.proofWorkspaceDirectory);
  }

  async #readTip() {
    const started = now();
    const tip = this.#store.optimisticTip();
    const txid = tip.outpoint.txid.toString('hex');
    const [rawValue, observedState] = await Promise.all([
      this.#rpc.getrawtransaction(txid, true),
      this.#rpc.gettxout(txid, tip.outpoint.vout),
    ]);
    const raw = inspectRawRead(rawValue, txid, 'accepted beta tip');
    const state = decodeStateNftCommitment(tip.state, {
      denominationSats: this.#identity.denominationSats,
    });
    if (tip.outpoint.vout !== 0) {
      fail('BETA_TIP_READBACK_REJECTED', 'the beta state NFT must remain output 0');
    }
    const rawOutput = raw.parsed.outputs[tip.outpoint.vout];
    const sourceOutput = rawOutput === undefined
      ? null
      : parseSerializedSourceOutput(rawOutput.serializedHex);
    const token = observedState?.tokenData ?? observedState?.token;
    const categoryWire = Buffer.from(this.#identity.instanceId, 'hex')
      .reverse().toString('hex');
    const expectedStateValueSats = (
      BigInt(this.#runtime.settlementPins.stateBaseSats)
      + BigInt(state.reserveSats)
    ).toString();
    if (
      observedState === null
      || sourceOutput === null
      || sourceOutput.valueSatoshis.toString() !== expectedStateValueSats
      || sourceOutput.token?.categoryWire !== this.#identity.instanceId
      || sourceOutput.token?.amount !== '0'
      || sourceOutput.token?.nft?.capability !== 'mutable'
      || sourceOutput.token?.nft?.commitmentHex !== tip.state.toString('hex')
      || token?.category !== categoryWire
      || token?.nft?.capability !== 'mutable'
      || String(token?.amount) !== '0'
      || token?.nft?.commitment !== tip.state.toString('hex')
      || observedSatoshis(observedState, 'BCHN state output')
        !== expectedStateValueSats
      || observedState?.scriptPubKey?.hex !== sourceOutput.lockingBytecodeHex
      || state.actionSequence !== String(tip.actionSequence)
      || state.maximumLiveNotes !== this.#runtime.identity.maximumLiveNotes
    ) {
      fail(
        'BETA_TIP_READBACK_REJECTED',
        'BCHN current state output differs from the persisted accepted zero-conf tip, reserve, or runtime capacity',
      );
    }
    return Object.freeze({
      tip,
      state,
      rawTransactionHex: raw.raw,
      timingMs: elapsed(started),
    });
  }

  async #selectFunding(tipTxid) {
    const started = now();
    const wallets = this.#wallet.spendableFundingWallets();
    const candidates = [...this.#store.availableFundingUtxos()]
      .filter((entry) => entry.txid.toString('hex') !== tipTxid)
      .sort((left, right) => {
        const amount = BigInt(right.valueSats) - BigInt(left.valueSats);
        if (amount !== 0n) return amount > 0n ? 1 : -1;
        return Buffer.compare(left.txid, right.txid) || left.vout - right.vout;
    });
    for (const candidate of candidates) {
      const txid = candidate.txid.toString('hex');
      const [rawValue, observed] = await Promise.all([
        this.#rpc.getrawtransaction(txid, true),
        this.#rpc.gettxout(txid, candidate.vout),
      ]);
      const source = inspectRawRead(rawValue, txid, 'funding source');
      const output = source.parsed.outputs[candidate.vout];
      const serialized = output === undefined
        ? null
        : parseSerializedSourceOutput(output.serializedHex);
      const observedToken = observed?.tokenData ?? observed?.token;
      if (
        output === undefined
        || serialized === null
        || observed === null
        || outputValueSats(output) !== candidate.valueSats
        || serialized.valueSatoshis.toString() !== candidate.valueSats
        || serialized.token !== null
        || (observedToken !== undefined && observedToken !== null)
        || observedSatoshis(observed, 'BCHN funding output') !== candidate.valueSats
        || observed?.scriptPubKey?.hex !== serialized.lockingBytecodeHex
      ) {
        fail(
          'BETA_FUNDING_SOURCE_REJECTED',
          'persisted funding UTXO is spent, token-bearing, or differs from exact BCHN bytes',
        );
      }
      const wallet = fundingProjection(
        wallets,
        output.lockingBytecode.toString('hex'),
        txid,
        candidate.vout,
      );
      return Object.freeze({
        txid,
        txidBytes: Buffer.from(txid, 'hex'),
        vout: candidate.vout,
        valueSats: candidate.valueSats,
        sourceTransactionHex: source.raw,
        wallet,
        timingMs: elapsed(started),
      });
    }
    fail(
      'BETA_FUNDING_UNAVAILABLE',
      'no independent unspent funding UTXO is available; prepare at least two fee UTXOs for serial zero-conf actions',
      { recoverable: true },
    );
  }

  async executeDeposit({ operationId: requestedOperationId } = {}) {
    return this.#execute({
      kind: 'deposit',
      noteId: undefined,
      operationId: operationId(requestedOperationId),
      payoutLockingBytecode: null,
    });
  }

  async executeWithdrawal({
    operationId: requestedOperationId,
    noteId = undefined,
    payoutLockingBytecode,
  } = {}) {
    if (!(payoutLockingBytecode instanceof Uint8Array)) {
      fail(
        'BETA_WITHDRAWAL_DESTINATION_REQUIRED',
        'withdrawal requires a canonical P2PKH payout locking bytecode',
      );
    }
    return this.#execute({
      kind: 'withdrawal',
      noteId,
      operationId: operationId(requestedOperationId),
      payoutLockingBytecode: Buffer.from(payoutLockingBytecode),
    });
  }

  async #execute({ kind, noteId, operationId: id, payoutLockingBytecode }) {
    const totalStarted = now();
    const telemetryBefore = storeTelemetry(this.#store, 'pre-action');
    if (this.#store.activeOperation() !== null) {
      fail(
        'BETA_ACTION_IN_PROGRESS',
        'resume or explicitly reject the active beta operation before starting another',
        { recoverable: true },
      );
    }
    const tipRead = await this.#readTip();
    const funding = await this.#selectFunding(tipRead.tip.outpoint.txid.toString('hex'));
    const change = this.#wallet.stageChangeWallet({ operationId: id });
    let reserved = false;
    try {
      let note;
      if (kind === 'deposit') {
        note = this.#wallet.stageDepositNote({
          operationId: id,
          postActionSequence: String(tipRead.tip.actionSequence + 1),
        });
        this.#store.putEncryptedRecord({
          recordId: note.privateStoreMaterial.recordId,
          record: note.privateStoreMaterial.encryptedRecord,
        });
      } else {
        note = this.#wallet.reserveOwnedNoteForWithdrawal({
          operationId: id,
          ...(noteId === undefined ? {} : { noteId }),
        });
      }
      this.#store.reserveOperation({
        operationId: id,
        kind,
        selectedNoteId: kind === 'withdrawal' ? note.note.noteId : null,
        funding: { txid: funding.txidBytes, vout: funding.vout },
      });
      reserved = true;

      const successorInput = Object.freeze({
      operationId: id,
      outputNoteLeaf: kind === 'deposit'
        ? Buffer.from(note.publicOutput.outputNoteLeaf, 'hex')
        : null,
      encryptedRecord: kind === 'deposit'
        ? note.publicOutput.encryptedRecord
        : null,
      publicNullifier: kind === 'withdrawal'
        ? Buffer.from(note.publicSpend.publicNullifier, 'hex')
        : null,
      withdrawalLockingBytecodeHash: kind === 'withdrawal'
        ? createHash('sha256').update(payoutLockingBytecode).digest()
        : null,
      });

    const treeStarted = now();
    const successor = this.#store.deriveProvingSuccessor(successorInput);
    const prepared = prepareV2DirectSettlement({
      changeLockingBytecode: Buffer.from(change.lockingBytecodeHex, 'hex'),
      denominationSats: this.#identity.denominationSats,
      feeRateSatsPerByte: '1',
      funding: {
        outpointIndex: String(funding.vout),
        publicKey: Buffer.from(funding.wallet.compressedPublicKeyHex, 'hex'),
        sourceTransactionHex: funding.sourceTransactionHex,
      },
      instanceId: this.#identity.instanceId,
      kind,
      networkId: 2,
      payoutLockingBytecode,
      pins: this.#runtime.settlementPins,
      postState: successor.state,
      preState: tipRead.state,
      previousBundleTransactionHex: tipRead.rawTransactionHex,
      profileId: this.#identity.profileId,
      unlockingBytecodeLengths: {
        verifier: [...DIRECT_V2_PF10_VERIFIER_UNLOCK_BYTES],
        state: DIRECT_V2_PF10_STATE_UNLOCK_BYTES,
      },
    });
    const transition = this.#store.finalizeProvingTransition({
      derivedSuccessor: successor,
      operationId: id,
      transactionContextHash: Buffer.from(prepared.contextHash, 'hex'),
    });
    const treeAndPreparationMs = elapsed(treeStarted);

    const circuitInput = buildDirectV2CircuitInput({
      transition,
      denominationSats: this.#identity.denominationSats,
      ...(kind === 'deposit'
        ? { output: note.circuitOutput }
        : { spend: note.circuitSpend }),
    });
    const proofStarted = now();
    const proofResult = await this.#dependencies.prove({
      artifacts: this.#proofArtifacts,
      circuitInput,
      expectedPublicInputs: transition.publicInputs,
      nativeProverInstallation: this.#nativeProverInstallation,
      workspaceDirectory: this.#proofWorkspace,
    });
    // The worker result is canonical JCS. Preserve its complete provenance
    // before any witness builder can consume a structurally similar lookalike.
    canonicalNativeProofResult(proofResult);
    const proofTotalMs = elapsed(proofStarted);
    const witnessStarted = now();
    const witness = buildDirectV2Pf10BetaActionWitness({
      actionPacket: transition.packet,
      denominationSats: this.#identity.denominationSats,
      proofResult,
      runtimeMaterial: this.#runtime.runtimeMaterial,
    });
    const witnessAssemblyMs = elapsed(witnessStarted);
    const assembled = assembleV2DirectSettlement(prepared, {
      actionPacket: transition.packet,
      verifierUnlockingBytecodes: witness.verifierUnlockingBytecodes,
      stateUnlockingBytecode: witness.stateUnlockingBytecode,
    });
    let vmMs = 0;
    let verifiedLocalVmEvidence;
    const signingStarted = now();
    const signed = await signV2DirectSettlement(assembled, {
      signFunding: async (request) => {
        if (request.publicKeyHex !== funding.wallet.compressedPublicKeyHex) {
          fail(
            'BETA_SIGNING_REQUEST_REJECTED',
            'funding signing request changed after exact preparation',
          );
        }
        return this.#wallet.signFunding({
          walletId: funding.wallet.walletId,
          digestHex: request.digestHex,
        });
      },
      createLocalVmEvidence: async (request) => {
        const vmStarted = now();
        const evidence = await this.#dependencies.createVmEvidence({
          ...request,
          tool: {
            name: '@bitauth/libauth',
            version: LIBAUTH_VERSION,
            vm: V2_VM_PROFILE,
            profileId: this.#identity.profileId,
            profileSha256: sha256(canonicalBytes(this.#profileCore)),
          },
        });
        vmMs = elapsed(vmStarted);
        verifiedLocalVmEvidence = evidence;
        return evidence;
      },
    });
    const signingAndVmMs = elapsed(signingStarted);
    const parsedSigned = parseV2RawTransaction(signed.rawTransactionHex);
    const changeOutput = selectChangeOutput(parsedSigned, change);
    const expected = expectedState(this.#identity, transition, parsedSigned);
    const timingsMs = Object.freeze({
      stateRead: tipRead.timingMs,
      fundingRead: funding.timingMs,
      treeAndPreparation: treeAndPreparationMs,
      witnessCalculation: proofResult.timingsMs.witnessCalculation,
      proofGeneration: proofResult.timingsMs.proofGeneration,
      proofVerification: proofResult.timingsMs.proofVerification,
      proofTotal: proofTotalMs,
      witnessAssembly: witnessAssemblyMs,
      signingAndVm: signingAndVmMs,
      localVm: vmMs,
    });
    const privateOutput = kind === 'deposit'
      ? note.privateStoreMaterial
      : null;
    const persisted = transactionArtifact({
      change: changeOutput,
      expectedState: expected,
      funding: Object.freeze({
        txid: funding.txid,
        vout: funding.vout,
        valueSats: funding.valueSats,
        walletId: funding.wallet.walletId,
      }),
      identity: this.#identity,
      kind,
      operation: id,
      outputNote: outputNoteArtifact(kind, privateOutput),
      proofResult,
      signed,
      timingsMs,
    });
    this.#store.stageOperationArtifacts({
      operationId: id,
      packet: transition.packet,
      proofArtifact: proofArtifact(proofResult),
      transactionArtifact: persisted.bytes,
    });
      return await this.#submitPersisted({
        operationId: id,
        totalStarted,
        telemetryBefore,
        verifiedLocalVmEvidence,
      });
    } catch (error) {
      const journalRecord = this.#journal.record(id);
      const definitelyPreSend = journalRecord === null || (
        journalRecord.state === 'attempted'
        && [
          'ADMISSION_BEFORE_SEND_FAILED',
          'ADMISSION_MEMPOOL_FAILED',
          'ADMISSION_MEMPOOL_REJECTED',
        ].includes(error?.code)
      );
      if (definitelyPreSend) {
        const reason = 'action-failed-before-network-send';
        try {
          this.#abortDefinitelyPreSend({ operationId: id, kind, reason, reserved });
        } catch (recoveryError) {
          fail(
            'BETA_PRE_SEND_ABORT_FAILED',
            `the action failed before network send, but scoped local rollback failed after ${error?.code ?? error?.name ?? 'an error'}`,
            { cause: recoveryError, recoverable: true },
          );
        }
      }
      throw error;
    }
  }

  #abortDefinitelyPreSend({ operationId: id, kind, reason, reserved }) {
    const journalMarker = this.#journal.markSafePreSendAbort({ operationId: id, kind, reason });
    if (this.#journal.record(id) !== null) fail('BETA_PRE_SEND_ABORT_DISAGREEMENT', 'safe pre-send abort has a delivery record');
    if (reserved) this.#store.markSafePreSendAbort({ operationId: id, kind, reason });
    try {
      this.#wallet.abortSafePreSendAction({ operationId: id, kind, reason });
    } catch (walletError) {
      if (!reserved && walletError?.code === 'ACTION_NOTE_UNKNOWN') {
        this.#wallet.markChangeOrphanRecoverable({ operationId: id, reason });
      } else throw walletError;
    }
    if (this.#dependencies.afterSafePreSendWalletAbort !== undefined) {
      this.#dependencies.afterSafePreSendWalletAbort(journalMarker);
    }
    if (reserved) this.#store.finalizeSafePreSendAbort({ operationId: id, kind, reason });
  }

  #recoverSafePreSendAbort(id) {
    const journalMarker = this.#journal.safePreSendAbortMarker(id);
    const storeMarker = this.#store.safePreSendAbortMarker(id);
    if (journalMarker === null) {
      if (storeMarker !== null) fail('BETA_PRE_SEND_ABORT_DISAGREEMENT', 'store pre-send abort marker has no matching journal marker');
      return false;
    }
    if (this.#journal.record(id) !== null) fail('BETA_PRE_SEND_ABORT_DISAGREEMENT', 'safe pre-send abort marker conflicts with a delivery record');
    if (storeMarker !== null && (storeMarker.kind !== journalMarker.kind || storeMarker.reason !== journalMarker.reason)) {
      fail('BETA_PRE_SEND_ABORT_DISAGREEMENT', 'store and journal pre-send abort markers differ');
    }
    if (storeMarker === null) this.#store.markSafePreSendAbort(journalMarker);
    this.#wallet.abortSafePreSendAction(journalMarker);
    this.#store.finalizeSafePreSendAbort(journalMarker);
    return true;
  }

  async #submitPersisted({
    operationId: id,
    exactRebroadcast = undefined,
    totalStarted = now(),
    telemetryBefore = storeTelemetry(this.#store, 'pre-reconciliation'),
    verifiedLocalVmEvidence = undefined,
  }) {
    const staged = this.#store.stagedOperation(id);
    if (staged === null) {
      fail('BETA_STAGED_ACTION_REQUIRED', 'no exact staged action exists');
    }
    const { value: artifact, transaction } = parseArtifact(
      staged.transactionArtifact,
    );
    // Reject a persisted containment tamper before local admission preparation,
    // network observation, or any store/wallet commit can consume the artifact.
    const proofContainment = validateV2BetaPersistedProofContainment(
      artifact.proofContainment,
    );
    if (
      artifact.operationId !== id
      || artifact.profileId !== this.#identity.profileId
      || artifact.instanceId !== this.#identity.instanceId
      || artifact.packetHex !== staged.packet.toString('hex')
    ) {
      fail(
        'BETA_ACTION_ARTIFACT_REJECTED',
        'persisted action identity differs from incremental store state',
      );
    }
    const packet = decodeActionPacket(staged.packet, {
      denominationSats: this.#identity.denominationSats,
    });
    if (
      packet.kind !== artifact.kind
      || packet.networkId !== 2
      || packet.instanceId !== this.#identity.instanceId
      || artifact.expectedState?.category !== this.#identity.instanceId
      || artifact.expectedState?.capability !== 'mutable'
      || artifact.expectedState?.tokenAmount !== '0'
      || typeof artifact.expectedState?.commitment !== 'string'
      || !/^[0-9a-f]{256}$/u.test(artifact.expectedState.commitment)
      || typeof artifact.expectedState?.valueSatoshis !== 'string'
      || !DECIMAL.test(artifact.expectedState.valueSatoshis)
      || artifact.expectedState?.valueSatoshis !== outputValueSats(transaction.outputs[0])
      || !encodeStateNftCommitment(packet.preState, {
        denominationSats: this.#identity.denominationSats,
      }).equals(staged.expectedTip.state)
      || encodeStateNftCommitment(packet.postState, {
        denominationSats: this.#identity.denominationSats,
      }).toString('hex') !== artifact.expectedState?.commitment
    ) {
      fail(
        'BETA_ACTION_ARTIFACT_REJECTED',
        'persisted packet does not bind the exact operation, accepted pre-state, and expected successor',
      );
    }
    const change = inspectChange(artifact.change, transaction);
    const outputNote = inspectOutputNote(artifact.outputNote, artifact.kind);
    inspectFundingArtifact(artifact.funding, staged, transaction);
    const proof = inspectProofArtifact(staged.proofArtifact, {
      actionArtifact: artifact,
      nativeProverSha256: this.#nativeProverSha256,
      packet: staged.packet,
      runtime: this.#runtime,
    });
    const localVmEvidence = verifiedLocalVmEvidence === undefined
      ? Buffer.from(artifact.localVmEvidenceHex, 'hex')
      : verifiedLocalVmEvidence;
    if (!(localVmEvidence instanceof Uint8Array)
      || Buffer.from(localVmEvidence).toString('hex') !== artifact.localVmEvidenceHex) {
      fail(
        'BETA_ACTION_ARTIFACT_REJECTED',
        'process-local VM evidence capability differs from the immutable transaction artifact',
      );
    }
    let depositMaterial = null;
    if (artifact.kind === 'deposit') {
      depositMaterial = this.#wallet.stageDepositNote({
        operationId: id,
        postActionSequence: packet.postState.actionSequence,
      }).privateStoreMaterial;
      if (
        depositMaterial.noteId !== outputNote.noteId
        || depositMaterial.recordId !== outputNote.recordId
        || !Buffer.from(depositMaterial.encryptedRecord).equals(packet.encryptedRecord)
      ) {
        fail(
          'BETA_DEPOSIT_PRIVATE_BINDING_REJECTED',
          'private staged deposit material differs from the public packet and immutable artifact',
        );
      }
      this.#store.putEncryptedRecord({
        recordId: depositMaterial.recordId,
        record: depositMaterial.encryptedRecord,
      });
    }
    const admissionInput = {
      rpc: this.#rpc,
      journal: this.#journal,
      rawTransactionHex: artifact.rawTransactionHex,
      carrierCount: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length,
      localVmEvidence,
      expectedState: artifact.expectedState,
      operationId: id,
      crashAt: null,
    };
    const prior = this.#journal.record(id);
    const admissionObservationBefore = observedRpc(
      observeLayer1BchnChipnetRpc(this.#rpc),
      'pre-admission BCHN observation',
    );
    const admissionStarted = now();
    let admission;
    try {
      if (prior === null) {
        admission = await this.#dependencies.submitAdmission(
          admissionInput,
          {
            beforeSendAttempt: async () => {
              this.#wallet.markActionSendAttempt({
                operationId: id,
                kind: artifact.kind,
              });
            },
          },
        );
      } else if (exactRebroadcast !== undefined) {
        admission = await this.#dependencies.rebroadcastAdmission(
          admissionInput,
          exactRebroadcast,
        );
      } else {
        admission = await this.#dependencies.reconcileAdmission(admissionInput);
      }
    } catch (error) {
      const record = this.#journal.record(id);
      if (record?.state === 'indeterminate') {
        try {
          this.#wallet.markActionIndeterminate({
            operationId: id,
            kind: artifact.kind,
          });
        } catch (walletError) {
          fail(
            'BETA_WALLET_INDETERMINATE_FAILED',
            'delivery is indeterminate and wallet state could not be marked safely',
            { cause: walletError, recoverable: true },
          );
        }
      }
      throw error;
    }
    const admissionMs = elapsed(admissionStarted);
    inspectAdmissionResult(admission, {
      expectedState: artifact.expectedState,
      journal: this.#journal,
      operation: id,
      rpc: this.#rpc,
      transaction,
    });
    const admissionObservation = prior === null
      ? assertOneShotAdmissionObservation(
        admissionObservationBefore,
        observeLayer1BchnChipnetRpc(this.#rpc),
      )
      : observedRpc(observeLayer1BchnChipnetRpc(this.#rpc), 'post-admission BCHN observation');

    const commitStarted = now();
    if (staged.state !== 'accepted_zero_conf') {
      this.#store.applyAcceptedZeroConfSuccessor({
        operationId: id,
        successor: {
          txid: Buffer.from(artifact.transactionId, 'hex'),
          vout: 0,
          acceptanceId: Buffer.from(admission.journal.metadataHash, 'hex'),
        },
        change: {
          txid: Buffer.from(change.txid, 'hex'),
          vout: change.vout,
          valueSats: change.valueSats,
        },
        ownedOutputNoteId: outputNote?.noteId ?? null,
        ownedOutputRecordId: outputNote?.recordId ?? null,
        ownedOutputNullifier: outputNote === null
          ? null
          : Buffer.from(depositMaterial.nullifier, 'hex'),
      });
    }
    this.#wallet.attachChangeWallet({
      operationId: id,
      txid: artifact.transactionId,
      vout: change.vout,
      valueSats: change.valueSats,
      acceptedCommit: true,
    });
    if (artifact.kind === 'deposit') {
      this.#wallet.attachAcceptedDeposit({
        operationId: id,
        noteIndex: Number(packet.preState.noteCount),
        txid: artifact.transactionId,
        acceptedCommit: true,
      });
    } else {
      this.#wallet.commitAcceptedWithdrawalSpend({
        operationId: id,
        txid: artifact.transactionId,
        acceptedCommit: true,
      });
    }
    this.#store.markLocalWalletCommitComplete({
      operationId: id,
      transactionId: Buffer.from(artifact.transactionId, 'hex'),
      transactionArtifactSha256: staged.transactionArtifactSha256,
    });
    const commitMs = elapsed(commitStarted);
    const vm = inspectV2LocalVmEvidence(localVmEvidence);
    const telemetryAfter = storeTelemetry(this.#store, 'post-action');
    const proofWork = proofTelemetry(proof, proofContainment);
    const telemetry = Object.freeze({
      schema: V2_BETA_PRODUCT_ACTION_TELEMETRY_SCHEMA,
      proof: proofWork,
      vm: projectV2LocalVmEvidenceTelemetry(localVmEvidence),
      store: Object.freeze({
        pre: telemetryBefore,
        post: telemetryAfter,
        delta: storeTelemetryDelta(telemetryBefore, telemetryAfter),
      }),
    });
    return Object.freeze({
      schema: V2_BETA_PRODUCT_ACTION_RESULT_SCHEMA,
      status: 'accepted-zero-conf-beta-unqualified',
      operationId: id,
      kind: artifact.kind,
      transactionId: artifact.transactionId,
      claims: claims(),
      cache: Object.freeze({
        runtimeManifestSha256: this.#runtime.runtimeManifestSha256,
        runtimeMaterialSha256: this.#runtime.runtimeMaterialSha256,
      }),
      proof: Object.freeze({
        resultSha256: artifact.proofResultSha256,
        verified: true,
        nativeBackend: proof.nativeProver.backend,
        nativeProverSha256: proof.nativeProver.sha256,
        ompThreads: proof.nativeProver.ompThreads,
        observedThreads: proof.nativeProver.threads,
        peakRssKiB: proof.nativeProver.peakRssKiB,
        userCpuTicks: proofWork.userTicks,
        systemCpuTicks: proofWork.systemTicks,
        totalCpuTicks: proofWork.totalTicks,
        cpuTicksPerWallMillisecond: proofWork.cpuTicksPerWallMillisecond,
        activeCpuThreads: proofWork.activeCpuThreads,
        containment: proofWork.containment,
      }),
      vm: Object.freeze({
        evidenceHash: vm.evidenceHash,
        acceptedInputCount: vm.inputs.length,
        inputCount: vm.transaction.inputCount,
        allInputsAccepted: vm.allInputsAccepted,
      }),
      telemetry,
      transaction: Object.freeze({
        bytes: transaction.sizeBytes,
        feeSats: artifact.measurements.feeSats,
        feeRateSatsPerByte: artifact.measurements.feeRateSatsPerByte,
        changeVout: change.vout,
        changeValueSats: change.valueSats,
      }),
      readback: admission.readback,
      rpcObservation: admissionObservation,
      timingsMs: Object.freeze({
        ...artifact.timingsMs,
        admission: admissionMs,
        commit: commitMs,
        total: elapsed(totalStarted),
      }),
    });
  }

  #assertPersistedIntent(staged, {
    expectedKind,
    expectedNoteId,
    expectedWithdrawalLockingBytecodeHash,
  }) {
    if (expectedKind !== undefined && staged.kind !== expectedKind) {
      fail(
        'BETA_ACTION_RECOVERY_INTENT_MISMATCH',
        `persisted operation ${staged.operationId} is ${staged.kind}, not ${expectedKind}`,
        { recoverable: true },
      );
    }
    if (
      expectedNoteId !== undefined
      && staged.resources.selectedNoteId !== expectedNoteId
    ) {
      fail(
        'BETA_ACTION_RECOVERY_INTENT_MISMATCH',
        `persisted operation ${staged.operationId} selects another note`,
        { recoverable: true },
      );
    }
    if (expectedWithdrawalLockingBytecodeHash !== undefined) {
      const packet = decodeActionPacket(staged.packet, {
        denominationSats: this.#identity.denominationSats,
      });
      if (
        staged.kind !== 'withdrawal'
        || packet.withdrawalLockingBytecodeHash
          !== expectedWithdrawalLockingBytecodeHash
      ) {
        fail(
          'BETA_ACTION_RECOVERY_INTENT_MISMATCH',
          `persisted operation ${staged.operationId} pays another withdrawal destination`,
          { recoverable: true },
        );
      }
    }
    return staged;
  }

  async resume(options = {}) {
    exactOptional(
      options,
      [
        'expectedKind', 'expectedNoteId',
        'expectedWithdrawalLockingBytecodeHash', 'operationId',
      ],
      ['operationId'],
      'beta action resume options',
    );
    const id = operationId(options.operationId);
    const expectedKind = options.expectedKind;
    if (expectedKind !== undefined && !['deposit', 'withdrawal'].includes(expectedKind)) {
      fail('BETA_ACTION_RECOVERY_KIND_INVALID', 'expectedKind must be deposit or withdrawal');
    }
    const expectedNoteId = options.expectedNoteId === undefined
      ? undefined : hash(options.expectedNoteId, 'expectedNoteId');
    const expectedWithdrawalLockingBytecodeHash =
      options.expectedWithdrawalLockingBytecodeHash === undefined
        ? undefined
        : hash(
          options.expectedWithdrawalLockingBytecodeHash,
          'expectedWithdrawalLockingBytecodeHash',
        );
    if (
      (expectedNoteId !== undefined
        || expectedWithdrawalLockingBytecodeHash !== undefined)
      && expectedKind !== 'withdrawal'
    ) {
      fail('BETA_ACTION_RECOVERY_KIND_INVALID', 'withdrawal intent may only accompany expectedKind withdrawal');
    }
    if (this.#recoverSafePreSendAbort(id)) {
      fail('BETA_ACTION_ABORTED_PRE_SEND', 'the exact operation was durably aborted before any network send', { recoverable: true });
    }
    const staged = this.#store.stagedOperation(id);
    if (staged === null) {
      fail(
        'BETA_STAGED_ACTION_REQUIRED',
        'only an immutable staged or accepted beta action can be resumed',
      );
    }
    this.#assertPersistedIntent(staged, {
      expectedKind,
      expectedNoteId,
      expectedWithdrawalLockingBytecodeHash,
    });
    return this.#submitPersisted({ operationId: id });
  }

  /**
   * Explicit exact-byte recovery. Ordinary resume remains read-only for every
   * claimed delivery; this path exists only for a user-acknowledged CAS token.
   */
  async rebroadcast(options = {}) {
    exactOptional(
      options,
      [
        'acknowledgedExactRebroadcast', 'expectedKind', 'expectedNoteId',
        'expectedWithdrawalLockingBytecodeHash', 'operationId',
        'priorAttemptToken',
      ],
      ['acknowledgedExactRebroadcast', 'operationId', 'priorAttemptToken'],
      'beta exact rebroadcast options',
    );
    if (options.acknowledgedExactRebroadcast !== true) {
      fail(
        'BETA_EXACT_REBROADCAST_ACK_REQUIRED',
        'exact rebroadcast requires explicit acknowledgement',
        { recoverable: true },
      );
    }
    if (typeof options.priorAttemptToken !== 'string'
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u
        .test(options.priorAttemptToken)) {
      fail(
        'BETA_EXACT_REBROADCAST_TOKEN_INVALID',
        'exact rebroadcast requires the current delivery attempt token',
        { recoverable: true },
      );
    }
    const id = operationId(options.operationId);
    const expectedKind = options.expectedKind;
    if (expectedKind !== undefined && !['deposit', 'withdrawal'].includes(expectedKind)) {
      fail('BETA_ACTION_RECOVERY_KIND_INVALID', 'expectedKind must be deposit or withdrawal');
    }
    const expectedNoteId = options.expectedNoteId === undefined
      ? undefined : hash(options.expectedNoteId, 'expectedNoteId');
    const expectedWithdrawalLockingBytecodeHash =
      options.expectedWithdrawalLockingBytecodeHash === undefined
        ? undefined
        : hash(
          options.expectedWithdrawalLockingBytecodeHash,
          'expectedWithdrawalLockingBytecodeHash',
        );
    if ((expectedNoteId !== undefined
      || expectedWithdrawalLockingBytecodeHash !== undefined)
      && expectedKind !== 'withdrawal') {
      fail('BETA_ACTION_RECOVERY_KIND_INVALID', 'withdrawal intent may only accompany expectedKind withdrawal');
    }
    if (this.#recoverSafePreSendAbort(id)) {
      fail('BETA_ACTION_ABORTED_PRE_SEND', 'the exact operation was durably aborted before any network send', { recoverable: true });
    }
    const staged = this.#store.stagedOperation(id);
    if (staged === null) {
      fail('BETA_STAGED_ACTION_REQUIRED', 'only an immutable staged beta action can be explicitly rebroadcast');
    }
    this.#assertPersistedIntent(staged, {
      expectedKind,
      expectedNoteId,
      expectedWithdrawalLockingBytecodeHash,
    });
    const delivery = this.#journal.record(id);
    if (delivery === null || !['attempted', 'indeterminate'].includes(delivery.state)) {
      fail(
        'BETA_EXACT_REBROADCAST_NOT_REQUIRED',
        `operation ${id} has no unresolved delivery claim`,
        { recoverable: true },
      );
    }
    if (delivery.attemptToken !== options.priorAttemptToken) {
      fail(
        'BETA_EXACT_REBROADCAST_TOKEN_STALE',
        'delivery attempt token changed; inspect current state before retrying',
        { recoverable: true },
      );
    }
    return this.#submitPersisted({
      operationId: id,
      exactRebroadcast: Object.freeze({
        acknowledgedExactRebroadcast: true,
        priorAttemptToken: options.priorAttemptToken,
      }),
    });
  }

  /** Secret-free, read-only discovery for the CAS token required by recovery. */
  recoveryStatus(options = {}) {
    exactOptional(
      options,
      ['operationId'],
      ['operationId'],
      'beta recovery status options',
    );
    const id = operationId(options.operationId);
    const active = this.#store.activeOperation();
    const staged = this.#store.stagedOperation(id);
    const delivery = this.#journal.record(id);
    const aborted = this.#journal.safePreSendAbortMarker(id);
    const activeForOperation = active?.operationId === id ? active : null;
    const exactRebroadcastAvailable = staged !== null
      && delivery !== null
      && ['attempted', 'indeterminate'].includes(delivery.state);
    return Object.freeze({
      schema: V2_BETA_PRODUCT_RECOVERY_STATUS_SCHEMA,
      operationId: id,
      kind: staged?.kind ?? activeForOperation?.kind ?? aborted?.kind ?? null,
      localState: activeForOperation?.state ?? null,
      safePreSendAborted: aborted !== null,
      staged: staged !== null,
      delivery: delivery === null ? null : Object.freeze({
        state: delivery.state,
        txid: delivery.txid,
        attemptToken: delivery.attemptToken,
        attemptCount: delivery.attemptCount,
      }),
      exactRebroadcastAvailable,
      claims: claims(),
    });
  }

  /**
   * Command-start recovery. Only a reservation with no delivery record is
   * provably pre-send; every staged/accepted or delivery-claimed operation is
   * routed through the immutable-artifact reconciliation path.
   */
  async recoverOrResumeActive(options = {}) {
    exactOptional(
      options,
      [
        'expectedKind', 'expectedNoteId', 'expectedOperationId',
        'expectedWithdrawalLockingBytecodeHash',
      ],
      [],
      'beta active action recovery options',
    );
    const expectedKind = options.expectedKind;
    if (expectedKind !== undefined && !['deposit', 'withdrawal'].includes(expectedKind)) {
      fail('BETA_ACTION_RECOVERY_KIND_INVALID', 'expectedKind must be deposit or withdrawal');
    }
    const expectedOperationId = options.expectedOperationId === undefined
      ? undefined : operationId(options.expectedOperationId);
    const expectedNoteId = options.expectedNoteId === undefined
      ? undefined : hash(options.expectedNoteId, 'expectedNoteId');
    const expectedWithdrawalLockingBytecodeHash =
      options.expectedWithdrawalLockingBytecodeHash === undefined
        ? undefined
        : hash(
          options.expectedWithdrawalLockingBytecodeHash,
          'expectedWithdrawalLockingBytecodeHash',
        );
    if (
      (expectedNoteId !== undefined
        || expectedWithdrawalLockingBytecodeHash !== undefined)
      && expectedKind !== 'withdrawal'
    ) {
      fail('BETA_ACTION_RECOVERY_KIND_INVALID', 'withdrawal intent may only accompany expectedKind withdrawal');
    }
    const active = this.#store.activeOperation();
    if (active === null) return null;
    const id = operationId(active.operationId);
    if (expectedOperationId !== undefined && id !== expectedOperationId) {
      fail(
        'BETA_ACTION_RECOVERY_ID_MISMATCH',
        `active operation ${id} differs from requested operation ${expectedOperationId}`,
        { recoverable: true },
      );
    }
    if (expectedKind !== undefined && active.kind !== expectedKind) {
      fail(
        'BETA_ACTION_RECOVERY_KIND_MISMATCH',
        `active operation ${id} is ${active.kind}; recover it with ${active.kind} before starting ${expectedKind}`,
        { recoverable: true },
      );
    }
    if (expectedNoteId !== undefined && active.selectedNoteId !== expectedNoteId) {
      fail(
        'BETA_ACTION_RECOVERY_INTENT_MISMATCH',
        `active operation ${id} selects another note`,
        { recoverable: true },
      );
    }
    if (this.#recoverSafePreSendAbort(id)) return null;
    const delivery = this.#journal.record(id);
    if (active.state === 'reserved') {
      if (delivery !== null) {
        fail(
          'BETA_ACTION_RECOVERY_RECONCILIATION_REQUIRED',
          `active operation ${id} has delivery state ${delivery.state} but no immutable staged artifact; inspect it read-only`,
          { recoverable: true },
        );
      }
      if (this.#store.stagedOperation(id) !== null) {
        fail('BETA_ACTION_RECOVERY_STATE_REJECTED', `active operation ${id} is reserved but has staged artifacts`);
      }
      this.#abortDefinitelyPreSend({
        operationId: id,
        kind: active.kind,
        reason: 'command-start-recovery-before-network-send',
        reserved: true,
      });
      return null;
    }
    if (!['staged', 'accepted_zero_conf'].includes(active.state)) {
      fail('BETA_ACTION_RECOVERY_STATE_REJECTED', `active operation ${id} is in unsupported state ${active.state}`);
    }
    const staged = this.#store.stagedOperation(id);
    if (staged === null || staged.kind !== active.kind) {
      fail('BETA_ACTION_RECOVERY_STATE_REJECTED', `active operation ${id} lacks its exact immutable ${active.kind} artifact`);
    }
    this.#assertPersistedIntent(staged, {
      expectedKind,
      expectedNoteId,
      expectedWithdrawalLockingBytecodeHash,
    });
    // #submitPersisted observes any delivery claim and chooses reconciliation
    // rather than a new send. This includes attempted and indeterminate rows.
    return this.#submitPersisted({ operationId: id });
  }
}

export async function createV2BetaProductActionLifecycle(
  options,
  ...forbiddenDependencies
) {
  if (forbiddenDependencies.length !== 0) {
    fail(
      'BETA_ACTION_INJECTION_REJECTED',
      'production lifecycle construction accepts exactly one options object',
    );
  }
  exact(options, [
    'journal', 'nativeProverInstallation', 'profileCore',
    'proofWorkspaceDirectory', 'rpc', 'runtimeCache', 'store', 'wallet',
  ], 'beta product action lifecycle options');
  const installedNativeProver = await consumeV2NativeGroth16ProverInstallation(
    options.nativeProverInstallation,
  );
  return new V2BetaProductActionLifecycle(
    options,
    undefined,
    PRODUCTION_FACTORY,
    installedNativeProver,
  );
}

/** Explicit test-only seam; it is never selected by production construction. */
export function createV2BetaProductActionLifecycleForTest(
  options,
  injectedDependencies,
) {
  return new V2BetaProductActionLifecycle(
    options,
    injectedDependencies,
    TEST_DEPENDENCY_FACTORY,
  );
}
