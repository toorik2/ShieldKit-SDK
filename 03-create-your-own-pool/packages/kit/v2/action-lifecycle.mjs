import { createHash } from 'node:crypto';
import { lstat, realpath } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';

import {
  secp256k1,
} from '@bitauth/libauth';

import {
  assembleV2DirectSettlement,
  prepareV2DirectSettlement,
  signV2DirectSettlement,
} from '../../action/v2/settlement.mjs';
import {
  decodeDirectV2Address,
} from '../../action/v2/address.mjs';
import {
  validateDirectV2OutputConstruction,
} from '../../action/v2/notes.mjs';
import {
  buildDirectV2CircuitInput,
} from '../../action/v2/circuit-witness.mjs';
import {
  decodeStateNftCommitment,
} from '../../action/v2/state.mjs';
import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
} from '../../action/v2/topology.mjs';
import {
  canonicalizeJcs,
  deriveProfileId,
  validateProfileCore,
} from '../../profile/v2/profile-core.mjs';
import {
  deriveV2Pf10RuntimeFromValidatedDescriptor,
  deriveV2Pf10StoreRuntimeMaterialsSha256,
  deriveV2SettlementPinsFromValidatedDescriptor,
} from '../../profile/v2/instance-descriptor.mjs';
import {
  proveV2DirectGroth16Default,
} from '../../prove/v2/groth16-proof-worker.mjs';
import {
  V2_GROTH16_PROOF_RESULT_SCHEMA,
} from '../../prove/v2/groth16-proof-child.mjs';
import {
  assertRequiredCgroupLimits,
} from '../../prove/v2/linux-cgroup-v2-worker.mjs';
import {
  buildDirectV2Pf10ActionWitness,
  DIRECT_V2_PF10_STATE_UNLOCK_BYTES,
  DIRECT_V2_PF10_VERIFIER_UNLOCK_BYTES,
} from '../../unlock-builder/v2/pf10-action-witness.mjs';
import {
  broadcastAction as mandatoryBroadcastAction,
  createV2SignedBroadcastMetadata,
  rebroadcastExactAction as mandatoryRebroadcastExactAction,
  reconcileObservedAction as mandatoryReconcileObservedAction,
} from './network-gate.mjs';
import {
  createV2LocalVmEvidence,
  inspectV2LocalVmEvidence,
  V2_VM_PROFILE,
} from './vm-evidence.mjs';
import {
  parseV2RawTransaction,
} from './transaction-policy.mjs';
import {
  validateV2ChipnetFundingWallet,
} from './funding-wallet.mjs';
import {
  assertV2PrivateActionStore,
} from './private-action-store.mjs';
import {
  commitV2PrivateActionMaterial,
} from './private-action-commitment.mjs';
import {
  V2_ACTION_LIFECYCLE_CRASH_STAGES,
  V2ActionLifecycleCrash,
} from './action-lifecycle-crash.mjs';

export {
  commitV2PrivateActionMaterial,
} from './private-action-commitment.mjs';
export {
  V2_ACTION_LIFECYCLE_CRASH_STAGES,
  V2ActionLifecycleCrash,
} from './action-lifecycle-crash.mjs';

export const V2_ACTION_LIFECYCLE_SCHEMA =
  'shieldkit-v2-direct-action-lifecycle-v1';
export const V2_OPERATION_PROOF_RECORD_SCHEMA =
  'shieldkit-v2-direct-operation-proof-v1';
export const V2_ACTION_PREFLIGHT_SCHEMA =
  'shieldkit-v2-direct-action-preflight-v1';
export const V2_HIGH_FEE_SIGNING_CONFIRMATION_SCHEMA =
  'shieldkit/v2-high-fee-signing-confirmation/v1';
export const V2_HIGH_FEE_SIGNING_ACKNOWLEDGEMENT =
  'authorize-fee-above-10-sat-per-byte';

const OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const HASH = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_U128 = (1n << 128n) - 1n;
const PROOF_ARTIFACT_NAMES = Object.freeze([
  'provingKey',
  'r1cs',
  'verificationKey',
  'wasm',
]);
const PROOF_TIMINGS = Object.freeze([
  'proofGeneration',
  'proofVerification',
  'total',
  'witnessCalculation',
  'witnessCheck',
]);
const require = createRequire(import.meta.url);
const LIBAUTH_VERSION = require('@bitauth/libauth/package.json').version;

export class V2ActionLifecycleError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined
      ? undefined
      : { cause: options.cause });
    this.name = 'V2ActionLifecycleError';
    this.code = code;
    this.recoverable = options?.recoverable === true;
  }
}

const fail = (code, message, options) => {
  throw new V2ActionLifecycleError(code, message, options);
};

function plain(value, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('INVALID_LIFECYCLE_INPUT', `${label} must be a plain object`);
  }
  return value;
}

function exact(value, keys, label) {
  plain(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    fail(
      'INVALID_LIFECYCLE_INPUT',
      `${label} has missing or unknown properties`,
    );
  }
  return value;
}

function operationId(value) {
  if (typeof value !== 'string' || !OPERATION_ID.test(value)) {
    fail(
      'INVALID_OPERATION_ID',
      'operationId must be 1 through 128 canonical identifier characters',
    );
  }
  return value;
}

async function assertPrivateProofWorkspace(directory) {
  const parsed = path.parse(directory);
  const components = path.relative(parsed.root, directory)
    .split(path.sep)
    .filter((component) => component.length !== 0);
  let current = parsed.root;
  for (const component of components) {
    current = path.join(current, component);
    let metadata;
    try {
      metadata = await lstat(current);
    } catch (error) {
      fail(
        'PROOF_WORKSPACE_UNSAFE',
        'proof workspace ancestry must already exist',
        { cause: error },
      );
    }
    if (
      metadata.isSymbolicLink()
      || !metadata.isDirectory()
      || (metadata.mode & 0o022) !== 0
    ) {
      fail(
        'PROOF_WORKSPACE_UNSAFE',
        'proof workspace ancestry must contain only non-writable non-symlink directories',
      );
    }
    if (
      current === directory
      && (
        (metadata.mode & 0o077) !== 0
        || (
          typeof process.getuid === 'function'
          && metadata.uid !== process.getuid()
        )
      )
    ) {
      fail(
        'PROOF_WORKSPACE_UNSAFE',
        'proof workspace must be current-user-owned with mode 0700 or stricter',
      );
    }
  }
  let resolved;
  try {
    resolved = await realpath(directory);
  } catch (error) {
    fail(
      'PROOF_WORKSPACE_UNSAFE',
      'proof workspace canonical path cannot be resolved',
      { cause: error },
    );
  }
  if (resolved !== directory) {
    fail(
      'PROOF_WORKSPACE_UNSAFE',
      'proof workspace must not resolve through a symlink or path alias',
    );
  }
  return directory;
}

function hex32(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail('INVALID_LIFECYCLE_INPUT', `${label} must be lowercase 32-byte hex`);
  }
  return value;
}

function bytes(value, length, label) {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    fail(
      'INVALID_LIFECYCLE_INPUT',
      `${label} must contain exactly ${length} bytes`,
    );
  }
  return Buffer.from(value);
}

function same(left, right) {
  return Buffer.from(left).equals(Buffer.from(right));
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalBytes(value) {
  return Buffer.from(canonicalizeJcs(value), 'utf8');
}

function freezeJson(value) {
  if (Array.isArray(value)) {
    value.forEach(freezeJson);
    return Object.freeze(value);
  }
  if (
    value !== null
    && typeof value === 'object'
    && Object.getPrototypeOf(value) === Object.prototype
  ) {
    Object.values(value).forEach(freezeJson);
    return Object.freeze(value);
  }
  return value;
}

function crash(requested, stage) {
  if (requested === stage) throw new V2ActionLifecycleCrash(stage);
}

function crashStage(value, prefix) {
  if (
    value !== null
    && (
      typeof value !== 'string'
      || !V2_ACTION_LIFECYCLE_CRASH_STAGES.includes(value)
      || !value.startsWith(`${prefix}.`)
    )
  ) {
    fail(
      'INVALID_CRASH_STAGE',
      `crashAt must be null or a supported ${prefix} stage`,
    );
  }
  return value;
}

function requireStore(value) {
  const methods = [
    'abandonOperation',
    'applyConfirmed',
    'assertBinding',
    'authorizeManualRetry',
    'binding',
    'canonicalState',
    'derivePacketPostState',
    'deriveProvingTransition',
    'operation',
    'prepareAction',
    'rebaseOperation',
    'recordConflictAndMaybeRetry',
    'releaseOperationForCanonicalSync',
    'settleConfirmedOperation',
    'transitionOperation',
    'updateOperationArtifacts',
  ];
  if (
    value === null
    || typeof value !== 'object'
    || methods.some((name) => typeof value[name] !== 'function')
  ) {
    fail(
      'INVALID_STORE',
      'store does not expose the complete V2 durable action interface',
    );
  }
  return value;
}

function normalizeStoreTip(value, label = 'canonical tip') {
  plain(value, label);
  exact(
    value,
    ['actionSequence', 'blockHash', 'height', 'outpoint', 'state'],
    label,
  );
  exact(value.outpoint, ['txid', 'vout'], `${label}.outpoint`);
  const actionSequence = value.actionSequence;
  const height = value.height;
  const vout = value.outpoint.vout;
  if (
    !Number.isSafeInteger(actionSequence)
    || actionSequence < 0
    || !Number.isSafeInteger(height)
    || height < 0
    || !Number.isInteger(vout)
    || vout < 0
    || vout > 0xffff_ffff
  ) {
    fail('INVALID_CANONICAL_TIP', `${label} contains invalid integer fields`);
  }
  return Object.freeze({
    state: bytes(value.state, 128, `${label}.state`),
    outpoint: Object.freeze({
      txid: bytes(value.outpoint.txid, 32, `${label}.outpoint.txid`),
      vout,
    }),
    actionSequence,
    height,
    blockHash: bytes(value.blockHash, 32, `${label}.blockHash`),
  });
}

function tipJson(value) {
  const tip = normalizeStoreTip(value);
  return freezeJson({
    state: tip.state.toString('hex'),
    txid: tip.outpoint.txid.toString('hex'),
    vout: tip.outpoint.vout,
    actionSequence: tip.actionSequence,
    height: tip.height,
    blockHash: tip.blockHash.toString('hex'),
  });
}

function preflightTip(value) {
  exact(
    value,
    ['actionSequence', 'blockHash', 'height', 'state', 'txid', 'vout'],
    'action preflight tip',
  );
  if (
    typeof value.state !== 'string'
    || !/^[0-9a-f]{256}$/.test(value.state)
  ) {
    fail(
      'INVALID_ACTION_PREFLIGHT',
      'action preflight tip.state must be lowercase 128-byte hex',
    );
  }
  return normalizeStoreTip({
    state: Buffer.from(value.state, 'hex'),
    outpoint: {
      txid: Buffer.from(
        hex32(value.txid, 'action preflight tip.txid'),
        'hex',
      ),
      vout: value.vout,
    },
    actionSequence: value.actionSequence,
    height: value.height,
    blockHash: Buffer.from(
      hex32(value.blockHash, 'action preflight tip.blockHash'),
      'hex',
    ),
  }, 'action preflight tip');
}

function sameTip(left, right) {
  return (
    same(left.state, right.state)
    && same(left.outpoint.txid, right.outpoint.txid)
    && left.outpoint.vout === right.outpoint.vout
    && left.actionSequence === right.actionSequence
    && left.height === right.height
    && same(left.blockHash, right.blockHash)
  );
}

function actionPreflight({
  operationId: id,
  kind,
  tip,
  publicValues,
  prepared,
}) {
  const core = {
    schema: V2_ACTION_PREFLIGHT_SCHEMA,
    operationId: id,
    kind,
    tip: tipJson(tip),
    publicValues: {
      outputNoteLeaf: publicValues.outputNoteLeaf?.toString('hex') ?? null,
      encryptedRecordSha256: publicValues.encryptedRecord === null
        ? null
        : sha256(publicValues.encryptedRecord),
      publicNullifier: publicValues.publicNullifier?.toString('hex') ?? null,
    },
    preparedPayloadHash: prepared.payloadHash,
    transactionContextHash: prepared.contextHash,
    measurements: {
      changeSats: prepared.measurements.changeSats,
      dustFloorSats: prepared.measurements.dustFloorSats,
      feeRateSatsPerByte: prepared.measurements.feeRateSatsPerByte,
      feeSats: prepared.measurements.feeSats,
      signedSizeBytes: prepared.measurements.signedSizeBytes,
    },
  };
  return freezeJson({
    ...core,
    preflightSha256: sha256(canonicalBytes(core)),
  });
}

function inspectActionPreflight(value) {
  exact(
    value,
    [
      'kind',
      'measurements',
      'operationId',
      'preflightSha256',
      'preparedPayloadHash',
      'publicValues',
      'schema',
      'tip',
      'transactionContextHash',
    ],
    'action preflight',
  );
  exact(
    value.publicValues,
    ['encryptedRecordSha256', 'outputNoteLeaf', 'publicNullifier'],
    'action preflight public values',
  );
  exact(
    value.measurements,
    [
      'changeSats',
      'dustFloorSats',
      'feeRateSatsPerByte',
      'feeSats',
      'signedSizeBytes',
    ],
    'action preflight measurements',
  );
  const { preflightSha256, ...core } = value;
  const nullableHash = (entry, label) => {
    if (entry !== null) hex32(entry, label);
  };
  nullableHash(
    value.publicValues.outputNoteLeaf,
    'action preflight outputNoteLeaf',
  );
  nullableHash(
    value.publicValues.encryptedRecordSha256,
    'action preflight encryptedRecordSha256',
  );
  nullableHash(
    value.publicValues.publicNullifier,
    'action preflight publicNullifier',
  );
  const canonicalMoney = (entry, label, { nonzero = false } = {}) => {
    if (
      typeof entry !== 'string'
      || !DECIMAL.test(entry)
      || (nonzero && entry === '0')
    ) {
      fail('INVALID_ACTION_PREFLIGHT', `${label} is not canonical money`);
    }
  };
  canonicalMoney(
    value.measurements.changeSats,
    'action preflight changeSats',
  );
  canonicalMoney(
    value.measurements.dustFloorSats,
    'action preflight dustFloorSats',
    { nonzero: true },
  );
  canonicalMoney(
    value.measurements.feeRateSatsPerByte,
    'action preflight feeRateSatsPerByte',
    { nonzero: true },
  );
  canonicalMoney(
    value.measurements.feeSats,
    'action preflight feeSats',
    { nonzero: true },
  );
  if (
    value.schema !== V2_ACTION_PREFLIGHT_SCHEMA
    || !['deposit', 'transfer', 'withdrawal'].includes(value.kind)
    || operationId(value.operationId) !== value.operationId
    || !HASH.test(value.preparedPayloadHash)
    || !HASH.test(value.transactionContextHash)
    || !HASH.test(preflightSha256)
    || !Number.isSafeInteger(value.measurements.signedSizeBytes)
    || value.measurements.signedSizeBytes < 1
    || sha256(canonicalBytes(core)) !== preflightSha256
  ) {
    fail(
      'INVALID_ACTION_PREFLIGHT',
      'action preflight identity, measurements, or commitment is invalid',
    );
  }
  return Object.freeze({
    token: freezeJson(value),
    tip: preflightTip(value.tip),
  });
}

function expectedTip(operation) {
  return normalizeStoreTip({
    state: operation.expectedState,
    outpoint: operation.expectedOutpoint,
    actionSequence: operation.expectedActionSequence,
    height: operation.expectedHeight,
    blockHash: operation.expectedBlockHash,
  }, 'operation expected tip');
}

function assertRuntimeBinding({
  descriptor,
  profileCore,
  runtimeResolution,
  runtimeMaterialsSha256,
  store,
}) {
  const profileId = deriveProfileId(profileCore);
  if (
    descriptor.profileId !== profileId
    || runtimeResolution.schema
      !== 'shieldkit-v2-direct-pf10-runtime-resolution-v1'
    || runtimeResolution.runtimeMaterial.profileId !== profileId
    || runtimeResolution.runtimeMaterial.instanceId !== descriptor.instanceId
    || runtimeResolution.runtimeMaterial.topologyId
      !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
    || runtimeResolution.descriptorSha256 !== descriptor.descriptor.sha256
    || runtimeResolution.manifestSha256 !== descriptor.manifest.sha256
    || runtimeResolution.runtimeMaterial.materialSha256
      !== runtimeMaterialsSha256.toString('hex')
  ) {
    fail(
      'RUNTIME_DESCRIPTOR_MISMATCH',
      'PF10 runtime resolution does not bind the validated profile and descriptor',
    );
  }
  store.assertBinding({
    profileId: Buffer.from(profileId, 'hex'),
    instanceId: Buffer.from(descriptor.instanceId, 'hex'),
    networkId: profileCore.network.id,
    denominationSats: profileCore.denominationSats,
    carrierCount:
      runtimeResolution.runtimeMaterial.verifierRoles.length,
    runtimeMaterialsSha256,
  });
  return profileId;
}

function normalizeContainment(value) {
  exact(
    value,
    ['arguments', 'backend', 'command', 'containment', 'termination'],
    'proof containment',
  );
  if (
    value.backend !== 'linux-systemd-cgroup-v2'
    || typeof value.command !== 'string'
    || value.command.length === 0
    || !Array.isArray(value.arguments)
    || value.arguments.some(
      (entry) => typeof entry !== 'string' || entry.length === 0,
    )
  ) {
    fail(
      'INVALID_PROOF_RECORD',
      'proof containment does not identify the required isolated worker',
    );
  }
  const containment = assertRequiredCgroupLimits(value.containment);
  exact(
    value.termination,
    ['exitCode', 'memoryEvents', 'memoryPeak', 'signal'],
    'proof containment termination',
  );
  exact(
    value.termination.memoryEvents,
    ['oom', 'oomKill'],
    'proof containment termination memoryEvents',
  );
  if (
    value.termination.exitCode !== 0
    || value.termination.signal !== null
    || !DECIMAL.test(value.termination.memoryPeak)
    || !Number.isSafeInteger(value.termination.memoryEvents.oom)
    || value.termination.memoryEvents.oom < containment.memoryEvents.oom
    || !Number.isSafeInteger(value.termination.memoryEvents.oomKill)
    || value.termination.memoryEvents.oomKill
      !== containment.memoryEvents.oomKill
  ) {
    fail(
      'INVALID_PROOF_RECORD',
      'proof containment does not record one successful non-OOM termination',
    );
  }
  return freezeJson(JSON.parse(JSON.stringify(value)));
}

function proofResultCore(value, runtimeMaterial) {
  exact(
    value,
    [
      'claims',
      'inputSha256',
      'proof',
      'publicInputs',
      'resultSha256',
      'schema',
      'sourceHashes',
      'timingsMs',
    ],
    'proof result',
  );
  exact(
    value.claims,
    ['proofVerified', 'singleThread', 'witnessValid'],
    'proof result claims',
  );
  exact(
    value.sourceHashes,
    PROOF_ARTIFACT_NAMES,
    'proof result sourceHashes',
  );
  exact(value.timingsMs, PROOF_TIMINGS, 'proof result timingsMs');
  if (
    value.schema !== V2_GROTH16_PROOF_RESULT_SCHEMA
    || value.claims.proofVerified !== true
    || value.claims.singleThread !== true
    || value.claims.witnessValid !== true
    || value.proof === null
    || Array.isArray(value.proof)
    || typeof value.proof !== 'object'
    || !Array.isArray(value.publicInputs)
    || value.publicInputs.length !== 2
    || value.publicInputs.some(
      (entry) =>
        typeof entry !== 'string'
        || !DECIMAL.test(entry)
        || BigInt(entry) > MAX_U128,
    )
    || !HASH.test(value.inputSha256)
    || !HASH.test(value.resultSha256)
    || PROOF_ARTIFACT_NAMES.some(
      (name) =>
        value.sourceHashes[name]
        !== runtimeMaterial.proofArtifactHashes[name],
    )
    || PROOF_TIMINGS.some(
      (name) =>
        typeof value.timingsMs[name] !== 'number'
        || !Number.isFinite(value.timingsMs[name])
        || value.timingsMs[name] < 0,
    )
  ) {
    fail(
      'INVALID_PROOF_RECORD',
      'stored proof result is not one verified single-thread result from the pinned artifacts',
    );
  }
  const childResult = {
    schema: value.schema,
    proof: value.proof,
    publicInputs: value.publicInputs,
    claims: value.claims,
    sourceHashes: value.sourceHashes,
    inputSha256: value.inputSha256,
    timingsMs: value.timingsMs,
  };
  if (sha256(canonicalBytes(childResult)) !== value.resultSha256) {
    fail(
      'INVALID_PROOF_RECORD',
      'stored proof result hash does not match its canonical worker result',
    );
  }
  return freezeJson(JSON.parse(JSON.stringify(value)));
}

function createProofRecord({
  containment,
  prepared,
  profileSha256,
  proofResult,
  runtimeResolution,
}) {
  const storedProof = proofResultCore({
    schema: proofResult.schema,
    proof: proofResult.proof,
    publicInputs: [...proofResult.publicInputs],
    claims: { ...proofResult.claims },
    sourceHashes: { ...proofResult.sourceHashes },
    inputSha256: proofResult.inputSha256,
    resultSha256: proofResult.resultSha256,
    timingsMs: { ...proofResult.timingsMs },
  }, runtimeResolution.runtimeMaterial);
  const core = {
    schema: V2_OPERATION_PROOF_RECORD_SCHEMA,
    descriptorSha256: runtimeResolution.descriptorSha256,
    manifestSha256: runtimeResolution.manifestSha256,
    profileSha256,
    runtimeArtifactSha256: runtimeResolution.runtimeArtifactSha256,
    runtimeMaterialsSha256:
      runtimeResolution.runtimeMaterial.materialSha256,
    qualificationEvidenceSha256:
      runtimeResolution.qualificationEvidenceSha256,
    prepared,
    proofResult: storedProof,
    containment: normalizeContainment(containment),
  };
  const record = {
    ...core,
    recordSha256: sha256(canonicalBytes(core)),
  };
  return canonicalBytes(record);
}

function inspectProofRecord(bytesValue, {
  profileSha256,
  runtimeResolution,
}) {
  if (!(bytesValue instanceof Uint8Array) || bytesValue.length === 0) {
    fail('PROOF_RECORD_REQUIRED', 'operation proof record is missing');
  }
  const bytesCopy = Buffer.from(bytesValue);
  let parsed;
  try {
    parsed = JSON.parse(bytesCopy.toString('utf8'));
  } catch {
    fail('INVALID_PROOF_RECORD', 'operation proof record is not JSON');
  }
  if (!bytesCopy.equals(canonicalBytes(parsed))) {
    fail(
      'INVALID_PROOF_RECORD',
      'operation proof record is not exact RFC8785/JCS bytes',
    );
  }
  exact(
    parsed,
    [
      'containment',
      'descriptorSha256',
      'manifestSha256',
      'prepared',
      'profileSha256',
      'proofResult',
      'qualificationEvidenceSha256',
      'recordSha256',
      'runtimeArtifactSha256',
      'runtimeMaterialsSha256',
      'schema',
    ],
    'operation proof record',
  );
  const { recordSha256, ...core } = parsed;
  if (
    parsed.schema !== V2_OPERATION_PROOF_RECORD_SCHEMA
    || !HASH.test(recordSha256)
    || sha256(canonicalBytes(core)) !== recordSha256
    || parsed.descriptorSha256 !== runtimeResolution.descriptorSha256
    || parsed.manifestSha256 !== runtimeResolution.manifestSha256
    || parsed.profileSha256 !== profileSha256
    || parsed.runtimeArtifactSha256
      !== runtimeResolution.runtimeArtifactSha256
    || parsed.runtimeMaterialsSha256
      !== runtimeResolution.runtimeMaterial.materialSha256
    || parsed.qualificationEvidenceSha256
      !== runtimeResolution.qualificationEvidenceSha256
  ) {
    fail(
      'INVALID_PROOF_RECORD',
      'operation proof record identity or canonical commitment is invalid',
    );
  }
  plain(parsed.prepared, 'stored prepared settlement');
  const proofResult = proofResultCore(
    parsed.proofResult,
    runtimeResolution.runtimeMaterial,
  );
  const containment = normalizeContainment(parsed.containment);
  return Object.freeze({
    prepared: freezeJson(parsed.prepared),
    proofResult,
    containment,
    recordSha256,
  });
}

function proofPublicValues(kind, output, publicNullifier) {
  const outputActive = kind === 'deposit' || kind === 'transfer';
  const spendActive = kind === 'transfer' || kind === 'withdrawal';
  if (
    outputActive
      ? (
          output === null
          || typeof output !== 'object'
          || typeof output.public?.outputNoteLeaf !== 'string'
          || !HASH.test(output.public.outputNoteLeaf)
          || !(output.public.encryptedRecord instanceof Uint8Array)
          || output.public.encryptedRecord.length !== 128
        )
      : output !== null
  ) {
    fail(
      'PRIVATE_ACTION_MISMATCH',
      `${kind} output construction presence or public material is invalid`,
    );
  }
  if (
    spendActive
      ? (
          typeof publicNullifier !== 'string'
          || !HASH.test(publicNullifier)
        )
      : publicNullifier !== null
  ) {
    fail(
      'PRIVATE_ACTION_MISMATCH',
      `${kind} public nullifier presence is invalid`,
    );
  }
  return Object.freeze({
    outputNoteLeaf: outputActive
      ? Buffer.from(output.public.outputNoteLeaf, 'hex')
      : null,
    encryptedRecord: outputActive
      ? Buffer.from(output.public.encryptedRecord)
      : null,
    publicNullifier: spendActive
      ? Buffer.from(publicNullifier, 'hex')
      : null,
  });
}

function assertOutputTargetsIntent(
  intent,
  output,
  expectedPostActionSequence = undefined,
) {
  if (intent.kind === 'withdrawal') {
    if (output !== null) {
      fail(
        'PRIVATE_ACTION_MISMATCH',
        'withdrawal cannot contain output note construction material',
      );
    }
    return;
  }
  if (output === null || typeof output !== 'object') {
    fail(
      'PRIVATE_ACTION_MISMATCH',
      `${intent.kind} requires output note construction material`,
    );
  }
  let target;
  try {
    target = decodeDirectV2Address(intent.target.bytes);
  } catch (error) {
    fail(
      'PRIVATE_ACTION_MISMATCH',
      'operation shield target cannot be decoded',
      { cause: error },
    );
  }
  if (
    output.witness?.authority !== target.authority
    || output.witness?.spendPublicKey !== target.spendPublicKey
    || output.witness?.incomingViewPublicKey
      !== target.incomingViewPublicKey
  ) {
    fail(
      'PRIVATE_ACTION_MISMATCH',
      'output note construction does not pay the immutable shield target',
    );
  }
  if (expectedPostActionSequence !== undefined) {
    try {
      validateDirectV2OutputConstruction({
        address: target,
        postActionSequence: String(expectedPostActionSequence),
        output,
      });
    } catch (error) {
      fail(
        'PRIVATE_ACTION_MISMATCH',
        `output construction is not valid for the exact successor sequence: ${
          error instanceof Error ? error.message : String(error)
        }`,
        { cause: error },
      );
    }
  }
}

function exactArtifactSet(operation) {
  const proofArtifacts = [
    operation.packet,
    operation.proof,
    operation.unsignedTx,
  ];
  const count = proofArtifacts.filter((entry) => entry !== null).length;
  if (count !== 0 && count !== proofArtifacts.length) {
    fail(
      'PARTIAL_OPERATION_ARTIFACTS',
      'operation has a partial packet/proof/unsigned artifact set',
    );
  }
  const signedCount = [operation.signedTx, operation.localVmEvidence]
    .filter((entry) => entry !== null).length;
  if (signedCount === 1) {
    fail(
      'PARTIAL_OPERATION_ARTIFACTS',
      'operation has a partial signed transaction/VM evidence set',
    );
  }
  return Object.freeze({
    proved: count === proofArtifacts.length,
    signed: signedCount === 2,
  });
}

function assertOperationRuntime(operation, runtimeMaterialsSha256) {
  if (!same(operation.runtimeMaterialsSha256, runtimeMaterialsSha256)) {
    fail(
      'OPERATION_RUNTIME_MISMATCH',
      'operation runtime material differs from the descriptor-bound store',
    );
  }
  return operation;
}

function makeVmEvidenceProducer(profileId, profileSha256) {
  return async (request) => createV2LocalVmEvidence({
    ...request,
    tool: {
      name: '@bitauth/libauth',
      version: LIBAUTH_VERSION,
      vm: V2_VM_PROFILE,
      profileId,
      profileSha256,
    },
  });
}

function signedFee(record) {
  const fee = record.prepared?.measurements?.feeSats;
  if (typeof fee !== 'string' || !DECIMAL.test(fee)) {
    fail(
      'INVALID_PROOF_RECORD',
      'prepared settlement has no canonical fee measurement',
    );
  }
  return fee;
}

function validatedFundingWallet(value) {
  try {
    return validateV2ChipnetFundingWallet(value);
  } catch (error) {
    fail(
      'FUNDING_WALLET_REQUIRED',
      'fundingWallet must be one validated local Chipnet funding wallet',
      { cause: error },
    );
  }
}

function highFeeSigningCore(id, prepared) {
  plain(prepared, 'prepared settlement');
  plain(prepared.measurements, 'prepared settlement measurements');
  const {
    feeRateSatsPerByte,
    feeSats,
    signedSizeBytes,
  } = prepared.measurements;
  if (
    typeof feeRateSatsPerByte !== 'string'
    || !DECIMAL.test(feeRateSatsPerByte)
    || typeof feeSats !== 'string'
    || !DECIMAL.test(feeSats)
    || !Number.isSafeInteger(signedSizeBytes)
    || signedSizeBytes <= 0
    || signedSizeBytes > 100_000
    || typeof prepared.contextHash !== 'string'
    || !HASH.test(prepared.contextHash)
    || typeof prepared.payloadHash !== 'string'
    || !HASH.test(prepared.payloadHash)
  ) {
    fail(
      'INVALID_PROOF_RECORD',
      'prepared settlement lacks canonical fee-confirmation facts',
    );
  }
  const fee = BigInt(feeSats);
  const rate = BigInt(feeRateSatsPerByte);
  const size = BigInt(signedSizeBytes);
  if (fee !== rate * size) {
    fail(
      'INVALID_PROOF_RECORD',
      'prepared settlement fee does not equal its exact signed size and rate',
    );
  }
  return {
    schema: V2_HIGH_FEE_SIGNING_CONFIRMATION_SCHEMA,
    purpose: V2_HIGH_FEE_SIGNING_ACKNOWLEDGEMENT,
    operationId: operationId(id),
    contextHash: prepared.contextHash,
    preparedPayloadHash: prepared.payloadHash,
    feeRateSatsPerByte,
    feeSats,
    signedSizeBytes,
  };
}

function highFeeSigningConfirmation(id, prepared) {
  const core = highFeeSigningCore(id, prepared);
  if (
    BigInt(core.feeSats)
    <= BigInt(core.signedSizeBytes) * 10n
  ) {
    fail(
      'HIGH_FEE_CONFIRMATION_NOT_REQUIRED',
      'fee does not exceed 10 satoshis per serialized byte',
    );
  }
  return freezeJson({
    ...core,
    confirmationHash: sha256(canonicalBytes(core)),
  });
}

function assertHighFeeSigningConfirmation(
  token,
  id,
  prepared,
) {
  const expectedCore = highFeeSigningCore(id, prepared);
  const highFee =
    BigInt(expectedCore.feeSats)
    > BigInt(expectedCore.signedSizeBytes) * 10n;
  if (!highFee) {
    if (token !== undefined) {
      fail(
        'UNEXPECTED_HIGH_FEE_CONFIRMATION',
        'high-fee confirmation is forbidden at 10 satoshis per byte or below',
      );
    }
    return;
  }
  if (
    token === null
    || typeof token !== 'object'
    || Array.isArray(token)
    || !Object.isFrozen(token)
  ) {
    fail(
      'HIGH_FEE_CONFIRMATION_REQUIRED',
      'signing above 10 satoshis per byte requires an immutable confirmation for this exact proved operation',
    );
  }
  exact(
    token,
    [...Object.keys(expectedCore), 'confirmationHash'],
    'high-fee signing confirmation',
  );
  if (
    canonicalizeJcs(
      Object.fromEntries(
        Object.keys(expectedCore).map((key) => [key, token[key]]),
      ),
    ) !== canonicalizeJcs(expectedCore)
    || token.confirmationHash !== sha256(canonicalBytes(expectedCore))
  ) {
    fail(
      'HIGH_FEE_CONFIRMATION_REQUIRED',
      'high-fee confirmation does not bind this exact proved operation and fee',
    );
  }
}

class V2DirectActionLifecycle {
  #descriptor;
  #fundingPrivateKey;
  #fundingPublicKeyHex;
  #fundingSignerClosed;
  #loadRawTransaction;
  #pins;
  #profileCore;
  #profileId;
  #profileSha256;
  #privateActionStore;
  #proofWorkspaceDirectory;
  #proveGroth16;
  #runtimeMaterialsSha256;
  #runtimeResolution;
  #store;
  #synchronizeCanonicalTip;

  constructor(value) {
    this.#descriptor = value.descriptor;
    this.#fundingPrivateKey = Buffer.from(
      value.fundingWallet.privateKeyHex,
      'hex',
    );
    this.#fundingPublicKeyHex =
      value.fundingWallet.compressedPublicKeyHex;
    this.#fundingSignerClosed = false;
    this.#loadRawTransaction = value.loadRawTransaction;
    this.#pins = value.pins;
    this.#profileCore = value.profileCore;
    this.#profileId = value.profileId;
    this.#profileSha256 = value.profileSha256;
    this.#privateActionStore = value.privateActionStore;
    this.#proofWorkspaceDirectory = value.proofWorkspaceDirectory;
    this.#proveGroth16 = value.proveGroth16;
    this.#runtimeMaterialsSha256 = value.runtimeMaterialsSha256;
    this.#runtimeResolution = value.runtimeResolution;
    this.#store = value.store;
    this.#synchronizeCanonicalTip = value.synchronizeCanonicalTip;
  }

  get identity() {
    return freezeJson({
      schema: V2_ACTION_LIFECYCLE_SCHEMA,
      eligibility: this.#runtimeResolution.eligibility,
      profileId: this.#profileId,
      instanceId: this.#descriptor.instanceId,
      networkId: this.#profileCore.network.id,
      runtimeMaterialsSha256:
        this.#runtimeMaterialsSha256.toString('hex'),
      descriptorSha256: this.#runtimeResolution.descriptorSha256,
      manifestSha256: this.#runtimeResolution.manifestSha256,
    });
  }

  confirmHighFeeSigning({
    operationId: id,
    acknowledgement,
  } = {}) {
    if (acknowledgement !== V2_HIGH_FEE_SIGNING_ACKNOWLEDGEMENT) {
      fail(
        'HIGH_FEE_ACKNOWLEDGEMENT_REQUIRED',
        `acknowledgement must exactly equal ${V2_HIGH_FEE_SIGNING_ACKNOWLEDGEMENT}`,
      );
    }
    const selectedId = operationId(id);
    const operation = this.#operation(selectedId);
    if (operation.journalState !== 'proved') {
      fail(
        'INVALID_OPERATION_STATE',
        `high-fee signing confirmation requires proved, found ${operation.journalState}`,
      );
    }
    const artifacts = exactArtifactSet(operation);
    if (!artifacts.proved || artifacts.signed) {
      fail(
        'PROOF_RECORD_REQUIRED',
        'high-fee signing confirmation requires the complete unsigned proved artifact set',
      );
    }
    const record = inspectProofRecord(operation.proof, {
      profileSha256: this.#profileSha256,
      runtimeResolution: this.#runtimeResolution,
    });
    this.#rebuildAssembled(operation, record);
    return highFeeSigningConfirmation(
      selectedId,
      record.prepared,
    );
  }

  closeFundingSigner() {
    if (!this.#fundingSignerClosed) {
      this.#fundingPrivateKey.fill(0);
      this.#fundingSignerClosed = true;
    }
    return freezeJson({
      closed: true,
      publicKeyHex: this.#fundingPublicKeyHex,
    });
  }

  #operation(id) {
    return assertOperationRuntime(
      this.#store.operation(operationId(id)),
      this.#runtimeMaterialsSha256,
    );
  }

  async #refreshTip({ phase, operationId: id, priorCanonicalTip }) {
    const request = freezeJson({
      phase,
      operationId: id,
      priorCanonicalTip: tipJson(priorCanonicalTip),
    });
    let reported;
    try {
      reported = await this.#synchronizeCanonicalTip(request);
    } catch (error) {
      if (error?.code === 'CANONICAL_TIP_CHANGED') {
        fail(
          'CANONICAL_TIP_CHANGED',
          `canonical tip changed during ${phase}`,
          { cause: error, recoverable: true },
        );
      }
      fail(
        'TIP_SYNCHRONIZATION_FAILED',
        `canonical tip synchronization failed during ${phase}: ${
          error instanceof Error ? error.message : String(error)
        }`,
        { cause: error, recoverable: true },
      );
    }
    const normalizedReported = normalizeStoreTip(
      reported,
      'synchronized canonical tip',
    );
    const current = normalizeStoreTip(
      this.#store.canonicalState(),
      'durable canonical tip',
    );
    if (!sameTip(normalizedReported, current)) {
      fail(
        'TIP_SYNCHRONIZATION_INCONSISTENT',
        'chain synchronization result differs from the durable canonical store tip',
        { recoverable: true },
      );
    }
    return current;
  }

  async #previousBundle(operation) {
    const transactionId = operation.expectedOutpoint.txid.toString('hex');
    let raw;
    try {
      raw = await this.#loadRawTransaction(freezeJson({
        networkId: this.#profileCore.network.id,
        transactionId,
      }));
    } catch (error) {
      fail(
        'SOURCE_TRANSACTION_FETCH_FAILED',
        `unable to load the exact previous rolling bundle: ${
          error instanceof Error ? error.message : String(error)
        }`,
        { cause: error, recoverable: true },
      );
    }
    if (typeof raw !== 'string') {
      fail(
        'SOURCE_TRANSACTION_INVALID',
        'loadRawTransaction must return lowercase raw transaction hex',
      );
    }
    let parsed;
    try {
      parsed = parseV2RawTransaction(raw);
    } catch (error) {
      fail(
        'SOURCE_TRANSACTION_INVALID',
        `previous rolling bundle is invalid: ${
          error instanceof Error ? error.message : String(error)
        }`,
        { cause: error },
      );
    }
    if (parsed.txid !== transactionId) {
      fail(
        'SOURCE_TRANSACTION_MISMATCH',
        'loaded previous rolling bundle does not match the expected state outpoint',
      );
    }
    return parsed.rawTransactionHex;
  }

  #prepareSettlement(operation, postState, previousBundleTransactionHex) {
    const preState = decodeStateNftCommitment(operation.expectedState, {
      denominationSats: this.#profileCore.denominationSats,
    });
    const prepared = prepareV2DirectSettlement({
      changeLockingBytecode: operation.intent.changeLockingBytecode,
      denominationSats: this.#profileCore.denominationSats,
      feeRateSatsPerByte:
        operation.intent.feePolicy.feeRateSatsPerByte,
      funding: {
        outpointIndex: String(operation.intent.funding.vout),
        publicKey: operation.intent.funding.compressedPublicKey,
        sourceTransactionHex:
          operation.intent.funding.rawSourceTransaction.toString('hex'),
      },
      instanceId: this.#descriptor.instanceId,
      kind: operation.kind,
      networkId: this.#profileCore.network.id,
      payoutLockingBytecode: operation.kind === 'withdrawal'
        ? operation.intent.target.bytes
        : null,
      pins: this.#pins,
      postState,
      preState,
      previousBundleTransactionHex,
      profileId: this.#profileId,
      unlockingBytecodeLengths: {
        verifier: [...DIRECT_V2_PF10_VERIFIER_UNLOCK_BYTES],
        state: DIRECT_V2_PF10_STATE_UNLOCK_BYTES,
      },
    });
    if (
      BigInt(prepared.measurements.feeSats)
      > BigInt(operation.intent.feePolicy.maximumFeeSats)
    ) {
      fail(
        'MAXIMUM_FEE_EXCEEDED',
        'prepared settlement fee exceeds the immutable operation maximum',
      );
    }
    return prepared;
  }

  #rebuildAssembled(operation, record) {
    const witness = buildDirectV2Pf10ActionWitness({
      actionPacket: operation.packet,
      denominationSats: this.#profileCore.denominationSats,
      proofResult: record.proofResult,
      runtimeMaterial: this.#runtimeResolution.runtimeMaterial,
    });
    const assembled = assembleV2DirectSettlement(record.prepared, {
      actionPacket: operation.packet,
      verifierUnlockingBytecodes:
        witness.verifierUnlockingBytecodes,
      stateUnlockingBytecode: witness.stateUnlockingBytecode,
    });
    if (
      !same(
        Buffer.from(assembled.unsignedTransactionHex, 'hex'),
        operation.unsignedTx,
      )
    ) {
      fail(
        'UNSIGNED_TRANSACTION_MISMATCH',
        're-derived proof witness differs from the persisted unsigned transaction',
      );
    }
    return Object.freeze({ assembled, witness });
  }

  #inspectDurableSignedArtifacts(operation, record = undefined) {
    const inspectedRecord = record ?? inspectProofRecord(operation.proof, {
      profileSha256: this.#profileSha256,
      runtimeResolution: this.#runtimeResolution,
    });
    this.#rebuildAssembled(operation, inspectedRecord);
    let transaction;
    let evidence;
    try {
      transaction = parseV2RawTransaction(
        operation.signedTx.toString('hex'),
        {
          carrierCount:
            this.#runtimeResolution.runtimeMaterial.verifierRoles.length,
        },
      );
      evidence = inspectV2LocalVmEvidence(operation.localVmEvidence);
    } catch (error) {
      fail(
        typeof error?.code === 'string'
          ? error.code
          : 'INVALID_SIGNED_ARTIFACTS',
        `durable signed artifacts failed local validation: ${
          error instanceof Error ? error.message : String(error)
        }`,
        { cause: error },
      );
    }
    if (
      evidence.carrierCount
        !== this.#runtimeResolution.runtimeMaterial.verifierRoles.length
      || evidence.instanceId !== this.#descriptor.instanceId
      || evidence.transaction.rawTransactionHex
        !== transaction.rawTransactionHex
      || evidence.transaction.txid !== transaction.txid
      || evidence.transaction.serializedBytes !== transaction.sizeBytes
      || evidence.tool.profileId !== this.#profileId
      || evidence.tool.profileSha256 !== this.#profileSha256
      || evidence.allInputsAccepted !== true
    ) {
      fail(
        'SIGNED_ARTIFACT_BINDING_MISMATCH',
        'durable signed transaction and VM evidence do not bind the exact profile, instance, topology, and transaction',
      );
    }
    return Object.freeze({
      evidence,
      record: inspectedRecord,
      transaction,
    });
  }

  async #preflightMaterial({
    operationId: id,
    intent,
    output,
    publicNullifier,
    phase,
  }) {
    if (
      intent === null
      || Array.isArray(intent)
      || typeof intent !== 'object'
      || !['deposit', 'transfer', 'withdrawal'].includes(intent.kind)
    ) {
      fail(
        'INVALID_LIFECYCLE_INPUT',
        'action preflight intent must select deposit, transfer, or withdrawal',
      );
    }
    assertOutputTargetsIntent(intent, output);
    const publicValues = proofPublicValues(
      intent.kind,
      output,
      publicNullifier,
    );
    const before = normalizeStoreTip(this.#store.canonicalState());
    const current = await this.#refreshTip({
      phase,
      operationId: id,
      priorCanonicalTip: before,
    });
    assertOutputTargetsIntent(
      intent,
      output,
      current.actionSequence + 1,
    );
    const derivedPost = this.#store.derivePacketPostState({
      kind: intent.kind,
      publicNullifier:
        publicValues.publicNullifier ?? Buffer.alloc(32),
      outputNoteLeaf:
        publicValues.outputNoteLeaf ?? Buffer.alloc(32),
    });
    const previousBundleTransactionHex = await this.#previousBundle({
      expectedOutpoint: current.outpoint,
    });
    const prepared = this.#prepareSettlement({
      expectedState: current.state,
      intent,
      kind: intent.kind,
    }, derivedPost.state, previousBundleTransactionHex);
    return Object.freeze({
      current,
      prepared,
      publicValues,
    });
  }

  async quoteAction({
    operationId: id,
    intent,
    output = null,
    publicNullifier = null,
  } = {}) {
    const selectedId = operationId(id);
    const material = await this.#preflightMaterial({
      operationId: selectedId,
      intent,
      output,
      publicNullifier,
      phase: 'funding-preflight',
    });
    return actionPreflight({
      operationId: selectedId,
      kind: intent.kind,
      tip: material.current,
      publicValues: material.publicValues,
      prepared: material.prepared,
    });
  }

  async prepareAction({
    operationId: id,
    intent,
    output = null,
    publicNullifier = null,
    preflight,
    crashAt = null,
  } = {}) {
    const selectedId = operationId(id);
    if (intent === undefined) {
      fail('INVALID_LIFECYCLE_INPUT', 'prepareAction intent is required');
    }
    const inspectedPreflight = inspectActionPreflight(preflight);
    if (
      inspectedPreflight.token.operationId !== selectedId
      || inspectedPreflight.token.kind !== intent.kind
    ) {
      fail(
        'ACTION_PREFLIGHT_MISMATCH',
        'action preflight operation or kind differs from prepareAction',
      );
    }
    const material = await this.#preflightMaterial({
      operationId: selectedId,
      intent,
      output,
      publicNullifier,
      phase: 'prepare',
    });
    const current = material.current;
    if (!sameTip(current, inspectedPreflight.tip)) {
      fail(
        'ACTION_PREFLIGHT_STALE',
        'canonical tip changed after exact funding preflight; regenerate action randomness and quote before proving',
        { recoverable: true },
      );
    }
    const repeatedPreflight = actionPreflight({
      operationId: selectedId,
      kind: intent.kind,
      tip: current,
      publicValues: material.publicValues,
      prepared: material.prepared,
    });
    if (
      canonicalizeJcs(repeatedPreflight)
      !== canonicalizeJcs(inspectedPreflight.token)
      || material.prepared.measurements.feeSats
        !== intent.feePolicy?.maximumFeeSats
    ) {
      fail(
        'ACTION_PREFLIGHT_MISMATCH',
        'prepareAction intent, private action material, or exact fee differs from its funding preflight',
      );
    }
    let privateAction;
    try {
      privateAction = await this.#privateActionStore.create({
        expectedActionSequence: current.actionSequence,
        kind: intent.kind,
        operationId: selectedId,
        output,
        publicNullifier,
      });
    } catch (error) {
      fail(
        error?.code ?? 'PRIVATE_ACTION_PERSISTENCE_FAILED',
        `private action material was not durably created: ${
          error instanceof Error ? error.message : String(error)
        }`,
        { cause: error, recoverable: true },
      );
    }
    let operation = this.#store.prepareAction({
      operationId: selectedId,
      kind: intent.kind,
      expectedState: current.state,
      expectedOutpoint: current.outpoint,
      expectedActionSequence: current.actionSequence,
      expectedHeight: current.height,
      expectedBlockHash: current.blockHash,
      runtimeMaterialsSha256: this.#runtimeMaterialsSha256,
      actionMaterialSha256: privateAction.actionMaterialSha256,
      privateActionRecordSha256:
        privateAction.privateActionRecordSha256,
      intent,
      packet: null,
      proof: null,
      unsignedTx: null,
      signedTx: null,
      localVmEvidence: null,
      crashAt,
    });
    operation = assertOperationRuntime(
      operation,
      this.#runtimeMaterialsSha256,
    );
    operation = this.#store.transitionOperation({
      operationId: selectedId,
      to: 'tip_synced',
      reason: null,
    });
    return operation;
  }

  async proveAction({
    operationId: id,
    spend = null,
    crashAt = null,
  } = {}) {
    const selectedId = operationId(id);
    const selectedCrash = crashStage(crashAt, 'prove');
    let operation = this.#operation(selectedId);
    if (operation.journalState === 'proved') {
      const artifacts = exactArtifactSet(operation);
      if (!artifacts.proved || artifacts.signed) {
        fail(
          'PARTIAL_OPERATION_ARTIFACTS',
          'proved operation does not contain the exact immutable proof artifact set',
        );
      }
      const record = inspectProofRecord(operation.proof, {
        profileSha256: this.#profileSha256,
        runtimeResolution: this.#runtimeResolution,
      });
      this.#rebuildAssembled(operation, record);
      return operation;
    }
    let privateAction;
    try {
      privateAction = await this.#privateActionStore.load({
        actionMaterialSha256:
          operation.actionMaterialSha256.toString('hex'),
        expectedActionSequence: operation.expectedActionSequence,
        kind: operation.kind,
        operationId: selectedId,
        privateActionRecordSha256:
          operation.privateActionRecordSha256.toString('hex'),
      });
    } catch (error) {
      fail(
        error?.code ?? 'PRIVATE_ACTION_RECORD_INVALID',
        `durable private action material cannot be loaded: ${
          error instanceof Error ? error.message : String(error)
        }`,
        { cause: error, recoverable: true },
      );
    }
    const {
      output,
      publicNullifier,
    } = privateAction;
    assertOutputTargetsIntent(
      operation.intent,
      output,
      operation.expectedActionSequence + 1,
    );
    if (operation.journalState === 'tip_synced') {
      operation = this.#store.transitionOperation({
        operationId: selectedId,
        to: 'proving',
        reason: null,
      });
      crash(selectedCrash, 'prove.after_transition');
    }
    if (operation.journalState !== 'proving') {
      fail(
        'INVALID_OPERATION_STATE',
        `proveAction requires tip_synced or proving, found ${operation.journalState}`,
      );
    }
    const artifactState = exactArtifactSet(operation);
    if (artifactState.proved) {
      const record = inspectProofRecord(operation.proof, {
        profileSha256: this.#profileSha256,
        runtimeResolution: this.#runtimeResolution,
      });
      this.#rebuildAssembled(operation, record);
      return this.#store.transitionOperation({
        operationId: selectedId,
        to: 'proved',
        reason: null,
      });
    }
    const publicValues = proofPublicValues(
      operation.kind,
      output,
      publicNullifier,
    );
    const derivedPost = this.#store.derivePacketPostState({
      kind: operation.kind,
      publicNullifier:
        publicValues.publicNullifier ?? Buffer.alloc(32),
      outputNoteLeaf:
        publicValues.outputNoteLeaf ?? Buffer.alloc(32),
    });
    const previousBundleTransactionHex =
      await this.#previousBundle(operation);
    const prepared = this.#prepareSettlement(
      operation,
      derivedPost.state,
      previousBundleTransactionHex,
    );
    const transition = this.#store.deriveProvingTransition({
      operationId: selectedId,
      outputNoteLeaf: publicValues.outputNoteLeaf,
      encryptedRecord: publicValues.encryptedRecord,
      publicNullifier: publicValues.publicNullifier,
      transactionContextHash: Buffer.from(prepared.contextHash, 'hex'),
    });
    if (
      canonicalizeJcs(transition.state)
      !== canonicalizeJcs(derivedPost.state)
    ) {
      fail(
        'STATE_TRANSITION_MISMATCH',
        'persistent proving transition differs from prepared post-state',
      );
    }
    const circuitInput = buildDirectV2CircuitInput({
      transition,
      spend: spend ?? undefined,
      output: output ?? undefined,
      denominationSats: this.#profileCore.denominationSats,
    });
    await assertPrivateProofWorkspace(this.#proofWorkspaceDirectory);
    let proofResult;
    try {
      proofResult = await this.#proveGroth16({
        artifacts: this.#runtimeResolution.proofArtifacts,
        circuitInput,
        expectedPublicInputs: transition.publicInputs,
        workspaceDirectory: this.#proofWorkspaceDirectory,
      });
    } catch (error) {
      fail(
        typeof error?.code === 'string'
          ? error.code
          : 'PROVING_FAILED',
        `isolated proof generation failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
        { cause: error, recoverable: true },
      );
    }
    crash(selectedCrash, 'prove.after_proof');
    const witness = buildDirectV2Pf10ActionWitness({
      actionPacket: transition.packet,
      denominationSats: this.#profileCore.denominationSats,
      proofResult,
      runtimeMaterial: this.#runtimeResolution.runtimeMaterial,
    });
    const assembled = assembleV2DirectSettlement(prepared, {
      actionPacket: transition.packet,
      verifierUnlockingBytecodes:
        witness.verifierUnlockingBytecodes,
      stateUnlockingBytecode: witness.stateUnlockingBytecode,
    });
    const proofRecord = createProofRecord({
      containment: proofResult.containment,
      prepared,
      profileSha256: this.#profileSha256,
      proofResult,
      runtimeResolution: this.#runtimeResolution,
    });
    this.#store.updateOperationArtifacts({
      operationId: selectedId,
      packet: transition.packet,
      proof: proofRecord,
      unsignedTx: Buffer.from(
        assembled.unsignedTransactionHex,
        'hex',
      ),
      signedTx: null,
      localVmEvidence: null,
    });
    crash(selectedCrash, 'prove.after_artifacts');
    operation = this.#store.transitionOperation({
      operationId: selectedId,
      to: 'proved',
      reason: null,
    });
    crash(selectedCrash, 'prove.after_proved');
    return operation;
  }

  async signAction({
    operationId: id,
    highFeeConfirmation = undefined,
    crashAt = null,
  } = {}) {
    const selectedId = operationId(id);
    const selectedCrash = crashStage(crashAt, 'sign');
    let operation = this.#operation(selectedId);
    if (operation.journalState === 'signed') {
      const artifacts = exactArtifactSet(operation);
      if (!artifacts.proved || !artifacts.signed) {
        fail(
          'PARTIAL_OPERATION_ARTIFACTS',
          'signed operation does not contain the exact immutable signed artifact set',
        );
      }
      this.#inspectDurableSignedArtifacts(operation);
      return operation;
    }
    if (operation.journalState !== 'proved') {
      fail(
        'INVALID_OPERATION_STATE',
        `signAction requires proved, found ${operation.journalState}`,
      );
    }
    const artifactState = exactArtifactSet(operation);
    if (!artifactState.proved) {
      fail(
        'PROOF_RECORD_REQUIRED',
        'proved operation is missing its immutable proof artifacts',
      );
    }
    if (artifactState.signed) {
      this.#inspectDurableSignedArtifacts(operation);
      return this.#store.transitionOperation({
        operationId: selectedId,
        to: 'signed',
        reason: null,
      });
    }
    if (this.#fundingSignerClosed) {
      fail(
        'FUNDING_SIGNER_CLOSED',
        'the lifecycle funding signer has been irreversibly zeroized',
      );
    }
    if (
      Buffer.from(operation.intent.funding.compressedPublicKey)
        .toString('hex') !== this.#fundingPublicKeyHex
    ) {
      fail(
        'FUNDING_WALLET_MISMATCH',
        'the operation funding input is not owned by this lifecycle funding wallet',
      );
    }
    const prior = normalizeStoreTip(this.#store.canonicalState());
    let current;
    try {
      current = await this.#refreshTip({
        phase: 'pre-sign',
        operationId: selectedId,
        priorCanonicalTip: prior,
      });
    } catch (error) {
      if (error?.code !== 'CANONICAL_TIP_CHANGED') throw error;
      const conflicted = this.#store.recordConflictAndMaybeRetry({
        operationId: selectedId,
        reason: 'canonical tip changed before funding signature',
        crashAt: null,
      });
      fail(
        'STALE_TIP_REPROOF_REQUIRED',
        `canonical tip changed before signing; operation is ${conflicted.journalState}`,
        { cause: error, recoverable: true },
      );
    }
    if (!sameTip(current, expectedTip(operation))) {
      const conflicted = this.#store.recordConflictAndMaybeRetry({
        operationId: selectedId,
        reason: 'canonical tip changed before funding signature',
        crashAt: null,
      });
      fail(
        'STALE_TIP_REPROOF_REQUIRED',
        `canonical tip changed before signing; operation is ${conflicted.journalState}`,
        { recoverable: true },
      );
    }
    crash(selectedCrash, 'sign.after_refresh');
    const record = inspectProofRecord(operation.proof, {
      profileSha256: this.#profileSha256,
      runtimeResolution: this.#runtimeResolution,
    });
    const { assembled } = this.#rebuildAssembled(operation, record);
    assertHighFeeSigningConfirmation(
      highFeeConfirmation,
      selectedId,
      record.prepared,
    );
    const fundingInputIndex =
      this.#runtimeResolution.runtimeMaterial.verifierRoles.length + 2;
    let signerCalled = false;
    const signed = await signV2DirectSettlement(assembled, {
      signFunding: async (request) => {
        if (signerCalled) {
          fail(
            'SIGNER_REENTRY',
            'funding signer was invoked more than once for one signAction call',
          );
        }
        signerCalled = true;
        if (
          canonicalizeJcs(request)
            !== canonicalizeJcs(assembled.signingRequest)
          || request.contextHash !== record.prepared.contextHash
          || request.fundingInputIndex !== fundingInputIndex
          || request.publicKeyHex !== this.#fundingPublicKeyHex
          || request.sighashContract
            !== 'SIGHASH_ALL|UTXOS|FORKID'
          || request.sighashType !== 0x61
          || typeof request.digestHex !== 'string'
          || !HASH.test(request.digestHex)
        ) {
          fail(
            'FUNDING_SIGNING_REQUEST_INVALID',
            'internally re-derived funding request does not match the exact durable operation',
          );
        }
        const signature = secp256k1.signMessageHashSchnorr(
          this.#fundingPrivateKey,
          Buffer.from(request.digestHex, 'hex'),
        );
        if (!(signature instanceof Uint8Array) || signature.length !== 64) {
          fail(
            'FUNDING_SIGNING_FAILED',
            'internal BCH Schnorr signing did not produce one 64-byte signature',
          );
        }
        return Buffer.from(signature);
      },
      createLocalVmEvidence: makeVmEvidenceProducer(
        this.#profileId,
        this.#profileSha256,
      ),
    });
    if (!signerCalled) {
      fail(
        'FUNDING_SIGNER_NOT_CALLED',
        'settlement signing returned without invoking the funding signer',
      );
    }
    crash(selectedCrash, 'sign.after_signature');
    this.#store.updateOperationArtifacts({
      operationId: selectedId,
      packet: operation.packet,
      proof: operation.proof,
      unsignedTx: operation.unsignedTx,
      signedTx: Buffer.from(signed.rawTransactionHex, 'hex'),
      localVmEvidence: Buffer.from(signed.localVmEvidenceHex, 'hex'),
    });
    crash(selectedCrash, 'sign.after_artifacts');
    operation = this.#store.transitionOperation({
      operationId: selectedId,
      to: 'signed',
      reason: null,
    });
    crash(selectedCrash, 'sign.after_signed');
    return operation;
  }

  async broadcastAction({
    operationId: id,
    delivery,
    transport,
    endpoint,
    highFeeConfirmation = undefined,
    log = undefined,
  } = {}) {
    const selectedId = operationId(id);
    const operation = this.#operation(selectedId);
    if (
      !['signed', 'broadcast', 'mempool'].includes(operation.journalState)
    ) {
      fail(
        'INVALID_OPERATION_STATE',
        `broadcastAction requires signed/broadcast/mempool, found ${operation.journalState}`,
      );
    }
    const artifacts = exactArtifactSet(operation);
    if (!artifacts.proved || !artifacts.signed) {
      fail(
        'SIGNED_ARTIFACTS_REQUIRED',
        'broadcast requires complete durable proof, transaction, and VM evidence',
      );
    }
    const { record } = this.#inspectDurableSignedArtifacts(operation);
    const metadata = createV2SignedBroadcastMetadata({
      action: operation.kind,
      feeSats: signedFee(record),
      instanceId: this.#descriptor.instanceId,
      localVmEvidence: operation.localVmEvidence,
      network: this.#profileCore.network.name,
      operationId: selectedId,
      profileId: this.#profileId,
      rawTxHex: operation.signedTx.toString('hex'),
      tip: tipJson(expectedTip(operation)),
    });
    return mandatoryBroadcastAction({
      store: this.#store,
      delivery,
      transport,
      endpoint,
      metadata,
      synchronizeCanonicalTip: async () => {
        const prior = normalizeStoreTip(this.#store.canonicalState());
        try {
          return await this.#refreshTip({
            phase: 'pre-broadcast',
            operationId: selectedId,
            priorCanonicalTip: prior,
          });
        } catch (error) {
          if (error?.code !== 'CANONICAL_TIP_CHANGED') throw error;
          if (operation.journalState !== 'signed') {
            fail(
              'CHAIN_RECONCILIATION_REQUIRED',
              'canonical tip changed after a prior broadcast; observe the exact transaction before any state transition or resubmission',
              { cause: error, recoverable: true },
            );
          }
          const conflicted = this.#store.recordConflictAndMaybeRetry({
            operationId: selectedId,
            reason: 'canonical tip changed before broadcast claim',
            crashAt: null,
          });
          fail(
            'STALE_TIP_REPROOF_REQUIRED',
            `canonical tip changed before broadcast; operation is ${conflicted.journalState}`,
            { cause: error, recoverable: true },
          );
        }
      },
      highFeeConfirmation,
      log,
    });
  }

  async recoverBroadcastAction({
    operationId: id,
    delivery,
    log = undefined,
  } = {}) {
    const selectedId = operationId(id);
    const operation = this.#operation(selectedId);
    if (
      !['signed', 'broadcast', 'mempool'].includes(operation.journalState)
    ) {
      fail(
        'INVALID_OPERATION_STATE',
        `recoverBroadcastAction requires signed/broadcast/mempool, found ${operation.journalState}`,
      );
    }
    const artifacts = exactArtifactSet(operation);
    if (!artifacts.proved || !artifacts.signed) {
      fail(
        'SIGNED_ARTIFACTS_REQUIRED',
        'broadcast recovery requires complete durable proof, transaction, and VM evidence',
      );
    }
    const { record } = this.#inspectDurableSignedArtifacts(operation);
    const metadata = createV2SignedBroadcastMetadata({
      action: operation.kind,
      feeSats: signedFee(record),
      instanceId: this.#descriptor.instanceId,
      localVmEvidence: operation.localVmEvidence,
      network: this.#profileCore.network.name,
      operationId: selectedId,
      profileId: this.#profileId,
      rawTxHex: operation.signedTx.toString('hex'),
      tip: tipJson(expectedTip(operation)),
    });
    return mandatoryReconcileObservedAction({
      store: this.#store,
      delivery,
      metadata,
      loadRawTransaction: async (request) =>
        this.#loadRawTransaction(request),
      log,
    });
  }

  async rebroadcastExactAction({
    operationId: id,
    delivery,
    transport,
    endpoint,
    priorAttemptToken,
    acknowledgement,
    highFeeConfirmation = undefined,
    log = undefined,
  } = {}) {
    const selectedId = operationId(id);
    const operation = this.#operation(selectedId);
    if (
      !['signed', 'broadcast', 'mempool'].includes(operation.journalState)
    ) {
      fail(
        'INVALID_OPERATION_STATE',
        `rebroadcastExactAction requires signed/broadcast/mempool, found ${operation.journalState}`,
      );
    }
    const artifacts = exactArtifactSet(operation);
    if (!artifacts.proved || !artifacts.signed) {
      fail(
        'SIGNED_ARTIFACTS_REQUIRED',
        'exact resubmission requires complete durable proof, transaction, and VM evidence',
      );
    }
    const { record } = this.#inspectDurableSignedArtifacts(operation);
    const metadata = createV2SignedBroadcastMetadata({
      action: operation.kind,
      feeSats: signedFee(record),
      instanceId: this.#descriptor.instanceId,
      localVmEvidence: operation.localVmEvidence,
      network: this.#profileCore.network.name,
      operationId: selectedId,
      profileId: this.#profileId,
      rawTxHex: operation.signedTx.toString('hex'),
      tip: tipJson(expectedTip(operation)),
    });
    return mandatoryRebroadcastExactAction({
      store: this.#store,
      delivery,
      transport,
      endpoint,
      metadata,
      synchronizeCanonicalTip: async () => {
        const prior = normalizeStoreTip(this.#store.canonicalState());
        return this.#refreshTip({
          phase: 'pre-rebroadcast',
          operationId: selectedId,
          priorCanonicalTip: prior,
        });
      },
      priorAttemptToken,
      acknowledgement,
      highFeeConfirmation,
      log,
    });
  }

  async confirmAction({ operationId: id } = {}) {
    const selectedId = operationId(id);
    let operation = this.#operation(selectedId);
    if (
      !['broadcast', 'mempool', 'confirmed', 'settled'].includes(
        operation.journalState,
      )
    ) {
      fail(
        'INVALID_OPERATION_STATE',
        `confirmAction requires broadcast/mempool/confirmed/settled, found ${operation.journalState}`,
      );
    }
    this.#inspectDurableSignedArtifacts(operation);
    // Confirmation and settlement are separate durable states. Always perform
    // a fresh authenticated chain synchronization before either reporting an
    // already-settled operation or crossing confirmed -> settled. Otherwise a
    // crash after applyConfirmed followed by a reorg could settle an orphaned
    // transaction solely from stale local undo data.
    const prior = normalizeStoreTip(this.#store.canonicalState());
    await this.#refreshTip({
      phase: 'confirm',
      operationId: selectedId,
      priorCanonicalTip: prior,
    });
    operation = this.#operation(selectedId);
    if (operation.journalState === 'settled') return operation;
    if (
      ['needs_reproof', 'reorged', 'conflicted'].includes(
        operation.journalState,
      )
    ) {
      fail(
        'STALE_TIP_REPROOF_REQUIRED',
        `authenticated history does not confirm the operation; it is ${operation.journalState}`,
        { recoverable: true },
      );
    }
    if (operation.journalState !== 'confirmed') {
      fail(
        'CONFIRMATION_PENDING',
        'authenticated chain synchronization has not confirmed the exact signed operation',
        { recoverable: true },
      );
    }
    return this.#store.settleConfirmedOperation({
      operationId: selectedId,
      crashAt: null,
    });
  }

  async resumeOperation({ operationId: id } = {}) {
    const selectedId = operationId(id);
    let operation = this.#operation(selectedId);
    const artifacts = exactArtifactSet(operation);
    if (operation.journalState === 'proving' && artifacts.proved) {
      const record = inspectProofRecord(operation.proof, {
        profileSha256: this.#profileSha256,
        runtimeResolution: this.#runtimeResolution,
      });
      this.#rebuildAssembled(operation, record);
      operation = this.#store.transitionOperation({
        operationId: selectedId,
        to: 'proved',
        reason: null,
      });
    }
    if (operation.journalState === 'proved' && artifacts.signed) {
      this.#inspectDurableSignedArtifacts(operation);
      operation = this.#store.transitionOperation({
        operationId: selectedId,
        to: 'signed',
        reason: null,
      });
    }
    if (operation.journalState === 'funding_selected') {
      const prior = normalizeStoreTip(this.#store.canonicalState());
      let current;
      try {
        current = await this.#refreshTip({
          phase: 'resume',
          operationId: selectedId,
          priorCanonicalTip: prior,
        });
      } catch (error) {
        if (error?.code !== 'CANONICAL_TIP_CHANGED') throw error;
        const conflicted = this.#store.recordConflictAndMaybeRetry({
          operationId: selectedId,
          reason: 'canonical tip changed before resume',
          crashAt: null,
        });
        fail(
          'STALE_TIP_REPROOF_REQUIRED',
          `canonical tip changed before resume; operation is ${conflicted.journalState}`,
          { cause: error, recoverable: true },
        );
      }
      if (!sameTip(current, expectedTip(operation))) {
        operation = this.#store.recordConflictAndMaybeRetry({
          operationId: selectedId,
          reason: 'canonical tip changed before resume',
          crashAt: null,
        });
      } else {
        operation = this.#store.transitionOperation({
          operationId: selectedId,
          to: 'tip_synced',
          reason: null,
        });
      }
    }
    if (['confirmed', 'settled'].includes(operation.journalState)) {
      operation = await this.confirmAction({
        operationId: selectedId,
      });
    }
    const next = {
      tip_synced: 'prove',
      proving: artifacts.proved ? 'recover-proof' : 'prove',
      proved: 'sign',
      needs_reproof: 'rebase',
      signed: 'explicit-broadcast',
      broadcast: 'chain-reconcile-no-resend',
      mempool: 'chain-reconcile-no-resend',
      confirmed: 'settle',
      settled: 'complete',
      conflicted: 'manual-resolution',
      reorged: 'rebase',
      abandoned: 'terminal',
    }[operation.journalState] ?? 'manual-resolution';
    return Object.freeze({ operation, next });
  }

  async rebaseOperation(value = {}) {
    exact(
      value,
      [
        'constructPrivateAction',
        'explicitUserSelection',
        'operationId',
      ],
      'rebase operation request',
    );
    const selectedId = operationId(value.operationId);
    if (typeof value.explicitUserSelection !== 'boolean') {
      fail(
        'INVALID_LIFECYCLE_INPUT',
        'rebase explicitUserSelection must be a boolean',
      );
    }
    if (typeof value.constructPrivateAction !== 'function') {
      fail(
        'PRIVATE_ACTION_CONSTRUCTOR_REQUIRED',
        'rebase requires a fresh private action constructor',
      );
    }
    let dormant = this.#operation(selectedId);
    if (
      dormant.journalState === 'conflicted'
      && value.explicitUserSelection !== true
    ) {
      fail(
        'EXPLICIT_RETRY_SELECTION_REQUIRED',
        'a conflicted operation can only be retried by an explicit user-selected rebase',
        { recoverable: true },
      );
    }
    if (
      !['needs_reproof', 'reorged', 'conflicted'].includes(
        dormant.journalState,
      )
    ) {
      fail(
        'INVALID_OPERATION_STATE',
        `rebaseOperation requires needs_reproof, reorged, or an explicitly selected conflicted state, found ${dormant.journalState}`,
      );
    }
    if (dormant.journalState === 'conflicted') {
      dormant = this.#store.authorizeManualRetry({
        operationId: selectedId,
        crashAt: null,
      });
    }
    this.#store.releaseOperationForCanonicalSync({
      operationId: selectedId,
    });
    const prior = normalizeStoreTip(this.#store.canonicalState());
    const request = freezeJson({
      phase: 'rebase',
      operationId: null,
      priorCanonicalTip: tipJson(prior),
    });
    let reported;
    try {
      reported = await this.#synchronizeCanonicalTip(request);
    } catch (error) {
      fail(
        'TIP_SYNCHRONIZATION_FAILED',
        `canonical tip synchronization failed during rebase: ${
          error instanceof Error ? error.message : String(error)
        }`,
        { cause: error, recoverable: true },
      );
    }
    const current = normalizeStoreTip(
      reported,
      'synchronized canonical tip',
    );
    if (!sameTip(
      current,
      normalizeStoreTip(
        this.#store.canonicalState(),
        'durable canonical tip',
      ),
    )) {
      fail(
        'TIP_SYNCHRONIZATION_INCONSISTENT',
        'rebase synchronization result differs from the durable canonical store tip',
        { recoverable: true },
      );
    }
    let replacement;
    try {
      replacement = await value.constructPrivateAction(freezeJson({
        expectedActionSequence: current.actionSequence,
        kind: dormant.kind,
        operationId: selectedId,
        postActionSequence: current.actionSequence + 1,
        tip: tipJson(current),
      }));
    } catch (error) {
      fail(
        error?.code ?? 'PRIVATE_ACTION_CONSTRUCTION_FAILED',
        `replacement private action material could not be constructed: ${
          error instanceof Error ? error.message : String(error)
        }`,
        { cause: error, recoverable: true },
      );
    }
    exact(
      replacement,
      ['output', 'publicNullifier'],
      'replacement private action',
    );
    assertOutputTargetsIntent(dormant.intent, replacement.output);
    const repeated = await this.#preflightMaterial({
      operationId: selectedId,
      intent: dormant.intent,
      output: replacement.output,
      publicNullifier: replacement.publicNullifier,
      phase: 'rebase-prepare',
    });
    if (!sameTip(current, repeated.current)) {
      fail(
        'CANONICAL_TIP_CHANGED',
        'canonical tip changed after replacement private action persistence; rebase again with fresh randomness',
        { recoverable: true },
      );
    }
    if (
      repeated.prepared.measurements.feeSats
        !== dormant.intent.feePolicy.maximumFeeSats
    ) {
      fail(
        'ACTION_PREFLIGHT_MISMATCH',
        'replacement action no longer matches the immutable exact fee',
        { recoverable: true },
      );
    }
    let privateAction;
    try {
      privateAction = await this.#privateActionStore.replace({
        expectedActionSequence: current.actionSequence,
        kind: dormant.kind,
        operationId: selectedId,
        output: replacement.output,
        publicNullifier: replacement.publicNullifier,
      });
    } catch (error) {
      fail(
        error?.code ?? 'PRIVATE_ACTION_PERSISTENCE_FAILED',
        `replacement private action material was not durably persisted: ${
          error instanceof Error ? error.message : String(error)
        }`,
        { cause: error, recoverable: true },
      );
    }
    return this.#store.rebaseOperation({
      operationId: selectedId,
      expectedState: current.state,
      expectedOutpoint: current.outpoint,
      expectedActionSequence: current.actionSequence,
      expectedHeight: current.height,
      expectedBlockHash: current.blockHash,
      actionMaterialSha256: privateAction.actionMaterialSha256,
      privateActionRecordSha256:
        privateAction.privateActionRecordSha256,
      crashAt: null,
    });
  }

  abandonOperation({ operationId: id, reason } = {}) {
    return this.#store.abandonOperation({
      operationId: operationId(id),
      reason,
      crashAt: null,
    });
  }
}

/**
 * Create the production V2 Direct action coordinator only from a descriptor
 * object that already passed signed-manifest validation. Runtime material is
 * resolved again inside this boundary and immediately bound to the store.
 */
export async function createV2DirectActionLifecycle(value) {
  exact(
    value,
    [
      'allowDevelopmentOnly',
      'descriptor',
      'fundingWallet',
      'loadRawTransaction',
      'profileCore',
      'privateActionStore',
      'proofWorkspaceDirectory',
      'store',
      'synchronizeCanonicalTip',
    ],
    'V2 action lifecycle options',
  );
  validateProfileCore(value.profileCore);
  const fundingWallet = validatedFundingWallet(value.fundingWallet);
  if (fundingWallet.networkId !== value.profileCore.network.id) {
    fail(
      'FUNDING_WALLET_NETWORK_MISMATCH',
      'funding wallet network differs from the validated profile network',
    );
  }
  const store = requireStore(value.store);
  const privateActionStore =
    assertV2PrivateActionStore(value.privateActionStore);
  if (typeof value.loadRawTransaction !== 'function') {
    fail(
      'CHAIN_READER_REQUIRED',
      'loadRawTransaction must be an injected read-only chain callback',
    );
  }
  if (typeof value.synchronizeCanonicalTip !== 'function') {
    fail(
      'TIP_SYNCHRONIZER_REQUIRED',
      'synchronizeCanonicalTip must be an injected authenticated chain callback',
    );
  }
  if (
    typeof value.proofWorkspaceDirectory !== 'string'
    || !path.isAbsolute(value.proofWorkspaceDirectory)
    || path.normalize(value.proofWorkspaceDirectory)
      !== value.proofWorkspaceDirectory
  ) {
    fail(
      'PROOF_WORKSPACE_REQUIRED',
      'proofWorkspaceDirectory must be an absolute private directory',
    );
  }
  await assertPrivateProofWorkspace(value.proofWorkspaceDirectory);
  const runtimeResolution =
    await deriveV2Pf10RuntimeFromValidatedDescriptor(value.descriptor);
  if (
    runtimeResolution.eligibility === 'development-only'
    && (
      value.allowDevelopmentOnly !== true
      || value.profileCore.network.id !== 2
    )
  ) {
    fail(
      'DEVELOPMENT_RUNTIME_REFUSED',
      'development-only PF10 material requires explicit opt-in and Chipnet',
    );
  }
  if (
    runtimeResolution.eligibility !== 'development-only'
    && runtimeResolution.eligibility !== 'final-qualified'
  ) {
    fail('RUNTIME_ELIGIBILITY_INVALID', 'PF10 runtime eligibility is invalid');
  }
  const runtimeMaterialsSha256 =
    deriveV2Pf10StoreRuntimeMaterialsSha256(runtimeResolution);
  const profileId = assertRuntimeBinding({
    descriptor: value.descriptor,
    fundingWallet,
    profileCore: value.profileCore,
    runtimeResolution,
    runtimeMaterialsSha256,
    store,
  });
  const profileSha256 = sha256(canonicalBytes(value.profileCore));
  return new V2DirectActionLifecycle({
    descriptor: value.descriptor,
    loadRawTransaction: value.loadRawTransaction,
    pins: deriveV2SettlementPinsFromValidatedDescriptor(value.descriptor),
    profileCore: value.profileCore,
    profileId,
    profileSha256,
    privateActionStore,
    proofWorkspaceDirectory: value.proofWorkspaceDirectory,
    proveGroth16: proveV2DirectGroth16Default,
    runtimeMaterialsSha256,
    runtimeResolution,
    store,
    synchronizeCanonicalTip: value.synchronizeCanonicalTip,
  });
}

export function inspectV2OperationProofRecord(
  bytesValue,
  options,
) {
  exact(
    options,
    ['profileCore', 'runtimeResolution'],
    'proof record inspection options',
  );
  const { profileCore, runtimeResolution } = options;
  validateProfileCore(profileCore);
  const runtimeMaterialsSha256 =
    deriveV2Pf10StoreRuntimeMaterialsSha256(runtimeResolution);
  const profileId = deriveProfileId(profileCore);
  if (
    runtimeResolution.runtimeMaterial.profileId !== profileId
    || runtimeResolution.runtimeMaterial.materialSha256
      !== runtimeMaterialsSha256.toString('hex')
  ) {
    fail(
      'RUNTIME_DESCRIPTOR_MISMATCH',
      'proof record inspection runtime does not bind the supplied profile core',
    );
  }
  return inspectProofRecord(bytesValue, {
    profileSha256: sha256(canonicalBytes(profileCore)),
    runtimeResolution,
  });
}
