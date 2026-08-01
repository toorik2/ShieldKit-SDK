import { createHash } from 'node:crypto';

import {
  encodeDataPush,
  encodeLockingBytecodeP2sh32,
  hash256,
} from '@bitauth/libauth';

import {
  encodeDirectV2BindingUnlock,
} from '../../action/v2/binding-unlock.mjs';
import {
  ACTION_PACKET_BYTES,
  actionPacketPublicLimbs,
  decodeActionPacket,
} from '../../action/v2/packet.mjs';
import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
} from '../../action/v2/topology.mjs';
import {
  canonicalizeJcs,
} from '../../profile/v2/profile-core.mjs';
import {
  V2_GROTH16_PROOF_RESULT_SCHEMA,
} from '../../prove/v2/groth16-proof-child.mjs';
import {
  V2_NATIVE_GROTH16_PROOF_RESULT_SCHEMA,
} from '../../prove/v2/native-groth16-proof-child.mjs';
import {
  parseStrictJson,
} from '../../prove/groth16.mjs';
import {
  computeDirectV2ExactMsm,
  encodeDirectV2MsmState,
} from './exact-msm.mjs';
import {
  computeDirectV2IdentityAwareMiller,
  encodeDirectV2MillerGenesisWitness,
  encodeDirectV2MillerProjectionSignal,
  parseDirectV2MillerVerificationKey,
} from './identity-aware-miller.mjs';
import {
  buildDirectV2Pf10FusedQGenesisUnlock,
} from './pf10-fused-q-genesis.mjs';
import {
  buildDirectV2PairFoldLoader,
  buildDirectV2PairFoldTerminalUnlock,
  buildDirectV2PairFoldUnlock,
  splitDirectV2PairFoldBody,
} from './total-pairfold-cashscript.mjs';
import {
  buildDirectV2TotalPairFoldWitness,
} from './total-pairfold.mjs';

export const DIRECT_V2_PF10_RUNTIME_SCHEMA =
  'shieldkit-v2-direct-pf10-runtime-material-v1';
export const DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA =
  'shieldkit-v2-direct-pf10-beta-runtime-material-v1';
export const DIRECT_V2_PF10_ACTION_WITNESS_SCHEMA =
  'shieldkit-v2-direct-pf10-action-witness-v1';
export const DIRECT_V2_PF10_BETA_ACTION_WITNESS_SCHEMA =
  'shieldkit-v2-direct-pf10-beta-action-witness-v1';
export const DIRECT_V2_PF10_BQ_SHARD_BYTES =
  Object.freeze([1_216, 1_216, 1_216, 1_216, 1_216]);
export const DIRECT_V2_PF10_EXACT_MSM_ZERO_PADDING_BYTES = 256;
export const DIRECT_V2_PF10_NONFINAL_MSM_PADDING_BYTES = 7_500;
export const DIRECT_V2_PF10_MILLER_ZERO_PADDING_BYTES = 256;
export const DIRECT_V2_PF10_EXECUTOR_DENSITY_PAD_BYTES = 384;
export const DIRECT_V2_PF10_EXECUTOR_FUNCTION_ID = 127;
export const DIRECT_V2_PF10_VERIFIER_UNLOCK_BYTES = Object.freeze([
  9_411,
  8_451,
  8_643,
  8_642,
  9_602,
  9_024,
  9_009,
  9_017,
  9_178,
  10_000,
]);
export const DIRECT_V2_PF10_STATE_UNLOCK_BYTES = 2_677;
export const DIRECT_V2_PF10_MAX_UNLOCK_BYTES = 10_000;

const HASH = /^[0-9a-f]{64}$/;
const HEX_32 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_U128 = (1n << 128n) - 1n;
const ELIGIBILITY = new Set(['development-only', 'final-qualified']);
export const DIRECT_V2_PF10_BETA_ELIGIBILITY =
  'beta-single-contributor-unqualified';
const PROOF_ARTIFACT_NAMES = Object.freeze([
  'provingKey',
  'r1cs',
  'verificationKey',
  'wasm',
]);
const validatedRuntimeMaterials = new WeakMap();
const validatedBetaRuntimeMaterials = new WeakMap();

export class DirectV2Pf10ActionWitnessError extends Error {
  constructor(code, message, cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'DirectV2Pf10ActionWitnessError';
    this.code = code;
  }
}

const fail = (code, message, cause) => {
  throw new DirectV2Pf10ActionWitnessError(code, message, cause);
};

function plainObject(value, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('PF10_RUNTIME_INVALID', `${label} must be a plain object`);
  }
  return value;
}

function exactKeys(value, expected, label) {
  plainObject(value, label);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])
  ) {
    fail(
      'PF10_RUNTIME_INVALID',
      `${label} has missing or unknown properties`,
    );
  }
  return value;
}

function bytes(value, label, expectedLength = undefined) {
  if (
    !(value instanceof Uint8Array)
    || value.length === 0
    || (
      expectedLength !== undefined
      && value.length !== expectedLength
    )
  ) {
    fail(
      'PF10_RUNTIME_INVALID',
      `${label} must be nonempty bytes${
        expectedLength === undefined
          ? ''
          : ` of length ${expectedLength}`
      }`,
    );
  }
  return Buffer.from(value);
}

function byteArray(value, count, label, expectedLength = undefined) {
  if (!Array.isArray(value) || value.length !== count) {
    fail(
      'PF10_RUNTIME_INVALID',
      `${label} must contain exactly ${count} byte strings`,
    );
  }
  return Object.freeze(value.map((entry, index) =>
    bytes(entry, `${label}[${index}]`, expectedLength)));
}

function hashRecord(value, label) {
  exactKeys(value, PROOF_ARTIFACT_NAMES, label);
  return Object.freeze(Object.fromEntries(
    PROOF_ARTIFACT_NAMES.map((name) => {
      if (typeof value[name] !== 'string' || !HASH.test(value[name])) {
        fail(
          'PF10_RUNTIME_INVALID',
          `${label}.${name} must be lowercase SHA-256`,
        );
      }
      return [name, value[name]];
    }),
  ));
}

const sha256Hex = (value) =>
  createHash('sha256').update(value).digest('hex');

const sameBytes = (left, right) =>
  Buffer.from(left).equals(Buffer.from(right));

const concat = (...parts) => Buffer.concat(parts.map((part) =>
  Buffer.from(part)));

const push = (value) => Buffer.from(encodeDataPush(value));

const encodedLength = (length) => push(Buffer.alloc(length)).length;

const pushHeaderLength = (length) => encodedLength(length) - length;

const p2sh32Lock = (redeem) => Buffer.from(
  encodeLockingBytecodeP2sh32(hash256(redeem)),
);

function normalizeJson(value, label) {
  if (
    value === null
    || typeof value === 'string'
    || typeof value === 'boolean'
  ) {
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      fail('PF10_RUNTIME_INVALID', `${label} contains a non-finite number`);
    }
    return value;
  }
  if (Array.isArray(value)) {
    if (
      Object.getPrototypeOf(value) !== Array.prototype
      || Object.getOwnPropertySymbols(value).length !== 0
      || Object.getOwnPropertyNames(value).length !== value.length + 1
    ) {
      fail('PF10_RUNTIME_INVALID', `${label} is not a dense JSON array`);
    }
    return value.map((entry, index) =>
      normalizeJson(entry, `${label}[${index}]`));
  }
  if (
    typeof value !== 'object'
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Object.getOwnPropertySymbols(value).length !== 0
  ) {
    fail('PF10_RUNTIME_INVALID', `${label} is not JSON data`);
  }
  const output = {};
  for (const name of Object.getOwnPropertyNames(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (
      name === 'toJSON'
      || !descriptor?.enumerable
      || !Object.hasOwn(descriptor, 'value')
    ) {
      fail(
        'PF10_RUNTIME_INVALID',
        `${label} contains a non-data JSON property`,
      );
    }
    output[name] = normalizeJson(
      descriptor.value,
      `${label}.${name}`,
    );
  }
  return output;
}

function immutableJson(value, label) {
  const normalized = normalizeJson(value, label);
  let canonical;
  try {
    canonical = canonicalizeJcs(normalized);
  } catch (error) {
    fail(
      'PF10_RUNTIME_INVALID',
      `${label} is not strict canonical JSON data`,
      error,
    );
  }
  return JSON.parse(canonical);
}

function exactIdentity(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail(
      'PF10_RUNTIME_INVALID',
      `${label} must be 32 lowercase hexadecimal bytes`,
    );
  }
  return value;
}

function exactRoles(value) {
  if (
    !Array.isArray(value)
    || value.length !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length
    || value.some(
      (role, index) =>
        role !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES[index],
    )
  ) {
    fail(
      'PF10_TOPOLOGY_MISMATCH',
      'runtime verifier roles do not exactly match PF10-FusedQGenesis',
    );
  }
  return DIRECT_V2_PF10_FUSED_VERIFIER_ROLES;
}

function materialCommitment(material) {
  const byteArtifacts = {
    bindingLockingBytecode:
      sha256Hex(material.bindingLockingBytecode),
    bindingRedeemBytecode:
      sha256Hex(material.bindingRedeemBytecode),
    exactMsmRedeems: material.exactMsmRedeems.map(sha256Hex),
    executorBody: sha256Hex(material.executorBody),
    fixedCarrierPads: material.fixedCarrierPads.map(sha256Hex),
    fusedRedeem: sha256Hex(material.fusedRedeem),
    stateUnlockingBytecode:
      sha256Hex(material.stateUnlockingBytecode),
    terminalRedeem: sha256Hex(material.terminalRedeem),
    verificationKeyBytes: sha256Hex(material.verificationKeyBytes),
    verifierLockingBytecodes:
      material.verifierLockingBytecodes.map(sha256Hex),
  };
  return sha256Hex(Buffer.from(canonicalizeJcs({
    schema: material.schema,
    eligibility: material.eligibility,
    profileId: material.profileId,
    instanceId: material.instanceId,
    topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
    verifierRoles: [...DIRECT_V2_PF10_FUSED_VERIFIER_ROLES],
    proofArtifactHashes: material.proofArtifactHashes,
    byteArtifacts,
    layout: {
      bqShardBytes: [...DIRECT_V2_PF10_BQ_SHARD_BYTES],
      exactMsmZeroPaddingBytes:
        DIRECT_V2_PF10_EXACT_MSM_ZERO_PADDING_BYTES,
      nonFinalMsmPaddingBytes:
        DIRECT_V2_PF10_NONFINAL_MSM_PADDING_BYTES,
      millerZeroPaddingBytes:
        DIRECT_V2_PF10_MILLER_ZERO_PADDING_BYTES,
      executorDensityPadBytes:
        DIRECT_V2_PF10_EXECUTOR_DENSITY_PAD_BYTES,
      executorFunctionId:
        DIRECT_V2_PF10_EXECUTOR_FUNCTION_ID,
      verifierUnlockBytes:
        [...DIRECT_V2_PF10_VERIFIER_UNLOCK_BYTES],
      stateUnlockBytes: DIRECT_V2_PF10_STATE_UNLOCK_BYTES,
    },
  }), 'utf8'));
}

/**
 * Validate the exact immutable, descriptor-pinned material required to turn
 * one verified Groth16 result into the ten PF10 verifier unlocks.
 *
 * This boundary performs no compilation, optimization, proving, signing,
 * network access, or fallback. Large proof artifacts remain path/hash records
 * at the caller; only the small VK and exact precompiled unlock materials are
 * accepted here.
 */
function validateDirectV2Pf10RuntimeMaterialForLane(value, {
  eligibility,
  schema,
  validatedMaterials,
}) {
  exactKeys(value, [
    'bindingLockingBytecode',
    'bindingRedeemBytecode',
    'eligibility',
    'exactMsmRedeems',
    'executorBody',
    'fixedCarrierPads',
    'fusedRedeem',
    'instanceId',
    'profileId',
    'proofArtifactHashes',
    'schema',
    'stateUnlockingBytecode',
    'terminalRedeem',
    'topologyId',
    'verificationKeyBytes',
    'verifierLockingBytecodes',
    'verifierRoles',
  ], 'PF10 runtime material');
  if (value.schema !== schema) {
    fail('PF10_RUNTIME_INVALID', 'PF10 runtime material schema is unsupported');
  }
  if (
    value.topologyId !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
    || value.eligibility !== eligibility
  ) {
    fail(
      'PF10_RUNTIME_INVALID',
      'PF10 runtime topology or qualification eligibility is invalid',
    );
  }
  const verifierRoles = exactRoles(value.verifierRoles);
  const proofArtifactHashes = hashRecord(
    value.proofArtifactHashes,
    'proofArtifactHashes',
  );
  const verificationKeyBytes = bytes(
    value.verificationKeyBytes,
    'verificationKeyBytes',
  );
  if (
    sha256Hex(verificationKeyBytes)
    !== proofArtifactHashes.verificationKey
  ) {
    fail(
      'PF10_VK_MISMATCH',
      'runtime verification-key bytes differ from the pinned proof artifact',
    );
  }
  let verificationKeyJson;
  let verificationKey;
  try {
    verificationKeyJson = immutableJson(
      parseStrictJson(verificationKeyBytes, 'PF10 verification key'),
      'PF10 verification key',
    );
    verificationKey =
      parseDirectV2MillerVerificationKey(verificationKeyJson);
  } catch (error) {
    fail(
      'PF10_VK_INVALID',
      `PF10 verification key is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
      error,
    );
  }
  const executorBody = bytes(value.executorBody, 'executorBody');
  const exactMsmRedeems = byteArray(
    value.exactMsmRedeems,
    3,
    'exactMsmRedeems',
  );
  const fixedCarrierPads = byteArray(
    value.fixedCarrierPads,
    3,
    'fixedCarrierPads',
    DIRECT_V2_PF10_NONFINAL_MSM_PADDING_BYTES,
  );
  const fusedRedeem = bytes(value.fusedRedeem, 'fusedRedeem');
  const terminalRedeem = bytes(value.terminalRedeem, 'terminalRedeem');
  const stateUnlockingBytecode = bytes(
    value.stateUnlockingBytecode,
    'stateUnlockingBytecode',
    DIRECT_V2_PF10_STATE_UNLOCK_BYTES,
  );
  const bindingRedeemBytecode = bytes(
    value.bindingRedeemBytecode,
    'bindingRedeemBytecode',
  );
  const bindingLockingBytecode = bytes(
    value.bindingLockingBytecode,
    'bindingLockingBytecode',
  );
  const verifierLockingBytecodes = byteArray(
    value.verifierLockingBytecodes,
    DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length,
    'verifierLockingBytecodes',
  );
  if (!p2sh32Lock(bindingRedeemBytecode).equals(bindingLockingBytecode)) {
    fail(
      'PF10_BINDING_MISMATCH',
      'binding redeem does not match the descriptor-pinned P2SH32 lock',
    );
  }
  exactMsmRedeems.forEach((redeem, index) => {
    if (!p2sh32Lock(redeem).equals(verifierLockingBytecodes[index + 5])) {
      fail(
        'PF10_PROGRAM_LOCK_MISMATCH',
        `exact-MSM redeem ${index} does not match verifier lock ${index + 5}`,
      );
    }
  });
  if (!p2sh32Lock(fusedRedeem).equals(verifierLockingBytecodes[8])) {
    fail(
      'PF10_PROGRAM_LOCK_MISMATCH',
      'fused-Q/genesis redeem does not match verifier lock 8',
    );
  }
  if (!p2sh32Lock(terminalRedeem).equals(verifierLockingBytecodes[9])) {
    fail(
      'PF10_PROGRAM_LOCK_MISMATCH',
      'terminal redeem does not match verifier lock 9',
    );
  }
  const pins = Object.freeze({
    schema,
    eligibility: value.eligibility,
    profileId: exactIdentity(value.profileId, 'profileId'),
    instanceId: exactIdentity(value.instanceId, 'instanceId'),
    topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
    verifierRoles,
    proofArtifactHashes,
    verificationKeyBytes,
    verificationKeyJson,
    verificationKey,
    executorBody,
    exactMsmRedeems,
    fixedCarrierPads,
    fusedRedeem,
    terminalRedeem,
    stateUnlockingBytecode,
    bindingRedeemBytecode,
    bindingLockingBytecode,
    verifierLockingBytecodes,
  });
  const validated = Object.freeze({
    schema: pins.schema,
    eligibility: pins.eligibility,
    profileId: pins.profileId,
    instanceId: pins.instanceId,
    topologyId: pins.topologyId,
    verifierRoles: pins.verifierRoles,
    proofArtifactHashes: pins.proofArtifactHashes,
    materialSha256: materialCommitment(pins),
  });
  validatedMaterials.set(validated, pins);
  return validated;
}

/** Validate normal development/final PF10 material only. */
export function validateDirectV2Pf10RuntimeMaterial(value) {
  if (!ELIGIBILITY.has(value?.eligibility)) {
    fail('PF10_RUNTIME_INVALID', 'PF10 runtime topology or qualification eligibility is invalid');
  }
  return validateDirectV2Pf10RuntimeMaterialForLane(value, {
    eligibility: value?.eligibility,
    schema: DIRECT_V2_PF10_RUNTIME_SCHEMA,
    validatedMaterials: validatedRuntimeMaterials,
  });
}

/**
 * Validate beta-only PF10 material. Its schema and capability are intentionally
 * separate from the descriptor/final runtime lane.
 */
export function validateDirectV2Pf10BetaRuntimeMaterial(value) {
  return validateDirectV2Pf10RuntimeMaterialForLane(value, {
    eligibility: DIRECT_V2_PF10_BETA_ELIGIBILITY,
    schema: DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA,
    validatedMaterials: validatedBetaRuntimeMaterials,
  });
}

function proofResult(value, pins) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
  ) {
    fail('PF10_PROOF_RESULT_INVALID', 'proofResult must be an object');
  }
  const legacyResult =
    value.schema === V2_GROTH16_PROOF_RESULT_SCHEMA
    && value.claims?.witnessValid === true
    && value.claims?.proofVerified === true
    && typeof value.claims?.singleThread === 'boolean';
  const nativeResult =
    value.schema === V2_NATIVE_GROTH16_PROOF_RESULT_SCHEMA
    && value.claims?.witnessCalculated === true
    && value.claims?.witnessR1csChecked === false
    && value.claims?.proofVerified === true
    && value.nativeProver?.backend === 'rapidsnark'
    && typeof value.nativeProver?.sha256 === 'string'
    && HASH.test(value.nativeProver.sha256)
    && Number.isSafeInteger(value.nativeProver?.ompThreads)
    && value.nativeProver.ompThreads >= 1
    && ['threads', 'peakRssKiB', 'userTicks', 'systemTicks'].every(
      (name) => Number.isSafeInteger(value.nativeProver?.[name])
        && value.nativeProver[name] >= 0,
    );
  if (
    (!legacyResult && !nativeResult)
    || value.proof === null
    || Array.isArray(value.proof)
    || typeof value.proof !== 'object'
    || !Array.isArray(value.publicInputs)
    || value.publicInputs.length !== 2
    || PROOF_ARTIFACT_NAMES.some(
      (name) =>
        value.sourceHashes?.[name] !== pins.proofArtifactHashes[name],
    )
  ) {
    fail(
      'PF10_PROOF_RESULT_INVALID',
      'proofResult is not one verified result from the pinned artifacts',
    );
  }
  const publicInputs = value.publicInputs.map((entry, index) => {
    if (
      typeof entry !== 'string'
      || !DECIMAL.test(entry)
      || BigInt(entry) > MAX_U128
    ) {
      fail(
        'PF10_PROOF_RESULT_INVALID',
        `proofResult public input ${index} is not a canonical u128`,
      );
    }
    return entry;
  });
  return Object.freeze({
    proof: immutableJson(value.proof, 'proofResult.proof'),
    publicInputs: Object.freeze(publicInputs),
    resultSha256:
      typeof value.resultSha256 === 'string' && HASH.test(value.resultSha256)
        ? value.resultSha256
        : null,
  });
}

function exactPacket(value, denominationSats, pins) {
  if (!(value instanceof Uint8Array) || value.length !== ACTION_PACKET_BYTES) {
    fail(
      'PF10_PACKET_INVALID',
      `actionPacket must contain exactly ${ACTION_PACKET_BYTES} bytes`,
    );
  }
  const packet = Buffer.from(value);
  let decoded;
  try {
    decoded = decodeActionPacket(packet, { denominationSats });
  } catch (error) {
    fail(
      'PF10_PACKET_INVALID',
      error instanceof Error ? error.message : String(error),
      error,
    );
  }
  if (
    decoded.preState.profileId !== pins.profileId
    || decoded.postState.profileId !== pins.profileId
    || decoded.instanceId !== pins.instanceId
  ) {
    fail(
      'PF10_PACKET_IDENTITY_MISMATCH',
      'action packet profile or instance differs from runtime material',
    );
  }
  return Object.freeze({ packet, decoded });
}

function splitBq(bigQ) {
  const total = DIRECT_V2_PF10_BQ_SHARD_BYTES.reduce(
    (sum, length) => sum + length,
    0,
  );
  if (!(bigQ instanceof Uint8Array) || bigQ.length !== total) {
    fail(
      'PF10_WITNESS_INVALID',
      `PairFold big-Q witness must contain exactly ${total} bytes`,
    );
  }
  let offset = 0;
  return Object.freeze(DIRECT_V2_PF10_BQ_SHARD_BYTES.map((length) => {
    const shard = Buffer.from(bigQ.subarray(offset, offset + length));
    offset += length;
    return shard;
  }));
}

function expectedFixedCarrierPads(template) {
  const blob = concat(...template.roles.map((role) => role.remoteTable));
  return Object.freeze(Array.from({ length: 3 }, (_, index) => {
    const start = index * DIRECT_V2_PF10_NONFINAL_MSM_PADDING_BYTES;
    const end = start + DIRECT_V2_PF10_NONFINAL_MSM_PADDING_BYTES;
    return concat(
      blob.subarray(start, end),
      Buffer.alloc(Math.max(0, end - blob.length)),
    );
  }));
}

function terminalUnlock(template, redeem, targetLength) {
  const fixedBytes =
    encodedLength(template.terminal.state.length)
    + encodedLength(template.terminal.records.length)
    + encodedLength(template.terminal.table.length)
    + encodedLength(redeem.length);
  let paddingBytes = Math.max(1, targetLength - fixedBytes - 3);
  while (
    paddingBytes > 0
    && fixedBytes + encodedLength(paddingBytes) > targetLength
  ) {
    paddingBytes -= 1;
  }
  if (paddingBytes < 1) {
    fail(
      'PF10_UNLOCK_LENGTH_MISMATCH',
      'terminal program cannot fit the topology-pinned unlock length',
    );
  }
  const unlock = Buffer.from(buildDirectV2PairFoldTerminalUnlock({
    state: template.terminal.state,
    records: template.terminal.records,
    table: template.terminal.table,
    densityPad: Buffer.alloc(paddingBytes),
    redeem,
  }));
  if (unlock.length !== targetLength) {
    fail(
      'PF10_UNLOCK_LENGTH_MISMATCH',
      `terminal unlock is ${unlock.length} bytes, expected ${targetLength}`,
    );
  }
  return unlock;
}

function assertUnlockLengths(unlocks, stateUnlock) {
  if (
    unlocks.length !== DIRECT_V2_PF10_VERIFIER_UNLOCK_BYTES.length
    || unlocks.some(
      (unlock, index) =>
        unlock.length !== DIRECT_V2_PF10_VERIFIER_UNLOCK_BYTES[index]
        || unlock.length > DIRECT_V2_PF10_MAX_UNLOCK_BYTES,
    )
    || stateUnlock.length !== DIRECT_V2_PF10_STATE_UNLOCK_BYTES
    || stateUnlock.length > DIRECT_V2_PF10_MAX_UNLOCK_BYTES
  ) {
    fail(
      'PF10_UNLOCK_LENGTH_MISMATCH',
      'PF10 verifier or state unlock differs from the frozen topology lengths',
    );
  }
}

/**
 * Convert exactly one packet-bound, locally verified proof into the immutable
 * PF10 action witness consumed by `assembleV2DirectSettlement`.
 */
function buildDirectV2Pf10ActionWitnessForLane({
  actionPacket,
  denominationSats,
  proofResult: proofResultValue,
  runtimeMaterial,
} = {}, {
  actionWitnessSchema,
  validatedMaterials,
  validatorName,
}) {
  const pins = validatedMaterials.get(runtimeMaterial);
  if (pins === undefined) {
    fail(
      'PF10_RUNTIME_UNVALIDATED',
      `runtimeMaterial must be returned by ${validatorName}`,
    );
  }
  if (
    typeof denominationSats !== 'string'
    || !DECIMAL.test(denominationSats)
    || BigInt(denominationSats) === 0n
  ) {
    fail(
      'PF10_PACKET_INVALID',
      'denominationSats must be a canonical nonzero decimal string',
    );
  }
  const packet = exactPacket(actionPacket, denominationSats, pins);
  const result = proofResult(proofResultValue, pins);
  const publicInputs = actionPacketPublicLimbs(
    packet.packet,
    { denominationSats },
  );
  if (
    publicInputs.some(
      (entry, index) => entry !== result.publicInputs[index],
    )
  ) {
    fail(
      'PF10_PUBLIC_INPUT_MISMATCH',
      'verified proof public inputs differ from the exact action packet digest',
    );
  }
  let msm;
  let trace;
  let template;
  let precomputedTemplate;
  try {
    msm = computeDirectV2ExactMsm(
      pins.verificationKeyJson,
      BigInt(publicInputs[0]),
      BigInt(publicInputs[1]),
    );
    trace = computeDirectV2IdentityAwareMiller({
      verificationKey: pins.verificationKey,
      proof: result.proof,
      q: msm.output,
    });
    template = buildDirectV2TotalPairFoldWitness(trace);
    precomputedTemplate = buildDirectV2TotalPairFoldWitness(
      trace,
      { precomputedFixedLines: true },
    );
  } catch (error) {
    fail(
      'PF10_WITNESS_INVALID',
      `PF10 witness derivation failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
      error,
    );
  }
  const expectedPads = expectedFixedCarrierPads(precomputedTemplate);
  if (
    pins.fixedCarrierPads.some(
      (pad, index) => !sameBytes(pad, expectedPads[index]),
    )
  ) {
    fail(
      'PF10_FIXED_TABLE_MISMATCH',
      'proof/VK-derived fixed-line carriers differ from pinned deployment bytes',
    );
  }
  const fragments = splitDirectV2PairFoldBody(pins.executorBody);
  const fragmentOffsets = precomputedTemplate.roles.map(
    (role, index) =>
      encodedLength(role.state.length)
      + encodedLength(role.records.length)
      + encodedLength(role.table.length)
      + encodedLength(DIRECT_V2_PF10_BQ_SHARD_BYTES[index])
      + 3,
  );
  const loader = buildDirectV2PairFoldLoader({
    body: pins.executorBody,
    fragmentOffsets,
    fragmentLengths: fragments.map((fragment) => fragment.length),
    functionId: DIRECT_V2_PF10_EXECUTOR_FUNCTION_ID,
    densityPadBytes: DIRECT_V2_PF10_EXECUTOR_DENSITY_PAD_BYTES,
  });
  for (let index = 0; index < 5; index += 1) {
    if (!sameBytes(loader.lock, pins.verifierLockingBytecodes[index])) {
      fail(
        'PF10_PROGRAM_LOCK_MISMATCH',
        `PairFold loader does not match verifier lock ${index}`,
      );
    }
  }
  const bq = splitBq(template.terminal.bigQ);
  const unlocks = [];
  for (let index = 0; index < 5; index += 1) {
    unlocks.push(Buffer.from(buildDirectV2PairFoldUnlock({
      state: precomputedTemplate.roles[index].state,
      records: precomputedTemplate.roles[index].records,
      table: precomputedTemplate.roles[index].table,
      bqShard: bq[index],
      bodyFragment: fragments[index],
      densityPad: loader.densityPad,
      loader: loader.loader,
    })));
  }
  for (let windowIndex = 0; windowIndex < 3; windowIndex += 1) {
    unlocks.push(concat(
      push(encodeDirectV2MsmState(msm.states[windowIndex])),
      push(Buffer.alloc(0)),
      push(pins.fixedCarrierPads[windowIndex]),
      push(pins.exactMsmRedeems[windowIndex]),
    ));
  }
  const packetDigest = createHash('sha256')
    .update(packet.packet)
    .digest();
  const projectionSignal = encodeDirectV2MillerProjectionSignal(
    trace,
    packetDigest,
  );
  const millerWitness = encodeDirectV2MillerGenesisWitness(trace);
  unlocks.push(Buffer.from(buildDirectV2Pf10FusedQGenesisUnlock({
    projectionSignal,
    msmState: encodeDirectV2MsmState(msm.states[3]),
    zInverse: msm.output.zInverse,
    exactMsmZeroPadding:
      Buffer.alloc(DIRECT_V2_PF10_EXACT_MSM_ZERO_PADDING_BYTES),
    slope: millerWitness.slope,
    endpoint: millerWitness.endpoint,
    residue: millerWitness.residue,
    millerZeroPadding:
      Buffer.alloc(DIRECT_V2_PF10_MILLER_ZERO_PADDING_BYTES),
    redeem: pins.fusedRedeem,
  })));
  unlocks.push(terminalUnlock(
    template,
    pins.terminalRedeem,
    DIRECT_V2_PF10_VERIFIER_UNLOCK_BYTES[9],
  ));
  const stateUnlockingBytecode = Buffer.from(
    pins.stateUnlockingBytecode,
  );
  assertUnlockLengths(unlocks, stateUnlockingBytecode);
  const bindingUnlockingBytecode = Buffer.from(
    encodeDirectV2BindingUnlock({
      packet: packet.packet,
      redeemScript: pins.bindingRedeemBytecode,
      sourceLockingBytecode: pins.bindingLockingBytecode,
    }),
  );
  const witness = Object.freeze({
    schema: actionWitnessSchema,
    topologyId: pins.topologyId,
    verifierRoles: pins.verifierRoles,
    eligibility: pins.eligibility,
    profileId: pins.profileId,
    instanceId: pins.instanceId,
    materialSha256: runtimeMaterial.materialSha256,
    proofResultSha256: result.resultSha256,
    publicInputs,
    actionPacket: Uint8Array.from(packet.packet),
    packetSha256: packetDigest.toString('hex'),
    verifierUnlockingBytecodes: Object.freeze(
      unlocks.map((unlock) => Uint8Array.from(unlock)),
    ),
    bindingUnlockingBytecode:
      Uint8Array.from(bindingUnlockingBytecode),
    stateUnlockingBytecode:
      Uint8Array.from(stateUnlockingBytecode),
    measurements: Object.freeze({
      verifierUnlockBytes: Object.freeze(
        unlocks.map((unlock) => unlock.length),
      ),
      bindingUnlockBytes: bindingUnlockingBytecode.length,
      stateUnlockBytes: stateUnlockingBytecode.length,
      maximumUnlockBytes: Math.max(
        bindingUnlockingBytecode.length,
        stateUnlockingBytecode.length,
        ...unlocks.map((unlock) => unlock.length),
      ),
    }),
  });
  return witness;
}

/** Convert normal development/final PF10 material into an action witness. */
export function buildDirectV2Pf10ActionWitness(value = {}) {
  return buildDirectV2Pf10ActionWitnessForLane(value, {
    actionWitnessSchema: DIRECT_V2_PF10_ACTION_WITNESS_SCHEMA,
    validatedMaterials: validatedRuntimeMaterials,
    validatorName: 'validateDirectV2Pf10RuntimeMaterial',
  });
}

/** Convert beta-only PF10 material into a beta-only action witness. */
export function buildDirectV2Pf10BetaActionWitness(value = {}) {
  return buildDirectV2Pf10ActionWitnessForLane(value, {
    actionWitnessSchema: DIRECT_V2_PF10_BETA_ACTION_WITNESS_SCHEMA,
    validatedMaterials: validatedBetaRuntimeMaterials,
    validatorName: 'validateDirectV2Pf10BetaRuntimeMaterial',
  });
}
