/**
 * Offline construction of the exact V2 Direct CashTokens genesis transaction.
 *
 * This module accepts no private key and has no network or broadcast path.
 * The caller supplies an authenticated raw funding transaction, receives one
 * exact BCH Schnorr signing request, and returns only the 64-byte signature.
 */
import { createHash } from 'node:crypto';

import {
  createVirtualMachineBch2026,
  decodeTransaction,
  encodeDataPush,
  encodeTransaction,
  generateSigningSerializationBch,
  hash160,
  hash256,
  secp256k1,
} from '@bitauth/libauth';

import {
  createDirectV2PoolModel,
} from '../../action/v2/transition.mjs';
import {
  deriveV2RollingBaseSats,
} from '../../action/v2/dust-policy.mjs';
import {
  encodeStateNftCommitment,
  MAX_MONEY_SATS,
} from '../../action/v2/state.mjs';
import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
  resolveDirectV2VerifierTopology,
} from '../../action/v2/topology.mjs';
import {
  verifyDirectV2BindingP2sh32Lock,
} from '../../action/v2/binding-unlock.mjs';
import {
  V2_FUNDING_SIGHASH_TYPE,
} from '../../action/v2/settlement.mjs';
import {
  buildDirectV2Pf10BetaRuntime,
  buildDirectV2Pf10DevelopmentRuntime,
} from '../../unlock-builder/v2/pf10-development-runtime-builder.mjs';
import {
  assertV2StandardTransactionEnvelope,
  parseSerializedSourceOutput,
  parseV2RawTransaction,
} from '../../kit/v2/transaction-policy.mjs';
import {
  assertV2VmResourceMetrics,
} from '../../kit/v2/vm-evidence.mjs';
import {
  canonicalizeJcs,
  deriveProfileId,
  validateProfileCore,
} from './profile-core.mjs';
import {
  assertV2BetaChipnetRuntimeResolution,
  deriveV2BetaChipnetSettlementPins,
} from './beta-chipnet-runtime.mjs';

export const V2_GENESIS_INTENT_SCHEMA =
  'shieldkit-v2-direct-genesis-intent-v1';
export const V2_GENESIS_PREPARED_SCHEMA =
  'shieldkit-v2-direct-genesis-prepared-v1';
export const V2_GENESIS_FINALIZED_SCHEMA =
  'shieldkit-v2-direct-genesis-finalized-v1';
export const V2_GENESIS_RUNTIME_SCHEMA =
  'shieldkit-v2-direct-authenticated-genesis-runtime-v1';
export const V2_BETA_CHIPNET_GENESIS_RUNTIME_SCHEMA =
  'shieldkit-v2-direct-beta-chipnet-authenticated-genesis-runtime-v1';
export const V2_GENESIS_TRANSACTION_VERSION = 2;
export const V2_GENESIS_INPUT_SEQUENCE = 0;
export const V2_GENESIS_LOCKTIME = 0;
export const V2_GENESIS_FEE_RATE_SATS_PER_BYTE = '1';
export const V2_GENESIS_MINIMUM_CHANGE_SATS = 546n;

const HEX = /^[0-9a-f]*$/;
const HEX_32 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const VM_METRIC_FIELDS = Object.freeze([
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
const validatedGenesisRuntimePins = new WeakMap();
const validatedFinalizedGenesisPins = new WeakMap();

export class V2GenesisError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options);
    this.name = 'V2GenesisError';
    this.code = code;
  }
}

const fail = (code, message, options) => {
  throw new V2GenesisError(code, message, options);
};

function exactKeys(value, label, expected) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('GENESIS_INPUT_INVALID', `${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])
  ) {
    fail(
      'GENESIS_INPUT_INVALID',
      `${label} has missing or unknown properties`,
    );
  }
}

function decimal(value, label, {
  minimum = 0n,
  maximum = MAX_MONEY_SATS,
} = {}) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) {
    fail(
      'GENESIS_INPUT_INVALID',
      `${label} must be a canonical unsigned decimal string`,
    );
  }
  const parsed = BigInt(value);
  if (parsed < minimum || parsed > maximum) {
    fail('GENESIS_INPUT_INVALID', `${label} is outside its allowed range`);
  }
  return parsed;
}

function bytes(value, label, length = undefined) {
  if (
    typeof value !== 'string'
    || value.length % 2 !== 0
    || !HEX.test(value)
    || (length !== undefined && value.length !== length * 2)
  ) {
    fail(
      'GENESIS_INPUT_INVALID',
      `${label} must be canonical lowercase hexadecimal${
        length === undefined ? '' : ` of exactly ${length} bytes`
      }`,
    );
  }
  return Buffer.from(value, 'hex');
}

function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

function p2pkhLock(publicKey) {
  return Buffer.concat([
    Buffer.from([0x76, 0xa9, 0x14]),
    Buffer.from(hash160(publicKey)),
    Buffer.from([0x88, 0xac]),
  ]);
}

function canonicalP2pkh(value, label) {
  const result = bytes(value, label, 25);
  if (
    result[0] !== 0x76
    || result[1] !== 0xa9
    || result[2] !== 0x14
    || result[23] !== 0x88
    || result[24] !== 0xac
  ) {
    fail('GENESIS_INPUT_INVALID', `${label} must be canonical P2PKH`);
  }
  return result;
}

function publicKey(value) {
  const result = bytes(value, 'fundingPublicKeyHex', 33);
  if (
    ![0x02, 0x03].includes(result[0])
    || !secp256k1.validatePublicKey(result)
  ) {
    fail(
      'GENESIS_INPUT_INVALID',
      'fundingPublicKeyHex must be a valid compressed secp256k1 public key',
    );
  }
  return result;
}

function proofArtifactPins(value, profileCore) {
  exactKeys(value, 'proofArtifacts', [
    'provingKey',
    'r1cs',
    'verificationKey',
    'wasm',
  ]);
  const pins = Object.fromEntries(Object.entries(value).map(
    ([name, record]) => {
      exactKeys(record, `proofArtifacts.${name}`, ['path', 'sha256']);
      if (
        typeof record.path !== 'string'
        || typeof record.sha256 !== 'string'
        || !HEX_32.test(record.sha256)
      ) {
        fail(
          'GENESIS_RUNTIME_INVALID',
          `proofArtifacts.${name} must contain an absolute path and SHA-256`,
        );
      }
      return [name, Object.freeze({ ...record })];
    },
  ));
  for (const [name, expected] of [
    ['r1cs', profileCore.proof.r1csSha256],
    ['verificationKey', profileCore.proof.verificationKeySha256],
    ['wasm', profileCore.proof.witnessWasmSha256],
  ]) {
    if (pins[name].sha256 !== expected) {
      fail(
        'GENESIS_RUNTIME_INVALID',
        `proofArtifacts.${name} differs from the profile core`,
      );
    }
  }
  return Object.freeze(pins);
}

function exactRuntimeTopology(build) {
  let topology;
  try {
    topology = resolveDirectV2VerifierTopology({
      id: build.topologyId,
      verifierRoles: build.verifierRoles,
    });
  } catch (error) {
    fail(
      'GENESIS_RUNTIME_INVALID',
      `PF10 runtime topology is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  if (
    topology.id !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
    || topology.verifierRoles.length
      !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length
    || topology.verifierRoles.some(
      (role, index) => role !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES[index],
    )
  ) {
    fail(
      'GENESIS_RUNTIME_INVALID',
      'genesis runtime is not the exact PF10-FusedQGenesis topology',
    );
  }
  return topology;
}

function exactDustDerivedBase(lockingBytecode, actual, label, token) {
  const expected = deriveV2RollingBaseSats({
    lockingBytecode,
    ...(token === undefined ? {} : { token }),
  });
  if (actual !== expected) {
    fail(
      'GENESIS_RUNTIME_INVALID',
      `${label} base is ${actual}, expected exact dust-derived ${expected}`,
    );
  }
  return actual;
}

function finalLocksCommitment(value) {
  return sha256Hex(Buffer.from(canonicalizeJcs({
    topologyId: value.topology.id,
    verifiers: value.verifiers.map((entry) => ({
      role: entry.role,
      baseSats: entry.baseSats.toString(),
      lockingBytecodeSha256: sha256Hex(entry.lockingBytecode),
    })),
    binding: {
      baseSats: value.binding.baseSats.toString(),
      lockingBytecodeSha256: sha256Hex(value.binding.lockingBytecode),
      redeemBytecodeSha256: sha256Hex(value.binding.redeemBytecode),
    },
    state: {
      baseSats: value.state.baseSats.toString(),
      lockingBytecodeSha256: sha256Hex(value.state.lockingBytecode),
      helperBytecodeSha256: sha256Hex(value.state.helperBytecode),
      helperUnlockingBytecodeSha256:
        sha256Hex(value.state.helperUnlockingBytecode),
    },
  }), 'utf8'));
}

function copyFinalLocks(value) {
  return Object.freeze({
    topology: value.topology,
    verifiers: Object.freeze(value.verifiers.map((entry) => Object.freeze({
      role: entry.role,
      baseSats: entry.baseSats,
      lockingBytecode: Buffer.from(entry.lockingBytecode),
    }))),
    binding: Object.freeze({
      baseSats: value.binding.baseSats,
      lockingBytecode: Buffer.from(value.binding.lockingBytecode),
      redeemBytecode: Buffer.from(value.binding.redeemBytecode),
    }),
    state: Object.freeze({
      baseSats: value.state.baseSats,
      lockingBytecode: Buffer.from(value.state.lockingBytecode),
      helperBytecode: Buffer.from(value.state.helperBytecode),
      helperUnlockingBytecode:
        Buffer.from(value.state.helperUnlockingBytecode),
    }),
  });
}

function issueGenesisRuntimeFromBuild({ build, instanceId, lane, profileCore }) {
  const profileId = deriveProfileId(profileCore);
  if (
    build.profileId !== profileId
    || build.instanceId !== instanceId
    || build.denominationSats !== profileCore.denominationSats
  ) {
    fail(
      'GENESIS_RUNTIME_INVALID',
      'PF10 runtime identity differs from the profile and instance',
    );
  }
  const topology = exactRuntimeTopology(build);
  const verifiers = Object.freeze(build.structural.verifierLocks.map(
    (lockingBytecode, index) => {
      const baseSats = BigInt(build.baseValues.verifierSats[index]);
      return Object.freeze({
        role: topology.verifierRoles[index],
        baseSats: exactDustDerivedBase(
          lockingBytecode,
          baseSats,
          `verifier ${index}`,
        ),
        lockingBytecode: Buffer.from(lockingBytecode),
      });
    },
  ));
  const binding = Object.freeze({
    baseSats: exactDustDerivedBase(
      build.structural.bindingLock,
      BigInt(build.baseValues.bindingSats),
      'binding',
    ),
    lockingBytecode: Buffer.from(build.structural.bindingLock),
    redeemBytecode: Buffer.from(build.structural.bindingRedeem),
  });
  try {
    verifyDirectV2BindingP2sh32Lock({
      redeemScript: binding.redeemBytecode,
      sourceLockingBytecode: binding.lockingBytecode,
    });
  } catch (error) {
    fail(
      'GENESIS_RUNTIME_INVALID',
      `PF10 binding lock/redeem pair is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  const stateToken = {
    category: Buffer.from(instanceId, 'hex'),
    amount: 0n,
    nft: { capability: 'mutable', commitment: Buffer.alloc(128) },
  };
  const state = Object.freeze({
    baseSats: exactDustDerivedBase(
      build.structural.stateLock,
      BigInt(build.baseValues.stateSats),
      'state',
      stateToken,
    ),
    lockingBytecode: Buffer.from(build.structural.stateLock),
    helperBytecode: Buffer.from(build.structural.stateHelper),
    helperUnlockingBytecode: Buffer.from(build.structural.stateUnlock),
  });
  const finalLocks = Object.freeze({ topology, verifiers, binding, state });
  const finalLocksSha256 = finalLocksCommitment(finalLocks);
  const handle = Object.freeze({
    schema: lane.schema,
    eligibility: lane.eligibility,
    profileId,
    instanceId,
    topologyId: topology.id,
    runtimeMaterialSha256: build.runtimeMaterial.materialSha256,
    finalLocksSha256,
    baseValues: Object.freeze({
      verifierSats: Object.freeze(verifiers.map((entry) => entry.baseSats.toString())),
      bindingSats: binding.baseSats.toString(),
      stateSats: state.baseSats.toString(),
    }),
  });
  validatedGenesisRuntimePins.set(handle, Object.freeze({
    schema: lane.schema,
    eligibility: lane.eligibility,
    profileId,
    instanceId,
    runtimeMaterialSha256: build.runtimeMaterial.materialSha256,
    finalLocksSha256,
    finalLocks,
  }));
  return handle;
}

/**
 * Deterministically build and authenticate all instance-specific genesis
 * locks. The returned handle is intentionally opaque: only a handle created
 * by this function is accepted by prepare/finalize.
 */
async function createGenesisRuntimeForLane(options, lane) {
  exactKeys(options, 'genesis runtime options', [
    ...(Object.hasOwn(options, 'artifactRoot') ? ['artifactRoot'] : []),
    'instanceId',
    'profileCore',
    'proofArtifacts',
    'repositoryRoot',
    'temporaryRoot',
  ]);
  const {
    artifactRoot,
    instanceId,
    profileCore,
    proofArtifacts,
    repositoryRoot,
    temporaryRoot,
  } = options;
  try {
    validateProfileCore(profileCore);
  } catch (error) {
    fail(
      'GENESIS_RUNTIME_INVALID',
      `profileCore is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  if (typeof instanceId !== 'string' || !HEX_32.test(instanceId)) {
    fail(
      'GENESIS_RUNTIME_INVALID',
      'instanceId must be exactly 32 lowercase hexadecimal bytes',
    );
  }
  const profileId = deriveProfileId(profileCore);
  const pins = proofArtifactPins(proofArtifacts, profileCore);
  let build;
  try {
    build = await lane.buildRuntime({
      repositoryRoot,
      ...(artifactRoot === undefined ? {} : { artifactRoot }),
      temporaryRoot,
      profileId,
      instanceId,
      proofArtifacts: pins,
    });
  } catch (error) {
    fail(
      'GENESIS_RUNTIME_INVALID',
      `PF10 runtime construction failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  return issueGenesisRuntimeFromBuild({ build, instanceId, lane, profileCore });
}

/**
 * Build the ordinary development-only authenticated V2 genesis runtime.
 */
export async function createV2GenesisRuntime(options = {}) {
  return createGenesisRuntimeForLane(options, Object.freeze({
    buildRuntime: buildDirectV2Pf10DevelopmentRuntime,
    eligibility: 'development-only',
    schema: V2_GENESIS_RUNTIME_SCHEMA,
  }));
}

/**
 * Build a separately branded single-contributor beta Chipnet genesis runtime.
 * This capability is intentionally not accepted by the normal descriptor or
 * action-runtime lanes.
 */
export async function createV2BetaChipnetGenesisRuntime(options = {}) {
  return createGenesisRuntimeForLane(options, Object.freeze({
    buildRuntime: buildDirectV2Pf10BetaRuntime,
    eligibility: 'beta-single-contributor-unqualified',
    schema: V2_BETA_CHIPNET_GENESIS_RUNTIME_SCHEMA,
  }));
}

/**
 * Issue the same opaque beta genesis capability from an already verified,
 * branded runtime resolution. This avoids compiling the identical PF10
 * instance a second time during pool creation; every lock, base value, helper,
 * topology role, and material hash was validator-authenticated by the cold
 * runtime verification and is copied from its branded resolution here.
 */
export function createV2BetaChipnetGenesisRuntimeFromResolution(options = {}) {
  exactKeys(options, 'beta genesis runtime resolution options', [
    'profileCore',
    'runtimeResolution',
  ]);
  try { validateProfileCore(options.profileCore); }
  catch (error) {
    fail('GENESIS_RUNTIME_INVALID', `profileCore is invalid: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
  }
  let runtime;
  try { runtime = assertV2BetaChipnetRuntimeResolution(options.runtimeResolution); }
  catch (error) {
    fail('GENESIS_RUNTIME_INVALID', 'a branded verified beta runtime resolution is required', { cause: error });
  }
  const profileId = deriveProfileId(options.profileCore);
  if (runtime.identity.profileId !== profileId
    || runtime.identity.denominationSats !== options.profileCore.denominationSats) {
    fail('GENESIS_RUNTIME_INVALID', 'verified runtime resolution differs from the supplied profile core');
  }
  const pins = deriveV2BetaChipnetSettlementPins(runtime);
  const build = Object.freeze({
    profileId,
    instanceId: runtime.identity.instanceId,
    denominationSats: runtime.identity.denominationSats,
    topologyId: pins.topologyId,
    verifierRoles: pins.verifierRoles,
    baseValues: Object.freeze({
      verifierSats: Object.freeze(pins.verifierCarriers.map((entry) => entry.baseValueSats)),
      bindingSats: pins.bindingBaseSats,
      stateSats: pins.stateBaseSats,
    }),
    structural: Object.freeze({
      verifierLocks: Object.freeze(pins.verifierCarriers.map((entry) => Buffer.from(entry.lockingBytecode))),
      bindingLock: Buffer.from(pins.bindingLockingBytecode),
      bindingRedeem: Buffer.from(pins.bindingRedeemBytecode),
      stateLock: Buffer.from(pins.stateLockingBytecode),
      stateHelper: Buffer.from(pins.stateHelperBytecode),
      stateUnlock: Buffer.from(pins.stateUnlockingBytecode),
    }),
    runtimeMaterial: runtime.runtimeMaterial,
  });
  return issueGenesisRuntimeFromBuild({
    build,
    instanceId: runtime.identity.instanceId,
    lane: Object.freeze({
      eligibility: 'beta-single-contributor-unqualified',
      schema: V2_BETA_CHIPNET_GENESIS_RUNTIME_SCHEMA,
    }),
    profileCore: options.profileCore,
  });
}

function genesisRuntimePins(value) {
  const pins = validatedGenesisRuntimePins.get(value);
  if (pins === undefined) {
    fail(
      'GENESIS_RUNTIME_INVALID',
      'genesis requires an opaque runtime returned by createV2GenesisRuntime',
    );
  }
  return pins;
}

function normalizeIntent(value, runtimeValue) {
  exactKeys(value, 'genesis intent', [
    'changeLockingBytecodeHex',
    'feeRateSatsPerByte',
    'fundingPublicKeyHex',
    'maximumLiveNotes',
    'profileCore',
    'schema',
    'sourceTransactionHex',
  ]);
  if (value.schema !== V2_GENESIS_INTENT_SCHEMA) {
    fail('GENESIS_INPUT_INVALID', 'genesis intent schema is unsupported');
  }
  let profileCore;
  try {
    validateProfileCore(value.profileCore);
    profileCore = value.profileCore;
  } catch (error) {
    fail(
      'GENESIS_INPUT_INVALID',
      `profileCore is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  if (
    profileCore.network.id !== 2
    || profileCore.network.name !== 'chipnet'
  ) {
    fail(
      'GENESIS_INPUT_INVALID',
      'development V2 genesis requires the exact Chipnet profile',
    );
  }
  const profileId = deriveProfileId(profileCore);
  const maximumLiveNotes = decimal(
    value.maximumLiveNotes,
    'maximumLiveNotes',
    { minimum: 1n, maximum: 0xffff_ffffn },
  );
  const fundingPublicKey = publicKey(value.fundingPublicKeyHex);
  const changeLockingBytecode = canonicalP2pkh(
    value.changeLockingBytecodeHex,
    'changeLockingBytecodeHex',
  );
  if (value.feeRateSatsPerByte !== V2_GENESIS_FEE_RATE_SATS_PER_BYTE) {
    fail(
      'GENESIS_INPUT_INVALID',
      'feeRateSatsPerByte must be exactly one satoshi per signed byte',
    );
  }
  let sourceTransaction;
  try {
    sourceTransaction = parseV2RawTransaction(value.sourceTransactionHex);
  } catch (error) {
    fail(
      'GENESIS_SOURCE_INVALID',
      `sourceTransactionHex is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  if (!HEX_32.test(sourceTransaction.txid) || /^0+$/.test(sourceTransaction.txid)) {
    fail('GENESIS_SOURCE_INVALID', 'source transaction ID is invalid');
  }
  const sourceSerializedOutput = sourceTransaction.outputs[0]?.serializedHex;
  if (sourceSerializedOutput === undefined) {
    fail(
      'GENESIS_SOURCE_INVALID',
      'source transaction must contain funding output zero',
    );
  }
  let sourceOutput;
  try {
    sourceOutput = parseSerializedSourceOutput(sourceSerializedOutput);
  } catch (error) {
    fail(
      'GENESIS_SOURCE_INVALID',
      `funding output zero is malformed: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  const expectedFundingLock = p2pkhLock(fundingPublicKey);
  if (
    sourceOutput.token !== null
    || !sourceOutput.lockingBytecode.equals(expectedFundingLock)
  ) {
    fail(
      'GENESIS_SOURCE_INVALID',
      'funding output zero must be tokenless and locked to the declared compressed public key',
    );
  }
  const instanceId = Buffer.from(sourceTransaction.txid, 'hex')
    .reverse()
    .toString('hex');
  const runtime = genesisRuntimePins(runtimeValue);
  if (
    runtime.profileId !== profileId
    || runtime.instanceId !== instanceId
  ) {
    fail(
      'GENESIS_RUNTIME_MISMATCH',
      'authenticated PF10 runtime does not match the exact profile and funding-derived instance',
    );
  }
  const finalLocks = copyFinalLocks(runtime.finalLocks);
  let model;
  let initialState;
  try {
    model = createDirectV2PoolModel({
      profileId,
      maximumLiveNotes: maximumLiveNotes.toString(),
      denominationSats: profileCore.denominationSats,
    });
    initialState = Buffer.from(encodeStateNftCommitment(model.state, {
      denominationSats: profileCore.denominationSats,
    }));
  } catch (error) {
    fail(
      'GENESIS_STATE_INVALID',
      `canonical empty state cannot be constructed: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  return Object.freeze({
    profileCore,
    profileId,
    maximumLiveNotes: maximumLiveNotes.toString(),
    fundingPublicKey,
    changeLockingBytecode,
    sourceTransaction,
    sourceRawTransactionHex: sourceTransaction.rawTransactionHex,
    sourceOutput,
    instanceId,
    runtimeMaterialSha256: runtime.runtimeMaterialSha256,
    runtimeSchema: runtime.schema,
    finalLocksSha256: runtime.finalLocksSha256,
    finalLocks,
    initialState,
  });
}

function libauthSourceOutput(value) {
  return Object.freeze({
    valueSatoshis: value.valueSatoshis,
    lockingBytecode: Uint8Array.from(value.lockingBytecode),
  });
}

function transactionFor(intent, changeSats, fundingUnlockingBytecode) {
  const categoryDisplayOrder = Buffer.from(intent.instanceId, 'hex').reverse();
  return {
    version: V2_GENESIS_TRANSACTION_VERSION,
    inputs: [{
      outpointTransactionHash: Uint8Array.from(categoryDisplayOrder),
      outpointIndex: 0,
      sequenceNumber: V2_GENESIS_INPUT_SEQUENCE,
      unlockingBytecode: Uint8Array.from(fundingUnlockingBytecode),
    }],
    outputs: [
      {
        valueSatoshis: intent.finalLocks.state.baseSats,
        lockingBytecode: Uint8Array.from(
          intent.finalLocks.state.lockingBytecode,
        ),
        token: {
          category: Uint8Array.from(categoryDisplayOrder),
          amount: 0n,
          nft: {
            capability: 'mutable',
            commitment: Uint8Array.from(intent.initialState),
          },
        },
      },
      ...intent.finalLocks.verifiers.map((entry) => ({
        valueSatoshis: entry.baseSats,
        lockingBytecode: Uint8Array.from(entry.lockingBytecode),
      })),
      {
        valueSatoshis: intent.finalLocks.binding.baseSats,
        lockingBytecode: Uint8Array.from(
          intent.finalLocks.binding.lockingBytecode,
        ),
      },
      {
        valueSatoshis: changeSats,
        lockingBytecode: Uint8Array.from(intent.changeLockingBytecode),
      },
    ],
    locktime: V2_GENESIS_LOCKTIME,
  };
}

function signedSizeAndChange(intent) {
  const fixedOutputValue =
    intent.finalLocks.state.baseSats
    + intent.finalLocks.binding.baseSats
    + intent.finalLocks.verifiers.reduce(
      (total, entry) => total + entry.baseSats,
      0n,
    );
  const placeholderUnlock = Buffer.concat([
    Buffer.from(encodeDataPush(Buffer.alloc(65))),
    Buffer.from(encodeDataPush(intent.fundingPublicKey)),
  ]);
  if (placeholderUnlock.length !== 100) {
    fail(
      'GENESIS_INTERNAL_ERROR',
      'canonical placeholder P2PKH unlock is not exactly 100 bytes',
    );
  }
  const sizingTransaction = transactionFor(intent, 1n, placeholderUnlock);
  const signedSizeBytes = Buffer.from(
    encodeTransaction(sizingTransaction),
  ).length;
  const feeSats =
    BigInt(signedSizeBytes) * BigInt(V2_GENESIS_FEE_RATE_SATS_PER_BYTE);
  const changeSats =
    intent.sourceOutput.valueSatoshis - fixedOutputValue - feeSats;
  if (changeSats < V2_GENESIS_MINIMUM_CHANGE_SATS) {
    fail(
      'GENESIS_INSUFFICIENT_FUNDING',
      `funding output cannot pay ${fixedOutputValue} sats in rolling outputs, ${feeSats} sats in fees, and the ${V2_GENESIS_MINIMUM_CHANGE_SATS}-sat minimum change`,
    );
  }
  const exactSizing = transactionFor(intent, changeSats, placeholderUnlock);
  if (Buffer.from(encodeTransaction(exactSizing)).length !== signedSizeBytes) {
    fail(
      'GENESIS_INTERNAL_ERROR',
      'genesis transaction size changed after exact change calculation',
    );
  }
  return Object.freeze({
    fixedOutputValue,
    signedSizeBytes,
    feeSats,
    changeSats,
  });
}

function buildPrepared(value, runtime) {
  const intent = normalizeIntent(value, runtime);
  const sizing = signedSizeAndChange(intent);
  const unsignedTransaction = transactionFor(
    intent,
    sizing.changeSats,
    Buffer.alloc(0),
  );
  const sourceOutputs = [libauthSourceOutput(intent.sourceOutput)];
  const signingSerialization = Buffer.from(
    generateSigningSerializationBch(
      {
        inputIndex: 0,
        sourceOutputs,
        transaction: unsignedTransaction,
      },
      {
        coveredBytecode: sourceOutputs[0].lockingBytecode,
        signingSerializationType:
          Uint8Array.of(V2_FUNDING_SIGHASH_TYPE),
      },
    ),
  );
  const signingDigest = Buffer.from(hash256(signingSerialization));
  return Object.freeze({
    intent,
    sizing,
    unsignedTransaction,
    unsignedTransactionHex: Buffer.from(
      encodeTransaction(unsignedTransaction),
    ).toString('hex'),
    signingSerialization,
    signingDigest,
  });
}

function preparedEnvelope(payload, built) {
  return Object.freeze({
    schema: V2_GENESIS_PREPARED_SCHEMA,
    stage: 'prepared',
    payload,
    payloadSha256: sha256Hex(Buffer.from(payload, 'utf8')),
    profileId: built.intent.profileId,
    instanceId: built.intent.instanceId,
    runtime: Object.freeze({
      schema: built.intent.runtimeSchema,
      runtimeMaterialSha256: built.intent.runtimeMaterialSha256,
      finalLocksSha256: built.intent.finalLocksSha256,
      topologyId: built.intent.finalLocks.topology.id,
      baseValues: Object.freeze({
        verifierSats: Object.freeze(
          built.intent.finalLocks.verifiers.map(
            (entry) => entry.baseSats.toString(),
          ),
        ),
        bindingSats: built.intent.finalLocks.binding.baseSats.toString(),
        stateSats: built.intent.finalLocks.state.baseSats.toString(),
      }),
    }),
    initialStateHex: built.intent.initialState.toString('hex'),
    unsignedTransactionHex: built.unsignedTransactionHex,
    signingRequest: Object.freeze({
      algorithm: 'BCH_SCHNORR_SECP256K1',
      inputIndex: 0,
      publicKeyHex: built.intent.fundingPublicKey.toString('hex'),
      sighashContract: 'SIGHASH_ALL|UTXOS|FORKID',
      sighashType: V2_FUNDING_SIGHASH_TYPE,
      signingSerializationHex: built.signingSerialization.toString('hex'),
      digestHex: built.signingDigest.toString('hex'),
    }),
    measurements: Object.freeze({
      signedSizeBytes: built.sizing.signedSizeBytes,
      feeRateSatsPerByte: V2_GENESIS_FEE_RATE_SATS_PER_BYTE,
      feeSats: built.sizing.feeSats.toString(),
      changeSats: built.sizing.changeSats.toString(),
      rollingOutputValueSats:
        built.sizing.fixedOutputValue.toString(),
      inputCount: 1,
      outputCount: 13,
    }),
  });
}

function inspectPrepared(value, runtime) {
  exactKeys(value, 'prepared genesis', [
    'initialStateHex',
    'instanceId',
    'measurements',
    'payload',
    'payloadSha256',
    'profileId',
    'runtime',
    'schema',
    'signingRequest',
    'stage',
    'unsignedTransactionHex',
  ]);
  if (
    value.schema !== V2_GENESIS_PREPARED_SCHEMA
    || value.stage !== 'prepared'
    || typeof value.payload !== 'string'
    || value.payloadSha256
      !== sha256Hex(Buffer.from(value.payload, 'utf8'))
  ) {
    fail(
      'GENESIS_PREPARED_MUTATED',
      'prepared genesis schema, stage, or payload hash is invalid',
    );
  }
  let intent;
  try {
    intent = JSON.parse(value.payload);
  } catch (error) {
    fail(
      'GENESIS_PREPARED_MUTATED',
      'prepared genesis payload is not JSON',
      { cause: error },
    );
  }
  if (canonicalizeJcs(intent) !== value.payload) {
    fail(
      'GENESIS_PREPARED_MUTATED',
      'prepared genesis payload is not exact RFC8785/JCS',
    );
  }
  const built = buildPrepared(intent, runtime);
  const expected = preparedEnvelope(value.payload, built);
  if (canonicalizeJcs(expected) !== canonicalizeJcs(value)) {
    fail(
      'GENESIS_PREPARED_MUTATED',
      'prepared genesis differs from its exact re-derived transaction',
    );
  }
  return built;
}

function canonicalFundingUnlock(signature, publicKey) {
  const withType = Buffer.concat([
    signature,
    Buffer.from([V2_FUNDING_SIGHASH_TYPE]),
  ]);
  const unlock = Buffer.concat([
    Buffer.from(encodeDataPush(withType)),
    Buffer.from(encodeDataPush(publicKey)),
  ]);
  if (
    unlock.length !== 100
    || unlock[0] !== 0x41
    || unlock[65] !== V2_FUNDING_SIGHASH_TYPE
    || unlock[66] !== 0x21
  ) {
    fail(
      'GENESIS_INTERNAL_ERROR',
      'funding signature does not encode as the canonical 100-byte P2PKH unlock',
    );
  }
  return unlock;
}

function inspectFinalTransaction(built, transaction, encoded) {
  let parsed;
  try {
    parsed = assertV2StandardTransactionEnvelope(
      parseV2RawTransaction(encoded.toString('hex')),
    );
  } catch (error) {
    fail(
      'GENESIS_TRANSACTION_INVALID',
      `signed genesis violates the full transaction envelope: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  if (
    parsed.sizeBytes !== built.sizing.signedSizeBytes
    || parsed.inputs.length !== 1
    || parsed.outputs.length !== 13
    || parsed.inputs[0].outpoint.txid
      !== built.intent.sourceTransaction.txid
    || parsed.inputs[0].outpoint.vout !== 0
    || parsed.inputs[0].sequence !== V2_GENESIS_INPUT_SEQUENCE
  ) {
    fail(
      'GENESIS_TRANSACTION_INVALID',
      'signed genesis transaction shape or source outpoint is invalid',
    );
  }
  const outputs = parsed.outputs.map((output) =>
    parseSerializedSourceOutput(output.serializedHex));
  const state = outputs[0];
  if (
    state.valueSatoshis !== built.intent.finalLocks.state.baseSats
    || !state.lockingBytecode.equals(
      built.intent.finalLocks.state.lockingBytecode,
    )
    || state.token?.categoryWire !== built.intent.instanceId
    || state.token.amount !== '0'
    || state.token.nft?.capability !== 'mutable'
    || state.token.nft.commitmentHex
      !== built.intent.initialState.toString('hex')
  ) {
    fail(
      'GENESIS_TRANSACTION_INVALID',
      'output zero is not the exact sole mutable state NFT',
    );
  }
  for (const [index, verifier] of built.intent.finalLocks.verifiers.entries()) {
    const output = outputs[index + 1];
    if (
      output.token !== null
      || output.valueSatoshis !== verifier.baseSats
      || !output.lockingBytecode.equals(verifier.lockingBytecode)
    ) {
      fail(
        'GENESIS_TRANSACTION_INVALID',
        `verifier output ${index + 1} differs from the exact rolling artifact`,
      );
    }
  }
  const binding = outputs[11];
  if (
    binding.token !== null
    || binding.valueSatoshis !== built.intent.finalLocks.binding.baseSats
    || !binding.lockingBytecode.equals(
      built.intent.finalLocks.binding.lockingBytecode,
    )
  ) {
    fail(
      'GENESIS_TRANSACTION_INVALID',
      'binding output 11 differs from the exact rolling artifact',
    );
  }
  const change = outputs[12];
  if (
    change.token !== null
    || change.valueSatoshis !== built.sizing.changeSats
    || !change.lockingBytecode.equals(built.intent.changeLockingBytecode)
  ) {
    fail(
      'GENESIS_TRANSACTION_INVALID',
      'change output 12 is not the exact tokenless P2PKH change',
    );
  }
  const fee =
    built.intent.sourceOutput.valueSatoshis
    - outputs.reduce((total, output) => total + output.valueSatoshis, 0n);
  if (
    fee !== built.sizing.feeSats
    || fee !== BigInt(parsed.sizeBytes)
  ) {
    fail(
      'GENESIS_TRANSACTION_INVALID',
      'signed genesis fee is not exactly one satoshi per serialized byte',
    );
  }
  const sourceOutputs = [libauthSourceOutput(built.intent.sourceOutput)];
  const vm = createVirtualMachineBch2026(true);
  const verdict = vm.verify({ sourceOutputs, transaction });
  if (verdict !== true) {
    fail(
      'GENESIS_VM_REJECTED',
      `BCH_2026_STANDARD rejected the exact signed genesis: ${verdict}`,
    );
  }
  const stateResult = vm.evaluate({
    inputIndex: 0,
    sourceOutputs,
    transaction,
  });
  const inputVerdict = vm.stateSuccess(stateResult);
  if (inputVerdict !== true) {
    fail(
      'GENESIS_VM_REJECTED',
      `BCH_2026_STANDARD rejected genesis input zero: ${inputVerdict}`,
    );
  }
  const metrics = assertV2VmResourceMetrics(
    Object.fromEntries(VM_METRIC_FIELDS.map((field) => {
      const metric = stateResult.metrics?.[field];
      if (!Number.isSafeInteger(metric) || metric < 0) {
        fail(
          'GENESIS_VM_EVIDENCE_INVALID',
          `BCH_2026_STANDARD did not report canonical ${field}`,
        );
      }
      return [field, String(metric)];
    })),
    {
      inputIndex: 0,
      unlockingBytecodeBytes: parsed.inputs[0].unlockingBytecodeBytes,
    },
  );
  return Object.freeze({ parsed, outputs, fee, metrics });
}

/**
 * Prepare the exact genesis transaction and its sole signing request.
 */
export function prepareV2Genesis(value, runtime) {
  const normalized = {
    ...value,
    schema: value?.schema ?? V2_GENESIS_INTENT_SCHEMA,
  };
  const built = buildPrepared(normalized, runtime);
  const payload = canonicalizeJcs(normalized);
  return preparedEnvelope(payload, built);
}

/**
 * Finalize one prepared genesis with a caller-supplied 64-byte Schnorr
 * signature, then execute the exact transaction in BCH_2026_STANDARD.
 */
export function finalizeV2Genesis(prepared, signatureValue, runtime) {
  const built = inspectPrepared(prepared, runtime);
  const signature = signatureValue instanceof Uint8Array
    ? Buffer.from(signatureValue)
    : bytes(signatureValue, 'signature', 64);
  if (signature.length !== 64) {
    fail(
      'GENESIS_SIGNATURE_INVALID',
      'signature must be exactly 64 bytes',
    );
  }
  if (
    !secp256k1.verifySignatureSchnorr(
      signature,
      built.intent.fundingPublicKey,
      built.signingDigest,
    )
  ) {
    fail(
      'GENESIS_SIGNATURE_INVALID',
      'signature does not verify for the exact 0x61 genesis digest',
    );
  }
  const transaction = transactionFor(
    built.intent,
    built.sizing.changeSats,
    canonicalFundingUnlock(signature, built.intent.fundingPublicKey),
  );
  const encoded = Buffer.from(encodeTransaction(transaction));
  const inspected = inspectFinalTransaction(built, transaction, encoded);
  const finalized = Object.freeze({
    schema: V2_GENESIS_FINALIZED_SCHEMA,
    stage: 'finalized',
    profileId: built.intent.profileId,
    instanceId: built.intent.instanceId,
    stateNftCategoryWire: built.intent.instanceId,
    source: Object.freeze({
      transactionId: built.intent.sourceTransaction.txid,
      outputIndex: 0,
      serializedOutputSha256: built.intent.sourceOutput.sha256,
    }),
    genesis: Object.freeze({
      transactionId: inspected.parsed.txid,
      outputIndex: 0,
      rawTransactionHex: encoded.toString('hex'),
      serializedBytes: inspected.parsed.sizeBytes,
    }),
    initialStateHex: built.intent.initialState.toString('hex'),
    signing: Object.freeze({
      sighashType: V2_FUNDING_SIGHASH_TYPE,
      digestHex: built.signingDigest.toString('hex'),
      signatureHex: signature.toString('hex'),
    }),
    measurements: Object.freeze({
      feeSats: inspected.fee.toString(),
      feeRateSatsPerByte: V2_GENESIS_FEE_RATE_SATS_PER_BYTE,
      changeSats: built.sizing.changeSats.toString(),
      inputCount: 1,
      outputCount: inspected.outputs.length,
      maximumTransactionBytes: 100_000,
      maximumUnlockingBytecodeBytes: 10_000,
      bch2026StandardVmAccepted: true,
      inputMetrics: inspected.metrics,
    }),
    claims: Object.freeze({
      localBch2026Accepted: true,
      broadcasted: false,
      mined: false,
      productionQualified: false,
    }),
  });
  validatedFinalizedGenesisPins.set(finalized, Object.freeze({
    profileId: built.intent.profileId,
    instanceId: built.intent.instanceId,
    maximumLiveNotes: built.intent.maximumLiveNotes,
    denominationSats: built.intent.profileCore.denominationSats,
    runtimeMaterialSha256: built.intent.runtimeMaterialSha256,
    finalLocksSha256: built.intent.finalLocksSha256,
    finalLocks: built.intent.finalLocks,
    initialStateHex: built.intent.initialState.toString('hex'),
    sourceTransactionId: built.intent.sourceTransaction.txid,
    sourceRawTransactionHex: built.intent.sourceRawTransactionHex,
    sourceSerializedBytes: built.intent.sourceTransaction.sizeBytes,
    genesisTransactionId: inspected.parsed.txid,
    genesisOutputIndex: 0,
    rawTransactionHex: encoded.toString('hex'),
    serializedBytes: inspected.parsed.sizeBytes,
  }));
  return finalized;
}

/**
 * Expose public package material only for a finalized genesis produced and
 * BCH_2026_STANDARD-verified by this module, paired with the exact opaque
 * runtime used to construct it. Caller-created finalized envelopes and runtime
 * copies are rejected.
 */
export function deriveV2FinalizedGenesisPackagePins(finalized, runtime) {
  const genesisPins = validatedFinalizedGenesisPins.get(finalized);
  if (genesisPins === undefined) {
    fail(
      'GENESIS_FINALIZED_INVALID',
      'instance packaging requires a finalized genesis returned by finalizeV2Genesis',
    );
  }
  const runtimePins = genesisRuntimePins(runtime);
  if (
    runtimePins.profileId !== genesisPins.profileId
    || runtimePins.instanceId !== genesisPins.instanceId
    || runtimePins.runtimeMaterialSha256
      !== genesisPins.runtimeMaterialSha256
    || runtimePins.finalLocksSha256 !== genesisPins.finalLocksSha256
  ) {
    fail(
      'GENESIS_RUNTIME_MISMATCH',
      'finalized genesis and authenticated runtime do not have one exact identity',
    );
  }
  return Object.freeze({
    profileId: genesisPins.profileId,
    instanceId: genesisPins.instanceId,
    maximumLiveNotes: genesisPins.maximumLiveNotes,
    denominationSats: genesisPins.denominationSats,
    runtimeMaterialSha256: genesisPins.runtimeMaterialSha256,
    finalLocksSha256: genesisPins.finalLocksSha256,
    finalLocks: copyFinalLocks(genesisPins.finalLocks),
    initialStateHex: genesisPins.initialStateHex,
    source: Object.freeze({
      transactionId: genesisPins.sourceTransactionId,
      outputIndex: 0,
      rawTransactionHex: genesisPins.sourceRawTransactionHex,
      serializedBytes: genesisPins.sourceSerializedBytes,
    }),
    genesis: Object.freeze({
      transactionId: genesisPins.genesisTransactionId,
      outputIndex: genesisPins.genesisOutputIndex,
      rawTransactionHex: genesisPins.rawTransactionHex,
      serializedBytes: genesisPins.serializedBytes,
    }),
  });
}

/**
 * Revalidate a packaged genesis from only signed/public package material.
 *
 * This boundary intentionally repeats the consensus-relevant checks performed
 * during `finalizeV2Genesis`: a prepared package is untrusted after it crosses
 * the offline-signing boundary. The source transaction is required so the
 * funding output, exact fee, and BCH_2026_STANDARD signature can be verified
 * without trusting a claimed source-output hash.
 */
export function inspectV2PackagedGenesisBinding(value) {
  exactKeys(value, 'packaged genesis binding', [
    'descriptor',
    'rawGenesisTransaction',
    'rawSourceTransaction',
    'settlementPins',
  ]);
  exactKeys(value.descriptor, 'packaged genesis descriptor binding', [
    'genesis',
    'initialState',
    'instanceId',
    'profileId',
  ]);
  exactKeys(value.descriptor.genesis, 'packaged genesis outpoint', [
    'outpointIndex',
    'transactionId',
  ]);
  const profileId = bytes(
    value.descriptor.profileId,
    'packaged genesis profileId',
    32,
  ).toString('hex');
  const instanceId = bytes(
    value.descriptor.instanceId,
    'packaged genesis instanceId',
    32,
  ).toString('hex');
  if (
    !(value.descriptor.initialState instanceof Uint8Array)
    || value.descriptor.initialState.length !== 128
  ) {
    fail(
      'GENESIS_PACKAGE_INVALID',
      'packaged genesis initialState must be exactly 128 bytes',
    );
  }
  const initialState = Buffer.from(value.descriptor.initialState);
  if (
    !initialState.subarray(0, 4).equals(Buffer.from('SKS2', 'ascii'))
    || initialState.subarray(4, 36).toString('hex') !== profileId
  ) {
    fail(
      'GENESIS_PACKAGE_INVALID',
      'packaged genesis initialState does not bind its profile',
    );
  }
  const genesisTransactionId = bytes(
    value.descriptor.genesis.transactionId,
    'packaged genesis transactionId',
    32,
  ).toString('hex');
  if (value.descriptor.genesis.outpointIndex !== 0) {
    fail(
      'GENESIS_PACKAGE_INVALID',
      'packaged genesis state outpoint must be output zero',
    );
  }
  if (
    !(value.rawGenesisTransaction instanceof Uint8Array)
    || value.rawGenesisTransaction.length === 0
    || !(value.rawSourceTransaction instanceof Uint8Array)
    || value.rawSourceTransaction.length === 0
  ) {
    fail(
      'GENESIS_PACKAGE_INVALID',
      'packaged source and genesis transactions must be nonempty bytes',
    );
  }

  exactKeys(value.settlementPins, 'packaged genesis settlement pins', [
    'bindingBaseSats',
    'bindingLockingBytecode',
    'bindingRedeemBytecode',
    'stateBaseSats',
    'stateLockingBytecode',
    'topologyId',
    'verifierCarriers',
    'verifierRoles',
  ]);
  const settlement = value.settlementPins;
  if (
    settlement.topologyId !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
    || !Array.isArray(settlement.verifierRoles)
    || settlement.verifierRoles.length
      !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length
    || settlement.verifierRoles.some(
      (role, index) =>
        role !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES[index],
    )
    || !Array.isArray(settlement.verifierCarriers)
    || settlement.verifierCarriers.length
      !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length
  ) {
    fail(
      'GENESIS_PACKAGE_INVALID',
      'packaged genesis settlement topology is not exact PF10',
    );
  }
  const packageAmount = (candidate, label) => {
    if (
      typeof candidate !== 'string'
      || !DECIMAL.test(candidate)
      || BigInt(candidate) <= 0n
      || BigInt(candidate) > MAX_MONEY_SATS
    ) {
      fail(
        'GENESIS_PACKAGE_INVALID',
        `packaged genesis ${label} must be a positive canonical decimal`,
      );
    }
    return BigInt(candidate);
  };
  const exactCarrier = (entry, index) => {
    exactKeys(entry, `packaged verifier carrier ${index}`, [
      'baseValueSats',
      'lockingBytecode',
    ]);
    if (
      !(entry.lockingBytecode instanceof Uint8Array)
      || entry.lockingBytecode.length === 0
    ) {
      fail(
        'GENESIS_PACKAGE_INVALID',
        `packaged verifier carrier ${index} is malformed`,
      );
    }
    return Object.freeze({
      baseValueSats: packageAmount(
        entry.baseValueSats,
        `verifier carrier ${index} baseValueSats`,
      ),
      lockingBytecode: Buffer.from(entry.lockingBytecode),
    });
  };
  const verifierCarriers = settlement.verifierCarriers.map(exactCarrier);
  const bindingBaseSats = packageAmount(
    settlement.bindingBaseSats,
    'bindingBaseSats',
  );
  const stateBaseSats = packageAmount(
    settlement.stateBaseSats,
    'stateBaseSats',
  );
  for (const [name, candidate] of [
    ['bindingLockingBytecode', settlement.bindingLockingBytecode],
    ['bindingRedeemBytecode', settlement.bindingRedeemBytecode],
    ['stateLockingBytecode', settlement.stateLockingBytecode],
  ]) {
    if (!(candidate instanceof Uint8Array) || candidate.length === 0) {
      fail(
        'GENESIS_PACKAGE_INVALID',
        `packaged genesis ${name} must be nonempty bytes`,
      );
    }
  }
  try {
    verifyDirectV2BindingP2sh32Lock({
      redeemScript: settlement.bindingRedeemBytecode,
      sourceLockingBytecode: settlement.bindingLockingBytecode,
    });
  } catch (error) {
    fail(
      'GENESIS_PACKAGE_INVALID',
      'packaged genesis binding lock and redeem are not the exact P2SH32 pair',
      { cause: error },
    );
  }

  let source;
  let genesis;
  try {
    source = assertV2StandardTransactionEnvelope(
      parseV2RawTransaction(
        Buffer.from(value.rawSourceTransaction).toString('hex'),
      ),
    );
    genesis = assertV2StandardTransactionEnvelope(
      parseV2RawTransaction(
        Buffer.from(value.rawGenesisTransaction).toString('hex'),
      ),
    );
  } catch (error) {
    fail(
      'GENESIS_PACKAGE_INVALID',
      `packaged source or genesis transaction is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  const sourceOutputHex = source.outputs[0]?.serializedHex;
  if (
    sourceOutputHex === undefined
    || /^0+$/.test(source.txid)
  ) {
    fail(
      'GENESIS_PACKAGE_INVALID',
      'packaged source transaction has no usable output zero',
    );
  }
  const sourceOutput = parseSerializedSourceOutput(sourceOutputHex);
  const expectedInstanceId = Buffer.from(source.txid, 'hex')
    .reverse()
    .toString('hex');
  if (
    expectedInstanceId !== instanceId
    || sourceOutput.token !== null
  ) {
    fail(
      'GENESIS_PACKAGE_INVALID',
      'packaged source output or funding-derived instanceId is invalid',
    );
  }
  const input = genesis.inputs[0];
  if (
    genesis.txid !== genesisTransactionId
    || genesis.version !== V2_GENESIS_TRANSACTION_VERSION
    || genesis.locktime !== V2_GENESIS_LOCKTIME
    || genesis.inputs.length !== 1
    || genesis.outputs.length !== 13
    || input.outpoint.txid !== source.txid
    || input.outpoint.vout !== 0
    || input.sequence !== V2_GENESIS_INPUT_SEQUENCE
    || input.unlockingBytecode.length !== 100
    || input.unlockingBytecode[0] !== 0x41
    || input.unlockingBytecode[65] !== V2_FUNDING_SIGHASH_TYPE
    || input.unlockingBytecode[66] !== 0x21
  ) {
    fail(
      'GENESIS_PACKAGE_INVALID',
      'packaged genesis transaction topology or funding unlock is invalid',
    );
  }
  const fundingPublicKey = input.unlockingBytecode.subarray(67);
  if (
    fundingPublicKey.length !== 33
    || ![0x02, 0x03].includes(fundingPublicKey[0])
    || !secp256k1.validatePublicKey(fundingPublicKey)
    || !sourceOutput.lockingBytecode.equals(p2pkhLock(fundingPublicKey))
  ) {
    fail(
      'GENESIS_PACKAGE_INVALID',
      'packaged genesis funding key does not control source output zero',
    );
  }
  const outputs = genesis.outputs.map((output) =>
    parseSerializedSourceOutput(output.serializedHex));
  const state = outputs[0];
  if (
    state.valueSatoshis !== stateBaseSats
    || !state.lockingBytecode.equals(
      Buffer.from(settlement.stateLockingBytecode),
    )
    || state.token?.categoryWire !== instanceId
    || state.token.amount !== '0'
    || state.token.nft?.capability !== 'mutable'
    || state.token.nft.commitmentHex !== initialState.toString('hex')
  ) {
    fail(
      'GENESIS_PACKAGE_INVALID',
      'packaged genesis output zero is not the exact state NFT',
    );
  }
  for (const [index, carrier] of verifierCarriers.entries()) {
    const output = outputs[index + 1];
    if (
      output.token !== null
      || output.valueSatoshis !== carrier.baseValueSats
      || !output.lockingBytecode.equals(carrier.lockingBytecode)
    ) {
      fail(
        'GENESIS_PACKAGE_INVALID',
        `packaged genesis verifier output ${index + 1} is not exact`,
      );
    }
  }
  const binding = outputs[11];
  if (
    binding.token !== null
    || binding.valueSatoshis !== bindingBaseSats
    || !binding.lockingBytecode.equals(
      Buffer.from(settlement.bindingLockingBytecode),
    )
  ) {
    fail(
      'GENESIS_PACKAGE_INVALID',
      'packaged genesis binding output is not exact',
    );
  }
  const change = outputs[12];
  if (change.token !== null) {
    fail(
      'GENESIS_PACKAGE_INVALID',
      'packaged genesis change output must be tokenless',
    );
  }
  canonicalP2pkh(
    change.lockingBytecode.toString('hex'),
    'packaged genesis change locking bytecode',
  );
  if (change.valueSatoshis < V2_GENESIS_MINIMUM_CHANGE_SATS) {
    fail(
      'GENESIS_PACKAGE_INVALID',
      'packaged genesis change is below the exact minimum',
    );
  }
  const outputTotal = outputs.reduce(
    (total, output) => total + output.valueSatoshis,
    0n,
  );
  const fee = sourceOutput.valueSatoshis - outputTotal;
  if (fee !== BigInt(genesis.sizeBytes)) {
    fail(
      'GENESIS_PACKAGE_INVALID',
      'packaged genesis fee is not exactly one satoshi per byte',
    );
  }
  const decoded = decodeTransaction(
    Uint8Array.from(value.rawGenesisTransaction),
  );
  if (typeof decoded === 'string') {
    fail(
      'GENESIS_PACKAGE_INVALID',
      `packaged genesis cannot be decoded for BCH VM execution: ${decoded}`,
    );
  }
  const vm = createVirtualMachineBch2026(true);
  const vmVerdict = vm.verify({
    sourceOutputs: [libauthSourceOutput(sourceOutput)],
    transaction: decoded,
  });
  if (vmVerdict !== true) {
    fail(
      'GENESIS_PACKAGE_INVALID',
      `BCH_2026_STANDARD rejected packaged genesis: ${vmVerdict}`,
    );
  }
  return Object.freeze({
    schema: 'shieldkit-v2-packaged-genesis-binding-v1',
    profileId,
    instanceId,
    sourceTransactionId: source.txid,
    genesisTransactionId: genesis.txid,
    stateOutputIndex: 0,
    transactionBytes: genesis.sizeBytes,
    feeSats: fee.toString(),
    bch2026StandardVmAccepted: true,
  });
}
