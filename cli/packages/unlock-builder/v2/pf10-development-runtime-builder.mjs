import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

import {
  binToHex,
  encodeDataPush,
  encodeLockingBytecodeP2sh32,
  hash256,
  hexToBin,
} from '@bitauth/libauth';
import {
  compileString,
  utils as cashcUtils,
} from '../vendor/verifier/vendor/cashc-resched/packages/cashc/dist/index.js';

import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
} from '../../action/v2/topology.mjs';
import {
  deriveV2RollingBaseSats,
} from '../../action/v2/dust-policy.mjs';
import { recordV2BetaRuntimeWork } from '../../profile/v2/beta-runtime-work-observer.mjs';
import {
  parseStrictJson,
} from '../../prove/groth16.mjs';
import {
  computeDirectV2ExactMsm,
  encodeDirectV2MsmState,
} from './exact-msm.mjs';
import {
  renderDirectV2ExactMsmRole,
} from './exact-msm-cashscript.mjs';
import {
  computeDirectV2IdentityAwareMiller,
  createDirectV2IdentityReferenceProof,
  encodeDirectV2MillerProjectionSignal,
  parseDirectV2MillerVerificationKey,
} from './identity-aware-miller.mjs';
import {
  renderDirectV2Pf10FusedQGenesisMillerComponent,
} from './identity-aware-miller-cashscript.mjs';
import {
  buildDirectV2Pf10FusedQGenesisRedeem,
  directV2Pf10ExactMsmArgumentPrefix,
} from './pf10-fused-q-genesis.mjs';
import {
  DIRECT_V2_PF10_BQ_SHARD_BYTES,
  DIRECT_V2_PF10_EXECUTOR_DENSITY_PAD_BYTES,
  DIRECT_V2_PF10_EXECUTOR_FUNCTION_ID,
  DIRECT_V2_PF10_EXACT_MSM_ZERO_PADDING_BYTES,
  DIRECT_V2_PF10_MILLER_ZERO_PADDING_BYTES,
  DIRECT_V2_PF10_NONFINAL_MSM_PADDING_BYTES,
  DIRECT_V2_PF10_BETA_ELIGIBILITY,
  DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA,
  DIRECT_V2_PF10_RUNTIME_SCHEMA,
  validateDirectV2Pf10BetaRuntimeMaterial,
  validateDirectV2Pf10RuntimeMaterial,
} from './pf10-action-witness.mjs';
import {
  buildDirectV2BindingLock,
  buildDirectV2BindingRedeem,
  buildDirectV2StateHelper,
  buildDirectV2StateTrampolineLock,
  buildDirectV2StateTrampolineUnlock,
} from './structural-covenants.mjs';
import {
  buildDirectV2PairFoldLoader,
  renderDirectV2TotalPairFoldExecutor,
  renderDirectV2TotalPairFoldTerminal,
  splitDirectV2PairFoldBody,
} from './total-pairfold-cashscript.mjs';
import {
  buildDirectV2TotalPairFoldWitness,
} from './total-pairfold.mjs';

export const DIRECT_V2_PF10_DEVELOPMENT_RUNTIME_BUILD_SCHEMA =
  'shieldkit-v2-direct-pf10-development-runtime-build-v1';
export const DIRECT_V2_PF10_BETA_RUNTIME_BUILD_SCHEMA =
  'shieldkit-v2-direct-pf10-beta-runtime-build-v1';
export const DIRECT_V2_PF10_LIBAUTH_EVIDENCE_SCHEMA =
  'shieldkit-v2-direct-pf10-local-libauth-evidence-v2';

const HASH = /^[0-9a-f]{64}$/;
const HEX_32 = /^[0-9a-f]{64}$/;
const PROOF_ARTIFACT_NAMES = Object.freeze([
  'provingKey',
  'r1cs',
  'verificationKey',
  'wasm',
]);
const NETWORK_ID = 2;
const DENOMINATION_SATS = 10_000_000n;
const MINIMUM_CHANGE_SATS = 546n;
const MODULE_REPOSITORY_ROOT = path.resolve(import.meta.dirname, '../../../..');
const EXPECTED_INPUT_COUNT = 13;
const EXPECTED_ACTIONS = Object.freeze([
  Object.freeze({ kind: 'deposit', outputCount: 13, transactionBytes: 97_852 }),
  Object.freeze({ kind: 'transfer', outputCount: 13, transactionBytes: 97_852 }),
  Object.freeze({ kind: 'withdrawal', outputCount: 14, transactionBytes: 97_886 }),
]);
const EXPECTED_ROW_NAMES = Object.freeze([
  'exec0',
  'exec1',
  'exec2',
  'exec3',
  'exec4',
  'msm5',
  'msm6',
  'msm7',
  'fused-q-genesis8',
  'terminal9',
  'binding10',
  'state11',
  'funding12',
]);
const EXPECTED_SETTLEMENT_PATH = Object.freeze([
  'prepareV2DirectSettlement',
  'assembleV2DirectSettlement',
  'signV2DirectSettlement',
]);
const EXPECTED_LIBAUTH_VERDICT =
  'production-builder-local-standard-pass-all-actions-precomputed-fixed-lines';
const EXPECTED_FIXED_PROGRAM_BYTES = Object.freeze({
  bindingRedeemBytes: 2_195,
  exactFinalRawBytes: 1_924,
  exactFinalRedeemBytes: 1_597,
  exactRawBytes: Object.freeze([1_682, 1_667, 1_675]),
  exactRedeemBytes: Object.freeze([1_387, 1_372, 1_380]),
  executorBodyBytes: 5_573,
  executorDensityPadBytes: 384,
  fixedLineCarrierBytes: 20_864,
  fusedRedeemBytes: 6_404,
  loaderBytes: 108,
  millerRawBytes: 5_430,
  millerRedeemBytes: 4_620,
  rawExecutorBytes: 10_937,
  stateHelperBytes: 2_674,
});
// The terminal embeds alpha/beta-derived fAB coefficients from the selected
// verification key. CashScript's canonical Script-number encoding can change
// their aggregate byte width between independently contributed keys, so those
// two measurements are verified against the exact compiled runtime below,
// never against one ceremony's accidental byte count.
const EXPECTED_SCOPE_SETTLEMENT_PATH =
  'prepareV2DirectSettlement -> assembleV2DirectSettlement -> signV2DirectSettlement -> createV2LocalVmEvidence';
const EXPECTED_SCOPE_PARENT_TRANSACTIONS =
  'deterministically constructed local serialized transactions; every child outpoint and source output is authenticated from exact parent bytes; no live-chain provenance is claimed';
const TERMINAL_INPUT_INDEX = 9;
const BINDING_INPUT_INDEX = 10;
const STATE_INPUT_INDEX = 11;
const FIRST_EXACT_INPUT_INDEX = 5;
const FUSED_INPUT_INDEX = 8;
const OPCOST_COMPILER_OPTIONS = Object.freeze({
  optimizeFor: 'opcost',
  rescheduleStacks: true,
});

export class DirectV2Pf10RuntimeBuildError extends Error {
  constructor(code, message, cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'DirectV2Pf10RuntimeBuildError';
    this.code = code;
  }
}

const fail = (code, message, cause) => {
  throw new DirectV2Pf10RuntimeBuildError(code, message, cause);
};

const sha256 = (value) =>
  createHash('sha256').update(value).digest('hex');

const execFileAsync = promisify(execFile);

const FILE_IDENTITY_FIELDS = Object.freeze([
  'birthtimeNs',
  'ctimeNs',
  'dev',
  'gid',
  'ino',
  'mode',
  'mtimeNs',
  'nlink',
  'size',
  'uid',
]);
const DIRECTORY_IDENTITY_FIELDS = Object.freeze([
  'dev',
  'gid',
  'ino',
  'mode',
  'uid',
]);

function filesystemIdentity(stat, fields = FILE_IDENTITY_FIELDS) {
  return Object.freeze(Object.fromEntries(
    fields.map((field) => [field, stat[field].toString()]),
  ));
}

function sameFilesystemIdentity(left, right, fields = FILE_IDENTITY_FIELDS) {
  return fields.every((field) => left[field] === right[field]);
}

const concat = (...parts) =>
  Buffer.concat(parts.map((part) => Buffer.from(part)));

const push = (value) => Buffer.from(encodeDataPush(value));

const encodedLength = (length) => push(Buffer.alloc(length)).length;

const pushHeaderLength = (length) => encodedLength(length) - length;

const p2sh32 = (redeem) =>
  Buffer.from(encodeLockingBytecodeP2sh32(hash256(redeem)));

function exactIdentity(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail('PF10_BUILD_INPUT_INVALID', `${label} must be 32 lowercase hex bytes`);
  }
  return value;
}

function exactArtifactRecord(value) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Object.keys(value).length !== PROOF_ARTIFACT_NAMES.length
    || PROOF_ARTIFACT_NAMES.some((name) => {
      const artifact = value[name];
      return (
        artifact === null
        || Array.isArray(artifact)
        || typeof artifact !== 'object'
        || Object.getPrototypeOf(artifact) !== Object.prototype
        || Object.keys(artifact).sort().join(',') !== 'path,sha256'
        || typeof artifact.path !== 'string'
        || !path.isAbsolute(artifact.path)
        || path.normalize(artifact.path) !== artifact.path
        || artifact.path.includes('\0')
        || typeof artifact.sha256 !== 'string'
        || !HASH.test(artifact.sha256)
      );
    })
  ) {
    fail(
      'PF10_BUILD_INPUT_INVALID',
      'proofArtifacts must contain exact path/SHA-256 records',
    );
  }
  return value;
}

function exactPinnedArtifactRecord(value, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Object.keys(value).sort().join(',') !== 'path,sha256'
    || typeof value.path !== 'string'
    || !path.isAbsolute(value.path)
    || path.normalize(value.path) !== value.path
    || value.path.includes('\0')
    || typeof value.sha256 !== 'string'
    || !HASH.test(value.sha256)
  ) {
    fail(
      'PF10_BUILD_INPUT_INVALID',
      `${label} must be an exact absolute path/SHA-256 record`,
    );
  }
  return value;
}

function exactKeys(value, label, keys) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')
  ) {
    fail('PF10_BUILD_LIBAUTH_INVALID', `${label} has missing or unknown properties`);
  }
}

function exactBooleanClaims(value) {
  const expected = {
    authenticatedSerializedParentOutputs: true,
    bchnMempool: false,
    bchnMined: false,
    finalKey: false,
    leanBch: false,
    libauthBch2026: true,
    liveChainParentProvenance: false,
    production: false,
    productionSettlementBuilderPath: true,
    releaseQualified: false,
    unmodifiedMaintainerBenchmark: false,
  };
  exactKeys(value, 'PF10 Libauth claims', Object.keys(expected));
  if (Object.entries(expected).some(([key, expectedValue]) => value[key] !== expectedValue)) {
    fail('PF10_BUILD_LIBAUTH_INVALID', 'PF10 Libauth claims are not development-only local evidence');
  }
}

function nonnegativeSafeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      `${label} must be a nonnegative safe integer`,
    );
  }
  return value;
}

function canonicalHex(value, label, { allowEmpty = false } = {}) {
  if (
    typeof value !== 'string'
    || value.length % 2 !== 0
    || (!allowEmpty && value.length === 0)
    || !/^[0-9a-f]*$/.test(value)
  ) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      `${label} must be canonical lowercase hexadecimal`,
    );
  }
  return value;
}

function exactHash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      `${label} must be 32 lowercase hexadecimal bytes`,
    );
  }
  return value;
}

function displayTransactionId(bytes) {
  return Buffer.from(hash256(bytes)).reverse().toString('hex');
}

function validateLibauthSourceParent(value, label) {
  exactKeys(value, label, [
    'rawTransactionHex',
    'rawTransactionSha256',
    'transactionId',
  ]);
  const raw = Buffer.from(
    canonicalHex(value.rawTransactionHex, `${label}.rawTransactionHex`),
    'hex',
  );
  if (
    value.rawTransactionSha256 !== sha256(raw)
    || value.transactionId !== displayTransactionId(raw)
  ) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      `${label} transaction hashes are inconsistent`,
    );
  }
  return Object.freeze({
    transactionId: value.transactionId,
  });
}

function validateLibauthRows(rows, kind) {
  if (!Array.isArray(rows) || rows.length !== EXPECTED_INPUT_COUNT) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      `PF10 Libauth ${kind} must record all 13 VM rows`,
    );
  }
  for (const [index, row] of rows.entries()) {
    const label = `PF10 Libauth ${kind} row ${index}`;
    exactKeys(row, label, [
      'arithmeticCost',
      'definedFunctions',
      'evaluatedInstructionCount',
      'hardAccepted',
      'hashDigestIterations',
      'index',
      'maximumHashDigestIterations',
      'maximumLegalOperationCost',
      'maximumOperationCost',
      'maximumSignatureChecks',
      'name',
      'operationCost',
      'operationPercent',
      'semanticAccepted',
      'signatureCheckCount',
      'stackPushedBytes',
      'unlockBytes',
    ]);
    if (
      row.index !== index
      || row.name !== EXPECTED_ROW_NAMES[index]
      || row.hardAccepted !== true
      || row.semanticAccepted !== true
    ) {
      fail(
        'PF10_BUILD_LIBAUTH_INVALID',
        `${label} identity or verdict is invalid`,
      );
    }
    for (const field of [
      'arithmeticCost',
      'definedFunctions',
      'evaluatedInstructionCount',
      'hashDigestIterations',
      'maximumHashDigestIterations',
      'maximumLegalOperationCost',
      'maximumOperationCost',
      'maximumSignatureChecks',
      'operationCost',
      'signatureCheckCount',
      'stackPushedBytes',
      'unlockBytes',
    ]) {
      nonnegativeSafeInteger(row[field], `${label}.${field}`);
    }
    if (
      row.unlockBytes > 10_000
      || row.operationCost > row.maximumOperationCost
      || row.maximumOperationCost > row.maximumLegalOperationCost
      || row.hashDigestIterations > row.maximumHashDigestIterations
      || row.signatureCheckCount > row.maximumSignatureChecks
      || typeof row.operationPercent !== 'number'
      || !Number.isFinite(row.operationPercent)
      || row.operationPercent < 0
      || row.operationPercent > 100
    ) {
      fail(
        'PF10_BUILD_LIBAUTH_INVALID',
        `${label} exceeds a full BCH hard limit`,
      );
    }
  }
}

function validateLibauthAction(action, expected) {
  const label = `PF10 Libauth ${expected.kind}`;
  exactKeys(action, label, [
    'construction',
    'contextHash',
    'feeRateSatsPerByte',
    'feeSats',
    'inputCount',
    'inputSources',
    'kind',
    'localVmEvidence',
    'mutationChecks',
    'outputCount',
    'packetSha256',
    'proofGenerationMs',
    'proofVerified',
    'rawTransactionHex',
    'rawTransactionSha256',
    'rows',
    'sourceOutputs',
    'sourceParents',
    'transactionBytes',
    'transactionHeadroomBytes',
    'transactionId',
    'transactionLimitBytes',
  ]);
  if (
    action.kind !== expected.kind
    || action.inputCount !== EXPECTED_INPUT_COUNT
    || action.outputCount !== expected.outputCount
    || action.transactionBytes !== expected.transactionBytes
    || action.transactionLimitBytes !== 100_000
    || action.transactionHeadroomBytes
      !== 100_000 - expected.transactionBytes
    || action.feeRateSatsPerByte !== '1'
    || action.feeSats !== expected.transactionBytes.toString()
    || action.proofVerified !== true
    || !Number.isSafeInteger(action.proofGenerationMs)
    || action.proofGenerationMs < 0
  ) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      `${label} topology, fee, proof, or size evidence is invalid`,
    );
  }
  exactHash(action.contextHash, `${label}.contextHash`);
  exactHash(action.packetSha256, `${label}.packetSha256`);
  const raw = Buffer.from(
    canonicalHex(action.rawTransactionHex, `${label}.rawTransactionHex`),
    'hex',
  );
  if (
    raw.length !== action.transactionBytes
    || action.rawTransactionSha256 !== sha256(raw)
    || action.transactionId !== displayTransactionId(raw)
  ) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      `${label} raw transaction hashes or byte count are inconsistent`,
    );
  }
  exactKeys(action.construction, `${label}.construction`, [
    'assemblyHash',
    'inputSequence',
    'localVmEvidenceHash',
    'path',
    'preparedPayloadHash',
  ]);
  if (
    action.construction.inputSequence !== 0
    || !Array.isArray(action.construction.path)
    || action.construction.path.length !== EXPECTED_SETTLEMENT_PATH.length
    || action.construction.path.some(
      (entry, index) => entry !== EXPECTED_SETTLEMENT_PATH[index],
    )
  ) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      `${label} did not use the exact production settlement path`,
    );
  }
  for (const field of [
    'assemblyHash',
    'localVmEvidenceHash',
    'preparedPayloadHash',
  ]) {
    exactHash(action.construction[field], `${label}.construction.${field}`);
  }
  exactKeys(action.sourceParents, `${label}.sourceParents`, [
    'funding',
    'previousBundle',
  ]);
  const previousBundle = validateLibauthSourceParent(
    action.sourceParents.previousBundle,
    `${label}.sourceParents.previousBundle`,
  );
  const funding = validateLibauthSourceParent(
    action.sourceParents.funding,
    `${label}.sourceParents.funding`,
  );
  if (previousBundle.transactionId === funding.transactionId) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      `${label} source parents must be distinct`,
    );
  }
  if (
    !Array.isArray(action.inputSources)
    || action.inputSources.length !== EXPECTED_INPUT_COUNT
    || !Array.isArray(action.sourceOutputs)
    || action.sourceOutputs.length !== EXPECTED_INPUT_COUNT
  ) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      `${label} must authenticate all 13 source outputs`,
    );
  }
  for (let index = 0; index < EXPECTED_INPUT_COUNT; index += 1) {
    const input = action.inputSources[index];
    const source = action.sourceOutputs[index];
    exactKeys(input, `${label}.inputSources[${index}]`, [
      'inputIndex',
      'outputIndex',
      'parentKind',
      'serializedOutputSha256',
      'transactionId',
    ]);
    exactKeys(source, `${label}.sourceOutputs[${index}]`, [
      'lockingBytecodeHex',
      'tokenPrefixHex',
      'valueSats',
    ]);
    const fundingInput = index === 12;
    const expectedParent = fundingInput ? funding : previousBundle;
    const expectedParentKind = fundingInput ? 'funding' : 'previous-bundle';
    const expectedOutputIndex = index < 10
      ? index + 1
      : index === 10
        ? 11
        : 0;
    if (
      input.inputIndex !== index
      || input.outputIndex !== expectedOutputIndex
      || input.parentKind !== expectedParentKind
      || input.transactionId !== expectedParent.transactionId
    ) {
      fail(
        'PF10_BUILD_LIBAUTH_INVALID',
        `${label}.inputSources[${index}] is not bound to its parent role`,
      );
    }
    exactHash(
      input.serializedOutputSha256,
      `${label}.inputSources[${index}].serializedOutputSha256`,
    );
    if (
      typeof source.valueSats !== 'string'
      || !/^(?:0|[1-9][0-9]*)$/.test(source.valueSats)
    ) {
      fail(
        'PF10_BUILD_LIBAUTH_INVALID',
        `${label}.sourceOutputs[${index}].valueSats is invalid`,
      );
    }
    canonicalHex(
      source.lockingBytecodeHex,
      `${label}.sourceOutputs[${index}].lockingBytecodeHex`,
      { allowEmpty: true },
    );
    canonicalHex(
      source.tokenPrefixHex,
      `${label}.sourceOutputs[${index}].tokenPrefixHex`,
      { allowEmpty: true },
    );
  }
  exactKeys(action.localVmEvidence, `${label}.localVmEvidence`, [
    'evidenceHash',
    'hex',
    'sha256',
  ]);
  const localVmBytes = Buffer.from(
    canonicalHex(
      action.localVmEvidence.hex,
      `${label}.localVmEvidence.hex`,
    ),
    'hex',
  );
  if (
    action.localVmEvidence.sha256 !== sha256(localVmBytes)
    || action.localVmEvidence.evidenceHash
      !== action.construction.localVmEvidenceHash
  ) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      `${label} local VM evidence hashes are inconsistent`,
    );
  }
  const expectedMutationChecks = [
    ['local-table', 0, [0]],
    ['local-table', 1, [1]],
    ['local-table', 2, [2]],
    ['local-table', 3, [3]],
    ['local-table', 4, [4]],
    ['local-table', 9, [9]],
    ['remote-carrier', 5, [0, 5]],
    ['remote-carrier', 6, [1, 6]],
    ['remote-carrier', 7, [3, 7]],
  ];
  if (
    !Array.isArray(action.mutationChecks)
    || action.mutationChecks.length !== expectedMutationChecks.length
  ) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      `${label} mutation evidence is incomplete`,
    );
  }
  for (const [index, expectedMutation] of expectedMutationChecks.entries()) {
    const mutation = action.mutationChecks[index];
    exactKeys(mutation, `${label}.mutationChecks[${index}]`, [
      'kind',
      'mutatedInput',
      'rejectingInputs',
    ]);
    if (
      mutation.kind !== expectedMutation[0]
      || mutation.mutatedInput !== expectedMutation[1]
      || !Array.isArray(mutation.rejectingInputs)
      || mutation.rejectingInputs.length !== expectedMutation[2].length
      || mutation.rejectingInputs.some(
        (entry, rejectingIndex) =>
          entry !== expectedMutation[2][rejectingIndex],
      )
    ) {
      fail(
        'PF10_BUILD_LIBAUTH_INVALID',
        `${label}.mutationChecks[${index}] is not the exact rejection probe`,
      );
    }
  }
  validateLibauthRows(action.rows, expected.kind);
}

function validateLibauthFixedEvidence(value, expectedTerminalProgramBytes) {
  if (
    expectedTerminalProgramBytes === null
    || Array.isArray(expectedTerminalProgramBytes)
    || typeof expectedTerminalProgramBytes !== 'object'
    || ![
      'raw,redeem',
      'redeem',
    ].includes(Object.keys(expectedTerminalProgramBytes).sort().join(','))
  ) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      'expected PF10 terminal program bytes must contain redeem and optional raw counts',
    );
  }
  for (const [field, bytes] of Object.entries(
    expectedTerminalProgramBytes,
  )) {
    const maximum = field === 'redeem' ? 10_000 : 100_000;
    if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > maximum) {
      fail(
        'PF10_BUILD_LIBAUTH_INVALID',
        `expected PF10 terminal ${field} byte count is invalid`,
      );
    }
  }
  exactKeys(
    value.fixedLineDerivation,
    'PF10 Libauth fixed-line derivation',
    [
      'digestMutationChecks',
      'inputs',
      'proofOrPublicInputs',
      'roleTableBytes',
      'roleTableHash256',
      'terminalTableBytes',
      'terminalTableHash256',
    ],
  );
  const derivation = value.fixedLineDerivation;
  const expectedInputs = [
    'deployment verification key gamma',
    'deployment verification key delta',
    'BN254 constants',
    'ATE NAF digits',
  ];
  const expectedRoleBytes = [6_912, 5_760, 6_144, 6_144, 7_296];
  if (
    derivation.proofOrPublicInputs !== false
    || !Array.isArray(derivation.inputs)
    || derivation.inputs.length !== expectedInputs.length
    || derivation.inputs.some(
      (entry, index) => entry !== expectedInputs[index],
    )
    || !Array.isArray(derivation.roleTableBytes)
    || derivation.roleTableBytes.length !== expectedRoleBytes.length
    || derivation.roleTableBytes.some(
      (entry, index) => entry !== expectedRoleBytes[index],
    )
    || !Array.isArray(derivation.roleTableHash256)
    || derivation.roleTableHash256.length !== expectedRoleBytes.length
    || derivation.roleTableHash256.some(
      (entry) => typeof entry !== 'string' || !HASH.test(entry),
    )
    || derivation.terminalTableBytes !== 768
    || typeof derivation.terminalTableHash256 !== 'string'
    || !HASH.test(derivation.terminalTableHash256)
  ) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      'PF10 Libauth fixed-line derivation is invalid',
    );
  }
  const expectedTables = [
    'executor0',
    'executor1',
    'executor2',
    'executor3',
    'executor4',
    'terminal9',
  ];
  if (
    !Array.isArray(derivation.digestMutationChecks)
    || derivation.digestMutationChecks.length !== expectedTables.length
  ) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      'PF10 Libauth fixed-line digest mutation evidence is incomplete',
    );
  }
  for (const [index, mutation] of
    derivation.digestMutationChecks.entries()) {
    exactKeys(
      mutation,
      `PF10 Libauth fixed-line mutation ${index}`,
      ['honestHash256', 'mutatedHash256', 'table'],
    );
    if (
      mutation.table !== expectedTables[index]
      || typeof mutation.honestHash256 !== 'string'
      || !HASH.test(mutation.honestHash256)
      || typeof mutation.mutatedHash256 !== 'string'
      || !HASH.test(mutation.mutatedHash256)
      || mutation.honestHash256 === mutation.mutatedHash256
      || mutation.honestHash256 !== (
        index < derivation.roleTableHash256.length
          ? derivation.roleTableHash256[index]
          : derivation.terminalTableHash256
      )
    ) {
      fail(
        'PF10_BUILD_LIBAUTH_INVALID',
        `PF10 Libauth fixed-line mutation ${index} is invalid`,
      );
    }
  }
  exactKeys(
    value.fixedPrograms,
    'PF10 Libauth fixed programs',
    [
      ...Object.keys(EXPECTED_FIXED_PROGRAM_BYTES),
      'rawTerminalBytes',
      'terminalRedeemBytes',
    ],
  );
  for (const [field, expected] of
    Object.entries(EXPECTED_FIXED_PROGRAM_BYTES)) {
    const actual = value.fixedPrograms[field];
    if (
      Array.isArray(expected)
        ? (
          !Array.isArray(actual)
          || actual.length !== expected.length
          || actual.some((entry, index) => entry !== expected[index])
        )
        : actual !== expected
    ) {
      fail(
        'PF10_BUILD_LIBAUTH_INVALID',
        `PF10 Libauth fixedPrograms.${field} is invalid`,
      );
    }
  }
  if (
    value.fixedPrograms.terminalRedeemBytes
      !== expectedTerminalProgramBytes.redeem
    || (
      expectedTerminalProgramBytes.raw !== undefined
      && value.fixedPrograms.rawTerminalBytes
        !== expectedTerminalProgramBytes.raw
    )
    || !Number.isSafeInteger(value.fixedPrograms.rawTerminalBytes)
    || value.fixedPrograms.rawTerminalBytes < 1
    || value.fixedPrograms.rawTerminalBytes > 100_000
  ) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      'PF10 Libauth terminal program bytes do not match the pinned verification-key runtime',
    );
  }
  if (
    !Array.isArray(value.identityExecutorRows)
    || value.identityExecutorRows.length !== 5
  ) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      'PF10 Libauth identity executor evidence is incomplete',
    );
  }
  for (const [index, row] of value.identityExecutorRows.entries()) {
    exactKeys(
      row,
      `PF10 Libauth identity executor ${index}`,
      ['index', 'operationCost', 'unlockBytes'],
    );
    if (
      row.index !== index
      || nonnegativeSafeInteger(
        row.operationCost,
        `PF10 Libauth identity executor ${index}.operationCost`,
      ) === 0
      || nonnegativeSafeInteger(
        row.unlockBytes,
        `PF10 Libauth identity executor ${index}.unlockBytes`,
      ) === 0
      || row.unlockBytes > 10_000
    ) {
      fail(
        'PF10_BUILD_LIBAUTH_INVALID',
        `PF10 Libauth identity executor ${index} is invalid`,
      );
    }
  }
}

function parseLibauthEvidence({
  bytes,
  expectedTerminalProgramBytes,
  profileId,
  instanceId,
  proofArtifactHashes,
}) {
  let value;
  try {
    value = parseStrictJson(bytes, 'PF10 Libauth evidence');
  } catch (error) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      `PF10 Libauth evidence is invalid JSON: ${error instanceof Error ? error.message : String(error)}`,
      error,
    );
  }
  exactKeys(value, 'PF10 Libauth evidence', [
    'claims',
    'eligibility',
    'environment',
    'exactDustBases',
    'generatedAt',
    'hardLimits',
    'identity',
    'pf10FusedQGenesisActions',
    'qualificationScope',
    'schema',
  ]);
  if (
    value.schema !== DIRECT_V2_PF10_LIBAUTH_EVIDENCE_SCHEMA
    || value.eligibility !== 'development-only'
  ) {
    fail('PF10_BUILD_LIBAUTH_INVALID', 'PF10 Libauth evidence schema or eligibility is invalid');
  }
  exactBooleanClaims(value.claims);
  exactKeys(value.environment, 'PF10 Libauth environment', [
    'architecture',
    'node',
    'platform',
  ]);
  if (
    value.environment.platform !== 'linux'
    || value.environment.architecture !== 'x64'
    || typeof value.environment.node !== 'string'
    || !/^v[0-9]+\.[0-9]+\.[0-9]+$/.test(value.environment.node)
  ) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      'PF10 Libauth environment is not the qualified Linux x64 Node runtime',
    );
  }
  if (
    typeof value.generatedAt !== 'string'
    || Number.isNaN(Date.parse(value.generatedAt))
    || new Date(value.generatedAt).toISOString() !== value.generatedAt
  ) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      'PF10 Libauth generatedAt is not a canonical UTC timestamp',
    );
  }
  exactKeys(value.qualificationScope, 'PF10 Libauth qualification scope', [
    'feePolicy',
    'inputSequence',
    'parentTransactions',
    'settlementPath',
  ]);
  if (
    value.qualificationScope.feePolicy
      !== 'exact signed bytes at 1 satoshi per byte'
    || value.qualificationScope.inputSequence !== 0
    || value.qualificationScope.parentTransactions
      !== EXPECTED_SCOPE_PARENT_TRANSACTIONS
    || value.qualificationScope.settlementPath
      !== EXPECTED_SCOPE_SETTLEMENT_PATH
  ) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      'PF10 Libauth qualification scope is invalid',
    );
  }
  exactKeys(value.identity, 'PF10 Libauth identity', [
    'instanceId',
    'profileId',
    'proofArtifactHashes',
    'runtimeMaterialSha256',
    'topologyId',
  ]);
  if (
    value.identity.profileId !== profileId
    || value.identity.instanceId !== instanceId
    || value.identity.topologyId !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
    || !HASH.test(value.identity.runtimeMaterialSha256)
  ) {
    fail('PF10_BUILD_LIBAUTH_INVALID', 'PF10 Libauth evidence identity or topology is not bound to this runtime');
  }
  exactKeys(value.identity.proofArtifactHashes, 'PF10 Libauth proof artifacts', PROOF_ARTIFACT_NAMES);
  if (PROOF_ARTIFACT_NAMES.some((name) => value.identity.proofArtifactHashes[name] !== proofArtifactHashes[name])) {
    fail('PF10_BUILD_LIBAUTH_INVALID', 'PF10 Libauth evidence proof artifacts are not bound to this runtime');
  }
  exactKeys(value.exactDustBases, 'PF10 Libauth dust bases', [
    'bindingSats',
    'minimumChangeSats',
    'stateSats',
    'verifierSats',
  ]);
  if (
    value.exactDustBases.bindingSats !== '1200'
    || value.exactDustBases.minimumChangeSats !== '546'
    || value.exactDustBases.stateSats !== '2500'
    || !Array.isArray(value.exactDustBases.verifierSats)
    || value.exactDustBases.verifierSats.length !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length
    || value.exactDustBases.verifierSats.some((entry) => entry !== '1200')
  ) {
    fail('PF10_BUILD_LIBAUTH_INVALID', 'PF10 Libauth evidence dust bases are not exact');
  }
  exactKeys(value.hardLimits, 'PF10 Libauth hard limits', [
    'standardVmResourcePercent',
    'transactionBytes',
    'unlockingBytecodeBytes',
  ]);
  if (
    value.hardLimits.standardVmResourcePercent !== 100
    || value.hardLimits.transactionBytes !== 100_000
    || value.hardLimits.unlockingBytecodeBytes !== 10_000
  ) {
    fail('PF10_BUILD_LIBAUTH_INVALID', 'PF10 Libauth evidence hard limits are invalid');
  }
  exactKeys(value.pf10FusedQGenesisActions, 'PF10 Libauth PF10 action evidence', [
    'actionCount',
    'actions',
    'fixedLineDerivation',
    'fixedPrograms',
    'identityExecutorRows',
    'topologyId',
    'verdict',
  ]);
  if (
    value.pf10FusedQGenesisActions.topologyId !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
    || value.pf10FusedQGenesisActions.actionCount !== 3
    || value.pf10FusedQGenesisActions.verdict !== EXPECTED_LIBAUTH_VERDICT
    || !Array.isArray(value.pf10FusedQGenesisActions.actions)
    || value.pf10FusedQGenesisActions.actions.length !== 3
  ) {
    fail('PF10_BUILD_LIBAUTH_INVALID', 'PF10 Libauth action topology is invalid');
  }
  validateLibauthFixedEvidence(
    value.pf10FusedQGenesisActions,
    expectedTerminalProgramBytes,
  );
  for (const [index, expected] of EXPECTED_ACTIONS.entries()) {
    validateLibauthAction(
      value.pf10FusedQGenesisActions.actions[index],
      expected,
    );
  }
  return value;
}

/**
 * Validate one exact per-instance Libauth qualification artifact.
 *
 * The caller pins the file bytes separately. This validator binds the
 * canonical evidence to the profile, funding-derived instance, proof
 * artifacts, topology, hard-limit verdicts, and the runtime material derived
 * from those same bytes. expectedTerminalProgramBytes must include the exact
 * optimized runtime artifact size. Qualification callers also supply the
 * independently compiled raw size; package consumers need not make raw,
 * non-runtime reproducibility artifacts part of the settlement boundary.
 * It deliberately has no global instance/hash pin:
 * every new genesis necessarily has a new instance-specific runtime.
 */
export function validateDirectV2Pf10LibauthEvidence(value) {
  exactKeys(value, 'PF10 Libauth validation options', [
    'bytes',
    'expectedTerminalProgramBytes',
    'instanceId',
    'profileId',
    'proofArtifactHashes',
    'runtimeMaterialSha256',
  ]);
  if (!(value.bytes instanceof Uint8Array)) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      'PF10 Libauth evidence bytes must be a byte array',
    );
  }
  const runtimeMaterialSha256 = exactIdentity(
    value.runtimeMaterialSha256,
    'PF10 Libauth runtimeMaterialSha256',
  );
  const parsed = parseLibauthEvidence({
    bytes: Buffer.from(value.bytes),
    expectedTerminalProgramBytes: value.expectedTerminalProgramBytes,
    profileId: exactIdentity(value.profileId, 'PF10 Libauth profileId'),
    instanceId: exactIdentity(value.instanceId, 'PF10 Libauth instanceId'),
    proofArtifactHashes: value.proofArtifactHashes,
  });
  if (parsed.identity.runtimeMaterialSha256 !== runtimeMaterialSha256) {
    fail(
      'PF10_BUILD_LIBAUTH_INVALID',
      'PF10 Libauth evidence runtime material hash is not bound to this runtime',
    );
  }
  return Object.freeze({
    schema: parsed.schema,
    eligibility: parsed.eligibility,
    sha256: sha256(Buffer.from(value.bytes)),
    runtimeMaterialSha256,
  });
}

function repositoryRelative(root, filename) {
  const relative = path.relative(root, filename);
  if (
    relative.length === 0
    || relative === '..'
    || relative.startsWith(`..${path.sep}`)
    || path.isAbsolute(relative)
  ) {
    fail(
      'PF10_BUILD_PATH_INVALID',
      `artifact path escapes the repository: ${filename}`,
    );
  }
  return relative.split(path.sep).join('/');
}

function artifactRelative(root, filename, label) {
  const relative = path.relative(root, filename);
  if (relative.length === 0 || relative === '..'
      || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    fail(
      'PF10_BUILD_PATH_INVALID',
      `${label} escapes artifactRoot: ${filename}`,
    );
  }
  return relative.split(path.sep).join('/');
}

async function canonicalRepository(value) {
  if (typeof value !== 'string' || !path.isAbsolute(value)
      || path.normalize(value) !== value || value.includes('\0')) {
    fail('PF10_BUILD_PATH_INVALID', 'repositoryRoot must be a normalized absolute path');
  }
  let moduleRoot;
  try {
    moduleRoot = await realpath(MODULE_REPOSITORY_ROOT);
  } catch (error) {
    fail('PF10_BUILD_PATH_INVALID', 'loaded builder checkout is not readable', error);
  }
  if (value !== moduleRoot) {
    fail(
      'PF10_BUILD_PATH_INVALID',
      'repositoryRoot must be the exact checkout containing the loaded PF10 builder',
    );
  }
  const record = await canonicalDirectoryRecord(
    value,
    'repositoryRoot',
    { privateOwner: false },
  );
  return record.path;
}

async function canonicalDirectoryRecord(value, label, { privateOwner }) {
  if (typeof value !== 'string' || !path.isAbsolute(value)
      || path.normalize(value) !== value || value.includes('\0')) {
    fail('PF10_BUILD_PATH_INVALID', `${label} must be a normalized absolute path`);
  }
  let metadata;
  let canonical;
  let handle;
  try {
    metadata = await lstat(value, { bigint: true });
    canonical = await realpath(value);
    handle = await open(
      value,
      fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
    );
    const opened = await handle.stat({ bigint: true });
    if (!sameFilesystemIdentity(
      filesystemIdentity(metadata, DIRECTORY_IDENTITY_FIELDS),
      filesystemIdentity(opened, DIRECTORY_IDENTITY_FIELDS),
      DIRECTORY_IDENTITY_FIELDS,
    )) {
      fail('PF10_BUILD_PATH_RACE', `${label} changed before it could be opened`);
    }
    metadata = opened;
  } catch (error) {
    if (error instanceof DirectV2Pf10RuntimeBuildError) throw error;
    fail('PF10_BUILD_PATH_INVALID', `${label} is not readable`, error);
  } finally {
    await handle?.close().catch(() => undefined);
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()
      || canonical !== value) {
    fail(
      'PF10_BUILD_PATH_INVALID',
      `${label} must be a canonical non-symlink directory`,
    );
  }
  if (privateOwner
      && ((metadata.mode & 0o077n) !== 0n
        || (typeof process.getuid === 'function'
          && metadata.uid !== BigInt(process.getuid())))) {
    fail(
      'PF10_BUILD_PATH_INVALID',
      `${label} must be an owner-private directory`,
    );
  }
  return Object.freeze({
    path: value,
    identity: filesystemIdentity(metadata, DIRECTORY_IDENTITY_FIELDS),
    privateOwner,
  });
}

async function assertDirectoryRecord(record, label) {
  const current = await canonicalDirectoryRecord(
    record.path,
    label,
    { privateOwner: record.privateOwner },
  );
  if (!sameFilesystemIdentity(
    record.identity,
    current.identity,
    DIRECTORY_IDENTITY_FIELDS,
  )) {
    fail('PF10_BUILD_PATH_RACE', `${label} identity changed`);
  }
  return current;
}

async function canonicalArtifactRoot(value, repositoryRoot, {
  requirePrivate,
}) {
  const selected = value === undefined ? repositoryRoot : value;
  return canonicalDirectoryRecord(
    selected,
    'artifactRoot',
    { privateOwner: requirePrivate || selected !== repositoryRoot },
  );
}

async function stableArtifact(root, value, label, includeData = false) {
  if (typeof value.path !== 'string' || !path.isAbsolute(value.path)
      || path.normalize(value.path) !== value.path || value.path.includes('\0')) {
    fail('PF10_BUILD_PATH_INVALID', `${label} path must be normalized and absolute`);
  }
  const filename = value.path;
  artifactRelative(root.path, filename, label);
  await assertDirectoryRecord(root, 'artifactRoot');
  let metadata;
  let canonical;
  let handle;
  try {
    metadata = await lstat(filename, { bigint: true });
    canonical = await realpath(filename);
  } catch (error) {
    fail('PF10_BUILD_PATH_INVALID', `${label} is not readable`, error);
  }
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || metadata.nlink !== 1n
    || metadata.size === 0n
    || canonical !== filename
  ) {
    fail(
      'PF10_BUILD_PATH_INVALID',
      `${label} must be one canonical nonempty regular file`,
    );
  }
  try {
    handle = await open(
      filename,
      fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
    );
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n
        || before.size === 0n
        || !sameFilesystemIdentity(
          filesystemIdentity(metadata),
          filesystemIdentity(before),
        )) {
      fail('PF10_BUILD_ARTIFACT_CHANGED', `${label} changed before it could be opened`);
    }
    const digest = createHash('sha256');
    const chunks = [];
    let size = 0n;
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      digest.update(chunk);
      size += BigInt(chunk.length);
      if (includeData) chunks.push(Buffer.from(chunk));
    }
    const after = await handle.stat({ bigint: true });
    const named = await lstat(filename, { bigint: true });
    const finalCanonical = await realpath(filename);
    if (
      !sameFilesystemIdentity(
        filesystemIdentity(before),
        filesystemIdentity(after),
      )
      || !sameFilesystemIdentity(
        filesystemIdentity(before),
        filesystemIdentity(named),
      )
      || finalCanonical !== filename
      || size !== before.size
    ) {
      fail('PF10_BUILD_ARTIFACT_CHANGED', `${label} changed while read`);
    }
    await assertDirectoryRecord(root, 'artifactRoot');
    const actual = digest.digest('hex');
    if (actual !== value.sha256) {
      fail(
        'PF10_BUILD_ARTIFACT_MISMATCH',
        `${label} SHA-256 differs from the supplied profile pin`,
      );
    }
    if (before.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail('PF10_BUILD_ARTIFACT_TOO_LARGE', `${label} is too large`);
    }
    return Object.freeze({
      path: artifactRelative(root.path, filename, label),
      bytes: Number(before.size),
      sha256: actual,
      data: includeData ? Buffer.concat(chunks) : undefined,
    });
  } catch (error) {
    if (error instanceof DirectV2Pf10RuntimeBuildError) throw error;
    fail('PF10_BUILD_PATH_INVALID', `${label} cannot be opened safely`, error);
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function privateTemporaryDirectory(value) {
  if (typeof value !== 'string' || !path.isAbsolute(value)
      || path.resolve(value) !== value) {
    fail('PF10_BUILD_PATH_INVALID', 'temporaryRoot must be a normalized absolute path');
  }
  const directory = value;
  const parent = path.dirname(directory);
  let exists = true;
  try {
    await lstat(directory);
  } catch (error) {
    if (error?.code !== 'ENOENT') {
      fail('PF10_BUILD_PATH_INVALID', 'temporaryRoot is not readable', error);
    }
    exists = false;
  }
  const parentRecord = await canonicalDirectoryRecord(
    parent,
    'temporaryRoot parent',
    { privateOwner: !exists },
  );
  try {
    await mkdir(directory, { mode: 0o700 });
  } catch (error) {
    if (error?.code !== 'EEXIST') {
      fail('PF10_BUILD_PATH_INVALID', 'temporaryRoot cannot be created', error);
    }
  }
  await assertDirectoryRecord(parentRecord, 'temporaryRoot parent');
  const rootRecord = await canonicalDirectoryRecord(
    directory,
    'temporaryRoot',
    { privateOwner: true },
  );
  const workDirectory = await mkdtemp(path.join(directory, 'pf10-runtime-'));
  const workRecord = await canonicalDirectoryRecord(
    workDirectory,
    'PF10 work directory',
    { privateOwner: true },
  );
  await assertDirectoryRecord(rootRecord, 'temporaryRoot');
  await assertDirectoryRecord(parentRecord, 'temporaryRoot parent');
  return Object.freeze({
    path: workDirectory,
    root: rootRecord,
    parent: parentRecord,
    work: workRecord,
  });
}

async function cleanupPrivateTemporaryDirectory(record) {
  await assertDirectoryRecord(record.parent, 'temporaryRoot parent');
  await assertDirectoryRecord(record.root, 'temporaryRoot');
  await assertDirectoryRecord(record.work, 'PF10 work directory');
  await rm(record.path, { recursive: true, force: false });
  await assertDirectoryRecord(record.root, 'temporaryRoot');
  await assertDirectoryRecord(record.parent, 'temporaryRoot parent');
}

function compile(source, files = {}) {
  try {
    return Buffer.from(cashcUtils.asmToBytecode(
      compileString(source, {
        files,
        ...OPCOST_COMPILER_OPTIONS,
      }).bytecode,
    ));
  } catch (error) {
    fail(
      'PF10_BUILD_COMPILE_FAILED',
      `CashC compilation failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
      error,
    );
  }
}

async function optimize({
  bytecode,
  label,
  optimizerRoot,
  workDirectory,
  onStage = undefined,
}) {
  const stageStarted = performance.now();
  const directory = await mkdtemp(path.join(workDirectory, `${label}-`));
  const input = path.join(directory, 'input.hex');
  const optimized = path.join(directory, 'optimized.hex');
  const canonical = path.join(directory, 'canonical.hex');
  await writeFile(input, binToHex(bytecode), {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });
  const run = async (program, args, step) => {
    try {
      await execFileAsync(program, args, {
        cwd: optimizerRoot,
        encoding: 'utf8',
        timeout: 120_000,
        maxBuffer: 16 * 1024 * 1024,
        windowsHide: true,
      });
    } catch (error) {
      const detail = error === null || typeof error !== 'object'
        ? error
        : error.stderr || error.stdout || error.signal || error.message;
      fail(
        'PF10_BUILD_OPTIMIZER_FAILED',
        `${label} ${step} failed: ${detail}`,
        error,
      );
    }
  };
  await run(
    process.execPath,
    [path.join(optimizerRoot, 'optimize.mjs'), input, optimized],
    'optimizer',
  );
  await run(
    process.execPath,
    [path.join(optimizerRoot, 'minpush_canon.mjs'), optimized, canonical],
    'minimal-push canonicalizer',
  );
  let encoded;
  try {
    encoded = (await readFile(canonical, 'utf8')).trim();
  } catch (error) {
    fail(
      'PF10_BUILD_OPTIMIZER_FAILED',
      `${label} canonical optimizer output is unreadable`,
      error,
    );
  }
  if (!/^(?:[0-9a-f]{2})+$/.test(encoded)) {
    fail(
      'PF10_BUILD_OPTIMIZER_FAILED',
      `${label} optimizer emitted noncanonical hexadecimal bytecode`,
    );
  }
  const result = Buffer.from(hexToBin(encoded));
  if (onStage !== undefined) {
    onStage(Object.freeze({
      label,
      elapsedMs: performance.now() - stageStarted,
    }));
  }
  return result;
}

const exactReproducibilityBytes = (value, label) => {
  if (!(value instanceof Uint8Array) || value.byteLength === 0) {
    fail(
      'PF10_REPRODUCIBILITY_INVALID',
      `${label} must be nonempty bytes`,
    );
  }
  return Buffer.from(value);
};

const exactReproducibilityProgram = (value, label) => {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.keys(value).sort().join(',') !== 'raw,source'
  ) {
    fail(
      'PF10_REPRODUCIBILITY_INVALID',
      `${label} must contain exact source and raw bytes`,
    );
  }
  const sourceBytes = exactReproducibilityBytes(
    value.source,
    `${label}.source`,
  );
  const source = sourceBytes.toString('utf8');
  if (!Buffer.from(source, 'utf8').equals(sourceBytes)) {
    fail(
      'PF10_REPRODUCIBILITY_INVALID',
      `${label}.source is not exact UTF-8`,
    );
  }
  return Object.freeze({
    source,
    sourceBytes,
    raw: exactReproducibilityBytes(value.raw, `${label}.raw`),
  });
};

/**
 * Reproduce every emitted PF10 verifier program from the retained CashScript
 * sources, then run the pinned optimizer/canonicalizer and bind those outputs
 * to the exact runtime bytecode. A manifest can count source files; this check
 * proves those sources actually rebuild the executable runtime.
 */
export async function validateDirectV2Pf10Reproducibility({
  repositoryRoot,
  temporaryRoot,
  programs,
  runtimeArtifacts,
} = {}) {
  const root = await canonicalRepository(repositoryRoot);
  if (
    programs === null
    || Array.isArray(programs)
    || typeof programs !== 'object'
    || Object.keys(programs).sort().join(',')
      !== 'exactFinal,exactMsm,executor,miller,terminal'
    || !Array.isArray(programs.exactMsm)
    || programs.exactMsm.length !== 3
  ) {
    fail(
      'PF10_REPRODUCIBILITY_INVALID',
      'programs must contain the exact PF10 reproducibility topology',
    );
  }
  if (
    runtimeArtifacts === null
    || Array.isArray(runtimeArtifacts)
    || typeof runtimeArtifacts !== 'object'
    || Object.keys(runtimeArtifacts).sort().join(',')
      !== 'exactMsmRedeems,executorBody,fusedRedeem,terminalRedeem'
    || !Array.isArray(runtimeArtifacts.exactMsmRedeems)
    || runtimeArtifacts.exactMsmRedeems.length !== 3
  ) {
    fail(
      'PF10_REPRODUCIBILITY_INVALID',
      'runtimeArtifacts must contain the exact PF10 executable topology',
    );
  }
  const parsedPrograms = Object.freeze({
    executor: exactReproducibilityProgram(
      programs.executor,
      'programs.executor',
    ),
    exactFinal: exactReproducibilityProgram(
      programs.exactFinal,
      'programs.exactFinal',
    ),
    miller: exactReproducibilityProgram(
      programs.miller,
      'programs.miller',
    ),
    terminal: exactReproducibilityProgram(
      programs.terminal,
      'programs.terminal',
    ),
    exactMsm: Object.freeze(programs.exactMsm.map((program, index) =>
      exactReproducibilityProgram(
        program,
        `programs.exactMsm[${index}]`,
      ))),
  });
  const expectedRuntime = Object.freeze({
    executorBody: exactReproducibilityBytes(
      runtimeArtifacts.executorBody,
      'runtimeArtifacts.executorBody',
    ),
    exactMsmRedeems: Object.freeze(
      runtimeArtifacts.exactMsmRedeems.map((value, index) =>
        exactReproducibilityBytes(
          value,
          `runtimeArtifacts.exactMsmRedeems[${index}]`,
        )),
    ),
    fusedRedeem: exactReproducibilityBytes(
      runtimeArtifacts.fusedRedeem,
      'runtimeArtifacts.fusedRedeem',
    ),
    terminalRedeem: exactReproducibilityBytes(
      runtimeArtifacts.terminalRedeem,
      'runtimeArtifacts.terminalRedeem',
    ),
  });
  const workDirectory = await privateTemporaryDirectory(temporaryRoot);
  try {
    const optimizerRoot = path.join(
      root,
      'shieldkit-groth/packages/unlock-builder/vendor/verifier/tools/singleton-artifact',
    );
    const lazyAffineLibrary = await readFile(path.join(
      root,
      'shieldkit-groth/packages/unlock-builder/vendor/verifier/build/singleton/bn254/lib/lazy/Bn254LazyAff_kspec.cash',
    ), 'utf8');
    const reproduce = async (
      name,
      program,
      expectedRedeem,
      { lazyLibrary = false } = {},
    ) => {
      const compiled = compile(
        program.source,
        lazyLibrary
          ? { 'Bn254LazyAff.cash': lazyAffineLibrary }
          : {},
      );
      if (!compiled.equals(program.raw)) {
        fail(
          'PF10_REPRODUCIBILITY_MISMATCH',
          `${name} retained raw bytecode is not compiled from its source`,
        );
      }
      const optimized = await optimize({
        bytecode: compiled,
        label: `reproduce-${name}`,
        optimizerRoot,
        workDirectory: workDirectory.path,
      });
      if (
        expectedRedeem !== undefined
        && !optimized.equals(expectedRedeem)
      ) {
        fail(
          'PF10_REPRODUCIBILITY_MISMATCH',
          `${name} optimized bytecode differs from the runtime`,
        );
      }
      return optimized;
    };
    const terminalRedeem = await reproduce(
      'terminal',
      parsedPrograms.terminal,
      expectedRuntime.terminalRedeem,
      { lazyLibrary: true },
    );
    const executorBody = await reproduce(
      'executor',
      parsedPrograms.executor,
      expectedRuntime.executorBody,
      { lazyLibrary: true },
    );
    const exactFinalRedeem = await reproduce(
      'exact-final',
      parsedPrograms.exactFinal,
    );
    const millerRedeem = await reproduce(
      'miller',
      parsedPrograms.miller,
      undefined,
      { lazyLibrary: true },
    );
    const exactMsmRedeems = [];
    for (let index = 0; index < parsedPrograms.exactMsm.length; index += 1) {
      exactMsmRedeems.push(await reproduce(
        `exact-msm-${index}`,
        parsedPrograms.exactMsm[index],
        expectedRuntime.exactMsmRedeems[index],
      ));
    }
    const fusedRedeem = Buffer.from(
      buildDirectV2Pf10FusedQGenesisRedeem({
        millerRedeem,
        exactMsmRedeem: exactFinalRedeem,
      }),
    );
    if (!fusedRedeem.equals(expectedRuntime.fusedRedeem)) {
      fail(
        'PF10_REPRODUCIBILITY_MISMATCH',
        'fused verifier runtime is not reproduced from exact-final and Miller sources',
      );
    }
    const programHashes = (program, redeem) => Object.freeze({
      source: sha256(program.sourceBytes),
      raw: sha256(program.raw),
      redeem: sha256(redeem),
      lock: sha256(p2sh32(redeem)),
    });
    return Object.freeze({
      executorBodySha256: sha256(executorBody),
      exactMsmRedeemSha256: Object.freeze(exactMsmRedeems.map(sha256)),
      fusedRedeemSha256: sha256(fusedRedeem),
      terminalRedeemSha256: sha256(terminalRedeem),
      programs: Object.freeze({
        executor: programHashes(parsedPrograms.executor, executorBody),
        exactFinal: programHashes(
          parsedPrograms.exactFinal,
          exactFinalRedeem,
        ),
        exactMsm: Object.freeze(parsedPrograms.exactMsm.map(
          (program, index) => programHashes(
            program,
            exactMsmRedeems[index],
          ),
        )),
        fused: Object.freeze({
          redeem: sha256(fusedRedeem),
          lock: sha256(p2sh32(fusedRedeem)),
        }),
        miller: programHashes(parsedPrograms.miller, millerRedeem),
        terminal: programHashes(parsedPrograms.terminal, terminalRedeem),
      }),
    });
  } finally {
    await cleanupPrivateTemporaryDirectory(workDirectory);
  }
}

function fixedTableCarrierLayout({
  template,
  carrierBytes,
  firstInputIndex,
  payloadOffset,
}) {
  let cursor = 0;
  const layout = template.roles.map((roleTemplate) => {
    let remaining = roleTemplate.remoteTable.length;
    const slices = [];
    while (remaining > 0) {
      const carrierIndex = Math.floor(cursor / carrierBytes);
      const withinCarrier = cursor % carrierBytes;
      const length = Math.min(
        remaining,
        carrierBytes - withinCarrier,
      );
      slices.push(Object.freeze({
        inputIndex: firstInputIndex + carrierIndex,
        payloadOffset: payloadOffset + withinCarrier,
        length,
      }));
      cursor += length;
      remaining -= length;
    }
    return Object.freeze(slices);
  });
  return Object.freeze({ layout: Object.freeze(layout), bytes: cursor });
}

function bqLayout(template) {
  return template.roles.map((roleTemplate, inputIndex) => ({
    inputIndex,
    offset:
      encodedLength(roleTemplate.state.length)
      + encodedLength(roleTemplate.records.length)
      + encodedLength(roleTemplate.table.length)
      + pushHeaderLength(DIRECT_V2_PF10_BQ_SHARD_BYTES[inputIndex]),
    length: DIRECT_V2_PF10_BQ_SHARD_BYTES[inputIndex],
  }));
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) {
    fail(
      'PF10_BUILD_LAYOUT_MISMATCH',
      `${label} is ${actual}, expected ${expected}`,
    );
  }
}

function immutableProgram({ source, raw, redeem }) {
  return Object.freeze({
    source,
    raw: Buffer.from(raw),
    redeem: Buffer.from(redeem),
    lock: p2sh32(redeem),
    hashes: Object.freeze({
      source: sha256(Buffer.from(source, 'utf8')),
      raw: sha256(raw),
      redeem: sha256(redeem),
      lock: sha256(p2sh32(redeem)),
    }),
  });
}

/**
 * Compile the exact PF10 instance-specific verifier programs from descriptor
 * identities and already content-pinned proof artifacts.
 */
async function buildDirectV2Pf10Runtime({
  repositoryRoot,
  artifactRoot: artifactRootValue = repositoryRoot,
  temporaryRoot,
  profileId: profileIdentity,
  instanceId: instanceIdentity,
  proofArtifacts: proofArtifactRecords,
  libauthEvidence: libauthEvidenceRecord = undefined,
  runtimeMaterialSchema,
  eligibility,
  runtimeBuildSchema,
  validateRuntimeMaterial,
  includeLibauthEvidence,
  requirePrivateArtifactRoot = false,
  onOptimizeStage: suppliedOptimizeStage = undefined,
} = {}) {
  const root = await canonicalRepository(repositoryRoot);
  const artifactRoot = await canonicalArtifactRoot(
    artifactRootValue,
    root,
    { requirePrivate: requirePrivateArtifactRoot },
  );
  const profileId = exactIdentity(profileIdentity, 'profileId');
  const instanceId = exactIdentity(instanceIdentity, 'instanceId');
  const proofArtifacts = exactArtifactRecord(proofArtifactRecords);
  if (suppliedOptimizeStage !== undefined
    && typeof suppliedOptimizeStage !== 'function') {
    fail(
      'PF10_BUILD_INPUT_INVALID',
      'onOptimizeStage must be a function when supplied',
    );
  }
  const onOptimizeStage = suppliedOptimizeStage;
  const libauthEvidence = libauthEvidenceRecord === undefined
    ? undefined
    : exactPinnedArtifactRecord(
      libauthEvidenceRecord,
      'PF10 Libauth evidence',
    );
  const workDirectory = await privateTemporaryDirectory(temporaryRoot);
  try {
    const verifiedArtifacts = {};
    for (const name of PROOF_ARTIFACT_NAMES) {
      verifiedArtifacts[name] = await stableArtifact(
        artifactRoot,
        proofArtifacts[name],
        `PF10 ${name}`,
        name === 'verificationKey',
      );
    }
    const verifiedLibauthEvidence = libauthEvidence === undefined
      ? undefined
      : await stableArtifact(
        artifactRoot,
        libauthEvidence,
        'PF10 Libauth evidence',
        true,
      );
    const verificationKeyBytes =
      Buffer.from(verifiedArtifacts.verificationKey.data);
    let verificationKeyJson;
    let verificationKey;
    try {
      verificationKeyJson = parseStrictJson(
        verificationKeyBytes,
        'PF10 verification key',
      );
      verificationKey =
        parseDirectV2MillerVerificationKey(verificationKeyJson);
    } catch (error) {
      fail(
        'PF10_BUILD_VK_INVALID',
        `PF10 verification key is invalid: ${
          error instanceof Error ? error.message : String(error)
        }`,
        error,
      );
    }
    const identityTrace = computeDirectV2IdentityAwareMiller({
      verificationKey,
      proof: createDirectV2IdentityReferenceProof(verificationKey),
      q: null,
    });
    const fixedTemplate = buildDirectV2TotalPairFoldWitness(
      identityTrace,
      { precomputedFixedLines: true },
    );
    const fixedRemoteBlob = concat(
      ...fixedTemplate.roles.map((entry) => entry.remoteTable),
    );
    const exactPaddingPayloadOffset =
      encodedLength(128)
      + encodedLength(0)
      + pushHeaderLength(DIRECT_V2_PF10_NONFINAL_MSM_PADDING_BYTES);
    const fixedCarrierPads = Object.freeze(Array.from(
      { length: 3 },
      (_, index) => {
        const start =
          index * DIRECT_V2_PF10_NONFINAL_MSM_PADDING_BYTES;
        const end =
          start + DIRECT_V2_PF10_NONFINAL_MSM_PADDING_BYTES;
        return concat(
          fixedRemoteBlob.subarray(start, end),
          Buffer.alloc(Math.max(0, end - fixedRemoteBlob.length)),
        );
      },
    ));
    const fixedTableCarriers = fixedTableCarrierLayout({
      template: fixedTemplate,
      carrierBytes: DIRECT_V2_PF10_NONFINAL_MSM_PADDING_BYTES,
      firstInputIndex: FIRST_EXACT_INPUT_INDEX,
      payloadOffset: exactPaddingPayloadOffset,
    });
    assertEqual(fixedRemoteBlob.length, 20_864, 'fixed remote-table blob');
    assertEqual(
      fixedTableCarriers.bytes,
      fixedRemoteBlob.length,
      'fixed carrier layout',
    );
    assertEqual(exactPaddingPayloadOffset, 134, 'carrier payload offset');
    fixedCarrierPads.forEach((pad, index) => assertEqual(
      pad.length,
      DIRECT_V2_PF10_NONFINAL_MSM_PADDING_BYTES,
      `fixed carrier pad ${index}`,
    ));

    const bindingOptions = Object.freeze({
      networkId: NETWORK_ID,
      profileId,
      stateCategory: instanceId,
      denominationSats: DENOMINATION_SATS,
      topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
      verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
    });
    const bindingRedeem = Buffer.from(
      buildDirectV2BindingRedeem(bindingOptions),
    );
    const bindingLock = Buffer.from(buildDirectV2BindingLock(bindingOptions));

    const identityMsm = computeDirectV2ExactMsm(
      verificationKeyJson,
      0n,
      0n,
    );
    const identityProjection = encodeDirectV2MillerProjectionSignal(
      identityTrace,
      Buffer.alloc(32),
    );
    const exactPrefixBytes = directV2Pf10ExactMsmArgumentPrefix({
      projectionSignal: identityProjection,
      msmState: encodeDirectV2MsmState(identityMsm.states[3]),
      zInverse: identityMsm.output.zInverse,
      exactMsmZeroPadding:
        Buffer.alloc(DIRECT_V2_PF10_EXACT_MSM_ZERO_PADDING_BYTES),
    }).length;
    const fusedStatePayloadOffset =
      encodedLength(480) + pushHeaderLength(128);
    const fusedResiduePayloadOffset =
      exactPrefixBytes
      + encodedLength(64)
      + encodedLength(384)
      + pushHeaderLength(1_152);
    assertEqual(exactPrefixBytes, 905, 'exact-MSM prefix width');
    assertEqual(fusedStatePayloadOffset, 485, 'fused state payload offset');
    assertEqual(
      fusedResiduePayloadOffset,
      1_360,
      'fused residue payload offset',
    );

    const optimizerRoot = path.join(
      root,
      'shieldkit-groth/packages/unlock-builder/vendor/verifier/tools/singleton-artifact',
    );
    const lazyAffineLibrary = await readFile(path.join(
      root,
      'shieldkit-groth/packages/unlock-builder/vendor/verifier/build/singleton/bn254/lib/lazy/Bn254LazyAff_kspec.cash',
    ), 'utf8');
    const pairFoldRenderOptions = {
      verificationKey,
      stateCategoryHex: instanceId,
      libraryImportPath: 'Bn254LazyAff.cash',
    };
    const terminalSource = renderDirectV2TotalPairFoldTerminal({
      ...pairFoldRenderOptions,
      template: fixedTemplate,
      bqShards: bqLayout(fixedTemplate),
      terminalInputIndex: TERMINAL_INPUT_INDEX,
      stateInputIndex: STATE_INPUT_INDEX,
      projectionInputIndex: FUSED_INPUT_INDEX,
      residueInputIndex: FUSED_INPUT_INDEX,
      residuePayloadOffset: fusedResiduePayloadOffset,
    });
    const terminalRaw = compile(terminalSource, {
      'Bn254LazyAff.cash': lazyAffineLibrary,
    });
    const terminalRedeem = await optimize({
      bytecode: terminalRaw,
      label: 'terminal',
      optimizerRoot,
      workDirectory: workDirectory.path,
      onStage: onOptimizeStage,
    });
    const terminal = immutableProgram({
      source: terminalSource,
      raw: terminalRaw,
      redeem: terminalRedeem,
    });

    const executorSource = renderDirectV2TotalPairFoldExecutor({
      ...pairFoldRenderOptions,
      template: fixedTemplate,
      terminalLockingBytecodeHex: binToHex(terminal.lock),
      bqShardBytes: DIRECT_V2_PF10_BQ_SHARD_BYTES,
      terminalInputIndex: TERMINAL_INPUT_INDEX,
      stateInputIndex: STATE_INPUT_INDEX,
      projectionInputIndex: FUSED_INPUT_INDEX,
      fixedTableCarriers: fixedTableCarriers.layout,
    });
    const executorRaw = compile(executorSource, {
      'Bn254LazyAff.cash': lazyAffineLibrary,
    });
    const executorBody = await optimize({
      bytecode: executorRaw,
      label: 'executor',
      optimizerRoot,
      workDirectory: workDirectory.path,
      onStage: onOptimizeStage,
    });
    const executor = immutableProgram({
      source: executorSource,
      raw: executorRaw,
      redeem: executorBody,
    });
    const fragments = splitDirectV2PairFoldBody(executorBody);
    const fragmentOffsets = fixedTemplate.roles.map((roleTemplate, index) =>
      encodedLength(roleTemplate.state.length)
      + encodedLength(roleTemplate.records.length)
      + encodedLength(roleTemplate.table.length)
      + encodedLength(DIRECT_V2_PF10_BQ_SHARD_BYTES[index])
      + 3);
    const loader = buildDirectV2PairFoldLoader({
      body: executorBody,
      fragmentOffsets,
      fragmentLengths: fragments.map((fragment) => fragment.length),
      functionId: DIRECT_V2_PF10_EXECUTOR_FUNCTION_ID,
      densityPadBytes: DIRECT_V2_PF10_EXECUTOR_DENSITY_PAD_BYTES,
    });

    const exactFinalSource = renderDirectV2ExactMsmRole({
      verificationKey: verificationKeyJson,
      windowIndex: 3,
      inputIndex: FUSED_INPUT_INDEX,
      successorInputIndex: TERMINAL_INPUT_INDEX,
      successorLockingBytecodeHex: binToHex(terminal.lock),
      successorStatePayloadOffset: 0,
      stateInputIndex: STATE_INPUT_INDEX,
      stateCategoryHex: instanceId,
      expectedInputCount: EXPECTED_INPUT_COUNT,
      packetInputIndex: BINDING_INPUT_INDEX,
      packetLockingBytecodeHex: binToHex(bindingLock),
      fixedWidthZInverse: true,
      zeroPaddingBytes: DIRECT_V2_PF10_EXACT_MSM_ZERO_PADDING_BYTES,
    });
    const exactFinalRaw = compile(exactFinalSource);
    const exactFinalOptimization = optimize({
      bytecode: exactFinalRaw,
      label: 'exact-final',
      optimizerRoot,
      workDirectory: workDirectory.path,
      onStage: onOptimizeStage,
    });
    const millerSource =
      renderDirectV2Pf10FusedQGenesisMillerComponent({
        verificationKey,
        ownWitnessPayloadOffset: exactPrefixBytes,
        successorLockingBytecodeHex: binToHex(terminal.lock),
        bindingLockingBytecodeHex: binToHex(bindingLock),
        stateCategoryHex: instanceId,
        zeroPaddingBytes: DIRECT_V2_PF10_MILLER_ZERO_PADDING_BYTES,
        libraryImportPath: 'Bn254LazyAff.cash',
      });
    const millerRaw = compile(millerSource, {
      'Bn254LazyAff.cash': lazyAffineLibrary,
    });
    const millerOptimization = optimize({
      bytecode: millerRaw,
      label: 'miller',
      optimizerRoot,
      workDirectory: workDirectory.path,
      onStage: onOptimizeStage,
    });
    const [exactFinalRedeem, millerRedeem] = await Promise.all([
      exactFinalOptimization,
      millerOptimization,
    ]);
    const exactFinal = immutableProgram({
      source: exactFinalSource,
      raw: exactFinalRaw,
      redeem: exactFinalRedeem,
    });
    const miller = immutableProgram({
      source: millerSource,
      raw: millerRaw,
      redeem: millerRedeem,
    });
    const fusedRedeem = Buffer.from(
      buildDirectV2Pf10FusedQGenesisRedeem({
        millerRedeem,
        exactMsmRedeem: exactFinalRedeem,
      }),
    );
    const fusedLock = p2sh32(fusedRedeem);

    const exactPrograms = Array(3);
    let successorLock = fusedLock;
    for (let windowIndex = 2; windowIndex >= 0; windowIndex -= 1) {
      const inputIndex = windowIndex + FIRST_EXACT_INPUT_INDEX;
      const source = renderDirectV2ExactMsmRole({
        verificationKey: verificationKeyJson,
        windowIndex,
        inputIndex,
        successorInputIndex: inputIndex + 1,
        successorLockingBytecodeHex: binToHex(successorLock),
        successorStatePayloadOffset:
          windowIndex === 2 ? fusedStatePayloadOffset : 2,
        stateInputIndex: STATE_INPUT_INDEX,
        stateCategoryHex: instanceId,
        expectedInputCount: EXPECTED_INPUT_COUNT,
        packetInputIndex: BINDING_INPUT_INDEX,
        packetLockingBytecodeHex: binToHex(bindingLock),
        zeroPaddingBytes: DIRECT_V2_PF10_NONFINAL_MSM_PADDING_BYTES,
        densityCarrierBytes: fixedCarrierPads[windowIndex],
      });
      const raw = compile(source);
      const redeem = await optimize({
        bytecode: raw,
        label: `exact-${windowIndex}`,
        optimizerRoot,
        workDirectory: workDirectory.path,
        onStage: onOptimizeStage,
      });
      const program = immutableProgram({ source, raw, redeem });
      exactPrograms[windowIndex] = program;
      successorLock = program.lock;
    }

    const verifierLocks = Object.freeze([
      ...Array(5).fill(Buffer.from(loader.lock)),
      ...exactPrograms.map((program) => Buffer.from(program.lock)),
      fusedLock,
      terminal.lock,
    ]);
    assertEqual(
      verifierLocks.length,
      DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length,
      'verifier lock count',
    );
    const verifierBaseValues = Object.freeze(verifierLocks.map(
      (lockingBytecode) => deriveV2RollingBaseSats({ lockingBytecode }),
    ));
    const bindingBaseValueSats = deriveV2RollingBaseSats({
      lockingBytecode: bindingLock,
    });
    const stateCategory = Buffer.from(hexToBin(instanceId));
    let stateBaseValueSats = 1_000n;
    let helper;
    let stateLock;
    let stateBaseConverged = false;
    for (let iteration = 0; iteration < 8; iteration += 1) {
      helper = Buffer.from(buildDirectV2StateHelper({
        bindingLock,
        verifierLocks,
        verifierBaseValues,
        bindingBaseValueSats,
        stateBaseValueSats,
        denominationSats: DENOMINATION_SATS,
        stateCategory: instanceId,
        minimumChangeSats: MINIMUM_CHANGE_SATS,
        topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
        verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
      }));
      stateLock = Buffer.from(buildDirectV2StateTrampolineLock({
        helper,
        bindingLock,
        topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
        verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
      }));
      const derivedStateBase = deriveV2RollingBaseSats({
        lockingBytecode: stateLock,
        token: {
          category: stateCategory,
          amount: 0n,
          nft: {
            capability: 'mutable',
            commitment: Buffer.alloc(128),
          },
        },
      });
      if (derivedStateBase === stateBaseValueSats) {
        stateBaseConverged = true;
        break;
      }
      stateBaseValueSats = derivedStateBase;
    }
    if (!stateBaseConverged) {
      fail(
        'PF10_BUILD_DUST_BASE_DID_NOT_CONVERGE',
        'PF10 state base did not reach the exact dust-derived fixed point',
      );
    }
    const stateUnlock = Buffer.from(
      buildDirectV2StateTrampolineUnlock(helper),
    );
    const proofArtifactHashes = Object.freeze(Object.fromEntries(
      PROOF_ARTIFACT_NAMES.map((name) => [
        name,
        verifiedArtifacts[name].sha256,
      ]),
    ));
    const runtimeMaterialInput = {
      schema: runtimeMaterialSchema,
      eligibility,
      profileId,
      instanceId,
      topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
      verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
      proofArtifactHashes,
      verificationKeyBytes,
      executorBody,
      exactMsmRedeems: exactPrograms.map((program) => program.redeem),
      fixedCarrierPads,
      fusedRedeem,
      terminalRedeem,
      stateUnlockingBytecode: stateUnlock,
      bindingRedeemBytecode: bindingRedeem,
      bindingLockingBytecode: bindingLock,
      verifierLockingBytecodes: verifierLocks,
    };
    const runtimeMaterial = validateRuntimeMaterial(runtimeMaterialInput);
    const parsedLibauthEvidence = verifiedLibauthEvidence === undefined
      ? undefined
      : validateDirectV2Pf10LibauthEvidence({
        bytes: verifiedLibauthEvidence.data,
        expectedTerminalProgramBytes: Object.freeze({
          raw: terminal.raw.length,
          redeem: terminal.redeem.length,
        }),
        profileId,
        instanceId,
        proofArtifactHashes,
        runtimeMaterialSha256: runtimeMaterial.materialSha256,
      });
    return Object.freeze({
      schema: runtimeBuildSchema,
      eligibility,
      profileId,
      instanceId,
      topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
      verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
      denominationSats: DENOMINATION_SATS.toString(),
      baseValues: Object.freeze({
        verifierSats: Object.freeze(
          verifierBaseValues.map((value) => value.toString()),
        ),
        bindingSats: bindingBaseValueSats.toString(),
        stateSats: stateBaseValueSats.toString(),
        minimumChangeSats: MINIMUM_CHANGE_SATS.toString(),
      }),
      proofArtifacts: Object.freeze(Object.fromEntries(
        PROOF_ARTIFACT_NAMES.map((name) => [
          name,
          Object.freeze({
            path: verifiedArtifacts[name].path,
            bytes: verifiedArtifacts[name].bytes,
            sha256: verifiedArtifacts[name].sha256,
          }),
        ]),
      )),
      ...(includeLibauthEvidence ? {
        libauthEvidence: verifiedLibauthEvidence === undefined
          ? undefined
          : Object.freeze({
            bytes: verifiedLibauthEvidence.bytes,
            data: Buffer.from(verifiedLibauthEvidence.data),
            path: verifiedLibauthEvidence.path,
            schema: parsedLibauthEvidence.schema,
            sha256: verifiedLibauthEvidence.sha256,
          }),
      } : {}),
      runtimeMaterial,
      runtimeMaterialInput: Object.freeze(runtimeMaterialInput),
      fixedTables: Object.freeze({
        remoteBlobBytes: fixedRemoteBlob.length,
        remoteBlobSha256: sha256(fixedRemoteBlob),
        carrierPadsSha256: Object.freeze(fixedCarrierPads.map(sha256)),
        roleTableHash256: Object.freeze(
          fixedTemplate.roles.map((entry) => entry.tableHash256),
        ),
        terminalTableHash256: fixedTemplate.terminal.tableHash256,
      }),
      layout: Object.freeze({
        exactPrefixBytes,
        exactPaddingPayloadOffset,
        fusedStatePayloadOffset,
        fusedResiduePayloadOffset,
        fragmentOffsets: Object.freeze(fragmentOffsets),
        fragmentLengths: Object.freeze(
          fragments.map((fragment) => fragment.length),
        ),
      }),
      programs: Object.freeze({
        executor,
        exactMsm: Object.freeze(exactPrograms),
        exactFinal,
        miller,
        fused: Object.freeze({
          redeem: fusedRedeem,
          lock: fusedLock,
          hashes: Object.freeze({
            redeem: sha256(fusedRedeem),
            lock: sha256(fusedLock),
          }),
        }),
        terminal,
      }),
      structural: Object.freeze({
        bindingRedeem,
        bindingLock,
        stateHelper: helper,
        stateUnlock,
        stateLock,
        verifierLocks,
      }),
      toolchain: Object.freeze({
        compiler: Object.freeze({
          name: 'cashc-resched',
          optimizeFor: 'opcost',
          rescheduleStacks: true,
        }),
        optimizer: Object.freeze({
          driver: repositoryRelative(
            root,
            path.join(optimizerRoot, 'optimize.mjs'),
          ),
          canonicalizer: repositoryRelative(
            root,
            path.join(optimizerRoot, 'minpush_canon.mjs'),
          ),
        }),
      }),
    });
  } finally {
    await cleanupPrivateTemporaryDirectory(workDirectory);
  }
}

/** Compile the descriptor-compatible development PF10 runtime. */
export async function buildDirectV2Pf10DevelopmentRuntime(value = {}) {
  return buildDirectV2Pf10Runtime({
    ...value,
    runtimeMaterialSchema: DIRECT_V2_PF10_RUNTIME_SCHEMA,
    eligibility: 'development-only',
    runtimeBuildSchema: DIRECT_V2_PF10_DEVELOPMENT_RUNTIME_BUILD_SCHEMA,
    validateRuntimeMaterial: validateDirectV2Pf10RuntimeMaterial,
    includeLibauthEvidence: true,
  });
}

/**
 * Compile beta-only PF10 runtime material. This lane intentionally accepts no
 * Libauth evidence and emits material rejected by the normal descriptor/final
 * runtime validator.
 */
export async function buildDirectV2Pf10BetaRuntime(value = {}) {
  recordV2BetaRuntimeWork({ type: 'cold-runtime-build' });
  if (value.artifactRoot === undefined) {
    fail(
      'PF10_BUILD_PATH_INVALID',
      'beta PF10 runtime requires an explicit artifactRoot',
    );
  }
  if (value.libauthEvidence !== undefined) {
    fail(
      'PF10_BETA_LIBAUTH_FORBIDDEN',
      'beta PF10 runtime does not accept Libauth evidence',
    );
  }
  return buildDirectV2Pf10Runtime({
    ...value,
    runtimeMaterialSchema: DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA,
    eligibility: DIRECT_V2_PF10_BETA_ELIGIBILITY,
    runtimeBuildSchema: DIRECT_V2_PF10_BETA_RUNTIME_BUILD_SCHEMA,
    validateRuntimeMaterial: validateDirectV2Pf10BetaRuntimeMaterial,
    includeLibauthEvidence: false,
    requirePrivateArtifactRoot: true,
  });
}
