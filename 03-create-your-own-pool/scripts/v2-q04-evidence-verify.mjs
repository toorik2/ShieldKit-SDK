#!/usr/bin/env node
import { createHash } from 'node:crypto';
import {
  chmodSync,
  createReadStream,
  mkdtempSync,
  rmSync,
} from 'node:fs';
import { lstat, readFile, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { parseStrictJson } from '../packages/profile/load.mjs';
import {
  createIndependentIndexedNullifierTree,
} from '../packages/pool/v2/qualification/independent-indexed-nullifier-tree.mjs';
import {
  createIndependentPoseidonOracle,
} from '../packages/pool/v2/qualification/independent-poseidon-oracle.mjs';
import {
  openQ04PersistentNullifierStore,
} from '../packages/pool/v2/qualification/persistent-nullifier-store.mjs';
import {
  Q04_DEPTH4_SYMBOLIC_CERTIFICATE_SCHEMA,
  verifyDepth4SymbolicCertificate,
} from '../packages/pool/v2/qualification/depth4-symbolic-certificate.mjs';
import {
  Q04_CHECKPOINT_PROBE_CASES,
  Q04_CHECKPOINT_PROBE_COUNT,
  q04CheckpointProbeCaseDigest,
  q04CheckpointProbeResultDigest,
  runQ04CheckpointProbes,
} from '../packages/pool/v2/qualification/q04-checkpoint-probes.mjs';

export const Q04_EVIDENCE_SCHEMA = 'shieldkit-v2-direct/q04-nullifier-stress/v3';
export const Q04_RESULT_SCHEMA = 'shieldkit-v2-direct/q04-evidence-verification-result/v3';
export const Q04_TRANSITION_SCHEMA = 'shieldkit-v2-direct/q04-transition-measurement/v1';
export const Q04_RUST_KAT_SCHEMA = 'shieldkit-v2-direct-q04-rust-cross-oracle-v1';
export const Q04_HISTORY_RESULT_SCHEMA = 'shieldkit-v2-direct/q04-history-result/v3';
export const Q04_DEPTH4_SCHEMA = 'shieldkit-v2-direct/q04-depth4-production-state-space/v3';
export const Q04_DEPTH4_SCOPE =
  'all-2^16-occupancy-masks-plus-911-shared-sqlite-control-skeletons-plus-paired-numeric-embeddings-plus-896-nonlocal-rank-permutations-plus-874-depth3-rank-states-plus-shared-kernel-symbolic-templates-nonformal';
export const Q04_DEPTH4_STATUS =
  'shared-sqlite-bounded-differential-and-symbolic-template-evidence';
export const Q04_DEPTH4_CHECKER_RESULT_SCHEMA =
  'shieldkit-v2-direct/q04-depth4-rust-certificate-check/v2';
export const Q04_CAMPAIGN_PROCESSES_SCHEMA =
  'shieldkit-v2-direct/q04-campaign-processes/v3';
export const Q04_FR_MODULUS_HEX = '30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001';
export const Q04_POSEIDON_PROFILE = 'shieldkit-pool-action-v2-direct-poseidon-v1';
export const Q04_NULLIFIER_DOMAINS = Object.freeze({
  leaf: '21e0792dda012608a23ccef2acfb69f6a5d8ea940de6399bdd1094d68e4ffce2',
  empty: '2633488611f1ffb2708b6ebb8994794c45c27f56b5d0d87d67a841123e3f0acb',
  node: '241df03119348914e68c8b8c34a7c35acea16196c2d1c23223f4a191007175a4',
});
export const Q04_SEED_DERIVATION = 'SHA256(ASCII(shieldkit-v2-q04-nullifier-history-v1) || history_u32be)';
export const Q04_KEY_DERIVATION = 'SHA256(ASCII(shieldkit-v2-q04-nullifier-key-v1) || seed32 || ordinal_u64be || attempt_u32be), rejection-sampled into Fr, deduplicated, and excluding reserved edge values';
export const Q04_FIXED_SEEDS = Object.freeze([
  '8e5d9a4520a6598c2afe5904e3d0db5a50f3d110eff811319b8690c38dac2a99',
  'a9d9fd22e18d7b38004a8c470055439a1a9827eca3ac62780c4966b045085b28',
  '7297823284ef95acfdf81160f470c017f36279a27c61343fef7fdbb375f0d594',
  '2e6f78cd79e340a1eda10939dc15977b103760bed09dbca4baddcd994a757a6f',
]);
export const Q04_EDGE_SCHEDULE = Object.freeze([
  Object.freeze({ history: 0, zeroOrdinal: 1, frMinusOneOrdinal: 2 }),
  Object.freeze({ history: 1, zeroOrdinal: 1000, frMinusOneOrdinal: 1 }),
  Object.freeze({ history: 2, zeroOrdinal: 1000, frMinusOneOrdinal: 1001 }),
  Object.freeze({ history: 3, zeroOrdinal: 24999, frMinusOneOrdinal: 25000 }),
]);
export const Q04_REQUIRED_PROBES = Object.freeze(
  Q04_CHECKPOINT_PROBE_CASES.map(({ kind }) => kind),
);
if (Q04_REQUIRED_PROBES.length !== Q04_CHECKPOINT_PROBE_COUNT) {
  throw new Error('Q-04 checkpoint probe definition count differs');
}

const HISTORY_COUNT = 4;
const ENTRIES_PER_HISTORY = 25_000;
const TOTAL_ENTRIES = HISTORY_COUNT * ENTRIES_PER_HISTORY;
const CHECKPOINT_INTERVAL = 1000;
const CHECKPOINTS_PER_HISTORY = ENTRIES_PER_HISTORY / CHECKPOINT_INTERVAL;
const TOTAL_CHECKPOINTS = HISTORY_COUNT * CHECKPOINTS_PER_HISTORY;
const TOTAL_PROBES = TOTAL_CHECKPOINTS * Q04_REQUIRED_PROBES.length;
const MAX_EVIDENCE_BYTES = 16 * 1024 * 1024;
const MAX_REFERENCE_BYTES = 512 * 1024 * 1024;
const MAX_NDJSON_LINE_BYTES = 2 * 1024 * 1024;
// Four serial phase measurements are independently rounded upward to integer
// milliseconds by the campaign. Their combined rounding excess over the
// outer monotonic clock is strictly below four milliseconds.
const Q04_RUNTIME_ROUNDING_SLACK_MS = 4;
const HEX_64 = /^[0-9a-f]{64}$/;
const HEX_40 = /^[0-9a-f]{40}$/;
const ERROR_CODE = /^[A-Z][A-Z0-9_]{1,63}$/;
const NODE_VERSION = /^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/;
const RFC3339_MILLISECONDS = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;
const FR_MODULUS = BigInt(`0x${Q04_FR_MODULUS_HEX}`);
const FR_MINUS_ONE = FR_MODULUS - 1n;
const SOURCE_SET_DOMAIN = 'shieldkit-v2-q04-source-set-v3';
const HISTORY_SET_DOMAIN = 'shieldkit-v2-q04-history-transition-set-v3';
const KEY_DOMAIN = 'shieldkit-v2-q04-nullifier-key-v1';
const INPUT_TRANSCRIPT_DOMAIN = 'ShieldKit/PoolActionV2Direct/Q04/input-transcript/v1\0';
const PATH_DIGEST_DOMAIN = 'ShieldKit/PoolActionV2Direct/Q04/path-digest/v1\0';
const STORE_INITIAL_DOMAIN = 'ShieldKit/PoolActionV2Direct/Q04/persistent-store/v1\0';
const STORE_TRANSITION_DOMAIN = 'ShieldKit/PoolActionV2Direct/Q04/persistent-transition/v1\0';
const EXPECTED_CHECKPOINTS = Object.freeze(
  Array.from({ length: CHECKPOINTS_PER_HISTORY }, (_, index) => (index + 1) * CHECKPOINT_INTERVAL),
);
const EXECUTION_REPOSITORY_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
);

export const Q04_CAMPAIGN_DEFINITION = Object.freeze({
  historyCount: HISTORY_COUNT,
  entriesPerHistory: ENTRIES_PER_HISTORY,
  checkpointInterval: CHECKPOINT_INTERVAL,
  checkpointsPerHistory: CHECKPOINTS_PER_HISTORY,
  totalEntries: TOTAL_ENTRIES,
  treeDepth: 32,
  totalProbes: TOTAL_PROBES,
});

export const Q04_FIXED_OPERATION_COUNTS = Object.freeze({
  acceptedInsertions: 100_000,
  predecessorMembershipChecks: 100_000,
  emptyAppendNonMembershipChecks: 100_000,
  postInsertionMembershipChecks: 100_000,
  indexedLeafWrites: 200_000,
  productionLeafHashCallsPerTransition: 3,
  productionPredecessorValidationLeafHashCallsPerTransition: 1,
  productionMutationLeafHashCallsPerTransition: 2,
  productionMutationNodeHashCallsPerTransition: 128,
  productionLogicalPathSiblingLookupsPerTransition: 64,
  productionPathOverrideHitsPerTransition: 1,
  productionPathAdapterNodeReadsPerTransition: 63,
  productionRootAdapterNodeReadsPerTransition: 1,
  productionTotalAdapterNodeReadsPerTransition: 64,
  productionLeafReadsPerTransition: 2,
  productionOrderLookupsPerTransition: 2,
  productionPostMembershipNodeHashCallsPerTransition: 32,
  productionPostMembershipNodeReadsPerTransition: 32,
  insertionAndPostMembershipNodeHashCallsPerTransition: 160,
  primaryOracleLeafHashCallsPerTransition: 2,
  primaryOracleNodeHashCallsPerTransition: 160,
  primaryOracleMembershipPathComputationsPerTransition: 3,
  primaryOracleStateUpdatePathsPerTransition: 2,
  productionLeafHashCalls: 300_000,
  productionPredecessorValidationLeafHashCalls: 100_000,
  productionMutationLeafHashCalls: 200_000,
  productionMutationNodeHashCalls: 12_800_000,
  productionLogicalPathSiblingLookups: 6_400_000,
  productionPathOverrideHits: 100_000,
  productionPathAdapterNodeReads: 6_300_000,
  productionRootAdapterNodeReads: 100_000,
  productionTotalAdapterNodeReads: 6_400_000,
  productionLeafReads: 200_000,
  productionOrderLookups: 200_000,
  productionPostMembershipNodeHashCalls: 3_200_000,
  productionPostMembershipNodeReads: 3_200_000,
  insertionAndPostMembershipNodeHashCalls: 16_000_000,
  primaryOracleLeafHashCalls: 200_000,
  primaryOracleNodeHashCalls: 16_000_000,
  primaryOracleMembershipPathComputations: 300_000,
  primaryOracleStateUpdatePaths: 200_000,
  checkpointWriterReopenCycles: 100,
  writerProcessCloses: 100,
  reopenWorkerProcessCloses: 100,
  adversarialProbes: 500,
  rustKatTransitionComparisons: 0,
});

export const Q04_SOURCE_DEFINITIONS = Object.freeze({
  productionCore: Object.freeze([
    Object.freeze({
      role: 'qualification-store',
      originPath: '03-create-your-own-pool/packages/pool/v2/qualification/persistent-nullifier-store.mjs',
    }),
    Object.freeze({
      role: 'shared-production-insertion-core',
      originPath: '03-create-your-own-pool/packages/pool/v2/persistent-indexed-nullifier.mjs',
    }),
    Object.freeze({
      role: 'shared-production-sqlite-adapter',
      originPath: '03-create-your-own-pool/packages/pool/v2/persistent-indexed-nullifier-sqlite.mjs',
    }),
    Object.freeze({
      role: 'production-poseidon',
      originPath: '03-create-your-own-pool/packages/action/v2/poseidon.mjs',
    }),
    Object.freeze({
      role: 'production-domains',
      originPath: '03-create-your-own-pool/packages/action/v2/domains.mjs',
    }),
  ]),
  primaryJsOracle: Object.freeze([
    Object.freeze({
      role: 'independent-bigint-poseidon',
      originPath: '03-create-your-own-pool/packages/pool/v2/qualification/independent-poseidon-oracle.mjs',
    }),
    Object.freeze({
      role: 'independent-treap-tree',
      originPath: '03-create-your-own-pool/packages/pool/v2/qualification/independent-indexed-nullifier-tree.mjs',
    }),
    Object.freeze({
      role: 'circomlib-parameter-source',
      originPath: 'node_modules/circomlib/circuits/poseidon_constants.circom',
    }),
  ]),
  rustKat: Object.freeze([
    Object.freeze({
      role: 'rust-kat-binary-source',
      originPath: '03-create-your-own-pool/crates/shieldkit-v2-recovery/src/bin/q04-poseidon-oracle.rs',
    }),
    Object.freeze({
      role: 'codec-modulus-source',
      originPath: '03-create-your-own-pool/crates/shieldkit-v2-codec/src/lib.rs',
    }),
    Object.freeze({
      role: 'compiled-codec-module',
      originPath: '03-create-your-own-pool/crates/shieldkit-v2-codec/src/notes.rs',
    }),
    Object.freeze({
      role: 'codec-manifest',
      originPath: '03-create-your-own-pool/crates/shieldkit-v2-codec/Cargo.toml',
    }),
  ]),
  depth4Checker: Object.freeze([
    Object.freeze({
      role: 'rust-free-term-certificate-checker',
      originPath:
        '03-create-your-own-pool/crates/shieldkit-v2-q04-certificate/src/main.rs',
    }),
    Object.freeze({
      role: 'rust-certificate-checker-manifest',
      originPath:
        '03-create-your-own-pool/crates/shieldkit-v2-q04-certificate/Cargo.toml',
    }),
    Object.freeze({
      role: 'rust-certificate-checker-lockfile',
      originPath:
        '03-create-your-own-pool/crates/shieldkit-v2-q04-certificate/Cargo.lock',
    }),
    Object.freeze({
      role: 'rust-certificate-checker-toolchain',
      originPath: '03-create-your-own-pool/rust-toolchain.toml',
    }),
  ]),
  campaign: Object.freeze([
    Object.freeze({
      role: 'history-schedule',
      originPath: '03-create-your-own-pool/packages/pool/v2/qualification/q04-schedule.mjs',
    }),
    Object.freeze({
      role: 'history-runner',
      originPath: '03-create-your-own-pool/scripts/v2-q04-history-runner.mjs',
    }),
    Object.freeze({
      role: 'campaign-driver',
      originPath: '03-create-your-own-pool/scripts/v2-q04-campaign.mjs',
    }),
    Object.freeze({
      role: 'segment-worker',
      originPath: '03-create-your-own-pool/scripts/v2-q04-segment-worker.mjs',
    }),
    Object.freeze({
      role: 'canonical-checkpoint-probes',
      originPath:
        '03-create-your-own-pool/packages/pool/v2/qualification/q04-checkpoint-probes.mjs',
    }),
    Object.freeze({
      role: 'reopen-worker',
      originPath: '03-create-your-own-pool/scripts/v2-q04-reopen-worker.mjs',
    }),
    Object.freeze({
      role: 'strict-json-parser',
      originPath: '03-create-your-own-pool/packages/profile/load.mjs',
    }),
    Object.freeze({
      role: 'evidence-verifier',
      originPath: '03-create-your-own-pool/scripts/v2-q04-evidence-verify.mjs',
    }),
  ]),
  depth4: Object.freeze([
    Object.freeze({
      role: 'depth4-production-state-space-runner',
      originPath:
        '03-create-your-own-pool/packages/pool/v2/qualification/depth4-production-state-space.mjs',
    }),
    Object.freeze({
      role: 'generic-action-indexed-nullifier-tree-model',
      originPath:
        '03-create-your-own-pool/packages/action/v2/indexed-nullifier-tree.mjs',
    }),
    Object.freeze({
      role: 'shared-kernel-symbolic-template-certificate',
      originPath:
        '03-create-your-own-pool/packages/pool/v2/qualification/depth4-symbolic-certificate.mjs',
    }),
  ]),
});

const sourceDefinition = (role, originPath) => Object.freeze({ role, originPath });
const RUST_MANIFEST_DEFINITION = sourceDefinition(
  'rust-kat-manifest',
  '03-create-your-own-pool/crates/shieldkit-v2-recovery/Cargo.toml',
);
const RUST_LOCK_DEFINITION = sourceDefinition(
  'rust-kat-lockfile',
  '03-create-your-own-pool/crates/shieldkit-v2-recovery/Cargo.lock',
);
const RUST_TOOLCHAIN_DEFINITION = sourceDefinition(
  'rust-toolchain',
  '03-create-your-own-pool/rust-toolchain.toml',
);
const NODE_LOCK_DEFINITION = sourceDefinition('node-lockfile', 'package-lock.json');

export const Q04_RUST_DOMAINS = Object.freeze([
  Object.freeze({ label: 'NOTE_LEAF', counter: 1, hex: '0765f493bd374585f9ab5c4a1efe55f4d400a1bc1c876506ef8c7644145f370a' }),
  Object.freeze({ label: 'NOTE_TREE_EMPTY', counter: 9, hex: '28fda61e6a38f74d91d7d8c4e279ba8e7b437a707948b9476bcfd650f5a60dad' }),
  Object.freeze({ label: 'NOTE_TREE_NODE', counter: 9, hex: '06a305c7bcf59e063a048eb6d2d870018d0051268abe747a3ddde39daf1b2153' }),
  Object.freeze({ label: 'NULLIFIER_TREE_LEAF', counter: 5, hex: '21e0792dda012608a23ccef2acfb69f6a5d8ea940de6399bdd1094d68e4ffce2' }),
  Object.freeze({ label: 'NULLIFIER_TREE_EMPTY', counter: 3, hex: '2633488611f1ffb2708b6ebb8994794c45c27f56b5d0d87d67a841123e3f0acb' }),
  Object.freeze({ label: 'NULLIFIER_TREE_NODE', counter: 0, hex: '241df03119348914e68c8b8c34a7c35acea16196c2d1c23223f4a191007175a4' }),
]);

export const Q04_RUST_KATS = Object.freeze([
  Object.freeze({
    name: 'empty_note',
    inputs: Object.freeze(['28fda61e6a38f74d91d7d8c4e279ba8e7b437a707948b9476bcfd650f5a60dad', '0']),
    output: '24fda6f2c3c9b7492e55e47bc6adc8041391570282c3c6cf97329abd31128081',
  }),
  Object.freeze({
    name: 'note_parent',
    inputs: Object.freeze([
      '06a305c7bcf59e063a048eb6d2d870018d0051268abe747a3ddde39daf1b2153',
      '24fda6f2c3c9b7492e55e47bc6adc8041391570282c3c6cf97329abd31128081',
      '24fda6f2c3c9b7492e55e47bc6adc8041391570282c3c6cf97329abd31128081',
    ]),
    output: '265399a22fcc1a8f382ddeec66cc3b4fee4e52a4352d5209fcad526fd21e769c',
  }),
  Object.freeze({
    name: 'empty_nullifier',
    inputs: Object.freeze(['2633488611f1ffb2708b6ebb8994794c45c27f56b5d0d87d67a841123e3f0acb', '0']),
    output: '18df533689e5101f3e88e6e91339f278f68a84c86f22997b1bb28be7dec598a6',
  }),
  Object.freeze({
    name: 'minimum_sentinel',
    inputs: Object.freeze([
      '21e0792dda012608a23ccef2acfb69f6a5d8ea940de6399bdd1094d68e4ffce2',
      '1',
      '0',
      '0',
      '1',
      '0',
    ]),
    output: '04b96bcec386361928f02ccd62ed02446db3d900d3ce3083f6dbd5007b8d20e5',
  }),
  Object.freeze({
    name: 'nullifier_parent',
    inputs: Object.freeze([
      '241df03119348914e68c8b8c34a7c35acea16196c2d1c23223f4a191007175a4',
      '04b96bcec386361928f02ccd62ed02446db3d900d3ce3083f6dbd5007b8d20e5',
      '18df533689e5101f3e88e6e91339f278f68a84c86f22997b1bb28be7dec598a6',
    ]),
    output: '1fd573ef8ff8f6825abec3fe3b725941e4035344df59e31ee23a9766de8a9221',
  }),
  Object.freeze({
    name: 'output_note_leaf',
    inputs: Object.freeze([
      '0765f493bd374585f9ab5c4a1efe55f4d400a1bc1c876506ef8c7644145f370a',
      '7',
      '11',
    ]),
    output: '0cda43a183b48956f4e64cb87efdcd9a716e8ad1354640895240cc3f2ffb6f09',
  }),
  Object.freeze({
    name: 'p2_zero_fr_minus_1',
    inputs: Object.freeze(['0', '30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000']),
    output: '28b2de3348b15076cbe645321cd2abbd0d2812669574ed4d5f978fe4e7de98bc',
  }),
  Object.freeze({
    name: 'p3_fr_minus_1_zero_7',
    inputs: Object.freeze([
      '30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000',
      '0',
      '7',
    ]),
    output: '23273fd701c327772475309dbcb4c09d0e078b2d9254e3de9d182900fd47944a',
  }),
  Object.freeze({
    name: 'p6_1_through_6',
    inputs: Object.freeze(['1', '2', '3', '4', '5', '6']),
    output: '2d1a03850084442813c8ebf094dea47538490a68b05f2239134a4cca2f6302e1',
  }),
  Object.freeze({
    name: 'p6_all_fr_minus_1',
    inputs: Object.freeze(Array(6).fill('30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000')),
    output: '1864ca75de675b4d3295bd19b556bf2d3f46029f09a0fc5438ecb3d857ebc3e5',
  }),
]);

const encodeFr = (value) => value.toString(16).padStart(64, '0');
const freeze = (value) => Object.freeze(value);

export class V2Q04EvidenceVerificationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2Q04EvidenceVerificationError';
  }
}

const fail = (message) => { throw new V2Q04EvidenceVerificationError(message); };

function object(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  return value;
}

function exactKeys(value, label, keys) {
  object(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} has missing or unknown properties`);
  }
}

function array(value, label, length) {
  if (!Array.isArray(value)) fail(`${label} must be an array`);
  if (length !== undefined && value.length !== length) fail(`${label} must contain exactly ${length} items`);
  return value;
}

function string(value, label, { nonempty = true, max = 4096 } = {}) {
  if (typeof value !== 'string' || (nonempty && value.length === 0)) fail(`${label} must be a ${nonempty ? 'nonempty ' : ''}string`);
  if (value.length > max || /[\u0000-\u001f\u007f]/.test(value)) fail(`${label} contains invalid characters`);
  return value;
}

function exact(value, expected, label) {
  if (value !== expected) fail(`${label} must be ${JSON.stringify(expected)}`);
}

function safeInteger(value, label, { minimum = 0 } = {}) {
  if (!Number.isSafeInteger(value) || value < minimum) fail(`${label} must be a safe integer >= ${minimum}`);
  return value;
}

function positiveInteger(value, label) {
  return safeInteger(value, label, { minimum: 1 });
}

function nonnegativeNumber(value, label) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) fail(`${label} must be a finite nonnegative number`);
  return value;
}

function sha256(value, label) {
  string(value, label);
  if (!HEX_64.test(value)) fail(`${label} must be a lowercase SHA-256 digest`);
  return value;
}

function frElement(value, label) {
  string(value, label);
  if (!HEX_64.test(value) || BigInt(`0x${value}`) >= FR_MODULUS) {
    fail(`${label} must be a canonical 32-byte big-endian BN254 Fr element`);
  }
  return value;
}

function timestamp(value, label) {
  string(value, label);
  const parsed = Date.parse(value);
  if (!RFC3339_MILLISECONDS.test(value) || Number.isNaN(parsed) || new Date(parsed).toISOString() !== value) {
    fail(`${label} must be a canonical UTC RFC3339 timestamp with milliseconds`);
  }
  return value;
}

function safeRelativePosixPath(value, label, { allowDot = false } = {}) {
  string(value, label, { max: 1024 });
  if (allowDot && value === '.') return value;
  if (path.posix.isAbsolute(value) || value.includes('\\') || !/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(value)) {
    fail(`${label} must be a safe relative POSIX path`);
  }
  const parts = value.split('/');
  if (parts.some((part) => part.length === 0 || part === '.' || part === '..') || path.posix.normalize(value) !== value) {
    fail(`${label} contains path traversal or a noncanonical segment`);
  }
  return value;
}

function parameterSourcePath(value, label) {
  string(value, label, { max: 4096 });
  const expectedSuffix = Q04_SOURCE_DEFINITIONS.primaryJsOracle[2].originPath;
  if (
    value.includes('\\')
    || path.posix.normalize(value) !== value
    || (
      value !== expectedSuffix
      && !value.endsWith(`/${expectedSuffix}`)
    )
  ) fail(`${label} must identify the canonical hashed circomlib parameter source`);
  return value;
}

function rejectForbiddenClaims(value, label = 'evidence') {
  if (typeof value === 'string') {
    if (/v2directstore/iu.test(value)) {
      fail(`${label} contains the forbidden direct-V2DirectStore claim`);
    }
    if (/rust.{0,48}transition.{0,48}oracle/iu.test(value)) {
      fail(`${label} contains the forbidden Rust transition-oracle claim`);
    }
    if (/node[-_\s]*writes?/iu.test(value)) {
      fail(`${label} contains forbidden node-write accounting`);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => rejectForbiddenClaims(item, `${label}[${index}]`));
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      if (/node[-_\s]*writes?/iu.test(key)) fail(`${label}.${key} uses forbidden node-write accounting`);
      rejectForbiddenClaims(item, `${label}.${key}`);
    }
  }
}

function fileReference(value, label, references, kind = 'file') {
  exactKeys(value, label, ['path', 'bytes', 'sha256']);
  const reference = Object.freeze({
    path: safeRelativePosixPath(value.path, `${label}.path`),
    bytes: positiveInteger(value.bytes, `${label}.bytes`),
    sha256: sha256(value.sha256, `${label}.sha256`),
    kind,
    label,
  });
  references.push(reference);
  return reference;
}

function sourceReference(value, label, definition, lane, references, sourceMaterials) {
  exactKeys(value, label, ['role', 'originPath', 'artifact']);
  exact(value.role, definition.role, `${label}.role`);
  exact(value.originPath, definition.originPath, `${label}.originPath`);
  safeRelativePosixPath(value.originPath, `${label}.originPath`);
  const artifact = fileReference(value.artifact, `${label}.artifact`, references);
  sourceMaterials.push(Object.freeze({
    lane,
    role: value.role,
    originPath: value.originPath,
    artifactPath: artifact.path,
    bytes: artifact.bytes,
    sha256: artifact.sha256,
  }));
  return Object.freeze({ role: value.role, originPath: value.originPath, artifact });
}

function sourceList(value, label, definitions, lane, references, sourceMaterials) {
  array(value, label, definitions.length);
  return value.map((entry, index) => sourceReference(
    entry,
    `${label}[${index}]`,
    definitions[index],
    lane,
    references,
    sourceMaterials,
  ));
}

function collectSourceMaterials(evidence) {
  const entries = [];
  const add = (lane, source) => entries.push({
    lane,
    role: source.role,
    originPath: source.originPath,
    bytes: source.artifact.bytes,
    sha256: source.artifact.sha256,
  });
  evidence.implementations.productionCore.sources.forEach((source) => add('productionCore', source));
  evidence.implementations.primaryJsOracle.sources.forEach((source) => add('primaryJsOracle', source));
  evidence.implementations.rustKat.sources.forEach((source) => add('rustKat', source));
  for (const field of ['cargoManifest', 'cargoLock', 'rustToolchain']) add('rustKat', evidence.implementations.rustKat[field]);
  evidence.implementations.depth4Checker.sources.forEach((source) =>
    add('depth4Checker', source)
  );
  evidence.provenance.campaignSources.forEach((source) => add('campaign', source));
  add('campaign', evidence.provenance.nodePackageLock);
  evidence.depth4.sources.forEach((source) => add('depth4', source));
  return entries;
}

export function deriveQ04SourceSetSha256(evidence) {
  const rows = collectSourceMaterials(evidence)
    .map((item) => [item.lane, item.role, item.originPath, String(item.bytes), item.sha256].join('\0'))
    .sort();
  return createHash('sha256')
    .update(`${SOURCE_SET_DOMAIN}\0${rows.join('\n')}`, 'utf8')
    .digest('hex');
}

export function deriveQ04HistoryTransitionSetSha256(histories) {
  const rows = histories.map((history) => {
    const artifact = history.transitionArtifact;
    return [
      String(history.index),
      artifact.path,
      String(artifact.bytes),
      artifact.sha256,
    ].join('\0');
  });
  return createHash('sha256')
    .update(`${HISTORY_SET_DOMAIN}\0${rows.join('\n')}`, 'utf8')
    .digest('hex');
}

function validateSubject(subject) {
  exactKeys(subject, 'subject', [
    'repository',
    'gitCommit',
    'gitTree',
    'workingTreeClean',
    'poseidonProfile',
    'treeDepth',
    'frModulus',
    'nullifierDomains',
    'sourceSetSha256',
  ]);
  string(subject.repository, 'subject.repository', { max: 256 });
  if (!HEX_40.test(subject.gitCommit)) fail('subject.gitCommit must be a lowercase 40-hex commit ID');
  if (!HEX_40.test(subject.gitTree)) fail('subject.gitTree must be a lowercase 40-hex tree ID');
  exact(subject.workingTreeClean, true, 'subject.workingTreeClean');
  exact(subject.poseidonProfile, Q04_POSEIDON_PROFILE, 'subject.poseidonProfile');
  exact(subject.treeDepth, 32, 'subject.treeDepth');
  exact(subject.frModulus, Q04_FR_MODULUS_HEX, 'subject.frModulus');
  exactKeys(subject.nullifierDomains, 'subject.nullifierDomains', ['leaf', 'empty', 'node']);
  for (const [field, expected] of Object.entries(Q04_NULLIFIER_DOMAINS)) {
    exact(subject.nullifierDomains[field], expected, `subject.nullifierDomains.${field}`);
  }
  sha256(subject.sourceSetSha256, 'subject.sourceSetSha256');
}

function validateDefinition(definition) {
  exactKeys(definition, 'definition', [
    'historyCount',
    'entriesPerHistory',
    'totalEntries',
    'checkpointInterval',
    'checkpointsPerHistory',
    'seedDerivation',
    'keyDerivation',
    'seeds',
    'edgeSchedule',
    'requiredProbeKinds',
  ]);
  exact(definition.historyCount, HISTORY_COUNT, 'definition.historyCount');
  exact(definition.entriesPerHistory, ENTRIES_PER_HISTORY, 'definition.entriesPerHistory');
  exact(definition.totalEntries, TOTAL_ENTRIES, 'definition.totalEntries');
  exact(definition.checkpointInterval, CHECKPOINT_INTERVAL, 'definition.checkpointInterval');
  exact(definition.checkpointsPerHistory, CHECKPOINTS_PER_HISTORY, 'definition.checkpointsPerHistory');
  exact(definition.seedDerivation, Q04_SEED_DERIVATION, 'definition.seedDerivation');
  exact(definition.keyDerivation, Q04_KEY_DERIVATION, 'definition.keyDerivation');
  array(definition.seeds, 'definition.seeds', HISTORY_COUNT);
  definition.seeds.forEach((seed, index) => exact(seed, Q04_FIXED_SEEDS[index], `definition.seeds[${index}]`));
  array(definition.edgeSchedule, 'definition.edgeSchedule', HISTORY_COUNT);
  definition.edgeSchedule.forEach((item, index) => {
    exactKeys(item, `definition.edgeSchedule[${index}]`, ['history', 'zeroOrdinal', 'frMinusOneOrdinal']);
    for (const field of ['history', 'zeroOrdinal', 'frMinusOneOrdinal']) {
      exact(item[field], Q04_EDGE_SCHEDULE[index][field], `definition.edgeSchedule[${index}].${field}`);
    }
  });
  array(definition.requiredProbeKinds, 'definition.requiredProbeKinds', Q04_REQUIRED_PROBES.length);
  definition.requiredProbeKinds.forEach((kind, index) => exact(kind, Q04_REQUIRED_PROBES[index], `definition.requiredProbeKinds[${index}]`));
}

function validateProductionCore(lane, references, sourceMaterials) {
  exactKeys(lane, 'implementations.productionCore', [
    'lane',
    'entrypoint',
    'sharedCore',
    'directV2DirectStoreExercised',
    'runtime',
    'transitionComparisons',
    'treeDepth',
    'poseidonPackage',
    'nodeVersion',
    'sqliteVersion',
    'sources',
  ]);
  exact(lane.lane, 'per-transition-production-shared-core', 'implementations.productionCore.lane');
  exact(lane.entrypoint, 'Q04PersistentNullifierStore', 'implementations.productionCore.entrypoint');
  exact(lane.sharedCore, 'derivePersistentIndexedNullifierInsertion/applyPersistentIndexedNullifierMutation', 'implementations.productionCore.sharedCore');
  exact(lane.directV2DirectStoreExercised, false, 'implementations.productionCore.directV2DirectStoreExercised');
  exact(lane.runtime, 'node', 'implementations.productionCore.runtime');
  exact(lane.transitionComparisons, TOTAL_ENTRIES, 'implementations.productionCore.transitionComparisons');
  exact(lane.treeDepth, 32, 'implementations.productionCore.treeDepth');
  exact(lane.poseidonPackage, 'poseidon-lite@0.3.0', 'implementations.productionCore.poseidonPackage');
  string(lane.nodeVersion, 'implementations.productionCore.nodeVersion', { max: 128 });
  if (!NODE_VERSION.test(lane.nodeVersion)) fail('implementations.productionCore.nodeVersion is invalid');
  string(lane.sqliteVersion, 'implementations.productionCore.sqliteVersion', { max: 128 });
  sourceList(lane.sources, 'implementations.productionCore.sources', Q04_SOURCE_DEFINITIONS.productionCore, 'productionCore', references, sourceMaterials);
}

function validatePrimaryJsOracle(lane, references, sourceMaterials) {
  exactKeys(lane, 'implementations.primaryJsOracle', [
    'lane',
    'poseidonImplementation',
    'treeImplementation',
    'orderedSet',
    'runtime',
    'transitionComparisons',
    'importsProductionCore',
    'independentPoseidonImplementation',
    'independentTreeImplementation',
    'independentParameterGeneration',
    'treeDepth',
    'frModulus',
    'supportedArities',
    'parameterPackage',
    'parameterSourceSha256',
    'nodeVersion',
    'sources',
  ]);
  exact(lane.lane, 'per-transition-primary-independent-oracle', 'implementations.primaryJsOracle.lane');
  exact(lane.poseidonImplementation, 'independent-bigint-optimized-circomlib-poseidon-oracle-v1', 'implementations.primaryJsOracle.poseidonImplementation');
  exact(lane.treeImplementation, 'independent-treap-sparse-depth32-indexed-nullifier-oracle-v1', 'implementations.primaryJsOracle.treeImplementation');
  exact(lane.orderedSet, 'sha256-priority-treap', 'implementations.primaryJsOracle.orderedSet');
  exact(lane.runtime, 'node', 'implementations.primaryJsOracle.runtime');
  exact(lane.transitionComparisons, TOTAL_ENTRIES, 'implementations.primaryJsOracle.transitionComparisons');
  exact(lane.importsProductionCore, false, 'implementations.primaryJsOracle.importsProductionCore');
  exact(lane.independentPoseidonImplementation, true, 'implementations.primaryJsOracle.independentPoseidonImplementation');
  exact(lane.independentTreeImplementation, true, 'implementations.primaryJsOracle.independentTreeImplementation');
  exact(lane.independentParameterGeneration, false, 'implementations.primaryJsOracle.independentParameterGeneration');
  exact(lane.treeDepth, 32, 'implementations.primaryJsOracle.treeDepth');
  exact(lane.frModulus, Q04_FR_MODULUS_HEX, 'implementations.primaryJsOracle.frModulus');
  array(lane.supportedArities, 'implementations.primaryJsOracle.supportedArities', 3);
  [2, 3, 6].forEach((arity, index) => exact(lane.supportedArities[index], arity, `implementations.primaryJsOracle.supportedArities[${index}]`));
  exact(lane.parameterPackage, 'circomlib@2.0.5', 'implementations.primaryJsOracle.parameterPackage');
  exact(lane.parameterSourceSha256, '94c9e4b5ea891ab4d1ba626f1d719f8c661014d9b628f6096c803f75f39e3eee', 'implementations.primaryJsOracle.parameterSourceSha256');
  string(lane.nodeVersion, 'implementations.primaryJsOracle.nodeVersion', { max: 128 });
  if (!NODE_VERSION.test(lane.nodeVersion)) fail('implementations.primaryJsOracle.nodeVersion is invalid');
  const sources = sourceList(lane.sources, 'implementations.primaryJsOracle.sources', Q04_SOURCE_DEFINITIONS.primaryJsOracle, 'primaryJsOracle', references, sourceMaterials);
  exact(sources[2].artifact.sha256, lane.parameterSourceSha256, 'implementations.primaryJsOracle parameter source artifact SHA-256');
  return Object.freeze({
    parameterSourceReference: sources[2].artifact,
  });
}

function validateRustKat(lane, references, sourceMaterials) {
  exactKeys(lane, 'implementations.rustKat', [
    'lane',
    'resultSchema',
    'implementation',
    'runtime',
    'transitionComparisons',
    'treeCampaign',
    'productionQualification',
    'independentImplementation',
    'independentEmbeddedParameterArtifact',
    'independentParameterGeneration',
    'importsJavaScript',
    'importsCircomTables',
    'cargoLocked',
    'domainsChecked',
    'knownAnswerTests',
    'packages',
    'rustVersion',
    'sources',
    'cargoManifest',
    'cargoLock',
    'rustToolchain',
    'binary',
    'result',
  ]);
  exact(lane.lane, 'fixed-known-answer-cross-check-only', 'implementations.rustKat.lane');
  exact(lane.resultSchema, Q04_RUST_KAT_SCHEMA, 'implementations.rustKat.resultSchema');
  exact(lane.implementation, 'rust-light-poseidon-bn254-x5', 'implementations.rustKat.implementation');
  exact(lane.runtime, 'rust', 'implementations.rustKat.runtime');
  exact(lane.transitionComparisons, 0, 'implementations.rustKat.transitionComparisons');
  exact(lane.treeCampaign, false, 'implementations.rustKat.treeCampaign');
  exact(lane.productionQualification, false, 'implementations.rustKat.productionQualification');
  exact(lane.independentImplementation, true, 'implementations.rustKat.independentImplementation');
  exact(lane.independentEmbeddedParameterArtifact, true, 'implementations.rustKat.independentEmbeddedParameterArtifact');
  exact(lane.independentParameterGeneration, false, 'implementations.rustKat.independentParameterGeneration');
  exact(lane.importsJavaScript, false, 'implementations.rustKat.importsJavaScript');
  exact(lane.importsCircomTables, false, 'implementations.rustKat.importsCircomTables');
  exact(lane.cargoLocked, true, 'implementations.rustKat.cargoLocked');
  exact(lane.domainsChecked, Q04_RUST_DOMAINS.length, 'implementations.rustKat.domainsChecked');
  exact(lane.knownAnswerTests, Q04_RUST_KATS.length, 'implementations.rustKat.knownAnswerTests');
  exactKeys(lane.packages, 'implementations.rustKat.packages', ['lightPoseidon', 'arkBn254', 'arkFf', 'sha2']);
  exact(lane.packages.lightPoseidon, '0.4.0', 'implementations.rustKat.packages.lightPoseidon');
  exact(lane.packages.arkBn254, '0.5.0', 'implementations.rustKat.packages.arkBn254');
  exact(lane.packages.arkFf, '0.5.0', 'implementations.rustKat.packages.arkFf');
  exact(lane.packages.sha2, '0.10.9', 'implementations.rustKat.packages.sha2');
  string(lane.rustVersion, 'implementations.rustKat.rustVersion', { max: 256 });
  if (!/^rustc 1\.97\.1(?:\s|$)/.test(lane.rustVersion)) fail('implementations.rustKat.rustVersion must report pinned rustc 1.97.1');
  sourceList(lane.sources, 'implementations.rustKat.sources', Q04_SOURCE_DEFINITIONS.rustKat, 'rustKat', references, sourceMaterials);
  sourceReference(lane.cargoManifest, 'implementations.rustKat.cargoManifest', RUST_MANIFEST_DEFINITION, 'rustKat', references, sourceMaterials);
  sourceReference(lane.cargoLock, 'implementations.rustKat.cargoLock', RUST_LOCK_DEFINITION, 'rustKat', references, sourceMaterials);
  sourceReference(lane.rustToolchain, 'implementations.rustKat.rustToolchain', RUST_TOOLCHAIN_DEFINITION, 'rustKat', references, sourceMaterials);
  fileReference(lane.binary, 'implementations.rustKat.binary', references);
  return fileReference(lane.result, 'implementations.rustKat.result', references);
}

function validateDepth4Checker(lane, references, sourceMaterials) {
  exactKeys(lane, 'implementations.depth4Checker', [
    'lane',
    'resultSchema',
    'runtime',
    'proofCalculus',
    'controlSkeletons',
    'representedConcreteRankStateGapTransitions',
    'formalJavaScriptSemanticsClaim',
    'stateQuotientClaim',
    'collisionAssumptionForTermEquality',
    'cargoLocked',
    'rustVersion',
    'sources',
    'binary',
    'result',
  ]);
  exact(
    lane.lane,
    'independent-rust-free-term-certificate-checker',
    'implementations.depth4Checker.lane',
  );
  exact(
    lane.resultSchema,
    Q04_DEPTH4_CHECKER_RESULT_SCHEMA,
    'implementations.depth4Checker.resultSchema',
  );
  exact(lane.runtime, 'rust', 'implementations.depth4Checker.runtime');
  exact(
    lane.proofCalculus,
    'independent-rust-free-term-tree-reduction-v1',
    'implementations.depth4Checker.proofCalculus',
  );
  exact(
    lane.controlSkeletons,
    911,
    'implementations.depth4Checker.controlSkeletons',
  );
  exact(
    lane.representedConcreteRankStateGapTransitions,
    '93928268313',
    'implementations.depth4Checker.representedConcreteRankStateGapTransitions',
  );
  exact(
    lane.formalJavaScriptSemanticsClaim,
    false,
    'implementations.depth4Checker.formalJavaScriptSemanticsClaim',
  );
  exact(
    lane.stateQuotientClaim,
    false,
    'implementations.depth4Checker.stateQuotientClaim',
  );
  exact(
    lane.collisionAssumptionForTermEquality,
    false,
    'implementations.depth4Checker.collisionAssumptionForTermEquality',
  );
  exact(lane.cargoLocked, true, 'implementations.depth4Checker.cargoLocked');
  string(
    lane.rustVersion,
    'implementations.depth4Checker.rustVersion',
    { max: 256 },
  );
  if (!/^rustc 1\.97\.1(?:\s|$)/.test(lane.rustVersion)) {
    fail(
      'implementations.depth4Checker.rustVersion must report pinned rustc 1.97.1',
    );
  }
  sourceList(
    lane.sources,
    'implementations.depth4Checker.sources',
    Q04_SOURCE_DEFINITIONS.depth4Checker,
    'depth4Checker',
    references,
    sourceMaterials,
  );
  fileReference(
    lane.binary,
    'implementations.depth4Checker.binary',
    references,
  );
  return fileReference(
    lane.result,
    'implementations.depth4Checker.result',
    references,
  );
}

function validateImplementations(implementations, references, sourceMaterials) {
  exactKeys(implementations, 'implementations', [
    'productionCore',
    'primaryJsOracle',
    'rustKat',
    'depth4Checker',
  ]);
  validateProductionCore(implementations.productionCore, references, sourceMaterials);
  const primaryJsOracle = validatePrimaryJsOracle(
    implementations.primaryJsOracle,
    references,
    sourceMaterials,
  );
  if (implementations.productionCore.nodeVersion !== implementations.primaryJsOracle.nodeVersion) {
    fail('production and primary JS oracle Node versions must match');
  }
  return Object.freeze({
    ...primaryJsOracle,
    rustResultReference: validateRustKat(
      implementations.rustKat,
      references,
      sourceMaterials,
    ),
    depth4CheckerResultReference: validateDepth4Checker(
      implementations.depth4Checker,
      references,
      sourceMaterials,
    ),
  });
}

function validateOperationCounts(operationCounts) {
  exactKeys(operationCounts, 'operationCounts', Object.keys(Q04_FIXED_OPERATION_COUNTS));
  for (const [field, expected] of Object.entries(Q04_FIXED_OPERATION_COUNTS)) {
    exact(operationCounts[field], expected, `operationCounts.${field}`);
  }
}

function validateHardware(hardware) {
  exactKeys(hardware, 'hardware', ['operatingSystem', 'architecture', 'cpuModel', 'logicalCpuCount', 'totalMemoryBytes', 'filesystem']);
  for (const field of ['operatingSystem', 'architecture', 'cpuModel', 'filesystem']) string(hardware[field], `hardware.${field}`, { max: 512 });
  positiveInteger(hardware.logicalCpuCount, 'hardware.logicalCpuCount');
  positiveInteger(hardware.totalMemoryBytes, 'hardware.totalMemoryBytes');
}

function validateRuntime(runtime, implementations) {
  exactKeys(runtime, 'runtime', ['nodeVersion', 'rustVersion', 'sqliteVersion', 'startedAt', 'finishedAt', 'elapsedMs', 'rustKatElapsedMs', 'depth4CheckerElapsedMs']);
  exact(runtime.nodeVersion, implementations.productionCore.nodeVersion, 'runtime.nodeVersion');
  exact(runtime.rustVersion, implementations.rustKat.rustVersion, 'runtime.rustVersion');
  exact(runtime.sqliteVersion, implementations.productionCore.sqliteVersion, 'runtime.sqliteVersion');
  const startedAt = timestamp(runtime.startedAt, 'runtime.startedAt');
  const finishedAt = timestamp(runtime.finishedAt, 'runtime.finishedAt');
  if (Date.parse(finishedAt) <= Date.parse(startedAt)) fail('runtime.finishedAt must be after runtime.startedAt');
  positiveInteger(runtime.elapsedMs, 'runtime.elapsedMs');
  positiveInteger(runtime.rustKatElapsedMs, 'runtime.rustKatElapsedMs');
  positiveInteger(
    runtime.depth4CheckerElapsedMs,
    'runtime.depth4CheckerElapsedMs',
  );
}

function validateCampaignProcess(
  processRecord,
  label,
  expectedBinarySha256,
) {
  exactKeys(processRecord, label, [
    'pid',
    'exitCode',
    'signal',
    'stdoutSha256',
    'stderrSha256',
    'binarySha256',
    'buildElapsedMs',
    'runElapsedMs',
  ]);
  positiveInteger(processRecord.pid, `${label}.pid`);
  exact(processRecord.exitCode, 0, `${label}.exitCode`);
  exact(processRecord.signal, null, `${label}.signal`);
  sha256(processRecord.stdoutSha256, `${label}.stdoutSha256`);
  sha256(processRecord.stderrSha256, `${label}.stderrSha256`);
  sha256(processRecord.binarySha256, `${label}.binarySha256`);
  exact(
    processRecord.binarySha256,
    expectedBinarySha256,
    `${label}.binarySha256`,
  );
  positiveInteger(processRecord.buildElapsedMs, `${label}.buildElapsedMs`);
  positiveInteger(processRecord.runElapsedMs, `${label}.runElapsedMs`);
}

function validateCampaignProcesses(
  processes,
  evidence,
  depth4Certificate,
) {
  exactKeys(processes, 'campaign processes', [
    'schema',
    'rustKat',
    'depth4Checker',
    'histories',
  ]);
  exact(
    processes.schema,
    Q04_CAMPAIGN_PROCESSES_SCHEMA,
    'campaign processes.schema',
  );
  validateCampaignProcess(
    processes.rustKat,
    'campaign processes.rustKat',
    evidence.implementations.rustKat.binary.sha256,
  );
  validateCampaignProcess(
    processes.depth4Checker,
    'campaign processes.depth4Checker',
    evidence.implementations.depth4Checker.binary.sha256,
  );
  exact(
    processes.rustKat.runElapsedMs,
    evidence.runtime.rustKatElapsedMs,
    'campaign processes.rustKat.runElapsedMs',
  );
  exact(
    processes.depth4Checker.runElapsedMs,
    evidence.runtime.depth4CheckerElapsedMs,
    'campaign processes.depth4Checker.runElapsedMs',
  );
  array(processes.histories, 'campaign processes.histories', HISTORY_COUNT);
  const runnerPids = new Set();
  processes.histories.forEach((execution, historyIndex) => {
    const label = `campaign processes.histories[${historyIndex}]`;
    exactKeys(execution, label, [
      'historyIndex',
      'pid',
      'exitCode',
      'signal',
      'configSha256',
      'transitionArtifact',
      'stdoutSha256',
      'stderrSha256',
    ]);
    exact(execution.historyIndex, historyIndex, `${label}.historyIndex`);
    positiveInteger(execution.pid, `${label}.pid`);
    if (runnerPids.has(execution.pid)) {
      fail('campaign processes histories must use four distinct runner PIDs');
    }
    runnerPids.add(execution.pid);
    exact(execution.exitCode, 0, `${label}.exitCode`);
    exact(execution.signal, null, `${label}.signal`);
    sha256(execution.configSha256, `${label}.configSha256`);
    exact(
      execution.configSha256,
      evidence.histories[historyIndex].configSha256,
      `${label}.configSha256`,
    );
    exactKeys(execution.transitionArtifact, `${label}.transitionArtifact`, [
      'path',
      'bytes',
      'sha256',
    ]);
    for (const field of ['path', 'bytes', 'sha256']) {
      exact(
        execution.transitionArtifact[field],
        evidence.histories[historyIndex].transitionArtifact[field],
        `${label}.transitionArtifact.${field}`,
      );
    }
    sha256(execution.stdoutSha256, `${label}.stdoutSha256`);
    sha256(execution.stderrSha256, `${label}.stderrSha256`);
  });
  nonnegativeNumber(
    depth4Certificate.elapsedMs,
    'depth-4 certificate.elapsedMs',
  );
  const longestHistoryElapsedMs = Math.max(
    ...evidence.histories.map((history) => history.measurements.elapsedMs),
  );
  const measuredLowerBoundMs =
    processes.rustKat.buildElapsedMs
    + processes.rustKat.runElapsedMs
    + processes.depth4Checker.buildElapsedMs
    + depth4Certificate.elapsedMs
    + processes.depth4Checker.runElapsedMs
    + longestHistoryElapsedMs;
  if (
    evidence.runtime.elapsedMs + Q04_RUNTIME_ROUNDING_SLACK_MS
      < measuredLowerBoundMs
  ) {
    fail(
      'runtime.elapsedMs does not cover all serial build/check phases and the longest concurrent history',
    );
  }
  return Object.freeze({
    measuredLowerBoundMs,
    roundingSlackMs: Q04_RUNTIME_ROUNDING_SLACK_MS,
    historyRunnerPids: Object.freeze([...runnerPids]),
  });
}

function validateCommand(command, label, {
  executable,
  executableKind = 'bare',
  arguments: expectedArguments,
  minimumArguments = 0,
  workingDirectory = '.',
} = {}) {
  exactKeys(command, label, ['executable', 'arguments', 'workingDirectory']);
  string(command.executable, `${label}.executable`, { max: 256 });
  if (
    executableKind === 'bare'
    && (command.executable.includes('/') || command.executable.includes('\\'))
  ) fail(`${label}.executable must be a bare executable name`);
  if (executableKind === 'relative') {
    safeRelativePosixPath(command.executable, `${label}.executable`);
  }
  if (executable !== undefined) exact(command.executable, executable, `${label}.executable`);
  array(command.arguments, `${label}.arguments`);
  if (command.arguments.length < minimumArguments || command.arguments.length > 64) fail(`${label}.arguments has an invalid count`);
  command.arguments.forEach((argument, index) => string(argument, `${label}.arguments[${index}]`, { max: 4096 }));
  if (expectedArguments !== undefined) {
    exact(command.arguments.length, expectedArguments.length, `${label}.arguments.length`);
    expectedArguments.forEach((argument, index) => exact(command.arguments[index], argument, `${label}.arguments[${index}]`));
  }
  safeRelativePosixPath(command.workingDirectory, `${label}.workingDirectory`, { allowDot: true });
  exact(command.workingDirectory, workingDirectory, `${label}.workingDirectory`);
}

function validateProvenance(provenance, references, sourceMaterials) {
  exactKeys(provenance, 'provenance', [
    'generatedAt',
    'commands',
    'campaignSources',
    'nodePackageLock',
    'inputManifest',
    'rawOutput',
    'resultTranscript',
  ]);
  timestamp(provenance.generatedAt, 'provenance.generatedAt');
  exactKeys(provenance.commands, 'provenance.commands', [
    'campaign',
    'rustKatBuild',
    'rustKatRun',
    'depth4CheckerBuild',
    'depth4CheckerRun',
  ]);
  validateCommand(provenance.commands.campaign, 'provenance.commands.campaign', { executable: 'node', minimumArguments: 1 });
  validateCommand(provenance.commands.rustKatBuild, 'provenance.commands.rustKatBuild', {
    executable: 'cargo',
    arguments: ['+1.97.1', 'build', '--locked', '--release', '--bin', 'q04-poseidon-oracle'],
    workingDirectory: '03-create-your-own-pool/crates/shieldkit-v2-recovery',
  });
  validateCommand(provenance.commands.rustKatRun, 'provenance.commands.rustKatRun', {
    executable: 'target/release/q04-poseidon-oracle',
    executableKind: 'relative',
    arguments: [],
    workingDirectory: '03-create-your-own-pool/crates/shieldkit-v2-recovery',
  });
  validateCommand(
    provenance.commands.depth4CheckerBuild,
    'provenance.commands.depth4CheckerBuild',
    {
      executable: 'cargo',
      arguments: [
        '+1.97.1',
        'build',
        '--locked',
        '--release',
        '--bin',
        'shieldkit-v2-q04-certificate',
      ],
      workingDirectory:
        '03-create-your-own-pool/crates/shieldkit-v2-q04-certificate',
    },
  );
  validateCommand(
    provenance.commands.depth4CheckerRun,
    'provenance.commands.depth4CheckerRun',
    {
      executable: 'bin/shieldkit-v2-q04-certificate',
      executableKind: 'relative',
      arguments: [
        'raw/depth4-symbolic-certificate.json',
        'snapshot/03-create-your-own-pool/packages/pool/v2/persistent-indexed-nullifier.mjs',
        'snapshot/03-create-your-own-pool/crates/shieldkit-v2-q04-certificate/src/main.rs',
      ],
      workingDirectory: '.',
    },
  );
  sourceList(provenance.campaignSources, 'provenance.campaignSources', Q04_SOURCE_DEFINITIONS.campaign, 'campaign', references, sourceMaterials);
  sourceReference(provenance.nodePackageLock, 'provenance.nodePackageLock', NODE_LOCK_DEFINITION, 'campaign', references, sourceMaterials);
  const rawOutput = fileReference(
    provenance.rawOutput,
    'provenance.rawOutput',
    references,
  );
  exact(
    rawOutput.path,
    'raw/campaign-processes.json',
    'provenance.rawOutput.path',
  );
  return Object.freeze({
    inputManifest: fileReference(provenance.inputManifest, 'provenance.inputManifest', references),
    rawOutput,
    resultTranscript: fileReference(provenance.resultTranscript, 'provenance.resultTranscript', references),
  });
}

function validateDepth4(depth4, references, sourceMaterials) {
  exactKeys(depth4, 'depth4', [
    'schema',
    'status',
    'scope',
    'productionQualification',
    'sources',
    'symbolicCertificate',
    'certificate',
  ]);
  exact(depth4.schema, Q04_DEPTH4_SCHEMA, 'depth4.schema');
  exact(depth4.status, Q04_DEPTH4_STATUS, 'depth4.status');
  exact(depth4.scope, Q04_DEPTH4_SCOPE, 'depth4.scope');
  exact(depth4.productionQualification, true, 'depth4.productionQualification');
  sourceList(
    depth4.sources,
    'depth4.sources',
    Q04_SOURCE_DEFINITIONS.depth4,
    'depth4',
    references,
    sourceMaterials,
  );
  return Object.freeze({
    certificate: fileReference(
      depth4.certificate,
      'depth4.certificate',
      references,
    ),
    symbolicCertificate: fileReference(
      depth4.symbolicCertificate,
      'depth4.symbolicCertificate',
      references,
    ),
  });
}

function validateProbe(probe, historyIndex, checkpointIndex, probeIndex) {
  const label = `histories[${historyIndex}].checkpoints[${checkpointIndex}].probes[${probeIndex}]`;
  exactKeys(probe, label, [
    'caseId',
    'caseSha256',
    'kind',
    'expectedOutcome',
    'accepted',
    'stateUnchanged',
    'errorCode',
    'inputSha256',
    'preStateSha256',
    'postStateSha256',
    'rejection',
    'resultSha256',
  ]);
  const definition = Q04_CHECKPOINT_PROBE_CASES[probeIndex];
  exact(probe.caseId, definition.id, `${label}.caseId`);
  exact(
    probe.caseSha256,
    q04CheckpointProbeCaseDigest(definition),
    `${label}.caseSha256`,
  );
  exact(probe.kind, definition.kind, `${label}.kind`);
  exact(probe.expectedOutcome, 'reject', `${label}.expectedOutcome`);
  exact(probe.accepted, false, `${label}.accepted`);
  exact(probe.stateUnchanged, true, `${label}.stateUnchanged`);
  string(probe.errorCode, `${label}.errorCode`, { max: 64 });
  if (!ERROR_CODE.test(probe.errorCode)) fail(`${label}.errorCode must be a stable uppercase error code`);
  sha256(probe.inputSha256, `${label}.inputSha256`);
  sha256(probe.preStateSha256, `${label}.preStateSha256`);
  sha256(probe.postStateSha256, `${label}.postStateSha256`);
  exact(probe.postStateSha256, probe.preStateSha256, `${label}.postStateSha256`);
  string(probe.rejection, `${label}.rejection`, { max: 4096 });
  sha256(probe.resultSha256, `${label}.resultSha256`);
  const { resultSha256, ...withoutDigest } = probe;
  exact(
    resultSha256,
    q04CheckpointProbeResultDigest(withoutDigest),
    `${label}.resultSha256`,
  );
}

function validateStorage(storage, label, { open, closed } = {}) {
  exactKeys(
    storage,
    label,
    open
      ? [
        'fileBytes',
        'freeListCount',
        'journalMode',
        'pageCount',
        'pageSize',
        'synchronous',
        'totalFileBytes',
      ]
      : ['fileBytes', 'totalFileBytes'],
  );
  exactKeys(storage.fileBytes, `${label}.fileBytes`, ['database', 'shm', 'wal']);
  for (const field of ['database', 'shm', 'wal']) {
    safeInteger(storage.fileBytes[field], `${label}.fileBytes.${field}`);
  }
  exact(
    storage.totalFileBytes,
    storage.fileBytes.database + storage.fileBytes.shm + storage.fileBytes.wal,
    `${label}.totalFileBytes`,
  );
  positiveInteger(storage.fileBytes.database, `${label}.fileBytes.database`);
  positiveInteger(storage.totalFileBytes, `${label}.totalFileBytes`);
  if (open) {
    for (const field of ['freeListCount', 'pageCount', 'pageSize', 'synchronous']) {
      safeInteger(storage[field], `${label}.${field}`);
    }
    exact(storage.journalMode, 'wal', `${label}.journalMode`);
  }
  if (closed) {
    exact(storage.fileBytes.wal, 0, `${label}.fileBytes.wal`);
    exact(storage.fileBytes.shm, 0, `${label}.fileBytes.shm`);
  }
}

function validateLifecycleMeasurement(measurement, label) {
  exactKeys(measurement, label, [
    'closeWallMs',
    'fsReadOps',
    'fsWriteOps',
    'involuntaryContextSwitches',
    'peakRssBytes',
    'readBytes',
    'systemCpuMicros',
    'userCpuMicros',
    'voluntaryContextSwitches',
    'wallMs',
    'writeBytes',
  ]);
  nonnegativeNumber(measurement.wallMs, `${label}.wallMs`);
  nonnegativeNumber(measurement.closeWallMs, `${label}.closeWallMs`);
  for (const field of [
    'fsReadOps',
    'fsWriteOps',
    'involuntaryContextSwitches',
    'peakRssBytes',
    'readBytes',
    'systemCpuMicros',
    'userCpuMicros',
    'voluntaryContextSwitches',
    'writeBytes',
  ]) safeInteger(measurement[field], `${label}.${field}`);
}

function validateCheckpoint(checkpoint, historyIndex, checkpointIndex, processIds) {
  const label = `histories[${historyIndex}].checkpoints[${checkpointIndex}]`;
  exactKeys(checkpoint, label, [
    'afterEntry',
    'closeExitCode',
    'reopenExitCode',
    'actualRoot',
    'oracleRoot',
    'logicalStoreSha256',
    'actualTranscriptSha256',
    'oracleTranscriptSha256',
    'probes',
    'discrepancies',
    'unexpectedAccepts',
    'workerPid',
    'reopenPid',
    'writerOpenAndAuditWallMs',
    'reopenOpenAndAuditWallMs',
    'reopenParentLifecycleWallMs',
    'phaseMeasurement',
    'segmentMeasurement',
    'reopenMeasurement',
    'storage',
  ]);
  exact(checkpoint.afterEntry, EXPECTED_CHECKPOINTS[checkpointIndex], `${label}.afterEntry`);
  exact(checkpoint.closeExitCode, 0, `${label}.closeExitCode`);
  exact(checkpoint.reopenExitCode, 0, `${label}.reopenExitCode`);
  frElement(checkpoint.actualRoot, `${label}.actualRoot`);
  frElement(checkpoint.oracleRoot, `${label}.oracleRoot`);
  exact(checkpoint.actualRoot, checkpoint.oracleRoot, `${label}.actualRoot`);
  sha256(checkpoint.logicalStoreSha256, `${label}.logicalStoreSha256`);
  sha256(checkpoint.actualTranscriptSha256, `${label}.actualTranscriptSha256`);
  sha256(checkpoint.oracleTranscriptSha256, `${label}.oracleTranscriptSha256`);
  exact(checkpoint.actualTranscriptSha256, checkpoint.oracleTranscriptSha256, `${label}.actualTranscriptSha256`);
  array(checkpoint.probes, `${label}.probes`, Q04_REQUIRED_PROBES.length);
  checkpoint.probes.forEach((probe, probeIndex) => validateProbe(probe, historyIndex, checkpointIndex, probeIndex));
  exact(checkpoint.discrepancies, 0, `${label}.discrepancies`);
  exact(checkpoint.unexpectedAccepts, 0, `${label}.unexpectedAccepts`);
  for (const field of ['workerPid', 'reopenPid']) {
    positiveInteger(checkpoint[field], `${label}.${field}`);
    if (processIds.has(checkpoint[field])) fail(`${label}.${field} reuses a campaign worker PID`);
    processIds.add(checkpoint[field]);
  }
  if (checkpoint.workerPid === checkpoint.reopenPid) {
    fail(`${label} must use a fresh reopen process`);
  }
  for (const field of [
    'writerOpenAndAuditWallMs',
    'reopenOpenAndAuditWallMs',
    'reopenParentLifecycleWallMs',
  ]) nonnegativeNumber(checkpoint[field], `${label}.${field}`);
  exactKeys(checkpoint.phaseMeasurement, `${label}.phaseMeasurement`, [
    'checkpointProbeAuditWallMs',
    'openAndStartAuditWallMs',
    'scheduleGenerationWallMs',
    'transitionLoopWallMs',
  ]);
  for (const [field, value] of Object.entries(checkpoint.phaseMeasurement)) {
    nonnegativeNumber(value, `${label}.phaseMeasurement.${field}`);
  }
  validateLifecycleMeasurement(checkpoint.segmentMeasurement, `${label}.segmentMeasurement`);
  validateLifecycleMeasurement(checkpoint.reopenMeasurement, `${label}.reopenMeasurement`);
  exactKeys(checkpoint.storage, `${label}.storage`, [
    'segmentPreClose',
    'segmentPostClose',
    'reopenPreClose',
    'reopenPostClose',
  ]);
  validateStorage(checkpoint.storage.segmentPreClose, `${label}.storage.segmentPreClose`, { open: true });
  validateStorage(checkpoint.storage.segmentPostClose, `${label}.storage.segmentPostClose`, { closed: true });
  validateStorage(checkpoint.storage.reopenPreClose, `${label}.storage.reopenPreClose`, { open: true });
  validateStorage(checkpoint.storage.reopenPostClose, `${label}.storage.reopenPostClose`, { closed: true });
}

function validateMeasurements(measurements, historyIndex) {
  const label = `histories[${historyIndex}].measurements`;
  exactKeys(measurements, label, [
    'elapsedMs',
    'peakRssBytes',
    'databaseBytes',
    'walBytes',
    'shmBytes',
    'totalFileBytes',
    'readBytes',
    'writeBytes',
  ]);
  nonnegativeNumber(measurements.elapsedMs, `${label}.elapsedMs`);
  positiveInteger(measurements.peakRssBytes, `${label}.peakRssBytes`);
  positiveInteger(measurements.databaseBytes, `${label}.databaseBytes`);
  for (const field of ['walBytes', 'shmBytes', 'totalFileBytes', 'readBytes', 'writeBytes']) {
    safeInteger(measurements[field], `${label}.${field}`);
  }
  exact(
    measurements.totalFileBytes,
    measurements.databaseBytes + measurements.walBytes + measurements.shmBytes,
    `${label}.totalFileBytes`,
  );
  exact(measurements.walBytes, 0, `${label}.walBytes`);
  exact(measurements.shmBytes, 0, `${label}.shmBytes`);
}

function transitionReference(value, historyIndex, references) {
  const label = `histories[${historyIndex}].transitionArtifact`;
  exact(value.path, `raw/history-${historyIndex}-transitions.ndjson`, `${label}.path`);
  const reference = fileReference(value, label, references, 'history-ndjson');
  return Object.freeze({ ...reference, historyIndex });
}

function validateOracleMetadata(metadata, historyIndex, implementations) {
  const label = `histories[${historyIndex}].oracleMetadata`;
  exactKeys(metadata, label, ['poseidon', 'tree']);
  exactKeys(metadata.poseidon, `${label}.poseidon`, [
    'implementation',
    'parameterSourcePath',
    'parameterSourceSha256',
    'supportedArities',
  ]);
  exact(
    metadata.poseidon.implementation,
    implementations.primaryJsOracle.poseidonImplementation,
    `${label}.poseidon.implementation`,
  );
  parameterSourcePath(
    metadata.poseidon.parameterSourcePath,
    `${label}.poseidon.parameterSourcePath`,
  );
  exact(
    metadata.poseidon.parameterSourceSha256,
    implementations.primaryJsOracle.parameterSourceSha256,
    `${label}.poseidon.parameterSourceSha256`,
  );
  array(metadata.poseidon.supportedArities, `${label}.poseidon.supportedArities`, 3);
  [2, 3, 6].forEach((arity, index) =>
    exact(metadata.poseidon.supportedArities[index], arity, `${label}.poseidon.supportedArities[${index}]`)
  );
  exactKeys(metadata.tree, `${label}.tree`, [
    'implementation',
    'depth',
    'frModulusHex',
    'orderedSet',
  ]);
  exact(
    metadata.tree.implementation,
    implementations.primaryJsOracle.treeImplementation,
    `${label}.tree.implementation`,
  );
  exact(metadata.tree.depth, 32, `${label}.tree.depth`);
  exact(metadata.tree.frModulusHex, Q04_FR_MODULUS_HEX, `${label}.tree.frModulusHex`);
  exact(metadata.tree.orderedSet, 'sha256-priority-treap', `${label}.tree.orderedSet`);
}

function validateHistory(history, historyIndex, references, processIds, implementations) {
  const label = `histories[${historyIndex}]`;
  exactKeys(history, label, [
    'schema',
    'configSha256',
    'qualifying',
    'index',
    'seed',
    'acceptedEntries',
    'inputTranscriptSha256',
    'actualTranscriptSha256',
    'oracleTranscriptSha256',
    'finalActualRoot',
    'finalOracleRoot',
    'comparisons',
    'checkpoints',
    'measurements',
    'transitionArtifact',
    'oracleMetadata',
  ]);
  exact(history.schema, Q04_HISTORY_RESULT_SCHEMA, `${label}.schema`);
  sha256(history.configSha256, `${label}.configSha256`);
  exact(history.qualifying, true, `${label}.qualifying`);
  exact(history.index, historyIndex, `${label}.index`);
  exact(history.seed, Q04_FIXED_SEEDS[historyIndex], `${label}.seed`);
  exact(history.acceptedEntries, ENTRIES_PER_HISTORY, `${label}.acceptedEntries`);
  sha256(history.inputTranscriptSha256, `${label}.inputTranscriptSha256`);
  sha256(history.actualTranscriptSha256, `${label}.actualTranscriptSha256`);
  sha256(history.oracleTranscriptSha256, `${label}.oracleTranscriptSha256`);
  exact(history.actualTranscriptSha256, history.oracleTranscriptSha256, `${label}.actualTranscriptSha256`);
  frElement(history.finalActualRoot, `${label}.finalActualRoot`);
  frElement(history.finalOracleRoot, `${label}.finalOracleRoot`);
  exact(history.finalActualRoot, history.finalOracleRoot, `${label}.finalActualRoot`);
  exactKeys(history.comparisons, `${label}.comparisons`, [
    'transitions',
    'predecessorMembershipPaths',
    'emptyAppendNonMembershipPaths',
    'postInsertionMembershipPaths',
    'discrepancies',
  ]);
  for (const field of ['transitions', 'predecessorMembershipPaths', 'emptyAppendNonMembershipPaths', 'postInsertionMembershipPaths']) {
    exact(history.comparisons[field], ENTRIES_PER_HISTORY, `${label}.comparisons.${field}`);
  }
  exact(history.comparisons.discrepancies, 0, `${label}.comparisons.discrepancies`);
  array(history.checkpoints, `${label}.checkpoints`, CHECKPOINTS_PER_HISTORY);
  history.checkpoints.forEach((checkpoint, checkpointIndex) =>
    validateCheckpoint(checkpoint, historyIndex, checkpointIndex, processIds)
  );
  const finalCheckpoint = history.checkpoints.at(-1);
  exact(finalCheckpoint.actualRoot, history.finalActualRoot, `${label}.finalActualRoot`);
  exact(finalCheckpoint.oracleRoot, history.finalOracleRoot, `${label}.finalOracleRoot`);
  exact(finalCheckpoint.actualTranscriptSha256, history.actualTranscriptSha256, `${label}.actualTranscriptSha256`);
  exact(finalCheckpoint.oracleTranscriptSha256, history.oracleTranscriptSha256, `${label}.oracleTranscriptSha256`);
  validateMeasurements(history.measurements, historyIndex);
  const finalStorage = finalCheckpoint.storage.reopenPostClose;
  exact(finalStorage.fileBytes.database, history.measurements.databaseBytes, `${label}.measurements.databaseBytes`);
  exact(finalStorage.fileBytes.wal, history.measurements.walBytes, `${label}.measurements.walBytes`);
  exact(finalStorage.fileBytes.shm, history.measurements.shmBytes, `${label}.measurements.shmBytes`);
  exact(finalStorage.totalFileBytes, history.measurements.totalFileBytes, `${label}.measurements.totalFileBytes`);
  const lifecycle = history.checkpoints.flatMap((checkpoint) => [
    checkpoint.segmentMeasurement,
    checkpoint.reopenMeasurement,
  ]);
  exact(
    lifecycle.reduce((total, measurement) => total + measurement.readBytes, 0),
    history.measurements.readBytes,
    `${label}.measurements.readBytes`,
  );
  exact(
    lifecycle.reduce((total, measurement) => total + measurement.writeBytes, 0),
    history.measurements.writeBytes,
    `${label}.measurements.writeBytes`,
  );
  const childPeakRssBytes = Math.max(...lifecycle.map((measurement) => measurement.peakRssBytes));
  if (history.measurements.peakRssBytes < childPeakRssBytes) {
    fail(`${label}.measurements.peakRssBytes is below an observed child process peak`);
  }
  validateOracleMetadata(history.oracleMetadata, historyIndex, implementations);
  return transitionReference(history.transitionArtifact, historyIndex, references);
}

function validateAggregate(aggregate) {
  exactKeys(aggregate, 'aggregate', [
    'acceptedEntries',
    'checkpoints',
    'probesRun',
    'expectedRejections',
    'unexpectedAccepts',
    'discrepancies',
    'transitionComparisons',
    'rustKatKnownAnswerTests',
    'rustKatDomainsChecked',
  ]);
  exact(aggregate.acceptedEntries, TOTAL_ENTRIES, 'aggregate.acceptedEntries');
  exact(aggregate.checkpoints, TOTAL_CHECKPOINTS, 'aggregate.checkpoints');
  exact(aggregate.probesRun, TOTAL_PROBES, 'aggregate.probesRun');
  exact(aggregate.expectedRejections, TOTAL_PROBES, 'aggregate.expectedRejections');
  exact(aggregate.unexpectedAccepts, 0, 'aggregate.unexpectedAccepts');
  exact(aggregate.discrepancies, 0, 'aggregate.discrepancies');
  exactKeys(aggregate.transitionComparisons, 'aggregate.transitionComparisons', ['productionCore', 'primaryJsOracle', 'rustKat']);
  exact(aggregate.transitionComparisons.productionCore, TOTAL_ENTRIES, 'aggregate.transitionComparisons.productionCore');
  exact(aggregate.transitionComparisons.primaryJsOracle, TOTAL_ENTRIES, 'aggregate.transitionComparisons.primaryJsOracle');
  exact(aggregate.transitionComparisons.rustKat, 0, 'aggregate.transitionComparisons.rustKat');
  exact(aggregate.rustKatKnownAnswerTests, Q04_RUST_KATS.length, 'aggregate.rustKatKnownAnswerTests');
  exact(aggregate.rustKatDomainsChecked, Q04_RUST_DOMAINS.length, 'aggregate.rustKatDomainsChecked');
}

function validateClaimBoundary(claimBoundary) {
  exactKeys(claimBoundary, 'claimBoundary', [
    'entriesPerHistory',
    'aggregateEntries',
    'singleHistory100kMeasured',
    'largerHistoryClaim',
    'depth4Scope',
    'depth4EnumeratesAllKeyHistories',
    'depth4LargerDepthClaim',
    'depth4ProductionKernelEquivalenceProved',
    'depth4ExternalCertificateCheckerVerified',
    'formalJavaScriptSemanticsClaim',
  ]);
  exact(claimBoundary.entriesPerHistory, ENTRIES_PER_HISTORY, 'claimBoundary.entriesPerHistory');
  exact(claimBoundary.aggregateEntries, TOTAL_ENTRIES, 'claimBoundary.aggregateEntries');
  exact(claimBoundary.singleHistory100kMeasured, false, 'claimBoundary.singleHistory100kMeasured');
  exact(claimBoundary.largerHistoryClaim, false, 'claimBoundary.largerHistoryClaim');
  exact(
    claimBoundary.depth4Scope,
    Q04_DEPTH4_SCOPE,
    'claimBoundary.depth4Scope',
  );
  exact(claimBoundary.depth4EnumeratesAllKeyHistories, false, 'claimBoundary.depth4EnumeratesAllKeyHistories');
  exact(claimBoundary.depth4LargerDepthClaim, false, 'claimBoundary.depth4LargerDepthClaim');
  exact(
    claimBoundary.depth4ProductionKernelEquivalenceProved,
    false,
    'claimBoundary.depth4ProductionKernelEquivalenceProved',
  );
  exact(
    claimBoundary.depth4ExternalCertificateCheckerVerified,
    true,
    'claimBoundary.depth4ExternalCertificateCheckerVerified',
  );
  exact(
    claimBoundary.formalJavaScriptSemanticsClaim,
    false,
    'claimBoundary.formalJavaScriptSemanticsClaim',
  );
}

function validateVerdict(verdict) {
  exactKeys(verdict, 'verdict', ['largeHistoryCampaign', 'rustPoseidonKat', 'depth4', 'q04Correctness', 'q07Performance']);
  exact(verdict.largeHistoryCampaign, 'pass', 'verdict.largeHistoryCampaign');
  exact(verdict.rustPoseidonKat, 'pass', 'verdict.rustPoseidonKat');
  exact(
    verdict.depth4,
    'verified-universal-template-with-nonformal-js-binding',
    'verdict.depth4',
  );
  exact(
    verdict.q04Correctness,
    'pass-bounded-100000-and-depth4-shared-kernel',
    'verdict.q04Correctness',
  );
  exact(verdict.q07Performance, 'separate', 'verdict.q07Performance');
}

function validateHashes(
  hashes,
  evidence,
  provenanceReferences,
  rustResultReference,
  depth4References,
  depth4CheckerResultReference,
  sourceSetSha256,
) {
  exactKeys(hashes, 'hashes', [
    'inputManifestSha256',
    'rawOutputSha256',
    'resultTranscriptSha256',
    'depth4CertificateSha256',
    'depth4SymbolicCertificateSha256',
    'depth4CheckerResultSha256',
    'rustKatResultSha256',
    'sourceSetSha256',
    'historyTransitionSetSha256',
  ]);
  for (const field of Object.keys(hashes)) sha256(hashes[field], `hashes.${field}`);
  exact(hashes.inputManifestSha256, provenanceReferences.inputManifest.sha256, 'hashes.inputManifestSha256');
  exact(hashes.rawOutputSha256, provenanceReferences.rawOutput.sha256, 'hashes.rawOutputSha256');
  exact(hashes.resultTranscriptSha256, provenanceReferences.resultTranscript.sha256, 'hashes.resultTranscriptSha256');
  exact(hashes.depth4CertificateSha256, depth4References.certificate.sha256, 'hashes.depth4CertificateSha256');
  exact(hashes.depth4SymbolicCertificateSha256, depth4References.symbolicCertificate.sha256, 'hashes.depth4SymbolicCertificateSha256');
  exact(hashes.depth4CheckerResultSha256, depth4CheckerResultReference.sha256, 'hashes.depth4CheckerResultSha256');
  exact(hashes.rustKatResultSha256, rustResultReference.sha256, 'hashes.rustKatResultSha256');
  exact(hashes.sourceSetSha256, sourceSetSha256, 'hashes.sourceSetSha256');
  exact(hashes.historyTransitionSetSha256, deriveQ04HistoryTransitionSetSha256(evidence.histories), 'hashes.historyTransitionSetSha256');
}

function validateDocument(evidence) {
  object(evidence, 'evidence');
  rejectForbiddenClaims(evidence);
  exactKeys(evidence, 'evidence', [
    'schema',
    'gate',
    'status',
    'subject',
    'definition',
    'implementations',
    'operationCounts',
    'hardware',
    'runtime',
    'provenance',
    'hashes',
    'depth4',
    'histories',
    'aggregate',
    'claimBoundary',
    'verdict',
  ]);
  exact(evidence.schema, Q04_EVIDENCE_SCHEMA, 'evidence.schema');
  exact(evidence.gate, 'Q-04', 'evidence.gate');
  exact(evidence.status, 'evidence-complete', 'evidence.status');
  const references = [];
  const sourceMaterials = [];
  validateSubject(evidence.subject);
  validateDefinition(evidence.definition);
  const implementationReferences = validateImplementations(
    evidence.implementations,
    references,
    sourceMaterials,
  );
  const {
    parameterSourceReference,
    rustResultReference,
    depth4CheckerResultReference,
  } = implementationReferences;
  validateOperationCounts(evidence.operationCounts);
  validateHardware(evidence.hardware);
  validateRuntime(evidence.runtime, evidence.implementations);
  const provenanceReferences = validateProvenance(evidence.provenance, references, sourceMaterials);
  if (Date.parse(evidence.provenance.generatedAt) < Date.parse(evidence.runtime.finishedAt)) {
    fail('provenance.generatedAt must not predate runtime.finishedAt');
  }
  const depth4References = validateDepth4(
    evidence.depth4,
    references,
    sourceMaterials,
  );
  array(evidence.histories, 'histories', HISTORY_COUNT);
  const processIds = new Set();
  const historyReferences = evidence.histories.map((history, index) =>
    validateHistory(history, index, references, processIds, evidence.implementations)
  );
  for (const field of ['configSha256', 'inputTranscriptSha256', 'actualTranscriptSha256', 'oracleTranscriptSha256']) {
    if (new Set(evidence.histories.map((history) => history[field])).size !== HISTORY_COUNT) {
      fail(`histories must contain four distinct ${field} values`);
    }
  }
  // Structure-only sanity bound. The file verifier additionally parses the
  // hash-bound process transcript and includes both Rust build phases plus the
  // depth-4 production certificate time. The four histories overlap, so only
  // their longest lane contributes to wall-clock time.
  const longestHistoryElapsedMs = Math.max(
    ...evidence.histories.map((history) => history.measurements.elapsedMs),
  );
  if (
    evidence.runtime.elapsedMs + Q04_RUNTIME_ROUNDING_SLACK_MS <
      longestHistoryElapsedMs +
      evidence.runtime.rustKatElapsedMs +
      evidence.runtime.depth4CheckerElapsedMs
  ) {
    fail(
      'runtime.elapsedMs must cover the longest concurrent history, Rust KAT, and depth-4 checker runtime',
    );
  }
  validateAggregate(evidence.aggregate);
  validateClaimBoundary(evidence.claimBoundary);
  validateVerdict(evidence.verdict);
  const sourceSetSha256 = deriveQ04SourceSetSha256(evidence);
  exact(evidence.subject.sourceSetSha256, sourceSetSha256, 'subject.sourceSetSha256');
  validateHashes(
    hashesOrFail(evidence.hashes),
    evidence,
    provenanceReferences,
    rustResultReference,
    depth4References,
    depth4CheckerResultReference,
    sourceSetSha256,
  );
  const distinctPaths = new Set();
  for (const reference of references) {
    if (distinctPaths.has(reference.path)) fail(`referenced artifact path is duplicated: ${reference.path}`);
    distinctPaths.add(reference.path);
  }
  return Object.freeze({
    references: Object.freeze(references),
    historyReferences: Object.freeze(historyReferences),
    parameterSourceReference,
    rustResultReference,
    depth4CheckerResultReference,
    rawOutputReference: provenanceReferences.rawOutput,
    sourceMaterials: Object.freeze(sourceMaterials),
    depth4References,
    summary: Object.freeze({
      schema: Q04_RESULT_SCHEMA,
      status: 'structure-valid',
      gate: 'Q-04',
      q04GatePass: false,
      q04Verdict: 'requires-file-and-cryptographic-replay',
      depth4BoundedEvidenceVerified: null,
      depth4Scope: evidence.depth4.scope,
      repository: evidence.subject.repository,
      gitCommit: evidence.subject.gitCommit,
      sourceSetSha256,
      histories: HISTORY_COUNT,
      entriesPerHistory: ENTRIES_PER_HISTORY,
      aggregateEntries: TOTAL_ENTRIES,
      checkpoints: TOTAL_CHECKPOINTS,
      probes: TOTAL_PROBES,
      discrepancies: 0,
      unexpectedAccepts: 0,
      singleHistory100kMeasured: false,
      largerHistoryClaim: false,
    }),
  });
}

function hashesOrFail(value) {
  object(value, 'hashes');
  return value;
}

export function validateQ04Evidence(evidence) {
  return validateDocument(evidence).summary;
}

function canonicalAbsolutePath(filename, label) {
  string(filename, label, { max: 4096 });
  if (!path.isAbsolute(filename)) fail(`${label} must be an explicit absolute path`);
  if (path.normalize(filename) !== filename) fail(`${label} must be lexically canonical and contain no traversal`);
  return filename;
}

async function canonicalRegularFile(filename, label, { maximumBytes = MAX_REFERENCE_BYTES } = {}) {
  canonicalAbsolutePath(filename, label);
  let metadata;
  try {
    metadata = await lstat(filename);
  } catch (error) {
    fail(`${label} is unavailable: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size === 0) {
    fail(`${label} must be a nonempty regular non-symlink file`);
  }
  if (metadata.size > maximumBytes) fail(`${label} exceeds ${maximumBytes} bytes`);
  let canonical;
  try {
    canonical = await realpath(filename);
  } catch (error) {
    fail(`${label} cannot be canonicalized: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (canonical !== filename) fail(`${label} must be canonical and must not resolve through a symlink`);
  return metadata;
}

async function sha256File(filename) {
  const digest = createHash('sha256');
  for await (const chunk of createReadStream(filename)) digest.update(chunk);
  return digest.digest('hex');
}

function resolveReference(bundleRoot, evidencePath, reference) {
  const filename = path.resolve(bundleRoot, ...reference.path.split('/'));
  if (filename === evidencePath || (filename !== bundleRoot && !filename.startsWith(`${bundleRoot}${path.sep}`))) {
    fail(`${reference.label}.path escapes the evidence bundle`);
  }
  return filename;
}

async function verifyReference(bundleRoot, evidencePath, reference) {
  const filename = resolveReference(bundleRoot, evidencePath, reference);
  const metadata = await canonicalRegularFile(filename, `${reference.label} artifact`);
  if (metadata.size !== reference.bytes) fail(`${reference.label} byte length does not match the referenced artifact`);
  let observedHash;
  try {
    observedHash = await sha256File(filename);
  } catch (error) {
    fail(`${reference.label} cannot be hashed: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (observedHash !== reference.sha256) fail(`${reference.label} SHA-256 does not match the referenced artifact`);
  return filename;
}

async function verifyStaticReferences(bundleRoot, evidencePath, references) {
  for (const reference of references) {
    if (reference.kind !== 'history-ndjson') await verifyReference(bundleRoot, evidencePath, reference);
  }
}

async function verifyExecutionSourceBindings(sourceMaterials) {
  const rows = [];
  for (const source of sourceMaterials) {
    const filename = path.resolve(
      EXECUTION_REPOSITORY_ROOT,
      ...source.originPath.split('/'),
    );
    if (
      filename === EXECUTION_REPOSITORY_ROOT ||
      !filename.startsWith(`${EXECUTION_REPOSITORY_ROOT}${path.sep}`)
    ) fail(`execution source ${source.originPath} escapes the repository root`);
    const metadata = await canonicalRegularFile(
      filename,
      `execution source ${source.originPath}`,
    );
    if (metadata.size !== source.bytes) {
      fail(
        `execution source ${source.originPath} byte length differs from ` +
          'the evidence artifact',
      );
    }
    const observedHash = await sha256File(filename);
    if (observedHash !== source.sha256) {
      fail(
        `execution source ${source.originPath} SHA-256 differs from ` +
          'the evidence artifact',
      );
    }
    rows.push([
      source.lane,
      source.role,
      source.originPath,
      source.artifactPath,
      String(source.bytes),
      source.sha256,
    ].join('\0'));
  }
  rows.sort();
  return freeze({
    files: rows.length,
    sha256: createHash('sha256')
      .update(
        `ShieldKit/Q04/execution-source-bindings/v1\0${rows.join('\n')}`,
        'utf8',
      )
      .digest('hex'),
  });
}

async function strictReferencedJson(bundleRoot, evidencePath, reference, label) {
  const filename = resolveReference(bundleRoot, evidencePath, reference);
  let value;
  try {
    value = parseStrictJson(await readFile(filename));
  } catch (error) {
    fail(`${label} is invalid strict JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  return value;
}

function validateRustKatResult(result) {
  exactKeys(result, 'Rust KAT result', ['schema', 'status', 'metadata', 'claims', 'domains', 'knownAnswerTests']);
  exact(result.schema, Q04_RUST_KAT_SCHEMA, 'Rust KAT result.schema');
  exact(result.status, 'kat-passed-local-only', 'Rust KAT result.status');
  exactKeys(result.metadata, 'Rust KAT result.metadata', [
    'implementation',
    'lightPoseidonVersion',
    'arkBn254Version',
    'arkFfVersion',
    'sha2Version',
    'fieldModulusHex',
    'inputOrdering',
    'arities',
  ]);
  exact(result.metadata.implementation, 'rust-light-poseidon-bn254-x5', 'Rust KAT result.metadata.implementation');
  exact(result.metadata.lightPoseidonVersion, '0.4.0', 'Rust KAT result.metadata.lightPoseidonVersion');
  exact(result.metadata.arkBn254Version, '0.5.0', 'Rust KAT result.metadata.arkBn254Version');
  exact(result.metadata.arkFfVersion, '0.5.0', 'Rust KAT result.metadata.arkFfVersion');
  exact(result.metadata.sha2Version, '0.10.9', 'Rust KAT result.metadata.sha2Version');
  exact(result.metadata.fieldModulusHex, Q04_FR_MODULUS_HEX, 'Rust KAT result.metadata.fieldModulusHex');
  exact(result.metadata.inputOrdering, 'state=[0, domain, payload...] ; new_circom(input_count) ; canonical big-endian Fr', 'Rust KAT result.metadata.inputOrdering');
  array(result.metadata.arities, 'Rust KAT result.metadata.arities', 3);
  [2, 3, 6].forEach((arity, index) => exact(result.metadata.arities[index], arity, `Rust KAT result.metadata.arities[${index}]`));
  exactKeys(result.claims, 'Rust KAT result.claims', [
    'independentImplementation',
    'independentEmbeddedParameterArtifact',
    'independentParameterGeneration',
    'importsJavaScript',
    'importsCircomTables',
    'productionQualification',
    'treeCampaign',
  ]);
  exact(result.claims.independentImplementation, true, 'Rust KAT result.claims.independentImplementation');
  exact(result.claims.independentEmbeddedParameterArtifact, true, 'Rust KAT result.claims.independentEmbeddedParameterArtifact');
  exact(result.claims.independentParameterGeneration, false, 'Rust KAT result.claims.independentParameterGeneration');
  exact(result.claims.importsJavaScript, false, 'Rust KAT result.claims.importsJavaScript');
  exact(result.claims.importsCircomTables, false, 'Rust KAT result.claims.importsCircomTables');
  exact(result.claims.productionQualification, false, 'Rust KAT result.claims.productionQualification');
  exact(result.claims.treeCampaign, false, 'Rust KAT result.claims.treeCampaign');
  array(result.domains, 'Rust KAT result.domains', Q04_RUST_DOMAINS.length);
  result.domains.forEach((domain, index) => {
    exactKeys(domain, `Rust KAT result.domains[${index}]`, ['label', 'counter', 'hex']);
    for (const field of ['label', 'counter', 'hex']) exact(domain[field], Q04_RUST_DOMAINS[index][field], `Rust KAT result.domains[${index}].${field}`);
  });
  array(result.knownAnswerTests, 'Rust KAT result.knownAnswerTests', Q04_RUST_KATS.length);
  result.knownAnswerTests.forEach((kat, index) => {
    const expected = Q04_RUST_KATS[index];
    exactKeys(kat, `Rust KAT result.knownAnswerTests[${index}]`, ['name', 'arity', 'inputs', 'output']);
    exact(kat.name, expected.name, `Rust KAT result.knownAnswerTests[${index}].name`);
    exact(kat.arity, expected.inputs.length, `Rust KAT result.knownAnswerTests[${index}].arity`);
    array(kat.inputs, `Rust KAT result.knownAnswerTests[${index}].inputs`, expected.inputs.length);
    expected.inputs.forEach((input, inputIndex) => exact(kat.inputs[inputIndex], input, `Rust KAT result.knownAnswerTests[${index}].inputs[${inputIndex}]`));
    exact(kat.output, expected.output, `Rust KAT result.knownAnswerTests[${index}].output`);
  });
}

function validateDepth4CheckerResult(
  result,
  symbolicCertificate,
  implementations,
) {
  exactKeys(result, 'depth-4 checker result', [
    'schema',
    'status',
    'certificateSchema',
    'certificateSha256',
    'productionSourceSha256',
    'checkerSourceSha256',
    'controlSkeletons',
    'representedConcreteRankStateGapTransitions',
    'proofCalculus',
    'formalJavaScriptSemanticsClaim',
    'stateQuotientClaim',
    'collisionAssumptionForTermEquality',
  ]);
  exact(
    result.schema,
    Q04_DEPTH4_CHECKER_RESULT_SCHEMA,
    'depth-4 checker result.schema',
  );
  exact(result.status, 'verified', 'depth-4 checker result.status');
  exact(
    result.certificateSchema,
    Q04_DEPTH4_SYMBOLIC_CERTIFICATE_SCHEMA,
    'depth-4 checker result.certificateSchema',
  );
  exact(
    result.certificateSha256,
    symbolicCertificate.certificateSha256,
    'depth-4 checker result.certificateSha256',
  );
  exact(
    result.productionSourceSha256,
    symbolicCertificate.semanticCore.productionSourceSha256,
    'depth-4 checker result.productionSourceSha256',
  );
  exact(
    result.productionSourceSha256,
    implementations.productionCore.sources[1].artifact.sha256,
    'depth-4 checker result production source artifact',
  );
  exact(
    result.checkerSourceSha256,
    implementations.depth4Checker.sources[0].artifact.sha256,
    'depth-4 checker result checker source artifact',
  );
  exact(
    result.controlSkeletons,
    911,
    'depth-4 checker result.controlSkeletons',
  );
  exact(
    result.representedConcreteRankStateGapTransitions,
    '93928268313',
    'depth-4 checker result.representedConcreteRankStateGapTransitions',
  );
  exact(
    result.proofCalculus,
    'independent-rust-free-term-tree-reduction-v1',
    'depth-4 checker result.proofCalculus',
  );
  exact(
    result.formalJavaScriptSemanticsClaim,
    false,
    'depth-4 checker result.formalJavaScriptSemanticsClaim',
  );
  exact(
    result.stateQuotientClaim,
    false,
    'depth-4 checker result.stateQuotientClaim',
  );
  exact(
    result.collisionAssumptionForTermEquality,
    false,
    'depth-4 checker result.collisionAssumptionForTermEquality',
  );
}

function validateDepth4Certificate(certificate, depth4, implementations) {
  exactKeys(certificate, 'depth-4 certificate', [
    'schema',
    'status',
    'definition',
    'claims',
    'occupancy',
    'indexed',
    'symbolic',
    'hashes',
    'oracle',
    'discrepancies',
    'elapsedMs',
    'evidenceDigestSha256',
  ]);
  exact(certificate.schema, Q04_DEPTH4_SCHEMA, 'depth-4 certificate.schema');
  exact(certificate.status, 'pass', 'depth-4 certificate.status');
  exactKeys(certificate.definition, 'depth-4 certificate.definition', [
    'depth',
    'capacity',
    'authenticatedOccupancyDefinition',
    'indexedControlSkeletonDefinition',
    'symbolicTemplateDefinition',
  ]);
  exact(certificate.definition.depth, 4, 'depth-4 certificate.definition.depth');
  exact(certificate.definition.capacity, 16, 'depth-4 certificate.definition.capacity');
  exact(
    certificate.definition.authenticatedOccupancyDefinition,
    'all 2^16 empty/nonempty physical-leaf occupancy masks; sentinel-shaped leaves at 0/1 and index-distinct normal-shaped leaves at 2..15',
    'depth-4 certificate.definition.authenticatedOccupancyDefinition',
  );
  exact(
    certificate.definition.indexedControlSkeletonDefinition,
    'one deterministic SQLite-backed control skeleton for every allocated count 0..13 and physically distinct valid adjacent predecessor/successor pair, with append at count+2; paired numeric embeddings and every eligible nonlocal rank permutation close, reopen, audit, and preserve the same normalized target trace',
    'depth-4 certificate.definition.indexedControlSkeletonDefinition',
  );
  exact(
    certificate.definition.symbolicTemplateDefinition,
    'one exact shared-kernel symbolic template for each of 911 local control skeletons; untouched allocated leaf hashes remain free terms and predecessor/target/successor keys remain order-constrained variables',
    'depth-4 certificate.definition.symbolicTemplateDefinition',
  );
  const expectedClaims = Object.freeze({
    productionPoseidon: true,
    independentPoseidonImplementation: true,
    authenticatedOccupancyStateSpaceExhaustive: true,
    indexedControlSkeletonsEnumerated: true,
    indexedControlSkeletonsAreStateQuotient: false,
    pairedNumericEmbeddingsUseSharedSqlite: true,
    nonlocalRankPermutationsUseSharedSqlite: true,
    everySqliteLaneReopenedAndAudited: true,
    sharedKernelSymbolicTemplatesChecked: true,
    sharedKernelSymbolicFormalTheorem: false,
    externalProofCheckerRequired: true,
    fullCapacityBoundaryCovered: true,
    terminalCapacityPrecedenceCovered: true,
    exhaustiveOverBn254Field: false,
    enumeratesAllFourteenKeyHistories: false,
    enumeratesAllDepth4IndexedHistories: false,
    largerDepthClaim: false,
  });
  exactKeys(certificate.claims, 'depth-4 certificate.claims', Object.keys(expectedClaims));
  for (const [field, expected] of Object.entries(expectedClaims)) {
    exact(certificate.claims[field], expected, `depth-4 certificate.claims.${field}`);
  }
  exactKeys(certificate.occupancy, 'depth-4 certificate.occupancy', [
    'statesChecked',
    'leafStateHashesChecked',
    'subtreeHashComparisons',
    'rootsSha256',
  ]);
  exact(certificate.occupancy.statesChecked, 65_536, 'depth-4 certificate.occupancy.statesChecked');
  exact(certificate.occupancy.leafStateHashesChecked, 32, 'depth-4 certificate.occupancy.leafStateHashesChecked');
  exact(certificate.occupancy.subtreeHashComparisons, 66_144, 'depth-4 certificate.occupancy.subtreeHashComparisons');
  sha256(certificate.occupancy.rootsSha256, 'depth-4 certificate.occupancy.rootsSha256');
  exactKeys(certificate.indexed, 'depth-4 certificate.indexed', [
    'classes',
    'controlSkeletonIds',
    'setupTransitions',
    'alphaRenamedSetupTransitions',
    'targetTransitions',
    'alphaRenamedTargetTransitions',
    'alphaRenamingMismatches',
    'nonlocalPermutationClasses',
    'nonlocalPermutationSetupTransitions',
    'nonlocalPermutationTargetTransitions',
    'nonlocalPermutationMismatches',
    'sqliteScheduleLanes',
    'durableReopenChecks',
    'duplicateAttempts',
    'semanticDuplicateRejections',
    'terminalCapacityPrecedenceRejections',
    'failClosedDuplicateAttempts',
    'capacityRejected',
    'capacityRejectedBeforeAdapterReads',
    'allocatedCountsCovered',
    'minimumKeyCovered',
    'maximumKeyCovered',
    'productionPersistentKernel',
    'qualificationSqliteAdapter',
    'recordedLeafCalls',
    'recordedNodeCalls',
    'depth3',
    'controlTraceDigestSha256',
    'classBreakdown',
  ]);
  const expectedClasses = Array.from(
    { length: 14 },
    (_, normalCount) => normalCount === 0 ? 1 : normalCount * (normalCount + 1),
  );
  const expectedSetupTransitions = expectedClasses.map(
    (classes, normalCount) => classes * normalCount,
  );
  const expectedNonlocalPermutationClasses = [
    0, 0, 0, 6, 20, 30, 42, 56, 72, 90, 110, 132, 156, 182,
  ];
  const expectedNonlocalPermutationSetupTransitions =
    expectedNonlocalPermutationClasses.map(
      (classes, normalCount) => classes * normalCount,
    );
  exact(certificate.indexed.classes, 911, 'depth-4 certificate.indexed.classes');
  exact(certificate.indexed.controlSkeletonIds, 911, 'depth-4 certificate.indexed.controlSkeletonIds');
  exact(certificate.indexed.setupTransitions, 9_100, 'depth-4 certificate.indexed.setupTransitions');
  exact(certificate.indexed.alphaRenamedSetupTransitions, 9_100, 'depth-4 certificate.indexed.alphaRenamedSetupTransitions');
  exact(certificate.indexed.targetTransitions, 911, 'depth-4 certificate.indexed.targetTransitions');
  exact(certificate.indexed.alphaRenamedTargetTransitions, 911, 'depth-4 certificate.indexed.alphaRenamedTargetTransitions');
  exact(certificate.indexed.alphaRenamingMismatches, 0, 'depth-4 certificate.indexed.alphaRenamingMismatches');
  exact(certificate.indexed.nonlocalPermutationClasses, 896, 'depth-4 certificate.indexed.nonlocalPermutationClasses');
  exact(certificate.indexed.nonlocalPermutationSetupTransitions, 9_068, 'depth-4 certificate.indexed.nonlocalPermutationSetupTransitions');
  exact(certificate.indexed.nonlocalPermutationTargetTransitions, 896, 'depth-4 certificate.indexed.nonlocalPermutationTargetTransitions');
  exact(certificate.indexed.nonlocalPermutationMismatches, 0, 'depth-4 certificate.indexed.nonlocalPermutationMismatches');
  exact(certificate.indexed.sqliteScheduleLanes, 2_718, 'depth-4 certificate.indexed.sqliteScheduleLanes');
  exact(certificate.indexed.durableReopenChecks, 2_718, 'depth-4 certificate.indexed.durableReopenChecks');
  exact(certificate.indexed.duplicateAttempts, 911, 'depth-4 certificate.indexed.duplicateAttempts');
  exact(certificate.indexed.semanticDuplicateRejections, 729, 'depth-4 certificate.indexed.semanticDuplicateRejections');
  exact(certificate.indexed.terminalCapacityPrecedenceRejections, 182, 'depth-4 certificate.indexed.terminalCapacityPrecedenceRejections');
  exact(certificate.indexed.failClosedDuplicateAttempts, 911, 'depth-4 certificate.indexed.failClosedDuplicateAttempts');
  exact(certificate.indexed.capacityRejected, true, 'depth-4 certificate.indexed.capacityRejected');
  exact(certificate.indexed.capacityRejectedBeforeAdapterReads, true, 'depth-4 certificate.indexed.capacityRejectedBeforeAdapterReads');
  exact(certificate.indexed.allocatedCountsCovered, 14, 'depth-4 certificate.indexed.allocatedCountsCovered');
  exact(certificate.indexed.minimumKeyCovered, true, 'depth-4 certificate.indexed.minimumKeyCovered');
  exact(certificate.indexed.maximumKeyCovered, true, 'depth-4 certificate.indexed.maximumKeyCovered');
  exact(certificate.indexed.productionPersistentKernel, true, 'depth-4 certificate.indexed.productionPersistentKernel');
  exact(certificate.indexed.qualificationSqliteAdapter, true, 'depth-4 certificate.indexed.qualificationSqliteAdapter');
  exactKeys(certificate.indexed.depth3, 'depth-4 certificate.indexed.depth3', [
    'definition',
    'states',
    'setupTransitions',
    'targetTransitions',
    'fullStates',
    'sqliteStates',
    'durableReopenChecks',
    'controlTraceMismatches',
    'recordedLeafCalls',
    'recordedNodeCalls',
  ]);
  exact(
    certificate.indexed.depth3.definition,
    'all sum(n!, n=0..6)=874 rank permutations embedded in the first eight physical leaves of the fixed depth-4 production kernel; all 873 valid next insertion gaps at counts 0..5',
    'depth-4 certificate.indexed.depth3.definition',
  );
  exact(certificate.indexed.depth3.states, 874, 'depth-4 certificate.indexed.depth3.states');
  exact(certificate.indexed.depth3.setupTransitions, 5_039, 'depth-4 certificate.indexed.depth3.setupTransitions');
  exact(certificate.indexed.depth3.targetTransitions, 873, 'depth-4 certificate.indexed.depth3.targetTransitions');
  exact(certificate.indexed.depth3.fullStates, 720, 'depth-4 certificate.indexed.depth3.fullStates');
  exact(certificate.indexed.depth3.sqliteStates, 874, 'depth-4 certificate.indexed.depth3.sqliteStates');
  exact(certificate.indexed.depth3.durableReopenChecks, 874, 'depth-4 certificate.indexed.depth3.durableReopenChecks');
  exact(certificate.indexed.depth3.controlTraceMismatches, 0, 'depth-4 certificate.indexed.depth3.controlTraceMismatches');
  const expectedRecordedTransitions =
    certificate.indexed.setupTransitions +
    certificate.indexed.targetTransitions +
    certificate.indexed.alphaRenamedSetupTransitions +
    certificate.indexed.alphaRenamedTargetTransitions +
    certificate.indexed.nonlocalPermutationSetupTransitions +
    certificate.indexed.nonlocalPermutationTargetTransitions +
    certificate.indexed.depth3.setupTransitions +
    certificate.indexed.depth3.targetTransitions;
  exact(
    certificate.indexed.depth3.recordedLeafCalls,
    (certificate.indexed.depth3.setupTransitions +
      certificate.indexed.depth3.targetTransitions) * 3,
    'depth-4 certificate.indexed.depth3.recordedLeafCalls',
  );
  exact(
    certificate.indexed.depth3.recordedNodeCalls,
    (certificate.indexed.depth3.setupTransitions +
      certificate.indexed.depth3.targetTransitions) * 16,
    'depth-4 certificate.indexed.depth3.recordedNodeCalls',
  );
  exact(
    certificate.indexed.recordedLeafCalls,
    expectedRecordedTransitions * 3,
    'depth-4 certificate.indexed.recordedLeafCalls',
  );
  exact(
    certificate.indexed.recordedNodeCalls,
    expectedRecordedTransitions * 16,
    'depth-4 certificate.indexed.recordedNodeCalls',
  );
  sha256(certificate.indexed.controlTraceDigestSha256, 'depth-4 certificate.indexed.controlTraceDigestSha256');
  array(certificate.indexed.classBreakdown, 'depth-4 certificate.indexed.classBreakdown', 14);
  certificate.indexed.classBreakdown.forEach((entry, normalCount) => {
    const label = `depth-4 certificate.indexed.classBreakdown[${normalCount}]`;
    exactKeys(entry, label, [
      'normalCount',
      'classes',
      'setupTransitions',
      'targetTransitions',
      'nonlocalPermutationClasses',
      'nonlocalPermutationSetupTransitions',
      'nonlocalPermutationTargetTransitions',
      'duplicateAttempts',
      'semanticDuplicateRejections',
      'terminalCapacityPrecedenceRejections',
    ]);
    exact(entry.normalCount, normalCount, `${label}.normalCount`);
    exact(entry.classes, expectedClasses[normalCount], `${label}.classes`);
    exact(entry.setupTransitions, expectedSetupTransitions[normalCount], `${label}.setupTransitions`);
    exact(entry.targetTransitions, expectedClasses[normalCount], `${label}.targetTransitions`);
    exact(
      entry.nonlocalPermutationClasses,
      expectedNonlocalPermutationClasses[normalCount],
      `${label}.nonlocalPermutationClasses`,
    );
    exact(
      entry.nonlocalPermutationSetupTransitions,
      expectedNonlocalPermutationSetupTransitions[normalCount],
      `${label}.nonlocalPermutationSetupTransitions`,
    );
    exact(
      entry.nonlocalPermutationTargetTransitions,
      expectedNonlocalPermutationClasses[normalCount],
      `${label}.nonlocalPermutationTargetTransitions`,
    );
    exact(entry.duplicateAttempts, expectedClasses[normalCount], `${label}.duplicateAttempts`);
    exact(
      entry.semanticDuplicateRejections,
      normalCount === 13 ? 0 : expectedClasses[normalCount],
      `${label}.semanticDuplicateRejections`,
    );
    exact(
      entry.terminalCapacityPrecedenceRejections,
      normalCount === 13 ? expectedClasses[normalCount] : 0,
      `${label}.terminalCapacityPrecedenceRejections`,
    );
  });
  exactKeys(certificate.symbolic, 'depth-4 certificate.symbolic', [
    'certificate',
    'verification',
  ]);
  exact(
    certificate.symbolic.certificate.schema,
    Q04_DEPTH4_SYMBOLIC_CERTIFICATE_SCHEMA,
    'depth-4 certificate.symbolic.certificate.schema',
  );
  let replayedSymbolicVerification;
  try {
    replayedSymbolicVerification = verifyDepth4SymbolicCertificate(
      certificate.symbolic.certificate,
    );
  } catch (error) {
    fail(
      `depth-4 symbolic certificate replay failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (
    JSON.stringify(certificate.symbolic.verification) !==
      JSON.stringify(replayedSymbolicVerification)
  ) fail('depth-4 symbolic verification summary differs from fresh replay');
  exactKeys(certificate.hashes, 'depth-4 certificate.hashes', [
    'comparisons',
    'discrepancies',
    'independentLeafCacheEntries',
    'independentNodeCacheEntries',
    'digestSha256',
  ]);
  exact(
    certificate.hashes.comparisons,
    certificate.occupancy.subtreeHashComparisons +
      certificate.occupancy.leafStateHashesChecked +
      certificate.indexed.recordedLeafCalls +
      certificate.indexed.recordedNodeCalls,
    'depth-4 certificate.hashes.comparisons',
  );
  exact(certificate.hashes.discrepancies, 0, 'depth-4 certificate.hashes.discrepancies');
  positiveInteger(
    certificate.hashes.independentLeafCacheEntries,
    'depth-4 certificate.hashes.independentLeafCacheEntries',
  );
  positiveInteger(
    certificate.hashes.independentNodeCacheEntries,
    'depth-4 certificate.hashes.independentNodeCacheEntries',
  );
  sha256(certificate.hashes.digestSha256, 'depth-4 certificate.hashes.digestSha256');
  exactKeys(certificate.oracle, 'depth-4 certificate.oracle', [
    'implementation',
    'parameterSourcePath',
    'parameterSourceSha256',
    'supportedArities',
  ]);
  exact(
    certificate.oracle.implementation,
    implementations.primaryJsOracle.poseidonImplementation,
    'depth-4 certificate.oracle.implementation',
  );
  parameterSourcePath(
    certificate.oracle.parameterSourcePath,
    'depth-4 certificate.oracle.parameterSourcePath',
  );
  exact(
    certificate.oracle.parameterSourceSha256,
    implementations.primaryJsOracle.parameterSourceSha256,
    'depth-4 certificate.oracle.parameterSourceSha256',
  );
  array(certificate.oracle.supportedArities, 'depth-4 certificate.oracle.supportedArities', 3);
  [2, 3, 6].forEach((arity, index) =>
    exact(certificate.oracle.supportedArities[index], arity, `depth-4 certificate.oracle.supportedArities[${index}]`)
  );
  exact(certificate.discrepancies, 0, 'depth-4 certificate.discrepancies');
  nonnegativeNumber(certificate.elapsedMs, 'depth-4 certificate.elapsedMs');
  sha256(certificate.evidenceDigestSha256, 'depth-4 certificate.evidenceDigestSha256');
  exact(depth4.productionQualification, true, 'depth4.productionQualification');
  return Object.freeze({
    status: Q04_DEPTH4_STATUS,
    scope: depth4.scope,
    productionPoseidon: certificate.claims.productionPoseidon,
    independentPoseidonImplementation:
      certificate.claims.independentPoseidonImplementation,
    authenticatedOccupancyStates: certificate.occupancy.statesChecked,
    indexedControlSkeletons: certificate.indexed.classes,
    indexedControlSkeletonsAreStateQuotient: false,
    pairedNumericEmbeddingsUseSharedSqlite: true,
    nonlocalRankPermutationClasses:
      certificate.indexed.nonlocalPermutationClasses,
    sqliteScheduleLanes: certificate.indexed.sqliteScheduleLanes,
    durableReopenChecks:
      certificate.indexed.durableReopenChecks +
      certificate.indexed.depth3.durableReopenChecks,
    sharedKernelSymbolicTemplatesVerified: true,
    sharedKernelSymbolicFormalTheorem: false,
    externalProofCheckerRequired: true,
    externalProofCheckerVerified: true,
    representedConcreteRankStateGapTransitions:
      replayedSymbolicVerification
        .representedConcreteRankStateGapTransitions,
    exhaustiveOverBn254Field: certificate.claims.exhaustiveOverBn254Field,
    enumeratesAllDepth4IndexedHistories:
      certificate.claims.enumeratesAllDepth4IndexedHistories,
    productionKernelEquivalenceProved: false,
    productionQualification: true,
  });
}

function u32be(value) {
  const output = Buffer.alloc(4);
  output.writeUInt32BE(value);
  return output;
}

function u64be(value) {
  const output = Buffer.alloc(8);
  output.writeBigUInt64BE(BigInt(value));
  return output;
}

const encodedFrBytes = (value) =>
  Buffer.from(value.toString(16).padStart(64, '0'), 'hex');
const bufferHex = (value) => Buffer.from(value).toString('hex');

function independentPathDigest(values) {
  const digest = createHash('sha256')
    .update(PATH_DIGEST_DOMAIN, 'ascii')
    .update(u32be(values.length));
  for (const value of values) digest.update(encodedFrBytes(value));
  return digest.digest('hex');
}

function independentTransitionDigest(ordinal, keyHex, transition) {
  const digest = createHash('sha256')
    .update(STORE_TRANSITION_DOMAIN, 'ascii')
    .update(u32be(ordinal))
    .update(Buffer.from(keyHex, 'hex'))
    .update(encodedFrBytes(transition.preRoot))
    .update(encodedFrBytes(transition.intermediateRoot))
    .update(encodedFrBytes(transition.postRoot))
    .update(u32be(transition.predecessor.index))
    .update(Buffer.from(transition.predecessor.key, 'hex'))
    .update(u32be(transition.predecessor.successorIndex))
    .update(Buffer.from(transition.predecessor.successorKey, 'hex'))
    .update(u32be(transition.append.index));
  for (const value of transition.predecessorPath) {
    digest.update(encodedFrBytes(value));
  }
  for (const value of transition.append.emptyPath) {
    digest.update(encodedFrBytes(value));
  }
  return digest.digest();
}

function createIndependentHistoryReplay({
  historyIndex,
  oracle,
}) {
  const tree = createIndependentIndexedNullifierTree({ oracle });
  let transcript = createHash('sha256')
    .update(STORE_INITIAL_DOMAIN, 'ascii')
    .update(u32be(historyIndex))
    .update(Buffer.from(Q04_FIXED_SEEDS[historyIndex], 'hex'))
    .digest();
  return freeze({
    insert(ordinal, keyHex) {
      const transition = tree.insert(Buffer.from(keyHex, 'hex'));
      const transitionDigest = independentTransitionDigest(
        ordinal,
        keyHex,
        transition,
      );
      transcript = createHash('sha256')
        .update(transcript)
        .update(transitionDigest)
        .digest();
      return freeze({
        preRoot: encodeFr(transition.preRoot),
        intermediateRoot: encodeFr(transition.intermediateRoot),
        postRoot: encodeFr(transition.postRoot),
        pathDigests: freeze({
          predecessorPathSha256:
            independentPathDigest(transition.predecessorPath),
          emptyAppendPathSha256:
            independentPathDigest(transition.append.emptyPath),
          postMembershipPathSha256:
            independentPathDigest(transition.postMembershipPath),
        }),
        transitionDigestSha256: transitionDigest.toString('hex'),
        transcriptChainSha256: transcript.toString('hex'),
        operationCounts: transition.metrics,
      });
    },
  });
}

function edgeValue(historyIndex, ordinal) {
  const schedule = Q04_EDGE_SCHEDULE[historyIndex];
  if (ordinal === schedule.zeroOrdinal) return 0n;
  if (ordinal === schedule.frMinusOneOrdinal) return FR_MINUS_ONE;
  return null;
}

function createHistoryKeyDeriver(historyIndex) {
  safeInteger(historyIndex, 'history index');
  if (historyIndex >= HISTORY_COUNT) fail('history index is outside Q-04 range');
  const seed = Buffer.from(Q04_FIXED_SEEDS[historyIndex], 'hex');
  const seen = new Set();
  return (ordinal) => {
    let selected = edgeValue(historyIndex, ordinal);
    if (selected === null) {
      for (let attempt = 0; attempt <= 0xffff_ffff; attempt += 1) {
        const digest = createHash('sha256')
          .update(KEY_DOMAIN, 'ascii')
          .update(seed)
          .update(u64be(ordinal))
          .update(u32be(attempt))
          .digest();
        const candidate = BigInt(`0x${digest.toString('hex')}`);
        if (candidate < FR_MODULUS && candidate !== 0n && candidate !== FR_MINUS_ONE && !seen.has(candidate.toString())) {
          selected = candidate;
          break;
        }
      }
    }
    if (selected === null || seen.has(selected.toString())) fail(`Q-04 key derivation failed at history ${historyIndex} ordinal ${ordinal}`);
    seen.add(selected.toString());
    return encodeFr(selected);
  };
}

export function deriveQ04HistoryKeyHexes(historyIndex, entryCount = ENTRIES_PER_HISTORY) {
  safeInteger(entryCount, 'entry count', { minimum: 1 });
  if (entryCount > ENTRIES_PER_HISTORY) fail('entry count exceeds the Q-04 history bound');
  const derive = createHistoryKeyDeriver(historyIndex);
  return Object.freeze(Array.from({ length: entryCount }, (_, index) => derive(index + 1)));
}

function validateActualMeasurement(value, label) {
  exactKeys(value, label, [
    'wallMicros',
    'userCpuMicros',
    'systemCpuMicros',
    'voluntaryContextSwitches',
    'involuntaryContextSwitches',
    'fsReadOps',
    'fsWriteOps',
    'rssBytes',
  ]);
  nonnegativeNumber(value.wallMicros, `${label}.wallMicros`);
  for (const field of ['userCpuMicros', 'systemCpuMicros', 'voluntaryContextSwitches', 'involuntaryContextSwitches', 'fsReadOps', 'fsWriteOps']) {
    safeInteger(value[field], `${label}.${field}`);
  }
  positiveInteger(value.rssBytes, `${label}.rssBytes`);
}

function validateOracleMeasurement(value, label) {
  exactKeys(value, label, [
    'wallMicros',
    'userCpuMicros',
    'systemCpuMicros',
    'voluntaryContextSwitches',
    'involuntaryContextSwitches',
    'rssBytes',
  ]);
  nonnegativeNumber(value.wallMicros, `${label}.wallMicros`);
  for (const field of ['userCpuMicros', 'systemCpuMicros', 'voluntaryContextSwitches', 'involuntaryContextSwitches']) {
    safeInteger(value[field], `${label}.${field}`);
  }
  positiveInteger(value.rssBytes, `${label}.rssBytes`);
}

function validateTransitionRecord(record, historyIndex, ordinal, expectedKey) {
  const label = `history ${historyIndex} transition ${ordinal}`;
  exactKeys(record, label, [
    'schema',
    'historyIndex',
    'ordinal',
    'key',
    'preRoot',
    'intermediateRoot',
    'postRoot',
    'pathDigests',
    'actual',
    'oracle',
    'discrepancies',
  ]);
  exact(record.schema, Q04_TRANSITION_SCHEMA, `${label}.schema`);
  exact(record.historyIndex, historyIndex, `${label}.historyIndex`);
  exact(record.ordinal, ordinal, `${label}.ordinal`);
  exact(record.key, expectedKey, `${label}.key`);
  frElement(record.preRoot, `${label}.preRoot`);
  frElement(record.intermediateRoot, `${label}.intermediateRoot`);
  frElement(record.postRoot, `${label}.postRoot`);
  exactKeys(record.pathDigests, `${label}.pathDigests`, ['predecessorPathSha256', 'emptyAppendPathSha256', 'postMembershipPathSha256']);
  for (const field of Object.keys(record.pathDigests)) sha256(record.pathDigests[field], `${label}.pathDigests.${field}`);
  exactKeys(record.actual, `${label}.actual`, ['transitionDigestSha256', 'transcriptChainSha256', 'operationCounts', 'measurement']);
  sha256(record.actual.transitionDigestSha256, `${label}.actual.transitionDigestSha256`);
  sha256(record.actual.transcriptChainSha256, `${label}.actual.transcriptChainSha256`);
  exactKeys(record.actual.operationCounts, `${label}.actual.operationCounts`, [
    'productionLeafHashCalls',
    'productionPredecessorValidationLeafHashCalls',
    'productionMutationLeafHashCalls',
    'productionMutationNodeHashCalls',
    'productionLogicalPathSiblingLookups',
    'productionPathOverrideHits',
    'productionPathAdapterNodeReads',
    'productionRootAdapterNodeReads',
    'productionTotalAdapterNodeReads',
    'productionLeafReads',
    'productionOrderLookups',
    'productionPostMembershipNodeHashCalls',
    'productionPostMembershipNodeReads',
  ]);
  exact(record.actual.operationCounts.productionLeafHashCalls, 3, `${label}.actual.operationCounts.productionLeafHashCalls`);
  exact(record.actual.operationCounts.productionPredecessorValidationLeafHashCalls, 1, `${label}.actual.operationCounts.productionPredecessorValidationLeafHashCalls`);
  exact(record.actual.operationCounts.productionMutationLeafHashCalls, 2, `${label}.actual.operationCounts.productionMutationLeafHashCalls`);
  exact(
    record.actual.operationCounts.productionLeafHashCalls,
    record.actual.operationCounts.productionPredecessorValidationLeafHashCalls
      + record.actual.operationCounts.productionMutationLeafHashCalls,
    `${label}.actual.operationCounts.productionLeafHashCalls components`,
  );
  exact(record.actual.operationCounts.productionMutationNodeHashCalls, 128, `${label}.actual.operationCounts.productionMutationNodeHashCalls`);
  exact(record.actual.operationCounts.productionLogicalPathSiblingLookups, 64, `${label}.actual.operationCounts.productionLogicalPathSiblingLookups`);
  exact(record.actual.operationCounts.productionPathOverrideHits, 1, `${label}.actual.operationCounts.productionPathOverrideHits`);
  exact(record.actual.operationCounts.productionPathAdapterNodeReads, 63, `${label}.actual.operationCounts.productionPathAdapterNodeReads`);
  exact(record.actual.operationCounts.productionRootAdapterNodeReads, 1, `${label}.actual.operationCounts.productionRootAdapterNodeReads`);
  exact(record.actual.operationCounts.productionTotalAdapterNodeReads, 64, `${label}.actual.operationCounts.productionTotalAdapterNodeReads`);
  exact(
    record.actual.operationCounts.productionTotalAdapterNodeReads,
    record.actual.operationCounts.productionPathAdapterNodeReads
      + record.actual.operationCounts.productionRootAdapterNodeReads,
    `${label}.actual.operationCounts.productionTotalAdapterNodeReads components`,
  );
  exact(record.actual.operationCounts.productionLeafReads, 2, `${label}.actual.operationCounts.productionLeafReads`);
  exact(record.actual.operationCounts.productionOrderLookups, 2, `${label}.actual.operationCounts.productionOrderLookups`);
  exact(record.actual.operationCounts.productionPostMembershipNodeHashCalls, 32, `${label}.actual.operationCounts.productionPostMembershipNodeHashCalls`);
  exact(record.actual.operationCounts.productionPostMembershipNodeReads, 32, `${label}.actual.operationCounts.productionPostMembershipNodeReads`);
  validateActualMeasurement(record.actual.measurement, `${label}.actual.measurement`);
  exactKeys(record.oracle, `${label}.oracle`, ['transitionDigestSha256', 'transcriptChainSha256', 'operationCounts', 'measurement']);
  sha256(record.oracle.transitionDigestSha256, `${label}.oracle.transitionDigestSha256`);
  sha256(record.oracle.transcriptChainSha256, `${label}.oracle.transcriptChainSha256`);
  exact(record.oracle.transitionDigestSha256, record.actual.transitionDigestSha256, `${label}.oracle.transitionDigestSha256`);
  exact(record.oracle.transcriptChainSha256, record.actual.transcriptChainSha256, `${label}.oracle.transcriptChainSha256`);
  exactKeys(record.oracle.operationCounts, `${label}.oracle.operationCounts`, ['leafHashCalls', 'nodeHashCalls', 'membershipPathComputations', 'stateUpdatePaths', 'treeDepth']);
  exact(record.oracle.operationCounts.leafHashCalls, 2, `${label}.oracle.operationCounts.leafHashCalls`);
  exact(record.oracle.operationCounts.nodeHashCalls, 160, `${label}.oracle.operationCounts.nodeHashCalls`);
  exact(record.oracle.operationCounts.membershipPathComputations, 3, `${label}.oracle.operationCounts.membershipPathComputations`);
  exact(record.oracle.operationCounts.stateUpdatePaths, 2, `${label}.oracle.operationCounts.stateUpdatePaths`);
  exact(record.oracle.operationCounts.treeDepth, 32, `${label}.oracle.operationCounts.treeDepth`);
  validateOracleMeasurement(record.oracle.measurement, `${label}.oracle.measurement`);
  exact(record.discrepancies, 0, `${label}.discrepancies`);
}

const EMPTY_DERIVED_TOTALS = Object.freeze({
  productionLeafHashCalls: 0,
  productionPredecessorValidationLeafHashCalls: 0,
  productionMutationLeafHashCalls: 0,
  productionMutationNodeHashCalls: 0,
  productionLogicalPathSiblingLookups: 0,
  productionPathOverrideHits: 0,
  productionPathAdapterNodeReads: 0,
  productionRootAdapterNodeReads: 0,
  productionTotalAdapterNodeReads: 0,
  productionLeafReads: 0,
  productionOrderLookups: 0,
  productionPostMembershipNodeHashCalls: 0,
  productionPostMembershipNodeReads: 0,
  primaryOracleLeafHashCalls: 0,
  primaryOracleNodeHashCalls: 0,
  primaryOracleMembershipPathComputations: 0,
  primaryOracleStateUpdatePaths: 0,
  checkpointWriterReopenCycles: 0,
  writerProcessCloses: 0,
  reopenWorkerProcessCloses: 0,
  productionReplayAcceptedInsertions: 0,
  productionReplayCheckpointProbes: 0,
  productionReplayReopenCycles: 0,
});

async function verifyHistoryNdjson(
  bundleRoot,
  evidencePath,
  reference,
  history,
  oracle,
) {
  const filename = resolveReference(bundleRoot, evidencePath, reference);
  const metadata = await canonicalRegularFile(filename, `${reference.label} artifact`);
  if (metadata.size !== reference.bytes) fail(`${reference.label} byte length does not match the referenced artifact`);
  const replayParent = mkdtempSync(
    path.join(tmpdir(), `shieldkit-q04-verify-h${reference.historyIndex}-`),
  );
  chmodSync(replayParent, 0o700);
  const replayPath = path.join(replayParent, 'production.sqlite');
  const replaySeed = Buffer.from(
    Q04_FIXED_SEEDS[reference.historyIndex],
    'hex',
  );
  let productionStore = null;
  try {
    productionStore = openQ04PersistentNullifierStore({
      path: replayPath,
      create: true,
      historyIndex: reference.historyIndex,
      seed: replaySeed,
    });
  const digest = createHash('sha256');
  const stream = createReadStream(filename);
  stream.on('data', (chunk) => digest.update(chunk));
  const lines = createInterface({ input: stream, crlfDelay: Infinity });
  const deriveKey = createHistoryKeyDeriver(reference.historyIndex);
  const inputTranscript = createHash('sha256')
    .update(INPUT_TRANSCRIPT_DOMAIN, 'ascii')
    .update(Buffer.from(Q04_FIXED_SEEDS[reference.historyIndex], 'hex'));
  const independentReplay = createIndependentHistoryReplay({
    historyIndex: reference.historyIndex,
    oracle,
  });
  const totals = { ...EMPTY_DERIVED_TOTALS };
  let records = 0;
  let previousPostRoot = null;
  let finalRecord = null;
  try {
    for await (const line of lines) {
      if (line.length === 0) fail(`${reference.label} contains an empty NDJSON record`);
      if (line.includes('\ufffd') || Buffer.byteLength(line, 'utf8') > MAX_NDJSON_LINE_BYTES) {
        fail(`${reference.label} contains invalid UTF-8 or an oversized NDJSON record`);
      }
      records += 1;
      if (records > ENTRIES_PER_HISTORY) fail(`${reference.label} contains more than ${ENTRIES_PER_HISTORY} records`);
      let record;
      try {
        record = parseStrictJson(Buffer.from(line, 'utf8'));
      } catch (error) {
        fail(`${reference.label} record ${records} is invalid strict JSON: ${error instanceof Error ? error.message : String(error)}`);
      }
      const expectedKey = deriveKey(records);
      inputTranscript.update(Buffer.from(expectedKey, 'hex'));
      validateTransitionRecord(record, reference.historyIndex, records, expectedKey);
      const replayed = independentReplay.insert(records, expectedKey);
      for (const field of ['preRoot', 'intermediateRoot', 'postRoot']) {
        exact(
          record[field],
          replayed[field],
          `history ${reference.historyIndex} transition ${records}.${field} independent replay`,
        );
      }
      for (const field of Object.keys(replayed.pathDigests)) {
        exact(
          record.pathDigests[field],
          replayed.pathDigests[field],
          `history ${reference.historyIndex} transition ${records}.pathDigests.${field} independent replay`,
        );
      }
      exact(
        record.actual.transitionDigestSha256,
        replayed.transitionDigestSha256,
        `history ${reference.historyIndex} transition ${records}.actual.transitionDigestSha256 independent replay`,
      );
      exact(
        record.oracle.transitionDigestSha256,
        replayed.transitionDigestSha256,
        `history ${reference.historyIndex} transition ${records}.oracle.transitionDigestSha256 independent replay`,
      );
      exact(
        record.actual.transcriptChainSha256,
        replayed.transcriptChainSha256,
        `history ${reference.historyIndex} transition ${records}.actual.transcriptChainSha256`,
      );
      exact(
        record.oracle.transcriptChainSha256,
        replayed.transcriptChainSha256,
        `history ${reference.historyIndex} transition ${records}.oracle.transcriptChainSha256`,
      );
      exact(
        record.oracle.operationCounts.leafHashCalls,
        replayed.operationCounts.leafHashCalls,
        `history ${reference.historyIndex} transition ${records}.oracle.operationCounts.leafHashCalls independent replay`,
      );
      exact(
        record.oracle.operationCounts.nodeHashCalls,
        replayed.operationCounts.nodeHashCalls,
        `history ${reference.historyIndex} transition ${records}.oracle.operationCounts.nodeHashCalls independent replay`,
      );
      exact(
        record.oracle.operationCounts.membershipPathComputations,
        replayed.operationCounts.membershipPathComputations,
        `history ${reference.historyIndex} transition ${records}.oracle.operationCounts.membershipPathComputations independent replay`,
      );
      exact(
        record.oracle.operationCounts.stateUpdatePaths,
        replayed.operationCounts.stateUpdatePaths,
        `history ${reference.historyIndex} transition ${records}.oracle.operationCounts.stateUpdatePaths independent replay`,
      );
      exact(
        record.oracle.operationCounts.treeDepth,
        replayed.operationCounts.treeDepth,
        `history ${reference.historyIndex} transition ${records}.oracle.operationCounts.treeDepth independent replay`,
      );
      const productionBefore = productionStore.state();
      const productionInputKey = Buffer.from(expectedKey, 'hex');
      const productionExpectedRoot = Buffer.from(productionBefore.root);
      const production = productionStore.insert({
        expectedCount: productionBefore.normalCount,
        expectedRoot: productionExpectedRoot,
        key: productionInputKey,
      });
      const productionMembership = productionStore.membershipPath(
        production.mutation.witness.append.index,
      );
      const productionLabel =
        `history ${reference.historyIndex} transition ${records} production replay`;
      exact(
        bufferHex(production.mutation.witness.preRoot),
        record.preRoot,
        `${productionLabel}.preRoot`,
      );
      exact(
        bufferHex(production.mutation.witness.intermediateRoot),
        record.intermediateRoot,
        `${productionLabel}.intermediateRoot`,
      );
      exact(
        bufferHex(production.mutation.witness.postRoot),
        record.postRoot,
        `${productionLabel}.postRoot`,
      );
      exact(
        independentPathDigest(
          production.mutation.witness.predecessorPath,
        ),
        record.pathDigests.predecessorPathSha256,
        `${productionLabel}.predecessorPathSha256`,
      );
      exact(
        independentPathDigest(production.mutation.witness.append.path),
        record.pathDigests.emptyAppendPathSha256,
        `${productionLabel}.emptyAppendPathSha256`,
      );
      exact(
        independentPathDigest(productionMembership.siblings),
        record.pathDigests.postMembershipPathSha256,
        `${productionLabel}.postMembershipPathSha256`,
      );
      exact(
        production.transitionDigestSha256,
        record.actual.transitionDigestSha256,
        `${productionLabel}.transitionDigestSha256`,
      );
      exact(
        production.transcriptChainSha256,
        record.actual.transcriptChainSha256,
        `${productionLabel}.transcriptChainSha256`,
      );
      exact(
        production.mutation.metrics.leafHashCalls,
        record.actual.operationCounts.productionLeafHashCalls,
        `${productionLabel}.leafHashCalls`,
      );
      exact(
        production.mutation.metrics.nodeHashCalls,
        record.actual.operationCounts.productionMutationNodeHashCalls,
        `${productionLabel}.nodeHashCalls`,
      );
      exact(
        production.mutation.metrics.nodeReads,
        record.actual.operationCounts.productionTotalAdapterNodeReads,
        `${productionLabel}.nodeReads`,
      );
      exact(
        productionMembership.metrics.nodeHashCalls,
        record.actual.operationCounts.productionPostMembershipNodeHashCalls,
        `${productionLabel}.postMembershipNodeHashCalls`,
      );
      totals.productionReplayAcceptedInsertions += 1;
      if (previousPostRoot !== null) exact(record.preRoot, previousPostRoot, `history ${reference.historyIndex} transition ${records}.preRoot`);
      previousPostRoot = record.postRoot;
      if (records % CHECKPOINT_INTERVAL === 0) {
        const checkpoint = history.checkpoints[(records / CHECKPOINT_INTERVAL) - 1];
        exact(record.postRoot, checkpoint.actualRoot, `history ${reference.historyIndex} checkpoint ${records}.actualRoot`);
        exact(record.postRoot, checkpoint.oracleRoot, `history ${reference.historyIndex} checkpoint ${records}.oracleRoot`);
        exact(record.actual.transcriptChainSha256, checkpoint.actualTranscriptSha256, `history ${reference.historyIndex} checkpoint ${records}.actualTranscriptSha256`);
        exact(record.oracle.transcriptChainSha256, checkpoint.oracleTranscriptSha256, `history ${reference.historyIndex} checkpoint ${records}.oracleTranscriptSha256`);
        const appendedIndex = production.mutation.witness.append.index;
        const lastKey = Buffer.from(expectedKey, 'hex');
        const aliasEvidence = {
          inputKey: productionInputKey,
          expectedRootInput: productionExpectedRoot,
          stateRootResult: productionBefore.root,
          writeRootResult: production.writes.root,
          mutationLeafKeyResult:
            production.mutation.nullifierLeaves.at(-1).key,
          membershipRootResult: productionMembership.root,
        };
        Object.values(aliasEvidence).forEach((buffer) => buffer.fill(0xff));
        const afterAlias = productionStore.audit();
        exact(
          bufferHex(productionStore.leaf(appendedIndex).key),
          expectedKey,
          `history ${reference.historyIndex} checkpoint ${records} alias leaf`,
        );
        exact(
          bufferHex(afterAlias.root),
          record.postRoot,
          `history ${reference.historyIndex} checkpoint ${records} alias root`,
        );
        const replayedProbes = runQ04CheckpointProbes({
          store: productionStore,
          lastKey,
          aliasEvidence,
        });
        if (JSON.stringify(replayedProbes) !== JSON.stringify(checkpoint.probes)) {
          fail(
            `history ${reference.historyIndex} checkpoint ${records} ` +
              'production probe replay differs',
          );
        }
        totals.productionReplayCheckpointProbes += replayedProbes.length;
        const beforeReopenState = productionStore.state();
        const beforeReopenAudit = productionStore.audit();
        exact(
          bufferHex(beforeReopenState.root),
          checkpoint.actualRoot,
          `history ${reference.historyIndex} checkpoint ${records} replay root`,
        );
        exact(
          bufferHex(beforeReopenState.transcriptChainSha256),
          checkpoint.actualTranscriptSha256,
          `history ${reference.historyIndex} checkpoint ${records} replay transcript`,
        );
        exact(
          beforeReopenAudit.logicalDigestSha256,
          checkpoint.logicalStoreSha256,
          `history ${reference.historyIndex} checkpoint ${records} replay logical store`,
        );
        productionStore.close();
        productionStore = openQ04PersistentNullifierStore({
          path: replayPath,
          create: false,
          historyIndex: reference.historyIndex,
          seed: replaySeed,
        });
        const afterReopenState = productionStore.state();
        const afterReopenAudit = productionStore.audit();
        exact(
          bufferHex(afterReopenState.root),
          bufferHex(beforeReopenState.root),
          `history ${reference.historyIndex} checkpoint ${records} reopened root`,
        );
        exact(
          bufferHex(afterReopenState.transcriptChainSha256),
          bufferHex(beforeReopenState.transcriptChainSha256),
          `history ${reference.historyIndex} checkpoint ${records} reopened transcript`,
        );
        exact(
          afterReopenAudit.logicalDigestSha256,
          beforeReopenAudit.logicalDigestSha256,
          `history ${reference.historyIndex} checkpoint ${records} reopened logical store`,
        );
        totals.productionReplayReopenCycles += 1;
      }
      totals.productionLeafHashCalls += record.actual.operationCounts.productionLeafHashCalls;
      totals.productionPredecessorValidationLeafHashCalls += record.actual.operationCounts.productionPredecessorValidationLeafHashCalls;
      totals.productionMutationLeafHashCalls += record.actual.operationCounts.productionMutationLeafHashCalls;
      totals.productionMutationNodeHashCalls += record.actual.operationCounts.productionMutationNodeHashCalls;
      totals.productionLogicalPathSiblingLookups += record.actual.operationCounts.productionLogicalPathSiblingLookups;
      totals.productionPathOverrideHits += record.actual.operationCounts.productionPathOverrideHits;
      totals.productionPathAdapterNodeReads += record.actual.operationCounts.productionPathAdapterNodeReads;
      totals.productionRootAdapterNodeReads += record.actual.operationCounts.productionRootAdapterNodeReads;
      totals.productionTotalAdapterNodeReads += record.actual.operationCounts.productionTotalAdapterNodeReads;
      totals.productionLeafReads += record.actual.operationCounts.productionLeafReads;
      totals.productionOrderLookups += record.actual.operationCounts.productionOrderLookups;
      totals.productionPostMembershipNodeHashCalls += record.actual.operationCounts.productionPostMembershipNodeHashCalls;
      totals.productionPostMembershipNodeReads += record.actual.operationCounts.productionPostMembershipNodeReads;
      totals.primaryOracleLeafHashCalls += record.oracle.operationCounts.leafHashCalls;
      totals.primaryOracleNodeHashCalls += record.oracle.operationCounts.nodeHashCalls;
      totals.primaryOracleMembershipPathComputations +=
        record.oracle.operationCounts.membershipPathComputations;
      totals.primaryOracleStateUpdatePaths +=
        record.oracle.operationCounts.stateUpdatePaths;
      finalRecord = record;
    }
  } catch (error) {
    stream.destroy();
    if (error instanceof V2Q04EvidenceVerificationError) throw error;
    fail(`${reference.label} cannot be streamed: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (records !== ENTRIES_PER_HISTORY) fail(`${reference.label} must contain exactly ${ENTRIES_PER_HISTORY} records`);
  const observedHash = digest.digest('hex');
  if (observedHash !== reference.sha256) fail(`${reference.label} SHA-256 does not match the referenced artifact`);
  exact(inputTranscript.digest('hex'), history.inputTranscriptSha256, `histories[${reference.historyIndex}].inputTranscriptSha256`);
  exact(finalRecord.postRoot, history.finalActualRoot, `histories[${reference.historyIndex}].finalActualRoot`);
  exact(finalRecord.postRoot, history.finalOracleRoot, `histories[${reference.historyIndex}].finalOracleRoot`);
  exact(finalRecord.actual.transcriptChainSha256, history.actualTranscriptSha256, `histories[${reference.historyIndex}].actualTranscriptSha256`);
  exact(finalRecord.oracle.transcriptChainSha256, history.oracleTranscriptSha256, `histories[${reference.historyIndex}].oracleTranscriptSha256`);
  totals.checkpointWriterReopenCycles = history.checkpoints.length;
  totals.writerProcessCloses = history.checkpoints.filter((checkpoint) => checkpoint.closeExitCode === 0).length;
  totals.reopenWorkerProcessCloses = history.checkpoints.filter((checkpoint) => checkpoint.reopenExitCode === 0).length;
    return Object.freeze(totals);
  } finally {
    if (productionStore !== null) productionStore.close();
    rmSync(replayParent, { recursive: true, force: false });
  }
}

function combineDerivedTotals(items) {
  const combined = { ...EMPTY_DERIVED_TOTALS };
  for (const item of items) {
    for (const field of Object.keys(combined)) combined[field] += item[field];
  }
  return Object.freeze({
    ...combined,
    insertionAndPostMembershipNodeHashCalls:
      combined.productionMutationNodeHashCalls
      + combined.productionPostMembershipNodeHashCalls,
  });
}

function verifyDerivedTotals(totals, operationCounts) {
  for (const field of [
    'productionLeafHashCalls',
    'productionPredecessorValidationLeafHashCalls',
    'productionMutationLeafHashCalls',
    'productionMutationNodeHashCalls',
    'productionLogicalPathSiblingLookups',
    'productionPathOverrideHits',
    'productionPathAdapterNodeReads',
    'productionRootAdapterNodeReads',
    'productionTotalAdapterNodeReads',
    'productionLeafReads',
    'productionOrderLookups',
    'productionPostMembershipNodeHashCalls',
    'productionPostMembershipNodeReads',
    'insertionAndPostMembershipNodeHashCalls',
    'primaryOracleLeafHashCalls',
    'primaryOracleNodeHashCalls',
    'primaryOracleMembershipPathComputations',
    'primaryOracleStateUpdatePaths',
    'checkpointWriterReopenCycles',
    'writerProcessCloses',
    'reopenWorkerProcessCloses',
  ]) {
    exact(totals[field], operationCounts[field], `derived operationCounts.${field}`);
  }
  exact(
    totals.productionReplayAcceptedInsertions,
    TOTAL_ENTRIES,
    'production replay accepted insertions',
  );
  exact(
    totals.productionReplayCheckpointProbes,
    TOTAL_PROBES,
    'production replay checkpoint probes',
  );
  exact(
    totals.productionReplayReopenCycles,
    TOTAL_CHECKPOINTS,
    'production replay reopen cycles',
  );
}

export function parseQ04EvidenceArguments(argv) {
  if (!Array.isArray(argv) || argv.length !== 1) {
    fail('usage: node v2-q04-evidence-verify.mjs /absolute/path/to/evidence.json');
  }
  return canonicalAbsolutePath(argv[0], 'evidence JSON path');
}

export async function verifyQ04EvidenceFile(filename) {
  canonicalAbsolutePath(filename, 'evidence JSON path');
  const metadata = await canonicalRegularFile(filename, 'evidence JSON', { maximumBytes: MAX_EVIDENCE_BYTES });
  let evidence;
  try {
    evidence = parseStrictJson(await readFile(filename));
  } catch (error) {
    fail(`evidence JSON is invalid: ${error instanceof Error ? error.message : String(error)}`);
  }
  const validated = validateDocument(evidence);
  const bundleRoot = path.dirname(filename);
  await verifyStaticReferences(bundleRoot, filename, validated.references);
  const parameterSourcePath = resolveReference(
    bundleRoot,
    filename,
    validated.parameterSourceReference,
  );
  let independentOracle;
  try {
    independentOracle = createIndependentPoseidonOracle({
      parameterSourcePath,
    });
  } catch (error) {
    fail(
      `independent Poseidon replay cannot initialize: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  validateRustKatResult(await strictReferencedJson(bundleRoot, filename, validated.rustResultReference, 'Rust KAT result'));
  const campaignProcesses = await strictReferencedJson(
    bundleRoot,
    filename,
    validated.rawOutputReference,
    'campaign process transcript',
  );
  const depth4Certificate = await strictReferencedJson(
    bundleRoot,
    filename,
    validated.depth4References.certificate,
    'depth-4 certificate',
  );
  const symbolicCertificate = await strictReferencedJson(
    bundleRoot,
    filename,
    validated.depth4References.symbolicCertificate,
    'depth-4 symbolic certificate',
  );
  if (
    JSON.stringify(symbolicCertificate) !==
      JSON.stringify(depth4Certificate.symbolic?.certificate)
  ) {
    fail(
      'depth-4 symbolic certificate artifact differs from the embedded certificate',
    );
  }
  validateDepth4CheckerResult(
    await strictReferencedJson(
      bundleRoot,
      filename,
      validated.depth4CheckerResultReference,
      'depth-4 checker result',
    ),
    symbolicCertificate,
    evidence.implementations,
  );
  const depth4BoundedEvidence = validateDepth4Certificate(
    depth4Certificate,
    evidence.depth4,
    evidence.implementations,
  );
  const campaignProcessEvidence = validateCampaignProcesses(
    campaignProcesses,
    evidence,
    depth4Certificate,
  );
  const executionSourceBindings = await verifyExecutionSourceBindings(
    validated.sourceMaterials,
  );
  const historyTotals = [];
  for (let index = 0; index < HISTORY_COUNT; index += 1) {
    historyTotals.push(await verifyHistoryNdjson(
      bundleRoot,
      filename,
      validated.historyReferences[index],
      evidence.histories[index],
      independentOracle,
    ));
  }
  const derivedOperationCounts = combineDerivedTotals(historyTotals);
  verifyDerivedTotals(derivedOperationCounts, evidence.operationCounts);
  return Object.freeze({
    ...validated.summary,
    status: 'verified',
    q04GatePass: true,
    q04Verdict: 'pass-bounded-100000-and-depth4-shared-kernel',
    evidencePath: filename,
    evidenceBytes: metadata.size,
    depth4BoundedEvidenceVerified: true,
    depth4BoundedEvidence,
    campaignProcessEvidence,
    executionSourceBindings,
    derivedOperationCounts,
  });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const evidencePath = parseQ04EvidenceArguments(process.argv.slice(2));
    const result = await verifyQ04EvidenceFile(evidencePath);
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`Q-04 evidence verification failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
