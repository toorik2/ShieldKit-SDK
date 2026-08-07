#!/usr/bin/env node
/*
 * Final Q-07 performance qualification.
 *
 * The signed final manifest authorizes only a benchmark authority and policy.
 * The authority signs the post-final machine statement after all measurements
 * exist. This avoids a D-01 -> Q-07 manifest cycle while binding the complete
 * raw evidence set to the exact final profile, descriptor, runtime, source
 * commit/tree, Q-02 corpus verification, and independently replayed B-02
 * result.
 */
import { spawnSync } from 'node:child_process';
import {
  createHash, createPublicKey, verify as verifySignature,
} from 'node:crypto';
import {
  chmodSync, closeSync, constants, existsSync, fstatSync, fsyncSync, lstatSync,
  mkdirSync, openSync, readFileSync, readdirSync, readSync, realpathSync,
  renameSync, writeSync,
} from 'node:fs';
import {
  dirname, isAbsolute, join, relative, resolve, sep,
} from 'node:path';
import { pathToFileURL } from 'node:url';
import { encodeTokenPrefix } from '@bitauth/libauth';

import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import {
  resolveV2FinalReleaseRoot, verifyV2FinalReleaseProfileCore,
} from '../packages/profile/v2/release-bootstrap.mjs';
import {
  deriveV2FinalLocksSha256FromValidatedDescriptor,
  deriveV2ManifestArtifactFromValidatedDescriptor,
  deriveV2Pf10RuntimeFromValidatedDescriptor,
  deriveV2SettlementPinsFromValidatedDescriptor,
  loadV2InstanceDescriptor,
} from '../packages/profile/v2/instance-descriptor.mjs';
import {
  ACTION_PACKET_BYTES, decodeActionPacket,
} from '../packages/action/v2/packet.mjs';
import {
  decodeStateNftCommitment, encodeStateNftCommitment,
} from '../packages/action/v2/state.mjs';
import {
  DIRECT_V2_ROLE_CODES,
} from '../packages/action/v2/context.mjs';
import {
  hashIndexedNullifierLeaf, hashIndexedNullifierNode,
} from '../packages/action/v2/poseidon.mjs';
import {
  createIndexedNullifierQualificationStore,
} from '../packages/action/v2/tree-qualification-store.mjs';
import {
  parseSerializedSourceOutput, parseV2RawTransaction,
} from '../packages/kit/v2/transaction-policy.mjs';
import {
  Q07_NOTE_TREE_DEPTH, appendQ07Note, auditQ07NoteAccumulator,
  createQ07NoteAccumulator,
} from '../packages/pool/v2/qualification/q07-note-accumulator.mjs';
import {
  V2_Q02_CORPUS_SCHEMA, verifyV2Q02FinalKeyCorpus,
} from './v2-q02-final-key-corpus.mjs';
import {
  V2_B02_TRANSACTIONS_ARTIFACT_ID, V2_B02_TRANSACTIONS_SCHEMA,
  revalidateV2B02FinalVmResult,
} from './v2-b02-final-vm.mjs';
import {
  V2_Q02_LANE_AUTHORITY_ARTIFACT_ID,
} from './v2-q02-lane-evidence.mjs';
import {
  V2_Q07_FIXED_DEPTH_COUNTER_KEYS, V2_Q07_HISTORY_ACTIONS,
  V2_Q07_SAMPLE_COUNT, V2_Q07_THRESHOLDS,
} from './v2-q07-evidence.mjs';

const workspace = resolve(dirname(new URL(import.meta.url).pathname), '../..');
const HASH = /^[0-9a-f]{64}$/u;
const SHA1 = /^[0-9a-f]{40}$/u;
const ID = /^[a-z][a-z0-9-]{0,63}$/u;
const ROOT_ID = /^[a-z][a-z0-9-]*$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
const BASE64_SIGNATURE = /^[A-Za-z0-9+/]{86}==$/u;
const SAFE_RELATIVE =
  /^(?!\/)(?!.*\\)(?!.*(?:^|\/)\.{1,2}(?:\/|$))[A-Za-z0-9][A-Za-z0-9._/-]*$/u;
const P2PKH = /^76a914[0-9a-f]{40}88ac$/u;
const EMPTY_SHA256 = createHash('sha256').update(Buffer.alloc(0)).digest('hex');
const ZERO_32 = '0'.repeat(64);
const READ_CHUNK_BYTES = 64 * 1024;
const MAX_HISTORY_LINE_BYTES = 64 * 1024;
const MAX_JCS_BYTES = 512 * 1024 * 1024;
const STABLE_FIELDS = Object.freeze([
  'dev', 'ino', 'mode', 'nlink', 'size', 'uid', 'mtimeNs', 'ctimeNs',
]);
const HISTORY_DOMAIN =
  'ShieldKit/V2/Q07/final-descriptor-bound-history/action-transcript/v1\0';
const ENVELOPE_DOMAIN =
  'ShieldKit/V2/Q07/final-performance/published-machine-envelope/v1\0';
const HISTORY_CLASS =
  'descriptor-bound-deterministic-local-replay-not-chain-authenticated';
const PHASES = Object.freeze([
  'proof-generation',
  'incremental-apply-1k',
  'incremental-apply-100k',
  'full-recovery',
  'bottom-up-snapshot-authentication',
  'raw-fallback',
  'suffix-replay',
  'cold-sqlite-io',
]);
const PHASE_STATE_COUNTS = Object.freeze({
  'proof-generation': [100_000, 100_000],
  // Both warm lanes are exact transitions inside the independently replayed
  // frozen history. A detached 100001st action is not qualification evidence.
  'incremental-apply-1k': [999, 1_000],
  'incremental-apply-100k': [99_999, 100_000],
  'full-recovery': [0, 100_000],
  'bottom-up-snapshot-authentication': [0, 100_000],
  'raw-fallback': [0, 100_000],
  'suffix-replay': [99_000, 100_000],
  'cold-sqlite-io': [100_000, 100_000],
});
function historyCheckpointCounts(actionCount) {
  const counts = new Set([0, actionCount]);
  for (const [start, end] of Object.values(PHASE_STATE_COUNTS)) {
    if (start <= actionCount) counts.add(start);
    if (end <= actionCount) counts.add(end);
  }
  return Object.freeze([...counts].sort((left, right) => left - right));
}
const ALGORITHM_PATHS = Object.freeze([
  'shieldkit-groth-94kb/packages/action/v2/context.mjs',
  'shieldkit-groth-94kb/packages/action/v2/note-tree.mjs',
  'shieldkit-groth-94kb/packages/action/v2/packet.mjs',
  'shieldkit-groth-94kb/packages/action/v2/poseidon.mjs',
  'shieldkit-groth-94kb/packages/action/v2/state.mjs',
  'shieldkit-groth-94kb/packages/action/v2/tree-qualification-store.mjs',
  'shieldkit-groth-94kb/packages/pool/v2/persistent-indexed-nullifier-sqlite.mjs',
  'shieldkit-groth-94kb/packages/pool/v2/persistent-indexed-nullifier.mjs',
  'shieldkit-groth-94kb/packages/pool/v2/qualification/q07-note-accumulator.mjs',
  'shieldkit-groth-94kb/packages/pool/v2/store.mjs',
]);
const INVENTORY_CLASSIFICATIONS = new Set([
  'authenticated-store', 'history-corpus', 'raw-command-output', 'raw-sample',
  'sample-input', 'sample-manifest', 'sample-output',
]);
const PLACEHOLDER = /\b(?:fixture|mock|placeholder|synthetic|todo|tbd|skipped|unavailable|unknown|not[- ]measured|n\/a)\b/iu;

export const V2_Q07_BENCHMARK_AUTHORITY_ARTIFACT_ID =
  'q07-benchmark-authority';
export const V2_Q07_BENCHMARK_AUTHORITY_SCHEMA =
  'shieldkit-v2-direct-q07-benchmark-authority-policy-v1';
export const V2_Q07_MACHINE_STATEMENT_SCHEMA =
  'shieldkit-v2-direct-q07-published-machine-statement-v1';
export const V2_Q07_MACHINE_ENVELOPE_SCHEMA =
  'shieldkit-v2-direct-q07-published-machine-envelope-v1';
export const V2_Q07_INVENTORY_SCHEMA =
  'shieldkit-v2-direct-q07-evidence-inventory-v2';
export const V2_Q07_RAW_SAMPLE_SCHEMA =
  'shieldkit-v2-direct-q07-raw-sample-v2';
export const V2_Q07_SAMPLE_INPUT_SCHEMA =
  'shieldkit-v2-direct-q07-sample-input-v1';
export const V2_Q07_MACHINE_RECEIPT_SCHEMA =
  'shieldkit-v2-direct-q07-machine-receipt-v1';
export const V2_Q07_SAMPLE_MANIFEST_SCHEMA =
  'shieldkit-v2-direct-q07-raw-sample-manifest-v2';
export const V2_Q07_HISTORY_SCHEMA =
  'shieldkit-v2-direct-q07-final-history-v1';
export const V2_Q07_FINAL_PERFORMANCE_SCHEMA =
  'shieldkit-v2-direct-q07-final-performance-v2';
export const V2_Q07_FAILURE_SCHEMA =
  'shieldkit-v2-direct-q07-final-performance-failure-v1';

export class V2Q07FinalPerformanceError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2Q07FinalPerformanceError';
  }
}

const fail = (message) => { throw new V2Q07FinalPerformanceError(message); };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonical = (value) => Buffer.from(canonicalizeJcs(value), 'utf8');

function plain(value, label) {
  if (
    value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) fail(`${label} must be a plain object`);
  return value;
}
function exact(value, keys, label) {
  plain(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((entry, index) => entry !== expected[index])
  ) fail(`${label} has missing or unknown properties`);
  return value;
}
function text(value, label, maximum = 512) {
  if (
    typeof value !== 'string' || value.length === 0 || value.length > maximum
    || value.includes('\0') || PLACEHOLDER.test(value)
  ) fail(`${label} is empty, oversized, or placeholder text`);
  return value;
}
function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) fail(`${label} must be lowercase SHA-256`);
  return value;
}
function decimal(value, label, minimum = 0n) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) fail(`${label} must be a canonical unsigned decimal string`);
  const parsed = BigInt(value);
  if (parsed < minimum) fail(`${label} is below its minimum`);
  return parsed;
}
function integer(value, label, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) fail(`${label} must be a safe integer`);
  return value;
}
function timestamp(value, label) {
  if (
    typeof value !== 'string'
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || new Date(value).toISOString() !== value
  ) fail(`${label} must be a canonical UTC millisecond timestamp`);
  return Date.parse(value);
}
function absolute(value, label) {
  if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value) fail(`${label} must be an absolute normalized path`);
  return value;
}
function safeRelative(value, label) {
  if (
    typeof value !== 'string' || !SAFE_RELATIVE.test(value)
    || value.endsWith('/')
  ) fail(`${label} must be an unambiguous safe relative path`);
  return value;
}
function inside(root, path, label) {
  safeRelative(path, label);
  const filename = resolve(root, path);
  if (!filename.startsWith(`${root}${sep}`)) fail(`${label} escapes its evidence root`);
  return filename;
}
function sameStat(left, right) {
  return STABLE_FIELDS.every((field) => left[field] === right[field]);
}
function directDirectory(pathname, label) {
  absolute(pathname, label);
  const entry = lstatSync(pathname, { bigint: true, throwIfNoEntry: false });
  if (
    !entry?.isDirectory() || entry.isSymbolicLink()
    || realpathSync(pathname) !== pathname
  ) fail(`${label} must be a direct canonical directory`);
  return pathname;
}
function openStable(pathname, label) {
  absolute(pathname, label);
  const named = lstatSync(pathname, { bigint: true, throwIfNoEntry: false });
  if (
    !named?.isFile() || named.isSymbolicLink() || named.nlink !== 1n
    || realpathSync(pathname) !== pathname
  ) fail(`${label} must be a direct single-link regular file`);
  let fd;
  try {
    fd = openSync(pathname, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const opened = fstatSync(fd, { bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || !sameStat(named, opened)) fail(`${label} changed while it was opened`);
    return Object.freeze({ fd, opened, named });
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    if (error instanceof V2Q07FinalPerformanceError) throw error;
    fail(`${label} cannot be opened safely: ${error instanceof Error ? error.message : String(error)}`);
  }
}
function closeStable(opened, pathname, label) {
  const after = fstatSync(opened.fd, { bigint: true });
  const named = lstatSync(pathname, { bigint: true, throwIfNoEntry: false });
  if (
    !named?.isFile() || named.isSymbolicLink() || named.nlink !== 1n
    || !sameStat(opened.opened, after) || !sameStat(after, named)
  ) fail(`${label} changed while it was read`);
}
function stableBytes(pathname, label, maximumBytes = MAX_JCS_BYTES) {
  const opened = openStable(pathname, label);
  try {
    if (opened.opened.size > BigInt(maximumBytes)) fail(`${label} exceeds its byte limit`);
    const bytes = readFileSync(opened.fd);
    closeStable(opened, pathname, label);
    return Buffer.from(bytes);
  } finally { closeSync(opened.fd); }
}
function stableDigest(pathname, label) {
  const opened = openStable(pathname, label);
  try {
    const digest = createHash('sha256');
    const chunk = Buffer.alloc(READ_CHUNK_BYTES);
    for (;;) {
      const count = readSync(opened.fd, chunk, 0, chunk.length, null);
      if (count === 0) break;
      digest.update(chunk.subarray(0, count));
    }
    closeStable(opened, pathname, label);
    return Object.freeze({
      bytes: opened.opened.size.toString(),
      sha256: digest.digest('hex'),
    });
  } finally { closeSync(opened.fd); }
}
function heldStableDigest(pathname, label) {
  const opened = openStable(pathname, label);
  let released = false;
  try {
    const digest = createHash('sha256');
    const chunk = Buffer.alloc(READ_CHUNK_BYTES);
    for (;;) {
      const count = readSync(opened.fd, chunk, 0, chunk.length, null);
      if (count === 0) break;
      digest.update(chunk.subarray(0, count));
    }
    return Object.freeze({
      bytes: opened.opened.size.toString(),
      release() {
        if (released) fail(`${label} stability pin was released twice`);
        released = true;
        try { closeStable(opened, pathname, label); } finally { closeSync(opened.fd); }
      },
      sha256: digest.digest('hex'),
      abandon() {
        if (!released) {
          released = true;
          closeSync(opened.fd);
        }
      },
    });
  } catch (error) {
    if (!released) closeSync(opened.fd);
    throw error;
  }
}
function parseJcs(bytes, label) {
  let value;
  try { value = JSON.parse(bytes); } catch { fail(`${label} is not JSON`); }
  if (!bytes.equals(canonical(value))) fail(`${label} must use exact RFC8785/JCS bytes`);
  return value;
}
function jcsFile(pathname, label, maximumBytes = MAX_JCS_BYTES) {
  const bytes = stableBytes(pathname, label, maximumBytes);
  return Object.freeze({ bytes, value: parseJcs(bytes, label), sha256: sha256(bytes) });
}
function physicalFiles(root, label) {
  directDirectory(root, label);
  const result = [];
  const walk = (directory, prefix) => {
    const directoryEntry = lstatSync(directory, { bigint: true });
    if (
      !directoryEntry.isDirectory() || directoryEntry.isSymbolicLink()
      || realpathSync(directory) !== directory
    ) fail(`${label} contains an unsafe directory`);
    for (const name of readdirSync(directory).sort()) {
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(name)) fail(`${label} contains an unsafe filename`);
      const filename = join(directory, name);
      const path = prefix === '' ? name : `${prefix}/${name}`;
      const entry = lstatSync(filename, { bigint: true });
      if (entry.isSymbolicLink()) fail(`${label} contains a symlink`);
      if (entry.isDirectory()) walk(filename, path);
      else if (entry.isFile() && entry.nlink === 1n && realpathSync(filename) === filename) result.push(path);
      else fail(`${label} contains a special or multiply linked artifact`);
    }
  };
  walk(root, '');
  return Object.freeze(result.sort());
}
function exactSet(actual, expected, label) {
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length
    || actual.some((entry, index) => entry !== wanted[index])
  ) fail(`${label} has missing, extra, or duplicate artifacts`);
}
function noPostFinalDigests(value, label) {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => noPostFinalDigests(entry, `${label}[${index}]`));
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      if (/(?:sha256|digest|reporthash|evidencehash)/iu.test(key)) fail(`${label} may not pre-pin a post-final digest`);
      noPostFinalDigests(child, `${label}.${key}`);
    }
  }
}

function canonicalPublicKey(value, label) {
  let key;
  try { key = createPublicKey(value); } catch { fail(`${label} is not a public key`); }
  const pem = key.export({ type: 'spki', format: 'pem' }).toString();
  if (key.asymmetricKeyType !== 'ed25519' || pem !== value) fail(`${label} must be canonical Ed25519 SPKI PEM`);
  return key;
}
function command(value, label) {
  exact(value, ['argv', 'id', 'phase'], label);
  if (!ID.test(value.id) || !PHASES.includes(value.phase)) fail(`${label} identity is invalid`);
  if (
    !Array.isArray(value.argv) || value.argv.length === 0
    || value.argv.some((entry) => typeof entry !== 'string' || entry.length === 0 || entry.length > 4096 || entry.includes('\0') || PLACEHOLDER.test(entry))
    || !isAbsolute(value.argv[0]) || resolve(value.argv[0]) !== value.argv[0]
    || ['/bin/sh', '/usr/bin/sh', '/bin/bash', '/usr/bin/bash', '/usr/bin/env'].includes(value.argv[0])
  ) fail(`${label}.argv must be an exact non-shell absolute command vector`);
  return value;
}
function authorityPolicy(value) {
  exact(value, [
    'artifactPaths', 'authority', 'commands', 'evidenceWindow',
    'machinePolicy', 'resourcePolicy', 'schema',
  ], 'Q-07 benchmark authority policy');
  if (value.schema !== V2_Q07_BENCHMARK_AUTHORITY_SCHEMA) fail('Q-07 benchmark authority policy schema is invalid');
  noPostFinalDigests(value, 'Q-07 benchmark authority policy');
  exact(value.artifactPaths, ['envelope', 'history', 'inventory', 'samplesManifest'], 'Q-07 authority artifactPaths');
  for (const [key, path] of Object.entries(value.artifactPaths)) safeRelative(path, `Q-07 authority artifactPaths.${key}`);
  if (new Set(Object.values(value.artifactPaths)).size !== 4) fail('Q-07 authority artifact paths must be distinct');
  exact(value.authority, ['authorityId', 'organization', 'publicKeyPem'], 'Q-07 benchmark authority');
  if (!ID.test(value.authority.authorityId)) fail('Q-07 authorityId is invalid');
  text(value.authority.organization, 'Q-07 authority organization');
  const publicKey = canonicalPublicKey(value.authority.publicKeyPem, 'Q-07 authority publicKeyPem');
  exact(value.evidenceWindow, ['notAfter', 'notBefore'], 'Q-07 authority evidenceWindow');
  const notBefore = timestamp(value.evidenceWindow.notBefore, 'Q-07 evidenceWindow.notBefore');
  const notAfter = timestamp(value.evidenceWindow.notAfter, 'Q-07 evidenceWindow.notAfter');
  if (notAfter <= notBefore) fail('Q-07 authority evidence window is empty or reversed');
  if (!Array.isArray(value.commands) || value.commands.length !== PHASES.length) fail('Q-07 policy must pin one command per phase');
  const commandIds = new Set();
  value.commands.forEach((entry, index) => {
    command(entry, `Q-07 authority command ${index}`);
    if (entry.phase !== PHASES[index] || commandIds.has(entry.id)) fail('Q-07 authority commands must be unique and phase ordered');
    commandIds.add(entry.id);
  });
  exact(value.machinePolicy, ['architecture', 'minimumLogicalCpus', 'minimumMemoryBytes', 'operatingSystem'], 'Q-07 machine policy');
  text(value.machinePolicy.architecture, 'Q-07 machine policy architecture');
  text(value.machinePolicy.operatingSystem, 'Q-07 machine policy operatingSystem');
  integer(value.machinePolicy.minimumLogicalCpus, 'Q-07 machine policy minimumLogicalCpus', 1);
  decimal(value.machinePolicy.minimumMemoryBytes, 'Q-07 machine policy minimumMemoryBytes', 1n);
  exact(value.resourcePolicy, [
    'cgroupVersion', 'coldIoProtocol', 'ioAccounting', 'memoryAccounting',
    'sampleCount',
  ], 'Q-07 resource policy');
  if (
    value.resourcePolicy.cgroupVersion !== '2'
    || value.resourcePolicy.coldIoProtocol !== 'fresh-process-after-parent-closed-durable-store-no-page-cache-drop-claim'
    || value.resourcePolicy.ioAccounting !== 'proc-pid-io'
    || value.resourcePolicy.memoryAccounting !== 'cgroup-v2-memory.peak'
    || value.resourcePolicy.sampleCount !== String(V2_Q07_SAMPLE_COUNT)
  ) fail('Q-07 resource policy is not the exact published-machine policy');
  return Object.freeze({ commandIds, notAfter, notBefore, publicKey, value });
}

/** Explicit parser seam; it never grants manifest authority. */
export function validateV2Q07AuthorityForTestOnly(value) {
  authorityPolicy(value);
  return Object.freeze(value);
}

function identity(value, label) {
  exact(value, [
    'descriptorSha256', 'finalLocksSha256', 'instanceId', 'manifestSha256',
    'profileId', 'profileSha256', 'releaseBootstrapSha256', 'releaseRootId',
    'runtimeMaterialSha256', 'sourceCommit', 'sourceTree', 'topologyId',
  ], label);
  for (const key of [
    'descriptorSha256', 'finalLocksSha256', 'instanceId', 'manifestSha256',
    'profileId', 'profileSha256', 'releaseBootstrapSha256',
    'runtimeMaterialSha256',
  ]) hash(value[key], `${label}.${key}`);
  if (!ROOT_ID.test(value.releaseRootId) || !ID.test(value.topologyId)) fail(`${label} releaseRootId or topologyId is invalid`);
  if (!SHA1.test(value.sourceCommit) || !SHA1.test(value.sourceTree)) fail(`${label} Git pins are invalid`);
  return value;
}
function hardPolicy(value, label) {
  exact(value, [
    'everyInputUnlockingBytecodeBytes', 'everyReportedVmResourcePercent',
    'narrowerMargins', 'serializedTransactionBytes',
  ], label);
  if (
    value.serializedTransactionBytes !== 100_000
    || value.everyInputUnlockingBytecodeBytes !== 10_000
    || value.everyReportedVmResourcePercent !== 100
    || value.narrowerMargins !== '90000/9500-non-blocking-risk-telemetry-only'
  ) fail(`${label} must bind only the exact 100000/10000/100% hard ceilings; smaller limits are telemetry`);
  return value;
}
function toolchain(value, label) {
  exact(value, ['lockfileSha256', 'nodeVersion', 'packages'], label);
  hash(value.lockfileSha256, `${label}.lockfileSha256`);
  if (!/^v22\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u.test(value.nodeVersion)) fail(`${label}.nodeVersion must be exact Node 22`);
  if (!Array.isArray(value.packages) || value.packages.length === 0) fail(`${label}.packages must be nonempty`);
  let prior = '';
  for (const entry of value.packages) {
    exact(entry, ['integritySha256', 'name', 'version'], `${label} package`);
    text(entry.name, `${label} package name`);
    text(entry.version, `${label} package version`);
    hash(entry.integritySha256, `${label} package integritySha256`);
    if (entry.name <= prior) fail(`${label}.packages must be uniquely name sorted`);
    prior = entry.name;
  }
  return value;
}
function machine(value, policy, label) {
  exact(value, [
    'architecture', 'benchmarkFilesystem', 'bootId', 'cpuModel', 'hostname',
    'kernelRelease', 'logicalCpus', 'machineId', 'operatingSystem',
    'totalMemoryBytes',
  ], label);
  for (const key of [
    'architecture', 'benchmarkFilesystem', 'cpuModel', 'hostname',
    'kernelRelease', 'machineId', 'operatingSystem',
  ]) text(value[key], `${label}.${key}`);
  if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u.test(value.bootId)) fail(`${label}.bootId must be a canonical Linux boot UUID`);
  integer(value.logicalCpus, `${label}.logicalCpus`, 1);
  const memory = decimal(value.totalMemoryBytes, `${label}.totalMemoryBytes`, 1n);
  if (
    value.architecture !== policy.architecture
    || value.operatingSystem !== policy.operatingSystem
    || value.logicalCpus < policy.minimumLogicalCpus
    || memory < BigInt(policy.minimumMemoryBytes)
  ) fail(`${label} violates the manifest-pinned machine policy`);
  return value;
}
function resources(value, policy, label) {
  exact(value, [
    'cgroupRoot', 'cgroupVersion', 'coldIoProtocol', 'ioAccounting',
    'isolation', 'memoryAccounting',
  ], label);
  if (
    value.cgroupVersion !== policy.cgroupVersion
    || value.coldIoProtocol !== policy.coldIoProtocol
    || value.ioAccounting !== policy.ioAccounting
    || value.memoryAccounting !== policy.memoryAccounting
    || value.isolation !== 'dedicated-published-benchmark-machine'
    || typeof value.cgroupRoot !== 'string'
    || !value.cgroupRoot.startsWith('/sys/fs/cgroup/')
    || value.cgroupRoot.includes('..') || resolve(value.cgroupRoot) !== value.cgroupRoot
  ) fail(`${label} differs from the exact resource policy`);
  return value;
}
function artifactDigests(value, label) {
  exact(value, [
    'b02ResultSha256', 'b02RevalidationSha256', 'historySha256',
    'historyVerificationSha256', 'inventorySha256', 'q02CorpusSha256',
    'q02VerificationSha256', 'samplesManifestSha256',
    'samplesVerificationSha256',
  ], label);
  for (const [key, digest] of Object.entries(value)) hash(digest, `${label}.${key}`);
  return value;
}

function verifyEnvelope({
  authorityArtifactSha256, envelope, expectedArtifacts, expectedIdentity,
  expectedBootId, expectedCgroupPaths, expectedEvidenceWindow,
  expectedMachineRunId, policy,
}) {
  exact(envelope, [
    'authorityArtifactSha256', 'schema', 'signatureBase64', 'signerId',
    'statement', 'statementSha256',
  ], 'Q-07 machine envelope');
  if (
    envelope.schema !== V2_Q07_MACHINE_ENVELOPE_SCHEMA
    || envelope.authorityArtifactSha256 !== authorityArtifactSha256
    || envelope.signerId !== policy.value.authority.authorityId
  ) fail('Q-07 machine envelope authority binding is invalid');
  hash(envelope.statementSha256, 'Q-07 machine envelope statementSha256');
  if (envelope.statementSha256 !== sha256(canonical(envelope.statement))) fail('Q-07 machine envelope statement hash drifts');
  const statement = envelope.statement;
  exact(statement, [
    'artifacts', 'commands', 'completedAt', 'hardPolicyCeilings', 'identity',
    'machine', 'resources', 'runId', 'schema', 'startedAt', 'toolchain',
  ], 'Q-07 machine statement');
  if (statement.schema !== V2_Q07_MACHINE_STATEMENT_SCHEMA || !ID.test(statement.runId)) fail('Q-07 machine statement identity is invalid');
  if (statement.runId !== expectedMachineRunId) fail('Q-07 machine statement runId differs from the raw sample manifest');
  identity(statement.identity, 'Q-07 machine statement identity');
  if (!canonical(statement.identity).equals(canonical(expectedIdentity))) fail('Q-07 machine statement final identity drifts');
  artifactDigests(statement.artifacts, 'Q-07 machine statement artifacts');
  if (!canonical(statement.artifacts).equals(canonical(expectedArtifacts))) fail('Q-07 machine statement does not bind exact recomputed artifacts');
  hardPolicy(statement.hardPolicyCeilings, 'Q-07 machine statement hardPolicyCeilings');
  const startedAt = timestamp(statement.startedAt, 'Q-07 machine statement startedAt');
  const completedAt = timestamp(statement.completedAt, 'Q-07 machine statement completedAt');
  if (
    completedAt <= startedAt || startedAt < policy.notBefore
    || completedAt > policy.notAfter
  ) fail('Q-07 machine statement is outside its authorized evidence window');
  if (
    expectedEvidenceWindow.start < startedAt
    || expectedEvidenceWindow.end > completedAt
  ) fail('Q-07 raw samples fall outside the signed machine run interval');
  if (!Array.isArray(statement.commands) || !canonical(statement.commands).equals(canonical(policy.value.commands))) fail('Q-07 machine statement commands differ from the pre-final policy');
  statement.commands.forEach((entry, index) => command(entry, `Q-07 machine statement command ${index}`));
  toolchain(statement.toolchain, 'Q-07 machine statement toolchain');
  machine(statement.machine, policy.value.machinePolicy, 'Q-07 machine statement machine');
  resources(statement.resources, policy.value.resourcePolicy, 'Q-07 machine statement resources');
  if (statement.machine.bootId !== expectedBootId) fail('Q-07 raw samples were not measured in the signed machine boot');
  if (expectedCgroupPaths.some(
    (path) =>
      path !== statement.resources.cgroupRoot
      && !path.startsWith(`${statement.resources.cgroupRoot}/`),
  )) fail('Q-07 raw cgroup measurements escape the signed machine resource root');
  if (typeof envelope.signatureBase64 !== 'string' || !BASE64_SIGNATURE.test(envelope.signatureBase64)) fail('Q-07 machine envelope signature is not canonical base64');
  const signature = Buffer.from(envelope.signatureBase64, 'base64');
  const message = Buffer.concat([Buffer.from(ENVELOPE_DOMAIN), canonical(statement)]);
  if (
    signature.length !== 64
    || signature.toString('base64') !== envelope.signatureBase64
    || !verifySignature(null, message, policy.publicKey, signature)
  ) fail('Q-07 machine envelope Ed25519 signature is invalid');
  return Object.freeze(statement);
}

/** Signature/binding test seam; callers must provide all independently derived expectations. */
export function verifyV2Q07PublishedEnvelopeForTestOnly(options) {
  exact(options, [
    'authorityArtifact', 'authorityArtifactSha256', 'envelope',
    'expectedArtifacts', 'expectedBootId', 'expectedCgroupPaths',
    'expectedEvidenceWindow', 'expectedIdentity', 'expectedMachineRunId',
  ], 'Q-07 envelope test options');
  if (sha256(canonical(options.authorityArtifact)) !== options.authorityArtifactSha256) fail('Q-07 test authority hash drifts');
  return verifyEnvelope({
    ...options,
    policy: authorityPolicy(options.authorityArtifact),
  });
}

function inventoryValue(value) {
  exact(value, ['artifacts', 'schema'], 'Q-07 evidence inventory');
  if (value.schema !== V2_Q07_INVENTORY_SCHEMA || !Array.isArray(value.artifacts) || value.artifacts.length === 0) fail('Q-07 evidence inventory is empty or has the wrong schema');
  const paths = new Set();
  let prior = '';
  for (const entry of value.artifacts) {
    exact(entry, ['bytes', 'classification', 'path', 'sha256'], 'Q-07 inventory artifact');
    safeRelative(entry.path, 'Q-07 inventory artifact path');
    hash(entry.sha256, 'Q-07 inventory artifact sha256');
    decimal(entry.bytes, 'Q-07 inventory artifact bytes');
    if (
      !INVENTORY_CLASSIFICATIONS.has(entry.classification)
      || paths.has(entry.path) || entry.path <= prior
    ) fail('Q-07 inventory artifacts must be uniquely path sorted and classified');
    paths.add(entry.path); prior = entry.path;
  }
  return Object.freeze({ paths, value });
}
function verifyInventory(root, inventoryPath, envelopePath) {
  const record = jcsFile(inside(root, inventoryPath, 'Q-07 inventory path'), 'Q-07 inventory');
  const parsed = inventoryValue(record.value);
  const physical = physicalFiles(root, 'Q-07 evidence directory');
  exactSet(physical, [inventoryPath, envelopePath, ...parsed.paths], 'Q-07 evidence inventory closure');
  for (const entry of record.value.artifacts) {
    const digest = stableDigest(inside(root, entry.path, `Q-07 inventory ${entry.path}`), `Q-07 inventory ${entry.path}`);
    if (digest.sha256 !== entry.sha256 || digest.bytes !== entry.bytes) fail(`Q-07 inventory artifact hash/size drifts: ${entry.path}`);
  }
  return Object.freeze({ ...parsed, sha256: record.sha256 });
}

function reference(value, label) {
  exact(value, ['path', 'sha256'], label);
  safeRelative(value.path, `${label}.path`);
  hash(value.sha256, `${label}.sha256`);
  return value;
}
function counters(value, label) {
  exact(value, V2_Q07_FIXED_DEPTH_COUNTER_KEYS, label);
  let total = 0;
  for (const key of V2_Q07_FIXED_DEPTH_COUNTER_KEYS) total += integer(value[key], `${label}.${key}`);
  if (total === 0) fail(`${label} cannot be all zero`);
  return value;
}
function rawSample(
  value,
  phase,
  ordinal,
  commandId,
  terminalStateSha256,
  historyCheckpoints,
  label,
) {
  exact(value, [
    'commandId', 'completedAt', 'execution', 'fixedDepthOperationCounts', 'io',
    'inputArtifact', 'monotonicEndNanoseconds',
    'monotonicStartNanoseconds', 'ordinal', 'outputArtifact', 'phase',
    'process', 'rss', 'sampleId', 'schema', 'startedAt', 'state',
    'wallNanoseconds',
  ], label);
  if (
    value.schema !== V2_Q07_RAW_SAMPLE_SCHEMA || value.phase !== phase
    || value.ordinal !== String(ordinal) || value.sampleId !== `${phase}-${String(ordinal).padStart(2, '0')}`
    || value.commandId !== commandId
  ) fail(`${label} identity or ordering is invalid`);
  reference(value.inputArtifact, `${label}.inputArtifact`);
  reference(value.outputArtifact, `${label}.outputArtifact`);
  const started = timestamp(value.startedAt, `${label}.startedAt`);
  const completed = timestamp(value.completedAt, `${label}.completedAt`);
  if (completed < started) fail(`${label} timestamps are reversed`);
  const monotonicStart = decimal(value.monotonicStartNanoseconds, `${label}.monotonicStartNanoseconds`);
  const monotonicEnd = decimal(value.monotonicEndNanoseconds, `${label}.monotonicEndNanoseconds`);
  const wall = decimal(value.wallNanoseconds, `${label}.wallNanoseconds`, 1n);
  if (monotonicEnd <= monotonicStart || monotonicEnd - monotonicStart !== wall) fail(`${label} wall time does not bind its monotonic endpoints`);
  const timestampNanoseconds = BigInt(completed - started) * 1_000_000n;
  if (
    wall < timestampNanoseconds
    || wall >= timestampNanoseconds + 1_000_000n
  ) fail(`${label} wall time differs from its UTC timestamp interval`);
  exact(value.execution, ['exitCode', 'signal', 'stderr', 'stdout'], `${label}.execution`);
  if (value.execution.exitCode !== 0 || value.execution.signal !== null) fail(`${label} command did not complete successfully`);
  reference(value.execution.stdout, `${label}.execution.stdout`);
  reference(value.execution.stderr, `${label}.execution.stderr`);
  exact(value.process, [
    'bootId', 'parentProcessId', 'processId', 'processInstanceId',
    'processStartTicks',
  ], `${label}.process`);
  if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u.test(value.process.bootId) || !ID.test(value.process.processInstanceId)) fail(`${label} process identity is invalid`);
  decimal(value.process.parentProcessId, `${label}.process.parentProcessId`, 1n);
  decimal(value.process.processId, `${label}.process.processId`, 1n);
  decimal(value.process.processStartTicks, `${label}.process.processStartTicks`, 1n);
  exact(value.rss, ['bytes', 'kind', 'path', 'source'], `${label}.rss`);
  const rssBytes = decimal(value.rss.bytes, `${label}.rss.bytes`, 1n);
  if (
    value.rss.kind !== 'cgroup-v2' || value.rss.source !== 'memory.peak'
    || typeof value.rss.path !== 'string' || !value.rss.path.startsWith('/sys/fs/cgroup/')
    || value.rss.path.includes('..') || resolve(value.rss.path) !== value.rss.path
  ) fail(`${label} RSS must be raw cgroup-v2 memory.peak evidence`);
  exact(value.io, [
    'readBytes', 'readSyscalls', 'storeLifecycle', 'writeBytes',
    'writeSyscalls',
  ], `${label}.io`);
  const readBytes = decimal(value.io.readBytes, `${label}.io.readBytes`);
  decimal(value.io.writeBytes, `${label}.io.writeBytes`);
  decimal(value.io.readSyscalls, `${label}.io.readSyscalls`);
  decimal(value.io.writeSyscalls, `${label}.io.writeSyscalls`);
  const expectedLifecycle = phase === 'cold-sqlite-io'
    ? 'fresh-process-after-parent-closed-durable-store'
    : ['incremental-apply-1k', 'incremental-apply-100k'].includes(phase)
      ? 'same-process-open-store-warm-io'
      : 'isolated-benchmark-process';
  if (value.io.storeLifecycle !== expectedLifecycle || (phase === 'cold-sqlite-io' && readBytes === 0n)) fail(`${label} cold/warm I/O lifecycle is invalid`);
  exact(value.state, [
    'endActionCount', 'endStateSha256', 'startActionCount',
    'startStateSha256',
  ], `${label}.state`);
  const [startCount, endCount] = PHASE_STATE_COUNTS[phase];
  if (
    value.state.startActionCount !== String(startCount)
    || value.state.endActionCount !== String(endCount)
  ) fail(`${label} state counts do not bind the frozen history phase`);
  hash(value.state.startStateSha256, `${label}.state.startStateSha256`);
  hash(value.state.endStateSha256, `${label}.state.endStateSha256`);
  if (
    historyCheckpoints.get(String(startCount)) !== value.state.startStateSha256
    || historyCheckpoints.get(String(endCount)) !== value.state.endStateSha256
    || (startCount === V2_Q07_HISTORY_ACTIONS
      && value.state.startStateSha256 !== terminalStateSha256)
    || (endCount === V2_Q07_HISTORY_ACTIONS
      && value.state.endStateSha256 !== terminalStateSha256)
  ) fail(`${label} does not bind exact independently replayed history checkpoints`);
  if (['incremental-apply-1k', 'incremental-apply-100k'].includes(phase)) counters(value.fixedDepthOperationCounts, `${label}.fixedDepthOperationCounts`);
  else if (value.fixedDepthOperationCounts !== null) fail(`${label} must not invent fixed-depth counters for this phase`);
  return Object.freeze({ completed, rssBytes, started, wall });
}
function expectedSampleInput({
  historySha256, identity: expectedIdentity, sample, storeArtifact,
  terminalStateSha256,
}) {
  return Object.freeze({
    commandId: sample.commandId,
    endCheckpoint: Object.freeze({
      actionCount: sample.state.endActionCount,
      stateSha256: sample.state.endStateSha256,
    }),
    historySha256,
    identity: expectedIdentity,
    phase: sample.phase,
    sampleId: sample.sampleId,
    schema: V2_Q07_SAMPLE_INPUT_SCHEMA,
    startCheckpoint: Object.freeze({
      actionCount: sample.state.startActionCount,
      stateSha256: sample.state.startStateSha256,
    }),
    storeArtifactSha256: storeArtifact.sha256,
    terminalStateSha256,
  });
}
function expectedMachineReceipt({
  historySha256, sample, storeArtifact, terminalStateSha256,
}) {
  return Object.freeze({
    commandId: sample.commandId,
    completedAt: sample.completedAt,
    fixedDepthOperationCounts: sample.fixedDepthOperationCounts,
    historySha256,
    inputArtifactSha256: sample.inputArtifact.sha256,
    io: sample.io,
    monotonicEndNanoseconds: sample.monotonicEndNanoseconds,
    monotonicStartNanoseconds: sample.monotonicStartNanoseconds,
    ordinal: sample.ordinal,
    phase: sample.phase,
    process: sample.process,
    rss: sample.rss,
    sampleId: sample.sampleId,
    schema: V2_Q07_MACHINE_RECEIPT_SCHEMA,
    startedAt: sample.startedAt,
    state: sample.state,
    storeArtifactSha256: storeArtifact.sha256,
    terminalStateSha256,
    wallNanoseconds: sample.wallNanoseconds,
  });
}
function nearestRank(values, numerator, denominator) {
  const sorted = [...values].sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
  return sorted[Math.ceil((sorted.length * numerator) / denominator) - 1];
}
export function nearestRankP95ForTestOnly(values) {
  if (
    !Array.isArray(values) || values.length !== V2_Q07_SAMPLE_COUNT
    || values.some((entry) => !Number.isSafeInteger(entry) || entry < 0)
  ) fail(`Q-07 requires exactly ${V2_Q07_SAMPLE_COUNT} nonnegative raw samples`);
  return Number(nearestRank(values.map(BigInt), 95, 100));
}
function sampleManifest(value, expectedIdentity) {
  exact(value, [
    'identity', 'machineRunId', 'phases', 'sampleCount', 'schema',
    'storeArtifact', 'storeBytes', 'terminalStateSha256',
  ], 'Q-07 raw sample manifest');
  if (
    value.schema !== V2_Q07_SAMPLE_MANIFEST_SCHEMA
    || value.sampleCount !== String(V2_Q07_SAMPLE_COUNT)
    || !ID.test(value.machineRunId)
  ) fail('Q-07 raw sample manifest identity is invalid');
  identity(value.identity, 'Q-07 raw sample manifest identity');
  if (!canonical(value.identity).equals(canonical(expectedIdentity))) fail('Q-07 raw sample manifest final identity drifts');
  decimal(value.storeBytes, 'Q-07 raw sample manifest storeBytes', 1n);
  reference(value.storeArtifact, 'Q-07 raw sample manifest storeArtifact');
  hash(value.terminalStateSha256, 'Q-07 raw sample manifest terminalStateSha256');
  if (!Array.isArray(value.phases) || value.phases.length !== PHASES.length) fail('Q-07 raw sample phase set is incomplete');
  const samplePaths = new Set();
  for (const [index, phase] of value.phases.entries()) {
    exact(phase, [
      'name', 'reportedP95Nanoseconds', 'reportedPeakRssBytes', 'samples',
    ], `Q-07 sample phase ${index}`);
    if (phase.name !== PHASES[index]) fail('Q-07 raw sample phases must be exact and ordered');
    decimal(phase.reportedP95Nanoseconds, `Q-07 ${phase.name} reportedP95Nanoseconds`, 1n);
    decimal(phase.reportedPeakRssBytes, `Q-07 ${phase.name} reportedPeakRssBytes`, 1n);
    if (!Array.isArray(phase.samples) || phase.samples.length !== V2_Q07_SAMPLE_COUNT) fail(`Q-07 ${phase.name} needs exactly ${V2_Q07_SAMPLE_COUNT} samples`);
    for (const ref of phase.samples) {
      reference(ref, `Q-07 ${phase.name} sample reference`);
      if (samplePaths.has(ref.path)) fail('Q-07 raw sample path is duplicated');
      samplePaths.add(ref.path);
    }
  }
  return Object.freeze({ samplePaths, value });
}
function performanceSummary(phases, storeBytes) {
  const byName = new Map(phases.map((entry) => [entry.name, entry]));
  const proof = byName.get('proof-generation');
  const apply1k = byName.get('incremental-apply-1k');
  const apply100k = byName.get('incremental-apply-100k');
  const recovery = byName.get('full-recovery');
  const bottomUp = byName.get('bottom-up-snapshot-authentication');
  const rawFallback = byName.get('raw-fallback');
  const suffixReplay = byName.get('suffix-replay');
  const cold = byName.get('cold-sqlite-io');
  const ratioBasisPoints = (apply100k.p95 * 10_000n + apply1k.p95 - 1n) / apply1k.p95;
  const recoveryPeakRss = [recovery, bottomUp, rawFallback, suffixReplay]
    .reduce((peak, entry) => entry.peakRss > peak ? entry.peakRss : peak, 0n);
  if (
    proof.p95 > BigInt(V2_Q07_THRESHOLDS.proofP95Ms) * 1_000_000n
    || proof.peakRss > BigInt(V2_Q07_THRESHOLDS.proverPeakRssBytes)
    || apply1k.p95 > BigInt(V2_Q07_THRESHOLDS.stateApplyP95Ms) * 1_000_000n
    || apply100k.p95 > BigInt(V2_Q07_THRESHOLDS.stateApplyP95Ms) * 1_000_000n
    || recovery.p95 > BigInt(V2_Q07_THRESHOLDS.fullRecoveryMs) * 1_000_000n
    || rawFallback.p95 > BigInt(V2_Q07_THRESHOLDS.fullRecoveryMs) * 1_000_000n
    || [recovery, bottomUp, rawFallback, suffixReplay].some(
      (entry) =>
        entry.peakRss > BigInt(V2_Q07_THRESHOLDS.recoveryPeakRssBytes),
    )
    || storeBytes > BigInt(V2_Q07_THRESHOLDS.storeBytes)
    || ratioBasisPoints > 11_000n
  ) fail('Q-07 hard performance threshold or warm-tree ratio is exceeded');
  return Object.freeze({
    coldIoP95Nanoseconds: cold.p95.toString(),
    coldIoPolicy: 'separate-non-blocking-io-telemetry',
    fullRecoveryP95Nanoseconds: recovery.p95.toString(),
    incrementalApply1kP95Nanoseconds: apply1k.p95.toString(),
    incrementalApply100kP95Nanoseconds: apply100k.p95.toString(),
    proofP95Nanoseconds: proof.p95.toString(),
    proverPeakRssBytes: proof.peakRss.toString(),
    rawFallbackP95Nanoseconds: rawFallback.p95.toString(),
    recoveryPeakRssBytes: recoveryPeakRss.toString(),
    storeBytes: storeBytes.toString(),
    warmRatioBasisPoints: ratioBasisPoints.toString(),
  });
}
function validateSampleSet({
  authority, expectedIdentity, historyVerification, inventory, manifest,
  readBytesArtifact, readJcsArtifact, readOpaqueArtifact,
}) {
  sampleManifest(manifest, expectedIdentity);
  const commands = new Map(authority.value.commands.map((entry) => [entry.phase, entry.id]));
  const inventoryByPath = new Map(inventory.value.artifacts.map((entry) => [entry.path, entry]));
  const referenced = new Set();
  const historyCheckpoints = new Map(
    historyVerification.checkpoints.map((entry) =>
      [entry.actionCount, entry.stateSha256]),
  );
  const checkedJcs = (ref, classification, label) => {
    reference(ref, `${label} reference`);
    if (referenced.has(ref.path)) fail('Q-07 evidence artifact is aliased or reused');
    const record = readJcsArtifact(ref, label);
    const bytes = canonical(record.value);
    const inventoryEntry = inventoryByPath.get(ref.path);
    if (
      record.sha256 !== ref.sha256
      || record.sha256 !== sha256(bytes)
      || inventoryEntry?.classification !== classification
      || inventoryEntry.sha256 !== record.sha256
      || inventoryEntry.bytes !== String(bytes.length)
    ) fail(`${label} hash/size/classification drifts: ${ref.path}`);
    referenced.add(ref.path);
    return Object.freeze({ ...record, bytes });
  };
  const checkedBytes = (ref, classification, label) => {
    reference(ref, `${label} reference`);
    if (referenced.has(ref.path)) fail('Q-07 evidence artifact is aliased or reused');
    const bytes = Buffer.from(readBytesArtifact(ref, label));
    const inventoryEntry = inventoryByPath.get(ref.path);
    if (
      sha256(bytes) !== ref.sha256
      || inventoryEntry?.classification !== classification
      || inventoryEntry.sha256 !== ref.sha256
      || inventoryEntry.bytes !== String(bytes.length)
    ) fail(`${label} hash/size/classification drifts: ${ref.path}`);
    referenced.add(ref.path);
    return bytes;
  };
  const storeDigest = readOpaqueArtifact(
    manifest.storeArtifact,
    'Q-07 authenticated store artifact',
  );
  const storeInventory = inventoryByPath.get(manifest.storeArtifact.path);
  if (
    referenced.has(manifest.storeArtifact.path)
    || storeDigest.sha256 !== manifest.storeArtifact.sha256
    || storeDigest.bytes !== manifest.storeBytes
    || storeInventory?.classification !== 'authenticated-store'
    || storeInventory.sha256 !== storeDigest.sha256
    || storeInventory.bytes !== storeDigest.bytes
  ) fail('Q-07 authenticated store artifact is absent, detached, or size-drifted');
  referenced.add(manifest.storeArtifact.path);
  const rawSamples = [];
  const phaseResults = [];
  const coldProcesses = new Set();
  const nonColdProcesses = new Set();
  const bootIds = new Set();
  const cgroupPaths = new Set();
  let evidenceStart = Number.POSITIVE_INFINITY;
  let evidenceEnd = Number.NEGATIVE_INFINITY;
  let warmCounters = null;
  for (const phase of manifest.phases) {
    const walls = [];
    const rssValues = [];
    for (const [index, ref] of phase.samples.entries()) {
      const label = `Q-07 ${phase.name} sample ${index + 1}`;
      const record = checkedJcs(ref, 'raw-sample', label);
      const measured = rawSample(
        record.value,
        phase.name,
        index + 1,
        commands.get(phase.name),
        manifest.terminalStateSha256,
        historyCheckpoints,
        label,
      );
      const input = checkedJcs(
        record.value.inputArtifact,
        'sample-input',
        `${label} input artifact`,
      );
      const expectedInput = expectedSampleInput({
        historySha256: historyVerification.fileSha256,
        identity: expectedIdentity,
        sample: record.value,
        storeArtifact: manifest.storeArtifact,
        terminalStateSha256: manifest.terminalStateSha256,
      });
      if (!canonical(input.value).equals(canonical(expectedInput))) {
        fail(`${label} input artifact is detached from the exact history checkpoint`);
      }
      const output = checkedJcs(
        record.value.outputArtifact,
        'sample-output',
        `${label} output artifact`,
      );
      const expectedReceipt = expectedMachineReceipt({
        historySha256: historyVerification.fileSha256,
        sample: record.value,
        storeArtifact: manifest.storeArtifact,
        terminalStateSha256: manifest.terminalStateSha256,
      });
      if (!canonical(output.value).equals(canonical(expectedReceipt))) {
        fail(`${label} output artifact is not the exact machine-readable receipt`);
      }
      const commandOutputs = {};
      for (const stream of ['stdout', 'stderr']) {
        const streamRef = record.value.execution[stream];
        const bytes = checkedBytes(
          streamRef,
          'raw-command-output',
          `${label} ${stream}`,
        );
        if (stream === 'stderr' && bytes.length !== 0) fail('Q-07 successful benchmark commands require empty raw stderr');
        if (stream === 'stdout') {
          const receipt = parseJcs(bytes, `${label} stdout receipt`);
          if (
            !canonical(receipt).equals(canonical(expectedReceipt))
            || !bytes.equals(output.bytes)
          ) fail('Q-07 stdout must be the exact JCS machine receipt and output artifact');
        }
        commandOutputs[stream] = bytes.toString('base64');
      }
      const processSet = phase.name === 'cold-sqlite-io' ? coldProcesses : nonColdProcesses;
      bootIds.add(record.value.process.bootId);
      cgroupPaths.add(record.value.rss.path);
      if (phase.name === 'cold-sqlite-io' && processSet.has(record.value.process.processInstanceId)) fail('Q-07 cold samples must use distinct fresh processes');
      processSet.add(record.value.process.processInstanceId);
      if (['incremental-apply-1k', 'incremental-apply-100k'].includes(phase.name)) {
        const serialized = canonical(record.value.fixedDepthOperationCounts);
        if (warmCounters === null) warmCounters = serialized;
        else if (!serialized.equals(warmCounters)) fail('Q-07 fixed-depth operation counts drift with history size or sample');
      }
      walls.push(measured.wall); rssValues.push(measured.rssBytes);
      evidenceStart = Math.min(evidenceStart, measured.started);
      evidenceEnd = Math.max(evidenceEnd, measured.completed);
      rawSamples.push(Object.freeze({
        inputArtifact: Object.freeze({
          path: record.value.inputArtifact.path,
          sha256: input.sha256,
          value: input.value,
        }),
        outputArtifact: Object.freeze({
          path: record.value.outputArtifact.path,
          sha256: output.sha256,
          value: output.value,
        }),
        path: ref.path,
        sha256: ref.sha256,
        stderrBase64: commandOutputs.stderr,
        stdoutBase64: commandOutputs.stdout,
        value: record.value,
      }));
    }
    const p95 = nearestRank(walls, 95, 100);
    const peakRss = rssValues.reduce((peak, entry) => entry > peak ? entry : peak, 0n);
    if (
      phase.reportedP95Nanoseconds !== p95.toString()
      || phase.reportedPeakRssBytes !== peakRss.toString()
    ) fail(`Q-07 ${phase.name} reported percentile or RSS differs from raw samples`);
    phaseResults.push(Object.freeze({ name: phase.name, p95, peakRss }));
  }
  for (const processId of coldProcesses) if (nonColdProcesses.has(processId)) fail('Q-07 cold process identity is reused by a warm or non-cold sample');
  if (bootIds.size !== 1) fail('Q-07 raw samples span multiple machine boots');
  const required = new Set([
    authority.value.artifactPaths.history,
    authority.value.artifactPaths.samplesManifest,
    ...referenced,
  ]);
  exactSet([...inventory.paths].sort(), [...required].sort(), 'Q-07 semantic inventory references');
  const performance = performanceSummary(
    phaseResults,
    decimal(manifest.storeBytes, 'Q-07 raw sample manifest storeBytes'),
  );
  return Object.freeze({
    bootId: [...bootIds][0],
    cgroupPaths: Object.freeze([...cgroupPaths].sort()),
    evidenceWindow: Object.freeze({ end: evidenceEnd, start: evidenceStart }),
    performance,
    rawSamples: Object.freeze(rawSamples),
    storeArtifact: Object.freeze({
      bytes: storeDigest.bytes,
      path: manifest.storeArtifact.path,
      sha256: storeDigest.sha256,
    }),
  });
}

/** Pure explicit sample fixture seam with complete artifact bytes and history pins. */
export function validateV2Q07SampleManifestForTestOnly(value, options = undefined) {
  if (options === undefined) {
    fail('Q-07 sample validation requires explicit signed-fixture context');
  }
  exact(options, [
    'authorityArtifact', 'expectedHistoryVerification', 'expectedIdentity',
    'inventory', 'rawSamples',
  ], 'Q-07 sample test options');
  const byPath = new Map(options.rawSamples.map((entry) => [entry.path, entry]));
  if (byPath.size !== options.rawSamples.length) {
    fail('Q-07 test artifacts contain duplicate paths');
  }
  const inventory = inventoryValue(options.inventory);
  return validateSampleSet({
    authority: authorityPolicy(options.authorityArtifact),
    historyVerification: options.expectedHistoryVerification,
    expectedIdentity: options.expectedIdentity,
    inventory,
    manifest: value,
    readJcsArtifact(ref) {
      const entry = byPath.get(ref.path);
      if (!entry || entry.sha256 !== ref.sha256 || entry.value === undefined) {
        fail(`Q-07 test JCS artifact is missing or hash-drifted: ${ref.path}`);
      }
      return Object.freeze({ sha256: entry.sha256, value: entry.value });
    },
    readBytesArtifact(ref) {
      const entry = byPath.get(ref.path);
      if (!entry || entry.sha256 !== ref.sha256 || !(entry.bytes instanceof Uint8Array)) fail(`Q-07 test byte artifact is missing or hash-drifted: ${ref.path}`);
      return Buffer.from(entry.bytes);
    },
    readOpaqueArtifact(ref) {
      const entry = byPath.get(ref.path);
      if (!entry || entry.sha256 !== ref.sha256 || !(entry.bytes instanceof Uint8Array)) {
        fail(`Q-07 test opaque artifact is missing or hash-drifted: ${ref.path}`);
      }
      const bytes = Buffer.from(entry.bytes);
      return Object.freeze({
        bytes: String(bytes.length),
        sha256: sha256(bytes),
      });
    },
  });
}

function sourceAlgorithms() {
  return Object.freeze(ALGORITHM_PATHS.map((path) => {
    const digest = stableDigest(resolve(workspace, path), `Q-07 production algorithm ${path}`);
    return Object.freeze({ path, sha256: digest.sha256 });
  }));
}
function validateAlgorithms(value, expected, label) {
  if (!Array.isArray(value) || !canonical(value).equals(canonical(expected))) fail(`${label} differs from the frozen production algorithms`);
  let prior = '';
  for (const entry of value) {
    exact(entry, ['path', 'sha256'], `${label} entry`);
    safeRelative(entry.path, `${label} path`);
    hash(entry.sha256, `${label} sha256`);
    if (entry.path <= prior) fail(`${label} must be uniquely path sorted`);
    prior = entry.path;
  }
  return value;
}
function stateEquals(left, right, context) {
  return encodeStateNftCommitment(left, context).equals(encodeStateNftCommitment(right, context));
}
function rootHex(value) { return value.toString(16).padStart(64, '0'); }
function stateSha256(state, stateContext) {
  return sha256(encodeStateNftCommitment(state, stateContext));
}
function stateTokenPrefixHash(state, instanceId, stateContext) {
  const commitment = encodeStateNftCommitment(state, stateContext);
  const prefix = encodeTokenPrefix({
    category: Uint8Array.from(Buffer.from(instanceId, 'hex').reverse()),
    amount: 0n,
    nft: { capability: 'mutable', commitment: Uint8Array.from(commitment) },
  });
  return sha256(Buffer.from(prefix));
}
function decodeContext(bytes, carrierCount, label) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 100 || !bytes.subarray(0, 4).equals(Buffer.from('SDC2'))) fail(`${label} is not an SDC2 context`);
  const kind = ({ 1: 'deposit', 2: 'transfer', 3: 'withdrawal' })[bytes[5]];
  if (kind === undefined || bytes.readUInt16LE(6) !== 0) fail(`${label} kind or flags are invalid`);
  const inputCount = bytes.readUInt16LE(80);
  const outputCount = bytes.readUInt16LE(82);
  const expectedInputs = carrierCount + 3;
  const expectedOutputs = carrierCount + (kind === 'withdrawal' ? 4 : 3);
  if (
    inputCount !== expectedInputs || outputCount !== expectedOutputs
    || bytes.length !== 100 + inputCount * 116 + outputCount * 76
  ) fail(`${label} does not have the exact PF10 context length`);
  const inputs = [];
  for (let index = 0; index < inputCount; index += 1) {
    const offset = 100 + index * 116;
    if (bytes[offset + 2] !== 0 || bytes[offset + 3] !== 0) fail(`${label} input role reserved bytes are nonzero`);
    inputs.push(Object.freeze({
      lockSha256: bytes.subarray(offset + 52, offset + 84).toString('hex'),
      ordinal: bytes[offset + 1],
      outpointIndex: bytes.readUInt32LE(offset + 36),
      outpointTransactionHash: bytes.subarray(offset + 4, offset + 36).toString('hex'),
      role: bytes[offset],
      sequence: bytes.readUInt32LE(offset + 40),
      tokenPrefixSha256: bytes.subarray(offset + 84, offset + 116).toString('hex'),
      valueSats: bytes.readBigUInt64LE(offset + 44),
    }));
  }
  const outputs = [];
  const outputBase = 100 + inputCount * 116;
  for (let index = 0; index < outputCount; index += 1) {
    const offset = outputBase + index * 76;
    if (bytes[offset + 2] !== 0 || bytes[offset + 3] !== 0) fail(`${label} output role reserved bytes are nonzero`);
    outputs.push(Object.freeze({
      lockSha256: bytes.subarray(offset + 12, offset + 44).toString('hex'),
      ordinal: bytes[offset + 1],
      role: bytes[offset],
      tokenPrefixSha256: bytes.subarray(offset + 44, offset + 76).toString('hex'),
      valueSats: bytes.readBigUInt64LE(offset + 4),
    }));
  }
  return Object.freeze({
    inputCount, inputs, instanceId: bytes.subarray(40, 72).toString('hex'),
    kind, locktime: bytes.readUInt32LE(76), networkId: bytes[4], outputCount,
    outputs, postActionSequence: bytes.readBigUInt64LE(92).toString(),
    preActionSequence: bytes.readBigUInt64LE(84).toString(),
    profileId: bytes.subarray(8, 40).toString('hex'),
    transactionVersion: bytes.readUInt32LE(72),
  });
}
function role(entry, code, ordinal, label) {
  if (entry.role !== code || entry.ordinal !== ordinal) fail(`${label} role is invalid`);
}
function publicBytecode(value, label, allowNull = false) {
  if (allowNull && value === null) return null;
  if (typeof value !== 'string' || value.length % 2 !== 0 || !P2PKH.test(value)) fail(`${label} must be exact canonical P2PKH bytecode`);
  return Buffer.from(value, 'hex');
}
function verifyContext(contextBytes, record, packet, spec, ordinal) {
  const label = `Q-07 history action ${ordinal} context`;
  const context = decodeContext(contextBytes, spec.carrierCount, label);
  if (
    context.networkId !== spec.networkId || context.kind !== packet.kind
    || context.profileId !== spec.identity.profileId
    || context.instanceId !== spec.identity.instanceId
    || context.transactionVersion !== 2 || context.locktime !== 0
    || context.preActionSequence !== packet.preState.actionSequence
    || context.postActionSequence !== packet.postState.actionSequence
  ) fail(`${label} header does not bind the exact action identity`);
  exact(record.publicLockingBytecodes, [
    'changeOutputHex', 'fundingInputHex', 'withdrawalOutputHex',
  ], `${label} publicLockingBytecodes`);
  const funding = publicBytecode(record.publicLockingBytecodes.fundingInputHex, `${label} fundingInputHex`);
  const change = publicBytecode(record.publicLockingBytecodes.changeOutputHex, `${label} changeOutputHex`);
  const withdrawal = publicBytecode(record.publicLockingBytecodes.withdrawalOutputHex, `${label} withdrawalOutputHex`, packet.kind !== 'withdrawal');
  if (
    packet.kind === 'withdrawal' && withdrawal === null
    || packet.kind !== 'withdrawal' && withdrawal !== null
  ) fail(`${label} withdrawal public lock presence is invalid`);
  const pins = spec.settlementPins;
  const empty = EMPTY_SHA256;
  const inputs = context.inputs;
  const outputs = context.outputs;
  for (let index = 0; index < spec.carrierCount; index += 1) {
    role(inputs[index], DIRECT_V2_ROLE_CODES.verifier, index, `${label} input ${index}`);
    role(outputs[index + 1], DIRECT_V2_ROLE_CODES.verifier, index, `${label} output ${index + 1}`);
    const expectedLock = sha256(pins.verifierCarriers[index].lockingBytecode);
    if (
      inputs[index].lockSha256 !== expectedLock || outputs[index + 1].lockSha256 !== expectedLock
      || inputs[index].tokenPrefixSha256 !== empty || outputs[index + 1].tokenPrefixSha256 !== empty
      || inputs[index].valueSats !== BigInt(pins.verifierCarriers[index].baseValueSats)
      || outputs[index + 1].valueSats !== BigInt(pins.verifierCarriers[index].baseValueSats)
    ) fail(`${label} verifier carrier ${index} differs from final settlement pins`);
  }
  const bindingIndex = spec.carrierCount;
  const stateIndex = spec.carrierCount + 1;
  const fundingIndex = spec.carrierCount + 2;
  role(inputs[bindingIndex], DIRECT_V2_ROLE_CODES.binding, 0, `${label} binding input`);
  role(inputs[stateIndex], DIRECT_V2_ROLE_CODES.state, 0, `${label} state input`);
  role(inputs[fundingIndex], DIRECT_V2_ROLE_CODES.funding, 0, `${label} funding input`);
  role(outputs[0], DIRECT_V2_ROLE_CODES.state, 0, `${label} state output`);
  role(outputs[spec.carrierCount + 1], DIRECT_V2_ROLE_CODES.binding, 0, `${label} binding output`);
  const bindingHash = sha256(pins.bindingLockingBytecode);
  const stateHash = sha256(pins.stateLockingBytecode);
  if (
    inputs[bindingIndex].lockSha256 !== bindingHash
    || outputs[spec.carrierCount + 1].lockSha256 !== bindingHash
    || inputs[bindingIndex].tokenPrefixSha256 !== empty
    || outputs[spec.carrierCount + 1].tokenPrefixSha256 !== empty
    || inputs[bindingIndex].valueSats !== BigInt(pins.bindingBaseSats)
    || outputs[spec.carrierCount + 1].valueSats !== BigInt(pins.bindingBaseSats)
  ) fail(`${label} binding carrier differs from final settlement pins`);
  if (
    inputs[stateIndex].lockSha256 !== stateHash || outputs[0].lockSha256 !== stateHash
    || inputs[stateIndex].tokenPrefixSha256 !== stateTokenPrefixHash(packet.preState, spec.identity.instanceId, spec.stateContext)
    || outputs[0].tokenPrefixSha256 !== stateTokenPrefixHash(packet.postState, spec.identity.instanceId, spec.stateContext)
    || inputs[stateIndex].valueSats !== BigInt(pins.stateBaseSats) + BigInt(packet.preState.reserveSats)
    || outputs[0].valueSats !== BigInt(pins.stateBaseSats) + BigInt(packet.postState.reserveSats)
  ) fail(`${label} state NFT/input/output differs from exact final state transition`);
  if (
    inputs[fundingIndex].lockSha256 !== sha256(funding)
    || inputs[fundingIndex].tokenPrefixSha256 !== empty
  ) fail(`${label} funding input is not the disclosed P2PKH source`);
  const changeIndex = outputs.length - 1;
  role(outputs[changeIndex], DIRECT_V2_ROLE_CODES.change, 0, `${label} change output`);
  if (outputs[changeIndex].lockSha256 !== sha256(change) || outputs[changeIndex].tokenPrefixSha256 !== empty) fail(`${label} change output is not disclosed canonical P2PKH`);
  if (packet.kind === 'withdrawal') {
    const withdrawalIndex = spec.carrierCount + 2;
    role(outputs[withdrawalIndex], DIRECT_V2_ROLE_CODES.withdrawal, 0, `${label} withdrawal output`);
    if (
      outputs[withdrawalIndex].lockSha256 !== sha256(withdrawal)
      || outputs[withdrawalIndex].tokenPrefixSha256 !== empty
      || outputs[withdrawalIndex].valueSats !== BigInt(spec.denominationSats)
      || packet.withdrawalLockingBytecodeHash !== sha256(withdrawal)
    ) fail(`${label} withdrawal output/hash/economics are invalid`);
  } else if (packet.withdrawalLockingBytecodeHash !== ZERO_32) fail(`${label} non-withdrawal packet has a withdrawal lock hash`);
  const inputTotal = inputs.reduce((sum, entry) => sum + entry.valueSats, 0n);
  const outputTotal = outputs.reduce((sum, entry) => sum + entry.valueSats, 0n);
  if (inputTotal <= outputTotal) fail(`${label} does not pay a positive fee`);
}
function parseHistoryLine(bytes, lineNumber) {
  if (bytes.length === 0 || bytes.length > MAX_HISTORY_LINE_BYTES) fail(`Q-07 history line ${lineNumber} is empty or oversized`);
  let textValue;
  try { textValue = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); } catch { fail(`Q-07 history line ${lineNumber} is not UTF-8`); }
  let value;
  try { value = JSON.parse(textValue); } catch { fail(`Q-07 history line ${lineNumber} is not JSON`); }
  if (canonicalizeJcs(value) !== textValue) fail(`Q-07 history line ${lineNumber} is not exact JCS`);
  return value;
}
function transcriptInitial(header) {
  return createHash('sha256').update(Buffer.from(HISTORY_DOMAIN)).update(canonical(header)).digest();
}
function actionPayload(record) {
  const { actionTranscriptSha256: _ignored, ...payload } = record;
  return payload;
}
function transcriptNext(previous, record) {
  return createHash('sha256')
    .update(Buffer.from(HISTORY_DOMAIN)).update(previous)
    .update(canonical(actionPayload(record))).digest();
}
function expectedKind(ordinal, actionCount) {
  return ordinal === 1 ? 'deposit' : ordinal === actionCount ? 'withdrawal' : 'transfer';
}
function historyHeader(value, spec, actionCount) {
  exact(value, [
    'actionCount', 'actionCounts', 'algorithmSources', 'classification',
    'denominationSats', 'identity', 'maximumLiveNotes', 'schema', 'type',
    'version',
  ], 'Q-07 history header');
  if (
    value.schema !== V2_Q07_HISTORY_SCHEMA || value.type !== 'header'
    || value.version !== '1' || value.classification !== HISTORY_CLASS
    || value.actionCount !== String(actionCount)
    || value.denominationSats !== spec.denominationSats
    || value.maximumLiveNotes !== spec.maximumLiveNotes
  ) fail('Q-07 history header shape or production parameters drift');
  exact(value.actionCounts, ['deposit', 'transfer', 'withdrawal'], 'Q-07 history actionCounts');
  const expectedCounts = { deposit: '1', transfer: String(actionCount - 2), withdrawal: '1' };
  if (!canonical(value.actionCounts).equals(canonical(expectedCounts))) fail('Q-07 history action counts are not exact');
  identity(value.identity, 'Q-07 history identity');
  if (!canonical(value.identity).equals(canonical(spec.identity))) fail('Q-07 history final identity drifts');
  validateAlgorithms(value.algorithmSources, spec.algorithmSources, 'Q-07 history algorithmSources');
  return value;
}
function verifyHistoryAction(record, ordinal, actionCount, state, noteAccumulator, nullifierStore, noteLeaves, transcript, spec) {
  const label = `Q-07 history action ${ordinal}`;
  exact(record, [
    'actionTranscriptSha256', 'contextHex', 'contextSha256', 'kind', 'ordinal',
    'packetHex', 'packetSha256', 'publicLockingBytecodes', 'schema', 'type',
  ], label);
  const kind = expectedKind(ordinal, actionCount);
  if (
    record.schema !== V2_Q07_HISTORY_SCHEMA || record.type !== 'action'
    || record.kind !== kind || record.ordinal !== String(ordinal)
    || typeof record.packetHex !== 'string' || record.packetHex.length !== ACTION_PACKET_BYTES * 2
    || !/^[0-9a-f]+$/u.test(record.packetHex)
    || typeof record.contextHex !== 'string' || record.contextHex.length % 2 !== 0
    || !/^[0-9a-f]+$/u.test(record.contextHex)
  ) fail(`${label} identity or byte encoding is invalid`);
  hash(record.packetSha256, `${label}.packetSha256`);
  hash(record.contextSha256, `${label}.contextSha256`);
  hash(record.actionTranscriptSha256, `${label}.actionTranscriptSha256`);
  const packetBytes = Buffer.from(record.packetHex, 'hex');
  const contextBytes = Buffer.from(record.contextHex, 'hex');
  if (sha256(packetBytes) !== record.packetSha256 || sha256(contextBytes) !== record.contextSha256) fail(`${label} packet/context hash drifts`);
  let packet;
  try { packet = decodeActionPacket(packetBytes, spec.stateContext); } catch (error) { fail(`${label} packet is invalid: ${error instanceof Error ? error.message : String(error)}`); }
  if (
    packet.kind !== kind || packet.networkId !== spec.networkId
    || packet.instanceId !== spec.identity.instanceId
    || packet.transactionContextHash !== record.contextSha256
    || !stateEquals(packet.preState, state, spec.stateContext)
  ) fail(`${label} packet identity or pre-state continuity is invalid`);
  let noteRoot = state.noteRoot;
  if (kind === 'withdrawal') {
    if (packet.outputNoteLeaf !== ZERO_32 || !Buffer.from(packet.encryptedRecord).equals(Buffer.alloc(128))) fail(`${label} withdrawal invents an output note`);
  } else {
    if (
      packet.outputNoteLeaf === ZERO_32 || noteLeaves.has(packet.outputNoteLeaf)
      || Buffer.from(packet.encryptedRecord).equals(Buffer.alloc(128))
    ) fail(`${label} output note is zero, duplicated, or missing its encrypted record`);
    noteLeaves.add(packet.outputNoteLeaf);
    try { noteRoot = appendQ07Note(noteAccumulator, Buffer.from(packet.outputNoteLeaf, 'hex')).postRoot.toString('hex'); }
    catch (error) { fail(`${label} output leaf is not accepted by the production note accumulator: ${error instanceof Error ? error.message : String(error)}`); }
  }
  let nullifierRoot = state.nullifierRoot;
  if (kind === 'deposit') {
    if (packet.publicNullifier !== ZERO_32) fail(`${label} deposit nullifier is nonzero`);
  } else {
    if (packet.publicNullifier === ZERO_32) fail(`${label} spend nullifier is zero`);
    try { nullifierRoot = rootHex(nullifierStore.insert(BigInt(`0x${packet.publicNullifier}`)).root); }
    catch (error) { fail(`${label} nullifier is duplicate or outside the production indexed tree: ${error instanceof Error ? error.message : String(error)}`); }
  }
  const expectedState = Object.freeze({
    actionSequence: String(ordinal),
    maximumLiveNotes: spec.maximumLiveNotes,
    noteCount: String(BigInt(state.noteCount) + (kind === 'withdrawal' ? 0n : 1n)),
    noteRoot,
    nullifierCount: String(BigInt(state.nullifierCount) + (kind === 'deposit' ? 0n : 1n)),
    nullifierRoot,
    profileId: spec.identity.profileId,
    reserveSats: kind === 'deposit' ? spec.denominationSats : kind === 'withdrawal' ? '0' : state.reserveSats,
  });
  if (!stateEquals(packet.postState, expectedState, spec.stateContext)) fail(`${label} post-state does not follow the frozen production tree/state algorithms`);
  verifyContext(contextBytes, record, packet, spec, ordinal);
  const expectedTranscript = transcriptNext(transcript, record);
  if (record.actionTranscriptSha256 !== expectedTranscript.toString('hex')) fail(`${label} transcript is invalid`);
  return Object.freeze({ state: expectedState, transcript: expectedTranscript });
}
function verifyHistory(pathname, spec, actionCount) {
  if (!Number.isSafeInteger(actionCount) || actionCount < 3 || actionCount > V2_Q07_HISTORY_ACTIONS) fail('Q-07 history action count is invalid');
  const opened = openStable(pathname, 'Q-07 final history');
  try {
    const all = createHash('sha256');
    const body = createHash('sha256');
    const chunk = Buffer.alloc(READ_CHUNK_BYTES);
    let carry = Buffer.alloc(0);
    let lineNumber = 0;
    let header = null;
    let ended = false;
    let end = null;
    let transcript = null;
    let state = decodeStateNftCommitment(spec.initialStateBytes, spec.stateContext);
    const checkpointCounts = new Set(historyCheckpointCounts(actionCount));
    const checkpoints = new Map([[
      '0',
      stateSha256(state, spec.stateContext),
    ]]);
    const noteAccumulator = createQ07NoteAccumulator();
    const noteLeaves = new Set();
    const nullifierStore = createIndexedNullifierQualificationStore({
      depth: Q07_NOTE_TREE_DEPTH,
      hashLeaf: hashIndexedNullifierLeaf,
      hashNode: hashIndexedNullifierNode,
      maximumInserts: actionCount - 1,
    });
    if (
      state.noteRoot !== auditQ07NoteAccumulator(noteAccumulator).rootHex
      || state.nullifierRoot !== rootHex(nullifierStore.snapshot().root)
      || state.noteCount !== '0' || state.nullifierCount !== '0'
      || state.reserveSats !== '0' || state.actionSequence !== '0'
    ) fail('Q-07 descriptor genesis differs from the production history trees');
    const processLine = (line, raw) => {
      lineNumber += 1;
      const value = parseHistoryLine(line, lineNumber);
      all.update(raw);
      if (lineNumber === 1) {
        header = historyHeader(value, spec, actionCount);
        transcript = transcriptInitial(header);
        body.update(raw);
        return;
      }
      if (ended) fail('Q-07 history has records after its end record');
      if (lineNumber <= actionCount + 1) {
        body.update(raw);
        const next = verifyHistoryAction(value, lineNumber - 1, actionCount, state, noteAccumulator, nullifierStore, noteLeaves, transcript, spec);
        state = next.state; transcript = next.transcript;
        const ordinal = lineNumber - 1;
        if (checkpointCounts.has(ordinal)) {
          checkpoints.set(String(ordinal), stateSha256(state, spec.stateContext));
        }
        return;
      }
      if (lineNumber !== actionCount + 2) fail('Q-07 history has an extra record');
      end = value; ended = true;
    };
    for (;;) {
      const count = readSync(opened.fd, chunk, 0, chunk.length, null);
      if (count === 0) break;
      const combined = carry.length === 0
        ? chunk.subarray(0, count)
        : Buffer.concat([carry, chunk.subarray(0, count)]);
      let start = 0;
      for (;;) {
        const newline = combined.indexOf(0x0a, start);
        if (newline === -1) break;
        processLine(combined.subarray(start, newline), combined.subarray(start, newline + 1));
        start = newline + 1;
      }
      carry = Buffer.from(combined.subarray(start));
      if (carry.length > MAX_HISTORY_LINE_BYTES) fail('Q-07 history contains an oversized unterminated line');
    }
    if (carry.length !== 0 || !ended || end === null) fail('Q-07 history is truncated or lacks final newlines');
    exact(end, [
      'actionCount', 'actionCounts', 'actionTranscriptSha256', 'bodySha256',
      'recordCount', 'schema', 'terminal', 'terminalStateHex',
      'terminalStateSha256', 'type', 'version',
    ], 'Q-07 history end');
    if (
      end.schema !== V2_Q07_HISTORY_SCHEMA || end.type !== 'end'
      || end.version !== '1' || end.actionCount !== String(actionCount)
      || end.recordCount !== String(actionCount + 2)
      || !canonical(end.actionCounts).equals(canonical(header.actionCounts))
      || end.bodySha256 !== body.digest('hex')
      || end.actionTranscriptSha256 !== transcript.toString('hex')
    ) fail('Q-07 history end identity, count, body, or transcript is invalid');
    exact(end.terminal, [
      'actionSequence', 'liveNotes', 'noteCount', 'noteRoot',
      'nullifierCount', 'nullifierRoot', 'reserveSats',
    ], 'Q-07 history terminal');
    const expectedTerminal = {
      actionSequence: String(actionCount),
      liveNotes: '0',
      noteCount: String(actionCount - 1),
      noteRoot: state.noteRoot,
      nullifierCount: String(actionCount - 1),
      nullifierRoot: state.nullifierRoot,
      reserveSats: '0',
    };
    if (!canonical(end.terminal).equals(canonical(expectedTerminal))) fail('Q-07 history terminal counts, roots, reserve, or live-note state drift');
    const terminalStateHex = encodeStateNftCommitment(state, spec.stateContext).toString('hex');
    if (
      end.terminalStateHex !== terminalStateHex
      || end.terminalStateSha256 !== sha256(Buffer.from(terminalStateHex, 'hex'))
    ) fail('Q-07 history terminal state commitment is invalid');
    const expectedCheckpointCounts = historyCheckpointCounts(actionCount);
    if (
      checkpoints.size !== expectedCheckpointCounts.length
      || expectedCheckpointCounts.some((count) => !checkpoints.has(String(count)))
    ) fail('Q-07 history did not materialize every required phase checkpoint');
    closeStable(opened, pathname, 'Q-07 final history');
    return Object.freeze({
      actionCount: String(actionCount),
      actionCounts: Object.freeze({ ...header.actionCounts }),
      actionTranscriptSha256: transcript.toString('hex'),
      algorithmSources: Object.freeze(header.algorithmSources.map((entry) => Object.freeze({ ...entry }))),
      bodySha256: end.bodySha256,
      chainAuthenticated: false,
      checkpoints: Object.freeze(expectedCheckpointCounts.map((count) =>
        Object.freeze({
          actionCount: String(count),
          stateSha256: checkpoints.get(String(count)),
        }))),
      fileSha256: all.digest('hex'),
      terminal: Object.freeze({ ...end.terminal }),
      terminalStateHex,
      terminalStateSha256: end.terminalStateSha256,
    });
  } finally { closeSync(opened.fd); }
}

/** Reduced signed-fixture history seam. It cannot be called by the production runner. */
export function verifyV2Q07FinalHistoryForTestOnly({
  actionCount, path, spec,
} = {}) {
  if (!Number.isSafeInteger(actionCount) || actionCount < 3 || actionCount > 64) fail('Q-07 test history actionCount must be 3 through 64');
  return verifyHistory(path, spec, actionCount);
}

function q02Result(value) {
  exact(value, [
    'cases', 'descriptorSha256', 'externalLaneRuns', 'manifestSha256',
    'mutations', 'q02Qualified', 'releaseBootstrapSha256', 'releaseRootId',
    'schema',
  ], 'Q-07 Q-02 verification result');
  if (
    value.cases !== 768 || value.mutations !== 9_984
    || value.externalLaneRuns !== 33_024 || value.q02Qualified !== true
    || value.schema !== V2_Q02_CORPUS_SCHEMA
  ) fail('Q-07 Q-02 verification result is incomplete or boolean-only');
  for (const key of ['descriptorSha256', 'manifestSha256', 'releaseBootstrapSha256']) hash(value[key], `Q-07 Q-02 result.${key}`);
  if (!ROOT_ID.test(value.releaseRootId) || typeof value.schema !== 'string' || value.schema.length === 0) fail('Q-07 Q-02 result identity is invalid');
  return value;
}
function historyResult(value, expectedActionCount = V2_Q07_HISTORY_ACTIONS) {
  exact(value, [
    'actionCount', 'actionCounts', 'actionTranscriptSha256',
    'algorithmSources', 'bodySha256', 'chainAuthenticated', 'checkpoints',
    'fileSha256', 'terminal', 'terminalStateHex', 'terminalStateSha256',
  ], 'Q-07 history verification result');
  if (
    value.actionCount !== String(expectedActionCount)
    || value.chainAuthenticated !== false
  ) fail('Q-07 history verification classification or action count drifts');
  for (const key of ['actionTranscriptSha256', 'bodySha256', 'fileSha256', 'terminalStateSha256']) hash(value[key], `Q-07 history verification.${key}`);
  if (typeof value.terminalStateHex !== 'string' || value.terminalStateHex.length !== 256 || !/^[0-9a-f]+$/u.test(value.terminalStateHex)) fail('Q-07 terminal state bytes are invalid');
  if (
    value.terminalStateSha256
      !== sha256(Buffer.from(value.terminalStateHex, 'hex'))
  ) fail('Q-07 terminal state hash does not bind the terminal state bytes');
  if (!Array.isArray(value.algorithmSources) || value.algorithmSources.length === 0) fail('Q-07 history verification lacks production algorithm sources');
  let priorAlgorithm = '';
  for (const entry of value.algorithmSources) {
    exact(entry, ['path', 'sha256'], 'Q-07 history verification algorithm source');
    safeRelative(entry.path, 'Q-07 history verification algorithm path');
    hash(entry.sha256, 'Q-07 history verification algorithm sha256');
    if (entry.path <= priorAlgorithm) fail('Q-07 history verification algorithm sources must be uniquely path sorted');
    priorAlgorithm = entry.path;
  }
  exact(value.actionCounts, ['deposit', 'transfer', 'withdrawal'], 'Q-07 history verification actionCounts');
  if (!canonical(value.actionCounts).equals(canonical({ deposit: '1', transfer: String(expectedActionCount - 2), withdrawal: '1' }))) fail('Q-07 history verification action counts drift');
  exact(value.terminal, ['actionSequence', 'liveNotes', 'noteCount', 'noteRoot', 'nullifierCount', 'nullifierRoot', 'reserveSats'], 'Q-07 history verification terminal');
  for (const key of ['noteRoot', 'nullifierRoot']) hash(value.terminal[key], `Q-07 history terminal.${key}`);
  if (
    value.terminal.actionSequence !== String(expectedActionCount)
    || value.terminal.liveNotes !== '0'
    || value.terminal.noteCount !== String(expectedActionCount - 1)
    || value.terminal.nullifierCount !== String(expectedActionCount - 1)
    || value.terminal.reserveSats !== '0'
  ) fail('Q-07 history verification terminal state is incomplete');
  const expectedCheckpointCounts = historyCheckpointCounts(expectedActionCount);
  if (
    !Array.isArray(value.checkpoints)
    || value.checkpoints.length !== expectedCheckpointCounts.length
  ) fail('Q-07 history verification checkpoint set is incomplete');
  value.checkpoints.forEach((entry, index) => {
    exact(entry, ['actionCount', 'stateSha256'], `Q-07 history checkpoint ${index}`);
    if (entry.actionCount !== String(expectedCheckpointCounts[index])) {
      fail('Q-07 history verification checkpoints are detached, missing, or reordered');
    }
    hash(entry.stateSha256, `Q-07 history checkpoint ${index}.stateSha256`);
  });
  const terminalCheckpoint = value.checkpoints.at(-1);
  if (terminalCheckpoint.stateSha256 !== value.terminalStateSha256) {
    fail('Q-07 terminal history checkpoint differs from the terminal state');
  }
  return value;
}
function b02Identity(result, expected) {
  for (const key of [
    'descriptorSha256', 'finalLocksSha256', 'instanceId', 'manifestSha256',
    'profileId', 'profileSha256', 'releaseBootstrapSha256', 'releaseRootId',
    'runtimeMaterialSha256', 'sourceCommit', 'sourceTree', 'topologyId',
  ]) if (result[key] !== expected[key]) fail(`Q-07 B-02 identity drifts at ${key}`);
  hardPolicy({
    ...result.hardPolicyCeilings,
    narrowerMargins: result.narrowerMargins,
  }, 'Q-07 independently revalidated B-02 hard policy');
}
function assertTokenlessLockAndValue(
  output,
  lockingBytecode,
  valueSats,
  label,
) {
  if (
    output.lockingBytecodeHex !== Buffer.from(lockingBytecode).toString('hex')
    || output.token !== null
    || output.valueSatoshis !== BigInt(valueSats)
  ) fail(`${label} differs from the exact final settlement lock/value/token pin`);
}
function assertStateOutput(output, settlementPins, instanceId, reserveSats, label) {
  if (
    output.lockingBytecodeHex
      !== Buffer.from(settlementPins.stateLockingBytecode).toString('hex')
    || output.valueSatoshis
      !== BigInt(settlementPins.stateBaseSats) + BigInt(reserveSats)
    || output.token?.categoryWire !== instanceId
    || output.token.amount !== '0'
    || output.token.nft?.capability !== 'mutable'
    || output.token.nft.commitmentHex.length !== 256
  ) fail(`${label} differs from the exact final state settlement pin`);
}
function assertB02FinalPins({
  b02Result, denominationSats, expectedAuthorityArtifactSha256,
  expectedIdentity, expectedTransactionsManifest,
  expectedTransactionsManifestSha256, settlementPins,
}) {
  exact(expectedTransactionsManifest, [
    'identity', 'maintainerBenchmark', 'schema', 'transactions',
  ], 'Q-07 signed-manifest B-02 transactions');
  if (
    expectedTransactionsManifest.schema !== V2_B02_TRANSACTIONS_SCHEMA
    || b02Result.authorityArtifactSha256 !== expectedAuthorityArtifactSha256
    || sha256(canonical(b02Result.laneAuthorityArtifact))
      !== expectedAuthorityArtifactSha256
    || b02Result.transactionsManifestSha256
      !== expectedTransactionsManifestSha256
    || sha256(canonical(expectedTransactionsManifest))
      !== expectedTransactionsManifestSha256
  ) fail('Q-07 B-02 authority or final transaction manifest is not signed-manifest pinned');
  if (
    !canonical(expectedTransactionsManifest.maintainerBenchmark).equals(
      canonical(b02Result.maintainerBenchmark),
    )
  ) fail('Q-07 B-02 maintainer benchmark differs from the signed transaction manifest');
  if (
    !canonical(expectedTransactionsManifest.identity).equals(
      canonical(expectedIdentity),
    )
    || !Array.isArray(expectedTransactionsManifest.transactions)
    || expectedTransactionsManifest.transactions.length !== 3
  ) fail('Q-07 signed-manifest B-02 transaction set has the wrong final identity or cardinality');
  b02Identity(b02Result, expectedIdentity);
  if (
    !Array.isArray(b02Result.transactions)
    || b02Result.transactions.length !== 3
  ) fail('Q-07 B-02 final settlement set is incomplete');
  const carrierCount = settlementPins.verifierCarriers.length;
  const kinds = ['deposit', 'transfer', 'withdrawal'];
  b02Result.transactions.forEach((entry, actionIndex) => {
    const kind = kinds[actionIndex];
    const pinned = expectedTransactionsManifest.transactions[actionIndex];
    if (entry.kind !== kind || !Array.isArray(entry.sourceOutputs)) {
      fail('Q-07 B-02 actions are missing or reordered');
    }
    if (
      pinned?.kind !== kind
      || pinned.rawTransactionHex !== entry.rawTransactionHex
      || pinned.rawTransactionSha256 !== entry.rawTransactionSha256
      || pinned.transactionId !== entry.transactionId
      || !canonical(pinned.sourceOutputs).equals(canonical(entry.sourceOutputs))
    ) fail(`Q-07 B-02 ${kind} result differs from the exact signed-manifest transaction`);
    let transaction;
    try {
      transaction = parseV2RawTransaction(entry.rawTransactionHex);
    } catch (error) {
      fail(`Q-07 B-02 ${kind} raw transaction is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`);
    }
    if (
      transaction.inputs.length !== carrierCount + 3
      || transaction.outputs.length
        !== carrierCount + (kind === 'withdrawal' ? 4 : 3)
      || entry.sourceOutputs.length !== transaction.inputs.length
    ) fail(`Q-07 B-02 ${kind} transaction does not have the exact final topology`);
    if (
      pinned.carrierCount !== carrierCount
      || pinned.inputCount !== transaction.inputs.length
      || pinned.outputCount !== transaction.outputs.length
      || pinned.serializedBytes !== transaction.sizeBytes
      || !Array.isArray(pinned.inputRoles)
      || !Array.isArray(pinned.outputRoles)
      || !canonical(pinned.inputRoles).equals(
        canonical(entry.inputRoleLayout),
      )
      || !canonical(pinned.outputRoles).equals(
        canonical(entry.outputRoleLayout),
      )
    ) fail(`Q-07 B-02 ${kind} signed-manifest topology metadata drifts`);
    const sources = entry.sourceOutputs.map((source, index) => {
      if (
        source.index !== index
        || source.outpoint.txid !== transaction.inputs[index].outpoint.txid
        || source.outpoint.vout !== transaction.inputs[index].outpoint.vout
      ) fail(`Q-07 B-02 ${kind} source output ${index} is detached`);
      try { return parseSerializedSourceOutput(source.serializedHex); } catch (error) {
        fail(`Q-07 B-02 ${kind} source output ${index} is invalid: ${
          error instanceof Error ? error.message : String(error)
        }`);
      }
    });
    for (let index = 0; index < carrierCount; index += 1) {
      assertTokenlessLockAndValue(
        sources[index],
        settlementPins.verifierCarriers[index].lockingBytecode,
        settlementPins.verifierCarriers[index].baseValueSats,
        `Q-07 B-02 ${kind} verifier source ${index}`,
      );
      assertTokenlessLockAndValue(
        parseSerializedSourceOutput(transaction.outputs[index + 1].serializedHex),
        settlementPins.verifierCarriers[index].lockingBytecode,
        settlementPins.verifierCarriers[index].baseValueSats,
        `Q-07 B-02 ${kind} verifier output ${index + 1}`,
      );
    }
    assertTokenlessLockAndValue(
      sources[carrierCount],
      settlementPins.bindingLockingBytecode,
      settlementPins.bindingBaseSats,
      `Q-07 B-02 ${kind} binding source`,
    );
    assertTokenlessLockAndValue(
      parseSerializedSourceOutput(
        transaction.outputs[carrierCount + 1].serializedHex,
      ),
      settlementPins.bindingLockingBytecode,
      settlementPins.bindingBaseSats,
      `Q-07 B-02 ${kind} binding output`,
    );
    const reserveBefore = kind === 'deposit' ? '0' : denominationSats;
    const reserveAfter = kind === 'withdrawal' ? '0' : denominationSats;
    assertStateOutput(
      sources[carrierCount + 1],
      settlementPins,
      expectedIdentity.instanceId,
      reserveBefore,
      `Q-07 B-02 ${kind} state source`,
    );
    assertStateOutput(
      parseSerializedSourceOutput(transaction.outputs[0].serializedHex),
      settlementPins,
      expectedIdentity.instanceId,
      reserveAfter,
      `Q-07 B-02 ${kind} state output`,
    );
    const funding = sources[carrierCount + 2];
    if (
      funding.token !== null
      || !P2PKH.test(funding.lockingBytecodeHex)
    ) fail(`Q-07 B-02 ${kind} funding source is not canonical tokenless P2PKH`);
    const publicStart = carrierCount + 2;
    const publicOutputs = transaction.outputs.slice(publicStart).map((output) =>
      parseSerializedSourceOutput(output.serializedHex));
    if (
      publicOutputs.some((output) =>
        output.token !== null || !P2PKH.test(output.lockingBytecodeHex))
      || (kind === 'withdrawal'
        && publicOutputs[0].valueSatoshis !== BigInt(denominationSats))
    ) fail(`Q-07 B-02 ${kind} public payout/change outputs are invalid`);
  });
  return true;
}

/** Explicit final-pin test seam; it grants no release or manifest authority. */
export function validateV2Q07B02FinalPinsForTestOnly(options) {
  exact(options, [
    'b02Result', 'denominationSats', 'expectedAuthorityArtifactSha256',
    'expectedIdentity', 'expectedTransactionsManifest',
    'expectedTransactionsManifestSha256', 'settlementPins',
  ], 'Q-07 B-02 final-pin test options');
  return assertB02FinalPins(options);
}
function independentTrustRoots(value) {
  exact(value, [
    'authorityArtifactSha256', 'authorityPublicKeyPem', 'b02Identity',
    'b02ResultSha256', 'historySha256', 'historyVerificationSha256',
    'identity', 'q02CorpusSha256', 'q02Verification', 'storeArtifact',
  ], 'Q-07 independent result trust roots');
  identity(value.identity, 'Q-07 independently expected final identity');
  identity(value.b02Identity, 'Q-07 independently expected B-02 identity');
  if (!canonical(value.identity).equals(canonical(value.b02Identity))) {
    fail('Q-07 independently expected final and B-02 identities differ');
  }
  for (const key of [
    'authorityArtifactSha256', 'b02ResultSha256', 'historySha256',
    'historyVerificationSha256', 'q02CorpusSha256',
  ]) hash(value[key], `Q-07 independent result trust roots.${key}`);
  canonicalPublicKey(
    value.authorityPublicKeyPem,
    'Q-07 independently expected benchmark authority public key',
  );
  q02Result(value.q02Verification);
  exact(value.storeArtifact, ['bytes', 'path', 'sha256'], 'Q-07 independently expected store artifact');
  decimal(value.storeArtifact.bytes, 'Q-07 independently expected store bytes', 1n);
  safeRelative(value.storeArtifact.path, 'Q-07 independently expected store path');
  hash(value.storeArtifact.sha256, 'Q-07 independently expected store sha256');
  return value;
}
function resultCore(
  value,
  {
    b02Revalidator,
    expectedActionCount = V2_Q07_HISTORY_ACTIONS,
    expectedTrustRoots,
  },
) {
  if (typeof b02Revalidator !== 'function' || expectedTrustRoots === undefined) {
    fail('Q-07 result revalidation requires an independent trust-root context');
  }
  const expected = independentTrustRoots(expectedTrustRoots);
  exact(value, [
    'authorityArtifact', 'authorityArtifactSha256', 'b02Result',
    'b02Revalidation', 'evidenceEnvelope', 'evidenceEnvelopeSha256',
    'evidenceInventory', 'evidenceInventorySha256', 'hardPolicyCeilings',
    'historyVerification', 'identity', 'performance', 'production',
    'q02Verification', 'q07Qualified', 'rawSamples', 'releaseQualified',
    'samplesManifest', 'schema', 'status',
  ], 'Q-07 final result');
  if (
    value.schema !== V2_Q07_FINAL_PERFORMANCE_SCHEMA
    || value.status !== 'q07-qualified-final-performance-not-production-or-release'
    || value.q07Qualified !== true || value.production !== false
    || value.releaseQualified !== false
  ) fail('Q-07 final result status is not exact');
  identity(value.identity, 'Q-07 final result identity');
  if (!canonical(value.identity).equals(canonical(expected.identity))) {
    fail('Q-07 result identity differs from the independently derived release/descriptor/final-manifest identity');
  }
  hardPolicy(value.hardPolicyCeilings, 'Q-07 final result hardPolicyCeilings');
  const policySha = sha256(canonical(value.authorityArtifact));
  if (
    value.authorityArtifactSha256 !== policySha
    || policySha !== expected.authorityArtifactSha256
    || value.authorityArtifact?.authority?.publicKeyPem
      !== expected.authorityPublicKeyPem
  ) fail('Q-07 result benchmark authority differs from the independent final-manifest pin');
  const authority = authorityPolicy(value.authorityArtifact);
  const parsedInventory = inventoryValue(value.evidenceInventory);
  if (value.evidenceInventorySha256 !== sha256(canonical(value.evidenceInventory))) fail('Q-07 result inventory hash drifts');
  if (value.evidenceEnvelopeSha256 !== sha256(canonical(value.evidenceEnvelope))) fail('Q-07 result envelope hash drifts');
  const history = historyResult(value.historyVerification, expectedActionCount);
  if (
    history.fileSha256 !== expected.historySha256
    || sha256(canonical(history)) !== expected.historyVerificationSha256
  ) fail('Q-07 standalone history differs from independent corpus/replay pins');
  if (
    value.samplesManifest.terminalStateSha256
      !== history.terminalStateSha256
  ) fail('Q-07 sample manifest does not bind the replayed history terminal state');
  const historyInventory = value.evidenceInventory.artifacts.find(
    (entry) => entry.path === authority.value.artifactPaths.history,
  );
  if (
    historyInventory?.classification !== 'history-corpus'
    || historyInventory.sha256 !== history.fileSha256
  ) fail('Q-07 standalone history is not the exact inventory-pinned corpus');
  const manifestBytes = canonical(value.samplesManifest);
  const manifestInventory = value.evidenceInventory.artifacts.find(
    (entry) => entry.path === authority.value.artifactPaths.samplesManifest,
  );
  if (
    manifestInventory?.classification !== 'sample-manifest'
    || manifestInventory.sha256 !== sha256(manifestBytes)
    || manifestInventory.bytes !== String(manifestBytes.length)
  ) fail('Q-07 standalone sample manifest is not the exact inventory-pinned artifact');
  q02Result(value.q02Verification);
  if (!canonical(value.q02Verification).equals(canonical(expected.q02Verification))) {
    fail('Q-07 Q-02 verification differs from the independent corpus replay');
  }
  const b02Derived = b02Revalidator(value.b02Result);
  if (!canonical(b02Derived).equals(canonical(value.b02Revalidation))) fail('Q-07 embedded B-02 revalidation drifts');
  if (sha256(canonical(value.b02Result)) !== expected.b02ResultSha256) {
    fail('Q-07 B-02 result differs from the independently supplied result hash');
  }
  b02Identity(value.b02Result, expected.b02Identity);
  if (
    value.q02Verification.descriptorSha256 !== value.identity.descriptorSha256
    || value.q02Verification.manifestSha256 !== value.identity.manifestSha256
    || value.q02Verification.releaseBootstrapSha256 !== value.identity.releaseBootstrapSha256
    || value.q02Verification.releaseRootId !== value.identity.releaseRootId
  ) fail('Q-07 Q-02 verification identity drifts');
  const embeddedArtifacts = value.rawSamples.flatMap((entry) => {
    exact(entry, [
      'inputArtifact', 'outputArtifact', 'path', 'sha256', 'stderrBase64',
      'stdoutBase64', 'value',
    ], 'Q-07 embedded raw sample');
    exact(entry.inputArtifact, ['path', 'sha256', 'value'], 'Q-07 embedded sample input artifact');
    exact(entry.outputArtifact, ['path', 'sha256', 'value'], 'Q-07 embedded sample output artifact');
    const decode = (encoded, label) => {
      if (typeof encoded !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(encoded)) fail(`${label} is not canonical base64`);
      const bytes = Buffer.from(encoded, 'base64');
      if (bytes.toString('base64') !== encoded) fail(`${label} is not canonical base64`);
      return bytes;
    };
    return [
      { path: entry.path, sha256: entry.sha256, value: entry.value },
      entry.inputArtifact,
      entry.outputArtifact,
      {
        bytes: decode(entry.stdoutBase64, 'Q-07 embedded stdout'),
        path: entry.value.execution.stdout.path,
        sha256: entry.value.execution.stdout.sha256,
      },
      {
        bytes: decode(entry.stderrBase64, 'Q-07 embedded stderr'),
        path: entry.value.execution.stderr.path,
        sha256: entry.value.execution.stderr.sha256,
      },
    ];
  });
  const embeddedByPath = new Map(
    embeddedArtifacts.map((entry) => [entry.path, entry]),
  );
  if (embeddedByPath.size !== embeddedArtifacts.length) {
    fail('Q-07 embedded sample artifacts contain aliases or duplicate paths');
  }
  const sampleVerification = validateSampleSet({
    authority,
    expectedIdentity: expected.identity,
    historyVerification: history,
    inventory: parsedInventory,
    manifest: value.samplesManifest,
    readBytesArtifact(ref) {
      const entry = embeddedByPath.get(ref.path);
      if (!entry || entry.sha256 !== ref.sha256 || !(entry.bytes instanceof Uint8Array)) {
        fail(`Q-07 embedded byte artifact is missing or hash-drifted: ${ref.path}`);
      }
      return Buffer.from(entry.bytes);
    },
    readJcsArtifact(ref) {
      const entry = embeddedByPath.get(ref.path);
      if (!entry || entry.sha256 !== ref.sha256 || entry.value === undefined) {
        fail(`Q-07 embedded JCS artifact is missing or hash-drifted: ${ref.path}`);
      }
      return Object.freeze({ sha256: entry.sha256, value: entry.value });
    },
    readOpaqueArtifact(ref) {
      if (
        ref.path !== expected.storeArtifact.path
        || ref.sha256 !== expected.storeArtifact.sha256
      ) fail('Q-07 store artifact differs from the independent physical pin');
      return expected.storeArtifact;
    },
  });
  if (
    value.rawSamples.length !== PHASES.length * V2_Q07_SAMPLE_COUNT
    || !canonical(value.rawSamples).equals(canonical(sampleVerification.rawSamples))
  ) fail('Q-07 standalone raw sample set has extras, omissions, aliases, or reordered values');
  if (!canonical(sampleVerification.performance).equals(canonical(value.performance))) fail('Q-07 result performance summary drifts');
  const normalizedSampleSet = sampleVerification.rawSamples.map((entry) => ({
    path: entry.path,
    sha256: entry.sha256,
    inputArtifactSha256: entry.inputArtifact.sha256,
    outputArtifactSha256: entry.outputArtifact.sha256,
    stderrSha256: entry.value.execution.stderr.sha256,
    stdoutSha256: entry.value.execution.stdout.sha256,
  }));
  const expectedArtifacts = {
    b02ResultSha256: expected.b02ResultSha256,
    b02RevalidationSha256: sha256(canonical(b02Derived)),
    historySha256: expected.historySha256,
    historyVerificationSha256: expected.historyVerificationSha256,
    inventorySha256: value.evidenceInventorySha256,
    q02CorpusSha256: expected.q02CorpusSha256,
    q02VerificationSha256: sha256(canonical(value.q02Verification)),
    samplesManifestSha256: sha256(canonical(value.samplesManifest)),
    samplesVerificationSha256: sha256(canonical({
      performance: sampleVerification.performance,
      rawSampleSetSha256: sha256(canonical(normalizedSampleSet)),
    })),
  };
  verifyEnvelope({
    authorityArtifactSha256: policySha,
    envelope: value.evidenceEnvelope,
    expectedArtifacts,
    expectedBootId: sampleVerification.bootId,
    expectedCgroupPaths: sampleVerification.cgroupPaths,
    expectedEvidenceWindow: sampleVerification.evidenceWindow,
    expectedIdentity: value.identity,
    expectedMachineRunId: value.samplesManifest.machineRunId,
    policy: authority,
  });
  return Object.freeze({
    b02Revalidation: b02Derived,
    historyVerification: history,
    performance: sampleVerification.performance,
    q02Verification: value.q02Verification,
  });
}

/**
 * Standalone revalidation of a written Q-07 result. The caller must supply
 * independently derived final-manifest, authority, Q-02, B-02, history, and
 * physical-store pins; embedded values can never nominate those trust roots.
 */
export function revalidateV2Q07FinalPerformanceResult(
  value,
  expectedTrustRoots,
) {
  return resultCore(value, {
    b02Revalidator: revalidateV2B02FinalVmResult,
    expectedTrustRoots,
  });
}

/** Explicit test-only B-02 seam. Production qualification never accepts it. */
export function revalidateV2Q07FinalPerformanceResultForTestOnly(
  value,
  {
    b02Revalidator, expectedTrustRoots,
    historyActionCount = V2_Q07_HISTORY_ACTIONS,
  } = {},
) {
  if (typeof b02Revalidator !== 'function') fail('Q-07 test result revalidation requires an explicit B-02 revalidator');
  return resultCore(value, {
    b02Revalidator,
    expectedActionCount: historyActionCount,
    expectedTrustRoots,
  });
}

function safeRuntime() {
  if (
    process.execArgv.length !== 0
    || Object.keys(process.env).some((key) =>
      key === 'NODE_OPTIONS' || key === 'NODE_PATH'
      || key.startsWith('LD_') || key.startsWith('DYLD_'))
  ) fail('Q-07 refuses ambient loader, module-path, preload, or dynamic-linker controls');
  if (process.versions.node.split('.')[0] !== '22') fail('Q-07 final qualification requires Node 22');
}
function trustedGit() {
  for (const candidate of ['/usr/bin/git', '/bin/git']) {
    const entry = lstatSync(candidate, { bigint: true, throwIfNoEntry: false });
    if (
      entry?.isFile() && !entry.isSymbolicLink() && entry.uid === 0n
      && (entry.mode & 0o022n) === 0n && realpathSync(candidate) === candidate
    ) return candidate;
  }
  fail('Q-07 requires a root-owned non-writable absolute Git executable');
}
function gitState(git) {
  const run = (args) => {
    const result = spawnSync(git, [
      '--no-replace-objects', '--literal-pathspecs',
      '-c', 'core.hooksPath=/dev/null', '-c', 'include.path=/dev/null',
      '-c', 'core.fsmonitor=false', ...args,
    ], {
      cwd: workspace,
      encoding: 'utf8',
      env: {
        GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1',
        GIT_NO_REPLACE_OBJECTS: '1', GIT_TERMINAL_PROMPT: '0',
        HOME: '/nonexistent', LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    if (result.error || result.status !== 0 || result.signal !== null || result.stderr !== '') fail('Q-07 sanitized trusted Git query failed');
    return result.stdout;
  };
  const root = run(['rev-parse', '--show-toplevel']).trim();
  const commit = run(['rev-parse', 'HEAD^{commit}']).trim();
  const tree = run(['rev-parse', 'HEAD^{tree}']).trim();
  const status = run(['status', '--porcelain=v1', '--untracked-files=all']);
  if (root !== workspace || !SHA1.test(commit) || !SHA1.test(tree) || status !== '') fail('Q-07 requires the exact clean compiled source commit/tree');
  for (const row of run(['ls-files', '-v', '-z']).split('\0')) if (row !== '' && !row.startsWith('H ')) fail('Q-07 rejects non-normal Git index flags');
  return Object.freeze({ commit, tree });
}

export function parseV2Q07FinalPerformanceArguments(argv) {
  const names = new Set([
    '--profile-core', '--descriptor', '--final-manifest', '--release-root',
    '--q02-corpus', '--b02-result', '--evidence-dir', '--expected-commit',
    '--expected-tree', '--output-dir',
  ]);
  if (!Array.isArray(argv) || argv.length !== names.size * 2) {
    fail('usage: v2-q07-final-performance.mjs --profile-core <absolute> --descriptor <absolute> --final-manifest <absolute> --release-root <compiled-root-id> --q02-corpus <absolute> --b02-result <absolute> --evidence-dir <absolute> --expected-commit <sha1> --expected-tree <sha1> --output-dir <absolute-new-directory>');
  }
  const fields = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    if (
      !names.has(argv[index]) || fields.has(argv[index])
      || typeof argv[index + 1] !== 'string' || argv[index + 1] === ''
    ) fail('Q-07 arguments are malformed');
    fields.set(argv[index], argv[index + 1]);
  }
  if (
    [...names].some((name) => !fields.has(name))
    || !ROOT_ID.test(fields.get('--release-root'))
    || !SHA1.test(fields.get('--expected-commit'))
    || !SHA1.test(fields.get('--expected-tree'))
  ) fail('Q-07 arguments are incomplete or expected pins are malformed');
  return Object.freeze({
    b02ResultPath: absolute(fields.get('--b02-result'), 'Q-07 B-02 result'),
    descriptorPath: absolute(fields.get('--descriptor'), 'Q-07 descriptor'),
    evidenceDirectory: absolute(fields.get('--evidence-dir'), 'Q-07 evidence directory'),
    expectedCommit: fields.get('--expected-commit'),
    expectedTree: fields.get('--expected-tree'),
    finalManifestPath: absolute(fields.get('--final-manifest'), 'Q-07 final manifest'),
    outputDirectory: absolute(fields.get('--output-dir'), 'Q-07 output directory'),
    profileCorePath: absolute(fields.get('--profile-core'), 'Q-07 profile core'),
    q02CorpusPath: absolute(fields.get('--q02-corpus'), 'Q-07 Q-02 corpus'),
    releaseRootId: fields.get('--release-root'),
  });
}
function writeResult(directory, filename, value) {
  if (existsSync(directory)) fail('Q-07 output directory already exists');
  directDirectory(dirname(directory), 'Q-07 output parent');
  mkdirSync(directory, { mode: 0o700 }); chmodSync(directory, 0o700);
  const entry = lstatSync(directory, { bigint: true });
  if (
    !entry.isDirectory() || entry.isSymbolicLink()
    || entry.uid !== BigInt(process.getuid()) || (entry.mode & 0o777n) !== 0o700n
    || realpathSync(directory) !== directory
  ) fail('Q-07 output directory is unsafe');
  const temporary = join(directory, '.writing');
  const target = join(directory, filename);
  let fd;
  try {
    fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
    writeSync(fd, canonical(value)); fsyncSync(fd);
  } finally { if (fd !== undefined) closeSync(fd); }
  chmodSync(temporary, 0o600); renameSync(temporary, target);
  const final = lstatSync(target, { bigint: true });
  if (
    !final.isFile() || final.isSymbolicLink() || final.nlink !== 1n
    || final.uid !== BigInt(process.getuid()) || (final.mode & 0o777n) !== 0o600n
    || realpathSync(target) !== target
  ) fail('Q-07 output artifact is unsafe');
  const directoryFd = openSync(directory, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0));
  try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
}
function writeFailure(options, error) {
  if (
    options && typeof options.outputDirectory === 'string'
    && isAbsolute(options.outputDirectory)
    && resolve(options.outputDirectory) === options.outputDirectory
    && !existsSync(options.outputDirectory)
  ) {
    try {
      writeResult(options.outputDirectory, 'failure.json', {
        production: false, q07Qualified: false,
        reason: error instanceof Error ? error.message : String(error),
        releaseQualified: false, schema: V2_Q07_FAILURE_SCHEMA,
        status: 'q07-not-qualified',
      });
    } catch { /* preserve the original blocker */ }
  }
}

export async function verifyV2Q07FinalPerformance(options) {
  try {
    exact(options, [
      'b02ResultPath', 'descriptorPath', 'evidenceDirectory',
      'expectedCommit', 'expectedTree', 'finalManifestPath', 'outputDirectory',
      'profileCorePath', 'q02CorpusPath', 'releaseRootId',
    ], 'Q-07 verifier options');
    safeRuntime();
    // A caller-controlled descriptor/path can never nominate its own trust root.
    const releaseRoot = resolveV2FinalReleaseRoot(options.releaseRootId);
    const git = gitState(trustedGit());
    if (git.commit !== options.expectedCommit || git.tree !== options.expectedTree) fail('Q-07 expected source commit/tree differs from the clean checkout');
    const profile = jcsFile(options.profileCorePath, 'Q-07 profile core');
    const release = verifyV2FinalReleaseProfileCore(releaseRoot, profile.bytes, profile.value);
    const descriptor = await loadV2InstanceDescriptor({
      descriptorPath: options.descriptorPath,
      profileCore: profile.value,
      trustedSigners: release.descriptorSigners,
    });
    const finalManifest = jcsFile(options.finalManifestPath, 'Q-07 final manifest');
    if (
      descriptor.manifest.filename !== options.finalManifestPath
      || descriptor.manifest.sha256 !== finalManifest.sha256
      || descriptor.profileId !== releaseRoot.profileId
      || descriptor.finalLocks.topology.id !== releaseRoot.topology.id
      || descriptor.finalLocks.verifiers.length !== releaseRoot.topology.verifierRoles.length
      || descriptor.finalLocks.verifiers.some((entry, index) => entry.role !== releaseRoot.topology.verifierRoles[index])
    ) fail('Q-07 descriptor/final-manifest/release-root/topology binding drifts');
    const q07ManifestArtifacts = finalManifest.value.artifacts
      .map((entry) => entry.id)
      .filter((id) => id.startsWith('q07-'));
    if (
      q07ManifestArtifacts.length !== 1
      || q07ManifestArtifacts[0] !== V2_Q07_BENCHMARK_AUTHORITY_ARTIFACT_ID
    ) fail('Q-07 pre-final manifest may pin only the benchmark authority/policy, never post-final evidence or report hashes');
    const runtime = await deriveV2Pf10RuntimeFromValidatedDescriptor(descriptor);
    if (
      runtime.eligibility !== 'final-qualified'
      || runtime.claims.finalKey !== true || runtime.claims.developmentKey !== false
      || runtime.claims.ceremonyQualified !== true || runtime.claims.production !== false
      || runtime.claims.releaseQualified !== false
    ) fail('Q-07 requires the exact D-01 final-qualified non-production PF10 runtime');
    const finalLocksSha256 = deriveV2FinalLocksSha256FromValidatedDescriptor(descriptor);
    const settlementPins = deriveV2SettlementPinsFromValidatedDescriptor(descriptor);
    const authorityPin = deriveV2ManifestArtifactFromValidatedDescriptor(
      descriptor,
      V2_Q07_BENCHMARK_AUTHORITY_ARTIFACT_ID,
    );
    const authorityFile = jcsFile(authorityPin.path, 'Q-07 manifest-pinned benchmark authority policy');
    if (authorityFile.sha256 !== authorityPin.sha256) fail('Q-07 benchmark authority policy hash differs from the signed manifest pin');
    const authority = authorityPolicy(authorityFile.value);
    const b02AuthorityPin = deriveV2ManifestArtifactFromValidatedDescriptor(
      descriptor,
      V2_Q02_LANE_AUTHORITY_ARTIFACT_ID,
    );
    const b02AuthorityFile = jcsFile(
      b02AuthorityPin.path,
      'Q-07 manifest-pinned B-02 lane authority',
    );
    if (b02AuthorityFile.sha256 !== b02AuthorityPin.sha256) {
      fail('Q-07 B-02 lane authority differs from the signed manifest pin');
    }
    const b02TransactionsPin = deriveV2ManifestArtifactFromValidatedDescriptor(
      descriptor,
      V2_B02_TRANSACTIONS_ARTIFACT_ID,
    );
    const b02TransactionsFile = jcsFile(
      b02TransactionsPin.path,
      'Q-07 manifest-pinned B-02 transactions',
    );
    if (b02TransactionsFile.sha256 !== b02TransactionsPin.sha256) {
      fail('Q-07 B-02 transactions differ from the signed manifest pin');
    }
    const expectedIdentity = Object.freeze({
      descriptorSha256: descriptor.descriptor.sha256,
      finalLocksSha256,
      instanceId: descriptor.instanceId,
      manifestSha256: descriptor.manifest.sha256,
      profileId: descriptor.profileId,
      profileSha256: profile.sha256,
      releaseBootstrapSha256: release.releaseBootstrapSha256,
      releaseRootId: release.releaseRootId,
      runtimeMaterialSha256: runtime.runtimeMaterial.materialSha256,
      sourceCommit: git.commit,
      sourceTree: git.tree,
      topologyId: descriptor.finalLocks.topology.id,
    });
    directDirectory(options.evidenceDirectory, 'Q-07 evidence directory');
    const inventory = verifyInventory(
      options.evidenceDirectory,
      authority.value.artifactPaths.inventory,
      authority.value.artifactPaths.envelope,
    );
    const algorithms = sourceAlgorithms();
    const initialState = decodeStateNftCommitment(descriptor.initialState, {
      denominationSats: profile.value.denominationSats,
    });
    const historyPath = inside(options.evidenceDirectory, authority.value.artifactPaths.history, 'Q-07 history path');
    const history = verifyHistory(historyPath, {
      algorithmSources: algorithms,
      carrierCount: settlementPins.verifierCarriers.length,
      denominationSats: profile.value.denominationSats,
      identity: expectedIdentity,
      initialStateBytes: descriptor.initialState,
      maximumLiveNotes: initialState.maximumLiveNotes,
      networkId: profile.value.network.id,
      settlementPins,
      stateContext: Object.freeze({ denominationSats: profile.value.denominationSats }),
    }, V2_Q07_HISTORY_ACTIONS);
    const historyInventory = inventory.value.artifacts.find((entry) => entry.path === authority.value.artifactPaths.history);
    if (
      historyInventory?.classification !== 'history-corpus'
      || historyInventory.sha256 !== history.fileSha256
    ) fail('Q-07 history is not the exact inventory-pinned corpus');
    const manifestPath = inside(options.evidenceDirectory, authority.value.artifactPaths.samplesManifest, 'Q-07 sample manifest path');
    const samplesFile = jcsFile(manifestPath, 'Q-07 raw sample manifest');
    const sampleInventory = inventory.value.artifacts.find((entry) => entry.path === authority.value.artifactPaths.samplesManifest);
    if (sampleInventory?.classification !== 'sample-manifest' || sampleInventory.sha256 !== samplesFile.sha256) fail('Q-07 raw sample manifest is not inventory-pinned');
    const sampleVerification = validateSampleSet({
      authority,
      expectedIdentity,
      historyVerification: history,
      inventory,
      manifest: samplesFile.value,
      readJcsArtifact(ref, label) {
        return jcsFile(
          inside(options.evidenceDirectory, ref.path, `${label} path`),
          label,
        );
      },
      readBytesArtifact(ref, label) {
        return stableBytes(inside(options.evidenceDirectory, ref.path, `${label} path`), label, 1024 * 1024);
      },
      readOpaqueArtifact(ref, label) {
        return stableDigest(
          inside(options.evidenceDirectory, ref.path, `${label} path`),
          label,
        );
      },
    });
    if (
      samplesFile.value.terminalStateSha256
        !== history.terminalStateSha256
    ) fail('Q-07 raw samples do not bind the replayed history terminal state');
    const b02File = jcsFile(options.b02ResultPath, 'Q-07 complete B-02 result');
    const b02Revalidation = revalidateV2B02FinalVmResult(b02File.value);
    assertB02FinalPins({
      b02Result: b02File.value,
      denominationSats: profile.value.denominationSats,
      expectedAuthorityArtifactSha256: b02AuthorityPin.sha256,
      expectedIdentity,
      expectedTransactionsManifest: b02TransactionsFile.value,
      expectedTransactionsManifestSha256: b02TransactionsPin.sha256,
      settlementPins,
    });
    const q02Corpus = heldStableDigest(options.q02CorpusPath, 'Q-07 Q-02 corpus');
    let q02Verification;
    try {
      q02Verification = await verifyV2Q02FinalKeyCorpus({
        corpusPath: options.q02CorpusPath,
        descriptorPath: options.descriptorPath,
        profileCorePath: options.profileCorePath,
        releaseRootId: options.releaseRootId,
      });
      q02Corpus.release();
    } catch (error) {
      q02Corpus.abandon();
      throw error;
    }
    q02Result(q02Verification);
    if (
      q02Verification.descriptorSha256 !== expectedIdentity.descriptorSha256
      || q02Verification.manifestSha256 !== expectedIdentity.manifestSha256
      || q02Verification.releaseBootstrapSha256 !== expectedIdentity.releaseBootstrapSha256
      || q02Verification.releaseRootId !== expectedIdentity.releaseRootId
    ) fail('Q-07 Q-02 corpus verification identity drifts');
    const sampleSet = sampleVerification.rawSamples.map((entry) => ({
      path: entry.path, sha256: entry.sha256,
      inputArtifactSha256: entry.inputArtifact.sha256,
      outputArtifactSha256: entry.outputArtifact.sha256,
      stderrSha256: entry.value.execution.stderr.sha256,
      stdoutSha256: entry.value.execution.stdout.sha256,
    }));
    const sampleSummary = {
      performance: sampleVerification.performance,
      rawSampleSetSha256: sha256(canonical(sampleSet)),
    };
    const expectedArtifacts = Object.freeze({
      b02ResultSha256: b02File.sha256,
      b02RevalidationSha256: sha256(canonical(b02Revalidation)),
      historySha256: history.fileSha256,
      historyVerificationSha256: sha256(canonical(history)),
      inventorySha256: inventory.sha256,
      q02CorpusSha256: q02Corpus.sha256,
      q02VerificationSha256: sha256(canonical(q02Verification)),
      samplesManifestSha256: samplesFile.sha256,
      samplesVerificationSha256: sha256(canonical(sampleSummary)),
    });
    const envelopeFile = jcsFile(
      inside(options.evidenceDirectory, authority.value.artifactPaths.envelope, 'Q-07 machine envelope path'),
      'Q-07 signed published-machine envelope',
    );
    verifyEnvelope({
      authorityArtifactSha256: authorityFile.sha256,
      envelope: envelopeFile.value,
      expectedArtifacts,
      expectedBootId: sampleVerification.bootId,
      expectedCgroupPaths: sampleVerification.cgroupPaths,
      expectedEvidenceWindow: sampleVerification.evidenceWindow,
      expectedIdentity,
      expectedMachineRunId: samplesFile.value.machineRunId,
      policy: authority,
    });
    const result = Object.freeze({
      authorityArtifact: authorityFile.value,
      authorityArtifactSha256: authorityFile.sha256,
      b02Result: b02File.value,
      b02Revalidation,
      evidenceEnvelope: envelopeFile.value,
      evidenceEnvelopeSha256: envelopeFile.sha256,
      evidenceInventory: inventory.value,
      evidenceInventorySha256: inventory.sha256,
      hardPolicyCeilings: Object.freeze({
        everyInputUnlockingBytecodeBytes: 10_000,
        everyReportedVmResourcePercent: 100,
        narrowerMargins: '90000/9500-non-blocking-risk-telemetry-only',
        serializedTransactionBytes: 100_000,
      }),
      historyVerification: history,
      identity: expectedIdentity,
      performance: sampleVerification.performance,
      production: false,
      q02Verification,
      q07Qualified: true,
      rawSamples: sampleVerification.rawSamples,
      releaseQualified: false,
      samplesManifest: samplesFile.value,
      schema: V2_Q07_FINAL_PERFORMANCE_SCHEMA,
      status: 'q07-qualified-final-performance-not-production-or-release',
    });
    revalidateV2Q07FinalPerformanceResult(result, {
      authorityArtifactSha256: authorityFile.sha256,
      authorityPublicKeyPem: authorityFile.value.authority.publicKeyPem,
      b02Identity: expectedIdentity,
      b02ResultSha256: b02File.sha256,
      historySha256: history.fileSha256,
      historyVerificationSha256: sha256(canonical(history)),
      identity: expectedIdentity,
      q02CorpusSha256: q02Corpus.sha256,
      q02Verification,
      storeArtifact: sampleVerification.storeArtifact,
    });
    writeResult(options.outputDirectory, 'q07-final-performance.json', result);
    return result;
  } catch (error) {
    writeFailure(options, error);
    throw error;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    process.stdout.write(`${JSON.stringify(
      await verifyV2Q07FinalPerformance(
        parseV2Q07FinalPerformanceArguments(process.argv.slice(2)),
      ),
    )}\n`);
  } catch (error) {
    process.stderr.write(`Q-07 final performance failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
