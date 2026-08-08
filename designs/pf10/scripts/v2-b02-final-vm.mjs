#!/usr/bin/env node
/*
 * B-02-final offline VM evidence verifier.
 *
 * This program never constructs or broadcasts a transaction and never selects
 * an authority. The only production trust root is the release root compiled
 * into this ShieldKit build. The standalone result replay derives evidence
 * from a self-contained success artifact; the separate TEST-ONLY structural
 * seam always returns b02Qualified:false.
 */
import { spawnSync } from 'node:child_process';
import {
  createHash,
  createPublicKey,
} from 'node:crypto';
import { createRequire } from 'node:module';
import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  writeSync,
} from 'node:fs';
import {
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  V2_MAX_TRANSACTION_BYTES,
  V2_MAX_UNLOCKING_BYTECODE_BYTES,
  assertV2StandardTransactionEnvelope,
  createV2InputRoleLayout,
  parseSerializedSourceOutput,
  parseV2RawTransaction,
} from '../packages/kit/v2/transaction-policy.mjs';
import {
  assertV2VmResourceMetrics,
  inspectV2LocalVmEvidence,
  V2_VM_PROFILE,
} from '../packages/kit/v2/vm-evidence.mjs';
import {
  canonicalizeJcs,
} from '../packages/profile/v2/profile-core.mjs';
import {
  resolveV2FinalReleaseRoot,
  verifyV2FinalReleaseProfileCore,
} from '../packages/profile/v2/release-bootstrap.mjs';
import {
  deriveV2FinalLocksSha256FromValidatedDescriptor,
  deriveV2ManifestArtifactFromValidatedDescriptor,
  deriveV2Pf10RuntimeFromValidatedDescriptor,
  deriveV2SettlementPinsFromValidatedDescriptor,
  loadV2InstanceDescriptor,
} from '../packages/profile/v2/instance-descriptor.mjs';
import {
  V2_Q02_LANE_AUTHORITY_ARTIFACT_ID,
  V2_Q02_LANE_AUTHORITIES_SCHEMA,
  deriveV2Q02LaneAuthorityContextFromValidatedDescriptor,
  verifyV2Q02AuthorityLaneEvidence,
} from './v2-q02-lane-evidence.mjs';
import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  directV2VerifierTopologyById,
} from '../packages/action/v2/topology.mjs';
import {
  verifyBchTransactionMerkleProof,
  verifyRawHeaderSegment,
} from '../packages/recover/raw-chain-recovery.mjs';
import {
  createV2LaneEvidencePrimitives,
} from './v2-lane-evidence-primitives.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const workspaceRoot = resolve(here, '../../..');
const HASH = /^[0-9a-f]{64}$/u;
const SHA1 = /^[0-9a-f]{40}$/u;
const ROOT_ID = /^[a-z][a-z0-9-]*$/u;
const SAFE_RELATIVE = /^(?!.*(?:^|[\\/])\.\.(?:[\\/]|$))(?![\\/]).+/u;
const ACTIONS = Object.freeze(['deposit', 'transfer', 'withdrawal']);
const LANE_ROLES = Object.freeze([
  'maintainer',
  'bchn-mempool',
  'bchn-mined',
  'leanbch',
]);
const MAINTAINER_REPOSITORY =
  'https://github.com/mr-zwets/zk-verifier-bench';
const LIBAUTH_VERSION = createRequire(import.meta.url)(
  '@bitauth/libauth/package.json',
).version;

export const V2_B02_RESULT_SCHEMA =
  'shieldkit-v2-direct-b02-final-vm-v1';
export const V2_B02_TRANSACTIONS_SCHEMA =
  'shieldkit-v2-direct-b02-final-transactions-v1';
export const V2_B02_TRANSACTIONS_ARTIFACT_ID =
  'b02-final-vm-transactions';
export const V2_B02_LANE_SUBJECT_SCHEMA =
  'shieldkit-v2-direct-b02-final-vm-subject-v1';
export const V2_B02_LANE_ENVELOPE_SCHEMA =
  'shieldkit-v2-direct-b02-final-vm-lane-envelope-v1';
export const V2_B02_LANE_ATTESTATION_DOMAIN =
  'shieldkit-v2-direct-b02-final-vm-lane-attestation';
export const V2_B02_LANE_ATTESTATION_VERSION = 1;
export const V2_B02_MACHINE_MANIFEST_SCHEMA =
  'shieldkit-v2-direct-b02-final-vm-machine-manifest-v1';
export const V2_B02_VM_INPUT_SCHEMA =
  'shieldkit-v2-direct-b02-final-vm-run-input-v1';
export const V2_B02_VM_OUTPUT_SCHEMA =
  'shieldkit-v2-direct-b02-final-vm-per-input-run-v1';
export const V2_B02_BCHN_MINED_INPUT_SCHEMA =
  'shieldkit-v2-direct-b02-final-vm-bchn-mined-input-v1';
export const V2_B02_BCHN_MINED_OUTPUT_SCHEMA =
  'shieldkit-v2-direct-b02-final-vm-bchn-mined-result-v1';
export const V2_B02_TEST_ONLY_STRUCTURAL_SCHEMA =
  'shieldkit-v2-direct-b02-test-only-structural-cycle-v1';
export const V2_B02_RESULT_REVALIDATION_SCHEMA =
  'shieldkit-v2-direct-b02-final-vm-result-revalidation-v1';

export class V2B02FinalVmError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2B02FinalVmError';
  }
}

const fail = (message) => {
  throw new V2B02FinalVmError(message);
};
const sha256 = (value) =>
  createHash('sha256').update(value).digest('hex');
const canonicalBytes = (value) =>
  Buffer.from(canonicalizeJcs(value), 'utf8');
const standaloneLanePrimitives = createV2LaneEvidencePrimitives({
  canonicalizeJcs,
  fail,
  parseRawTransaction: parseV2RawTransaction,
  parseSerializedSourceOutput,
  verifyBchTransactionMerkleProof,
  verifyRawHeaderSegment,
});

function plain(value, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail(`${label} must be a plain object`);
  }
  return value;
}

function exact(value, keys, label) {
  plain(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((entry, index) => entry !== expected[index])
  ) {
    fail(`${label} has missing or unknown properties`);
  }
  return value;
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail(`${label} must be 32 lowercase hexadecimal bytes`);
  }
  return value;
}

function integer(value, low, high, label) {
  if (!Number.isSafeInteger(value) || value < low || value > high) {
    fail(`${label} is outside its integer range`);
  }
  return value;
}

function absolute(value, label) {
  if (
    typeof value !== 'string'
    || !isAbsolute(value)
    || resolve(value) !== value
  ) {
    fail(`${label} must be an absolute normalized path`);
  }
  return value;
}

function relativeName(value, label) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > 4096
    || isAbsolute(value)
    || !SAFE_RELATIVE.test(value)
    || value.split(/[\\/]/u).some((part) => part === '' || part === '.')
  ) {
    fail(`${label} must be a safe normalized relative path`);
  }
  return value;
}

function directFile(pathname, label) {
  absolute(pathname, label);
  const entry = lstatSync(pathname, { throwIfNoEntry: false });
  if (
    entry === undefined
    || !entry.isFile()
    || entry.isSymbolicLink()
    || entry.nlink !== 1
    || realpathSync(pathname) !== pathname
  ) {
    fail(`${label} must be a direct single-link regular file without symlink ancestors`);
  }
  return entry;
}

function directDirectory(pathname, label) {
  absolute(pathname, label);
  const entry = lstatSync(pathname, { throwIfNoEntry: false });
  if (
    entry === undefined
    || !entry.isDirectory()
    || entry.isSymbolicLink()
    || realpathSync(pathname) !== pathname
  ) {
    fail(`${label} must be a direct canonical directory without symlink ancestors`);
  }
  return entry;
}

function sameFile(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.nlink === right.nlink
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function stableFile(
  pathname,
  label,
  {
    allowEmpty = false,
    maximumBytes = 256 * 1024 * 1024,
  } = {},
) {
  const named = directFile(pathname, label);
  let descriptor;
  try {
    descriptor = openSync(
      pathname,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0),
    );
    const before = fstatSync(descriptor, { bigint: true });
    if (
      !before.isFile()
      || before.nlink !== 1n
      || (!allowEmpty && before.size === 0n)
      || before.size > BigInt(maximumBytes)
      || before.dev !== BigInt(named.dev)
      || before.ino !== BigInt(named.ino)
    ) {
      fail(`${label} changed type, link count, or identity before opening`);
    }
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    const finalNamed = lstatSync(pathname, {
      bigint: true,
      throwIfNoEntry: false,
    });
    if (
      !sameFile(before, after)
      || finalNamed === undefined
      || !finalNamed.isFile()
      || finalNamed.isSymbolicLink()
      || finalNamed.dev !== after.dev
      || finalNamed.ino !== after.ino
      || realpathSync(pathname) !== pathname
    ) {
      fail(`${label} changed while being read`);
    }
    return Buffer.from(bytes);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function jcsFile(pathname, label) {
  const bytes = stableFile(pathname, label);
  let value;
  try {
    value = JSON.parse(bytes);
  } catch {
    fail(`${label} is not JSON`);
  }
  if (!bytes.equals(canonicalBytes(value))) {
    fail(`${label} must use exact RFC8785/JCS bytes`);
  }
  return Object.freeze({
    bytes,
    path: pathname,
    sha256: sha256(bytes),
    value,
  });
}

function evidenceReference(value, label) {
  exact(value, ['path', 'sha256'], label);
  return Object.freeze({
    path: relativeName(value.path, `${label}.path`),
    sha256: hash(value.sha256, `${label}.sha256`),
  });
}

function resolveEvidenceReference(
  value,
  root,
  label,
  { allowEmpty = false, jcs = false } = {},
) {
  const reference = evidenceReference(value, label);
  const pathname = resolve(root, reference.path);
  if (
    pathname === root
    || (!pathname.startsWith(`${root}${sep}`))
  ) {
    fail(`${label} escapes the lane evidence directory`);
  }
  const bytes = stableFile(pathname, label, { allowEmpty });
  if (sha256(bytes) !== reference.sha256) {
    fail(`${label} SHA-256 differs from its exact reference`);
  }
  if (!jcs) {
    return Object.freeze({ ...reference, bytes, pathname });
  }
  let parsed;
  try {
    parsed = JSON.parse(bytes);
  } catch {
    fail(`${label} is not JSON`);
  }
  if (!bytes.equals(canonicalBytes(parsed))) {
    fail(`${label} must use exact RFC8785/JCS bytes`);
  }
  return Object.freeze({
    ...reference,
    bytes,
    pathname,
    value: parsed,
  });
}

function allFiles(root) {
  const files = [];
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const pathname = join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        fail('B-02 lane evidence directory contains a symlink');
      }
      if (entry.isDirectory()) {
        visit(pathname);
      } else if (entry.isFile()) {
        directFile(pathname, 'B-02 lane evidence file');
        files.push(relative(root, pathname).split(sep).join('/'));
      } else {
        fail('B-02 lane evidence directory contains a non-regular entry');
      }
    }
  };
  visit(root);
  return Object.freeze(files.sort());
}

function normalizeReferencedFiles(value, label) {
  if (
    !Array.isArray(value)
    || value.some((entry) => typeof entry !== 'string')
  ) {
    fail(`${label} must be an array of paths`);
  }
  const sorted = [...value].sort();
  if (
    new Set(sorted).size !== sorted.length
    || sorted.some((entry) => relativeName(entry, label) !== entry)
  ) {
    fail(`${label} must be sorted-unique safe relative paths`);
  }
  return Object.freeze(sorted);
}

function assertExactEvidenceClosure(referenced, actual) {
  const expected = normalizeReferencedFiles(
    referenced,
    'B-02 referenced evidence files',
  );
  const observed = normalizeReferencedFiles(
    actual,
    'B-02 actual evidence files',
  );
  if (canonicalizeJcs(expected) !== canonicalizeJcs(observed)) {
    fail('B-02 lane evidence directory has a missing or unreferenced file');
  }
  return true;
}

function bindReferencedArtifact(referenced, root, artifact, label) {
  const path = relative(root, artifact.pathname).split(sep).join('/');
  if (
    path === '..'
    || path.startsWith('../')
    || isAbsolute(path)
  ) {
    fail(`${label} escapes the lane evidence directory`);
  }
  const previous = referenced.get(path);
  if (previous !== undefined && previous !== artifact.sha256) {
    fail(`${label} conflicts with an earlier reference to the same path`);
  }
  referenced.set(path, artifact.sha256);
  return path;
}

function revalidateEvidenceClosure(root, referenced) {
  const actual = allFiles(root);
  assertExactEvidenceClosure([...referenced.keys()].sort(), actual);
  for (const [path, expectedSha256] of referenced) {
    const bytes = stableFile(resolve(root, path), `B-02 final evidence recheck ${path}`, {
      allowEmpty: true,
    });
    if (sha256(bytes) !== expectedSha256) {
      fail(`B-02 evidence file changed after verification: ${path}`);
    }
  }
  return actual;
}

function parseArguments(argv) {
  const names = new Set([
    '--profile-core',
    '--descriptor',
    '--final-manifest',
    '--release-root',
    '--transactions',
    '--lane-evidence-dir',
    '--expected-commit',
    '--expected-tree',
    '--output-dir',
  ]);
  if (!Array.isArray(argv) || argv.length !== names.size * 2) {
    fail('usage: v2-b02-final-vm.mjs --profile-core <absolute-file> --descriptor <absolute-file> --final-manifest <absolute-file> --release-root <compiled-root-id> --transactions <absolute-file> --lane-evidence-dir <absolute-directory> --expected-commit <sha1> --expected-tree <sha1> --output-dir <absolute-new-directory>');
  }
  const fields = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (
      !names.has(name)
      || fields.has(name)
      || typeof value !== 'string'
      || value.length === 0
    ) {
      fail('B-02 arguments are malformed, duplicated, or unknown');
    }
    fields.set(name, value);
  }
  for (const name of names) {
    if (!fields.has(name)) fail(`B-02 requires ${name}`);
  }
  if (
    !ROOT_ID.test(fields.get('--release-root'))
    || !SHA1.test(fields.get('--expected-commit'))
    || !SHA1.test(fields.get('--expected-tree'))
  ) {
    fail('B-02 release root or expected Git pins are malformed');
  }
  return Object.freeze({
    profileCorePath: absolute(
      fields.get('--profile-core'),
      'B-02 profile core',
    ),
    descriptorPath: absolute(
      fields.get('--descriptor'),
      'B-02 descriptor',
    ),
    finalManifestPath: absolute(
      fields.get('--final-manifest'),
      'B-02 final manifest',
    ),
    releaseRootId: fields.get('--release-root'),
    transactionsPath: absolute(
      fields.get('--transactions'),
      'B-02 transactions manifest',
    ),
    laneEvidenceDirectory: absolute(
      fields.get('--lane-evidence-dir'),
      'B-02 lane evidence directory',
    ),
    expectedCommit: fields.get('--expected-commit'),
    expectedTree: fields.get('--expected-tree'),
    outputDirectory: absolute(
      fields.get('--output-dir'),
      'B-02 output directory',
    ),
  });
}

export const parseV2B02Arguments = parseArguments;

function assertSafeRuntime(
  environment = process.env,
  execArgv = process.execArgv,
) {
  if (!Array.isArray(execArgv) || execArgv.length !== 0) {
    fail('B-02 refuses process.execArgv loader or preload controls');
  }
  const contaminated = Object.keys(environment).filter((key) =>
    key === 'NODE_OPTIONS'
      || key === 'NODE_PATH'
      || key === 'NODE_V8_COVERAGE'
      || key.startsWith('LD_')
      || key.startsWith('DYLD_'));
  if (contaminated.length !== 0) {
    fail(`B-02 refuses ambient loader, preload, or dynamic-linker controls: ${contaminated.sort().join(',')}`);
  }
  return true;
}

/** TEST-ONLY: pure ambient-control validator; it grants no authority. */
export function assertV2B02SafeRuntimeForTestOnly(
  environment,
  execArgv,
) {
  return assertSafeRuntime(environment, execArgv);
}

function trustedGit() {
  for (const candidate of ['/usr/bin/git', '/bin/git']) {
    const entry = lstatSync(candidate, { throwIfNoEntry: false });
    if (
      entry?.isFile()
      && !entry.isSymbolicLink()
      && entry.uid === 0
      && (entry.mode & 0o022) === 0
      && realpathSync(candidate) === candidate
    ) {
      return candidate;
    }
  }
  fail('B-02 requires a root-owned non-writable absolute Git executable');
}

const gitEnvironment = Object.freeze({
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_TERMINAL_PROMPT: '0',
  HOME: '/nonexistent',
  LANG: 'C',
  LC_ALL: 'C',
  PATH: '/usr/bin:/bin',
});

function gitQuery(git, args, { encoding = 'utf8' } = {}) {
  const result = spawnSync(
    git,
    [
      '--no-replace-objects',
      '--literal-pathspecs',
      '-c',
      'core.hooksPath=/dev/null',
      '-c',
      'include.path=/dev/null',
      '-c',
      'core.fsmonitor=false',
      ...args,
    ],
    {
      cwd: workspaceRoot,
      encoding,
      env: gitEnvironment,
      maxBuffer: 32 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  if (
    result.error !== undefined
    || result.status !== 0
    || result.signal !== null
    || (encoding === 'utf8' && result.stderr !== '')
    || (encoding === null && result.stderr.length !== 0)
  ) {
    fail('B-02 sanitized trusted Git query failed');
  }
  return result.stdout;
}

function gitState(git) {
  const version = gitQuery(git, ['--version']).trim();
  const root = gitQuery(git, ['rev-parse', '--show-toplevel']).trim();
  const commit = gitQuery(git, ['rev-parse', 'HEAD^{commit}']).trim();
  const tree = gitQuery(git, ['rev-parse', 'HEAD^{tree}']).trim();
  const status = gitQuery(
    git,
    ['status', '--porcelain=v1', '--untracked-files=all'],
  );
  if (
    root !== workspaceRoot
    || !/^git version \d+\.\d+(?:\.\d+)?(?:[.A-Za-z0-9+-]*)$/u.test(version)
    || !SHA1.test(commit)
    || !SHA1.test(tree)
    || status !== ''
  ) {
    fail('B-02 requires the exact clean compiled source checkout');
  }
  const flags = gitQuery(git, ['ls-files', '-v', '-z'], {
    encoding: null,
  }).toString('utf8');
  for (const row of flags.split('\0')) {
    if (row !== '' && !row.startsWith('H ')) {
      fail('B-02 rejects non-normal Git index flags');
    }
  }
  return Object.freeze({
    commit,
    tree,
    gitExecutable: git,
    gitVersion: version,
    environment: gitEnvironment,
    replaceObjectsDisabled: true,
  });
}

function expectedInputRoles(carrierCount) {
  return createV2InputRoleLayout(carrierCount);
}

function expectedOutputRoles(kind, carrierCount) {
  const roles = [
    Object.freeze({ index: 0, kind: 'state', ordinal: null }),
    ...Array.from({ length: carrierCount }, (_, ordinal) =>
      Object.freeze({
        index: ordinal + 1,
        kind: 'verifier',
        ordinal,
      })),
    Object.freeze({
      index: carrierCount + 1,
      kind: 'binding',
      ordinal: null,
    }),
  ];
  if (kind === 'withdrawal') {
    roles.push(Object.freeze({
      index: carrierCount + 2,
      kind: 'withdrawal',
      ordinal: null,
    }));
  }
  roles.push(Object.freeze({
    index: roles.length,
    kind: 'change',
    ordinal: null,
  }));
  return Object.freeze(roles);
}

function roleLayout(value, expected, label) {
  if (!Array.isArray(value) || value.length !== expected.length) {
    fail(`${label} length differs from the exact topology`);
  }
  for (const [index, role] of value.entries()) {
    exact(role, ['index', 'kind', 'ordinal'], `${label}[${index}]`);
    if (
      role.index !== expected[index].index
      || role.kind !== expected[index].kind
      || role.ordinal !== expected[index].ordinal
    ) {
      fail(`${label}[${index}] differs from the exact topology`);
    }
  }
  return expected;
}

function measureRawTransaction(rawTransactionHex, carrierCount) {
  let transaction;
  try {
    transaction = parseV2RawTransaction(rawTransactionHex);
    transaction = assertV2StandardTransactionEnvelope(
      transaction,
      carrierCount === undefined ? {} : { carrierCount },
    );
  } catch (error) {
    fail(`B-02 raw transaction violates a hard serialization policy: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
  const maximumUnlockingBytecodeBytes = Math.max(
    ...transaction.inputs.map((entry) => entry.unlockingBytecodeBytes),
  );
  return Object.freeze({
    transaction,
    rawTransactionSha256: sha256(transaction.bytes),
    maximumUnlockingBytecodeBytes,
    hardPolicy: Object.freeze({
      serializedTransactionBytes: Object.freeze({
        actual: transaction.sizeBytes,
        maximum: V2_MAX_TRANSACTION_BYTES,
      }),
      everyInputUnlockingBytecodeBytes: Object.freeze({
        actualMaximum: maximumUnlockingBytecodeBytes,
        maximum: V2_MAX_UNLOCKING_BYTECODE_BYTES,
      }),
    }),
    narrowerTelemetry: Object.freeze({
      serializedTransactionAtOrBelow90000:
        transaction.sizeBytes <= 90_000,
      everyInputUnlockingBytecodeAtOrBelow9500:
        maximumUnlockingBytecodeBytes <= 9_500,
      policy: 'non-blocking-risk-telemetry-only',
    }),
  });
}

export function measureV2B02RawTransactionForTestOnly(
  rawTransactionHex,
) {
  return measureRawTransaction(rawTransactionHex, undefined);
}

function normalizedSourceOutput(value, expectedInput, label) {
  exact(
    value,
    ['index', 'outpoint', 'serializedHex', 'sha256'],
    label,
  );
  integer(value.index, 0, Number.MAX_SAFE_INTEGER, `${label}.index`);
  exact(value.outpoint, ['txid', 'vout'], `${label}.outpoint`);
  hash(value.outpoint.txid, `${label}.outpoint.txid`);
  integer(
    value.outpoint.vout,
    0,
    0xffff_ffff,
    `${label}.outpoint.vout`,
  );
  let parsed;
  try {
    parsed = parseSerializedSourceOutput(value.serializedHex);
  } catch (error) {
    fail(`${label} is not an exact serialized source output: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
  if (
    value.index !== expectedInput.index
    || value.outpoint.txid !== expectedInput.outpoint.txid
    || value.outpoint.vout !== expectedInput.outpoint.vout
    || value.sha256 !== parsed.sha256
  ) {
    fail(`${label} bytes, hash, index, or outpoint differ from the transaction`);
  }
  return Object.freeze({
    index: value.index,
    outpoint: Object.freeze({ ...value.outpoint }),
    serializedHex: parsed.serializedHex,
    sha256: parsed.sha256,
    parsed,
  });
}

function identityRecord(value, label) {
  exact(value, [
    'descriptorSha256',
    'finalLocksSha256',
    'instanceId',
    'manifestSha256',
    'profileId',
    'profileSha256',
    'releaseBootstrapSha256',
    'releaseRootId',
    'runtimeMaterialSha256',
    'sourceCommit',
    'sourceTree',
    'topologyId',
  ], label);
  for (const key of [
    'descriptorSha256',
    'finalLocksSha256',
    'instanceId',
    'manifestSha256',
    'profileId',
    'profileSha256',
    'releaseBootstrapSha256',
    'runtimeMaterialSha256',
  ]) hash(value[key], `${label}.${key}`);
  if (
    !ROOT_ID.test(value.releaseRootId)
    || !SHA1.test(value.sourceCommit)
    || !SHA1.test(value.sourceTree)
    || typeof value.topologyId !== 'string'
    || value.topologyId.length === 0
    || value.topologyId.length > 128
  ) {
    fail(`${label} root, source, or topology identity is malformed`);
  }
  return Object.freeze({ ...value });
}

function maintainerTool(value, label) {
  exact(value, [
    'commit',
    'executableSha256',
    'lockfileSha256',
    'repositoryUrl',
    'runnerSha256',
    'sourceSha256',
    'tree',
    'version',
  ], label);
  if (
    value.repositoryUrl !== MAINTAINER_REPOSITORY
    || !SHA1.test(value.commit)
    || !SHA1.test(value.tree)
    || typeof value.version !== 'string'
    || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u.test(value.version)
  ) {
    fail(`${label} does not identify the approved upstream maintainer benchmark revision`);
  }
  for (const key of [
    'executableSha256',
    'lockfileSha256',
    'runnerSha256',
    'sourceSha256',
  ]) hash(value[key], `${label}.${key}`);
  return Object.freeze({ ...value });
}

function assertFinalRuntime(runtime) {
  if (
    runtime.eligibility !== 'final-qualified'
    || runtime.claims?.finalKey !== true
    || runtime.claims.developmentKey !== false
    || runtime.claims.ceremonyQualified !== true
    || runtime.claims.production !== false
    || runtime.claims.releaseQualified !== false
  ) {
    fail('B-02 requires final-qualified PF10 runtime material with finalKey true, developmentKey false, ceremonyQualified true, and production/release false');
  }
  return runtime;
}

function assertDescriptorTopology(descriptor, releaseRoot) {
  if (
    descriptor.profileId !== releaseRoot.profileId
    || descriptor.finalLocks.topology.id !== releaseRoot.topology.id
    || descriptor.finalLocks.verifiers.length
      !== releaseRoot.topology.verifierRoles.length
    || descriptor.finalLocks.verifiers.some(
      (entry, index) =>
        entry.role !== releaseRoot.topology.verifierRoles[index],
    )
  ) {
    fail('B-02 descriptor identity or exact final PF10 topology differs from the compiled release root');
  }
}

function localInputBindings(local, transaction, sourceOutputs) {
  return Object.freeze(local.inputs.map((input, index) => {
    const transactionInput = transaction.inputs[index];
    if (
      input.index !== index
      || input.accepted !== true
      || input.sourceOutput.serializedHex
        !== sourceOutputs[index].serializedHex
      || input.sourceOutput.sha256 !== sourceOutputs[index].sha256
      || input.outpoint.txid !== transactionInput.outpoint.txid
      || input.outpoint.vout !== transactionInput.outpoint.vout
      || input.unlockingBytecodeBytes
        !== transactionInput.unlockingBytecodeBytes
    ) {
      fail(`B-02 local Libauth input ${index} does not bind its exact transaction and source output`);
    }
    return Object.freeze({
      accepted: true,
      index,
      metrics: input.metrics,
      outpoint: Object.freeze({ ...input.outpoint }),
      role: input.role,
      sourceOutputSha256: input.sourceOutput.sha256,
      unlockingBytecodeSha256: sha256(
        transactionInput.unlockingBytecode,
      ),
    });
  }));
}

function percentageRecord(used, maximum, label) {
  const numerator = BigInt(used);
  const denominator = BigInt(maximum);
  if (numerator > denominator) {
    fail(`${label} exceeds 100 percent`);
  }
  return Object.freeze({
    used,
    maximum,
    percentBasisPoints:
      denominator === 0n
        ? 0
        : Number((numerator * 10_000n) / denominator),
  });
}

function localResourceMeasurements(bindings) {
  return Object.freeze(bindings.map((input) => Object.freeze({
    inputIndex: input.index,
    operationCost: percentageRecord(
      input.metrics.operationCost,
      input.metrics.maximumOperationCost,
      `B-02 input ${input.index} operation cost`,
    ),
    hashDigestIterations: percentageRecord(
      input.metrics.hashDigestIterations,
      input.metrics.maximumHashDigestIterations,
      `B-02 input ${input.index} hash digest iterations`,
    ),
    signatureChecks: percentageRecord(
      input.metrics.signatureCheckCount,
      input.metrics.maximumSignatureCheckCount,
      `B-02 input ${input.index} signature checks`,
    ),
  })));
}

function assertDescriptorLocks(
  kind,
  transaction,
  sourceOutputs,
  settlementPins,
  instanceId,
) {
  const carrierCount = settlementPins.verifierCarriers.length;
  for (const [index, source] of sourceOutputs.entries()) {
    const expectedLock =
      index < carrierCount
        ? settlementPins.verifierCarriers[index].lockingBytecode
        : index === carrierCount
          ? settlementPins.bindingLockingBytecode
          : index === carrierCount + 1
            ? settlementPins.stateLockingBytecode
            : null;
    if (
      expectedLock !== null
      && source.parsed.lockingBytecodeHex
        !== Buffer.from(expectedLock).toString('hex')
    ) {
      fail(`B-02 source output ${index} locking bytecode differs from the final descriptor`);
    }
  }
  const outputRoles = expectedOutputRoles(kind, carrierCount);
  for (const role of outputRoles) {
    const output = parseSerializedSourceOutput(
      transaction.outputs[role.index].serializedHex,
    );
    const expectedLock =
      role.kind === 'state'
        ? settlementPins.stateLockingBytecode
        : role.kind === 'verifier'
          ? settlementPins.verifierCarriers[role.ordinal].lockingBytecode
          : role.kind === 'binding'
            ? settlementPins.bindingLockingBytecode
            : null;
    if (
      expectedLock !== null
      && output.lockingBytecodeHex
        !== Buffer.from(expectedLock).toString('hex')
    ) {
      fail(`B-02 ${kind} output ${role.index} does not carry its final descriptor lock`);
    }
    if (
      role.kind === 'state'
      && (
        output.token?.categoryWire !== instanceId
        || output.token.amount !== '0'
        || output.token.nft?.capability !== 'mutable'
        || output.token.nft.commitmentHex.length !== 256
      )
    ) {
      fail(`B-02 ${kind} state output does not carry the exact instance mutable NFT shape`);
    }
    if (
      ['verifier', 'binding', 'withdrawal', 'change'].includes(role.kind)
      && output.token !== null
    ) {
      fail(`B-02 ${kind} ${role.kind} output must be tokenless`);
    }
    if (
      ['withdrawal', 'change'].includes(role.kind)
      && !/^76a914[0-9a-f]{40}88ac$/u.test(output.lockingBytecodeHex)
    ) {
      fail(`B-02 ${kind} ${role.kind} output must be canonical P2PKH`);
    }
  }
}

function laneSubject({
  identity,
  inputBindings,
  kind,
  rawTransactionHex,
  rawTransactionSha256,
  sourceOutputs,
  transactionId,
}) {
  return Object.freeze({
    schema: V2_B02_LANE_SUBJECT_SCHEMA,
    identity,
    inputBindings,
    kind,
    rawTransactionHex,
    rawTransactionSha256,
    sourceOutputs: Object.freeze(sourceOutputs.map((entry) =>
      Object.freeze({
        index: entry.index,
        outpoint: entry.outpoint,
        serializedHex: entry.serializedHex,
        sha256: entry.sha256,
      }))),
    transactionId,
  });
}

function collectEnvelopeArtifacts(
  envelopeArtifact,
  laneRoot,
  role,
  referenced,
) {
  bindReferencedArtifact(
    referenced,
    laneRoot,
    envelopeArtifact,
    `B-02 ${role} lane envelope`,
  );
  const envelope = envelopeArtifact.value;
  plain(envelope.execution, `B-02 ${role} lane execution`);
  const artifacts = {};
  for (const [name, options] of Object.entries({
    stdin: { jcs: true },
    stdout: { jcs: true },
    stderr: { allowEmpty: true },
    machineManifest: { jcs: true },
  })) {
    const root = dirname(envelopeArtifact.pathname);
    const artifact = resolveEvidenceReference(
      envelope.execution[name],
      root,
      `B-02 ${role} lane ${name}`,
      options,
    );
    const relativePath = relative(laneRoot, artifact.pathname)
      .split(sep).join('/');
    if (
      relativePath.startsWith('../')
      || relativePath === '..'
      || isAbsolute(relativePath)
    ) {
      fail(`B-02 ${role} lane ${name} escapes the lane evidence directory`);
    }
    bindReferencedArtifact(
      referenced,
      laneRoot,
      artifact,
      `B-02 ${role} lane ${name}`,
    );
    artifacts[name] = artifact;
  }
  return Object.freeze(artifacts);
}

function externalResourceMeasurements(stdout, role) {
  if (!Array.isArray(stdout.inputs)) return Object.freeze([]);
  return Object.freeze(stdout.inputs.map((input) => Object.freeze({
    inputIndex: input.inputIndex,
    operationCost: percentageRecord(
      String(input.operationCost),
      String(input.maximumOperationCost),
      `B-02 ${role} input ${input.inputIndex} operation cost`,
    ),
    hashDigestIterations: percentageRecord(
      String(input.hashDigestIterations),
      String(input.maximumHashDigestIterations),
      `B-02 ${role} input ${input.inputIndex} hash iterations`,
    ),
    signatureChecks: percentageRecord(
      String(input.signatureCheckCount),
      String(input.maximumSignatureCheckCount),
      `B-02 ${role} input ${input.inputIndex} signature checks`,
    ),
  })));
}

function verifyLane({
  authorityContext,
  expectedMaintainerTool,
  expectedTransaction,
  laneRoot,
  reference,
  referenced,
  role,
  sourceOutputs,
  subject,
}) {
  const envelopeArtifact = resolveEvidenceReference(
    reference,
    laneRoot,
    `B-02 ${role} lane envelope`,
    { jcs: true },
  );
  const artifacts = collectEnvelopeArtifacts(
    envelopeArtifact,
    laneRoot,
    role,
    referenced,
  );
  const derived = verifyV2Q02AuthorityLaneEvidence({
    attestationDomain: V2_B02_LANE_ATTESTATION_DOMAIN,
    attestationVersion: V2_B02_LANE_ATTESTATION_VERSION,
    authorityContext,
    bchnMinedInputSchema: V2_B02_BCHN_MINED_INPUT_SCHEMA,
    bchnMinedOutputSchema: V2_B02_BCHN_MINED_OUTPUT_SCHEMA,
    envelopePath: envelopeArtifact.pathname,
    envelopeSchema: V2_B02_LANE_ENVELOPE_SCHEMA,
    expectedRole: role,
    expectedSubject: subject,
    expectedTransaction,
    machineManifestSchema: V2_B02_MACHINE_MANIFEST_SCHEMA,
    subjectField: 'subject',
    vmInputSchema: V2_B02_VM_INPUT_SCHEMA,
    vmOutputSchema: V2_B02_VM_OUTPUT_SCHEMA,
  });
  if (
    derived.lane !== role
    || derived.derivedOutcome !== 'accepted'
    || derived.envelopeSha256 !== envelopeArtifact.sha256
  ) {
    fail(`B-02 ${role} lane did not derive acceptance from its exact signed evidence`);
  }
  if (
    role === 'maintainer'
    && canonicalizeJcs(envelopeArtifact.value.tool)
      !== canonicalizeJcs(expectedMaintainerTool)
  ) {
    fail('B-02 maintainer envelope differs from the signed-manifest approved upstream revision');
  }
  if (role === 'maintainer' || role === 'leanbch') {
    const exactSources = sourceOutputs.map((entry) => entry.serializedHex);
    if (
      canonicalizeJcs(artifacts.stdin.value.sourceOutputs)
        !== canonicalizeJcs(exactSources)
    ) {
      fail(`B-02 ${role} lane did not consume the exact source-output bytes`);
    }
  }
  return Object.freeze({
    accepted: true,
    command: envelopeArtifact.value.command,
    completedAt: envelopeArtifact.value.completedAt,
    evidence: Object.freeze({
      envelope: envelopeArtifact.value,
      machineManifest: artifacts.machineManifest.value,
      stderrBase64: artifacts.stderr.bytes.toString('base64'),
      stdin: artifacts.stdin.value,
      stdout: artifacts.stdout.value,
    }),
    envelopeSha256: envelopeArtifact.sha256,
    executionArtifactSha256s: Object.freeze({
      machineManifest: artifacts.machineManifest.sha256,
      stderr: artifacts.stderr.sha256,
      stdin: artifacts.stdin.sha256,
      stdout: artifacts.stdout.sha256,
    }),
    identitySha256: sha256(canonicalBytes(subject.identity)),
    inputBindingSha256: sha256(canonicalBytes(subject.inputBindings)),
    machineManifestSha256: artifacts.machineManifest.sha256,
    machineManifest: artifacts.machineManifest.value,
    rawTransactionSha256: subject.rawTransactionSha256,
    resources: externalResourceMeasurements(artifacts.stdout.value, role),
    role,
    runId: derived.runId,
    sourceOutputSha256s: Object.freeze(
      sourceOutputs.map((entry) => entry.sha256),
    ),
    subjectSha256: sha256(canonicalBytes(subject)),
    startedAt: envelopeArtifact.value.startedAt,
    tool: envelopeArtifact.value.tool,
    toolSha256: sha256(canonicalBytes(envelopeArtifact.value.tool)),
    transactionId: subject.transactionId,
  });
}

function transactionEntryShape(value, label) {
  exact(value, [
    'carrierCount',
    'inputCount',
    'inputRoles',
    'kind',
    'lanes',
    'localLibauth',
    'outputCount',
    'outputRoles',
    'rawTransactionHex',
    'rawTransactionSha256',
    'serializedBytes',
    'sourceOutputs',
    'transactionId',
  ], label);
  if (!ACTIONS.includes(value.kind)) fail(`${label}.kind is invalid`);
  integer(value.carrierCount, 1, 255, `${label}.carrierCount`);
  integer(value.inputCount, 1, 258, `${label}.inputCount`);
  integer(value.outputCount, 1, 259, `${label}.outputCount`);
  integer(
    value.serializedBytes,
    1,
    V2_MAX_TRANSACTION_BYTES,
    `${label}.serializedBytes`,
  );
  hash(value.rawTransactionSha256, `${label}.rawTransactionSha256`);
  hash(value.transactionId, `${label}.transactionId`);
  const inputRoles = expectedInputRoles(value.carrierCount);
  const outputRoles = expectedOutputRoles(value.kind, value.carrierCount);
  roleLayout(value.inputRoles, inputRoles, `${label}.inputRoles`);
  roleLayout(value.outputRoles, outputRoles, `${label}.outputRoles`);
  if (
    value.inputCount !== inputRoles.length
    || value.outputCount !== outputRoles.length
  ) {
    fail(`${label} input or output count differs from the exact role layout`);
  }
  evidenceReference(value.localLibauth, `${label}.localLibauth`);
  exact(value.lanes, LANE_ROLES, `${label}.lanes`);
  for (const role of LANE_ROLES) {
    evidenceReference(value.lanes[role], `${label}.lanes.${role}`);
  }
  if (
    !Array.isArray(value.sourceOutputs)
    || value.sourceOutputs.length !== inputRoles.length
  ) {
    fail(`${label}.sourceOutputs must contain every input source output`);
  }
  return Object.freeze({ inputRoles, outputRoles });
}

function validateTransactionsManifest(value, expectedIdentity) {
  exact(value, [
    'identity',
    'maintainerBenchmark',
    'schema',
    'transactions',
  ], 'B-02 transactions manifest');
  if (value.schema !== V2_B02_TRANSACTIONS_SCHEMA) {
    fail('B-02 transactions manifest schema is unsupported');
  }
  const identity = identityRecord(
    value.identity,
    'B-02 transactions manifest identity',
  );
  if (
    canonicalizeJcs(identity) !== canonicalizeJcs(expectedIdentity)
  ) {
    fail('B-02 transactions manifest identity differs from the final descriptor, runtime, root, or source');
  }
  const maintainerBenchmark = maintainerTool(
    value.maintainerBenchmark,
    'B-02 maintainer benchmark provenance',
  );
  if (
    !Array.isArray(value.transactions)
    || value.transactions.length !== ACTIONS.length
  ) {
    fail('B-02 transactions manifest must contain exactly three transactions');
  }
  value.transactions.forEach((entry, index) => {
    transactionEntryShape(entry, `B-02 transaction ${index}`);
    if (entry.kind !== ACTIONS[index]) {
      fail('B-02 transactions must be exactly ordered deposit, transfer, withdrawal');
    }
  });
  if (
    new Set(value.transactions.map((entry) => entry.transactionId)).size
      !== ACTIONS.length
    || new Set(
      value.transactions.map((entry) => entry.rawTransactionSha256),
    ).size !== ACTIONS.length
  ) {
    fail('B-02 deposit, transfer, and withdrawal raw transactions must be distinct');
  }
  return Object.freeze({
    identity,
    maintainerBenchmark,
    transactions: value.transactions,
  });
}

function derivedLaneRecord(value, expected, label) {
  exact(value, [
    'accepted',
    'envelopeSha256',
    'identitySha256',
    'inputBindingSha256',
    'machineManifestSha256',
    'rawTransactionSha256',
    'resources',
    'role',
    'runId',
    'sourceOutputSha256s',
    'subjectSha256',
    'toolSha256',
    'transactionId',
  ], label);
  if (
    value.accepted !== true
    || value.role !== expected.role
    || value.identitySha256 !== expected.identitySha256
    || value.rawTransactionSha256 !== expected.rawTransactionSha256
    || value.transactionId !== expected.transactionId
    || value.inputBindingSha256 !== expected.inputBindingSha256
    || canonicalizeJcs(value.sourceOutputSha256s)
      !== canonicalizeJcs(expected.sourceOutputSha256s)
  ) {
    fail(`${label} acceptance, transaction, sources, or per-input binding differs`);
  }
  for (const key of [
    'envelopeSha256',
    'identitySha256',
    'inputBindingSha256',
    'machineManifestSha256',
    'rawTransactionSha256',
    'subjectSha256',
    'toolSha256',
    'transactionId',
  ]) hash(value[key], `${label}.${key}`);
  hash(value.runId, `${label}.runId`);
  if (
    !Array.isArray(value.resources)
    || (
      ['maintainer', 'leanbch'].includes(value.role)
      && value.resources.length !== expected.inputCount
    )
    || (
      ['bchn-mempool', 'bchn-mined'].includes(value.role)
      && value.resources.length !== 0
    )
  ) {
    fail(`${label}.resources do not contain the exact role-specific per-input records`);
  }
  const seenInputs = new Set();
  for (const resource of value.resources) {
    exact(resource, [
      'hashDigestIterations',
      'inputIndex',
      'operationCost',
      'signatureChecks',
    ], `${label}.resources`);
    integer(
      resource.inputIndex,
      0,
      expected.inputCount - 1,
      `${label}.resources.inputIndex`,
    );
    if (seenInputs.has(resource.inputIndex)) {
      fail(`${label}.resources duplicate an input index`);
    }
    seenInputs.add(resource.inputIndex);
    for (const name of [
      'hashDigestIterations',
      'operationCost',
      'signatureChecks',
    ]) {
      exact(
        resource[name],
        ['maximum', 'percentBasisPoints', 'used'],
        `${label}.resources.${name}`,
      );
      if (
        typeof resource[name].used !== 'string'
        || !/^(0|[1-9][0-9]*)$/u.test(resource[name].used)
        || typeof resource[name].maximum !== 'string'
        || !/^(0|[1-9][0-9]*)$/u.test(resource[name].maximum)
        || BigInt(resource[name].used) > BigInt(resource[name].maximum)
      ) {
        fail(`${label}.resources.${name} exceeds 100 percent or is noncanonical`);
      }
      const expectedBasisPoints =
        resource[name].maximum === '0'
          ? 0
          : Number(
            (BigInt(resource[name].used) * 10_000n)
              / BigInt(resource[name].maximum),
          );
      if (resource[name].percentBasisPoints !== expectedBasisPoints) {
        fail(`${label}.resources.${name} percentage is inconsistent`);
      }
    }
  }
  return value;
}

function validateDerivedCycle(value) {
  exact(value, [
    'actualEvidenceFiles',
    'identity',
    'referencedEvidenceFiles',
    'transactions',
  ], 'B-02 derived cycle');
  const identity = identityRecord(value.identity, 'B-02 derived identity');
  if (
    !Array.isArray(value.transactions)
    || value.transactions.length !== 3
  ) {
    fail('B-02 derived cycle requires exactly three transactions');
  }
  const runIds = new Set();
  for (const [index, entry] of value.transactions.entries()) {
    exact(entry, [
      'inputBindingSha256',
      'kind',
      'lanes',
      'localAccepted',
      'outputRoles',
      'rawTransactionHex',
      'rawTransactionSha256',
      'serializedBytes',
      'sourceOutputSha256s',
      'transactionId',
    ], `B-02 derived transaction ${index}`);
    if (entry.kind !== ACTIONS[index] || entry.localAccepted !== true) {
      fail('B-02 derived transaction action order or local acceptance is invalid');
    }
    const measured = measureRawTransaction(entry.rawTransactionHex);
    if (
      measured.rawTransactionSha256 !== entry.rawTransactionSha256
      || measured.transaction.txid !== entry.transactionId
      || measured.transaction.sizeBytes !== entry.serializedBytes
    ) {
      fail(`B-02 derived ${entry.kind} raw transaction bytes or identity differ`);
    }
    hash(entry.inputBindingSha256, `B-02 ${entry.kind} input binding`);
    if (
      !Array.isArray(entry.sourceOutputSha256s)
      || entry.sourceOutputSha256s.length !== measured.transaction.inputs.length
    ) {
      fail(`B-02 derived ${entry.kind} source-output closure is incomplete`);
    }
    entry.sourceOutputSha256s.forEach((entryHash, sourceIndex) =>
      hash(entryHash, `B-02 ${entry.kind} source output ${sourceIndex}`));
    const expectedRoles = expectedOutputRoles(
      entry.kind,
      measured.transaction.inputs.length - 3,
    );
    integer(
      measured.transaction.inputs.length - 3,
      1,
      255,
      `B-02 derived ${entry.kind} carrier count`,
    );
    roleLayout(
      entry.outputRoles,
      expectedRoles,
      `B-02 derived ${entry.kind} output roles`,
    );
    exact(entry.lanes, LANE_ROLES, `B-02 ${entry.kind} lanes`);
    for (const role of LANE_ROLES) {
      const lane = derivedLaneRecord(
        entry.lanes[role],
        {
          identitySha256: sha256(canonicalBytes(identity)),
          inputCount: measured.transaction.inputs.length,
          inputBindingSha256: entry.inputBindingSha256,
          rawTransactionSha256: entry.rawTransactionSha256,
          role,
          sourceOutputSha256s: entry.sourceOutputSha256s,
          transactionId: entry.transactionId,
        },
        `B-02 ${entry.kind} ${role} lane`,
      );
      if (runIds.has(lane.runId)) {
        fail('B-02 external lane run IDs must be globally unique');
      }
      runIds.add(lane.runId);
    }
  }
  assertExactEvidenceClosure(
    value.referencedEvidenceFiles,
    value.actualEvidenceFiles,
  );
  return Object.freeze({
    identity,
    runCount: runIds.size,
    transactionCount: 3,
  });
}

/**
 * TEST-ONLY: validate a pure, already-derived cycle. This seam cannot open
 * files, resolve a release root, or return qualification.
 */
export function verifyV2B02StructuralCycleForTestOnly(value) {
  const result = validateDerivedCycle(value);
  return Object.freeze({
    schema: V2_B02_TEST_ONLY_STRUCTURAL_SCHEMA,
    b02Qualified: false,
    production: false,
    releaseQualified: false,
    structurallyValid: true,
    ...result,
  });
}

function createOutput(directory) {
  if (existsSync(directory)) {
    fail('B-02 refuses a preexisting output directory');
  }
  directDirectory(dirname(directory), 'B-02 output parent');
  mkdirSync(directory, { mode: 0o700 });
  chmodSync(directory, 0o700);
  const entry = lstatSync(directory);
  if (
    !entry.isDirectory()
    || entry.isSymbolicLink()
    || entry.uid !== process.getuid()
    || (entry.mode & 0o7777) !== 0o700
    || realpathSync(directory) !== directory
  ) {
    fail('B-02 output directory must be direct user-owned mode 0700');
  }
}

function writeDirect(directory, filename, value) {
  const pathname = join(directory, filename);
  const temporary = join(
    directory,
    `.${process.pid}.${Date.now()}.${filename}.tmp`,
  );
  const bytes = canonicalBytes(value);
  const descriptor = openSync(
    temporary,
    fsConstants.O_WRONLY
      | fsConstants.O_CREAT
      | fsConstants.O_EXCL
      | (fsConstants.O_NOFOLLOW ?? 0),
    0o600,
  );
  try {
    writeSync(descriptor, bytes);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  chmodSync(temporary, 0o600);
  renameSync(temporary, pathname);
  const entry = lstatSync(pathname);
  if (
    !entry.isFile()
    || entry.isSymbolicLink()
    || entry.nlink !== 1
    || entry.uid !== process.getuid()
    || (entry.mode & 0o7777) !== 0o600
  ) {
    fail(`B-02 ${filename} is not a direct user-owned 0600 file`);
  }
  const directoryDescriptor = openSync(
    directory,
    fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY ?? 0),
  );
  try {
    fsyncSync(directoryDescriptor);
  } finally {
    closeSync(directoryDescriptor);
  }
  return Object.freeze({
    path: pathname,
    sha256: sha256(bytes),
  });
}

function writeFailure(options, error, { outputCreated = false } = {}) {
  try {
    if (!existsSync(options.outputDirectory)) {
      createOutput(options.outputDirectory);
    } else if (outputCreated) {
      directDirectory(options.outputDirectory, 'B-02 failure output');
      if (readdirSync(options.outputDirectory).length !== 0) return;
    } else {
      return;
    }
    const unboundedReason =
      error instanceof Error ? error.message : String(error);
    const reason = unboundedReason
      .replace(/[\u0000-\u001f\u007f]+/gu, ' ')
      .slice(0, 4096);
    writeDirect(options.outputDirectory, 'failure.json', {
      schema: V2_B02_RESULT_SCHEMA,
      status: 'b02-not-qualified',
      b02Qualified: false,
      production: false,
      releaseQualified: false,
      request: {
        expectedCommit: options.expectedCommit,
        expectedTree: options.expectedTree,
        releaseRootId: options.releaseRootId,
      },
      reason,
    });
  } catch {
    // Preserve the primary failure and never overwrite an existing directory.
  }
}

function verifyTransaction({
  authorityContext,
  identity,
  laneRoot,
  maintainerBenchmark,
  manifestEntry,
  referenced,
  settlementPins,
}) {
  const shape = transactionEntryShape(
    manifestEntry,
    `B-02 ${manifestEntry.kind} transaction`,
  );
  const measured = measureRawTransaction(
    manifestEntry.rawTransactionHex,
    manifestEntry.carrierCount,
  );
  const transaction = measured.transaction;
  if (
    manifestEntry.rawTransactionSha256 !== measured.rawTransactionSha256
    || manifestEntry.transactionId !== transaction.txid
    || manifestEntry.serializedBytes !== transaction.sizeBytes
    || manifestEntry.inputCount !== transaction.inputs.length
    || manifestEntry.outputCount !== transaction.outputs.length
  ) {
    fail(`B-02 ${manifestEntry.kind} transaction metadata differs from its exact raw bytes`);
  }
  roleLayout(
    manifestEntry.inputRoles,
    shape.inputRoles,
    `B-02 ${manifestEntry.kind} input roles`,
  );
  roleLayout(
    manifestEntry.outputRoles,
    shape.outputRoles,
    `B-02 ${manifestEntry.kind} output roles`,
  );
  const sourceOutputs = Object.freeze(
    manifestEntry.sourceOutputs.map((entry, index) =>
      normalizedSourceOutput(
        entry,
        transaction.inputs[index],
        `B-02 ${manifestEntry.kind} source output ${index}`,
      )),
  );
  assertDescriptorLocks(
    manifestEntry.kind,
    transaction,
    sourceOutputs,
    settlementPins,
    identity.instanceId,
  );

  const localArtifact = resolveEvidenceReference(
    manifestEntry.localLibauth,
    laneRoot,
    `B-02 ${manifestEntry.kind} local Libauth evidence`,
  );
  bindReferencedArtifact(
    referenced,
    laneRoot,
    localArtifact,
    `B-02 ${manifestEntry.kind} local Libauth evidence`,
  );
  let local;
  try {
    local = inspectV2LocalVmEvidence(localArtifact.bytes);
  } catch (error) {
    fail(`B-02 ${manifestEntry.kind} local Libauth evidence is invalid: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
  if (
    local.allInputsAccepted !== true
    || local.instanceId !== identity.instanceId
    || local.carrierCount !== manifestEntry.carrierCount
    || local.transaction.rawTransactionHex
      !== manifestEntry.rawTransactionHex
    || local.transaction.txid !== manifestEntry.transactionId
    || local.tool.profileId !== identity.profileId
    || local.tool.profileSha256 !== identity.profileSha256
  ) {
    fail(`B-02 ${manifestEntry.kind} local Libauth evidence differs from the final identity or raw transaction`);
  }
  const inputBindings = localInputBindings(
    local,
    transaction,
    sourceOutputs,
  );
  const inputBindingSha256 = sha256(canonicalBytes(inputBindings));
  const subject = laneSubject({
    identity,
    inputBindings,
    kind: manifestEntry.kind,
    rawTransactionHex: manifestEntry.rawTransactionHex,
    rawTransactionSha256: manifestEntry.rawTransactionSha256,
    sourceOutputs,
    transactionId: manifestEntry.transactionId,
  });
  const expectedTransaction = Object.freeze({
    expectation: 'accept',
    rawTransactionSha256: manifestEntry.rawTransactionSha256,
    transactionId: manifestEntry.transactionId,
  });
  const lanes = {};
  for (const role of LANE_ROLES) {
    lanes[role] = verifyLane({
      authorityContext,
      expectedMaintainerTool: maintainerBenchmark,
      expectedTransaction,
      laneRoot,
      reference: manifestEntry.lanes[role],
      referenced,
      role,
      sourceOutputs,
      subject,
    });
  }
  const localResources = localResourceMeasurements(inputBindings);
  for (const role of ['maintainer', 'leanbch']) {
    for (const [index, resource] of lanes[role].resources.entries()) {
      const localResource = localResources[index];
      if (
        resource.inputIndex !== index
        || localResource.inputIndex !== index
        || resource.operationCost.maximum
          !== localResource.operationCost.maximum
        || resource.hashDigestIterations.maximum
          !== localResource.hashDigestIterations.maximum
        || resource.signatureChecks.maximum
          !== localResource.signatureChecks.maximum
      ) {
        fail(`B-02 ${role} lane reports a VM resource ceiling different from local BCH_2026_STANDARD input ${index}`);
      }
    }
  }
  return Object.freeze({
    derived: Object.freeze({
      inputBindingSha256,
      kind: manifestEntry.kind,
      lanes: Object.freeze(lanes),
      localAccepted: true,
      outputRoles: shape.outputRoles,
      rawTransactionHex: manifestEntry.rawTransactionHex,
      rawTransactionSha256: manifestEntry.rawTransactionSha256,
      serializedBytes: transaction.sizeBytes,
      sourceOutputSha256s: Object.freeze(
        sourceOutputs.map((entry) => entry.sha256),
      ),
      transactionId: transaction.txid,
    }),
    result: Object.freeze({
      kind: manifestEntry.kind,
      transactionId: transaction.txid,
      rawTransactionSha256: manifestEntry.rawTransactionSha256,
      serializedBytes: transaction.sizeBytes,
      inputCount: transaction.inputs.length,
      outputCount: transaction.outputs.length,
      maximumUnlockingBytecodeBytes:
        measured.maximumUnlockingBytecodeBytes,
      sourceOutputSha256s: Object.freeze(
        sourceOutputs.map((entry) => entry.sha256),
      ),
      inputRoleLayout: shape.inputRoles,
      outputRoleLayout: shape.outputRoles,
      localLibauthEvidenceSha256: localArtifact.sha256,
      localLibauth: Object.freeze({
        evidenceSha256: localArtifact.sha256,
        tool: local.tool,
      }),
      inputBindings,
      localResources,
      rawTransactionHex: manifestEntry.rawTransactionHex,
      sourceOutputs: Object.freeze(sourceOutputs.map((entry) =>
        Object.freeze({
          index: entry.index,
          outpoint: entry.outpoint,
          serializedHex: entry.serializedHex,
          sha256: entry.sha256,
        }))),
      externalLanes: Object.freeze(Object.fromEntries(
        LANE_ROLES.map((role) => [
          role,
          Object.freeze({
            command: lanes[role].command,
            completedAt: lanes[role].completedAt,
            evidence: lanes[role].evidence,
            envelopeSha256: lanes[role].envelopeSha256,
            executionArtifactSha256s:
              lanes[role].executionArtifactSha256s,
            machineManifestSha256:
              lanes[role].machineManifestSha256,
            machineManifest: lanes[role].machineManifest,
            resources: lanes[role].resources,
            runId: lanes[role].runId,
            startedAt: lanes[role].startedAt,
            subjectSha256: lanes[role].subjectSha256,
            tool: lanes[role].tool,
            toolSha256: lanes[role].toolSha256,
          }),
        ]),
      )),
      hardPolicy: measured.hardPolicy,
      narrowerTelemetry: measured.narrowerTelemetry,
    }),
  });
}

function boundedText(value, label, maximum = 4096) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > maximum
  ) {
    fail(`${label} must be a bounded nonempty string`);
  }
  return value;
}

function standaloneCommand(value, label) {
  exact(value, ['arguments', 'executable'], label);
  boundedText(value.executable, `${label}.executable`);
  if (
    !Array.isArray(value.arguments)
    || value.arguments.length > 128
    || value.arguments.some(
      (entry) =>
        typeof entry !== 'string' || entry.length > 16_384,
    )
  ) {
    fail(`${label}.arguments must be a bounded string array`);
  }
  return Object.freeze({
    arguments: Object.freeze([...value.arguments]),
    executable: value.executable,
  });
}

function standaloneTool(value, label) {
  exact(value, [
    'commit',
    'executableSha256',
    'lockfileSha256',
    'repositoryUrl',
    'runnerSha256',
    'sourceSha256',
    'tree',
    'version',
  ], label);
  if (
    typeof value.repositoryUrl !== 'string'
    || !/^https:\/\/[^/?#\s]+\/\S+$/u.test(value.repositoryUrl)
    || !SHA1.test(value.commit)
    || !SHA1.test(value.tree)
    || typeof value.version !== 'string'
    || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u.test(value.version)
  ) {
    fail(`${label} repository, revision, tree, or version is invalid`);
  }
  for (const key of [
    'executableSha256',
    'lockfileSha256',
    'runnerSha256',
    'sourceSha256',
  ]) hash(value[key], `${label}.${key}`);
  return Object.freeze({ ...value });
}

function standaloneAuthorityArtifact(value, expectedIdentity) {
  exact(value, [
    'authorities',
    'chipnetPolicy',
    'evidenceWindow',
    'finalLocksSha256',
    'instanceId',
    'network',
    'profileId',
    'schema',
    'topologyId',
  ], 'B-02 standalone lane authority artifact');
  if (
    value.schema !== V2_Q02_LANE_AUTHORITIES_SCHEMA
    || value.finalLocksSha256 !== expectedIdentity.finalLocksSha256
    || value.instanceId !== expectedIdentity.instanceId
    || value.profileId !== expectedIdentity.profileId
    || value.topologyId !== expectedIdentity.topologyId
  ) {
    fail('B-02 standalone lane authority artifact differs from the final identity');
  }
  exact(value.network, ['id', 'name'], 'B-02 standalone lane network');
  if (value.network.id !== 2 || value.network.name !== 'chipnet') {
    fail('B-02 standalone lane authority artifact must select Chipnet');
  }
  exact(
    value.evidenceWindow,
    ['notAfter', 'notBefore'],
    'B-02 standalone evidence window',
  );
  const notBefore = standaloneLanePrimitives.canonicalTimestamp(
    value.evidenceWindow.notBefore,
    'B-02 standalone evidenceWindow.notBefore',
  );
  const notAfter = standaloneLanePrimitives.canonicalTimestamp(
    value.evidenceWindow.notAfter,
    'B-02 standalone evidenceWindow.notAfter',
  );
  if (notAfter <= notBefore) {
    fail('B-02 standalone evidence window is empty or reversed');
  }
  exact(
    value.chipnetPolicy,
    ['checkpoint', 'minimumConfirmations'],
    'B-02 standalone Chipnet policy',
  );
  exact(
    value.chipnetPolicy.checkpoint,
    ['blockHash', 'chainwork', 'height', 'maximumTarget'],
    'B-02 standalone Chipnet checkpoint',
  );
  hash(
    value.chipnetPolicy.checkpoint.blockHash,
    'B-02 standalone checkpoint.blockHash',
  );
  hash(
    value.chipnetPolicy.checkpoint.maximumTarget,
    'B-02 standalone checkpoint.maximumTarget',
  );
  integer(
    value.chipnetPolicy.checkpoint.height,
    0,
    Number.MAX_SAFE_INTEGER,
    'B-02 standalone checkpoint.height',
  );
  integer(
    value.chipnetPolicy.minimumConfirmations,
    1,
    10_000,
    'B-02 standalone minimumConfirmations',
  );
  if (
    typeof value.chipnetPolicy.checkpoint.chainwork !== 'string'
    || !/^(0|[1-9][0-9]*)$/u.test(
      value.chipnetPolicy.checkpoint.chainwork,
    )
  ) {
    fail('B-02 standalone checkpoint.chainwork must be canonical decimal');
  }
  if (
    !Array.isArray(value.authorities)
    || value.authorities.length !== LANE_ROLES.length
  ) {
    fail('B-02 standalone authority artifact requires exactly four lane roles');
  }
  const byRole = new Map();
  const authorityIds = new Set();
  const keyHashes = new Set();
  for (const [index, authority] of value.authorities.entries()) {
    const label = `B-02 standalone authority ${index}`;
    exact(authority, [
      'authorityId',
      'command',
      'organization',
      'publicKey',
      'role',
      'tool',
    ], label);
    if (
      typeof authority.authorityId !== 'string'
      || !/^[a-z0-9][a-z0-9._-]{0,127}$/u.test(authority.authorityId)
      || !LANE_ROLES.includes(authority.role)
      || byRole.has(authority.role)
      || authorityIds.has(authority.authorityId)
    ) {
      fail(`${label} id or role is invalid or duplicated`);
    }
    boundedText(authority.organization, `${label}.organization`, 256);
    const command = standaloneCommand(
      authority.command,
      `${label}.command`,
    );
    const tool = standaloneTool(authority.tool, `${label}.tool`);
    let key;
    try {
      key = createPublicKey(authority.publicKey);
    } catch {
      fail(`${label}.publicKey is invalid`);
    }
    const canonicalPublicKey = key.export({
      format: 'pem',
      type: 'spki',
    }).toString();
    const keySha256 = sha256(
      key.export({ format: 'der', type: 'spki' }),
    );
    if (
      key.asymmetricKeyType !== 'ed25519'
      || authority.publicKey !== canonicalPublicKey
      || keyHashes.has(keySha256)
    ) {
      fail(`${label}.publicKey must be unique canonical Ed25519 SPKI`);
    }
    authorityIds.add(authority.authorityId);
    keyHashes.add(keySha256);
    byRole.set(authority.role, Object.freeze({
      ...authority,
      command,
      key,
      tool,
    }));
  }
  if (LANE_ROLES.some((role) => !byRole.has(role))) {
    fail('B-02 standalone authority artifact omits a required role');
  }
  return Object.freeze({
    authoritySetSha256: sha256(canonicalBytes(value)),
    byRole,
    checkpoint: Object.freeze({ ...value.chipnetPolicy.checkpoint }),
    minimumConfirmations: value.chipnetPolicy.minimumConfirmations,
    network: Object.freeze({ ...value.network }),
    notAfter,
    notBefore,
  });
}

function standaloneSourceVerification(value, identity) {
  exact(value, [
    'commit',
    'environment',
    'gitExecutable',
    'gitVersion',
    'replaceObjectsDisabled',
    'tree',
  ], 'B-02 standalone source verification');
  if (
    value.commit !== identity.sourceCommit
    || value.tree !== identity.sourceTree
    || !['/usr/bin/git', '/bin/git'].includes(value.gitExecutable)
    || !/^git version \d+\.\d+(?:\.\d+)?(?:[.A-Za-z0-9+-]*)$/u.test(
      value.gitVersion,
    )
    || value.replaceObjectsDisabled !== true
    || canonicalizeJcs(value.environment) !== canonicalizeJcs(gitEnvironment)
  ) {
    fail('B-02 standalone source verification is not the exact sanitized Git binding');
  }
  return value;
}

function standaloneLocalTool(value, identity, label) {
  exact(
    value,
    ['name', 'profileId', 'profileSha256', 'version', 'vm'],
    label,
  );
  if (
    value.name !== '@bitauth/libauth'
    || value.version !== LIBAUTH_VERSION
    || value.vm !== V2_VM_PROFILE
    || value.profileId !== identity.profileId
    || value.profileSha256 !== identity.profileSha256
  ) {
    fail(`${label} differs from the installed BCH_2026_STANDARD Libauth evaluator or final profile`);
  }
  return Object.freeze({ ...value });
}

function standaloneExecutionReference(value, label) {
  exact(value, ['path', 'sha256'], label);
  relativeName(value.path, `${label}.path`);
  hash(value.sha256, `${label}.sha256`);
  return value;
}

function standaloneStderr(value, label) {
  if (
    typeof value !== 'string'
    || value.length > (256 * 1024 * 1024 * 4 / 3) + 4
  ) {
    fail(`${label} must be bounded canonical base64`);
  }
  let bytes;
  try {
    bytes = Buffer.from(value, 'base64');
  } catch {
    fail(`${label} must be bounded canonical base64`);
  }
  if (bytes.toString('base64') !== value) {
    fail(`${label} must be bounded canonical base64`);
  }
  return bytes;
}

function standaloneInputBindings(
  value,
  transaction,
  sourceOutputs,
  expectedRoles,
  label,
) {
  if (!Array.isArray(value) || value.length !== transaction.inputs.length) {
    fail(`${label} must contain every input exactly once`);
  }
  return Object.freeze(value.map((binding, index) => {
    exact(binding, [
      'accepted',
      'index',
      'metrics',
      'outpoint',
      'role',
      'sourceOutputSha256',
      'unlockingBytecodeSha256',
    ], `${label}[${index}]`);
    exact(
      binding.outpoint,
      ['txid', 'vout'],
      `${label}[${index}].outpoint`,
    );
    roleLayout(
      [binding.role],
      [expectedRoles[index]],
      `${label}[${index}].role`,
    );
    const input = transaction.inputs[index];
    if (
      binding.accepted !== true
      || binding.index !== index
      || binding.outpoint.txid !== input.outpoint.txid
      || binding.outpoint.vout !== input.outpoint.vout
      || binding.sourceOutputSha256 !== sourceOutputs[index].sha256
      || binding.unlockingBytecodeSha256
        !== sha256(input.unlockingBytecode)
    ) {
      fail(`${label}[${index}] does not bind the exact accepted transaction input and source output`);
    }
    let metrics;
    try {
      metrics = assertV2VmResourceMetrics(binding.metrics, {
        inputIndex: index,
        unlockingBytecodeBytes: input.unlockingBytecodeBytes,
      });
    } catch (error) {
      fail(`${label}[${index}] VM resource metrics are invalid: ${
        error instanceof Error ? error.message : String(error)
      }`);
    }
    return Object.freeze({
      ...binding,
      metrics,
      outpoint: Object.freeze({ ...binding.outpoint }),
      role: expectedRoles[index],
    });
  }));
}

function standaloneLane({
  authority,
  authorityContext,
  expectedDescriptor,
  inputBindings,
  lane,
  localResources,
  role,
  sourceOutputs,
  subject,
  transaction,
}) {
  const label = `B-02 standalone ${subject.kind} ${role} lane`;
  exact(lane, [
    'command',
    'completedAt',
    'envelopeSha256',
    'evidence',
    'executionArtifactSha256s',
    'machineManifest',
    'machineManifestSha256',
    'resources',
    'runId',
    'startedAt',
    'subjectSha256',
    'tool',
    'toolSha256',
  ], label);
  exact(lane.evidence, [
    'envelope',
    'machineManifest',
    'stderrBase64',
    'stdin',
    'stdout',
  ], `${label}.evidence`);
  const envelope = lane.evidence.envelope;
  exact(envelope, [
    'authorityRole',
    'authoritySetSha256',
    'command',
    'completedAt',
    'descriptor',
    'execution',
    'runId',
    'schema',
    'signature',
    'startedAt',
    'subject',
    'tool',
  ], `${label}.evidence.envelope`);
  exact(envelope.execution, [
    'exitCode',
    'machineManifest',
    'signal',
    'stderr',
    'stdin',
    'stdout',
  ], `${label}.evidence.envelope.execution`);
  if (envelope.authorityRole !== role) {
    fail(`${label} signed authority role differs from its lane`);
  }
  if (envelope.execution.exitCode !== 0 || envelope.execution.signal !== null) {
    fail(`${label} command did not exit successfully`);
  }
  for (const name of ['machineManifest', 'stderr', 'stdin', 'stdout']) {
    standaloneExecutionReference(
      envelope.execution[name],
      `${label}.evidence.envelope.execution.${name}`,
    );
  }
  const stderr = standaloneStderr(
    lane.evidence.stderrBase64,
    `${label}.evidence.stderrBase64`,
  );
  const embeddedArtifactHashes = Object.freeze({
    machineManifest: sha256(canonicalBytes(
      lane.evidence.machineManifest,
    )),
    stderr: sha256(stderr),
    stdin: sha256(canonicalBytes(lane.evidence.stdin)),
    stdout: sha256(canonicalBytes(lane.evidence.stdout)),
  });
  exact(
    lane.executionArtifactSha256s,
    ['machineManifest', 'stderr', 'stdin', 'stdout'],
    `${label}.executionArtifactSha256s`,
  );
  for (const name of Object.keys(embeddedArtifactHashes)) {
    hash(
      lane.executionArtifactSha256s[name],
      `${label}.executionArtifactSha256s.${name}`,
    );
    if (
      lane.executionArtifactSha256s[name]
        !== embeddedArtifactHashes[name]
      || envelope.execution[name].sha256
        !== embeddedArtifactHashes[name]
    ) {
      fail(`${label} embedded ${name} differs from its signed execution reference`);
    }
  }
  if (
    sha256(canonicalBytes(envelope)) !== lane.envelopeSha256
    || canonicalizeJcs(lane.command) !== canonicalizeJcs(envelope.command)
    || canonicalizeJcs(lane.tool) !== canonicalizeJcs(envelope.tool)
    || canonicalizeJcs(lane.machineManifest)
      !== canonicalizeJcs(lane.evidence.machineManifest)
    || lane.machineManifestSha256
      !== embeddedArtifactHashes.machineManifest
    || lane.toolSha256 !== sha256(canonicalBytes(lane.tool))
    || lane.subjectSha256 !== sha256(canonicalBytes(subject))
    || lane.runId !== envelope.runId
    || lane.startedAt !== envelope.startedAt
    || lane.completedAt !== envelope.completedAt
  ) {
    fail(`${label} summary differs from the embedded signed evidence`);
  }
  hash(lane.envelopeSha256, `${label}.envelopeSha256`);
  hash(lane.machineManifestSha256, `${label}.machineManifestSha256`);
  hash(lane.runId, `${label}.runId`);
  hash(lane.subjectSha256, `${label}.subjectSha256`);
  hash(lane.toolSha256, `${label}.toolSha256`);
  standaloneCommand(lane.command, `${label}.command`);
  const normalizedTool = standaloneTool(lane.tool, `${label}.tool`);
  if (
    canonicalizeJcs(normalizedTool) !== canonicalizeJcs(authority.tool)
  ) {
    fail(`${label} tool differs from its descriptor-pinned authority`);
  }
  let signedWindow;
  try {
    signedWindow = standaloneLanePrimitives.verifySignedLaneEnvelope({
      attestationDomain: V2_B02_LANE_ATTESTATION_DOMAIN,
      attestationVersion: V2_B02_LANE_ATTESTATION_VERSION,
      authority,
      envelope,
      envelopeKeys: [
        'authorityRole',
        'authoritySetSha256',
        'command',
        'completedAt',
        'descriptor',
        'execution',
        'runId',
        'schema',
        'signature',
        'startedAt',
        'subject',
        'tool',
      ],
      envelopeSchema: V2_B02_LANE_ENVELOPE_SCHEMA,
      expectedAuthoritySetSha256:
        authorityContext.authoritySetSha256,
      expectedDescriptor,
      subjectValidator: (candidate) => {
        if (
          canonicalizeJcs(candidate.subject)
            !== canonicalizeJcs(subject)
        ) {
          fail(`${label} signed subject differs from the embedded transaction closure`);
        }
      },
      window: authorityContext,
    });
    standaloneLanePrimitives.validateMachineManifest(
      lane.evidence.machineManifest,
      signedWindow.startedAt,
      signedWindow.completedAt,
      {
        label: `${label}.evidence.machineManifest`,
        schema: V2_B02_MACHINE_MANIFEST_SCHEMA,
      },
    );
  } catch (error) {
    if (error instanceof V2B02FinalVmError) throw error;
    fail(`${label} signature or machine evidence is invalid: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
  const expectedTransaction = Object.freeze({
    expectation: 'accept',
    rawTransactionSha256: subject.rawTransactionSha256,
    transactionId: subject.transactionId,
  });
  let accepted;
  try {
    if (role === 'maintainer' || role === 'leanbch') {
      accepted = standaloneLanePrimitives.validateExternalPerInputLane({
        context: { topology: { inputCount: transaction.inputs.length } },
        expected: expectedTransaction,
        role,
        stdin: lane.evidence.stdin,
        stdinSchema: V2_B02_VM_INPUT_SCHEMA,
        stdout: lane.evidence.stdout,
        stdoutSchema: V2_B02_VM_OUTPUT_SCHEMA,
      });
    } else if (role === 'bchn-mempool') {
      accepted = standaloneLanePrimitives.validateBchnMempoolLane({
        expected: expectedTransaction,
        stdin: lane.evidence.stdin,
        stdout: lane.evidence.stdout,
      });
    } else {
      accepted = standaloneLanePrimitives.validateBchnMinedLane({
        context: {
          checkpoint: authorityContext.checkpoint,
          minimumConfirmations: authorityContext.minimumConfirmations,
        },
        expected: expectedTransaction,
        stdin: lane.evidence.stdin,
        stdinSchema: V2_B02_BCHN_MINED_INPUT_SCHEMA,
        stdout: lane.evidence.stdout,
        stdoutSchema: V2_B02_BCHN_MINED_OUTPUT_SCHEMA,
      });
    }
  } catch (error) {
    if (error instanceof V2B02FinalVmError) throw error;
    fail(`${label} raw outcome evidence is invalid: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
  if (accepted !== true) {
    fail(`${label} does not independently derive acceptance`);
  }
  const derivedResources = externalResourceMeasurements(
    lane.evidence.stdout,
    role,
  );
  if (
    canonicalizeJcs(derivedResources) !== canonicalizeJcs(lane.resources)
  ) {
    fail(`${label} reported resources differ from its exact per-input stdout`);
  }
  if (role === 'maintainer' || role === 'leanbch') {
    for (const [index, resource] of derivedResources.entries()) {
      if (
        resource.inputIndex !== index
        || resource.operationCost.maximum
          !== localResources[index].operationCost.maximum
        || resource.hashDigestIterations.maximum
          !== localResources[index].hashDigestIterations.maximum
        || resource.signatureChecks.maximum
          !== localResources[index].signatureChecks.maximum
        || lane.evidence.stdout.inputs[index].sourceOutputSha256
          !== sourceOutputs[index].sha256
        || lane.evidence.stdout.inputs[index].unlockingBytecodeSha256
          !== inputBindings[index].unlockingBytecodeSha256
      ) {
        fail(`${label} per-input resource or byte binding differs from the local BCH_2026_STANDARD closure`);
      }
    }
  }
  return Object.freeze({
    peakResourceBasisPoints: derivedResources.reduce(
      (peak, resource) => Math.max(
        peak,
        resource.operationCost.percentBasisPoints,
        resource.hashDigestIterations.percentBasisPoints,
        resource.signatureChecks.percentBasisPoints,
      ),
      0,
    ),
    runId: lane.runId,
  });
}

/**
 * Pure standalone replay of a written B-02 success artifact. The caller
 * supplies no trust root and this function performs no I/O: it re-derives raw
 * transaction limits, Libauth metric accounting, all signed lane outcomes,
 * BCHN raw-chain inclusion, and every embedded binding from the result.
 */
export function revalidateV2B02FinalVmResult(value) {
  exact(value, [
    'authorityArtifactSha256',
    'authoritySetSha256',
    'b02Qualified',
    'descriptorSha256',
    'externalLaneRunCount',
    'finalLocksSha256',
    'hardPolicyCeilings',
    'instanceId',
    'laneAuthorityArtifact',
    'laneEvidenceFileCount',
    'maintainerBenchmark',
    'manifestSha256',
    'narrowerMargins',
    'production',
    'profileId',
    'profileSha256',
    'releaseBootstrapSha256',
    'releaseQualified',
    'releaseRootId',
    'runtimeQualification',
    'runtimeMaterialSha256',
    'schema',
    'sourceCommit',
    'sourceTree',
    'sourceVerification',
    'status',
    'topologyId',
    'transactions',
    'transactionsManifestSha256',
  ], 'B-02 standalone result');
  if (
    value.schema !== V2_B02_RESULT_SCHEMA
    || value.status
      !== 'b02-qualified-final-vm-not-production-or-release'
    || value.b02Qualified !== true
    || value.production !== false
    || value.releaseQualified !== false
  ) {
    fail('B-02 standalone result is not an exact successful non-production/non-release artifact');
  }
  const identity = identityRecord(Object.fromEntries([
    'descriptorSha256',
    'finalLocksSha256',
    'instanceId',
    'manifestSha256',
    'profileId',
    'profileSha256',
    'releaseBootstrapSha256',
    'releaseRootId',
    'runtimeMaterialSha256',
    'sourceCommit',
    'sourceTree',
    'topologyId',
  ].map((key) => [key, value[key]])), 'B-02 standalone identity');
  exact(
    value.runtimeQualification,
    ['claims', 'eligibility', 'runtimeMaterialSha256'],
    'B-02 standalone runtime qualification',
  );
  exact(value.runtimeQualification.claims, [
    'ceremonyQualified',
    'developmentKey',
    'finalKey',
    'production',
    'releaseQualified',
  ], 'B-02 standalone runtime claims');
  if (
    value.runtimeQualification.eligibility !== 'final-qualified'
    || value.runtimeQualification.runtimeMaterialSha256
      !== identity.runtimeMaterialSha256
    || value.runtimeQualification.claims.finalKey !== true
    || value.runtimeQualification.claims.developmentKey !== false
    || value.runtimeQualification.claims.ceremonyQualified !== true
    || value.runtimeQualification.claims.production !== false
    || value.runtimeQualification.claims.releaseQualified !== false
  ) {
    fail('B-02 standalone result requires exact final-qualified non-production/non-release PF10 runtime claims');
  }
  let topology;
  try {
    topology = directV2VerifierTopologyById(identity.topologyId);
  } catch (error) {
    fail(`B-02 standalone topology is unsupported: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
  if (topology.id !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID) {
    fail('B-02 standalone result requires the exact final fused PF10 topology');
  }
  standaloneSourceVerification(value.sourceVerification, identity);
  for (const key of [
    'authorityArtifactSha256',
    'authoritySetSha256',
    'transactionsManifestSha256',
  ]) hash(value[key], `B-02 standalone result.${key}`);
  const authorityContext = standaloneAuthorityArtifact(
    value.laneAuthorityArtifact,
    identity,
  );
  if (
    value.authoritySetSha256 !== authorityContext.authoritySetSha256
    || value.authorityArtifactSha256
      !== authorityContext.authoritySetSha256
  ) {
    fail('B-02 standalone authority artifact hashes do not bind the embedded authority artifact');
  }
  const maintainerBenchmark = maintainerTool(
    value.maintainerBenchmark,
    'B-02 standalone maintainer benchmark',
  );
  if (
    canonicalizeJcs(maintainerBenchmark)
      !== canonicalizeJcs(authorityContext.byRole.get('maintainer').tool)
  ) {
    fail('B-02 standalone maintainer benchmark differs from its descriptor-pinned authority');
  }
  exact(value.hardPolicyCeilings, [
    'everyInputUnlockingBytecodeBytes',
    'everyReportedVmResourcePercent',
    'serializedTransactionBytes',
  ], 'B-02 standalone hard policy ceilings');
  if (
    value.hardPolicyCeilings.serializedTransactionBytes
      !== V2_MAX_TRANSACTION_BYTES
    || value.hardPolicyCeilings.everyInputUnlockingBytecodeBytes
      !== V2_MAX_UNLOCKING_BYTECODE_BYTES
    || value.hardPolicyCeilings.everyReportedVmResourcePercent !== 100
    || value.narrowerMargins
      !== '90000/9500-non-blocking-risk-telemetry-only'
  ) {
    fail('B-02 standalone hard ceilings or non-blocking telemetry label drift');
  }
  integer(
    value.laneEvidenceFileCount,
    1,
    Number.MAX_SAFE_INTEGER,
    'B-02 standalone laneEvidenceFileCount',
  );
  if (
    value.externalLaneRunCount !== 12
    || !Array.isArray(value.transactions)
    || value.transactions.length !== ACTIONS.length
  ) {
    fail('B-02 standalone result requires exactly three actions and twelve lane runs');
  }
  const expectedDescriptor = Object.freeze({
    descriptorSha256: identity.descriptorSha256,
    finalLocksSha256: identity.finalLocksSha256,
    instanceId: identity.instanceId,
    manifestSha256: identity.manifestSha256,
    network: authorityContext.network,
    profileId: identity.profileId,
    topologyId: identity.topologyId,
  });
  const runIds = new Set();
  const transactionIds = new Set();
  const rawHashes = new Set();
  let maximumSerializedTransactionBytes = 0;
  let maximumUnlockingBytecodeBytes = 0;
  let peakVmResourcePercentBasisPoints = 0;
  const actions = value.transactions.map((entry, actionIndex) => {
    const label = `B-02 standalone ${ACTIONS[actionIndex]} result`;
    exact(entry, [
      'externalLanes',
      'hardPolicy',
      'inputBindings',
      'inputCount',
      'inputRoleLayout',
      'kind',
      'localLibauth',
      'localLibauthEvidenceSha256',
      'localResources',
      'maximumUnlockingBytecodeBytes',
      'narrowerTelemetry',
      'outputCount',
      'outputRoleLayout',
      'rawTransactionHex',
      'rawTransactionSha256',
      'serializedBytes',
      'sourceOutputSha256s',
      'sourceOutputs',
      'transactionId',
    ], label);
    if (entry.kind !== ACTIONS[actionIndex]) {
      fail('B-02 standalone actions must be exactly deposit, transfer, withdrawal');
    }
    const measured = measureRawTransaction(
      entry.rawTransactionHex,
      topology.carrierCount,
    );
    const transaction = measured.transaction;
    if (
      entry.transactionId !== transaction.txid
      || entry.rawTransactionSha256 !== measured.rawTransactionSha256
      || entry.serializedBytes !== transaction.sizeBytes
      || entry.inputCount !== transaction.inputs.length
      || entry.outputCount !== transaction.outputs.length
      || entry.maximumUnlockingBytecodeBytes
        !== measured.maximumUnlockingBytecodeBytes
      || transaction.inputs.length !== topology.inputCount
      || transaction.outputs.length
        !== (
          entry.kind === 'withdrawal'
            ? topology.withdrawalOutputCount
            : topology.depositTransferOutputCount
        )
    ) {
      fail(`${label} raw transaction identity, size, or final topology differs`);
    }
    if (
      transactionIds.has(transaction.txid)
      || rawHashes.has(measured.rawTransactionSha256)
    ) {
      fail('B-02 standalone action transactions must be distinct');
    }
    transactionIds.add(transaction.txid);
    rawHashes.add(measured.rawTransactionSha256);
    const inputRoles = expectedInputRoles(topology.carrierCount);
    const outputRoles = expectedOutputRoles(
      entry.kind,
      topology.carrierCount,
    );
    roleLayout(entry.inputRoleLayout, inputRoles, `${label}.inputRoleLayout`);
    roleLayout(
      entry.outputRoleLayout,
      outputRoles,
      `${label}.outputRoleLayout`,
    );
    if (
      !Array.isArray(entry.sourceOutputs)
      || entry.sourceOutputs.length !== transaction.inputs.length
    ) {
      fail(`${label}.sourceOutputs do not cover every input`);
    }
    const sourceOutputs = Object.freeze(entry.sourceOutputs.map(
      (source, index) => normalizedSourceOutput(
        source,
        transaction.inputs[index],
        `${label}.sourceOutputs[${index}]`,
      ),
    ));
    const sourceHashes = sourceOutputs.map((source) => source.sha256);
    if (
      canonicalizeJcs(entry.sourceOutputSha256s)
        !== canonicalizeJcs(sourceHashes)
    ) {
      fail(`${label}.sourceOutputSha256s differ from exact serialized source outputs`);
    }
    const inputBindings = standaloneInputBindings(
      entry.inputBindings,
      transaction,
      sourceOutputs,
      inputRoles,
      `${label}.inputBindings`,
    );
    const localResources = localResourceMeasurements(inputBindings);
    if (
      canonicalizeJcs(localResources)
        !== canonicalizeJcs(entry.localResources)
    ) {
      fail(`${label}.localResources differ from the exact Libauth per-input metrics`);
    }
    exact(
      entry.localLibauth,
      ['evidenceSha256', 'tool'],
      `${label}.localLibauth`,
    );
    hash(
      entry.localLibauth.evidenceSha256,
      `${label}.localLibauth.evidenceSha256`,
    );
    hash(
      entry.localLibauthEvidenceSha256,
      `${label}.localLibauthEvidenceSha256`,
    );
    if (
      entry.localLibauth.evidenceSha256
        !== entry.localLibauthEvidenceSha256
    ) {
      fail(`${label}.localLibauth evidence hash bindings differ`);
    }
    standaloneLocalTool(
      entry.localLibauth.tool,
      identity,
      `${label}.localLibauth.tool`,
    );
    if (
      canonicalizeJcs(entry.hardPolicy)
        !== canonicalizeJcs(measured.hardPolicy)
      || canonicalizeJcs(entry.narrowerTelemetry)
        !== canonicalizeJcs(measured.narrowerTelemetry)
    ) {
      fail(`${label} hard policy or telemetry differs from its raw bytes`);
    }
    const subject = laneSubject({
      identity,
      inputBindings,
      kind: entry.kind,
      rawTransactionHex: entry.rawTransactionHex,
      rawTransactionSha256: entry.rawTransactionSha256,
      sourceOutputs,
      transactionId: entry.transactionId,
    });
    exact(entry.externalLanes, LANE_ROLES, `${label}.externalLanes`);
    for (const role of LANE_ROLES) {
      const lane = standaloneLane({
        authority: authorityContext.byRole.get(role),
        authorityContext,
        expectedDescriptor,
        inputBindings,
        lane: entry.externalLanes[role],
        localResources,
        role,
        sourceOutputs,
        subject,
        transaction,
      });
      if (runIds.has(lane.runId)) {
        fail('B-02 standalone external lane run IDs must be globally unique');
      }
      runIds.add(lane.runId);
      peakVmResourcePercentBasisPoints = Math.max(
        peakVmResourcePercentBasisPoints,
        lane.peakResourceBasisPoints,
      );
    }
    for (const resource of localResources) {
      peakVmResourcePercentBasisPoints = Math.max(
        peakVmResourcePercentBasisPoints,
        resource.operationCost.percentBasisPoints,
        resource.hashDigestIterations.percentBasisPoints,
        resource.signatureChecks.percentBasisPoints,
      );
    }
    maximumSerializedTransactionBytes = Math.max(
      maximumSerializedTransactionBytes,
      transaction.sizeBytes,
    );
    maximumUnlockingBytecodeBytes = Math.max(
      maximumUnlockingBytecodeBytes,
      measured.maximumUnlockingBytecodeBytes,
    );
    return Object.freeze({
      inputCount: transaction.inputs.length,
      inputs: Object.freeze(inputBindings.map((binding, index) =>
        Object.freeze({
          accepted: true,
          hashDigestIterations: Number(
            binding.metrics.hashDigestIterations,
          ),
          inputIndex: index,
          maximumHashDigestIterations: Number(
            binding.metrics.maximumHashDigestIterations,
          ),
          maximumOperationCost: Number(
            binding.metrics.maximumOperationCost,
          ),
          maximumSignatureChecks: Number(
            binding.metrics.maximumSignatureCheckCount,
          ),
          operationCost: Number(binding.metrics.operationCost),
          role: binding.role,
          signatureCheckCount: Number(
            binding.metrics.signatureCheckCount,
          ),
          sourceOutputSha256: binding.sourceOutputSha256,
          unlockBytes: transaction.inputs[index].unlockingBytecodeBytes,
          unlockingBytecodeSha256:
            binding.unlockingBytecodeSha256,
        }))),
      kind: entry.kind,
      rawTransactionSha256: measured.rawTransactionSha256,
      transactionBytes: transaction.sizeBytes,
      transactionId: transaction.txid,
    });
  });
  if (
    runIds.size !== 12
    || peakVmResourcePercentBasisPoints > 10_000
    || maximumSerializedTransactionBytes > V2_MAX_TRANSACTION_BYTES
    || maximumUnlockingBytecodeBytes
      > V2_MAX_UNLOCKING_BYTECODE_BYTES
  ) {
    fail('B-02 standalone hard transaction, unlocking, lane, or VM resource closure is incomplete');
  }
  return Object.freeze({
    schema: V2_B02_RESULT_REVALIDATION_SCHEMA,
    actions: Object.freeze(actions),
    b02Qualified: true,
    externalLaneRunCount: runIds.size,
    hardPolicyQualified: true,
    identity,
    maximumSerializedTransactionBytes,
    maximumUnlockingBytecodeBytes,
    peakVmResourcePercentBasisPoints,
    production: false,
    releaseQualified: false,
    resultSha256: sha256(canonicalBytes(value)),
    runtimeQualification: Object.freeze({
      claims: Object.freeze({ ...value.runtimeQualification.claims }),
      eligibility: value.runtimeQualification.eligibility,
      runtimeMaterialSha256:
        value.runtimeQualification.runtimeMaterialSha256,
    }),
    transactionCount: actions.length,
  });
}

export async function runV2B02FinalVm(options, dependencies = undefined) {
  if (
    dependencies !== undefined
    && (
      dependencies === null
      || typeof dependencies !== 'object'
      || Object.keys(dependencies).length !== 0
    )
  ) {
    fail('B-02 production verifier refuses injected dependencies or test doubles');
  }
  exact(options, [
    'descriptorPath',
    'expectedCommit',
    'expectedTree',
    'finalManifestPath',
    'laneEvidenceDirectory',
    'outputDirectory',
    'profileCorePath',
    'releaseRootId',
    'transactionsPath',
  ], 'B-02 options');
  let outputCreated = false;
  try {
    assertSafeRuntime();

    // Trust-order invariant: resolve immutable compiled authority before any
    // caller-selected profile, descriptor, manifest, evidence, or output path.
    const releaseRoot = resolveV2FinalReleaseRoot(options.releaseRootId);

    const git = gitState(trustedGit());
    if (
      git.commit !== options.expectedCommit
      || git.tree !== options.expectedTree
    ) {
      fail('B-02 live source differs from the exact expected commit/tree');
    }

    directFile(options.profileCorePath, 'B-02 profile core');
    directFile(options.descriptorPath, 'B-02 descriptor');
    directFile(options.finalManifestPath, 'B-02 final manifest');
    directFile(options.transactionsPath, 'B-02 transactions manifest');
    directDirectory(
      options.laneEvidenceDirectory,
      'B-02 lane evidence directory',
    );

    const profile = jcsFile(
      options.profileCorePath,
      'B-02 profile core',
    );
    const release = verifyV2FinalReleaseProfileCore(
      releaseRoot,
      profile.bytes,
      profile.value,
    );
    const descriptor = await loadV2InstanceDescriptor({
      descriptorPath: options.descriptorPath,
      profileCore: profile.value,
      trustedSigners: release.descriptorSigners,
    });
    if (descriptor.manifest.filename !== options.finalManifestPath) {
      fail('B-02 final manifest path is not the exact signed descriptor pin');
    }
    assertDescriptorTopology(descriptor, releaseRoot);
    const runtime = assertFinalRuntime(
      await deriveV2Pf10RuntimeFromValidatedDescriptor(descriptor),
    );
    const finalLocksSha256 =
      deriveV2FinalLocksSha256FromValidatedDescriptor(descriptor);
    const settlementPins =
      deriveV2SettlementPinsFromValidatedDescriptor(descriptor);
    const authorityContext =
      deriveV2Q02LaneAuthorityContextFromValidatedDescriptor(descriptor);

    const transactionsPin =
      deriveV2ManifestArtifactFromValidatedDescriptor(
        descriptor,
        V2_B02_TRANSACTIONS_ARTIFACT_ID,
      );
    if (transactionsPin.path !== options.transactionsPath) {
      fail('B-02 transactions path is not the exact signed-manifest artifact pin');
    }
    const transactionsFile = jcsFile(
      options.transactionsPath,
      'B-02 transactions manifest',
    );
    if (transactionsFile.sha256 !== transactionsPin.sha256) {
      fail('B-02 transactions manifest hash differs from its signed-manifest pin');
    }

    // Resolve the authority artifact through the same validated descriptor.
    // This explicit pin is recorded in the final result.
    const authorityPin =
      deriveV2ManifestArtifactFromValidatedDescriptor(
        descriptor,
        V2_Q02_LANE_AUTHORITY_ARTIFACT_ID,
      );
    const authorityArtifact = jcsFile(
      authorityPin.path,
      'B-02 lane authority artifact',
    );
    if (authorityArtifact.sha256 !== authorityPin.sha256) {
      fail('B-02 lane authority artifact hash differs from its signed-manifest pin');
    }
    const identity = identityRecord({
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
    }, 'B-02 final identity');
    const manifest = validateTransactionsManifest(
      transactionsFile.value,
      identity,
    );

    const referenced = new Map();
    const verifiedTransactions = manifest.transactions.map((entry) =>
      verifyTransaction({
        authorityContext,
        identity,
        laneRoot: options.laneEvidenceDirectory,
        maintainerBenchmark: manifest.maintainerBenchmark,
        manifestEntry: entry,
        referenced,
        settlementPins,
      }));
    const actualFiles = revalidateEvidenceClosure(
      options.laneEvidenceDirectory,
      referenced,
    );
    const derived = validateDerivedCycle({
      actualEvidenceFiles: actualFiles,
      identity,
      referencedEvidenceFiles: [...referenced.keys()].sort(),
      transactions: verifiedTransactions.map((entry) => entry.derived),
    });
    if (derived.runCount !== 12) {
      fail('B-02 requires twelve distinct external lane runs');
    }

    createOutput(options.outputDirectory);
    outputCreated = true;
    const result = Object.freeze({
      schema: V2_B02_RESULT_SCHEMA,
      status: 'b02-qualified-final-vm-not-production-or-release',
      b02Qualified: true,
      production: false,
      releaseQualified: false,
      ...identity,
      runtimeQualification: Object.freeze({
        claims: Object.freeze({
          ceremonyQualified: runtime.claims.ceremonyQualified,
          developmentKey: runtime.claims.developmentKey,
          finalKey: runtime.claims.finalKey,
          production: runtime.claims.production,
          releaseQualified: runtime.claims.releaseQualified,
        }),
        eligibility: runtime.eligibility,
        runtimeMaterialSha256: runtime.runtimeMaterial.materialSha256,
      }),
      authoritySetSha256: authorityContext.authoritySetSha256,
      authorityArtifactSha256: authorityPin.sha256,
      laneAuthorityArtifact: authorityArtifact.value,
      sourceVerification: git,
      transactionsManifestSha256: transactionsFile.sha256,
      maintainerBenchmark: manifest.maintainerBenchmark,
      hardPolicyCeilings: Object.freeze({
        serializedTransactionBytes: V2_MAX_TRANSACTION_BYTES,
        everyInputUnlockingBytecodeBytes:
          V2_MAX_UNLOCKING_BYTECODE_BYTES,
        everyReportedVmResourcePercent: 100,
      }),
      narrowerMargins: '90000/9500-non-blocking-risk-telemetry-only',
      transactions: Object.freeze(
        verifiedTransactions.map((entry) => entry.result),
      ),
      laneEvidenceFileCount: actualFiles.length,
      externalLaneRunCount: derived.runCount,
    });
    revalidateV2B02FinalVmResult(result);
    const artifact = writeDirect(
      options.outputDirectory,
      'b02-final-vm.json',
      result,
    );
    return Object.freeze({
      ...result,
      artifactPath: artifact.path,
      artifactSha256: artifact.sha256,
    });
  } catch (error) {
    writeFailure(options, error, { outputCreated });
    throw error;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const result = await runV2B02FinalVm(
      parseArguments(process.argv.slice(2)),
    );
    process.stdout.write(`${canonicalizeJcs(result)}\n`);
  } catch (error) {
    process.stderr.write(`B-02 final VM verification failed: ${
      error instanceof Error ? error.message : String(error)
    }\n`);
    process.exitCode = 1;
  }
}
