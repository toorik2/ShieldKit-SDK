#!/usr/bin/env node
/* Q-05 local-evidence verifier. It authenticates and replays only local tests. */
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
} from 'node:fs';
import { userInfo } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson, parseStrictJson } from '../packages/profile/load.mjs';

export const Q05_BUNDLE_SCHEMA = 'shieldkit-v2-direct/q05-commit-bound-evidence-bundle/v3';
export const Q05_EVIDENCE_SCHEMA = 'shieldkit-v2-direct/q05-commit-bound-local-evidence/v3';
export const Q05_SOURCE_BINDING_SCHEMA = 'shieldkit-v2-direct/q05-source-binding/v3';
export const Q05_JS_EVIDENCE_SCHEMA = 'shieldkit-v2-direct/q05-js-local-evidence/v3';
export const Q05_JS_REPORT_SCHEMA = 'shieldkit-v2-q05-crypto-safety-report/v3';
export const Q05_RUST_EVIDENCE_SCHEMA = 'shieldkit-v2-direct/q05-rust-notes-test/v3';
export const Q05_RESULT_SCHEMA = 'shieldkit-v2-direct/q05-commit-bound-evidence-verification-result/v3';
export const Q05_EXECUTION_ENVIRONMENT_SCHEMA = 'shieldkit-v2-direct/q05-controlled-spawn-environment/v2';
export const Q05_EXECUTION_SNAPSHOT_SCHEMA = 'shieldkit-v2-direct/q05-exact-head-execution-snapshot/v1';
export const Q05_DEPENDENCY_INVENTORY_SCHEMA = 'shieldkit-v2-direct/q05-installed-dependency-inventory/v1';
export const Q05_MINIMUM_NODE_VERSION = '22.5.0';

const HASH = /^[0-9a-f]{64}$/;
const GIT_OBJECT = /^[0-9a-f]{40}$/;
const projectRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
const repositoryRoot = resolve(projectRoot, '../..');
const projectPrefix = 'shieldkit-groth-94kb';
const rustCratePath = 'crates/shieldkit-v2-codec';
const userHome = userInfo().homedir;
const gitPath = '/usr/bin/git';
const tarPath = '/usr/bin/tar';
const secureTemporaryPrefix = '/tmp/shieldkit-q05-';
const q05RuntimeDependencyRoots = Object.freeze([
  Object.freeze({ name: '@noble/hashes', path: 'node_modules/@noble/hashes', version: '1.8.0' }),
  Object.freeze({ name: 'poseidon-lite', path: 'node_modules/poseidon-lite', version: '0.3.0' }),
]);
const rustHost = process.platform === 'linux' && process.arch === 'x64'
  ? 'x86_64-unknown-linux-gnu'
  : process.platform === 'linux' && process.arch === 'arm64'
    ? 'aarch64-unknown-linux-gnu'
    : undefined;
const rustToolchainRoot = rustHost === undefined
  ? ''
  : resolve(userHome, `.rustup/toolchains/1.97.1-${rustHost}`);
const cargoPath = resolve(rustToolchainRoot, 'bin/cargo');
const rustcPath = resolve(rustToolchainRoot, 'bin/rustc');
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const fail = (message) => { throw new Q05EvidenceVerificationError(message); };

const clearedEnvironmentPatterns = Object.freeze([
  'HOME',
  'GIT_*',
  'NODE_OPTIONS',
  'NODE_PATH',
  'LD_*',
  'DYLD_*',
  'RUSTC',
  'RUSTC_WRAPPER',
  'RUSTC_WORKSPACE_WRAPPER',
  'RUSTFLAGS',
  'CARGO_ENCODED_RUSTFLAGS',
  'CARGO_TARGET_*_RUSTFLAGS',
  'CARGO_HOME',
  'CARGO_TARGET_DIR',
  'RUSTUP_HOME',
  'npm_config_*',
  'NPM_CONFIG_*',
]);
const hostRejectedEnvironmentPatterns = Object.freeze([
  'HOME-mismatch',
  'NODE_OPTIONS',
  'NODE_PATH',
  'LD_*',
  'DYLD_*',
  'process.execArgv',
]);
const expectedPassed = Object.freeze({
  canonicalNonzeroSecretCases: 1,
  invalidSpendSecretCases: 3,
  invalidIncomingViewSecretCases: 3,
  invalidPointCases: 4,
  malformedRecordLengthCases: 4,
  invalidRecordFieldCases: 3,
  authenticatedRecordByteMutations: 128,
  wrongRecipientCases: 1,
  zeroEphemeralPointRecordCases: 1,
  reuseVisibleEqualityChecks: 3,
  serializedJsonCanaryNonEmissionChecks: 1,
});
const expectedJsTranscript = Object.freeze([
  'canonicalNonzeroSecretCases:derive-valid-address',
  'invalidSpendSecretCases:zero',
  'invalidSpendSecretCases:babyjub-subgroup-order',
  'invalidSpendSecretCases:bn254-scalar-field-modulus',
  'invalidIncomingViewSecretCases:zero',
  'invalidIncomingViewSecretCases:babyjub-subgroup-order',
  'invalidIncomingViewSecretCases:bn254-scalar-field-modulus',
  ...Array.from({ length: 4 }, (_, index) => `invalidPointCases:point-${index}`),
  'malformedRecordLengthCases:length-0',
  'malformedRecordLengthCases:length-1',
  'malformedRecordLengthCases:length-127',
  'malformedRecordLengthCases:length-129',
  'invalidRecordFieldCases:field-32',
  'invalidRecordFieldCases:field-64',
  'invalidRecordFieldCases:field-96',
  ...Array.from({ length: 128 }, (_, index) => `authenticatedRecordByteMutations:byte-${index}`),
  'wrongRecipientCases:foreign-address-output',
  'zeroEphemeralPointRecordCases:zero-ephemeral-point',
  'reuseVisibleEqualityChecks:note-commitment',
  'reuseVisibleEqualityChecks:output-leaf',
  'reuseVisibleEqualityChecks:encrypted-record',
  'serializedJsonCanaryNonEmissionChecks:report-excludes-secret-canaries',
]);
const expectedRustTests = Object.freeze([
  'authenticates_every_record_byte_and_rejects_wrong_leaf_key_and_context_replay',
  'mirrors_js_rejection_sampling_bounds_and_exhaustion',
  'pins_complete_js_address_note_record_leaf_and_nullifier_vector',
  'q05_rejects_point_field_and_foreign_output_corpus_without_secret_emission',
  'rejects_malformed_noncanonical_zero_and_non_subgroup_inputs',
]);
const expectedLimits = Object.freeze([
  'local deterministic test evidence only; not an independent audit',
  'no global spent-randomness registry exists at this address/note API boundary',
  'reuse is detectable here only when identical public outputs are compared',
  'the serialized JSON report intentionally excludes canary scalar strings, witnesses, and ciphertext bytes',
  'the serialized-JSON canary check does not establish process-memory zeroization or general stdout/stderr non-emission',
  'this does not qualify a circuit, profile, transaction, or release',
]);
const expectedBoundaries = Object.freeze([
  'local evidence only; not BCH chain execution or transaction validation',
  'not an independent cryptographic audit or audit closure',
  'not final-profile, circuit, release, or qualification evidence',
  'not authenticated external evidence or a clean-host attestation',
  'does not establish global spent-randomness or reuse prevention',
  'does not establish process-memory zeroization',
  'does not authenticate a compromised parent process',
]);

export const Q05_VALIDATED_PROPERTIES = Object.freeze([
  'canonical-nonzero-secret-address-derivation',
  'invalid-spend-secret-rejection',
  'invalid-incoming-view-secret-rejection',
  'encoded-address-invalid-point-rejection',
  'encrypted-record-length-rejection',
  'encrypted-record-noncanonical-field-rejection',
  'encrypted-record-authenticated-byte-mutation-rejection',
  'foreign-recipient-record-rejection',
  'zero-ephemeral-point-record-rejection',
  'deterministic-rng-public-output-equality-observation',
  'serialized-json-secret-canary-non-emission',
]);

export const Q05_SOURCE_DEFINITIONS = Object.freeze([
  Object.freeze({ role: 'q05-js-workspace-package', path: 'package.json' }),
  Object.freeze({ role: 'q05-js-workspace-lockfile', path: 'package-lock.json' }),
  Object.freeze({ role: 'q05-canonical-json', path: `${projectPrefix}/packages/profile/load.mjs` }),
  Object.freeze({ role: 'q05-js-corpus', path: `${projectPrefix}/packages/action/v2/notes.q05-evidence.mjs` }),
  Object.freeze({ role: 'q05-js-address', path: `${projectPrefix}/packages/action/v2/address.mjs` }),
  Object.freeze({ role: 'q05-js-notes', path: `${projectPrefix}/packages/action/v2/notes.mjs` }),
  Object.freeze({ role: 'q05-js-domains', path: `${projectPrefix}/packages/action/v2/domains.mjs` }),
  Object.freeze({ role: 'q05-rust-manifest', path: `${projectPrefix}/${rustCratePath}/Cargo.toml` }),
  Object.freeze({ role: 'q05-rust-lockfile', path: `${projectPrefix}/${rustCratePath}/Cargo.lock` }),
  Object.freeze({ role: 'q05-rust-library', path: `${projectPrefix}/${rustCratePath}/src/lib.rs` }),
  Object.freeze({ role: 'q05-rust-notes', path: `${projectPrefix}/${rustCratePath}/src/notes.rs` }),
  Object.freeze({ role: 'q05-rust-tests', path: `${projectPrefix}/${rustCratePath}/tests/notes.rs` }),
  Object.freeze({ role: 'q05-rust-toolchain', path: `${projectPrefix}/rust-toolchain.toml` }),
  Object.freeze({ role: 'q05-generator', path: `${projectPrefix}/scripts/v2-q05-evidence.mjs` }),
  Object.freeze({ role: 'q05-verifier', path: `${projectPrefix}/scripts/v2-q05-evidence-verify.mjs` }),
]);

export class Q05EvidenceVerificationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'Q05EvidenceVerificationError';
  }
}

const exactKeys = (value, keys, label) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown fields`);
  return value;
};
const equalArray = (actual, expected, label) => {
  if (!Array.isArray(actual) || actual.length !== expected.length || actual.some((value, index) => value !== expected[index])) fail(`${label} differs from its fixed Q-05 definition`);
};
const sha = (value, label) => {
  if (typeof value !== 'string' || !HASH.test(value)) fail(`${label} must be lowercase SHA-256`);
  return value;
};
const gitObject = (value, label) => {
  if (typeof value !== 'string' || !GIT_OBJECT.test(value)) fail(`${label} must be a lowercase Git object ID`);
  return value;
};
const containedPath = (root, value, label) => {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\\') || value.split('/').some((part) => !part || part === '.' || part === '..')) fail(`${label} is not a contained relative path`);
  const absolute = resolve(root, value);
  if (relative(root, absolute).startsWith(`..${sep}`) || relative(root, absolute) === '') fail(`${label} escapes its root`);
  return absolute;
};

function parseCanonicalJson(bytes, label) {
  let value;
  try {
    value = parseStrictJson(bytes);
  } catch (error) {
    fail(`${label} is not strict JSON: ${error.message}`);
  }
  if (!Buffer.from(canonicalJson(value)).equals(Buffer.from(bytes))) fail(`${label} is not canonical JSON`);
  return value;
}

export function assertQ05SafeHostEnvironment(environment = process.env, execArgv = process.execArgv) {
  const contaminated = [];
  if (environment.HOME !== userHome) contaminated.push('HOME');
  for (const [key, value] of Object.entries(environment)) {
    if (typeof value !== 'string' || value.length === 0) continue;
    if (key === 'NODE_OPTIONS' || key === 'NODE_PATH' || key.startsWith('LD_') || key.startsWith('DYLD_')) contaminated.push(key);
  }
  if (!Array.isArray(execArgv) || execArgv.length !== 0) contaminated.push('process.execArgv');
  if (contaminated.length > 0) fail(`host process environment is contaminated: ${[...new Set(contaminated)].join(', ')}`);
}

export function q05ControlledEnvironment(purpose, _untrustedEnvironment = process.env) {
  const common = {
    LANG: 'C',
    LC_ALL: 'C',
    PATH: '/usr/bin:/bin',
    TZ: 'UTC',
  };
  let variables;
  if (purpose === 'git') {
    variables = {
      ...common,
      GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_OPTIONAL_LOCKS: '0',
      GIT_PAGER: 'cat',
      GIT_TERMINAL_PROMPT: '0',
      HOME: '/nonexistent/shieldkit-q05-git',
    };
  } else if (purpose === 'archive') {
    variables = { ...common, HOME: userHome };
  } else if (purpose === 'node') {
    variables = { ...common, HOME: userHome };
  } else if (purpose === 'npm') {
    variables = {
      ...common,
      HOME: userHome,
      NPM_CONFIG_AUDIT: 'false',
      NPM_CONFIG_FUND: 'false',
      NPM_CONFIG_GLOBALCONFIG: '/nonexistent/shieldkit-q05-global-npmrc',
      NPM_CONFIG_IGNORE_SCRIPTS: 'true',
      NPM_CONFIG_USERCONFIG: '/dev/null',
    };
  } else if (purpose === 'cargo') {
    variables = {
      ...common,
      CARGO_HOME: resolve(userHome, '.cargo'),
      CARGO_INCREMENTAL: '0',
      CARGO_NET_OFFLINE: 'true',
      CARGO_TERM_COLOR: 'never',
      HOME: userHome,
      RUSTC: rustcPath,
      RUSTUP_HOME: resolve(userHome, '.rustup'),
    };
  } else if (purpose === 'rustc') {
    variables = { ...common, HOME: userHome };
  } else {
    fail(`unknown Q-05 subprocess purpose: ${purpose}`);
  }
  return Object.freeze({
    schema: Q05_EXECUTION_ENVIRONMENT_SCHEMA,
    purpose,
    inherited: false,
    clearedPatterns: clearedEnvironmentPatterns,
    hostRejectedPatterns: hostRejectedEnvironmentPatterns,
    variables: Object.freeze(variables),
  });
}

function regularFileIdentity(requestedPath, label, executable = false) {
  if (typeof requestedPath !== 'string' || !requestedPath.startsWith('/')) fail(`${label} executable path must be absolute`);
  let resolvedPath;
  let stat;
  try {
    resolvedPath = realpathSync(requestedPath);
    stat = lstatSync(resolvedPath);
  } catch {
    fail(`${label} executable is unavailable`);
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (executable && (stat.mode & 0o111) === 0)) fail(`${label} must resolve to a direct${executable ? ' executable' : ''} regular file`);
  return Object.freeze({
    requestedPath,
    resolvedPath,
    bytes: stat.size,
    mode: (stat.mode & 0o777).toString(8).padStart(4, '0'),
    sha256: digest(readFileSync(resolvedPath)),
  });
}

function executableIdentity(requestedPath, label) {
  return regularFileIdentity(requestedPath, `${label} executable`, true);
}

function controlledSpawn(identity, args, cwd, boundary, label, environmentOverrides = {}) {
  assertQ05SafeHostEnvironment();
  const environment = Object.freeze({ ...boundary.variables, ...environmentOverrides });
  const result = spawnSync(identity.resolvedPath, args, {
    cwd,
    encoding: 'utf8',
    env: environment,
    maxBuffer: 128 * 1024 * 1024,
  });
  if (result.error || result.status !== 0 || result.signal) fail(`${label} failed`);
  return result;
}

const gitCommandPrefix = Object.freeze([
  '--no-replace-objects',
  '-c', 'core.fsmonitor=false',
  '-c', 'core.hooksPath=/dev/null',
  '-c', 'core.pager=cat',
  '-c', 'pager.status=false',
  '-C', repositoryRoot,
]);

export function q05Git(args, label) {
  const executable = executableIdentity(gitPath, 'Git');
  const environment = q05ControlledEnvironment('git');
  const result = controlledSpawn(executable, [...gitCommandPrefix, ...args], repositoryRoot, environment, label);
  if (result.stderr !== '') fail(`${label} emitted unexpected Git stderr`);
  return result.stdout;
}

export function validateQ05TrackedIndexFlags(output) {
  if (typeof output !== 'string' || !output.endsWith('\0')) fail('Git tracked-index flag output is malformed');
  for (const record of output.slice(0, -1).split('\0')) {
    if (!/^H .+/u.test(record)) fail(`tracked path has a non-normal Git index flag: ${record.slice(0, 1) || '<missing>'}`);
  }
  return true;
}

export function q05GitExecutionBoundary() {
  const executable = executableIdentity(gitPath, 'Git');
  const environment = q05ControlledEnvironment('git');
  const result = controlledSpawn(executable, ['--version'], repositoryRoot, environment, 'Git version probe');
  if (result.stderr !== '' || !/^git version [0-9]+\.[0-9]+\.[0-9]+\n$/.test(result.stdout)) fail('Git version probe emitted unexpected output');
  return Object.freeze({
    executable,
    environment,
    commandPrefix: gitCommandPrefix,
    versionStdout: result.stdout,
    versionStdoutSha256: digest(Buffer.from(result.stdout)),
    versionStderr: result.stderr,
    versionStderrSha256: digest(Buffer.from(result.stderr)),
  });
}

function assertCleanCommittedCheckout() {
  if (resolve(q05Git(['rev-parse', '--show-toplevel'], 'git root').trim()) !== repositoryRoot) fail('verifier workspace root is not the checkout root');
  if (q05Git(['status', '--porcelain=v1', '--untracked-files=all'], 'git status') !== '') fail('source checkout is dirty; commit-bound evidence is not valid');
  validateQ05TrackedIndexFlags(q05Git(['ls-files', '-v', '-z'], 'git tracked-index flags'));
  return Object.freeze({
    head: gitObject(q05Git(['rev-parse', 'HEAD'], 'git HEAD').trim(), 'HEAD'),
    tree: gitObject(q05Git(['rev-parse', 'HEAD^{tree}'], 'git tree').trim(), 'HEAD tree'),
  });
}

function gitBlobFor(path) {
  const record = q05Git(['ls-tree', 'HEAD', '--', path], `git tree entry for ${path}`).trim();
  const match = record.match(/^100644 blob ([0-9a-f]{40})\t(.+)$/);
  if (!match || match[2] !== path) fail(`committed source path ${path} is not a regular blob`);
  return match[1];
}

function secureTemporaryDirectory(label) {
  assertQ05SafeHostEnvironment();
  const path = mkdtempSync(secureTemporaryPrefix);
  chmodSync(path, 0o700);
  const stat = lstatSync(path);
  if (
    !stat.isDirectory()
    || stat.isSymbolicLink()
    || realpathSync(path) !== path
    || (stat.mode & 0o777) !== 0o700
    || (typeof process.getuid === 'function' && stat.uid !== process.getuid())
  ) fail(`${label} temporary directory is not a direct user-owned mode-0700 directory`);
  return path;
}

function secureEmptyDirectory(path, label) {
  mkdirSync(path, { mode: 0o700 });
  chmodSync(path, 0o700);
  const stat = lstatSync(path);
  if (
    !stat.isDirectory()
    || stat.isSymbolicLink()
    || realpathSync(path) !== path
    || (stat.mode & 0o777) !== 0o700
    || readdirSync(path).length !== 0
    || (typeof process.getuid === 'function' && stat.uid !== process.getuid())
  ) fail(`${label} must be a fresh direct user-owned mode-0700 directory`);
  return path;
}

function makeTreeRemovable(path) {
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    return;
  }
  if (stat.isDirectory() && !stat.isSymbolicLink()) {
    chmodSync(path, 0o700);
    for (const entry of readdirSync(path)) makeTreeRemovable(join(path, entry));
  } else if (!stat.isSymbolicLink()) {
    chmodSync(path, 0o600);
  }
}

export function destroyQ05ExecutionSnapshot(snapshot) {
  const container = snapshot?.container;
  if (
    typeof container !== 'string'
    || !container.startsWith(secureTemporaryPrefix)
    || dirname(container) !== dirname(secureTemporaryPrefix)
  ) fail('refusing to remove an invalid Q-05 snapshot path');
  const stat = lstatSync(container);
  if (
    !stat.isDirectory()
    || stat.isSymbolicLink()
    || realpathSync(container) !== container
    || (typeof process.getuid === 'function' && stat.uid !== process.getuid())
  ) fail('refusing to remove an insecure Q-05 snapshot');
  makeTreeRemovable(container);
  rmSync(container, { recursive: true, force: false });
}

function gitBlobObjectId(bytes) {
  return createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
}

function committedTreeEntries() {
  const output = q05Git(['ls-tree', '-r', '-z', '--full-tree', 'HEAD'], 'git exact HEAD tree');
  if (!output.endsWith('\0')) fail('Git exact HEAD tree output is malformed');
  return Object.freeze(output.slice(0, -1).split('\0').map((record, index) => {
    const match = record.match(/^(100644|100755) blob ([0-9a-f]{40})\t(.+)$/u);
    if (!match) fail(`Git exact HEAD tree entry ${index} is not a supported regular blob`);
    containedPath(repositoryRoot, match[3], `Git exact HEAD path ${match[3]}`);
    return Object.freeze({ mode: match[1], gitBlob: match[2], path: match[3] });
  }));
}

function validateExactHeadSnapshot(snapshotRepositoryRoot, expectedTree) {
  const inventory = [];
  for (const entry of expectedTree) {
    const absolute = containedPath(snapshotRepositoryRoot, entry.path, `snapshot source ${entry.path}`);
    let stat;
    try {
      stat = lstatSync(absolute);
    } catch {
      fail(`snapshot source ${entry.path} is missing`);
    }
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || realpathSync(absolute) !== absolute) fail(`snapshot source ${entry.path} is not a direct single-link regular file`);
    const bytes = readFileSync(absolute);
    if (gitBlobObjectId(bytes) !== entry.gitBlob) fail(`snapshot source ${entry.path} differs from its exact HEAD blob`);
    if (entry.mode === '100755' && (stat.mode & 0o111) === 0) fail(`snapshot executable ${entry.path} lost its executable mode`);
    inventory.push(Object.freeze({
      path: entry.path,
      mode: entry.mode,
      gitBlob: entry.gitBlob,
      bytes: bytes.length,
      sha256: digest(bytes),
    }));
  }
  return Object.freeze({
    fileCount: inventory.length,
    inventorySha256: digest(Buffer.from(canonicalJson(inventory))),
  });
}

function inventoryRegularTree(root, relativeRoot) {
  const absoluteRoot = containedPath(root, relativeRoot, `dependency root ${relativeRoot}`);
  const entries = [];
  const visit = (absolute, relativePath) => {
    const stat = lstatSync(absolute);
    if (stat.isSymbolicLink()) fail(`installed dependency ${relativePath} must not contain symlinks`);
    if (stat.isDirectory()) {
      for (const name of readdirSync(absolute).sort()) visit(join(absolute, name), `${relativePath}/${name}`);
      return;
    }
    if (!stat.isFile() || stat.nlink !== 1 || realpathSync(absolute) !== absolute) fail(`installed dependency ${relativePath} is not a direct single-link regular file`);
    const bytes = readFileSync(absolute);
    entries.push(Object.freeze({
      path: relativePath,
      mode: (stat.mode & 0o777).toString(8).padStart(4, '0'),
      bytes: bytes.length,
      sha256: digest(bytes),
    }));
  };
  visit(absoluteRoot, relativeRoot);
  return entries;
}

function makeDependencyTreeImmutable(root, relativeRoot) {
  const absoluteRoot = containedPath(root, relativeRoot, `dependency root ${relativeRoot}`);
  const visit = (absolute) => {
    const stat = lstatSync(absolute);
    if (stat.isSymbolicLink()) fail('installed Q-05 runtime dependency must not contain symlinks');
    if (stat.isDirectory()) {
      for (const name of readdirSync(absolute)) visit(join(absolute, name));
      chmodSync(absolute, 0o500);
    } else if (stat.isFile() && stat.nlink === 1) {
      chmodSync(absolute, 0o400);
    } else {
      fail('installed Q-05 runtime dependency contains an unsupported entry');
    }
  };
  visit(absoluteRoot);
}

function installedDependencyInventory(snapshotRepositoryRoot) {
  const packages = [];
  for (const definition of q05RuntimeDependencyRoots) {
    makeDependencyTreeImmutable(snapshotRepositoryRoot, definition.path);
    const packageJsonPath = containedPath(snapshotRepositoryRoot, `${definition.path}/package.json`, `${definition.name} package.json`);
    const packageJson = parseCanonicalJson(Buffer.from(canonicalJson(parseStrictJson(readFileSync(packageJsonPath)))), `${definition.name} package metadata`);
    if (packageJson.name !== definition.name || packageJson.version !== definition.version) fail(`installed dependency ${definition.name} identity differs from the Q-05 lock`);
    const files = inventoryRegularTree(snapshotRepositoryRoot, definition.path);
    packages.push(Object.freeze({
      name: definition.name,
      version: definition.version,
      root: definition.path,
      fileCount: files.length,
      files: Object.freeze(files),
      filesSha256: digest(Buffer.from(canonicalJson(files))),
    }));
  }
  const inventory = Object.freeze({
    schema: Q05_DEPENDENCY_INVENTORY_SCHEMA,
    packages: Object.freeze(packages),
  });
  return Object.freeze({ ...inventory, sha256: digest(Buffer.from(canonicalJson(inventory))) });
}

function npmToolchain() {
  const runtime = currentNodeRuntime();
  const npmCliPath = resolve(dirname(runtime.executable.resolvedPath), '../lib/node_modules/npm/bin/npm-cli.js');
  const npmPackagePath = resolve(dirname(runtime.executable.resolvedPath), '../lib/node_modules/npm/package.json');
  const npmCli = regularFileIdentity(npmCliPath, 'npm CLI');
  const npmPackage = regularFileIdentity(npmPackagePath, 'npm package metadata');
  const environment = q05ControlledEnvironment('npm');
  const version = controlledSpawn(runtime.executable, [npmCli.resolvedPath, '--version'], repositoryRoot, environment, 'npm version probe');
  if (version.stderr !== '' || !/^[0-9]+\.[0-9]+\.[0-9]+\n$/u.test(version.stdout)) fail('npm version probe emitted unexpected output');
  return Object.freeze({
    runtime,
    npmCli,
    npmPackage,
    versionStdout: version.stdout,
    versionStdoutSha256: digest(Buffer.from(version.stdout)),
    versionStderr: version.stderr,
    versionStderrSha256: digest(Buffer.from(version.stderr)),
  });
}

function normalizeSnapshotRecord(record) {
  exactKeys(record, [
    'archiveTool', 'dependencyInventory', 'git', 'npm', 'npmInstall', 'permissions',
    'schema', 'trackedFiles',
  ], 'Q-05 execution snapshot');
  if (record.schema !== Q05_EXECUTION_SNAPSHOT_SCHEMA) fail('Q-05 execution snapshot schema differs');
  return record;
}

export function createQ05ExecutionSnapshot(checkout = assertCleanCommittedCheckout()) {
  const container = secureTemporaryDirectory('Q-05 execution snapshot');
  try {
    const snapshotRepositoryRoot = secureEmptyDirectory(join(container, 'source'), 'Q-05 snapshot source root');
    const archivePath = join(container, 'source.tar');
    const npmCache = secureEmptyDirectory(join(container, 'npm-cache'), 'Q-05 npm cache');
    const archiveTool = executableIdentity(tarPath, 'tar');
    const archiveEnvironment = q05ControlledEnvironment('archive');
    q05Git(['archive', '--format=tar', `--output=${archivePath}`, 'HEAD'], 'git exact HEAD archive');
    chmodSync(archivePath, 0o600);
    const archiveStat = lstatSync(archivePath);
    if (!archiveStat.isFile() || archiveStat.isSymbolicLink() || archiveStat.nlink !== 1 || (archiveStat.mode & 0o777) !== 0o600) fail('Git exact HEAD archive is not a secure regular file');
    const extraction = controlledSpawn(
      archiveTool,
      ['--extract', '--file', archivePath, '--directory', snapshotRepositoryRoot, '--no-same-owner', '--no-same-permissions'],
      container,
      archiveEnvironment,
      'exact HEAD archive extraction',
    );
    if (extraction.stdout !== '' || extraction.stderr !== '') fail('exact HEAD archive extraction emitted unexpected output');
    rmSync(archivePath, { force: false });

    const expectedTree = committedTreeEntries();
    const trackedFiles = validateExactHeadSnapshot(snapshotRepositoryRoot, expectedTree);
    const npm = npmToolchain();
    const npmEnvironment = q05ControlledEnvironment('npm');
    const npmInstallCommand = Object.freeze([
      npm.npmCli.resolvedPath,
      'ci',
      '--ignore-scripts',
      '--no-audit',
      '--no-fund',
      '--loglevel=silent',
    ]);
    const install = controlledSpawn(
      npm.runtime.executable,
      npmInstallCommand,
      snapshotRepositoryRoot,
      npmEnvironment,
      'Q-05 immutable npm ci',
      { NPM_CONFIG_CACHE: npmCache },
    );
    if (install.stdout !== '' || install.stderr !== '') fail('Q-05 immutable npm ci emitted unexpected output');
    const trackedAfterInstall = validateExactHeadSnapshot(snapshotRepositoryRoot, expectedTree);
    if (canonicalJson(trackedAfterInstall) !== canonicalJson(trackedFiles)) fail('npm ci changed exact HEAD tracked bytes');
    const dependencyInventory = installedDependencyInventory(snapshotRepositoryRoot);
    const record = Object.freeze({
      schema: Q05_EXECUTION_SNAPSHOT_SCHEMA,
      git: Object.freeze({ head: checkout.head, tree: checkout.tree, replaceObjectsDisabled: true }),
      permissions: Object.freeze({ containerMode: '0700', sourceRootMode: '0700', npmCacheMode: '0700' }),
      archiveTool,
      trackedFiles,
      npm,
      npmInstall: Object.freeze({
        command: Object.freeze(['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund', '--loglevel=silent']),
        environment: npmEnvironment,
        cache: 'fresh-mode-0700',
        stdout: install.stdout,
        stdoutSha256: digest(Buffer.from(install.stdout)),
        stderr: install.stderr,
        stderrSha256: digest(Buffer.from(install.stderr)),
      }),
      dependencyInventory,
    });
    normalizeSnapshotRecord(record);
    return Object.freeze({
      container,
      repositoryRoot: snapshotRepositoryRoot,
      projectRoot: resolve(snapshotRepositoryRoot, projectPrefix),
      cargoTargetRoot: join(container, 'cargo-target'),
      expectedTree,
      record,
    });
  } catch (error) {
    const partial = Object.freeze({ container });
    try {
      destroyQ05ExecutionSnapshot(partial);
    } catch {
      // Preserve the original snapshot failure.
    }
    throw error;
  }
}

export function createQ05ExecutionSnapshotForTestOnly() {
  const checkout = Object.freeze({
    head: gitObject(q05Git(['rev-parse', 'HEAD'], 'test-only Git HEAD').trim(), 'test-only HEAD'),
    tree: gitObject(q05Git(['rev-parse', 'HEAD^{tree}'], 'test-only Git tree').trim(), 'test-only HEAD tree'),
  });
  return createQ05ExecutionSnapshot(checkout);
}

export function validateQ05ExecutionSnapshot(snapshot) {
  normalizeSnapshotRecord(snapshot.record);
  const tracked = validateExactHeadSnapshot(snapshot.repositoryRoot, snapshot.expectedTree);
  if (canonicalJson(tracked) !== canonicalJson(snapshot.record.trackedFiles)) fail('Q-05 exact HEAD snapshot tracked inventory changed');
  const dependencies = installedDependencyInventory(snapshot.repositoryRoot);
  if (canonicalJson(dependencies) !== canonicalJson(snapshot.record.dependencyInventory)) fail('Q-05 installed dependency inventory changed');
  return snapshot.record;
}

export function isQ05SupportedNodeVersion(version) {
  if (typeof version !== 'string') return false;
  const match = /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u.exec(version);
  if (match === null) return false;
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  if (![major, minor, patch].every(Number.isSafeInteger)) return false;
  return major > 22 || (major === 22 && minor >= 5);
}

function currentNodeRuntime() {
  const executable = executableIdentity(realpathSync(process.execPath), 'Node');
  if (!isQ05SupportedNodeVersion(process.version)) {
    fail(`Q-05 evidence requires Node >=${Q05_MINIMUM_NODE_VERSION}`);
  }
  return Object.freeze({
    executable,
    version: process.version,
    platform: process.platform,
    arch: process.arch,
  });
}

function validateNodeRuntime(value) {
  exactKeys(value, ['arch', 'executable', 'platform', 'version'], 'Node runtime');
  const current = currentNodeRuntime();
  if (canonicalJson(value) !== canonicalJson(current)) fail('Node runtime differs from the verifier runtime');
  return current;
}

function cargoConfigBoundary(sourceRoot) {
  const crate = containedPath(sourceRoot, rustCratePath, 'Rust crate path');
  const searched = new Set([
    resolve(userHome, '.cargo/config'),
    resolve(userHome, '.cargo/config.toml'),
  ]);
  for (let cursor = crate; ; cursor = dirname(cursor)) {
    searched.add(resolve(cursor, '.cargo/config'));
    searched.add(resolve(cursor, '.cargo/config.toml'));
    if (cursor === dirname(cursor)) break;
  }
  const searchedPaths = [...searched].sort();
  const present = searchedPaths.filter((path) => existsSync(path));
  if (present.length > 0) fail(`Cargo configuration files are outside the Q-05 controlled boundary: ${present.join(', ')}`);
  return Object.freeze({
    searchPolicy: 'canonical-cargo-home-and-source-ancestor-chain',
    searchedPathCount: searchedPaths.length,
    requiredAbsent: true,
    commandPolicy: Object.freeze({
      locked: true,
      offline: true,
      testTarget: 'notes',
      testThreads: 1,
    }),
  });
}

function pinnedRustToolchain(sourceRoot) {
  if (rustHost === undefined) fail('Q-05 Rust evidence does not support this platform/architecture');
  const crate = containedPath(sourceRoot, rustCratePath, 'Rust crate path');
  const cargo = executableIdentity(cargoPath, 'Cargo 1.97.1');
  const rustc = executableIdentity(rustcPath, 'rustc 1.97.1');
  const cargoEnvironment = q05ControlledEnvironment('cargo');
  const rustcEnvironment = q05ControlledEnvironment('rustc');
  const cargoResult = controlledSpawn(cargo, ['--version'], crate, cargoEnvironment, 'Cargo version probe');
  const rustcResult = controlledSpawn(rustc, ['--version', '--verbose'], crate, rustcEnvironment, 'rustc version probe');
  if (cargoResult.stderr !== '' || !/^cargo 1\.97\.1 \([0-9a-f]+ [0-9]{4}-[0-9]{2}-[0-9]{2}\)\n$/.test(cargoResult.stdout)) fail('Cargo version probe emitted unexpected output');
  if (rustcResult.stderr !== '' || !/^rustc 1\.97\.1\b/.test(rustcResult.stdout) || !/^release: 1\.97\.1$/m.test(rustcResult.stdout)) fail('rustc 1.97.1 version probe emitted unexpected output');
  return Object.freeze({
    cargo,
    rustc,
    cargoProbeEnvironment: cargoEnvironment,
    rustcProbeEnvironment: rustcEnvironment,
    cargoVersionStdout: cargoResult.stdout,
    cargoVersionStdoutSha256: digest(Buffer.from(cargoResult.stdout)),
    cargoVersionStderr: cargoResult.stderr,
    cargoVersionStderrSha256: digest(Buffer.from(cargoResult.stderr)),
    rustcVersionStdout: rustcResult.stdout,
    rustcVersionStdoutSha256: digest(Buffer.from(rustcResult.stdout)),
    rustcVersionStderr: rustcResult.stderr,
    rustcVersionStderrSha256: digest(Buffer.from(rustcResult.stderr)),
  });
}

function strictRustStdout(stdout) {
  if (typeof stdout !== 'string') fail('Rust stdout must be a string');
  const match = stdout.match(/^\nrunning 5 tests\n((?:test [A-Za-z0-9_]+ \.\.\. ok\n){5})\ntest result: ok\. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in ([0-9]+(?:\.[0-9]+)?s)\n\n$/);
  if (!match) fail('Rust stdout contains unexpected, missing, or malformed output');
  const names = match[1].trimEnd().split('\n').map((line) => line.slice(5, -7));
  equalArray(names, expectedRustTests, 'Rust test names');
  return stdout.replace(`finished in ${match[2]}`, 'finished in <duration>');
}

function strictRustStderr(stderr) {
  if (typeof stderr !== 'string') fail('Rust stderr must be a string');
  if (stderr !== '') fail('Rust stderr contains unexpected output');
  return stderr;
}

function q05SnapshotRootFromCargoTarget(cargoTargetRoot) {
  if (typeof cargoTargetRoot !== 'string' || resolve(cargoTargetRoot) !== cargoTargetRoot) fail('Cargo target root is not an absolute normalized path');
  const snapshotRoot = dirname(cargoTargetRoot);
  if (
    cargoTargetRoot !== join(snapshotRoot, 'cargo-target')
    || !/^\/tmp\/shieldkit-q05-[A-Za-z0-9]+$/u.test(snapshotRoot)
  ) fail('Cargo target root is not inside a direct Q-05 private snapshot container');
  return snapshotRoot;
}

function normalizeCargoJsonValue(value, snapshotRoot) {
  if (typeof value === 'string') {
    // Cargo embeds paths both as standalone JSON fields and inside values such
    // as path+file:// package IDs. A replay cannot use its new snapshot root
    // to normalize a recorded old one, so normalize only the bounded private
    // container which owns both source and cargo-target paths.
    for (const match of value.matchAll(/\/tmp\/shieldkit-q05-[A-Za-z0-9]+(?=\/|$)/gu)) {
      if (match[0] !== snapshotRoot) fail('Cargo preparation references a foreign Q-05 snapshot container');
    }
    return value.replaceAll(snapshotRoot, '<q05-snapshot>');
  }
  if (Array.isArray(value)) return value.map((entry) => normalizeCargoJsonValue(entry, snapshotRoot));
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, normalizeCargoJsonValue(entry, snapshotRoot)]));
  }
  return value;
}

function parseCargoPreparation(stdout, cargoTargetRoot) {
  const snapshotRoot = q05SnapshotRootFromCargoTarget(cargoTargetRoot);
  if (typeof stdout !== 'string' || !stdout.endsWith('\n')) fail('Cargo JSON preparation stdout is malformed');
  const messages = stdout.slice(0, -1).split('\n').map((line, index) => {
    try {
      return JSON.parse(line);
    } catch {
      fail(`Cargo JSON preparation line ${index} is not JSON`);
    }
  });
  if (
    messages.length === 0
    || messages.filter((message) => message?.reason === 'build-finished').length !== 1
    || messages.at(-1)?.reason !== 'build-finished'
    || messages.at(-1)?.success !== true
  ) fail('Cargo JSON preparation did not finish successfully');
  for (const message of messages) {
    if (!['compiler-artifact', 'build-script-executed', 'build-finished'].includes(message?.reason)) fail(`Cargo JSON preparation emitted unexpected message: ${message?.reason ?? '<missing>'}`);
  }
  const selected = messages.filter((message) => (
    message.reason === 'compiler-artifact'
    && message.target?.name === 'notes'
    && Array.isArray(message.target?.kind)
    && message.target.kind.length === 1
    && message.target.kind[0] === 'test'
    && message.profile?.test === true
    && typeof message.executable === 'string'
  ));
  if (selected.length !== 1) fail('Cargo JSON preparation did not select exactly one notes test executable');
  if (selected[0].manifest_path !== join(snapshotRoot, 'source', projectPrefix, rustCratePath, 'Cargo.toml')) fail('Cargo-selected notes test manifest path is not the exact snapshot crate manifest');
  const selectedPath = resolve(selected[0].executable);
  if (relative(cargoTargetRoot, selectedPath).startsWith(`..${sep}`) || relative(cargoTargetRoot, selectedPath) === '') fail('Cargo-selected notes test executable escapes the fresh target');
  const normalizedLines = messages
    .slice(0, -1)
    .map((message) => canonicalJson(normalizeCargoJsonValue(message, snapshotRoot)))
    .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
  normalizedLines.push(canonicalJson(normalizeCargoJsonValue(messages.at(-1), snapshotRoot)));
  const normalizedStdout = `${normalizedLines.join('\n')}\n`;
  return Object.freeze({ selectedPath, normalizedStdout });
}

function runQ05JsEvidenceAt(sourceRoot) {
  const runtime = currentNodeRuntime();
  const environment = q05ControlledEnvironment('node');
  const args = Object.freeze(['packages/action/v2/notes.q05-evidence.mjs']);
  const result = controlledSpawn(runtime.executable, args, sourceRoot, environment, 'Q-05 JS corpus');
  if (result.stderr !== '') fail('Q-05 JS corpus emitted unexpected stderr');
  if (!result.stdout.endsWith('\n') || result.stdout.slice(0, -1).includes('\n')) fail('Q-05 JS corpus must emit exactly one JSON line');
  let report;
  try {
    report = parseStrictJson(Buffer.from(result.stdout.slice(0, -1)));
  } catch (error) {
    fail(`Q-05 JS corpus output is not strict JSON: ${error.message}`);
  }
  if (`${canonicalJson(report)}\n` !== result.stdout) fail('Q-05 JS corpus stdout is not canonical JSON');
  validateQ05JsReport(report);
  const value = Object.freeze({
    schema: Q05_JS_EVIDENCE_SCHEMA,
    report,
    stdout: result.stdout,
    stdoutSha256: digest(Buffer.from(result.stdout)),
    stderr: result.stderr,
    stderrSha256: digest(Buffer.from(result.stderr)),
    execution: Object.freeze({
      runtime,
      environment,
      cwd: projectPrefix,
      args,
    }),
  });
  validateQ05JsEvidence(value);
  return value;
}

export function runQ05JsEvidenceForTestOnly(sourceRoot = projectRoot) {
  return runQ05JsEvidenceAt(sourceRoot);
}

export function runQ05JsEvidenceFromSnapshot(snapshot) {
  validateQ05ExecutionSnapshot(snapshot);
  const value = runQ05JsEvidenceAt(snapshot.projectRoot);
  validateQ05ExecutionSnapshot(snapshot);
  return value;
}

function runQ05RustEvidenceAt(sourceRoot, cargoTargetRoot) {
  const toolchain = pinnedRustToolchain(sourceRoot);
  const environment = q05ControlledEnvironment('cargo');
  const configBoundary = cargoConfigBoundary(sourceRoot);
  const crate = containedPath(sourceRoot, rustCratePath, 'Rust crate path');
  secureEmptyDirectory(cargoTargetRoot, 'Q-05 Cargo target');
  const preparationCommand = Object.freeze([
    'test', '--quiet', '--locked', '--offline', '--test', 'notes', '--no-run',
    '--message-format=json-render-diagnostics',
  ]);
  const preparation = controlledSpawn(
    toolchain.cargo,
    preparationCommand,
    crate,
    environment,
    'Q-05 Rust preparation',
    { CARGO_TARGET_DIR: cargoTargetRoot },
  );
  if (preparation.stderr !== '') fail('Q-05 Rust preparation emitted unexpected stderr');
  const prepared = parseCargoPreparation(preparation.stdout, cargoTargetRoot);
  // Cargo's output mode otherwise depends on the invoking host's umask
  // (typically 0755 under 0022, but 0700 under the restrictive 0077 used by
  // the evidence runners). Normalize the private, freshly built executable so
  // its recorded metadata is deterministic and never group/world accessible.
  const preparedIdentity = executableIdentity(
    prepared.selectedPath,
    'Cargo-selected Rust notes test',
  );
  chmodSync(preparedIdentity.resolvedPath, 0o700);
  const selectedIdentity = executableIdentity(
    preparedIdentity.resolvedPath,
    'normalized Cargo-selected Rust notes test',
  );
  const selectedRelativePath = relative(cargoTargetRoot, selectedIdentity.resolvedPath).split(sep).join('/');
  const selectedExecutable = Object.freeze({
    targetRelativePath: selectedRelativePath,
    bytes: selectedIdentity.bytes,
    mode: selectedIdentity.mode,
    sha256: selectedIdentity.sha256,
  });
  const command = Object.freeze(['<cargo-json-selected-notes-test-executable>', '--test-threads=1']);
  const testEnvironment = q05ControlledEnvironment('rustc');
  const result = controlledSpawn(selectedIdentity, ['--test-threads=1'], crate, testEnvironment, 'Q-05 Rust notes corpus');
  const normalizedStdout = strictRustStdout(result.stdout);
  const normalizedStderr = strictRustStderr(result.stderr);
  const value = Object.freeze({
    schema: Q05_RUST_EVIDENCE_SCHEMA,
    cratePath: rustCratePath,
    command,
    commandResult: Object.freeze({ status: 'ok', tests: 5, passed: 5, failed: 0, ignored: 0, filteredOut: 0 }),
    testNames: expectedRustTests,
    stdout: result.stdout,
    stdoutSha256: digest(Buffer.from(result.stdout)),
    stderr: result.stderr,
    stderrSha256: digest(Buffer.from(result.stderr)),
    normalizedStdout,
    normalizedStdoutSha256: digest(Buffer.from(normalizedStdout)),
    normalizedStderr,
    normalizedStderrSha256: digest(Buffer.from(normalizedStderr)),
    toolchain,
    selectedExecutable,
    execution: Object.freeze({
      environment,
      configBoundary,
      preparationCommand,
      preparationStdout: preparation.stdout,
      preparationStdoutSha256: digest(Buffer.from(preparation.stdout)),
      normalizedPreparationStdout: prepared.normalizedStdout,
      normalizedPreparationStdoutSha256: digest(Buffer.from(prepared.normalizedStdout)),
      preparationStderr: preparation.stderr,
      preparationStderrSha256: digest(Buffer.from(preparation.stderr)),
      cargoTarget: Object.freeze({
        kind: 'fresh-temporary-mode-0700',
        initialEntries: 0,
        recordedPath: '<fresh-cargo-target>',
      }),
      testEnvironment,
      cwd: rustCratePath,
    }),
  });
  validateQ05RustEvidence(value, sourceRoot);
  return value;
}

export function runQ05RustEvidenceForTestOnly(sourceRoot = projectRoot) {
  if (sourceRoot !== projectRoot) fail('test-only Q-05 Rust execution requires the canonical project root');
  const snapshot = createQ05ExecutionSnapshotForTestOnly();
  try {
    return runQ05RustEvidenceFromSnapshot(snapshot);
  } finally {
    destroyQ05ExecutionSnapshot(snapshot);
  }
}

export function runQ05RustEvidenceFromSnapshot(snapshot) {
  validateQ05ExecutionSnapshot(snapshot);
  const value = runQ05RustEvidenceAt(snapshot.projectRoot, snapshot.cargoTargetRoot);
  validateQ05ExecutionSnapshot(snapshot);
  return value;
}

export function validateQ05JsReport(value) {
  exactKeys(value, ['deterministic', 'limits', 'passed', 'schema', 'scope', 'totalChecks', 'transcript'], 'JS report');
  if (value.schema !== Q05_JS_REPORT_SCHEMA || value.deterministic !== true || value.scope !== 'local JS address/note/record negative corpus') fail('JS report identity differs');
  exactKeys(value.passed, Object.keys(expectedPassed), 'JS report.passed');
  let sum = 0;
  for (const [key, expected] of Object.entries(expectedPassed)) {
    if (value.passed[key] !== expected) fail(`JS report.passed.${key} differs from required count`);
    sum += value.passed[key];
  }
  if (value.totalChecks !== sum) fail('JS report totalChecks does not equal dynamically reported checks');
  exactKeys(value.transcript, ['format', 'labels', 'sha256'], 'JS report transcript');
  if (
    value.transcript.format !== 'shieldkit-v2-q05-executed-check-labels/v1'
    || !Array.isArray(value.transcript.labels)
    || value.transcript.labels.length !== sum
    || sha(value.transcript.sha256, 'JS transcript hash') !== digest(Buffer.from(JSON.stringify(value.transcript.labels)))
  ) fail('JS report transcript is invalid');
  equalArray(value.transcript.labels, expectedJsTranscript, 'JS report transcript labels');
  equalArray(value.limits, expectedLimits, 'JS report limits');
  return Object.freeze({ totalChecks: sum, transcriptSha256: value.transcript.sha256 });
}

export function validateQ05JsEvidence(value) {
  exactKeys(value, ['execution', 'report', 'schema', 'stderr', 'stderrSha256', 'stdout', 'stdoutSha256'], 'JS evidence');
  if (value.schema !== Q05_JS_EVIDENCE_SCHEMA) fail('JS evidence schema differs');
  const reportResult = validateQ05JsReport(value.report);
  if (typeof value.stdout !== 'string' || sha(value.stdoutSha256, 'JS stdout hash') !== digest(Buffer.from(value.stdout))) fail('JS stdout capture is invalid');
  if (typeof value.stderr !== 'string' || sha(value.stderrSha256, 'JS stderr hash') !== digest(Buffer.from(value.stderr))) fail('JS stderr capture is invalid');
  if (value.stderr !== '') fail('JS evidence contains unexpected stderr');
  if (value.stdout !== `${canonicalJson(value.report)}\n`) fail('JS stdout is not exactly the canonical serialized JSON report');
  exactKeys(value.execution, ['args', 'cwd', 'environment', 'runtime'], 'JS execution');
  equalArray(value.execution.args, ['packages/action/v2/notes.q05-evidence.mjs'], 'JS execution args');
  if (value.execution.cwd !== projectPrefix) fail('JS execution cwd differs');
  validateNodeRuntime(value.execution.runtime);
  if (canonicalJson(value.execution.environment) !== canonicalJson(q05ControlledEnvironment('node'))) fail('JS controlled environment differs');
  return reportResult;
}

export function validateQ05RustEvidence(value, sourceRoot = projectRoot) {
  exactKeys(value, [
    'command', 'commandResult', 'cratePath', 'execution', 'normalizedStderr', 'normalizedStderrSha256',
    'normalizedStdout', 'normalizedStdoutSha256', 'schema', 'stderr', 'stderrSha256', 'stdout',
    'stdoutSha256', 'testNames', 'toolchain', 'selectedExecutable',
  ], 'Rust evidence');
  if (value.schema !== Q05_RUST_EVIDENCE_SCHEMA || value.cratePath !== rustCratePath) fail('Rust evidence identity differs');
  equalArray(value.command, ['<cargo-json-selected-notes-test-executable>', '--test-threads=1'], 'Rust command');
  exactKeys(value.commandResult, ['failed', 'filteredOut', 'ignored', 'passed', 'status', 'tests'], 'Rust command result');
  const result = value.commandResult;
  if (result.status !== 'ok' || result.tests !== 5 || result.passed !== 5 || result.failed !== 0 || result.ignored !== 0 || result.filteredOut !== 0) fail('Rust command result differs from the exact five-test corpus');
  equalArray(value.testNames, expectedRustTests, 'Rust test names');
  if (typeof value.stdout !== 'string' || sha(value.stdoutSha256, 'Rust stdout hash') !== digest(Buffer.from(value.stdout))) fail('Rust stdout capture is invalid');
  if (typeof value.stderr !== 'string' || sha(value.stderrSha256, 'Rust stderr hash') !== digest(Buffer.from(value.stderr))) fail('Rust stderr capture is invalid');
  const normalizedStdout = strictRustStdout(value.stdout);
  const normalizedStderr = strictRustStderr(value.stderr);
  if (value.normalizedStdout !== normalizedStdout || sha(value.normalizedStdoutSha256, 'Rust normalized stdout hash') !== digest(Buffer.from(normalizedStdout))) fail('Rust normalized stdout differs');
  if (value.normalizedStderr !== normalizedStderr || sha(value.normalizedStderrSha256, 'Rust normalized stderr hash') !== digest(Buffer.from(normalizedStderr))) fail('Rust normalized stderr differs');
  if (canonicalJson(value.toolchain) !== canonicalJson(pinnedRustToolchain(sourceRoot))) fail('Rust toolchain differs from the pinned Rust 1.97.1 toolchain');
  exactKeys(value.selectedExecutable, ['bytes', 'mode', 'sha256', 'targetRelativePath'], 'Rust selected executable');
  if (
    !Number.isSafeInteger(value.selectedExecutable.bytes)
    || value.selectedExecutable.bytes < 1
    || value.selectedExecutable.mode !== '0700'
    || typeof value.selectedExecutable.targetRelativePath !== 'string'
    || !/^debug\/deps\/notes-[0-9a-f]{16}$/u.test(value.selectedExecutable.targetRelativePath)
  ) fail('Rust selected executable metadata is invalid');
  sha(value.selectedExecutable.sha256, 'Rust selected executable hash');
  exactKeys(value.execution, [
    'cargoTarget', 'configBoundary', 'cwd', 'environment', 'normalizedPreparationStdout',
    'normalizedPreparationStdoutSha256', 'preparationCommand', 'preparationStderr',
    'preparationStderrSha256', 'preparationStdout', 'preparationStdoutSha256', 'testEnvironment',
  ], 'Rust execution');
  if (value.execution.cwd !== rustCratePath) fail('Rust execution cwd differs');
  equalArray(value.execution.preparationCommand, [
    'test', '--quiet', '--locked', '--offline', '--test', 'notes', '--no-run',
    '--message-format=json-render-diagnostics',
  ], 'Rust preparation command');
  if (canonicalJson(value.execution.environment) !== canonicalJson(q05ControlledEnvironment('cargo'))) fail('Rust controlled environment differs');
  if (canonicalJson(value.execution.testEnvironment) !== canonicalJson(q05ControlledEnvironment('rustc'))) fail('Rust test environment differs');
  if (canonicalJson(value.execution.configBoundary) !== canonicalJson(cargoConfigBoundary(sourceRoot))) fail('Rust Cargo config boundary differs');
  exactKeys(value.execution.cargoTarget, ['initialEntries', 'kind', 'recordedPath'], 'Rust Cargo target');
  if (
    value.execution.cargoTarget.kind !== 'fresh-temporary-mode-0700'
    || value.execution.cargoTarget.initialEntries !== 0
    || value.execution.cargoTarget.recordedPath !== '<fresh-cargo-target>'
  ) fail('Rust Cargo target was not a fresh mode-0700 directory');
  if (
    typeof value.execution.preparationStdout !== 'string'
    || sha(value.execution.preparationStdoutSha256, 'Rust preparation stdout hash') !== digest(Buffer.from(value.execution.preparationStdout))
    || typeof value.execution.preparationStderr !== 'string'
    || sha(value.execution.preparationStderrSha256, 'Rust preparation stderr hash') !== digest(Buffer.from(value.execution.preparationStderr))
    || value.execution.preparationStderr !== ''
  ) fail('Rust preparation streams are invalid');
  let selectedPath;
  try {
    const messages = value.execution.preparationStdout.trimEnd().split('\n').map((line) => JSON.parse(line));
    selectedPath = messages.find((message) => message?.target?.name === 'notes' && message?.profile?.test === true && typeof message?.executable === 'string')?.executable;
  } catch {
    fail('Rust preparation stdout is not complete Cargo JSON');
  }
  if (typeof selectedPath !== 'string' || !selectedPath.endsWith(`/${value.selectedExecutable.targetRelativePath}`)) fail('Rust preparation did not select the recorded test executable');
  let cargoTargetRoot = selectedPath;
  for (const _part of value.selectedExecutable.targetRelativePath.split('/')) cargoTargetRoot = dirname(cargoTargetRoot);
  const parsedPreparation = parseCargoPreparation(value.execution.preparationStdout, cargoTargetRoot);
  if (
    value.execution.normalizedPreparationStdout !== parsedPreparation.normalizedStdout
    || sha(value.execution.normalizedPreparationStdoutSha256, 'Rust normalized preparation stdout hash') !== digest(Buffer.from(parsedPreparation.normalizedStdout))
  ) fail('Rust normalized preparation stdout differs');
  return Object.freeze({
    tests: 5,
    passed: 5,
    selectedExecutableSha256: value.selectedExecutable.sha256,
    normalizedStdoutSha256: value.normalizedStdoutSha256,
    normalizedStderrSha256: value.normalizedStderrSha256,
  });
}

export function validateQ05ValidatedProperties(properties) {
  equalArray(properties, Q05_VALIDATED_PROPERTIES, 'evidence validatedProperties');
}

function validateSourceBinding(value, checkout, snapshot) {
  exactKeys(value, ['executionSnapshot', 'git', 'gitExecution', 'schema', 'sourceRoot', 'sources'], 'source binding');
  if (value.schema !== Q05_SOURCE_BINDING_SCHEMA || value.sourceRoot !== projectPrefix) fail('source binding schema or bound source root differs');
  exactKeys(value.git, ['head', 'tree'], 'source binding.git');
  if (gitObject(value.git.head, 'source binding.git.head') !== checkout.head || gitObject(value.git.tree, 'source binding.git.tree') !== checkout.tree) fail('source binding HEAD or tree differs from this checkout');
  if (canonicalJson(value.gitExecution) !== canonicalJson(q05GitExecutionBoundary())) fail('source binding Git execution boundary differs');
  validateQ05ExecutionSnapshot(snapshot);
  if (canonicalJson(value.executionSnapshot) !== canonicalJson(snapshot.record)) fail('source binding exact-HEAD execution snapshot differs');
  if (!Array.isArray(value.sources) || value.sources.length !== Q05_SOURCE_DEFINITIONS.length) fail('source binding must cover the complete fixed source set');
  for (const [index, expected] of Q05_SOURCE_DEFINITIONS.entries()) {
    const source = value.sources[index];
    exactKeys(source, ['gitBlob', 'path', 'role', 'sha256'], `source binding.sources[${index}]`);
    if (source.role !== expected.role || source.path !== expected.path) fail(`source binding source ${index} role or path differs`);
    if (gitObject(source.gitBlob, `source binding.sources[${index}].gitBlob`) !== gitBlobFor(expected.path)) fail(`source binding source ${expected.path} Git blob differs`);
    const actual = readFileSync(containedPath(snapshot.repositoryRoot, expected.path, `snapshot source ${expected.path}`));
    if (sha(source.sha256, `source binding source ${expected.path} hash`) !== digest(actual)) fail(`source binding source ${expected.path} exact-HEAD snapshot hash differs`);
  }
  return Object.freeze({
    head: checkout.head,
    tree: checkout.tree,
    sourceCount: value.sources.length,
    sourceRoot: snapshot.projectRoot,
  });
}

function secureFile(root, relativePath, label) {
  const absolute = containedPath(root, relativePath, label);
  let stat;
  try {
    stat = lstatSync(absolute);
  } catch {
    fail(`${label} is missing`);
  }
  if (
    !stat.isFile()
    || stat.isSymbolicLink()
    || stat.nlink !== 1
    || realpathSync(absolute) !== absolute
    || (stat.mode & 0o777) !== 0o600
    || (typeof process.getuid === 'function' && stat.uid !== process.getuid())
  ) fail(`${label} must be a direct single-link user-owned mode-0600 regular file`);
  return absolute;
}

function readSecureFile(absolute, label) {
  const named = lstatSync(absolute);
  const descriptor = openSync(absolute, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const initial = fstatSync(descriptor);
    if (
      initial.dev !== named.dev
      || initial.ino !== named.ino
      || initial.nlink !== 1
      || (initial.mode & 0o777) !== 0o600
      || (typeof process.getuid === 'function' && initial.uid !== process.getuid())
    ) fail(`${label} changed before it was opened`);
    const bytes = readFileSync(descriptor);
    const final = fstatSync(descriptor);
    if (
      final.dev !== initial.dev
      || final.ino !== initial.ino
      || final.nlink !== 1
      || final.size !== initial.size
      || final.mtimeMs !== initial.mtimeMs
      || final.ctimeMs !== initial.ctimeMs
    ) fail(`${label} changed while it was read`);
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

function replayComparableRust(value) {
  return Object.freeze({
    schema: value.schema,
    cratePath: value.cratePath,
    command: value.command,
    commandResult: value.commandResult,
    testNames: value.testNames,
    normalizedStdout: value.normalizedStdout,
    normalizedStdoutSha256: value.normalizedStdoutSha256,
    normalizedStderr: value.normalizedStderr,
    normalizedStderrSha256: value.normalizedStderrSha256,
    // Debug metadata makes otherwise equivalent Rust test executables differ
    // byte-for-byte when their secure snapshot roots differ. Each run still
    // records and validates the exact selected executable hash; replay compares
    // only the stable selection identity and metadata.
    selectedExecutable: Object.freeze({
      targetRelativePath: value.selectedExecutable.targetRelativePath,
      bytes: value.selectedExecutable.bytes,
      mode: value.selectedExecutable.mode,
    }),
    toolchain: value.toolchain,
    execution: Object.freeze({
      environment: value.execution.environment,
      configBoundary: value.execution.configBoundary,
      preparationCommand: value.execution.preparationCommand,
      normalizedPreparationStdout: value.execution.normalizedPreparationStdout,
      normalizedPreparationStdoutSha256: value.execution.normalizedPreparationStdoutSha256,
      preparationStderr: value.execution.preparationStderr,
      preparationStderrSha256: value.execution.preparationStderrSha256,
      cargoTarget: value.execution.cargoTarget,
      testEnvironment: value.execution.testEnvironment,
      cwd: value.execution.cwd,
    }),
  });
}

export function verifyQ05EvidenceBundle(bundlePath) {
  if (typeof bundlePath !== 'string' || resolve(bundlePath) !== bundlePath) fail('bundle path must be an absolute normalized path');
  let rootStat;
  try {
    rootStat = lstatSync(bundlePath);
  } catch {
    fail('bundle root is missing');
  }
  if (
    !rootStat.isDirectory()
    || rootStat.isSymbolicLink()
    || realpathSync(bundlePath) !== bundlePath
    || (rootStat.mode & 0o777) !== 0o700
    || (typeof process.getuid === 'function' && rootStat.uid !== process.getuid())
  ) fail('bundle root must be a direct user-owned mode-0700 directory');

  const checkout = assertCleanCommittedCheckout();
  const snapshot = createQ05ExecutionSnapshot(checkout);
  try {
    const manifest = parseCanonicalJson(readSecureFile(secureFile(bundlePath, 'manifest.json', 'manifest'), 'manifest'), 'manifest');
    exactKeys(manifest, ['artifacts', 'schema'], 'manifest');
    if (manifest.schema !== Q05_BUNDLE_SCHEMA || !Array.isArray(manifest.artifacts) || manifest.artifacts.length !== 4) fail('manifest schema or artifact count differs');
    const expectedRoles = ['evidence', 'js-evidence', 'rust-evidence', 'source-binding'];
    const artifacts = new Map();
    for (const entry of manifest.artifacts) {
      exactKeys(entry, ['bytes', 'path', 'role', 'sha256'], 'manifest artifact');
      if (!expectedRoles.includes(entry.role) || artifacts.has(entry.role) || !Number.isSafeInteger(entry.bytes) || entry.bytes < 1) fail('manifest artifact metadata is invalid or ambiguous');
      sha(entry.sha256, `manifest artifact ${entry.role} hash`);
      const bytes = readSecureFile(secureFile(bundlePath, entry.path, `artifact ${entry.role}`), `artifact ${entry.role}`);
      if (bytes.length !== entry.bytes || digest(bytes) !== entry.sha256) fail(`artifact ${entry.role} byte count or hash differs`);
      artifacts.set(entry.role, Object.freeze({ bytes, sha256: entry.sha256 }));
    }
    equalArray([...artifacts.keys()].sort(), expectedRoles, 'manifest artifact roles');
    equalArray(readdirSync(bundlePath).sort(), ['evidence.json', 'js-evidence.json', 'manifest.json', 'rust-evidence.json', 'source-binding.json'], 'bundle entries');

    const sourceResult = validateSourceBinding(parseCanonicalJson(artifacts.get('source-binding').bytes, 'source binding'), checkout, snapshot);
    const js = parseCanonicalJson(artifacts.get('js-evidence').bytes, 'JS evidence');
    const jsResult = validateQ05JsEvidence(js);
    const rust = parseCanonicalJson(artifacts.get('rust-evidence').bytes, 'Rust evidence');
    const rustResult = validateQ05RustEvidence(rust, sourceResult.sourceRoot);
    const evidence = parseCanonicalJson(artifacts.get('evidence').bytes, 'evidence');
    exactKeys(evidence, ['boundaries', 'jsEvidenceSha256', 'rustEvidenceSha256', 'schema', 'sourceBindingSha256', 'status', 'validatedProperties'], 'evidence');
    if (evidence.schema !== Q05_EVIDENCE_SCHEMA || evidence.status !== 'local-evidence-only') fail('evidence identity differs');
    equalArray(evidence.boundaries, expectedBoundaries, 'evidence boundaries');
    validateQ05ValidatedProperties(evidence.validatedProperties);
    if (
      sha(evidence.sourceBindingSha256, 'evidence source binding reference') !== artifacts.get('source-binding').sha256
      || sha(evidence.jsEvidenceSha256, 'evidence JS reference') !== artifacts.get('js-evidence').sha256
      || sha(evidence.rustEvidenceSha256, 'evidence Rust reference') !== artifacts.get('rust-evidence').sha256
    ) fail('evidence artifact reference does not resolve');

    const freshJs = runQ05JsEvidenceFromSnapshot(snapshot);
    const freshRust = runQ05RustEvidenceFromSnapshot(snapshot);
    if (canonicalJson(freshJs) !== canonicalJson(js)) fail('fresh JS replay differs from bound JS evidence');
    if (canonicalJson(replayComparableRust(freshRust)) !== canonicalJson(replayComparableRust(rust))) fail('fresh Rust replay differs from bound normalized Rust evidence');
    return Object.freeze({
      schema: Q05_RESULT_SCHEMA,
      status: 'verified-local-evidence-only',
      head: sourceResult.head,
      tree: sourceResult.tree,
      sourceCount: sourceResult.sourceCount,
      jsChecks: jsResult.totalChecks,
      jsTranscriptSha256: jsResult.transcriptSha256,
      rustTests: rustResult.tests,
      rustSelectedExecutableSha256: freshRust.selectedExecutable.sha256,
      rustStdoutTranscriptSha256: rustResult.normalizedStdoutSha256,
      rustStderrTranscriptSha256: rustResult.normalizedStderrSha256,
    });
  } finally {
    destroyQ05ExecutionSnapshot(snapshot);
  }
}

function parseArguments(argv) {
  if (argv.length !== 2 || argv[0] !== '--bundle') fail('usage: v2-q05-evidence-verify.mjs --bundle /absolute/bundle-directory');
  return argv[1];
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    process.stdout.write(`${canonicalJson(verifyQ05EvidenceBundle(parseArguments(process.argv.slice(2))))}\n`);
  } catch (error) {
    process.stderr.write(`Q05 evidence verification failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
