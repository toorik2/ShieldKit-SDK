#!/usr/bin/env node
/*
 * Q-06 commit-bound evidence wrapper. This is deliberately a narrow local
 * provenance envelope around the two existing full public campaigns. It does
 * not turn their deterministic local evidence into a chain, release, or
 * fault-injection qualification.
 */
import { createHash } from 'node:crypto';
import {
  chmodSync, closeSync, constants, existsSync, fsyncSync, lstatSync, mkdirSync,
  openSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync,
  readlinkSync, unlinkSync, writeSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { userInfo } from 'node:os';
import { basename, dirname, isAbsolute, join, relative as pathRelative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { canonicalJson, parseStrictJson } from '../packages/profile/load.mjs';

export const V2_Q06_EVIDENCE_SCHEMA = 'shieldkit-v2-direct/q06-commit-bound-evidence/v2';
export const V2_Q06_BUNDLE_SCHEMA = 'shieldkit-v2-direct/q06-commit-bound-bundle/v2';
export const V2_Q06_SOURCE_SET_SCHEMA = 'shieldkit-v2-direct/q06-source-set/v1';
export const V2_Q06_RESULT_SCHEMA = 'shieldkit-v2-direct/q06-commit-bound-verification/v2';

const HASH = /^[0-9a-f]{64}$/u;
const GIT = /^[0-9a-f]{40}$/u;
const MODE = /^(100644|100755)$/u;
const CRASH_SCHEMA = 'shieldkit-v2-direct-crash-qualification-v1';
const REORG_SCHEMA = 'shieldkit-v2-direct-reorg-sequential-sibling-qualification-v2';
const REPLAY_RESULT_SCHEMA = 'shieldkit-v2-direct/captured-recovery-action-corpus-replay/v1';
const REPLAY_CORPUS_SCHEMA = 'shieldkit-v2-direct/captured-recovery-action-corpus/v1';
const EXTERNAL_CRASH_SCHEMA = 'shieldkit-v2-direct-external-crash-corpus-v1';
const DEPENDENCY_CLOSURE_SCHEMA = 'shieldkit-v2-direct/npm-lock-dependency-closure-v1';
const IMMUTABLE_INSTALL_SCHEMA = 'shieldkit-v2-direct/npm-ci-closure-record-v1';
const INSTALLED_INVENTORY_SCHEMA = 'shieldkit-v2-direct/installed-dependency-inventory-v1';
const CRASH_CASES = 10_000;
const REORG_DEPTHS = Object.freeze([1, 2, 10, 100]);
const WALLET_COUNTS = Object.freeze([2, 4, 8, 16]);
const trustedGitCandidates = Object.freeze(['/usr/bin/git', '/bin/git']);
const userHome = userInfo().homedir;
const controlledEnvironmentBoundary = Object.freeze({
  inherited: false,
  hostRejected: Object.freeze([
    'NODE_OPTIONS',
    'NODE_PATH',
    'LD_*',
    'DYLD_*',
    'dangerous process.execArgv loaders/preloads',
    'HOME mismatch with the operating-system user record',
  ]),
  node: Object.freeze({
    HOME: userHome,
    LANG: 'C',
    LC_ALL: 'C',
    PATH: '/usr/bin:/bin',
    TZ: 'UTC',
  }),
  git: Object.freeze({
    GIT_CONFIG_COUNT: '0',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_TERMINAL_PROMPT: '0',
    HOME: '/nonexistent/shieldkit-q06-git',
    LANG: 'C',
    LC_ALL: 'C',
    PATH: '/usr/bin:/bin',
    TZ: 'UTC',
  }),
  npm: Object.freeze({
    HOME: userHome,
    LANG: 'C',
    LC_ALL: 'C',
    NPM_CONFIG_AUDIT: 'false',
    NPM_CONFIG_FUND: 'false',
    NPM_CONFIG_GLOBALCONFIG: '/nonexistent/shieldkit-q06-global-npmrc',
    NPM_CONFIG_IGNORE_SCRIPTS: 'true',
    NPM_CONFIG_USERCONFIG: '/dev/null',
    PATH: '/usr/bin:/bin',
    TZ: 'UTC',
  }),
});
const Q06_BOUNDARIES = Object.freeze([
  'Q-06 combines a 10,000-case deterministic in-process interruption matrix with six outer-process SIGKILL checks immediately before or after selected complete public store/journal calls; it does not cover SIGKILL inside those calls, power-loss, or filesystem faults.',
  'Q-06 reorg and sibling-conflict evidence is deterministic sequential single-process execution with an independent rollback-history checker; it is not concurrent, live-chain, distributed, or multi-device evidence.',
  'Public verification establishes local self-consistency only: sourceRoot must be this verifier module exact checkout, but no trusted signature or external root anchors that checkout.',
  'Installed dependency bytes and symlink targets are content-addressed and rechecked; targets must resolve within the installed inventory or to a completely tracked source tree, but same-UID malicious path replacement during verification remains out of scope.',
  'The exact canonical 101-event recovery corpus is preserved in the bundle and independently replayed through a fresh production store by public verification; this remains local store-intake evidence, not authenticated chain replay.',
]);
const CRASH_STAGES = Object.freeze([
  'operation.after_pending', 'operation.after_intent', 'operation.before_commit',
  'prepare.after_pending', 'prepare.after_intent', 'prepare.after_note', 'prepare.after_utxo', 'prepare.before_commit',
  'reservation.after_note', 'reservation.after_utxo', 'reservation.before_commit',
  'abandon.after_reservations', 'abandon.after_overlay', 'abandon.before_commit',
  'conflict.after_counter', 'conflict.after_resources', 'conflict.before_commit',
  'rebase.after_artifacts', 'rebase.before_commit', 'confirmed.before_commit',
  'prove.after_transition', 'prove.after_proof', 'prove.after_artifacts', 'prove.after_proved',
  'sign.after_refresh', 'sign.after_signature', 'sign.after_artifacts', 'sign.after_signed',
  'delivery.claim-or-create.after_insert', 'delivery.recovery-claim.after_update', 'delivery.submitted.after_update',
  'delivery.indeterminate.after_update', 'delivery.observed.after_update', 'delivery.locally-reconciled.after_update',
]);
const CRASH_INVARIANT_KEYS = Object.freeze([
  'noCanonicalCommitBeforeAuthenticatedConfirmation', 'authenticatedConfirmationCommitsCanonicalState',
  'noLostOrDuplicatedReservations', 'noUnsignedBroadcastableState', 'noDuplicateSend', 'exactResumabilityOrAbandon',
]);
const CRASH_RESERVATION_ASSERTION_STAGES = Object.freeze(CRASH_STAGES.slice(3, 19));
const CRASH_UNSIGNED_REJECTION_STAGES = Object.freeze(CRASH_STAGES.slice(20, 27));
const REORG_INVARIANT_KEYS = Object.freeze([
  'canonicalTipUnchangedBeforeApplyConfirmed', 'reorgAncestorCanonicalTipMatched',
  'reorgedOperationStateExact', 'reorgedFundingReservationRetained', 'reorgAbandonFundingReleased',
  'reorgUndoLogCleared', 'sequentialSiblingStaleParentRejected', 'siblingConflictFundingReleased',
  'siblingRebaseFundingReacquired', 'siblingAbandonFundingReleased',
  'sequentialSiblingWinnerTipPreservedAfterReopen', 'maliciousDuplicateNullifierRejected',
  'maliciousDuplicateNoteReservationRejected', 'maliciousAttemptCanonicalTipUnchanged',
  'deepWipeSnapshotCanonicalTipMatched', 'deepWipeExactCapturedEventIngestions',
]);
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repositoryRoot = resolve(projectRoot, '..');
const crashScript = 'shieldkit-groth-94kb/scripts/v2-crash-qualification.mjs';
const reorgScript = 'shieldkit-groth-94kb/scripts/v2-reorg-concurrency-qualification.mjs';

export class V2Q06CommitBoundEvidenceError extends Error {
  constructor(message) { super(message); this.name = 'V2Q06CommitBoundEvidenceError'; }
}
const fail = (message) => { throw new V2Q06CommitBoundEvidenceError(message); };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail(`${label} must be a plain object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown fields`);
  return value;
}
function bool(value, label) { if (typeof value !== 'boolean') fail(`${label} must be boolean`); return value; }
function nonnegative(value, label) { if (!Number.isSafeInteger(value) || value < 0) fail(`${label} must be a nonnegative safe integer`); return value; }
function directDirectory(path, label, create = false) {
  if (!isAbsolute(path) || resolve(path) !== path) fail(`${label} must be an absolute normalized path`);
  if (create) mkdirSync(path, { mode: 0o700 });
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isDirectory() || (stat.mode & 0o777) !== 0o700 || (typeof process.getuid === 'function' && stat.uid !== process.getuid()) || realpathSync(path) !== path) fail(`${label} must be a direct user-owned mode-0700 directory`);
  return stat;
}
function outputParent(path) {
  const parent = resolve(path); directDirectory(parent, 'output directory');
  if (parent === repositoryRoot || parent.startsWith(`${repositoryRoot}/`)) fail('output directory must be outside the source checkout so commit-bound source remains clean');
  return parent;
}
function child(root, name, label) {
  if (typeof name !== 'string' || name.length === 0 || basename(name) !== name) fail(`${label} must be one direct filename`);
  const path = join(root, name); if (dirname(path) !== root) fail(`${label} escapes its bundle`); return path;
}
function ownedFile(path, label) {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600 || (typeof process.getuid === 'function' && stat.uid !== process.getuid()) || realpathSync(path) !== path) fail(`${label} must be a direct user-owned mode-0600 single-link file`);
  return stat;
}
function writeFully(fd, bytes) { for (let offset = 0; offset < bytes.length;) { const count = writeSync(fd, bytes, offset, bytes.length - offset); if (count <= 0) fail('atomic write made no progress'); offset += count; } }
function writeAtomicBytes(root, name, bytes) {
  if (!Buffer.isBuffer(bytes)) fail('artifact bytes must be a Buffer');
  const target = child(root, name, 'artifact');
  if (existsSync(target)) fail(`refusing to overwrite ${target}`);
  const temporary = child(root, `.${name}.${process.pid}.${Date.now()}.tmp`, 'temporary artifact'); let fd;
  try {
    fd = openSync(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0), 0o600);
    chmodSync(temporary, 0o600); writeFully(fd, bytes); fsyncSync(fd); closeSync(fd); fd = undefined;
    ownedFile(temporary, 'temporary artifact'); renameSync(temporary, target); ownedFile(target, 'artifact');
    return Object.freeze({ path: name, bytes: bytes.length, sha256: sha256(bytes) });
  } finally { if (fd !== undefined) closeSync(fd); if (existsSync(temporary)) unlinkSync(temporary); }
}
function writeAtomic(root, name, value) {
  return writeAtomicBytes(root, name, Buffer.from(canonicalJson(value), 'utf8'));
}
function fsyncDirectory(path) { const fd = openSync(path, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0) | (constants.O_NOFOLLOW ?? 0)); try { fsyncSync(fd); } finally { closeSync(fd); } }
function parseCanonical(bytes, label) {
  let value; try { value = parseStrictJson(bytes); } catch (error) { fail(`${label} is not strict JSON: ${error instanceof Error ? error.message : String(error)}`); }
  if (canonicalJson(value) !== text.decode(bytes)) fail(`${label} is not canonical JSON`);
  return value;
}
export function assertV2Q06SafeHostEnvironment(
  environment = process.env,
  execArguments = process.execArgv,
) {
  const contaminated = [];
  if (environment.HOME !== userHome) contaminated.push('HOME');
  for (const [key, value] of Object.entries(environment)) {
    if (typeof value !== 'string' || value.length === 0) continue;
    if (
      key === 'NODE_OPTIONS'
      || key === 'NODE_PATH'
      || key.startsWith('LD_')
      || key.startsWith('DYLD_')
    ) contaminated.push(key);
  }
  if (
    !Array.isArray(execArguments)
    || execArguments.some((entry) =>
      typeof entry !== 'string'
      || /^(?:-r|--require|--import|--loader|--experimental-loader)(?:=|$)/u.test(entry))
  ) contaminated.push('process.execArgv');
  if (contaminated.length > 0) {
    fail(`Q-06 host process environment is contaminated: ${[...new Set(contaminated)].join(', ')}`);
  }
}
function trustedGitExecutable() {
  for (const candidate of trustedGitCandidates) {
    const entry = lstatSync(candidate, { throwIfNoEntry: false });
    if (
      entry?.isFile()
      && !entry.isSymbolicLink()
      && entry.nlink === 1
      && entry.uid === 0
      && (entry.mode & 0o022) === 0
      && realpathSync(candidate) === candidate
    ) return candidate;
  }
  fail(`no trusted Git executable exists at ${trustedGitCandidates.join(' or ')}`);
}
function git(root, args) {
  const executable = trustedGitExecutable();
  const prefix = Object.freeze([
    '--no-replace-objects',
    '-c', 'core.fsmonitor=false',
    '-c', 'core.hooksPath=/dev/null',
    '-c', 'core.pager=cat',
    '-c', 'pager.status=false',
    '-C', root,
  ]);
  const result = spawnSync(executable, [...prefix, ...args], {
    cwd: root,
    encoding: 'utf8',
    env: controlledEnvironmentBoundary.git,
    maxBuffer: 16 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error || result.status !== 0 || result.signal) fail(`${executable} ${args.join(' ')} failed: ${(result.stderr || result.error?.message || '').trim()}`);
  if (result.stderr !== '') fail(`${executable} ${args.join(' ')} emitted unexpected stderr`);
  return result.stdout;
}
function trackedEntries(root) {
  const raw = git(root, ['ls-files', '-s', '-z']); const entries = [];
  for (const record of raw.split('\0')) {
    if (record === '') continue;
    const match = record.match(/^(100644|100755) ([0-9a-f]{40}) [0-3]\t(.+)$/u);
    if (!match) fail(`tracked entry is not a regular committed file: ${record.slice(0, 120)}`);
    const [, mode, blob, path] = match;
    if (path.includes('\\') || path.split('/').some((part) => part === '' || part === '.' || part === '..')) fail(`tracked path is unsafe: ${path}`);
    const absolute = resolve(root, path); if (!absolute.startsWith(`${root}/`)) fail(`tracked path escapes checkout: ${path}`);
    const stat = lstatSync(absolute); if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1 || realpathSync(absolute) !== absolute) fail(`tracked path is not a direct single-link file: ${path}`);
    const bytes = readFileSync(absolute); entries.push(Object.freeze({ path, mode, blob, bytes: bytes.length, sha256: sha256(bytes) }));
  }
  if (entries.length === 0) fail('source checkout has no tracked files');
  return entries;
}
function lockPath(path) { return /(?:^|\/)(?:package-lock\.json|Cargo\.lock|pnpm-lock\.yaml|yarn\.lock)$/u.test(path); }
function runtimeRecord() {
  const executable = realpathSync(process.execPath); const stat = lstatSync(executable);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1) fail('runtime executable must be a direct single-link file');
  const gitExecutable = trustedGitExecutable();
  const gitVersion = spawnSync(gitExecutable, ['--version'], {
    encoding: 'utf8',
    env: controlledEnvironmentBoundary.git,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (
    gitVersion.error
    || gitVersion.status !== 0
    || gitVersion.signal
    || gitVersion.stderr !== ''
    || !/^git version [0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[.A-Za-z0-9+-]*)?\n$/u.test(gitVersion.stdout)
  ) fail('trusted Git version probe failed');
  return Object.freeze({
    nodeVersion: process.version,
    executable,
    executableSha256: sha256(readFileSync(executable)),
    platform: process.platform,
    arch: process.arch,
    git: Object.freeze({
      executable: gitExecutable,
      executableSha256: sha256(readFileSync(gitExecutable)),
      version: gitVersion.stdout.trim(),
    }),
    environmentBoundary: controlledEnvironmentBoundary,
  });
}
function npmRuntimeRecord() {
  // Always use the npm CLI installed beside this exact Node executable. An
  // ambient npm_execpath or PATH entry is caller-controlled and is ignored.
  const executable = resolve(dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js');
  if (!isAbsolute(executable) || resolve(executable) !== executable) fail('npm CLI path must be absolute and normalized for immutable-install evidence');
  const resolved = realpathSync(executable); const stat = lstatSync(resolved);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1) fail('npm CLI must be a direct single-link file');
  const version = spawnSync(process.execPath, [resolved, '--version'], {
    encoding: 'utf8',
    env: controlledEnvironmentBoundary.npm,
    maxBuffer: 64 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (version.error || version.status !== 0 || version.signal || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\n$/u.test(version.stdout)) fail('npm CLI version probe failed');
  return Object.freeze({ executable: resolved, executableSha256: sha256(readFileSync(resolved)), version: version.stdout.trim() });
}
function dependencyClosureRecord(root) {
  const lockPath = join(root, 'package-lock.json'); const packagePath = join(root, 'package.json');
  if (!existsSync(lockPath) || !existsSync(packagePath)) fail('Q-06 immutable-install evidence requires root package-lock.json and package.json');
  const lockBytes = readFileSync(lockPath); const packageBytes = readFileSync(packagePath);
  let lock; try { lock = parseStrictJson(lockBytes); } catch (error) { fail(`package lock is not strict JSON: ${error instanceof Error ? error.message : String(error)}`); }
  if (lock === null || Array.isArray(lock) || typeof lock !== 'object' || !Number.isSafeInteger(lock.lockfileVersion) || lock.lockfileVersion < 1 || lock.packages === null || Array.isArray(lock.packages) || typeof lock.packages !== 'object') fail('package lock does not contain an npm package closure');
  const packages = Object.entries(lock.packages).map(([path, entry]) => {
    if (typeof path !== 'string' || entry === null || Array.isArray(entry) || typeof entry !== 'object') fail('package lock contains an invalid package closure entry');
    return Object.freeze({ path, entry });
  }).sort((left, right) => left.path.localeCompare(right.path));
  return Object.freeze({ schema: DEPENDENCY_CLOSURE_SCHEMA, lockfilePath: 'package-lock.json', lockfileSha256: sha256(lockBytes), packageJsonSha256: sha256(packageBytes), lockfileVersion: lock.lockfileVersion, packageCount: packages.length, closureSha256: sha256(Buffer.from(canonicalJson(packages), 'utf8')) });
}
function npmJson(root, args, label, environment = controlledEnvironmentBoundary.npm) {
  const result = spawnSync(process.execPath, [npmRuntimeRecord().executable, ...args], {
    cwd: root,
    encoding: 'utf8',
    env: environment,
    maxBuffer: 16 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error || result.status !== 0 || result.signal) fail(`${label} failed: ${(result.stderr || result.error?.message || '').trim()}`);
  let value; try { value = parseStrictJson(Buffer.from(result.stdout)); } catch (error) { fail(`${label} did not emit strict JSON: ${error instanceof Error ? error.message : String(error)}`); }
  return Object.freeze({ stdout: result.stdout, stderr: result.stderr, value });
}
function pathWithin(root, candidate) {
  return candidate === root || candidate.startsWith(`${root}/`);
}

function validateTrackedSymlinkTarget(sourceRoot, target, trackedPaths) {
  const pending = [target];
  while (pending.length > 0) {
    const current = pending.pop();
    const stat = lstatSync(current);
    if (stat.isSymbolicLink()) fail('dependency symlink target contains a nested symlink outside node_modules');
    if (stat.isDirectory()) {
      for (const name of readdirSync(current)) pending.push(join(current, name));
      continue;
    }
    if (!stat.isFile() || stat.nlink !== 1 || realpathSync(current) !== current) {
      fail('dependency symlink target contains a special or multiply-linked source path');
    }
    const tracked = pathRelative(sourceRoot, current);
    if (
      tracked === '' ||
      tracked.startsWith('../') ||
      isAbsolute(tracked) ||
      !trackedPaths.has(tracked)
    ) {
      fail(`dependency symlink target escapes tracked source coverage: ${tracked}`);
    }
  }
}

function installedDependencyInventory(root) {
  const base = join(root, 'node_modules'); const observed = lstatSync(base, { throwIfNoEntry: false });
  if (observed === undefined || observed.isSymbolicLink() || !observed.isDirectory()) fail('immutable install did not produce a direct node_modules directory');
  const trackedPaths = new Set(git(root, ['ls-files', '-z']).split('\0').filter((entry) => entry !== ''));
  const entries = []; let totalFileBytes = 0;
  const walk = (directory, prefix) => {
    const names = readdirSync(directory).sort();
    for (const name of names) {
      if (name.includes('/') || name === '.' || name === '..') fail('installed dependency inventory encountered an unsafe name');
      const path = join(directory, name); const relative = prefix === '' ? name : `${prefix}/${name}`; const stat = lstatSync(path);
      if (stat.isSymbolicLink()) {
        const target = readlinkSync(path);
        const resolvedTarget = realpathSync(path);
        if (pathWithin(base, resolvedTarget)) {
          entries.push(Object.freeze({
            path: relative,
            type: 'symlink',
            target,
            resolvedScope: 'installed-inventory',
            resolvedPath: pathRelative(base, resolvedTarget),
          }));
        } else if (pathWithin(root, resolvedTarget)) {
          validateTrackedSymlinkTarget(root, resolvedTarget, trackedPaths);
          entries.push(Object.freeze({
            path: relative,
            type: 'symlink',
            target,
            resolvedScope: 'tracked-source',
            resolvedPath: pathRelative(root, resolvedTarget),
          }));
        } else {
          fail(`installed dependency symlink escapes bound inventories: ${relative}`);
        }
      } else if (stat.isDirectory()) {
        entries.push(Object.freeze({ path: relative, type: 'directory', mode: stat.mode & 0o777 })); walk(path, relative);
      } else if (stat.isFile() && stat.nlink === 1) {
        const bytes = readFileSync(path); totalFileBytes += bytes.length;
        entries.push(Object.freeze({ path: relative, type: 'file', mode: stat.mode & 0o777, bytes: bytes.length, sha256: sha256(bytes) }));
      } else fail(`installed dependency inventory rejects special or multiply-linked path: ${relative}`);
    }
  };
  walk(base, '');
  return Object.freeze({ schema: INSTALLED_INVENTORY_SCHEMA, root: 'node_modules', entries: entries.length, totalFileBytes, inventorySha256: sha256(Buffer.from(canonicalJson(entries), 'utf8')) });
}
/** TEST-ONLY: exercises dependency symlink closure without running npm ci. */
export function installedDependencyInventoryForTest(root) {
  return installedDependencyInventory(root);
}
function immutableInstallRecord(root, closure, stagingDirectory) {
  const npm = npmRuntimeRecord();
  const cache = join(stagingDirectory, 'npm-cache');
  mkdirSync(cache, { mode: 0o700 });
  chmodSync(cache, 0o700);
  const cacheEntry = lstatSync(cache);
  if (
    !cacheEntry.isDirectory()
    || cacheEntry.isSymbolicLink()
    || (cacheEntry.mode & 0o777) !== 0o700
    || (typeof process.getuid === 'function' && cacheEntry.uid !== process.getuid())
    || realpathSync(cache) !== cache
  ) fail('Q-06 npm cache is not a fresh direct user-owned mode-0700 directory');
  const installEnvironment = Object.freeze({
    ...controlledEnvironmentBoundary.npm,
    NPM_CONFIG_CACHE: cache,
  });
  const command = Object.freeze([process.execPath, npm.executable, 'ci', '--ignore-scripts', '--no-audit', '--fund=false']);
  const install = npmJson(root, command.slice(2).concat('--json'), 'npm ci immutable install', installEnvironment);
  const tree = npmJson(root, ['ls', '--all', '--json', '--omit=optional'], 'npm dependency closure inspection');
  const installedInventory = installedDependencyInventory(root);
  return Object.freeze({
    schema: IMMUTABLE_INSTALL_SCHEMA,
    command,
    npm,
    lockfileSha256: closure.lockfileSha256,
    packageJsonSha256: closure.packageJsonSha256,
    installStdoutSha256: sha256(Buffer.from(install.stdout)),
    installStderrSha256: sha256(Buffer.from(install.stderr)),
    installedClosureSha256: sha256(Buffer.from(canonicalJson(tree.value), 'utf8')),
    installedInventory,
    environmentBoundary: Object.freeze({
      ...controlledEnvironmentBoundary,
      npmInstallCache: 'fresh-private-mode-0700',
    }),
    statement: 'Local npm ci --ignore-scripts executed successfully; npm ls captured metadata and a content-addressed inventory captured installed file bytes and symlink targets. Every symlink resolves within that inventory or to a completely tracked source tree. This is reproducible local evidence, not external attestation of registry, host, or supply-chain trust; same-UID replacement races remain out of scope.',
  });
}
function sourceSet(root = repositoryRoot) {
  const sourceRoot = resolve(root); if (realpathSync(sourceRoot) !== sourceRoot) fail('source root must be a direct checkout path');
  if (git(sourceRoot, ['rev-parse', '--show-toplevel']).trim() !== sourceRoot) fail('source root must be the exact Git checkout root');
  if (git(sourceRoot, ['status', '--porcelain=v1', '--untracked-files=all']) !== '') fail('real Q-06 evidence requires an exact clean committed source checkout');
  const gitCommit = git(sourceRoot, ['rev-parse', 'HEAD']).trim(); const gitTree = git(sourceRoot, ['rev-parse', 'HEAD^{tree}']).trim();
  if (!GIT.test(gitCommit) || !GIT.test(gitTree)) fail('Git commit/tree identity is invalid');
  const all = trackedEntries(sourceRoot); const files = all.filter((entry) => !lockPath(entry.path)); const locks = all.filter((entry) => lockPath(entry.path));
  const dependencyClosure = dependencyClosureRecord(sourceRoot);
  const sourceSetSha256 = sha256(Buffer.from(canonicalJson({ files, locks, dependencyClosure }), 'utf8'));
  return Object.freeze({ schema: V2_Q06_SOURCE_SET_SCHEMA, sourceRoot, gitCommit, gitTree, runtime: runtimeRecord(), files, locks, dependencyClosure, sourceSetSha256 });
}
function sameJson(left, right) { return canonicalJson(left) === canonicalJson(right); }
function validateRuntime(value, requireCurrent) {
  exact(value, ['arch', 'environmentBoundary', 'executable', 'executableSha256', 'git', 'nodeVersion', 'platform'], 'runtime');
  if (typeof value.nodeVersion !== 'string' || !/^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/u.test(value.nodeVersion) || typeof value.executable !== 'string' || !isAbsolute(value.executable) || resolve(value.executable) !== value.executable || !HASH.test(value.executableSha256) || typeof value.platform !== 'string' || typeof value.arch !== 'string') fail('runtime identity is invalid');
  exact(value.git, ['executable', 'executableSha256', 'version'], 'runtime Git');
  if (
    typeof value.git.executable !== 'string'
    || !isAbsolute(value.git.executable)
    || !HASH.test(value.git.executableSha256)
    || !/^git version [0-9]+\.[0-9]+/u.test(value.git.version)
    || !sameJson(value.environmentBoundary, controlledEnvironmentBoundary)
  ) fail('runtime Git or controlled-environment identity is invalid');
  if (requireCurrent && !sameJson(value, runtimeRecord())) fail('runtime identity differs from this verifier runtime');
  return value;
}
function validateDependencyClosure(value, { checkCurrent = false, root = null } = {}) {
  exact(value, ['closureSha256', 'lockfilePath', 'lockfileSha256', 'lockfileVersion', 'packageCount', 'packageJsonSha256', 'schema'], 'dependency closure');
  if (value.schema !== DEPENDENCY_CLOSURE_SCHEMA || value.lockfilePath !== 'package-lock.json' || !HASH.test(value.lockfileSha256) || !HASH.test(value.packageJsonSha256) || !HASH.test(value.closureSha256) || !Number.isSafeInteger(value.lockfileVersion) || value.lockfileVersion < 1 || !Number.isSafeInteger(value.packageCount) || value.packageCount < 1) fail('dependency closure identity is invalid');
  if (checkCurrent) {
    const current = dependencyClosureRecord(root);
    if (!sameJson(value, current)) fail('bound package lock or dependency closure differs from this verifier checkout');
  }
  return value;
}
function validateImmutableInstall(value, closure, { checkCurrent = false, root = null } = {}) {
  exact(value, ['command', 'environmentBoundary', 'installStderrSha256', 'installStdoutSha256', 'installedClosureSha256', 'installedInventory', 'lockfileSha256', 'npm', 'packageJsonSha256', 'schema', 'statement'], 'immutable install record');
  exact(value.npm, ['executable', 'executableSha256', 'version'], 'immutable install npm runtime');
  exact(value.installedInventory, ['entries', 'inventorySha256', 'root', 'schema', 'totalFileBytes'], 'installed dependency inventory');
  if (value.schema !== IMMUTABLE_INSTALL_SCHEMA || !Array.isArray(value.command) || value.command.length !== 6 || value.command[0] !== process.execPath || typeof value.command[1] !== 'string' || !isAbsolute(value.command[1]) || value.command[2] !== 'ci' || value.command[3] !== '--ignore-scripts' || value.command[4] !== '--no-audit' || value.command[5] !== '--fund=false' || !HASH.test(value.installStdoutSha256) || !HASH.test(value.installStderrSha256) || !HASH.test(value.installedClosureSha256) || value.lockfileSha256 !== closure.lockfileSha256 || value.packageJsonSha256 !== closure.packageJsonSha256 || typeof value.statement !== 'string' || !value.statement.includes('Every symlink resolves within that inventory or to a completely tracked source tree') || !value.statement.includes('not external attestation') || !value.statement.includes('same-UID replacement races remain out of scope')) fail('immutable install record is invalid');
  exact(value.environmentBoundary, ['git', 'hostRejected', 'inherited', 'node', 'npm', 'npmInstallCache'], 'immutable install environment boundary');
  if (
    value.environmentBoundary.inherited !== false
    || value.environmentBoundary.npmInstallCache !== 'fresh-private-mode-0700'
    || !sameJson(
      Object.freeze({
        git: value.environmentBoundary.git,
        hostRejected: value.environmentBoundary.hostRejected,
        inherited: value.environmentBoundary.inherited,
        node: value.environmentBoundary.node,
        npm: value.environmentBoundary.npm,
      }),
      controlledEnvironmentBoundary,
    )
  ) fail('immutable install environment boundary is invalid');
  if (typeof value.npm.executable !== 'string' || !isAbsolute(value.npm.executable) || !HASH.test(value.npm.executableSha256) || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u.test(value.npm.version)) fail('immutable install npm identity is invalid');
  if (value.installedInventory.schema !== INSTALLED_INVENTORY_SCHEMA || value.installedInventory.root !== 'node_modules' || !Number.isSafeInteger(value.installedInventory.entries) || value.installedInventory.entries < 1 || !Number.isSafeInteger(value.installedInventory.totalFileBytes) || value.installedInventory.totalFileBytes < 1 || !HASH.test(value.installedInventory.inventorySha256)) fail('installed dependency inventory identity is invalid');
  if (checkCurrent) {
    if (!sameJson(value.npm, npmRuntimeRecord())) fail('immutable install npm runtime differs from this verifier runtime');
    const installed = npmJson(root, ['ls', '--all', '--json', '--omit=optional'], 'npm dependency closure verification');
    if (value.installedClosureSha256 !== sha256(Buffer.from(canonicalJson(installed.value), 'utf8'))) fail('installed dependency closure differs from the recorded npm ci closure');
    if (!sameJson(value.installedInventory, installedDependencyInventory(root))) fail('installed dependency content inventory differs from the recorded npm ci inventory');
  }
  return value;
}
function validateSourceRecord(value, { checkCurrent = false, enforceVerifierRoot = checkCurrent } = {}) {
  exact(value, ['dependencyClosure', 'files', 'gitCommit', 'gitTree', 'locks', 'runtime', 'schema', 'sourceRoot', 'sourceSetSha256'], 'source set');
  if (value.schema !== V2_Q06_SOURCE_SET_SCHEMA || !isAbsolute(value.sourceRoot) || resolve(value.sourceRoot) !== value.sourceRoot || !GIT.test(value.gitCommit) || !GIT.test(value.gitTree)) fail('source set identity is invalid');
  if (enforceVerifierRoot && value.sourceRoot !== repositoryRoot) fail('bundle sourceRoot differs from this verifier module exact checkout');
  validateRuntime(value.runtime, checkCurrent);
  validateDependencyClosure(value.dependencyClosure, { checkCurrent, root: value.sourceRoot });
  const seen = new Set();
  for (const [label, entries] of [['files', value.files], ['locks', value.locks]]) {
    if (!Array.isArray(entries) || entries.length === 0 && label === 'files') fail(`source set ${label} is invalid`);
    for (const entry of entries) {
      exact(entry, ['blob', 'bytes', 'mode', 'path', 'sha256'], `source set ${label} entry`);
      if (typeof entry.path !== 'string' || entry.path.includes('\\') || entry.path.split('/').some((part) => part === '' || part === '.' || part === '..') || seen.has(entry.path) || !MODE.test(entry.mode) || !GIT.test(entry.blob) || !Number.isSafeInteger(entry.bytes) || entry.bytes < 0 || !HASH.test(entry.sha256)) fail(`source set ${label} entry is invalid`);
      if ((label === 'locks') !== lockPath(entry.path)) fail(`source set lock classification is invalid: ${entry.path}`); seen.add(entry.path);
    }
  }
  if (!HASH.test(value.sourceSetSha256) || value.sourceSetSha256 !== sha256(Buffer.from(canonicalJson({ files: value.files, locks: value.locks, dependencyClosure: value.dependencyClosure }), 'utf8'))) fail('source set digest is invalid');
  if (checkCurrent) {
    const current = sourceSet(value.sourceRoot);
    if (!sameJson({ ...value, runtime: current.runtime }, current)) fail('bound source checkout changed or does not cover every tracked source/lock file');
  }
  return value;
}
function expectedCrashCounts(cases = CRASH_CASES) {
  if (!Number.isSafeInteger(cases) || cases < 1 || cases > CRASH_CASES) fail('expected crash cases are invalid');
  return Object.freeze(Object.fromEntries(CRASH_STAGES.map((stage, index) => [
    stage,
    Math.max(0, Math.floor((cases - 1 - index) / CRASH_STAGES.length) + 1),
  ])));
}
function sumCrashStages(counts, stages) {
  return stages.reduce((sum, stage) => sum + counts[stage], 0);
}
function expectedCrashInvariants(counts, cases) {
  const deliveryStages = CRASH_STAGES.slice(-6);
  return Object.freeze({
    noCanonicalCommitBeforeAuthenticatedConfirmation:
      cases - sumCrashStages(counts, deliveryStages),
    authenticatedConfirmationCommitsCanonicalState: counts['confirmed.before_commit'],
    noLostOrDuplicatedReservations:
      sumCrashStages(counts, CRASH_RESERVATION_ASSERTION_STAGES),
    noUnsignedBroadcastableState:
      sumCrashStages(counts, CRASH_UNSIGNED_REJECTION_STAGES),
    noDuplicateSend: sumCrashStages(counts, deliveryStages),
    exactResumabilityOrAbandon: cases,
  });
}
function validateTranscript(value, expectedStatus, expectedSignal, expected, label) {
  exact(value, ['signal', 'status', 'stderr', 'stderrSha256', 'stdout', 'stdoutSha256'], label);
  if (value.status !== expectedStatus || value.signal !== expectedSignal || typeof value.stdout !== 'string' || typeof value.stderr !== 'string' || !HASH.test(value.stdoutSha256) || !HASH.test(value.stderrSha256) || value.stdoutSha256 !== sha256(Buffer.from(value.stdout)) || value.stderrSha256 !== sha256(Buffer.from(value.stderr))) fail(`${label} transcript hash or termination differs`);
  let decoded; try { decoded = parseStrictJson(Buffer.from(value.stdout)); } catch { fail(`${label} stdout is not a strict JSON transcript`); }
  if (!sameJson(decoded, expected) || value.stdout !== `${JSON.stringify(expected)}\n`) fail(`${label} transcript event differs`);
}
function validateExternalCrashCorpus(value) {
  exact(value, ['cases', 'limitations', 'schema'], 'external SIGKILL corpus');
  if (value.schema !== EXTERNAL_CRASH_SCHEMA || !Array.isArray(value.cases) || value.cases.length !== 6 || !Array.isArray(value.limitations) || value.limitations.length !== 2) fail('external SIGKILL corpus identity is invalid');
  const expected = [
    ['sqlite-create-before', 'verify-sqlite-create-before', ['canonical-unchanged', 'operation-presence-exact']],
    ['sqlite-create-after', 'verify-sqlite-create-after', ['canonical-unchanged', 'operation-presence-exact']],
    ['sqlite-reserve-before', 'verify-sqlite-reserve-before', ['canonical-unchanged', 'operation-state-exact', 'note-and-utxo-reservations-exact']],
    ['sqlite-reserve-after', 'verify-sqlite-reserve-after', ['canonical-unchanged', 'operation-state-exact', 'note-and-utxo-reservations-exact']],
    ['delivery-submit-before', 'verify-delivery-submit-before', ['delivery-state-exact', 'duplicate-send-claim-rejected']],
    ['delivery-submit-after', 'verify-delivery-submit-after', ['delivery-state-exact', 'duplicate-send-claim-rejected']],
  ];
  for (const [index, [crashMode, verifyMode, invariants]] of expected.entries()) {
    const item = value.cases[index]; exact(item, ['crash', 'crashMode', 'invariants', 'verify', 'verifyMode'], `external SIGKILL case ${index}`);
    if (item.crashMode !== crashMode || item.verifyMode !== verifyMode || !sameJson(item.invariants, invariants)) fail(`external SIGKILL case ${index} matrix differs`);
    validateTranscript(item.crash, null, 'SIGKILL', { event: 'ready-to-kill', mode: crashMode }, `external SIGKILL case ${index} crash`);
    validateTranscript(item.verify, 0, null, { event: 'verified', mode: verifyMode, invariants }, `external SIGKILL case ${index} verifier`);
  }
  if (!value.limitations.some((item) => typeof item === 'string' && item.includes('does not exercise termination inside those calls'))) fail('external SIGKILL corpus does not disclose its outer-call representativeness gap');
  return value;
}
function validateCrash(value, { expectedCases = CRASH_CASES } = {}) {
  exact(value, ['caseCountsByStage', 'cases', 'discrepancies', 'elapsedMs', 'externalCrashCorpus', 'invariantCounts', 'limitations', 'qualification', 'schema', 'seed', 'storage'], 'crash campaign');
  if (value.schema !== CRASH_SCHEMA || value.qualification !== 'development-only' || value.seed !== 'shieldkit-v2-crash-qualification-20260729' || value.cases !== expectedCases || typeof value.storage !== 'string' || !Array.isArray(value.discrepancies) || value.discrepancies.length !== 0 || !Array.isArray(value.limitations) || value.limitations.length < 2) fail('crash campaign identity or zero-discrepancy boundary is invalid');
  nonnegative(value.elapsedMs, 'crash campaign elapsedMs');
  exact(value.caseCountsByStage, CRASH_STAGES, 'crash campaign caseCountsByStage');
  const expected = expectedCrashCounts(expectedCases); for (const stage of CRASH_STAGES) if (value.caseCountsByStage[stage] !== expected[stage]) fail(`crash campaign stage coverage differs: ${stage}`);
  exact(value.invariantCounts, CRASH_INVARIANT_KEYS, 'crash campaign invariantCounts');
  for (const key of CRASH_INVARIANT_KEYS) nonnegative(value.invariantCounts[key], `crash campaign invariant ${key}`);
  validateExternalCrashCorpus(value.externalCrashCorpus);
  const expectedInvariants = expectedCrashInvariants(expected, expectedCases);
  for (const key of CRASH_INVARIANT_KEYS) {
    if (value.invariantCounts[key] !== expectedInvariants[key]) {
      fail(`crash campaign invariant count differs from its executed predicate stages: ${key}`);
    }
  }
  if (!value.limitations.some((item) => typeof item === 'string' && item.includes('only SIGKILLs an outer child immediately before or after selected complete public calls'))) fail('crash campaign does not disclose its outer-call representativeness gap');
  return value;
}
/** TEST-ONLY: validates real reduced runner output against the same stage-derived contract. */
export function validateV2Q06CrashCampaignForTest(value, expectedCases) {
  return validateCrash(value, { expectedCases });
}
function validateReorg(value) {
  exact(value, ['deepWipeReplay', 'discrepancies', 'elapsedMs', 'invariantCounts', 'limitations', 'maliciousSelfTransfer', 'qualification', 'reorgDepths', 'schema', 'seed', 'sequentialSiblingConflicts', 'storage'], 'reorg campaign');
  if (value.schema !== REORG_SCHEMA || value.qualification !== 'development-only-local-sequential-durability' || value.seed !== 'shieldkit-v2-reorg-sequential-sibling-qualification-20260730' || typeof value.storage !== 'string' || !Array.isArray(value.discrepancies) || value.discrepancies.length !== 0 || !Array.isArray(value.limitations) || value.limitations.length < 4) fail('reorg campaign identity or zero-discrepancy boundary is invalid');
  nonnegative(value.elapsedMs, 'reorg campaign elapsedMs');
  if (!Array.isArray(value.reorgDepths) || value.reorgDepths.length !== REORG_DEPTHS.length || !Array.isArray(value.sequentialSiblingConflicts) || value.sequentialSiblingConflicts.length !== WALLET_COUNTS.length) fail('reorg campaign matrix is incomplete');
  for (const [index, depth] of REORG_DEPTHS.entries()) { const row = value.reorgDepths[index]; exact(row, ['actions', 'depth', 'reopenedAfterEveryConfirmation', 'rollbackHistoryCheckerMatched'], `reorg depth ${depth}`); if (row.depth !== depth || row.actions !== depth || bool(row.reopenedAfterEveryConfirmation, `reorg depth ${depth}.reopenedAfterEveryConfirmation`) !== true || bool(row.rollbackHistoryCheckerMatched, `reorg depth ${depth}.rollbackHistoryCheckerMatched`) !== true) fail(`reorg depth ${depth} coverage differs`); }
  for (const [index, participants] of WALLET_COUNTS.entries()) { const row = value.sequentialSiblingConflicts[index]; exact(row, ['deterministicSequentialSchedule', 'losers', 'participants', 'reopened', 'siblingOperations', 'winner'], `sequential sibling conflict ${participants}`); if (row.participants !== participants || row.siblingOperations !== participants || row.losers !== participants - 1 || row.winner !== `wallet-${participants}-${participants - 1}` || bool(row.reopened, `sequential sibling conflict ${participants}.reopened`) !== true || bool(row.deterministicSequentialSchedule, `sequential sibling conflict ${participants}.deterministicSequentialSchedule`) !== true) fail(`sequential sibling conflict ${participants} coverage differs`); }
  exact(value.maliciousSelfTransfer, ['duplicateNullifierRejected', 'duplicateReservationRejected', 'reopened', 'selfTarget'], 'malicious self transfer');
  for (const [key, item] of Object.entries(value.maliciousSelfTransfer)) if (bool(item, `malicious self transfer.${key}`) !== true) fail('malicious self-transfer matrix differs');
  exact(value.deepWipeReplay, ['actionCorpusBytes', 'actionCorpusSha256', 'actionIds', 'actions', 'authenticatedSnapshotInstalled', 'crossedHundredActionBoundary', 'exactCapturedCorpusIngested', 'rollbackHistoryCheckerMatched', 'sourceDatabaseBytes', 'terminalCanonicalSha256'], 'deep wipe replay');
  if (value.deepWipeReplay.actions !== 101 || value.deepWipeReplay.actionIds !== value.deepWipeReplay.actions || nonnegative(value.deepWipeReplay.actionCorpusBytes, 'deep wipe replay actionCorpusBytes') < 1 || !HASH.test(value.deepWipeReplay.actionCorpusSha256) || !HASH.test(value.deepWipeReplay.terminalCanonicalSha256) || nonnegative(value.deepWipeReplay.sourceDatabaseBytes, 'deep wipe replay sourceDatabaseBytes') < 1 || bool(value.deepWipeReplay.authenticatedSnapshotInstalled, 'deep wipe replay authenticatedSnapshotInstalled') !== true || bool(value.deepWipeReplay.exactCapturedCorpusIngested, 'deep wipe replay exactCapturedCorpusIngested') !== true || bool(value.deepWipeReplay.crossedHundredActionBoundary, 'deep wipe replay crossedHundredActionBoundary') !== true || bool(value.deepWipeReplay.rollbackHistoryCheckerMatched, 'deep wipe replay rollbackHistoryCheckerMatched') !== true) fail('deep wipe/replay coverage differs');
  exact(value.invariantCounts, REORG_INVARIANT_KEYS, 'reorg campaign invariantCounts');
  const expected = { canonicalTipUnchangedBeforeApplyConfirmed: 321, reorgAncestorCanonicalTipMatched: 4, reorgedOperationStateExact: 113, reorgedFundingReservationRetained: 113, reorgAbandonFundingReleased: 113, reorgUndoLogCleared: 4, sequentialSiblingStaleParentRejected: 26, siblingConflictFundingReleased: 26, siblingRebaseFundingReacquired: 26, siblingAbandonFundingReleased: 26, sequentialSiblingWinnerTipPreservedAfterReopen: 4, maliciousDuplicateNullifierRejected: 1, maliciousDuplicateNoteReservationRejected: 1, maliciousAttemptCanonicalTipUnchanged: 1, deepWipeSnapshotCanonicalTipMatched: 1, deepWipeExactCapturedEventIngestions: 101 };
  for (const key of REORG_INVARIANT_KEYS) if (value.invariantCounts[key] !== expected[key]) fail(`reorg campaign invariant differs: ${key}`);
  if (!value.limitations.some((item) => typeof item === 'string' && item.includes('there is no barrier, overlapping call, worker process, or concurrency evidence'))) fail('reorg campaign does not disclose its sequential scheduling boundary');
  if (!value.limitations.some((item) => typeof item === 'string' && item.includes('Same-UID malicious replacement'))) fail('reorg campaign does not disclose its same-UID path-replacement boundary');
  return value;
}
function artifactReference(root, entry, label) {
  exact(entry, ['bytes', 'path', 'role', 'sha256'], label);
  if (typeof entry.role !== 'string' || typeof entry.path !== 'string' || !Number.isSafeInteger(entry.bytes) || entry.bytes < 0 || !HASH.test(entry.sha256)) fail(`${label} is invalid`);
  const path = child(root, entry.path, label); const stat = ownedFile(path, label); const bytes = readFileSync(path);
  if (stat.size !== entry.bytes || bytes.length !== entry.bytes || sha256(bytes) !== entry.sha256) fail(`${label} hash differs`);
  return Object.freeze({ ...entry, absolutePath: path, bytesValue: bytes, value: parseCanonical(bytes, label) });
}
function expectedCommand(name, value) {
  exact(value, ['argv', 'exitStatus', 'name', 'stderrSha256', 'stdoutSha256'], `execution command ${name}`);
  const script = name === 'crash' ? crashScript : reorgScript;
  const expectedLength = name === 'crash' ? 4 : 6;
  if (value.name !== name || !Array.isArray(value.argv) || value.argv.length !== expectedLength || value.argv[0] !== process.execPath || value.argv[1] !== script || value.argv[2] !== '--output' || typeof value.argv[3] !== 'string' || !isAbsolute(value.argv[3]) || value.exitStatus !== 0 || !HASH.test(value.stdoutSha256) || !HASH.test(value.stderrSha256)) fail(`execution command ${name} differs from the public full-campaign command`);
  if (name === 'reorg' && (value.argv[4] !== '--corpus-output' || typeof value.argv[5] !== 'string' || !isAbsolute(value.argv[5]) || value.argv[5] === value.argv[3])) fail('execution command reorg lacks a distinct canonical corpus output');
}
function validateReplayCorpusArtifact(reference, reorg, { replay }) {
  const expected = reorg.deepWipeReplay;
  if (
    reference.bytes !== expected.actionCorpusBytes ||
    reference.sha256 !== expected.actionCorpusSha256
  ) {
    fail('captured recovery corpus artifact differs from the reorg campaign binding');
  }
  if (
    reference.value === null ||
    typeof reference.value !== 'object' ||
    reference.value.schema !== REPLAY_CORPUS_SCHEMA ||
    !Array.isArray(reference.value.events) ||
    reference.value.events.length !== expected.actions
  ) {
    fail('captured recovery corpus schema or action count differs');
  }
  if (!replay) return null;
  const childArguments = [
    reorgScript,
    '--replay-corpus',
    reference.absolutePath,
    '--expected-sha256',
    reference.sha256,
    '--expected-actions',
    String(expected.actions),
  ];
  const replayed = spawnSync(process.execPath, childArguments, {
    cwd: repositoryRoot,
    encoding: 'utf8',
    env: controlledEnvironmentBoundary.node,
    maxBuffer: 4 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (replayed.error || replayed.status !== 0 || replayed.signal) {
    fail(`independent captured recovery corpus replay failed: ${(replayed.stderr || replayed.error?.message || '').trim()}`);
  }
  let result;
  try { result = parseStrictJson(Buffer.from(replayed.stdout)); } catch { fail('independent captured recovery corpus replay emitted invalid JSON'); }
  exact(result, ['actionCorpusBytes', 'actionCorpusSha256', 'actions', 'canonicalTipUnchangedBeforeApplyConfirmed', 'exactCapturedEventIngestions', 'schema', 'terminalCanonicalSha256'], 'independent captured recovery corpus replay result');
  if (
    result.schema !== REPLAY_RESULT_SCHEMA ||
    result.actions !== expected.actions ||
    result.actionCorpusBytes !== expected.actionCorpusBytes ||
    result.actionCorpusSha256 !== expected.actionCorpusSha256 ||
    result.terminalCanonicalSha256 !== expected.terminalCanonicalSha256 ||
    result.canonicalTipUnchangedBeforeApplyConfirmed !== expected.actions ||
    result.exactCapturedEventIngestions !==
      reorg.invariantCounts.deepWipeExactCapturedEventIngestions
  ) {
    fail('independent captured recovery corpus replay differs from campaign evidence');
  }
  return result;
}
function verifyBundle(bundlePath, { verifySource = true, allowTestOnly = false, enforceVerifierRoot = verifySource } = {}) {
  if (verifySource) assertV2Q06SafeHostEnvironment();
  const root = resolve(bundlePath); directDirectory(root, 'bundle root'); const manifestPath = child(root, 'manifest.json', 'manifest'); ownedFile(manifestPath, 'manifest');
  const manifest = parseCanonical(readFileSync(manifestPath), 'manifest'); exact(manifest, ['artifacts', 'schema'], 'manifest');
  if (manifest.schema !== V2_Q06_BUNDLE_SCHEMA || !Array.isArray(manifest.artifacts) || manifest.artifacts.length !== 5) fail('manifest schema or artifact count is invalid');
  const names = new Set(['manifest.json']); const refs = new Map();
  for (const entry of manifest.artifacts) { if (refs.has(entry.role) || names.has(entry.path)) fail('manifest has ambiguous artifact references'); refs.set(entry.role, artifactReference(root, entry, `artifact ${entry.role}`)); names.add(entry.path); }
  if (refs.size !== 5 || !refs.has('source-set') || !refs.has('crash-campaign') || !refs.has('reorg-campaign') || !refs.has('replay-corpus') || !refs.has('execution') || canonicalJson(readdirSync(root).sort()) !== canonicalJson([...names].sort())) fail('bundle has missing or unreferenced artifacts');
  const execution = refs.get('execution').value;
  exact(execution, ['boundaries', 'commands', 'crashCampaignSha256', 'immutableInstall', 'reorgCampaignSha256', 'replayCorpusSha256', 'runtime', 'schema', 'sourceSetSha256', 'testOnly'], 'execution evidence');
  if (execution.schema !== V2_Q06_EVIDENCE_SCHEMA || !Array.isArray(execution.boundaries) || !sameJson(execution.boundaries, Q06_BOUNDARIES) || !HASH.test(execution.sourceSetSha256) || !HASH.test(execution.crashCampaignSha256) || !HASH.test(execution.reorgCampaignSha256) || !HASH.test(execution.replayCorpusSha256) || typeof execution.testOnly !== 'boolean') fail('execution evidence boundary is invalid');
  if (execution.testOnly && !allowTestOnly) fail('test-only Q-06 evidence is nonqualifying and rejected by the public verifier');
  validateRuntime(execution.runtime, verifySource && !execution.testOnly);
  if (!Array.isArray(execution.commands) || (execution.testOnly ? execution.commands.length !== 0 : execution.commands.length !== 2)) fail('execution command set is invalid');
  if (!execution.testOnly) { expectedCommand('crash', execution.commands[0]); expectedCommand('reorg', execution.commands[1]); }
  if (execution.crashCampaignSha256 !== refs.get('crash-campaign').sha256 || execution.reorgCampaignSha256 !== refs.get('reorg-campaign').sha256 || execution.replayCorpusSha256 !== refs.get('replay-corpus').sha256) fail('execution evidence campaign or replay-corpus hashes differ');
  const source = validateSourceRecord(refs.get('source-set').value, { checkCurrent: verifySource && !execution.testOnly, enforceVerifierRoot });
  if (!sameJson(execution.runtime, source.runtime)) fail('execution runtime differs from its bound source runtime');
  if (execution.testOnly) {
    if (execution.immutableInstall !== null) fail('test-only execution must not claim an immutable install');
  } else validateImmutableInstall(execution.immutableInstall, source.dependencyClosure, { checkCurrent: verifySource, root: source.sourceRoot });
  if (execution.sourceSetSha256 !== source.sourceSetSha256) fail('execution evidence source binding differs');
  validateCrash(refs.get('crash-campaign').value);
  const reorg = validateReorg(refs.get('reorg-campaign').value);
  const replay = validateReplayCorpusArtifact(
    refs.get('replay-corpus'),
    reorg,
    { replay: !execution.testOnly },
  );
  return Object.freeze({ schema: V2_Q06_RESULT_SCHEMA, bundlePath: root, status: execution.testOnly ? 'verified-test-only-nonqualifying' : 'verified-locally-self-consistent-q06-evidence', gitCommit: source.gitCommit, gitTree: source.gitTree, sourceSetSha256: source.sourceSetSha256, replayCorpusSha256: refs.get('replay-corpus').sha256, replayedRecoveryCorpus: replay !== null, testOnly: execution.testOnly, boundaries: Q06_BOUNDARIES });
}
function runPublicCampaign(root, bundle, name, script) {
  const output = child(bundle, `.${name}-raw-${process.pid}-${Date.now()}.json`, 'campaign staging output');
  const corpusOutput = name === 'reorg'
    ? child(bundle, `.reorg-corpus-raw-${process.pid}-${Date.now()}.json`, 'replay corpus staging output')
    : null;
  const childArguments = [script, '--output', output, ...(corpusOutput === null ? [] : ['--corpus-output', corpusOutput])];
  const argv = [process.execPath, ...childArguments];
  const result = spawnSync(process.execPath, childArguments, {
    cwd: root,
    encoding: 'utf8',
    env: controlledEnvironmentBoundary.node,
    maxBuffer: 4 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error || result.status !== 0 || result.signal) fail(`${name} full public campaign failed: ${(result.stderr || result.error?.message || '').trim()}`);
  try {
    ownedFile(output, `${name} campaign staging output`);
    const value = parseStrictJson(readFileSync(output));
    let corpusBytes = null;
    if (corpusOutput !== null) {
      ownedFile(corpusOutput, 'replay corpus staging output');
      corpusBytes = readFileSync(corpusOutput);
    }
    return Object.freeze({ value, corpusBytes, command: Object.freeze({ name, argv, exitStatus: 0, stdoutSha256: sha256(Buffer.from(result.stdout)), stderrSha256: sha256(Buffer.from(result.stderr)) }) });
  } finally {
    if (existsSync(output)) unlinkSync(output);
    if (corpusOutput !== null && existsSync(corpusOutput)) unlinkSync(corpusOutput);
  }
}
function createBundle({ outputDirectory, stagingDirectory = outputDirectory, source, crash, reorg, replayCorpus, commands, immutableInstall = null, testOnly }) {
  const parent = resolve(outputDirectory); const stageParent = resolve(stagingDirectory); directDirectory(parent, 'output directory'); directDirectory(stageParent, 'bundle staging directory');
  const name = `q06-commit-bound-${Date.now()}-${process.pid}`; const root = join(stageParent, name); const promoted = join(parent, name);
  if (existsSync(root) || existsSync(promoted)) fail('refusing to overwrite Q-06 bundle'); directDirectory(root, 'bundle root', true);
  try {
    validateSourceRecord(source); validateCrash(crash); validateReorg(reorg);
    if (!Buffer.isBuffer(replayCorpus)) fail('captured recovery replay corpus bytes are required');
    const sourceArtifact = writeAtomic(root, 'source-set.json', source);
    const crashArtifact = writeAtomic(root, 'crash-campaign.json', crash);
    const reorgArtifact = writeAtomic(root, 'reorg-campaign.json', reorg);
    const replayCorpusArtifact = writeAtomicBytes(root, 'replay-corpus.json', replayCorpus);
    validateReplayCorpusArtifact(
      Object.freeze({
        ...replayCorpusArtifact,
        absolutePath: child(root, replayCorpusArtifact.path, 'replay corpus artifact'),
        bytesValue: replayCorpus,
        value: parseCanonical(replayCorpus, 'replay corpus artifact'),
      }),
      reorg,
      { replay: false },
    );
    if (testOnly ? immutableInstall !== null : immutableInstall === null) fail('immutable install evidence boundary is invalid');
    if (!testOnly) validateImmutableInstall(immutableInstall, source.dependencyClosure, { checkCurrent: true, root: source.sourceRoot });
    const execution = Object.freeze({ schema: V2_Q06_EVIDENCE_SCHEMA, sourceSetSha256: source.sourceSetSha256, runtime: source.runtime, commands, immutableInstall, crashCampaignSha256: crashArtifact.sha256, reorgCampaignSha256: reorgArtifact.sha256, replayCorpusSha256: replayCorpusArtifact.sha256, testOnly, boundaries: Q06_BOUNDARIES });
    const executionArtifact = writeAtomic(root, 'execution.json', execution);
    const manifest = Object.freeze({ schema: V2_Q06_BUNDLE_SCHEMA, artifacts: [Object.freeze({ role: 'source-set', ...sourceArtifact }), Object.freeze({ role: 'crash-campaign', ...crashArtifact }), Object.freeze({ role: 'reorg-campaign', ...reorgArtifact }), Object.freeze({ role: 'replay-corpus', ...replayCorpusArtifact }), Object.freeze({ role: 'execution', ...executionArtifact })] });
    writeAtomic(root, 'manifest.json', manifest); fsyncDirectory(root); fsyncDirectory(stageParent);
    const stagedResult = verifyBundle(root, { verifySource: !testOnly, allowTestOnly: testOnly });
    // Campaign children only ever wrote beneath private staging. Re-read all
    // tracked bytes, locks, and the exact runtime immediately before rename.
    if (!testOnly && !sameJson(source, sourceSet(repositoryRoot))) fail('source checkout or runtime changed before Q-06 bundle promotion');
    if (stageParent !== parent) {
      // Final pre-promotion inventory pass: bundle/source verification above
      // and this content-addressed dependency recheck all complete privately.
      validateImmutableInstall(immutableInstall, source.dependencyClosure, { checkCurrent: true, root: source.sourceRoot });
      renameSync(root, promoted); fsyncDirectory(parent); fsyncDirectory(stageParent);
      return Object.freeze({ ...stagedResult, bundlePath: promoted });
    }
    fsyncDirectory(parent);
    return verifyBundle(root, { verifySource: false, allowTestOnly: true });
  } catch (error) { try { rmSync(root, { recursive: true, force: true }); } catch { /* retain original failure */ } throw error; }
}
export async function runV2Q06CommitBoundEvidence(options = {}) {
  if (options === null || Array.isArray(options) || typeof options !== 'object' || Object.keys(options).some((key) => key !== 'outputDirectory')) fail('public Q-06 generator accepts only outputDirectory and rejects injected/reduced campaign seams');
  assertV2Q06SafeHostEnvironment();
  const sourceBeforeInstall = sourceSet(repositoryRoot); const parent = outputParent(options.outputDirectory); const provisional = join(parent, `.q06-staging-${Date.now()}-${process.pid}`);
  // The staging directory is private and short-lived; all published artifacts
  // are canonicalized and sealed by createBundle.
  directDirectory(provisional, 'campaign staging directory', true);
  try {
    const immutableInstall = immutableInstallRecord(repositoryRoot, sourceBeforeInstall.dependencyClosure, provisional);
    const source = sourceSet(repositoryRoot);
    if (!sameJson(sourceBeforeInstall, source)) fail('source checkout or runtime changed during immutable dependency installation');
    const crash = runPublicCampaign(repositoryRoot, provisional, 'crash', crashScript);
    const reorg = runPublicCampaign(repositoryRoot, provisional, 'reorg', reorgScript);
    if (git(repositoryRoot, ['status', '--porcelain=v1', '--untracked-files=all']) !== '' || !sameJson(source, sourceSet(repositoryRoot))) fail('source checkout or runtime changed after Q-06 campaign execution');
    const result = createBundle({ outputDirectory: parent, stagingDirectory: provisional, source, crash: crash.value, reorg: reorg.value, replayCorpus: reorg.corpusBytes, commands: [crash.command, reorg.command], immutableInstall, testOnly: false });
    if (git(repositoryRoot, ['status', '--porcelain=v1', '--untracked-files=all']) !== '' || !sameJson(source, sourceSet(repositoryRoot))) fail('source checkout changed during Q-06 evidence generation');
    return result;
  } finally { if (existsSync(provisional)) rmSync(provisional, { recursive: true, force: true }); }
}
/** TEST-ONLY: injected fixtures are explicitly nonqualifying and never public evidence. */
export async function runV2Q06CommitBoundEvidenceForTest({ outputDirectory, source, crash, reorg, replayCorpus } = {}) {
  return createBundle({ outputDirectory, source, crash, reorg, replayCorpus, commands: [], testOnly: true });
}
export function verifyV2Q06CommitBoundBundle(bundlePath) { return verifyBundle(bundlePath); }
/** TEST-ONLY: permits the visibly nonqualifying fixture boundary without a live checkout. */
export function verifyV2Q06CommitBoundBundleForTest(bundlePath) { return verifyBundle(bundlePath, { verifySource: false, allowTestOnly: true }); }
/** TEST-ONLY: exercises the public checkout-root binding without claiming a live source verification. */
export function verifyV2Q06CheckoutRootBindingForTest(bundlePath) { return verifyBundle(bundlePath, { verifySource: false, allowTestOnly: true, enforceVerifierRoot: true }); }
export function parseV2Q06CommitBoundArguments(argv, cwd = process.cwd()) {
  if (!Array.isArray(argv) || argv.length !== 2 || !['--output-directory', '--verify'].includes(argv[0]) || typeof argv[1] !== 'string' || argv[1].startsWith('--')) fail('usage: v2-q06-commit-bound-evidence.mjs --output-directory <existing-mode-0700-directory> | --verify <bundle>');
  return Object.freeze(argv[0] === '--verify' ? { mode: 'verify', bundlePath: resolve(cwd, argv[1]) } : { mode: 'run', outputDirectory: resolve(cwd, argv[1]) });
}
export function publicV2Q06GeneratorOptions(argumentsValue) {
  exact(argumentsValue, ['mode', 'outputDirectory'], 'Q-06 run CLI arguments');
  if (argumentsValue.mode !== 'run' || typeof argumentsValue.outputDirectory !== 'string') fail('Q-06 run CLI arguments are invalid');
  return Object.freeze({ outputDirectory: argumentsValue.outputDirectory });
}
// TEST-ONLY fixture builder; it cannot fabricate a public bundle because the
// public verifier rejects execution.testOnly before accepting any provenance.
export function q06TestFixtures() {
  const files = [Object.freeze({ path: 'test-source.mjs', mode: '100644', blob: 'a'.repeat(40), bytes: 1, sha256: sha256('x') })]; const locks = [];
  const dependencyClosure = Object.freeze({ schema: DEPENDENCY_CLOSURE_SCHEMA, lockfilePath: 'package-lock.json', lockfileSha256: 'd'.repeat(64), packageJsonSha256: 'e'.repeat(64), lockfileVersion: 3, packageCount: 1, closureSha256: 'f'.repeat(64) });
  const source = Object.freeze({ schema: V2_Q06_SOURCE_SET_SCHEMA, sourceRoot: '/test/q06-source', gitCommit: 'b'.repeat(40), gitTree: 'c'.repeat(40), runtime: runtimeRecord(), files, locks, dependencyClosure, sourceSetSha256: sha256(Buffer.from(canonicalJson({ files, locks, dependencyClosure }))) });
  const counts = expectedCrashCounts(); const expectedInvariants = expectedCrashInvariants(counts, CRASH_CASES);
  const transcript = (value, status, signal) => { const stdout = `${JSON.stringify(value)}\n`; return Object.freeze({ stdout, stderr: '', stdoutSha256: sha256(Buffer.from(stdout)), stderrSha256: sha256(Buffer.alloc(0)), status, signal }); };
  const externalCases = [
    ['sqlite-create-before', 'verify-sqlite-create-before', ['canonical-unchanged', 'operation-presence-exact']], ['sqlite-create-after', 'verify-sqlite-create-after', ['canonical-unchanged', 'operation-presence-exact']],
    ['sqlite-reserve-before', 'verify-sqlite-reserve-before', ['canonical-unchanged', 'operation-state-exact', 'note-and-utxo-reservations-exact']], ['sqlite-reserve-after', 'verify-sqlite-reserve-after', ['canonical-unchanged', 'operation-state-exact', 'note-and-utxo-reservations-exact']],
    ['delivery-submit-before', 'verify-delivery-submit-before', ['delivery-state-exact', 'duplicate-send-claim-rejected']], ['delivery-submit-after', 'verify-delivery-submit-after', ['delivery-state-exact', 'duplicate-send-claim-rejected']],
  ].map(([crashMode, verifyMode, invariants]) => Object.freeze({ crashMode, verifyMode, invariants, crash: transcript({ event: 'ready-to-kill', mode: crashMode }, null, 'SIGKILL'), verify: transcript({ event: 'verified', mode: verifyMode, invariants }, 0, null) }));
  const externalCrashCorpus = Object.freeze({ schema: EXTERNAL_CRASH_SCHEMA, cases: externalCases, limitations: ['SIGKILL is delivered to an outer child immediately before or after selected complete public store/journal calls; it does not exercise termination inside those calls, transaction internals, power-loss, or filesystem-fault semantics.', 'test-only fixture'] });
  const crash = Object.freeze({ schema: CRASH_SCHEMA, qualification: 'development-only', seed: 'shieldkit-v2-crash-qualification-20260729', cases: CRASH_CASES, caseCountsByStage: counts, invariantCounts: expectedInvariants, externalCrashCorpus, discrepancies: [], elapsedMs: 0, storage: 'test-only', limitations: ['The 10,000-case deterministic in-process matrix verifies injected rollback/resume hooks. Its six-case companion only SIGKILLs an outer child immediately before or after selected complete public calls; neither covers termination inside those calls, transaction internals, power-loss, or filesystem faults.', 'test-only fixture'] });
  const replayCorpus = Buffer.from(canonicalJson(Object.freeze({ schema: REPLAY_CORPUS_SCHEMA, events: Array.from({ length: 101 }, () => Object.freeze({})) })), 'utf8');
  const replayCorpusSha256 = sha256(replayCorpus);
  const reorg = Object.freeze({ schema: REORG_SCHEMA, qualification: 'development-only-local-sequential-durability', seed: 'shieldkit-v2-reorg-sequential-sibling-qualification-20260730', reorgDepths: REORG_DEPTHS.map((depth) => ({ depth, actions: depth, reopenedAfterEveryConfirmation: true, rollbackHistoryCheckerMatched: true })), sequentialSiblingConflicts: WALLET_COUNTS.map((participants) => ({ participants, siblingOperations: participants, losers: participants - 1, winner: `wallet-${participants}-${participants - 1}`, reopened: true, deterministicSequentialSchedule: true })), maliciousSelfTransfer: { selfTarget: true, duplicateNullifierRejected: true, duplicateReservationRejected: true, reopened: true }, deepWipeReplay: { actions: 101, sourceDatabaseBytes: 1, authenticatedSnapshotInstalled: true, actionIds: 101, actionCorpusBytes: replayCorpus.length, actionCorpusSha256: replayCorpusSha256, crossedHundredActionBoundary: true, exactCapturedCorpusIngested: true, rollbackHistoryCheckerMatched: true, terminalCanonicalSha256: '2'.repeat(64) }, invariantCounts: { canonicalTipUnchangedBeforeApplyConfirmed: 321, reorgAncestorCanonicalTipMatched: 4, reorgedOperationStateExact: 113, reorgedFundingReservationRetained: 113, reorgAbandonFundingReleased: 113, reorgUndoLogCleared: 4, sequentialSiblingStaleParentRejected: 26, siblingConflictFundingReleased: 26, siblingRebaseFundingReacquired: 26, siblingAbandonFundingReleased: 26, sequentialSiblingWinnerTipPreservedAfterReopen: 4, maliciousDuplicateNullifierRejected: 1, maliciousDuplicateNoteReservationRejected: 1, maliciousAttemptCanonicalTipUnchanged: 1, deepWipeSnapshotCanonicalTipMatched: 1, deepWipeExactCapturedEventIngestions: 101 }, storage: 'test-only', elapsedMs: 0, discrepancies: [], limitations: ['test-only', 'test-only', 'Sibling conflicts are scheduled deterministically and sequentially in one process; there is no barrier, overlapping call, worker process, or concurrency evidence.', 'Same-UID malicious replacement of the corpus or database path during measurement is out of scope.'] });
  return Object.freeze({ source, crash, reorg, replayCorpus });
}
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try { const args = parseV2Q06CommitBoundArguments(process.argv.slice(2)); const result = args.mode === 'verify' ? verifyV2Q06CommitBoundBundle(args.bundlePath) : await runV2Q06CommitBoundEvidence(publicV2Q06GeneratorOptions(args)); process.stdout.write(`${canonicalJson(result)}\n`); }
  catch (error) { process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; }
}
