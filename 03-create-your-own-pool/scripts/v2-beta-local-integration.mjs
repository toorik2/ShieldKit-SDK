#!/usr/bin/env node

/**
 * Build and independently verify one private, local-only V2 beta evidence
 * root. This is deliberately a custody and qualification boundary, not an
 * instance-descriptor, pool launcher, broadcaster, or release mechanism.
 */
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  chmod, lstat, mkdir, open, readdir, realpath,
} from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  canonicalizeJcs, deriveProfileId, validateProfileCore,
} from '../packages/profile/v2/profile-core.mjs';
import {
  createV2BetaLocalProfilePackage, deriveV2BetaLocalInstanceId,
  deriveV2BetaLocalProfileCore, validateV2BetaLocalProfilePackage,
  V2_BETA_LOCAL_ELIGIBILITY, V2_BETA_LOCAL_FALSE_CLAIMS,
} from '../packages/profile/v2/beta-local-profile.mjs';
import {
  runV2BetaLocalPersistenceRecovery,
  verifyV2BetaLocalPersistenceRecovery,
} from '../packages/kit/v2/beta-local-persistence-recovery.mjs';
import {
  buildDeterministicDirectV2Chain,
} from './v2-circuit-model.mjs';
import {
  createV2BetaLocalProvenancePin, runBetaProofQualification,
  validateV2BetaLocalProvenancePin, verifyBetaProofQualification,
} from './v2-beta-proof-qualification.mjs';
import {
  resolveV2BetaSingleContributorHistoricalCeremony,
  V2_BETA_SINGLE_CONTRIBUTOR_FALSE_CLAIMS,
} from './v2-beta-single-contributor-ceremony.mjs';
import {
  parseBetaOptions, runPf10LibauthQualification,
} from './v2-pf10-libauth-qualification.mjs';
import {
  verifyPf10BetaLibauthQualification,
} from './v2-pf10-beta-libauth-qualification.mjs';
import {
  runV2Pf10BetaRuntime, verifyV2Pf10BetaRuntime,
  V2_PF10_BETA_RUNTIME_MANIFEST,
} from './v2-pf10-beta-runtime.mjs';

const ROOT = path.resolve(import.meta.dirname, '../..');
const HASH = /^[0-9a-f]{64}$/u;
const COMPLETION_FILE = 'beta-local-complete.json';
const INVENTORY_FILE = 'private-inventory.json';
const SCHEMA = 'shieldkit-v2-direct-beta-local-integration-v1';
const STATUS = 'beta-single-contributor-local-integration-verified-unqualified';
const PRIVATE_DIR_MODE = 0o700;
const PRIVATE_FILE_MODE = 0o600;
const CARRIER_COUNT = 10;
const MAXIMUM_LIVE_NOTES = '32';
const DENOMINATION_SATS = '10000000';

export class V2BetaLocalIntegrationError extends Error {
  constructor(message) { super(message); this.name = 'V2BetaLocalIntegrationError'; }
}
const fail = (message) => { throw new V2BetaLocalIntegrationError(message); };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonicalBytes = (value) => Buffer.from(canonicalizeJcs(value), 'utf8');
const jsonHash = (value) => sha256(canonicalBytes(value));

function assertSafeRuntime() {
  const allowedExecArguments = new Set([
    '--test', '--test-concurrency=1', '--test-reporter=tap',
  ]);
  if (process.execArgv.some((entry) => !allowedExecArguments.has(entry))) {
    fail('beta integration refuses Node preload, loader, inspector, or evaluator arguments');
  }
  const contaminated = Object.keys(process.env).filter((name) =>
    name === 'NODE_OPTIONS'
      || name === 'NODE_PATH'
      || name === 'NODE_V8_COVERAGE'
      || name.startsWith('LD_')
      || name.startsWith('DYLD_'));
  if (contaminated.length !== 0) {
    fail(`beta integration refuses ambient loader controls: ${contaminated.sort().join(',')}`);
  }
}

function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) fail(`${label} must be a plain object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown properties`);
  return value;
}
function boundedAbsolute(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || path.resolve(value) !== value) fail(`${label} must be an absolute normalized path`);
  return value;
}
function repoOutput(value, label) {
  const resolved = path.resolve(value); const relative = path.relative(ROOT, resolved);
  if (relative === '' || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) fail(`${label} must be strictly below this ShieldKit checkout`);
  if (!relative.startsWith(`.codex-build${path.sep}`)) fail(`${label} must be below the private .codex-build directory`);
  return resolved;
}
function relativePath(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\\') || value.startsWith('/') || value.split('/').some((part) => part === '' || part === '.' || part === '..')) fail(`${label} must be a normalized relative POSIX path`);
  return value;
}
async function exists(filename) {
  try { await lstat(filename); return true; } catch (error) { if (error?.code === 'ENOENT') return false; throw error; }
}
async function assertPrivateDirectory(filename, label) {
  const meta = await lstat(filename);
  if (!meta.isDirectory() || meta.isSymbolicLink() || (meta.mode & 0o077) !== 0 || await realpath(filename) !== filename) fail(`${label} must be a private canonical directory`);
  return meta;
}
const sameFile = (left, right) => left.dev === right.dev
  && left.ino === right.ino
  && left.size === right.size
  && left.mtimeNs === right.mtimeNs
  && left.ctimeNs === right.ctimeNs;
async function measureRegular(filename, label, { readBytes = false } = {}) {
  const resolved = path.resolve(filename);
  const initial = await lstat(resolved, { bigint: true });
  if (!initial.isFile() || initial.isSymbolicLink() || initial.nlink !== 1n
      || initial.size <= 0n || (initial.mode & 0o077n) !== 0n
      || await realpath(resolved) !== resolved) {
    fail(`${label} must be a private nonempty canonical single-link regular file`);
  }
  const handle = await open(
    resolved,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
  );
  let bytes;
  let byteLength = 0;
  const digest = createHash('sha256');
  const chunks = readBytes ? [] : undefined;
  try {
    const before = await handle.stat({ bigint: true });
    if (!sameFile(initial, before)) fail(`${label} changed before it was read`);
    for await (const chunk of handle.createReadStream({
      autoClose: false,
      highWaterMark: 1024 * 1024,
    })) {
      digest.update(chunk);
      byteLength += chunk.length;
      if (readBytes) chunks.push(Buffer.from(chunk));
    }
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(resolved, { bigint: true });
    if (!sameFile(before, after) || !sameFile(after, pathAfter)
        || BigInt(byteLength) !== after.size
        || await realpath(resolved) !== resolved) {
      fail(`${label} changed while it was read`);
    }
    bytes = readBytes ? Buffer.concat(chunks, byteLength) : undefined;
  } finally {
    await handle.close();
  }
  return Object.freeze({
    byteLength,
    filename: resolved,
    sha256: digest.digest('hex'),
    ...(readBytes ? { bytes } : {}),
  });
}
async function readRegular(filename, label, { canonicalJson = false } = {}) {
  const measured = await measureRegular(filename, label, { readBytes: true });
  const { bytes } = measured;
  let value;
  if (canonicalJson) {
    try { value = JSON.parse(bytes.toString('utf8')); } catch (error) { fail(`${label} is not JSON: ${error.message}`); }
    if (!bytes.equals(canonicalBytes(value))) fail(`${label} must be exact canonical JCS`);
  }
  return Object.freeze({ ...measured, ...(canonicalJson ? { value } : {}) });
}
async function writePrivate(filename, bytes) {
  await mkdir(path.dirname(filename), { recursive: true, mode: PRIVATE_DIR_MODE });
  const handle = await open(filename, 'wx', PRIVATE_FILE_MODE);
  try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
}
async function writeJson(filename, value) { await writePrivate(filename, canonicalBytes(value)); }
async function copyPrivate(source, target, label) {
  await mkdir(path.dirname(target), { recursive: true, mode: PRIVATE_DIR_MODE });
  const resolvedSource = path.resolve(source);
  const sourceBefore = await lstat(resolvedSource, { bigint: true });
  if (!sourceBefore.isFile() || sourceBefore.isSymbolicLink()
      || sourceBefore.nlink !== 1n || sourceBefore.size <= 0n
      || (sourceBefore.mode & 0o077n) !== 0n
      || await realpath(resolvedSource) !== resolvedSource) {
    fail(`${label} must be a private canonical single-link file`);
  }
  const sourceHandle = await open(
    resolvedSource,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
  );
  const targetHandle = await open(target, 'wx', PRIVATE_FILE_MODE);
  const digest = createHash('sha256');
  let byteLength = 0;
  try {
    const openedSource = await sourceHandle.stat({ bigint: true });
    if (!sameFile(sourceBefore, openedSource)) {
      fail(`${label} changed before copying`);
    }
    for await (const chunk of sourceHandle.createReadStream({
      autoClose: false,
      highWaterMark: 1024 * 1024,
    })) {
      digest.update(chunk);
      byteLength += chunk.length;
      let offset = 0;
      while (offset < chunk.length) {
        const { bytesWritten } = await targetHandle.write(
          chunk,
          offset,
          chunk.length - offset,
        );
        if (bytesWritten <= 0) fail(`${label} copy made no progress`);
        offset += bytesWritten;
      }
    }
    await targetHandle.sync();
    const sourceAfter = await sourceHandle.stat({ bigint: true });
    const pathAfter = await lstat(resolvedSource, { bigint: true });
    if (!sameFile(openedSource, sourceAfter)
        || !sameFile(sourceAfter, pathAfter)
        || BigInt(byteLength) !== sourceAfter.size) {
      fail(`${label} changed while copying`);
    }
  } finally {
    await Promise.allSettled([sourceHandle.close(), targetHandle.close()]);
  }
  await chmod(target, PRIVATE_FILE_MODE);
  const copied = await measureRegular(target, `${label} copy`);
  if (copied.sha256 !== digest.digest('hex')
      || copied.byteLength !== byteLength) {
    fail(`${label} copy hash differs from source`);
  }
  return copied;
}
async function walkFiles(directory, prefix = '') {
  const entries = await readdir(directory, { withFileTypes: true }); const result = [];
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const relative = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    const filename = path.join(directory, entry.name); const meta = await lstat(filename);
    if (entry.isDirectory()) {
      if (meta.isSymbolicLink() || (meta.mode & 0o077) !== 0) fail(`unsafe directory in beta output: ${relative}`);
      result.push(...await walkFiles(filename, relative));
    } else if (entry.isFile()) {
      if (meta.isSymbolicLink() || meta.nlink !== 1 || (meta.mode & 0o077) !== 0) fail(`unsafe file in beta output: ${relative}`);
      result.push(relative);
    } else fail(`unsafe filesystem entry in beta output: ${relative}`);
  }
  return result;
}
async function inventory(directory, { exclude = new Set() } = {}) {
  const files = await walkFiles(directory); const entries = [];
  for (const relative of files) {
    if (exclude.has(relative)) continue;
    const source = await measureRegular(path.join(directory, relative), `inventory ${relative}`);
    entries.push(Object.freeze({ bytes: source.byteLength, path: relative, sha256: source.sha256 }));
  }
  return Object.freeze(entries.sort((a, b) => a.path.localeCompare(b.path)));
}

const BUILD_OPTIONS = Object.freeze({
  '--ceremony-dir': 'ceremonyDirectory', '--b01-manifest': 'b01Manifest',
  '--b01-runtime': 'b01Runtime', '--output': 'outputDirectory',
  '--temporary-root': 'temporaryRoot',
});
export function parseV2BetaLocalIntegrationArguments(argv, cwd = process.cwd()) {
  if (!Array.isArray(argv) || argv.length % 2 !== 0) fail('beta integration arguments must be complete option/value pairs');
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const option = argv[index]; const key = BUILD_OPTIONS[option]; const value = argv[index + 1];
    if (key === undefined || Object.hasOwn(values, key) || typeof value !== 'string' || value.length === 0 || value.startsWith('--')) fail(`invalid or duplicate beta integration option: ${String(option)}`);
    values[key] = path.resolve(cwd, value);
  }
  for (const [option, key] of Object.entries(BUILD_OPTIONS)) if (!Object.hasOwn(values, key)) fail(`missing required beta integration option: ${option}`);
  for (const key of ['ceremonyDirectory', 'b01Manifest', 'b01Runtime', 'temporaryRoot']) boundedAbsolute(values[key], key);
  return Object.freeze({ ...values, outputDirectory: repoOutput(values.outputDirectory, 'output directory') });
}
export function parseV2BetaLocalIntegrationVerifyArguments(argv, cwd = process.cwd()) {
  if (!Array.isArray(argv) || argv.length !== 4 || argv[0] !== '--verify' || argv[2] !== '--temporary-root') fail('usage: --verify <output-directory> --temporary-root <absolute-directory>');
  const outputDirectory = repoOutput(path.resolve(cwd, argv[1]), 'output directory');
  const temporaryRoot = path.resolve(cwd, argv[3]); boundedAbsolute(temporaryRoot, 'temporary root');
  return Object.freeze({ outputDirectory, temporaryRoot });
}

function artifactPath(runtime, id) {
  const artifacts = runtime?.artifactManifest?.artifacts;
  if (!Array.isArray(artifacts)) fail('B01 runtime artifact manifest is absent');
  const entry = artifacts.find((candidate) => candidate?.id === id);
  if (entry === undefined || typeof entry.path !== 'string' || !HASH.test(entry.sha256)) fail(`B01 runtime artifact is absent or invalid: ${id}`);
  return entry;
}
async function bindB01({ b01Manifest, b01Runtime, ceremonyResolution }) {
  const manifest = await readRegular(b01Manifest, 'B01 manifest', { canonicalJson: true });
  if (`sha256:${manifest.sha256}` !== ceremonyResolution.b01ManifestSha256) fail('B01 manifest differs from the ceremony-bound B01 manifest hash');
  const runtime = manifest.value.runtime;
  if (runtime === null || typeof runtime !== 'object' || Array.isArray(runtime)) fail('B01 manifest runtime is absent');
  const suppliedRuntime = path.resolve(b01Runtime); await assertPrivateDirectory(suppliedRuntime, 'supplied B01 runtime');
  const runtimeManifest = await readRegular(path.join(suppliedRuntime, 'runtime-build-manifest.json'), 'B01 runtime build manifest', { canonicalJson: true });
  if (runtime.manifestSha256 !== runtimeManifest.sha256) fail('B01 runtime build manifest does not match the supplied B01 manifest');
  const artifactIds = new Set();
  const artifactPaths = new Set();
  for (const entry of runtime.artifactManifest?.artifacts ?? []) {
    if (typeof entry?.path !== 'string' || !HASH.test(entry.sha256)) fail('B01 artifact manifest entry is invalid');
    const relative = relativePath(entry.path, 'B01 artifact path');
    if (typeof entry.id !== 'string' || artifactIds.has(entry.id)
        || artifactPaths.has(relative)) {
      fail('B01 artifact manifest contains duplicate identities or paths');
    }
    artifactIds.add(entry.id);
    artifactPaths.add(relative);
    const artifact = await measureRegular(path.join(suppliedRuntime, relative), `B01 artifact ${relative}`);
    if (artifact.sha256 !== entry.sha256) fail(`B01 runtime artifact differs from manifest: ${relative}`);
  }
  const expectedRuntimeFiles = new Set([
    'runtime-build-manifest.json',
    ...artifactPaths,
  ]);
  const actualRuntimeFiles = new Set(await walkFiles(suppliedRuntime));
  if (actualRuntimeFiles.size !== expectedRuntimeFiles.size
      || [...actualRuntimeFiles].some((entry) => !expectedRuntimeFiles.has(entry))) {
    fail('B01 runtime inventory is not exhaustive');
  }
  const needed = Object.freeze({
    profileCore: artifactPath(runtime, 'profile-core'), witnessWasm: artifactPath(runtime, 'proof-witness-wasm'),
    circuitSymbols: artifactPath(runtime, 'proof-circuit-symbols'), initialZkey: artifactPath(runtime, 'proof-initial-proving-key'),
    powersOfTau: artifactPath(runtime, 'proof-powers-of-tau'), r1cs: artifactPath(runtime, 'proof-r1cs'),
  });
  const proof = runtime.proofArtifacts;
  for (const [name, proofName] of Object.entries({
    witnessWasm: 'witnessWasm',
    circuitSymbols: 'circuitSymbols',
    initialZkey: 'initialProvingKey',
    powersOfTau: 'powersOfTau',
    r1cs: 'r1cs',
  })) {
    if (proof?.[proofName] !== needed[name].sha256) {
      fail(`B01 proof artifact pin differs: ${name}`);
    }
  }
  return Object.freeze({ manifest, runtime: runtimeManifest, runtimeDirectory: suppliedRuntime, needed });
}

async function copyCeremony(source, target) {
  if (await exists(target)) fail('ceremony custody directory already exists');
  const sourceMeta = await lstat(source);
  if (!sourceMeta.isDirectory() || sourceMeta.isSymbolicLink() || await realpath(source) !== source) fail('source ceremony must be a canonical directory');
  await mkdir(target, { mode: PRIVATE_DIR_MODE });
  async function recurse(from, to) {
    for (const entry of await readdir(from, { withFileTypes: true })) {
      const sourceFile = path.join(from, entry.name); const targetFile = path.join(to, entry.name); const meta = await lstat(sourceFile);
      if (entry.isDirectory()) {
        if (meta.isSymbolicLink()) fail(`ceremony contains symlinked directory: ${entry.name}`);
        await mkdir(targetFile, { mode: PRIVATE_DIR_MODE }); await recurse(sourceFile, targetFile);
      } else if (entry.isFile()) {
        if (meta.isSymbolicLink() || meta.nlink !== 1) fail(`ceremony contains unsafe file: ${entry.name}`);
        await copyPrivate(sourceFile, targetFile, `ceremony ${entry.name}`);
      } else fail(`ceremony contains unsafe entry: ${entry.name}`);
    }
  }
  await recurse(source, target);
}
function makePersistenceActions({ profileId, instanceId }) {
  const fixture = buildDeterministicDirectV2Chain({
    profileId,
    instanceId,
    maximumLiveNotes: MAXIMUM_LIVE_NOTES,
  });
  return Object.freeze([
    'deposit', 'transfer', 'withdrawal',
  ].map((kind, expectedActionSequence) => Object.freeze({
    expectedActionSequence,
    kind,
    operationId: `v2op:${sha256(Buffer.from(
      `ShieldKit beta local private action ${profileId} ${instanceId} ${kind}`,
      'utf8',
    ))}`,
    output: fixture.preparedActions[kind].output,
    publicNullifier: fixture.preparedActions[kind].publicNullifier,
  })));
}
async function gitBinding() {
  const { execFile } = await import('node:child_process');
  const call = (args) => new Promise((resolve, reject) => execFile(
    '/usr/bin/git',
    [
      '--no-replace-objects',
      '-c', 'core.fsmonitor=false',
      '-c', 'core.hooksPath=/dev/null',
      '-c', 'core.pager=cat',
      '-c', 'include.path=/dev/null',
      '-C', ROOT,
      ...args,
    ],
    {
      cwd: ROOT,
      maxBuffer: 16 * 1024 * 1024,
      env: {
        HOME: '/nonexistent',
        LANG: 'C',
        LC_ALL: 'C',
        PATH: '/usr/bin:/bin',
        GIT_CONFIG_COUNT: '0',
        GIT_CONFIG_GLOBAL: '/dev/null',
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_OPTIONAL_LOCKS: '0',
        GIT_TERMINAL_PROMPT: '0',
      },
    },
    (error, stdout) => error === null ? resolve(stdout.trim()) : reject(error),
  ));
  const [commit, tree, status] = await Promise.all([
    call(['rev-parse', 'HEAD^{commit}']),
    call(['rev-parse', 'HEAD^{tree}']),
    call(['status', '--porcelain=v1', '--untracked-files=all']),
  ]);
  if (!/^[0-9a-f]{40}$/.test(commit) || !/^[0-9a-f]{40}$/.test(tree)) fail('cannot establish current Git commit/tree');
  if (status !== '') fail('beta integration requires a clean Git checkout so its commit/tree binding is meaningful');
  return Object.freeze({ commit, tree, clean: status === '' });
}
async function verifyGitBinding(value) {
  exact(value, ['clean', 'commit', 'tree'], 'beta integration Git binding');
  if (value.clean !== true || !/^[0-9a-f]{40}$/u.test(value.commit)
      || !/^[0-9a-f]{40}$/u.test(value.tree)) {
    fail('beta integration Git binding is invalid');
  }
  const current = await gitBinding().catch(() => undefined);
  if (current?.commit === value.commit && current.tree === value.tree) return;
  const { execFile } = await import('node:child_process');
  const resolveObject = (expression) => new Promise((resolve, reject) =>
    execFile(
      '/usr/bin/git',
      ['--no-replace-objects', '-C', ROOT, 'rev-parse', '--verify', expression],
      {
        env: {
          HOME: '/nonexistent', LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin',
          GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1',
          GIT_OPTIONAL_LOCKS: '0', GIT_TERMINAL_PROMPT: '0',
        },
      },
      (error, stdout) => error === null ? resolve(stdout.trim()) : reject(error),
    ));
  const [commit, tree] = await Promise.all([
    resolveObject(`${value.commit}^{commit}`),
    resolveObject(`${value.commit}^{tree}`),
  ]);
  if (commit !== value.commit || tree !== value.tree) {
    fail('beta integration historical Git commit/tree no longer resolves');
  }
}
function currentBetaClaims(value, label) {
  exact(value, Object.keys(V2_BETA_LOCAL_FALSE_CLAIMS), label);
  if (canonicalizeJcs(value) !== canonicalizeJcs(V2_BETA_LOCAL_FALSE_CLAIMS)) fail(`${label} differs from fixed beta-only claims`);
  return V2_BETA_LOCAL_FALSE_CLAIMS;
}
function ceremonyClaims(value, label) {
  exact(value, Object.keys(V2_BETA_SINGLE_CONTRIBUTOR_FALSE_CLAIMS), label);
  if (canonicalizeJcs(value)
      !== canonicalizeJcs(V2_BETA_SINGLE_CONTRIBUTOR_FALSE_CLAIMS)) {
    fail(`${label} differs from the exact single-contributor ceremony claims`);
  }
  return V2_BETA_SINGLE_CONTRIBUTOR_FALSE_CLAIMS;
}

export async function buildV2BetaLocalIntegration(options) {
  assertSafeRuntime();
  const input = parseV2BetaLocalIntegrationArguments([
    '--ceremony-dir', options.ceremonyDirectory, '--b01-manifest', options.b01Manifest,
    '--b01-runtime', options.b01Runtime, '--output', options.outputDirectory,
    '--temporary-root', options.temporaryRoot,
  ], ROOT);
  if (await exists(input.outputDirectory)) fail('beta integration output must not already exist');
  await mkdir(path.dirname(input.outputDirectory), { recursive: true, mode: PRIVATE_DIR_MODE });
  await assertPrivateDirectory(path.dirname(input.outputDirectory), 'beta integration output parent');
  await mkdir(input.outputDirectory, { mode: PRIVATE_DIR_MODE });
  const output = input.outputDirectory;
  // No cleanup here: incomplete private roots are evidence of a failed build.
  const git = await gitBinding();
  await writeJson(path.join(output, 'build-start.json'), Object.freeze({ schema: SCHEMA, status: 'incomplete', eligibility: V2_BETA_LOCAL_ELIGIBILITY, claims: V2_BETA_LOCAL_FALSE_CLAIMS, git }));
  const original = await resolveV2BetaSingleContributorHistoricalCeremony({ ceremonyDirectory: input.ceremonyDirectory });
  ceremonyClaims(original.claims, 'original ceremony claims');
  await mkdir(path.join(output, 'custody'), { mode: PRIVATE_DIR_MODE });
  await mkdir(path.join(output, 'custody/b01'), { mode: PRIVATE_DIR_MODE });
  await assertPrivateDirectory(path.join(output, 'custody'), 'beta custody directory');
  await assertPrivateDirectory(path.join(output, 'custody/b01'), 'B01 custody directory');
  await copyCeremony(input.ceremonyDirectory, path.join(output, 'custody/ceremony'));
  const copied = await resolveV2BetaSingleContributorHistoricalCeremony({ ceremonyDirectory: path.join(output, 'custody/ceremony') });
  const { artifacts: _originalArtifacts, ...originalResolution } = original;
  const { artifacts: _copiedArtifacts, ...copiedResolution } = copied;
  if (canonicalizeJcs(originalResolution) !== canonicalizeJcs(copiedResolution)) fail('copied ceremony did not resolve to the original historic verification result');
  const b01 = await bindB01({ b01Manifest: input.b01Manifest, b01Runtime: input.b01Runtime, ceremonyResolution: copied });
  await copyPrivate(input.b01Manifest, path.join(output, 'custody/b01/manifest.json'), 'B01 manifest');
  await copyPrivate(path.join(b01.runtimeDirectory, b01.needed.profileCore.path), path.join(output, 'custody/b01/profile-core.json'), 'B01 profile core');
  const baseProfile = await readRegular(
    path.join(output, 'custody/b01/profile-core.json'),
    'copied B01 profile core',
    { canonicalJson: true },
  );
  const baseCore = baseProfile.value; validateProfileCore(baseCore);
  if (deriveProfileId(baseCore) !== b01.manifest.value.profile?.profileId) fail('B01 profile core does not have the B01 profile identity');
  const wasm = await copyPrivate(path.join(b01.runtimeDirectory, b01.needed.witnessWasm.path), path.join(output, 'custody/b01/main-chipnet.wasm'), 'B01 witness wasm');
  const symbols = await copyPrivate(path.join(b01.runtimeDirectory, b01.needed.circuitSymbols.path), path.join(output, 'custody/b01/main-chipnet.sym'), 'B01 circuit symbols');
  const r1cs = await measureRegular(path.join(output, 'custody/ceremony/relation.r1cs'), 'copied ceremony r1cs');
  const initial = await measureRegular(path.join(output, 'custody/ceremony/initial.zkey'), 'copied ceremony initial zkey');
  const ptau = await measureRegular(path.join(output, 'custody/ceremony/powers-of-tau.ptau'), 'copied ceremony ptau');
  const betaZkey = await measureRegular(path.join(output, 'custody/ceremony/result/beta-proving-key.zkey'), 'copied ceremony beta proving key');
  const verificationKey = await measureRegular(path.join(output, 'custody/ceremony/result/verification-key.json'), 'copied ceremony verification key');
  for (const [label, copy, expected] of [
    ['r1cs', r1cs, copied.artifacts.r1cs], ['initial zkey', initial, copied.artifacts.initialZkey],
    ['powers of tau', ptau, copied.artifacts.powersOfTau], ['beta proving key', betaZkey, copied.artifacts.betaProvingKey],
    ['verification key', verificationKey, copied.artifacts.verificationKey],
  ]) if (copy.sha256 !== expected.sha256.slice(7)
    || String(copy.byteLength) !== String(expected.bytes)) {
    fail(`copied ceremony ${label} does not match resolved ceremony artifact`);
  }
  const betaCore = deriveV2BetaLocalProfileCore({ baseProfileCore: baseCore, verificationKeySha256: verificationKey.sha256 });
  const profileCorePath = path.join(output, 'profile/profile-core.json'); await writeJson(profileCorePath, betaCore.profileCore);
  const provenance = createV2BetaLocalProvenancePin(copied); const provenancePath = path.join(output, 'profile/beta-provenance.json'); await writeJson(provenancePath, provenance);
  const betaProfile = createV2BetaLocalProfilePackage({
    baseProfileCore: baseCore,
    b01Manifest: b01.manifest.value,
    profileCore: betaCore.profileCore, profileCoreSha256: betaCore.profileCoreSha256,
    ceremony: { ceremonyId: copied.ceremonyId, b01ManifestSha256: copied.b01ManifestSha256, preparationSha256: copied.preparationSha256, resultSha256: copied.resultSha256, transcriptSha256: copied.transcriptSha256, betaProvingKeySha256: copied.betaProvingKeySha256, verificationKeySha256: copied.verificationKeySha256, initialZkeySha256: `sha256:${initial.sha256}`, powersOfTauSha256: `sha256:${ptau.sha256}`, circuitSymbolsSha256: `sha256:${symbols.sha256}`, source: copied.source },
    artifacts: {
      r1cs: { bytes: r1cs.byteLength, path: 'custody/ceremony/relation.r1cs', sha256: r1cs.sha256 }, witnessWasm: { bytes: wasm.byteLength, path: 'custody/b01/main-chipnet.wasm', sha256: wasm.sha256 }, circuitSymbols: { bytes: symbols.byteLength, path: 'custody/b01/main-chipnet.sym', sha256: symbols.sha256 }, initialZkey: { bytes: initial.byteLength, path: 'custody/ceremony/initial.zkey', sha256: initial.sha256 }, powersOfTau: { bytes: ptau.byteLength, path: 'custody/ceremony/powers-of-tau.ptau', sha256: ptau.sha256 }, betaProvingKey: { bytes: betaZkey.byteLength, path: 'custody/ceremony/result/beta-proving-key.zkey', sha256: betaZkey.sha256 }, verificationKey: { bytes: verificationKey.byteLength, path: 'custody/ceremony/result/verification-key.json', sha256: verificationKey.sha256 },
    },
  });
  const betaProfilePath = path.join(output, 'profile/beta-profile-package.json'); await writeJson(betaProfilePath, betaProfile);
  const instanceId = deriveV2BetaLocalInstanceId({ profileId: betaProfile.profileId, ceremonyResultSha256: copied.resultSha256 });
  const proof = await runBetaProofQualification({ ceremonyDirectory: path.join(output, 'custody/ceremony'), profileCore: profileCorePath, r1cs: path.join(output, 'custody/ceremony/relation.r1cs'), wasm: path.join(output, 'custody/b01/main-chipnet.wasm'), zkey: path.join(output, 'custody/ceremony/result/beta-proving-key.zkey'), verificationKey: path.join(output, 'custody/ceremony/result/verification-key.json'), outputDirectory: path.join(output, 'proof/qualification'), instanceId, maximumLiveNotes: MAXIMUM_LIVE_NOTES, singleThread: false });
  const proofVerification = await verifyBetaProofQualification({ evidencePath: proof.evidencePath });
  const proofEvidence = await readRegular(
    proof.evidencePath,
    'beta proof qualification evidence',
    { canonicalJson: true },
  );
  const runtime = await runV2Pf10BetaRuntime(['--profile-core', profileCorePath, '--profile-package', betaProfilePath, '--qualification-evidence', proof.evidencePath, '--instance-id', instanceId, '--output', path.relative(ROOT, path.join(output, 'runtime')), '--temporary-root', input.temporaryRoot], { cwd: ROOT });
  const runtimeVerification = await verifyV2Pf10BetaRuntime({ outputDirectory: runtime.outputDirectory, temporaryRoot: input.temporaryRoot });
  const runtimeManifest = await readRegular(
    path.join(runtime.outputDirectory, V2_PF10_BETA_RUNTIME_MANIFEST),
    'beta runtime manifest',
    { canonicalJson: true },
  );
  const libauth = await runPf10LibauthQualification(parseBetaOptions(['--output', path.join(output, 'libauth'), '--profile-core', profileCorePath, '--qualification-root', path.dirname(proof.evidencePath), '--r1cs', path.join(output, 'custody/ceremony/relation.r1cs'), '--verification-key', path.join(output, 'custody/ceremony/result/verification-key.json'), '--wasm', path.join(output, 'custody/b01/main-chipnet.wasm'), '--beta-zkey', path.join(output, 'custody/ceremony/result/beta-proving-key.zkey'), '--temporary-root', input.temporaryRoot]), { betaLocal: true });
  const libauthVerification = await verifyPf10BetaLibauthQualification({ output: libauth.outputDirectory, betaProofEvidencePath: proof.evidencePath });
  const libauthEvidence = await readRegular(
    path.join(libauth.outputDirectory, 'libauth.json'),
    'beta Libauth evidence',
    { canonicalJson: true },
  );
  const preparedActions = makePersistenceActions({
    profileId: betaProfile.profileId,
    instanceId,
  });
  const betaRuntime = Object.freeze({
    manifest: runtimeManifest.value,
    manifestSha256: runtimeManifest.sha256,
    verification: runtimeVerification,
  });
  const betaProofQualification = Object.freeze({
    evidence: proofEvidence.value,
    evidenceSha256: proofEvidence.sha256,
    verification: proofVerification,
  });
  const betaLibauthQualification = Object.freeze({
    evidence: libauthEvidence.value,
    evidenceSha256: libauthEvidence.sha256,
    verification: libauthVerification,
  });
  const persistenceInput = Object.freeze({
    betaLibauthQualification,
    betaProfilePackage: betaProfile,
    betaProofQualification,
    betaRuntime,
    carrierCount: CARRIER_COUNT,
    genesis: {
      blockHash: sha256(Buffer.from(`ShieldKit beta local genesis block ${instanceId}`, 'utf8')),
      height: 0,
      outpoint: {
        txid: sha256(Buffer.from(`ShieldKit beta local genesis outpoint ${instanceId}`, 'utf8')),
        vout: 0,
      },
    },
    instanceId,
    maximumLiveNotes: MAXIMUM_LIVE_NOTES,
    preparedActions,
    privateActionDirectory: path.join(output, 'persistence/prepared-actions'),
    profileCore: betaCore.profileCore,
    stateStorePath: path.join(output, 'persistence/state/pool.sqlite'),
  });
  const persistence = await runV2BetaLocalPersistenceRecovery(persistenceInput);
  const persistenceVerification = await verifyV2BetaLocalPersistenceRecovery({
    betaLibauthQualification,
    betaProfilePackage: betaProfile,
    betaProofQualification,
    betaRuntime,
    evidence: persistence,
    preparedActions,
    privateActionDirectory: persistenceInput.privateActionDirectory,
    profileCore: betaCore.profileCore,
    stateStorePath: persistenceInput.stateStorePath,
  });
  await writeJson(path.join(output, 'persistence/evidence.json'), persistence);
  const records = await inventory(output, { exclude: new Set([INVENTORY_FILE, COMPLETION_FILE]) });
  const inventoryValue = Object.freeze({ schema: `${SCHEMA}-private-inventory`, files: records, sha256: jsonHash(records) });
  await writeJson(path.join(output, INVENTORY_FILE), inventoryValue);
  const betaProfileFile = await measureRegular(
    betaProfilePath,
    'beta profile package',
  );
  const provenanceFile = await measureRegular(
    provenancePath,
    'beta provenance',
  );
  const inventoryFile = await measureRegular(
    path.join(output, INVENTORY_FILE),
    'private inventory',
  );
  const completion = Object.freeze({ schema: SCHEMA, status: STATUS, eligibility: V2_BETA_LOCAL_ELIGIBILITY, assuranceClass: 'beta-single-contributor', claims: V2_BETA_LOCAL_FALSE_CLAIMS, identity: Object.freeze({ profileId: betaProfile.profileId, instanceId, maximumLiveNotes: MAXIMUM_LIVE_NOTES, denominationSats: DENOMINATION_SATS, carrierCount: CARRIER_COUNT }), git, custody: Object.freeze({ ceremonyResultSha256: copied.resultSha256, b01ManifestSha256: copied.b01ManifestSha256 }), profile: Object.freeze({ coreSha256: betaCore.profileCoreSha256, packageSha256: betaProfileFile.sha256, provenanceSha256: provenanceFile.sha256 }), verification: Object.freeze({ proof: proofVerification, runtime: runtimeVerification, libauth: libauthVerification, persistence: persistenceVerification }), privateInventory: Object.freeze({ path: INVENTORY_FILE, bytes: inventoryFile.byteLength, sha256: inventoryFile.sha256 }) });
  await writeJson(path.join(output, COMPLETION_FILE), completion);
  return Object.freeze({ outputDirectory: output, completionPath: path.join(output, COMPLETION_FILE), completionSha256: sha256(canonicalBytes(completion)), profileId: betaProfile.profileId, instanceId, eligibility: V2_BETA_LOCAL_ELIGIBILITY });
}

export async function verifyV2BetaLocalIntegration({ outputDirectory, temporaryRoot }) {
  assertSafeRuntime();
  const output = repoOutput(outputDirectory, 'output directory'); await assertPrivateDirectory(output, 'beta integration output');
  const completion = await readRegular(path.join(output, COMPLETION_FILE), 'beta integration completion', { canonicalJson: true });
  const value = completion.value;
  exact(value, ['assuranceClass', 'claims', 'custody', 'eligibility', 'git', 'identity', 'privateInventory', 'profile', 'schema', 'status', 'verification'], 'beta integration completion');
  if (value.schema !== SCHEMA || value.status !== STATUS || value.eligibility !== V2_BETA_LOCAL_ELIGIBILITY || value.assuranceClass !== 'beta-single-contributor') fail('beta integration completion boundary is invalid');
  currentBetaClaims(value.claims, 'beta integration completion claims');
  await verifyGitBinding(value.git);
  if (value.identity.maximumLiveNotes !== MAXIMUM_LIVE_NOTES || value.identity.carrierCount !== CARRIER_COUNT || value.identity.denominationSats !== DENOMINATION_SATS || !HASH.test(value.identity.profileId) || !HASH.test(value.identity.instanceId)) fail('beta integration identity is invalid');
  const files = await inventory(output, { exclude: new Set([INVENTORY_FILE, COMPLETION_FILE]) });
  const retained = await readRegular(path.join(output, INVENTORY_FILE), 'private inventory', { canonicalJson: true });
  exact(retained.value, ['files', 'schema', 'sha256'], 'private inventory');
  if (retained.value.schema !== `${SCHEMA}-private-inventory` || retained.value.sha256 !== jsonHash(retained.value.files) || canonicalizeJcs(retained.value.files) !== canonicalizeJcs(files)) fail('private inventory differs from exhaustive beta output inventory');
  if (value.privateInventory.sha256 !== retained.sha256 || value.privateInventory.bytes !== retained.bytes.length || value.privateInventory.path !== INVENTORY_FILE) fail('completion does not bind the private inventory');
  const ceremony = await resolveV2BetaSingleContributorHistoricalCeremony({ ceremonyDirectory: path.join(output, 'custody/ceremony') });
  if (ceremony.resultSha256 !== value.custody.ceremonyResultSha256 || ceremony.b01ManifestSha256 !== value.custody.b01ManifestSha256) fail('copied ceremony resolution does not match completion custody pins');
  const base = await readRegular(path.join(output, 'custody/b01/profile-core.json'), 'copied B01 profile', { canonicalJson: true }); validateProfileCore(base.value);
  const copiedB01 = await readRegular(
    path.join(output, 'custody/b01/manifest.json'),
    'copied B01 manifest',
    { canonicalJson: true },
  );
  if (`sha256:${copiedB01.sha256}` !== ceremony.b01ManifestSha256) {
    fail('copied B01 manifest differs from ceremony custody');
  }
  const core = await readRegular(path.join(output, 'profile/profile-core.json'), 'beta profile core', { canonicalJson: true }); validateProfileCore(core.value);
  const packageFile = await readRegular(path.join(output, 'profile/beta-profile-package.json'), 'beta profile package', { canonicalJson: true }); const betaPackage = validateV2BetaLocalProfilePackage(packageFile.value, core.value);
  const provenance = await readRegular(path.join(output, 'profile/beta-provenance.json'), 'beta provenance pin', { canonicalJson: true }); validateV2BetaLocalProvenancePin(provenance.value);
  if (canonicalizeJcs(betaPackage.baseProfile.profileCore)
      !== canonicalizeJcs(base.value)
    || canonicalizeJcs(betaPackage.b01Manifest)
      !== canonicalizeJcs(copiedB01.value)
    || canonicalizeJcs(provenance.value)
      !== canonicalizeJcs(createV2BetaLocalProvenancePin(ceremony))
    || betaPackage.profileId !== value.identity.profileId || deriveProfileId(core.value) !== value.identity.profileId || deriveV2BetaLocalInstanceId({ profileId: value.identity.profileId, ceremonyResultSha256: ceremony.resultSha256 }) !== value.identity.instanceId || core.sha256 !== value.profile.coreSha256 || packageFile.sha256 !== value.profile.packageSha256 || provenance.sha256 !== value.profile.provenanceSha256) fail('beta profile/instance binding differs from completion');
  const proof = await verifyBetaProofQualification({ evidencePath: path.join(output, 'proof/qualification/qualification-evidence.json') });
  const runtime = await verifyV2Pf10BetaRuntime({ outputDirectory: path.join(output, 'runtime'), temporaryRoot });
  const libauth = await verifyPf10BetaLibauthQualification({ output: path.join(output, 'libauth'), betaProofEvidencePath: path.join(output, 'proof/qualification/qualification-evidence.json') });
  const [proofEvidence, runtimeManifest, libauthEvidence] = await Promise.all([
    readRegular(
      path.join(output, 'proof/qualification/qualification-evidence.json'),
      'beta proof qualification evidence',
      { canonicalJson: true },
    ),
    readRegular(
      path.join(output, 'runtime', V2_PF10_BETA_RUNTIME_MANIFEST),
      'beta runtime manifest',
      { canonicalJson: true },
    ),
    readRegular(
      path.join(output, 'libauth/libauth.json'),
      'beta Libauth evidence',
      { canonicalJson: true },
    ),
  ]);
  const preparedActions = makePersistenceActions({
    profileId: betaPackage.profileId,
    instanceId: value.identity.instanceId,
  });
  const betaRuntime = Object.freeze({
    manifest: runtimeManifest.value,
    manifestSha256: runtimeManifest.sha256,
    verification: runtime,
  });
  const betaProofQualification = Object.freeze({
    evidence: proofEvidence.value,
    evidenceSha256: proofEvidence.sha256,
    verification: proof,
  });
  const betaLibauthQualification = Object.freeze({
    evidence: libauthEvidence.value,
    evidenceSha256: libauthEvidence.sha256,
    verification: libauth,
  });
  const persistenceEvidence = (await readRegular(path.join(output, 'persistence/evidence.json'), 'persistence evidence', { canonicalJson: true })).value;
  const persistence = await verifyV2BetaLocalPersistenceRecovery({
    betaLibauthQualification,
    betaProfilePackage: betaPackage,
    betaProofQualification,
    betaRuntime,
    evidence: persistenceEvidence,
    preparedActions,
    privateActionDirectory: path.join(output, 'persistence/prepared-actions'),
    profileCore: core.value,
    stateStorePath: path.join(output, 'persistence/state/pool.sqlite'),
  });
  for (const [name, fresh] of Object.entries({
    proof,
    runtime,
    libauth,
    persistence,
  })) {
    if (canonicalizeJcs(fresh)
        !== canonicalizeJcs(value.verification[name])) {
      fail(`fresh ${name} verification differs from the completion record`);
    }
  }
  for (const candidate of [proof, runtime, libauth, persistence]) if (candidate?.eligibility !== undefined && candidate.eligibility !== V2_BETA_LOCAL_ELIGIBILITY) fail('a sub-verifier left the beta-only eligibility boundary');
  return Object.freeze({ schema: `${SCHEMA}-verification`, status: STATUS, eligibility: V2_BETA_LOCAL_ELIGIBILITY, claims: V2_BETA_LOCAL_FALSE_CLAIMS, completionSha256: completion.sha256, profileId: betaPackage.profileId, instanceId: value.identity.instanceId });
}

async function main(argv = process.argv.slice(2)) {
  if (argv[0] === '--verify') return verifyV2BetaLocalIntegration(parseV2BetaLocalIntegrationVerifyArguments(argv));
  return buildV2BetaLocalIntegration(parseV2BetaLocalIntegrationArguments(argv));
}
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().then(
    (result) => process.stdout.write(
      `${canonicalizeJcs(result)}\n`,
      () => process.exit(0),
    ),
    (error) => process.stderr.write(
      `${error?.stack ?? error}\n`,
      () => process.exit(1),
    ),
  );
}
