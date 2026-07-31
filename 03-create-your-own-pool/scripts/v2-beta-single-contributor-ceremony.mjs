#!/usr/bin/env node
/**
 * One-contributor Phase-2 setup for BETA-only local integration.
 *
 * This lane is intentionally separate from D-01. It cannot emit a final-key,
 * production, release, or ceremony-qualified claim. The operator CLI accepts
 * secret entropy only from the controlling terminal on the CLI path; it is
 * never a command-line argument, environment variable, file, or retained log
 * field.
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
} from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { constants as fsConstants } from 'node:fs';
import {
  chmod,
  lstat,
  mkdtemp,
  open,
  readdir,
  realpath,
  rename,
  rm,
} from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { canonicalJson, parseStrictJson } from '../packages/profile/load.mjs';
import {
  BETA_SINGLE_CONTRIBUTOR_CEREMONY_PROFILE,
  createBetaSingleContributorContributionRequest,
  signBetaSingleContributorContributionReceipt,
  verifyBetaSingleContributorExternalReceiptChain,
} from '../packages/profile/setup/external-contribution.mjs';
import {
  BETA_SINGLE_CONTRIBUTOR_ENTROPY_POLICY,
  BETA_SINGLE_CONTRIBUTOR_ENTROPY_POLICY_SHA256,
  BETA_SINGLE_CONTRIBUTOR_MAX_DICE_ROLLS,
  BETA_SINGLE_CONTRIBUTOR_MIN_DICE_ROLLS,
  deriveBetaSingleContributorEntropy,
} from '../packages/profile/setup/beta-single-contributor-entropy.mjs';
import {
  collectV2FinalZkeyToolchainManifest,
  verifyV2FinalZkeyToolchainManifest,
} from '../packages/profile/v2/final-zkey-verification.mjs';
import {
  verifyV2B01PreFreezeBundle,
} from './v2-b01-pre-freeze.mjs';

export const V2_BETA_SINGLE_CONTRIBUTOR_PREPARATION_SCHEMA =
  'shieldkit-v2-beta-single-contributor-preparation-v2';
export const V2_BETA_SINGLE_CONTRIBUTOR_RESULT_SCHEMA =
  'shieldkit-v2-beta-single-contributor-result-v2';
export const V2_BETA_SINGLE_CONTRIBUTOR_VERIFICATION_SCHEMA =
  'shieldkit-v2-beta-single-contributor-verification-v2';

const B01_SCHEMA = 'shieldkit-v2-direct-b01-pre-freeze-v1';
const HASH = /^sha256:[0-9a-f]{64}$/u;
const RAW_HASH = /^[0-9a-f]{64}$/u;
const ID = /^[a-z0-9][a-z0-9._-]{0,127}$/u;
const GIT = /^[0-9a-f]{40}$/u;
const CONTRIBUTION_PROMPT = 'Enter a random text. (Entropy):';
const REPOSITORY_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
);
const BETA_IMPLEMENTATION_SCHEMA =
  'shieldkit/v2-beta-single-contributor-implementation/v1';
const BETA_IMPLEMENTATION_ENTRYPOINT =
  '03-create-your-own-pool/scripts/v2-beta-single-contributor-ceremony.mjs';
const GIT_ENVIRONMENT = Object.freeze({
  GIT_CONFIG_COUNT: '0',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_NOSYSTEM: '1',
  LANG: 'C',
  LC_ALL: 'C',
  PATH: '',
  TZ: 'UTC',
});
const PRIVATE_KEY_FILE = 'participant-signing-key.pem';
const INTERNAL_TTY_READER_MODE = '__shieldkit_internal_beta_tty_reader_v1';
const PREPARATION_FILES = Object.freeze([
  'initial.zkey',
  'participant-signing-key.pem',
  'powers-of-tau.ptau',
  'preparation.json',
  'relation.r1cs',
]);
const POST_CONTRIBUTION_FILES = Object.freeze([
  ...PREPARATION_FILES.filter((name) => name !== PRIVATE_KEY_FILE),
  'result',
]);
const RESULT_FILES = Object.freeze([
  'beta-proving-key.zkey',
  'receipt.json',
  'result.json',
  'transcript.json',
  'verification-key.json',
]);
const FALSE_CLAIMS = Object.freeze({
  b02Qualified: false,
  ceremonyQualified: false,
  d01Qualified: false,
  d02Qualified: false,
  finalKey: false,
  participantIndependenceEstablished: false,
  production: false,
  q01FinalReplayQualified: false,
  q02Qualified: false,
  q03Qualified: false,
  q07Qualified: false,
  q08Qualified: false,
  q09Qualified: false,
  releaseQualified: false,
});
const REQUEST_HASH_DOMAIN = 'shieldkit/v2/beta/phase2/request/v1\0';

export class V2BetaSingleContributorCeremonyError extends Error {
  constructor(code, message, cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'V2BetaSingleContributorCeremonyError';
    this.code = code;
  }
}

const fail = (code, message, cause) => {
  throw new V2BetaSingleContributorCeremonyError(code, message, cause);
};
const sha256 = (bytes) =>
  `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const jcsBytes = (value) => Buffer.from(canonicalJson(value), 'utf8');
const requestSha256 = (request) => {
  const digest = createHash('sha256');
  digest.update(REQUEST_HASH_DOMAIN, 'utf8');
  digest.update(jcsBytes(request));
  return `sha256:${digest.digest('hex')}`;
};

function exactKeys(value, label, keys) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail('BETA_SCHEMA_INVALID', `${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length
    || actual.some((entry, index) => entry !== expected[index])) {
    fail('BETA_SCHEMA_INVALID', `${label} has missing or unknown properties`);
  }
  return value;
}

async function measureImplementationSourceFile(relativePath) {
  const filename = path.join(REPOSITORY_ROOT, relativePath);
  const label = `beta implementation ${relativePath}`;
  const initial = await lstat(filename, { bigint: true });
  if (await realpath(filename) !== filename) {
    fail('BETA_IMPLEMENTATION_CHANGED', `${label} has symlink traversal`);
  }
  assertStableImplementationFileStat(initial, label);
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  let handle;
  try {
    handle = await open(filename, flags);
    const before = await handle.stat({ bigint: true });
    assertStableImplementationFileStat(before, label);
    if (!sameIdentity(initial, before) || initial.mode !== before.mode
      || before.size > 32n * 1024n * 1024n) {
      fail('BETA_IMPLEMENTATION_CHANGED', `${label} changed or is oversized`);
    }
    const digest = createHash('sha256');
    for await (const chunk of handle.createReadStream({ autoClose: false })) digest.update(chunk);
    const after = await handle.stat({ bigint: true });
    const afterPath = await lstat(filename, { bigint: true });
    assertStableImplementationFileStat(after, label);
    assertStableImplementationFileStat(afterPath, label);
    if (!sameIdentity(before, after) || !sameIdentity(after, afterPath)
      || before.mode !== after.mode || after.mode !== afterPath.mode) {
      fail('BETA_IMPLEMENTATION_CHANGED', `${label} changed during measurement`);
    }
    return Object.freeze({
      bytes: String(after.size),
      mode: Number(after.mode & 0o7777n).toString(8).padStart(4, '0'),
      path: relativePath,
      sha256: `sha256:${digest.digest('hex')}`,
    });
  } finally {
    await handle?.close();
  }
}

function trustedGit(args, {
  binary = false,
  repositoryRoot = REPOSITORY_ROOT,
} = {}) {
  const result = spawnSync('/usr/bin/git', args, {
    cwd: repositoryRoot,
    encoding: binary ? null : 'utf8',
    env: GIT_ENVIRONMENT,
    maxBuffer: 16 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error || result.status !== 0 || result.signal !== null) {
    fail('BETA_IMPLEMENTATION_INVALID', `trusted Git failed: ${args.join(' ')}`);
  }
  return result.stdout;
}

function implementationSourceIdentity(repositoryRoot = REPOSITORY_ROOT) {
  const source = Object.freeze({
    gitCommit: String(trustedGit(
      ['rev-parse', '--verify', 'HEAD'],
      { repositoryRoot },
    )).trim(),
    gitTree: String(trustedGit(
      ['rev-parse', '--verify', 'HEAD^{tree}'],
      { repositoryRoot },
    )).trim(),
  });
  if (!GIT.test(source.gitCommit) || !GIT.test(source.gitTree)) {
    fail('BETA_IMPLEMENTATION_INVALID', 'beta implementation Git identity is invalid');
  }
  return source;
}

export function assertV2BetaSingleContributorCleanCheckout(
  repositoryRoot = REPOSITORY_ROOT,
) {
  const status = Buffer.from(trustedGit([
    'status',
    '--porcelain=v1',
    '-z',
    '--untracked-files=all',
    '--ignore-submodules=none',
  ], { binary: true, repositoryRoot }));
  if (status.length !== 0) {
    fail(
      'BETA_IMPLEMENTATION_DIRTY',
      'beta implementation requires a clean Git index and worktree',
    );
  }
}

function trackedImplementationPaths() {
  const output = Buffer.from(trustedGit(['ls-files', '--cached', '-z'], { binary: true }));
  const raw = output.subarray(0, output.length - (output.at(-1) === 0 ? 1 : 0));
  const decoded = raw.toString('utf8');
  if (!Buffer.from(decoded, 'utf8').equals(raw)) {
    fail('BETA_IMPLEMENTATION_INVALID', 'tracked paths must be canonical UTF-8');
  }
  const paths = decoded.split('\0').sort();
  if (paths.length === 0
    || paths.some((entry, index) => entry.length === 0
      || path.posix.normalize(entry) !== entry
      || path.posix.isAbsolute(entry)
      || entry.startsWith('../')
      || entry.includes('\\')
      || (index > 0 && entry === paths[index - 1]))
    || !paths.includes(BETA_IMPLEMENTATION_ENTRYPOINT)) {
    fail('BETA_IMPLEMENTATION_INVALID', 'tracked beta implementation inventory is invalid');
  }
  return paths;
}

export async function collectV2BetaSingleContributorImplementationManifest() {
  assertV2BetaSingleContributorCleanCheckout();
  const source = implementationSourceIdentity();
  const files = [];
  for (const relativePath of trackedImplementationPaths()) {
    files.push(await measureImplementationSourceFile(relativePath));
  }
  assertV2BetaSingleContributorCleanCheckout();
  const finalSource = implementationSourceIdentity();
  if (canonicalJson(finalSource) !== canonicalJson(source)) {
    fail('BETA_IMPLEMENTATION_CHANGED', 'beta implementation source changed during measurement');
  }
  return Object.freeze({
    schema: BETA_IMPLEMENTATION_SCHEMA,
    entropyPolicy: BETA_SINGLE_CONTRIBUTOR_ENTROPY_POLICY,
    source,
    files: Object.freeze(files),
  });
}

function validateImplementationManifest(value) {
  exactKeys(value, 'beta implementation manifest', ['entropyPolicy', 'files', 'schema', 'source']);
  if (value.schema !== BETA_IMPLEMENTATION_SCHEMA
    || canonicalJson(value.entropyPolicy)
      !== canonicalJson(BETA_SINGLE_CONTRIBUTOR_ENTROPY_POLICY)
    || !Array.isArray(value.files)
    || value.files.length === 0
    || !GIT.test(value.source?.gitCommit)
    || !GIT.test(value.source?.gitTree)) {
    fail('BETA_IMPLEMENTATION_INVALID', 'beta implementation manifest is invalid');
  }
  exactKeys(value.source, 'beta implementation source', ['gitCommit', 'gitTree']);
  value.files.forEach((file, index) => {
    exactKeys(file, `beta implementation file ${index}`, ['bytes', 'mode', 'path', 'sha256']);
    if (typeof file.path !== 'string'
      || path.posix.normalize(file.path) !== file.path
      || path.posix.isAbsolute(file.path)
      || file.path.startsWith('../')
      || file.path.includes('\\')
      || (index > 0 && file.path <= value.files[index - 1].path)
      || !/^[0-7]{4}$/u.test(file.mode)
      || !HASH.test(file.sha256)
      || !/^(?:0|[1-9][0-9]*)$/u.test(file.bytes)) {
      fail('BETA_IMPLEMENTATION_INVALID', 'beta implementation file inventory is invalid');
    }
  });
  if (!value.files.some((file) => file.path === BETA_IMPLEMENTATION_ENTRYPOINT)) {
    fail('BETA_IMPLEMENTATION_INVALID', 'beta implementation entrypoint is absent');
  }
  return value;
}

async function verifyImplementationManifest(expected) {
  validateImplementationManifest(expected);
  const current = await collectV2BetaSingleContributorImplementationManifest();
  if (canonicalJson(current) !== canonicalJson(expected)) {
    fail('BETA_IMPLEMENTATION_CHANGED', 'beta implementation source or entropy policy changed');
  }
  return current;
}

function assertNodeVersion() {
  const [major, minor] = process.versions.node.split('.').map(Number);
  if (major < 22 || (major === 22 && minor < 5)) {
    fail('BETA_NODE_UNSUPPORTED', 'the beta ceremony requires Node >=22.5.0');
  }
  // The mandatory portable runner launches each file under these exact benign
  // node:test controls. No preload, loader, inspector, policy, or evaluator
  // argument is accepted in either the CLI or test path.
  const benignTestArguments = new Set([
    '--test',
    '--test-concurrency=1',
    '--test-reporter=tap',
  ]);
  if (process.execArgv.some((argument) => !benignTestArguments.has(argument))) {
    fail('BETA_RUNTIME_UNSAFE', 'the beta ceremony refuses Node preload, loader, or exec arguments');
  }
  const contaminated = Object.keys(process.env).filter((name) =>
    name === 'NODE_OPTIONS'
      || name === 'NODE_PATH'
      || name === 'NODE_V8_COVERAGE'
      || name.startsWith('LD_')
      || name.startsWith('DYLD_'));
  if (contaminated.length !== 0) {
    fail(
      'BETA_RUNTIME_UNSAFE',
      `the beta ceremony refuses ambient loader controls: ${contaminated.sort().join(',')}`,
    );
  }
}

function sameIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function owner(stat) {
  return typeof process.getuid !== 'function' || stat.uid === BigInt(process.getuid());
}

function validPrivateFileStat(stat, { allowExecutable = false } = {}) {
  const mode = Number(stat.mode & 0o7777n);
  return stat.isFile()
    && !stat.isSymbolicLink()
    && stat.nlink === 1n
    && owner(stat)
    && stat.size > 0n
    && (allowExecutable || mode === 0o600);
}

function assertStablePrivateFileStat(stat, label, options = {}) {
  if (!validPrivateFileStat(stat, options)) {
    fail(
      'BETA_INPUT_CHANGED',
      `${label} ceased to be a user-owned nonempty single-link private file`,
    );
  }
}

function assertStableImplementationFileStat(stat, label) {
  const mode = Number(stat.mode & 0o7777n);
  if (!stat.isFile()
    || stat.isSymbolicLink()
    || stat.nlink !== 1n
    || !owner(stat)
    || (mode & 0o022) !== 0) {
    fail(
      'BETA_IMPLEMENTATION_CHANGED',
      `${label} must be a user-owned single-link file without group/other write access`,
    );
  }
}

async function directPrivateDirectory(directory, label) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory)) {
    fail('BETA_PATH_INVALID', `${label} must be an absolute path`);
  }
  const requested = path.resolve(directory);
  let stat;
  let resolved;
  try {
    stat = await lstat(requested, { bigint: true });
    resolved = await realpath(requested);
  } catch (error) {
    fail('BETA_PATH_INVALID', `${label} is not readable`, error);
  }
  if (!stat.isDirectory() || stat.isSymbolicLink() || !owner(stat)
    || Number(stat.mode & 0o7777n) !== 0o700 || resolved !== requested) {
    fail(
      'BETA_PATH_INVALID',
      `${label} must be a direct user-owned mode-0700 directory without symlink traversal`,
    );
  }
  return requested;
}

async function directPrivateFile(filename, label, { allowExecutable = false } = {}) {
  if (typeof filename !== 'string' || !path.isAbsolute(filename)) {
    fail('BETA_PATH_INVALID', `${label} must be an absolute path`);
  }
  const requested = path.resolve(filename);
  let stat;
  let resolved;
  try {
    stat = await lstat(requested, { bigint: true });
    resolved = await realpath(requested);
  } catch (error) {
    fail('BETA_PATH_INVALID', `${label} is not readable`, error);
  }
  if (!validPrivateFileStat(stat, { allowExecutable }) || resolved !== requested) {
    fail(
      'BETA_PATH_INVALID',
      `${label} must be a direct user-owned ${allowExecutable ? '' : 'mode-0600 '}nonempty single-link file`,
    );
  }
  return Object.freeze({ filename: requested, stat });
}

async function measurePrivateFile(filename, label, expectedHash = undefined) {
  const file = await directPrivateFile(filename, label);
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  let handle;
  try {
    handle = await open(file.filename, flags);
    const before = await handle.stat({ bigint: true });
    assertStablePrivateFileStat(before, label);
    if (!sameIdentity(file.stat, before)) {
      fail('BETA_INPUT_CHANGED', `${label} changed before measurement`);
    }
    const digest = createHash('sha256');
    for await (const chunk of handle.createReadStream({ autoClose: false, highWaterMark: 1024 * 1024 })) {
      digest.update(chunk);
    }
    const after = await handle.stat({ bigint: true });
    const afterPath = await lstat(file.filename, { bigint: true });
    assertStablePrivateFileStat(after, label);
    assertStablePrivateFileStat(afterPath, label);
    if (!sameIdentity(before, after) || !sameIdentity(after, afterPath)) {
      fail('BETA_INPUT_CHANGED', `${label} changed during measurement`);
    }
    const result = Object.freeze({
      bytes: String(after.size),
      sha256: `sha256:${digest.digest('hex')}`,
    });
    if (expectedHash !== undefined && result.sha256 !== expectedHash) {
      fail('BETA_HASH_MISMATCH', `${label} does not match its pinned SHA-256`);
    }
    return result;
  } finally {
    await handle?.close();
  }
}

async function copyPrivateFile(source, destination, label, expectedHash) {
  const sourceFile = await directPrivateFile(source, label);
  const readFlags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  let input;
  let output;
  try {
    input = await open(sourceFile.filename, readFlags);
    const before = await input.stat({ bigint: true });
    assertStablePrivateFileStat(before, label);
    if (!sameIdentity(sourceFile.stat, before)) {
      fail('BETA_INPUT_CHANGED', `${label} changed before private copying`);
    }
    output = await open(
      destination,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL
        | (fsConstants.O_NOFOLLOW ?? 0),
      0o600,
    );
    const digest = createHash('sha256');
    let bytes = 0n;
    for await (const chunk of input.createReadStream({ autoClose: false, highWaterMark: 1024 * 1024 })) {
      const part = Buffer.from(chunk);
      digest.update(part);
      bytes += BigInt(part.length);
      let offset = 0;
      while (offset < part.length) {
        const { bytesWritten } = await output.write(part, offset, part.length - offset);
        if (bytesWritten <= 0) fail('BETA_IO_FAILED', `${label} private copy made no progress`);
        offset += bytesWritten;
      }
    }
    await output.sync();
    const after = await input.stat({ bigint: true });
    const afterPath = await lstat(sourceFile.filename, { bigint: true });
    assertStablePrivateFileStat(after, label);
    assertStablePrivateFileStat(afterPath, label);
    if (!sameIdentity(before, after) || !sameIdentity(after, afterPath) || bytes !== after.size) {
      fail('BETA_INPUT_CHANGED', `${label} changed during private copying`);
    }
    const measured = `sha256:${digest.digest('hex')}`;
    if (measured !== expectedHash) {
      fail('BETA_HASH_MISMATCH', `${label} does not match the B-01 pin`);
    }
    await chmod(destination, 0o600);
    return Object.freeze({ bytes: String(bytes), sha256: measured });
  } finally {
    await output?.close();
    await input?.close();
  }
}

async function writeExclusive(filename, bytes) {
  let handle;
  try {
    handle = await open(
      filename,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL
        | (fsConstants.O_NOFOLLOW ?? 0),
      0o600,
    );
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle?.close();
  }
  await chmod(filename, 0o600);
}

async function writeCanonical(filename, value) {
  const bytes = jcsBytes(value);
  await writeExclusive(filename, bytes);
  return sha256(bytes);
}

async function readPrivateBytes(filename, label, maximumBytes = 16n * 1024n * 1024n) {
  const file = await directPrivateFile(filename, label);
  if (file.stat.size > maximumBytes) {
    fail('BETA_SCHEMA_INVALID', `${label} exceeds its size limit`);
  }
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  let handle;
  let bytes;
  try {
    handle = await open(file.filename, flags);
    const before = await handle.stat({ bigint: true });
    assertStablePrivateFileStat(before, label);
    if (!sameIdentity(file.stat, before)) {
      fail('BETA_INPUT_CHANGED', `${label} changed before it was read`);
    }
    bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const afterPath = await lstat(file.filename, { bigint: true });
    assertStablePrivateFileStat(after, label);
    assertStablePrivateFileStat(afterPath, label);
    if (!sameIdentity(before, after) || !sameIdentity(after, afterPath)
      || BigInt(bytes.length) !== after.size) {
      fail('BETA_INPUT_CHANGED', `${label} changed while it was read`);
    }
  } finally {
    await handle?.close();
  }
  return bytes;
}

async function readCanonical(filename, label) {
  const bytes = await readPrivateBytes(filename, label);
  let value;
  try {
    parseStrictJson(bytes);
    value = JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    fail('BETA_SCHEMA_INVALID', `${label} is not strict JSON`, error);
  }
  if (!bytes.equals(jcsBytes(value))) {
    fail('BETA_SCHEMA_INVALID', `${label} must use exact canonical JSON bytes`);
  }
  return Object.freeze({ bytes, sha256: sha256(bytes), value });
}

async function assertExactInventory(directory, expected, label) {
  const actual = (await readdir(directory)).sort();
  const wanted = [...expected].sort();
  if (canonicalJson(actual) !== canonicalJson(wanted)) {
    fail('BETA_INVENTORY_INVALID', `${label} has extra or missing entries`);
  }
}

async function runPinnedSnarkjs(toolchain, args, {
  abortSignal,
  cwd,
  secretPromptBytes,
  requirePrompt = false,
  timeoutMs = 30 * 60 * 1000,
} = {}) {
  if (abortSignal?.aborted) {
    fail('BETA_SNARKJS_ABORTED', `pinned snarkjs ${args[0]} ${args[1]} was not started after operator abort`);
  }
  return new Promise((resolve, reject) => {
    const child = spawn(toolchain.nodeExecutable, [toolchain.snarkjsCli, ...args], {
      cwd,
      env: { LANG: 'C', LC_ALL: 'C', PATH: '', TZ: 'UTC' },
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let settled = false;
    let supplied = false;
    let aborted;
    let outputWindow = Buffer.alloc(0);
    let promptPayload;
    let killTimer;
    let timeoutTimer;
    const promptNeedle = Buffer.from(CONTRIBUTION_PROMPT, 'ascii');
    const signalHandlers = new Map();
    let abortEventHandler;
    const removeSignalHandlers = () => {
      for (const [signal, handler] of signalHandlers) process.removeListener(signal, handler);
      if (abortEventHandler !== undefined) {
        abortSignal.removeEventListener('abort', abortEventHandler);
      }
    };
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutTimer);
      clearTimeout(killTimer);
      removeSignalHandlers();
      outputWindow.fill(0);
      promptNeedle.fill(0);
      promptPayload?.fill(0);
      if (error) reject(error);
      else resolve();
    };
    const abortChild = (reason) => {
      if (aborted !== undefined || settled) return;
      aborted = reason;
      child.stdin.destroy();
      if (child.exitCode === null && child.signalCode === null) {
        child.kill('SIGTERM');
        killTimer = setTimeout(() => {
          if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
        }, 5_000);
        killTimer.unref();
      }
    };
    if (abortSignal !== undefined) {
      abortEventHandler = () => abortChild('operator requested abort');
      abortSignal.addEventListener('abort', abortEventHandler, { once: true });
      if (abortSignal.aborted) abortEventHandler();
    } else {
      for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGQUIT', 'SIGTSTP']) {
        const handler = () => abortChild(`operator signal ${signal}`);
        signalHandlers.set(signal, handler);
        process.on(signal, handler);
      }
    }
    timeoutTimer = setTimeout(() => abortChild('operation deadline exceeded'), timeoutMs);
    timeoutTimer.unref();
    const scan = (chunk) => {
      if (!requirePrompt || supplied) return;
      const combined = Buffer.concat([outputWindow, Buffer.from(chunk)]);
      const found = combined.indexOf(promptNeedle) !== -1;
      const retained = Math.min(promptNeedle.length - 1, combined.length);
      outputWindow.fill(0);
      outputWindow = Buffer.from(combined.subarray(combined.length - retained));
      combined.fill(0);
      if (!found) return;
      supplied = true;
      if (!(secretPromptBytes instanceof Uint8Array) || secretPromptBytes.byteLength !== 135) {
        abortChild('invalid internal entropy prompt');
        return;
      }
      promptPayload = Buffer.alloc(secretPromptBytes.byteLength + 1);
      Buffer.from(
        secretPromptBytes.buffer,
        secretPromptBytes.byteOffset,
        secretPromptBytes.byteLength,
      ).copy(promptPayload);
      promptPayload[promptPayload.length - 1] = 0x0a;
      child.stdin.end(promptPayload, () => promptPayload.fill(0));
    };
    child.stdout.on('data', scan);
    child.stderr.on('data', scan);
    child.stdout.on('error', () => {});
    child.stderr.on('error', () => {});
    child.stdin.on('error', () => {});
    child.once('error', (error) => finish(new V2BetaSingleContributorCeremonyError(
      'BETA_SNARKJS_FAILED',
      `pinned snarkjs could not start ${args[0]} ${args[1]}`,
      error,
    )));
    child.once('close', (code, signal) => {
      if (aborted !== undefined) {
        finish(new V2BetaSingleContributorCeremonyError(
          'BETA_SNARKJS_ABORTED',
          `pinned snarkjs ${args[0]} ${args[1]} aborted: ${aborted}`,
        ));
      } else if (code !== 0) {
        finish(new V2BetaSingleContributorCeremonyError(
          'BETA_SNARKJS_FAILED',
          `pinned snarkjs rejected ${args[0]} ${args[1]} (exit ${code ?? signal})`,
        ));
      } else if (requirePrompt && !supplied) {
        finish(new V2BetaSingleContributorCeremonyError(
          'BETA_ENTROPY_PROMPT_MISSING',
          'pinned snarkjs completed without requesting contribution entropy',
        ));
      } else finish();
    });
    if (!requirePrompt) child.stdin.end();
  });
}

function parseB01Manifest(value) {
  if (value?.schema !== B01_SCHEMA
    || value.status !== 'b01-pre-freeze-candidate-awaiting-independent-review'
    || value.b01PreFreezeCandidate !== true
    || value.ceremonyAuthorized !== false
    || value.claims?.developmentKey !== true
    || value.claims?.finalKey !== false
    || value.production !== false
    || value.releaseQualified !== false
    || !GIT.test(value.source?.gitCommit)
    || !GIT.test(value.source?.gitTree)
    || !RAW_HASH.test(value.runtime?.proofArtifacts?.r1cs)
    || !RAW_HASH.test(value.runtime?.proofArtifacts?.powersOfTau)
    || !RAW_HASH.test(value.runtime?.proofArtifacts?.initialProvingKey)
    || typeof value.runtime?.path !== 'string'
    || !path.isAbsolute(value.runtime.path)) {
    fail('BETA_B01_INVALID', 'B-01-pre manifest is not an exact non-authorized development-key candidate');
  }
  return value;
}

function publicKeySpkiBase64(privateKey) {
  return createPublicKey(privateKey)
    .export({ type: 'spki', format: 'der' })
    .toString('base64');
}

function canonicalVerificationKey(bytes) {
  let value;
  try {
    parseStrictJson(bytes);
    value = JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    fail('BETA_VERIFICATION_KEY_INVALID', 'snarkjs exported invalid verification-key JSON', error);
  }
  return jcsBytes(value);
}

function validatePreparation(value) {
  exactKeys(value, 'beta preparation', [
    'artifacts', 'assurance', 'b01', 'ceremonyId', 'claims', 'participant',
    'entropyPolicySha256', 'implementation', 'implementationSha256', 'request',
    'schema', 'source', 'status', 'toolchain', 'toolchainSha256',
  ]);
  if (value.schema !== V2_BETA_SINGLE_CONTRIBUTOR_PREPARATION_SCHEMA
    || value.status !== 'prepared-awaiting-local-secret-contribution'
    || canonicalJson(value.assurance) !== canonicalJson(BETA_SINGLE_CONTRIBUTOR_CEREMONY_PROFILE)
    || canonicalJson(value.claims) !== canonicalJson(FALSE_CLAIMS)
    || !ID.test(value.ceremonyId)
    || !ID.test(value.participant?.id)
    || typeof value.participant.publicKeySpkiBase64 !== 'string'
    || value.entropyPolicySha256 !== BETA_SINGLE_CONTRIBUTOR_ENTROPY_POLICY_SHA256
    || !HASH.test(value.implementationSha256)
    || !HASH.test(value.toolchainSha256)
    || !HASH.test(value.b01?.manifestSha256)
    || !GIT.test(value.source?.gitCommit)
    || !GIT.test(value.source?.gitTree)) {
    fail('BETA_SCHEMA_INVALID', 'beta preparation claim or identity boundary is invalid');
  }
  exactKeys(value.participant, 'beta preparation participant', ['id', 'publicKeySpkiBase64']);
  exactKeys(value.source, 'beta preparation source', ['gitCommit', 'gitTree']);
  exactKeys(value.b01, 'beta preparation B-01 binding', ['bundleStatus', 'manifestSha256']);
  validateImplementationManifest(value.implementation);
  if (canonicalJson(value.implementation.source) !== canonicalJson(value.source)) {
    fail('BETA_IMPLEMENTATION_INVALID', 'beta implementation does not bind the preparation source');
  }
  if (value.b01.bundleStatus
    !== 'verified-b01-pre-freeze-candidate-awaiting-independent-review') {
    fail('BETA_SCHEMA_INVALID', 'beta preparation B-01 verification status is invalid');
  }
  for (const [name, artifact] of Object.entries(value.artifacts ?? {})) {
    const expectedFiles = {
      initialZkey: 'initial.zkey',
      ptau: 'powers-of-tau.ptau',
      r1cs: 'relation.r1cs',
    };
    if (!['initialZkey', 'ptau', 'r1cs'].includes(name)
      || artifact?.file !== expectedFiles[name]
      || !HASH.test(artifact.sha256)
      || !/^[1-9][0-9]*$/u.test(artifact.bytes)) {
      fail('BETA_SCHEMA_INVALID', 'beta preparation artifact record is invalid');
    }
  }
  if (Object.keys(value.artifacts ?? {}).length !== 3
    || sha256(jcsBytes(value.toolchain)) !== value.toolchainSha256
    || sha256(jcsBytes(value.implementation)) !== value.implementationSha256) {
    fail('BETA_SCHEMA_INVALID', 'beta preparation toolchain or artifact inventory is invalid');
  }
  const expectedRequest = createBetaSingleContributorContributionRequest({
    ceremonyId: value.ceremonyId,
    entropyPolicySha256: value.entropyPolicySha256,
    implementationSha256: value.implementationSha256,
    sequence: 1,
    r1csSha256: value.artifacts.r1cs.sha256,
    ptauSha256: value.artifacts.ptau.sha256,
    previousZkeySha256: value.artifacts.initialZkey.sha256,
  });
  if (canonicalJson(expectedRequest) !== canonicalJson(value.request)) {
    fail('BETA_SCHEMA_INVALID', 'beta preparation request does not bind its artifacts');
  }
  return value;
}

async function fsyncDirectory(directory) {
  let handle;
  try {
    handle = await open(directory, fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY ?? 0));
    await handle.sync();
  } finally {
    await handle?.close();
  }
}

/** Prepare a private, B-01-bound beta contribution directory. */
export async function prepareV2BetaSingleContributorCeremony({
  b01Bundle,
  ceremonyId,
  outputDirectory,
  participantId,
}) {
  assertNodeVersion();
  if (!ID.test(ceremonyId) || !ID.test(participantId)) {
    fail('BETA_ID_INVALID', 'ceremonyId and participantId must be lowercase stable identifiers');
  }
  if (typeof outputDirectory !== 'string' || !path.isAbsolute(outputDirectory)) {
    fail('BETA_PATH_INVALID', 'outputDirectory must be an absolute new path');
  }
  const target = path.resolve(outputDirectory);
  if (target === REPOSITORY_ROOT || target.startsWith(`${REPOSITORY_ROOT}${path.sep}`)) {
    fail('BETA_PATH_INVALID', 'beta custody material must be created outside the source checkout');
  }
  const parent = await directPrivateDirectory(path.dirname(target), 'beta output parent');
  try {
    await lstat(target);
    fail('BETA_PATH_INVALID', 'beta output directory must not already exist');
  } catch (error) {
    if (error instanceof V2BetaSingleContributorCeremonyError) throw error;
    if (error?.code !== 'ENOENT') throw error;
  }

  const verifiedB01 = await verifyV2B01PreFreezeBundle(b01Bundle);
  const b01Record = await readCanonical(
    path.join(await directPrivateDirectory(b01Bundle, 'B-01-pre bundle'), 'manifest.json'),
    'B-01-pre manifest',
  );
  const b01 = parseB01Manifest(b01Record.value);
  if (verifiedB01.manifestSha256 !== b01Record.sha256.slice('sha256:'.length)) {
    fail('BETA_B01_INVALID', 'B-01-pre verifier and manifest hash disagree');
  }
  const implementation = await collectV2BetaSingleContributorImplementationManifest();
  const implementationSha256 = sha256(jcsBytes(implementation));
  if (canonicalJson(implementation.source) !== canonicalJson(b01.source)) {
    fail('BETA_IMPLEMENTATION_INVALID', 'B-01 source and beta implementation source differ');
  }
  const runtime = await directPrivateDirectory(b01.runtime.path, 'B-01-bound runtime');
  const sources = Object.freeze({
    r1cs: path.join(runtime, 'proof', 'main-chipnet.r1cs'),
    ptau: path.join(runtime, 'proof', 'powers-of-tau.ptau'),
    initialZkey: path.join(runtime, 'proof', 'initial.zkey'),
  });
  const expected = Object.freeze({
    r1cs: `sha256:${b01.runtime.proofArtifacts.r1cs}`,
    ptau: `sha256:${b01.runtime.proofArtifacts.powersOfTau}`,
    initialZkey: `sha256:${b01.runtime.proofArtifacts.initialProvingKey}`,
  });

  let stage;
  try {
    stage = await mkdtemp(path.join(parent, '.shieldkit-v2-beta-prepare-'));
    await chmod(stage, 0o700);
    await directPrivateDirectory(stage, 'beta preparation stage');
    const artifacts = {
      r1cs: {
        file: 'relation.r1cs',
        ...await copyPrivateFile(sources.r1cs, path.join(stage, 'relation.r1cs'), 'B-01 R1CS', expected.r1cs),
      },
      ptau: {
        file: 'powers-of-tau.ptau',
        ...await copyPrivateFile(sources.ptau, path.join(stage, 'powers-of-tau.ptau'), 'B-01 Powers of Tau', expected.ptau),
      },
      initialZkey: {
        file: 'initial.zkey',
        ...await copyPrivateFile(sources.initialZkey, path.join(stage, 'initial.zkey'), 'B-01 initial zkey', expected.initialZkey),
      },
    };
    const toolchain = await collectV2FinalZkeyToolchainManifest();
    const resolvedToolchain = await verifyV2FinalZkeyToolchainManifest(toolchain);
    await runPinnedSnarkjs(resolvedToolchain, [
      'powersoftau', 'verify', path.join(stage, artifacts.ptau.file),
    ], { cwd: stage });
    await runPinnedSnarkjs(resolvedToolchain, [
      'zkey', 'verify', path.join(stage, artifacts.r1cs.file),
      path.join(stage, artifacts.ptau.file), path.join(stage, artifacts.initialZkey.file),
    ], { cwd: stage });
    await verifyV2FinalZkeyToolchainManifest(toolchain);
    await verifyImplementationManifest(implementation);

    const { privateKey } = generateKeyPairSync('ed25519');
    const privateKeyBytes = Buffer.from(privateKey.export({ type: 'pkcs8', format: 'pem' }));
    try {
      await writeExclusive(path.join(stage, PRIVATE_KEY_FILE), privateKeyBytes);
    } finally {
      privateKeyBytes.fill(0);
    }
    const request = createBetaSingleContributorContributionRequest({
      ceremonyId,
      entropyPolicySha256: BETA_SINGLE_CONTRIBUTOR_ENTROPY_POLICY_SHA256,
      implementationSha256,
      sequence: 1,
      r1csSha256: artifacts.r1cs.sha256,
      ptauSha256: artifacts.ptau.sha256,
      previousZkeySha256: artifacts.initialZkey.sha256,
    });
    const preparation = Object.freeze({
      schema: V2_BETA_SINGLE_CONTRIBUTOR_PREPARATION_SCHEMA,
      status: 'prepared-awaiting-local-secret-contribution',
      assurance: BETA_SINGLE_CONTRIBUTOR_CEREMONY_PROFILE,
      claims: FALSE_CLAIMS,
      ceremonyId,
      participant: Object.freeze({
        id: participantId,
        publicKeySpkiBase64: publicKeySpkiBase64(privateKey),
      }),
      source: Object.freeze({
        gitCommit: b01.source.gitCommit,
        gitTree: b01.source.gitTree,
      }),
      b01: Object.freeze({
        bundleStatus: verifiedB01.status,
        manifestSha256: b01Record.sha256,
      }),
      entropyPolicySha256: BETA_SINGLE_CONTRIBUTOR_ENTROPY_POLICY_SHA256,
      implementation,
      implementationSha256,
      artifacts: Object.freeze({
        initialZkey: Object.freeze(artifacts.initialZkey),
        ptau: Object.freeze(artifacts.ptau),
        r1cs: Object.freeze(artifacts.r1cs),
      }),
      request,
      toolchain,
      toolchainSha256: sha256(jcsBytes(toolchain)),
    });
    await writeCanonical(path.join(stage, 'preparation.json'), preparation);
    await assertExactInventory(stage, PREPARATION_FILES, 'beta preparation stage');
    await fsyncDirectory(stage);
    await rename(stage, target);
    stage = undefined;
    await fsyncDirectory(parent);
    return Object.freeze({
      ceremonyDirectory: target,
      claims: FALSE_CLAIMS,
      preparationSha256: sha256(jcsBytes(preparation)),
      status: preparation.status,
    });
  } finally {
    if (stage !== undefined) await rm(stage, { recursive: true, force: true });
  }
}

function terminalState() {
  const result = spawnSync('/usr/bin/stty', ['--file=/dev/tty', '-g'], {
    env: { LANG: 'C', LC_ALL: 'C', PATH: '', TZ: 'UTC' },
    encoding: 'utf8',
  });
  const state = String(result.stdout ?? '').trim();
  if (result.status !== 0 || !/^[0-9a-f:]+$/iu.test(state)) {
    fail('BETA_TTY_FAILED', 'could not capture the controlling terminal state');
  }
  return state;
}

function restoreTerminalState(state) {
  const result = spawnSync('/usr/bin/stty', ['--file=/dev/tty', state], {
    env: { LANG: 'C', LC_ALL: 'C', PATH: '', TZ: 'UTC' },
    stdio: 'ignore',
  });
  return result.status === 0;
}

async function runInternalTtyReader() {
  if (process.stdin.isTTY !== true || process.stdout.isTTY === true) return 64;
  let total = 0;
  for await (const chunk of process.stdin) {
    const bytes = Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    const newline = bytes.findIndex((byte) => byte === 0x0a || byte === 0x0d);
    const length = newline === -1 ? bytes.length : newline;
    if (total + length > BETA_SINGLE_CONTRIBUTOR_MAX_DICE_ROLLS) {
      bytes.fill(0);
      return 65;
    }
    total += length;
    if (length > 0) {
      await new Promise((resolve, reject) => {
        process.stdout.write(bytes.subarray(0, length), (error) => {
          bytes.fill(0);
          if (error) reject(error);
          else resolve();
        });
      });
    } else {
      bytes.fill(0);
    }
    if (newline !== -1) return 0;
  }
  return 66;
}

/** Read 100 through 128 d6 outcomes without echoing or retaining them. */
export async function readV2BetaDiceFromControllingTerminal() {
  let tty;
  let originalTerminalState;
  let terminalModified = false;
  let collected;
  let acceptedDice;
  let interruptedSignal;
  let reader;
  let readerKillTimer;
  const signals = ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGQUIT', 'SIGTSTP'];
  const handlers = new Map();
  const removeHandlers = () => {
    for (const [signal, handler] of handlers) process.removeListener(signal, handler);
  };
  try {
    tty = await open('/dev/tty', fsConstants.O_RDWR | (fsConstants.O_NOCTTY ?? 0));
    originalTerminalState = terminalState();
    const disable = spawnSync('/usr/bin/stty', ['--file=/dev/tty', '-echo'], {
      env: { LANG: 'C', LC_ALL: 'C', PATH: '', TZ: 'UTC' },
      stdio: 'ignore',
    });
    if (disable.status !== 0) fail('BETA_TTY_FAILED', 'could not disable terminal echo');
    terminalModified = true;
    for (const signal of signals) {
      const handler = () => {
        if (interruptedSignal !== undefined) return;
        interruptedSignal = signal;
        collected?.fill(0);
        acceptedDice?.fill(0);
        removeHandlers();
        // The blocking TTY read lives in a disposable child, so terminating it
        // reliably releases the parent to restore the exact terminal state in
        // the ordinary finally path. No host signal listener can intercept
        // this child-directed termination.
        if (reader !== undefined
          && reader.exitCode === null
          && reader.signalCode === null) {
          reader.kill('SIGTERM');
          readerKillTimer = setTimeout(() => {
            if (reader.exitCode === null && reader.signalCode === null) reader.kill('SIGKILL');
          }, 5_000);
          readerKillTimer.unref();
        }
      };
      handlers.set(signal, handler);
      process.prependListener(signal, handler);
    }
    await tty.write(Buffer.from(
      'Enter 100-128 physical d6 results (digits 1-6 only; no spaces), then press Enter. Nothing will echo:\n> ',
      'utf8',
    ));
    collected = Buffer.alloc(BETA_SINGLE_CONTRIBUTOR_MAX_DICE_ROLLS);
    let length = 0;
    if (interruptedSignal !== undefined) {
      fail('BETA_TTY_INTERRUPTED', `dice entry interrupted by ${interruptedSignal}`);
    }
    reader = spawn(process.execPath, [fileURLToPath(import.meta.url), INTERNAL_TTY_READER_MODE], {
      env: { LANG: 'C', LC_ALL: 'C', PATH: '', TZ: 'UTC' },
      shell: false,
      stdio: [tty.fd, 'pipe', 'ignore'],
      windowsHide: true,
    });
    let overflow = false;
    reader.stdout.on('data', (chunk) => {
      const chunkBytes = Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
      if (length + chunk.length > collected.length) {
        collected.fill(0);
        chunkBytes.fill(0);
        overflow = true;
        reader.kill('SIGTERM');
        return;
      }
      chunkBytes.copy(collected, length);
      length += chunk.length;
      chunkBytes.fill(0);
    });
    reader.stdout.on('error', () => {});
    const readerResult = await new Promise((resolve, reject) => {
      reader.once('error', (error) => reject(new V2BetaSingleContributorCeremonyError(
        'BETA_TTY_FAILED',
        'could not start the isolated controlling-terminal reader',
        error,
      )));
      reader.once('close', (code, signal) => resolve({ code, signal }));
    });
    clearTimeout(readerKillTimer);
    if (interruptedSignal !== undefined) {
      fail('BETA_TTY_INTERRUPTED', `dice entry interrupted by ${interruptedSignal}`);
    }
    if (overflow || readerResult.code === 65) {
      fail('BETA_DICE_INVALID', 'dice entry exceeded the maximum accepted length');
    }
    if (readerResult.code !== 0 || readerResult.signal !== null) {
      fail('BETA_TTY_FAILED', 'isolated controlling-terminal reader did not complete');
    }
    const dice = Buffer.from(collected.subarray(0, length));
    collected.fill(0);
    if (dice.length < BETA_SINGLE_CONTRIBUTOR_MIN_DICE_ROLLS
      || dice.length > BETA_SINGLE_CONTRIBUTOR_MAX_DICE_ROLLS
      || dice.some((byte) => byte < 0x31 || byte > 0x36)) {
      dice.fill(0);
      fail('BETA_DICE_INVALID', 'dice entry must be 100 through 128 digits from 1 through 6');
    }
    acceptedDice = dice;
    return acceptedDice;
  } finally {
    removeHandlers();
    clearTimeout(readerKillTimer);
    collected?.fill(0);
    if (reader !== undefined && reader.exitCode === null && reader.signalCode === null) {
      reader.kill('SIGKILL');
    }
    const restored = !terminalModified || restoreTerminalState(originalTerminalState);
    await tty?.write(Buffer.from('\n', 'utf8')).catch(() => {});
    await tty?.close().catch(() => {});
    if (!restored) {
      acceptedDice?.fill(0);
      fail('BETA_TTY_RESTORE_FAILED', 'could not restore the controlling terminal state');
    }
    if (interruptedSignal !== undefined) {
      acceptedDice?.fill(0);
      fail('BETA_TTY_INTERRUPTED', `dice entry interrupted by ${interruptedSignal}`);
    }
  }
}

async function loadPreparation(ceremonyDirectory) {
  const directory = await directPrivateDirectory(ceremonyDirectory, 'beta ceremony directory');
  const entries = await readdir(directory, { withFileTypes: true });
  const names = entries.map((entry) => entry.name).sort();
  if (names.some((name) => name.startsWith('.contribution-stage-')
    || name.startsWith('.verification-stage-'))) {
    fail(
      'BETA_STALE_STAGE',
      'an interrupted beta stage exists; do not retry this ceremony in place—preserve diagnostics and prepare a fresh ceremony ID',
    );
  }
  const allowed = [...PREPARATION_FILES, 'result'].sort();
  if (canonicalJson(names) !== canonicalJson(allowed)
    && canonicalJson(names) !== canonicalJson(POST_CONTRIBUTION_FILES)
    && canonicalJson(names) !== canonicalJson(PREPARATION_FILES)) {
    fail('BETA_INVENTORY_INVALID', 'beta ceremony directory has extra or missing entries');
  }
  const preparationRecord = await readCanonical(
    path.join(directory, 'preparation.json'),
    'beta preparation',
  );
  const preparation = validatePreparation(preparationRecord.value);
  await verifyImplementationManifest(preparation.implementation);
  return Object.freeze({
    directory,
    preparation,
    preparationSha256: preparationRecord.sha256,
  });
}

async function remeasurePreparationArtifacts(directory, preparation) {
  const measured = {};
  for (const name of ['initialZkey', 'ptau', 'r1cs']) {
    const artifact = preparation.artifacts[name];
    measured[name] = await measurePrivateFile(
      path.join(directory, artifact.file),
      `beta ${name}`,
      artifact.sha256,
    );
    if (measured[name].bytes !== artifact.bytes) {
      fail('BETA_HASH_MISMATCH', `beta ${name} size changed`);
    }
  }
  return Object.freeze(measured);
}

async function loadPreparedParticipantPrivateKey(loaded) {
  const keyFilename = path.join(loaded.directory, PRIVATE_KEY_FILE);
  let privateKey;
  let privateKeyBytes;
  try {
    privateKeyBytes = await readPrivateBytes(
      keyFilename,
      'beta participant signing key',
      64n * 1024n,
    );
    privateKey = createPrivateKey(privateKeyBytes);
  } catch (error) {
    if (error instanceof V2BetaSingleContributorCeremonyError) throw error;
    fail('BETA_SIGNING_KEY_INVALID', 'beta signing key is not a valid private key', error);
  } finally {
    privateKeyBytes?.fill(0);
  }
  if (privateKey.asymmetricKeyType !== 'ed25519'
    || publicKeySpkiBase64(privateKey) !== loaded.preparation.participant.publicKeySpkiBase64) {
    fail('BETA_SIGNING_KEY_INVALID', 'beta signing key does not match the preparation participant');
  }
  return privateKey;
}

/** Complete all non-secret contribution checks before asking for physical rolls. */
export async function preflightV2BetaSingleContributorCeremony({ ceremonyDirectory }) {
  assertNodeVersion();
  const loaded = await loadPreparation(ceremonyDirectory);
  if ((await readdir(loaded.directory)).includes('result')) {
    fail('BETA_ALREADY_CONTRIBUTED', 'beta result already exists; contributions are never retried in place');
  }
  await remeasurePreparationArtifacts(loaded.directory, loaded.preparation);
  await verifyV2FinalZkeyToolchainManifest(loaded.preparation.toolchain);
  await loadPreparedParticipantPrivateKey(loaded);
  return Object.freeze({
    ceremonyDirectory: loaded.directory,
    entropyPolicySha256: loaded.preparation.entropyPolicySha256,
    implementationSha256: loaded.preparation.implementationSha256,
    status: 'ready-for-local-secret-contribution',
  });
}

/**
 * Execute the secret contribution and atomically publish only verified output.
 * Programmatic callers should run the exported secretless preflight before
 * collecting rolls; this function repeats every check after receiving them.
 */
export async function contributeV2BetaSingleContributorCeremony({
  ceremonyDirectory,
  dice,
  osRandomBytes = undefined,
  snarkjsTimeoutMs = 30 * 60 * 1000,
}) {
  if (!(dice instanceof Uint8Array)) {
    fail('BETA_DICE_INVALID', 'the ceremony executor accepts dice only as a Uint8Array');
  }
  const diceBytes = Buffer.from(dice.buffer, dice.byteOffset, dice.byteLength);
  const abortController = new AbortController();
  const contributionSignals = ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGQUIT', 'SIGTSTP'];
  const contributionSignalHandlers = new Map();
  let abortedSignal;
  let osBytes;
  let entropy;
  let stage;
  let preserveStage = false;
  let published = false;
  const clearEntropyInputs = () => {
    diceBytes.fill(0);
    osBytes?.fill(0);
    entropy?.promptBytes.fill(0);
  };
  const throwIfAborted = () => {
    if (abortController.signal.aborted) {
      fail(
        'BETA_OPERATOR_ABORTED',
        `beta contribution aborted by operator signal ${abortedSignal ?? 'unknown'}`,
      );
    }
  };
  for (const signal of contributionSignals) {
    const handler = () => {
      if (published || abortController.signal.aborted) return;
      abortedSignal = signal;
      clearEntropyInputs();
      abortController.abort();
    };
    contributionSignalHandlers.set(signal, handler);
    process.on(signal, handler);
  }
  try {
    if (!Number.isSafeInteger(snarkjsTimeoutMs)
      || snarkjsTimeoutMs < 1
      || snarkjsTimeoutMs > 30 * 60 * 1000) {
      fail('BETA_TIMEOUT_INVALID', 'snarkjsTimeoutMs must be an integer from 1 through 1800000');
    }
    if (diceBytes.length < BETA_SINGLE_CONTRIBUTOR_MIN_DICE_ROLLS
      || diceBytes.length > BETA_SINGLE_CONTRIBUTOR_MAX_DICE_ROLLS
      || diceBytes.some((byte) => byte < 0x31 || byte > 0x36)) {
      fail('BETA_DICE_INVALID', 'dice must be 100 through 128 ASCII bytes from 1 through 6');
    }
    if (osRandomBytes === undefined) {
      osBytes = randomBytes(64);
    } else {
      if (!(osRandomBytes instanceof Uint8Array) || osRandomBytes.byteLength !== 64) {
        fail('BETA_OS_RANDOM_INVALID', 'osRandomBytes must be exactly 64 bytes');
      }
      osBytes = Buffer.from(
        osRandomBytes.buffer,
        osRandomBytes.byteOffset,
        osRandomBytes.byteLength,
      );
    }
    throwIfAborted();
    assertNodeVersion();
    const loaded = await loadPreparation(ceremonyDirectory);
    throwIfAborted();
    if ((await readdir(loaded.directory)).includes('result')) {
      fail('BETA_ALREADY_CONTRIBUTED', 'beta result already exists; contributions are never retried in place');
    }
    throwIfAborted();
    await remeasurePreparationArtifacts(loaded.directory, loaded.preparation);
    throwIfAborted();
    const toolchain = await verifyV2FinalZkeyToolchainManifest(loaded.preparation.toolchain);
    throwIfAborted();
    const keyFilename = path.join(loaded.directory, PRIVATE_KEY_FILE);
    const privateKey = await loadPreparedParticipantPrivateKey(loaded);
    throwIfAborted();
    stage = await mkdtemp(path.join(loaded.directory, '.contribution-stage-'));
    await chmod(stage, 0o700);
    await directPrivateDirectory(stage, 'beta contribution stage');
    throwIfAborted();
    entropy = deriveBetaSingleContributorEntropy({
      dice: diceBytes,
      osRandomBytes: osBytes,
      request: loaded.preparation.request,
    });
    preserveStage = true;
    // These two raw sources are no longer needed after the KDF. Clear the
    // caller-owned views immediately rather than retaining them during setup.
    diceBytes.fill(0);
    osBytes.fill(0);
    throwIfAborted();
    const outputZkey = path.join(stage, 'beta-proving-key.zkey');
    await runPinnedSnarkjs(toolchain, [
      'zkey', 'contribute',
      path.join(loaded.directory, loaded.preparation.artifacts.initialZkey.file),
      outputZkey,
      `--name=${loaded.preparation.participant.id}`,
    ], {
      abortSignal: abortController.signal,
      cwd: stage,
      secretPromptBytes: entropy.promptBytes,
      requirePrompt: true,
      timeoutMs: snarkjsTimeoutMs,
    });
    entropy.promptBytes.fill(0);
    throwIfAborted();
    await chmod(outputZkey, 0o600);
    const output = await measurePrivateFile(outputZkey, 'beta proving key');
    if (output.sha256 === loaded.preparation.artifacts.initialZkey.sha256) {
      fail('BETA_CONTRIBUTION_INVALID', 'beta proving key hash equals the input zkey hash');
    }
    await runPinnedSnarkjs(toolchain, [
      'zkey', 'verify',
      path.join(loaded.directory, loaded.preparation.artifacts.r1cs.file),
      path.join(loaded.directory, loaded.preparation.artifacts.ptau.file),
      outputZkey,
    ], {
      abortSignal: abortController.signal,
      cwd: stage,
      timeoutMs: snarkjsTimeoutMs,
    });
    throwIfAborted();
    const rawVerificationKey = path.join(stage, '.verification-key.raw.json');
    await runPinnedSnarkjs(toolchain, [
      'zkey', 'export', 'verificationkey', outputZkey, rawVerificationKey,
    ], {
      abortSignal: abortController.signal,
      cwd: stage,
      timeoutMs: snarkjsTimeoutMs,
    });
    throwIfAborted();
    await chmod(rawVerificationKey, 0o600);
    const rawVerificationKeyBytes = await readPrivateBytes(
      rawVerificationKey,
      'raw beta verification key',
    );
    const canonicalVk = canonicalVerificationKey(rawVerificationKeyBytes);
    rawVerificationKeyBytes.fill(0);
    await rm(rawVerificationKey, { force: true });
    await writeExclusive(path.join(stage, 'verification-key.json'), canonicalVk);
    const verificationKey = await measurePrivateFile(
      path.join(stage, 'verification-key.json'),
      'beta verification key',
    );
    await verifyV2FinalZkeyToolchainManifest(loaded.preparation.toolchain);
    await remeasurePreparationArtifacts(loaded.directory, loaded.preparation);
    await verifyImplementationManifest(loaded.preparation.implementation);

    const receipt = signBetaSingleContributorContributionReceipt({
      request: loaded.preparation.request,
      contributedZkeySha256: output.sha256,
      participantId: loaded.preparation.participant.id,
      participantPrivateKey: privateKey,
      entropyCommitment: entropy.entropyCommitment,
    });
    const transcript = verifyBetaSingleContributorExternalReceiptChain({
      ceremonyId: loaded.preparation.ceremonyId,
      r1csSha256: loaded.preparation.artifacts.r1cs.sha256,
      ptauSha256: loaded.preparation.artifacts.ptau.sha256,
      initialZkeySha256: loaded.preparation.artifacts.initialZkey.sha256,
      receipts: [receipt],
    });
    const receiptSha256 = await writeCanonical(path.join(stage, 'receipt.json'), receipt);
    const transcriptFileSha256 = await writeCanonical(path.join(stage, 'transcript.json'), transcript);
    const result = Object.freeze({
      schema: V2_BETA_SINGLE_CONTRIBUTOR_RESULT_SCHEMA,
      status: 'beta-single-contributor-cryptographically-verified-unqualified',
      assuranceClass: 'beta-single-contributor',
      claims: FALSE_CLAIMS,
      ceremonyId: loaded.preparation.ceremonyId,
      participant: loaded.preparation.participant,
      source: loaded.preparation.source,
      preparationSha256: loaded.preparationSha256,
      b01ManifestSha256: loaded.preparation.b01.manifestSha256,
      entropyPolicySha256: loaded.preparation.entropyPolicySha256,
      implementationSha256: loaded.preparation.implementationSha256,
      toolchainSha256: loaded.preparation.toolchainSha256,
      requestSha256: entropy.requestSha256,
      entropyCommitment: entropy.entropyCommitment,
      receiptSha256,
      transcriptFileSha256,
      transcriptSha256: transcript.transcriptSha256,
      artifacts: Object.freeze({
        betaProvingKey: Object.freeze({
          bytes: output.bytes,
          file: 'beta-proving-key.zkey',
          sha256: output.sha256,
        }),
        verificationKey: Object.freeze({
          bytes: verificationKey.bytes,
          file: 'verification-key.json',
          sha256: verificationKey.sha256,
        }),
      }),
      verification: Object.freeze({
        entropyTransport: 'child-stdin-after-pinned-snarkjs-prompt',
        pinnedToolchainCheckedBeforeAndAfter: true,
        zkeyVerify: true,
        verificationKeyExportedAndCanonicalized: true,
      }),
    });
    await writeCanonical(path.join(stage, 'result.json'), result);
    await assertExactInventory(stage, RESULT_FILES, 'beta result stage');
    await fsyncDirectory(stage);
    throwIfAborted();
    // Remove and durably record deletion of the private receipt-signing key
    // before the completed result becomes visible.
    await rm(keyFilename, { force: false });
    await fsyncDirectory(loaded.directory);
    throwIfAborted();
    await rename(stage, path.join(loaded.directory, 'result'));
    stage = undefined;
    published = true;
    await fsyncDirectory(loaded.directory);
    return Object.freeze({
      ceremonyDirectory: loaded.directory,
      claims: FALSE_CLAIMS,
      resultSha256: sha256(jcsBytes(result)),
      status: result.status,
    });
  } finally {
    for (const [signal, handler] of contributionSignalHandlers) {
      process.removeListener(signal, handler);
    }
    clearEntropyInputs();
    if (stage !== undefined && !preserveStage) {
      await rm(stage, { recursive: true, force: true });
    }
  }
}

function validateResult(value, preparationSha256) {
  exactKeys(value, 'beta result', [
    'artifacts', 'assuranceClass', 'b01ManifestSha256', 'ceremonyId', 'claims',
    'entropyCommitment', 'entropyPolicySha256', 'implementationSha256',
    'participant', 'preparationSha256', 'receiptSha256', 'requestSha256',
    'schema', 'source', 'status', 'toolchainSha256', 'transcriptFileSha256',
    'transcriptSha256', 'verification',
  ]);
  if (value.schema !== V2_BETA_SINGLE_CONTRIBUTOR_RESULT_SCHEMA
    || value.status !== 'beta-single-contributor-cryptographically-verified-unqualified'
    || value.assuranceClass !== 'beta-single-contributor'
    || canonicalJson(value.claims) !== canonicalJson(FALSE_CLAIMS)
    || value.preparationSha256 !== preparationSha256
    || !HASH.test(value.b01ManifestSha256)
    || value.entropyPolicySha256 !== BETA_SINGLE_CONTRIBUTOR_ENTROPY_POLICY_SHA256
    || !HASH.test(value.implementationSha256)
    || !HASH.test(value.toolchainSha256)
    || !HASH.test(value.requestSha256)
    || !HASH.test(value.entropyCommitment)
    || !HASH.test(value.receiptSha256)
    || !HASH.test(value.transcriptFileSha256)
    || !HASH.test(value.transcriptSha256)
    || value.verification?.entropyTransport !== 'child-stdin-after-pinned-snarkjs-prompt'
    || value.verification?.pinnedToolchainCheckedBeforeAndAfter !== true
    || value.verification?.zkeyVerify !== true
    || value.verification?.verificationKeyExportedAndCanonicalized !== true) {
    fail('BETA_SCHEMA_INVALID', 'beta result claim or verification boundary is invalid');
  }
  exactKeys(value.artifacts, 'beta result artifacts', ['betaProvingKey', 'verificationKey']);
  exactKeys(value.participant, 'beta result participant', ['id', 'publicKeySpkiBase64']);
  exactKeys(value.source, 'beta result source', ['gitCommit', 'gitTree']);
  exactKeys(value.verification, 'beta result verification', [
    'entropyTransport', 'pinnedToolchainCheckedBeforeAndAfter',
    'verificationKeyExportedAndCanonicalized', 'zkeyVerify',
  ]);
  for (const [name, expectedFile] of Object.entries({
    betaProvingKey: 'beta-proving-key.zkey',
    verificationKey: 'verification-key.json',
  })) {
    const artifact = value.artifacts[name];
    exactKeys(artifact, `beta result ${name}`, ['bytes', 'file', 'sha256']);
    if (artifact.file !== expectedFile || !HASH.test(artifact.sha256)
      || !/^[1-9][0-9]*$/u.test(artifact.bytes)) {
      fail('BETA_SCHEMA_INVALID', `beta result ${name} is invalid`);
    }
  }
  return value;
}

/** Independently re-read, re-hash, and cryptographically verify a beta result. */
export async function verifyV2BetaSingleContributorCeremony({ ceremonyDirectory }) {
  assertNodeVersion();
  const loaded = await loadPreparation(ceremonyDirectory);
  await remeasurePreparationArtifacts(loaded.directory, loaded.preparation);
  const resultDirectory = await directPrivateDirectory(
    path.join(loaded.directory, 'result'),
    'beta result directory',
  );
  await assertExactInventory(resultDirectory, RESULT_FILES, 'beta result directory');
  const resultRecord = await readCanonical(path.join(resultDirectory, 'result.json'), 'beta result');
  const result = validateResult(resultRecord.value, loaded.preparationSha256);
  if (result.ceremonyId !== loaded.preparation.ceremonyId
    || canonicalJson(result.participant) !== canonicalJson(loaded.preparation.participant)
    || canonicalJson(result.source) !== canonicalJson(loaded.preparation.source)
    || result.b01ManifestSha256 !== loaded.preparation.b01.manifestSha256
    || result.entropyPolicySha256 !== loaded.preparation.entropyPolicySha256
    || result.implementationSha256 !== loaded.preparation.implementationSha256
    || result.toolchainSha256 !== loaded.preparation.toolchainSha256) {
    fail('BETA_BINDING_INVALID', 'beta result is not bound to its preparation');
  }
  const receiptRecord = await readCanonical(path.join(resultDirectory, 'receipt.json'), 'beta receipt');
  const transcriptRecord = await readCanonical(path.join(resultDirectory, 'transcript.json'), 'beta transcript');
  if (receiptRecord.sha256 !== result.receiptSha256
    || transcriptRecord.sha256 !== result.transcriptFileSha256) {
    fail('BETA_HASH_MISMATCH', 'beta receipt or transcript hash does not match the result');
  }
  const transcript = verifyBetaSingleContributorExternalReceiptChain({
    ceremonyId: loaded.preparation.ceremonyId,
    r1csSha256: loaded.preparation.artifacts.r1cs.sha256,
    ptauSha256: loaded.preparation.artifacts.ptau.sha256,
    initialZkeySha256: loaded.preparation.artifacts.initialZkey.sha256,
    receipts: [receiptRecord.value],
  });
  if (canonicalJson(transcript) !== canonicalJson(transcriptRecord.value)
    || transcript.transcriptSha256 !== result.transcriptSha256
    || transcript.betaProvingKeySha256 !== result.artifacts.betaProvingKey.sha256
    || transcript.entropyPolicySha256 !== loaded.preparation.entropyPolicySha256
    || transcript.implementationSha256 !== loaded.preparation.implementationSha256
    || receiptRecord.value.entropyCommitment !== result.entropyCommitment
    || canonicalJson(receiptRecord.value.participant)
      !== canonicalJson(loaded.preparation.participant)) {
    fail('BETA_TRANSCRIPT_INVALID', 'beta receipt/transcript/result binding is invalid');
  }
  if (result.requestSha256 !== requestSha256(loaded.preparation.request)) {
    fail('BETA_BINDING_INVALID', 'beta result request hash does not bind the preparation request');
  }
  const provingKey = await measurePrivateFile(
    path.join(resultDirectory, result.artifacts.betaProvingKey.file),
    'beta proving key',
    result.artifacts.betaProvingKey.sha256,
  );
  const verificationKey = await measurePrivateFile(
    path.join(resultDirectory, result.artifacts.verificationKey.file),
    'beta verification key',
    result.artifacts.verificationKey.sha256,
  );
  if (provingKey.bytes !== result.artifacts.betaProvingKey.bytes
    || verificationKey.bytes !== result.artifacts.verificationKey.bytes) {
    fail('BETA_HASH_MISMATCH', 'beta proving or verification key size changed');
  }
  const toolchain = await verifyV2FinalZkeyToolchainManifest(loaded.preparation.toolchain);
  await runPinnedSnarkjs(toolchain, [
    'zkey', 'verify',
    path.join(loaded.directory, loaded.preparation.artifacts.r1cs.file),
    path.join(loaded.directory, loaded.preparation.artifacts.ptau.file),
    path.join(resultDirectory, result.artifacts.betaProvingKey.file),
  ], { cwd: resultDirectory });
  let temporary;
  try {
    temporary = await mkdtemp(path.join(loaded.directory, '.verification-stage-'));
    await chmod(temporary, 0o700);
    const exported = path.join(temporary, 'verification-key.json');
    await runPinnedSnarkjs(toolchain, [
      'zkey', 'export', 'verificationkey',
      path.join(resultDirectory, result.artifacts.betaProvingKey.file), exported,
    ], { cwd: temporary });
    await chmod(exported, 0o600);
    const exportedBytes = await readPrivateBytes(exported, 're-exported beta verification key');
    const retainedBytes = await readPrivateBytes(
      path.join(resultDirectory, result.artifacts.verificationKey.file),
      'retained beta verification key',
    );
    const canonical = canonicalVerificationKey(exportedBytes);
    try {
      if (sha256(canonical) !== result.artifacts.verificationKey.sha256
        || !canonical.equals(retainedBytes)) {
        fail('BETA_VERIFICATION_KEY_INVALID', 'beta proving key exports a different verification key');
      }
    } finally {
      exportedBytes.fill(0);
      retainedBytes.fill(0);
      canonical.fill(0);
    }
  } finally {
    if (temporary !== undefined) await rm(temporary, { recursive: true, force: true });
  }
  await verifyV2FinalZkeyToolchainManifest(loaded.preparation.toolchain);
  await remeasurePreparationArtifacts(loaded.directory, loaded.preparation);
  await verifyImplementationManifest(loaded.preparation.implementation);
  return Object.freeze({
    schema: V2_BETA_SINGLE_CONTRIBUTOR_VERIFICATION_SCHEMA,
    status: 'beta-single-contributor-reverified-unqualified',
    claims: FALSE_CLAIMS,
    ceremonyId: loaded.preparation.ceremonyId,
    preparationSha256: loaded.preparationSha256,
    resultSha256: resultRecord.sha256,
    betaProvingKeySha256: provingKey.sha256,
    entropyPolicySha256: loaded.preparation.entropyPolicySha256,
    implementationSha256: loaded.preparation.implementationSha256,
    verificationKeySha256: verificationKey.sha256,
    transcriptFileSha256: transcriptRecord.sha256,
    transcriptSha256: transcript.transcriptSha256,
  });
}

function options(argv) {
  if (!Array.isArray(argv) || argv.length === 0) {
    fail('BETA_ARGUMENT_INVALID', 'a beta ceremony subcommand is required');
  }
  const [command, ...rest] = argv;
  if (!['prepare', 'contribute', 'verify'].includes(command) || rest.length % 2 !== 0) {
    fail('BETA_ARGUMENT_INVALID', 'usage: v2-beta-single-contributor-ceremony.mjs prepare --b01-bundle <absolute> --ceremony-id <id> --participant-id <id> --output-dir <absolute-new-dir> | contribute --ceremony-dir <absolute> | verify --ceremony-dir <absolute>');
  }
  const values = {};
  for (let index = 0; index < rest.length; index += 2) {
    const name = rest[index];
    const value = rest[index + 1];
    if (typeof value !== 'string' || value.length === 0 || value.startsWith('--')
      || Object.hasOwn(values, name)) {
      fail('BETA_ARGUMENT_INVALID', 'beta ceremony arguments are invalid or duplicated');
    }
    values[name] = value;
  }
  if (command === 'prepare') {
    exactKeys(values, 'prepare arguments', [
      '--b01-bundle', '--ceremony-id', '--output-dir', '--participant-id',
    ]);
    for (const name of ['--b01-bundle', '--output-dir']) {
      if (!path.isAbsolute(values[name]) || path.resolve(values[name]) !== values[name]) {
        fail('BETA_ARGUMENT_INVALID', `${name} must be an absolute canonical path`);
      }
    }
    return Object.freeze({
      command,
      b01Bundle: values['--b01-bundle'],
      ceremonyId: values['--ceremony-id'],
      outputDirectory: values['--output-dir'],
      participantId: values['--participant-id'],
    });
  }
  exactKeys(values, `${command} arguments`, ['--ceremony-dir']);
  if (!path.isAbsolute(values['--ceremony-dir'])
    || path.resolve(values['--ceremony-dir']) !== values['--ceremony-dir']) {
    fail('BETA_ARGUMENT_INVALID', '--ceremony-dir must be an absolute canonical path');
  }
  return Object.freeze({ command, ceremonyDirectory: values['--ceremony-dir'] });
}

export function parseV2BetaSingleContributorArguments(argv) {
  return options(argv);
}

async function main(argv) {
  process.umask(0o077);
  const parsed = options(argv);
  if (parsed.command === 'prepare') {
    const { command: _command, ...input } = parsed;
    return prepareV2BetaSingleContributorCeremony(input);
  }
  if (parsed.command === 'verify') {
    return verifyV2BetaSingleContributorCeremony({ ceremonyDirectory: parsed.ceremonyDirectory });
  }
  await preflightV2BetaSingleContributorCeremony({
    ceremonyDirectory: parsed.ceremonyDirectory,
  });
  const dice = await readV2BetaDiceFromControllingTerminal();
  return contributeV2BetaSingleContributorCeremony({
    ceremonyDirectory: parsed.ceremonyDirectory,
    dice,
  });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  if (process.argv.length === 3 && process.argv[2] === INTERNAL_TTY_READER_MODE) {
    try {
      process.exitCode = await runInternalTtyReader();
    } catch {
      process.exitCode = 67;
    }
  } else {
    try {
      const result = await main(process.argv.slice(2));
      process.stdout.write(`${canonicalJson(result)}\n`);
    } catch (error) {
      process.stderr.write(`${error instanceof Error ? `${error.name}: ${error.message}` : String(error)}\n`);
      process.exitCode = 1;
    }
  }
}
