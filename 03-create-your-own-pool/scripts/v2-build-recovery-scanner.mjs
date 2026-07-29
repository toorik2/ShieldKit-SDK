#!/usr/bin/env node

/** Build and locally publish the native V2 recovery scanner. No network is used. */
import { createHash, randomBytes } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { chmod, lstat, mkdir, open, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { dirname, basename, join, relative, resolve, sep } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import {
  RECOVERY_SCANNER_ARTIFACT_SCHEMA,
  RECOVERY_SCANNER_LINUX_X64_ARTIFACT_ID,
  RECOVERY_SCANNER_LINUX_X64_FILENAME,
  RECOVERY_SCANNER_MANIFEST_FILENAME,
  RECOVERY_SCANNER_TARGET,
  V2_RECOVERY_SCANNER_PROTOCOL_SCHEMAS,
} from '../packages/profile/v2/recovery-scanner-artifact.mjs';

const CRATE_RELATIVE_PATH = 'crates/shieldkit-v2-recovery';
const BINARY_NAME = 'shieldkit-v2-recovery';
const REVISION = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
export const PINNED_RECOVERY_SCANNER_RUST_TOOLCHAIN = '1.97.1';

export class V2RecoveryScannerBuildError extends Error {
  constructor(message) { super(message); this.name = 'V2RecoveryScannerBuildError'; }
}
const fail = (message) => { throw new V2RecoveryScannerBuildError(message); };
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

function exactKeys(value, keys, label) {
  if (Object.getPrototypeOf(value) !== Object.prototype) fail(`${label} must be a plain object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown options`);
}

function requireSafeRelativePath(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0') || value === '.' || value === '..') fail(`${label} must be a nonempty path`);
  return value;
}

function inside(parent, candidate) {
  const relation = relative(parent, candidate);
  return relation !== '' && !relation.startsWith(`..${sep}`) && relation !== '..' && !relation.includes(`..${sep}`);
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino
    && left.size === right.size && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs && left.nlink === right.nlink
    && left.mode === right.mode;
}

async function stableRegularFile(path, label, expectedLinks, {
  executable = false,
} = {}) {
  const beforePath = await lstat(path);
  if (
    !beforePath.isFile()
    || beforePath.isSymbolicLink()
    || beforePath.nlink !== expectedLinks
    || (executable && (beforePath.mode & 0o111) === 0)
  ) {
    fail(
      `${label} must be a regular, non-symlink, ${expectedLinks}-link${
        executable ? ' executable' : ''
      } file`,
    );
  }
  const handle = await open(
    path,
    fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0),
  );
  try {
    const beforeFd = await handle.stat();
    if (!beforeFd.isFile() || !sameIdentity(beforePath, beforeFd)) fail(`${label} FD/path identity differs before read`);
    const data = await handle.readFile();
    const afterFd = await handle.stat();
    const afterPath = await lstat(path);
    if (!afterFd.isFile() || !afterPath.isFile() || afterPath.isSymbolicLink() || !sameIdentity(beforeFd, afterFd) || !sameIdentity(beforeFd, afterPath)) fail(`${label} changed while being read`);
    return Object.freeze({ data, bytes: afterFd.size, sha256: sha256(data), identity: Object.freeze({ dev: afterFd.dev, ino: afterFd.ino }) });
  } finally {
    await handle.close();
  }
}

async function regularSingleLink(path, label) {
  return await stableRegularFile(path, label, 1);
}

async function cargoReleaseBinary(targetDirectory) {
  const release = join(targetDirectory, 'release');
  const binaryPath = join(release, BINARY_NAME);
  const binary = await stableRegularFile(
    binaryPath,
    'built recovery scanner',
    2,
    { executable: true },
  );
  const deps = join(release, 'deps');
  const depsInfo = await lstat(deps);
  if (!depsInfo.isDirectory() || depsInfo.isSymbolicLink()) fail('built recovery scanner deps must be a real directory');
  const entries = await readdir(deps, { withFileTypes: true });
  const siblings = [];
  for (const entry of entries) {
    const candidate = join(deps, entry.name);
    const info = await lstat(candidate);
    if (info.dev === binary.identity.dev && info.ino === binary.identity.ino) siblings.push({ candidate, info });
  }
  if (siblings.length !== 1) fail('built recovery scanner must have exactly one same-inode release/deps sibling');
  const sibling = siblings[0];
  if (!sibling.info.isFile() || sibling.info.isSymbolicLink() || sibling.info.nlink !== 2) fail('built recovery scanner release/deps sibling has unsafe topology');
  const checkedSibling = await stableRegularFile(
    sibling.candidate,
    'built recovery scanner release/deps sibling',
    2,
    { executable: true },
  );
  if (checkedSibling.identity.dev !== binary.identity.dev || checkedSibling.identity.ino !== binary.identity.ino || checkedSibling.sha256 !== binary.sha256) fail('built recovery scanner release/deps sibling changed identity or bytes');
  return binary;
}

async function fsyncFile(path) {
  const handle = await open(path, 'r');
  try { await handle.sync(); } finally { await handle.close(); }
}
async function fsyncDirectory(path) {
  const handle = await open(path, 'r');
  try { await handle.sync(); } finally { await handle.close(); }
}

async function defaultRunner({ command, args, cwd, env = undefined }) {
  return await new Promise((resolveResult, reject) => {
    const child = spawn(command, args, {
      cwd,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
      // Keep the required cargo argv exact while making dependency resolution
      // fail closed if a local cache is insufficient; this builder never uses
      // the network as provenance or as a dependency source.
      env: {
        ...process.env,
        CARGO_NET_OFFLINE: 'true',
        MISE_RUST_VERSION: PINNED_RECOVERY_SCANNER_RUST_TOOLCHAIN,
        RUSTUP_TOOLCHAIN: PINNED_RECOVERY_SCANNER_RUST_TOOLCHAIN,
        ...env,
      },
    });
    const stdout = []; const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', (code, signal) => resolveResult({ code, signal, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') }));
  });
}

async function runChecked(runner, command, args, cwd, env = undefined) {
  const result = await runner({ command, args: Object.freeze([...args]), cwd, env });
  if (Object.getPrototypeOf(result) !== Object.prototype || !Number.isInteger(result.code) || typeof result.stdout !== 'string' || typeof result.stderr !== 'string') fail(`runner returned an invalid result for ${command}`);
  if (result.code !== 0) fail(`${command} ${args.join(' ')} failed with exit ${result.code}: ${result.stderr.trim()}`);
  return result.stdout.trim();
}

async function canonicalWorkspace(value) {
  const candidate = resolve(value);
  const metadata = await lstat(candidate);
  if (
    !metadata.isDirectory()
    || metadata.isSymbolicLink()
    || await realpath(candidate) !== candidate
  ) {
    fail('workspaceRoot must be a canonical real directory');
  }
  return candidate;
}

async function locateCrate(workspaceRoot) {
  const crate = resolve(workspaceRoot, CRATE_RELATIVE_PATH);
  if (!inside(workspaceRoot, crate)) fail('recovery scanner crate escaped workspace');
  const cargoToml = join(crate, 'Cargo.toml');
  const cargoLock = join(crate, 'Cargo.lock');
  const toml = (await regularSingleLink(cargoToml, 'recovery scanner Cargo.toml')).data.toString('utf8');
  if (!/^name\s*=\s*"shieldkit-v2-recovery"\s*$/m.test(toml)) fail('recovery scanner crate has the wrong Cargo package name');
  await regularSingleLink(cargoLock, 'recovery scanner Cargo.lock');
  return Object.freeze({ crate, cargoLock, cargoToml });
}

async function buildInternal(options, runner) {
  exactKeys(options, ['allowDevelopmentOnly', 'output', 'workspaceRoot'], 'build options');
  if (typeof options.allowDevelopmentOnly !== 'boolean') fail('allowDevelopmentOnly must be boolean');
  if (typeof options.workspaceRoot !== 'string' || options.workspaceRoot.length === 0) fail('workspaceRoot must be a nonempty path');
  requireSafeRelativePath(options.output, 'output');
  if (process.platform !== 'linux' || process.arch !== 'x64') fail('recovery scanner builder supports Linux x64 only');
  const workspaceRoot = await canonicalWorkspace(options.workspaceRoot);
  const output = resolve(workspaceRoot, options.output);
  if (!inside(workspaceRoot, output)) fail('output must be inside workspaceRoot');
  try { await lstat(output); fail('output must not already exist'); } catch (error) { if (!(error && error.code === 'ENOENT')) throw error; }
  const source = await locateCrate(workspaceRoot);
  const revision = await runChecked(runner, 'git', ['rev-parse', 'HEAD'], workspaceRoot);
  if (!REVISION.test(revision) || /^0+$/.test(revision)) fail('git rev-parse HEAD did not return a nonzero 40- or 64-character lowercase revision');
  const sourceStatus = await runChecked(
    runner,
    'git',
    ['status', '--porcelain=v1', '-z'],
    workspaceRoot,
  );
  const dirty = sourceStatus.length !== 0;
  if (dirty && !options.allowDevelopmentOnly) fail('dirty source revision requires allowDevelopmentOnly');
  const rustc = await runChecked(runner, 'rustc', ['--version'], source.crate);
  const cargo = await runChecked(runner, 'cargo', ['--version'], source.crate);
  if (
    !rustc.startsWith(
      `rustc ${PINNED_RECOVERY_SCANNER_RUST_TOOLCHAIN}`,
    )
    || !cargo.startsWith(
      `cargo ${PINNED_RECOVERY_SCANNER_RUST_TOOLCHAIN}`,
    )
  ) {
    fail(
      `recovery scanner requires Rust toolchain ${
        PINNED_RECOVERY_SCANNER_RUST_TOOLCHAIN
      }`,
    );
  }
  const cargoTomlBefore = await regularSingleLink(
    source.cargoToml,
    'recovery scanner Cargo.toml',
  );
  const cargoLockBefore = await regularSingleLink(
    source.cargoLock,
    'recovery scanner Cargo.lock',
  );
  const targetDirectory = join(workspaceRoot, `.shieldkit-v2-recovery-target-${process.pid}-${randomBytes(12).toString('hex')}`);
  await mkdir(targetDirectory, { mode: 0o700 });
  const targetMetadata = await lstat(targetDirectory);
  if (
    !targetMetadata.isDirectory()
    || targetMetadata.isSymbolicLink()
    || (targetMetadata.mode & 0o777) !== 0o700
  ) {
    await rm(targetDirectory, { recursive: true, force: true });
    fail('private Cargo target directory is not an exact mode-0700 directory');
  }
  let built;
  try {
    await runChecked(runner, 'cargo', ['build', '--locked', '--release'], source.crate, { CARGO_TARGET_DIR: targetDirectory });
    built = await cargoReleaseBinary(targetDirectory);
  } finally {
    await rm(targetDirectory, { recursive: true, force: true });
  }
  const [
    revisionAfter,
    sourceStatusAfter,
    rustcAfter,
    cargoAfter,
    cargoTomlAfter,
    cargoLockAfter,
  ] = await Promise.all([
    runChecked(runner, 'git', ['rev-parse', 'HEAD'], workspaceRoot),
    runChecked(
      runner,
      'git',
      ['status', '--porcelain=v1', '-z'],
      workspaceRoot,
    ),
    runChecked(runner, 'rustc', ['--version'], source.crate),
    runChecked(runner, 'cargo', ['--version'], source.crate),
    regularSingleLink(
      source.cargoToml,
      'recovery scanner Cargo.toml',
    ),
    regularSingleLink(
      source.cargoLock,
      'recovery scanner Cargo.lock',
    ),
  ]);
  if (
    revisionAfter !== revision
    || sourceStatusAfter !== sourceStatus
    || rustcAfter !== rustc
    || cargoAfter !== cargo
    || cargoTomlAfter.sha256 !== cargoTomlBefore.sha256
    || cargoLockAfter.sha256 !== cargoLockBefore.sha256
  ) {
    fail(
      'recovery scanner source, lockfile, or toolchain changed during the build',
    );
  }
  const parent = dirname(output);
  const parentInfo = await lstat(parent);
  if (!parentInfo.isDirectory() || parentInfo.isSymbolicLink()) fail('output parent must be a real directory');
  const stage = await new Promise((resolveStage, reject) => {
    const candidate = join(parent, `.${basename(output)}.stage-${process.pid}-${randomBytes(12).toString('hex')}`);
    mkdir(candidate, { mode: 0o700 }).then(() => resolveStage(candidate), reject);
  });
  try {
    const stagedBinary = join(stage, RECOVERY_SCANNER_LINUX_X64_FILENAME);
    await writeFile(stagedBinary, built.data, { mode: 0o700, flag: 'wx' });
    await chmod(stagedBinary, 0o755);
    await fsyncFile(stagedBinary);
    const manifest = {
      schema: RECOVERY_SCANNER_ARTIFACT_SCHEMA,
      target: RECOVERY_SCANNER_TARGET,
      binaryArtifactId: RECOVERY_SCANNER_LINUX_X64_ARTIFACT_ID,
      binarySha256: built.sha256,
      binaryBytes: built.bytes,
      cargoLockSha256: cargoLockBefore.sha256,
      cargoVersion: cargo,
      eligibility: dirty ? 'dirty-source-development-only' : 'clean-source-build',
      protocolSchemas: V2_RECOVERY_SCANNER_PROTOCOL_SCHEMAS,
      rustcVersion: rustc,
      sourceRevision: revision,
    };
    const manifestBytes = Buffer.from(canonicalizeJcs(manifest), 'utf8');
    const manifestPath = join(stage, RECOVERY_SCANNER_MANIFEST_FILENAME);
    await writeFile(manifestPath, manifestBytes, { mode: 0o600, flag: 'wx' });
    await fsyncFile(manifestPath);
    await fsyncDirectory(stage);
    // Reserve the output only after all staged bytes are durable. mkdir and
    // writeFile(flag: 'wx') are no-replace operations. Copy the binary first
    // and the manifest completion marker last. Final files are single-link
    // copies, so a crash after the marker cannot leave an otherwise complete
    // package that the descriptor validator rejects solely because the
    // private stage still exists.
    //
    // Never delete output on failure: once the no-replace mkdir succeeds,
    // another process can add data there. An interrupted output is
    // deliberately non-publishable (no manifest) and requires a new target or
    // an explicit user-directed quarantine operation.
    await mkdir(output, { mode: 0o700 });
    await fsyncDirectory(parent);
    const publishedBinary = join(
      output,
      RECOVERY_SCANNER_LINUX_X64_FILENAME,
    );
    await writeFile(
      publishedBinary,
      built.data,
      { mode: 0o700, flag: 'wx' },
    );
    await chmod(publishedBinary, 0o755);
    await fsyncFile(publishedBinary);
    const publishedManifest = join(
      output,
      RECOVERY_SCANNER_MANIFEST_FILENAME,
    );
    await writeFile(
      publishedManifest,
      manifestBytes,
      { mode: 0o600, flag: 'wx' },
    );
    await fsyncFile(publishedManifest);
    await fsyncDirectory(output);
    await fsyncDirectory(parent);
    // Publication is complete. Failure to remove a private, random stage is
    // cleanup debt, not permission to report the durable output as failed or
    // to touch the final target.
    await rm(stage, { recursive: true, force: true }).catch(() => undefined);
    await fsyncDirectory(parent).catch(() => undefined);
    return Object.freeze({ output, manifest: Object.freeze(manifest) });
  } catch (error) {
    await rm(stage, { recursive: true, force: true });
    throw error;
  }
}

export async function buildV2RecoveryScanner(options) {
  return await buildInternal(options, defaultRunner);
}

/** Test-only injection seam. Production callers must use buildV2RecoveryScanner. */
export async function buildV2RecoveryScannerForUnitTest(options, runner) {
  if (typeof runner !== 'function') fail('unit-test runner must be a function');
  return await buildInternal(options, runner);
}

export function parseV2RecoveryScannerBuildArguments(argv, cwd = process.cwd()) {
  if (!Array.isArray(argv) || (argv.length !== 2 && argv.length !== 3)) fail('usage: v2-build-recovery-scanner.mjs --output <new-output-directory> [--development-only]');
  const developmentOnly = argv.length === 3;
  if (argv[0] !== '--output' || typeof argv[1] !== 'string' || argv[1].length === 0 || argv[1].startsWith('-') || (developmentOnly && argv[2] !== '--development-only')) fail('usage: v2-build-recovery-scanner.mjs --output <new-output-directory> [--development-only]');
  return Object.freeze({ workspaceRoot: resolve(cwd), output: argv[1], allowDevelopmentOnly: developmentOnly });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = await buildV2RecoveryScanner(parseV2RecoveryScannerBuildArguments(process.argv.slice(2)));
    process.stdout.write(`${canonicalizeJcs(result.manifest)}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
    process.exitCode = 1;
  }
}
