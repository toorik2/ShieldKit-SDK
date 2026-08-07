/**
 * Final Groth16 proving-key verification.
 *
 * This module deliberately does not accept a command runner, a verifier
 * callback, or a pre-computed result. A caller either supplies local files and
 * a manifest-pinned toolchain, or no final-key claim can be made.
 *
 * Qualification also requires the documented clean-host boundary: the current
 * user must control an immutable installation while verification runs. Full
 * before/after closure measurements detect ordinary drift, but no same-process
 * API can prevent a hostile same-UID actor from performing a perfectly timed
 * replace-and-restore attack on executable dependencies.
 */
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { constants as fsConstants } from 'node:fs';
import {
  chmod,
  lstat,
  mkdtemp,
  open,
  readFile,
  realpath,
  rm,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { parseStrictJson } from '../load.mjs';
import { canonicalizeJcs } from './profile-core.mjs';
import {
  collectNpmBuildClosure,
  NPM_BUILD_CLOSURE_SCHEMA,
  verifyNpmBuildClosure,
} from './npm-closure.mjs';

export const V2_FINAL_ZKEY_TOOLCHAIN_SCHEMA =
  'shieldkit-v2-direct-final-zkey-toolchain-v1';
export const V2_FINAL_ZKEY_VERIFICATION_SCHEMA =
  'shieldkit-v2-direct-final-zkey-verification-v1';
export const V2_FINAL_ZKEY_RESOLUTION_SCHEMA =
  'shieldkit-v2-direct-final-zkey-cryptographic-resolution-v1';

const HASH = /^sha256:[0-9a-f]{64}$/;
const VERSION = /^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/;
const execFileAsync = promisify(execFile);
const snarkjsRoot = path.dirname(fileURLToPath(import.meta.resolve('snarkjs')));
const installedSnarkjsCli = path.join(snarkjsRoot, 'build', 'cli.cjs');
const installedSnarkjsPackage = path.join(snarkjsRoot, 'package.json');
const installedRepositoryRoot = path.dirname(path.dirname(snarkjsRoot));

export class V2FinalZkeyVerificationError extends Error {
  constructor(code, message, cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'V2FinalZkeyVerificationError';
    this.code = code;
  }
}

const fail = (code, message, cause) => {
  throw new V2FinalZkeyVerificationError(code, message, cause);
};

const sha256 = (bytes) =>
  `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

function exactKeys(value, label, keys) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail('FINAL_ZKEY_SCHEMA_INVALID', `${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail('FINAL_ZKEY_SCHEMA_INVALID', `${label} has missing or unknown properties`);
  }
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail('FINAL_ZKEY_SCHEMA_INVALID', `${label} must be a lowercase sha256 identifier`);
  }
  return value;
}

function version(value, label) {
  if (typeof value !== 'string' || !VERSION.test(value)) {
    fail('FINAL_ZKEY_SCHEMA_INVALID', `${label} must be an exact version string`);
  }
  return value;
}

function sameIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const entry of Object.values(value)) deepFreeze(entry);
    Object.freeze(value);
  }
  return value;
}

/** A manifest record for the executable bytes which make the final-key claim. */
export function parseV2FinalZkeyToolchainManifest(value) {
  exactKeys(value, 'final zkey toolchain manifest', ['node', 'npmClosure', 'schema', 'snarkjs']);
  if (value.schema !== V2_FINAL_ZKEY_TOOLCHAIN_SCHEMA) {
    fail('FINAL_ZKEY_SCHEMA_INVALID', 'final zkey toolchain manifest schema is invalid');
  }
  exactKeys(value.node, 'final zkey toolchain manifest.node', ['executableSha256', 'version']);
  exactKeys(value.snarkjs, 'final zkey toolchain manifest.snarkjs', [
    'cliSha256', 'packageJsonSha256', 'version',
  ]);
  if (
    value.npmClosure === null
    || Array.isArray(value.npmClosure)
    || typeof value.npmClosure !== 'object'
    || value.npmClosure.schema !== NPM_BUILD_CLOSURE_SCHEMA
    || !Array.isArray(value.npmClosure.roots)
    || !value.npmClosure.roots.includes('node_modules/snarkjs')
  ) {
    fail('FINAL_ZKEY_SCHEMA_INVALID', 'final zkey toolchain manifest must include the complete snarkjs npm closure');
  }
  return Object.freeze({
    schema: value.schema,
    node: Object.freeze({
      executableSha256: hash(value.node.executableSha256, 'toolchain.node.executableSha256'),
      version: version(value.node.version, 'toolchain.node.version'),
    }),
    snarkjs: Object.freeze({
      cliSha256: hash(value.snarkjs.cliSha256, 'toolchain.snarkjs.cliSha256'),
      packageJsonSha256: hash(value.snarkjs.packageJsonSha256, 'toolchain.snarkjs.packageJsonSha256'),
      version: version(value.snarkjs.version, 'toolchain.snarkjs.version'),
    }),
    // Deep validation is deliberately repeated immediately before execution by
    // verifyNpmBuildClosure, which measures every package and file it names.
    npmClosure: deepFreeze(structuredClone(value.npmClosure)),
  });
}

async function canonicalRegularFile(value, label, { requireUnique = true } = {}) {
  if (typeof value !== 'string' || !path.isAbsolute(value)) {
    fail('FINAL_ZKEY_PATH_INVALID', `${label} must be an absolute path`);
  }
  const requested = path.resolve(value);
  let beforePath;
  let resolved;
  try {
    beforePath = await lstat(requested, { bigint: true });
    resolved = await realpath(requested);
  } catch (error) {
    fail('FINAL_ZKEY_PATH_INVALID', `${label} is not readable`, error);
  }
  if (
    !beforePath.isFile()
    || beforePath.isSymbolicLink()
    || (requireUnique && beforePath.nlink !== 1n)
    || resolved !== requested
    || beforePath.size <= 0n
  ) {
    fail('FINAL_ZKEY_PATH_INVALID', `${label} must be a nonempty canonical regular${requireUnique ? ' unique' : ''} file`);
  }
  return Object.freeze({ filename: requested, metadata: beforePath });
}

async function copyAndMeasurePrivate(source, destination, label, expectedHash) {
  const sourceFile = await canonicalRegularFile(source, label);
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  let input;
  let output;
  try {
    input = await open(sourceFile.filename, flags);
    const before = await input.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || !sameIdentity(sourceFile.metadata, before)) {
      fail('FINAL_ZKEY_INPUT_CHANGED', `${label} changed before private verification copy`);
    }
    output = await open(destination, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    const digest = createHash('sha256');
    for await (const chunk of input.createReadStream({ autoClose: false, highWaterMark: 1024 * 1024 })) {
      const bytes = Buffer.from(chunk);
      digest.update(bytes);
      let position = 0;
      while (position < bytes.length) {
        const { bytesWritten } = await output.write(bytes, position, bytes.length - position);
        if (bytesWritten <= 0) fail('FINAL_ZKEY_IO_FAILED', `${label} private copy made no progress`);
        position += bytesWritten;
      }
    }
    await output.sync();
    const after = await input.stat({ bigint: true });
    const afterPath = await lstat(sourceFile.filename, { bigint: true });
    if (!sameIdentity(sourceFile.metadata, after) || !sameIdentity(after, afterPath)) {
      fail('FINAL_ZKEY_INPUT_CHANGED', `${label} changed while private verification copy was made`);
    }
    const measured = `sha256:${digest.digest('hex')}`;
    if (measured !== expectedHash) {
      fail('FINAL_ZKEY_ARTIFACT_HASH_MISMATCH', `${label} does not match its manifest-pinned hash`);
    }
    await chmod(destination, 0o600);
    return Object.freeze({ filename: destination, sha256: measured, bytes: after.size });
  } finally {
    await output?.close();
    await input?.close();
  }
}

async function measureInstalledFile(filename, label) {
  const file = await canonicalRegularFile(filename, label, { requireUnique: false });
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  let handle;
  try {
    handle = await open(file.filename, flags);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || !sameIdentity(file.metadata, before)) {
      fail('FINAL_ZKEY_TOOLCHAIN_CHANGED', `${label} changed before it could be measured`);
    }
    const digest = createHash('sha256');
    for await (const chunk of handle.createReadStream({ autoClose: false, highWaterMark: 1024 * 1024 })) digest.update(chunk);
    const after = await handle.stat({ bigint: true });
    const afterPath = await lstat(file.filename, { bigint: true });
    if (!sameIdentity(before, after) || !sameIdentity(after, afterPath)) {
      fail('FINAL_ZKEY_TOOLCHAIN_CHANGED', `${label} changed while it was measured`);
    }
    return Object.freeze({ filename: file.filename, sha256: `sha256:${digest.digest('hex')}` });
  } finally {
    await handle?.close();
  }
}

/** Measure the installed executable and bundled snarkjs package for manifest creation. */
export async function collectV2FinalZkeyToolchainManifest() {
  const nodeExecutable = await measureInstalledFile(path.resolve(process.execPath), 'Node executable');
  const cli = await measureInstalledFile(path.resolve(installedSnarkjsCli), 'snarkjs CLI');
  const packageFile = await measureInstalledFile(path.resolve(installedSnarkjsPackage), 'snarkjs package.json');
  let packageValue;
  try {
    packageValue = parseStrictJson(await readFile(packageFile.filename));
  } catch (error) {
    if (error instanceof V2FinalZkeyVerificationError) throw error;
    fail('FINAL_ZKEY_TOOLCHAIN_INVALID', 'installed snarkjs package.json is invalid', error);
  }
  if (typeof packageValue.version !== 'string' || !VERSION.test(packageValue.version)) {
    fail('FINAL_ZKEY_TOOLCHAIN_INVALID', 'installed snarkjs package.json has no exact version');
  }
  const npmClosure = await collectNpmBuildClosure({
    repositoryRoot: installedRepositoryRoot,
    roots: ['node_modules/snarkjs'],
  });
  return parseV2FinalZkeyToolchainManifest({
    schema: V2_FINAL_ZKEY_TOOLCHAIN_SCHEMA,
    node: { executableSha256: nodeExecutable.sha256, version: process.version },
    snarkjs: {
      cliSha256: cli.sha256,
      packageJsonSha256: packageFile.sha256,
      version: packageValue.version,
    },
    npmClosure,
  });
}

/** Verify that the exact local CLI and package named by a pinned manifest exist. */
async function verifyToolchainManifest(value, {
  historicalRootLockfile,
}) {
  const expected = parseV2FinalZkeyToolchainManifest(value);
  try {
    let closure = expected.npmClosure;
    if (historicalRootLockfile) {
      const current = await collectNpmBuildClosure({
        repositoryRoot: installedRepositoryRoot,
        lockfilePath: expected.npmClosure.lockfile.path,
        roots: expected.npmClosure.roots,
      });
      closure = deepFreeze({
        ...structuredClone(expected.npmClosure),
        lockfile: {
          ...structuredClone(expected.npmClosure.lockfile),
          bytes: current.lockfile.bytes,
          sha256: current.lockfile.sha256,
        },
      });
    }
    await verifyNpmBuildClosure(closure, {
      repositoryRoot: installedRepositoryRoot,
    });
  } catch (error) {
    fail('FINAL_ZKEY_TOOLCHAIN_MISMATCH', 'installed snarkjs dependency closure does not match the final-key toolchain manifest', error);
  }
  const actual = await collectV2FinalZkeyToolchainManifest();
  if (actual.node.version !== expected.node.version || actual.node.executableSha256 !== expected.node.executableSha256) {
    fail('FINAL_ZKEY_TOOLCHAIN_MISMATCH', 'the running Node executable does not match the final-key toolchain manifest');
  }
  if (
    actual.snarkjs.version !== expected.snarkjs.version
    || actual.snarkjs.cliSha256 !== expected.snarkjs.cliSha256
    || actual.snarkjs.packageJsonSha256 !== expected.snarkjs.packageJsonSha256
  ) {
    fail('FINAL_ZKEY_TOOLCHAIN_MISMATCH', 'installed snarkjs does not match the final-key toolchain manifest');
  }
  const nodeExecutable = await measureInstalledFile(path.resolve(process.execPath), 'Node executable');
  const cli = await measureInstalledFile(path.resolve(installedSnarkjsCli), 'snarkjs CLI');
  if (
    nodeExecutable.sha256 !== expected.node.executableSha256
    || cli.sha256 !== expected.snarkjs.cliSha256
  ) {
    fail(
      'FINAL_ZKEY_TOOLCHAIN_CHANGED',
      'Node or snarkjs changed during final-key toolchain verification',
    );
  }
  return Object.freeze({ nodeExecutable: nodeExecutable.filename, snarkjsCli: cli.filename, manifest: expected });
}

/** Verify the normal final-key toolchain, including the exact current root lockfile. */
export async function verifyV2FinalZkeyToolchainManifest(value) {
  return verifyToolchainManifest(value, { historicalRootLockfile: false });
}

/**
 * Reverify a historic ceremony toolchain after unrelated workspace additions
 * changed the enclosing root lockfile. Only that lockfile's whole-file byte
 * envelope is adapted to the current checkout: every relevant lock identity,
 * installed package byte, Node byte, and snarkjs byte remains exact. Callers
 * must separately authenticate the historic root lockfile from immutable
 * source provenance and bind it to `value.npmClosure.lockfile`.
 */
export async function verifyV2HistoricalFinalZkeyToolchainManifest(value) {
  return verifyToolchainManifest(value, { historicalRootLockfile: true });
}

function artifact(value, label) {
  exactKeys(value, label, ['path', 'sha256']);
  if (typeof value.path !== 'string' || !path.isAbsolute(value.path)) {
    fail('FINAL_ZKEY_SCHEMA_INVALID', `${label}.path must be an absolute path`);
  }
  return Object.freeze({ path: path.resolve(value.path), sha256: hash(value.sha256, `${label}.sha256`) });
}

function verificationInput(value) {
  exactKeys(value, 'final zkey verification input', [
    'finalZkey', 'ptau', 'r1cs', 'schema', 'toolchain', 'verificationKey',
  ]);
  if (value.schema !== V2_FINAL_ZKEY_VERIFICATION_SCHEMA) {
    fail('FINAL_ZKEY_SCHEMA_INVALID', 'final zkey verification input schema is invalid');
  }
  return Object.freeze({
    finalZkey: artifact(value.finalZkey, 'finalZkey'),
    ptau: artifact(value.ptau, 'ptau'),
    r1cs: artifact(value.r1cs, 'r1cs'),
    schema: value.schema,
    toolchain: parseV2FinalZkeyToolchainManifest(value.toolchain),
    verificationKey: artifact(value.verificationKey, 'verificationKey'),
  });
}

export function buildV2FinalZkeySnarkjsCommands({ r1csPath, ptauPath, zkeyPath, verificationKeyPath }) {
  for (const [label, value] of Object.entries({ r1csPath, ptauPath, zkeyPath, verificationKeyPath })) {
    if (typeof value !== 'string' || !path.isAbsolute(value)) {
      fail('FINAL_ZKEY_COMMAND_INVALID', `${label} must be an absolute path`);
    }
  }
  return Object.freeze({
    verify: Object.freeze(['zkey', 'verify', r1csPath, ptauPath, zkeyPath]),
    exportVerificationKey: Object.freeze(['zkey', 'export', 'verificationkey', zkeyPath, verificationKeyPath]),
  });
}

async function runPinnedSnarkjs(toolchain, args, cwd) {
  try {
    await execFileAsync(toolchain.nodeExecutable, [toolchain.snarkjsCli, ...args], {
      cwd,
      env: { LANG: 'C', LC_ALL: 'C', PATH: '', TZ: 'UTC' },
      maxBuffer: 8 * 1024 * 1024,
      shell: false,
      windowsHide: true,
    });
  } catch (error) {
    fail('FINAL_ZKEY_SNARKJS_REJECTED', `pinned snarkjs rejected ${args[0]} ${args[1]}`, error);
  }
}

async function privateVerificationDirectory() {
  const directory = await mkdtemp(path.join(tmpdir(), 'shieldkit-v2-final-zkey-'));
  await chmod(directory, 0o700);
  const metadata = await lstat(directory, { bigint: true });
  const uid = typeof process.getuid === 'function' ? BigInt(process.getuid()) : undefined;
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || (metadata.mode & 0o077n) !== 0n || (uid !== undefined && metadata.uid !== uid)) {
    await rm(directory, { force: true, recursive: true }).catch(() => {});
    fail('FINAL_ZKEY_TEMP_UNSAFE', 'could not create an owner-private final-key verification directory');
  }
  return directory;
}

async function canonicalManifestVerificationKey(privatePath, expectedHash) {
  const bytes = await readFile(privatePath);
  if (sha256(bytes) !== expectedHash) {
    fail('FINAL_ZKEY_ARTIFACT_HASH_MISMATCH', 'verification key does not match its manifest-pinned hash');
  }
  let value;
  try {
    // parseStrictJson rejects duplicate keys and other ambiguous JSON, but it
    // deliberately returns null-prototype objects. Reparse only after that
    // strict validation so the JCS implementation receives ordinary JSON
    // objects without weakening the duplicate-key boundary.
    parseStrictJson(bytes);
    value = JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    fail('FINAL_ZKEY_VK_INVALID', 'manifest-pinned verification key is not strict JSON', error);
  }
  const canonical = Buffer.from(canonicalizeJcs(value), 'utf8');
  if (!bytes.equals(canonical)) {
    fail('FINAL_ZKEY_VK_INVALID', 'manifest-pinned verification key must use exact JCS bytes');
  }
  return canonical;
}

async function canonicalExportedVerificationKey(filename) {
  let value;
  try {
    const bytes = await readFile(filename);
    parseStrictJson(bytes);
    value = JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    fail('FINAL_ZKEY_VK_INVALID', 'snarkjs exported an invalid verification key', error);
  }
  return Buffer.from(canonicalizeJcs(value), 'utf8');
}

/**
 * Cryptographically verify a final zkey, then independently derive and bind
 * its verification key. Every consumed artifact is copied after stable hash
 * verification into a fresh 0700 directory, which is always removed.
 */
export async function verifyV2FinalZkeyCryptographically(input) {
  const request = verificationInput(input);
  const toolchain = await verifyV2FinalZkeyToolchainManifest(request.toolchain);
  let directory;
  try {
    directory = await privateVerificationDirectory();
    const r1cs = await copyAndMeasurePrivate(request.r1cs.path, path.join(directory, 'relation.r1cs'), 'r1cs', request.r1cs.sha256);
    const ptau = await copyAndMeasurePrivate(request.ptau.path, path.join(directory, 'powers.ptau'), 'ptau', request.ptau.sha256);
    const finalZkey = await copyAndMeasurePrivate(request.finalZkey.path, path.join(directory, 'final.zkey'), 'final zkey', request.finalZkey.sha256);
    const expectedVerificationKeyPath = path.join(directory, 'expected-verification-key.json');
    await copyAndMeasurePrivate(request.verificationKey.path, expectedVerificationKeyPath, 'verification key', request.verificationKey.sha256);
    const expectedVerificationKey = await canonicalManifestVerificationKey(expectedVerificationKeyPath, request.verificationKey.sha256);
    const exportedVerificationKeyPath = path.join(directory, 'derived-verification-key.json');
    const commands = buildV2FinalZkeySnarkjsCommands({
      r1csPath: r1cs.filename,
      ptauPath: ptau.filename,
      zkeyPath: finalZkey.filename,
      verificationKeyPath: exportedVerificationKeyPath,
    });
    await runPinnedSnarkjs(toolchain, commands.verify, directory);
    await runPinnedSnarkjs(toolchain, commands.exportVerificationKey, directory);
    // Detect toolchain replacement during either process. The clean-host
    // threat model cannot make arbitrary local mutation impossible, but a
    // before-and-after full closure measurement closes ordinary TOCTOU drift.
    await verifyV2FinalZkeyToolchainManifest(request.toolchain);
    const derivedVerificationKey = await canonicalExportedVerificationKey(exportedVerificationKeyPath);
    if (!derivedVerificationKey.equals(expectedVerificationKey) || sha256(derivedVerificationKey) !== request.verificationKey.sha256) {
      fail('FINAL_ZKEY_VK_MISMATCH', 'final zkey exports a verification key different from the manifest-pinned verification key');
    }
    return Object.freeze({
      schema: V2_FINAL_ZKEY_RESOLUTION_SCHEMA,
      finalZkeySha256: request.finalZkey.sha256,
      r1csSha256: request.r1cs.sha256,
      ptauSha256: request.ptau.sha256,
      toolchain: request.toolchain,
      verificationKeySha256: request.verificationKey.sha256,
    });
  } finally {
    if (directory !== undefined) await rm(directory, { force: true, recursive: true });
  }
}
