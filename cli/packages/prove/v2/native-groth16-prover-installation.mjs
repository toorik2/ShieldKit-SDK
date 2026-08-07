import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { availableParallelism } from 'node:os';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';

import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';
import { parseStrictJson } from '../groth16.mjs';
import {
  RAPIDSNARK_COMMIT,
  V2_NATIVE_PROVER_MANIFEST_SCHEMA,
  assertV2NativeProverManifest,
} from '../../../scripts/setup-v2-native-prover.mjs';

export const V2_NATIVE_GROTH16_PROVER_INSTALLATION_SCHEMA =
  'shieldkit-v2-native-groth16-prover-installation-v1';
export const V2_NATIVE_RAPIDSNARK_BINARY_SHA256 =
  'f0b4390847b5fb62a31a795d6d411c6c1c145cab8108acd984521814846515ef';

const HASH = /^[0-9a-f]{64}$/u;
const CAPABILITIES = new WeakMap();
let contentReadObserver;

export class V2NativeGroth16ProverInstallationError extends Error {
  constructor(code, message, cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'V2NativeGroth16ProverInstallationError';
    this.code = code;
  }
}

const fail = (code, message, cause = undefined) => {
  throw new V2NativeGroth16ProverInstallationError(code, message, cause);
};
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');

function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    fail('NATIVE_PROVER_INSTALLATION_INVALID', `${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail('NATIVE_PROVER_INSTALLATION_INVALID', `${label} has missing or unknown properties`);
  }
  return value;
}

function absolute(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value)
    || path.normalize(value) !== value || value.includes('\0')) {
    fail('NATIVE_PROVER_INSTALLATION_INVALID', `${label} must be a normalized absolute path`);
  }
  return value;
}

function runtime() {
  const match = /^v([0-9]+)\.([0-9]+)\./u.exec(process.version);
  if (match === null || Number(match[1]) < 22
    || (Number(match[1]) === 22 && Number(match[2]) < 5)) {
    fail('NATIVE_PROVER_RUNTIME_UNSUPPORTED', 'native prover installation requires Node.js >=22.5');
  }
  const contaminatedEnvironment = Object.entries(process.env).find(([name, value]) => value !== undefined && value !== ''
    && (name === 'NODE_OPTIONS' || name === 'NODE_PATH' || name.startsWith('LD_') || name.startsWith('DYLD_')));
  const contaminatedArguments = process.execArgv.find((value) => /^(?:--(?:experimental-)?loader(?:=|$)|--import(?:=|$)|--require(?:=|$)|-r(?:$|\S))/u.test(value));
  if (contaminatedEnvironment || contaminatedArguments) {
    fail('NATIVE_PROVER_RUNTIME_UNSUPPORTED', 'native prover installation refuses Node/module-loader/dynamic-linker environment contamination');
  }
}

function identity(stat) {
  return Object.freeze({
    dev: stat.dev.toString(), ino: stat.ino.toString(), mode: stat.mode.toString(),
    uid: stat.uid.toString(), gid: stat.gid.toString(), size: stat.size.toString(),
    nlink: stat.nlink.toString(), mtimeNs: stat.mtimeNs.toString(),
    ctimeNs: stat.ctimeNs.toString(), birthtimeNs: stat.birthtimeNs.toString(),
  });
}

function same(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode
    && left.uid === right.uid && left.gid === right.gid && left.size === right.size
    && left.nlink === right.nlink && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs && left.birthtimeNs === right.birthtimeNs;
}

function privateDirectoryStat(stat, label) {
  return stat.isDirectory() && !stat.isSymbolicLink()
    && (process.getuid === undefined || stat.uid === BigInt(process.getuid()))
    && (stat.mode & 0o777n) === 0o700n
    ? stat : fail('NATIVE_PROVER_INSTALLATION_UNTRUSTED', `${label} must be a private owner-controlled canonical directory`);
}

function privateFileStat(stat, mode, label) {
  return stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1n
    && (process.getuid === undefined || stat.uid === BigInt(process.getuid()))
    && (stat.mode & 0o777n) === mode
    ? stat : fail('NATIVE_PROVER_INSTALLATION_UNTRUSTED', `${label} must be a private canonical non-hardlinked regular file`);
}

async function privateDirectory(filename) {
  const target = absolute(filename, 'installationDirectory');
  const stat = await lstat(target, { bigint: true }).catch((error) =>
    fail('NATIVE_PROVER_INSTALLATION_UNAVAILABLE', 'installationDirectory is unavailable', error));
  privateDirectoryStat(stat, 'installationDirectory');
  if (await realpath(target) !== target) {
    fail('NATIVE_PROVER_INSTALLATION_UNTRUSTED', 'installationDirectory must be a private owner-controlled canonical directory');
  }
  return Object.freeze({ path: target, identity: identity(stat) });
}

async function privateFile(filename, mode, label) {
  const target = absolute(filename, label);
  const pathBefore = await lstat(target, { bigint: true }).catch((error) =>
    fail('NATIVE_PROVER_INSTALLATION_UNAVAILABLE', `${label} is unavailable`, error));
  privateFileStat(pathBefore, mode, label);
  if (await realpath(target) !== target) {
    fail('NATIVE_PROVER_INSTALLATION_UNTRUSTED', `${label} must be a private canonical non-hardlinked regular file`);
  }
  let handle;
  try {
    handle = await open(target, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const opened = await handle.stat({ bigint: true });
    privateFileStat(opened, mode, label);
    if (!same(identity(pathBefore), identity(opened))) {
      fail('NATIVE_PROVER_INSTALLATION_RACE', `${label} changed before it could be opened`);
    }
    const bytes = await handle.readFile();
    contentReadObserver?.(Object.freeze({ label, path: target, bytes: bytes.length }));
    const handleAfter = await handle.stat({ bigint: true });
    const pathAfter = await lstat(target, { bigint: true });
    if (!same(identity(opened), identity(handleAfter))
      || !same(identity(opened), identity(pathAfter))
      || await realpath(target) !== target) {
      fail('NATIVE_PROVER_INSTALLATION_RACE', `${label} changed while it was read`);
    }
    return Object.freeze({ path: target, bytes: bytes.length, sha256: hash(bytes), identity: identity(opened), content: bytes });
  } catch (error) {
    if (error instanceof V2NativeGroth16ProverInstallationError) throw error;
    fail('NATIVE_PROVER_INSTALLATION_UNAVAILABLE', `${label} cannot be opened safely`, error);
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

// This is deliberately a metadata-only check. The caller must already hold an
// installation capability made by privateFile(), which read and SHA-256 checked
// the exact bytes. Warm proof requests retain that binding by requiring the
// exact private, canonical file identity rather than reading a large binary
// again.
async function privateFileIdentity(filename, mode, label) {
  const target = absolute(filename, label);
  const before = await lstat(target, { bigint: true }).catch((error) =>
    fail('NATIVE_PROVER_INSTALLATION_UNAVAILABLE', `${label} is unavailable`, error));
  privateFileStat(before, mode, label);
  if (await realpath(target) !== target) {
    fail('NATIVE_PROVER_INSTALLATION_UNTRUSTED', `${label} must be a private canonical non-hardlinked regular file`);
  }
  const after = await lstat(target, { bigint: true }).catch((error) =>
    fail('NATIVE_PROVER_INSTALLATION_UNAVAILABLE', `${label} is unavailable`, error));
  privateFileStat(after, mode, label);
  if (!same(identity(before), identity(after)) || await realpath(target) !== target) {
    fail('NATIVE_PROVER_INSTALLATION_RACE', `${label} changed while its warm receipt was checked`);
  }
  return identity(before);
}

function policy(value) {
  exact(value, ['binarySha256', 'nproc'], 'native prover installation policy');
  if (!HASH.test(value.binarySha256) || !Number.isSafeInteger(value.nproc) || value.nproc < 1) {
    fail('NATIVE_PROVER_INSTALLATION_INVALID', 'native prover installation policy is invalid');
  }
  return Object.freeze({ ...value });
}

function receiptIdentity(value, label) {
  exact(value, ['birthtimeNs', 'ctimeNs', 'dev', 'gid', 'ino', 'mode', 'mtimeNs', 'nlink', 'size', 'uid'], label);
  if (Object.values(value).some((part) => typeof part !== 'string' || !/^[0-9]+$/u.test(part))) {
    fail('NATIVE_PROVER_INSTALLATION_INVALID', `${label} must contain exact unsigned decimal identity fields`);
  }
  return Object.freeze({ ...value });
}

function capabilityFromVerifiedReceipt({ installationDirectory, installationIdentity, manifest, binary }) {
  const result = Object.freeze({
    schema: V2_NATIVE_GROTH16_PROVER_INSTALLATION_SCHEMA,
    installationDirectory,
    manifestSha256: manifest.sha256,
    binary: Object.freeze({
      path: binary.path,
      bytes: binary.bytes,
      sha256: binary.sha256,
      identity: binary.identity,
    }),
  });
  CAPABILITIES.set(result, Object.freeze({
    installationDirectory,
    installationIdentity,
    manifestSha256: manifest.sha256,
    binary: Object.freeze({ path: binary.path, sha256: binary.sha256, identity: binary.identity }),
  }));
  return result;
}

const productionPolicy = () => Object.freeze({
  binarySha256: V2_NATIVE_RAPIDSNARK_BINARY_SHA256,
  nproc: availableParallelism(),
});

async function inspect(directory, expected) {
  const installation = await privateDirectory(directory);
  const manifest = await privateFile(path.join(installation.path, 'manifest.json'), 0o600n, 'manifest');
  const directoryAfterManifest = await privateDirectory(installation.path);
  if (!same(installation.identity, directoryAfterManifest.identity)) {
    fail('NATIVE_PROVER_INSTALLATION_RACE', 'installationDirectory changed while the manifest was read');
  }
  let parsed;
  try {
    // parseStrictJson detects duplicate keys and deliberately returns
    // null-prototype records; JCS validation requires ordinary JSON records.
    parsed = JSON.parse(JSON.stringify(parseStrictJson(manifest.content, 'native prover manifest')));
    if (!manifest.content.equals(Buffer.from(canonicalizeJcs(parsed), 'utf8'))) {
      fail('NATIVE_PROVER_INSTALLATION_INVALID', 'native prover manifest must use exact RFC8785/JCS bytes');
    }
    parsed = assertV2NativeProverManifest(parsed);
  } catch (error) {
    if (error instanceof V2NativeGroth16ProverInstallationError) throw error;
    fail('NATIVE_PROVER_INSTALLATION_INVALID', 'native prover manifest is invalid', error);
  }
  if (parsed.schema !== V2_NATIVE_PROVER_MANIFEST_SCHEMA || parsed.source.commit !== RAPIDSNARK_COMMIT
    || parsed.build.nproc !== expected.nproc || parsed.binary.sha256 !== expected.binarySha256) {
    fail('NATIVE_PROVER_INSTALLATION_PIN_MISMATCH', 'native prover manifest does not bind the exact local native prover policy');
  }
  const binary = await privateFile(path.join(installation.path, parsed.binary.path), 0o700n, 'native prover binary');
  const directoryAfterBinary = await privateDirectory(installation.path);
  if (!same(installation.identity, directoryAfterBinary.identity)) {
    fail('NATIVE_PROVER_INSTALLATION_RACE', 'installationDirectory changed while the native prover binary was read');
  }
  if (binary.bytes !== parsed.binary.bytes || binary.sha256 !== parsed.binary.sha256
    || binary.sha256 !== expected.binarySha256 || !HASH.test(manifest.sha256)) {
    fail('NATIVE_PROVER_INSTALLATION_PIN_MISMATCH', 'native prover binary differs from its exact manifest pin');
  }
  return Object.freeze({ installationDirectory: installation.path, installationIdentity: directoryAfterBinary.identity, manifest, binary });
}

async function load(directory, expected) {
  const checkedPolicy = policy(expected);
  const inspected = await inspect(directory, checkedPolicy);
  return capabilityFromVerifiedReceipt({
    installationDirectory: inspected.installationDirectory,
    installationIdentity: inspected.installationIdentity,
    manifest: inspected.manifest,
    binary: inspected.binary,
  });
}

/** Resolve a compact public record; the usable proof capability remains private. */
export async function loadV2NativeGroth16ProverInstallation(value) {
  runtime(); exact(value, ['installationDirectory'], 'native prover installation input');
  return load(value.installationDirectory, productionPolicy());
}

/** Explicit unit-test seam; production callers must use the fixed policy loader. */
export async function loadV2NativeGroth16ProverInstallationForTest(value) {
  runtime(); exact(value, ['installationDirectory', 'policy'], 'native prover installation test input');
  return load(value.installationDirectory, value.policy);
}

/** Test-only observability seam for proving no content read occurs on warm receipt use. */
export function setV2NativeGroth16ProverContentReadObserverForTest(value) {
  if (value !== undefined && typeof value !== 'function') {
    fail('NATIVE_PROVER_INSTALLATION_INVALID', 'content read observer must be a function or undefined');
  }
  const previous = contentReadObserver;
  contentReadObserver = value;
  return () => { if (contentReadObserver === value) contentReadObserver = previous; };
}

/**
 * Derive a native proving capability only from an opaque, already-loaded
 * product artifact capability. Its receipt was content-verified at install;
 * this warm path validates the exact private canonical manifest and binary
 * identities without opening either file for content.
 */
export async function deriveV2NativeGroth16ProverInstallationFromProductArtifact(value) {
  runtime();
  let product;
  try { product = await import('../../profile/v2/beta-product-artifact-installation.mjs'); }
  catch (error) { fail('NATIVE_PROVER_INSTALLATION_UNAVAILABLE', 'product artifact installation module is unavailable', error); }
  if (typeof product.deriveV2BetaProductNativeProverReceipt !== 'function') {
    fail('NATIVE_PROVER_INSTALLATION_UNAVAILABLE', 'product artifact installation lacks its native receipt derivation');
  }
  let receipt;
  try { receipt = product.deriveV2BetaProductNativeProverReceipt(value); }
  catch (error) { fail('NATIVE_PROVER_INSTALLATION_CAPABILITY_REQUIRED', 'native warm capability requires a locally loaded product artifact installation', error); }
  exact(receipt, ['binary', 'installationDirectory', 'manifest', 'receiptSha256'], 'product native receipt');
  exact(receipt.manifest, ['bytes', 'identity', 'path', 'sha256'], 'product native manifest receipt');
  exact(receipt.binary, ['bytes', 'identity', 'path', 'sha256'], 'product native binary receipt');
  if (!HASH.test(receipt.receiptSha256) || !HASH.test(receipt.manifest.sha256) || !HASH.test(receipt.binary.sha256)
    || !Number.isSafeInteger(receipt.manifest.bytes) || receipt.manifest.bytes < 1
    || !Number.isSafeInteger(receipt.binary.bytes) || receipt.binary.bytes < 1) {
    fail('NATIVE_PROVER_INSTALLATION_INVALID', 'product native receipt hashes or byte lengths are invalid');
  }
  const installation = await privateDirectory(receipt.installationDirectory);
  const expectedManifestPath = path.join(installation.path, 'manifest.json');
  const expectedBinaryPath = path.join(installation.path, 'bin', 'prover');
  if (receipt.manifest.path !== expectedManifestPath || receipt.binary.path !== expectedBinaryPath) {
    fail('NATIVE_PROVER_INSTALLATION_INVALID', 'product native receipt paths are not the fixed native installation layout');
  }
  const manifest = Object.freeze({ path: expectedManifestPath, bytes: receipt.manifest.bytes, sha256: receipt.manifest.sha256, identity: receiptIdentity(receipt.manifest.identity, 'product native manifest receipt.identity') });
  const binary = Object.freeze({ path: expectedBinaryPath, bytes: receipt.binary.bytes, sha256: receipt.binary.sha256, identity: receiptIdentity(receipt.binary.identity, 'product native binary receipt.identity') });
  const manifestIdentity = await privateFileIdentity(manifest.path, 0o600n, 'native prover manifest');
  const binaryIdentity = await privateFileIdentity(binary.path, 0o700n, 'native prover binary');
  if (!same(manifest.identity, manifestIdentity) || !same(binary.identity, binaryIdentity)) {
    fail('NATIVE_PROVER_INSTALLATION_RACE', 'product native receipt identity differs; reinstallation is required');
  }
  return capabilityFromVerifiedReceipt({
    installationDirectory: installation.path,
    installationIdentity: installation.identity,
    manifest,
    binary,
  });
}

/**
 * Consume only a loader-branded, install-time SHA-256-verified capability.
 * Warm use checks the exact installation and binary identities without reading
 * the binary content again.
 */
export async function consumeV2NativeGroth16ProverInstallation(value) {
  runtime();
  const capability = CAPABILITIES.get(value);
  if (capability === undefined) {
    fail('NATIVE_PROVER_INSTALLATION_CAPABILITY_REQUIRED', 'native proving requires a loader-branded installation capability');
  }
  const installation = await privateDirectory(capability.installationDirectory);
  if (!same(capability.installationIdentity, installation.identity)) {
    fail('NATIVE_PROVER_INSTALLATION_RACE', 'native prover installation directory changed after resolution');
  }
  const binaryIdentity = await privateFileIdentity(capability.binary.path, 0o700n, 'native prover binary');
  if (!same(capability.binary.identity, binaryIdentity)) {
    fail('NATIVE_PROVER_INSTALLATION_RACE', 'native prover binary identity changed after install-time verification');
  }
  return Object.freeze({
    path: capability.binary.path,
    sha256: capability.binary.sha256,
    identity: capability.binary.identity,
  });
}
