import {
  createHash,
  createPublicKey,
  randomBytes,
  verify as verifySignature,
} from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  chmod,
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  rm,
} from 'node:fs/promises';
import path from 'node:path';

import {
  parseV2RawTransaction,
} from '../../kit/v2/transaction-policy.mjs';
import {
  deriveV2FinalizedGenesisPackagePins,
  inspectV2PackagedGenesisBinding,
} from './genesis.mjs';
import {
  ARTIFACT_MANIFEST_SCHEMA,
  descriptorAttestationBytes,
  deriveV2FinalLocksSha256FromValidatedDescriptor,
  deriveV2Pf10RuntimeFromValidatedDescriptor,
  deriveV2Pf10StoreRuntimeMaterialsSha256,
  deriveV2PreparedPackageRuntimeMaterialSha256,
  deriveV2RecoveryScannerFromValidatedDescriptor,
  deriveV2SettlementPinsFromValidatedDescriptor,
  INSTANCE_DESCRIPTOR_ATTESTATION_DOMAIN,
  INSTANCE_DESCRIPTOR_ATTESTATION_VERSION,
  INSTANCE_DESCRIPTOR_SCHEMA,
  loadV2InstanceDescriptor,
} from './instance-descriptor.mjs';
import {
  canonicalizeJcs,
  deriveProfileId,
  validateProfileCore,
} from './profile-core.mjs';
import {
  parseV2RecoveryScannerArtifact,
  RECOVERY_SCANNER_LINUX_X64_ARTIFACT_ID,
  RECOVERY_SCANNER_LINUX_X64_FILENAME,
  RECOVERY_SCANNER_MANIFEST_ARTIFACT_ID,
  RECOVERY_SCANNER_MANIFEST_FILENAME,
} from './recovery-scanner-artifact.mjs';

export const V2_INSTANCE_PACKAGE_PREPARED_SCHEMA =
  'shieldkit-v2-instance-package-prepared-v1';
export const V2_INSTANCE_PACKAGE_SIGNING_REQUEST_SCHEMA =
  'shieldkit-v2-instance-package-signing-request-v1';
export const V2_INSTANCE_PACKAGE_FINALIZED_SCHEMA =
  'shieldkit-v2-instance-package-finalized-v1';
export const V2_GENESIS_PACKAGE_BINDING_SCHEMA =
  'shieldkit-v2-genesis-package-binding-v1';

const RUNTIME_BUNDLE_SCHEMA =
  'shieldkit-v2-direct-pf10-development-runtime-bundle-v2';
const HASH = /^[0-9a-f]{64}$/;
const ARTIFACT_ID = /^[a-z0-9][a-z0-9-]*$/;
const PATH_COMPONENT = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const SIGNER_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const RUNTIME_REQUIRED_KEYS = Object.freeze([
  'artifactManifestTemplate',
  'eligibility',
  'finalLocks',
  'instanceId',
  'profileId',
  'runtimeMaterialSha256',
  'schema',
  'topologyId',
  'verifierRoles',
]);
const RUNTIME_ALLOWED_KEYS = new Set([
  ...RUNTIME_REQUIRED_KEYS,
  'build',
  'determinism',
  'libauthEvidence',
  'prerequisites',
  'profileCore',
  'profilePackage',
  'proofArtifacts',
  'qualification',
]);

export class V2InstancePackageError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options);
    this.name = 'V2InstancePackageError';
    this.code = code;
  }
}

const fail = (code, message, options) => {
  throw new V2InstancePackageError(code, message, options);
};
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

function plain(value, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('INSTANCE_PACKAGE_INVALID', `${label} must be a plain object`);
  }
  return value;
}

function exact(value, keys, label) {
  plain(value, label);
  const actual = Object.keys(value).sort();
  const wanted = [...keys].sort();
  if (
    actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])
  ) {
    fail(
      'INSTANCE_PACKAGE_INVALID',
      `${label} has missing or unknown properties`,
    );
  }
  return value;
}

function allowed(value, required, permitted, label) {
  plain(value, label);
  const actual = Object.keys(value);
  if (
    required.some((key) => !Object.hasOwn(value, key))
    || actual.some((key) => !permitted.has(key))
  ) {
    fail(
      'INSTANCE_PACKAGE_INVALID',
      `${label} has missing or unknown properties`,
    );
  }
  return value;
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail(
      'INSTANCE_PACKAGE_INVALID',
      `${label} must be 32 lowercase hexadecimal bytes`,
    );
  }
  return value;
}

function decimal(value, label) {
  if (
    typeof value !== 'string'
    || !DECIMAL.test(value)
    || BigInt(value) === 0n
  ) {
    fail(
      'INSTANCE_PACKAGE_INVALID',
      `${label} must be a nonzero canonical decimal`,
    );
  }
  return value;
}

function relativePath(value, label) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || path.isAbsolute(value)
    || value.includes('\\')
    || value.includes('\0')
  ) {
    fail(
      'INSTANCE_PACKAGE_INVALID',
      `${label} must be a relative slash-separated path`,
    );
  }
  const components = value.split('/');
  if (components.some((component) => !PATH_COMPONENT.test(component))) {
    fail(
      'INSTANCE_PACKAGE_INVALID',
      `${label} contains traversal or an invalid path component`,
    );
  }
  return value;
}

function artifactEntry(value, label) {
  exact(value, ['id', 'path', 'sha256'], label);
  if (typeof value.id !== 'string' || !ARTIFACT_ID.test(value.id)) {
    fail('INSTANCE_PACKAGE_INVALID', `${label}.id is not canonical`);
  }
  return Object.freeze({
    id: value.id,
    path: relativePath(value.path, `${label}.path`),
    sha256: hash(value.sha256, `${label}.sha256`),
  });
}

function artifactManifest(value, profileId, instanceId) {
  exact(
    value,
    ['artifacts', 'instanceId', 'profileId', 'schema'],
    'runtime artifact manifest template',
  );
  if (
    value.schema !== ARTIFACT_MANIFEST_SCHEMA
    || value.profileId !== profileId
    || value.instanceId !== instanceId
    || !Array.isArray(value.artifacts)
    || value.artifacts.length === 0
  ) {
    fail(
      'INSTANCE_PACKAGE_INVALID',
      'runtime artifact manifest identity or artifacts are invalid',
    );
  }
  const artifacts = value.artifacts.map((entry, index) =>
    artifactEntry(entry, `runtime artifact[${index}]`));
  const paths = new Set();
  for (let index = 0; index < artifacts.length; index += 1) {
    const entry = artifacts[index];
    if (
      (index > 0 && artifacts[index - 1].id >= entry.id)
      || paths.has(entry.path)
    ) {
      fail(
        'INSTANCE_PACKAGE_INVALID',
        'runtime artifacts must be ID-sorted with unique IDs and paths',
      );
    }
    paths.add(entry.path);
  }
  return Object.freeze(artifacts);
}

function finalLocks(value, pins, artifacts) {
  exact(
    value,
    ['binding', 'state', 'topologyId', 'verifiers'],
    'runtime finalLocks',
  );
  const topology = pins.finalLocks.topology;
  if (
    value.topologyId !== topology.id
    || value.topologyId !== pins.finalLocks.topology.id
    || !Array.isArray(value.verifiers)
    || value.verifiers.length !== pins.finalLocks.verifiers.length
  ) {
    fail(
      'INSTANCE_PACKAGE_INVALID',
      'runtime finalLocks topology differs from the finalized genesis',
    );
  }
  const artifact = (id, label) => {
    if (
      typeof id !== 'string'
      || !ARTIFACT_ID.test(id)
      || !artifacts.has(id)
    ) {
      fail(
        'INSTANCE_PACKAGE_INVALID',
        `${label} does not reference a runtime artifact`,
      );
    }
    return id;
  };
  const verifiers = value.verifiers.map((entry, index) => {
    exact(
      entry,
      ['baseSats', 'lockingArtifactId', 'role'],
      `runtime finalLocks verifier[${index}]`,
    );
    const expected = pins.finalLocks.verifiers[index];
    if (
      entry.role !== expected.role
      || entry.role !== topology.verifierRoles[index]
      || BigInt(decimal(entry.baseSats, `verifier[${index}].baseSats`))
        !== expected.baseSats
    ) {
      fail(
        'INSTANCE_PACKAGE_INVALID',
        `runtime verifier ${index} differs from the finalized genesis`,
      );
    }
    return Object.freeze({
      role: entry.role,
      lockingArtifactId: artifact(
        entry.lockingArtifactId,
        `runtime verifier ${index}`,
      ),
      baseSats: entry.baseSats,
    });
  });
  exact(
    value.binding,
    ['baseSats', 'lockingArtifactId', 'redeemArtifactId'],
    'runtime finalLocks binding',
  );
  exact(
    value.state,
    [
      'baseSats',
      'helperArtifactId',
      'helperUnlockArtifactId',
      'lockingArtifactId',
    ],
    'runtime finalLocks state',
  );
  if (
    BigInt(decimal(value.binding.baseSats, 'binding.baseSats'))
      !== pins.finalLocks.binding.baseSats
    || BigInt(decimal(value.state.baseSats, 'state.baseSats'))
      !== pins.finalLocks.state.baseSats
  ) {
    fail(
      'INSTANCE_PACKAGE_INVALID',
      'runtime structural base values differ from the finalized genesis',
    );
  }
  return Object.freeze({
    topologyId: value.topologyId,
    verifiers: Object.freeze(verifiers),
    binding: Object.freeze({
      lockingArtifactId: artifact(
        value.binding.lockingArtifactId,
        'runtime binding lock',
      ),
      redeemArtifactId: artifact(
        value.binding.redeemArtifactId,
        'runtime binding redeem',
      ),
      baseSats: value.binding.baseSats,
    }),
    state: Object.freeze({
      lockingArtifactId: artifact(
        value.state.lockingArtifactId,
        'runtime state lock',
      ),
      helperArtifactId: artifact(
        value.state.helperArtifactId,
        'runtime state helper',
      ),
      helperUnlockArtifactId: artifact(
        value.state.helperUnlockArtifactId,
        'runtime state helper unlock',
      ),
      baseSats: value.state.baseSats,
    }),
  });
}

function sameIdentity(left, right) {
  return (
    left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs
  );
}

async function canonicalRoot(directory, label) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory)) {
    fail('INSTANCE_PACKAGE_INVALID', `${label} must be an absolute path`);
  }
  const resolved = path.resolve(directory);
  let metadata;
  try {
    metadata = await lstat(resolved);
  } catch (error) {
    fail('INSTANCE_PACKAGE_IO', `${label} does not exist`, { cause: error });
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail('INSTANCE_PACKAGE_INVALID', `${label} must be a real directory`);
  }
  if (await realpath(resolved) !== resolved) {
    fail('INSTANCE_PACKAGE_INVALID', `${label} must not traverse a symlink`);
  }
  return resolved;
}

async function openStable(filename, label, { executable = false } = {}) {
  if (typeof filename !== 'string' || !path.isAbsolute(filename)) {
    fail('INSTANCE_PACKAGE_INVALID', `${label} must be an absolute path`);
  }
  const resolved = path.resolve(filename);
  const parent = await canonicalRoot(path.dirname(resolved), `${label} parent`);
  if (!resolved.startsWith(`${parent}${path.sep}`)) {
    fail('INSTANCE_PACKAGE_INVALID', `${label} escapes its parent`);
  }
  let before;
  try {
    before = await lstat(resolved);
  } catch (error) {
    fail('INSTANCE_PACKAGE_IO', `${label} does not exist`, { cause: error });
  }
  if (
    before.isSymbolicLink()
    || !before.isFile()
    || before.nlink !== 1
    || (executable && (before.mode & 0o111) === 0)
  ) {
    fail(
      'INSTANCE_PACKAGE_INVALID',
      `${label} must be one stable regular single-link${
        executable ? ' executable' : ''
      } file`,
    );
  }
  let handle;
  try {
    handle = await open(
      resolved,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0),
    );
    const opened = await handle.stat();
    const current = await lstat(resolved);
    if (
      !opened.isFile()
      || opened.nlink !== 1
      || current.isSymbolicLink()
      || !current.isFile()
      || current.nlink !== 1
      || !sameIdentity(before, opened)
      || !sameIdentity(opened, current)
    ) {
      fail('INSTANCE_PACKAGE_INVALID', `${label} changed while opening`);
    }
    return Object.freeze({ filename: resolved, handle, before: opened });
  } catch (error) {
    await handle?.close().catch(() => undefined);
    if (error instanceof V2InstancePackageError) throw error;
    fail('INSTANCE_PACKAGE_IO', `${label} cannot be opened`, { cause: error });
  }
}

async function assertStable(opened, label) {
  const after = await opened.handle.stat();
  const current = await lstat(opened.filename).catch(() => undefined);
  if (
    current === undefined
    || current.isSymbolicLink()
    || !current.isFile()
    || current.nlink !== 1
    || after.nlink !== 1
    || !sameIdentity(opened.before, after)
    || !sameIdentity(opened.before, current)
  ) {
    fail('INSTANCE_PACKAGE_INVALID', `${label} changed while reading`);
  }
}

async function readStable(filename, label, options = {}) {
  const opened = await openStable(filename, label, options);
  try {
    const bytes = await opened.handle.readFile();
    await assertStable(opened, label);
    return Buffer.from(bytes);
  } finally {
    await opened.handle.close();
  }
}

async function parseCanonicalFile(filename, label) {
  const bytes = await readStable(filename, label);
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    fail('INSTANCE_PACKAGE_INVALID', `${label} is not JSON`);
  }
  const canonicalBytes = Buffer.from(canonicalizeJcs(value), 'utf8');
  if (!bytes.equals(canonicalBytes)) {
    fail(
      'INSTANCE_PACKAGE_INVALID',
      `${label} must use exact RFC8785/JCS canonical bytes`,
    );
  }
  return Object.freeze({ value, bytes: canonicalBytes });
}

async function ensureDirectory(root, relative) {
  let cursor = root;
  for (const component of relative.split('/').slice(0, -1)) {
    cursor = path.join(cursor, component);
    try {
      await mkdir(cursor, { mode: 0o700 });
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
      const metadata = await lstat(cursor);
      if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
        fail(
          'INSTANCE_PACKAGE_INVALID',
          'package staging path contains a non-directory',
        );
      }
    }
  }
}

async function writeExact(root, relative, bytes, mode = 0o600) {
  relativePath(relative, 'package output path');
  await ensureDirectory(root, relative);
  const filename = path.join(root, relative);
  const handle = await open(filename, 'wx', mode);
  try {
    await handle.writeFile(Buffer.from(bytes));
    await handle.sync();
  } finally {
    await handle.close();
  }
  await chmod(filename, mode);
  return filename;
}

async function copyPinned({
  destinationRoot,
  destinationRelative,
  executable = false,
  expectedBytes = undefined,
  expectedSha256,
  label,
  source,
}) {
  const opened = await openStable(source, label, { executable });
  await ensureDirectory(destinationRoot, destinationRelative);
  const destination = path.join(destinationRoot, destinationRelative);
  const output = await open(destination, 'wx', executable ? 0o755 : 0o600);
  const digest = createHash('sha256');
  let bytes = 0;
  try {
    for await (const chunk of opened.handle.createReadStream({
      autoClose: false,
    })) {
      digest.update(chunk);
      bytes += chunk.length;
      await output.write(chunk);
    }
    await assertStable(opened, label);
    if (
      digest.digest('hex') !== expectedSha256
      || (
        expectedBytes !== undefined
        && bytes !== expectedBytes
      )
    ) {
      fail(
        'INSTANCE_PACKAGE_PIN_MISMATCH',
        `${label} differs from its exact hash or byte pin`,
      );
    }
    await output.sync();
  } finally {
    await output.close();
    await opened.handle.close();
  }
  await chmod(destination, executable ? 0o755 : 0o600);
  return Object.freeze({ bytes, destination, sha256: expectedSha256 });
}

async function privateStage(target, label) {
  if (typeof target !== 'string' || !path.isAbsolute(target)) {
    fail('INSTANCE_PACKAGE_INVALID', `${label} must be an absolute path`);
  }
  const output = path.resolve(target);
  const parent = await canonicalRoot(path.dirname(output), `${label} parent`);
  if (output !== path.join(parent, path.basename(output))) {
    fail('INSTANCE_PACKAGE_INVALID', `${label} must be a direct child path`);
  }
  try {
    await lstat(output);
    fail('INSTANCE_PACKAGE_EXISTS', `${label} already exists`);
  } catch (error) {
    if (
      error instanceof V2InstancePackageError
      || error?.code !== 'ENOENT'
    ) {
      throw error;
    }
  }
  const stage = path.join(
    parent,
    `.${path.basename(output)}.stage-${process.pid}-${
      randomBytes(12).toString('hex')
    }`,
  );
  await mkdir(stage, { mode: 0o700 });
  return Object.freeze({ output, parent, stage });
}

async function walk(root, relative = '') {
  const directory = path.join(root, relative);
  const entries = await readdir(directory, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name));
  const directories = [];
  const files = [];
  for (const entry of entries) {
    if (entry.isSymbolicLink()) {
      fail('INSTANCE_PACKAGE_INVALID', 'staging tree contains a symlink');
    }
    const child = relative === '' ? entry.name : `${relative}/${entry.name}`;
    if (entry.isDirectory()) {
      directories.push(child);
      const nested = await walk(root, child);
      directories.push(...nested.directories);
      files.push(...nested.files);
    } else if (entry.isFile()) {
      files.push(child);
    } else {
      fail(
        'INSTANCE_PACKAGE_INVALID',
        'staging tree contains a non-file entry',
      );
    }
  }
  return Object.freeze({ directories, files });
}

async function fsyncDirectory(directory) {
  const handle = await open(directory, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function copyStableStageFile(source, destination, label) {
  const opened = await openStable(source, label);
  const fileMode = opened.before.mode & 0o777;
  if (fileMode !== 0o600 && fileMode !== 0o755) {
    await opened.handle.close();
    fail(
      'INSTANCE_PACKAGE_INVALID',
      `${label} must have exact mode 0600 or 0755`,
    );
  }
  let output;
  try {
    output = await open(destination, 'wx', fileMode);
    for await (const chunk of opened.handle.createReadStream({
      autoClose: false,
    })) {
      await output.write(chunk);
    }
    await assertStable(opened, label);
    await output.sync();
  } finally {
    await output?.close().catch(() => undefined);
    await opened.handle.close();
  }
  await chmod(destination, fileMode);
  const published = await lstat(destination);
  if (
    !published.isFile()
    || published.isSymbolicLink()
    || published.nlink !== 1
    || (published.mode & 0o777) !== fileMode
  ) {
    fail(
      'INSTANCE_PACKAGE_INVALID',
      `${label} did not publish as one exact single-link file`,
    );
  }
}

async function publishStage(stage, output, parent, completionMarker) {
  const tree = await walk(stage);
  if (!tree.files.includes(completionMarker)) {
    fail(
      'INSTANCE_PACKAGE_INVALID',
      `staging tree is missing completion marker ${completionMarker}`,
    );
  }
  try {
    try {
      await mkdir(output, { mode: 0o700 });
    } catch (error) {
      if (error?.code === 'EEXIST') {
        fail(
          'INSTANCE_PACKAGE_EXISTS',
          'package output appeared during no-replace publication',
        );
      }
      throw error;
    }
    await fsyncDirectory(parent);
    for (const relative of tree.directories) {
      await mkdir(path.join(output, relative), { mode: 0o700 });
    }
    for (const relative of tree.files) {
      if (relative === completionMarker) continue;
      await copyStableStageFile(
        path.join(stage, relative),
        path.join(output, relative),
        `staged package file ${relative}`,
      );
    }
    for (const relative of [...tree.directories].reverse()) {
      await fsyncDirectory(path.join(output, relative));
    }
    await fsyncDirectory(output);
    await copyStableStageFile(
      path.join(stage, completionMarker),
      path.join(output, completionMarker),
      `staged package completion marker ${completionMarker}`,
    );
    await fsyncDirectory(output);
    await fsyncDirectory(parent);
    // The marker-last output is now durable and every final file has link
    // count one. A stale private stage is cleanup debt only; never turn it
    // into authority to delete or invalidate the published output.
    await rm(stage, { recursive: true, force: false })
      .catch(() => undefined);
    await fsyncDirectory(parent).catch(() => undefined);
  } catch (error) {
    // Never recursively remove output. After its no-replace mkdir succeeds,
    // another process or user can add data there. A failed publish remains
    // safely incomplete because the descriptor/signing-request completion
    // marker is copied last.
    await rm(stage, { recursive: true, force: true }).catch(() => undefined);
    throw error;
  }
}

function signer(value, label = 'instance package signer') {
  exact(value, ['publicKey', 'signerId'], label);
  if (
    typeof value.signerId !== 'string'
    || !SIGNER_ID.test(value.signerId)
    || typeof value.publicKey !== 'string'
  ) {
    fail('INSTANCE_PACKAGE_SIGNER_INVALID', `${label} is malformed`);
  }
  let publicKey;
  try {
    publicKey = createPublicKey(value.publicKey);
  } catch (error) {
    fail(
      'INSTANCE_PACKAGE_SIGNER_INVALID',
      `${label} publicKey is invalid`,
      { cause: error },
    );
  }
  if (publicKey.asymmetricKeyType !== 'ed25519') {
    fail(
      'INSTANCE_PACKAGE_SIGNER_INVALID',
      `${label} publicKey must be Ed25519`,
    );
  }
  return Object.freeze({
    signerId: value.signerId,
    publicKey: value.publicKey,
    key: publicKey,
  });
}

function trustedSigner(value, trustedSigners) {
  if (!Array.isArray(trustedSigners) || trustedSigners.length === 0) {
    fail(
      'INSTANCE_PACKAGE_SIGNER_INVALID',
      'trustedSigners must contain the prepared signer',
    );
  }
  const seen = new Set();
  let matched;
  for (const [index, candidate] of trustedSigners.entries()) {
    const parsed = signer(candidate, `trustedSigners[${index}]`);
    if (seen.has(parsed.signerId)) {
      fail(
        'INSTANCE_PACKAGE_SIGNER_INVALID',
        'trustedSigners signerId values must be unique',
      );
    }
    seen.add(parsed.signerId);
    if (
      parsed.signerId === value.signerId
      && parsed.publicKey === value.publicKey
    ) {
      matched = parsed;
    }
  }
  if (matched === undefined) {
    fail(
      'INSTANCE_PACKAGE_SIGNER_INVALID',
      'prepared signer is not in trustedSigners',
    );
  }
  return matched;
}

function signatureBytes(value) {
  if (value instanceof Uint8Array) {
    const bytes = Buffer.from(value);
    if (bytes.length === 64) return bytes;
  }
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'base64');
    if (
      bytes.length === 64
      && bytes.toString('base64') === value
    ) {
      return bytes;
    }
  }
  fail(
    'INSTANCE_PACKAGE_SIGNATURE_INVALID',
    'signature must be exactly 64 Ed25519 bytes or canonical base64',
  );
}

async function loadRuntimeBundle(manifestPath, pins) {
  const parsed = await parseCanonicalFile(
    manifestPath,
    'PF10 runtime build manifest',
  );
  const value = allowed(
    parsed.value,
    RUNTIME_REQUIRED_KEYS,
    RUNTIME_ALLOWED_KEYS,
    'PF10 runtime build manifest',
  );
  if (
    value.schema !== RUNTIME_BUNDLE_SCHEMA
    || value.eligibility !== 'development-only'
    || value.profileId !== pins.profileId
    || value.instanceId !== pins.instanceId
    || value.runtimeMaterialSha256 !== pins.runtimeMaterialSha256
    || value.topologyId !== pins.finalLocks.topology.id
    || !Array.isArray(value.verifierRoles)
    || value.verifierRoles.length
      !== pins.finalLocks.topology.verifierRoles.length
    || value.verifierRoles.some(
      (role, index) =>
        role !== pins.finalLocks.topology.verifierRoles[index],
    )
  ) {
    fail(
      'INSTANCE_PACKAGE_IDENTITY_MISMATCH',
      'PF10 runtime build identity differs from the finalized genesis',
    );
  }
  const entries = artifactManifest(
    value.artifactManifestTemplate,
    pins.profileId,
    pins.instanceId,
  );
  const byId = new Map(entries.map((entry) => [entry.id, entry]));
  const locks = finalLocks(value.finalLocks, pins, byId);
  return Object.freeze({
    root: await canonicalRoot(
      path.dirname(path.resolve(manifestPath)),
      'PF10 runtime bundle root',
    ),
    manifestPath: path.resolve(manifestPath),
    manifestBytes: parsed.bytes,
    manifestSha256: sha256(parsed.bytes),
    entries,
    byId,
    finalLocks: locks,
  });
}

async function assertStructuralBytes(stage, locks, pins) {
  const pairs = [
    ...locks.verifiers.map((entry, index) => [
      entry.lockingArtifactId,
      pins.finalLocks.verifiers[index].lockingBytecode,
      `verifier ${index}`,
    ]),
    [
      locks.binding.lockingArtifactId,
      pins.finalLocks.binding.lockingBytecode,
      'binding lock',
    ],
    [
      locks.binding.redeemArtifactId,
      pins.finalLocks.binding.redeemBytecode,
      'binding redeem',
    ],
    [
      locks.state.lockingArtifactId,
      pins.finalLocks.state.lockingBytecode,
      'state lock',
    ],
    [
      locks.state.helperArtifactId,
      pins.finalLocks.state.helperBytecode,
      'state helper',
    ],
    [
      locks.state.helperUnlockArtifactId,
      pins.finalLocks.state.helperUnlockingBytecode,
      'state helper unlock',
    ],
  ];
  for (const [artifactId, expected, label] of pairs) {
    const manifest = pins.runtime.byId.get(artifactId);
    const actual = await readStable(
      path.join(stage, manifest.path),
      `staged ${label}`,
    );
    if (!actual.equals(Buffer.from(expected))) {
      fail(
        'INSTANCE_PACKAGE_IDENTITY_MISMATCH',
        `staged ${label} differs from the VM-checked finalized genesis`,
      );
    }
  }
}

function appendArtifact(artifacts, entry) {
  if (
    artifacts.some(
      (candidate) =>
        candidate.id === entry.id
        || candidate.path === entry.path,
    )
  ) {
    fail(
      'INSTANCE_PACKAGE_INVALID',
      `package artifact ${entry.id} collides by ID or path`,
    );
  }
  artifacts.push(Object.freeze(entry));
}

function signingRequest(unsignedDescriptor, manifestBytes, signerValue) {
  const descriptorBytes = Buffer.from(
    canonicalizeJcs(unsignedDescriptor),
    'utf8',
  );
  const message = descriptorAttestationBytes({
    descriptor: unsignedDescriptor,
    canonicalManifestBytes: manifestBytes,
    signature: signerValue,
  });
  return Object.freeze({
    descriptorBytes,
    message,
    request: Object.freeze({
      schema: V2_INSTANCE_PACKAGE_SIGNING_REQUEST_SCHEMA,
      algorithm: 'ed25519',
      domain: INSTANCE_DESCRIPTOR_ATTESTATION_DOMAIN,
      version: INSTANCE_DESCRIPTOR_ATTESTATION_VERSION,
      signer: Object.freeze({
        signerId: signerValue.signerId,
        publicKey: signerValue.publicKey,
      }),
      descriptorSha256: sha256(descriptorBytes),
      manifestSha256: sha256(manifestBytes),
      messageSha256: sha256(message),
      messageBase64: message.toString('base64'),
    }),
  });
}

function genesisPackageBinding(value) {
  exact(
    value,
    [
      'finalLocksSha256',
      'genesisOutputIndex',
      'genesisTransactionId',
      'initialStateSha256',
      'instanceId',
      'profileId',
      'rawGenesisSha256',
      'rawSourceSha256',
      'runtimeMaterialSha256',
      'schema',
      'sourceOutputIndex',
      'sourceTransactionId',
    ],
    'genesis package binding',
  );
  if (
    value.schema !== V2_GENESIS_PACKAGE_BINDING_SCHEMA
    || value.genesisOutputIndex !== 0
    || value.sourceOutputIndex !== 0
  ) {
    fail(
      'INSTANCE_PACKAGE_GENESIS_INVALID',
      'genesis package binding schema or outpoints are invalid',
    );
  }
  for (const field of [
    'finalLocksSha256',
    'genesisTransactionId',
    'initialStateSha256',
    'instanceId',
    'profileId',
    'rawGenesisSha256',
    'rawSourceSha256',
    'runtimeMaterialSha256',
    'sourceTransactionId',
  ]) {
    hash(value[field], `genesis package binding.${field}`);
  }
  return Object.freeze({ ...value });
}

export async function prepareV2InstancePackage(value) {
  exact(
    value,
    [
      'finalizedGenesis',
      'genesisRuntime',
      'preparedDirectory',
      'recoveryScannerManifestPath',
      'runtimeBuildManifestPath',
      'signer',
    ],
    'prepare instance package options',
  );
  let genesisPins;
  try {
    genesisPins = deriveV2FinalizedGenesisPackagePins(
      value.finalizedGenesis,
      value.genesisRuntime,
    );
  } catch (error) {
    fail(
      'INSTANCE_PACKAGE_GENESIS_INVALID',
      'instance package requires the exact VM-checked finalized genesis and runtime',
      { cause: error },
    );
  }
  const packageSigner = signer(value.signer);
  const runtime = await loadRuntimeBundle(
    value.runtimeBuildManifestPath,
    genesisPins,
  );
  const scannerSource = await parseCanonicalFile(
    value.recoveryScannerManifestPath,
    'recovery scanner manifest',
  );
  let scanner;
  try {
    scanner = parseV2RecoveryScannerArtifact(scannerSource.bytes);
  } catch (error) {
    fail(
      'INSTANCE_PACKAGE_SCANNER_INVALID',
      error instanceof Error
        ? error.message
        : 'recovery scanner manifest is invalid',
      { cause: error },
    );
  }
  const scannerBinaryPath = path.join(
    path.dirname(path.resolve(value.recoveryScannerManifestPath)),
    RECOVERY_SCANNER_LINUX_X64_FILENAME,
  );
  const output = await privateStage(
    value.preparedDirectory,
    'prepared instance package directory',
  );
  try {
    for (const entry of runtime.entries) {
      await copyPinned({
        destinationRoot: output.stage,
        destinationRelative: entry.path,
        expectedSha256: entry.sha256,
        label: `runtime artifact ${entry.id}`,
        source: path.join(runtime.root, entry.path),
      });
    }
    const profileEntry = runtime.byId.get('profile-core');
    if (profileEntry === undefined) {
      fail(
        'INSTANCE_PACKAGE_INVALID',
        'runtime bundle is missing profile-core',
      );
    }
    const profileBytes = await readStable(
      path.join(output.stage, profileEntry.path),
      'staged profile core',
    );
    let profileCore;
    try {
      profileCore = JSON.parse(profileBytes.toString('utf8'));
      if (
        !profileBytes.equals(
          Buffer.from(canonicalizeJcs(profileCore), 'utf8'),
        )
      ) {
        throw new Error('profile core is not canonical JCS');
      }
      validateProfileCore(profileCore);
    } catch (error) {
      fail(
        'INSTANCE_PACKAGE_INVALID',
        `runtime profile core is invalid: ${
          error instanceof Error ? error.message : String(error)
        }`,
        { cause: error },
      );
    }
    if (
      deriveProfileId(profileCore) !== genesisPins.profileId
      || profileCore.denominationSats !== genesisPins.denominationSats
      || profileCore.baseVerifierArtifacts.some((entry) => {
        const artifact = runtime.byId.get(entry.id);
        return artifact === undefined || artifact.sha256 !== entry.sha256;
      })
    ) {
      fail(
        'INSTANCE_PACKAGE_IDENTITY_MISMATCH',
        'runtime profile core or its base artifacts differ from the finalized genesis',
      );
    }
    await assertStructuralBytes(output.stage, runtime.finalLocks, {
      ...genesisPins,
      runtime,
    });

    const artifacts = [...runtime.entries];
    appendArtifact(artifacts, {
      id: 'pf10-runtime-build-manifest',
      path: 'reproducibility/runtime-build-manifest.json',
      sha256: runtime.manifestSha256,
    });
    await writeExact(
      output.stage,
      'reproducibility/runtime-build-manifest.json',
      runtime.manifestBytes,
    );
    appendArtifact(artifacts, {
      id: RECOVERY_SCANNER_MANIFEST_ARTIFACT_ID,
      path: `recovery/${RECOVERY_SCANNER_MANIFEST_FILENAME}`,
      sha256: scanner.sha256,
    });
    await writeExact(
      output.stage,
      `recovery/${RECOVERY_SCANNER_MANIFEST_FILENAME}`,
      scanner.canonicalBytes,
    );
    appendArtifact(artifacts, {
      id: RECOVERY_SCANNER_LINUX_X64_ARTIFACT_ID,
      path: `recovery/${RECOVERY_SCANNER_LINUX_X64_FILENAME}`,
      sha256: scanner.manifest.binarySha256,
    });
    await copyPinned({
      destinationRoot: output.stage,
      destinationRelative:
        `recovery/${RECOVERY_SCANNER_LINUX_X64_FILENAME}`,
      executable: true,
      expectedBytes: scanner.manifest.binaryBytes,
      expectedSha256: scanner.manifest.binarySha256,
      label: 'recovery scanner executable',
      source: scannerBinaryPath,
    });
    const rawGenesis = Buffer.from(
      genesisPins.genesis.rawTransactionHex,
      'hex',
    );
    if (
      rawGenesis.length !== genesisPins.genesis.serializedBytes
      || parseV2RawTransaction(rawGenesis.toString('hex')).txid
        !== genesisPins.genesis.transactionId
    ) {
      fail(
        'INSTANCE_PACKAGE_GENESIS_INVALID',
        'finalized genesis raw transaction identity is inconsistent',
      );
    }
    appendArtifact(artifacts, {
      id: 'genesis-raw-transaction',
      path: 'genesis/genesis.raw.tx',
      sha256: sha256(rawGenesis),
    });
    await writeExact(
      output.stage,
      'genesis/genesis.raw.tx',
      rawGenesis,
    );
    const rawGenesisSource = Buffer.from(
      genesisPins.source.rawTransactionHex,
      'hex',
    );
    if (
      rawGenesisSource.length !== genesisPins.source.serializedBytes
      || parseV2RawTransaction(rawGenesisSource.toString('hex')).txid
        !== genesisPins.source.transactionId
    ) {
      fail(
        'INSTANCE_PACKAGE_GENESIS_INVALID',
        'finalized genesis source transaction identity is inconsistent',
      );
    }
    appendArtifact(artifacts, {
      id: 'genesis-source-raw-transaction',
      path: 'genesis/source.raw.tx',
      sha256: sha256(rawGenesisSource),
    });
    await writeExact(
      output.stage,
      'genesis/source.raw.tx',
      rawGenesisSource,
    );
    const bindingRecord = genesisPackageBinding({
      schema: V2_GENESIS_PACKAGE_BINDING_SCHEMA,
      profileId: genesisPins.profileId,
      instanceId: genesisPins.instanceId,
      sourceTransactionId: genesisPins.source.transactionId,
      sourceOutputIndex: genesisPins.source.outputIndex,
      genesisTransactionId: genesisPins.genesis.transactionId,
      genesisOutputIndex: genesisPins.genesis.outputIndex,
      rawSourceSha256: sha256(rawGenesisSource),
      rawGenesisSha256: sha256(rawGenesis),
      initialStateSha256: sha256(
        Buffer.from(genesisPins.initialStateHex, 'hex'),
      ),
      finalLocksSha256: genesisPins.finalLocksSha256,
      runtimeMaterialSha256: genesisPins.runtimeMaterialSha256,
    });
    const bindingBytes = Buffer.from(
      canonicalizeJcs(bindingRecord),
      'utf8',
    );
    appendArtifact(artifacts, {
      id: 'genesis-package-binding',
      path: 'genesis/binding.json',
      sha256: sha256(bindingBytes),
    });
    await writeExact(
      output.stage,
      'genesis/binding.json',
      bindingBytes,
    );
    artifacts.sort((left, right) => left.id.localeCompare(right.id));
    const manifest = Object.freeze({
      schema: ARTIFACT_MANIFEST_SCHEMA,
      profileId: genesisPins.profileId,
      instanceId: genesisPins.instanceId,
      artifacts: Object.freeze(artifacts),
    });
    const manifestBytes = Buffer.from(canonicalizeJcs(manifest), 'utf8');
    const unsignedDescriptor = Object.freeze({
      schema: INSTANCE_DESCRIPTOR_SCHEMA,
      profileId: genesisPins.profileId,
      instanceId: genesisPins.instanceId,
      stateNftCategory: genesisPins.instanceId,
      genesis: Object.freeze({
        transactionId: genesisPins.genesis.transactionId,
        outpointIndex: genesisPins.genesis.outputIndex,
      }),
      initialState: genesisPins.initialStateHex,
      manifest: Object.freeze({
        path: 'manifest.json',
        sha256: sha256(manifestBytes),
      }),
      finalLocks: runtime.finalLocks,
      signature: null,
    });
    await writeExact(output.stage, 'manifest.json', manifestBytes);
    const unsignedDescriptorPath = await writeExact(
      output.stage,
      'instance.unsigned.json',
      Buffer.from(canonicalizeJcs(unsignedDescriptor), 'utf8'),
    );
    const runtimeValidation =
      await deriveV2PreparedPackageRuntimeMaterialSha256({
        unsignedDescriptorPath,
        profileCore,
      });
    if (
      runtimeValidation.eligibility !== 'development-only'
      || runtimeValidation.runtimeMaterialSha256
        !== genesisPins.runtimeMaterialSha256
    ) {
      fail(
        'INSTANCE_PACKAGE_IDENTITY_MISMATCH',
        'packaged PF10 runtime material differs from the VM-checked finalized genesis',
      );
    }
    const request = signingRequest(
      unsignedDescriptor,
      manifestBytes,
      packageSigner,
    );
    await writeExact(
      output.stage,
      'signing-request.json',
      Buffer.from(canonicalizeJcs(request.request), 'utf8'),
    );
    await fsyncDirectory(output.stage);
    await publishStage(
      output.stage,
      output.output,
      output.parent,
      'signing-request.json',
    );
    return Object.freeze({
      schema: V2_INSTANCE_PACKAGE_PREPARED_SCHEMA,
      preparedDirectory: output.output,
      profileId: genesisPins.profileId,
      instanceId: genesisPins.instanceId,
      descriptorSha256: request.request.descriptorSha256,
      manifestSha256: request.request.manifestSha256,
      messageSha256: request.request.messageSha256,
      signingRequestPath: path.join(
        output.output,
        'signing-request.json',
      ),
    });
  } catch (error) {
    await rm(output.stage, { recursive: true, force: true })
      .catch(() => undefined);
    throw error;
  }
}

function signingRequestValue(value) {
  exact(
    value,
    [
      'algorithm',
      'descriptorSha256',
      'domain',
      'manifestSha256',
      'messageBase64',
      'messageSha256',
      'schema',
      'signer',
      'version',
    ],
    'instance package signing request',
  );
  if (
    value.schema !== V2_INSTANCE_PACKAGE_SIGNING_REQUEST_SCHEMA
    || value.algorithm !== 'ed25519'
    || value.domain !== INSTANCE_DESCRIPTOR_ATTESTATION_DOMAIN
    || value.version !== INSTANCE_DESCRIPTOR_ATTESTATION_VERSION
    || typeof value.messageBase64 !== 'string'
  ) {
    fail(
      'INSTANCE_PACKAGE_INVALID',
      'instance package signing request identity is unsupported',
    );
  }
  const requestSigner = signer(value.signer, 'prepared signer');
  const message = Buffer.from(value.messageBase64, 'base64');
  if (
    message.length === 0
    || message.toString('base64') !== value.messageBase64
    || sha256(message) !== hash(value.messageSha256, 'messageSha256')
  ) {
    fail(
      'INSTANCE_PACKAGE_INVALID',
      'instance package signing message is not canonical or hash-bound',
    );
  }
  return Object.freeze({
    ...value,
    descriptorSha256: hash(value.descriptorSha256, 'descriptorSha256'),
    manifestSha256: hash(value.manifestSha256, 'manifestSha256'),
    signer: requestSigner,
    message,
  });
}

async function copyPreparedArtifacts(prepared, manifest, stage) {
  const paths = new Set();
  for (const [index, rawEntry] of manifest.artifacts.entries()) {
    const entry = artifactEntry(rawEntry, `prepared artifact[${index}]`);
    if (
      (index > 0 && manifest.artifacts[index - 1].id >= entry.id)
      || paths.has(entry.path)
    ) {
      fail(
        'INSTANCE_PACKAGE_INVALID',
        'prepared artifacts must be ID-sorted with unique IDs and paths',
      );
    }
    paths.add(entry.path);
    await copyPinned({
      destinationRoot: stage,
      destinationRelative: entry.path,
      executable:
        entry.id === RECOVERY_SCANNER_LINUX_X64_ARTIFACT_ID,
      expectedSha256: entry.sha256,
      label: `prepared artifact ${entry.id}`,
      source: path.join(prepared, entry.path),
    });
  }
}

export async function finalizeV2InstancePackage(value) {
  exact(
    value,
    [
      'outputDirectory',
      'preparedDirectory',
      'signature',
      'trustedSigners',
    ],
    'finalize instance package options',
  );
  const prepared = await canonicalRoot(
    value.preparedDirectory,
    'prepared instance package directory',
  );
  const [manifestFile, descriptorFile, requestFile] = await Promise.all([
    parseCanonicalFile(
      path.join(prepared, 'manifest.json'),
      'prepared artifact manifest',
    ),
    parseCanonicalFile(
      path.join(prepared, 'instance.unsigned.json'),
      'prepared unsigned descriptor',
    ),
    parseCanonicalFile(
      path.join(prepared, 'signing-request.json'),
      'prepared signing request',
    ),
  ]);
  const request = signingRequestValue(requestFile.value);
  const approvedSigner = trustedSigner(request.signer, value.trustedSigners);
  if (
    sha256(manifestFile.bytes) !== request.manifestSha256
    || sha256(descriptorFile.bytes) !== request.descriptorSha256
  ) {
    fail(
      'INSTANCE_PACKAGE_PIN_MISMATCH',
      'prepared descriptor or manifest differs from the signing request',
    );
  }
  const unsignedDescriptor = descriptorFile.value;
  if (unsignedDescriptor.signature !== null) {
    fail(
      'INSTANCE_PACKAGE_INVALID',
      'prepared descriptor must be unsigned',
    );
  }
  const recomputed = descriptorAttestationBytes({
    descriptor: unsignedDescriptor,
    canonicalManifestBytes: manifestFile.bytes,
    signature: request.signer,
  });
  if (!request.message.equals(recomputed)) {
    fail(
      'INSTANCE_PACKAGE_PIN_MISMATCH',
      'prepared signing message differs from descriptor attestation bytes',
    );
  }
  const signature = signatureBytes(value.signature);
  if (!verifySignature(null, request.message, approvedSigner.key, signature)) {
    fail(
      'INSTANCE_PACKAGE_SIGNATURE_INVALID',
      'Ed25519 signature does not verify for the exact prepared attestation',
    );
  }
  const manifest = manifestFile.value;
  exact(
    manifest,
    ['artifacts', 'instanceId', 'profileId', 'schema'],
    'prepared artifact manifest',
  );
  if (
    manifest.schema !== ARTIFACT_MANIFEST_SCHEMA
    || manifest.profileId !== unsignedDescriptor.profileId
    || manifest.instanceId !== unsignedDescriptor.instanceId
    || unsignedDescriptor.manifest?.path !== 'manifest.json'
    || unsignedDescriptor.manifest?.sha256 !== request.manifestSha256
    || !Array.isArray(manifest.artifacts)
    || manifest.artifacts.length === 0
  ) {
    fail(
      'INSTANCE_PACKAGE_IDENTITY_MISMATCH',
      'prepared descriptor and artifact manifest identities differ',
    );
  }
  const output = await privateStage(
    value.outputDirectory,
    'final instance package directory',
  );
  try {
    await copyPreparedArtifacts(prepared, manifest, output.stage);
    const signedDescriptor = Object.freeze({
      ...unsignedDescriptor,
      signature: Object.freeze({
        algorithm: 'ed25519',
        attestationDomain: request.domain,
        attestationVersion: request.version,
        signerId: request.signer.signerId,
        publicKey: request.signer.publicKey,
        signature: signature.toString('base64'),
      }),
    });
    await writeExact(output.stage, 'manifest.json', manifestFile.bytes);
    await writeExact(
      output.stage,
      'instance.json',
      Buffer.from(canonicalizeJcs(signedDescriptor), 'utf8'),
    );
    const profileEntry = manifest.artifacts.find(
      (entry) => entry.id === 'profile-core',
    );
    if (profileEntry === undefined) {
      fail(
        'INSTANCE_PACKAGE_INVALID',
        'final package is missing profile-core',
      );
    }
    const profileFile = await parseCanonicalFile(
      path.join(output.stage, profileEntry.path),
      'final profile core',
    );
    const loaded = await loadV2InstanceDescriptor({
      descriptorPath: path.join(output.stage, 'instance.json'),
      profileCore: profileFile.value,
      trustedSigners: value.trustedSigners,
    });
    const runtimeResolution =
      await deriveV2Pf10RuntimeFromValidatedDescriptor(loaded);
    const runtimeMaterialSha256 =
      deriveV2Pf10StoreRuntimeMaterialsSha256(runtimeResolution)
        .toString('hex');
    const genesisBindingArtifact = manifest.artifacts.find(
      (entry) => entry.id === 'genesis-package-binding',
    );
    if (genesisBindingArtifact === undefined) {
      fail(
        'INSTANCE_PACKAGE_GENESIS_INVALID',
        'final package is missing its signed genesis binding',
      );
    }
    const parsedGenesisBinding = await parseCanonicalFile(
      path.join(output.stage, genesisBindingArtifact.path),
      'final genesis package binding',
    );
    const packageBinding = genesisPackageBinding(
      parsedGenesisBinding.value,
    );
    if (
      packageBinding.profileId !== loaded.profileId
      || packageBinding.instanceId !== loaded.instanceId
      || packageBinding.genesisTransactionId
        !== loaded.genesis.transactionId
      || packageBinding.genesisOutputIndex !== loaded.genesis.outpointIndex
      || packageBinding.initialStateSha256 !== sha256(loaded.initialState)
      || packageBinding.finalLocksSha256
        !== deriveV2FinalLocksSha256FromValidatedDescriptor(loaded)
      || packageBinding.runtimeMaterialSha256 !== runtimeMaterialSha256
    ) {
      fail(
        'INSTANCE_PACKAGE_IDENTITY_MISMATCH',
        'signed genesis binding differs from descriptor or derived PF10 runtime',
      );
    }
    await deriveV2RecoveryScannerFromValidatedDescriptor(loaded);
    const genesisArtifact = manifest.artifacts.find(
      (entry) => entry.id === 'genesis-raw-transaction',
    );
    const genesisSourceArtifact = manifest.artifacts.find(
      (entry) => entry.id === 'genesis-source-raw-transaction',
    );
    if (
      genesisArtifact === undefined
      || genesisSourceArtifact === undefined
    ) {
      fail(
        'INSTANCE_PACKAGE_INVALID',
        'final package is missing its raw source or genesis transaction',
      );
    }
    const [rawGenesis, rawGenesisSource] = await Promise.all([
      readStable(
        path.join(output.stage, genesisArtifact.path),
        'final raw genesis transaction',
      ),
      readStable(
        path.join(output.stage, genesisSourceArtifact.path),
        'final raw genesis source transaction',
      ),
    ]);
    let genesisInspection;
    try {
      genesisInspection = inspectV2PackagedGenesisBinding({
        descriptor: {
          profileId: loaded.profileId,
          instanceId: loaded.instanceId,
          initialState: loaded.initialState,
          genesis: loaded.genesis,
        },
        rawGenesisTransaction: rawGenesis,
        rawSourceTransaction: rawGenesisSource,
        settlementPins:
          deriveV2SettlementPinsFromValidatedDescriptor(loaded),
      });
    } catch (error) {
      fail(
        'INSTANCE_PACKAGE_GENESIS_INVALID',
        `final packaged genesis is not bound to the signed descriptor: ${
          error instanceof Error ? error.message : String(error)
        }`,
        { cause: error },
      );
    }
    if (
      packageBinding.rawGenesisSha256 !== sha256(rawGenesis)
      || packageBinding.rawSourceSha256 !== sha256(rawGenesisSource)
      || packageBinding.sourceTransactionId
        !== genesisInspection.sourceTransactionId
      || packageBinding.sourceOutputIndex !== 0
    ) {
      fail(
        'INSTANCE_PACKAGE_GENESIS_INVALID',
        'signed genesis binding differs from exact source/genesis bytes',
      );
    }
    await fsyncDirectory(output.stage);
    await publishStage(
      output.stage,
      output.output,
      output.parent,
      'instance.json',
    );
    return Object.freeze({
      schema: V2_INSTANCE_PACKAGE_FINALIZED_SCHEMA,
      outputDirectory: output.output,
      profileId: loaded.profileId,
      instanceId: loaded.instanceId,
      descriptorPath: path.join(output.output, 'instance.json'),
      descriptorSha256: loaded.descriptor.sha256,
      manifestSha256: loaded.manifest.sha256,
      genesisTransactionId: loaded.genesis.transactionId,
      runtimeMaterialSha256,
    });
  } catch (error) {
    await rm(output.stage, { recursive: true, force: true })
      .catch(() => undefined);
    throw error;
  }
}
