import {
  createHash,
  createPublicKey,
  randomBytes,
  verify as verifySignature,
} from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  link,
  lstat,
  open,
  realpath,
  unlink,
} from 'node:fs/promises';
import path from 'node:path';

import { canonicalizeJcs, deriveProfileId } from './profile-core.mjs';
import {
  parseV2RecoveryScannerArtifact,
  RECOVERY_SCANNER_ARTIFACT_SCHEMA,
  RECOVERY_SCANNER_LINUX_X64_ARTIFACT_ID,
  RECOVERY_SCANNER_MANIFEST_ARTIFACT_ID,
  V2_RECOVERY_SCANNER_PROTOCOL_SCHEMAS,
} from './recovery-scanner-artifact.mjs';
import {
  inspectV2DevelopmentProfilePackage,
} from './development-profile.mjs';
import {
  parseCircuitBuildAttestation,
  parseDevelopmentSetupAttestation,
} from './build-attestation.mjs';
import {
  parseV2RelationSourceManifest,
} from './relation-source-manifest.mjs';
import {
  V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID,
  verifyV2FinalRuntimeEvidence,
} from './final-runtime-evidence.mjs';
import {
  parseV2FinalZkeyToolchainManifest,
  V2_FINAL_ZKEY_VERIFICATION_SCHEMA,
  verifyV2FinalZkeyCryptographically,
} from './final-zkey-verification.mjs';
import {
  createDirectV2PoolModel,
} from '../../action/v2/transition.mjs';
import {
  deriveV2RollingBaseSats,
} from '../../action/v2/dust-policy.mjs';
import {
  decodeStateNftCommitment,
  encodeStateNftCommitment,
} from '../../action/v2/state.mjs';
import {
  verifyDirectV2BindingP2sh32Lock,
} from '../../action/v2/binding-unlock.mjs';
import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
  DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
  DIRECT_V2_PF11_ORACLE_VERIFIER_ROLES,
  resolveDirectV2VerifierTopology,
} from '../../action/v2/topology.mjs';
import {
  DIRECT_V2_PF10_RUNTIME_SCHEMA,
  validateDirectV2Pf10RuntimeMaterial,
} from '../../unlock-builder/v2/pf10-action-witness.mjs';
import {
  validateDirectV2Pf10LibauthEvidence,
} from '../../unlock-builder/v2/pf10-development-runtime-builder.mjs';
import {
  buildDirectV2StateHelper,
  buildDirectV2StateTrampolineLock,
  buildDirectV2StateTrampolineUnlock,
} from '../../unlock-builder/v2/structural-covenants.mjs';

export const INSTANCE_DESCRIPTOR_SCHEMA = 'shieldkit-instance-descriptor-v2-direct';
export const ARTIFACT_MANIFEST_SCHEMA = 'shieldkit-artifact-manifest-v2-direct';
export const INSTANCE_DESCRIPTOR_ATTESTATION_DOMAIN = 'shieldkit-instance-descriptor-attestation';
export const INSTANCE_DESCRIPTOR_ATTESTATION_VERSION = 1;
export const PF10_RUNTIME_ARTIFACT_SCHEMA =
  'shieldkit-v2-direct-pf10-runtime-artifact-v3';
export const PF10_FINAL_RUNTIME_ARTIFACT_SCHEMA =
  'shieldkit-v2-direct-pf10-final-runtime-artifact-v2';
export const PF10_RUNTIME_MANIFEST_ARTIFACT_ID =
  'pf10-runtime-material';
export const PF10_CANONICAL_QUALIFICATION_RECORD_SCHEMA =
  'shieldkit-v2-direct-pf10-canonical-qualification-record-v1';
export const PF10_UNSIGNED_RUNTIME_REFERENCE_VALIDATION_SCHEMA =
  'shieldkit-v2-direct-pf10-unsigned-runtime-reference-validation-v1';
export const PF10_UNSIGNED_RUNTIME_REFERENCE_COUNT = 27;
export const PROFILE_CORE_MANIFEST_ARTIFACT_ID = 'profile-core';
export {
  RECOVERY_SCANNER_ARTIFACT_SCHEMA,
  RECOVERY_SCANNER_LINUX_X64_ARTIFACT_ID,
  RECOVERY_SCANNER_MANIFEST_ARTIFACT_ID,
  V2_RECOVERY_SCANNER_PROTOCOL_SCHEMAS,
} from './recovery-scanner-artifact.mjs';
// Compatibility export for the PF11 semantic oracle. New callers must use the
// signed finalLocks.topologyId plus its exact ordered verifier role list.
export const V2_INSTANCE_VERIFIER_ROLES =
  DIRECT_V2_PF11_ORACLE_VERIFIER_ROLES;
const HEX_32 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const PATH_COMPONENT = /^(?!\.?(?:$|\.))[A-Za-z0-9][A-Za-z0-9._-]*$/;
const SIGNER_ID = /^[a-z][a-z0-9-]*$/;
const ARTIFACT_ID = /^[a-z][a-z0-9-]*$/;
const UNSIGNED_DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_U128 = (1n << 128n) - 1n;
const DEVELOPMENT_QUALIFICATION_SCHEMA =
  'shieldkit-v2-direct-development-groth16-qualification-v4';
const DEVELOPMENT_QUALIFICATION_CLASS =
  'deterministic-development-key-proof-test-evidence';
const DEVELOPMENT_QUALIFICATION_FIXTURE =
  'deterministic-deposit-transfer-withdrawal-chain';
const DEVELOPMENT_ACTION_NAMES = Object.freeze([
  'deposit',
  'transfer',
  'withdrawal',
]);
const V2_MINIMUM_CHANGE_SATS = '546';
const validatedDescriptorPins = new WeakMap();
const validatedPf10RuntimeResolutions = new WeakMap();
const validatedRecoveryScannerResolutions = new WeakMap();

export class InstanceDescriptorError extends Error {
  constructor(message) { super(message); this.name = 'InstanceDescriptorError'; }
}
const fail = (message) => { throw new InstanceDescriptorError(message); };
const exactKeys = (value, label, expected) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) fail(`${label} must be a plain object`);
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail(`${label} has missing or unknown properties`);
};
const hex32 = (value, label) => { if (typeof value !== 'string' || !HEX_32.test(value)) fail(`${label} must be 32 lowercase hexadecimal bytes`); return value; };
const decimal = (value, label) => { if (typeof value !== 'string' || !DECIMAL.test(value) || BigInt(value) === 0n) fail(`${label} must be a nonzero canonical unsigned decimal string`); return value; };
const bytesHex = (value, length, label) => { if (typeof value !== 'string' || !new RegExp(`^[0-9a-f]{${length * 2}}$`).test(value)) fail(`${label} must be ${length} lowercase hexadecimal bytes`); return Buffer.from(value, 'hex'); };
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

function relativePath(value, label) {
  if (typeof value !== 'string' || value.length === 0 || path.isAbsolute(value) || value.includes('\\')) fail(`${label} must be a relative slash-separated path`);
  const components = value.split('/');
  if (components.some((component) => !PATH_COMPONENT.test(component))) fail(`${label} contains traversal or invalid path component`);
  return value;
}

async function regularFile(root, relative, label) {
  const resolved = path.resolve(root, relative);
  if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) fail(`${label} escapes its root`);
  let entry;
  try { entry = await lstat(resolved); } catch { fail(`${label} does not exist`); }
  if (
    entry.isSymbolicLink()
    || !entry.isFile()
    || entry.nlink !== 1
  ) fail(`${label} must be one regular non-symlink file`);
  const canonicalRoot = await realpath(root);
  const canonicalFile = await realpath(resolved);
  if (canonicalRoot !== root) fail(`${label} root must not resolve through a symlink`);
  if (canonicalFile !== resolved) fail(`${label} path must not traverse a symlink`);
  if (!canonicalFile.startsWith(`${canonicalRoot}${path.sep}`)) fail(`${label} resolves outside its root`);
  return resolved;
}

function sameFileIdentity(left, right) {
  return (
    left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs
  );
}

async function openPinnedFile(root, relative, label) {
  const filename = await regularFile(root, relative, label);
  const expected = await lstat(filename);
  let handle;
  try {
    handle = await open(
      filename,
      fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
    );
    const before = await handle.stat();
    const current = await lstat(filename);
    if (
      !before.isFile()
      || before.nlink !== 1
      || current.isSymbolicLink()
      || !current.isFile()
      || current.nlink !== 1
      || !sameFileIdentity(expected, before)
      || !sameFileIdentity(before, current)
    ) {
      fail(`${label} changed while opening`);
    }
    return Object.freeze({ filename, handle, before });
  } catch (error) {
    await handle?.close().catch(() => undefined);
    if (error instanceof InstanceDescriptorError) throw error;
    fail(`${label} cannot be opened`);
  }
}

async function assertPinnedFileUnchanged(pinned, label) {
  const after = await pinned.handle.stat();
  const current = await lstat(pinned.filename).catch(() => undefined);
  if (
    current === undefined
    || current.isSymbolicLink()
    || !current.isFile()
    || current.nlink !== 1
    || after.nlink !== 1
    || !sameFileIdentity(pinned.before, after)
    || !sameFileIdentity(pinned.before, current)
  ) {
    fail(`${label} changed while reading`);
  }
}

async function readPinnedFile(root, relative, expectedHash, label) {
  const pinned = await openPinnedFile(root, relative, label);
  try {
    const data = await pinned.handle.readFile();
    await assertPinnedFileUnchanged(pinned, label);
    if (sha256(data) !== hex32(expectedHash, `${label}.sha256`)) fail(`${label} SHA-256 pin mismatch`);
    return Object.freeze({ filename: pinned.filename, data: Buffer.from(data), sha256: expectedHash });
  } finally {
    await pinned.handle.close();
  }
}

async function readStableFile(root, relative, label) {
  const pinned = await openPinnedFile(root, relative, label);
  try {
    const data = await pinned.handle.readFile();
    await assertPinnedFileUnchanged(pinned, label);
    return Object.freeze({
      filename: pinned.filename,
      data: Buffer.from(data),
    });
  } finally {
    await pinned.handle.close();
  }
}

/** Verify an opaque artifact without retaining its bytes in the descriptor. */
async function verifyPinnedFile(root, relative, expectedHash, label) {
  const pinned = await openPinnedFile(root, relative, label);
  try {
    const digest = createHash('sha256');
    for await (const chunk of pinned.handle.createReadStream({
      autoClose: false,
    })) {
      digest.update(chunk);
    }
    await assertPinnedFileUnchanged(pinned, label);
    if (digest.digest('hex') !== hex32(expectedHash, `${label}.sha256`)) {
      fail(`${label} SHA-256 pin mismatch`);
    }
    return Object.freeze({ filename: pinned.filename, sha256: expectedHash });
  } finally {
    await pinned.handle.close();
  }
}

async function verifyPinnedExecutable(
  root,
  relative,
  expectedHash,
  expectedBytes,
  label,
) {
  const pinned = await openPinnedFile(root, relative, label);
  try {
    if (
      (pinned.before.mode & 0o111) === 0
      || pinned.before.size !== expectedBytes
    ) {
      fail(
        `${label} must be executable and match its declared byte count`,
      );
    }
    const digest = createHash('sha256');
    for await (const chunk of pinned.handle.createReadStream({
      autoClose: false,
    })) {
      digest.update(chunk);
    }
    await assertPinnedFileUnchanged(pinned, label);
    if (digest.digest('hex') !== hex32(
      expectedHash,
      `${label}.sha256`,
    )) {
      fail(`${label} SHA-256 pin mismatch`);
    }
    return Object.freeze({
      filename: pinned.filename,
      sha256: expectedHash,
      bytes: expectedBytes,
    });
  } finally {
    await pinned.handle.close();
  }
}

function artifactEntry(value, label) {
  exactKeys(value, label, ['id', 'path', 'sha256']);
  if (typeof value.id !== 'string' || !ARTIFACT_ID.test(value.id)) fail(`${label}.id must be canonical`);
  return Object.freeze({ id: value.id, path: relativePath(value.path, `${label}.path`), sha256: hex32(value.sha256, `${label}.sha256`) });
}

function manifest(value) {
  exactKeys(value, 'artifact manifest', ['artifacts', 'instanceId', 'profileId', 'schema']);
  if (value.schema !== ARTIFACT_MANIFEST_SCHEMA) fail('artifact manifest schema is unsupported');
  const artifacts = value.artifacts;
  if (!Array.isArray(artifacts) || artifacts.length === 0) fail('artifact manifest artifacts must be nonempty array');
  const parsed = artifacts.map((entry, index) => artifactEntry(entry, `artifact manifest artifacts[${index}]`));
  for (let index = 1; index < parsed.length; index += 1) if (parsed[index - 1].id >= parsed[index].id) fail('artifact manifest artifacts must be id-sorted and unique');
  return Object.freeze({ profileId: hex32(value.profileId, 'artifact manifest profileId'), instanceId: hex32(value.instanceId, 'artifact manifest instanceId'), artifacts: parsed });
}

function referencedArtifactId(value, label, artifacts) {
  if (typeof value !== 'string' || !artifacts.has(value)) {
    fail(`${label} is not a manifest artifact`);
  }
  return value;
}

function verifyProfileBaseArtifactPins(profileCore, artifacts) {
  for (const entry of profileCore.baseVerifierArtifacts) {
    const artifact = artifacts.get(entry.id);
    if (artifact === undefined) {
      fail(
        `signed artifact manifest is missing profile base verifier artifact ${entry.id}`,
      );
    }
    if (artifact.sha256 !== entry.sha256) {
      fail(
        `signed artifact manifest hash differs from profile base verifier artifact ${entry.id}`,
      );
    }
  }
}

function finalLockDescription(value, artifacts) {
  exactKeys(value, 'instance descriptor finalLocks', [
    'binding',
    'state',
    'topologyId',
    'verifiers',
  ]);
  if (!Array.isArray(value.verifiers)) {
    fail('instance descriptor finalLocks.verifiers must be an array');
  }
  let topology;
  try {
    topology = resolveDirectV2VerifierTopology({
      id: value.topologyId,
      verifierRoles: value.verifiers.map((entry) => entry?.role),
    });
  } catch (error) {
    fail(`instance descriptor verifier topology is invalid: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
  const seenRoles = new Set();
  const seenVerifierArtifacts = new Set();
  const verifiers = value.verifiers.map((entry, index) => {
    const label = `instance descriptor finalLocks.verifiers[${index}]`;
    exactKeys(entry, label, ['baseSats', 'lockingArtifactId', 'role']);
    const expectedRole = topology.verifierRoles[index];
    if (
      entry.role !== expectedRole
      || seenRoles.has(entry.role)
    ) {
      fail(
        'instance descriptor finalLocks.verifiers roles must be exact, ordered, and unique',
      );
    }
    seenRoles.add(entry.role);
    const lockingArtifactId = referencedArtifactId(
      entry.lockingArtifactId,
      `${label}.lockingArtifactId`,
      artifacts,
    );
    if (seenVerifierArtifacts.has(lockingArtifactId)) {
      fail(
        'instance descriptor finalLocks.verifiers locking artifacts must be unique',
      );
    }
    seenVerifierArtifacts.add(lockingArtifactId);
    return Object.freeze({
      role: entry.role,
      lockingArtifactId,
      baseSats: decimal(entry.baseSats, `${label}.baseSats`),
    });
  });
  exactKeys(value.binding, 'instance descriptor finalLocks.binding', [
    'baseSats',
    'lockingArtifactId',
    'redeemArtifactId',
  ]);
  const binding = Object.freeze({
    lockingArtifactId: referencedArtifactId(
      value.binding.lockingArtifactId,
      'instance descriptor finalLocks.binding.lockingArtifactId',
      artifacts,
    ),
    redeemArtifactId: referencedArtifactId(
      value.binding.redeemArtifactId,
      'instance descriptor finalLocks.binding.redeemArtifactId',
      artifacts,
    ),
    baseSats: decimal(
      value.binding.baseSats,
      'instance descriptor finalLocks.binding.baseSats',
    ),
  });
  exactKeys(value.state, 'instance descriptor finalLocks.state', [
    'baseSats',
    'helperArtifactId',
    'helperUnlockArtifactId',
    'lockingArtifactId',
  ]);
  const state = Object.freeze({
    lockingArtifactId: referencedArtifactId(
      value.state.lockingArtifactId,
      'instance descriptor finalLocks.state.lockingArtifactId',
      artifacts,
    ),
    helperArtifactId: referencedArtifactId(
      value.state.helperArtifactId,
      'instance descriptor finalLocks.state.helperArtifactId',
      artifacts,
    ),
    helperUnlockArtifactId: referencedArtifactId(
      value.state.helperUnlockArtifactId,
      'instance descriptor finalLocks.state.helperUnlockArtifactId',
      artifacts,
    ),
    baseSats: decimal(
      value.state.baseSats,
      'instance descriptor finalLocks.state.baseSats',
    ),
  });
  return Object.freeze({
    topology,
    topologyId: topology.id,
    verifiers: Object.freeze(verifiers),
    binding,
    state,
  });
}

function descriptor(value, profileId, { allowUnsigned = false } = {}) {
  exactKeys(value, 'instance descriptor', ['finalLocks', 'genesis', 'initialState', 'instanceId', 'manifest', 'profileId', 'schema', 'signature', 'stateNftCategory']);
  if (value.schema !== INSTANCE_DESCRIPTOR_SCHEMA) fail('instance descriptor schema is unsupported');
  if (hex32(value.profileId, 'instance descriptor profileId') !== profileId) fail('instance descriptor profileId does not match profile core');
  const instanceId = hex32(value.instanceId, 'instance descriptor instanceId');
  if (hex32(value.stateNftCategory, 'instance descriptor stateNftCategory') !== instanceId) fail('instance descriptor stateNftCategory must equal instanceId wire bytes');
  exactKeys(value.genesis, 'instance descriptor genesis', ['outpointIndex', 'transactionId']);
  if (!Number.isInteger(value.genesis.outpointIndex) || value.genesis.outpointIndex < 0 || value.genesis.outpointIndex > 0xffff_ffff) fail('instance descriptor genesis outpointIndex is invalid');
  const initialState = bytesHex(value.initialState, 128, 'instance descriptor initialState');
  exactKeys(value.manifest, 'instance descriptor manifest', ['path', 'sha256']);
  const manifestRef = Object.freeze({ path: relativePath(value.manifest.path, 'instance descriptor manifest.path'), sha256: hex32(value.manifest.sha256, 'instance descriptor manifest.sha256') });
  if (value.signature === null) {
    if (!allowUnsigned) fail('instance descriptor signature is required');
  } else {
    exactKeys(value.signature, 'instance descriptor signature', ['algorithm', 'attestationDomain', 'attestationVersion', 'publicKey', 'signature', 'signerId']);
    if (value.signature.algorithm !== 'ed25519' || typeof value.signature.signerId !== 'string' || !SIGNER_ID.test(value.signature.signerId)) fail('instance descriptor signature is malformed');
    if (
      value.signature.attestationDomain !== INSTANCE_DESCRIPTOR_ATTESTATION_DOMAIN
      || value.signature.attestationVersion !== INSTANCE_DESCRIPTOR_ATTESTATION_VERSION
    ) fail('instance descriptor signature uses unsupported or legacy attestation semantics');
    if (typeof value.signature.publicKey !== 'string' || typeof value.signature.signature !== 'string') fail('instance descriptor signature key material is malformed');
  }
  return Object.freeze({ value, instanceId, genesis: Object.freeze({ transactionId: hex32(value.genesis.transactionId, 'instance descriptor genesis transactionId'), outpointIndex: value.genesis.outpointIndex }), initialState, manifestRef, signature: value.signature });
}

export function descriptorAttestationBytes({ descriptor: descriptorValue, canonicalManifestBytes, signature }) {
  if (!(canonicalManifestBytes instanceof Uint8Array)) fail('canonical manifest bytes must be bytes');
  if (signature === null || signature === undefined) fail('descriptor attestation requires a signature envelope');
  const unsignedDescriptor = { ...descriptorValue, signature: null };
  return Buffer.from(canonicalizeJcs({
    domain: INSTANCE_DESCRIPTOR_ATTESTATION_DOMAIN,
    version: INSTANCE_DESCRIPTOR_ATTESTATION_VERSION,
    signer: {
      signerId: signature.signerId,
      publicKey: signature.publicKey,
    },
    descriptorJcs: canonicalizeJcs(unsignedDescriptor),
    manifestSha256: sha256(canonicalManifestBytes),
  }), 'utf8');
}

function verifyPinnedSignature(signature, descriptorValue, canonicalManifestBytes, trustedSigners) {
  if (!Array.isArray(trustedSigners) || trustedSigners.length === 0) {
    fail('trustedSigners must contain at least one pinned Ed25519 signer');
  }
  const signerIds = new Set();
  const parsedSigners = trustedSigners.map((entry, index) => {
    const label = `trustedSigners[${index}]`;
    exactKeys(entry, label, ['publicKey', 'signerId']);
    if (
      typeof entry.signerId !== 'string'
      || !SIGNER_ID.test(entry.signerId)
      || typeof entry.publicKey !== 'string'
    ) {
      fail(`${label} is malformed`);
    }
    if (signerIds.has(entry.signerId)) {
      fail('trustedSigners signerId values must be unique');
    }
    signerIds.add(entry.signerId);
    let key;
    try {
      key = createPublicKey(entry.publicKey);
    } catch {
      fail(`${label}.publicKey is invalid`);
    }
    if (key.asymmetricKeyType !== 'ed25519') {
      fail(`${label}.publicKey must be Ed25519`);
    }
    return entry;
  });
  const pinned = parsedSigners.find(
    (entry) => entry.signerId === signature.signerId,
  );
  if (pinned === undefined || pinned.publicKey !== signature.publicKey) fail('descriptor signature signer is not pinned');
  let key; let signatureBytes;
  try { key = createPublicKey(signature.publicKey); signatureBytes = Buffer.from(signature.signature, 'base64'); } catch { fail('descriptor signature key material is invalid'); }
  const attestation = descriptorAttestationBytes({ descriptor: descriptorValue, canonicalManifestBytes, signature });
  if (
    key.asymmetricKeyType !== 'ed25519'
    || signatureBytes.length !== 64
    || signatureBytes.toString('base64') !== signature.signature
    || !verifySignature(null, attestation, key, signatureBytes)
  ) fail('descriptor signature verification failed');
  return Object.freeze({
    algorithm: 'ed25519',
    signerId: signature.signerId,
    publicKey: signature.publicKey,
  });
}

function verifyExactStructuralStateArtifacts({
  artifacts,
  bindingLock,
  denominationSats,
  finalLocks,
  stateCategory,
}) {
  let expectedHelper;
  let expectedHelperUnlock;
  let expectedStateLock;
  try {
    expectedHelper = Buffer.from(buildDirectV2StateHelper({
      bindingLock,
      verifierLocks: finalLocks.verifiers.map((entry) =>
        artifacts.get(entry.lockingArtifactId).data),
      verifierBaseValues: finalLocks.verifiers.map(
        (entry) => entry.baseSats,
      ),
      bindingBaseValueSats: finalLocks.binding.baseSats,
      stateBaseValueSats: finalLocks.state.baseSats,
      denominationSats,
      stateCategory,
      minimumChangeSats: V2_MINIMUM_CHANGE_SATS,
      topologyId: finalLocks.topology.id,
      verifierRoles: finalLocks.topology.verifierRoles,
    }));
    expectedHelperUnlock = Buffer.from(
      buildDirectV2StateTrampolineUnlock(expectedHelper),
    );
    expectedStateLock = Buffer.from(
      buildDirectV2StateTrampolineLock({
        helper: expectedHelper,
        bindingLock,
        topologyId: finalLocks.topology.id,
        verifierRoles: finalLocks.topology.verifierRoles,
      }),
    );
  } catch (error) {
    fail(
      `instance descriptor cannot derive the exact structural state artifacts: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  const actualHelper = artifacts.get(
    finalLocks.state.helperArtifactId,
  ).data;
  if (!actualHelper.equals(expectedHelper)) {
    fail(
      'instance descriptor state helper artifact is not the exact structural helper',
    );
  }
  const actualHelperUnlock = artifacts.get(
    finalLocks.state.helperUnlockArtifactId,
  ).data;
  if (!actualHelperUnlock.equals(expectedHelperUnlock)) {
    fail(
      'instance descriptor state helper-unlock artifact is not canonical for the exact structural helper',
    );
  }
  const actualStateLock = artifacts.get(
    finalLocks.state.lockingArtifactId,
  ).data;
  if (!actualStateLock.equals(expectedStateLock)) {
    fail(
      'instance descriptor state locking artifact is not the exact structural trampoline lock',
    );
  }
}

function verifyExactDustDerivedBaseValues({
  artifacts,
  finalLocks,
  initialState,
  instanceId,
}) {
  for (const [index, verifier] of finalLocks.verifiers.entries()) {
    const expected = deriveV2RollingBaseSats({
      lockingBytecode: artifacts.get(verifier.lockingArtifactId).data,
    });
    if (BigInt(verifier.baseSats) !== expected) {
      fail(
        `instance descriptor verifier ${index} baseSats must equal the exact dust-derived value ${expected}`,
      );
    }
  }
  const bindingExpected = deriveV2RollingBaseSats({
    lockingBytecode: artifacts.get(
      finalLocks.binding.lockingArtifactId,
    ).data,
  });
  if (BigInt(finalLocks.binding.baseSats) !== bindingExpected) {
    fail(
      `instance descriptor binding baseSats must equal the exact dust-derived value ${bindingExpected}`,
    );
  }
  const stateExpected = deriveV2RollingBaseSats({
    lockingBytecode: artifacts.get(
      finalLocks.state.lockingArtifactId,
    ).data,
    token: {
      category: Buffer.from(instanceId, 'hex'),
      amount: 0n,
      nft: {
        capability: 'mutable',
        commitment: Buffer.from(initialState),
      },
    },
  });
  if (BigInt(finalLocks.state.baseSats) !== stateExpected) {
    fail(
      `instance descriptor state baseSats must equal the exact dust-derived value ${stateExpected}`,
    );
  }
}

function finalLocksPackageSha256(finalLocks, artifacts) {
  return sha256(Buffer.from(canonicalizeJcs({
    topologyId: finalLocks.topology.id,
    verifiers: finalLocks.verifiers.map((entry) => ({
      role: entry.role,
      baseSats: entry.baseSats,
      lockingBytecodeSha256: sha256(
        artifacts.get(entry.lockingArtifactId).data,
      ),
    })),
    binding: {
      baseSats: finalLocks.binding.baseSats,
      lockingBytecodeSha256: sha256(
        artifacts.get(finalLocks.binding.lockingArtifactId).data,
      ),
      redeemBytecodeSha256: sha256(
        artifacts.get(finalLocks.binding.redeemArtifactId).data,
      ),
    },
    state: {
      baseSats: finalLocks.state.baseSats,
      lockingBytecodeSha256: sha256(
        artifacts.get(finalLocks.state.lockingArtifactId).data,
      ),
      helperBytecodeSha256: sha256(
        artifacts.get(finalLocks.state.helperArtifactId).data,
      ),
      helperUnlockingBytecodeSha256: sha256(
        artifacts.get(finalLocks.state.helperUnlockArtifactId).data,
      ),
    },
  }), 'utf8'));
}

/**
 * Load only a fully pinned, locally present instance descriptor. Structural
 * artifact bytes are exposed only after schema, profile, state, manifest,
 * every regular artifact, exact protocol-defined topology, binding P2SH32,
 * and pinned-identity Ed25519 verification all succeed. Opaque large
 * artifacts are streamed through SHA-256 verification and returned by
 * immutable path/hash record.
 */
async function loadV2InstanceDescriptorInternal({
  allowUnsigned,
  descriptorPath,
  profileCore,
  trustedSigners,
}) {
  if (typeof descriptorPath !== 'string' || !path.isAbsolute(descriptorPath)) fail('descriptorPath must be absolute');
  const root = path.dirname(descriptorPath);
  const name = path.basename(descriptorPath);
  const descriptorFile = await readStableFile(
    root,
    name,
    'instance descriptor',
  );
  let raw;
  try { raw = JSON.parse(descriptorFile.data.toString('utf8')); } catch { fail('instance descriptor is not JSON'); }
  if (!descriptorFile.data.equals(Buffer.from(canonicalizeJcs(raw), 'utf8'))) fail('instance descriptor must use exact RFC8785/JCS canonical bytes');
  const profileId = deriveProfileId(profileCore);
  const parsed = descriptor(raw, profileId, { allowUnsigned });
  let decodedInitialState;
  try { decodedInitialState = decodeStateNftCommitment(parsed.initialState, { denominationSats: profileCore.denominationSats }); }
  catch (error) { fail(`instance descriptor initialState is invalid: ${error instanceof Error ? error.message : String(error)}`); }
  if (decodedInitialState.profileId !== profileId) fail('instance descriptor initialState profileId does not match profile core');
  let expectedInitialState;
  try {
    const initialModel = createDirectV2PoolModel({
      profileId,
      maximumLiveNotes: decodedInitialState.maximumLiveNotes,
      denominationSats: profileCore.denominationSats,
    });
    expectedInitialState = encodeStateNftCommitment(initialModel.state, {
      denominationSats: profileCore.denominationSats,
    });
  } catch (error) {
    fail(`instance descriptor initialState cannot derive canonical genesis: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!parsed.initialState.equals(expectedInitialState)) {
    fail('instance descriptor initialState must be the exact canonical empty genesis state');
  }
  const manifestFile = await readPinnedFile(root, parsed.manifestRef.path, parsed.manifestRef.sha256, 'artifact manifest');
  let rawManifest;
  try { rawManifest = JSON.parse(manifestFile.data.toString('utf8')); } catch { fail('artifact manifest is not JSON'); }
  const canonicalManifest = Buffer.from(canonicalizeJcs(rawManifest), 'utf8');
  if (!manifestFile.data.equals(canonicalManifest)) fail('artifact manifest must use exact RFC8785/JCS canonical bytes');
  const parsedManifest = manifest(rawManifest);
  if (parsedManifest.profileId !== profileId || parsedManifest.instanceId !== parsed.instanceId) fail('artifact manifest does not bind descriptor profileId and instanceId');
  const artifactMap = new Map(parsedManifest.artifacts.map((entry) => [entry.id, entry]));
  const canonicalProfileCoreSha256 = sha256(
    Buffer.from(canonicalizeJcs(profileCore), 'utf8'),
  );
  const profileCoreArtifact = artifactMap.get(
    PROFILE_CORE_MANIFEST_ARTIFACT_ID,
  );
  if (
    profileCoreArtifact === undefined
    || profileCoreArtifact.sha256 !== canonicalProfileCoreSha256
  ) {
    fail('signed artifact manifest does not pin the exact profile core');
  }
  verifyProfileBaseArtifactPins(profileCore, artifactMap);
  const finalLocks = finalLockDescription(raw.finalLocks, artifactMap);
  const attestation = parsed.signature === null
    ? null
    : verifyPinnedSignature(
      parsed.signature,
      raw,
      canonicalManifest,
      trustedSigners,
    );
  const referencedIds = [
    ...finalLocks.verifiers.map((entry) => entry.lockingArtifactId),
    finalLocks.binding.lockingArtifactId,
    finalLocks.binding.redeemArtifactId,
    finalLocks.state.lockingArtifactId,
    finalLocks.state.helperArtifactId,
    finalLocks.state.helperUnlockArtifactId,
  ];
  const structuralArtifactIds = new Set(referencedIds);
  const artifacts = new Map();
  for (const entry of parsedManifest.artifacts) {
    const label = `artifact ${entry.id}`;
    artifacts.set(
      entry.id,
      structuralArtifactIds.has(entry.id)
        ? await readPinnedFile(root, entry.path, entry.sha256, label)
        : await verifyPinnedFile(root, entry.path, entry.sha256, label),
    );
  }
  for (const artifactId of referencedIds) {
    if (artifacts.get(artifactId).data.length === 0) {
      fail(`referenced artifact ${artifactId} must be nonempty`);
    }
  }
  const bindingLock = artifacts.get(
    finalLocks.binding.lockingArtifactId,
  ).data;
  const bindingRedeem = artifacts.get(
    finalLocks.binding.redeemArtifactId,
  ).data;
  try {
    verifyDirectV2BindingP2sh32Lock({
      redeemScript: bindingRedeem,
      sourceLockingBytecode: bindingLock,
    });
  } catch (error) {
    fail(
      `instance descriptor binding locking/redeem artifacts do not form the exact P2SH32 pair: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  verifyExactStructuralStateArtifacts({
    artifacts,
    bindingLock,
    denominationSats: profileCore.denominationSats,
    finalLocks,
    stateCategory: parsed.instanceId,
  });
  verifyExactDustDerivedBaseValues({
    artifacts,
    finalLocks,
    initialState: parsed.initialState,
    instanceId: parsed.instanceId,
  });
  const loaded = Object.freeze({
    profileId, instanceId: parsed.instanceId, stateNftCategory: parsed.instanceId, genesis: parsed.genesis,
    initialState: Buffer.from(parsed.initialState), finalLocks,
    descriptor: Object.freeze({
      sha256: sha256(descriptorFile.data),
      canonicalBytes: Buffer.from(descriptorFile.data),
    }),
    attestation,
    manifest: Object.freeze({
      filename: manifestFile.filename,
      sha256: parsed.manifestRef.sha256,
      canonicalBytes: Buffer.from(canonicalManifest),
    }),
    artifacts,
  });
  const pins = Object.freeze({
    root,
    profileId,
    instanceId: parsed.instanceId,
    maximumLiveNotes: decodedInitialState.maximumLiveNotes,
    denominationSats: profileCore.denominationSats,
    profileCoreSha256: canonicalProfileCoreSha256,
    profileProof: Object.freeze({ ...profileCore.proof }),
    profileBaseArtifacts: Object.freeze(Object.fromEntries(
      profileCore.baseVerifierArtifacts.map((entry) => [
        entry.id,
        entry.sha256,
      ]),
    )),
    profileToolchain: Object.freeze(profileCore.toolchain.map((entry) =>
      Object.freeze({ ...entry }))),
    profileToolchainSha256: sha256(
      Buffer.from(canonicalizeJcs(profileCore.toolchain), 'utf8'),
    ),
    artifactEntries: Object.freeze(Object.fromEntries(
      parsedManifest.artifacts.map((entry) => [
        entry.id,
        Object.freeze({
          path: entry.path,
          sha256: entry.sha256,
        }),
      ]),
    )),
    topologyId: finalLocks.topology.id,
    verifierRoles: finalLocks.topology.verifierRoles,
    verifierCarriers: Object.freeze(finalLocks.verifiers.map((entry) =>
      Object.freeze({
        baseValueSats: entry.baseSats,
        lockingBytecodeHex: artifacts.get(
          entry.lockingArtifactId,
        ).data.toString('hex'),
      }))),
    bindingBaseSats: finalLocks.binding.baseSats,
    bindingLockingBytecodeHex: bindingLock.toString('hex'),
    bindingRedeemBytecodeHex: bindingRedeem.toString('hex'),
    stateBaseSats: finalLocks.state.baseSats,
    stateLockingBytecodeHex: artifacts.get(
      finalLocks.state.lockingArtifactId,
    ).data.toString('hex'),
    stateHelperUnlockArtifactId:
      finalLocks.state.helperUnlockArtifactId,
    finalLocksSha256: finalLocksPackageSha256(finalLocks, artifacts),
  });
  if (!allowUnsigned) {
    validatedDescriptorPins.set(loaded, pins);
  }
  return Object.freeze({ loaded, pins });
}

export async function loadV2InstanceDescriptor({
  descriptorPath,
  profileCore,
  trustedSigners = undefined,
}) {
  return (
    await loadV2InstanceDescriptorInternal({
      allowUnsigned: false,
      descriptorPath,
      profileCore,
      trustedSigners,
    })
  ).loaded;
}

/**
 * Derive settlement pins only from a descriptor returned by
 * `loadV2InstanceDescriptor`. Fresh byte copies prevent callers from mutating
 * the validated module-private pin record.
 */
export function deriveV2SettlementPinsFromValidatedDescriptor(value) {
  const pins = validatedDescriptorPins.get(value);
  if (pins === undefined) {
    fail(
      'V2 settlement pins require a descriptor validated by loadV2InstanceDescriptor',
    );
  }
  return Object.freeze({
    topologyId: pins.topologyId,
    verifierRoles: pins.verifierRoles,
    verifierCarriers: Object.freeze(pins.verifierCarriers.map((entry) =>
      Object.freeze({
        baseValueSats: entry.baseValueSats,
        lockingBytecode: Buffer.from(entry.lockingBytecodeHex, 'hex'),
      }))),
    bindingBaseSats: pins.bindingBaseSats,
    bindingLockingBytecode: Buffer.from(
      pins.bindingLockingBytecodeHex,
      'hex',
    ),
    bindingRedeemBytecode: Buffer.from(
      pins.bindingRedeemBytecodeHex,
      'hex',
    ),
    stateBaseSats: pins.stateBaseSats,
    stateLockingBytecode: Buffer.from(
      pins.stateLockingBytecodeHex,
      'hex',
    ),
  });
}

export function deriveV2FinalLocksSha256FromValidatedDescriptor(value) {
  const pins = validatedDescriptorPins.get(value);
  if (pins === undefined) {
    fail(
      'V2 final-lock digest requires a descriptor validated by loadV2InstanceDescriptor',
    );
  }
  return pins.finalLocksSha256;
}

/**
 * Resolve one opaque artifact only from a descriptor authenticated by
 * `loadV2InstanceDescriptor`. This is the bridge used by offline
 * qualification replay: the caller receives the already-opened package path
 * and signed-manifest hash, never authority to substitute an arbitrary
 * pathname or digest.
 */
export function deriveV2ManifestArtifactFromValidatedDescriptor(
  value,
  artifactId,
) {
  const pins = validatedDescriptorPins.get(value);
  if (pins === undefined) {
    fail(
      'V2 manifest artifact resolution requires a descriptor validated by loadV2InstanceDescriptor',
    );
  }
  if (typeof artifactId !== 'string' || !ARTIFACT_ID.test(artifactId)) {
    fail('V2 manifest artifact id must be canonical');
  }
  const entry = pins.artifactEntries[artifactId];
  const artifact = value.artifacts.get(artifactId);
  if (entry === undefined || artifact === undefined) {
    fail(`signed artifact manifest is missing required ${artifactId} artifact`);
  }
  if (
    artifact.sha256 !== entry.sha256
    || typeof artifact.filename !== 'string'
    || !path.isAbsolute(artifact.filename)
  ) {
    fail(`validated manifest artifact ${artifactId} is internally inconsistent`);
  }
  return Object.freeze({
    artifactId,
    path: artifact.filename,
    sha256: entry.sha256,
    descriptorSha256: value.descriptor.sha256,
    manifestSha256: value.manifest.sha256,
    profileId: pins.profileId,
    instanceId: pins.instanceId,
    topologyId: pins.topologyId,
    finalLocksSha256: pins.finalLocksSha256,
  });
}

function requiredRecoveryScannerArtifact(pins, artifactId) {
  const artifact = pins.artifactEntries[artifactId];
  if (artifact === undefined) {
    fail(
      `signed artifact manifest is missing required ${artifactId} artifact`,
    );
  }
  return artifact;
}

/**
 * Resolve the native recovery scanner only from the module-private pins
 * installed by `loadV2InstanceDescriptor`. The signed outer manifest pins both
 * the canonical scanner manifest and its executable; the inner manifest binds
 * the executable identity, byte count, source revision, Cargo lockfile, host
 * target, toolchain, and exact native protocol ABI.
 */
export async function deriveV2RecoveryScannerFromValidatedDescriptor(value) {
  const pins = validatedDescriptorPins.get(value);
  if (pins === undefined) {
    fail(
      'V2 recovery scanner requires a descriptor validated by loadV2InstanceDescriptor',
    );
  }
  if (process.platform !== 'linux' || process.arch !== 'x64') {
    fail('V2 recovery scanner requires the signed linux-x64 target');
  }

  const scannerManifestArtifact = requiredRecoveryScannerArtifact(
    pins,
    RECOVERY_SCANNER_MANIFEST_ARTIFACT_ID,
  );
  const binaryArtifact = requiredRecoveryScannerArtifact(
    pins,
    RECOVERY_SCANNER_LINUX_X64_ARTIFACT_ID,
  );
  const scannerManifestFile = await readPinnedFile(
    pins.root,
    scannerManifestArtifact.path,
    scannerManifestArtifact.sha256,
    `artifact ${RECOVERY_SCANNER_MANIFEST_ARTIFACT_ID}`,
  );
  let parsedScannerArtifact;
  try {
    parsedScannerArtifact = parseV2RecoveryScannerArtifact(
      scannerManifestFile.data,
    );
  } catch (error) {
    fail(
      error instanceof Error
        ? error.message
        : 'recovery scanner manifest is invalid',
    );
  }
  const parsedManifest = parsedScannerArtifact.manifest;
  if (parsedManifest.binarySha256 !== binaryArtifact.sha256) {
    fail(
      'recovery scanner binarySha256 differs from the signed outer-manifest SHA-256 pin',
    );
  }
  const binary = await verifyPinnedExecutable(
    pins.root,
    binaryArtifact.path,
    binaryArtifact.sha256,
    parsedManifest.binaryBytes,
    `artifact ${RECOVERY_SCANNER_LINUX_X64_ARTIFACT_ID}`,
  );
  const resolution = Object.freeze({
    schema: 'shieldkit-v2-recovery-scanner-resolution-v1',
    target: parsedManifest.target,
    binaryPath: binary.filename,
    binarySha256: binary.sha256,
    binaryBytes: binary.bytes,
    cargoLockSha256: parsedManifest.cargoLockSha256,
    sourceRevision: parsedManifest.sourceRevision,
    eligibility: parsedManifest.eligibility,
    rustcVersion: parsedManifest.rustcVersion,
    cargoVersion: parsedManifest.cargoVersion,
    protocolSchemas: parsedManifest.protocolSchemas,
    descriptorSha256: value.descriptor.sha256,
    artifactManifestSha256: value.manifest.sha256,
    scannerManifestSha256: scannerManifestArtifact.sha256,
  });
  validatedRecoveryScannerResolutions.set(
    resolution,
    Object.freeze({
      binaryPath: binary.filename,
      binarySha256: binary.sha256,
      binaryBytes: binary.bytes,
    }),
  );
  return resolution;
}

/**
 * Convert a validated scanner resolution into the minimal native-execution
 * capability. Object copies and caller-created path/hash pairs are rejected.
 */
export function deriveV2RecoveryScannerExecutionPin(value) {
  const pin = validatedRecoveryScannerResolutions.get(value);
  if (pin === undefined) {
    fail(
      'V2 recovery scanner execution requires a resolution derived from a validated descriptor',
    );
  }
  return Object.freeze({ ...pin });
}

/**
 * Compatibility boundary for the PF11-only settlement assembler. It rejects a
 * signed PF10 descriptor rather than silently interpreting ten roles as PF11.
 */
export function derivePf11SettlementPinsFromValidatedDescriptor(value) {
  const pins = deriveV2SettlementPinsFromValidatedDescriptor(value);
  if (
    pins.topologyId !== DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID
    || pins.verifierRoles.length !==
      DIRECT_V2_PF11_ORACLE_VERIFIER_ROLES.length
    || pins.verifierRoles.some(
      (role, index) => role !== DIRECT_V2_PF11_ORACLE_VERIFIER_ROLES[index],
    )
  ) {
    fail('PF11 settlement pins require the signed PF11 oracle topology');
  }
  return pins;
}

function runtimeArtifactId(value, label, artifactEntries) {
  if (
    typeof value !== 'string'
    || !ARTIFACT_ID.test(value)
    || !Object.hasOwn(artifactEntries, value)
  ) {
    fail(`${label} is not a signed manifest artifact`);
  }
  return value;
}

function parsePf10RuntimeArtifact(value, pins) {
  exactKeys(value, 'PF10 runtime artifact', [
    'attestationArtifacts',
    'eligibility',
    'instanceId',
    'libauthEvidenceArtifactId',
    'profileArtifacts',
    'profileId',
    'proofArtifacts',
    'qualificationEvidenceArtifactId',
    'rawQualificationEvidenceArtifactId',
    'schema',
    'setupArtifacts',
    'topologyId',
    'unlockArtifacts',
    'verifierRoles',
  ]);
  if (
    value.schema !== PF10_RUNTIME_ARTIFACT_SCHEMA
    || value.profileId !== pins.profileId
    || value.instanceId !== pins.instanceId
    || value.topologyId !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
    || value.eligibility !== 'development-only'
    || !Array.isArray(value.verifierRoles)
    || value.verifierRoles.length
      !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length
    || value.verifierRoles.some(
      (role, index) =>
        role !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES[index],
    )
  ) {
    fail('PF10 development runtime artifact identity, topology, or eligibility is invalid');
  }
  exactKeys(value.profileArtifacts, 'PF10 runtime profileArtifacts', [
    'baseVerifierManifestArtifactId',
    'profileCoreArtifactId',
    'profilePackageArtifactId',
    'toolchainManifestArtifactId',
    'topologySpecArtifactId',
  ]);
  exactKeys(
    value.attestationArtifacts,
    'PF10 runtime attestationArtifacts',
    [
      'circuitBuildAttestationArtifactId',
      'developmentSetupAttestationArtifactId',
      'relationManifestArtifactId',
    ],
  );
  exactKeys(value.setupArtifacts, 'PF10 runtime setupArtifacts', [
    'circuitSymbolsArtifactId',
    'initialProvingKeyArtifactId',
    'powersOfTauArtifactId',
  ]);
  exactKeys(value.proofArtifacts, 'PF10 runtime proofArtifacts', [
    'provingKeyArtifactId',
    'r1csArtifactId',
    'verificationKeyArtifactId',
    'witnessWasmArtifactId',
  ]);
  exactKeys(value.unlockArtifacts, 'PF10 runtime unlockArtifacts', [
    'exactMsmRedeemArtifactIds',
    'executorBodyArtifactId',
    'fixedCarrierPadArtifactIds',
    'fusedRedeemArtifactId',
    'terminalRedeemArtifactId',
  ]);
  if (
    !Array.isArray(value.unlockArtifacts.exactMsmRedeemArtifactIds)
    || value.unlockArtifacts.exactMsmRedeemArtifactIds.length !== 3
    || !Array.isArray(value.unlockArtifacts.fixedCarrierPadArtifactIds)
    || value.unlockArtifacts.fixedCarrierPadArtifactIds.length !== 3
  ) {
    fail(
      'PF10 runtime artifact must reference three exact-MSM redeems and three fixed carrier pads',
    );
  }
  const profileArtifacts = Object.freeze({
    profileCore: runtimeArtifactId(
      value.profileArtifacts.profileCoreArtifactId,
      'PF10 profile core',
      pins.artifactEntries,
    ),
    profilePackage: runtimeArtifactId(
      value.profileArtifacts.profilePackageArtifactId,
      'PF10 profile package',
      pins.artifactEntries,
    ),
    baseVerifierManifest: runtimeArtifactId(
      value.profileArtifacts.baseVerifierManifestArtifactId,
      'PF10 base verifier manifest',
      pins.artifactEntries,
    ),
    topologySpec: runtimeArtifactId(
      value.profileArtifacts.topologySpecArtifactId,
      'PF10 topology specification',
      pins.artifactEntries,
    ),
    toolchainManifest: runtimeArtifactId(
      value.profileArtifacts.toolchainManifestArtifactId,
      'PF10 toolchain manifest',
      pins.artifactEntries,
    ),
  });
  const attestationArtifacts = Object.freeze({
    circuitBuildAttestation: runtimeArtifactId(
      value.attestationArtifacts.circuitBuildAttestationArtifactId,
      'PF10 circuit build attestation',
      pins.artifactEntries,
    ),
    developmentSetupAttestation: runtimeArtifactId(
      value.attestationArtifacts.developmentSetupAttestationArtifactId,
      'PF10 development setup attestation',
      pins.artifactEntries,
    ),
    relationManifest: runtimeArtifactId(
      value.attestationArtifacts.relationManifestArtifactId,
      'PF10 relation source manifest',
      pins.artifactEntries,
    ),
  });
  const setupArtifacts = Object.freeze({
    circuitSymbols: runtimeArtifactId(
      value.setupArtifacts.circuitSymbolsArtifactId,
      'PF10 circuit symbol table',
      pins.artifactEntries,
    ),
    initialProvingKey: runtimeArtifactId(
      value.setupArtifacts.initialProvingKeyArtifactId,
      'PF10 initial proving key',
      pins.artifactEntries,
    ),
    powersOfTau: runtimeArtifactId(
      value.setupArtifacts.powersOfTauArtifactId,
      'PF10 Powers of Tau',
      pins.artifactEntries,
    ),
  });
  const proofArtifacts = Object.freeze({
    provingKey: runtimeArtifactId(
      value.proofArtifacts.provingKeyArtifactId,
      'PF10 proving key',
      pins.artifactEntries,
    ),
    r1cs: runtimeArtifactId(
      value.proofArtifacts.r1csArtifactId,
      'PF10 R1CS',
      pins.artifactEntries,
    ),
    verificationKey: runtimeArtifactId(
      value.proofArtifacts.verificationKeyArtifactId,
      'PF10 verification key',
      pins.artifactEntries,
    ),
    wasm: runtimeArtifactId(
      value.proofArtifacts.witnessWasmArtifactId,
      'PF10 witness WASM',
      pins.artifactEntries,
    ),
  });
  const unlockArtifacts = Object.freeze({
    executorBody: runtimeArtifactId(
      value.unlockArtifacts.executorBodyArtifactId,
      'PF10 executor body',
      pins.artifactEntries,
    ),
    exactMsmRedeems: Object.freeze(
      value.unlockArtifacts.exactMsmRedeemArtifactIds.map(
        (artifactId, index) => runtimeArtifactId(
          artifactId,
          `PF10 exact-MSM redeem ${index}`,
          pins.artifactEntries,
        ),
      ),
    ),
    fixedCarrierPads: Object.freeze(
      value.unlockArtifacts.fixedCarrierPadArtifactIds.map(
        (artifactId, index) => runtimeArtifactId(
          artifactId,
          `PF10 fixed carrier pad ${index}`,
          pins.artifactEntries,
        ),
      ),
    ),
    fusedRedeem: runtimeArtifactId(
      value.unlockArtifacts.fusedRedeemArtifactId,
      'PF10 fused redeem',
      pins.artifactEntries,
    ),
    terminalRedeem: runtimeArtifactId(
      value.unlockArtifacts.terminalRedeemArtifactId,
      'PF10 terminal redeem',
      pins.artifactEntries,
    ),
  });
  const qualificationEvidenceArtifactId = runtimeArtifactId(
    value.qualificationEvidenceArtifactId,
    'PF10 qualification evidence',
    pins.artifactEntries,
  );
  const rawQualificationEvidenceArtifactId = runtimeArtifactId(
    value.rawQualificationEvidenceArtifactId,
    'PF10 raw qualification evidence',
    pins.artifactEntries,
  );
  const libauthEvidenceArtifactId = runtimeArtifactId(
    value.libauthEvidenceArtifactId,
    'PF10 per-instance Libauth evidence',
    pins.artifactEntries,
  );
  const allIds = [
    ...Object.values(profileArtifacts),
    ...Object.values(attestationArtifacts),
    ...Object.values(setupArtifacts),
    ...Object.values(proofArtifacts),
    unlockArtifacts.executorBody,
    ...unlockArtifacts.exactMsmRedeems,
    ...unlockArtifacts.fixedCarrierPads,
    unlockArtifacts.fusedRedeem,
    unlockArtifacts.terminalRedeem,
    qualificationEvidenceArtifactId,
    rawQualificationEvidenceArtifactId,
    libauthEvidenceArtifactId,
  ];
  if (new Set(allIds).size !== allIds.length) {
    fail('PF10 runtime artifact references must be unique');
  }
  return Object.freeze({
    kind: 'development',
    eligibility: value.eligibility,
    profileArtifacts,
    attestationArtifacts,
    setupArtifacts,
    proofArtifacts,
    unlockArtifacts,
    qualificationEvidenceArtifactId,
    rawQualificationEvidenceArtifactId,
    libauthEvidenceArtifactId,
  });
}

function unsignedRuntimeArtifactEntries(value) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('unsigned PF10 runtime artifactEntries must be a plain object');
  }
  const entries = {};
  for (const artifactId of Object.keys(value)) {
    if (!ARTIFACT_ID.test(artifactId)) {
      fail('unsigned PF10 runtime artifactEntries has a noncanonical artifact ID');
    }
    const entry = value[artifactId];
    exactKeys(
      entry,
      `unsigned PF10 runtime artifactEntries.${artifactId}`,
      ['id', 'sha256'],
    );
    if (entry.id !== artifactId || !ARTIFACT_ID.test(entry.id)) {
      fail(
        `unsigned PF10 runtime artifactEntries.${artifactId}.id must equal its canonical map key`,
      );
    }
    entries[artifactId] = Object.freeze({
      id: artifactId,
      sha256: hex32(
        entry.sha256,
        `unsigned PF10 runtime artifactEntries.${artifactId}.sha256`,
      ),
    });
  }
  return Object.freeze(entries);
}

function pf10RuntimeReferencedArtifactIds(runtime) {
  return Object.freeze([
    runtime.profileArtifacts.profileCore,
    runtime.profileArtifacts.profilePackage,
    runtime.profileArtifacts.baseVerifierManifest,
    runtime.profileArtifacts.topologySpec,
    runtime.profileArtifacts.toolchainManifest,
    runtime.attestationArtifacts.circuitBuildAttestation,
    runtime.attestationArtifacts.developmentSetupAttestation,
    runtime.attestationArtifacts.relationManifest,
    runtime.setupArtifacts.circuitSymbols,
    runtime.setupArtifacts.initialProvingKey,
    runtime.setupArtifacts.powersOfTau,
    runtime.proofArtifacts.provingKey,
    runtime.proofArtifacts.r1cs,
    runtime.proofArtifacts.verificationKey,
    runtime.proofArtifacts.wasm,
    runtime.unlockArtifacts.executorBody,
    ...runtime.unlockArtifacts.exactMsmRedeems,
    ...runtime.unlockArtifacts.fixedCarrierPads,
    runtime.unlockArtifacts.fusedRedeem,
    runtime.unlockArtifacts.terminalRedeem,
    runtime.qualificationEvidenceArtifactId,
    runtime.rawQualificationEvidenceArtifactId,
    runtime.libauthEvidenceArtifactId,
  ]);
}

/**
 * Validate the complete development-runtime reference topology before an
 * unsigned package is signed or passed to a broader descriptor resolver.
 *
 * `artifactEntries` is deliberately the exact 27-entry reference map, not an
 * artifact manifest: every record is `{ id, sha256 }`, every map key must be
 * its record's canonical ID, and no unreferenced entry is accepted. The
 * runtime artifact's own `pf10-runtime-material` record, final-lock records,
 * and reproducibility records are outside this runtime-reference boundary.
 * The result returns only normalized IDs, never paths, bytes, or an execution
 * capability.
 */
export function validateV2UnsignedPf10RuntimeArtifactReferences(value) {
  exactKeys(value, 'unsigned PF10 runtime reference validation options', [
    'artifactEntries',
    'instanceId',
    'profileId',
    'runtimeArtifact',
  ]);
  const profileId = hex32(value.profileId, 'unsigned PF10 runtime profileId');
  const instanceId = hex32(value.instanceId, 'unsigned PF10 runtime instanceId');
  const artifactEntries = unsignedRuntimeArtifactEntries(value.artifactEntries);
  const runtime = parsePf10RuntimeArtifact(value.runtimeArtifact, {
    artifactEntries,
    instanceId,
    profileId,
  });
  const referencedArtifactIds = pf10RuntimeReferencedArtifactIds(runtime);
  if (
    referencedArtifactIds.length !== PF10_UNSIGNED_RUNTIME_REFERENCE_COUNT
    || new Set(referencedArtifactIds).size !== referencedArtifactIds.length
  ) {
    fail('PF10 runtime artifact normalized reference count is invalid');
  }
  const suppliedIds = Object.keys(artifactEntries).sort();
  const expectedIds = [...referencedArtifactIds].sort();
  if (
    suppliedIds.length !== expectedIds.length
    || suppliedIds.some((artifactId, index) => artifactId !== expectedIds[index])
  ) {
    fail(
      `unsigned PF10 runtime artifactEntries must contain exactly the ${PF10_UNSIGNED_RUNTIME_REFERENCE_COUNT} referenced artifact IDs`,
    );
  }
  return Object.freeze({
    schema: PF10_UNSIGNED_RUNTIME_REFERENCE_VALIDATION_SCHEMA,
    eligibility: runtime.eligibility,
    references: Object.freeze({
      profileArtifacts: runtime.profileArtifacts,
      attestationArtifacts: runtime.attestationArtifacts,
      setupArtifacts: runtime.setupArtifacts,
      proofArtifacts: runtime.proofArtifacts,
      unlockArtifacts: runtime.unlockArtifacts,
      qualificationEvidenceArtifactId: runtime.qualificationEvidenceArtifactId,
      rawQualificationEvidenceArtifactId:
        runtime.rawQualificationEvidenceArtifactId,
      libauthEvidenceArtifactId: runtime.libauthEvidenceArtifactId,
    }),
    referencedArtifactIds,
    referencedArtifactCount: referencedArtifactIds.length,
  });
}

function parsePf10FinalRuntimeArtifact(value, pins) {
  exactKeys(value, 'PF10 final runtime artifact', [
    'buildArtifacts',
    'ceremonyArtifacts',
    'eligibility',
    'instanceId',
    'profileId',
    'proofArtifacts',
    'schema',
    'topologyId',
    'unlockArtifacts',
    'verifierRoles',
  ]);
  if (
    value.schema !== PF10_FINAL_RUNTIME_ARTIFACT_SCHEMA
    || value.eligibility !== 'final-qualified'
    || value.profileId !== pins.profileId
    || value.instanceId !== pins.instanceId
    || value.topologyId !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
    || !Array.isArray(value.verifierRoles)
    || value.verifierRoles.length
      !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length
    || value.verifierRoles.some(
      (role, index) =>
        role !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES[index],
    )
  ) {
    fail('PF10 final runtime identity, topology, or eligibility is invalid');
  }
  exactKeys(value.buildArtifacts, 'PF10 final runtime buildArtifacts', [
    'circuitBuildAttestationArtifactId',
    'circuitSymbolsArtifactId',
    'initialProvingKeyArtifactId',
    'powersOfTauArtifactId',
    'relationSourceManifestArtifactId',
    'snarkjsToolchainArtifactId',
  ]);
  exactKeys(value.proofArtifacts, 'PF10 final runtime proofArtifacts', [
    'finalProvingKeyArtifactId',
    'r1csArtifactId',
    'verificationKeyArtifactId',
    'witnessWasmArtifactId',
  ]);
  exactKeys(value.unlockArtifacts, 'PF10 final runtime unlockArtifacts', [
    'exactMsmRedeemArtifactIds',
    'executorBodyArtifactId',
    'fixedCarrierPadArtifactIds',
    'fusedRedeemArtifactId',
    'terminalRedeemArtifactId',
  ]);
  exactKeys(
    value.ceremonyArtifacts,
    'PF10 final runtime ceremonyArtifacts',
    [
      'beaconArtifactId',
      'contributorRegistryArtifactId',
      'evidencePolicyArtifactId',
      'reproducibilityHostArtifactIds',
      'transcriptArtifactId',
      'transcriptVerificationArtifactIds',
    ],
  );
  if (
    !Array.isArray(value.unlockArtifacts.exactMsmRedeemArtifactIds)
    || value.unlockArtifacts.exactMsmRedeemArtifactIds.length !== 3
    || !Array.isArray(value.unlockArtifacts.fixedCarrierPadArtifactIds)
    || value.unlockArtifacts.fixedCarrierPadArtifactIds.length !== 3
    || !Array.isArray(
      value.ceremonyArtifacts.transcriptVerificationArtifactIds,
    )
    || value.ceremonyArtifacts.transcriptVerificationArtifactIds.length !== 2
    || !Array.isArray(
      value.ceremonyArtifacts.reproducibilityHostArtifactIds,
    )
    || value.ceremonyArtifacts.reproducibilityHostArtifactIds.length !== 2
  ) {
    fail('PF10 final runtime artifact counts are invalid');
  }
  const artifactId = (candidate, label) => runtimeArtifactId(
    candidate,
    label,
    pins.artifactEntries,
  );
  const buildArtifacts = Object.freeze({
    circuitBuildAttestation: artifactId(
      value.buildArtifacts.circuitBuildAttestationArtifactId,
      'PF10 final circuit build attestation',
    ),
    circuitSymbols: artifactId(
      value.buildArtifacts.circuitSymbolsArtifactId,
      'PF10 final circuit symbols',
    ),
    initialProvingKey: artifactId(
      value.buildArtifacts.initialProvingKeyArtifactId,
      'PF10 final initial proving key',
    ),
    powersOfTau: artifactId(
      value.buildArtifacts.powersOfTauArtifactId,
      'PF10 final Powers of Tau',
    ),
    relationSourceManifest: artifactId(
      value.buildArtifacts.relationSourceManifestArtifactId,
      'PF10 final relation source manifest',
    ),
    snarkjsToolchain: artifactId(
      value.buildArtifacts.snarkjsToolchainArtifactId,
      'PF10 final SnarkJS toolchain manifest',
    ),
  });
  const proofArtifacts = Object.freeze({
    provingKey: artifactId(
      value.proofArtifacts.finalProvingKeyArtifactId,
      'PF10 final proving key',
    ),
    r1cs: artifactId(
      value.proofArtifacts.r1csArtifactId,
      'PF10 final R1CS',
    ),
    verificationKey: artifactId(
      value.proofArtifacts.verificationKeyArtifactId,
      'PF10 final verification key',
    ),
    wasm: artifactId(
      value.proofArtifacts.witnessWasmArtifactId,
      'PF10 final witness WASM',
    ),
  });
  const unlockArtifacts = Object.freeze({
    executorBody: artifactId(
      value.unlockArtifacts.executorBodyArtifactId,
      'PF10 final executor body',
    ),
    exactMsmRedeems: Object.freeze(
      value.unlockArtifacts.exactMsmRedeemArtifactIds.map(
        (candidate, index) => artifactId(
          candidate,
          `PF10 final exact-MSM redeem ${index}`,
        ),
      ),
    ),
    fixedCarrierPads: Object.freeze(
      value.unlockArtifacts.fixedCarrierPadArtifactIds.map(
        (candidate, index) => artifactId(
          candidate,
          `PF10 final fixed carrier pad ${index}`,
        ),
      ),
    ),
    fusedRedeem: artifactId(
      value.unlockArtifacts.fusedRedeemArtifactId,
      'PF10 final fused redeem',
    ),
    terminalRedeem: artifactId(
      value.unlockArtifacts.terminalRedeemArtifactId,
      'PF10 final terminal redeem',
    ),
  });
  const ceremonyArtifacts = Object.freeze({
    policy: artifactId(
      value.ceremonyArtifacts.evidencePolicyArtifactId,
      'PF10 final evidence policy',
    ),
    contributorRegistry: artifactId(
      value.ceremonyArtifacts.contributorRegistryArtifactId,
      'PF10 final contributor registry',
    ),
    transcript: artifactId(
      value.ceremonyArtifacts.transcriptArtifactId,
      'PF10 final ceremony transcript',
    ),
    beacon: artifactId(
      value.ceremonyArtifacts.beaconArtifactId,
      'PF10 final ceremony beacon',
    ),
    transcriptVerifications: Object.freeze(
      value.ceremonyArtifacts.transcriptVerificationArtifactIds.map(
        (candidate, index) => artifactId(
          candidate,
          `PF10 final transcript verification ${index}`,
        ),
      ),
    ),
    reproductions: Object.freeze(
      value.ceremonyArtifacts.reproducibilityHostArtifactIds.map(
        (candidate, index) => artifactId(
          candidate,
          `PF10 final reproducibility host ${index}`,
        ),
      ),
    ),
  });
  if (ceremonyArtifacts.policy !== V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID) {
    fail(
      `PF10 final runtime policy must use fixed artifact ID ${V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID}`,
    );
  }
  const allIds = [
    ...Object.values(buildArtifacts),
    ...Object.values(proofArtifacts),
    unlockArtifacts.executorBody,
    ...unlockArtifacts.exactMsmRedeems,
    ...unlockArtifacts.fixedCarrierPads,
    unlockArtifacts.fusedRedeem,
    unlockArtifacts.terminalRedeem,
    ceremonyArtifacts.policy,
    ceremonyArtifacts.contributorRegistry,
    ceremonyArtifacts.transcript,
    ceremonyArtifacts.beacon,
    ...ceremonyArtifacts.transcriptVerifications,
    ...ceremonyArtifacts.reproductions,
  ];
  if (new Set(allIds).size !== allIds.length) {
    fail('PF10 final runtime artifact references must be unique');
  }
  return Object.freeze({
    kind: 'final',
    eligibility: 'final-qualified',
    buildArtifacts,
    proofArtifacts,
    unlockArtifacts,
    ceremonyArtifacts,
  });
}

async function verifyPf10RuntimeProfileBindings({
  pins,
  readRuntimeBytes,
  runtime,
}) {
  if (
    runtime.profileArtifacts.profileCore
      !== PROFILE_CORE_MANIFEST_ARTIFACT_ID
    || pins.artifactEntries[runtime.profileArtifacts.profileCore].sha256
      !== pins.profileCoreSha256
  ) {
    fail('PF10 runtime profile core does not match the signed descriptor profile');
  }
  const packageBytes = await readRuntimeBytes(
    runtime.profileArtifacts.profilePackage,
    'PF10 development profile package',
  );
  let rawPackage;
  try {
    rawPackage = JSON.parse(packageBytes.toString('utf8'));
  } catch {
    fail('PF10 development profile package is not JSON');
  }
  if (!packageBytes.equals(Buffer.from(canonicalizeJcs(rawPackage), 'utf8'))) {
    fail('PF10 development profile package must use exact RFC8785/JCS bytes');
  }
  let profilePackage;
  try {
    profilePackage = inspectV2DevelopmentProfilePackage(rawPackage);
  } catch (error) {
    fail(
      `PF10 development profile package is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (
    profilePackage.profileId !== pins.profileId
    || profilePackage.profileCoreSha256 !== pins.profileCoreSha256
  ) {
    fail('PF10 development profile package identity differs from the descriptor');
  }

  const assertPackageArtifact = async (
    record,
    artifactId,
    label,
  ) => {
    const entry = pins.artifactEntries[artifactId];
    if (
      record === null
      || Array.isArray(record)
      || typeof record !== 'object'
      || record.sha256 !== entry.sha256
    ) {
      fail(`${label} differs from the signed runtime artifact`);
    }
    const filename = await regularFile(
      pins.root,
      entry.path,
      label,
    );
    const metadata = await lstat(filename, { bigint: true });
    if (
      !Number.isSafeInteger(record.bytes)
      || BigInt(record.bytes) !== metadata.size
    ) {
      fail(`${label} byte length differs from the profile package`);
    }
  };

  const generatedBindings = Object.freeze({
    baseVerifierManifest: runtime.profileArtifacts.baseVerifierManifest,
    circuitBuildAttestation:
      runtime.attestationArtifacts.circuitBuildAttestation,
    developmentSetupAttestation:
      runtime.attestationArtifacts.developmentSetupAttestation,
    profileCore: runtime.profileArtifacts.profileCore,
    relationManifest: runtime.attestationArtifacts.relationManifest,
    toolchainManifest: runtime.profileArtifacts.toolchainManifest,
    topologySpec: runtime.profileArtifacts.topologySpec,
  });
  for (const [name, artifactId] of Object.entries(generatedBindings)) {
    await assertPackageArtifact(
      profilePackage.generatedArtifacts[name],
      artifactId,
      `PF10 generated profile artifact ${name}`,
    );
  }
  const proofBindings = Object.freeze({
    circuitSymbols: runtime.setupArtifacts.circuitSymbols,
    initialProvingKey: runtime.setupArtifacts.initialProvingKey,
    powersOfTau: runtime.setupArtifacts.powersOfTau,
    provingKey: runtime.proofArtifacts.provingKey,
    r1cs: runtime.proofArtifacts.r1cs,
    verificationKey: runtime.proofArtifacts.verificationKey,
    witnessWasm: runtime.proofArtifacts.wasm,
  });
  for (const [name, artifactId] of Object.entries(proofBindings)) {
    await assertPackageArtifact(
      profilePackage.proofArtifacts[name],
      artifactId,
      `PF10 profile proof artifact ${name}`,
    );
  }

  const [
    buildBytes,
    setupBytes,
    relationBytes,
  ] = await Promise.all([
    readRuntimeBytes(
      runtime.attestationArtifacts.circuitBuildAttestation,
      'PF10 circuit build attestation',
    ),
    readRuntimeBytes(
      runtime.attestationArtifacts.developmentSetupAttestation,
      'PF10 development setup attestation',
    ),
    readRuntimeBytes(
      runtime.attestationArtifacts.relationManifest,
      'PF10 relation source manifest',
    ),
  ]);
  let build;
  let setup;
  try {
    build = parseCircuitBuildAttestation(buildBytes);
    setup = parseDevelopmentSetupAttestation(setupBytes);
    parseV2RelationSourceManifest(relationBytes);
  } catch (error) {
    fail(
      `PF10 copied build/setup provenance is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (
    build.sourceManifest.bytes !== relationBytes.length
    || build.sourceManifest.sha256 !== sha256(relationBytes)
    || setup.buildAttestation.bytes !== buildBytes.length
    || setup.buildAttestation.sha256 !== sha256(buildBytes)
    || setup.r1cs.bytes !== build.artifacts.r1cs.bytes
    || setup.r1cs.sha256 !== build.artifacts.r1cs.sha256
    || build.artifacts.r1cs.sha256
      !== profilePackage.proofArtifacts.r1cs.sha256
    || build.artifacts.sym.sha256
      !== profilePackage.proofArtifacts.circuitSymbols.sha256
    || build.artifacts.wasm.sha256
      !== profilePackage.proofArtifacts.witnessWasm.sha256
    || setup.ptau.artifact.sha256
      !== profilePackage.proofArtifacts.powersOfTau.sha256
    || setup.zkeyChain.initial.sha256
      !== profilePackage.proofArtifacts.initialProvingKey.sha256
    || setup.zkeyChain.contributions[0].output.sha256
      !== profilePackage.proofArtifacts.provingKey.sha256
    || setup.finalEvidence.verificationKey.sha256
      !== profilePackage.proofArtifacts.verificationKey.sha256
  ) {
    fail('PF10 copied profile, build, setup, and proof provenance do not agree');
  }
  return profilePackage;
}

async function verifyPf10FinalBuildBindings({
  pins,
  readRuntimeBytes,
  runtime,
}) {
  const [buildBytes, relationBytes, toolchainBytes] = await Promise.all([
    readRuntimeBytes(
      runtime.buildArtifacts.circuitBuildAttestation,
      'PF10 final circuit build attestation',
    ),
    readRuntimeBytes(
      runtime.buildArtifacts.relationSourceManifest,
      'PF10 final relation source manifest',
    ),
    readRuntimeBytes(
      runtime.buildArtifacts.snarkjsToolchain,
      'PF10 final SnarkJS toolchain manifest',
    ),
  ]);
  let build;
  let toolchain;
  try {
    build = parseCircuitBuildAttestation(buildBytes);
    parseV2RelationSourceManifest(relationBytes);
    const rawToolchain = JSON.parse(toolchainBytes.toString('utf8'));
    if (
      !toolchainBytes.equals(
        Buffer.from(canonicalizeJcs(rawToolchain), 'utf8'),
      )
    ) {
      fail(
        'PF10 final SnarkJS toolchain manifest must use exact RFC8785/JCS bytes',
      );
    }
    toolchain = parseV2FinalZkeyToolchainManifest(rawToolchain);
  } catch (error) {
    fail(
      `PF10 final circuit/toolchain provenance is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  const expected = {
    r1cs: runtime.proofArtifacts.r1cs,
    sym: runtime.buildArtifacts.circuitSymbols,
    wasm: runtime.proofArtifacts.wasm,
  };
  if (
    build.sourceManifest.bytes !== relationBytes.length
    || build.sourceManifest.sha256 !== sha256(relationBytes)
  ) {
    fail('PF10 final circuit build does not bind the relation source manifest');
  }
  for (const [name, artifactId] of Object.entries(expected)) {
    const entry = pins.artifactEntries[artifactId];
    const attested = build.artifacts[name];
    if (
      attested === undefined
      || attested.sha256 !== entry.sha256
    ) {
      fail(`PF10 final circuit build ${name} differs from the signed manifest`);
    }
    const filename = await regularFile(
      pins.root,
      entry.path,
      `PF10 final circuit build ${name}`,
    );
    const metadata = await lstat(filename, { bigint: true });
    if (BigInt(attested.bytes) !== metadata.size) {
      fail(`PF10 final circuit build ${name} byte length is invalid`);
    }
  }
  const profileSnarkjs = pins.profileToolchain.find(
    (entry) => entry.name === 'snarkjs',
  );
  const closureSnarkjs = toolchain.npmClosure.packages.find(
    (entry) => entry.packagePath === 'node_modules/snarkjs',
  );
  const closureLock = closureSnarkjs?.lock;
  if (
    profileSnarkjs === undefined
    || closureLock === undefined
    || profileSnarkjs.version !== toolchain.snarkjs.version
    || closureLock.version !== profileSnarkjs.version
    || sha256(Buffer.from(canonicalizeJcs({
      integrity: closureLock.integrity,
      resolved: closureLock.resolved,
      version: closureLock.version,
    }), 'utf8')) !== profileSnarkjs.sha256
  ) {
    fail(
      'PF10 final SnarkJS closure differs from the frozen profile toolchain',
    );
  }
  return Object.freeze({
    evidence: Object.freeze({
      buildAttestationSha256: sha256(buildBytes),
      relationSourceManifestSha256: sha256(relationBytes),
      snarkjsToolchainManifestSha256: sha256(toolchainBytes),
    }),
    toolchain,
  });
}

function nonnegativeFinite(value, label) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    fail(`${label} must be a nonnegative finite number`);
  }
  return value;
}

function qualificationFileEvidence(value, label) {
  exactKeys(value, label, ['bytes', 'path', 'sha256']);
  if (
    !Number.isSafeInteger(value.bytes)
    || value.bytes <= 0
    || typeof value.path !== 'string'
    || value.path.length === 0
  ) {
    fail(`${label} file evidence is invalid`);
  }
  return Object.freeze({
    bytes: value.bytes,
    path: value.path,
    sha256: hex32(value.sha256, `${label}.sha256`),
  });
}

function developmentQualificationEvidence(bytes, {
  instanceId,
  maximumLiveNotes,
  profileCoreSha256,
  profileId,
  proofArtifactHashes,
  denominationSats,
}) {
  let value;
  try {
    value = JSON.parse(Buffer.from(bytes).toString('utf8'));
    canonicalizeJcs(value);
  } catch (error) {
    fail(
      `PF10 qualification evidence is not valid JSON data: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  exactKeys(value, 'PF10 qualification evidence', [
    'actions',
    'claims',
    'evidenceClass',
    'fixture',
    'identity',
    'measurements',
    'prover',
    'schema',
    'sourceArtifacts',
    'versions',
  ]);
  if (
    value.schema !== DEVELOPMENT_QUALIFICATION_SCHEMA
    || value.evidenceClass !== DEVELOPMENT_QUALIFICATION_CLASS
    || value.fixture !== DEVELOPMENT_QUALIFICATION_FIXTURE
  ) {
    fail('PF10 qualification evidence schema, class, or fixture is invalid');
  }
  exactKeys(value.claims, 'PF10 qualification evidence claims', [
    'bchVm',
    'developmentKey',
    'finalKey',
    'production',
  ]);
  if (
    value.claims.developmentKey !== true
    || value.claims.finalKey !== false
    || value.claims.bchVm !== false
    || value.claims.production !== false
  ) {
    fail('PF10 development qualification evidence makes invalid claims');
  }
  exactKeys(value.identity, 'PF10 qualification evidence identity', [
    'denominationSats',
    'instanceId',
    'maximumLiveNotes',
    'profileId',
  ]);
  if (
    value.identity.profileId !== profileId
    || value.identity.instanceId !== instanceId
    || value.identity.maximumLiveNotes !== maximumLiveNotes
    || value.identity.denominationSats !== denominationSats
  ) {
    fail('PF10 qualification evidence identity or capacity is invalid');
  }
  exactKeys(value.sourceArtifacts, 'PF10 qualification sourceArtifacts', [
    'developmentZkey',
    'profileCore',
    'r1cs',
    'verificationKey',
    'wasm',
  ]);
  const sourceArtifacts = Object.freeze(Object.fromEntries(
    Object.entries(value.sourceArtifacts).map(([name, evidence]) => [
      name,
      qualificationFileEvidence(
        evidence,
        `PF10 qualification sourceArtifacts.${name}`,
      ),
    ]),
  ));
  const expectedSourceHashes = {
    developmentZkey: proofArtifactHashes.provingKey,
    profileCore: profileCoreSha256,
    r1cs: proofArtifactHashes.r1cs,
    verificationKey: proofArtifactHashes.verificationKey,
    wasm: proofArtifactHashes.wasm,
  };
  for (const [name, expected] of Object.entries(expectedSourceHashes)) {
    if (sourceArtifacts[name].sha256 !== expected) {
      fail(
        `PF10 qualification source artifact ${name} differs from the signed artifact set`,
      );
    }
  }

  exactKeys(value.actions, 'PF10 qualification actions', DEVELOPMENT_ACTION_NAMES);
  for (const name of DEVELOPMENT_ACTION_NAMES) {
    const action = value.actions[name];
    const label = `PF10 qualification actions.${name}`;
    exactKeys(action, label, [
      'files',
      'packetDigest',
      'proofVerified',
      'publicInputs',
      'timingsMs',
      'witnessValid',
    ]);
    if (action.witnessValid !== true || action.proofVerified !== true) {
      fail(`${label} is not witness-checked and proof-verified`);
    }
    const packetDigest = hex32(action.packetDigest, `${label}.packetDigest`);
    if (
      !Array.isArray(action.publicInputs)
      || action.publicInputs.length !== 2
      || action.publicInputs.some((entry) => (
        typeof entry !== 'string'
        || !UNSIGNED_DECIMAL.test(entry)
        || BigInt(entry) > MAX_U128
      ))
    ) {
      fail(`${label}.publicInputs does not match the unsigned u128x2 ABI`);
    }
    exactKeys(action.files, `${label}.files`, [
      'v2DirectGroth16Adapter',
      'input',
      'packet',
      'proof',
      'publicSignals',
      'witness',
    ]);
    const files = Object.fromEntries(
      Object.entries(action.files).map(([fileName, evidence]) => [
        fileName,
        qualificationFileEvidence(evidence, `${label}.files.${fileName}`),
      ]),
    );
    if (
      files.packet.bytes !== 552
      || files.packet.sha256 !== packetDigest
    ) {
      fail(`${label} packet evidence is invalid`);
    }
    exactKeys(action.timingsMs, `${label}.timingsMs`, [
      'proofGeneration',
      'proofVerification',
      'total',
      'witnessCalculation',
      'witnessCheck',
    ]);
    for (const [timing, measurement] of Object.entries(action.timingsMs)) {
      nonnegativeFinite(measurement, `${label}.timingsMs.${timing}`);
    }
  }

  exactKeys(value.versions, 'PF10 qualification versions', [
    'node',
    'snarkjs',
  ]);
  if (
    typeof value.versions.node !== 'string'
    || value.versions.node.length === 0
    || typeof value.versions.snarkjs !== 'string'
    || value.versions.snarkjs.length === 0
  ) {
    fail('PF10 qualification tool versions are invalid');
  }
  exactKeys(value.prover, 'PF10 qualification prover', [
    'backend',
    'mode',
    'provingSystem',
  ]);
  if (
    value.prover.backend !== 'snarkjs'
    || value.prover.provingSystem !== 'groth16'
    || !['default', 'single-thread'].includes(value.prover.mode)
  ) {
    fail('PF10 qualification prover identity is invalid');
  }
  exactKeys(value.measurements, 'PF10 qualification measurements', [
    'peakRss',
    'totalWallMs',
  ]);
  nonnegativeFinite(
    value.measurements.totalWallMs,
    'PF10 qualification measurements.totalWallMs',
  );
  const peakRss = value.measurements.peakRss;
  if (peakRss?.available === true) {
    exactKeys(peakRss, 'PF10 qualification measurements.peakRss', [
      'available',
      'bytes',
      'source',
    ]);
    if (
      !Number.isSafeInteger(peakRss.bytes)
      || peakRss.bytes <= 0
      || peakRss.source !== 'process.resourceUsage().maxRSS-kibibytes'
    ) {
      fail('PF10 qualification peak RSS evidence is invalid');
    }
  } else {
    exactKeys(peakRss, 'PF10 qualification measurements.peakRss', [
      'available',
      'reason',
    ]);
    if (peakRss.available !== false || typeof peakRss.reason !== 'string') {
      fail('PF10 qualification peak RSS unavailability is invalid');
    }
  }
  return Object.freeze(value);
}

function canonicalDevelopmentQualificationRecord(
  bytes,
  {
    rawEvidence,
    rawEvidenceSha256,
  },
) {
  let value;
  try {
    value = JSON.parse(Buffer.from(bytes).toString('utf8'));
    canonicalizeJcs(value);
  } catch (error) {
    fail(
      `PF10 canonical qualification record is not valid JSON data: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  const canonicalBytes = Buffer.from(canonicalizeJcs(value), 'utf8');
  if (!Buffer.from(bytes).equals(canonicalBytes)) {
    fail('PF10 canonical qualification record must use exact RFC8785/JCS bytes');
  }
  exactKeys(value, 'PF10 canonical qualification record', [
    'actions',
    'claims',
    'evidenceClass',
    'identity',
    'qualificationSchema',
    'rawEvidenceSha256',
    'schema',
    'sourceArtifacts',
  ]);
  exactKeys(value.identity, 'PF10 canonical qualification identity', [
    'denominationSats',
    'instanceId',
    'maximumLiveNotes',
    'profileId',
  ]);
  exactKeys(value.claims, 'PF10 canonical qualification claims', [
    'bchVm',
    'developmentKey',
    'finalKey',
    'production',
  ]);
  exactKeys(
    value.sourceArtifacts,
    'PF10 canonical qualification sourceArtifacts',
    [
      'developmentZkeySha256',
      'r1csSha256',
      'verificationKeySha256',
      'witnessWasmSha256',
    ],
  );
  exactKeys(
    value.actions,
    'PF10 canonical qualification actions',
    DEVELOPMENT_ACTION_NAMES,
  );
  for (const name of DEVELOPMENT_ACTION_NAMES) {
    exactKeys(
      value.actions[name],
      `PF10 canonical qualification actions.${name}`,
      ['proofVerified', 'witnessValid'],
    );
  }
  const expected = {
    schema: PF10_CANONICAL_QUALIFICATION_RECORD_SCHEMA,
    qualificationSchema: rawEvidence.schema,
    evidenceClass: rawEvidence.evidenceClass,
    identity: {
      profileId: rawEvidence.identity.profileId,
      instanceId: rawEvidence.identity.instanceId,
      maximumLiveNotes: rawEvidence.identity.maximumLiveNotes,
      denominationSats: rawEvidence.identity.denominationSats,
    },
    claims: {
      developmentKey: rawEvidence.claims.developmentKey,
      finalKey: rawEvidence.claims.finalKey,
      bchVm: rawEvidence.claims.bchVm,
      production: rawEvidence.claims.production,
    },
    sourceArtifacts: {
      r1csSha256: rawEvidence.sourceArtifacts.r1cs.sha256,
      witnessWasmSha256: rawEvidence.sourceArtifacts.wasm.sha256,
      verificationKeySha256:
        rawEvidence.sourceArtifacts.verificationKey.sha256,
      developmentZkeySha256:
        rawEvidence.sourceArtifacts.developmentZkey.sha256,
    },
    rawEvidenceSha256,
    actions: Object.fromEntries(DEVELOPMENT_ACTION_NAMES.map((name) => [
      name,
      {
        witnessValid: rawEvidence.actions[name].witnessValid,
        proofVerified: rawEvidence.actions[name].proofVerified,
      },
    ])),
  };
  if (canonicalizeJcs(value) !== canonicalizeJcs(expected)) {
    fail(
      'PF10 canonical qualification record differs from its signed raw v4 evidence',
    );
  }
  return Object.freeze(value);
}

/**
 * Validate the two development-only PF10 qualification artifacts before they
 * are signed into an instance descriptor. This is the unsigned bundle
 * counterpart of the exact validation performed while resolving a signed
 * descriptor: the raw v4 evidence is checked against the current identity and
 * proof pins, then the canonical record is byte- and field-bound to that exact
 * raw evidence.
 */
export function validateV2DevelopmentPf10QualificationArtifacts({
  canonicalRecordBytes,
  rawEvidenceBytes,
  instanceId,
  maximumLiveNotes,
  profileCoreSha256,
  profileId,
  proofArtifactHashes,
  denominationSats,
}) {
  const rawBytes = Buffer.from(rawEvidenceBytes);
  const canonicalBytes = Buffer.from(canonicalRecordBytes);
  const rawEvidence = developmentQualificationEvidence(rawBytes, {
    instanceId,
    maximumLiveNotes,
    profileCoreSha256,
    profileId,
    proofArtifactHashes,
    denominationSats,
  });
  const canonicalRecord = canonicalDevelopmentQualificationRecord(
    canonicalBytes,
    {
      rawEvidence,
      rawEvidenceSha256: sha256(rawBytes),
    },
  );
  return Object.freeze({
    canonicalRecord,
    canonicalRecordSha256: sha256(canonicalBytes),
    rawEvidence,
    rawEvidenceSha256: sha256(rawBytes),
  });
}

/**
 * Resolve the exact PF10 proof and unlock material from the signed manifest.
 * The fixed metadata artifact ID prevents caller-selected artifact rebinding.
 *
 * Current V2 profile semantics can establish development-only material. A
 * final-qualified resolver remains fail-closed until the final profile schema
 * pins the proving key and a separately validated qualification record.
 */
async function derivePf10RuntimeFromValidatedPins({
  brandResolution,
  identity,
  pins,
}) {
  if (
    pins.topologyId !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
    || pins.verifierRoles.length
      !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length
    || pins.verifierRoles.some(
      (role, index) =>
        role !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES[index],
    )
  ) {
    fail('PF10 runtime material requires the signed PF10 topology');
  }
  const runtimeEntry =
    pins.artifactEntries[PF10_RUNTIME_MANIFEST_ARTIFACT_ID];
  if (runtimeEntry === undefined) {
    fail(
      `signed manifest is missing ${PF10_RUNTIME_MANIFEST_ARTIFACT_ID}`,
    );
  }
  const runtimeFile = await readPinnedFile(
    pins.root,
    runtimeEntry.path,
    runtimeEntry.sha256,
    'PF10 runtime material artifact',
  );
  let rawRuntime;
  try {
    rawRuntime = JSON.parse(runtimeFile.data.toString('utf8'));
  } catch {
    fail('PF10 runtime material artifact is not JSON');
  }
  const canonicalRuntime = Buffer.from(
    canonicalizeJcs(rawRuntime),
    'utf8',
  );
  if (!runtimeFile.data.equals(canonicalRuntime)) {
    fail('PF10 runtime material artifact must use exact RFC8785/JCS bytes');
  }
  const runtimePins = {
    ...pins,
    profileId: identity.profileId,
    instanceId: identity.instanceId,
  };
  const runtime = rawRuntime.schema === PF10_RUNTIME_ARTIFACT_SCHEMA
    ? parsePf10RuntimeArtifact(rawRuntime, runtimePins)
    : rawRuntime.schema === PF10_FINAL_RUNTIME_ARTIFACT_SCHEMA
      ? parsePf10FinalRuntimeArtifact(rawRuntime, runtimePins)
      : fail('PF10 runtime material artifact schema is unsupported');
  const proofHashPins = {
    r1cs: pins.profileProof.r1csSha256,
    verificationKey: pins.profileProof.verificationKeySha256,
    wasm: pins.profileProof.witnessWasmSha256,
  };
  for (const [name, expectedHash] of Object.entries(proofHashPins)) {
    const artifactId = runtime.proofArtifacts[name];
    if (pins.artifactEntries[artifactId].sha256 !== expectedHash) {
      fail(
        `PF10 ${name} manifest hash differs from the signed profile core`,
      );
    }
  }
  const proofArtifacts = {};
  for (const [name, artifactId] of Object.entries(
    runtime.proofArtifacts,
  )) {
    const entry = pins.artifactEntries[artifactId];
    proofArtifacts[name] = Object.freeze({
      path: await regularFile(
        pins.root,
        entry.path,
        `PF10 proof artifact ${name}`,
      ),
      sha256: entry.sha256,
    });
  }
  const readRuntimeBytes = async (artifactId, label) => {
    const entry = pins.artifactEntries[artifactId];
    return (await readPinnedFile(
      pins.root,
      entry.path,
      entry.sha256,
      label,
    )).data;
  };
  let developmentEvidence;
  let finalBuildEvidence;
  let finalZkeyToolchain;
  if (runtime.kind === 'development') {
    await verifyPf10RuntimeProfileBindings({
      pins,
      readRuntimeBytes,
      runtime,
    });
    const qualificationRecord = await readRuntimeBytes(
      runtime.qualificationEvidenceArtifactId,
      'PF10 canonical qualification record',
    );
    const rawQualificationEvidence = await readRuntimeBytes(
      runtime.rawQualificationEvidenceArtifactId,
      'PF10 raw qualification evidence',
    );
    const parsedRawQualification = developmentQualificationEvidence(
      rawQualificationEvidence,
      {
        profileId: pins.profileId,
        instanceId: pins.instanceId,
        maximumLiveNotes: pins.maximumLiveNotes,
        denominationSats: pins.denominationSats,
        profileCoreSha256: pins.profileCoreSha256,
        proofArtifactHashes: Object.fromEntries(
          Object.entries(proofArtifacts).map(([name, artifact]) => [
            name,
            artifact.sha256,
          ]),
        ),
      },
    );
    canonicalDevelopmentQualificationRecord(qualificationRecord, {
      rawEvidence: parsedRawQualification,
      rawEvidenceSha256:
        pins.artifactEntries[
          runtime.rawQualificationEvidenceArtifactId
        ].sha256,
    });
    developmentEvidence = Object.freeze({
      qualificationEvidenceSha256:
        pins.artifactEntries[
          runtime.qualificationEvidenceArtifactId
        ].sha256,
      rawQualificationEvidenceSha256:
        pins.artifactEntries[
          runtime.rawQualificationEvidenceArtifactId
        ].sha256,
      libauthEvidenceSha256:
        pins.artifactEntries[runtime.libauthEvidenceArtifactId].sha256,
    });
  } else {
    const verifiedFinalBuild = await verifyPf10FinalBuildBindings({
      pins,
      readRuntimeBytes,
      runtime,
    });
    finalBuildEvidence = Object.freeze({
      ...verifiedFinalBuild.evidence,
      relationSourceManifestArtifactId:
        runtime.buildArtifacts.relationSourceManifest,
    });
    finalZkeyToolchain = verifiedFinalBuild.toolchain;
  }
  const runtimeMaterial = validateDirectV2Pf10RuntimeMaterial({
    schema: DIRECT_V2_PF10_RUNTIME_SCHEMA,
    eligibility: runtime.eligibility,
    profileId: identity.profileId,
    instanceId: identity.instanceId,
    topologyId: pins.topologyId,
    verifierRoles: pins.verifierRoles,
    proofArtifactHashes: Object.fromEntries(
      Object.entries(proofArtifacts).map(([name, artifact]) => [
        name,
        artifact.sha256,
      ]),
    ),
    verificationKeyBytes: await readRuntimeBytes(
      runtime.proofArtifacts.verificationKey,
      'PF10 verification key',
    ),
    executorBody: await readRuntimeBytes(
      runtime.unlockArtifacts.executorBody,
      'PF10 executor body',
    ),
    exactMsmRedeems: await Promise.all(
      runtime.unlockArtifacts.exactMsmRedeems.map(
        (artifactId, index) => readRuntimeBytes(
          artifactId,
          `PF10 exact-MSM redeem ${index}`,
        ),
      ),
    ),
    fixedCarrierPads: await Promise.all(
      runtime.unlockArtifacts.fixedCarrierPads.map(
        (artifactId, index) => readRuntimeBytes(
          artifactId,
          `PF10 fixed carrier pad ${index}`,
        ),
      ),
    ),
    fusedRedeem: await readRuntimeBytes(
      runtime.unlockArtifacts.fusedRedeem,
      'PF10 fused redeem',
    ),
    terminalRedeem: await readRuntimeBytes(
      runtime.unlockArtifacts.terminalRedeem,
      'PF10 terminal redeem',
    ),
    stateUnlockingBytecode: await readRuntimeBytes(
      pins.stateHelperUnlockArtifactId,
      'PF10 state helper unlock',
    ),
    bindingRedeemBytecode: Buffer.from(
      pins.bindingRedeemBytecodeHex,
      'hex',
    ),
    bindingLockingBytecode: Buffer.from(
      pins.bindingLockingBytecodeHex,
      'hex',
    ),
    verifierLockingBytecodes: pins.verifierCarriers.map(
      (entry) => Buffer.from(entry.lockingBytecodeHex, 'hex'),
    ),
  });
  let finalEvidence;
  let finalZkeyEvidence;
  if (runtime.kind === 'development') {
    const libauthEvidence = await readRuntimeBytes(
      runtime.libauthEvidenceArtifactId,
      'PF10 per-instance Libauth evidence',
    );
    try {
      validateDirectV2Pf10LibauthEvidence({
        bytes: libauthEvidence,
        profileId: identity.profileId,
        instanceId: identity.instanceId,
        proofArtifactHashes: Object.fromEntries(
          Object.entries(proofArtifacts).map(([name, artifact]) => [
            name,
            artifact.sha256,
          ]),
        ),
        runtimeMaterialSha256: runtimeMaterial.materialSha256,
      });
    } catch (error) {
      fail(
        `PF10 per-instance Libauth evidence is invalid: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  } else {
    try {
      finalEvidence = await verifyV2FinalRuntimeEvidence({
        artifactEntries: pins.artifactEntries,
        finalLocksSha256: pins.finalLocksSha256,
        instanceId: identity.instanceId,
        profileBaseArtifacts: pins.profileBaseArtifacts,
        profileId: identity.profileId,
        profileProof: pins.profileProof,
        profileToolchainSha256: pins.profileToolchainSha256,
        readArtifactBytes: readRuntimeBytes,
        runtimeMaterialSha256: runtimeMaterial.materialSha256,
        runtimeReferences: Object.freeze({
          policy: runtime.ceremonyArtifacts.policy,
          contributorRegistry:
            runtime.ceremonyArtifacts.contributorRegistry,
          transcript: runtime.ceremonyArtifacts.transcript,
          beacon: runtime.ceremonyArtifacts.beacon,
          transcriptVerifications:
            runtime.ceremonyArtifacts.transcriptVerifications,
          reproductions: runtime.ceremonyArtifacts.reproductions,
          relationSourceManifest:
            runtime.buildArtifacts.relationSourceManifest,
          circuitBuildAttestation:
            runtime.buildArtifacts.circuitBuildAttestation,
          snarkjsToolchain: runtime.buildArtifacts.snarkjsToolchain,
          circuitSymbols: runtime.buildArtifacts.circuitSymbols,
          powersOfTau: runtime.buildArtifacts.powersOfTau,
          initialZkey: runtime.buildArtifacts.initialProvingKey,
          finalZkey: runtime.proofArtifacts.provingKey,
          r1cs: runtime.proofArtifacts.r1cs,
          witnessWasm: runtime.proofArtifacts.wasm,
          verificationKey: runtime.proofArtifacts.verificationKey,
        }),
      });
    } catch (error) {
      fail(
        `PF10 final ceremony/reproduction evidence is invalid: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
    try {
      const powersOfTauEntry =
        pins.artifactEntries[runtime.buildArtifacts.powersOfTau];
      const powersOfTauPath = await regularFile(
        pins.root,
        powersOfTauEntry.path,
        'PF10 final Powers of Tau',
      );
      const cryptographic = await verifyV2FinalZkeyCryptographically({
        schema: V2_FINAL_ZKEY_VERIFICATION_SCHEMA,
        toolchain: finalZkeyToolchain,
        r1cs: {
          path: proofArtifacts.r1cs.path,
          sha256: `sha256:${proofArtifacts.r1cs.sha256}`,
        },
        ptau: {
          path: powersOfTauPath,
          sha256: `sha256:${powersOfTauEntry.sha256}`,
        },
        finalZkey: {
          path: proofArtifacts.provingKey.path,
          sha256: `sha256:${proofArtifacts.provingKey.sha256}`,
        },
        verificationKey: {
          path: proofArtifacts.verificationKey.path,
          sha256: `sha256:${proofArtifacts.verificationKey.sha256}`,
        },
      });
      finalZkeyEvidence = Object.freeze({
        schema: cryptographic.schema,
        finalZkeySha256: proofArtifacts.provingKey.sha256,
        powersOfTauSha256: powersOfTauEntry.sha256,
        r1csSha256: proofArtifacts.r1cs.sha256,
        snarkjsToolchainManifestSha256:
          pins.artifactEntries[
            runtime.buildArtifacts.snarkjsToolchain
          ].sha256,
        verificationKeySha256: proofArtifacts.verificationKey.sha256,
      });
    } catch (error) {
      fail(
        `PF10 final proving key failed local cryptographic verification: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }
  const claims = Object.freeze(runtime.kind === 'final'
    ? {
        ceremonyQualified: true,
        developmentKey: false,
        finalKey: true,
        production: false,
        releaseQualified: false,
      }
    : {
        ceremonyQualified: false,
        developmentKey: true,
        finalKey: false,
        production: false,
        releaseQualified: false,
      });
  const resolution = Object.freeze({
    schema: 'shieldkit-v2-direct-pf10-runtime-resolution-v1',
    eligibility: runtime.eligibility,
    claims,
    runtimeMaterial,
    proofArtifacts: Object.freeze(proofArtifacts),
    descriptorSha256: identity.descriptor.sha256,
    manifestSha256: identity.manifest.sha256,
    runtimeArtifactSha256: runtimeEntry.sha256,
    qualificationEvidenceSha256: runtime.kind === 'final'
      ? finalEvidence.transcriptSha256
      : developmentEvidence.qualificationEvidenceSha256,
    ...(runtime.kind === 'development' ? {
      rawQualificationEvidenceSha256:
        developmentEvidence.rawQualificationEvidenceSha256,
      libauthEvidenceSha256:
        developmentEvidence.libauthEvidenceSha256,
    } : {}),
    developmentEvidence,
    finalBuildEvidence,
    finalEvidence,
    finalZkeyEvidence,
  });
  if (brandResolution) {
    validatedPf10RuntimeResolutions.set(
      resolution,
      runtimeMaterial.materialSha256,
    );
  }
  return resolution;
}

export async function deriveV2Pf10RuntimeFromValidatedDescriptor(value) {
  const pins = validatedDescriptorPins.get(value);
  if (pins === undefined) {
    fail(
      'PF10 runtime material requires a descriptor validated by loadV2InstanceDescriptor',
    );
  }
  return derivePf10RuntimeFromValidatedPins({
    brandResolution: true,
    identity: value,
    pins,
  });
}

/**
 * Validate an unsigned, staged package using the full descriptor/runtime
 * parser without creating a signed-descriptor or action-runtime capability.
 * Only the derived semantic digest and eligibility leave this boundary.
 */
export async function deriveV2PreparedPackageRuntimeMaterialSha256(value) {
  exactKeys(value, 'prepared package runtime validation options', [
    'profileCore',
    'unsignedDescriptorPath',
  ]);
  const { loaded, pins } = await loadV2InstanceDescriptorInternal({
    allowUnsigned: true,
    descriptorPath: value.unsignedDescriptorPath,
    profileCore: value.profileCore,
    trustedSigners: undefined,
  });
  if (loaded.attestation !== null) {
    fail('prepared package runtime validation requires signature: null');
  }
  const resolution = await derivePf10RuntimeFromValidatedPins({
    brandResolution: false,
    identity: loaded,
    pins,
  });
  if (
    resolution.eligibility !== 'development-only'
    || resolution.claims.developmentKey !== true
    || resolution.claims.finalKey !== false
  ) {
    fail(
      'unsigned staged package validation cannot establish a final-qualified runtime',
    );
  }
  return Object.freeze({
    schema:
      'shieldkit-v2-prepared-package-runtime-material-validation-v1',
    eligibility: resolution.eligibility,
    runtimeMaterialSha256: resolution.runtimeMaterial.materialSha256,
  });
}

/**
 * Bridge one module-private validated runtime resolution to the exact binary
 * digest required by the durable store. A lookalike or cloned resolution is
 * rejected rather than being accepted on caller-supplied fields.
 */
export function deriveV2Pf10StoreRuntimeMaterialsSha256(value) {
  const digest = validatedPf10RuntimeResolutions.get(value);
  if (digest === undefined) {
    fail(
      'PF10 store binding requires a runtime resolution returned by deriveV2Pf10RuntimeFromValidatedDescriptor',
    );
  }
  return Buffer.from(digest, 'hex');
}

async function syncDirectory(directory) {
  const handle = await open(directory, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

/**
 * Atomically create a new local secret file, refusing overwrite and using
 * 0600. `writeTemporaryFile` is a narrow failure-injection seam for tests; the
 * final path is never opened for writing.
 */
export async function createV2SecretFile(
  filename,
  data,
  options = undefined,
) {
  if (typeof filename !== 'string' || !path.isAbsolute(filename) || !(data instanceof Uint8Array)) fail('secret filename must be absolute and data must be bytes');
  let writeTemporaryFile = async (handle, bytes) => handle.writeFile(bytes);
  if (options !== undefined) {
    exactKeys(
      options,
      'secret file test options',
      ['writeTemporaryFile'],
    );
    if (typeof options.writeTemporaryFile !== 'function') {
      fail('secret file test writeTemporaryFile must be a function');
    }
    writeTemporaryFile = options.writeTemporaryFile;
  }
  const parent = path.dirname(filename);
  const parentStat = await lstat(parent).catch(() => undefined);
  if (parentStat === undefined || parentStat.isSymbolicLink() || !parentStat.isDirectory()) fail('secret parent must be an existing non-symlink directory');
  const secretBytes = Buffer.from(data);
  let handle;
  let temporary;
  let published = false;
  try {
    for (let attempt = 0; attempt < 16; attempt += 1) {
      temporary = path.join(
        parent,
        `.shieldkit-secret-${randomBytes(16).toString('hex')}.tmp`,
      );
      try {
        handle = await open(temporary, 'wx', 0o600);
        break;
      } catch (error) {
        if (error?.code !== 'EEXIST') throw error;
      }
    }
    if (handle === undefined) {
      fail('secret file creation could not allocate a temporary file');
    }
    await writeTemporaryFile(handle, secretBytes);
    await handle.chmod(0o600);
    const temporaryStat = await handle.stat();
    if (!temporaryStat.isFile() || temporaryStat.size !== secretBytes.length) {
      fail('secret temporary file was not written completely');
    }
    await handle.sync();
    const closing = handle;
    handle = undefined;
    await closing.close();
    try {
      await link(temporary, filename);
    } catch (error) {
      if (error?.code === 'EEXIST') {
        fail('secret file already exists');
      }
      throw error;
    }
    published = true;
    await unlink(temporary);
    temporary = undefined;
    const finalStat = await lstat(filename);
    if (
      finalStat.isSymbolicLink()
      || !finalStat.isFile()
      || (finalStat.mode & 0o777) !== 0o600
      || finalStat.size !== secretBytes.length
    ) {
      fail('published secret file metadata is invalid');
    }
    await syncDirectory(parent);
  } catch (error) {
    if (handle !== undefined) {
      await handle.close().catch(() => undefined);
    }
    if (published) {
      await unlink(filename).catch(() => undefined);
    }
    if (temporary !== undefined) {
      await unlink(temporary).catch(() => undefined);
    }
    if (published) {
      await syncDirectory(parent).catch(() => undefined);
    }
    if (error instanceof InstanceDescriptorError) throw error;
    fail('secret file creation failed');
  }
}
