/**
 * Beta-only operational PF10 runtime capability.
 *
 * This deliberately does not load an instance descriptor and is not accepted
 * by the normal development/final descriptor resolver. It turns one exact,
 * independently rebuilt beta runtime directory into an opaque local
 * capability for a separately branded beta Chipnet bootstrap path.
 */
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';

import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
} from '../../action/v2/topology.mjs';
import {
  canonicalizeJcs,
  deriveProfileId,
  validateProfileCore,
} from './profile-core.mjs';
import {
  validateV2BetaLocalProfilePackage,
  V2_BETA_LOCAL_ELIGIBILITY,
  V2_BETA_LOCAL_FALSE_CLAIMS,
} from './beta-local-profile.mjs';
import {
  DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA,
} from '../../unlock-builder/v2/pf10-action-witness.mjs';
import {
  buildDirectV2Pf10BetaRuntime,
} from '../../unlock-builder/v2/pf10-development-runtime-builder.mjs';
import {
  V2_PF10_BETA_RUNTIME_BUNDLE_SCHEMA,
  V2_PF10_BETA_RUNTIME_MANIFEST,
  verifyV2Pf10BetaRuntime,
} from '../../../scripts/v2-pf10-beta-runtime.mjs';
import {
  V2BetaChipnetRuntimeCacheError,
  installV2BetaLinkedRuntimeCache as installLinkedCache,
  loadV2BetaLinkedRuntimeCache as loadLinkedCache,
  installV2BetaChipnetRuntimeCache as installCache,
  loadV2BetaChipnetRuntimeCache as loadCache,
} from './beta-chipnet-runtime-cache.mjs';
import {
  assertV2Pf10SpecializedRuntimeCapability,
} from '../../unlock-builder/v2/pf10-instance-specializer.mjs';
import {
  deriveV2BetaProductLinkedRuntimeTemplate,
} from './beta-product-artifact-installation.mjs';
import { recordV2BetaRuntimeWork } from './beta-runtime-work-observer.mjs';

export const V2_BETA_CHIPNET_RUNTIME_RESOLUTION_SCHEMA =
  'shieldkit-v2-direct-pf10-beta-chipnet-runtime-resolution-v1';

const HASH = /^[0-9a-f]{64}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
const MAXIMUM_LIVE_NOTES = 210_000_000n;
const resolutions = new WeakMap();
const linkedProofArtifacts = new WeakSet();
const linkedResolutionProofArtifacts = new WeakMap();

export class V2BetaChipnetRuntimeError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options);
    this.name = 'V2BetaChipnetRuntimeError';
    this.code = code;
  }
}

const fail = (code, message, options) => {
  throw new V2BetaChipnetRuntimeError(code, message, options);
};

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function exact(value, keys, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) fail('BETA_CHIPNET_RUNTIME_INVALID', `${label} must be a plain object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) fail('BETA_CHIPNET_RUNTIME_INVALID', `${label} has missing or unknown properties`);
  return value;
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail('BETA_CHIPNET_RUNTIME_INVALID', `${label} must be 32 lowercase hexadecimal bytes`);
  }
  return value;
}

function capacity(value, label) {
  if (
    typeof value !== 'string'
    || !DECIMAL.test(value)
    || BigInt(value) === 0n
    || BigInt(value) > MAXIMUM_LIVE_NOTES
  ) fail('BETA_CHIPNET_RUNTIME_INVALID', `${label} must be canonical decimal in [1, 210000000]`);
  return value;
}

function exactClaims(value, label) {
  if (canonicalizeJcs(value) !== canonicalizeJcs(V2_BETA_LOCAL_FALSE_CLAIMS)) {
    fail('BETA_CHIPNET_RUNTIME_INVALID', `${label} differs from the immutable beta claim boundary`);
  }
  return value;
}

async function readCanonicalPrivateJson(filename, label) {
  const resolved = path.resolve(filename);
  let before;
  try {
    before = await lstat(resolved);
  } catch (error) {
    fail('BETA_CHIPNET_RUNTIME_UNAVAILABLE', `${label} is unavailable`, { cause: error });
  }
  if (
    !before.isFile()
    || before.isSymbolicLink()
    || before.nlink !== 1
    || (before.mode & 0o077) !== 0
    || await realpath(resolved) !== resolved
  ) fail('BETA_CHIPNET_RUNTIME_UNSAFE_PATH', `${label} must be a private canonical single-link file`);
  let handle;
  try {
    handle = await open(resolved, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const opened = await handle.stat();
    const bytes = await handle.readFile();
    const after = await handle.stat();
    const pathAfter = await lstat(resolved);
    if (
      opened.dev !== before.dev || opened.ino !== before.ino
      || after.dev !== before.dev || after.ino !== before.ino
      || pathAfter.dev !== before.dev || pathAfter.ino !== before.ino
      || opened.size !== before.size || after.size !== before.size
      || pathAfter.size !== before.size || pathAfter.isSymbolicLink()
    ) fail('BETA_CHIPNET_RUNTIME_UNSAFE_PATH', `${label} changed while it was read`);
    let value;
    try {
      value = JSON.parse(bytes.toString('utf8'));
    } catch (error) {
      fail('BETA_CHIPNET_RUNTIME_INVALID', `${label} is not JSON`, { cause: error });
    }
    if (!bytes.equals(Buffer.from(canonicalizeJcs(value), 'utf8'))) {
      fail('BETA_CHIPNET_RUNTIME_INVALID', `${label} must use exact RFC8785/JCS bytes`);
    }
    return Object.freeze({ bytes: Buffer.from(bytes), filename: resolved, sha256: sha256(bytes), value });
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function readPrivateArtifact(root, reference, label) {
  exact(reference, ['bytes', 'id', 'path', 'sha256'], label);
  if (
    !Number.isSafeInteger(reference.bytes)
    || reference.bytes <= 0
    || typeof reference.id !== 'string'
    || typeof reference.path !== 'string'
    || reference.path.length === 0
    || path.isAbsolute(reference.path)
    || reference.path.includes('\\')
    || reference.path.split('/').some((part) => part === '' || part === '.' || part === '..')
  ) fail('BETA_CHIPNET_RUNTIME_INVALID', `${label} reference is malformed`);
  hash(reference.sha256, `${label}.sha256`);
  const filename = path.resolve(root, reference.path);
  const relative = path.relative(root, filename);
  if (relative === '' || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    fail('BETA_CHIPNET_RUNTIME_UNSAFE_PATH', `${label} escapes the runtime directory`);
  }
  let metadata;
  try {
    metadata = await lstat(filename);
  } catch (error) {
    fail('BETA_CHIPNET_RUNTIME_UNAVAILABLE', `${label} is unavailable`, { cause: error });
  }
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || metadata.nlink !== 1
    || (metadata.mode & 0o077) !== 0
    || await realpath(filename) !== filename
  ) fail('BETA_CHIPNET_RUNTIME_UNSAFE_PATH', `${label} must be a private canonical single-link file`);
  let handle;
  try {
    handle = await open(filename, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const before = await handle.stat();
    const bytes = await handle.readFile();
    const after = await handle.stat();
    const pathAfter = await lstat(filename);
    if (
      before.dev !== metadata.dev || before.ino !== metadata.ino
      || after.dev !== metadata.dev || after.ino !== metadata.ino
      || pathAfter.dev !== metadata.dev || pathAfter.ino !== metadata.ino
      || before.size !== metadata.size || after.size !== metadata.size
      || pathAfter.size !== metadata.size || pathAfter.isSymbolicLink()
      || bytes.length !== reference.bytes || sha256(bytes) !== reference.sha256
    ) fail('BETA_CHIPNET_RUNTIME_INVALID', `${label} differs from its manifest reference`);
    return Object.freeze({
      bytes: Buffer.from(bytes),
      filename,
      sha256: reference.sha256,
    });
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function proofArtifactReferences(manifest) {
  exact(manifest.proofArtifacts, ['provingKey', 'r1cs', 'verificationKey', 'wasm'], 'beta runtime proofArtifacts');
  return manifest.proofArtifacts;
}

function validateManifestBoundary(manifest) {
  exact(manifest, [
    'artifacts', 'assuranceClass', 'claims', 'eligibility', 'identity',
    'profile', 'proofArtifacts', 'proofQualification', 'runtime', 'schema',
    'status',
  ], 'beta Chipnet runtime manifest');
  if (
    manifest.schema !== V2_PF10_BETA_RUNTIME_BUNDLE_SCHEMA
    || manifest.status !== 'beta-local-runtime-built-unqualified'
    || manifest.eligibility !== V2_BETA_LOCAL_ELIGIBILITY
    || manifest.assuranceClass !== 'beta-single-contributor'
  ) fail('BETA_CHIPNET_RUNTIME_INVALID', 'runtime manifest is not the exact beta-only runtime format');
  exactClaims(manifest.claims, 'runtime manifest claims');
  exact(manifest.identity, ['denominationSats', 'instanceId', 'maximumLiveNotes'], 'runtime manifest identity');
  if (
    manifest.identity.denominationSats !== '10000000'
    || hash(manifest.identity.instanceId, 'runtime manifest instanceId') === undefined
  ) fail('BETA_CHIPNET_RUNTIME_INVALID', 'runtime manifest identity is invalid');
  capacity(manifest.identity.maximumLiveNotes, 'runtime manifest maximumLiveNotes');
  exact(manifest.profile, ['betaProfilePackage', 'ceremonyResultSha256', 'profileCore', 'profileId'], 'runtime manifest profile');
  hash(manifest.profile.profileId, 'runtime manifest profileId');
  if (typeof manifest.profile.ceremonyResultSha256 !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(manifest.profile.ceremonyResultSha256)) {
    fail('BETA_CHIPNET_RUNTIME_INVALID', 'runtime manifest ceremony binding is invalid');
  }
  exact(manifest.runtime, [
    'artifacts', 'baseValues', 'fixedTables', 'layout', 'material',
    'materialSha256', 'programs', 'reproducibility', 'structural',
    'topologyId', 'verifierRoles',
  ], 'beta runtime material');
  if (
    manifest.runtime.topologyId !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
    || !Array.isArray(manifest.runtime.verifierRoles)
    || manifest.runtime.verifierRoles.length !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length
    || manifest.runtime.verifierRoles.some((role, index) => role !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES[index])
  ) fail('BETA_CHIPNET_RUNTIME_INVALID', 'runtime manifest topology is not exact PF10-FusedQGenesis');
  hash(manifest.runtime.materialSha256, 'runtime manifest materialSha256');
  return manifest;
}

function copySettlementPins(pins) {
  return Object.freeze({
    topologyId: pins.topologyId,
    verifierRoles: Object.freeze([...pins.verifierRoles]),
    verifierCarriers: Object.freeze(pins.verifierCarriers.map((entry) => Object.freeze({
      baseValueSats: entry.baseValueSats,
      lockingBytecode: Buffer.from(entry.lockingBytecode),
    }))),
    bindingBaseSats: pins.bindingBaseSats,
    bindingLockingBytecode: Buffer.from(pins.bindingLockingBytecode),
    bindingRedeemBytecode: Buffer.from(pins.bindingRedeemBytecode),
    stateBaseSats: pins.stateBaseSats,
    stateHelperBytecode: Buffer.from(pins.stateHelperBytecode),
    stateLockingBytecode: Buffer.from(pins.stateLockingBytecode),
    stateUnlockingBytecode: Buffer.from(pins.stateUnlockingBytecode),
  });
}

function settlementPinsFromBuild(build) {
  if (
    build.topologyId !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
    || build.runtimeMaterial.schema !== DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA
    || build.eligibility !== V2_BETA_LOCAL_ELIGIBILITY
    || build.verifierRoles.length !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length
    || build.verifierRoles.some((role, index) => role !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES[index])
  ) fail('BETA_CHIPNET_RUNTIME_INVALID', 'rebuilt material is not the exact beta PF10 topology');
  return Object.freeze({
    topologyId: build.topologyId,
    verifierRoles: Object.freeze([...build.verifierRoles]),
    verifierCarriers: Object.freeze(build.structural.verifierLocks.map((lockingBytecode, index) => Object.freeze({
      baseValueSats: build.baseValues.verifierSats[index],
      lockingBytecode: Buffer.from(lockingBytecode),
    }))),
    bindingBaseSats: build.baseValues.bindingSats,
    bindingLockingBytecode: Buffer.from(build.structural.bindingLock),
    bindingRedeemBytecode: Buffer.from(build.structural.bindingRedeem),
    stateBaseSats: build.baseValues.stateSats,
    stateHelperBytecode: Buffer.from(build.structural.stateHelper),
    stateLockingBytecode: Buffer.from(build.structural.stateLock),
    stateUnlockingBytecode: Buffer.from(build.structural.stateUnlock),
  });
}

function resolutionFromPins(pins, binding = undefined) {
  const resolution = Object.freeze({
    schema: V2_BETA_CHIPNET_RUNTIME_RESOLUTION_SCHEMA,
    eligibility: V2_BETA_LOCAL_ELIGIBILITY,
    claims: V2_BETA_LOCAL_FALSE_CLAIMS,
    identity: Object.freeze({ ...pins.identity }),
    runtimeManifestSha256: pins.runtimeManifestSha256,
    proofArtifacts: Object.freeze(Object.fromEntries(Object.entries(pins.proofArtifacts).map(([name, entry]) => [name, Object.freeze({ ...entry })]))),
    // Preserve the validator-issued, frozen WeakMap capability. Serializing or
    // cloning this object erases the beta witness builder's validation brand.
    runtimeMaterial: pins.runtimeMaterial,
    runtimeMaterialSha256: pins.runtimeMaterialSha256,
    settlementPins: copySettlementPins(pins.settlementPins),
    ...(binding === undefined ? {} : {
      descriptorSha256: binding.descriptorSha256,
      manifestSha256: binding.manifestSha256,
    }),
  });
  resolutions.set(resolution, Object.freeze({ ...pins, binding }));
  return resolution;
}

function freezeJson(value) {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) freezeJson(child);
    Object.freeze(value);
  }
  return value;
}

function copyProfileCore(value) {
  const copy = JSON.parse(canonicalizeJcs(value));
  validateProfileCore(copy);
  return freezeJson(copy);
}

/**
 * Load and independently rebuild one exact private beta PF10 runtime.
 * This operation has no descriptor, signing, chain, or broadcast capability.
 */
export async function loadV2BetaChipnetRuntime(value = {}) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).some((key) => !['allowedOutputRoot', 'runtimeDirectory', 'temporaryRoot'].includes(key))
    || !Object.hasOwn(value, 'runtimeDirectory') || !Object.hasOwn(value, 'temporaryRoot')) {
    fail('BETA_CHIPNET_RUNTIME_INVALID', 'beta Chipnet runtime load options has missing or unknown properties');
  }
  if (typeof value.runtimeDirectory !== 'string' || typeof value.temporaryRoot !== 'string'
    || (value.allowedOutputRoot !== undefined && typeof value.allowedOutputRoot !== 'string')) {
    fail('BETA_CHIPNET_RUNTIME_INVALID', 'runtimeDirectory, temporaryRoot, and optional allowedOutputRoot must be strings');
  }
  const runtimeDirectory = path.resolve(value.runtimeDirectory);
  recordV2BetaRuntimeWork({ type: 'full-runtime-verification' });
  const verification = await verifyV2Pf10BetaRuntime({
    ...(value.allowedOutputRoot === undefined ? {} : { allowedOutputRoot: path.resolve(value.allowedOutputRoot) }),
    outputDirectory: runtimeDirectory,
    temporaryRoot: path.resolve(value.temporaryRoot),
  });
  if (
    verification.eligibility !== V2_BETA_LOCAL_ELIGIBILITY
    || canonicalizeJcs(verification.claims) !== canonicalizeJcs(V2_BETA_LOCAL_FALSE_CLAIMS)
  ) fail('BETA_CHIPNET_RUNTIME_INVALID', 'independent beta runtime verification escaped its claim boundary');

  const manifestFile = await readCanonicalPrivateJson(
    path.join(runtimeDirectory, V2_PF10_BETA_RUNTIME_MANIFEST),
    'beta runtime manifest',
  );
  const manifest = validateManifestBoundary(manifestFile.value);
  if (manifestFile.sha256 !== verification.manifestSha256) {
    fail('BETA_CHIPNET_RUNTIME_INVALID', 'independent verification and loaded manifest hashes differ');
  }
  const [profileFile, packageFile] = await Promise.all([
    readPrivateArtifact(runtimeDirectory, manifest.profile.profileCore, 'beta profile core'),
    readPrivateArtifact(runtimeDirectory, manifest.profile.betaProfilePackage, 'beta profile package'),
  ]);
  let profileCore;
  let profilePackage;
  try {
    profileCore = JSON.parse(profileFile.bytes.toString('utf8'));
    profilePackage = JSON.parse(packageFile.bytes.toString('utf8'));
    validateProfileCore(profileCore);
    profilePackage = validateV2BetaLocalProfilePackage(profilePackage, profileCore);
  } catch (error) {
    fail('BETA_CHIPNET_RUNTIME_INVALID', 'beta profile or beta profile package is invalid', { cause: error });
  }
  if (
    profileCore.network.id !== 2
    || profileCore.network.name !== 'chipnet'
    || profileCore.denominationSats !== manifest.identity.denominationSats
  ) fail('BETA_CHIPNET_RUNTIME_INVALID', 'beta runtime profile is not the exact Chipnet 0.1 BCH profile');
  const profileId = deriveProfileId(profileCore);
  if (profileId !== manifest.profile.profileId || profilePackage.profileId !== profileId) {
    fail('BETA_CHIPNET_RUNTIME_INVALID', 'beta runtime profile identity differs from its beta profile package');
  }
  const references = proofArtifactReferences(manifest);
  const proofSources = Object.fromEntries(await Promise.all(Object.entries(references).map(async ([name, ref]) => [
    name,
    await readPrivateArtifact(runtimeDirectory, ref, `beta proof artifact ${name}`),
  ])));
  const build = await buildDirectV2Pf10BetaRuntime({
    repositoryRoot: path.resolve(import.meta.dirname, '../../../../..'),
    artifactRoot: runtimeDirectory,
    temporaryRoot: path.resolve(value.temporaryRoot),
    profileId,
    instanceId: manifest.identity.instanceId,
    proofArtifacts: Object.freeze({
      provingKey: Object.freeze({ path: proofSources.provingKey.filename, sha256: proofSources.provingKey.sha256 }),
      r1cs: Object.freeze({ path: proofSources.r1cs.filename, sha256: proofSources.r1cs.sha256 }),
      verificationKey: Object.freeze({ path: proofSources.verificationKey.filename, sha256: proofSources.verificationKey.sha256 }),
      wasm: Object.freeze({ path: proofSources.wasm.filename, sha256: proofSources.wasm.sha256 }),
    }),
  });
  if (
    build.runtimeMaterial.schema !== DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA
    || build.runtimeMaterial.materialSha256 !== verification.runtimeMaterialSha256
    || build.runtimeMaterial.materialSha256 !== manifest.runtime.materialSha256
  ) fail('BETA_CHIPNET_RUNTIME_INVALID', 'beta runtime material did not independently reproduce the verified manifest');
  const pins = Object.freeze({
    identity: Object.freeze({
      profileId,
      instanceId: manifest.identity.instanceId,
      maximumLiveNotes: manifest.identity.maximumLiveNotes,
      denominationSats: manifest.identity.denominationSats,
    }),
    runtimeManifestSha256: manifestFile.sha256,
    profileCore: copyProfileCore(profileCore),
    proofArtifacts: Object.freeze(Object.fromEntries(Object.entries(proofSources).map(([name, source]) => [name, Object.freeze({
      path: source.filename,
      sha256: source.sha256,
    })]))),
    // buildDirectV2Pf10BetaRuntime returns the frozen, validator-branded
    // capability required by buildDirectV2Pf10BetaActionWitness.
    runtimeMaterial: build.runtimeMaterial,
    runtimeMaterialSha256: build.runtimeMaterial.materialSha256,
    stateUnlockingBytecode: Buffer.from(build.structural.stateUnlock),
    settlementPins: settlementPinsFromBuild(build),
  });
  return resolutionFromPins(pins);
}

/**
 * Explicitly perform the expensive full verifier once, then atomically install
 * a compact local cache. This never changes the beta qualification boundary.
 */
export async function installV2BetaChipnetRuntimeCache(value = {}) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).some((key) => !['allowedOutputRoot', 'cacheRoot', 'runtimeDirectory', 'temporaryRoot'].includes(key))
    || !Object.hasOwn(value, 'cacheRoot') || !Object.hasOwn(value, 'runtimeDirectory') || !Object.hasOwn(value, 'temporaryRoot')) {
    fail('BETA_CHIPNET_RUNTIME_INVALID', 'beta Chipnet runtime cache install options has missing or unknown properties');
  }
  if (typeof value.runtimeDirectory !== 'string'
    || typeof value.temporaryRoot !== 'string'
    || typeof value.cacheRoot !== 'string'
    || (value.allowedOutputRoot !== undefined && typeof value.allowedOutputRoot !== 'string')) {
    fail('BETA_CHIPNET_RUNTIME_INVALID', 'runtimeDirectory, temporaryRoot, cacheRoot, and optional allowedOutputRoot must be strings');
  }
  try {
    return await installCache({
      ...(value.allowedOutputRoot === undefined ? {} : { allowedOutputRoot: path.resolve(value.allowedOutputRoot) }),
      runtimeDirectory: path.resolve(value.runtimeDirectory),
      temporaryRoot: path.resolve(value.temporaryRoot),
      cacheRoot: path.resolve(value.cacheRoot),
    });
  } catch (error) {
    fail(
      error instanceof V2BetaChipnetRuntimeCacheError
        ? error.code
        : 'BETA_CHIPNET_RUNTIME_CACHE_INSTALL_REJECTED',
      error instanceof Error ? error.message : 'beta runtime cache installation failed',
      { cause: error },
    );
  }
}

/**
 * Load a previously fully verified beta cache. There is no cold rebuild
 * fallback: callers must explicitly install or refresh the cache.
 */
export async function loadCachedV2BetaChipnetRuntime(value = {}) {
  exact(value, ['cacheRoot', 'runtimeDirectory'], 'beta Chipnet cached runtime load options');
  if (typeof value.runtimeDirectory !== 'string' || typeof value.cacheRoot !== 'string') {
    fail('BETA_CHIPNET_RUNTIME_INVALID', 'runtimeDirectory and cacheRoot must be strings');
  }
  let cached;
  try {
    cached = await loadCache({
      runtimeDirectory: path.resolve(value.runtimeDirectory),
      cacheRoot: path.resolve(value.cacheRoot),
    });
  } catch (error) {
    fail(
      error instanceof V2BetaChipnetRuntimeCacheError
        ? error.code
        : 'BETA_CHIPNET_RUNTIME_CACHE_REJECTED',
      error instanceof Error ? error.message : 'beta runtime cache is unavailable or invalid',
      { cause: error },
    );
  }
  return resolutionFromPins(cached);
}

/** Load the retained generic linker template from a receipt-branded install. */
export async function loadV2BetaProductLinkedRuntimeTemplate(value = {}) {
  exact(value, ['artifactInstallation'], 'linked runtime template options');
  return deriveV2BetaProductLinkedRuntimeTemplate(value.artifactInstallation);
}

/**
 * Persist an opaque native-specializer result. The native assertion is the
 * only admission boundary; profile code never accepts a structural result.
 */
export async function installV2BetaProductLinkedRuntimeCache(value = {}) {
  exact(value, ['artifactInstallation', 'cacheRoot', 'specializedRuntime'], 'linked runtime cache install options');
  if (typeof value.cacheRoot !== 'string') fail('BETA_CHIPNET_RUNTIME_INVALID', 'linked runtime cacheRoot must be a string');
  try {
    return await installLinkedCache({
      artifactInstallation: value.artifactInstallation,
      cacheRoot: path.resolve(value.cacheRoot),
      specializedRuntime: value.specializedRuntime,
      assertSpecializedRuntime: assertV2Pf10SpecializedRuntimeCapability,
    });
  } catch (error) {
    fail(error instanceof V2BetaChipnetRuntimeCacheError ? error.code : 'BETA_LINKED_RUNTIME_CACHE_REJECTED', error instanceof Error ? error.message : 'linked runtime cache installation failed', { cause: error });
  }
}

/** Load a receipt-bound linked cache without verifier, qualification, or build. */
export async function loadV2BetaProductLinkedRuntimeCache(value = {}) {
  exact(value, ['artifactInstallation', 'cacheRoot', 'instanceId'], 'linked runtime cache load options');
  if (typeof value.cacheRoot !== 'string' || typeof value.instanceId !== 'string') fail('BETA_CHIPNET_RUNTIME_INVALID', 'linked runtime cacheRoot and instanceId must be strings');
  let cached;
  try {
    cached = await loadLinkedCache({ artifactInstallation: value.artifactInstallation, cacheRoot: path.resolve(value.cacheRoot), instanceId: value.instanceId });
  } catch (error) {
    fail(error instanceof V2BetaChipnetRuntimeCacheError ? error.code : 'BETA_LINKED_RUNTIME_CACHE_REJECTED', error instanceof Error ? error.message : 'linked runtime cache is unavailable or invalid', { cause: error });
  }
  recordV2BetaRuntimeWork({ type: 'linked-runtime-cache-load' });
  const resolution = resolutionFromPins(cached);
  const proofArtifacts = Object.freeze({
    schema: 'shieldkit-v2-beta-receipt-bound-proof-artifacts-v1',
    installationReceiptSha256: cached.installationReceiptSha256,
    artifacts: Object.freeze(Object.fromEntries(Object.entries(cached.proofArtifacts).map(([name, entry]) => [name, Object.freeze({ ...entry, identity: Object.freeze({ ...cached.proofArtifactIdentities[name] }) })]))),
  });
  linkedProofArtifacts.add(proofArtifacts);
  linkedResolutionProofArtifacts.set(resolution, proofArtifacts);
  return resolution;
}

/** Reject lookalikes and return only a resolution made by this module. */
export function assertV2BetaChipnetRuntimeResolution(value) {
  if (resolutions.get(value) === undefined) {
    fail('BETA_CHIPNET_RUNTIME_UNBRANDED', 'beta Chipnet runtime resolution must be returned by loadV2BetaChipnetRuntime or bindV2BetaChipnetRuntimeResolution');
  }
  return value;
}

/**
 * Return the opaque receipt-bound proof-artifact capability for a linked
 * runtime. It contains immutable path/hash/identity tuples and never asks a
 * warm action to rehash the proving key, R1CS, or WASM.
 */
export function deriveV2BetaChipnetNativeProofArtifacts(value) {
  assertV2BetaChipnetRuntimeResolution(value);
  const capability = linkedResolutionProofArtifacts.get(value);
  if (capability === undefined) fail('BETA_LINKED_RUNTIME_PROOF_ARTIFACTS_REQUIRED', 'native proof artifacts require a branded linked runtime resolution');
  return capability;
}

/** Reject copied proof artifact records before they reach the native worker. */
export function assertV2BetaChipnetNativeProofArtifacts(value) {
  if (!linkedProofArtifacts.has(value)) fail('BETA_LINKED_RUNTIME_PROOF_ARTIFACTS_UNBRANDED', 'native proof artifacts must be derived from a branded linked runtime resolution');
  return value;
}

/** Derive the exact opaque runtime-material digest required by the beta store. */
export function deriveV2BetaChipnetStoreRuntimeMaterialsSha256(value) {
  const pins = resolutions.get(value);
  if (pins === undefined) {
    fail('BETA_CHIPNET_RUNTIME_UNBRANDED', 'beta store binding requires a branded beta Chipnet runtime resolution');
  }
  return Buffer.from(pins.runtimeMaterialSha256, 'hex');
}

/** Derive fresh settlement-pin byte copies from a branded beta resolution. */
export function deriveV2BetaChipnetSettlementPins(value) {
  const pins = resolutions.get(value);
  if (pins === undefined) {
    fail('BETA_CHIPNET_RUNTIME_UNBRANDED', 'beta settlement pins require a branded beta Chipnet runtime resolution');
  }
  return copySettlementPins(pins.settlementPins);
}

/**
 * Derive the validator-authenticated state unlock required only while issuing
 * a beta genesis capability. The bytecode is kept in the resolution's private
 * WeakMap pins, so a structural lookalike cannot supply or replace it.
 */
export function deriveV2BetaChipnetGenesisStateUnlock(value) {
  const pins = resolutions.get(value);
  if (pins === undefined || pins.stateUnlockingBytecode === undefined) {
    fail('BETA_CHIPNET_RUNTIME_UNBRANDED', 'beta genesis state unlock requires a branded beta Chipnet runtime resolution');
  }
  return Buffer.from(pins.stateUnlockingBytecode);
}

/**
 * Return an immutable copy of the exact profile core independently validated
 * while issuing this branded runtime resolution. Callers never re-read or
 * trust an adjacent convenience file during an action.
 */
export function deriveV2BetaChipnetProfileCore(value) {
  const pins = resolutions.get(value);
  if (pins === undefined) {
    fail('BETA_CHIPNET_RUNTIME_UNBRANDED', 'beta profile core requires a branded beta Chipnet runtime resolution');
  }
  return copyProfileCore(pins.profileCore);
}

/**
 * Bind a loaded beta runtime to a future descriptor/manifest pair once. This
 * remains beta-only; it never creates a normal descriptor capability.
 */
export function bindV2BetaChipnetRuntimeResolution(value, binding = {}) {
  const pins = resolutions.get(value);
  if (pins === undefined) {
    fail('BETA_CHIPNET_RUNTIME_UNBRANDED', 'beta runtime binding requires a branded beta Chipnet runtime resolution');
  }
  if (pins.binding !== undefined || Object.hasOwn(value, 'descriptorSha256') || Object.hasOwn(value, 'manifestSha256')) {
    fail('BETA_CHIPNET_RUNTIME_ALREADY_BOUND', 'beta runtime resolution may be bound to a descriptor and manifest only once');
  }
  exact(binding, ['descriptorSha256', 'manifestSha256'], 'beta runtime descriptor binding');
  const normalized = Object.freeze({
    descriptorSha256: hash(binding.descriptorSha256, 'descriptorSha256'),
    manifestSha256: hash(binding.manifestSha256, 'manifestSha256'),
  });
  // Mark the source capability before returning its bound successor. A caller
  // must not be able to fork one independently verified runtime into several
  // descriptor/manifest bindings by retaining the original object.
  resolutions.set(value, Object.freeze({ ...pins, binding: normalized }));
  const bound = resolutionFromPins(pins, normalized);
  const proofArtifacts = linkedResolutionProofArtifacts.get(value);
  if (proofArtifacts !== undefined) {
    linkedResolutionProofArtifacts.delete(value);
    linkedResolutionProofArtifacts.set(bound, proofArtifacts);
  }
  return bound;
}
