/**
 * Durable, locally verified cache for the beta-only PF10 runtime material.
 *
 * A cache entry is created only from the successful full runtime verifier. It
 * is deliberately not a signature or a substitute for proof-artifact pins:
 * the action prover continues to hash every referenced proof artifact before
 * use. Loading a cache revalidates the compact material and therefore issues
 * a fresh process-local PF10 WeakMap capability without compiling CashScript.
 */
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  chmod, lstat, mkdir, mkdtemp, open, readFile, readdir, realpath, rename,
  rm,
} from 'node:fs/promises';
import path from 'node:path';

import { deriveV2RollingBaseSats } from '../../action/v2/dust-policy.mjs';
import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
} from '../../action/v2/topology.mjs';
import {
  DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA,
  validateDirectV2Pf10BetaRuntimeMaterial,
} from '../../unlock-builder/v2/pf10-action-witness.mjs';
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
  V2_PF10_BETA_RUNTIME_BUNDLE_SCHEMA,
  V2_PF10_BETA_RUNTIME_MANIFEST,
  verifyV2Pf10BetaRuntime,
} from '../../../scripts/v2-pf10-beta-runtime.mjs';
import {
  assertV2BetaProductArtifactInstallationCapability,
  deriveV2BetaProductLinkedRuntimeTemplate,
} from './beta-product-artifact-installation.mjs';

export const V2_BETA_CHIPNET_RUNTIME_CACHE_SCHEMA =
  'shieldkit-v2-direct-pf10-beta-chipnet-runtime-cache-v1';
export const V2_BETA_CHIPNET_RUNTIME_CACHE_FILE =
  'beta-runtime-cache.json';

const ROOT = path.resolve(import.meta.dirname, '../../../..');
const HASH = /^[0-9a-f]{64}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
const MAXIMUM_LIVE_NOTES = 210_000_000n;
const MATERIAL_BYTES = Object.freeze([
  'bindingLockingBytecode', 'bindingRedeemBytecode', 'executorBody',
  'fusedRedeem', 'stateUnlockingBytecode', 'terminalRedeem',
  'verificationKeyBytes',
]);
const SOURCE_SEEDS = Object.freeze([
  '03-create-your-own-pool/packages/profile/v2/beta-chipnet-runtime-cache.mjs',
  '03-create-your-own-pool/packages/profile/v2/beta-chipnet-runtime.mjs',
  '03-create-your-own-pool/scripts/v2-pf10-beta-runtime.mjs',
  '03-create-your-own-pool/packages/unlock-builder/v2/pf10-action-witness.mjs',
  '03-create-your-own-pool/packages/unlock-builder/v2/pf10-development-runtime-builder.mjs',
  '03-create-your-own-pool/packages/unlock-builder/v2/pf10-instance-specializer.mjs',
  // Audited literal/conditional dynamic dependencies in the verified build
  // closure. Keep these explicit: the scanner below intentionally accepts
  // only static ESM declarations so generated JavaScript held in strings can
  // never manufacture a source-fingerprint dependency.
  '03-create-your-own-pool/packages/profile/setup/development.mjs',
  '03-create-your-own-pool/packages/profile/v2/instance-descriptor.mjs',
  '03-create-your-own-pool/packages/unlock-builder/vendor/verifier/lanes/bn254-onetx/src/c7/v2-direct-groth16-adapter-input.mjs',
  'package-lock.json',
]);
const LOADED_RUNTIME_CACHES = new WeakSet();

function freezeJson(value) {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) freezeJson(child);
    Object.freeze(value);
  }
  return value;
}

function copyCanonicalJson(value) {
  return freezeJson(JSON.parse(canonicalizeJcs(value)));
}

export class V2BetaChipnetRuntimeCacheError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options);
    this.name = 'V2BetaChipnetRuntimeCacheError';
    this.code = code;
  }
}

const fail = (code, message, options = undefined) => {
  throw new V2BetaChipnetRuntimeCacheError(code, message, options);
};
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonicalBytes = (value) => Buffer.from(canonicalizeJcs(value), 'utf8');

function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('BETA_RUNTIME_CACHE_INVALID', `${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])) {
    fail('BETA_RUNTIME_CACHE_INVALID', `${label} has missing or unknown properties`);
  }
  return value;
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail('BETA_RUNTIME_CACHE_INVALID', `${label} must be lowercase SHA-256`);
  }
  return value;
}

function privateDirectory(value, label) {
  if (typeof value !== 'string' || value.length === 0) {
    fail('BETA_RUNTIME_CACHE_INVALID', `${label} is required`);
  }
  return path.resolve(value);
}

async function assertPrivateDirectory(directory, label) {
  const resolved = privateDirectory(directory, label);
  let metadata;
  try { metadata = await lstat(resolved); }
  catch (error) { fail('BETA_RUNTIME_CACHE_UNAVAILABLE', `${label} is unavailable`, { cause: error }); }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()
    || (metadata.mode & 0o077) !== 0 || await realpath(resolved) !== resolved) {
    fail('BETA_RUNTIME_CACHE_UNSAFE_PATH', `${label} must be a private canonical directory`);
  }
  return resolved;
}

async function readPrivateCanonicalJson(filename, label) {
  const resolved = path.resolve(filename);
  let initial;
  try { initial = await lstat(resolved); }
  catch (error) { fail('BETA_RUNTIME_CACHE_UNAVAILABLE', `${label} is unavailable`, { cause: error }); }
  if (!initial.isFile() || initial.isSymbolicLink() || initial.nlink !== 1
    || (initial.mode & 0o077) !== 0 || await realpath(resolved) !== resolved) {
    fail('BETA_RUNTIME_CACHE_UNSAFE_PATH', `${label} must be a private canonical single-link file`);
  }
  let handle;
  try {
    handle = await open(resolved, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const before = await handle.stat();
    const bytes = await handle.readFile();
    const after = await handle.stat();
    const pathAfter = await lstat(resolved);
    if (before.dev !== initial.dev || before.ino !== initial.ino
      || after.dev !== initial.dev || after.ino !== initial.ino
      || pathAfter.dev !== initial.dev || pathAfter.ino !== initial.ino
      || before.size !== after.size || pathAfter.size !== before.size
      || pathAfter.isSymbolicLink()) {
      fail('BETA_RUNTIME_CACHE_UNSAFE_PATH', `${label} changed while it was read`);
    }
    let value;
    try { value = JSON.parse(bytes.toString('utf8')); }
    catch (error) { fail('BETA_RUNTIME_CACHE_INVALID', `${label} is not JSON`, { cause: error }); }
    if (!bytes.equals(canonicalBytes(value))) {
      fail('BETA_RUNTIME_CACHE_INVALID', `${label} must use exact RFC8785/JCS bytes`);
    }
    return Object.freeze({ filename: resolved, bytes: Buffer.from(bytes), sha256: sha256(bytes), value });
  } finally { await handle?.close().catch(() => undefined); }
}

function relativeArtifact(root, reference, label) {
  exact(reference, ['bytes', 'id', 'path', 'sha256'], label);
  if (!Number.isSafeInteger(reference.bytes) || reference.bytes <= 0
    || typeof reference.id !== 'string' || typeof reference.path !== 'string'
    || reference.path.length === 0 || path.isAbsolute(reference.path)
    || reference.path.includes('\\')
    || reference.path.split('/').some((part) => part === '' || part === '.' || part === '..')) {
    fail('BETA_RUNTIME_CACHE_INVALID', `${label} reference is malformed`);
  }
  hash(reference.sha256, `${label}.sha256`);
  const filename = path.resolve(root, reference.path);
  const relative = path.relative(root, filename);
  if (relative === '' || relative === '..' || relative.startsWith(`..${path.sep}`)
    || path.isAbsolute(relative)) {
    fail('BETA_RUNTIME_CACHE_UNSAFE_PATH', `${label} escapes runtime directory`);
  }
  return Object.freeze({ ...reference, filename });
}

async function assertPinnedArtifactPath(reference, label) {
  let metadata;
  try { metadata = await lstat(reference.filename); }
  catch (error) { fail('BETA_RUNTIME_CACHE_UNAVAILABLE', `${label} is unavailable`, { cause: error }); }
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1
    || (metadata.mode & 0o077) !== 0 || await realpath(reference.filename) !== reference.filename
    || metadata.size !== reference.bytes) {
    fail('BETA_RUNTIME_CACHE_UNSAFE_PATH', `${label} is not its pinned private regular file`);
  }
  return reference;
}

async function readPinnedArtifact(reference, label) {
  await assertPinnedArtifactPath(reference, label);
  let handle;
  try {
    handle = await open(reference.filename, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const before = await handle.stat();
    const bytes = await handle.readFile();
    const after = await handle.stat();
    const afterPath = await lstat(reference.filename);
    if (before.dev !== after.dev || before.ino !== after.ino
      || before.dev !== afterPath.dev || before.ino !== afterPath.ino
      || before.size !== after.size || before.size !== afterPath.size
      || bytes.length !== reference.bytes || sha256(bytes) !== reference.sha256) {
      fail('BETA_RUNTIME_CACHE_UNSAFE_PATH', `${label} changed or differs from its runtime pin`);
    }
    return Buffer.from(bytes);
  } finally { await handle?.close().catch(() => undefined); }
}

function encodeBytes(value, label) {
  if (!(value instanceof Uint8Array) || value.length === 0) {
    fail('BETA_RUNTIME_CACHE_INVALID', `${label} must be nonempty bytes`);
  }
  return Buffer.from(value).toString('base64');
}

function decodeBytes(value, label) {
  if (typeof value !== 'string' || value.length === 0) {
    fail('BETA_RUNTIME_CACHE_INVALID', `${label} must be canonical base64`);
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length === 0 || bytes.toString('base64') !== value) {
    fail('BETA_RUNTIME_CACHE_INVALID', `${label} must be canonical base64`);
  }
  return Uint8Array.from(bytes);
}

function serializeMaterial(value) {
  exact(value, [
    'bindingLockingBytecode', 'bindingRedeemBytecode', 'eligibility',
    'exactMsmRedeems', 'executorBody', 'fixedCarrierPads', 'fusedRedeem',
    'instanceId', 'profileId', 'proofArtifactHashes', 'schema',
    'stateUnlockingBytecode', 'terminalRedeem', 'topologyId',
    'verificationKeyBytes', 'verifierLockingBytecodes', 'verifierRoles',
  ], 'verified runtime material');
  const result = {};
  for (const name of MATERIAL_BYTES) result[name] = encodeBytes(value[name], `runtime material ${name}`);
  for (const name of ['exactMsmRedeems', 'fixedCarrierPads', 'verifierLockingBytecodes']) {
    if (!Array.isArray(value[name])) fail('BETA_RUNTIME_CACHE_INVALID', `runtime material ${name} must be an array`);
    result[name] = value[name].map((entry, index) => encodeBytes(entry, `runtime material ${name}[${index}]`));
  }
  for (const name of ['eligibility', 'instanceId', 'profileId', 'schema', 'topologyId']) result[name] = value[name];
  result.verifierRoles = [...value.verifierRoles];
  result.proofArtifactHashes = { ...value.proofArtifactHashes };
  return result;
}

function deserializeMaterial(value) {
  exact(value, [
    'bindingLockingBytecode', 'bindingRedeemBytecode', 'eligibility',
    'exactMsmRedeems', 'executorBody', 'fixedCarrierPads', 'fusedRedeem',
    'instanceId', 'profileId', 'proofArtifactHashes', 'schema',
    'stateUnlockingBytecode', 'terminalRedeem', 'topologyId',
    'verificationKeyBytes', 'verifierLockingBytecodes', 'verifierRoles',
  ], 'cached runtime material');
  const result = {};
  for (const name of MATERIAL_BYTES) result[name] = decodeBytes(value[name], `cached runtime material ${name}`);
  for (const name of ['exactMsmRedeems', 'fixedCarrierPads', 'verifierLockingBytecodes']) {
    if (!Array.isArray(value[name])) fail('BETA_RUNTIME_CACHE_INVALID', `cached runtime material ${name} must be an array`);
    result[name] = value[name].map((entry, index) => decodeBytes(entry, `cached runtime material ${name}[${index}]`));
  }
  for (const name of ['eligibility', 'instanceId', 'profileId', 'schema', 'topologyId']) result[name] = value[name];
  result.verifierRoles = [...value.verifierRoles];
  result.proofArtifactHashes = { ...value.proofArtifactHashes };
  return result;
}

function decimal(value, label) {
  if (typeof value !== 'string' || !DECIMAL.test(value) || BigInt(value) === 0n) {
    fail('BETA_RUNTIME_CACHE_INVALID', `${label} must be a positive canonical decimal`);
  }
  return value;
}

function serializeSettlementPins(value) {
  exact(value, [
    'bindingBaseSats', 'bindingLockingBytecode', 'bindingRedeemBytecode',
    'stateBaseSats', 'stateHelperBytecode', 'stateLockingBytecode',
    'stateUnlockingBytecode', 'topologyId', 'verifierCarriers', 'verifierRoles',
  ], 'verified settlement pins');
  if (value.topologyId !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
    || !Array.isArray(value.verifierRoles)
    || canonicalizeJcs(value.verifierRoles) !== canonicalizeJcs(DIRECT_V2_PF10_FUSED_VERIFIER_ROLES)
    || !Array.isArray(value.verifierCarriers)
    || value.verifierCarriers.length !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length) {
    fail('BETA_RUNTIME_CACHE_INVALID', 'verified settlement pins topology is invalid');
  }
  return Object.freeze({
    topologyId: value.topologyId,
    verifierRoles: [...value.verifierRoles],
    verifierCarriers: value.verifierCarriers.map((entry, index) => {
      exact(entry, ['baseValueSats', 'lockingBytecode'], `verified verifier carrier ${index}`);
      return Object.freeze({ baseValueSats: decimal(entry.baseValueSats, `verified verifier carrier ${index} base`), lockingBytecode: encodeBytes(entry.lockingBytecode, `verified verifier carrier ${index} lock`) });
    }),
    bindingBaseSats: decimal(value.bindingBaseSats, 'verified binding base'),
    bindingLockingBytecode: encodeBytes(value.bindingLockingBytecode, 'verified binding lock'),
    bindingRedeemBytecode: encodeBytes(value.bindingRedeemBytecode, 'verified binding redeem'),
    stateBaseSats: decimal(value.stateBaseSats, 'verified state base'),
    stateHelperBytecode: encodeBytes(value.stateHelperBytecode, 'verified state helper'),
    stateLockingBytecode: encodeBytes(value.stateLockingBytecode, 'verified state lock'),
    stateUnlockingBytecode: encodeBytes(value.stateUnlockingBytecode, 'verified state unlock'),
  });
}

function deserializeSettlementPins(value) {
  exact(value, [
    'bindingBaseSats', 'bindingLockingBytecode', 'bindingRedeemBytecode',
    'stateBaseSats', 'stateHelperBytecode', 'stateLockingBytecode',
    'stateUnlockingBytecode', 'topologyId', 'verifierCarriers', 'verifierRoles',
  ], 'cached settlement pins');
  if (value.topologyId !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
    || !Array.isArray(value.verifierRoles)
    || canonicalizeJcs(value.verifierRoles) !== canonicalizeJcs(DIRECT_V2_PF10_FUSED_VERIFIER_ROLES)
    || !Array.isArray(value.verifierCarriers)
    || value.verifierCarriers.length !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length) {
    fail('BETA_RUNTIME_CACHE_INVALID', 'cached settlement pins topology is invalid');
  }
  return Object.freeze({
    topologyId: value.topologyId,
    verifierRoles: Object.freeze([...value.verifierRoles]),
    verifierCarriers: Object.freeze(value.verifierCarriers.map((entry, index) => {
      exact(entry, ['baseValueSats', 'lockingBytecode'], `cached verifier carrier ${index}`);
      return Object.freeze({ baseValueSats: decimal(entry.baseValueSats, `cached verifier carrier ${index} base`), lockingBytecode: decodeBytes(entry.lockingBytecode, `cached verifier carrier ${index} lock`) });
    })),
    bindingBaseSats: decimal(value.bindingBaseSats, 'cached binding base'),
    bindingLockingBytecode: decodeBytes(value.bindingLockingBytecode, 'cached binding lock'),
    bindingRedeemBytecode: decodeBytes(value.bindingRedeemBytecode, 'cached binding redeem'),
    stateBaseSats: decimal(value.stateBaseSats, 'cached state base'),
    stateHelperBytecode: decodeBytes(value.stateHelperBytecode, 'cached state helper'),
    stateLockingBytecode: decodeBytes(value.stateLockingBytecode, 'cached state lock'),
    stateUnlockingBytecode: decodeBytes(value.stateUnlockingBytecode, 'cached state unlock'),
  });
}

function importsFrom(source) {
  const imports = [];
  // Static ESM declarations are top-level grammar productions. Anchoring the
  // scan to a line start prevents source-code examples held in strings from
  // being mistaken for live imports (and therefore from poisoning the cache
  // source closure). The runtime closure currently contains no dynamic
  // dependency which is not listed explicitly in SOURCE_SEEDS above.
  const pattern = /^[\t ]*(?:import|export)\s+(?:[\w*${},\s]*?\s+from\s+)?['"]([^'"]+)['"]/gmu;
  for (const match of source.matchAll(pattern)) imports.push(match[1]);
  return imports;
}

export function extractV2BetaRuntimeImportsForTest(source) {
  if (typeof source !== 'string') {
    fail('BETA_RUNTIME_CACHE_INVALID', 'runtime source must be a string');
  }
  return Object.freeze(importsFrom(source));
}

async function sourceFingerprint() {
  const pending = [...SOURCE_SEEDS];
  const records = new Map();
  while (pending.length !== 0) {
    const relative = pending.pop();
    if (records.has(relative)) continue;
    const filename = path.resolve(ROOT, relative);
    const normalized = path.relative(ROOT, filename).split(path.sep).join('/');
    if (normalized !== relative || filename === ROOT || !filename.startsWith(`${ROOT}${path.sep}`)) {
      fail('BETA_RUNTIME_CACHE_INVALID', `runtime source escapes repository: ${relative}`);
    }
    let bytes;
    try { bytes = await readFile(filename); }
    catch (error) { fail('BETA_RUNTIME_CACHE_UNAVAILABLE', `runtime source is unavailable: ${relative}`, { cause: error }); }
    records.set(relative, Object.freeze({ bytes: bytes.length, path: relative, sha256: sha256(bytes) }));
    if (!relative.endsWith('.mjs') && !relative.endsWith('.js')) continue;
    for (const specifier of importsFrom(bytes.toString('utf8'))) {
      if (!specifier.startsWith('.')) continue;
      const target = path.resolve(path.dirname(filename), specifier);
      const targetRelative = path.relative(ROOT, target).split(path.sep).join('/');
      if (targetRelative === '..' || targetRelative.startsWith('../') || path.isAbsolute(targetRelative)) {
        fail('BETA_RUNTIME_CACHE_INVALID', `runtime import escapes repository: ${specifier}`);
      }
      pending.push(targetRelative);
    }
  }
  return sha256(canonicalBytes([...records.values()].sort((a, b) => a.path.localeCompare(b.path))));
}

function exactClaims(value, label) {
  if (canonicalizeJcs(value) !== canonicalizeJcs(V2_BETA_LOCAL_FALSE_CLAIMS)) {
    fail('BETA_RUNTIME_CACHE_INVALID', `${label} differs from the immutable beta claim boundary`);
  }
  return value;
}

function cacheDirectoryName(runtimeManifestSha256, runtimeSourceSha256) {
  hash(runtimeManifestSha256, 'runtime manifest hash');
  hash(runtimeSourceSha256, 'runtime source fingerprint');
  return sha256(canonicalBytes({ runtimeManifestSha256, runtimeSourceSha256 }));
}

export function deriveV2BetaRuntimeCacheDirectoryNameForTest(
  runtimeManifestSha256,
  runtimeSourceSha256,
) {
  return cacheDirectoryName(runtimeManifestSha256, runtimeSourceSha256);
}

function cacheValue({ manifest, manifestSha256, material, materialSha256, settlementPins, sourceSha256 }) {
  exact(manifest, [
    'artifacts', 'assuranceClass', 'claims', 'eligibility', 'identity',
    'profile', 'proofArtifacts', 'proofQualification', 'runtime', 'schema',
    'status',
  ], 'verified beta runtime manifest');
  if (manifest.schema !== V2_PF10_BETA_RUNTIME_BUNDLE_SCHEMA
    || manifest.status !== 'beta-local-runtime-built-unqualified'
    || manifest.eligibility !== V2_BETA_LOCAL_ELIGIBILITY
    || manifest.assuranceClass !== 'beta-single-contributor') {
    fail('BETA_RUNTIME_CACHE_INVALID', 'verified runtime manifest escaped beta-only boundary');
  }
  exactClaims(manifest.claims, 'verified runtime manifest claims');
  if (manifest.runtime?.materialSha256 !== materialSha256
    || material.schema !== DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA
    || material.eligibility !== V2_BETA_LOCAL_ELIGIBILITY
    || material.topologyId !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
    || material.profileId !== manifest.profile?.profileId
    || material.instanceId !== manifest.identity?.instanceId) {
    fail('BETA_RUNTIME_CACHE_INVALID', 'verified runtime material does not bind beta manifest identity');
  }
  hash(manifestSha256, 'runtime manifest hash');
  hash(materialSha256, 'runtime material hash');
  hash(sourceSha256, 'runtime source fingerprint');
  return Object.freeze({
    schema: V2_BETA_CHIPNET_RUNTIME_CACHE_SCHEMA,
    status: 'verified-reproduction-cache-unqualified',
    eligibility: V2_BETA_LOCAL_ELIGIBILITY,
    claims: V2_BETA_LOCAL_FALSE_CLAIMS,
    runtimeManifestSha256: manifestSha256,
    runtimeMaterialSha256: materialSha256,
    runtimeSourceSha256: sourceSha256,
    identity: Object.freeze({
      profileId: manifest.profile.profileId,
      instanceId: manifest.identity.instanceId,
      maximumLiveNotes: manifest.identity.maximumLiveNotes,
      denominationSats: manifest.identity.denominationSats,
    }),
    proofArtifacts: Object.freeze(Object.fromEntries(Object.entries(manifest.proofArtifacts)
      .map(([name, entry]) => [name, Object.freeze({ ...entry })]))),
    material: Object.freeze(serializeMaterial(material)),
    settlementPins: serializeSettlementPins(settlementPins),
  });
}

function validateCache(value) {
  exact(value, [
    'claims', 'eligibility', 'identity', 'material', 'proofArtifacts', 'settlementPins',
    'runtimeManifestSha256', 'runtimeMaterialSha256', 'runtimeSourceSha256',
    'schema', 'status',
  ], 'beta runtime cache');
  if (value.schema !== V2_BETA_CHIPNET_RUNTIME_CACHE_SCHEMA
    || value.status !== 'verified-reproduction-cache-unqualified'
    || value.eligibility !== V2_BETA_LOCAL_ELIGIBILITY) {
    fail('BETA_RUNTIME_CACHE_INVALID', 'cache schema, status, or eligibility is invalid');
  }
  exactClaims(value.claims, 'cache claims');
  exact(value.identity, ['denominationSats', 'instanceId', 'maximumLiveNotes', 'profileId'], 'cache identity');
  if (value.identity.denominationSats !== '10000000'
    || typeof value.identity.maximumLiveNotes !== 'string'
    || !DECIMAL.test(value.identity.maximumLiveNotes)
    || BigInt(value.identity.maximumLiveNotes) === 0n
    || BigInt(value.identity.maximumLiveNotes) > MAXIMUM_LIVE_NOTES) {
    fail('BETA_RUNTIME_CACHE_INVALID', 'cache identity is invalid');
  }
  for (const name of ['instanceId', 'profileId']) hash(value.identity[name], `cache identity ${name}`);
  for (const name of ['runtimeManifestSha256', 'runtimeMaterialSha256', 'runtimeSourceSha256']) hash(value[name], name);
  exact(value.proofArtifacts, ['provingKey', 'r1cs', 'verificationKey', 'wasm'], 'cache proof artifacts');
  deserializeSettlementPins(value.settlementPins);
  return value;
}

async function writeCache(cacheRoot, cache) {
  const root = await assertPrivateDirectory(cacheRoot, 'cache root');
  const destination = path.join(root, cacheDirectoryName(
    cache.runtimeManifestSha256,
    cache.runtimeSourceSha256,
  ));
  try {
    await lstat(destination);
    await assertPrivateDirectory(destination, 'existing runtime cache directory');
    const entries = await readdir(destination);
    if (entries.length !== 1 || entries[0] !== V2_BETA_CHIPNET_RUNTIME_CACHE_FILE) {
      fail('BETA_RUNTIME_CACHE_INVALID', 'existing runtime cache has unexpected entries');
    }
    const existing = await readPrivateCanonicalJson(path.join(destination, V2_BETA_CHIPNET_RUNTIME_CACHE_FILE), 'existing runtime cache');
    if (canonicalizeJcs(validateCache(existing.value)) !== canonicalizeJcs(cache)) {
      fail('BETA_RUNTIME_CACHE_EXISTS', 'existing cache entry differs from verified runtime');
    }
    return Object.freeze({ cacheDirectory: destination, cacheSha256: existing.sha256, installed: false });
  } catch (error) {
    if (error instanceof V2BetaChipnetRuntimeCacheError) throw error;
    if (error?.code !== 'ENOENT') throw error;
  }
  const stage = await mkdtemp(path.join(root, '.beta-runtime-cache-stage-'));
  try {
    await chmod(stage, 0o700);
    const filename = path.join(stage, V2_BETA_CHIPNET_RUNTIME_CACHE_FILE);
    const bytes = canonicalBytes(cache);
    const handle = await open(filename, 'wx', 0o600);
    try { await handle.writeFile(bytes); await handle.sync(); }
    finally { await handle.close(); }
    const stageHandle = await open(stage, fsConstants.O_RDONLY);
    try { await stageHandle.sync(); } finally { await stageHandle.close(); }
    await rename(stage, destination);
    const rootHandle = await open(root, fsConstants.O_RDONLY);
    try { await rootHandle.sync(); } finally { await rootHandle.close(); }
    return Object.freeze({ cacheDirectory: destination, cacheSha256: sha256(bytes), installed: true });
  } catch (error) {
    await rm(stage, { recursive: true, force: true }).catch(() => undefined);
    throw error;
  }
}

async function currentRuntimeManifest(runtimeDirectory) {
  const runtime = await assertPrivateDirectory(runtimeDirectory, 'runtime directory');
  const manifest = await readPrivateCanonicalJson(
    path.join(runtime, V2_PF10_BETA_RUNTIME_MANIFEST),
    'beta runtime manifest',
  );
  exact(manifest.value, [
    'artifacts', 'assuranceClass', 'claims', 'eligibility', 'identity',
    'profile', 'proofArtifacts', 'proofQualification', 'runtime', 'schema',
    'status',
  ], 'beta runtime manifest');
  return Object.freeze({ runtime, manifest });
}

async function settlementPinsFromVerifiedRuntime(runtime, manifest, material) {
  const base = manifest.runtime?.baseValues;
  const structural = manifest.runtime?.structural;
  exact(base, ['bindingSats', 'minimumChangeSats', 'stateSats', 'verifierSats'], 'verified runtime base values');
  exact(structural, ['bindingLock', 'bindingRedeem', 'stateHelper', 'stateLock', 'stateUnlock', 'verifierLocks'], 'verified runtime structural artifacts');
  if (!Array.isArray(base.verifierSats) || base.verifierSats.length !== material.verifierLockingBytecodes.length
    || !Array.isArray(structural.verifierLocks) || structural.verifierLocks.length !== material.verifierLockingBytecodes.length
    || base.minimumChangeSats !== '546') {
    fail('BETA_RUNTIME_CACHE_INVALID', 'verified runtime settlement shape is invalid');
  }
  const refs = Object.freeze({
    bindingLock: relativeArtifact(runtime, structural.bindingLock, 'binding lock'),
    bindingRedeem: relativeArtifact(runtime, structural.bindingRedeem, 'binding redeem'),
    stateHelper: relativeArtifact(runtime, structural.stateHelper, 'state helper'),
    stateLock: relativeArtifact(runtime, structural.stateLock, 'state lock'),
    stateUnlock: relativeArtifact(runtime, structural.stateUnlock, 'state unlock'),
    verifierLocks: structural.verifierLocks.map((entry, index) => relativeArtifact(runtime, entry, `verifier lock ${index}`)),
  });
  const [bindingLock, bindingRedeem, stateHelper, stateLock, stateUnlock, verifierLocks] = await Promise.all([
    readPinnedArtifact(refs.bindingLock, 'binding lock'),
    readPinnedArtifact(refs.bindingRedeem, 'binding redeem'),
    readPinnedArtifact(refs.stateHelper, 'state helper'),
    readPinnedArtifact(refs.stateLock, 'state lock'),
    readPinnedArtifact(refs.stateUnlock, 'state unlock'),
    Promise.all(refs.verifierLocks.map((entry, index) => readPinnedArtifact(entry, `verifier lock ${index}`))),
  ]);
  if (!bindingLock.equals(Buffer.from(material.bindingLockingBytecode))
    || !bindingRedeem.equals(Buffer.from(material.bindingRedeemBytecode))
    || !stateUnlock.equals(Buffer.from(material.stateUnlockingBytecode))
    || verifierLocks.some((entry, index) => !entry.equals(Buffer.from(material.verifierLockingBytecodes[index])))) {
    fail('BETA_RUNTIME_CACHE_INVALID', 'verified runtime structural artifacts differ from validated material');
  }
  const verifierSats = verifierLocks.map((lockingBytecode, index) => {
    const derived = deriveV2RollingBaseSats({ lockingBytecode }).toString();
    if (derived !== decimal(base.verifierSats[index], `verifier ${index} base`)) fail('BETA_RUNTIME_CACHE_INVALID', `verified verifier ${index} base differs from its lock`);
    return derived;
  });
  const bindingSats = deriveV2RollingBaseSats({ lockingBytecode: bindingLock }).toString();
  const stateSats = deriveV2RollingBaseSats({
    lockingBytecode: stateLock,
    token: { category: Buffer.from(material.instanceId, 'hex'), amount: 0n, nft: { capability: 'mutable', commitment: Buffer.alloc(128) } },
  }).toString();
  if (bindingSats !== decimal(base.bindingSats, 'binding base') || stateSats !== decimal(base.stateSats, 'state base')) {
    fail('BETA_RUNTIME_CACHE_INVALID', 'verified binding or state base differs from its lock');
  }
  return Object.freeze({
    topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
    verifierRoles: Object.freeze([...DIRECT_V2_PF10_FUSED_VERIFIER_ROLES]),
    verifierCarriers: Object.freeze(verifierLocks.map((lockingBytecode, index) => Object.freeze({ baseValueSats: verifierSats[index], lockingBytecode }))),
    bindingBaseSats: bindingSats,
    bindingLockingBytecode: bindingLock,
    bindingRedeemBytecode: bindingRedeem,
    stateBaseSats: stateSats,
    stateHelperBytecode: stateHelper,
    stateLockingBytecode: stateLock,
    stateUnlockingBytecode: stateUnlock,
  });
}

async function warmSettlementPins(runtime, manifest, rawMaterial, cached) {
  const pins = deserializeSettlementPins(cached);
  const base = manifest.runtime?.baseValues;
  const structural = manifest.runtime?.structural;
  exact(base, ['bindingSats', 'minimumChangeSats', 'stateSats', 'verifierSats'], 'warm runtime base values');
  exact(structural, ['bindingLock', 'bindingRedeem', 'stateHelper', 'stateLock', 'stateUnlock', 'verifierLocks'], 'warm runtime structural artifacts');
  if (base.minimumChangeSats !== '546' || !Array.isArray(base.verifierSats)
    || base.verifierSats.length !== pins.verifierCarriers.length
    || canonicalizeJcs(base.verifierSats) !== canonicalizeJcs(pins.verifierCarriers.map((entry) => entry.baseValueSats))
    || base.bindingSats !== pins.bindingBaseSats || base.stateSats !== pins.stateBaseSats
    || !Array.isArray(structural.verifierLocks) || structural.verifierLocks.length !== pins.verifierCarriers.length) {
    fail('BETA_RUNTIME_CACHE_INVALID', 'warm runtime settlement values differ from the authenticated cache');
  }
  const refs = Object.freeze({
    bindingLock: relativeArtifact(runtime, structural.bindingLock, 'warm binding lock'),
    bindingRedeem: relativeArtifact(runtime, structural.bindingRedeem, 'warm binding redeem'),
    stateHelper: relativeArtifact(runtime, structural.stateHelper, 'warm state helper'),
    stateLock: relativeArtifact(runtime, structural.stateLock, 'warm state lock'),
    stateUnlock: relativeArtifact(runtime, structural.stateUnlock, 'warm state unlock'),
    verifierLocks: structural.verifierLocks.map((entry, index) => relativeArtifact(runtime, entry, `warm verifier lock ${index}`)),
  });
  const [bindingLock, bindingRedeem, stateHelper, stateLock, stateUnlock, verifierLocks] = await Promise.all([
    readPinnedArtifact(refs.bindingLock, 'warm binding lock'),
    readPinnedArtifact(refs.bindingRedeem, 'warm binding redeem'),
    readPinnedArtifact(refs.stateHelper, 'warm state helper'),
    readPinnedArtifact(refs.stateLock, 'warm state lock'),
    readPinnedArtifact(refs.stateUnlock, 'warm state unlock'),
    Promise.all(refs.verifierLocks.map((entry, index) => readPinnedArtifact(entry, `warm verifier lock ${index}`))),
  ]);
  if (!bindingLock.equals(Buffer.from(pins.bindingLockingBytecode))
    || !bindingRedeem.equals(Buffer.from(pins.bindingRedeemBytecode))
    || !stateHelper.equals(Buffer.from(pins.stateHelperBytecode))
    || !stateLock.equals(Buffer.from(pins.stateLockingBytecode))
    || !stateUnlock.equals(Buffer.from(pins.stateUnlockingBytecode))
    || !stateUnlock.equals(Buffer.from(rawMaterial.stateUnlockingBytecode))
    || !bindingLock.equals(Buffer.from(rawMaterial.bindingLockingBytecode))
    || !bindingRedeem.equals(Buffer.from(rawMaterial.bindingRedeemBytecode))
    || verifierLocks.some((entry, index) => !entry.equals(Buffer.from(pins.verifierCarriers[index].lockingBytecode))
      || !entry.equals(Buffer.from(rawMaterial.verifierLockingBytecodes[index])))) {
    fail('BETA_RUNTIME_CACHE_INVALID', 'warm runtime structural bytes differ from authenticated pins');
  }
  return pins;
}

/** Perform the expensive verifier once and atomically install its compact cache. */
export async function installV2BetaChipnetRuntimeCache({
  allowedOutputRoot, runtimeDirectory, temporaryRoot, cacheRoot,
} = {}) {
  const root = await assertPrivateDirectory(cacheRoot, 'cache root');
  let installed;
  const verification = await verifyV2Pf10BetaRuntime({
    ...(allowedOutputRoot === undefined ? {} : { allowedOutputRoot }),
    outputDirectory: runtimeDirectory,
    temporaryRoot,
    onVerifiedRuntime: async ({ manifest, manifestSha256, runtimeMaterialInput, runtimeMaterialSha256 }) => {
      const settlementPins = await settlementPinsFromVerifiedRuntime(
        runtimeDirectory,
        manifest,
        runtimeMaterialInput,
      );
      const cache = cacheValue({
        manifest,
        manifestSha256,
        material: runtimeMaterialInput,
        materialSha256: runtimeMaterialSha256,
        settlementPins,
        sourceSha256: await sourceFingerprint(),
      });
      installed = Object.freeze({
        ...await writeCache(root, cache),
        runtimeSourceSha256: cache.runtimeSourceSha256,
      });
    },
  });
  if (installed === undefined) fail('BETA_RUNTIME_CACHE_INVALID', 'full runtime verification did not install a cache');
  return Object.freeze({ ...installed, verification });
}

/** Load a verified cache without compiler, optimizer, reproduction, or fallback. */
export async function loadV2BetaChipnetRuntimeCache({
  runtimeDirectory, cacheRoot,
} = {}) {
  const { runtime, manifest } = await currentRuntimeManifest(runtimeDirectory);
  const root = await assertPrivateDirectory(cacheRoot, 'cache root');
  const runtimeSourceSha256 = await sourceFingerprint();
  const cacheDirectory = path.join(root, cacheDirectoryName(
    manifest.sha256,
    runtimeSourceSha256,
  ));
  await assertPrivateDirectory(cacheDirectory, 'beta runtime cache directory');
  const cacheEntries = await readdir(cacheDirectory);
  if (cacheEntries.length !== 1 || cacheEntries[0] !== V2_BETA_CHIPNET_RUNTIME_CACHE_FILE) {
    fail('BETA_RUNTIME_CACHE_INVALID', 'beta runtime cache has unexpected entries');
  }
  const cacheFile = await readPrivateCanonicalJson(
    path.join(cacheDirectory, V2_BETA_CHIPNET_RUNTIME_CACHE_FILE),
    'beta runtime cache',
  );
  const cache = validateCache(cacheFile.value);
  if (cache.runtimeManifestSha256 !== manifest.sha256) {
    fail('BETA_RUNTIME_CACHE_STALE', 'cache is not bound to this exact runtime manifest');
  }
  if (cache.runtimeSourceSha256 !== runtimeSourceSha256) {
    fail('BETA_RUNTIME_CACHE_STALE', 'cache was built by different runtime source inputs');
  }
  const raw = deserializeMaterial(cache.material);
  const material = validateDirectV2Pf10BetaRuntimeMaterial(raw);
  if (material.materialSha256 !== cache.runtimeMaterialSha256
    || manifest.value.runtime?.materialSha256 !== material.materialSha256) {
    fail('BETA_RUNTIME_CACHE_INVALID', 'cached material does not equal the runtime manifest commitment');
  }
  const profileReference = relativeArtifact(runtime, manifest.value.profile?.profileCore, 'profile core');
  const packageReference = relativeArtifact(runtime, manifest.value.profile?.betaProfilePackage, 'beta profile package');
  const [profileFile, packageFile] = await Promise.all([
    readPrivateCanonicalJson(profileReference.filename, 'profile core'),
    readPrivateCanonicalJson(packageReference.filename, 'beta profile package'),
  ]);
  validateProfileCore(profileFile.value);
  const profilePackage = validateV2BetaLocalProfilePackage(packageFile.value, profileFile.value);
  const profileId = deriveProfileId(profileFile.value);
  if (profileId !== cache.identity.profileId || profilePackage.profileId !== profileId
    || manifest.value.profile?.profileId !== profileId
    || manifest.value.identity?.instanceId !== cache.identity.instanceId
    || manifest.value.identity?.maximumLiveNotes !== cache.identity.maximumLiveNotes
    || manifest.value.identity?.denominationSats !== cache.identity.denominationSats) {
    fail('BETA_RUNTIME_CACHE_INVALID', 'cache, profile, and runtime manifest identities differ');
  }
  const proofArtifacts = Object.fromEntries(await Promise.all(
    Object.entries(cache.proofArtifacts).map(async ([name, reference]) => {
      const manifestReference = relativeArtifact(runtime, manifest.value.proofArtifacts?.[name], `runtime proof ${name}`);
      const cachedReference = relativeArtifact(runtime, reference, `cache proof ${name}`);
      const { filename: _manifestFilename, ...manifestPinned } = manifestReference;
      const { filename: _cachedFilename, ...cachedPinned } = cachedReference;
      if (canonicalizeJcs(manifestPinned) !== canonicalizeJcs(cachedPinned)) {
        fail('BETA_RUNTIME_CACHE_INVALID', `cache proof ${name} differs from runtime manifest`);
      }
      await assertPinnedArtifactPath(cachedReference, `cache proof ${name}`);
      return [name, Object.freeze({ path: cachedReference.filename, sha256: cachedReference.sha256 })];
    }),
  ));
  const vk = await readPrivateCanonicalJson(proofArtifacts.verificationKey.path, 'verification key');
  if (vk.sha256 !== material.proofArtifactHashes.verificationKey) {
    fail('BETA_RUNTIME_CACHE_INVALID', 'cached verification key differs from runtime material pin');
  }
  const settlementPins = await warmSettlementPins(
    runtime,
    manifest.value,
    raw,
    cache.settlementPins,
  );
  const loaded = Object.freeze({
    identity: Object.freeze({ ...cache.identity }),
    // This value is re-read from the pinned runtime artifact and validated
    // above. It remains private input to the higher-level branded resolution;
    // it is never trusted from the serialized compact cache.
    profileCore: copyCanonicalJson(profileFile.value),
    runtimeManifestSha256: manifest.sha256,
    proofArtifacts: Object.freeze(proofArtifacts),
    runtimeMaterial: material,
    runtimeMaterialSha256: material.materialSha256,
    // Retain this validator-authenticated bytecode only inside the process-local
    // loaded capability. It is needed to issue the genesis runtime without a
    // second PF10 compilation, and is never accepted from the compact cache as
    // an unvalidated public field.
    stateUnlockingBytecode: Buffer.from(raw.stateUnlockingBytecode),
    settlementPins,
  });
  LOADED_RUNTIME_CACHES.add(loaded);
  return loaded;
}

export const V2_BETA_LINKED_RUNTIME_CACHE_SCHEMA =
  'shieldkit-v2-direct-pf10-beta-linked-runtime-cache-v1';
const V2_BETA_LINKED_RUNTIME_CACHE_FILE = 'beta-linked-runtime-cache.json';
const LINKED_RUNTIME_CACHES = new WeakSet();

function linkedCacheName(cache) {
  return sha256(canonicalBytes({
    installationReceiptSha256: cache.installationReceiptSha256,
    instanceId: cache.identity.instanceId,
    runtimeMaterialSha256: cache.runtimeMaterialSha256,
    runtimeSourceSha256: cache.runtimeSourceSha256,
  }));
}

function linkedCacheValue({ template, specialized, sourceSha256 }) {
  const raw = specialized.runtimeMaterialInput;
  const material = validateDirectV2Pf10BetaRuntimeMaterial(raw);
  if (specialized.instanceId !== material.instanceId
    || specialized.profileId !== template.identity.profileId
    || material.profileId !== template.identity.profileId
    || material.materialSha256 !== specialized.runtimeMaterial.materialSha256) {
    fail('BETA_LINKED_RUNTIME_CACHE_INVALID', 'specialized runtime identity or material is not exact');
  }
  const pins = Object.freeze({
    topologyId: material.topologyId,
    verifierRoles: material.verifierRoles,
    verifierCarriers: specialized.structural.verifierLocks.map((lockingBytecode, index) => Object.freeze({ baseValueSats: specialized.baseValues.verifierSats[index], lockingBytecode })),
    bindingBaseSats: specialized.baseValues.bindingSats,
    bindingLockingBytecode: specialized.structural.bindingLock,
    bindingRedeemBytecode: specialized.structural.bindingRedeem,
    stateBaseSats: specialized.baseValues.stateSats,
    stateHelperBytecode: specialized.structural.stateHelper,
    stateLockingBytecode: specialized.structural.stateLock,
    stateUnlockingBytecode: specialized.structural.stateUnlock,
  });
  const serializedPins = serializeSettlementPins(pins);
  return Object.freeze({
    schema: V2_BETA_LINKED_RUNTIME_CACHE_SCHEMA,
    status: 'linked-runtime-cache-unqualified',
    eligibility: V2_BETA_LOCAL_ELIGIBILITY,
    claims: V2_BETA_LOCAL_FALSE_CLAIMS,
    installationReceiptSha256: template.installationReceiptSha256,
    genericRuntimeManifestSha256: template.templateRuntimeManifestSha256,
    runtimeSourceSha256: sourceSha256,
    runtimeMaterialSha256: material.materialSha256,
    identity: Object.freeze({ ...template.identity, instanceId: material.instanceId }),
    proofArtifacts: Object.freeze(Object.fromEntries(Object.entries(template.proofArtifacts).map(([name, entry]) => [name, Object.freeze({ ...entry })]))),
    material: Object.freeze(serializeMaterial(raw)),
    settlementPins: serializedPins,
  });
}

function validateLinkedCache(value) {
  exact(value, [
    'claims', 'eligibility', 'genericRuntimeManifestSha256', 'identity',
    'installationReceiptSha256', 'material', 'proofArtifacts', 'runtimeMaterialSha256',
    'runtimeSourceSha256', 'schema', 'settlementPins', 'status',
  ], 'linked runtime cache');
  if (value.schema !== V2_BETA_LINKED_RUNTIME_CACHE_SCHEMA
    || value.status !== 'linked-runtime-cache-unqualified'
    || value.eligibility !== V2_BETA_LOCAL_ELIGIBILITY) {
    fail('BETA_LINKED_RUNTIME_CACHE_INVALID', 'linked runtime cache boundary is invalid');
  }
  exactClaims(value.claims, 'linked runtime cache claims');
  for (const name of ['installationReceiptSha256', 'genericRuntimeManifestSha256', 'runtimeMaterialSha256', 'runtimeSourceSha256']) hash(value[name], `linked runtime cache ${name}`);
  exact(value.identity, ['denominationSats', 'instanceId', 'maximumLiveNotes', 'profileId'], 'linked runtime cache identity');
  if (value.identity.maximumLiveNotes !== '100000' || value.identity.denominationSats !== '10000000') fail('BETA_LINKED_RUNTIME_CACHE_INVALID', 'linked runtime cache capacity is not exactly 100000');
  hash(value.identity.instanceId, 'linked runtime cache instanceId'); hash(value.identity.profileId, 'linked runtime cache profileId');
  exact(value.proofArtifacts, ['provingKey', 'r1cs', 'verificationKey', 'wasm'], 'linked runtime cache proof artifacts');
  for (const [name, entry] of Object.entries(value.proofArtifacts)) {
    exact(entry, ['bytes', 'identity', 'path', 'sha256'], `linked runtime cache proof ${name}`);
    if (!Number.isSafeInteger(entry.bytes) || entry.bytes <= 0 || typeof entry.path !== 'string') fail('BETA_LINKED_RUNTIME_CACHE_INVALID', `linked runtime cache proof ${name} is invalid`);
    hash(entry.sha256, `linked runtime cache proof ${name}`);
    exact(entry.identity, ['birthtimeNs', 'ctimeNs', 'dev', 'gid', 'ino', 'mode', 'mtimeNs', 'nlink', 'size', 'uid'], `linked runtime cache proof ${name} identity`);
    if (Object.values(entry.identity).some((field) => typeof field !== 'string' || !/^[0-9]+$/u.test(field))) fail('BETA_LINKED_RUNTIME_CACHE_INVALID', `linked runtime cache proof ${name} identity is invalid`);
  }
  deserializeSettlementPins(value.settlementPins);
  return value;
}

async function writeLinkedCache(cacheRoot, cache) {
  const root = await assertPrivateDirectory(cacheRoot, 'linked runtime cache root');
  const destination = path.join(root, linkedCacheName(cache));
  try {
    await lstat(destination);
    await assertPrivateDirectory(destination, 'existing linked runtime cache directory');
    const entries = await readdir(destination);
    if (entries.length !== 1 || entries[0] !== V2_BETA_LINKED_RUNTIME_CACHE_FILE) fail('BETA_LINKED_RUNTIME_CACHE_INVALID', 'existing linked runtime cache has unexpected entries');
    const existing = await readPrivateCanonicalJson(path.join(destination, V2_BETA_LINKED_RUNTIME_CACHE_FILE), 'existing linked runtime cache');
    if (canonicalizeJcs(validateLinkedCache(existing.value)) !== canonicalizeJcs(cache)) fail('BETA_LINKED_RUNTIME_CACHE_EXISTS', 'existing linked runtime cache differs from the asserted specialization');
    return Object.freeze({ cacheDirectory: destination, cacheSha256: existing.sha256, installed: false });
  } catch (error) {
    if (error instanceof V2BetaChipnetRuntimeCacheError) throw error;
    if (error?.code !== 'ENOENT') throw error;
  }
  const stage = await mkdtemp(path.join(root, '.beta-linked-runtime-cache-stage-'));
  try {
    await chmod(stage, 0o700);
    const filename = path.join(stage, V2_BETA_LINKED_RUNTIME_CACHE_FILE);
    const handle = await open(filename, 'wx', 0o600);
    try { await handle.writeFile(canonicalBytes(cache)); await handle.sync(); } finally { await handle.close(); }
    const stageHandle = await open(stage, fsConstants.O_RDONLY); try { await stageHandle.sync(); } finally { await stageHandle.close(); }
    await rename(stage, destination);
    const rootHandle = await open(root, fsConstants.O_RDONLY); try { await rootHandle.sync(); } finally { await rootHandle.close(); }
    return Object.freeze({ cacheDirectory: destination, cacheSha256: sha256(canonicalBytes(cache)), installed: true });
  } catch (error) { await rm(stage, { recursive: true, force: true }).catch(() => undefined); throw error; }
}

/** Install from an opaque native-specializer assertion, never from a lookalike. */
export async function installV2BetaLinkedRuntimeCache({ artifactInstallation, cacheRoot, specializedRuntime, assertSpecializedRuntime } = {}) {
  if (typeof assertSpecializedRuntime !== 'function') fail('BETA_LINKED_RUNTIME_CACHE_CAPABILITY_REQUIRED', 'linked runtime cache install requires the native specialized-runtime assertion');
  const installation = assertV2BetaProductArtifactInstallationCapability(artifactInstallation);
  const template = await deriveV2BetaProductLinkedRuntimeTemplate(installation);
  const specialized = assertSpecializedRuntime(specializedRuntime);
  const cache = linkedCacheValue({ template, specialized, sourceSha256: await sourceFingerprint() });
  const written = await writeLinkedCache(cacheRoot, cache);
  return Object.freeze({ ...written, installationReceiptSha256: cache.installationReceiptSha256, runtimeMaterialSha256: cache.runtimeMaterialSha256 });
}

/** Load a compact linked cache and re-issue only a fresh process-local capability. */
export async function loadV2BetaLinkedRuntimeCache({ artifactInstallation, cacheRoot, instanceId } = {}) {
  const installation = assertV2BetaProductArtifactInstallationCapability(artifactInstallation);
  const template = await deriveV2BetaProductLinkedRuntimeTemplate(installation);
  if (typeof instanceId !== 'string' || !HASH.test(instanceId)) fail('BETA_LINKED_RUNTIME_CACHE_INVALID', 'linked runtime cache instance must be exact lowercase 32-byte hex');
  const sourceSha256 = await sourceFingerprint();
  const root = await assertPrivateDirectory(cacheRoot, 'linked runtime cache root');
  // Cache names include the material hash, so select only a single private
  // candidate by parsing compact cache records rather than guessing a hash.
  const candidates = await readdir(root, { withFileTypes: true });
  const matches = [];
  for (const candidate of candidates) {
    if (!candidate.isDirectory() || candidate.name.startsWith('.')) continue;
    const directory = await assertPrivateDirectory(path.join(root, candidate.name), 'linked runtime cache directory');
    const entries = await readdir(directory);
    if (entries.length !== 1 || entries[0] !== V2_BETA_LINKED_RUNTIME_CACHE_FILE) continue;
    const record = await readPrivateCanonicalJson(path.join(directory, V2_BETA_LINKED_RUNTIME_CACHE_FILE), 'linked runtime cache');
    const cache = validateLinkedCache(record.value);
    if (cache.installationReceiptSha256 === template.installationReceiptSha256 && cache.identity.instanceId === instanceId) matches.push({ cache, record });
  }
  if (matches.length !== 1) fail('BETA_LINKED_RUNTIME_CACHE_UNAVAILABLE', 'exactly one linked runtime cache is required');
  const { cache, record } = matches[0];
  if (cache.runtimeSourceSha256 !== sourceSha256 || cache.genericRuntimeManifestSha256 !== template.templateRuntimeManifestSha256
    || canonicalizeJcs({ ...cache.identity, instanceId: template.identity.instanceId }) !== canonicalizeJcs(template.identity)
    || canonicalizeJcs(cache.proofArtifacts) !== canonicalizeJcs(template.proofArtifacts)) fail('BETA_LINKED_RUNTIME_CACHE_STALE', 'linked runtime cache is not bound to this artifact installation');
  const raw = deserializeMaterial(cache.material); const material = validateDirectV2Pf10BetaRuntimeMaterial(raw);
  if (material.materialSha256 !== cache.runtimeMaterialSha256 || material.instanceId !== instanceId || material.profileId !== template.identity.profileId) fail('BETA_LINKED_RUNTIME_CACHE_INVALID', 'linked runtime material differs from cache identity');
  const pins = deserializeSettlementPins(cache.settlementPins);
  if (!Buffer.from(pins.bindingLockingBytecode).equals(Buffer.from(raw.bindingLockingBytecode))
    || !Buffer.from(pins.bindingRedeemBytecode).equals(Buffer.from(raw.bindingRedeemBytecode))
    || !Buffer.from(pins.stateUnlockingBytecode).equals(Buffer.from(raw.stateUnlockingBytecode))
    || pins.verifierCarriers.some((entry, index) => !Buffer.from(entry.lockingBytecode).equals(Buffer.from(raw.verifierLockingBytecodes[index])))) fail('BETA_LINKED_RUNTIME_CACHE_INVALID', 'linked runtime structural pins differ from compact material');
  const loaded = Object.freeze({ identity: Object.freeze({ ...cache.identity }), profileCore: template.profileCore, runtimeManifestSha256: cache.genericRuntimeManifestSha256, installationReceiptSha256: cache.installationReceiptSha256, proofArtifactIdentities: Object.freeze(Object.fromEntries(Object.entries(cache.proofArtifacts).map(([name, entry]) => [name, Object.freeze({ ...entry.identity })]))), proofArtifacts: Object.freeze(Object.fromEntries(Object.entries(template.proofArtifacts).map(([name, entry]) => [name, Object.freeze({ path: path.join(installation.installationDirectory, ...entry.path.split('/')), sha256: entry.sha256 })]))), runtimeMaterial: material, runtimeMaterialSha256: material.materialSha256, settlementPins: pins, cacheSha256: record.sha256 });
  LINKED_RUNTIME_CACHES.add(loaded); return loaded;
}

export function assertLoadedV2BetaLinkedRuntimeCache(value) {
  if (!LINKED_RUNTIME_CACHES.has(value)) fail('BETA_LINKED_RUNTIME_CACHE_CAPABILITY_REQUIRED', 'a locally loaded linked runtime cache capability is required');
  return value;
}

/**
 * Require a process-local capability issued only by the verified warm-cache
 * loader. Structural lookalikes cannot enter the product action lane.
 */
export function assertLoadedV2BetaChipnetRuntimeCache(value) {
  if (!LOADED_RUNTIME_CACHES.has(value)) {
    fail(
      'BETA_RUNTIME_CACHE_CAPABILITY_REQUIRED',
      'a capability returned by loadV2BetaChipnetRuntimeCache is required',
    );
  }
  return value;
}
