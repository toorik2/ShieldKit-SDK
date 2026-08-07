/**
 * Instance-home binding.  A home is private, canonical and immutable at
 * publication time.  It is not a convenience config file: it binds a local
 * instance to one exact, authority-backed profile.
 */

import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  rmSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

import {
  assertBackendId,
  assertProfileId,
  assertInstanceId,
  assertHomeId,
  newHomeId,
  NETWORKS,
} from '../contracts/identity.mjs';
import { ERROR_CODES, cliFail } from '../contracts/errors.mjs';
import { loadClosedCatalog, resolveAliasSafe } from './catalog-bridge.mjs';

export const HOME_SCHEMA = 'shieldkit-home/v1';

const HOME_KEYS = Object.freeze([
  'backendApiVersion', 'backendId', 'createdAt', 'designId', 'genesisDescriptorHash',
  'homeId', 'instanceId', 'labOptIn', 'network', 'networkGenesis', 'profileId', 'schema', 'source',
  'toolkitVersion',
]);
const HEX64 = /^[0-9a-f]{64}$/;

function homeFail(message, details = null) {
  cliFail(ERROR_CODES.HOME_NOT_FOUND, message, details ? { details } : undefined);
}

function absoluteHomePath(value) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) {
    homeFail('home path must be a non-empty path without NUL');
  }
  return path.resolve(value);
}

function ownUid(stat) {
  return typeof process.getuid !== 'function' || stat.uid === process.getuid();
}

function assertNoSymlinkAncestors(target) {
  const abs = path.resolve(target);
  const root = path.parse(abs).root;
  const parts = abs.slice(root.length).split(path.sep).filter(Boolean);
  let current = root;
  for (const part of parts) {
    current = path.join(current, part);
    try {
      const stat = lstatSync(current);
      if (stat.isSymbolicLink()) homeFail(`symlink path component is forbidden: ${current}`);
    } catch (error) {
      if (error?.code === 'ENOENT') return;
      if (error instanceof Error && error.code === ERROR_CODES.HOME_NOT_FOUND) throw error;
      homeFail(`cannot inspect home path component: ${current}`);
    }
  }
}

function assertPrivateDirectory(directory, { create = false } = {}) {
  const abs = absoluteHomePath(directory);
  assertNoSymlinkAncestors(path.dirname(abs));
  if (create) mkdirSync(abs, { recursive: true, mode: 0o700 });
  let stat;
  try { stat = lstatSync(abs); }
  catch { homeFail(`home directory is unavailable: ${abs}`); }
  if (!stat.isDirectory() || stat.isSymbolicLink() || !ownUid(stat) || (stat.mode & 0o077) !== 0) {
    homeFail(`home directory must be an owner-controlled private non-symlink directory: ${abs}`);
  }
  return abs;
}

function assertPrivateFile(filename, label = 'home manifest') {
  const abs = path.resolve(filename);
  assertNoSymlinkAncestors(path.dirname(abs));
  let stat;
  try { stat = lstatSync(abs); }
  catch { homeFail(`${label} is unavailable: ${abs}`); }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || !ownUid(stat) || (stat.mode & 0o077) !== 0) {
    homeFail(`${label} must be an owner-controlled private single-link regular file: ${abs}`);
  }
  return stat;
}

function readPrivateJson(filename, label) {
  const linked = assertPrivateFile(filename, label);
  let fd;
  try {
    fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || !ownUid(opened) || (opened.mode & 0o077) !== 0
      || opened.ino !== linked.ino || opened.dev !== linked.dev) {
      homeFail(`${label} changed while opening`);
    }
    return JSON.parse(readFileSync(fd, 'utf8'));
  } catch (error) {
    if (error?.code === ERROR_CODES.HOME_NOT_FOUND) throw error;
    homeFail(`${label} is not valid private JSON: ${filename}`);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function assertExactObject(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) {
    homeFail(`${label} must be a plain JSON object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    homeFail(`${label} has missing or unknown fields`);
  }
  return value;
}

function validateManifest(raw) {
  assertExactObject(raw, HOME_KEYS, 'home.json');
  if (raw.schema !== HOME_SCHEMA || raw.backendApiVersion !== 1) homeFail('home.json has an unsupported schema or backend API version');
  if (Object.hasOwn(raw, 'tip') || Object.hasOwn(raw, 'path')) {
    homeFail('home.json may not store a tip or caller-controlled path');
  }
  if (typeof raw.designId !== 'string' || raw.designId.length === 0
    || raw.network !== NETWORKS.chipnet.networkId
    || raw.networkGenesis !== NETWORKS.chipnet.genesisHash
    || typeof raw.createdAt !== 'string' || !Number.isFinite(Date.parse(raw.createdAt))
    || (raw.toolkitVersion !== null && (typeof raw.toolkitVersion !== 'string' || raw.toolkitVersion.length === 0))
    || typeof raw.genesisDescriptorHash !== 'string' || !HEX64.test(raw.genesisDescriptorHash)
    || typeof raw.instanceId !== 'string' || !HEX64.test(raw.instanceId)
    || typeof raw.labOptIn !== 'boolean' || raw.source !== null) {
    homeFail('home.json has invalid immutable fields');
  }
  const catalog = loadClosedCatalog();
  const catalogDesign = catalog.designs.find((design) => design.id === raw.designId);
  if (!catalogDesign || catalogDesign.backendId !== raw.backendId
    || catalogDesign.backendApiVersion !== raw.backendApiVersion
    || catalogDesign.network !== raw.network) {
    homeFail('home.json does not bind an exact closed-catalog design/backend/API');
  }
  if (catalogDesign.profileStatus === 'unfrozen') {
    homeFail(`home.json may not bind unfrozen design ${raw.designId}`);
  }
  return Object.freeze({
    schema: HOME_SCHEMA,
    homeId: assertHomeId(raw.homeId),
    backendId: assertBackendId(raw.backendId),
    backendApiVersion: 1,
    profileId: assertProfileId(raw.profileId),
    designId: raw.designId,
    instanceId: assertInstanceId(raw.instanceId),
    network: raw.network,
    networkGenesis: raw.networkGenesis,
    genesisDescriptorHash: raw.genesisDescriptorHash,
    createdAt: raw.createdAt,
    toolkitVersion: raw.toolkitVersion,
    labOptIn: raw.labOptIn,
    source: null,
  });
}

/** Read and validate an existing home without following symlinks. */
export function readHomeManifest(homePath) {
  const abs = assertPrivateDirectory(homePath);
  const manifestPath = path.join(abs, 'home.json');
  if (!existsSync(manifestPath)) return null;
  const manifest = validateManifest(readPrivateJson(manifestPath, 'home manifest'));
  // Computed values are last, so raw JSON can never override them.
  return Object.freeze({ ...manifest, path: abs, manifestPath });
}

/** Resolve a CLI context; every supplied selector is an exact assertion. */
export function resolveHomeContext({
  homePath = null,
  design = null,
  profile = null,
  defaultHome = null,
  requireHome = false,
} = {}) {
  const candidate = homePath || defaultHome || null;
  let home = null;
  if (candidate) {
    const abs = absoluteHomePath(candidate);
    assertNoSymlinkAncestors(abs);
    const manifestPath = path.join(abs, 'home.json');
    if (existsSync(manifestPath)) {
      home = readHomeManifest(abs);
    } else if (requireHome) {
      cliFail(ERROR_CODES.HOME_NOT_FOUND, `home not found at ${abs}`);
    } else if (existsSync(abs) && isLegacyDataHome(abs)) {
      cliFail(
        ERROR_CODES.LEGACY_DATA_HOME_NOT_AUTO,
        `path looks like legacy PF10 --data-home; migration requires a validated PF10 migration receipt: ${abs}`,
      );
    }
  }

  const exactProfile = typeof profile === 'string' && HEX64.test(profile) ? profile : null;
  const selectedDesign = design ? resolveAliasSafe(design) : (profile && !exactProfile ? resolveAliasSafe(profile) : null);
  if (design && profile && !exactProfile) {
    const profileDesign = resolveAliasSafe(profile);
    if (selectedDesign.id !== profileDesign.id) {
      cliFail(ERROR_CODES.HOME_DESIGN_MISMATCH, '--design and --profile select different designs');
    }
  }
  const resolvedDesign = exactProfile
    ? Object.freeze({ ...(selectedDesign || {}), id: selectedDesign?.id ?? null, backendId: selectedDesign?.backendId ?? null, profileId: exactProfile, profileStatus: 'frozen' })
    : selectedDesign;

  if (home && resolvedDesign) {
    if (resolvedDesign.profileStatus === 'unfrozen') {
      cliFail(ERROR_CODES.HOME_PROFILE_MISMATCH, `design ${resolvedDesign.id} has no frozen profile identity and cannot open an exact home`);
    }
    // A family alias (e.g. PF10) is not an exact profile selector. The home
    // supplies the pin; any supplied exact profile remains an assertion.
    if (resolvedDesign.profileId !== null && resolvedDesign.profileId !== undefined && home.profileId !== resolvedDesign.profileId) {
      cliFail(
        ERROR_CODES.HOME_PROFILE_MISMATCH,
        `home profile ${home.profileId} conflicts with requested profile ${resolvedDesign.profileId}`,
      );
    }
    if ((resolvedDesign.backendId !== null && resolvedDesign.backendId !== undefined && home.backendId !== resolvedDesign.backendId)
      || (resolvedDesign.id !== null && resolvedDesign.id !== undefined && home.designId !== resolvedDesign.id)) {
      cliFail(ERROR_CODES.HOME_DESIGN_MISMATCH, `home design ${home.designId} conflicts with ${resolvedDesign.id}`);
    }
  }

  return Object.freeze({
    home,
    design: home
      ? Object.freeze({
        ...((resolvedDesign?.id ? resolvedDesign : null) || resolveDesignFromHome(home)),
        id: home.designId,
        profileId: home.profileId,
        profileStatus: 'frozen',
        backendId: home.backendId,
        instanceId: home.instanceId,
        homeId: home.homeId,
        network: home.network,
        networkGenesis: home.networkGenesis,
      })
      : resolvedDesign,
    homeWins: Boolean(home),
  });
}

function resolveDesignFromHome(home) {
  const catalog = loadClosedCatalog();
  const hit = catalog.designs.find((d) => d.backendId === home.backendId && d.id === home.designId);
  return hit || Object.freeze({ id: home.designId, backendId: home.backendId, profileId: home.profileId, profileStatus: 'frozen', network: home.network });
}

/** Detect old data home only; it is never a migration authority. */
export function isLegacyDataHome(absPath) {
  const abs = absoluteHomePath(absPath);
  assertNoSymlinkAncestors(abs);
  if (existsSync(path.join(abs, 'home.json'))) return false;
  return existsSync(path.join(abs, 'session.json'))
    || existsSync(path.join(abs, 'shieldkit', 'v2-beta-product', 'session.json'))
    || existsSync(path.join(abs, 'v2-beta-product', 'session.json'));
}

export function findLegacySession(absPath) {
  const abs = absoluteHomePath(absPath);
  for (const candidate of [
    path.join(abs, 'session.json'),
    path.join(abs, 'v2-beta-product', 'session.json'),
    path.join(abs, 'shieldkit', 'v2-beta-product', 'session.json'),
  ]) {
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

function fsyncDirectory(directory) {
  let fd;
  try { fd = openSync(directory, constants.O_RDONLY); fsyncSync(fd); }
  finally { if (fd !== undefined) closeSync(fd); }
}

function writePrivateExclusive(filename, body, label) {
  let fd;
  try {
    fd = openSync(filename, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    writeSync(fd, body, undefined, 'utf8');
    fsyncSync(fd);
  } catch (error) {
    if (error?.code === 'EEXIST') homeFail(`${label} already exists and is immutable: ${filename}`);
    homeFail(`cannot exclusively publish ${label}: ${filename}`);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
  fsyncDirectory(path.dirname(filename));
}

/** Create a new immutable home binding. Existing manifests are never replaced. */
export function writeHomeManifest(homePath, {
  backendId,
  profileId,
  designId,
  instanceId,
  network = NETWORKS.chipnet.networkId,
  networkGenesis = NETWORKS.chipnet.genesisHash,
  toolkitVersion = null,
  genesisDescriptorHash,
  labOptIn = false,
  source = null,
} = {}) {
  if (source !== null) homeFail('home source metadata is not an identity authority; use a validated migration receipt');
  if (instanceId === null || instanceId === undefined || genesisDescriptorHash === null || genesisDescriptorHash === undefined) {
    homeFail('an immutable bound home requires an exact instanceId and accepted genesis descriptor hash');
  }
  const abs = assertPrivateDirectory(homePath, { create: true });
  for (const child of ['state', 'runtime', 'exports']) assertPrivateDirectory(path.join(abs, child), { create: true });
  const manifest = validateManifest({
    schema: HOME_SCHEMA,
    homeId: newHomeId(),
    backendId: assertBackendId(backendId),
    backendApiVersion: 1,
    profileId: assertProfileId(profileId),
    designId,
    instanceId: assertInstanceId(instanceId),
    network,
    networkGenesis,
    genesisDescriptorHash,
    createdAt: new Date().toISOString(),
    toolkitVersion,
    labOptIn: labOptIn === true,
    source: null,
  });
  const manifestPath = path.join(abs, 'home.json');
  writePrivateExclusive(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'home manifest');
  return readHomeManifest(abs);
}

const LEGACY_POINTER_SCHEMA = 'shieldkit-pf10-legacy-pointer/v1';
const LEGACY_POINTER_KEYS = Object.freeze([
  'backendId', 'designId', 'genesisDescriptorHash', 'genesisOutpoint', 'instanceId',
  'legacyDataHome', 'network', 'profileId', 'schema', 'sourceDataDirectory',
]);

function writeLegacyPointer(home, receipt) {
  const pointer = {
    schema: LEGACY_POINTER_SCHEMA,
    backendId: receipt.backendId,
    designId: receipt.designId,
    profileId: receipt.profileId,
    instanceId: receipt.instanceId,
    network: receipt.network,
    genesisDescriptorHash: receipt.genesisDescriptorHash,
    genesisOutpoint: receipt.genesisOutpoint,
    legacyDataHome: receipt.sourceDataHome,
    sourceDataDirectory: receipt.sourceDataDirectory,
  };
  assertExactObject(pointer, LEGACY_POINTER_KEYS, 'legacy migration pointer');
  const filename = path.join(home.path, 'runtime', 'legacy-pf10-pointer.json');
  writePrivateExclusive(filename, `${JSON.stringify(pointer, null, 2)}\n`, 'legacy PF10 pointer');
  return filename;
}

/**
 * Open the immutable PF10 bridge pointer and re-bind every identity field to
 * the already validated home. Adapter code must never parse this file itself.
 */
export function readLegacyPf10Pointer(home) {
  if (!home || typeof home !== 'object' || typeof home.path !== 'string') {
    homeFail('validated bound home required before reading a PF10 legacy pointer');
  }
  const filename = path.join(home.path, 'runtime', 'legacy-pf10-pointer.json');
  if (!existsSync(filename)) return null;
  const pointer = assertExactObject(readPrivateJson(filename, 'legacy PF10 pointer'), LEGACY_POINTER_KEYS, 'legacy PF10 pointer');
  if (pointer.schema !== LEGACY_POINTER_SCHEMA
    || pointer.backendId !== home.backendId
    || pointer.designId !== home.designId
    || pointer.profileId !== home.profileId
    || pointer.instanceId !== home.instanceId
    || pointer.network !== home.network
    || pointer.genesisDescriptorHash !== home.genesisDescriptorHash
    || pointer.genesisOutpoint === null || Array.isArray(pointer.genesisOutpoint)
    || typeof pointer.genesisOutpoint !== 'object'
    || Object.keys(pointer.genesisOutpoint).sort().join(',') !== 'txid,vout'
    || !HEX64.test(pointer.genesisOutpoint.txid)
    || pointer.genesisOutpoint.vout !== 0
    || typeof pointer.legacyDataHome !== 'string'
    || !path.isAbsolute(pointer.legacyDataHome)
    || path.normalize(pointer.legacyDataHome) !== pointer.legacyDataHome
    || typeof pointer.sourceDataDirectory !== 'string'
    || pointer.sourceDataDirectory !== path.join(pointer.legacyDataHome, 'shieldkit', 'v2-beta-product')) {
    homeFail('legacy PF10 pointer does not match the immutable home or deterministic product layout');
  }
  assertNoSymlinkAncestors(pointer.legacyDataHome);
  return Object.freeze({
    ...pointer,
    genesisOutpoint: Object.freeze({ ...pointer.genesisOutpoint }),
    path: filename,
  });
}

function destinationForMigration(value, source) {
  if (typeof value !== 'string' || value.length === 0) {
    cliFail(ERROR_CODES.MIGRATION_REQUIRED, 'pool import requires --home <new bound home>');
  }
  const destination = absoluteHomePath(value);
  if (destination === source) {
    cliFail(ERROR_CODES.MIGRATION_REQUIRED, 'new bound home must differ from the legacy PF10 data-home');
  }
  assertNoSymlinkAncestors(path.dirname(destination));
  return destination;
}

function createExclusiveMigrationDestination(destination) {
  try {
    // Claim the leaf before publication. This avoids treating a pre-existing
    // writable directory as a migration destination, and makes all later
    // O_EXCL file publication relative to a directory we just created.
    mkdirSync(destination, { mode: 0o700 });
  } catch (error) {
    if (error?.code === 'EEXIST') {
      cliFail(ERROR_CODES.MIGRATION_REQUIRED, `new bound home must not already exist: ${destination}`);
    }
    cliFail(ERROR_CODES.MIGRATION_REQUIRED, `cannot exclusively create new bound home: ${destination}`);
  }
  return assertPrivateDirectory(destination);
}

/**
 * Import exactly one committed PF10 beta data home into an immutable unified
 * home. The source stays untouched; the destination receives an immutable
 * pointer back to the validated legacy authority for reversible operations.
 */
export async function migrateFromLegacyDataHome({ dataHome, destHome, design, dryRun = false } = {}) {
  const src = absoluteHomePath(dataHome);
  if (!isLegacyDataHome(src)) cliFail(ERROR_CODES.MIGRATION_REQUIRED, `not a legacy PF10 data-home: ${src}`);
  const canonicalPf10 = resolveAliasSafe('pf10');
  if (design?.id !== canonicalPf10.id || design?.backendId !== canonicalPf10.backendId) {
    cliFail(ERROR_CODES.MIGRATION_REQUIRED, 'legacy data-home migration is PF10-only; --design must select PF10 exactly');
  }
  // Keep design/catalog listing data-only: load PF10 product authority only
  // for an explicit migration command.
  const { derivePf10LegacyMigrationReceipt } = await import('./pf10-context-bridge.mjs');
  const receipt = derivePf10LegacyMigrationReceipt({ dataHome: src, design: canonicalPf10 });
  const destination = destinationForMigration(destHome, src);
  if (dryRun === true) {
    return Object.freeze({
      dryRun: true,
      home: null,
      destination,
      receipt,
      sourcePreserved: true,
      networkMutated: false,
    });
  }
  const claimedDestination = createExclusiveMigrationDestination(destination);
  try {
    const home = writeHomeManifest(claimedDestination, {
      backendId: receipt.backendId,
      profileId: receipt.profileId,
      designId: receipt.designId,
      instanceId: receipt.instanceId,
      network: receipt.network,
      genesisDescriptorHash: receipt.genesisDescriptorHash,
    });
    const legacyPointerPath = writeLegacyPointer(home, receipt);
    // Re-open through the strict reader before reporting migration success.
    readLegacyPf10Pointer(home);
    return Object.freeze({
      dryRun: false,
      home,
      receipt,
      legacyPointerPath,
      sourcePreserved: true,
      networkMutated: false,
    });
  } catch (error) {
    // This directory was exclusively created above and has not been returned
    // to any caller. Roll back an incomplete publication rather than leave a
    // manifest without its authority pointer.
    rmSync(claimedDestination, { recursive: true, force: true });
    fsyncDirectory(path.dirname(claimedDestination));
    throw error;
  }
}

/** Single writer lock. No stale-lock deletion: recovery needs explicit operator action. */
export function acquireHomeLock(homePath) {
  const abs = assertPrivateDirectory(homePath);
  const runtime = assertPrivateDirectory(path.join(abs, 'runtime'), { create: true });
  const lockPath = path.join(runtime, 'home.lock');
  const token = randomUUID();
  try {
    writePrivateExclusive(lockPath, `${JSON.stringify({ schema: 'shieldkit-home-lock/v1', pid: process.pid, token, at: Date.now() })}\n`, 'home lock');
  } catch (error) {
    if (error?.code === ERROR_CODES.HOME_NOT_FOUND && existsSync(lockPath)) {
      cliFail(ERROR_CODES.LOCK_HELD, `home lock is already held: ${lockPath}`);
    }
    throw error;
  }
  return Object.freeze({
    token,
    lockPath,
    release() {
      try {
        const current = readPrivateJson(lockPath, 'home lock');
        if (current?.token !== token) return false;
        unlinkSync(lockPath);
        fsyncDirectory(runtime);
        return true;
      } catch {
        return false;
      }
    },
  });
}
