/**
 * Private, secret-free local session layout for the unqualified V2 beta lane.
 * This file records paths and public schema only: never keys, notes, witnesses,
 * proofs, transaction bytes, or delivery credentials.
 */
import { randomUUID } from 'node:crypto';
import { homedir } from 'node:os';
import {
  closeSync, constants as fsConstants, fsyncSync, fstatSync, lstatSync,
  linkSync, mkdirSync, openSync, readSync, realpathSync, unlinkSync,
  writeSync,
} from 'node:fs';
import path from 'node:path';

import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';
import { V2_BETA_PRODUCT_CONTEXT_CONFIG_SCHEMA } from './beta-product-context.mjs';

export const V2_BETA_PRODUCT_CONFIG_SCHEMA =
  'shieldkit-v2-beta-product-session-config-v1';
export const V2_BETA_PRODUCT_CONFIG_FILENAME = 'session.json';

export class V2BetaProductConfigError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'V2BetaProductConfigError';
    this.code = code;
  }
}

const fail = (code, message, options = undefined) => {
  throw new V2BetaProductConfigError(code, message, options);
};

function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('BETA_PRODUCT_CONFIG_INVALID', `${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail('BETA_PRODUCT_CONFIG_INVALID', `${label} has missing or unknown properties`);
  }
  return value;
}

function absolute(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value)
    || path.normalize(value) !== value || value.includes('\0')) {
    fail('BETA_PRODUCT_CONFIG_PATH_REJECTED', `${label} must be a normalized absolute path`);
  }
  return value;
}

function owned(stat, label) {
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
    fail('BETA_PRODUCT_CONFIG_PATH_REJECTED', `${label} is not owned by the current user`);
  }
}

function privateDirectory(value, label) {
  const directory = absolute(value, label);
  let stat;
  try { stat = lstatSync(directory); }
  catch (error) { fail('BETA_PRODUCT_CONFIG_PATH_REJECTED', `${label} is unavailable`, { cause: error }); }
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700) {
    fail('BETA_PRODUCT_CONFIG_PATH_REJECTED', `${label} must be a private 0700 directory`);
  }
  owned(stat, label);
  try {
    if (realpathSync(directory) !== directory) fail('BETA_PRODUCT_CONFIG_PATH_REJECTED', `${label} is not canonical`);
  } catch (error) {
    if (error instanceof V2BetaProductConfigError) throw error;
    fail('BETA_PRODUCT_CONFIG_PATH_REJECTED', `${label} cannot be canonicalized`, { cause: error });
  }
  return directory;
}

function trustedParentDirectory(value, label) {
  const directory = absolute(value, label);
  let stat;
  try { stat = lstatSync(directory); }
  catch (error) { fail('BETA_PRODUCT_CONFIG_PATH_REJECTED', `${label} is unavailable`, { cause: error }); }
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o022) !== 0) {
    fail('BETA_PRODUCT_CONFIG_PATH_REJECTED', `${label} must be an owner-controlled directory not writable by group or other users`);
  }
  owned(stat, label);
  if (realpathSync(directory) !== directory) {
    fail('BETA_PRODUCT_CONFIG_PATH_REJECTED', `${label} must be canonical`);
  }
  return directory;
}

function strictDescendant(child, parent, label) {
  const relative = path.relative(parent, child);
  if (relative === '' || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    fail('BETA_PRODUCT_CONFIG_PATH_REJECTED', `${label} escapes the private product data directory`);
  }
}

function privateFile(value, parent, label) {
  const filename = absolute(value, label);
  strictDescendant(filename, parent, label);
  if (path.dirname(filename) !== parent) fail('BETA_PRODUCT_CONFIG_PATH_REJECTED', `${label} must be directly below its private parent`);
  const stat = lstatSync(filename);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600) {
    fail('BETA_PRODUCT_CONFIG_PATH_REJECTED', `${label} must be a private 0600 single-link regular file`);
  }
  owned(stat, label);
  if (realpathSync(filename) !== filename) fail('BETA_PRODUCT_CONFIG_PATH_REJECTED', `${label} is not canonical`);
  return filename;
}

function defaultDataHome() {
  const xdg = process.env.XDG_DATA_HOME;
  if (xdg !== undefined && xdg !== '') return absolute(xdg, 'XDG_DATA_HOME');
  const home = absolute(homedir(), 'user home directory');
  return path.join(home, '.local', 'share');
}

function layoutForDataHome(dataHome) {
  const base = absolute(dataHome, 'dataHome');
  const dataDirectory = path.join(base, 'shieldkit', 'v2-beta-product');
  return Object.freeze({
    configPath: path.join(dataDirectory, V2_BETA_PRODUCT_CONFIG_FILENAME),
    config: Object.freeze({
      schema: V2_BETA_PRODUCT_CONFIG_SCHEMA,
      dataDirectory,
      deploymentDirectory: path.join(dataDirectory, 'deployment'),
      runtimeCacheRoot: path.join(dataDirectory, 'runtime-cache'),
      nativeProverDirectory: path.join(dataDirectory, 'v2-beta-product-artifacts', 'native'),
      proofWorkspaceDirectory: path.join(dataDirectory, 'proof-workspace'),
      storeDatabasePath: path.join(dataDirectory, 'store', 'pool.sqlite'),
      walletDatabasePath: path.join(dataDirectory, 'wallet', 'wallet.sqlite'),
      journalDatabasePath: path.join(dataDirectory, 'journal', 'delivery.sqlite'),
      poolCreateJournalDatabasePath: path.join(dataDirectory, 'journal', 'pool-create.sqlite'),
    }),
  });
}

/** Derive the deterministic XDG/home layout without reading unsafe shell expansions. */
export function deriveV2BetaProductDataLayout(value = {}) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).some((key) => key !== 'dataHome')) {
    fail('BETA_PRODUCT_CONFIG_INVALID', 'beta product data layout options has unknown properties');
  }
  const dataHome = value.dataHome === undefined ? defaultDataHome() : absolute(value.dataHome, 'dataHome');
  return layoutForDataHome(dataHome);
}

function createPrivateDirectory(directory, parent, label) {
  if (parent !== null) trustedParentDirectory(parent, `${label} parent`);
  try { mkdirSync(directory, { mode: 0o700 }); }
  catch (error) {
    if (error?.code !== 'EEXIST') fail('BETA_PRODUCT_CONFIG_PATH_REJECTED', `${label} cannot be created`, { cause: error });
  }
  return privateDirectory(directory, label);
}

function ensureLayoutDirectories(layout) {
  const dataHome = path.dirname(path.dirname(layout.config.dataDirectory));
  trustedParentDirectory(dataHome, 'dataHome');
  const shieldkit = createPrivateDirectory(path.dirname(layout.config.dataDirectory), dataHome, 'ShieldKit data directory');
  const root = createPrivateDirectory(layout.config.dataDirectory, shieldkit, 'product data directory');
  for (const [name, directory] of Object.entries({
    deploymentDirectory: layout.config.deploymentDirectory,
    runtimeCacheRoot: layout.config.runtimeCacheRoot,
    proofWorkspaceDirectory: layout.config.proofWorkspaceDirectory,
    storeDirectory: path.dirname(layout.config.storeDatabasePath),
    walletDirectory: path.dirname(layout.config.walletDatabasePath),
    journalDirectory: path.dirname(layout.config.journalDatabasePath),
  })) {
    strictDescendant(directory, root, name);
    createPrivateDirectory(directory, root, name);
  }
}

/** Validate an already-created config and every configured private path. */
export function validateV2BetaProductConfig(value) {
  exact(value, [
    'dataDirectory', 'deploymentDirectory', 'journalDatabasePath',
    'nativeProverDirectory', 'proofWorkspaceDirectory', 'runtimeCacheRoot',
    'poolCreateJournalDatabasePath', 'schema',
    'storeDatabasePath', 'walletDatabasePath',
  ], 'beta product session config');
  if (value.schema !== V2_BETA_PRODUCT_CONFIG_SCHEMA) {
    fail('BETA_PRODUCT_CONFIG_INVALID', 'beta product session config schema is unsupported');
  }
  const dataDirectory = privateDirectory(value.dataDirectory, 'dataDirectory');
  const directories = {};
  for (const name of [
    'deploymentDirectory', 'runtimeCacheRoot', 'proofWorkspaceDirectory',
  ]) {
    strictDescendant(absolute(value[name], name), dataDirectory, name);
    directories[name] = privateDirectory(value[name], name);
  }
  if (value.nativeProverDirectory !== path.join(dataDirectory, 'v2-beta-product-artifacts', 'native')) {
    fail('BETA_PRODUCT_CONFIG_PATH_REJECTED', 'nativeProverDirectory differs from the deterministic artifact-installation destination');
  }
  const artifactDirectory = path.dirname(value.nativeProverDirectory);
  strictDescendant(artifactDirectory, dataDirectory, 'nativeProverDirectory parent');
  try {
    privateDirectory(artifactDirectory, 'nativeProverDirectory parent');
    directories.nativeProverDirectory = privateDirectory(value.nativeProverDirectory, 'nativeProverDirectory');
  } catch (error) {
    if (error instanceof V2BetaProductConfigError && error.code === 'BETA_PRODUCT_CONFIG_PATH_REJECTED'
      && error.message === 'nativeProverDirectory parent is unavailable') {
      directories.nativeProverDirectory = absolute(value.nativeProverDirectory, 'nativeProverDirectory');
    } else throw error;
  }
  const databases = {};
  for (const name of [
    'storeDatabasePath', 'walletDatabasePath', 'journalDatabasePath',
    'poolCreateJournalDatabasePath',
  ]) {
    const filename = absolute(value[name], name);
    strictDescendant(filename, dataDirectory, name);
    privateDirectory(path.dirname(filename), `${name} parent`);
    databases[name] = filename;
  }
  return Object.freeze({ schema: value.schema, dataDirectory, ...directories, ...databases });
}

function readCanonicalConfig(configPath) {
  const filename = absolute(configPath, 'configPath');
  const parent = privateDirectory(path.dirname(filename), 'configPath parent');
  if (path.basename(filename) !== V2_BETA_PRODUCT_CONFIG_FILENAME) fail('BETA_PRODUCT_CONFIG_PATH_REJECTED', 'configPath filename is not canonical');
  let fd;
  try {
    fd = openSync(filename, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const before = fstatSync(fd);
    privateFile(filename, parent, 'configPath');
    if (!before.isFile() || before.nlink !== 1 || (before.mode & 0o777) !== 0o600) {
      fail('BETA_PRODUCT_CONFIG_PATH_REJECTED', 'configPath handle is not a private single-link file');
    }
    const bytes = Buffer.alloc(before.size);
    const read = readSync(fd, bytes, 0, bytes.length, 0);
    if (read !== bytes.length || fstatSync(fd).ino !== before.ino || fstatSync(fd).dev !== before.dev) {
      fail('BETA_PRODUCT_CONFIG_RACE', 'configPath changed while being read');
    }
    let parsed;
    try { parsed = JSON.parse(bytes.toString('utf8')); }
    catch (error) { fail('BETA_PRODUCT_CONFIG_INVALID', 'config is not JSON', { cause: error }); }
    if (!bytes.equals(Buffer.from(canonicalizeJcs(parsed), 'utf8'))) {
      fail('BETA_PRODUCT_CONFIG_INVALID', 'config must use exact canonical JCS bytes');
    }
    return parsed;
  } catch (error) {
    if (error instanceof V2BetaProductConfigError) throw error;
    fail('BETA_PRODUCT_CONFIG_PATH_REJECTED', 'config cannot be opened without following links', { cause: error });
  } finally { if (fd !== undefined) closeSync(fd); }
}

function writeCanonicalConfig(configPath, config) {
  const parent = privateDirectory(path.dirname(configPath), 'configPath parent');
  const bytes = Buffer.from(canonicalizeJcs(config), 'utf8');
  const temporary = path.join(parent, `.${V2_BETA_PRODUCT_CONFIG_FILENAME}.${randomUUID()}.tmp`);
  let fd;
  try {
    fd = openSync(temporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    if (writeSync(fd, bytes) !== bytes.length) fail('BETA_PRODUCT_CONFIG_WRITE_FAILED', 'config write was incomplete');
    fsyncSync(fd);
    closeSync(fd); fd = undefined;
    // link(2) publishes a fully fsynced same-directory inode without rename's
    // replacement semantics. Exactly one concurrent creator can win; all
    // others receive EEXIST and must validate the winner's canonical config.
    try { linkSync(temporary, configPath); }
    catch (error) {
      if (error?.code === 'EEXIST') fail('BETA_PRODUCT_CONFIG_EXISTS', 'config already exists');
      throw error;
    }
    unlinkSync(temporary);
    const directoryFd = openSync(parent, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
    try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
  } catch (error) {
    try { if (fd !== undefined) closeSync(fd); } catch {}
    try { unlinkSync(temporary); } catch {}
    if (error instanceof V2BetaProductConfigError) throw error;
    fail('BETA_PRODUCT_CONFIG_WRITE_FAILED', 'config creation failed', { cause: error });
  }
}

/** Create the fixed private layout and atomically write its secret-free config once. */
export function createV2BetaProductConfig(value = {}) {
  const layout = deriveV2BetaProductDataLayout(value);
  ensureLayoutDirectories(layout);
  writeCanonicalConfig(layout.configPath, layout.config);
  const loaded = validateV2BetaProductConfig(readCanonicalConfig(layout.configPath));
  return Object.freeze({ configPath: layout.configPath, config: loaded });
}

/** Load the deterministic config through one O_NOFOLLOW file handle. */
export function loadV2BetaProductConfig(value = {}) {
  const layout = deriveV2BetaProductDataLayout(value);
  const config = validateV2BetaProductConfig(readCanonicalConfig(layout.configPath));
  if (config.dataDirectory !== layout.config.dataDirectory) {
    fail('BETA_PRODUCT_CONFIG_PATH_REJECTED', 'config dataDirectory differs from its deterministic location');
  }
  return Object.freeze({ configPath: layout.configPath, config });
}

/**
 * Atomically establish the fixed private layout on first use, or load the
 * winner's exact config after a concurrent first-run creator publishes it.
 */
export function createOrLoadV2BetaProductConfig(value = {}) {
  try { return createV2BetaProductConfig(value); }
  catch (error) {
    if (!(error instanceof V2BetaProductConfigError)
      || error.code !== 'BETA_PRODUCT_CONFIG_EXISTS') throw error;
    return loadV2BetaProductConfig(value);
  }
}

/** Convert the persisted secret-free layout to the exact context schema. */
export function toV2BetaProductContextConfig(value) {
  const config = validateV2BetaProductConfig(value);
  // Config records a planned atomic artifact destination. Context construction
  // remains deliberately unavailable until the receipt installer has published
  // its private native directory at this exact path.
  privateDirectory(config.nativeProverDirectory, 'nativeProverDirectory');
  return Object.freeze({
    schema: V2_BETA_PRODUCT_CONTEXT_CONFIG_SCHEMA,
    productDataDirectory: config.dataDirectory,
    deploymentDirectory: config.deploymentDirectory,
    runtimeCacheRoot: config.runtimeCacheRoot,
    nativeProverDirectory: config.nativeProverDirectory,
    proofWorkspaceDirectory: config.proofWorkspaceDirectory,
    storeDatabasePath: config.storeDatabasePath,
    walletDatabasePath: config.walletDatabasePath,
    journalDatabasePath: config.journalDatabasePath,
  });
}
