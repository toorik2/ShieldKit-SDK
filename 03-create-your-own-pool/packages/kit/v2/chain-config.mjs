import {
  link,
  lstat,
  mkdtemp,
  open,
  readFile,
  realpath,
  rmdir,
  unlink,
} from 'node:fs/promises';
import path from 'node:path';

import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';
import { assertV2SecureEndpoint } from './https-transport.mjs';

export const V2_CHAIN_CONFIG_SCHEMA = 'shieldkit-v2-cli-chain-v1';
export const V2_CHAIN_CONFIG_PROTOCOL = 'v2-direct';
export const V2_CHAIN_CONFIG_NETWORK = 'chipnet';
export const V2_CHAIN_CONFIG_MIN_CONFIRMATION_DEPTH = 1;
export const V2_CHAIN_CONFIG_MAX_CONFIRMATION_DEPTH = 100;
export const V2_CHAIN_CONFIG_MIN_REQUEST_TIMEOUT_MS = 1_000;
export const V2_CHAIN_CONFIG_MAX_REQUEST_TIMEOUT_MS = 60_000;

const MAX_CONFIG_BYTES = 16 * 1024;

export class V2ChainConfigError extends Error {
  constructor(code, message, cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'V2ChainConfigError';
    this.code = code;
  }
}

const fail = (code, message, cause) => {
  throw new V2ChainConfigError(code, message, cause);
};

function exact(value, keys, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('CHAIN_CONFIG_INVALID', `${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    fail('CHAIN_CONFIG_INVALID', `${label} has missing or unknown fields`);
  }
  return value;
}

function boundedInteger(value, minimum, maximum, label) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(
      'CHAIN_CONFIG_INVALID',
      `${label} must be an integer from ${minimum} through ${maximum}`,
    );
  }
  return value;
}

function absoluteNormalizedPath(value, label) {
  if (
    typeof value !== 'string'
    || !path.isAbsolute(value)
    || path.normalize(value) !== value
    || value.includes('\0')
  ) {
    fail('CHAIN_CONFIG_PATH_INVALID', `${label} must be a normalized absolute path`);
  }
  return value;
}

async function regularNonSymlinkFile(filename, label) {
  const absolute = absoluteNormalizedPath(filename, label);
  let metadata;
  try {
    metadata = await lstat(absolute);
  } catch (error) {
    fail('CHAIN_CONFIG_UNAVAILABLE', `${label} is unavailable`, error);
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    fail('CHAIN_CONFIG_PATH_INVALID', `${label} must be a regular non-symlink file`);
  }
  let canonical;
  try {
    canonical = await realpath(absolute);
  } catch (error) {
    fail('CHAIN_CONFIG_UNAVAILABLE', `${label} cannot be resolved`, error);
  }
  if (canonical !== absolute) {
    fail('CHAIN_CONFIG_PATH_INVALID', `${label} must not resolve through a symlink`);
  }
  return metadata;
}

async function trustedDirectory(directory, label) {
  const absolute = absoluteNormalizedPath(directory, label);
  let metadata;
  try {
    metadata = await lstat(absolute);
  } catch (error) {
    fail('CHAIN_CONFIG_UNAVAILABLE', `${label} is unavailable`, error);
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail('CHAIN_CONFIG_PATH_INVALID', `${label} must be a directory, not a symlink`);
  }
  let canonical;
  try {
    canonical = await realpath(absolute);
  } catch (error) {
    fail('CHAIN_CONFIG_UNAVAILABLE', `${label} cannot be resolved`, error);
  }
  if (canonical !== absolute) {
    fail('CHAIN_CONFIG_PATH_INVALID', `${label} must not resolve through a symlink`);
  }
  return absolute;
}

async function syncDirectory(directory) {
  const handle = await open(directory, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

/** Parse a non-secret, local-only V2 Direct chain configuration. */
export function parseV2ChainConfig(value) {
  exact(value, [
    'confirmationDepth',
    'endpoint',
    'network',
    'protocol',
    'requestTimeoutMs',
    'schema',
  ], 'chain configuration');
  if (value.schema !== V2_CHAIN_CONFIG_SCHEMA || value.protocol !== V2_CHAIN_CONFIG_PROTOCOL) {
    fail(
      'CHAIN_CONFIG_INVALID',
      'chain configuration must select shieldkit-v2-cli-chain-v1 and v2-direct',
    );
  }
  if (value.network === 'mainnet') {
    fail('V2_MAINNET_OUTSIDE_PLAN', 'V2 Direct mainnet configuration is outside this plan');
  }
  if (value.network !== V2_CHAIN_CONFIG_NETWORK) {
    fail('CHAIN_CONFIG_INVALID', 'chain configuration must select chipnet');
  }
  let endpoint;
  try {
    endpoint = assertV2SecureEndpoint(value.endpoint);
  } catch (error) {
    fail(
      'CHAIN_CONFIG_INVALID',
      `chain configuration endpoint is unsafe: ${
        error instanceof Error ? error.message : String(error)
      }`,
      error,
    );
  }
  if (endpoint.network === 'mainnet') {
    fail('V2_MAINNET_OUTSIDE_PLAN', 'V2 Direct mainnet endpoint is outside this plan');
  }
  if (endpoint.network !== V2_CHAIN_CONFIG_NETWORK) {
    fail('CHAIN_CONFIG_INVALID', 'chain configuration endpoint must select chipnet');
  }
  let suppliedEndpoint;
  try {
    suppliedEndpoint = canonicalizeJcs(value.endpoint);
  } catch (error) {
    fail('CHAIN_CONFIG_INVALID', 'chain configuration endpoint is not canonical JSON data', error);
  }
  if (suppliedEndpoint !== canonicalizeJcs(endpoint)) {
    fail('CHAIN_CONFIG_INVALID', 'chain configuration endpoint must use canonical endpoint fields');
  }
  return Object.freeze({
    schema: V2_CHAIN_CONFIG_SCHEMA,
    protocol: V2_CHAIN_CONFIG_PROTOCOL,
    network: V2_CHAIN_CONFIG_NETWORK,
    endpoint,
    confirmationDepth: boundedInteger(
      value.confirmationDepth,
      V2_CHAIN_CONFIG_MIN_CONFIRMATION_DEPTH,
      V2_CHAIN_CONFIG_MAX_CONFIRMATION_DEPTH,
      'chain configuration confirmationDepth',
    ),
    requestTimeoutMs: boundedInteger(
      value.requestTimeoutMs,
      V2_CHAIN_CONFIG_MIN_REQUEST_TIMEOUT_MS,
      V2_CHAIN_CONFIG_MAX_REQUEST_TIMEOUT_MS,
      'chain configuration requestTimeoutMs',
    ),
  });
}

/** Load one exact RFC 8785/JCS chain configuration from a local regular file. */
export async function loadV2ChainConfig(filename) {
  const metadata = await regularNonSymlinkFile(filename, 'chain configuration');
  if (metadata.size > MAX_CONFIG_BYTES) {
    fail(
      'CHAIN_CONFIG_INVALID',
      `chain configuration exceeds ${MAX_CONFIG_BYTES} bytes`,
    );
  }
  let bytes;
  try {
    bytes = await readFile(filename);
  } catch (error) {
    fail('CHAIN_CONFIG_UNAVAILABLE', 'chain configuration cannot be read', error);
  }
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    fail('CHAIN_CONFIG_INVALID', 'chain configuration is not valid JSON', error);
  }
  let config;
  try {
    config = parseV2ChainConfig(parsed);
  } catch (error) {
    if (error instanceof V2ChainConfigError) throw error;
    fail('CHAIN_CONFIG_INVALID', 'chain configuration cannot be parsed', error);
  }
  if (!bytes.equals(Buffer.from(canonicalizeJcs(config), 'utf8'))) {
    fail('CHAIN_CONFIG_INVALID', 'chain configuration must use exact RFC8785/JCS bytes');
  }
  return config;
}

/** Atomically create, but never replace, one canonical chain configuration. */
export async function createV2ChainConfig({ filename, config } = {}) {
  const target = absoluteNormalizedPath(filename, 'chain configuration filename');
  const parsed = parseV2ChainConfig(config);
  const directory = await trustedDirectory(
    path.dirname(target),
    'chain configuration parent directory',
  );
  const canonical = Buffer.from(canonicalizeJcs(parsed), 'utf8');
  const temporaryDirectory = await mkdtemp(
    path.join(directory, '.shieldkit-v2-chain-config-'),
  );
  const temporary = path.join(temporaryDirectory, 'config.json');
  let handle;
  try {
    handle = await open(temporary, 'wx', 0o600);
    await handle.writeFile(canonical);
    await handle.sync();
    await handle.close();
    handle = undefined;
    try {
      await link(temporary, target);
    } catch (error) {
      if (error?.code === 'EEXIST') {
        fail('CHAIN_CONFIG_EXISTS', 'chain configuration already exists', error);
      }
      fail('CHAIN_CONFIG_UNAVAILABLE', 'chain configuration cannot be created', error);
    }
    await syncDirectory(directory);
  } finally {
    await handle?.close();
    await unlink(temporary).catch((error) => {
      if (error?.code !== 'ENOENT') throw error;
    });
    await rmdir(temporaryDirectory).catch((error) => {
      if (error?.code !== 'ENOENT') throw error;
    });
  }
  return parsed;
}
