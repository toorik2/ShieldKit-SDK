/**
 * Instance binding — the unit of "a pool".
 *
 * ShieldKit creates shielded pools; the Chipnet playground is our pool,
 * and your pool is the same thing with your genesis.
 *
 * loadInstance(ref) resolves either:
 *   - a directory containing instance.json (+ local profile bundle), or
 *   - the built-in id "chipnet-playground"
 */
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadVerifierProfileBundle } from './load.mjs';

export class InstanceError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'InstanceError';
    this.code = code;
  }
}

const fail = (code, message) => {
  throw new InstanceError(code, message);
};

const HASH = /^sha256:[0-9a-f]{64}$/;
const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../..');

/** Built-in playground descriptor (coordinates only; bundle is local/downloaded). */
export const CHIPNET_PLAYGROUND_ID = 'chipnet-playground';

/**
 * @typedef {object} InstanceDescriptor
 * @property {string} id
 * @property {'chipnet'|'mainnet'} network
 * @property {string} profileId
 * @property {string} instanceId
 * @property {string} [setupMode]
 * @property {string} [stateNftCategory]
 * @property {string} [reserveCapSatoshis]
 * @property {string} [label]
 * @property {string} [role] - 'playground' | 'custom'
 * @property {object} [profileBundle]
 */

/**
 * Resolve path to the official playground instance.json in this monorepo.
 */
export function playgroundInstancePath() {
  return path.join(repoRoot, 'examples/chipnet-playground/instance.json');
}

/**
 * Default search paths for the playground profile bundle (first hit wins).
 */
export function playgroundBundleSearchPaths() {
  const env = process.env.SHIELDKIT_PLAYGROUND_BUNDLE;
  const paths = [];
  if (env) paths.push(path.resolve(env));
  paths.push(path.join(repoRoot, 'examples/chipnet-playground/bundle'));
  paths.push(path.join(repoRoot, '.cache/profile-build-live/profile-bundle'));
  return paths;
}

async function readJson(filePath) {
  let text;
  try {
    text = await readFile(filePath, 'utf8');
  } catch {
    fail('INSTANCE_NOT_FOUND', `cannot read instance descriptor: ${filePath}`);
  }
  try {
    return JSON.parse(text);
  } catch {
    fail('INSTANCE_JSON', `invalid instance.json: ${filePath}`);
  }
}

function validateDescriptor(raw, sourcePath) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    fail('INSTANCE_SHAPE', 'instance.json must be an object');
  }
  const network = raw.network?.name ?? raw.network;
  if (network !== 'chipnet' && network !== 'mainnet') {
    fail('INSTANCE_NETWORK', 'instance.network must be chipnet or mainnet');
  }
  const profileId = raw.profileId ?? raw.expectedProfile?.profileId;
  const instanceId = raw.instanceId ?? raw.expectedProfile?.instanceId;
  if (typeof profileId !== 'string' || !HASH.test(profileId)) {
    fail('INSTANCE_PROFILE_ID', 'instance.profileId must be sha256:…');
  }
  if (typeof instanceId !== 'string' || !HASH.test(instanceId)) {
    fail('INSTANCE_INSTANCE_ID', 'instance.instanceId must be sha256:…');
  }
  return {
    id: raw.id ?? path.basename(path.dirname(sourcePath)),
    network,
    profileId,
    instanceId,
    setupMode: raw.setupMode ?? 'development-only',
    stateNftCategory: raw.stateNftCategory ?? raw.genesis?.stateNftCategory,
    reserveCapSatoshis: raw.reserveCapSatoshis ?? raw.genesis?.reserveCapSatoshis,
    categoryInputOutpoint: raw.categoryInputOutpoint ?? raw.genesis?.categoryInputOutpoint,
    label: raw.label ?? raw.id ?? 'pool',
    role: raw.role ?? (raw.id === CHIPNET_PLAYGROUND_ID ? 'playground' : 'custom'),
    denominationSatoshis: raw.denominationSatoshis ?? '10000000',
    explorers: raw.explorers ?? null,
    profileBundle: raw.profileBundle ?? null,
    warnings: Array.isArray(raw.warnings) ? raw.warnings : [],
    sourcePath,
  };
}

async function resolveBundleDirectory(descriptor, opts) {
  if (opts.bundleDirectory) return path.resolve(opts.bundleDirectory);
  if (process.env.SHIELDKIT_PLAYGROUND_BUNDLE && descriptor.role === 'playground') {
    return path.resolve(process.env.SHIELDKIT_PLAYGROUND_BUNDLE);
  }
  if (descriptor.profileBundle?.path) {
    const base = path.dirname(descriptor.sourcePath);
    return path.resolve(base, descriptor.profileBundle.path);
  }
  if (descriptor.role === 'playground') {
    for (const candidate of playgroundBundleSearchPaths()) {
      try {
        await readFile(path.join(candidate, 'manifest.json'));
        return candidate;
      } catch {
        // try next
      }
    }
    fail(
      'PLAYGROUND_BUNDLE_MISSING',
      'Chipnet playground profile bundle not found. Fetch pinned release: '
        + '`node scripts/fetch-playground-bundle.mjs` (sha256 in examples/chipnet-playground/instance.json), '
        + 'or set SHIELDKIT_PLAYGROUND_BUNDLE. See examples/chipnet-playground/README.md.',
    );
  }
  // custom: default bundle/ beside instance.json
  const beside = path.join(path.dirname(descriptor.sourcePath), 'bundle');
  try {
    await readFile(path.join(beside, 'manifest.json'));
    return beside;
  } catch {
    fail(
      'BUNDLE_MISSING',
      `profile bundle not found for instance ${descriptor.id}; pass bundleDirectory or place bundle/ next to instance.json`,
    );
  }
}

/**
 * Load a pool instance descriptor and authenticate its profile bundle.
 *
 * @param {string} ref - "chipnet-playground" or path to instance dir / instance.json
 * @param {object} [opts]
 * @param {string} [opts.bundleDirectory] - override profile bundle path
 * @param {boolean} [opts.loadBundle=true] - if false, return descriptor only
 * @returns {Promise<object>}
 */
export async function loadInstance(ref, opts = {}) {
  if (typeof ref !== 'string' || ref.length === 0) {
    fail('INSTANCE_REF', 'loadInstance ref must be a non-empty string');
  }
  const loadBundle = opts.loadBundle !== false;

  let instancePath;
  if (ref === CHIPNET_PLAYGROUND_ID || ref === 'playground') {
    instancePath = playgroundInstancePath();
  } else if (ref.endsWith('instance.json')) {
    instancePath = path.resolve(ref);
  } else {
    instancePath = path.resolve(ref, 'instance.json');
  }

  const raw = await readJson(instancePath);
  const descriptor = validateDescriptor(raw, instancePath);

  const baseWarnings = [
    'Unaudited — Work In Progress',
    ...(descriptor.warnings),
  ];
  if (descriptor.role === 'playground') {
    baseWarnings.push(
      'Chipnet playground: live example only — not a hosted pool service for third-party apps.',
      'development-only; not production privacy. Create your own pool for real use (same SDK, your genesis).',
    );
  }
  if (descriptor.setupMode === 'development-only') {
    baseWarnings.push('development-only setup is not a multi-party ceremony.');
  }

  const result = {
    schema: 'shieldkit/instance/v1',
    ...descriptor,
    warnings: Object.freeze([...new Set(baseWarnings)]),
    expectedProfile: Object.freeze({
      network: descriptor.network,
      profileId: descriptor.profileId,
      instanceId: descriptor.instanceId,
    }),
  };

  if (!loadBundle) {
    return Object.freeze(result);
  }

  const bundleDirectory = await resolveBundleDirectory(descriptor, opts);
  let loaded;
  try {
    loaded = await loadVerifierProfileBundle(bundleDirectory, result.expectedProfile);
  } catch (error) {
    fail(
      'BUNDLE_AUTH_FAILED',
      `profile bundle rejected for instance ${descriptor.id}: ${error.message}`,
    );
  }

  return Object.freeze({
    ...result,
    bundleDirectory,
    loaded,
    setupMode: loaded.manifest?.setup?.mode ?? descriptor.setupMode,
  });
}

/**
 * CreateKit-ready config from a loaded instance.
 */
export function instanceToKitConfig(instance, extra = {}) {
  if (!instance?.bundleDirectory || !instance?.expectedProfile) {
    fail('INSTANCE_INCOMPLETE', 'instance must be loadInstance(..., { loadBundle: true }) result');
  }
  return {
    network: instance.network,
    bundleDirectory: instance.bundleDirectory,
    expectedProfile: instance.expectedProfile,
    ...extra,
  };
}
