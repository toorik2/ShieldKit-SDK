/**
 * Identity model — CLI_ARCHITECTURE_PLAN.md § Identity model
 * Six distinct identifiers; tip is never an identity.
 */

import { createHash, randomUUID } from 'node:crypto';

export const IDENTITY_SCHEMA = 'shieldkit-identity/v1';

export const NETWORKS = Object.freeze({
  chipnet: Object.freeze({
    networkId: 'bch-chipnet',
    name: 'chipnet',
    // BCHN Chipnet genesis, pinned from bchn-src/src/chainparams.cpp.
    genesisHash: '000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b',
  }),
});

const HEX40 = /^[0-9a-f]{40}$/;
const HEX64 = /^[0-9a-f]{64}$/;

export class IdentityError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'IdentityError';
    this.code = code;
  }
}

const fail = (code, message) => {
  throw new IdentityError(code, message);
};

/**
 * Return an exact profile identity only from an authority-bearing source.
 *
 * A design summary (roles, topology, proof system, &c.) is deliberately not
 * a profile: it omits the ABI, denomination, encodings, artifacts and
 * toolchain.  Callers with an unfrozen design must expose profileId: null,
 * profileStatus: 'unfrozen' (or 'unselected' for a profile family) instead of
 * minting a look-alike hash.
 */
export function computeProfileId(source) {
  if (source === null || typeof source !== 'object' || Array.isArray(source)) {
    fail('PROFILE_AUTHORITY_REQUIRED', 'profile identity requires a pinned id or validated complete profile core');
  }
  if (typeof source.profileId === 'string') return assertProfileId(source.profileId);
  fail(
    'PROFILE_AUTHORITY_REQUIRED',
    'the generic kernel accepts only a profile id already derived by an authority-bearing backend; summaries and unvalidated profile cores are not profiles',
  );
}

/** Normalize the two honest identity states used by the CLI. */
export function resolveProfileIdentity({ profileId = null, profileCore = null, profileStatus = null } = {}) {
  if (profileCore !== null) {
    fail('PROFILE_AUTHORITY_REQUIRED', 'backend profile cores must be validated by their backend before entering the generic identity envelope');
  }
  if (profileId !== null) {
    if (profileStatus !== null && profileStatus !== 'frozen') {
      fail('PROFILE_STATUS', 'an exact profile identity must have frozen status');
    }
    return Object.freeze({ profileId: computeProfileId({ profileId }), profileStatus: 'frozen' });
  }
  if (profileStatus !== 'unfrozen' && profileStatus !== 'unselected') {
    fail('PROFILE_AUTHORITY_REQUIRED', 'missing profile identity must be explicitly marked unfrozen or unselected');
  }
  return Object.freeze({ profileId: null, profileStatus });
}

export function assertProfileId(value, label = 'profileId') {
  if (typeof value !== 'string' || !HEX64.test(value)) {
    fail('INVALID_PROFILE_ID', `${label} must be 64-char lowercase hex content id`);
  }
  return value;
}

export function assertInstanceId(value, label = 'instanceId') {
  if (typeof value !== 'string' || !HEX64.test(value)) {
    fail('INVALID_INSTANCE_ID', `${label} must be 64-char lowercase hex`);
  }
  return value;
}

export function assertHomeId(value, label = 'homeId') {
  if (typeof value !== 'string' || !HEX64.test(value)) {
    fail('INVALID_HOME_ID', `${label} must be 64-char lowercase hex`);
  }
  return value;
}

export function assertOperationId(value, label = 'operationId') {
  // The PF10 product uses namespaced IDs (e.g. deposit.<64hex>). They are
  // database keys, never path components, so keep one bounded safe alphabet.
  const namespaced = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
  if (typeof value !== 'string' || !namespaced.test(value)) {
    fail('INVALID_OPERATION_ID', `${label} must be 1-128 safe identifier characters`);
  }
  return value;
}

export function assertBackendId(value, label = 'backendId') {
  if (typeof value !== 'string' || value.length === 0) {
    fail('INVALID_BACKEND_ID', `${label} must be a non-empty string`);
  }
  return value;
}

export function newHomeId() {
  return createHash('sha256').update(`home:${randomUUID()}`).digest('hex');
}

export function newOperationId() {
  return randomUUID();
}

/**
 * Tip is a mutable chain observation — never an identity field on home/profile.
 */
export function isTipObservation(value) {
  return value !== null
    && typeof value === 'object'
    && value.kind === 'tip'
    && typeof value.height === 'number';
}

/**
 * Build the six-field identity envelope fragment.
 * Rejects accidental inclusion of tip as identity.
 */
export function buildIdentityFields({
  backendId,
  profileId = null,
  profileCore = null,
  profileStatus = null,
  instanceId = null,
  homeId = null,
  operationId = null,
  network = NETWORKS.chipnet.networkId,
} = {}) {
  if (arguments[0] && Object.hasOwn(arguments[0], 'tip')) {
    fail('TIP_NOT_IDENTITY', 'tip is a mutable observation, not an identity field');
  }
  const exactProfile = resolveProfileIdentity({ profileId, profileCore, profileStatus });
  return Object.freeze({
    schema: IDENTITY_SCHEMA,
    backendId: assertBackendId(backendId),
    ...exactProfile,
    instanceId: instanceId === null ? null : assertInstanceId(instanceId),
    homeId: homeId === null ? null : assertHomeId(homeId),
    operationId: operationId === null ? null : assertOperationId(operationId),
    network: typeof network === 'string' ? network : fail('NETWORK', 'network required'),
  });
}

/**
 * Resolve a friendly alias to an exact registry entry (data-only).
 * Does not load backend modules.
 */
export function resolveAlias(alias, catalog) {
  if (typeof alias !== 'string' || alias.length === 0) {
    fail('ALIAS_REQUIRED', 'design alias required');
  }
  if (!catalog || !Array.isArray(catalog.designs)) {
    fail('CATALOG_REQUIRED', 'closed design catalog required');
  }
  const key = alias.toLowerCase();
  const hit = catalog.designs.find((d) => {
    const aliases = [d.alias, d.id, ...(d.aliases || [])].filter(Boolean).map((a) => String(a).toLowerCase());
    return aliases.includes(key);
  });
  if (!hit) fail('UNKNOWN_ALIAS', `unknown design alias: ${alias}`);
  return Object.freeze({ ...hit });
}

export function assertGitSha(value, label = 'commit') {
  if (typeof value !== 'string' || !HEX40.test(value)) {
    fail('INVALID_COMMIT', `${label} must be 40-char lowercase git sha`);
  }
  return value;
}
