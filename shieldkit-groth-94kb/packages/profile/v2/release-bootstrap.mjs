/*
 * The final-release qualification root is deliberately compiled into the
 * verifier. It is not an artifact selected by a descriptor, manifest, CLI
 * argument, or network response: any of those would allow a package to name
 * its own authority.
 *
 * There is intentionally no approved V2 Direct final release at present.
 * Adding one requires a reviewed source change which adds an exact profile
 * core digest and descriptor signing keys below.
 */
import { createHash, createPublicKey } from 'node:crypto';

import {
  canonicalizeJcs,
  deriveProfileId,
} from './profile-core.mjs';
import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
} from '../../action/v2/topology.mjs';

export const V2_FINAL_RELEASE_BOOTSTRAP_SCHEMA =
  'shieldkit-v2-direct-final-release-bootstrap-v1';

export class V2FinalReleaseBootstrapError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2FinalReleaseBootstrapError';
  }
}

const fail = (message) => {
  throw new V2FinalReleaseBootstrapError(message);
};
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const HASH = /^[0-9a-f]{64}$/;
const ID = /^[a-z][a-z0-9-]*$/;
const CLEAN_HOST_ROLES = Object.freeze([
  'clean-host-a',
  'clean-host-b',
]);

function plain(value, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail(`${label} must be a plain object`);
  }
  return value;
}

function exact(value, keys, label) {
  plain(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((entry, index) => entry !== expected[index])
  ) {
    fail(`${label} has missing or unknown properties`);
  }
  return value;
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail(`${label} must be 32 lowercase hexadecimal bytes`);
  }
  return value;
}

function signer(value, label) {
  exact(value, ['publicKey', 'signerId'], label);
  if (typeof value.signerId !== 'string' || !ID.test(value.signerId)) {
    fail(`${label}.signerId is invalid`);
  }
  if (typeof value.publicKey !== 'string' || value.publicKey.length === 0) {
    fail(`${label}.publicKey must be a canonical Ed25519 SPKI PEM`);
  }
  let key;
  try {
    key = createPublicKey(value.publicKey);
  } catch {
    fail(`${label}.publicKey is invalid`);
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    fail(`${label}.publicKey must be Ed25519`);
  }
  const publicKey = key.export({ format: 'pem', type: 'spki' }).toString();
  if (publicKey !== value.publicKey) {
    fail(`${label}.publicKey must use canonical SPKI PEM`);
  }
  return Object.freeze({ signerId: value.signerId, publicKey });
}

function cleanHost(value, label, expectedRole) {
  exact(value, [
    'independenceDomain',
    'organizationId',
    'publicKey',
    'role',
    'signerId',
  ], label);
  if (value.role !== expectedRole) {
    fail(`${label}.role must be ${expectedRole}`);
  }
  const parsedSigner = signer(
    { publicKey: value.publicKey, signerId: value.signerId },
    label,
  );
  if (
    typeof value.organizationId !== 'string'
    || !ID.test(value.organizationId)
    || typeof value.independenceDomain !== 'string'
    || !ID.test(value.independenceDomain)
  ) {
    fail(`${label} organization and independence domain are invalid`);
  }
  return Object.freeze({
    ...parsedSigner,
    role: expectedRole,
    organizationId: value.organizationId,
    independenceDomain: value.independenceDomain,
  });
}

function releaseRoot(value, index) {
  const label = `final release bootstrap roots[${index}]`;
  exact(value, [
    'cleanHosts',
    'descriptorSigners',
    'network',
    'profileCoreSha256',
    'profileId',
    'rootId',
    'topology',
  ], label);
  if (typeof value.rootId !== 'string' || !ID.test(value.rootId)) {
    fail(`${label}.rootId is invalid`);
  }
  exact(value.network, ['id', 'name'], `${label}.network`);
  if (value.network.id !== 2 || value.network.name !== 'chipnet') {
    fail(`${label}.network must be the final Chipnet network`);
  }
  exact(value.topology, ['id', 'verifierRoles'], `${label}.topology`);
  if (
    value.topology.id !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
    || !Array.isArray(value.topology.verifierRoles)
    || value.topology.verifierRoles.length
      !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length
    || value.topology.verifierRoles.some(
      (role, roleIndex) => role !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES[roleIndex],
    )
  ) {
    fail(`${label}.topology must be the exact final PF10 topology`);
  }
  const profileCoreSha256 = hash(
    value.profileCoreSha256,
    `${label}.profileCoreSha256`,
  );
  const profileId = hash(value.profileId, `${label}.profileId`);
  if (!Array.isArray(value.descriptorSigners) || value.descriptorSigners.length === 0) {
    fail(`${label}.descriptorSigners must be nonempty`);
  }
  const descriptorSigners = value.descriptorSigners.map((entry, signerIndex) =>
    signer(entry, `${label}.descriptorSigners[${signerIndex}]`));
  for (let signerIndex = 1; signerIndex < descriptorSigners.length; signerIndex += 1) {
    if (
      descriptorSigners[signerIndex - 1].signerId
      >= descriptorSigners[signerIndex].signerId
    ) {
      fail(`${label}.descriptorSigners must be signerId-sorted and unique`);
    }
  }
  if (
    !Array.isArray(value.cleanHosts)
    || value.cleanHosts.length !== CLEAN_HOST_ROLES.length
  ) {
    fail(`${label}.cleanHosts must contain the exact two clean-host roles`);
  }
  const cleanHosts = Object.freeze(value.cleanHosts.map(
    (entry, hostIndex) => cleanHost(
      entry,
      `${label}.cleanHosts[${hostIndex}]`,
      CLEAN_HOST_ROLES[hostIndex],
    ),
  ));
  const allSigners = [...descriptorSigners, ...cleanHosts];
  if (
    new Set(allSigners.map((entry) => entry.signerId)).size
      !== allSigners.length
    || new Set(allSigners.map((entry) => entry.publicKey)).size
      !== allSigners.length
    || new Set(cleanHosts.map((entry) => entry.organizationId)).size
      !== cleanHosts.length
    || new Set(cleanHosts.map((entry) => entry.independenceDomain)).size
      !== cleanHosts.length
  ) {
    fail(`${label} descriptor and clean-host authorities must be distinct`);
  }
  return Object.freeze({
    rootId: value.rootId,
    profileId,
    profileCoreSha256,
    network: Object.freeze({ id: 2, name: 'chipnet' }),
    topology: Object.freeze({
      id: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
      verifierRoles: Object.freeze([...DIRECT_V2_PF10_FUSED_VERIFIER_ROLES]),
    }),
    descriptorSigners: Object.freeze(descriptorSigners),
    cleanHosts,
  });
}

function bootstrap(value) {
  exact(value, ['roots', 'schema'], 'final release bootstrap');
  if (value.schema !== V2_FINAL_RELEASE_BOOTSTRAP_SCHEMA) {
    fail('final release bootstrap schema is unsupported');
  }
  if (!Array.isArray(value.roots)) {
    fail('final release bootstrap roots must be an array');
  }
  const roots = value.roots.map(releaseRoot);
  for (let index = 1; index < roots.length; index += 1) {
    if (roots[index - 1].rootId >= roots[index].rootId) {
      fail('final release bootstrap roots must be rootId-sorted and unique');
    }
  }
  return Object.freeze(roots);
}

const COMPILED_BOOTSTRAP = Object.freeze({
  roots: Object.freeze([]),
  schema: V2_FINAL_RELEASE_BOOTSTRAP_SCHEMA,
});
const COMPILED_BOOTSTRAP_BYTES = Buffer.from(
  canonicalizeJcs(COMPILED_BOOTSTRAP),
  'utf8',
);
const COMPILED_ROOTS = bootstrap(COMPILED_BOOTSTRAP);

export const V2_FINAL_RELEASE_BOOTSTRAP_SHA256 = sha256(
  COMPILED_BOOTSTRAP_BYTES,
);

/**
 * Resolve only a root compiled into this version of ShieldKit. Before a final
 * release exists the intentionally empty registry fails closed.
 */
export function resolveV2FinalReleaseRoot(rootId) {
  if (typeof rootId !== 'string' || !ID.test(rootId)) {
    fail('final release root id is malformed');
  }
  if (COMPILED_ROOTS.length === 0) {
    fail('this ShieldKit build has no approved V2 Direct final release roots');
  }
  const root = COMPILED_ROOTS.find((entry) => entry.rootId === rootId);
  if (root === undefined) {
    fail('final release root id is not approved by this ShieldKit build');
  }
  return root;
}

export function assertV2FinalReleaseRoot(root) {
  if (!COMPILED_ROOTS.includes(root)) {
    fail('value is not a final release root resolved by this ShieldKit build');
  }
  return root;
}

/**
 * Bind a caller-supplied copy of profile core to the selected immutable root.
 * The file location is intentionally not trusted; only its exact canonical
 * bytes and derived identity are accepted.
 */
export function verifyV2FinalReleaseProfileCore(root, profileCoreBytes, profileCore) {
  assertV2FinalReleaseRoot(root);
  if (!(profileCoreBytes instanceof Uint8Array)) {
    fail('final release profile core must be bytes');
  }
  const canonicalBytes = Buffer.from(canonicalizeJcs(profileCore), 'utf8');
  if (!Buffer.from(profileCoreBytes).equals(canonicalBytes)) {
    fail('final release profile core must use exact RFC8785/JCS bytes');
  }
  if (sha256(canonicalBytes) !== root.profileCoreSha256) {
    fail('final release profile core SHA-256 differs from its approved root');
  }
  const profileId = deriveProfileId(profileCore);
  if (profileId !== root.profileId) {
    fail('final release profile core identity differs from its approved root');
  }
  if (
    profileCore.network?.id !== root.network.id
    || profileCore.network?.name !== root.network.name
  ) {
    fail('final release profile core network differs from its approved root');
  }
  return Object.freeze({
    profileId,
    profileCoreSha256: root.profileCoreSha256,
    descriptorSigners: root.descriptorSigners,
    cleanHosts: root.cleanHosts,
    releaseBootstrapSha256: V2_FINAL_RELEASE_BOOTSTRAP_SHA256,
    releaseRootId: root.rootId,
  });
}
