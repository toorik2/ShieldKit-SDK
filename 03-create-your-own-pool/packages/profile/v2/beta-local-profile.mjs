import { createHash } from 'node:crypto';

import {
  canonicalizeJcs,
  deriveProfileId,
  validateProfileCore,
} from './profile-core.mjs';

export const V2_BETA_LOCAL_PROFILE_PACKAGE_SCHEMA =
  'shieldkit-v2-direct-beta-single-contributor-profile-package-v1';
export const V2_BETA_LOCAL_ELIGIBILITY =
  'beta-single-contributor-unqualified';
export const V2_BETA_LOCAL_PROFILE_STATUS =
  'beta-single-contributor-profile-cryptographically-bound-unqualified';
export const V2_BETA_LOCAL_INSTANCE_DOMAIN =
  'shieldkit/v2-beta-local-instance/v1';

const HASH = /^[0-9a-f]{64}$/u;
const PREFIXED_HASH = /^sha256:[0-9a-f]{64}$/u;
const GIT = /^[0-9a-f]{40}$/u;
const ID = /^[a-z0-9][a-z0-9._-]{0,127}$/u;

export const V2_BETA_LOCAL_FALSE_CLAIMS = Object.freeze({
  b02Qualified: false,
  bchVm: false,
  betaSingleContributor: true,
  ceremonyQualified: false,
  d01Qualified: false,
  d02Qualified: false,
  developmentKey: false,
  finalKey: false,
  participantIndependenceEstablished: false,
  production: false,
  q01FinalReplayQualified: false,
  q01Qualified: false,
  q02Qualified: false,
  q03Qualified: false,
  q04Qualified: false,
  q05Qualified: false,
  q06Qualified: false,
  q07Qualified: false,
  q08Qualified: false,
  q09Qualified: false,
  releaseQualified: false,
});

export class V2BetaLocalProfileError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'V2BetaLocalProfileError';
    this.code = code;
  }
}

const fail = (code, message) => {
  throw new V2BetaLocalProfileError(code, message);
};

function plain(value, label) {
  if (value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('BETA_PROFILE_INVALID', `${label} must be a plain object`);
  }
  return value;
}

function object(value, label, keys) {
  plain(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length
    || actual.some((entry, index) => entry !== expected[index])) {
    fail('BETA_PROFILE_INVALID', `${label} has missing or unknown properties`);
  }
  return value;
}

function rawHash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail('BETA_PROFILE_INVALID', `${label} must be lowercase SHA-256 hex`);
  }
  return value;
}

function prefixedHash(value, label) {
  if (typeof value !== 'string' || !PREFIXED_HASH.test(value)) {
    fail('BETA_PROFILE_INVALID', `${label} must be prefixed lowercase SHA-256`);
  }
  return value;
}

function relativePath(value, label) {
  if (typeof value !== 'string'
    || value.length === 0
    || value.includes('\\')
    || value.startsWith('/')
    || value === '..'
    || value.startsWith('../')
    || value.split('/').some((part) => part === '' || part === '.' || part === '..')) {
    fail('BETA_PROFILE_INVALID', `${label} must be a normalized relative POSIX path`);
  }
  return value;
}

function artifact(value, label) {
  object(value, label, ['bytes', 'path', 'sha256']);
  if (!Number.isSafeInteger(value.bytes) || value.bytes <= 0) {
    fail('BETA_PROFILE_INVALID', `${label}.bytes must be a positive safe integer`);
  }
  return Object.freeze({
    bytes: value.bytes,
    path: relativePath(value.path, `${label}.path`),
    sha256: rawHash(value.sha256, `${label}.sha256`),
  });
}

function cloneJson(value) {
  return JSON.parse(canonicalizeJcs(value));
}

const sha256 = (value) =>
  createHash('sha256').update(value).digest('hex');

/**
 * Derive the synthetic, local-only beta instance identity. The ceremony result
 * binds the complete prepared lineage and the profile ID binds the beta VK.
 * This is not a BCH genesis-category derivation and must never be broadcast.
 */
export function deriveV2BetaLocalInstanceId({
  profileId,
  ceremonyResultSha256,
}) {
  rawHash(profileId, 'profileId');
  prefixedHash(ceremonyResultSha256, 'ceremonyResultSha256');
  return createHash('sha256')
    .update(V2_BETA_LOCAL_INSTANCE_DOMAIN, 'utf8')
    .update(Buffer.from([0]))
    .update(Buffer.from(profileId, 'hex'))
    .update(Buffer.from(ceremonyResultSha256.slice(7), 'hex'))
    .digest('hex');
}

/**
 * Derive the beta profile from the frozen B-01 profile by changing exactly
 * the verification-key commitment. All relation, ABI, topology-source,
 * network, tree, and toolchain commitments remain byte-identical.
 */
export function deriveV2BetaLocalProfileCore({
  baseProfileCore,
  verificationKeySha256,
}) {
  validateProfileCore(baseProfileCore);
  rawHash(verificationKeySha256, 'verificationKeySha256');
  const profileCore = cloneJson(baseProfileCore);
  profileCore.proof.verificationKeySha256 = verificationKeySha256;
  validateProfileCore(profileCore);
  const before = cloneJson(baseProfileCore);
  before.proof.verificationKeySha256 = verificationKeySha256;
  if (canonicalizeJcs(before) !== canonicalizeJcs(profileCore)) {
    fail('BETA_PROFILE_INVALID', 'beta profile changed more than its verification-key commitment');
  }
  return Object.freeze({
    profileCore: Object.freeze(profileCore),
    profileId: deriveProfileId(profileCore),
    profileCoreSha256: sha256(Buffer.from(canonicalizeJcs(profileCore), 'utf8')),
  });
}

function validateCeremony(value) {
  object(value, 'beta profile ceremony', [
    'b01ManifestSha256',
    'betaProvingKeySha256',
    'ceremonyId',
    'circuitSymbolsSha256',
    'initialZkeySha256',
    'powersOfTauSha256',
    'preparationSha256',
    'resultSha256',
    'source',
    'transcriptSha256',
    'verificationKeySha256',
  ]);
  if (typeof value.ceremonyId !== 'string' || !ID.test(value.ceremonyId)) {
    fail('BETA_PROFILE_INVALID', 'beta profile ceremonyId is invalid');
  }
  for (const name of [
    'b01ManifestSha256',
    'betaProvingKeySha256',
    'circuitSymbolsSha256',
    'initialZkeySha256',
    'powersOfTauSha256',
    'preparationSha256',
    'resultSha256',
    'transcriptSha256',
    'verificationKeySha256',
  ]) prefixedHash(value[name], `beta profile ceremony.${name}`);
  object(value.source, 'beta profile ceremony source', ['gitCommit', 'gitTree']);
  if (!GIT.test(value.source.gitCommit) || !GIT.test(value.source.gitTree)) {
    fail('BETA_PROFILE_INVALID', 'beta profile ceremony source is invalid');
  }
  return value;
}

function validateB01Manifest(value, {
  artifacts,
  baseProfileCore,
  ceremony,
}) {
  object(value, 'B-01 manifest', [
    'b01PreFreezeCandidate', 'boundaries', 'ceremonyAuthorized', 'claims',
    'localOnly', 'packetAbi', 'preCeremony', 'production', 'profile',
    'q01Pre', 'releaseQualified', 'reviewed', 'runtime', 'schema', 'source',
    'status', 'topology',
  ]);
  if (
    value.schema !== 'shieldkit-v2-direct-b01-pre-freeze-v1'
    || value.status !== 'b01-pre-freeze-candidate-awaiting-independent-review'
    || value.b01PreFreezeCandidate !== true
    || value.reviewed !== false
    || value.ceremonyAuthorized !== false
    || value.localOnly !== true
    || value.preCeremony !== true
    || value.production !== false
    || value.releaseQualified !== false
  ) {
    fail('BETA_PROFILE_INVALID', 'B-01 manifest boundary is invalid');
  }
  object(value.claims, 'B-01 manifest claims', [
    'bchVm', 'developmentKey', 'finalKey', 'production', 'releaseQualified',
  ]);
  if (canonicalizeJcs(value.claims) !== canonicalizeJcs({
    bchVm: false,
    developmentKey: true,
    finalKey: false,
    production: false,
    releaseQualified: false,
  })) fail('BETA_PROFILE_INVALID', 'B-01 manifest claims are invalid');
  object(value.source, 'B-01 manifest source', [
    'gitCommit', 'gitTree', 'repositoryRoot',
  ]);
  if (
    value.source.gitCommit !== ceremony.source.gitCommit
    || value.source.gitTree !== ceremony.source.gitTree
  ) fail('BETA_PROFILE_INVALID', 'B-01 source differs from beta ceremony');
  object(value.profile, 'B-01 manifest profile', [
    'profileCoreSha256', 'profileId', 'r1csSha256', 'relationSha256',
    'verificationKeySha256', 'witnessWasmSha256',
  ]);
  const baseBytes = Buffer.from(canonicalizeJcs(baseProfileCore), 'utf8');
  if (
    value.profile.profileId !== deriveProfileId(baseProfileCore)
    || value.profile.profileCoreSha256 !== sha256(baseBytes)
    || value.profile.r1csSha256 !== baseProfileCore.proof.r1csSha256
    || value.profile.relationSha256 !== baseProfileCore.proof.relationSha256
    || value.profile.verificationKeySha256
      !== baseProfileCore.proof.verificationKeySha256
    || value.profile.witnessWasmSha256
      !== baseProfileCore.proof.witnessWasmSha256
  ) fail('BETA_PROFILE_INVALID', 'B-01 profile differs from embedded base profile');
  plain(value.runtime, 'B-01 manifest runtime');
  plain(value.runtime.proofArtifacts, 'B-01 runtime proof artifacts');
  const expectedRuntimeArtifacts = {
    circuitSymbols: artifacts.circuitSymbols.sha256,
    initialProvingKey: artifacts.initialZkey.sha256,
    powersOfTau: artifacts.powersOfTau.sha256,
    r1cs: artifacts.r1cs.sha256,
    verificationKey: baseProfileCore.proof.verificationKeySha256,
    witnessWasm: artifacts.witnessWasm.sha256,
  };
  for (const [name, expected] of Object.entries(expectedRuntimeArtifacts)) {
    if (value.runtime.proofArtifacts[name] !== expected) {
      fail(
        'BETA_PROFILE_INVALID',
        `B-01 runtime proof artifact differs: ${name}`,
      );
    }
  }
  if (`sha256:${sha256(Buffer.from(canonicalizeJcs(value), 'utf8'))}`
      !== ceremony.b01ManifestSha256) {
    fail('BETA_PROFILE_INVALID', 'B-01 manifest hash differs from beta ceremony');
  }
  return Object.freeze(cloneJson(value));
}

export function createV2BetaLocalProfilePackage({
  baseProfileCore,
  b01Manifest,
  profileCore,
  profileCoreSha256,
  ceremony,
  artifacts,
}) {
  validateProfileCore(baseProfileCore);
  validateProfileCore(profileCore);
  rawHash(profileCoreSha256, 'profileCoreSha256');
  validateCeremony(ceremony);
  const baseProfileId = deriveProfileId(baseProfileCore);
  const canonicalBaseProfileCore = cloneJson(baseProfileCore);
  const baseProfileCoreSha256 = sha256(
    Buffer.from(canonicalizeJcs(canonicalBaseProfileCore), 'utf8'),
  );
  const calculatedProfileId = deriveProfileId(profileCore);
  const calculatedCoreSha256 = sha256(
    Buffer.from(canonicalizeJcs(profileCore), 'utf8'),
  );
  if (calculatedCoreSha256 !== profileCoreSha256) {
    fail('BETA_PROFILE_INVALID', 'beta profile-core hash is inconsistent');
  }
  const expectedBeta = deriveV2BetaLocalProfileCore({
    baseProfileCore: canonicalBaseProfileCore,
    verificationKeySha256: ceremony.verificationKeySha256.slice(7),
  });
  if (canonicalizeJcs(expectedBeta.profileCore)
      !== canonicalizeJcs(profileCore)
    || expectedBeta.profileId !== calculatedProfileId
    || expectedBeta.profileCoreSha256 !== profileCoreSha256) {
    fail(
      'BETA_PROFILE_INVALID',
      'beta profile is not the exact B-01 base profile with only its VK commitment replaced',
    );
  }
  object(artifacts, 'beta profile artifacts', [
    'betaProvingKey',
    'circuitSymbols',
    'initialZkey',
    'powersOfTau',
    'r1cs',
    'verificationKey',
    'witnessWasm',
  ]);
  const checkedArtifacts = Object.freeze(Object.fromEntries(
    Object.entries(artifacts).map(([name, value]) => [
      name,
      artifact(value, `beta profile artifacts.${name}`),
    ]),
  ));
  const checkedB01Manifest = validateB01Manifest(b01Manifest, {
    artifacts: checkedArtifacts,
    baseProfileCore: canonicalBaseProfileCore,
    ceremony,
  });
  if (`sha256:${checkedArtifacts.betaProvingKey.sha256}`
      !== ceremony.betaProvingKeySha256
    || `sha256:${checkedArtifacts.verificationKey.sha256}`
      !== ceremony.verificationKeySha256
    || `sha256:${checkedArtifacts.initialZkey.sha256}`
      !== ceremony.initialZkeySha256
    || `sha256:${checkedArtifacts.powersOfTau.sha256}`
      !== ceremony.powersOfTauSha256
    || `sha256:${checkedArtifacts.circuitSymbols.sha256}`
      !== ceremony.circuitSymbolsSha256
    || checkedArtifacts.verificationKey.sha256
      !== profileCore.proof.verificationKeySha256
    || checkedArtifacts.r1cs.sha256 !== profileCore.proof.r1csSha256
    || checkedArtifacts.witnessWasm.sha256
      !== profileCore.proof.witnessWasmSha256) {
    fail('BETA_PROFILE_INVALID', 'beta profile proof artifacts differ from ceremony/profile pins');
  }
  return Object.freeze({
    schema: V2_BETA_LOCAL_PROFILE_PACKAGE_SCHEMA,
    status: V2_BETA_LOCAL_PROFILE_STATUS,
    eligibility: V2_BETA_LOCAL_ELIGIBILITY,
    assuranceClass: 'beta-single-contributor',
    claims: V2_BETA_LOCAL_FALSE_CLAIMS,
    profileId: calculatedProfileId,
    profileCoreSha256,
    baseProfile: Object.freeze({
      profileId: baseProfileId,
      profileCoreSha256: baseProfileCoreSha256,
      profileCore: Object.freeze(canonicalBaseProfileCore),
    }),
    b01Manifest: checkedB01Manifest,
    ceremony: Object.freeze(cloneJson(ceremony)),
    artifacts: checkedArtifacts,
  });
}

export function validateV2BetaLocalProfilePackage(value, profileCore) {
  object(value, 'beta profile package', [
    'artifacts',
    'assuranceClass',
    'b01Manifest',
    'baseProfile',
    'ceremony',
    'claims',
    'eligibility',
    'profileCoreSha256',
    'profileId',
    'schema',
    'status',
  ]);
  if (value.schema !== V2_BETA_LOCAL_PROFILE_PACKAGE_SCHEMA
    || value.status !== V2_BETA_LOCAL_PROFILE_STATUS
    || value.eligibility !== V2_BETA_LOCAL_ELIGIBILITY
    || value.assuranceClass !== 'beta-single-contributor'
    || canonicalizeJcs(value.claims)
      !== canonicalizeJcs(V2_BETA_LOCAL_FALSE_CLAIMS)) {
    fail('BETA_PROFILE_INVALID', 'beta profile package boundary is invalid');
  }
  object(value.baseProfile, 'beta profile baseProfile', [
    'profileCore', 'profileCoreSha256', 'profileId',
  ]);
  rawHash(value.baseProfile.profileId, 'beta profile baseProfile.profileId');
  rawHash(
    value.baseProfile.profileCoreSha256,
    'beta profile baseProfile.profileCoreSha256',
  );
  validateProfileCore(value.baseProfile.profileCore);
  const canonicalBaseBytes = Buffer.from(
    canonicalizeJcs(value.baseProfile.profileCore),
    'utf8',
  );
  if (
    deriveProfileId(value.baseProfile.profileCore)
      !== value.baseProfile.profileId
    || sha256(canonicalBaseBytes) !== value.baseProfile.profileCoreSha256
  ) {
    fail('BETA_PROFILE_INVALID', 'embedded B-01 base profile identity is invalid');
  }
  validateCeremony(value.ceremony);
  const rebuilt = createV2BetaLocalProfilePackage({
    baseProfileCore: value.baseProfile.profileCore,
    b01Manifest: value.b01Manifest,
    profileCore,
    profileCoreSha256: value.profileCoreSha256,
    ceremony: value.ceremony,
    artifacts: value.artifacts,
  });
  if (canonicalizeJcs(rebuilt) !== canonicalizeJcs(value)) {
    fail('BETA_PROFILE_INVALID', 'beta profile package is not canonical or self-consistent');
  }
  return rebuilt;
}
