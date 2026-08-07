import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from 'node:crypto';

import { canonicalizeJcs } from './profile-core.mjs';

export const V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID =
  'final-evidence-policy';
export const V2_FINAL_EVIDENCE_POLICY_SCHEMA =
  'shieldkit-v2-direct-final-evidence-policy-v1';
export const V2_FINAL_SIGNED_EVIDENCE_SCHEMA =
  'shieldkit-v2-direct-final-signed-evidence-v1';
export const V2_FINAL_CONTRIBUTOR_REGISTRY_SCHEMA =
  'shieldkit-v2-direct-final-contributor-registry-v1';
export const V2_FINAL_CEREMONY_TRANSCRIPT_SCHEMA =
  'shieldkit-v2-direct-final-ceremony-transcript-v2';
export const V2_FINAL_CEREMONY_CONTRIBUTION_SCHEMA =
  'shieldkit-v2-direct-final-ceremony-contribution-v1';
export const V2_FINAL_CEREMONY_BEACON_SCHEMA =
  'shieldkit-v2-direct-final-ceremony-beacon-v1';
export const V2_FINAL_TRANSCRIPT_VERIFICATION_SCHEMA =
  'shieldkit-v2-direct-final-transcript-verification-v2';
export const V2_FINAL_REPRODUCTION_SCHEMA =
  'shieldkit-v2-direct-final-reproduction-v2';
export const V2_FINAL_EVIDENCE_SIGNATURE_DOMAIN =
  'shieldkit-v2-direct-final-evidence-signature-v1\0';

const HASH = /^[0-9a-f]{64}$/;
const GIT_OBJECT = /^[0-9a-f]{40}$/;
const IDENTIFIER = /^[a-z][a-z0-9-]*$/;
const EXPECTED_TRANSCRIPT_VERIFIER_ROLES = Object.freeze([
  'transcript-verifier-a',
  'transcript-verifier-b',
]);
const EXPECTED_REPRODUCTION_ROLES = Object.freeze([
  'reproduction-host-a',
  'reproduction-host-b',
]);
const MINIMUM_CONTRIBUTORS = 5;

export class V2FinalRuntimeEvidenceError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2FinalRuntimeEvidenceError';
  }
}

const fail = (message) => {
  throw new V2FinalRuntimeEvidenceError(message);
};

const sha256 = (value) =>
  createHash('sha256').update(value).digest('hex');

const canonicalBytes = (value) =>
  Buffer.from(canonicalizeJcs(value), 'utf8');

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

function identifier(value, label) {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) {
    fail(`${label} must be a canonical identifier`);
  }
  return value;
}

function positiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail(`${label} must be a positive safe integer`);
  }
  return value;
}

function parseCanonical(bytes, label) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    fail(`${label} must be nonempty bytes`);
  }
  let value;
  try {
    value = JSON.parse(Buffer.from(bytes).toString('utf8'));
  } catch {
    fail(`${label} is not JSON`);
  }
  let canonical;
  try {
    canonical = canonicalBytes(value);
  } catch (error) {
    fail(`${label} is not strict JSON: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
  if (!Buffer.from(bytes).equals(canonical)) {
    fail(`${label} must use exact RFC8785/JCS bytes`);
  }
  return value;
}

function artifactReference(value, label, artifactEntries) {
  exact(value, ['artifactId', 'sha256'], label);
  const artifactId = identifier(value.artifactId, `${label}.artifactId`);
  const expected = expectedReference(artifactId, artifactEntries, label);
  if (hash(value.sha256, `${label}.sha256`) !== expected.sha256) {
    fail(`${label} does not match the signed artifact manifest`);
  }
  return expected;
}

function expectedReference(artifactId, artifactEntries, label) {
  const canonicalArtifactId = identifier(artifactId, `${label}.artifactId`);
  const entry = artifactEntries[canonicalArtifactId];
  if (entry === undefined) {
    fail(`${label} is not a signed manifest artifact`);
  }
  plain(entry, `${label} manifest entry`);
  return Object.freeze({
    artifactId: canonicalArtifactId,
    sha256: hash(entry.sha256, `${label} manifest entry.sha256`),
  });
}

/**
 * Make the artifact manifest an integrity boundary, rather than merely a
 * reference lookup. Every byte sequence consumed by final-evidence validation
 * must match the independently signed manifest entry before it is parsed or
 * otherwise used. The cache also prevents a mutable loader from supplying two
 * different byte sequences for the same pinned artifact during one resolve.
 */
function pinnedArtifactReader({ artifactEntries, readArtifactBytes }) {
  const cache = new Map();
  return async (reference, label) => {
    const expected = expectedReference(
      reference.artifactId,
      artifactEntries,
      label,
    );
    if (expected.sha256 !== reference.sha256) {
      fail(`${label} reference does not match the signed artifact manifest`);
    }
    let pending = cache.get(expected.artifactId);
    if (pending === undefined) {
      pending = (async () => {
        let bytes;
        try {
          bytes = await readArtifactBytes(expected.artifactId, label);
        } catch (error) {
          fail(`${label} could not be read: ${
            error instanceof Error ? error.message : String(error)
          }`);
        }
        if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
          fail(`${label} must be nonempty bytes`);
        }
        const copied = Buffer.from(bytes);
        if (sha256(copied) !== expected.sha256) {
          fail(`${label} sha256 does not match the signed artifact manifest`);
        }
        return copied;
      })();
      cache.set(expected.artifactId, pending);
    }
    return pending;
  };
}

async function verifyNestedArtifactReferences(value, {
  artifactEntries,
  readPinnedArtifact,
  label,
}) {
  const references = [];
  const visit = (entry, path) => {
    if (entry === null || typeof entry !== 'object') return;
    if (Array.isArray(entry)) {
      entry.forEach((child, index) => visit(child, `${path}[${index}]`));
      return;
    }
    const keys = Object.keys(entry).sort();
    if (
      keys.length === 2
      && keys[0] === 'artifactId'
      && keys[1] === 'sha256'
    ) {
      references.push(artifactReference(entry, path, artifactEntries));
      return;
    }
    Object.entries(entry).forEach(([key, child]) => visit(child, `${path}.${key}`));
  };
  visit(value, label);
  await Promise.all(references.map((reference, index) => readPinnedArtifact(
    reference,
    `${label} nested artifact[${index}]`,
  )));
}

function sameReference(actual, expected, label) {
  if (
    actual.artifactId !== expected.artifactId
    || actual.sha256 !== expected.sha256
  ) {
    fail(`${label} differs from the final runtime artifact`);
  }
}

function authority(value, label, expectedRole = undefined) {
  exact(value, [
    'independenceDomain',
    'organizationId',
    'publicKeyPem',
    'role',
    'signerId',
  ], label);
  const role = identifier(value.role, `${label}.role`);
  if (expectedRole !== undefined && role !== expectedRole) {
    fail(`${label}.role must be ${expectedRole}`);
  }
  const signerId = identifier(value.signerId, `${label}.signerId`);
  const organizationId = identifier(
    value.organizationId,
    `${label}.organizationId`,
  );
  const independenceDomain = identifier(
    value.independenceDomain,
    `${label}.independenceDomain`,
  );
  if (
    typeof value.publicKeyPem !== 'string'
    || value.publicKeyPem.length === 0
  ) {
    fail(`${label}.publicKeyPem must be a nonempty Ed25519 SPKI PEM`);
  }
  let publicKey;
  try {
    publicKey = createPublicKey(value.publicKeyPem);
  } catch {
    fail(`${label}.publicKeyPem is invalid`);
  }
  if (publicKey.asymmetricKeyType !== 'ed25519') {
    fail(`${label}.publicKeyPem must contain an Ed25519 public key`);
  }
  const canonicalPem = publicKey.export({
    format: 'pem',
    type: 'spki',
  }).toString();
  if (canonicalPem !== value.publicKeyPem) {
    fail(`${label}.publicKeyPem must use canonical SPKI PEM encoding`);
  }
  const publicKeySha256 = sha256(publicKey.export({
    format: 'der',
    type: 'spki',
  }));
  return Object.freeze({
    role,
    signerId,
    organizationId,
    independenceDomain,
    publicKey,
    publicKeyPem: canonicalPem,
    publicKeySha256,
  });
}

function sortedAuthorities(values, label, expectedRoles = undefined) {
  if (!Array.isArray(values) || values.length === 0) {
    fail(`${label} must be a nonempty array`);
  }
  const parsed = values.map((entry, index) =>
    authority(entry, `${label}[${index}]`));
  for (let index = 1; index < parsed.length; index += 1) {
    if (parsed[index - 1].role >= parsed[index].role) {
      fail(`${label} must be strictly role-sorted without duplicates`);
    }
  }
  if (
    expectedRoles !== undefined
    && (
      parsed.length !== expectedRoles.length
      || parsed.some((entry, index) => entry.role !== expectedRoles[index])
    )
  ) {
    fail(`${label} does not contain the exact required roles`);
  }
  return Object.freeze(parsed);
}

function parsePolicy(value, {
  expectedPolicySha256,
  policyBytes,
}) {
  exact(value, [
    'ceremony',
    'network',
    'schema',
  ], 'final evidence policy');
  if (
    value.schema !== V2_FINAL_EVIDENCE_POLICY_SCHEMA
    || sha256(policyBytes) !== expectedPolicySha256
  ) {
    fail('final evidence policy schema or hash is invalid');
  }
  exact(value.network, ['id', 'name'], 'final evidence policy network');
  if (value.network.id !== 2 || value.network.name !== 'chipnet') {
    fail('final evidence policy is restricted to Chipnet');
  }
  exact(value.ceremony, [
    'contributors',
    'coordinator',
    'minimumContributors',
    'reproducibilityHosts',
    'transcriptVerifiers',
  ], 'final evidence policy ceremony');
  if (value.ceremony.minimumContributors !== MINIMUM_CONTRIBUTORS) {
    fail(`final evidence policy requires exactly the ${MINIMUM_CONTRIBUTORS}-contributor threshold`);
  }
  const coordinator = authority(
    value.ceremony.coordinator,
    'final evidence policy ceremony.coordinator',
    'ceremony-coordinator',
  );
  if (
    !Array.isArray(value.ceremony.contributors)
    || value.ceremony.contributors.length < MINIMUM_CONTRIBUTORS
  ) {
    fail(`final evidence policy must authorize at least ${MINIMUM_CONTRIBUTORS} contributors`);
  }
  const contributors = Object.freeze(value.ceremony.contributors.map(
    (entry, index) => authority(
      entry,
      `final evidence policy ceremony.contributors[${index}]`,
      'ceremony-contributor',
    ),
  ));
  for (let index = 1; index < contributors.length; index += 1) {
    if (contributors[index - 1].signerId >= contributors[index].signerId) {
      fail('final evidence policy contributors must be signerId-sorted and unique');
    }
  }
  const transcriptVerifiers = sortedAuthorities(
    value.ceremony.transcriptVerifiers,
    'final evidence policy ceremony.transcriptVerifiers',
    EXPECTED_TRANSCRIPT_VERIFIER_ROLES,
  );
  const reproducibilityHosts = sortedAuthorities(
    value.ceremony.reproducibilityHosts,
    'final evidence policy ceremony.reproducibilityHosts',
    EXPECTED_REPRODUCTION_ROLES,
  );
  const all = [
    coordinator,
    ...contributors,
    ...transcriptVerifiers,
    ...reproducibilityHosts,
  ];
  for (const [property, description] of [
    ['signerId', 'signer IDs'],
    ['publicKeySha256', 'public keys'],
    ['organizationId', 'organizations'],
    ['independenceDomain', 'independence domains'],
  ]) {
    const values = new Set(all.map((entry) => entry[property]));
    if (values.size !== all.length) {
      fail(`final evidence policy ${description} must be globally distinct`);
    }
  }
  const authorities = new Map(all.map((entry) => [entry.signerId, entry]));
  return Object.freeze({
    coordinator,
    contributors,
    transcriptVerifiers,
    reproducibilityHosts,
    authorities,
  });
}

function decodeCanonicalSignature(value, label) {
  if (
    typeof value !== 'string'
    || value.length !== 88
    || !/^[A-Za-z0-9+/]{86}==$/.test(value)
  ) {
    fail(`${label} must be canonical base64 for a 64-byte signature`);
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length !== 64 || decoded.toString('base64') !== value) {
    fail(`${label} must be canonical base64 for a 64-byte signature`);
  }
  return decoded;
}

function signedEvidence(value, {
  label,
  policy,
  expectedRole,
  expectedSchema,
  contributor = false,
}) {
  exact(value, [
    'role',
    'schema',
    'signatureBase64',
    'signerId',
    'statement',
    'statementSha256',
  ], label);
  if (
    value.schema !== V2_FINAL_SIGNED_EVIDENCE_SCHEMA
    || value.role !== expectedRole
  ) {
    fail(`${label} signed-evidence schema or role is invalid`);
  }
  const signerId = identifier(value.signerId, `${label}.signerId`);
  const signer = policy.authorities.get(signerId);
  if (
    signer === undefined
    || signer.role !== expectedRole
    || (contributor && !policy.contributors.includes(signer))
  ) {
    fail(`${label} signer is not authorized for ${expectedRole}`);
  }
  plain(value.statement, `${label}.statement`);
  if (value.statement.schema !== expectedSchema) {
    fail(`${label}.statement schema is invalid`);
  }
  const statementBytes = canonicalBytes(value.statement);
  if (
    hash(value.statementSha256, `${label}.statementSha256`)
      !== sha256(statementBytes)
  ) {
    fail(`${label}.statementSha256 does not bind its statement`);
  }
  const signature = decodeCanonicalSignature(
    value.signatureBase64,
    `${label}.signatureBase64`,
  );
  const signingBytes = Buffer.concat([
    Buffer.from(V2_FINAL_EVIDENCE_SIGNATURE_DOMAIN, 'utf8'),
    Buffer.from(expectedRole, 'utf8'),
    Buffer.from([0]),
    statementBytes,
  ]);
  if (!verifySignature(null, signingBytes, signer.publicKey, signature)) {
    fail(`${label} signature is invalid`);
  }
  return Object.freeze({
    role: expectedRole,
    signer,
    statement: value.statement,
    statementSha256: value.statementSha256,
  });
}

function parseContributorStatement(value, {
  artifactEntries,
  expectedPolicy,
  expectedProfileId,
  expectedSequence,
  expectedToolchainSha256,
  label,
}) {
  exact(value, [
    'commandTranscript',
    'inputZkeySha256',
    'outputZkeySha256',
    'policy',
    'profileId',
    'schema',
    'sequence',
    'toolchainSha256',
  ], label);
  if (
    value.schema !== V2_FINAL_CEREMONY_CONTRIBUTION_SCHEMA
    || value.profileId !== expectedProfileId
    || value.sequence !== expectedSequence
    || value.toolchainSha256 !== expectedToolchainSha256
  ) {
    fail(`${label} identity, sequence, or toolchain is invalid`);
  }
  sameReference(
    artifactReference(value.policy, `${label}.policy`, artifactEntries),
    expectedPolicy,
    `${label}.policy`,
  );
  const commandTranscript = artifactReference(
    value.commandTranscript,
    `${label}.commandTranscript`,
    artifactEntries,
  );
  const inputZkeySha256 = hash(
    value.inputZkeySha256,
    `${label}.inputZkeySha256`,
  );
  const outputZkeySha256 = hash(
    value.outputZkeySha256,
    `${label}.outputZkeySha256`,
  );
  if (inputZkeySha256 === outputZkeySha256) {
    fail(`${label} must change the zkey`);
  }
  return Object.freeze({
    commandTranscript,
    inputZkeySha256,
    outputZkeySha256,
  });
}

function parseRegistryStatement(value, {
  artifactEntries,
  expectedPolicy,
  expectedProfileId,
  policy,
}) {
  exact(value, [
    'contributors',
    'policy',
    'profileId',
    'schema',
  ], 'final contributor registry statement');
  if (
    value.schema !== V2_FINAL_CONTRIBUTOR_REGISTRY_SCHEMA
    || value.profileId !== expectedProfileId
  ) {
    fail('final contributor registry identity is invalid');
  }
  sameReference(
    artifactReference(
      value.policy,
      'final contributor registry policy',
      artifactEntries,
    ),
    expectedPolicy,
    'final contributor registry policy',
  );
  if (
    !Array.isArray(value.contributors)
    || value.contributors.length < MINIMUM_CONTRIBUTORS
  ) {
    fail(`final contributor registry requires at least ${MINIMUM_CONTRIBUTORS} contributors`);
  }
  const seen = new Set();
  const parsed = Object.freeze(value.contributors.map((entry, index) => {
    const label = `final contributor registry contributors[${index}]`;
    exact(entry, [
      'independenceDomain',
      'organizationId',
      'publicKeySha256',
      'sequence',
      'signerId',
    ], label);
    if (entry.sequence !== index + 1) {
      fail('final contributor registry sequence must be contiguous from one');
    }
    const signerId = identifier(entry.signerId, `${label}.signerId`);
    const authority = policy.authorities.get(signerId);
    if (
      authority === undefined
      || authority.role !== 'ceremony-contributor'
      || entry.organizationId !== authority.organizationId
      || entry.independenceDomain !== authority.independenceDomain
      || entry.publicKeySha256 !== authority.publicKeySha256
      || seen.has(signerId)
    ) {
      fail(`${label} does not match one distinct policy contributor`);
    }
    seen.add(signerId);
    return Object.freeze({ sequence: entry.sequence, signerId });
  }));
  return parsed;
}

function parseBeaconStatement(value, {
  artifactEntries,
  expectedFinalZkey,
  expectedPolicy,
  expectedProfileId,
  expectedToolchainSha256,
}) {
  exact(value, [
    'beaconValue',
    'commandTranscript',
    'finalZkey',
    'inputZkeySha256',
    'iterations',
    'policy',
    'profileId',
    'schema',
    'toolchainSha256',
  ], 'final ceremony beacon statement');
  if (
    value.schema !== V2_FINAL_CEREMONY_BEACON_SCHEMA
    || value.profileId !== expectedProfileId
    || value.toolchainSha256 !== expectedToolchainSha256
  ) {
    fail('final ceremony beacon identity or toolchain is invalid');
  }
  sameReference(
    artifactReference(
      value.policy,
      'final ceremony beacon policy',
      artifactEntries,
    ),
    expectedPolicy,
    'final ceremony beacon policy',
  );
  sameReference(
    artifactReference(
      value.finalZkey,
      'final ceremony beacon finalZkey',
      artifactEntries,
    ),
    expectedFinalZkey,
    'final ceremony beacon finalZkey',
  );
  const beaconValue = artifactReference(
    value.beaconValue,
    'final ceremony beacon beaconValue',
    artifactEntries,
  );
  const commandTranscript = artifactReference(
    value.commandTranscript,
    'final ceremony beacon commandTranscript',
    artifactEntries,
  );
  if (beaconValue.artifactId === commandTranscript.artifactId) {
    fail('final ceremony beacon value and command transcript must be distinct artifacts');
  }
  positiveInteger(value.iterations, 'final ceremony beacon iterations');
  return Object.freeze({
    inputZkeySha256: hash(
      value.inputZkeySha256,
      'final ceremony beacon inputZkeySha256',
    ),
    outputZkeySha256: expectedFinalZkey.sha256,
    beaconValue,
    commandTranscript,
  });
}

function parseTranscriptStatement(value, {
  artifactEntries,
  expected,
  expectedToolchainSha256,
  policy,
}) {
  exact(value, [
    'beacon',
    'circuitBuildAttestation',
    'contributions',
    'contributorRegistry',
    'finalZkey',
    'initialZkey',
    'policy',
    'powersOfTau',
    'profileId',
    'r1cs',
    'relationSourceManifest',
    'schema',
    'snarkjsToolchain',
    'verificationKey',
  ], 'final ceremony transcript statement');
  if (
    value.schema !== V2_FINAL_CEREMONY_TRANSCRIPT_SCHEMA
    || value.profileId !== expected.profileId
  ) {
    fail('final ceremony transcript identity is invalid');
  }
  for (const [name, reference] of [
    ['policy', expected.policy],
    ['contributorRegistry', expected.contributorRegistry],
    ['beacon', expected.beacon],
    ['relationSourceManifest', expected.relationSourceManifest],
    ['circuitBuildAttestation', expected.circuitBuildAttestation],
    ['r1cs', expected.r1cs],
    ['powersOfTau', expected.powersOfTau],
    ['initialZkey', expected.initialZkey],
    ['finalZkey', expected.finalZkey],
    ['snarkjsToolchain', expected.snarkjsToolchain],
    ['verificationKey', expected.verificationKey],
  ]) {
    sameReference(
      artifactReference(
        value[name],
        `final ceremony transcript ${name}`,
        artifactEntries,
      ),
      reference,
      `final ceremony transcript ${name}`,
    );
  }
  if (
    !Array.isArray(value.contributions)
    || value.contributions.length < MINIMUM_CONTRIBUTORS
  ) {
    fail(`final ceremony transcript requires at least ${MINIMUM_CONTRIBUTORS} contributions`);
  }
  const seen = new Set();
  const commandTranscripts = new Set();
  let previousZkeySha256 = expected.initialZkey.sha256;
  const contributions = [];
  for (const [index, envelope] of value.contributions.entries()) {
    const label = `final ceremony transcript contributions[${index}]`;
    const signed = signedEvidence(envelope, {
      label,
      policy,
      expectedRole: 'ceremony-contributor',
      expectedSchema: V2_FINAL_CEREMONY_CONTRIBUTION_SCHEMA,
      contributor: true,
    });
    if (seen.has(signed.signer.signerId)) {
      fail('final ceremony transcript reuses a contributor identity');
    }
    seen.add(signed.signer.signerId);
    const statement = parseContributorStatement(signed.statement, {
      artifactEntries,
      expectedPolicy: expected.policy,
      expectedProfileId: expected.profileId,
      expectedSequence: index + 1,
      expectedToolchainSha256,
      label: `${label}.statement`,
    });
    if (statement.inputZkeySha256 !== previousZkeySha256) {
      fail('final ceremony transcript contribution chain is discontinuous');
    }
    if (commandTranscripts.has(statement.commandTranscript.artifactId)) {
      fail('final ceremony transcript reuses a contribution command transcript');
    }
    commandTranscripts.add(statement.commandTranscript.artifactId);
    previousZkeySha256 = statement.outputZkeySha256;
    contributions.push(Object.freeze({
      sequence: index + 1,
      signerId: signed.signer.signerId,
      outputZkeySha256: statement.outputZkeySha256,
    }));
  }
  return Object.freeze({
    contributions: Object.freeze(contributions),
    preBeaconZkeySha256: previousZkeySha256,
  });
}

function parseTranscriptVerificationStatement(value, {
  artifactEntries,
  expected,
  expectedRole,
  expectedToolchainSha256,
}) {
  exact(value, [
    'beacon',
    'commandTranscript',
    'finalZkey',
    'machineManifest',
    'policy',
    'powersOfTau',
    'profileId',
    'r1cs',
    'result',
    'schema',
    'snarkjsToolchain',
    'verificationLog',
    'toolchainSha256',
    'transcript',
    'verificationKey',
  ], `${expectedRole} statement`);
  if (
    value.schema !== V2_FINAL_TRANSCRIPT_VERIFICATION_SCHEMA
    || value.profileId !== expected.profileId
    || value.result !== 'verified'
    || value.toolchainSha256 !== expectedToolchainSha256
  ) {
    fail(`${expectedRole} identity, result, or toolchain is invalid`);
  }
  for (const [name, reference] of [
    ['policy', expected.policy],
    ['transcript', expected.transcript],
    ['beacon', expected.beacon],
    ['r1cs', expected.r1cs],
    ['powersOfTau', expected.powersOfTau],
    ['finalZkey', expected.finalZkey],
    ['snarkjsToolchain', expected.snarkjsToolchain],
    ['verificationKey', expected.verificationKey],
  ]) {
    sameReference(
      artifactReference(
        value[name],
        `${expectedRole} ${name}`,
        artifactEntries,
      ),
      reference,
      `${expectedRole} ${name}`,
    );
  }
  const commandTranscript = artifactReference(
    value.commandTranscript,
    `${expectedRole} commandTranscript`,
    artifactEntries,
  );
  const machineManifest = artifactReference(
    value.machineManifest,
    `${expectedRole} machineManifest`,
    artifactEntries,
  );
  const verificationLog = artifactReference(
    value.verificationLog,
    `${expectedRole} verificationLog`,
    artifactEntries,
  );
  if (
    new Set([
      commandTranscript.artifactId,
      machineManifest.artifactId,
      verificationLog.artifactId,
    ]).size !== 3
  ) {
    fail(`${expectedRole} command, machine, and verification artifacts must be distinct`);
  }
  return Object.freeze({
    machineManifestSha256: machineManifest.sha256,
  });
}

function parseReproductionStatement(value, {
  artifactEntries,
  expected,
  expectedRole,
  expectedToolchainSha256,
}) {
  exact(value, [
    'circuitBuildAttestation',
    'circuitSymbols',
    'commandTranscript',
    'finalLocksSha256',
    'finalZkey',
    'instanceId',
    'lockfile',
    'machineManifest',
    'policy',
    'profileId',
    'relationSourceManifest',
    'results',
    'r1cs',
    'runtimeMaterialSha256',
    'schema',
    'snarkjsToolchain',
    'sourceCommit',
    'sourceTree',
    'toolchainSha256',
    'transcript',
    'verificationKey',
    'witnessWasm',
  ], `${expectedRole} statement`);
  if (
    value.schema !== V2_FINAL_REPRODUCTION_SCHEMA
    || value.profileId !== expected.profileId
    || value.instanceId !== expected.instanceId
    || value.finalLocksSha256 !== expected.finalLocksSha256
    || value.runtimeMaterialSha256 !== expected.runtimeMaterialSha256
    || value.toolchainSha256 !== expectedToolchainSha256
  ) {
    fail(`${expectedRole} identity or runtime binding is invalid`);
  }
  for (const [name, reference] of [
    ['policy', expected.policy],
    ['transcript', expected.transcript],
    ['relationSourceManifest', expected.relationSourceManifest],
    ['circuitBuildAttestation', expected.circuitBuildAttestation],
    ['r1cs', expected.r1cs],
    ['witnessWasm', expected.witnessWasm],
    ['circuitSymbols', expected.circuitSymbols],
    ['finalZkey', expected.finalZkey],
    ['snarkjsToolchain', expected.snarkjsToolchain],
    ['verificationKey', expected.verificationKey],
  ]) {
    sameReference(
      artifactReference(
        value[name],
        `${expectedRole} ${name}`,
        artifactEntries,
      ),
      reference,
      `${expectedRole} ${name}`,
    );
  }
  exact(value.results, [
    'circuitReproduced',
    'finalZkeyVerified',
    'runtimeReproduced',
    'verificationKeyExported',
  ], `${expectedRole} results`);
  if (
    value.results.circuitReproduced !== true
    || value.results.finalZkeyVerified !== true
    || value.results.runtimeReproduced !== true
    || value.results.verificationKeyExported !== true
  ) {
    fail(`${expectedRole} did not reproduce and verify every final artifact`);
  }
  if (
    typeof value.sourceCommit !== 'string'
    || !GIT_OBJECT.test(value.sourceCommit)
    || typeof value.sourceTree !== 'string'
    || !GIT_OBJECT.test(value.sourceTree)
  ) {
    fail(`${expectedRole} source commit/tree are invalid`);
  }
  const commandTranscript = artifactReference(
    value.commandTranscript,
    `${expectedRole} commandTranscript`,
    artifactEntries,
  );
  const lockfile = artifactReference(
    value.lockfile,
    `${expectedRole} lockfile`,
    artifactEntries,
  );
  const machineManifest = artifactReference(
    value.machineManifest,
    `${expectedRole} machineManifest`,
    artifactEntries,
  );
  if (
    new Set([
      commandTranscript.artifactId,
      lockfile.artifactId,
      machineManifest.artifactId,
    ]).size !== 3
  ) {
    fail(`${expectedRole} command, lockfile, and machine artifacts must be distinct`);
  }
  return Object.freeze({
    sourceCommit: value.sourceCommit,
    sourceTree: value.sourceTree,
    lockfileSha256: lockfile.sha256,
    machineManifestSha256: machineManifest.sha256,
  });
}

/**
 * Verify the D-01 evidence needed to use a final Groth16 key.
 *
 * The signed descriptor and profile core remain the trust root. The final
 * evidence policy must itself be one of the profile-core base artifacts, so a
 * release manifest cannot silently substitute ceremony identities.
 */
export async function verifyV2FinalRuntimeEvidence({
  artifactEntries,
  finalLocksSha256,
  instanceId,
  profileBaseArtifacts,
  profileId,
  profileProof,
  profileToolchainSha256,
  readArtifactBytes,
  runtimeMaterialSha256,
  runtimeReferences,
}) {
  plain(artifactEntries, 'final runtime artifactEntries');
  plain(profileBaseArtifacts, 'final runtime profileBaseArtifacts');
  plain(profileProof, 'final runtime profileProof');
  plain(runtimeReferences, 'final runtime references');
  if (typeof readArtifactBytes !== 'function') {
    fail('final runtime readArtifactBytes must be a function');
  }
  hash(profileId, 'final runtime profileId');
  hash(instanceId, 'final runtime instanceId');
  hash(finalLocksSha256, 'final runtime finalLocksSha256');
  hash(runtimeMaterialSha256, 'final runtime runtimeMaterialSha256');
  hash(profileToolchainSha256, 'final runtime profileToolchainSha256');

  const policyEntry =
    artifactEntries[V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID];
  if (
    policyEntry === undefined
    || profileBaseArtifacts[V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID]
      !== policyEntry.sha256
    || runtimeReferences.policy
      !== V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID
  ) {
    fail('final evidence policy is not frozen in the profile core and runtime');
  }
  const references = Object.freeze({
    profileId,
    instanceId,
    policy: expectedReference(
      runtimeReferences.policy,
      artifactEntries,
      'final runtime policy',
    ),
    contributorRegistry: expectedReference(
      runtimeReferences.contributorRegistry,
      artifactEntries,
      'final runtime contributor registry',
    ),
    transcript: expectedReference(
      runtimeReferences.transcript,
      artifactEntries,
      'final runtime transcript',
    ),
    beacon: expectedReference(
      runtimeReferences.beacon,
      artifactEntries,
      'final runtime beacon',
    ),
    relationSourceManifest: expectedReference(
      runtimeReferences.relationSourceManifest,
      artifactEntries,
      'final runtime relation source manifest',
    ),
    circuitBuildAttestation: expectedReference(
      runtimeReferences.circuitBuildAttestation,
      artifactEntries,
      'final runtime circuit build attestation',
    ),
    r1cs: expectedReference(
      runtimeReferences.r1cs,
      artifactEntries,
      'final runtime R1CS',
    ),
    witnessWasm: expectedReference(
      runtimeReferences.witnessWasm,
      artifactEntries,
      'final runtime witness WASM',
    ),
    circuitSymbols: expectedReference(
      runtimeReferences.circuitSymbols,
      artifactEntries,
      'final runtime circuit symbols',
    ),
    powersOfTau: expectedReference(
      runtimeReferences.powersOfTau,
      artifactEntries,
      'final runtime Powers of Tau',
    ),
    initialZkey: expectedReference(
      runtimeReferences.initialZkey,
      artifactEntries,
      'final runtime initial zkey',
    ),
    finalZkey: expectedReference(
      runtimeReferences.finalZkey,
      artifactEntries,
      'final runtime final zkey',
    ),
    verificationKey: expectedReference(
      runtimeReferences.verificationKey,
      artifactEntries,
      'final runtime verification key',
    ),
    snarkjsToolchain: expectedReference(
      runtimeReferences.snarkjsToolchain,
      artifactEntries,
      'final runtime snarkjs toolchain',
    ),
    finalLocksSha256,
    runtimeMaterialSha256,
  });
  if (
    references.r1cs.sha256 !== profileProof.r1csSha256
    || references.witnessWasm.sha256 !== profileProof.witnessWasmSha256
    || references.verificationKey.sha256
      !== profileProof.verificationKeySha256
  ) {
    fail('final runtime proof artifacts differ from the frozen profile core');
  }

  const readPinnedArtifact = pinnedArtifactReader({
    artifactEntries,
    readArtifactBytes,
  });
  // Verify every top-level final-runtime artifact before any evidence envelope
  // is parsed. This includes binary circuit/setup material: although this
  // module does not interpret it, accepting a mutable loader for it would make
  // the signed transcript's references meaningless.
  await Promise.all([
    ['policy', references.policy],
    ['contributor registry', references.contributorRegistry],
    ['transcript', references.transcript],
    ['beacon', references.beacon],
    ['relation source manifest', references.relationSourceManifest],
    ['circuit build attestation', references.circuitBuildAttestation],
    ['R1CS', references.r1cs],
    ['witness WASM', references.witnessWasm],
    ['circuit symbols', references.circuitSymbols],
    ['Powers of Tau', references.powersOfTau],
    ['initial zkey', references.initialZkey],
    ['final zkey', references.finalZkey],
    ['verification key', references.verificationKey],
    ['snarkjs toolchain', references.snarkjsToolchain],
  ].map(([name, reference]) => readPinnedArtifact(
    reference,
    `final runtime ${name}`,
  )));

  const policyBytes = await readPinnedArtifact(
    references.policy,
    'final evidence policy',
  );
  const policy = parsePolicy(
    parseCanonical(policyBytes, 'final evidence policy'),
    {
      expectedPolicySha256: references.policy.sha256,
      policyBytes,
    },
  );

  const registryEnvelope = parseCanonical(
    await readPinnedArtifact(
      references.contributorRegistry,
      'final contributor registry',
    ),
    'final contributor registry',
  );
  const registrySigned = signedEvidence(registryEnvelope, {
    label: 'final contributor registry',
    policy,
    expectedRole: 'ceremony-coordinator',
    expectedSchema: V2_FINAL_CONTRIBUTOR_REGISTRY_SCHEMA,
  });
  await verifyNestedArtifactReferences(registrySigned.statement, {
    artifactEntries,
    readPinnedArtifact,
    label: 'final contributor registry statement',
  });
  const registry = parseRegistryStatement(registrySigned.statement, {
    artifactEntries,
    expectedPolicy: references.policy,
    expectedProfileId: profileId,
    policy,
  });

  const beaconEnvelope = parseCanonical(
    await readPinnedArtifact(
      references.beacon,
      'final ceremony beacon',
    ),
    'final ceremony beacon',
  );
  const beaconSigned = signedEvidence(beaconEnvelope, {
    label: 'final ceremony beacon',
    policy,
    expectedRole: 'ceremony-coordinator',
    expectedSchema: V2_FINAL_CEREMONY_BEACON_SCHEMA,
  });
  await verifyNestedArtifactReferences(beaconSigned.statement, {
    artifactEntries,
    readPinnedArtifact,
    label: 'final ceremony beacon statement',
  });
  const beacon = parseBeaconStatement(beaconSigned.statement, {
    artifactEntries,
    expectedFinalZkey: references.finalZkey,
    expectedPolicy: references.policy,
    expectedProfileId: profileId,
    expectedToolchainSha256: profileToolchainSha256,
  });

  const transcriptEnvelope = parseCanonical(
    await readPinnedArtifact(
      references.transcript,
      'final ceremony transcript',
    ),
    'final ceremony transcript',
  );
  const transcriptSigned = signedEvidence(transcriptEnvelope, {
    label: 'final ceremony transcript',
    policy,
    expectedRole: 'ceremony-coordinator',
    expectedSchema: V2_FINAL_CEREMONY_TRANSCRIPT_SCHEMA,
  });
  await verifyNestedArtifactReferences(transcriptSigned.statement, {
    artifactEntries,
    readPinnedArtifact,
    label: 'final ceremony transcript statement',
  });
  const transcript = parseTranscriptStatement(transcriptSigned.statement, {
    artifactEntries,
    expected: references,
    expectedToolchainSha256: profileToolchainSha256,
    policy,
  });
  if (
    transcript.preBeaconZkeySha256 !== beacon.inputZkeySha256
    || beacon.outputZkeySha256 !== references.finalZkey.sha256
    || registry.length !== transcript.contributions.length
    || registry.some((entry, index) => (
      entry.sequence !== transcript.contributions[index].sequence
      || entry.signerId !== transcript.contributions[index].signerId
    ))
  ) {
    fail('final ceremony registry, contribution chain, beacon, and final zkey do not agree');
  }

  if (
    !Array.isArray(runtimeReferences.transcriptVerifications)
    || runtimeReferences.transcriptVerifications.length !== 2
    || !Array.isArray(runtimeReferences.reproductions)
    || runtimeReferences.reproductions.length !== 2
  ) {
    fail('final runtime requires exactly two transcript verifications and two reproductions');
  }
  const transcriptVerificationReferences = runtimeReferences
    .transcriptVerifications.map((artifactId, index) => expectedReference(
      artifactId,
      artifactEntries,
      `${EXPECTED_TRANSCRIPT_VERIFIER_ROLES[index]} evidence`,
    ));
  const reproductionReferences = runtimeReferences.reproductions.map(
    (artifactId, index) => expectedReference(
      artifactId,
      artifactEntries,
      `${EXPECTED_REPRODUCTION_ROLES[index]} evidence`,
    ),
  );
  const transcriptVerificationResults = [];
  for (const [index, reference] of transcriptVerificationReferences.entries()) {
    const expectedRole = EXPECTED_TRANSCRIPT_VERIFIER_ROLES[index];
    const envelope = parseCanonical(
      await readPinnedArtifact(reference, `${expectedRole} evidence`),
      `${expectedRole} evidence`,
    );
    const signed = signedEvidence(envelope, {
      label: `${expectedRole} evidence`,
      policy,
      expectedRole,
      expectedSchema: V2_FINAL_TRANSCRIPT_VERIFICATION_SCHEMA,
    });
    await verifyNestedArtifactReferences(signed.statement, {
      artifactEntries,
      readPinnedArtifact,
      label: `${expectedRole} evidence statement`,
    });
    transcriptVerificationResults.push(
      parseTranscriptVerificationStatement(signed.statement, {
        artifactEntries,
        expected: references,
        expectedRole,
        expectedToolchainSha256: profileToolchainSha256,
      }),
    );
  }
  if (
    transcriptVerificationResults[0].machineManifestSha256
      === transcriptVerificationResults[1].machineManifestSha256
  ) {
    fail('final transcript verification hosts must have distinct machine manifests');
  }

  const reproductionResults = [];
  for (const [index, reference] of reproductionReferences.entries()) {
    const expectedRole = EXPECTED_REPRODUCTION_ROLES[index];
    const envelope = parseCanonical(
      await readPinnedArtifact(reference, `${expectedRole} evidence`),
      `${expectedRole} evidence`,
    );
    const signed = signedEvidence(envelope, {
      label: `${expectedRole} evidence`,
      policy,
      expectedRole,
      expectedSchema: V2_FINAL_REPRODUCTION_SCHEMA,
    });
    await verifyNestedArtifactReferences(signed.statement, {
      artifactEntries,
      readPinnedArtifact,
      label: `${expectedRole} evidence statement`,
    });
    reproductionResults.push(parseReproductionStatement(signed.statement, {
      artifactEntries,
      expected: references,
      expectedRole,
      expectedToolchainSha256: profileToolchainSha256,
    }));
  }
  if (
    reproductionResults[0].machineManifestSha256
      === reproductionResults[1].machineManifestSha256
    || reproductionResults[0].sourceCommit
      !== reproductionResults[1].sourceCommit
    || reproductionResults[0].sourceTree
      !== reproductionResults[1].sourceTree
    || reproductionResults[0].lockfileSha256
      !== reproductionResults[1].lockfileSha256
  ) {
    fail('final reproduction hosts are not distinct or did not reproduce identical source and lockfile inputs');
  }

  return Object.freeze({
    schema: 'shieldkit-v2-direct-final-runtime-evidence-resolution-v2',
    policySha256: references.policy.sha256,
    contributorRegistrySha256: references.contributorRegistry.sha256,
    transcriptSha256: references.transcript.sha256,
    beaconSha256: references.beacon.sha256,
    snarkjsToolchainSha256: references.snarkjsToolchain.sha256,
    contributorCount: transcript.contributions.length,
    transcriptVerificationSha256s: Object.freeze(
      runtimeReferences.transcriptVerifications.map(
        (artifactId) => artifactEntries[artifactId].sha256,
      ),
    ),
    reproductionSha256s: Object.freeze(
      runtimeReferences.reproductions.map(
        (artifactId) => artifactEntries[artifactId].sha256,
      ),
    ),
    sourceCommit: reproductionResults[0].sourceCommit,
    sourceTree: reproductionResults[0].sourceTree,
    lockfileSha256: reproductionResults[0].lockfileSha256,
  });
}
