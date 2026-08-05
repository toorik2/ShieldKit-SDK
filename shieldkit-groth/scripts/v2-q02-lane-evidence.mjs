/*
 * Offline replay for externally produced Q-02 evidence.
 *
 * This module derives a lane result from signed raw evidence. It deliberately
 * has no qualification boolean and no caller-selected trust-root CLI. The
 * qualifying Q-02 gate must obtain its authority artifact through a signed V2
 * instance manifest and call
 * `deriveV2Q02LaneAuthorityContextFromValidatedDescriptor`.
 */
import {
  createPublicKey,
} from 'node:crypto';
import {
  dirname,
} from 'node:path';

import {
  canonicalizeJcs,
} from '../packages/profile/v2/profile-core.mjs';
import {
  deriveV2ManifestArtifactFromValidatedDescriptor,
} from '../packages/profile/v2/instance-descriptor.mjs';
import {
  verifyBchTransactionMerkleProof,
  verifyRawHeaderSegment,
} from '../packages/recover/raw-chain-recovery.mjs';
import {
  parseSerializedSourceOutput,
  parseV2RawTransaction,
} from '../packages/kit/v2/transaction-policy.mjs';
import {
  directV2VerifierTopologyById,
} from '../packages/action/v2/topology.mjs';
import {
  createV2LaneEvidenceContextBrand,
  createV2LaneEvidencePrimitives,
} from './v2-lane-evidence-primitives.mjs';

const HASH = /^[0-9a-f]{64}$/;
const GIT_HASH = /^[0-9a-f]{40}$/;
const IDENTIFIER = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const SEMVER = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
const ROLES = Object.freeze([
  'maintainer',
  'bchn-mempool',
  'bchn-mined',
  'leanbch',
]);
const KINDS = new Set(['deposit', 'transfer', 'withdrawal']);
const MUTATION_FIELDS = new Set([
  'proof',
  'packet',
  'state',
  'profile',
  'category',
  'carrier',
  'token',
  'value',
  'role',
  'outpoint',
  'fee',
  'change',
  'payout',
]);

export const V2_Q02_LANE_AUTHORITY_ARTIFACT_ID =
  'q02-lane-authorities';
export const V2_Q02_LANE_AUTHORITIES_SCHEMA =
  'shieldkit-v2-direct-q02-lane-authorities-v2';
export const V2_Q02_LANE_ENVELOPE_SCHEMA =
  'shieldkit-v2-direct-q02-lane-envelope-v2';
export const V2_Q02_LANE_ATTESTATION_DOMAIN =
  'shieldkit-v2-direct-q02-lane-attestation';
export const V2_Q02_LANE_ATTESTATION_VERSION = 2;

export class V2Q02LaneEvidenceError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2Q02LaneEvidenceError';
  }
}

const fail = (message) => {
  throw new V2Q02LaneEvidenceError(message);
};
const {
  assertExactInputCount,
  canonicalBytes,
  canonicalTimestamp,
  exact,
  hash,
  integer,
  jcsReference,
  plain,
  readStableDirectFile,
  relativeReference,
  sha256,
  text,
  validateBchnMempoolLane,
  validateBchnMinedLane,
  validateExternalPerInputLane,
  validateMachineManifest,
  verifySignedLaneEnvelope,
} = createV2LaneEvidencePrimitives({
  canonicalizeJcs,
  fail,
  parseRawTransaction: parseV2RawTransaction,
  parseSerializedSourceOutput: parseSerializedSourceOutput,
  verifyBchTransactionMerkleProof,
  verifyRawHeaderSegment,
});

function tool(value, label) {
  exact(value, [
    'commit',
    'executableSha256',
    'lockfileSha256',
    'repositoryUrl',
    'runnerSha256',
    'sourceSha256',
    'tree',
    'version',
  ], label);
  if (
    typeof value.repositoryUrl !== 'string'
    || !/^https:\/\/[^/?#\s]+\/\S+$/u.test(value.repositoryUrl)
    || typeof value.commit !== 'string'
    || !GIT_HASH.test(value.commit)
    || typeof value.tree !== 'string'
    || !GIT_HASH.test(value.tree)
    || typeof value.version !== 'string'
    || !SEMVER.test(value.version)
  ) {
    fail(`${label} repository, revision, tree, or version pin is invalid`);
  }
  for (const key of [
    'executableSha256',
    'lockfileSha256',
    'runnerSha256',
    'sourceSha256',
  ]) {
    hash(value[key], `${label}.${key}`);
  }
  return Object.freeze({ ...value });
}

function command(value, label) {
  exact(value, ['arguments', 'executable'], label);
  text(value.executable, `${label}.executable`, 4096);
  if (
    !Array.isArray(value.arguments)
    || value.arguments.length > 128
    || value.arguments.some(
      (entry) => typeof entry !== 'string' || entry.length > 16_384,
    )
  ) {
    fail(`${label}.arguments must be a bounded string array`);
  }
  return Object.freeze({
    executable: value.executable,
    arguments: Object.freeze([...value.arguments]),
  });
}

function publicAuthority(value, label) {
  exact(value, [
    'authorityId',
    'command',
    'organization',
    'publicKey',
    'role',
    'tool',
  ], label);
  if (
    typeof value.authorityId !== 'string'
    || !IDENTIFIER.test(value.authorityId)
    || !ROLES.includes(value.role)
  ) {
    fail(`${label} id or role is invalid`);
  }
  text(value.organization, `${label}.organization`, 256);
  let key;
  try {
    key = createPublicKey(value.publicKey);
  } catch {
    fail(`${label}.publicKey is invalid`);
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    fail(`${label}.publicKey must be Ed25519`);
  }
  return Object.freeze({
    authorityId: value.authorityId,
    command: command(value.command, `${label}.command`),
    key,
    keyFingerprint: sha256(key.export({ type: 'spki', format: 'der' })),
    organization: value.organization,
    publicKey: value.publicKey,
    role: value.role,
    tool: tool(value.tool, `${label}.tool`),
  });
}

function parseAuthorityArtifact(bytes, pins) {
  let value;
  try {
    value = JSON.parse(bytes);
  } catch {
    fail('Q-02 lane authority artifact is not JSON');
  }
  if (!bytes.equals(canonicalBytes(value))) {
    fail('Q-02 lane authority artifact must use exact RFC8785/JCS bytes');
  }
  exact(value, [
    'authorities',
    'chipnetPolicy',
    'evidenceWindow',
    'finalLocksSha256',
    'instanceId',
    'network',
    'profileId',
    'schema',
    'topologyId',
  ], 'Q-02 lane authority artifact');
  if (
    value.schema !== V2_Q02_LANE_AUTHORITIES_SCHEMA
    || value.profileId !== pins.profileId
    || value.instanceId !== pins.instanceId
    || value.topologyId !== pins.topologyId
    || value.finalLocksSha256 !== pins.finalLocksSha256
  ) {
    fail('Q-02 lane authority artifact does not bind the final descriptor');
  }
  exact(value.network, ['id', 'name'], 'Q-02 lane network');
  if (value.network.id !== 2 || value.network.name !== 'chipnet') {
    fail('Q-02 external qualification is restricted to Chipnet');
  }
  exact(
    value.evidenceWindow,
    ['notAfter', 'notBefore'],
    'Q-02 lane evidence window',
  );
  const notBefore = canonicalTimestamp(
    value.evidenceWindow.notBefore,
    'Q-02 evidenceWindow.notBefore',
  );
  const notAfter = canonicalTimestamp(
    value.evidenceWindow.notAfter,
    'Q-02 evidenceWindow.notAfter',
  );
  if (notAfter <= notBefore) {
    fail('Q-02 lane evidence window is empty or reversed');
  }
  exact(
    value.chipnetPolicy,
    ['checkpoint', 'minimumConfirmations'],
    'Q-02 Chipnet policy',
  );
  exact(
    value.chipnetPolicy.checkpoint,
    ['blockHash', 'chainwork', 'height', 'maximumTarget'],
    'Q-02 Chipnet checkpoint',
  );
  hash(
    value.chipnetPolicy.checkpoint.blockHash,
    'Q-02 checkpoint.blockHash',
  );
  hash(
    value.chipnetPolicy.checkpoint.maximumTarget,
    'Q-02 checkpoint.maximumTarget',
  );
  integer(
    value.chipnetPolicy.checkpoint.height,
    0,
    Number.MAX_SAFE_INTEGER,
    'Q-02 checkpoint.height',
  );
  if (
    typeof value.chipnetPolicy.checkpoint.chainwork !== 'string'
    || !/^(0|[1-9][0-9]*)$/u.test(
      value.chipnetPolicy.checkpoint.chainwork,
    )
  ) {
    fail('Q-02 checkpoint.chainwork must be canonical decimal');
  }
  integer(
    value.chipnetPolicy.minimumConfirmations,
    1,
    10_000,
    'Q-02 minimumConfirmations',
  );
  if (
    !Array.isArray(value.authorities)
    || value.authorities.length !== ROLES.length
  ) {
    fail('Q-02 lane authority artifact must contain exactly four roles');
  }
  const byRole = new Map();
  const authorityIds = new Set();
  const keyFingerprints = new Set();
  for (const [index, entry] of value.authorities.entries()) {
    const authority = publicAuthority(
      entry,
      `Q-02 lane authority ${index}`,
    );
    if (
      byRole.has(authority.role)
      || authorityIds.has(authority.authorityId)
      || keyFingerprints.has(authority.keyFingerprint)
    ) {
      fail('Q-02 lane roles, authority ids, and Ed25519 keys must be distinct');
    }
    byRole.set(authority.role, authority);
    authorityIds.add(authority.authorityId);
    keyFingerprints.add(authority.keyFingerprint);
  }
  if (ROLES.some((role) => !byRole.has(role))) {
    fail('Q-02 lane authority artifact omits a required role');
  }
  const topology = directV2VerifierTopologyById(value.topologyId);
  return Object.freeze({
    byRole,
    checkpoint: Object.freeze({ ...value.chipnetPolicy.checkpoint }),
    minimumConfirmations: value.chipnetPolicy.minimumConfirmations,
    network: Object.freeze({ ...value.network }),
    notAfter,
    notBefore,
    topology,
  });
}

const authorityContexts = createV2LaneEvidenceContextBrand({
  fail,
  label: 'Q-02 lane authority context',
});

/**
 * Parse an authority artifact whose hash and descriptor bindings have already
 * been obtained from a signed instance manifest. This lower-level constructor
 * exists for deterministic parser tests; it does not return qualification.
 */
export function createV2Q02PinnedLaneAuthorityContext(value) {
  exact(value, [
    'artifactBytes',
    'artifactSha256',
    'descriptorSha256',
    'finalLocksSha256',
    'instanceId',
    'manifestSha256',
    'profileId',
    'topologyId',
  ], 'Q-02 pinned authority context');
  if (!(value.artifactBytes instanceof Uint8Array)) {
    fail('Q-02 authority artifact must be bytes');
  }
  for (const key of [
    'artifactSha256',
    'descriptorSha256',
    'finalLocksSha256',
    'instanceId',
    'manifestSha256',
    'profileId',
  ]) {
    hash(value[key], `Q-02 authority context.${key}`);
  }
  text(value.topologyId, 'Q-02 authority context.topologyId', 128);
  const artifactBytes = Buffer.from(value.artifactBytes);
  if (sha256(artifactBytes) !== value.artifactSha256) {
    fail('Q-02 authority artifact hash differs from its signed-manifest pin');
  }
  const parsed = parseAuthorityArtifact(artifactBytes, value);
  const privateContext = {
    ...parsed,
    authoritySetSha256: value.artifactSha256,
    descriptorSha256: value.descriptorSha256,
    finalLocksSha256: value.finalLocksSha256,
    instanceId: value.instanceId,
    manifestSha256: value.manifestSha256,
    profileId: value.profileId,
    topologyId: value.topologyId,
  };
  return authorityContexts.create({
    authoritySetSha256: value.artifactSha256,
    checkpoint: Object.freeze({ ...parsed.checkpoint }),
    descriptorSha256: value.descriptorSha256,
    finalLocksSha256: value.finalLocksSha256,
    instanceId: value.instanceId,
    manifestSha256: value.manifestSha256,
    profileId: value.profileId,
    topologyId: value.topologyId,
  }, privateContext);
}

/**
 * Resolve the only production authority context accepted by Q-02: an artifact
 * whose path and SHA-256 were authenticated by the signed instance manifest.
 */
export function deriveV2Q02LaneAuthorityContextFromValidatedDescriptor(
  descriptor,
) {
  const pin = deriveV2ManifestArtifactFromValidatedDescriptor(
    descriptor,
    V2_Q02_LANE_AUTHORITY_ARTIFACT_ID,
  );
  const artifactBytes = readStableDirectFile(
    pin.path,
    'signed-manifest Q-02 lane authority artifact',
  );
  return createV2Q02PinnedLaneAuthorityContext({
    artifactBytes,
    artifactSha256: pin.sha256,
    descriptorSha256: pin.descriptorSha256,
    finalLocksSha256: pin.finalLocksSha256,
    instanceId: pin.instanceId,
    manifestSha256: pin.manifestSha256,
    profileId: pin.profileId,
    topologyId: pin.topologyId,
  });
}

function mutation(value, expectation, label) {
  if (expectation === 'accept') {
    if (value !== null) fail(`${label} must be null for an accepted base case`);
    return null;
  }
  exact(value, [
    'baseBundleSha256',
    'field',
    'mutantBundleSha256',
  ], label);
  if (!MUTATION_FIELDS.has(value.field)) {
    fail(`${label}.field is not a required Q-02 mutation`);
  }
  hash(value.baseBundleSha256, `${label}.baseBundleSha256`);
  hash(value.mutantBundleSha256, `${label}.mutantBundleSha256`);
  if (value.baseBundleSha256 === value.mutantBundleSha256) {
    fail(`${label} base and mutant bundle hashes must differ`);
  }
  return Object.freeze({ ...value });
}

function caseBinding(value, label) {
  exact(value, [
    'caseId',
    'expectation',
    'index',
    'kind',
    'localVmEvidenceSha256',
    'metadataSha256',
    'mutation',
    'packetSha256',
    'proofSha256',
    'rawTransactionSha256',
    'transactionId',
  ], label);
  if (
    !KINDS.has(value.kind)
    || !Number.isInteger(value.index)
    || value.index < 0
    || value.index >= 256
    || value.caseId !== `${value.kind}-${value.index}`
    || !['accept', 'reject'].includes(value.expectation)
  ) {
    fail(`${label} identity is invalid`);
  }
  for (const key of [
    'localVmEvidenceSha256',
    'metadataSha256',
    'packetSha256',
    'proofSha256',
    'rawTransactionSha256',
    'transactionId',
  ]) {
    hash(value[key], `${label}.${key}`);
  }
  return Object.freeze({
    ...value,
    mutation: mutation(value.mutation, value.expectation, `${label}.mutation`),
  });
}

function equalJcs(left, right) {
  return canonicalBytes(left).equals(canonicalBytes(right));
}

function verifyAuthorityLaneEnvelope({
  attestationDomain,
  attestationVersion,
  authorityContext,
  bchnMinedInputSchema,
  bchnMinedOutputSchema,
  envelopePath,
  envelopeSchema,
  expectedRole,
  expectedInputCount = undefined,
  expectedSourceOutputSha256s = undefined,
  expectedSubject,
  expectedTransaction,
  machineManifestSchema,
  subjectField,
  vmInputSchema,
  vmOutputSchema,
}) {
  authorityContexts.assert(authorityContext);
  const context = authorityContexts.get(authorityContext);
  if (!ROLES.includes(expectedRole)) {
    fail('lane evidence expected role is unsupported');
  }
  if (!['case', 'subject'].includes(subjectField)) {
    fail('lane evidence subject field is unsupported');
  }
  text(attestationDomain, 'lane attestation domain', 256);
  integer(
    attestationVersion,
    1,
    Number.MAX_SAFE_INTEGER,
    'lane attestation version',
  );
  text(envelopeSchema, 'lane envelope schema', 256);
  text(machineManifestSchema, 'lane machine-manifest schema', 256);
  text(vmInputSchema, 'lane VM input schema', 256);
  text(vmOutputSchema, 'lane VM output schema', 256);
  text(bchnMinedInputSchema, 'lane BCHN-mined input schema', 256);
  text(bchnMinedOutputSchema, 'lane BCHN-mined output schema', 256);
  plain(expectedSubject, 'expected lane subject');
  exact(
    expectedTransaction,
    ['expectation', 'rawTransactionSha256', 'transactionId'],
    'expected lane transaction',
  );
  hash(
    expectedTransaction.rawTransactionSha256,
    'expected lane transaction.rawTransactionSha256',
  );
  hash(
    expectedTransaction.transactionId,
    'expected lane transaction.transactionId',
  );
  if (!['accept', 'reject'].includes(expectedTransaction.expectation)) {
    fail('expected lane transaction expectation is invalid');
  }
  if (expectedInputCount !== undefined) {
    integer(expectedInputCount, 1, 258, 'expected lane input count');
  }
  if (expectedSourceOutputSha256s !== undefined) {
    if (!Array.isArray(expectedSourceOutputSha256s)
      || expectedSourceOutputSha256s.length === 0) {
      fail('expected lane source-output hashes must be a nonempty array');
    }
    for (const [index, digest] of expectedSourceOutputSha256s.entries()) {
      hash(digest, `expected lane source-output hash ${index}`);
    }
    if (expectedRole !== 'maintainer' && expectedRole !== 'leanbch') {
      fail('only maintainer/LeanBCH lanes carry source-output closures');
    }
  }

  const envelopeBytes = readStableDirectFile(
    envelopePath,
    `${expectedRole} lane envelope`,
  );
  let envelope;
  try {
    envelope = JSON.parse(envelopeBytes);
  } catch {
    fail(`${expectedRole} lane envelope is not JSON`);
  }
  if (!envelopeBytes.equals(canonicalBytes(envelope))) {
    fail(`${expectedRole} lane envelope must use exact RFC8785/JCS bytes`);
  }
  const envelopeKeys = [
    'authorityRole',
    'authoritySetSha256',
    'command',
    'completedAt',
    'descriptor',
    'execution',
    'runId',
    'schema',
    'signature',
    'startedAt',
    subjectField,
    'tool',
  ];
  exact(envelope, envelopeKeys, `${expectedRole} lane envelope`);
  if (
    envelope.authorityRole !== expectedRole
    || envelope.authoritySetSha256
      !== authorityContext.authoritySetSha256
    || typeof envelope.runId !== 'string'
    || !HASH.test(envelope.runId)
  ) {
    fail(`${expectedRole} lane envelope role, authority set, or run id is invalid`);
  }
  const authority = context.byRole.get(expectedRole);
  const expectedDescriptor = {
    descriptorSha256: context.descriptorSha256,
    finalLocksSha256: context.finalLocksSha256,
    instanceId: context.instanceId,
    manifestSha256: context.manifestSha256,
    network: context.network,
    profileId: context.profileId,
    topologyId: context.topologyId,
  };
  const { startedAt, completedAt } = verifySignedLaneEnvelope({
    attestationDomain,
    attestationVersion,
    authority,
    envelope,
    envelopeKeys,
    envelopeSchema,
    expectedAuthoritySetSha256: authorityContext.authoritySetSha256,
    expectedDescriptor,
    subjectValidator: (candidate) => {
      if (!equalJcs(candidate[subjectField], expectedSubject)) {
        fail(`${expectedRole} lane envelope does not bind its exact subject`);
      }
    },
    window: context,
  });
  exact(envelope.execution, [
    'exitCode',
    'machineManifest',
    'signal',
    'stderr',
    'stdin',
    'stdout',
  ], `${expectedRole} lane execution`);
  if (
    envelope.execution.exitCode !== 0
    || envelope.execution.signal !== null
  ) {
    fail(`${expectedRole} lane command did not exit successfully`);
  }
  const root = dirname(envelopePath);
  const stdin = jcsReference(
    envelope.execution.stdin,
    root,
    `${expectedRole} lane stdin`,
  );
  const stdout = jcsReference(
    envelope.execution.stdout,
    root,
    `${expectedRole} lane stdout`,
  );
  relativeReference(
    envelope.execution.stderr,
    root,
    `${expectedRole} lane stderr`,
    { allowEmpty: true },
  );
  const machine = jcsReference(
    envelope.execution.machineManifest,
    root,
    `${expectedRole} lane machine manifest`,
  );
  validateMachineManifest(machine.value, startedAt, completedAt, {
    label: `${expectedRole} lane machine manifest`,
    schema: machineManifestSchema,
  });

  let actualInputCount;
  let actualSourceOutputSha256s = null;
  if (expectedRole === 'maintainer' || expectedRole === 'leanbch') {
    let transaction;
    try { transaction = parseV2RawTransaction(stdin.value.rawTransactionHex); } catch {
      fail(`${expectedRole} stdin transaction is invalid`);
    }
    actualInputCount = transaction.inputs.length;
    actualSourceOutputSha256s = stdin.value.sourceOutputs.map((entry, index) => {
      if (typeof entry !== 'string' || !/^[0-9a-f]+$/u.test(entry)
        || entry.length % 2 !== 0) {
        fail(`${expectedRole} stdin source output ${index} is malformed`);
      }
      return sha256(Buffer.from(entry, 'hex'));
    });
  } else if (expectedRole === 'bchn-mempool') {
    const raw = stdin.value?.params?.[0]?.[0];
    let transaction;
    try { transaction = parseV2RawTransaction(raw); } catch {
      fail('BCHN mempool stdin transaction is invalid');
    }
    actualInputCount = transaction.inputs.length;
  } else {
    let transaction;
    try { transaction = parseV2RawTransaction(stdin.value.rawTransactionHex); } catch {
      fail('BCHN mined stdin transaction is invalid');
    }
    actualInputCount = transaction.inputs.length;
  }
  assertExactInputCount(actualInputCount, expectedInputCount, 'lane evidence input count');
  if (expectedSourceOutputSha256s !== undefined
    && !equalJcs(actualSourceOutputSha256s, expectedSourceOutputSha256s)) {
    fail('lane evidence source-output closure differs from exact expected hashes');
  }

  let accepted;
  if (expectedRole === 'maintainer' || expectedRole === 'leanbch') {
    accepted = validateExternalPerInputLane({
      context,
      expected: expectedTransaction,
      expectedInputCount:
        expectedInputCount ?? context.topology.inputCount,
      role: expectedRole,
      stdin: stdin.value,
      stdinSchema: vmInputSchema,
      stdout: stdout.value,
      stdoutSchema: vmOutputSchema,
    });
  } else if (expectedRole === 'bchn-mempool') {
    accepted = validateBchnMempoolLane({
      expected: expectedTransaction,
      stdin: stdin.value,
      stdout: stdout.value,
    });
  } else {
    accepted = validateBchnMinedLane({
      context,
      expected: expectedTransaction,
      stdin: stdin.value,
      stdinSchema: bchnMinedInputSchema,
      stdout: stdout.value,
      stdoutSchema: bchnMinedOutputSchema,
    });
  }
  if ((expectedTransaction.expectation === 'accept') !== accepted) {
    fail('lane-derived outcome contradicts the required transaction outcome');
  }
  return Object.freeze({
    authorityId: authority.authorityId,
    derivedOutcome: accepted ? 'accepted' : 'rejected',
    envelopeSha256: sha256(envelopeBytes),
    lane: expectedRole,
    runId: envelope.runId,
    execution: Object.freeze({
      command: envelope.command,
      completedAt: envelope.completedAt,
      machineManifest: machine.value,
      machineManifestSha256: machine.sha256,
      startedAt: envelope.startedAt,
      stdin: stdin.value,
      stdinSha256: stdin.sha256,
      stdout: stdout.value,
      stdoutSha256: stdout.sha256,
      tool: envelope.tool,
    }),
  });
}

/**
 * Replay a policy-specific signed lane envelope under the authority set
 * authenticated by the signed V2 descriptor. This function derives evidence;
 * it never returns a qualification claim.
 */
export function verifyV2Q02AuthorityLaneEvidence(value) {
  plain(value, 'manifest-pinned authority lane evidence request');
  const required = [
    'attestationDomain',
    'attestationVersion',
    'authorityContext',
    'bchnMinedInputSchema',
    'bchnMinedOutputSchema',
    'envelopePath',
    'envelopeSchema',
    'expectedRole',
    'expectedSubject',
    'expectedTransaction',
    'machineManifestSchema',
    'subjectField',
    'vmInputSchema',
    'vmOutputSchema',
  ];
  const optional = new Set(['expectedInputCount', 'expectedSourceOutputSha256s']);
  if (Object.keys(value).some((key) => !required.includes(key) && !optional.has(key))
    || required.some((key) => !Object.hasOwn(value, key))) {
    fail('manifest-pinned authority lane evidence request has missing or unknown properties');
  }
  return verifyAuthorityLaneEnvelope(value);
}

/**
 * Verify one signed lane run against a manifest-pinned authority context and
 * an exact case derived by the Q-02 corpus gate.
 */
export function verifyV2Q02LaneEvidence({
  authorityContext,
  envelopePath,
  expectedCase,
}) {
  const expected = caseBinding(expectedCase, 'expected Q-02 lane case');
  const derived = verifyAuthorityLaneEnvelope({
    attestationDomain: V2_Q02_LANE_ATTESTATION_DOMAIN,
    attestationVersion: V2_Q02_LANE_ATTESTATION_VERSION,
    authorityContext,
    bchnMinedInputSchema:
      'shieldkit-v2-direct-q02-bchn-mined-input-v2',
    bchnMinedOutputSchema:
      'shieldkit-v2-direct-q02-bchn-mined-result-v2',
    envelopePath,
    envelopeSchema: V2_Q02_LANE_ENVELOPE_SCHEMA,
    expectedRole: (() => {
      const envelopeBytes = readStableDirectFile(
        envelopePath,
        'Q-02 lane envelope role discovery',
      );
      let envelope;
      try {
        envelope = JSON.parse(envelopeBytes);
      } catch {
        fail('Q-02 lane envelope is not JSON');
      }
      if (!ROLES.includes(envelope.authorityRole)) {
        fail('Q-02 lane envelope role is invalid');
      }
      return envelope.authorityRole;
    })(),
    expectedSubject: expected,
    expectedTransaction: {
      expectation: expected.expectation,
      rawTransactionSha256: expected.rawTransactionSha256,
      transactionId: expected.transactionId,
    },
    machineManifestSchema:
      'shieldkit-v2-direct-q02-machine-manifest-v2',
    subjectField: 'case',
    vmInputSchema: 'shieldkit-v2-direct-q02-vm-run-input-v2',
    vmOutputSchema: 'shieldkit-v2-direct-q02-per-input-run-v2',
  });
  return Object.freeze({
    authorityId: derived.authorityId,
    caseId: expected.caseId,
    derivedOutcome: derived.derivedOutcome,
    envelopeSha256: derived.envelopeSha256,
    execution: derived.execution,
    lane: derived.lane,
    qualification: false,
    runId: derived.runId,
    schema: V2_Q02_LANE_ENVELOPE_SCHEMA,
  });
}
