#!/usr/bin/env node
/*
 * Q-08 pair qualification is an offline verifier for two independently
 * signed clean-host journeys. It never creates host evidence, substitutes a
 * release root, or promotes the result to production/release qualification.
 */
import { createHash } from 'node:crypto';
import {
  chmodSync, closeSync, constants, existsSync, fsyncSync, fstatSync, lstatSync, mkdirSync,
  openSync, readFileSync, realpathSync, renameSync, writeSync,
} from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  deriveV2Pf10RuntimeFromValidatedDescriptor,
  deriveV2SettlementPinsFromValidatedDescriptor,
  loadV2InstanceDescriptor,
} from '../packages/profile/v2/instance-descriptor.mjs';
import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import {
  resolveV2FinalReleaseRoot,
  verifyV2FinalReleaseProfileCore,
} from '../packages/profile/v2/release-bootstrap.mjs';
import {
  verifyV2Q08HostTranscriptForRelease,
  V2_Q08_HOST_STATEMENT_SCHEMA,
} from '../packages/profile/v2/q08-host-evidence.mjs';
import { parseV2RawTransaction } from '../packages/kit/v2/transaction-policy.mjs';
import {
  deriveV2Q02LaneAuthorityContextFromValidatedDescriptor,
} from './v2-q02-lane-evidence.mjs';
import {
  normalizeV2Q08LaneEvidenceReferences,
  verifyV2Q08ActionLaneEvidence,
} from './v2-q08-lane-evidence.mjs';

const HASH = /^[0-9a-f]{64}$/;
const SHA1 = /^[0-9a-f]{40}$/;
const ROOT_ID = /^[a-z][a-z0-9-]*$/;
const STEPS = Object.freeze([
  'npmCi', 'wallet', 'fundingAddress', 'sync', 'deposit', 'transfer', 'withdraw',
  'deleteLocalState', 'recover', 'recoveredSpend',
]);
const ACTIONS = new Set(['deposit', 'transfer', 'withdraw', 'recoveredSpend']);
const STABLE_FIELDS = Object.freeze([
  'dev', 'ino', 'size', 'mode', 'nlink', 'uid', 'mtimeNs', 'ctimeNs',
]);

export const V2_Q08_PAIR_SCHEMA =
  'shieldkit-v2-direct-q08-pair-qualification-v1';

export class V2Q08PairQualificationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2Q08PairQualificationError';
  }
}

const fail = (message) => { throw new V2Q08PairQualificationError(message); };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonicalBytes = (value) => Buffer.from(canonicalizeJcs(value), 'utf8');

function plain(value, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) {
    fail(`${label} must be a plain object`);
  }
  return value;
}

function exact(value, keys, label) {
  plain(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} has missing or unknown properties`);
  }
  return value;
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) fail(`${label} must be a lowercase SHA-256 digest`);
  return value;
}

function absolute(value, label) {
  if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value) {
    fail(`${label} must be an absolute normalized path`);
  }
  return value;
}

function stableBytes(filename, label) {
  absolute(filename, label);
  const pathname = lstatSync(filename, { bigint: true, throwIfNoEntry: false });
  let canonicalPath;
  try {
    canonicalPath = realpathSync(filename);
  } catch {
    fail(`${label} must be a direct single-link regular file`);
  }
  if (pathname === undefined || !pathname.isFile() || pathname.isSymbolicLink()
    || pathname.nlink !== 1n || canonicalPath !== filename) {
    fail(`${label} must be a direct single-link regular file`);
  }
  let descriptor;
  try {
    descriptor = openSync(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const before = fstatSync(descriptor, { bigint: true });
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    const finalPath = lstatSync(filename, { bigint: true, throwIfNoEntry: false });
    if (
      !before.isFile()
      || before.nlink !== 1n
      || !after.isFile()
      || after.nlink !== 1n
      || finalPath === undefined
      || !finalPath.isFile()
      || finalPath.isSymbolicLink()
      || finalPath.nlink !== 1n
      || STABLE_FIELDS.some((field) =>
        pathname[field] !== before[field]
        || before[field] !== after[field]
        || after[field] !== finalPath[field])
    ) {
      fail(`${label} changed while it was read`);
    }
    return Buffer.from(bytes);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function canonicalJsonFile(filename, label) {
  const bytes = stableBytes(filename, label);
  let value;
  try { value = JSON.parse(bytes); } catch { fail(`${label} is not JSON`); }
  if (!bytes.equals(canonicalBytes(value))) fail(`${label} must use exact RFC8785/JCS bytes`);
  return Object.freeze({ bytes, sha256: sha256(bytes), value });
}

function assertFinalRuntime(runtime) {
  if (runtime?.eligibility !== 'final-qualified' || runtime.claims?.finalKey !== true
    || runtime.claims.developmentKey !== false || runtime.claims.ceremonyQualified !== true
    || runtime.claims.production !== false || runtime.claims.releaseQualified !== false) {
    fail('Q-08 pair requires a final-qualified, non-production, non-release runtime');
  }
}

async function verifyFinalInputs(input, releaseRoot) {
  const profileCoreFile = canonicalJsonFile(input.profileCorePath, 'Q-08 pair profile core');
  const release = verifyV2FinalReleaseProfileCore(
    releaseRoot, profileCoreFile.bytes, profileCoreFile.value,
  );
  const descriptor = await loadV2InstanceDescriptor({
    descriptorPath: input.descriptorPath,
    profileCore: profileCoreFile.value,
    trustedSigners: release.descriptorSigners,
  });
  if (descriptor.profileId !== releaseRoot.profileId
    || descriptor.finalLocks.topology.id !== releaseRoot.topology.id
    || descriptor.finalLocks.verifiers.length !== releaseRoot.topology.verifierRoles.length
    || descriptor.finalLocks.verifiers.some((entry, index) => entry.role !== releaseRoot.topology.verifierRoles[index])) {
    fail('Q-08 pair descriptor identity or exact PF10 topology differs from its approved release root');
  }
  const runtime = await deriveV2Pf10RuntimeFromValidatedDescriptor(descriptor);
  assertFinalRuntime(runtime);
  const settlementPins =
    deriveV2SettlementPinsFromValidatedDescriptor(descriptor);
  const laneAuthorityContext =
    deriveV2Q02LaneAuthorityContextFromValidatedDescriptor(descriptor);
  return Object.freeze({
    profileId: descriptor.profileId,
    profileSha256: release.profileCoreSha256,
    instanceId: descriptor.instanceId,
    carrierCount: settlementPins.verifierCarriers.length,
    descriptorSha256: descriptor.descriptor.sha256,
    manifestSha256: descriptor.manifest.sha256,
    runtimeMaterialSha256: runtime.runtimeMaterial.materialSha256,
    releaseRootId: release.releaseRootId,
    releaseBootstrapSha256: release.releaseBootstrapSha256,
    topologyId: descriptor.finalLocks.topology.id,
    verifierRoles: Object.freeze(descriptor.finalLocks.verifiers.map((entry) => entry.role)),
    laneAuthorityContext,
  });
}

function parseActionResult(
  step,
  result,
  identity,
  {
    evidenceRoot,
    testOnly,
  },
) {
  exact(result, [
    'action', 'laneEvidence', 'rawTransactionHex', 'status', 'transactionId',
    ...(step === 'recoveredSpend' ? ['spentNoteId'] : []),
  ], `Q-08 pair ${step} result`);
  const action = step === 'recoveredSpend' ? 'withdraw' : step;
  if (result.status !== 'confirmed' || result.action !== action
    || typeof result.rawTransactionHex !== 'string' || !/^[0-9a-f]+$/.test(result.rawTransactionHex)
    || !HASH.test(result.transactionId)) {
    fail(`Q-08 pair ${step} result is invalid`);
  }
  let transaction;
  try { transaction = parseV2RawTransaction(result.rawTransactionHex); } catch { fail(`Q-08 pair ${step} raw transaction cannot be parsed`); }
  if (transaction.txid !== result.transactionId) fail(`Q-08 pair ${step} txid does not bind its raw transaction bytes`);
  const laneEvidence =
    normalizeV2Q08LaneEvidenceReferences(result.laneEvidence);
  if (!testOnly) {
    verifyV2Q08ActionLaneEvidence({
      authorityContext: identity.laneAuthorityContext,
      evidenceRoot,
      expected: {
        action: result.action,
        carrierCount: identity.carrierCount,
        instanceId: identity.instanceId,
        journeyStep: step,
        profileId: identity.profileId,
        profileSha256: identity.profileSha256,
        rawTransactionHex: result.rawTransactionHex,
        spentNoteId:
          step === 'recoveredSpend' ? result.spentNoteId : null,
        transactionId: result.transactionId,
      },
      laneEvidence,
    });
  }
  return Object.freeze({ ...result, laneEvidence });
}

function validateStep(
  step,
  entry,
  index,
  previousSha256,
  identity,
  {
    evidenceRoot,
    testOnly,
  },
) {
  exact(entry, ['command', 'entrySha256', 'previousSha256', 'result', 'sequence', 'stderrSha256', 'stdoutSha256', 'step'], `Q-08 pair step ${index}`);
  if (entry.sequence !== index || entry.step !== step || entry.previousSha256 !== previousSha256
    || !HASH.test(entry.entrySha256) || !HASH.test(entry.stdoutSha256) || !HASH.test(entry.stderrSha256)) {
    fail(`Q-08 pair step ${index} ordering or hashes are invalid`);
  }
  const { entrySha256, ...payload } = entry;
  if (sha256(canonicalBytes(payload)) !== entrySha256) fail(`Q-08 pair step ${index} hash chain is invalid`);
  exact(entry.command, ['arguments', 'executable'], `Q-08 pair ${step} command`);
  if (typeof entry.command.executable !== 'string' || entry.command.executable.length === 0
    || !Array.isArray(entry.command.arguments) || entry.command.arguments.some((arg) => typeof arg !== 'string' || arg.length === 0)
    || /fixture|test-only|mock/i.test(`${entry.command.executable}\0${entry.command.arguments.join('\0')}`)) {
    fail(`Q-08 pair ${step} command is malformed or non-production`);
  }
  if (step === 'npmCi') {
    exact(entry.result, ['status'], 'Q-08 pair npmCi result');
    if (entry.result.status !== 'installed-immutable' || entry.command.executable !== 'npm'
      || canonicalizeJcs(entry.command.arguments) !== canonicalizeJcs(['ci', '--ignore-scripts', '--no-audit', '--no-fund'])) {
      fail('Q-08 pair requires immutable npm ci evidence');
    }
  } else if (ACTIONS.has(step)) {
    parseActionResult(step, entry.result, identity, {
      evidenceRoot,
      testOnly,
    });
    if (step === 'recoveredSpend') {
      if (!HASH.test(entry.result.spentNoteId)) fail('Q-08 pair recovered spend lacks its note binding');
    }
  } else if (step === 'fundingAddress') {
    exact(entry.result, ['fundingAddress', 'status'], 'Q-08 pair funding-address result');
    if (entry.result.status !== 'funding-address-displayed' || typeof entry.result.fundingAddress !== 'string' || entry.result.fundingAddress.length < 8) fail('Q-08 pair funding address result is invalid');
  } else if (step === 'recover') {
    exact(entry.result, ['recoveredNoteId', 'status'], 'Q-08 pair recovery result');
    if (entry.result.status !== 'recovered-from-chain-history' || !HASH.test(entry.result.recoveredNoteId)) fail('Q-08 pair recovery result is invalid');
  } else {
    const status = { wallet: 'wallet-ready', sync: 'synced-from-genesis', deleteLocalState: 'local-state-deleted' }[step];
    exact(entry.result, ['status'], `Q-08 pair ${step} result`);
    if (entry.result.status !== status) fail(`Q-08 pair ${step} result is invalid`);
  }
  return entry.entrySha256;
}

function validateStatement(
  statement,
  identity,
  {
    evidenceRoot,
    testOnly,
  },
) {
  exact(statement, [
    'carrierCount', 'commandPlanSha256', 'descriptorSha256',
    'fundingCheckpointSha256', 'git',
    'hostIdentity', 'instanceId', 'manifestSha256', 'profileId',
    'profileSha256', 'releaseBootstrapSha256', 'releaseRootId',
    'runtimeMaterialSha256', 'schema', 'sourcePinSha256', 'status', 'steps',
  ], 'Q-08 pair host statement');
  if (statement.schema !== V2_Q08_HOST_STATEMENT_SCHEMA
    || statement.status !== 'host-journey-complete-awaiting-independent-pair-verification'
    || statement.profileId !== identity.profileId || statement.instanceId !== identity.instanceId
    || statement.descriptorSha256 !== identity.descriptorSha256 || statement.manifestSha256 !== identity.manifestSha256
    || statement.runtimeMaterialSha256 !== identity.runtimeMaterialSha256 || statement.releaseRootId !== identity.releaseRootId
    || statement.releaseBootstrapSha256 !== identity.releaseBootstrapSha256
    || statement.profileSha256 !== identity.profileSha256
    || statement.carrierCount !== identity.carrierCount) {
    fail('Q-08 pair host statement does not bind the approved final release inputs');
  }
  for (const key of ['commandPlanSha256', 'sourcePinSha256', 'fundingCheckpointSha256', 'hostIdentity', 'profileSha256']) hash(statement[key], `Q-08 pair ${key}`);
  if (!Number.isSafeInteger(statement.carrierCount)
    || statement.carrierCount < 1
    || statement.carrierCount > 255) {
    fail('Q-08 pair carrier count is invalid');
  }
  exact(statement.git, ['commit', 'tree'], 'Q-08 pair statement git binding');
  if (!SHA1.test(statement.git.commit) || !SHA1.test(statement.git.tree)) fail('Q-08 pair statement git binding is invalid');
  if (!Array.isArray(statement.steps) || statement.steps.length !== STEPS.length) fail('Q-08 pair statement must contain the exact ten-step journey');
  let previousSha256 = null;
  let fundingAddress;
  let recoveredNoteId;
  const actionTransactionIds = [];
  for (const [index, step] of STEPS.entries()) {
    const entry = statement.steps[index];
    previousSha256 = validateStep(
      step,
      entry,
      index,
      previousSha256,
      identity,
      { evidenceRoot, testOnly },
    );
    if (step === 'fundingAddress') fundingAddress = entry.result.fundingAddress;
    if (step === 'recover') recoveredNoteId = entry.result.recoveredNoteId;
    if (ACTIONS.has(step)) actionTransactionIds.push(entry.result.transactionId);
    if (step === 'recoveredSpend' && entry.result.spentNoteId !== recoveredNoteId) fail('Q-08 pair recovered spend does not bind recovered chain-history note');
  }
  if (fundingAddress === undefined) fail('Q-08 pair statement lacks funding address evidence');
  if (new Set(actionTransactionIds).size !== actionTransactionIds.length) {
    fail('Q-08 host journey reuses an action transaction');
  }
  return Object.freeze({
    ...statement,
    fundingAddress,
    actionTransactionIds: Object.freeze(actionTransactionIds),
  });
}

function assertPair(left, right) {
  if (left.hostIdentity === right.hostIdentity) fail('Q-08 pair requires distinct host identities');
  const shared = [
    'schema', 'status', 'profileId', 'profileSha256', 'carrierCount',
    'instanceId', 'descriptorSha256', 'manifestSha256',
    'runtimeMaterialSha256', 'releaseRootId', 'releaseBootstrapSha256', 'commandPlanSha256',
    'sourcePinSha256',
  ];
  for (const key of shared) if (left[key] !== right[key]) fail(`Q-08 pair hosts disagree on shared ${key} binding`);
  if (canonicalizeJcs(left.git) !== canonicalizeJcs(right.git)) fail('Q-08 pair hosts disagree on their source git binding');
  if (
    left.fundingCheckpointSha256 === right.fundingCheckpointSha256
    || left.fundingAddress === right.fundingAddress
  ) {
    fail('Q-08 pair requires independently funded host journeys');
  }
  const allTransactions = [
    ...left.actionTransactionIds,
    ...right.actionTransactionIds,
  ];
  if (new Set(allTransactions).size !== allTransactions.length) {
    fail('Q-08 pair host journeys reuse an action transaction');
  }
}

function writeCanonicalPrivatePair(outputDirectory, record) {
  absolute(outputDirectory, 'Q-08 pair output directory');
  if (existsSync(outputDirectory)) fail('Q-08 pair refuses a preexisting output directory');
  const parent = lstatSync(dirname(outputDirectory), { throwIfNoEntry: false });
  if (parent === undefined || !parent.isDirectory() || parent.isSymbolicLink()) {
    fail('Q-08 pair output parent must be a direct directory');
  }
  if (realpathSync(dirname(outputDirectory)) !== dirname(outputDirectory)) {
    fail('Q-08 pair output parent must not traverse a symlink');
  }
  mkdirSync(outputDirectory, { mode: 0o700 });
  const directory = lstatSync(outputDirectory);
  if (!directory.isDirectory() || directory.isSymbolicLink()) fail('Q-08 pair output directory is invalid');
  chmodSync(outputDirectory, 0o700);
  const destination = join(outputDirectory, 'q08-pair-qualification.json');
  const temporary = join(outputDirectory, `.${process.pid}.${Date.now()}.tmp`);
  const bytes = canonicalBytes(record);
  let descriptor;
  try {
    descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
    writeSync(descriptor, bytes); fstatSync(descriptor); // force kernel validation before fsync
    fsyncSync(descriptor);
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
  chmodSync(temporary, 0o600);
  renameSync(temporary, destination);
  const written = lstatSync(destination);
  if (
    !written.isFile()
    || written.isSymbolicLink()
    || written.nlink !== 1
    || (written.mode & 0o7777) !== 0o600
  ) {
    fail('Q-08 pair record is not one direct 0600 regular file');
  }
  let directoryDescriptor;
  try {
    directoryDescriptor = openSync(outputDirectory, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    fsyncSync(directoryDescriptor);
  } finally { if (directoryDescriptor !== undefined) closeSync(directoryDescriptor); }
  return Object.freeze({ path: destination, sha256: sha256(bytes) });
}

export function parseV2Q08PairArguments(argv) {
  const names = new Set(['--profile-core', '--descriptor', '--host-a-envelope', '--host-b-envelope', '--output-dir', '--expected-commit', '--expected-tree', '--release-root']);
  if (!Array.isArray(argv) || argv.length !== names.size * 2) fail('usage: v2-q08-pair-qualification.mjs --profile-core <absolute> --descriptor <absolute> --host-a-envelope <absolute> --host-b-envelope <absolute> --output-dir <absolute-new-dir> --expected-commit <sha1> --expected-tree <sha1> --release-root <compiled-root-id>');
  const fields = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index]; const value = argv[index + 1];
    if (!names.has(name) || fields.has(name) || typeof value !== 'string' || value.length === 0) fail('Q-08 pair arguments are malformed or duplicated');
    fields.set(name, value);
  }
  const expectedCommit = fields.get('--expected-commit'); const expectedTree = fields.get('--expected-tree');
  if (!SHA1.test(expectedCommit) || !SHA1.test(expectedTree) || !ROOT_ID.test(fields.get('--release-root'))) fail('Q-08 pair expected git pins or release root id are invalid');
  return Object.freeze({
    profileCorePath: absolute(fields.get('--profile-core'), 'Q-08 pair profile core'),
    descriptorPath: absolute(fields.get('--descriptor'), 'Q-08 pair descriptor'),
    hostAEnvelopePath: absolute(fields.get('--host-a-envelope'), 'Q-08 pair host A envelope'),
    hostBEnvelopePath: absolute(fields.get('--host-b-envelope'), 'Q-08 pair host B envelope'),
    outputDirectory: absolute(fields.get('--output-dir'), 'Q-08 pair output directory'),
    expectedCommit, expectedTree, releaseRootId: fields.get('--release-root'),
  });
}

const PAIR_INPUT_KEYS = Object.freeze([
  'descriptorPath',
  'expectedCommit',
  'expectedTree',
  'hostAEnvelopePath',
  'hostBEnvelopePath',
  'profileCorePath',
  'releaseRootId',
]);

async function derivePairRecord(options, seam = undefined) {
  const testOnly = seam?.testOnly === true;
  if (seam !== undefined && (!testOnly || Object.keys(seam).some((key) => !['testOnly', 'verifyFinalInputs', 'verifyEnvelope'].includes(key)))) {
    fail('Q-08 pair dependency injection is restricted to explicit TEST-ONLY mode');
  }
  exact(options, PAIR_INPUT_KEYS, 'Q-08 pair inputs');
  if (!SHA1.test(options.expectedCommit) || !SHA1.test(options.expectedTree) || !ROOT_ID.test(options.releaseRootId)) fail('Q-08 pair expected git pins or release root id are invalid');
  // This precedes all caller-selected file reads. Production roots are compiled,
  // never descriptor-selected. TEST-ONLY has no root capability at all.
  const releaseRoot = testOnly ? null : resolveV2FinalReleaseRoot(options.releaseRootId);
  const inputs = testOnly
    ? await seam.verifyFinalInputs(options)
    : await verifyFinalInputs(options, releaseRoot);
  exact(inputs, [
    'carrierCount', 'descriptorSha256', 'instanceId',
    ...(!testOnly ? ['laneAuthorityContext'] : []),
    'manifestSha256', 'profileId', 'profileSha256',
    'releaseBootstrapSha256', 'releaseRootId', 'runtimeMaterialSha256',
    'topologyId', 'verifierRoles',
  ], 'Q-08 pair final input verification result');
  for (const key of [
    'descriptorSha256', 'instanceId', 'manifestSha256', 'profileId',
    'profileSha256', 'releaseBootstrapSha256', 'runtimeMaterialSha256',
  ]) hash(inputs[key], `Q-08 pair ${key}`);
  if (
    inputs.releaseRootId !== options.releaseRootId
    || !ROOT_ID.test(inputs.releaseRootId)
    || typeof inputs.topologyId !== 'string'
    || !Array.isArray(inputs.verifierRoles)
    || !Number.isSafeInteger(inputs.carrierCount)
    || inputs.carrierCount < 1
    || inputs.carrierCount > 255
  ) {
    fail('Q-08 pair final input verification result is malformed');
  }
  const aBytes = stableBytes(options.hostAEnvelopePath, 'Q-08 pair host A envelope');
  const bBytes = stableBytes(options.hostBEnvelopePath, 'Q-08 pair host B envelope');
  const inspect = testOnly ? seam.verifyEnvelope : (bytes) => verifyV2Q08HostTranscriptForRelease({ envelopeBytes: bytes, releaseRoot });
  const [hostA, hostB] = [inspect(aBytes), inspect(bBytes)];
  if (hostA.authority?.role !== 'clean-host-a' || hostB.authority?.role !== 'clean-host-b') fail('Q-08 pair requires the exact clean-host A/B release roles');
  if (
    hostA.authority.signerId === hostB.authority.signerId
    || hostA.authority.publicKey === hostB.authority.publicKey
    || hostA.authority.organizationId === hostB.authority.organizationId
    || hostA.authority.independenceDomain === hostB.authority.independenceDomain
    || hostA.envelopeSha256 === hostB.envelopeSha256
    || hostA.statementSha256 === hostB.statementSha256
  ) {
    fail('Q-08 pair requires two distinct release-authorized host authorities and journeys');
  }
  const a = validateStatement(hostA.statement, inputs, {
    evidenceRoot: dirname(options.hostAEnvelopePath),
    testOnly,
  });
  const b = validateStatement(hostB.statement, inputs, {
    evidenceRoot: dirname(options.hostBEnvelopePath),
    testOnly,
  });
  if (a.git.commit !== options.expectedCommit || a.git.tree !== options.expectedTree || b.git.commit !== options.expectedCommit || b.git.tree !== options.expectedTree) fail('Q-08 pair host statements disagree with requested source git pins');
  assertPair(a, b);
  if (testOnly) {
    return Object.freeze({
      schema: V2_Q08_PAIR_SCHEMA,
      status: 'test-only-nonqualifying',
      q08Qualified: false,
      production: false,
      releaseQualified: false,
    });
  }
  return Object.freeze({
    schema: V2_Q08_PAIR_SCHEMA,
    status: 'q08-pair-qualified', q08Qualified: true, production: false, releaseQualified: false,
    profileId: inputs.profileId, profileSha256: inputs.profileSha256,
    instanceId: inputs.instanceId, carrierCount: inputs.carrierCount,
    descriptorSha256: inputs.descriptorSha256, manifestSha256: inputs.manifestSha256,
    runtimeMaterialSha256: inputs.runtimeMaterialSha256, releaseRootId: inputs.releaseRootId,
    releaseBootstrapSha256: inputs.releaseBootstrapSha256,
    topology: Object.freeze({ id: inputs.topologyId, verifierRoles: Object.freeze([...inputs.verifierRoles]) }),
    git: Object.freeze({ commit: a.git.commit, tree: a.git.tree }), sourcePinSha256: a.sourcePinSha256,
    hosts: Object.freeze({
      a: Object.freeze({ hostIdentity: a.hostIdentity, fundingCheckpointSha256: a.fundingCheckpointSha256, envelopeSha256: hostA.envelopeSha256, statementSha256: hostA.statementSha256 }),
      b: Object.freeze({ hostIdentity: b.hostIdentity, fundingCheckpointSha256: b.fundingCheckpointSha256, envelopeSha256: hostB.envelopeSha256, statementSha256: hostB.statementSha256 }),
    }),
  });
}

/**
 * TEST-ONLY accepts structural doubles solely to unit-test refusal paths. It
 * returns false and writes nothing; the CLI cannot select this mode.
 */
export async function runV2Q08PairQualification(options, seam = undefined) {
  exact(options, [...PAIR_INPUT_KEYS, 'outputDirectory'], 'Q-08 pair options');
  const { outputDirectory, ...inputs } = options;
  const record = await derivePairRecord(inputs, seam);
  if (record.q08Qualified !== true) return record;
  const artifact = writeCanonicalPrivatePair(options.outputDirectory, record);
  return Object.freeze({ ...record, artifactSha256: artifact.sha256, artifactPath: artifact.path });
}

/**
 * Re-derive the complete signed-host pair and require a caller-supplied pair
 * record to be byte-for-byte equal. This is the Q-09 consumption boundary:
 * a JSON field claiming q08Qualified is never trusted by itself.
 */
export async function verifyV2Q08PairQualificationArtifact(options) {
  exact(
    options,
    [...PAIR_INPUT_KEYS, 'pairArtifactPath'],
    'Q-08 pair artifact verification options',
  );
  const { pairArtifactPath, ...inputs } = options;
  const expected = await derivePairRecord(inputs);
  if (expected.q08Qualified !== true) {
    fail('Q-08 pair artifact verification did not derive qualifying evidence');
  }
  const artifact = canonicalJsonFile(
    absolute(pairArtifactPath, 'Q-08 pair qualification artifact'),
    'Q-08 pair qualification artifact',
  );
  const expectedBytes = canonicalBytes(expected);
  if (!artifact.bytes.equals(expectedBytes)) {
    fail('Q-08 pair qualification artifact differs from the independently re-derived record');
  }
  return Object.freeze({
    ...expected,
    artifactPath: pairArtifactPath,
    artifactSha256: artifact.sha256,
  });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const result = await runV2Q08PairQualification(parseV2Q08PairArguments(process.argv.slice(2)));
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`Q-08 pair qualification failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
