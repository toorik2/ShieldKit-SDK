#!/usr/bin/env node
/*
 * Q-09 Chipnet rollout evidence validator.
 *
 * This command is intentionally offline: it never asks an RPC node for an
 * answer and it never manufactures a settlement. Operators first collect raw
 * headers and raw transactions from independently retained Chipnet sources,
 * then give this validator the immutable observations. The validator derives
 * every pass/fail conclusion from those raw records. In particular it does
 * not accept a caller-provided count, duration, "passed" summary, fixture, or
 * mock as evidence.
 */
import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import {
  chmodSync, closeSync, constants, existsSync, fsyncSync, lstatSync, mkdirSync,
  openSync, readFileSync, realpathSync, renameSync, writeSync,
} from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  deriveV2FinalLocksSha256FromValidatedDescriptor,
  deriveV2Pf10RuntimeFromValidatedDescriptor,
  deriveV2SettlementPinsFromValidatedDescriptor,
  loadV2InstanceDescriptor,
} from '../packages/profile/v2/instance-descriptor.mjs';
import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import {
  resolveV2FinalReleaseRoot,
  verifyV2FinalReleaseProfileCore,
} from '../packages/profile/v2/release-bootstrap.mjs';
import { decodeActionPacket } from '../packages/action/v2/packet.mjs';
import { decodeStateNftCommitment, encodeStateNftCommitment } from '../packages/action/v2/state.mjs';
import {
  assertV2StandardTransactionEnvelope, parseSerializedSourceOutput,
  parseV2RawTransaction,
} from '../packages/kit/v2/transaction-policy.mjs';
import { inspectV2LocalVmEvidence } from '../packages/kit/v2/vm-evidence.mjs';
import { verifyV2Q02FinalKeyCorpus } from './v2-q02-final-key-corpus.mjs';
import { verifyV2Q08PairQualificationArtifact } from './v2-q08-pair-qualification.mjs';
import {
  verifyBchTransactionMerkleProof,
  verifyRawHeaderSegment,
} from '../packages/recover/raw-chain-recovery.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const workspaceRoot = resolve(here, '../..');
const HEX_32 = /^[0-9a-f]{64}$/;
const HEX_40 = /^[0-9a-f]{40}$/;
const HEX = /^[0-9a-f]+$/;
const ROOT_ID = /^[a-z][a-z0-9-]*$/;
const MAX_JSON_BYTES = 128 * 1024 * 1024;
const CHIPNET_ID = 2;
const MIN_CONFIRMATIONS = 6;
const MIN_SETTLEMENTS = 1_000;
const MIN_SOAK_SECONDS = 30 * 24 * 60 * 60;
const MIN_HIGH_CAPACITY = 210_000_000n;
const PLAYGROUND_CAPACITY = 32;
const ACTION_KINDS = Object.freeze(['deposit', 'transfer', 'withdrawal']);

export const V2_Q09_CHAIN_EVIDENCE_SCHEMA = 'shieldkit-v2-direct-q09-chipnet-chain-evidence/v1';
export const V2_Q09_SETTLEMENT_JOURNAL_SCHEMA = 'shieldkit-v2-direct-q09-settlement-journal/v1';
export const V2_Q09_PLAYGROUND_SCHEMA = 'shieldkit-v2-direct-q09-playground-evidence/v1';
export const V2_Q09_SOURCE_PIN_SCHEMA = 'shieldkit-v2-direct-q09-source-pin/v1';
export const V2_Q09_CHAIN_OBSERVERS_SCHEMA = 'shieldkit-v2-direct-q09-chain-observers/v1';
export const V2_Q09_SOURCE_PIN_ARTIFACT_ID = 'q09-source-pin';
export const V2_Q09_CHAIN_OBSERVERS_ARTIFACT_ID = 'q09-chain-observers';
export const V2_Q09_RESULT_SCHEMA = 'shieldkit-v2-direct-q09-chipnet-rollout-validation/v1';

export class V2Q09ChipnetSoakError extends Error {
  constructor(message) { super(message); this.name = 'V2Q09ChipnetSoakError'; }
}
const fail = (message) => { throw new V2Q09ChipnetSoakError(message); };
const canonical = (value) => canonicalizeJcs(value);
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const sha256Json = (value) => sha256(Buffer.from(canonical(value), 'utf8'));
const now = () => new Date().toISOString();

function exactKeys(value, expected, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) fail(`${label} must be a plain object`);
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail(`${label} has missing or unknown properties`);
}
function hex32(value, label) { if (typeof value !== 'string' || !HEX_32.test(value)) fail(`${label} must be 32 lowercase hexadecimal bytes`); return value; }
function positiveInteger(value, label) { if (!Number.isSafeInteger(value) || value < 0) fail(`${label} must be a nonnegative safe integer`); return value; }
function absolute(path, label) { if (typeof path !== 'string' || !isAbsolute(path) || resolve(path) !== path) fail(`${label} must be an absolute normalized path`); return path; }
function directFile(path, label) {
  absolute(path, label); const entry = lstatSync(path, { throwIfNoEntry: false });
  if (entry === undefined || !entry.isFile() || entry.isSymbolicLink() || entry.nlink !== 1 || entry.size <= 0 || entry.size > MAX_JSON_BYTES) fail(`${label} must be a bounded direct regular file`);
  if (realpathSync(path) !== path) fail(`${label} must not traverse a symlink`);
  return entry;
}
function privateNewDirectory(path) {
  absolute(path, 'Q-09 output directory'); if (existsSync(path)) fail('Q-09 refuses a preexisting output directory');
  const parent = dirname(path); const parentEntry = lstatSync(parent, { throwIfNoEntry: false });
  if (parentEntry === undefined || !parentEntry.isDirectory() || parentEntry.isSymbolicLink() || realpathSync(parent) !== parent) fail('Q-09 output parent must be a direct canonical directory');
  mkdirSync(path, { mode: 0o700 }); const entry = lstatSync(path);
  if (!entry.isDirectory() || entry.isSymbolicLink() || realpathSync(path) !== path) fail('Q-09 output directory is not direct'); chmodSync(path, 0o700);
}
function readCanonicalJson(path, label) {
  directFile(path, label); const bytes = readFileSync(path); let value;
  try { value = JSON.parse(bytes.toString('utf8')); } catch { fail(`${label} is not JSON`); }
  if (!bytes.equals(Buffer.from(canonical(value), 'utf8'))) fail(`${label} must be exact RFC8785/JCS bytes`);
  return Object.freeze({ path, bytes: Buffer.from(bytes), value, sha256: sha256(bytes) });
}
function atomicPrivateJson(path, value) {
  if (existsSync(path)) fail(`Q-09 refuses to overwrite ${path}`);
  const parent = dirname(path); const parentEntry = lstatSync(parent);
  if (!parentEntry.isDirectory() || parentEntry.isSymbolicLink() || realpathSync(parent) !== parent) fail('Q-09 output parent is invalid');
  const bytes = Buffer.from(canonical(value), 'utf8'); const temporary = join(parent, `.${process.pid}.${Date.now()}.tmp`);
  const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
  try { writeSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
  chmodSync(temporary, 0o600); renameSync(temporary, path);
  const written = lstatSync(path);
  if (!written.isFile() || written.isSymbolicLink() || written.nlink !== 1 || (written.mode & 0o7777) !== 0o600) fail('Q-09 output file is not one direct 0600 regular file');
  const parentFd = openSync(parent, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0));
  try { fsyncSync(parentFd); } finally { closeSync(parentFd); }
  return Object.freeze({ path, sha256: sha256(bytes), bytes: bytes.length });
}
function blockHashForTime(seconds) { return new Date(seconds * 1000).toISOString(); }
function decimal(value, label) { if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) fail(`${label} must be canonical decimal`); return BigInt(value); }
function verifyMerkleInclusion({ rawTransactionHex, transactionId, transactionIndex, merkleBranch, header, label }) {
  if (!HEX_32.test(transactionId) || !Number.isSafeInteger(transactionIndex) || transactionIndex < 0 || !Array.isArray(merkleBranch) || merkleBranch.some((hash) => !HEX_32.test(hash)) || !Number.isSafeInteger(header.transactionCount)) fail(`${label} merkle inclusion is malformed`);
  let proof; try { proof = verifyBchTransactionMerkleProof({ rawTransaction: Buffer.from(rawTransactionHex, 'hex'), transactionIndex, transactionCount: header.transactionCount, branch: merkleBranch, headerMerkleRoot: header.merkleRoot }); } catch (error) { fail(`${label} does not prove raw-header transaction inclusion: ${error instanceof Error ? error.message : String(error)}`); }
  if (proof.transactionId !== transactionId) fail(`${label} Merkle proof transaction ID differs from raw transaction`);
}
function parseChainBoundTransaction(value, chain, label) {
  exactKeys(value, ['blockHash', 'blockHeight', 'merkleBranch', 'rawTransactionHex', 'transactionId', 'transactionIndex'], label);
  if (!Number.isSafeInteger(value.blockHeight) || !HEX_32.test(value.blockHash) || !HEX_32.test(value.transactionId) || typeof value.rawTransactionHex !== 'string' || !HEX.test(value.rawTransactionHex) || value.rawTransactionHex.length % 2 !== 0) fail(`${label} is malformed`);
  const header = chain.headers.get(value.blockHeight); if (header === undefined || header.hash !== value.blockHash || chain.tip.height - value.blockHeight + 1 < MIN_CONFIRMATIONS) fail(`${label} lacks canonical confirmations`);
  let transaction; try { transaction = parseV2RawTransaction(value.rawTransactionHex); } catch { fail(`${label} raw transaction is invalid`); }
  if (transaction.txid !== value.transactionId) fail(`${label} transaction ID does not bind raw bytes`);
  verifyMerkleInclusion({ ...value, header, label }); return Object.freeze({ transaction, header, ...value });
}
function validateDescriptorGenesis(value, identity, chain, label) {
  exactKeys(value, ['blockHash', 'blockHeight', 'merkleBranch', 'rawTransactionHex', 'transactionId', 'transactionIndex'], label);
  if (value.transactionId !== identity.genesis.transactionId) fail(`${label} transaction ID differs from descriptor genesis`);
  const included = parseChainBoundTransaction(value, chain, label); if (included.transaction.outputs[identity.genesis.outpointIndex] === undefined) fail(`${label} does not contain descriptor genesis outpoint`);
  let output; try { output = parseSerializedSourceOutput(included.transaction.outputs[identity.genesis.outpointIndex].serializedHex); } catch (error) { fail(`${label} state output is malformed: ${error instanceof Error ? error.message : String(error)}`); }
  if (output.token?.categoryWire !== identity.instanceId || output.token?.amount !== '0' || output.token?.nft?.capability !== 'mutable' || output.token?.nft?.commitmentHex !== identity.initialStateHex || output.lockingBytecodeHex !== identity.stateLockingBytecodeHex || output.valueSatoshis !== BigInt(identity.stateBaseSats)) fail(`${label} state output is not descriptor-bound`);
  return Object.freeze({ outpoint: { txid: value.transactionId, vout: identity.genesis.outpointIndex }, state: Buffer.from(identity.initialStateHex, 'hex'), transactionId: value.transactionId });
}
function verifyObserverAttestations(attestations, statement, observerSet, label) {
  if (!Array.isArray(attestations) || attestations.length < 2) fail(`${label} requires two signed observer attestations`);
  const signedBytes = Buffer.from(canonical(statement), 'utf8'); const seen = new Set();
  for (const [index, attestation] of attestations.entries()) { exactKeys(attestation, ['algorithm', 'observerId', 'signatureBase64'], `${label} attestation ${index}`); const key = observerSet.observers.get(attestation.observerId); if (attestation.algorithm !== 'ed25519' || key === undefined || seen.has(attestation.observerId) || typeof attestation.signatureBase64 !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(attestation.signatureBase64)) fail(`${label} attestation is untrusted or malformed`); const signature = Buffer.from(attestation.signatureBase64, 'base64'); if (signature.length !== 64 || !verifySignature(null, signedBytes, key, signature)) fail(`${label} attestation signature is invalid`); seen.add(attestation.observerId); }
}
function exactChainTime(value, label) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.000Z$/.test(value) || !Number.isFinite(Date.parse(value))) fail(`${label} is not canonical UTC time`);
  return value;
}
function assertNoForbiddenText(value, label) {
  const text = canonical(value).toLowerCase();
  if (/(?:fixture|mock|test-only|synthetic|faucet|sponsor|batch(?:ing)?|coordinator|development)/u.test(text)) fail(`${label} contains a prohibited substitute or topology`);
}

export function parseV2Q09Arguments(argv) {
  const names = new Set(['--output-dir', '--descriptor', '--playground-descriptor', '--profile-core', '--release-root', '--source-pin', '--chain-observers', '--q02-corpus', '--q08-host-a', '--q08-host-b', '--q08-pair', '--chain-evidence', '--settlements', '--playground', '--expected-commit', '--expected-tree']);
  if (!Array.isArray(argv) || argv.length !== names.size * 2) fail('usage: v2-chipnet-soak.mjs --output-dir <absolute-new-dir> --descriptor <absolute> --playground-descriptor <absolute> --profile-core <absolute> --release-root <compiled-root-id> --source-pin <absolute> --chain-observers <absolute> --q02-corpus <absolute> --q08-host-a <absolute> --q08-host-b <absolute> --q08-pair <absolute> --chain-evidence <absolute> --settlements <absolute> --playground <absolute> --expected-commit <sha1> --expected-tree <sha1>');
  const fields = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index]; const value = argv[index + 1];
    if (!names.has(name) || fields.has(name) || typeof value !== 'string' || value.length === 0) fail('Q-09 arguments are malformed or duplicated'); fields.set(name, value);
  }
  for (const name of names) if (!fields.has(name)) fail(`Q-09 requires ${name}`);
  const expectedCommit = fields.get('--expected-commit'); const expectedTree = fields.get('--expected-tree');
  if (!HEX_40.test(expectedCommit) || !HEX_40.test(expectedTree)) fail('Q-09 expected commit and tree must be lowercase SHA-1 values');
  if (!ROOT_ID.test(fields.get('--release-root'))) fail('Q-09 release root id is malformed');
  return Object.freeze({
    outputDirectory: absolute(fields.get('--output-dir'), 'Q-09 output directory'), descriptorPath: absolute(fields.get('--descriptor'), 'Q-09 descriptor'), playgroundDescriptorPath: absolute(fields.get('--playground-descriptor'), 'Q-09 playground descriptor'), profileCorePath: absolute(fields.get('--profile-core'), 'Q-09 profile core'), releaseRootId: fields.get('--release-root'), sourcePinPath: absolute(fields.get('--source-pin'), 'Q-09 source pin'), chainObserversPath: absolute(fields.get('--chain-observers'), 'Q-09 chain observers'), q02CorpusPath: absolute(fields.get('--q02-corpus'), 'Q-09 Q-02 corpus'), q08HostAPath: absolute(fields.get('--q08-host-a'), 'Q-09 Q-08 host A'), q08HostBPath: absolute(fields.get('--q08-host-b'), 'Q-09 Q-08 host B'), q08PairPath: absolute(fields.get('--q08-pair'), 'Q-09 Q-08 pair artifact'), chainEvidencePath: absolute(fields.get('--chain-evidence'), 'Q-09 chain evidence'), settlementsPath: absolute(fields.get('--settlements'), 'Q-09 settlement journal'), playgroundPath: absolute(fields.get('--playground'), 'Q-09 playground evidence'), expectedCommit, expectedTree,
  });
}

async function capture(executable, arguments_, { cwd, env }) {
  const { spawn } = await import('node:child_process');
  const child = spawn(executable, arguments_, { cwd, env, shell: false, stdio: ['ignore', 'pipe', 'pipe'] }); let stdout = ''; let stderr = ''; let spawnError;
  child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8'); child.stdout.on('data', (value) => { stdout += value; }); child.stderr.on('data', (value) => { stderr += value; }); child.once('error', (error) => { spawnError = error; });
  const result = await new Promise((done) => child.once('close', (exitCode, signal) => done({ exitCode, signal })));
  if (spawnError) fail(`Q-09 cannot spawn ${executable}: ${spawnError.message}`); return Object.freeze({ ...result, stdout, stderr });
}
async function gitState(runner) {
  const run = async (args) => { const result = await runner('git', args, { cwd: workspaceRoot, env: process.env }); if (result.exitCode !== 0 || result.signal !== null) fail(`Q-09 git ${args.join(' ')} failed`); return result.stdout.trim(); };
  const [commit, tree, status] = await Promise.all([run(['rev-parse', 'HEAD^{commit}']), run(['rev-parse', 'HEAD^{tree}']), run(['status', '--porcelain=v1', '--untracked-files=all'])]);
  if (!HEX_40.test(commit) || !HEX_40.test(tree) || status !== '') fail('Q-09 requires an exact clean Git commit and tree'); return Object.freeze({ commit, tree });
}
function assertFinalRuntime(runtime) {
  if (runtime?.eligibility !== 'final-qualified') fail('Q-09 refuses development-only runtime material');
  const claims = runtime.claims;
  if (claims?.finalKey !== true || claims?.developmentKey !== false || claims?.ceremonyQualified !== true || claims?.production !== false || claims?.releaseQualified !== false) fail('Q-09 requires a D-01-qualified final key without a premature production or release claim');
}
function assertRootedDescriptor(descriptor, releaseRoot, label) {
  if (
    descriptor.profileId !== releaseRoot.profileId
    || descriptor.finalLocks.topology.id !== releaseRoot.topology.id
    || descriptor.finalLocks.verifiers.length
      !== releaseRoot.topology.verifierRoles.length
    || descriptor.finalLocks.verifiers.some(
      (entry, index) => entry.role !== releaseRoot.topology.verifierRoles[index],
    )
  ) {
    fail(`${label} does not match the approved final release profile or PF10 topology`);
  }
}
function releaseProfile(input) {
  const releaseRoot = resolveV2FinalReleaseRoot(input.releaseRootId);
  const profileRecord = readCanonicalJson(input.profileCorePath, 'Q-09 profile core');
  const release = verifyV2FinalReleaseProfileCore(
    releaseRoot,
    profileRecord.bytes,
    profileRecord.value,
  );
  return Object.freeze({ profile: profileRecord.value, profileSha256: profileRecord.sha256, release, releaseRoot });
}
async function defaultFinalIdentity(input) {
  const { profile, profileSha256, release, releaseRoot } = releaseProfile(input);
  const descriptor = await loadV2InstanceDescriptor({ descriptorPath: input.descriptorPath, profileCore: profile, trustedSigners: release.descriptorSigners });
  assertRootedDescriptor(descriptor, releaseRoot, 'Q-09 qualification descriptor');
  const runtime = await deriveV2Pf10RuntimeFromValidatedDescriptor(descriptor); assertFinalRuntime(runtime);
  // The source pin is later checked again against the descriptor-derived
  // identity. Reading it here supplies the exact source revision to the
  // descriptor resolver without accepting it as an unbound assertion.
  const source = readCanonicalJson(input.sourcePinPath, 'Q-09 source pin');
  exactKeys(source.value, ['chainObserverSetSha256', 'commit', 'descriptorSha256', 'finalLocksSha256', 'instanceId', 'playgroundDescriptorSha256', 'profileId', 'schema', 'tree'], 'Q-09 source pin');
  if (source.value.schema !== V2_Q09_SOURCE_PIN_SCHEMA || !HEX_40.test(source.value.commit) || !HEX_40.test(source.value.tree)) fail('Q-09 source pin is malformed');
  const sourceArtifact = descriptor.artifacts.get(V2_Q09_SOURCE_PIN_ARTIFACT_ID);
  if (sourceArtifact === undefined || resolve(sourceArtifact.filename) !== input.sourcePinPath || sourceArtifact.sha256 !== source.sha256) fail('Q-09 source pin must be a signed final-manifest artifact');
  const observersArtifact = descriptor.artifacts.get(V2_Q09_CHAIN_OBSERVERS_ARTIFACT_ID);
  if (observersArtifact === undefined || resolve(observersArtifact.filename) !== input.chainObserversPath || observersArtifact.sha256 !== source.value.chainObserverSetSha256) fail('Q-09 trusted chain observers must be a signed final-manifest artifact');
  const pins = deriveV2SettlementPinsFromValidatedDescriptor(descriptor);
  const initial = decodeStateNftCommitment(descriptor.initialState, { denominationSats: profile.denominationSats });
  if (BigInt(initial.maximumLiveNotes) < MIN_HIGH_CAPACITY) fail('Q-09 qualification instance capacity is below 210,000,000 notes');
  return Object.freeze({ profileId: descriptor.profileId, profileSha256, instanceId: descriptor.instanceId, descriptorSha256: descriptor.descriptor.sha256, manifestSha256: descriptor.manifest.sha256, runtimeMaterialSha256: runtime.runtimeMaterial.materialSha256, finalLocksSha256: deriveV2FinalLocksSha256FromValidatedDescriptor(descriptor), releaseRootId: release.releaseRootId, releaseBootstrapSha256: release.releaseBootstrapSha256, sourceCommit: source.value.commit, sourceTree: source.value.tree, denominationSats: profile.denominationSats, maximumLiveNotes: initial.maximumLiveNotes, genesis: descriptor.genesis, initialStateHex: Buffer.from(descriptor.initialState).toString('hex'), carrierCount: pins.verifierCarriers.length, stateLockingBytecodeHex: pins.stateLockingBytecode.toString('hex'), stateBaseSats: pins.stateBaseSats, topologyId: pins.topologyId });
}
async function defaultPlaygroundIdentity(input, qualificationIdentity) {
  const { profile, profileSha256, release, releaseRoot } = releaseProfile(input);
  if (release.releaseRootId !== qualificationIdentity.releaseRootId || release.releaseBootstrapSha256 !== qualificationIdentity.releaseBootstrapSha256) fail('Q-09 playground release root differs from the qualification instance');
  const descriptor = await loadV2InstanceDescriptor({ descriptorPath: input.playgroundDescriptorPath, profileCore: profile, trustedSigners: release.descriptorSigners }); assertRootedDescriptor(descriptor, releaseRoot, 'Q-09 playground descriptor'); const runtime = await deriveV2Pf10RuntimeFromValidatedDescriptor(descriptor); assertFinalRuntime(runtime);
  const initial = decodeStateNftCommitment(descriptor.initialState, { denominationSats: profile.denominationSats });
  if (descriptor.profileId !== qualificationIdentity.profileId || initial.maximumLiveNotes !== String(PLAYGROUND_CAPACITY)) fail('Q-09 playground must be a separate final-qualified 32-live-note instance of the qualification profile');
  const source = readCanonicalJson(input.sourcePinPath, 'Q-09 source pin'); const sourceArtifact = descriptor.artifacts.get(V2_Q09_SOURCE_PIN_ARTIFACT_ID); const observerArtifact = descriptor.artifacts.get(V2_Q09_CHAIN_OBSERVERS_ARTIFACT_ID);
  if (sourceArtifact === undefined || observerArtifact === undefined || resolve(sourceArtifact.filename) !== input.sourcePinPath || resolve(observerArtifact.filename) !== input.chainObserversPath || sourceArtifact.sha256 !== source.sha256 || observerArtifact.sha256 !== source.value.chainObserverSetSha256 || source.value.playgroundDescriptorSha256 !== descriptor.descriptor.sha256) fail('Q-09 playground descriptor does not pin the shared source and observer artifacts');
  const pins = deriveV2SettlementPinsFromValidatedDescriptor(descriptor);
  return Object.freeze({ profileId: descriptor.profileId, profileSha256, instanceId: descriptor.instanceId, descriptorSha256: descriptor.descriptor.sha256, finalLocksSha256: deriveV2FinalLocksSha256FromValidatedDescriptor(descriptor), releaseRootId: release.releaseRootId, releaseBootstrapSha256: release.releaseBootstrapSha256, denominationSats: profile.denominationSats, maximumLiveNotes: initial.maximumLiveNotes, genesis: descriptor.genesis, initialStateHex: Buffer.from(descriptor.initialState).toString('hex'), carrierCount: pins.verifierCarriers.length, stateLockingBytecodeHex: pins.stateLockingBytecode.toString('hex'), stateBaseSats: pins.stateBaseSats });
}
function parseSourcePin(path, identity, expected, chainObserversSha256 = null) {
  const source = readCanonicalJson(path, 'Q-09 source pin'); exactKeys(source.value, ['chainObserverSetSha256', 'commit', 'descriptorSha256', 'finalLocksSha256', 'instanceId', 'playgroundDescriptorSha256', 'profileId', 'schema', 'tree'], 'Q-09 source pin');
  if (source.value.schema !== V2_Q09_SOURCE_PIN_SCHEMA || !HEX_40.test(source.value.commit) || !HEX_40.test(source.value.tree) || source.value.commit !== expected.commit || source.value.tree !== expected.tree || source.value.profileId !== identity.profileId || source.value.instanceId !== identity.instanceId || source.value.descriptorSha256 !== identity.descriptorSha256 || source.value.finalLocksSha256 !== identity.finalLocksSha256) fail('Q-09 source pin does not bind the final descriptor/final locks/current source');
  if (!HEX_32.test(source.value.chainObserverSetSha256) || !HEX_32.test(source.value.playgroundDescriptorSha256) || (chainObserversSha256 !== null && source.value.chainObserverSetSha256 !== chainObserversSha256)) fail('Q-09 source pin does not bind the trusted chain-observer set/playground descriptor'); return source;
}
function requireIdentity(value, identity, label) {
  if (value.profileId !== identity.profileId || value.instanceId !== identity.instanceId || value.finalLocksSha256 !== identity.finalLocksSha256 || value.sourceCommit !== identity.sourceCommit || value.sourceTree !== identity.sourceTree) fail(`${label} identity/final-lock/source pin mismatch`);
}
export function parseChainObservers(path) {
  const record = readCanonicalJson(path, 'Q-09 chain observers'); exactKeys(record.value, ['anchors', 'minimumTipChainWork', 'observers', 'schema'], 'Q-09 chain observers');
  if (record.value.schema !== V2_Q09_CHAIN_OBSERVERS_SCHEMA || !Array.isArray(record.value.observers) || record.value.observers.length < 2) fail('Q-09 requires at least two trusted chain observers');
  const observers = new Map(); const publicKeys = new Set();
  for (const [index, observer] of record.value.observers.entries()) {
    exactKeys(observer, ['id', 'publicKeyPem'], `Q-09 chain observer ${index}`);
    if (typeof observer.id !== 'string' || !/^[a-z][a-z0-9-]{1,63}$/.test(observer.id) || typeof observer.publicKeyPem !== 'string' || observers.has(observer.id)) fail('Q-09 chain observer is invalid or duplicate');
    let key; try { key = createPublicKey(observer.publicKeyPem); } catch { fail('Q-09 chain observer public key is invalid'); }
    if (key.asymmetricKeyType !== 'ed25519') fail('Q-09 chain observer key must be Ed25519');
    const spkiDer = key.export({ format: 'der', type: 'spki' }).toString('hex');
    if (publicKeys.has(spkiDer)) fail('Q-09 chain observer key is shared by multiple observer IDs');
    publicKeys.add(spkiDer); observers.set(observer.id, key);
  }
  if (!Array.isArray(record.value.anchors) || record.value.anchors.length === 0 || decimal(record.value.minimumTipChainWork, 'Q-09 minimum tip chainwork') === 0n) fail('Q-09 requires a source-pinned canonical-work anchor and minimum tip work');
  const anchors = new Map();
  for (const [index, anchor] of record.value.anchors.entries()) { exactKeys(anchor, ['chainWork', 'hash', 'height', 'maximumTarget'], `Q-09 chain anchor ${index}`); if (!Number.isSafeInteger(anchor.height) || anchor.height < 0 || !HEX_32.test(anchor.hash) || !HEX_32.test(anchor.maximumTarget) || anchors.has(anchor.height)) fail('Q-09 chain anchor is invalid or duplicate'); anchors.set(anchor.height, Object.freeze({ height: anchor.height, hash: anchor.hash, maximumTarget: anchor.maximumTarget, chainWork: decimal(anchor.chainWork, `Q-09 chain anchor ${index}.chainWork`) })); }
  return Object.freeze({ ...record, observers, anchors, minimumTipChainWork: decimal(record.value.minimumTipChainWork, 'Q-09 minimum tip chainwork') });
}
function parseChain(path, identity, observerSet) {
  const record = readCanonicalJson(path, 'Q-09 chain evidence'); assertNoForbiddenText(record.value, 'Q-09 chain evidence');
  exactKeys(record.value, ['anchor', 'attestations', 'genesis', 'headers', 'instanceId', 'network', 'profileId', 'schema', 'tipHeight'], 'Q-09 chain evidence');
  if (record.value.schema !== V2_Q09_CHAIN_EVIDENCE_SCHEMA || record.value.profileId !== identity.profileId || record.value.instanceId !== identity.instanceId || record.value.network?.id !== CHIPNET_ID || record.value.network?.name !== 'chipnet' || !Array.isArray(record.value.headers) || record.value.headers.length < 2 || !Number.isSafeInteger(record.value.tipHeight)) fail('Q-09 chain evidence is not canonical Chipnet header evidence');
  exactKeys(record.value.network, ['id', 'name'], 'Q-09 chain network');
  if (!Array.isArray(record.value.attestations) || record.value.attestations.length < 2) fail('Q-09 requires two signed canonical-chain attestations');
  exactKeys(record.value.anchor, ['chainWork', 'hash', 'height'], 'Q-09 chain evidence anchor');
  const anchor = observerSet.anchors.get(record.value.anchor.height);
  if (anchor === undefined || anchor.hash !== record.value.anchor.hash || anchor.chainWork !== decimal(record.value.anchor.chainWork, 'Q-09 chain evidence anchor chainwork')) fail('Q-09 chain evidence anchor is not source-pinned');
  const statement = { anchor: record.value.anchor, genesis: record.value.genesis, headers: record.value.headers, instanceId: record.value.instanceId, network: record.value.network, profileId: record.value.profileId, schema: record.value.schema, tipHeight: record.value.tipHeight };
  const signedBytes = Buffer.from(canonical(statement), 'utf8'); const seenObservers = new Set();
  for (const [index, attestation] of record.value.attestations.entries()) {
    exactKeys(attestation, ['algorithm', 'observerId', 'signatureBase64'], `Q-09 chain attestation ${index}`);
    const key = observerSet.observers.get(attestation.observerId);
    if (attestation.algorithm !== 'ed25519' || key === undefined || seenObservers.has(attestation.observerId) || typeof attestation.signatureBase64 !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(attestation.signatureBase64)) fail('Q-09 chain attestation is untrusted or malformed');
    let signature; try { signature = Buffer.from(attestation.signatureBase64, 'base64'); } catch { fail('Q-09 chain attestation signature is malformed'); }
    if (signature.length !== 64 || !verifySignature(null, signedBytes, key, signature)) fail('Q-09 chain attestation signature is invalid'); seenObservers.add(attestation.observerId);
  }
  let segment;
  try { segment = verifyRawHeaderSegment({ checkpoint: { blockHash: anchor.hash, height: anchor.height, chainwork: anchor.chainWork.toString(10), maximumTarget: anchor.maximumTarget }, rawHeaders: record.value.headers.map((entry) => Buffer.from(entry?.rawHeaderHex ?? '', 'hex')), tip: { blockHash: record.value.headers.at(-1)?.hash, height: record.value.tipHeight, chainwork: record.value.headers.at(-1)?.chainWork } }); } catch (error) { fail(`Q-09 raw header segment is invalid: ${error instanceof Error ? error.message : String(error)}`); }
  const headers = new Map();
  for (const [index, entry] of record.value.headers.entries()) {
    exactKeys(entry, ['chainWork', 'hash', 'height', 'rawHeaderHex', 'transactionCount'], `Q-09 header ${index}`); const parsed = segment.headers[index];
    if (entry.hash !== parsed.id || !Number.isSafeInteger(entry.height) || entry.height !== parsed.height || entry.chainWork !== parsed.chainwork || !Number.isSafeInteger(entry.transactionCount) || entry.transactionCount < 1) fail('Q-09 headers must be raw-header-linked, PoW-valid, exact-chainwork and carry a positive transaction count');
    if (headers.has(entry.height)) fail('Q-09 headers contain duplicate heights'); const normalized = Object.freeze({ ...entry, merkleRoot: parsed.merkleRoot, seconds: parsed.timestamp, chainWork: BigInt(parsed.chainwork) }); headers.set(entry.height, normalized);
  }
  const previous = segment.headers.at(-1);
  if (previous.height !== record.value.tipHeight || BigInt(previous.chainwork) < observerSet.minimumTipChainWork) fail('Q-09 tip height/work does not meet the source-pinned canonical-chain floor');
  exactKeys(record.value.genesis, ['blockHash', 'blockHeight', 'merkleBranch', 'rawTransactionHex', 'transactionId', 'transactionIndex'], 'Q-09 canonical genesis');
  const genesis = record.value.genesis;
  if (!Number.isSafeInteger(genesis.blockHeight) || genesis.blockHeight < 0 || !HEX_32.test(genesis.blockHash) || !HEX_32.test(genesis.transactionId) || typeof genesis.rawTransactionHex !== 'string' || !HEX.test(genesis.rawTransactionHex) || genesis.rawTransactionHex.length % 2 !== 0 || genesis.transactionId !== identity.genesis.transactionId) fail('Q-09 canonical genesis provenance is malformed');
  const genesisHeader = headers.get(genesis.blockHeight); if (genesisHeader === undefined || genesisHeader.hash !== genesis.blockHash || previous.height - genesis.blockHeight + 1 < MIN_CONFIRMATIONS) fail('Q-09 genesis is not sufficiently confirmed on the canonical Chipnet chain');
  let genesisTx; try { genesisTx = parseV2RawTransaction(genesis.rawTransactionHex); } catch (error) { fail(`Q-09 canonical genesis transaction is malformed: ${error instanceof Error ? error.message : String(error)}`); }
  if (genesisTx.txid !== genesis.transactionId || genesisTx.outputs[identity.genesis.outpointIndex] === undefined) fail('Q-09 canonical genesis raw transaction does not bind descriptor outpoint');
  verifyMerkleInclusion({ rawTransactionHex: genesis.rawTransactionHex, transactionId: genesis.transactionId, transactionIndex: genesis.transactionIndex, merkleBranch: genesis.merkleBranch, header: genesisHeader, label: 'Q-09 canonical genesis' });
  let genesisOutput; try { genesisOutput = parseSerializedSourceOutput(genesisTx.outputs[identity.genesis.outpointIndex].serializedHex); } catch (error) { fail(`Q-09 canonical genesis state output is malformed: ${error instanceof Error ? error.message : String(error)}`); }
  if (genesisOutput.token?.categoryWire !== identity.instanceId || genesisOutput.token?.amount !== '0' || genesisOutput.token?.nft?.capability !== 'mutable' || genesisOutput.token?.nft?.commitmentHex !== identity.initialStateHex || genesisOutput.lockingBytecodeHex !== identity.stateLockingBytecodeHex || genesisOutput.valueSatoshis !== BigInt(identity.stateBaseSats)) fail('Q-09 canonical genesis state output is not final-lock-bound');
  return Object.freeze({ ...record, headers, tip: previous, genesis: Object.freeze({ header: genesisHeader, transaction: genesisTx }) });
}
function packetOccurrence(unlock, packet) { let count = 0; let offset = unlock.indexOf(packet); while (offset !== -1) { count += 1; offset = unlock.indexOf(packet, offset + 1); } return count; }
function liveNotes(state) { return BigInt(state.noteCount) - BigInt(state.nullifierCount); }
function parsePlaygroundSettlement(value, identity, chain, previous, label, { requireInclusion = true, requireLocalVmEvidence = false, forbiddenTransactionIds = new Set() } = {}) {
  const rawKeys = requireInclusion ? ['blockHash', 'blockHeight', 'merkleBranch', 'packetHex', 'rawTransactionHex', 'stateOutputIndex', 'transactionId', 'transactionIndex'] : ['packetHex', 'rawTransactionHex', 'stateOutputIndex', 'transactionId', ...(requireLocalVmEvidence ? ['localVmEvidenceHex'] : [])];
  exactKeys(value, rawKeys, label); if (forbiddenTransactionIds.has(value.transactionId)) fail(`${label} reuses a high-capacity or earlier canonical transaction`);
  let tx;
  // Settlement evidence carries both the exact chain-inclusion tuple and the
  // packet/state binding fields. Keep the chain parser's closed schema: only
  // pass its six authenticated inclusion fields, rather than broadening that
  // parser to accept settlement-only properties.
  if (requireInclusion) tx = parseChainBoundTransaction({
    blockHash: value.blockHash,
    blockHeight: value.blockHeight,
    merkleBranch: value.merkleBranch,
    rawTransactionHex: value.rawTransactionHex,
    transactionId: value.transactionId,
    transactionIndex: value.transactionIndex,
  }, chain, label).transaction;
  else { try { tx = parseV2RawTransaction(value.rawTransactionHex); } catch { fail(`${label} candidate raw transaction is invalid`); } if (tx.txid !== value.transactionId) fail(`${label} candidate transaction ID does not bind raw bytes`); }
  try { assertV2StandardTransactionEnvelope(tx, { carrierCount: identity.carrierCount }); } catch (error) { fail(`${label} does not have the exact playground topology: ${error instanceof Error ? error.message : String(error)}`); }
  if (value.stateOutputIndex !== 0 || tx.inputs[identity.carrierCount + 1]?.outpoint.txid !== previous.outpoint.txid || tx.inputs[identity.carrierCount + 1]?.outpoint.vout !== previous.outpoint.vout) fail(`${label} does not spend the exact prior playground state outpoint`);
  if (typeof value.packetHex !== 'string' || !HEX.test(value.packetHex) || value.packetHex.length !== 1_104) fail(`${label} packet is malformed`); const packet = Buffer.from(value.packetHex, 'hex');
  if (packetOccurrence(tx.inputs[identity.carrierCount].unlockingBytecode, packet) !== 1) fail(`${label} packet is not exactly once in its binding input`);
  let decoded; try { decoded = decodeActionPacket(packet, { denominationSats: identity.denominationSats }); } catch (error) { fail(`${label} packet is invalid: ${error instanceof Error ? error.message : String(error)}`); }
  if (decoded.networkId !== CHIPNET_ID || decoded.preState.profileId !== identity.profileId || decoded.postState.profileId !== identity.profileId || decoded.instanceId !== identity.instanceId || !encodeStateNftCommitment(decoded.preState, { denominationSats: identity.denominationSats }).equals(previous.state)) fail(`${label} packet does not bind the exact prior playground state/profile/instance`);
  let output; try { output = parseSerializedSourceOutput(tx.outputs[0].serializedHex); } catch { fail(`${label} successor state output is malformed`); } const post = encodeStateNftCommitment(decoded.postState, { denominationSats: identity.denominationSats });
  if (output.token?.categoryWire !== identity.instanceId || output.token?.amount !== '0' || output.token?.nft?.capability !== 'mutable' || output.token?.nft?.commitmentHex !== post.toString('hex') || output.lockingBytecodeHex !== identity.stateLockingBytecodeHex || output.valueSatoshis !== BigInt(identity.stateBaseSats) + BigInt(decoded.postState.reserveSats)) fail(`${label} successor state output does not bind playground descriptor state`);
  return Object.freeze({ kind: decoded.kind, transactionId: value.transactionId, outpoint: { txid: value.transactionId, vout: 0 }, state: post, decoded, raw: value, transaction: tx });
}
function inspectContentionCandidateVmEvidence(candidate, identity, label) {
  if (typeof candidate.raw.localVmEvidenceHex !== 'string' || !HEX.test(candidate.raw.localVmEvidenceHex) || candidate.raw.localVmEvidenceHex.length === 0 || candidate.raw.localVmEvidenceHex.length % 2 !== 0) fail(`${label} local VM evidence must be nonempty canonical hexadecimal bytes`);
  let evidence;
  try { evidence = inspectV2LocalVmEvidence(Buffer.from(candidate.raw.localVmEvidenceHex, 'hex')); } catch (error) { fail(`${label} local VM evidence is invalid: ${error instanceof Error ? error.message : String(error)}`); }
  if (evidence.transaction.rawTransactionHex !== candidate.raw.rawTransactionHex || evidence.transaction.txid !== candidate.transactionId || evidence.instanceId !== identity.instanceId || evidence.carrierCount !== identity.carrierCount || evidence.tool.profileId !== identity.profileId || evidence.tool.profileSha256 !== identity.profileSha256) fail(`${label} local VM evidence does not bind the exact candidate transaction, instance, carrier count, and profile`);
  return evidence;
}
function assertSameContentionCovenantPrevouts(candidate, winner, carrierCount, label) {
  for (let index = 0; index < carrierCount + 2; index += 1) {
    const actual = candidate.transaction.inputs[index]?.outpoint;
    const expected = winner.transaction.inputs[index]?.outpoint;
    if (actual?.txid !== expected?.txid || actual?.vout !== expected?.vout) fail(`${label} covenant input ${index} does not share the confirmed winner's exact prepared prevout`);
  }
}
function parseSettlements(path, identity, chain) {
  const record = readCanonicalJson(path, 'Q-09 settlement journal'); assertNoForbiddenText(record.value, 'Q-09 settlement journal');
  exactKeys(record.value, ['chainEvidenceSha256', 'entries', 'finalLocksSha256', 'instanceId', 'profileId', 'schema', 'sourceCommit', 'sourceTree'], 'Q-09 settlement journal'); requireIdentity(record.value, identity, 'Q-09 settlement journal');
  if (record.value.schema !== V2_Q09_SETTLEMENT_JOURNAL_SCHEMA || record.value.chainEvidenceSha256 !== chain.sha256 || !Array.isArray(record.value.entries) || record.value.entries.length < MIN_SETTLEMENTS) fail('Q-09 requires at least 1,000 chain-bound direct settlements');
  const txids = new Set(); let previousEntryHash = null; let currentOutpoint = { txid: identity.genesis.transactionId, vout: identity.genesis.outpointIndex }; let currentState = Buffer.from(identity.initialStateHex, 'hex'); let firstTime = null; let lastTime = null; const actionCounts = Object.fromEntries(ACTION_KINDS.map((kind) => [kind, 0]));
  for (const [sequence, entry] of record.value.entries.entries()) {
    exactKeys(entry, ['blockHash', 'blockHeight', 'entrySha256', 'kind', 'merkleBranch', 'packetHex', 'previousEntrySha256', 'rawTransactionHex', 'stateOutputIndex', 'transactionId', 'transactionIndex'], `Q-09 settlement ${sequence}`);
    const { entrySha256, ...payload } = entry; if (entry.previousEntrySha256 !== previousEntryHash || !HEX_32.test(entrySha256) || sha256Json(payload) !== entrySha256 || entry.kind === 'withdraw' || !ACTION_KINDS.includes(entry.kind)) fail('Q-09 settlement journal is rewritten, gapped, or action-mislabeled');
    if (!Number.isSafeInteger(entry.blockHeight) || entry.blockHeight < 0 || !HEX_32.test(entry.blockHash) || !HEX_32.test(entry.transactionId) || typeof entry.rawTransactionHex !== 'string' || !HEX.test(entry.rawTransactionHex) || entry.rawTransactionHex.length % 2 !== 0 || typeof entry.packetHex !== 'string' || !HEX.test(entry.packetHex) || entry.packetHex.length !== 1_104 || !Number.isSafeInteger(entry.stateOutputIndex) || entry.stateOutputIndex !== 0 || txids.has(entry.transactionId)) fail('Q-09 settlement entry is malformed or duplicate');
    const header = chain.headers.get(entry.blockHeight); if (header === undefined || header.hash !== entry.blockHash || chain.tip.height - entry.blockHeight + 1 < MIN_CONFIRMATIONS) fail('Q-09 settlement has missing canonical confirmation evidence');
    let tx; try { tx = assertV2StandardTransactionEnvelope(parseV2RawTransaction(entry.rawTransactionHex), { carrierCount: identity.carrierCount }); } catch (error) { fail(`Q-09 settlement ${sequence} transaction envelope is invalid: ${error instanceof Error ? error.message : String(error)}`); }
    if (tx.txid !== entry.transactionId) fail('Q-09 settlement transaction ID does not bind raw bytes'); verifyMerkleInclusion({ rawTransactionHex: entry.rawTransactionHex, transactionId: entry.transactionId, transactionIndex: entry.transactionIndex, merkleBranch: entry.merkleBranch, header, label: `Q-09 settlement ${sequence}` }); txids.add(entry.transactionId);
    const stateInputIndex = identity.carrierCount + 1; if (tx.inputs[stateInputIndex]?.outpoint.txid !== currentOutpoint.txid || tx.inputs[stateInputIndex]?.outpoint.vout !== currentOutpoint.vout) fail('Q-09 settlement does not spend the unique previous state outpoint');
    const packet = Buffer.from(entry.packetHex, 'hex'); if (packet.length !== 552 || packetOccurrence(tx.inputs[identity.carrierCount].unlockingBytecode, packet) !== 1) fail('Q-09 settlement packet is not exactly once in the binding input');
    let decoded; try { decoded = decodeActionPacket(packet, { denominationSats: identity.denominationSats }); } catch (error) { fail(`Q-09 settlement packet is invalid: ${error instanceof Error ? error.message : String(error)}`); }
    if (decoded.kind !== entry.kind || decoded.networkId !== CHIPNET_ID || decoded.instanceId !== identity.instanceId || !encodeStateNftCommitment(decoded.preState, { denominationSats: identity.denominationSats }).equals(currentState)) fail('Q-09 packet does not bind the current final-profile state');
    const output = tx.outputs[0]; let source; try { source = parseSerializedSourceOutput(output.serializedHex); } catch (error) { fail(`Q-09 settlement state output is malformed: ${error instanceof Error ? error.message : String(error)}`); }
    const post = encodeStateNftCommitment(decoded.postState, { denominationSats: identity.denominationSats });
    if (source.token?.categoryWire !== identity.instanceId || source.token?.amount !== '0' || source.token?.nft?.capability !== 'mutable' || source.token?.nft?.commitmentHex !== post.toString('hex') || source.lockingBytecodeHex !== identity.stateLockingBytecodeHex || source.valueSatoshis !== BigInt(identity.stateBaseSats) + BigInt(decoded.postState.reserveSats)) fail('Q-09 settlement successor state output is not final-lock-bound');
    currentOutpoint = { txid: entry.transactionId, vout: 0 }; currentState = post; previousEntryHash = entrySha256; actionCounts[entry.kind] += 1; if (firstTime === null) firstTime = header.seconds; lastTime = header.seconds;
  }
  if (firstTime === null || lastTime === null || lastTime - firstTime < MIN_SOAK_SECONDS) fail('Q-09 raw canonical block-header span is shorter than 30 days');
  return Object.freeze({ record, firstBlockTime: blockHashForTime(firstTime), lastBlockTime: blockHashForTime(lastTime), elapsedSeconds: lastTime - firstTime, actionCounts, terminalStateSha256: sha256(currentState), terminalOutpoint: currentOutpoint, txids: Object.freeze([...txids]) });
}
function parsePlayground(path, qualificationIdentity, identity, chain, settlements, observerSet) {
  const record = readCanonicalJson(path, 'Q-09 32-note playground evidence'); assertNoForbiddenText(record.value, 'Q-09 playground evidence');
  exactKeys(record.value, ['attestations', 'chainEvidenceSha256', 'contention', 'eraseRecover', 'finalLocksSha256', 'genesis', 'instanceId', 'playgroundDescriptorSha256', 'profileId', 'runs', 'schema', 'sourceCommit', 'sourceTree'], 'Q-09 playground evidence');
  if (record.value.profileId !== identity.profileId || record.value.instanceId !== identity.instanceId || record.value.finalLocksSha256 !== identity.finalLocksSha256 || record.value.playgroundDescriptorSha256 !== identity.descriptorSha256 || record.value.sourceCommit !== qualificationIdentity.sourceCommit || record.value.sourceTree !== qualificationIdentity.sourceTree) fail('Q-09 playground evidence does not bind the separate final-qualified 32-note instance');
  if (record.value.schema !== V2_Q09_PLAYGROUND_SCHEMA || record.value.chainEvidenceSha256 !== chain.sha256 || !Array.isArray(record.value.runs) || record.value.runs.length === 0) fail('Q-09 playground evidence is malformed');
  if (record.value.runs.length !== 1 || !Array.isArray(record.value.runs[0]?.fill) || record.value.runs[0].fill.length !== PLAYGROUND_CAPACITY) fail('Q-09 playground requires exactly 32 raw fill transactions, never an aggregate count');
  const { attestations, ...statement } = record.value; verifyObserverAttestations(attestations, statement, observerSet, 'Q-09 playground evidence');
  const playgroundGenesis = validateDescriptorGenesis(record.value.genesis, identity, chain, 'Q-09 playground descriptor genesis');
  const canonicalIds = new Set([...settlements.txids, playgroundGenesis.transactionId]); let tip = playgroundGenesis;
  for (const [index, run] of record.value.runs.entries()) {
    exactKeys(run, ['admission33', 'fill', 'refill', 'withdraw'], `Q-09 playground run ${index}`);
    if (liveNotes(decodeStateNftCommitment(tip.state, { denominationSats: identity.denominationSats })) !== 0n || !Array.isArray(run.fill) || run.fill.length !== PLAYGROUND_CAPACITY || !Array.isArray(run.withdraw) || run.withdraw.length === 0 || !Array.isArray(run.refill) || run.refill.length === 0) fail('Q-09 playground run lacks an exact zero-to-32 fill/withdraw/refill lineage');
    for (const [ordinal, evidence] of run.fill.entries()) { const next = parsePlaygroundSettlement(evidence, identity, chain, tip, `Q-09 playground fill ${ordinal}`, { forbiddenTransactionIds: canonicalIds }); if (next.kind !== 'deposit' || liveNotes(next.decoded.postState) !== BigInt(ordinal + 1)) fail('Q-09 playground fill is not exactly one contiguous deposit per live-note increment'); canonicalIds.add(next.transactionId); tip = next; }
    if (liveNotes(decodeStateNftCommitment(tip.state, { denominationSats: identity.denominationSats })) !== BigInt(PLAYGROUND_CAPACITY)) fail('Q-09 playground did not reach exactly 32 live notes');
    exactKeys(run.admission33, ['admissionJournal', 'action', 'liveNoteCount', 'proofInvocationCountAfter', 'proofInvocationCountBefore', 'result'], `Q-09 playground run ${index} admission33`);
    if (run.admission33.action !== 'deposit' || run.admission33.result !== 'rejected-capacity-before-proving' || run.admission33.liveNoteCount !== PLAYGROUND_CAPACITY || !Number.isSafeInteger(run.admission33.proofInvocationCountBefore) || run.admission33.proofInvocationCountBefore < 0 || run.admission33.proofInvocationCountAfter !== run.admission33.proofInvocationCountBefore || !HEX_32.test(run.admission33.admissionJournal)) fail('Q-09 playground deposit 33 was not rejected before proving with a hash-bound admission journal');
    for (const [ordinal, evidence] of run.withdraw.entries()) { const before = liveNotes(decodeStateNftCommitment(tip.state, { denominationSats: identity.denominationSats })); const next = parsePlaygroundSettlement(evidence, identity, chain, tip, `Q-09 playground withdraw ${ordinal}`, { forbiddenTransactionIds: canonicalIds }); if (next.kind !== 'withdrawal' || liveNotes(next.decoded.postState) !== before - 1n) fail('Q-09 playground withdrawal does not lower the live-note count by one'); canonicalIds.add(next.transactionId); tip = next; }
    for (const [ordinal, evidence] of run.refill.entries()) { const before = liveNotes(decodeStateNftCommitment(tip.state, { denominationSats: identity.denominationSats })); const next = parsePlaygroundSettlement(evidence, identity, chain, tip, `Q-09 playground refill ${ordinal}`, { forbiddenTransactionIds: canonicalIds }); if (next.kind !== 'deposit' || liveNotes(next.decoded.postState) !== before + 1n || liveNotes(next.decoded.postState) > BigInt(PLAYGROUND_CAPACITY)) fail('Q-09 playground refill is not a valid one-note deposit'); canonicalIds.add(next.transactionId); tip = next; }
    if (liveNotes(decodeStateNftCommitment(tip.state, { denominationSats: identity.denominationSats })) !== BigInt(PLAYGROUND_CAPACITY)) fail('Q-09 playground refill does not restore 32 live notes');
  }
  exactKeys(record.value.eraseRecover, ['deleteStateJournal', 'recoveredSpend', 'recoveryJournal'], 'Q-09 erase/recover'); exactKeys(record.value.eraseRecover.recoveryJournal, ['attestations', 'entries', 'recoveredNoteId', 'schema'], 'Q-09 recovery journal'); if (!HEX_32.test(record.value.eraseRecover.deleteStateJournal) || !HEX_32.test(record.value.eraseRecover.recoveryJournal.recoveredNoteId) || record.value.eraseRecover.recoveryJournal.schema !== 'shieldkit-v2-direct-q09-recovery-journal/v1' || !Array.isArray(record.value.eraseRecover.recoveryJournal.entries) || record.value.eraseRecover.recoveryJournal.entries.length === 0) fail('Q-09 erase/recover must contain signed raw recovery journal content'); const { attestations: recoveryAttestations, ...recoveryStatement } = record.value.eraseRecover.recoveryJournal; verifyObserverAttestations(recoveryAttestations, recoveryStatement, observerSet, 'Q-09 recovery journal'); let recoveredTip = playgroundGenesis; const recoveredIds = new Set([...settlements.txids]); for (const [ordinal, evidence] of record.value.eraseRecover.recoveryJournal.entries.entries()) { const next = parsePlaygroundSettlement(evidence, identity, chain, recoveredTip, `Q-09 recovery journal entry ${ordinal}`, { forbiddenTransactionIds: recoveredIds }); recoveredIds.add(next.transactionId); recoveredTip = next; } if (!recoveredTip.state.equals(tip.state) || recoveredTip.outpoint.txid !== tip.outpoint.txid) fail('Q-09 recovery journal does not independently reconstruct the terminal playground lineage'); const { recoveredNoteId, ...recoveredEvidence } = record.value.eraseRecover.recoveredSpend; const recoveredSpend = parsePlaygroundSettlement(recoveredEvidence, identity, chain, recoveredTip, 'Q-09 recovered-note spend', { forbiddenTransactionIds: canonicalIds }); if (recoveredSpend.kind !== 'withdrawal' || !HEX_32.test(recoveredNoteId) || recoveredNoteId !== record.value.eraseRecover.recoveryJournal.recoveredNoteId) fail('Q-09 recovered spend does not bind the recovered note journal'); canonicalIds.add(recoveredSpend.transactionId); tip = recoveredSpend;
  exactKeys(record.value.contention, ['attempts', 'winnerTransactionId'], 'Q-09 contention'); if (!Array.isArray(record.value.contention.attempts) || record.value.contention.attempts.length < 2 || !HEX_32.test(record.value.contention.winnerTransactionId)) fail('Q-09 contention evidence is incomplete');
  const contentionPrior = tip; let winner = null; let winnerCandidate = null; const preparedCandidates = [];
  for (const [ordinal, attempt] of record.value.contention.attempts.entries()) { exactKeys(attempt, ['candidate', 'deliveryJournal', 'result', ...(attempt?.result === 'confirmed-winner' ? ['canonical'] : [])], `Q-09 contention attempt ${ordinal}`); if (!['confirmed-winner', 'conflicted-not-broadcast', 'needs-reproof'].includes(attempt.result)) fail('Q-09 contention attempt result is invalid'); const candidate = parsePlaygroundSettlement(attempt.candidate, identity, chain, contentionPrior, `Q-09 contention candidate ${ordinal}`, { requireInclusion: false, requireLocalVmEvidence: true, forbiddenTransactionIds: canonicalIds }); inspectContentionCandidateVmEvidence(candidate, identity, `Q-09 contention candidate ${ordinal}`); preparedCandidates.push({ candidate, ordinal }); exactKeys(attempt.deliveryJournal, ['attestations', 'entries', 'schema'], `Q-09 contention delivery journal ${ordinal}`); if (attempt.deliveryJournal.schema !== 'shieldkit-v2-direct-q09-delivery-journal/v1' || !Array.isArray(attempt.deliveryJournal.entries) || attempt.deliveryJournal.entries.length === 0) fail('Q-09 contention delivery journal is missing'); const { attestations: deliveryAttestations, ...deliveryStatement } = attempt.deliveryJournal; verifyObserverAttestations(deliveryAttestations, deliveryStatement, observerSet, `Q-09 contention delivery journal ${ordinal}`); let previousHash = null; for (const [index, entry] of attempt.deliveryJournal.entries.entries()) { exactKeys(entry, ['candidateTransactionId', 'entrySha256', 'event', 'previousSha256', 'sequence', 'stateOutpoint', 'status'], `Q-09 contention delivery entry ${ordinal}:${index}`); const { entrySha256, ...entryPayload } = entry; if (entry.sequence !== index || entry.previousSha256 !== previousHash || entry.candidateTransactionId !== candidate.transactionId || entry.stateOutpoint?.txid !== contentionPrior.outpoint.txid || entry.stateOutpoint?.vout !== contentionPrior.outpoint.vout || !HEX_32.test(entrySha256) || sha256Json(entryPayload) !== entrySha256) fail('Q-09 contention delivery journal is not hash-chained to the same prior state'); previousHash = entrySha256; }
    if (attempt.result === 'confirmed-winner') { if (winner !== null || candidate.transactionId !== record.value.contention.winnerTransactionId) fail('Q-09 contention winner identity is invalid'); const canonical = parsePlaygroundSettlement(attempt.canonical, identity, chain, contentionPrior, `Q-09 contention winner ${ordinal}`, { forbiddenTransactionIds: canonicalIds }); if (canonical.transactionId !== candidate.transactionId || canonical.raw.rawTransactionHex !== attempt.candidate.rawTransactionHex || canonical.raw.packetHex !== attempt.candidate.packetHex) fail('Q-09 contention winner canonical transaction differs from its prepared candidate'); winner = canonical; winnerCandidate = candidate; canonicalIds.add(canonical.transactionId); }
    else { if (canonicalIds.has(candidate.transactionId) || attempt.result === 'conflicted-not-broadcast' && !attempt.deliveryJournal.entries.some((entry) => entry.status === 'not-broadcast') || attempt.result === 'needs-reproof' && !attempt.deliveryJournal.entries.some((entry) => entry.status === 'stale-tip-needs-reproof')) fail('Q-09 contention loser journal contradicts no-send/stale-tip lifecycle'); }
  }
  if (winner === null || winnerCandidate === null) fail('Q-09 contention must prove exactly one canonical winner and non-broadcast/reproof losers');
  for (const { candidate, ordinal } of preparedCandidates) assertSameContentionCovenantPrevouts(candidate, winnerCandidate, identity.carrierCount, `Q-09 contention candidate ${ordinal}`);
  return record;
}

/** Read-only test/integration entrypoint; it can only reject or return parsed
 * raw chain data and never writes a Q-09 artifact. */
export function validateV2Q09ChainEvidence(path, identity, observerSet) { return parseChain(path, identity, observerSet); }
export function validateV2Q09PlaygroundEvidence(path, qualificationIdentity, playgroundIdentity, chain, settlements, observerSet) { return parsePlayground(path, qualificationIdentity, playgroundIdentity, chain, settlements, observerSet); }
export function validateV2Q09PlaygroundCandidate(value, identity, chain, previous, options = {}) { return parsePlaygroundSettlement(value, identity, chain, previous, 'Q-09 standalone playground candidate', options); }
export function assertV2Q09Q08PairBinding(q08, identity) {
  if (
    q08?.q08Qualified !== true || q08.production !== false || q08.releaseQualified !== false
    || q08.profileId !== identity.profileId
    || q08.profileSha256 !== identity.profileSha256
    || q08.instanceId !== identity.instanceId
    || q08.carrierCount !== identity.carrierCount
    || q08.descriptorSha256 !== identity.descriptorSha256 || q08.manifestSha256 !== identity.manifestSha256
    || q08.runtimeMaterialSha256 !== identity.runtimeMaterialSha256
    || q08.releaseRootId !== identity.releaseRootId || q08.releaseBootstrapSha256 !== identity.releaseBootstrapSha256
    || q08.topology?.id !== identity.topologyId || q08.git?.commit !== identity.sourceCommit
    || q08.git?.tree !== identity.sourceTree || !HEX_32.test(q08.artifactSha256)
    || !HEX_32.test(q08.hosts?.a?.envelopeSha256) || !HEX_32.test(q08.hosts?.b?.envelopeSha256)
    || !HEX_32.test(q08.hosts?.a?.statementSha256) || !HEX_32.test(q08.hosts?.b?.statementSha256)
  ) fail('Q-09 Q-08 pair artifact does not exactly bind the final root, runtime, topology, and source');
  return q08;
}

export async function runV2Q09ChipnetSoak(options, dependencies = {}) {
  const runner = dependencies.runner ?? capture; const verifyFinalInputs = dependencies.verifyFinalInputs ?? defaultFinalIdentity; const testOnly = options?.testOnly === true;
  if (!testOnly && (dependencies.verifyFinalInputs !== undefined || dependencies.verifyPlaygroundInputs !== undefined || dependencies.testOnlyEvidence !== undefined || dependencies.runner !== undefined)) fail('Q-09 production qualification refuses injected test doubles');
  const git = await gitState(runner); if (git.commit !== options.expectedCommit || git.tree !== options.expectedTree) fail('Q-09 live Git commit/tree differs from the exact requested clean source');
  for (const [key, label] of Object.entries({ descriptorPath: 'Q-09 descriptor', playgroundDescriptorPath: 'Q-09 playground descriptor', profileCorePath: 'Q-09 profile core', sourcePinPath: 'Q-09 source pin', chainObserversPath: 'Q-09 chain observers', q02CorpusPath: 'Q-09 Q-02 corpus', chainEvidencePath: 'Q-09 chain evidence', settlementsPath: 'Q-09 settlements', playgroundPath: 'Q-09 playground' })) directFile(options[key], label);
  const identity = await verifyFinalInputs(options); exactKeys(identity, ['carrierCount', 'denominationSats', 'descriptorSha256', 'finalLocksSha256', 'genesis', 'initialStateHex', 'instanceId', 'manifestSha256', 'maximumLiveNotes', 'profileId', 'profileSha256', 'releaseBootstrapSha256', 'releaseRootId', 'runtimeMaterialSha256', 'sourceCommit', 'sourceTree', 'stateBaseSats', 'stateLockingBytecodeHex', 'topologyId'], 'Q-09 final input verification result');
  if (!HEX_32.test(identity.profileId) || !HEX_32.test(identity.profileSha256) || !HEX_32.test(identity.instanceId) || !HEX_32.test(identity.descriptorSha256) || !HEX_32.test(identity.finalLocksSha256) || !HEX_32.test(identity.manifestSha256) || !HEX_32.test(identity.runtimeMaterialSha256) || !ROOT_ID.test(identity.releaseRootId) || !HEX_32.test(identity.releaseBootstrapSha256) || !HEX_40.test(identity.sourceCommit) || !HEX_40.test(identity.sourceTree) || identity.sourceCommit !== git.commit || identity.sourceTree !== git.tree || !Number.isSafeInteger(identity.carrierCount) || identity.carrierCount < 1 || BigInt(identity.maximumLiveNotes) < MIN_HIGH_CAPACITY || !/^[0-9]+$/.test(identity.denominationSats) || !/^[0-9]+$/.test(identity.stateBaseSats) || !HEX.test(identity.initialStateHex) || identity.initialStateHex.length !== 256 || !HEX.test(identity.stateLockingBytecodeHex)) fail('Q-09 final input verifier returned invalid final material');
  const verifyPlaygroundInputs = dependencies.verifyPlaygroundInputs ?? defaultPlaygroundIdentity;
  const playgroundIdentity = await verifyPlaygroundInputs(options, identity); exactKeys(playgroundIdentity, ['carrierCount', 'denominationSats', 'descriptorSha256', 'finalLocksSha256', 'genesis', 'initialStateHex', 'instanceId', 'maximumLiveNotes', 'profileId', 'profileSha256', 'releaseBootstrapSha256', 'releaseRootId', 'stateBaseSats', 'stateLockingBytecodeHex'], 'Q-09 playground final input verification result');
  if (playgroundIdentity.profileId !== identity.profileId || playgroundIdentity.profileSha256 !== identity.profileSha256 || playgroundIdentity.releaseRootId !== identity.releaseRootId || playgroundIdentity.releaseBootstrapSha256 !== identity.releaseBootstrapSha256 || !HEX_32.test(playgroundIdentity.instanceId) || playgroundIdentity.instanceId === identity.instanceId || !HEX_32.test(playgroundIdentity.descriptorSha256) || !HEX_32.test(playgroundIdentity.finalLocksSha256) || playgroundIdentity.maximumLiveNotes !== String(PLAYGROUND_CAPACITY) || playgroundIdentity.denominationSats !== identity.denominationSats || !Number.isSafeInteger(playgroundIdentity.carrierCount) || playgroundIdentity.carrierCount < 1 || !HEX.test(playgroundIdentity.initialStateHex) || playgroundIdentity.initialStateHex.length !== 256 || !HEX.test(playgroundIdentity.stateLockingBytecodeHex) || !/^[0-9]+$/.test(playgroundIdentity.stateBaseSats)) fail('Q-09 playground final input verifier did not establish a separate 32-note final-qualified instance');
  const sourcePin = parseSourcePin(options.sourcePinPath, identity, git);
  // A test-only seam intentionally stops before any caller-supplied evidence
  // could be interpreted as a rollout. It is unavailable from the CLI and
  // writes only a nonqualifying marker; production always parses raw inputs.
  if (testOnly && dependencies.testOnlyEvidence !== undefined) {
    await dependencies.testOnlyEvidence();
    privateNewDirectory(options.outputDirectory);
    atomicPrivateJson(join(options.outputDirectory, 'test-only.json'), { schema: V2_Q09_RESULT_SCHEMA, status: 'test-only-nonqualifying', q09Qualified: false, validated: ['final-identity', 'source-pin', 'test-order-only'] });
    return Object.freeze({ schema: V2_Q09_RESULT_SCHEMA, status: 'test-only-nonqualifying', q09Qualified: false });
  }
  const observers = parseChainObservers(options.chainObserversPath); parseSourcePin(options.sourcePinPath, identity, git, observers.sha256);
  const q02 = await verifyV2Q02FinalKeyCorpus({ corpusPath: options.q02CorpusPath, descriptorPath: options.descriptorPath, profileCorePath: options.profileCorePath, releaseRootId: options.releaseRootId });
  if (q02.q02Qualified !== true || q02.cases !== 768 || q02.mutations !== 9_984 || q02.releaseRootId !== identity.releaseRootId || q02.releaseBootstrapSha256 !== identity.releaseBootstrapSha256) fail('Q-09 Q-02 final-key verifier did not establish the required root-bound 768-case corpus');
  const q02Corpus = readCanonicalJson(options.q02CorpusPath, 'Q-09 Q-02 final-key corpus');
  const q08 = await verifyV2Q08PairQualificationArtifact({
    profileCorePath: options.profileCorePath,
    descriptorPath: options.descriptorPath,
    hostAEnvelopePath: options.q08HostAPath,
    hostBEnvelopePath: options.q08HostBPath,
    pairArtifactPath: options.q08PairPath,
    releaseRootId: options.releaseRootId,
    expectedCommit: options.expectedCommit,
    expectedTree: options.expectedTree,
  });
  assertV2Q09Q08PairBinding(q08, identity);
  const chain = parseChain(options.chainEvidencePath, identity, observers); const settlements = parseSettlements(options.settlementsPath, identity, chain); const playground = parsePlayground(options.playgroundPath, identity, playgroundIdentity, chain, settlements, observers);
  privateNewDirectory(options.outputDirectory);
  try {
    if (testOnly) {
      atomicPrivateJson(join(options.outputDirectory, 'test-only.json'), { schema: V2_Q09_RESULT_SCHEMA, status: 'test-only-nonqualifying', q09Qualified: false, validated: ['final-identity', 'source-pin', 'q02', 'q08', 'chain', 'settlements', 'playground'] });
      return Object.freeze({ schema: V2_Q09_RESULT_SCHEMA, status: 'test-only-nonqualifying', q09Qualified: false });
    }
    const result = Object.freeze({ schema: V2_Q09_RESULT_SCHEMA, status: 'chipnet-rollout-qualified', q09Qualified: true, profileId: identity.profileId, instanceId: identity.instanceId, descriptorSha256: identity.descriptorSha256, manifestSha256: identity.manifestSha256, runtimeMaterialSha256: identity.runtimeMaterialSha256, finalLocksSha256: identity.finalLocksSha256, releaseRootId: identity.releaseRootId, releaseBootstrapSha256: identity.releaseBootstrapSha256, topologyId: identity.topologyId, git, sourcePinSha256: sourcePin.sha256, q02CorpusSha256: q02Corpus.sha256, q08PairArtifactSha256: q08.artifactSha256, q08HostEnvelopeSha256s: Object.freeze([q08.hosts.a.envelopeSha256, q08.hosts.b.envelopeSha256]), q08HostStatementSha256s: Object.freeze([q08.hosts.a.statementSha256, q08.hosts.b.statementSha256]), chainEvidenceSha256: chain.sha256, settlementJournalSha256: settlements.record.sha256, playground: Object.freeze({ descriptorSha256: playgroundIdentity.descriptorSha256, finalLocksSha256: playgroundIdentity.finalLocksSha256, instanceId: playgroundIdentity.instanceId, maximumLiveNotes: playgroundIdentity.maximumLiveNotes, releaseRootId: playgroundIdentity.releaseRootId, releaseBootstrapSha256: playgroundIdentity.releaseBootstrapSha256, evidenceSha256: playground.sha256 }), settlementCount: settlements.record.value.entries.length, actionCounts: settlements.actionCounts, soak: Object.freeze({ firstBlockTime: settlements.firstBlockTime, lastBlockTime: settlements.lastBlockTime, elapsedSeconds: settlements.elapsedSeconds, minimumElapsedSeconds: MIN_SOAK_SECONDS, tipHeight: chain.tip.height, minimumConfirmations: MIN_CONFIRMATIONS }), terminal: Object.freeze({ stateSha256: settlements.terminalStateSha256, outpoint: settlements.terminalOutpoint }), rawSettlementTransactionIds: settlements.txids, publication: 'allowed-only-after-this-derived-record' });
    const artifact = atomicPrivateJson(join(options.outputDirectory, 'q09-chipnet-rollout-validation.json'), result); return Object.freeze({ ...result, artifactSha256: artifact.sha256 });
  } catch (error) {
    atomicPrivateJson(join(options.outputDirectory, 'failure.json'), { schema: V2_Q09_RESULT_SCHEMA, status: 'failed-preserved', q09Qualified: false, at: now(), message: error instanceof Error ? error.message : String(error) }); throw error;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try { process.stdout.write(`${JSON.stringify(await runV2Q09ChipnetSoak(parseV2Q09Arguments(process.argv.slice(2))), null, 2)}\n`); } catch (error) { process.stderr.write(`Q-09 Chipnet rollout validation failed: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; }
}
