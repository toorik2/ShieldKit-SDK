#!/usr/bin/env node

/*
 * Q-07's lifecycle corpus is an intentionally non-chain artifact.  It has
 * real V2 note encryption, trees, state commitments, packets, and SDC2
 * transaction contexts, but no transaction ids, blocks, or chain claims.
 *
 * Its one purpose is to make the exact 100,000-action lifecycle replayable
 * without smuggling a fixture run into a chain-qualification result.
 */
import { createHash } from 'node:crypto';
import {
  chmodSync, closeSync, constants, existsSync, fsyncSync, fstatSync, lstatSync,
  mkdirSync, openSync, readSync, realpathSync, renameSync, unlinkSync, writeSync,
} from 'node:fs';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { encodeTokenPrefix } from '@bitauth/libauth';

import { canonicalJson, parseStrictJson } from '../packages/profile/load.mjs';
import {
  constructDirectV2Output, deriveDirectV2Address, deriveDirectV2Nullifier,
  recoverDirectV2Output, validateDirectV2OutputConstruction,
} from '../packages/action/v2/notes.mjs';
import { encodeActionPacket, decodeActionPacket, ACTION_PACKET_BYTES } from '../packages/action/v2/packet.mjs';
import { encodeStateNftCommitment } from '../packages/action/v2/state.mjs';
import {
  encodeDirectV2TransactionContext, hashDirectV2TransactionContext,
  validateDirectV2RoleTopology, DIRECT_V2_ROLE_CODES,
} from '../packages/action/v2/context.mjs';
import {
  hashIndexedNullifierLeaf, hashIndexedNullifierNode,
} from '../packages/action/v2/poseidon.mjs';
import { createIndexedNullifierQualificationStore } from '../packages/action/v2/tree-qualification-store.mjs';
import {
  Q07_NOTE_TREE_DEPTH, appendQ07Note, auditQ07NoteAccumulator,
  createQ07NoteAccumulator,
} from '../packages/pool/v2/qualification/q07-note-accumulator.mjs';

export const V2_Q07_LIFECYCLE_CORPUS_SCHEMA =
  'shieldkit-v2-direct/q07-non-chain-lifecycle-corpus/v1';
export const V2_Q07_LIFECYCLE_CORPUS_VERSION = '1';
export const V2_Q07_LIFECYCLE_ACTION_COUNT = 100_000;
export const V2_Q07_LIFECYCLE_CARRIER_COUNT = 10;
export const V2_Q07_LIFECYCLE_FILENAME = 'q07-non-chain-lifecycle.ndjson';
export const V2_Q07_LIFECYCLE_TRANSCRIPT_DOMAIN =
  'ShieldKit/V2/Q07/non-chain-lifecycle/action-transcript/v1\0';
export const V2_Q07_LIFECYCLE_CONTEXT_CLASS =
  'deterministic-non-chain-fixture-context-not-chain-authenticated';
export const V2_Q07_LIFECYCLE_ACCOUNT_CLASSIFICATION =
  'explicit-public-deterministic-qualification-only-non-operational';

const ACTION_COUNTS = Object.freeze({ deposit: '1', transfer: '99998', withdrawal: '1' });
const ZERO_32 = '0'.repeat(64);
const HEX_32 = /^[0-9a-f]{64}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
const MAX_LINE_BYTES = 20 * 1024;
const READ_CHUNK_BYTES = 64 * 1024;
const PROFILE_ID = digest('profile-id').toString('hex');
const INSTANCE_ID = digest('instance-id').toString('hex');
const NETWORK_ID = '2';
const DENOMINATION_SATS = '10000000';
// The corpus intentionally keeps one live note while binding the frozen
// production/profile capacity of 32 slots.
const MAXIMUM_LIVE_NOTES = '32';
const FIXTURE_CARRIER_SATS = 1000n;
const FIXTURE_BINDING_SATS = 1000n;
const FIXTURE_STATE_BASE_SATS = 1000n;
const FIXTURE_CHANGE_SATS = 2000n;
const FIXTURE_FEE_SATS = 100n;
const ACCOUNT_SECRETS = Object.freeze({
  // These deliberately public scalars are not wallet material.
  spendSecret: fr(7n),
  incomingViewSecret: fr(8n),
});

export class V2Q07LifecycleCorpusError extends Error {
  constructor(message) { super(message); this.name = 'V2Q07LifecycleCorpusError'; }
}
const fail = (message) => { throw new V2Q07LifecycleCorpusError(message); };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const rawHash = (bytes) => createHash('sha256').update(bytes).digest();
const stateContext = Object.freeze({ denominationSats: DENOMINATION_SATS });

function digest(label) {
  return createHash('sha256').update(`ShieldKit/V2/Q07/non-chain-lifecycle/${label}`, 'utf8').digest();
}
function fr(value) { return value.toString(16).padStart(64, '0'); }
function exactKeys(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown properties`);
  return value;
}
function hex32(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) fail(`${label} must be lowercase 32-byte hex`);
  return value;
}
function decimal(value, label) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) fail(`${label} must be a canonical unsigned decimal string`);
  return value;
}
function decimalEquals(value, expected, label) {
  decimal(value, label); if (value !== String(expected)) fail(`${label} has an unexpected value`); return value;
}
function canonicalLine(value) { return canonicalJson(value); }
function writeFully(fd, bytes) {
  let offset = 0;
  while (offset < bytes.length) { const written = writeSync(fd, bytes, offset, bytes.length - offset); if (written <= 0) fail('corpus write made no progress'); offset += written; }
}
function canonicalPath(path, label) {
  if (typeof path !== 'string' || !isAbsolute(path) || resolve(path) !== path) fail(`${label} must be an absolute normalized path`);
  return path;
}
function assertPrivateDirectory(path, { create = false } = {}) {
  canonicalPath(path, 'outputDirectory'); if (create) mkdirSync(path, { recursive: true, mode: 0o700 });
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700 || (typeof process.getuid === 'function' && stat.uid !== process.getuid())) fail(`outputDirectory must be a direct user-owned mode-0700 directory: ${path}`);
  if (realpathSync(path) !== path) fail('outputDirectory cannot traverse a symlink');
}
function outputPath(directory, filename) {
  if (typeof filename !== 'string' || filename.length === 0 || basename(filename) !== filename) fail('filename must be one direct filename');
  const path = join(directory, filename); if (dirname(path) !== directory) fail('output path escapes outputDirectory'); return path;
}
function assertSingleLinkFile(fd, pathname, label) {
  const stat = fstatSync(fd);
  if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600 || (typeof process.getuid === 'function' && stat.uid !== process.getuid())) fail(`${label} must be a single-link user-owned mode-0600 regular file`);
  const named = lstatSync(pathname);
  if (named.isSymbolicLink() || named.dev !== stat.dev || named.ino !== stat.ino || named.nlink !== 1 || realpathSync(pathname) !== pathname) fail(`${label} path changed, is linked, or traverses a symlink`);
  return stat;
}
function noFollowRead(pathname, label) {
  try { return openSync(pathname, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)); }
  catch (error) { fail(`${label} cannot be opened as a direct regular file: ${error instanceof Error ? error.message : String(error)}`); }
}

/** The exact publicly disclosed account is part of the corpus header. */
export function createQ07LifecycleQualificationAccount() {
  const address = deriveDirectV2Address({
    networkId: Number(NETWORK_ID), profileId: PROFILE_ID, instanceId: INSTANCE_ID,
    spendSecret: ACCOUNT_SECRETS.spendSecret, incomingViewSecret: ACCOUNT_SECRETS.incomingViewSecret,
  });
  return Object.freeze({
    address,
    credentialsClassification: V2_Q07_LIFECYCLE_ACCOUNT_CLASSIFICATION,
    incomingViewSecret: ACCOUNT_SECRETS.incomingViewSecret,
    spendSecret: ACCOUNT_SECRETS.spendSecret,
  });
}
function cryptoAccount(account) {
  return Object.freeze({
    address: account.address,
    incomingViewSecret: account.incomingViewSecret,
    spendSecret: account.spendSecret,
  });
}

function createHeaderForActionCount(actionCount) {
  if (!Number.isSafeInteger(actionCount) || actionCount < 3 || actionCount > V2_Q07_LIFECYCLE_ACTION_COUNT) fail('actionCount is invalid');
  const actionCounts = actionCount === V2_Q07_LIFECYCLE_ACTION_COUNT
    ? ACTION_COUNTS
    : Object.freeze({ deposit: '1', transfer: String(actionCount - 2), withdrawal: '1' });
  return Object.freeze({
    actionCount: String(actionCount), actionCounts, account: createQ07LifecycleQualificationAccount(),
    carrierCount: String(V2_Q07_LIFECYCLE_CARRIER_COUNT), contextClass: V2_Q07_LIFECYCLE_CONTEXT_CLASS,
    denominationSats: DENOMINATION_SATS, instanceId: INSTANCE_ID, maximumLiveNotes: MAXIMUM_LIVE_NOTES,
    networkId: NETWORK_ID, profileId: PROFILE_ID, schema: V2_Q07_LIFECYCLE_CORPUS_SCHEMA,
    type: 'header', version: V2_Q07_LIFECYCLE_CORPUS_VERSION,
  });
}
/** Public qualification header: the only public shape is the exact 100,000-action history. */
export function createQ07LifecycleHeader() {
  return createHeaderForActionCount(V2_Q07_LIFECYCLE_ACTION_COUNT);
}

function verifyHeader(value, { expectedActionCount = undefined } = {}) {
  exactKeys(value, ['actionCount', 'actionCounts', 'account', 'carrierCount', 'contextClass', 'denominationSats', 'instanceId', 'maximumLiveNotes', 'networkId', 'profileId', 'schema', 'type', 'version'], 'header');
  if (value.schema !== V2_Q07_LIFECYCLE_CORPUS_SCHEMA || value.type !== 'header' || value.version !== V2_Q07_LIFECYCLE_CORPUS_VERSION) fail('header schema identity is invalid');
  const count = Number(decimal(value.actionCount, 'header.actionCount'));
  if (!Number.isSafeInteger(count) || count < 3 || count > V2_Q07_LIFECYCLE_ACTION_COUNT || String(count) !== value.actionCount) fail('header.actionCount is invalid');
  if (expectedActionCount !== undefined && count !== expectedActionCount) fail('header action count does not match required shape');
  const expectedCounts = count === V2_Q07_LIFECYCLE_ACTION_COUNT ? ACTION_COUNTS : { deposit: '1', transfer: String(count - 2), withdrawal: '1' };
  exactKeys(value.actionCounts, ['deposit', 'transfer', 'withdrawal'], 'header.actionCounts');
  for (const key of Object.keys(expectedCounts)) decimalEquals(value.actionCounts[key], expectedCounts[key], `header.actionCounts.${key}`);
  decimalEquals(value.carrierCount, V2_Q07_LIFECYCLE_CARRIER_COUNT, 'header.carrierCount'); decimalEquals(value.networkId, NETWORK_ID, 'header.networkId');
  decimalEquals(value.denominationSats, DENOMINATION_SATS, 'header.denominationSats'); decimalEquals(value.maximumLiveNotes, MAXIMUM_LIVE_NOTES, 'header.maximumLiveNotes');
  hex32(value.profileId, 'header.profileId'); hex32(value.instanceId, 'header.instanceId');
  if (value.profileId !== PROFILE_ID || value.instanceId !== INSTANCE_ID || value.contextClass !== V2_Q07_LIFECYCLE_CONTEXT_CLASS) fail('header identity/classification mismatch');
  exactKeys(value.account, ['address', 'credentialsClassification', 'incomingViewSecret', 'spendSecret'], 'header.account');
  if (value.account.credentialsClassification !== V2_Q07_LIFECYCLE_ACCOUNT_CLASSIFICATION) fail('header account classification is invalid');
  const expectedAccount = createQ07LifecycleQualificationAccount();
  if (canonicalLine(value.account) !== canonicalLine(expectedAccount)) fail('header account is not the exact public qualification account');
  return Object.freeze({ header: value, actionCount: count, account: expectedAccount });
}

function rngFor(ordinal) {
  let cursor = 0;
  return Object.freeze({ bytes(length) {
    const result = Buffer.alloc(length); let offset = 0;
    while (offset < length) { const chunk = digest(`output-rng/${ordinal}/${cursor}`); cursor += 1; chunk.copy(result, offset, 0, Math.min(chunk.length, length - offset)); offset += Math.min(chunk.length, length - offset); }
    return result;
  } });
}
/*
 * The production context commits hashes of literal CashToken prefix bytes.
 * `INSTANCE_ID` is the state NFT category in protocol/wire order; libauth's model expects display
 * order and reverses during serialisation (same rule as rolling-bundle.mjs).
 */
function fixtureStateTokenPrefix(state, stateCategory = INSTANCE_ID) {
  hex32(stateCategory, 'state NFT category');
  const commitment = encodeStateNftCommitment(state, stateContext);
  return Buffer.from(encodeTokenPrefix({
    category: Uint8Array.from(Buffer.from(stateCategory, 'hex').reverse()),
    amount: 0n,
    nft: { capability: 'mutable', commitment: Uint8Array.from(commitment) },
  }));
}
function fixtureBytecode() { return Buffer.from([0x51]); }
function fixtureWithdrawalBytecode() { return Buffer.from([0x51]); }
function fixtureHash(label, ordinal, index) { return digest(`context/${label}/${ordinal}/${index}`).toString('hex'); }
function assertFixtureValueConservation(inputs, outputs) {
  const inputTotal = inputs.reduce((total, input) => total + BigInt(input.valueSats), 0n);
  const outputTotal = outputs.reduce((total, output) => total + BigInt(output.valueSats), 0n);
  if (inputTotal !== outputTotal + FIXTURE_FEE_SATS) fail('internal non-chain SDC2 fixture values do not conserve exactly one fixed fee');
}
function fixtureContext({ kind, ordinal, preState, postState, stateCategory = INSTANCE_ID }) {
  const carrierCount = V2_Q07_LIFECYCLE_CARRIER_COUNT; const inputs = []; const outputs = [];
  const preReserve = BigInt(preState.reserveSats); const postReserve = BigInt(postState.reserveSats);
  const reserveDelta = postReserve > preReserve ? postReserve - preReserve : 0n;
  const fundingSats = reserveDelta + FIXTURE_CHANGE_SATS + FIXTURE_FEE_SATS;
  for (let index = 0; index < carrierCount; index += 1) inputs.push({ role: { kind: 'verifier', ordinal: String(index) }, outpointTransactionHash: fixtureHash('carrier-input', ordinal, index), outpointIndex: String(index), sequence: '0', valueSats: FIXTURE_CARRIER_SATS.toString(), lockingBytecode: fixtureBytecode(), tokenPrefix: Buffer.alloc(0) });
  inputs.push({ role: { kind: 'binding', ordinal: '0' }, outpointTransactionHash: fixtureHash('binding-input', ordinal, 0), outpointIndex: '0', sequence: '0', valueSats: FIXTURE_BINDING_SATS.toString(), lockingBytecode: fixtureBytecode(), tokenPrefix: Buffer.alloc(0) });
  inputs.push({ role: { kind: 'state', ordinal: '0' }, outpointTransactionHash: fixtureHash('state-input', ordinal, 0), outpointIndex: '0', sequence: '0', valueSats: (FIXTURE_STATE_BASE_SATS + preReserve).toString(), lockingBytecode: fixtureBytecode(), tokenPrefix: fixtureStateTokenPrefix(preState, stateCategory) });
  inputs.push({ role: { kind: 'funding', ordinal: '0' }, outpointTransactionHash: fixtureHash('funding-input', ordinal, 0), outpointIndex: '0', sequence: '0', valueSats: fundingSats.toString(), lockingBytecode: fixtureBytecode(), tokenPrefix: Buffer.alloc(0) });
  outputs.push({ role: { kind: 'state', ordinal: '0' }, valueSats: (FIXTURE_STATE_BASE_SATS + postReserve).toString(), lockingBytecode: fixtureBytecode(), tokenPrefix: fixtureStateTokenPrefix(postState, stateCategory) });
  for (let index = 0; index < carrierCount; index += 1) outputs.push({ role: { kind: 'verifier', ordinal: String(index) }, valueSats: FIXTURE_CARRIER_SATS.toString(), lockingBytecode: fixtureBytecode(), tokenPrefix: Buffer.alloc(0) });
  outputs.push({ role: { kind: 'binding', ordinal: '0' }, valueSats: FIXTURE_BINDING_SATS.toString(), lockingBytecode: fixtureBytecode(), tokenPrefix: Buffer.alloc(0) });
  if (kind === 'withdrawal') outputs.push({ role: { kind: 'withdrawal', ordinal: '0' }, valueSats: DENOMINATION_SATS, lockingBytecode: fixtureWithdrawalBytecode(), tokenPrefix: Buffer.alloc(0) });
  outputs.push({ role: { kind: 'change', ordinal: '0' }, valueSats: FIXTURE_CHANGE_SATS.toString(), lockingBytecode: fixtureBytecode(), tokenPrefix: Buffer.alloc(0) });
  assertFixtureValueConservation(inputs, outputs);
  const value = Object.freeze({ networkId: Number(NETWORK_ID), kind, profileId: PROFILE_ID, instanceId: INSTANCE_ID, transactionVersion: '2', locktime: '0', preActionSequence: preState.actionSequence, postActionSequence: postState.actionSequence, inputs, outputs });
  const bytes = encodeDirectV2TransactionContext(value, { carrierCount });
  validateDirectV2RoleTopology(value, carrierCount);
  return Object.freeze({ bytes, hash: hashDirectV2TransactionContext(value, { carrierCount }).toString('hex') });
}
function expectedFixtureContextFromPacket(packet, ordinal) {
  return fixtureContext({ kind: packet.kind, ordinal, preState: packet.preState, postState: packet.postState });
}
/** Explicit test-only seam for asserting state-NFT category binding. */
export function createQ07LifecycleFixtureContextForTest({ kind, ordinal, preState, postState, stateCategory = INSTANCE_ID } = {}) {
  if (!Number.isSafeInteger(ordinal) || ordinal < 1 || ordinal > 64) fail('test-only context ordinal must be an integer from 1 through 64');
  return fixtureContext({ kind, ordinal, preState, postState, stateCategory });
}
/**
 * Decode the fixed-width production SDC2 preimage sufficiently to enforce its
 * header, action sequence and PF10 role layout. The subsequent byte-for-byte
 * comparison to `fixtureContext` binds every field hash (including the real
 * pre/post CashToken prefixes) through the production encoder.
 */
export function decodeQ07LifecycleContext(bytes) {
  if (!(bytes instanceof Uint8Array)) fail('context must be bytes');
  const value = Buffer.from(bytes);
  if (!value.subarray(0, 4).equals(Buffer.from('SDC2', 'ascii'))) fail('context magic is invalid');
  const kind = ({ 1: 'deposit', 2: 'transfer', 3: 'withdrawal' })[value[5]];
  if (value[4] !== Number(NETWORK_ID) || kind === undefined || value.readUInt16LE(6) !== 0) fail('context network, kind, or flags are invalid');
  const inputCount = value.readUInt16LE(80); const outputCount = value.readUInt16LE(82);
  const expectedInputs = V2_Q07_LIFECYCLE_CARRIER_COUNT + 3;
  const expectedOutputs = V2_Q07_LIFECYCLE_CARRIER_COUNT + (kind === 'withdrawal' ? 4 : 3);
  const expectedLength = 100 + (inputCount * 116) + (outputCount * 76);
  if (inputCount !== expectedInputs || outputCount !== expectedOutputs || value.length !== expectedLength) fail('context does not have the PF10 role topology length');
  if (value.subarray(8, 40).toString('hex') !== PROFILE_ID || value.subarray(40, 72).toString('hex') !== INSTANCE_ID || value.readUInt32LE(72) !== 2 || value.readUInt32LE(76) !== 0) fail('context header identity is invalid');
  const preActionSequence = value.readBigUInt64LE(84); const postActionSequence = value.readBigUInt64LE(92);
  if (postActionSequence !== preActionSequence + 1n) fail('context action sequence does not increment');
  const expectedInputRoles = [
    ...Array.from({ length: V2_Q07_LIFECYCLE_CARRIER_COUNT }, (_, ordinal) => [DIRECT_V2_ROLE_CODES.verifier, ordinal]),
    [DIRECT_V2_ROLE_CODES.binding, 0], [DIRECT_V2_ROLE_CODES.state, 0], [DIRECT_V2_ROLE_CODES.funding, 0],
  ];
  const expectedOutputRoles = [
    [DIRECT_V2_ROLE_CODES.state, 0],
    ...Array.from({ length: V2_Q07_LIFECYCLE_CARRIER_COUNT }, (_, ordinal) => [DIRECT_V2_ROLE_CODES.verifier, ordinal]),
    [DIRECT_V2_ROLE_CODES.binding, 0],
    ...(kind === 'withdrawal' ? [[DIRECT_V2_ROLE_CODES.withdrawal, 0]] : []),
    [DIRECT_V2_ROLE_CODES.change, 0],
  ];
  const inputValueSats = [];
  for (let index = 0; index < expectedInputRoles.length; index += 1) {
    const offset = 100 + (index * 116); const [role, ordinal] = expectedInputRoles[index];
    if (value[offset] !== role || value[offset + 1] !== ordinal || value[offset + 2] !== 0 || value[offset + 3] !== 0) fail(`context input role ${index} is invalid`);
    inputValueSats.push(value.readBigUInt64LE(offset + 44));
  }
  const outputBase = 100 + (inputCount * 116);
  const outputValueSats = [];
  for (let index = 0; index < expectedOutputRoles.length; index += 1) {
    const offset = outputBase + (index * 76); const [role, ordinal] = expectedOutputRoles[index];
    if (value[offset] !== role || value[offset + 1] !== ordinal || value[offset + 2] !== 0 || value[offset + 3] !== 0) fail(`context output role ${index} is invalid`);
    outputValueSats.push(value.readBigUInt64LE(offset + 4));
  }
  return Object.freeze({ kind, preActionSequence: preActionSequence.toString(), postActionSequence: postActionSequence.toString(), inputCount: String(inputCount), outputCount: String(outputCount), inputValueSats: Object.freeze(inputValueSats), outputValueSats: Object.freeze(outputValueSats), sha256: sha256(value) });
}
function assertDecodedFixtureEconomics(context, packet) {
  const inputs = context.inputValueSats; const outputs = context.outputValueSats;
  const carrierCount = V2_Q07_LIFECYCLE_CARRIER_COUNT;
  const preReserve = BigInt(packet.preState.reserveSats); const postReserve = BigInt(packet.postState.reserveSats);
  const expectedFunding = (postReserve > preReserve ? postReserve - preReserve : 0n) + FIXTURE_CHANGE_SATS + FIXTURE_FEE_SATS;
  if (inputs.length !== carrierCount + 3 || outputs.length !== carrierCount + (packet.kind === 'withdrawal' ? 4 : 3)) fail('context economics has unexpected role counts');
  for (let index = 0; index < carrierCount; index += 1) if (inputs[index] !== FIXTURE_CARRIER_SATS || outputs[index + 1] !== FIXTURE_CARRIER_SATS) fail('context carrier value is invalid');
  if (inputs[carrierCount] !== FIXTURE_BINDING_SATS || outputs[carrierCount + 1] !== FIXTURE_BINDING_SATS || inputs[carrierCount + 1] !== FIXTURE_STATE_BASE_SATS + preReserve || outputs[0] !== FIXTURE_STATE_BASE_SATS + postReserve || inputs[carrierCount + 2] !== expectedFunding || outputs.at(-1) !== FIXTURE_CHANGE_SATS) fail('context state, binding, funding, or change value is invalid');
  if (packet.kind === 'withdrawal' && outputs[carrierCount + 2] !== BigInt(DENOMINATION_SATS)) fail('context withdrawal payout value is invalid');
  const inputTotal = inputs.reduce((total, amount) => total + amount, 0n); const outputTotal = outputs.reduce((total, amount) => total + amount, 0n);
  if (inputTotal !== outputTotal + FIXTURE_FEE_SATS) fail('context inputs and outputs do not conserve the fixed fee');
}
function rootHex(value) { return value.toString(16).padStart(64, '0'); }
function initialState(noteAccumulator, nullifierStore) {
  return Object.freeze({ profileId: PROFILE_ID, noteRoot: auditQ07NoteAccumulator(noteAccumulator).rootHex, nullifierRoot: rootHex(nullifierStore.snapshot().root), noteCount: '0', nullifierCount: '0', maximumLiveNotes: MAXIMUM_LIVE_NOTES, reserveSats: '0', actionSequence: '0' });
}
function successorState(preState, { kind, noteRoot, nullifierRoot }) {
  const notes = BigInt(preState.noteCount); const nullifiers = BigInt(preState.nullifierCount); const sequence = BigInt(preState.actionSequence) + 1n;
  return Object.freeze({ profileId: PROFILE_ID, noteRoot, nullifierRoot, noteCount: String(notes + (kind === 'withdrawal' ? 0n : 1n)), nullifierCount: String(nullifiers + (kind === 'deposit' ? 0n : 1n)), maximumLiveNotes: MAXIMUM_LIVE_NOTES, reserveSats: kind === 'deposit' ? DENOMINATION_SATS : kind === 'withdrawal' ? '0' : preState.reserveSats, actionSequence: String(sequence) });
}
function actionKind(ordinal, actionCount) { return ordinal === 1 ? 'deposit' : ordinal === actionCount ? 'withdrawal' : 'transfer'; }
function actionPayload(record) { const { actionTranscriptSha256: _ignored, ...payload } = record; return payload; }
function transcriptInitial(header) { return rawHash(Buffer.concat([Buffer.from(V2_Q07_LIFECYCLE_TRANSCRIPT_DOMAIN, 'utf8'), Buffer.from(canonicalLine(header), 'utf8')])); }
function transcriptNext(previous, record) { return rawHash(Buffer.concat([Buffer.from(V2_Q07_LIFECYCLE_TRANSCRIPT_DOMAIN, 'utf8'), previous, Buffer.from(canonicalLine(actionPayload(record)), 'utf8')])); }
function recordFor({ ordinal, kind, packet, context, priorTranscript }) {
  const record = { contextHex: context.bytes.toString('hex'), contextSha256: sha256(context.bytes), kind, ordinal: String(ordinal), packetHex: packet.toString('hex'), packetSha256: sha256(packet), schema: V2_Q07_LIFECYCLE_CORPUS_SCHEMA, type: 'action' };
  const next = transcriptNext(priorTranscript, record);
  return Object.freeze({ ...record, actionTranscriptSha256: next.toString('hex') });
}

/** Test-only reduced seam. It is deliberately not accepted by the CLI. */
export function writeQ07LifecycleCorpusForTest({ outputDirectory, actionCount, filename = V2_Q07_LIFECYCLE_FILENAME } = {}) {
  if (!Number.isSafeInteger(actionCount) || actionCount < 3 || actionCount > 64) fail('test-only actionCount must be an integer from 3 through 64');
  return writeCorpus({ outputDirectory, filename, actionCount, testOnly: true });
}
export function writeQ07LifecycleCorpus({ outputDirectory, filename = V2_Q07_LIFECYCLE_FILENAME } = {}) {
  return writeCorpus({ outputDirectory, filename, actionCount: V2_Q07_LIFECYCLE_ACTION_COUNT, testOnly: false });
}
function writeCorpus({ outputDirectory, filename, actionCount, testOnly }) {
  canonicalPath(outputDirectory, 'outputDirectory'); assertPrivateDirectory(outputDirectory, { create: true });
  const finalPath = outputPath(outputDirectory, filename); if (existsSync(finalPath)) fail(`refusing to overwrite existing corpus: ${finalPath}`);
  const temporaryPath = outputPath(outputDirectory, `.${filename}.${process.pid}.${Date.now()}.tmp`);
  let fd; let completed = false;
  try {
    fd = openSync(temporaryPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600); chmodSync(temporaryPath, 0o600); assertSingleLinkFile(fd, temporaryPath, 'temporary corpus');
    const header = createHeaderForActionCount(actionCount);
    const body = createHash('sha256'); const all = createHash('sha256'); const emitBody = (line) => { const bytes = Buffer.from(`${canonicalLine(line)}\n`, 'utf8'); writeFully(fd, bytes); body.update(bytes); all.update(bytes); };
    emitBody(header);
    let transcript = transcriptInitial(header); const account = createQ07LifecycleQualificationAccount(); const noteAccumulator = createQ07NoteAccumulator();
    const nullifierStore = createIndexedNullifierQualificationStore({ depth: Q07_NOTE_TREE_DEPTH, maximumInserts: actionCount - 1, hashLeaf: hashIndexedNullifierLeaf, hashNode: hashIndexedNullifierNode });
    let state = initialState(noteAccumulator, nullifierStore); let live = null;
    for (let ordinal = 1; ordinal <= actionCount; ordinal += 1) {
      const kind = actionKind(ordinal, actionCount); let output = null; let nullifierRoot = state.nullifierRoot;
      if (kind !== 'withdrawal') {
        output = constructDirectV2Output({ address: account.address, postActionSequence: String(ordinal), rng: rngFor(ordinal) });
        validateDirectV2OutputConstruction({ address: account.address, postActionSequence: String(ordinal), output });
      }
      let publicNullifier = ZERO_32;
      if (kind !== 'deposit') {
        if (live === null) fail('internal lifecycle lost its only live note');
        publicNullifier = deriveDirectV2Nullifier({ profileId: PROFILE_ID, instanceId: INSTANCE_ID, spendSecret: account.spendSecret, rho: live.rho, noteCommitment: live.noteCommitment }).toString(16).padStart(64, '0');
        const inserted = nullifierStore.insert(BigInt(`0x${publicNullifier}`)); nullifierRoot = rootHex(inserted.root);
      }
      const appended = output === null ? null : appendQ07Note(noteAccumulator, Buffer.from(output.public.outputNoteLeaf, 'hex'));
      const postState = successorState(state, { kind, noteRoot: appended === null ? state.noteRoot : appended.postRoot.toString('hex'), nullifierRoot });
      const context = fixtureContext({ kind, ordinal, preState: state, postState });
      const packet = encodeActionPacket({ kind, networkId: Number(NETWORK_ID), instanceId: INSTANCE_ID, preState: state, postState, publicNullifier, outputNoteLeaf: output === null ? ZERO_32 : output.public.outputNoteLeaf, encryptedRecord: output === null ? Buffer.alloc(128) : output.public.encryptedRecord, withdrawalLockingBytecodeHash: kind === 'withdrawal' ? sha256(fixtureWithdrawalBytecode()) : ZERO_32, transactionContextHash: context.hash }, stateContext);
      const decoded = decodeActionPacket(packet, stateContext); if (decoded.transactionContextHash !== context.hash || packet.length !== ACTION_PACKET_BYTES) fail('internal packet/context construction mismatch');
      const record = recordFor({ ordinal, kind, packet, context, priorTranscript: transcript }); transcript = Buffer.from(record.actionTranscriptSha256, 'hex'); emitBody(record);
      if (output !== null) live = recoverDirectV2Output({ account: cryptoAccount(account), outputNoteLeaf: output.public.outputNoteLeaf, encryptedRecord: output.public.encryptedRecord }); else live = null;
      state = postState;
    }
    const terminalStateHex = encodeStateNftCommitment(state, stateContext).toString('hex');
    const end = Object.freeze({ actionCount: String(actionCount), actionCounts: header.actionCounts, actionTranscriptSha256: transcript.toString('hex'), bodySha256: body.digest('hex'), recordCount: String(actionCount + 2), schema: V2_Q07_LIFECYCLE_CORPUS_SCHEMA, terminalStateHex, terminalStateSha256: sha256(Buffer.from(terminalStateHex, 'hex')), type: 'end', version: V2_Q07_LIFECYCLE_CORPUS_VERSION });
    const endBytes = Buffer.from(`${canonicalLine(end)}\n`, 'utf8'); writeFully(fd, endBytes); all.update(endBytes); fsyncSync(fd); assertSingleLinkFile(fd, temporaryPath, 'temporary corpus'); closeSync(fd); fd = undefined;
    if (existsSync(finalPath)) fail(`refusing to overwrite existing corpus: ${finalPath}`); renameSync(temporaryPath, finalPath); const dirfd = openSync(outputDirectory, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0) | (constants.O_NOFOLLOW ?? 0)); try { fsyncSync(dirfd); } finally { closeSync(dirfd); }
    completed = true;
    return Object.freeze({ schema: V2_Q07_LIFECYCLE_CORPUS_SCHEMA, path: finalPath, actionCount: String(actionCount), fileSha256: all.digest('hex'), bodySha256: end.bodySha256, terminalStateHex, chainAuthenticated: false, q07Qualified: false, qualification: testOnly ? 'test-only-nonqualifying' : 'non-chain-corpus-generated-not-q07-qualified' });
  } finally { if (fd !== undefined) closeSync(fd); if (!completed && existsSync(temporaryPath)) unlinkSync(temporaryPath); }
}

function parseCanonicalLine(bytes, lineNumber) {
  if (bytes.length === 0 || bytes.length > MAX_LINE_BYTES) fail(`corpus line ${lineNumber} is empty or oversized`);
  let value; try { value = parseStrictJson(bytes); } catch (error) { fail(`corpus line ${lineNumber} is not strict JSON: ${error instanceof Error ? error.message : String(error)}`); }
  let text; try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); } catch { fail(`corpus line ${lineNumber} is not UTF-8`); }
  if (canonicalLine(value) !== text) fail(`corpus line ${lineNumber} is not canonical JSON`); return value;
}
function verifyAction(record, ordinal, actionCount, header, state, live, noteAccumulator, nullifierStore, transcript) {
  exactKeys(record, ['actionTranscriptSha256', 'contextHex', 'contextSha256', 'kind', 'ordinal', 'packetHex', 'packetSha256', 'schema', 'type'], `action ${ordinal}`);
  if (record.schema !== V2_Q07_LIFECYCLE_CORPUS_SCHEMA || record.type !== 'action') fail(`action ${ordinal} schema identity is invalid`);
  decimalEquals(record.ordinal, ordinal, `action ${ordinal}.ordinal`); const expectedKind = actionKind(ordinal, actionCount); if (record.kind !== expectedKind) fail(`action ${ordinal}.kind is invalid`);
  const packetHex = typeof record.packetHex === 'string' && /^[0-9a-f]{1104}$/.test(record.packetHex) ? record.packetHex : fail(`action ${ordinal}.packetHex is invalid`);
  const contextHex = typeof record.contextHex === 'string' && /^[0-9a-f]*$/.test(record.contextHex) && record.contextHex.length % 2 === 0 ? record.contextHex : fail(`action ${ordinal}.contextHex is invalid`);
  hex32(record.packetSha256, `action ${ordinal}.packetSha256`); hex32(record.contextSha256, `action ${ordinal}.contextSha256`); hex32(record.actionTranscriptSha256, `action ${ordinal}.actionTranscriptSha256`);
  const packet = Buffer.from(packetHex, 'hex'); const context = Buffer.from(contextHex, 'hex'); if (sha256(packet) !== record.packetSha256 || sha256(context) !== record.contextSha256) fail(`action ${ordinal} byte hash mismatch`);
  let decoded; try { decoded = decodeActionPacket(packet, stateContext); } catch (error) { fail(`action ${ordinal} packet is invalid: ${error instanceof Error ? error.message : String(error)}`); }
  if (decoded.kind !== expectedKind || decoded.networkId !== Number(NETWORK_ID) || decoded.instanceId !== INSTANCE_ID) fail(`action ${ordinal} packet identity mismatch`);
  if (encodeStateNftCommitment(decoded.preState, stateContext).toString('hex') !== encodeStateNftCommitment(state, stateContext).toString('hex')) fail(`action ${ordinal} pre-state discontinuity`);
  const decodedContext = decodeQ07LifecycleContext(context);
  if (decodedContext.kind !== decoded.kind || decodedContext.preActionSequence !== decoded.preState.actionSequence || decodedContext.postActionSequence !== decoded.postState.actionSequence) fail(`action ${ordinal} decoded context does not bind the packet action boundary`);
  assertDecodedFixtureEconomics(decodedContext, decoded);
  const expectedContext = expectedFixtureContextFromPacket(decoded, ordinal);
  if (!context.equals(expectedContext.bytes)) fail(`action ${ordinal} context does not match the production SDC2 fixture topology`);
  if (expectedContext.hash !== record.contextSha256 || decoded.transactionContextHash !== record.contextSha256) fail(`action ${ordinal} transaction context binding mismatch`);
  if (expectedKind === 'withdrawal' && decoded.withdrawalLockingBytecodeHash !== sha256(fixtureWithdrawalBytecode())) fail(`action ${ordinal} withdrawal locking-bytecode hash is not bound to the SDC2 payout`);
  let nextNullifierRoot = state.nullifierRoot;
  if (expectedKind !== 'deposit') {
    if (live === null) fail(`action ${ordinal} has no live note to spend`);
    const expectedNullifier = deriveDirectV2Nullifier({ profileId: PROFILE_ID, instanceId: INSTANCE_ID, spendSecret: header.account.spendSecret, rho: live.rho, noteCommitment: live.noteCommitment }).toString(16).padStart(64, '0');
    if (decoded.publicNullifier !== expectedNullifier) fail(`action ${ordinal} nullifier does not spend the live note`);
    const inserted = nullifierStore.insert(BigInt(`0x${expectedNullifier}`)); nextNullifierRoot = rootHex(inserted.root);
  } else if (decoded.publicNullifier !== ZERO_32) fail(`action ${ordinal} deposit nullifier is nonzero`);
  let nextLive = null; let nextNoteRoot = state.noteRoot;
  if (expectedKind !== 'withdrawal') {
    const recovered = recoverDirectV2Output({ account: cryptoAccount(header.account), outputNoteLeaf: decoded.outputNoteLeaf, encryptedRecord: decoded.encryptedRecord });
    const appended = appendQ07Note(noteAccumulator, Buffer.from(decoded.outputNoteLeaf, 'hex')); nextNoteRoot = appended.postRoot.toString('hex'); nextLive = recovered;
  } else if (decoded.outputNoteLeaf !== ZERO_32 || !decoded.encryptedRecord.equals(Buffer.alloc(128))) fail(`action ${ordinal} withdrawal has an output record`);
  const expectedState = successorState(state, { kind: expectedKind, noteRoot: nextNoteRoot, nullifierRoot: nextNullifierRoot });
  if (encodeStateNftCommitment(decoded.postState, stateContext).toString('hex') !== encodeStateNftCommitment(expectedState, stateContext).toString('hex')) fail(`action ${ordinal} post-state transition mismatch`);
  const expectedTranscript = transcriptNext(transcript, record).toString('hex'); if (record.actionTranscriptSha256 !== expectedTranscript) fail(`action ${ordinal} transcript mismatch`);
  return Object.freeze({ state: expectedState, live: nextLive, transcript: Buffer.from(expectedTranscript, 'hex') });
}

/** Verify only the full 100,000-action non-chain corpus. */
export function verifyQ07LifecycleCorpus({ path } = {}) {
  return verifyCorpus({ path, expectedActionCount: V2_Q07_LIFECYCLE_ACTION_COUNT, testOnly: false });
}
/** Explicit test-only reduced verification seam; never used by the CLI. */
export function verifyQ07LifecycleCorpusForTest({ path, actionCount } = {}) {
  if (!Number.isSafeInteger(actionCount) || actionCount < 3 || actionCount > 64) fail('test-only actionCount must be an integer from 3 through 64');
  return verifyCorpus({ path, expectedActionCount: actionCount, testOnly: true });
}
function verifyCorpus({ path, expectedActionCount, testOnly }) {
  canonicalPath(path, 'path'); const fd = noFollowRead(path, 'corpus');
  try {
    const initial = assertSingleLinkFile(fd, path, 'corpus'); const all = createHash('sha256'); const body = createHash('sha256'); let carry = Buffer.alloc(0); let lineNumber = 0; let header = null; let actionCount = 0; let transcript = null; let state = null; let live = null; let noteAccumulator = null; let nullifierStore = null; let ended = false; let end = null;
    const processLine = (line, raw) => {
      lineNumber += 1; const value = parseCanonicalLine(line, lineNumber); all.update(raw);
      if (lineNumber === 1) {
        const verified = verifyHeader(value, { expectedActionCount }); header = verified.header; actionCount = verified.actionCount; transcript = transcriptInitial(header); noteAccumulator = createQ07NoteAccumulator(); nullifierStore = createIndexedNullifierQualificationStore({ depth: Q07_NOTE_TREE_DEPTH, maximumInserts: actionCount - 1, hashLeaf: hashIndexedNullifierLeaf, hashNode: hashIndexedNullifierNode }); state = initialState(noteAccumulator, nullifierStore); body.update(raw); return;
      }
      if (ended) fail('corpus contains records after end');
      if (lineNumber <= actionCount + 1) { body.update(raw); const result = verifyAction(value, lineNumber - 1, actionCount, header, state, live, noteAccumulator, nullifierStore, transcript); state = result.state; live = result.live; transcript = result.transcript; return; }
      if (lineNumber !== actionCount + 2) fail('corpus has an extra line'); end = value; ended = true;
    };
    const chunk = Buffer.alloc(READ_CHUNK_BYTES);
    for (;;) { const bytes = readSync(fd, chunk, 0, chunk.length, null); if (bytes === 0) break; const combined = carry.length === 0 ? chunk.subarray(0, bytes) : Buffer.concat([carry, chunk.subarray(0, bytes)]); let start = 0; for (;;) { const newline = combined.indexOf(0x0a, start); if (newline === -1) break; processLine(combined.subarray(start, newline), combined.subarray(start, newline + 1)); start = newline + 1; } carry = Buffer.from(combined.subarray(start)); if (carry.length > MAX_LINE_BYTES) fail('corpus has an oversized unterminated line'); }
    if (carry.length !== 0) fail('corpus must end with one newline per record'); if (!ended || end === null) fail('corpus is truncated before end');
    exactKeys(end, ['actionCount', 'actionCounts', 'actionTranscriptSha256', 'bodySha256', 'recordCount', 'schema', 'terminalStateHex', 'terminalStateSha256', 'type', 'version'], 'end');
    if (end.schema !== V2_Q07_LIFECYCLE_CORPUS_SCHEMA || end.type !== 'end' || end.version !== V2_Q07_LIFECYCLE_CORPUS_VERSION) fail('end schema identity is invalid'); decimalEquals(end.actionCount, actionCount, 'end.actionCount'); decimalEquals(end.recordCount, actionCount + 2, 'end.recordCount');
    if (canonicalLine(end.actionCounts) !== canonicalLine(header.actionCounts)) fail('end action counts mismatch'); hex32(end.actionTranscriptSha256, 'end.actionTranscriptSha256'); hex32(end.bodySha256, 'end.bodySha256'); if (end.actionTranscriptSha256 !== transcript.toString('hex') || end.bodySha256 !== body.digest('hex')) fail('end transcript or body hash mismatch');
    const terminal = encodeStateNftCommitment(state, stateContext).toString('hex'); if (end.terminalStateHex !== terminal || end.terminalStateSha256 !== sha256(Buffer.from(terminal, 'hex'))) fail('end terminal state mismatch');
    const final = fstatSync(fd); if (final.dev !== initial.dev || final.ino !== initial.ino || final.size !== initial.size || final.mtimeMs !== initial.mtimeMs || final.ctimeMs !== initial.ctimeMs || final.nlink !== 1) fail('corpus changed while being read');
    return Object.freeze({ schema: V2_Q07_LIFECYCLE_CORPUS_SCHEMA, path, actionCount: String(actionCount), fileSha256: all.digest('hex'), bodySha256: end.bodySha256, terminalStateHex: terminal, actionTranscriptSha256: transcript.toString('hex'), chainAuthenticated: false, q07Qualified: false, qualification: testOnly ? 'test-only-nonqualifying' : 'non-chain-corpus-verified-not-q07-qualified' });
  } finally { closeSync(fd); }
}

export function parseQ07LifecycleCorpusArguments(argv, cwd = process.cwd()) {
  if (!Array.isArray(argv) || argv.length !== 2 || !['--output-directory', '--verify'].includes(argv[0]) || typeof argv[1] !== 'string' || argv[1].length === 0 || argv[1].startsWith('--')) fail('usage: v2-q07-lifecycle-corpus.mjs --output-directory <new-mode-0700-directory> | --verify <full-corpus.ndjson>');
  return argv[0] === '--output-directory'
    ? Object.freeze({ mode: 'generate', outputDirectory: resolve(cwd, argv[1]) })
    : Object.freeze({ mode: 'verify', path: resolve(cwd, argv[1]) });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try { const args = parseQ07LifecycleCorpusArguments(process.argv.slice(2)); const result = args.mode === 'generate' ? writeQ07LifecycleCorpus(args) : verifyQ07LifecycleCorpus(args); process.stdout.write(`${canonicalLine(result)}\n`); }
  catch (error) { process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; }
}
