#!/usr/bin/env node

/**
 * Deterministic development-only durability qualification. This intentionally
 * uses the production V2 SQLite store and delivery journal; no in-memory store
 * substitute, chain transport, or network broadcast is involved.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { encodeTransaction } from '@bitauth/libauth';

import { encodeDirectV2Address } from '../packages/action/v2/address.mjs';
import { deriveDirectV2Address } from '../packages/action/v2/notes.mjs';
import { decodeActionPacket, encodeActionPacket } from '../packages/action/v2/packet.mjs';
import {
  decodeStateNftCommitment,
  encodeStateNftCommitment,
} from '../packages/action/v2/state.mjs';
import { createDirectV2PoolModel } from '../packages/action/v2/transition.mjs';
import {
  V2_ACTION_LIFECYCLE_CRASH_STAGES,
  V2ActionLifecycleCrash,
} from '../packages/kit/v2/action-lifecycle.mjs';
import {
  openV2DeliveryJournal,
  V2_DELIVERY_JOURNAL_CRASH_STAGES,
  V2DeliveryJournalCrash,
} from '../packages/kit/v2/delivery-journal.mjs';
import { parseV2RawTransaction } from '../packages/kit/v2/transaction-policy.mjs';
import {
  openV2DirectStore,
  V2_OPERATION_ABANDON_CRASH_STAGES,
  V2_OPERATION_CONFLICT_CRASH_STAGES,
  V2_OPERATION_CREATE_CRASH_STAGES,
  V2_OPERATION_PREPARE_CRASH_STAGES,
  V2_OPERATION_REBASE_CRASH_STAGES,
  V2_OPERATION_SETTLE_CRASH_STAGES,
  V2StoreCrashInjection,
} from '../packages/pool/v2/store.mjs';

const CASES = 10_000;
const SEED = 'shieldkit-v2-crash-qualification-20260729';
const b = (byte, length = 32) => Buffer.alloc(length, byte);
const fr = (value) => Buffer.from(value.toString(16).padStart(64, '0'), 'hex');
const PROFILE_ID = b(0x11);
const INSTANCE_ID = b(0x22);
const RUNTIME_MATERIALS_SHA256 = b(0x33);
const NETWORK_ID = 2;
const DENOMINATION_SATS = '10000000';
const CARRIER_COUNT = 7;
const STATE_CONTEXT = Object.freeze({ denominationSats: DENOMINATION_SATS });
const FUNDING_PUBLIC_KEY = Buffer.from(
  '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  'hex',
);
const CHANGE_LOCK = Buffer.from(
  '76a914111111111111111111111111111111111111111188ac',
  'hex',
);
const WITHDRAWAL_LOCK = Buffer.from(
  '76a914222222222222222222222222222222222222222288ac',
  'hex',
);
const FUNDING_LOCK = p2pkhForPublicKey(FUNDING_PUBLIC_KEY);
const SHIELD_ADDRESS = encodeDirectV2Address(deriveDirectV2Address({
  networkId: NETWORK_ID,
  profileId: PROFILE_ID.toString('hex'),
  instanceId: INSTANCE_ID.toString('hex'),
  spendSecret: fr(3n).toString('hex'),
  incomingViewSecret: fr(4n).toString('hex'),
}));

export class V2CrashQualificationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2CrashQualificationError';
  }
}

function fail(message) {
  throw new V2CrashQualificationError(message);
}

export function parseV2CrashQualificationArguments(argv, cwd = process.cwd()) {
  if (!Array.isArray(argv) || argv.length !== 2 || argv[0] !== '--output') {
    fail('usage: v2-crash-qualification.mjs --output <new-evidence.json>');
  }
  const value = argv[1];
  if (typeof value !== 'string' || value.length === 0 || value.startsWith('--')) {
    fail('--output must name a new evidence file');
  }
  return Object.freeze({ output: resolve(cwd, value) });
}

const EXTERNAL_CRASH_WORKER = fileURLToPath(new URL('./v2-crash-qualification-worker.mjs', import.meta.url));

function parseExternalWorkerOutput(result, mode) {
  if (result.error) fail(`external crash worker ${mode} could not start: ${result.error.message}`);
  const line = result.stdout.trim();
  if (line.length === 0) fail(`external crash worker ${mode} emitted no result`);
  let value;
  try {
    value = JSON.parse(line);
  } catch {
    fail(`external crash worker ${mode} emitted malformed JSON`);
  }
  if (value === null || typeof value !== 'object' || value.mode !== mode) {
    fail(`external crash worker ${mode} emitted an unexpected result`);
  }
  return value;
}

function runExternalWorker(mode, path) {
  return spawnSync(process.execPath, [EXTERNAL_CRASH_WORKER, '--mode', mode, '--path', path], {
    encoding: 'utf8',
    timeout: 15_000,
    maxBuffer: 64 * 1024,
  });
}

/**
 * Small production-representative process-crash corpus. Every writer is a
 * separate child which is actually SIGKILLed; every assertion is made by a
 * fresh verifier process. This intentionally stays separate from the exact
 * 10,000-case in-process campaign below.
 */
export function runV2ExternalCrashCorpus({ directory } = {}) {
  if (
    typeof directory !== 'string' ||
    directory.length === 0 ||
    resolve(directory) !== directory
  ) {
    fail('external crash corpus requires an absolute normalized directory');
  }
  const observed = lstatSync(directory, { throwIfNoEntry: false });
  if (
    observed === undefined ||
    !observed.isDirectory() ||
    observed.isSymbolicLink() ||
    realpathSync(directory) !== directory
  ) {
    fail('external crash corpus requires a directory');
  }
  if (readdirSync(directory).length !== 0) {
    fail('external crash corpus requires a new empty directory');
  }
  chmodSync(directory, 0o700);
  const cases = Object.freeze([
    ['sqlite-create-before', 'verify-sqlite-create-before'],
    ['sqlite-create-after', 'verify-sqlite-create-after'],
    ['sqlite-reserve-before', 'verify-sqlite-reserve-before'],
    ['sqlite-reserve-after', 'verify-sqlite-reserve-after'],
    ['delivery-submit-before', 'verify-delivery-submit-before'],
    ['delivery-submit-after', 'verify-delivery-submit-after'],
  ]);
  const results = [];
  for (const [crashMode, verifyMode] of cases) {
    const path = join(directory, `${crashMode}.sqlite`);
    if (existsSync(path)) fail(`external crash corpus path already exists: ${path}`);
    const crashed = runExternalWorker(crashMode, path);
    const crashSignal = crashed.signal;
    const crashOutput = parseExternalWorkerOutput(crashed, crashMode);
    if (crashed.status !== null || crashSignal !== 'SIGKILL' || crashOutput.event !== 'ready-to-kill') {
      fail(`external crash worker ${crashMode} did not terminate with SIGKILL`);
    }
    const verified = runExternalWorker(verifyMode, path);
    const verifyOutput = parseExternalWorkerOutput(verified, verifyMode);
    if (verified.status !== 0 || verified.signal !== null || verifyOutput.event !== 'verified') {
      fail(`external crash verifier ${verifyMode} did not complete cleanly`);
    }
    results.push(Object.freeze({ crashMode, verifyMode, signal: crashSignal, invariants: verifyOutput.invariants }));
  }
  return Object.freeze({
    schema: 'shieldkit-v2-direct-external-crash-corpus-v1',
    cases: results,
    limitations: Object.freeze([
      'SIGKILL exercises process termination at selected post-transaction boundaries, not power-loss or filesystem-fault semantics.',
      'The corpus has no network transport, live-chain confirmation, or multi-device synchronization.',
    ]),
  });
}

function p2pkhForPublicKey(publicKey) {
  const sha = createHash('sha256').update(publicKey).digest();
  const hash = createHash('ripemd160').update(sha).digest();
  return Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), hash, Buffer.from([0x88, 0xac])]);
}

function initialStore() {
  const model = createDirectV2PoolModel({
    profileId: PROFILE_ID.toString('hex'),
    maximumLiveNotes: '210000000',
    denominationSats: DENOMINATION_SATS,
  });
  return Object.freeze({
    profileId: PROFILE_ID,
    instanceId: INSTANCE_ID,
    networkId: NETWORK_ID,
    denominationSats: DENOMINATION_SATS,
    carrierCount: CARRIER_COUNT,
    runtimeMaterialsSha256: RUNTIME_MATERIALS_SHA256,
    state: encodeStateNftCommitment(model.state, STATE_CONTEXT),
    outpoint: { txid: b(0x44), vout: 0 },
    actionSequence: 0,
    height: 100,
    blockHash: b(0x55),
  });
}

function canonical(value) {
  return {
    state: Buffer.from(value.state),
    outpoint: { txid: Buffer.from(value.outpoint.txid), vout: value.outpoint.vout },
    actionSequence: value.actionSequence,
    height: value.height,
    blockHash: Buffer.from(value.blockHash),
  };
}

function fundingSource(tag, valueSats) {
  const value = Buffer.alloc(8);
  value.writeBigUInt64LE(BigInt(valueSats));
  const rawSourceTransaction = Buffer.concat([
    Buffer.from('0200000001', 'hex'),
    createHash('sha256').update(tag).digest(),
    Buffer.from('0000000000ffffffff01', 'hex'),
    value,
    Buffer.from([FUNDING_LOCK.length]),
    FUNDING_LOCK,
    Buffer.alloc(4),
  ]);
  const parsed = parseV2RawTransaction(rawSourceTransaction.toString('hex'));
  return Object.freeze({
    rawSourceTransaction,
    txid: Buffer.from(parsed.txid, 'hex'),
    vout: 0,
    valueSats,
    lockingBytecode: FUNDING_LOCK,
    compressedPublicKey: FUNDING_PUBLIC_KEY,
  });
}

function operationRequest(store, operationId, kind, { selectedNoteId = null, crashAt = null } = {}) {
  const expected = store.canonicalState();
  const fundingValueSats = kind === 'deposit' ? '10200000' : '200000';
  return {
    operationId,
    kind,
    expectedState: expected.state,
    expectedOutpoint: expected.outpoint,
    expectedActionSequence: expected.actionSequence,
    expectedHeight: expected.height,
    expectedBlockHash: expected.blockHash,
    runtimeMaterialsSha256: RUNTIME_MATERIALS_SHA256,
    actionMaterialSha256: b(0xa6),
    privateActionRecordSha256: b(0xa7),
    intent: {
      kind,
      target: kind === 'withdrawal'
        ? { type: 'withdrawal_locking_bytecode', bytes: WITHDRAWAL_LOCK }
        : { type: 'shield_address', bytes: SHIELD_ADDRESS },
      selectedNoteId,
      funding: fundingSource(operationId, fundingValueSats),
      changeLockingBytecode: CHANGE_LOCK,
      feePolicy: { feeRateSatsPerByte: '1', maximumFeeSats: '100000' },
    },
    packet: null,
    proof: null,
    unsignedTx: null,
    signedTx: null,
    localVmEvidence: null,
    crashAt,
  };
}

function nullifierFor(noteId) {
  const result = createHash('sha256').update(`V2CrashQualification/${noteId}`).digest();
  result[0] = 0;
  return result;
}

function putReservedTransferInputs(store, request, operationId) {
  const noteId = request.intent.selectedNoteId;
  const recordId = `${operationId}-record`;
  store.putEncryptedRecord({ recordId, record: b(0x70, 128) });
  store.putOwnedNote({
    noteId,
    recordId,
    noteIndex: createHash('sha256').update(noteId).digest().readUInt32LE(0),
    nullifier: nullifierFor(noteId),
  });
  store.putFundingUtxo({
    txid: request.intent.funding.txid,
    vout: request.intent.funding.vout,
    valueSats: request.intent.funding.valueSats,
  });
}

function assertCanonicalUnchanged(store, expected, invariants) {
  assert.deepEqual(canonical(store.canonicalState()), canonical(expected));
  invariants.noCanonicalCommitBeforeAuthenticatedConfirmation += 1;
}

function assertReservations(store, request, operationId, expected, invariants) {
  const noteId = request.intent.selectedNoteId;
  const note = noteId === null ? null : store.ownedNote(noteId);
  const utxo = store.fundingUtxo({
    txid: request.intent.funding.txid,
    vout: request.intent.funding.vout,
  });
  assert.equal(note === null ? null : note.reservationOperationId, expected ? operationId : null);
  assert.equal(utxo.reservationOperationId, expected ? operationId : null);
  invariants.noLostOrDuplicatedReservations += 1;
}

function packetFixture(store, expected, kind, marker) {
  const preState = decodeStateNftCommitment(expected.state, STATE_CONTEXT);
  const publicNullifier = kind === 'deposit' ? Buffer.alloc(32) : fr(BigInt(marker + 1));
  const outputNoteLeaf = kind === 'withdrawal' ? Buffer.alloc(32) : fr(BigInt(marker + 2));
  const derived = store.derivePacketPostState({ kind, publicNullifier, outputNoteLeaf });
  return Buffer.from(encodeActionPacket({
    kind,
    networkId: NETWORK_ID,
    instanceId: INSTANCE_ID.toString('hex'),
    preState,
    postState: derived.state,
    publicNullifier: publicNullifier.toString('hex'),
    outputNoteLeaf: outputNoteLeaf.toString('hex'),
    encryptedRecord: kind === 'withdrawal' ? Buffer.alloc(128) : b((marker + 7) & 0xff, 128),
    withdrawalLockingBytecodeHash: kind === 'withdrawal'
      ? createHash('sha256').update(WITHDRAWAL_LOCK).digest('hex')
      : Buffer.alloc(32).toString('hex'),
    transactionContextHash: b((marker + 4) & 0xff).toString('hex'),
  }, STATE_CONTEXT));
}

function operationTransactions(expected, operation, packet) {
  const decoded = decodeActionPacket(packet, STATE_CONTEXT);
  const fundingValue = BigInt(operation.intent.funding.valueSats);
  const parentHash = Uint8Array.from(expected.outpoint.txid);
  const fundingHash = Uint8Array.from(operation.intent.funding.txid);
  const bindingUnlock = Buffer.concat([Buffer.from('4d2802', 'hex'), packet, Buffer.from([0x01, 0x51])]);
  const fundingUnlock = Buffer.concat([Buffer.from([0x41]), Buffer.alloc(64), Buffer.from([0x61, 0x21]), FUNDING_PUBLIC_KEY]);
  const inputs = (signed) => [
    ...Array.from({ length: CARRIER_COUNT + 2 }, (_, index) => ({
      outpointTransactionHash: parentHash,
      outpointIndex: index === CARRIER_COUNT + 1 ? 0 : index + 1,
      sequenceNumber: 0,
      unlockingBytecode: index === CARRIER_COUNT ? bindingUnlock : Uint8Array.of(0x51),
    })),
    {
      outpointTransactionHash: fundingHash,
      outpointIndex: operation.intent.funding.vout,
      sequenceNumber: 0,
      unlockingBytecode: signed ? fundingUnlock : new Uint8Array(),
    },
  ];
  const outputs = (changeValue) => [
    {
      valueSatoshis: BigInt(decoded.postState.reserveSats) + 1_000n,
      lockingBytecode: Uint8Array.of(0x51),
      token: {
        category: Uint8Array.from(Buffer.from(INSTANCE_ID).reverse()), amount: 0n,
        nft: { capability: 'mutable', commitment: encodeStateNftCommitment(decoded.postState, STATE_CONTEXT) },
      },
    },
    ...Array.from({ length: CARRIER_COUNT }, (_, index) => ({ valueSatoshis: 1_000n + BigInt(index), lockingBytecode: Uint8Array.of(0x51) })),
    { valueSatoshis: 2_000n, lockingBytecode: Uint8Array.of(0x51) },
    { valueSatoshis: changeValue, lockingBytecode: CHANGE_LOCK },
  ];
  const encode = (signed, changeValue) => Buffer.from(encodeTransaction({ version: 2, inputs: inputs(signed), outputs: outputs(changeValue), locktime: 0 }));
  const fee = BigInt(encode(true, 546n).length);
  const change = fundingValue - BigInt(DENOMINATION_SATS) - fee;
  assert.ok(change >= 546n);
  return Object.freeze({ unsigned: encode(false, change), signed: encode(true, change) });
}

function enterProving(store, operationId, marker) {
  const expected = store.canonicalState();
  const request = operationRequest(store, operationId, 'deposit');
  const operation = store.createOperation(request);
  store.putFundingUtxo({ txid: operation.intent.funding.txid, vout: 0, valueSats: operation.intent.funding.valueSats });
  store.reserveResources({ operationId, noteId: null, utxoTxid: operation.intent.funding.txid, utxoVout: 0, crashAt: null });
  store.transitionOperation({ operationId, to: 'tip_synced', reason: null });
  store.transitionOperation({ operationId, to: 'proving', reason: null });
  const packet = packetFixture(store, expected, 'deposit', marker);
  const transactions = operationTransactions(expected, operation, packet);
  return Object.freeze({ request, operation, packet, transactions });
}

function persistProofArtifacts(store, operationId, prepared, marker) {
  store.updateOperationArtifacts({
    operationId,
    packet: prepared.packet,
    proof: b((marker + 1) & 0xff),
    unsignedTx: prepared.transactions.unsigned,
    signedTx: null,
    localVmEvidence: null,
  });
}

function enterProved(store, operationId, marker) {
  const prepared = enterProving(store, operationId, marker);
  persistProofArtifacts(store, operationId, prepared, marker);
  store.transitionOperation({ operationId, to: 'proved', reason: null });
  return prepared;
}

function addSignedArtifacts(store, operationId, proved) {
  const operation = store.operation(operationId);
  store.updateOperationArtifacts({
    operationId,
    packet: proved.packet,
    proof: operation.proof,
    unsignedTx: proved.transactions.unsigned,
    signedTx: proved.transactions.signed,
    localVmEvidence: b(0x99),
  });
}

function confirmedArgs(store, operationId, expected, prepared, marker, crashAt) {
  const operation = store.operation(operationId);
  const packet = decodeActionPacket(operation.packet, STATE_CONTEXT);
  const signed = parseV2RawTransaction(operation.signedTx.toString('hex'));
  const successorTxid = Buffer.from(signed.txid, 'hex');
  return {
    operationId,
    expected: {
      state: expected.state,
      outpoint: expected.outpoint,
      actionSequence: expected.actionSequence,
    },
    next: {
      state: encodeStateNftCommitment(packet.postState, STATE_CONTEXT),
      outpoint: { txid: successorTxid, vout: 0 },
      actionSequence: expected.actionSequence + 1,
      height: expected.height + 1,
      blockHash: b(0x90 + (marker & 0x0f)),
    },
    records: [{ recordId: `${operationId}-output`, record: Buffer.from(packet.encryptedRecord) }],
    notes: {
      insert: [{
        noteId: `${operationId}-note`,
        recordId: `${operationId}-output`,
        noteIndex: Number(packet.preState.noteCount),
        nullifier: nullifierFor(`${operationId}-note`),
      }],
      spend: [],
    },
    funding: {
      spend: { txid: prepared.operation.intent.funding.txid, vout: 0 },
      change: [{
        txid: successorTxid,
        vout: CARRIER_COUNT + 2,
        valueSats: signed.outputs[CARRIER_COUNT + 2].valueSatoshis.toString(),
      }],
    },
    undo: b((marker + 9) & 0xff, 5),
    crashAt,
  };
}

function assertNotBroadcastableUnsigned(store, operationId, invariants) {
  assert.throws(() => store.transitionOperation({ operationId, to: 'broadcast', reason: null }));
  invariants.noUnsignedBroadcastableState += 1;
}

function deliveryIdentity(operationId) {
  const digest = (label) => createHash('sha256').update(`${SEED}/${operationId}/${label}`).digest('hex');
  return Object.freeze({
    operationId,
    txid: digest('txid'),
    metadataHash: digest('metadata'),
    evidenceHash: digest('evidence'),
    carrierCount: CARRIER_COUNT,
    roleLayoutHash: digest('roles'),
  });
}

function deliveryRawTransactionSha256(operationId) {
  return createHash('sha256').update(`${SEED}/${operationId}/raw-transaction`).digest('hex');
}

const STORE_CASES = Object.freeze([
  ...V2_OPERATION_CREATE_CRASH_STAGES.map((stage) => ({ family: 'store', stage })),
  ...V2_OPERATION_PREPARE_CRASH_STAGES.map((stage) => ({ family: 'prepare', stage })),
  ...['reservation.after_note', 'reservation.after_utxo', 'reservation.before_commit']
    .map((stage) => ({ family: 'reservation', stage })),
  ...V2_OPERATION_ABANDON_CRASH_STAGES.map((stage) => ({ family: 'abandon', stage })),
  ...V2_OPERATION_CONFLICT_CRASH_STAGES.map((stage) => ({ family: 'conflict', stage })),
  ...V2_OPERATION_REBASE_CRASH_STAGES.map((stage) => ({ family: 'rebase', stage })),
  { family: 'confirmed', stage: 'confirmed.before_commit' },
]);
const CASES_BY_STAGE = Object.freeze([
  ...STORE_CASES,
  ...V2_ACTION_LIFECYCLE_CRASH_STAGES.map((stage) => ({ family: 'lifecycle', stage })),
  ...V2_DELIVERY_JOURNAL_CRASH_STAGES.map((stage) => ({ family: 'delivery', stage })),
]);

function throwLifecycle(stage) {
  throw new V2ActionLifecycleCrash(stage);
}

function runStoreCrashCase(store, path, entry, id, invariants) {
  const expected = store.canonicalState();
  if (entry.family === 'store') {
    const request = operationRequest(store, id, 'deposit', { crashAt: entry.stage });
    assert.throws(() => store.createOperation(request), V2StoreCrashInjection);
    store.close();
    store = openV2DirectStore({ path, ...initialStore() });
    assert.throws(() => store.operation(id));
    assertCanonicalUnchanged(store, expected, invariants);
    return store;
  }
  if (entry.family === 'confirmed') {
    const deposit = enterProved(store, id, 0x40);
    addSignedArtifacts(store, id, deposit);
    store.transitionOperation({ operationId: id, to: 'signed', reason: null });
    store.transitionOperation({ operationId: id, to: 'broadcast', reason: null });
    const args = confirmedArgs(store, id, expected, deposit, 0x40, entry.stage);
    assert.throws(() => store.applyConfirmed(args), V2StoreCrashInjection);
    store.close();
    store = openV2DirectStore({ path, ...initialStore() });
    assert.equal(store.operation(id).journalState, 'broadcast');
    assertCanonicalUnchanged(store, expected, invariants);
    const confirmed = confirmedArgs(store, id, expected, deposit, 0x40, null);
    store.applyConfirmed(confirmed);
    assert.notDeepEqual(canonical(store.canonicalState()), canonical(expected));
    invariants.authenticatedConfirmationCommitsCanonicalState += 1;
    return store;
  }
  const request = operationRequest(store, id, 'transfer', { selectedNoteId: `${id}-note`, crashAt: entry.stage });
  putReservedTransferInputs(store, request, id);
  if (entry.family === 'prepare') {
    assert.throws(() => store.prepareAction(request), V2StoreCrashInjection);
    store.close();
    store = openV2DirectStore({ path, ...initialStore() });
    assert.throws(() => store.operation(id));
    assertReservations(store, request, id, false, invariants);
    assertCanonicalUnchanged(store, expected, invariants);
    return store;
  }
  const operation = store.createOperation({ ...request, crashAt: null });
  if (entry.family === 'reservation') {
    assert.throws(() => store.reserveResources({ operationId: id, noteId: request.intent.selectedNoteId, utxoTxid: operation.intent.funding.txid, utxoVout: 0, crashAt: entry.stage }), V2StoreCrashInjection);
    store.close();
    store = openV2DirectStore({ path, ...initialStore() });
    assert.equal(store.operation(id).journalState, 'draft');
    assertReservations(store, request, id, false, invariants);
    assertCanonicalUnchanged(store, expected, invariants);
    return store;
  }
  store.reserveResources({ operationId: id, noteId: request.intent.selectedNoteId, utxoTxid: operation.intent.funding.txid, utxoVout: 0, crashAt: null });
  if (entry.family === 'abandon') {
    assert.throws(() => store.abandonOperation({ operationId: id, reason: 'qualification', crashAt: entry.stage }), V2StoreCrashInjection);
    store.close();
    store = openV2DirectStore({ path, ...initialStore() });
    assert.equal(store.operation(id).journalState, 'funding_selected');
    assertReservations(store, request, id, true, invariants);
    assertCanonicalUnchanged(store, expected, invariants);
    return store;
  }
  if (entry.family === 'conflict') {
    assert.throws(() => store.recordConflictAndMaybeRetry({ operationId: id, reason: 'qualification', crashAt: entry.stage }), V2StoreCrashInjection);
  } else {
    store.recordConflictAndMaybeRetry({ operationId: id, reason: 'qualification', crashAt: null });
  }
  if (entry.family === 'conflict') {
    store.close();
    store = openV2DirectStore({ path, ...initialStore() });
    assert.equal(store.operation(id).journalState, 'funding_selected');
    assertReservations(store, request, id, true, invariants);
    assertCanonicalUnchanged(store, expected, invariants);
    return store;
  }
  // A non-crashing conflict enters needs_reproof, then the real rebase hook is
  // injected before its transaction commits.
  assert.equal(store.operation(id).journalState, 'needs_reproof');
  assert.throws(() => store.rebaseOperation({
    operationId: id,
    expectedState: expected.state,
    expectedOutpoint: expected.outpoint,
    expectedActionSequence: expected.actionSequence,
    expectedHeight: expected.height,
    expectedBlockHash: expected.blockHash,
    // Rebase material is a fresh deterministic artifact. Keep both hashes
    // distinct from the draft request so this crash qualification exercises
    // V12's durable replacement fields rather than merely satisfying shape.
    actionMaterialSha256: b(0xa8),
    privateActionRecordSha256: b(0xa9),
    crashAt: entry.stage,
  }), V2StoreCrashInjection);
  store.close();
  store = openV2DirectStore({ path, ...initialStore() });
  assert.equal(store.operation(id).journalState, 'needs_reproof');
  assert.deepEqual(store.operation(id).actionMaterialSha256, b(0xa6));
  assert.deepEqual(store.operation(id).privateActionRecordSha256, b(0xa7));
  // Conflict recovery deliberately releases wallet resources before rebase;
  // the later rebase transaction reacquires both rows atomically. A crash
  // before that commit must preserve the release, not strand a reservation.
  assertReservations(store, request, id, false, invariants);
  assertCanonicalUnchanged(store, expected, invariants);
  return store;
}

function runLifecycleCase(store, path, stage, id, marker, invariants) {
  const canonicalBefore = store.canonicalState();
  let prepared;
  try {
    if (stage === 'prove.after_transition' || stage === 'prove.after_proof') {
      enterProving(store, id, marker);
      throwLifecycle(stage);
    }
    if (stage === 'prove.after_artifacts') {
      prepared = enterProving(store, id, marker);
      persistProofArtifacts(store, id, prepared, marker);
      throwLifecycle(stage);
    }
    prepared = enterProved(store, id, marker);
    if (stage === 'sign.after_refresh' || stage === 'sign.after_signature') throwLifecycle(stage);
    if (stage === 'prove.after_proved') throwLifecycle(stage);
    addSignedArtifacts(store, id, prepared);
    if (stage === 'sign.after_artifacts') throwLifecycle(stage);
    store.transitionOperation({ operationId: id, to: 'signed', reason: null });
    if (stage === 'sign.after_signed') throwLifecycle(stage);
  } catch (error) {
    assert.ok(error instanceof V2ActionLifecycleCrash && error.stage === stage);
  }
  store.close();
  store = openV2DirectStore({ path, ...initialStore() });
  const operation = store.operation(id);
  if (stage === 'prove.after_transition' || stage === 'prove.after_proof') {
    assert.equal(operation.journalState, 'proving');
    assert.equal(operation.packet, null);
    assertNotBroadcastableUnsigned(store, id, invariants);
  } else if (stage === 'prove.after_artifacts') {
    assert.equal(operation.journalState, 'proving');
    assert.ok(operation.packet !== null && operation.unsignedTx !== null);
    store.transitionOperation({ operationId: id, to: 'proved', reason: null });
    assertNotBroadcastableUnsigned(store, id, invariants);
  }
  else if (stage === 'sign.after_artifacts') {
    assert.equal(operation.journalState, 'proved');
    assertNotBroadcastableUnsigned(store, id, invariants);
    store.transitionOperation({ operationId: id, to: 'signed', reason: null });
  } else if (stage === 'sign.after_signed') assert.equal(operation.journalState, 'signed');
  else {
    assert.equal(operation.journalState, 'proved');
    assertNotBroadcastableUnsigned(store, id, invariants);
  }
  assertCanonicalUnchanged(store, canonicalBefore, invariants);
  invariants.exactResumabilityOrAbandon += 1;
  return store;
}

function runDeliveryCase(directory, stage, id, invariants) {
  const path = join(directory, `${id}.sqlite`);
  const identity = deliveryIdentity(id);
  const rawTransactionSha256 = deliveryRawTransactionSha256(id);
  let journal = openV2DeliveryJournal(path);
  if (stage === 'delivery.claim-or-create.after_insert') {
    journal.close();
    journal = openV2DeliveryJournal(path, { crashAt: stage });
    assert.throws(() => journal.claimOrCreate(identity), V2DeliveryJournalCrash);
    journal.close();
    journal = openV2DeliveryJournal(path);
    assert.equal(journal.record(id), null);
    journal.claimOrCreate(identity);
  } else if (stage === 'delivery.recovery-claim.after_update') {
    const firstClaim = journal.claimOrCreate(identity);
    journal.close();
    journal = openV2DeliveryJournal(path, { crashAt: stage });
    assert.throws(
      () => journal.claimExactResubmission({ identity, priorAttemptToken: firstClaim.attemptToken }),
      V2DeliveryJournalCrash,
    );
    journal.close();
    journal = openV2DeliveryJournal(path);
    const record = journal.record(id);
    assert.equal(record.state, 'attempted');
    assert.equal(record.attemptToken, firstClaim.attemptToken);
    journal.claimExactResubmission({ identity, priorAttemptToken: firstClaim.attemptToken });
  } else {
    const claim = journal.claimOrCreate(identity);
    if (stage === 'delivery.submitted.after_update') {
      journal.close(); journal = openV2DeliveryJournal(path, { crashAt: stage });
      assert.throws(() => journal.markSubmitted({ operationId: id, txid: identity.txid, attemptToken: claim.attemptToken, rawTransactionSha256 }), V2DeliveryJournalCrash);
      journal.close(); journal = openV2DeliveryJournal(path);
      assert.equal(journal.record(id).state, 'attempted');
      journal.markSubmitted({ operationId: id, txid: identity.txid, attemptToken: claim.attemptToken, rawTransactionSha256 });
    } else if (stage === 'delivery.indeterminate.after_update') {
      journal.close(); journal = openV2DeliveryJournal(path, { crashAt: stage });
      assert.throws(() => journal.markIndeterminate({ operationId: id, attemptToken: claim.attemptToken, reason: 'timeout' }), V2DeliveryJournalCrash);
      journal.close(); journal = openV2DeliveryJournal(path);
      assert.equal(journal.record(id).state, 'attempted');
      journal.markIndeterminate({ operationId: id, attemptToken: claim.attemptToken, reason: 'timeout' });
    } else if (stage === 'delivery.observed.after_update') {
      journal.close(); journal = openV2DeliveryJournal(path, { crashAt: stage });
      assert.throws(() => journal.reconcileObserved({ operationId: id, txid: identity.txid, rawTransactionSha256 }), V2DeliveryJournalCrash);
      journal.close(); journal = openV2DeliveryJournal(path);
      assert.equal(journal.record(id).state, 'attempted');
      journal.reconcileObserved({ operationId: id, txid: identity.txid, rawTransactionSha256 });
    } else {
      journal.markSubmitted({ operationId: id, txid: identity.txid, attemptToken: claim.attemptToken, rawTransactionSha256 });
      journal.close(); journal = openV2DeliveryJournal(path, { crashAt: stage });
      assert.throws(() => journal.markLocallyReconciled({ operationId: id, txid: identity.txid, rawTransactionSha256 }), V2DeliveryJournalCrash);
      journal.close(); journal = openV2DeliveryJournal(path);
      assert.equal(journal.record(id).state, 'submitted');
      journal.markLocallyReconciled({ operationId: id, txid: identity.txid, rawTransactionSha256 });
    }
  }
  const record = journal.record(id);
  assert.ok(record !== null);
  assert.throws(() => journal.claimOrCreate(identity));
  journal.close();
  journal = openV2DeliveryJournal(path);
  assert.equal(journal.record(id).state, record.state);
  journal.close();
  invariants.noDuplicateSend += 1;
  invariants.exactResumabilityOrAbandon += 1;
}

export function runV2CrashQualification({ output, cases = CASES } = {}) {
  if (!Number.isSafeInteger(cases) || cases < 1 || cases > CASES) {
    fail(`cases must be an integer from 1 through ${CASES}`);
  }
  if (typeof output !== 'string' || existsSync(output)) fail('output evidence path must not already exist');
  mkdirSync(join(tmpdir(), 'shieldkit-v2-crash-qualification'), { recursive: true, mode: 0o700 });
  const workspace = mkdtempSync(join(tmpdir(), 'shieldkit-v2-crash-qualification', 'run-'));
  const started = performance.now();
  const stageCounts = Object.fromEntries(CASES_BY_STAGE.map((entry) => [entry.stage, 0]));
  const invariants = {
    noCanonicalCommitBeforeAuthenticatedConfirmation: 0,
    authenticatedConfirmationCommitsCanonicalState: 0,
    noLostOrDuplicatedReservations: 0,
    noUnsignedBroadcastableState: 0,
    noDuplicateSend: 0,
    exactResumabilityOrAbandon: 0,
  };
  let store = null;
  let storePath = null;
  try {
    for (let index = 0; index < cases; index += 1) {
      const entry = CASES_BY_STAGE[index % CASES_BY_STAGE.length];
      const id = `q-${index}`;
      stageCounts[entry.stage] += 1;
      if (entry.family === 'delivery') {
        runDeliveryCase(join(workspace, 'delivery'), entry.stage, id, invariants);
        continue;
      }
      if (index % 40 === 0 || store === null) {
        store?.close();
        const storeDirectory = join(workspace, `store-${index}`);
        mkdirSync(storeDirectory, { recursive: true, mode: 0o700 });
        storePath = join(storeDirectory, 'private', 'pool.sqlite');
        store = openV2DirectStore({ path: storePath, ...initialStore() });
      }
      if (entry.family === 'lifecycle') {
        store = runLifecycleCase(store, storePath, entry.stage, id, index, invariants);
      } else {
        store = runStoreCrashCase(store, storePath, entry, id, invariants);
        invariants.exactResumabilityOrAbandon += 1;
      }
    }
  } finally {
    store?.close();
  }
  const elapsedMs = Math.round(performance.now() - started);
  const evidence = Object.freeze({
    schema: 'shieldkit-v2-direct-crash-qualification-v1',
    qualification: 'development-only',
    seed: SEED,
    cases,
    caseCountsByStage: stageCounts,
    invariantCounts: invariants,
    discrepancies: [],
    elapsedMs,
    storage: 'node:sqlite V2 direct store and V2 delivery journal reopened after every injected interruption',
    limitations: [
      'Deterministic in-process crash injection verifies transaction rollback and durable resume boundaries; it is not a SIGKILL, power-loss, or filesystem-fault campaign.',
      'No network transport, chain confirmation, proving, or funding signer is invoked; signed/unsigned transaction lifecycle storage is exercised with deterministic locally constructed BCH transactions.',
    ],
  });
  try {
    mkdirSync(dirname(output), { recursive: true, mode: 0o700 });
    writeFileSync(output, `${JSON.stringify(evidence, null, 2)}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
  return evidence;
}

if (process.argv[1]?.endsWith('v2-crash-qualification.mjs')) {
  try {
    const { output } = parseV2CrashQualificationArguments(process.argv.slice(2));
    const evidence = runV2CrashQualification({ output });
    process.stdout.write(`${JSON.stringify({ schema: 'shieldkit-v2-direct-crash-qualification-command-result-v1', output, cases: evidence.cases, elapsedMs: evidence.elapsedMs, discrepancies: evidence.discrepancies.length })}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
    process.exitCode = 1;
  }
}
