#!/usr/bin/env node

/*
 * Worker for the focused Q-06 external crash corpus. It deliberately does not
 * catch target-process termination: a parent must observe SIGKILL and invoke a
 * separate verifier process before accepting a case.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, writeSync } from 'node:fs';
import { dirname } from 'node:path';

import { openV2DeliveryJournal } from '../packages/kit/v2/delivery-journal.mjs';
import { parseV2RawTransaction } from '../packages/kit/v2/transaction-policy.mjs';
import { openV2DirectStore } from '../packages/pool/v2/store.mjs';
import { encodeDirectV2Address } from '../packages/action/v2/address.mjs';
import { deriveDirectV2Address } from '../packages/action/v2/notes.mjs';
import { createDirectV2PoolModel } from '../packages/action/v2/transition.mjs';
import { encodeStateNftCommitment } from '../packages/action/v2/state.mjs';

const PROFILE_ID = Buffer.alloc(32, 0x11);
const INSTANCE_ID = Buffer.alloc(32, 0x22);
const RUNTIME_MATERIALS_SHA256 = Buffer.alloc(32, 0x33);
const NETWORK_ID = 2;
const DENOMINATION_SATS = '10000000';
const STATE_CONTEXT = Object.freeze({ denominationSats: DENOMINATION_SATS });
const OPERATION_ID = 'external-crash-operation';
const NOTE_ID = 'external-crash-note';
const fr = (value) => Buffer.from(value.toString(16).padStart(64, '0'), 'hex');
const FUNDING_PUBLIC_KEY = Buffer.from(
  '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  'hex',
);
const SHIELD_ADDRESS = encodeDirectV2Address(deriveDirectV2Address({
  networkId: NETWORK_ID,
  profileId: PROFILE_ID.toString('hex'),
  instanceId: INSTANCE_ID.toString('hex'),
  spendSecret: fr(3n).toString('hex'),
  incomingViewSecret: fr(4n).toString('hex'),
}));

function fail(message) { throw new Error(`V2 external crash worker: ${message}`); }

function argumentsFor(argv) {
  if (argv.length !== 4 || argv[0] !== '--mode' || argv[2] !== '--path' || argv[1].startsWith('--') || argv[3].startsWith('--')) {
    fail('usage: v2-crash-qualification-worker.mjs --mode <mode> --path <sqlite-path>');
  }
  return Object.freeze({ mode: argv[1], path: argv[3] });
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
    carrierCount: 7,
    runtimeMaterialsSha256: RUNTIME_MATERIALS_SHA256,
    state: encodeStateNftCommitment(model.state, STATE_CONTEXT),
    outpoint: { txid: Buffer.alloc(32, 0x44), vout: 0 },
    actionSequence: 0,
    height: 100,
    blockHash: Buffer.alloc(32, 0x55),
  });
}

function canonical(store) {
  const value = store.canonicalState();
  return {
    state: Buffer.from(value.state),
    outpoint: { txid: Buffer.from(value.outpoint.txid), vout: value.outpoint.vout },
    actionSequence: value.actionSequence,
    height: value.height,
    blockHash: Buffer.from(value.blockHash),
  };
}

function fundingSource() {
  const valueSats = '10200000';
  const value = Buffer.alloc(8);
  value.writeBigUInt64LE(BigInt(valueSats));
  const lockingBytecode = p2pkhForPublicKey(FUNDING_PUBLIC_KEY);
  const rawSourceTransaction = Buffer.concat([
    Buffer.from('0200000001', 'hex'),
    createHash('sha256').update('external-crash-funding').digest(),
    Buffer.from('0000000000ffffffff01', 'hex'),
    value,
    Buffer.from([lockingBytecode.length]),
    lockingBytecode,
    Buffer.alloc(4),
  ]);
  const parsed = parseV2RawTransaction(rawSourceTransaction.toString('hex'));
  return Object.freeze({
    rawSourceTransaction,
    txid: Buffer.from(parsed.txid, 'hex'),
    vout: 0,
    valueSats,
    lockingBytecode,
    compressedPublicKey: FUNDING_PUBLIC_KEY,
  });
}

function p2pkhForPublicKey(publicKey) {
  const sha = createHash('sha256').update(publicKey).digest();
  const hash = createHash('ripemd160').update(sha).digest();
  return Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), hash, Buffer.from([0x88, 0xac])]);
}

function request(store) {
  const expected = store.canonicalState();
  return Object.freeze({
    operationId: OPERATION_ID,
    kind: 'transfer',
    expectedState: expected.state,
    expectedOutpoint: expected.outpoint,
    expectedActionSequence: expected.actionSequence,
    expectedHeight: expected.height,
    expectedBlockHash: expected.blockHash,
    runtimeMaterialsSha256: RUNTIME_MATERIALS_SHA256,
    actionMaterialSha256: Buffer.alloc(32, 0xa6),
    privateActionRecordSha256: Buffer.alloc(32, 0xa7),
    intent: {
      kind: 'transfer',
      target: { type: 'shield_address', bytes: SHIELD_ADDRESS },
      selectedNoteId: NOTE_ID,
      funding: fundingSource(),
      changeLockingBytecode: Buffer.from('76a914111111111111111111111111111111111111111188ac', 'hex'),
      feePolicy: { feeRateSatsPerByte: '1', maximumFeeSats: '100000' },
    },
    packet: null,
    proof: null,
    unsignedTx: null,
    signedTx: null,
    localVmEvidence: null,
    crashAt: null,
  });
}

function seedReservationInputs(store) {
  store.putEncryptedRecord({ recordId: 'external-crash-record', record: Buffer.alloc(128, 0x70) });
  const nullifier = createHash('sha256').update(NOTE_ID).digest();
  nullifier[0] = 0;
  store.putOwnedNote({ noteId: NOTE_ID, recordId: 'external-crash-record', noteIndex: 7, nullifier });
  const funding = fundingSource();
  store.putFundingUtxo({ txid: funding.txid, vout: 0, valueSats: funding.valueSats });
}

function identity() {
  const hash = (label) => createHash('sha256').update(`external-crash/${label}`).digest('hex');
  return Object.freeze({
    operationId: OPERATION_ID,
    txid: hash('txid'),
    metadataHash: hash('metadata'),
    evidenceHash: hash('evidence'),
    carrierCount: 7,
    roleLayoutHash: hash('roles'),
  });
}

function readyToKill(mode) {
  writeSync(
    process.stdout.fd,
    `${JSON.stringify({ event: 'ready-to-kill', mode })}\n`,
  );
  process.kill(process.pid, 'SIGKILL');
  fail('SIGKILL unexpectedly returned');
}

function verifyCanonicalUnchanged(store) {
  const expected = initialStore();
  assert.deepEqual(canonical(store), {
    state: expected.state,
    outpoint: expected.outpoint,
    actionSequence: expected.actionSequence,
    height: expected.height,
    blockHash: expected.blockHash,
  });
}

function runSqliteCrash(mode, path) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const store = openV2DirectStore({ path, ...initialStore() });
  if (mode.startsWith('sqlite-reserve')) seedReservationInputs(store);
  if (mode === 'sqlite-create-before') readyToKill(mode);
  store.createOperation(request(store));
  if (mode === 'sqlite-reserve-before') readyToKill(mode);
  if (mode === 'sqlite-create-after') readyToKill(mode);
  store.reserveResources({ operationId: OPERATION_ID, noteId: NOTE_ID, utxoTxid: fundingSource().txid, utxoVout: 0, crashAt: null });
  readyToKill(mode);
}

function verifySqlite(mode, path) {
  const store = openV2DirectStore({ path, ...initialStore() });
  const isCreate = mode.includes('create');
  try {
    verifyCanonicalUnchanged(store);
    const after = mode.endsWith('after');
    if (isCreate && !after) assert.throws(() => store.operation(OPERATION_ID));
    else {
      const operation = store.operation(OPERATION_ID);
      assert.equal(operation.journalState, !isCreate && after ? 'funding_selected' : 'draft');
      if (!isCreate) {
        const note = store.ownedNote(NOTE_ID);
        const utxo = store.fundingUtxo({ txid: fundingSource().txid, vout: 0 });
        assert.equal(note.reservationOperationId, after ? OPERATION_ID : null);
        assert.equal(utxo.reservationOperationId, after ? OPERATION_ID : null);
      }
    }
  } finally { store.close(); }
  return isCreate
    ? ['canonical-unchanged', 'operation-presence-exact']
    : ['canonical-unchanged', 'operation-state-exact', 'note-and-utxo-reservations-exact'];
}

function runDeliveryCrash(mode, path) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const journal = openV2DeliveryJournal(path);
  const item = identity();
  const claim = journal.claimOrCreate(item);
  if (mode === 'delivery-submit-before') readyToKill(mode);
  journal.markSubmitted({
    operationId: OPERATION_ID,
    txid: item.txid,
    attemptToken: claim.attemptToken,
    rawTransactionSha256: createHash('sha256').update('external-crash-raw-transaction').digest('hex'),
  });
  readyToKill(mode);
}

function verifyDelivery(mode, path) {
  const journal = openV2DeliveryJournal(path);
  try {
    const record = journal.record(OPERATION_ID);
    assert.ok(record !== null);
    assert.equal(record.state, mode.endsWith('after') ? 'submitted' : 'attempted');
    assert.throws(() => journal.claimOrCreate(identity()));
  } finally { journal.close(); }
  return ['delivery-state-exact', 'duplicate-send-claim-rejected'];
}

function main() {
  const { mode, path } = argumentsFor(process.argv.slice(2));
  if (['sqlite-create-before', 'sqlite-create-after', 'sqlite-reserve-before', 'sqlite-reserve-after'].includes(mode)) {
    runSqliteCrash(mode, path);
    return;
  }
  if (['delivery-submit-before', 'delivery-submit-after'].includes(mode)) {
    runDeliveryCrash(mode, path);
    return;
  }
  let invariants;
  if (['verify-sqlite-create-before', 'verify-sqlite-create-after', 'verify-sqlite-reserve-before', 'verify-sqlite-reserve-after'].includes(mode)) {
    invariants = verifySqlite(mode.replace('verify-', ''), path);
  } else if (['verify-delivery-submit-before', 'verify-delivery-submit-after'].includes(mode)) {
    invariants = verifyDelivery(mode.replace('verify-', ''), path);
  } else fail(`unsupported mode ${mode}`);
  process.stdout.write(`${JSON.stringify({ event: 'verified', mode, invariants })}\n`);
}

main();
