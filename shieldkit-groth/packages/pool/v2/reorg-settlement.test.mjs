import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { encodeTransaction } from '@bitauth/libauth';

import { encodeDirectV2Address } from '../../action/v2/address.mjs';
import { deriveDirectV2Address } from '../../action/v2/notes.mjs';
import { decodeActionPacket, encodeActionPacket } from '../../action/v2/packet.mjs';
import {
  decodeStateNftCommitment,
  encodeStateNftCommitment,
} from '../../action/v2/state.mjs';
import { createDirectV2PoolModel } from '../../action/v2/transition.mjs';
import { parseV2RawTransaction } from '../../kit/v2/transaction-policy.mjs';
import {
  openV2DirectStore,
  V2_OPERATION_MAX_AUTOMATIC_CONFLICTS,
  V2StoreError,
} from './store.mjs';

// Unit-only durable-store tests. Transactions are deterministic local fixtures:
// they exercise V2DirectStore admission and lifecycle mutation, not a BCH VM,
// broadcast, mining, Schnorr verification, or proof-system qualification.
const b = (byte, length = 32) => Buffer.alloc(length, byte);
const fr = (value) => Buffer.from(value.toString(16).padStart(64, '0'), 'hex');
const PROFILE_ID = b(0x81);
const INSTANCE_ID = b(0x82);
const RUNTIME = b(0x83);
const NETWORK_ID = 2;
const DENOMINATION_SATS = '10000000';
const CARRIER_COUNT = 7;
const STATE_CONTEXT = Object.freeze({ denominationSats: DENOMINATION_SATS });
const FUNDING_PUBLIC_KEY = Buffer.from('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'hex');
const CHANGE_LOCK = Buffer.from('76a914111111111111111111111111111111111111111188ac', 'hex');

function p2pkh(publicKey) {
  const sha = createHash('sha256').update(publicKey).digest();
  return Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), createHash('ripemd160').update(sha).digest(), Buffer.from([0x88, 0xac])]);
}
const FUNDING_LOCK = p2pkh(FUNDING_PUBLIC_KEY);
const SHIELD_ADDRESS = encodeDirectV2Address(deriveDirectV2Address({
  networkId: NETWORK_ID,
  profileId: PROFILE_ID.toString('hex'),
  instanceId: INSTANCE_ID.toString('hex'),
  spendSecret: fr(3n).toString('hex'),
  incomingViewSecret: fr(4n).toString('hex'),
}));

function initialStore() {
  const model = createDirectV2PoolModel({
    profileId: PROFILE_ID.toString('hex'),
    maximumLiveNotes: '210000000',
    denominationSats: DENOMINATION_SATS,
  });
  return {
    profileId: PROFILE_ID,
    instanceId: INSTANCE_ID,
    networkId: NETWORK_ID,
    denominationSats: DENOMINATION_SATS,
    carrierCount: CARRIER_COUNT,
    runtimeMaterialsSha256: RUNTIME,
    state: encodeStateNftCommitment(model.state, STATE_CONTEXT),
    outpoint: { txid: b(0x84), vout: 0 },
    actionSequence: 0,
    height: 100,
    blockHash: b(0x85),
  };
}

function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'shieldkit-v2-reorg-settlement-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const initial = initialStore();
  const path = join(directory, 'private', 'pool.sqlite');
  return { initial, path, store: openV2DirectStore({ path, ...initial }) };
}

function funding(tag) {
  const value = Buffer.alloc(8);
  value.writeBigUInt64LE(10_200_000n);
  const rawSourceTransaction = Buffer.concat([
    Buffer.from('0200000001', 'hex'),
    createHash('sha256').update(`v2-reorg-settlement/${tag}`).digest(),
    Buffer.from('0000000000ffffffff01', 'hex'), value,
    Buffer.from([FUNDING_LOCK.length]), FUNDING_LOCK, Buffer.alloc(4),
  ]);
  const parsed = parseV2RawTransaction(rawSourceTransaction.toString('hex'));
  return {
    rawSourceTransaction,
    txid: Buffer.from(parsed.txid, 'hex'),
    vout: 0,
    valueSats: '10200000',
    lockingBytecode: FUNDING_LOCK,
    compressedPublicKey: FUNDING_PUBLIC_KEY,
  };
}

function createReserved(store, operationId) {
  const expected = store.canonicalState();
  const source = funding(operationId);
  const operation = store.createOperation({
    operationId,
    kind: 'deposit',
    expectedState: expected.state,
    expectedOutpoint: expected.outpoint,
    expectedActionSequence: expected.actionSequence,
    expectedHeight: expected.height,
    expectedBlockHash: expected.blockHash,
    runtimeMaterialsSha256: RUNTIME,
    actionMaterialSha256: Buffer.alloc(32, 0xa6),
    privateActionRecordSha256: Buffer.alloc(32, 0xa7),
    intent: {
      kind: 'deposit',
      target: { type: 'shield_address', bytes: SHIELD_ADDRESS },
      selectedNoteId: null,
      funding: source,
      changeLockingBytecode: CHANGE_LOCK,
      feePolicy: { feeRateSatsPerByte: '1', maximumFeeSats: '100000' },
    },
    packet: null,
    proof: null,
    unsignedTx: null,
    signedTx: null,
    localVmEvidence: null,
    crashAt: null,
  });
  store.putFundingUtxo({ txid: source.txid, vout: 0, valueSats: source.valueSats });
  store.reserveResources({ operationId, noteId: null, utxoTxid: source.txid, utxoVout: 0, crashAt: null });
  return { expected, operation, source };
}

function packetFor(store, expected, marker) {
  const derived = store.derivePacketPostState({
    kind: 'deposit', publicNullifier: Buffer.alloc(32), outputNoteLeaf: fr(BigInt(marker + 1)),
  });
  return Buffer.from(encodeActionPacket({
    kind: 'deposit',
    networkId: NETWORK_ID,
    instanceId: INSTANCE_ID.toString('hex'),
    preState: decodeStateNftCommitment(expected.state, STATE_CONTEXT),
    postState: derived.state,
    publicNullifier: Buffer.alloc(32).toString('hex'),
    outputNoteLeaf: fr(BigInt(marker + 1)).toString('hex'),
    encryptedRecord: b(marker & 0xff, 128),
    withdrawalLockingBytecodeHash: Buffer.alloc(32).toString('hex'),
    transactionContextHash: b((marker + 9) & 0xff).toString('hex'),
  }, STATE_CONTEXT));
}

function transactionFor(expected, operation, packet) {
  const postState = decodeActionPacket(packet, STATE_CONTEXT).postState;
  const bindingUnlock = Buffer.concat([Buffer.from('4d2802', 'hex'), packet, Buffer.from([0x01, 0x51])]);
  const fundingUnlock = Buffer.concat([Buffer.from([0x41]), Buffer.alloc(64), Buffer.from([0x61, 0x21]), FUNDING_PUBLIC_KEY]);
  const inputs = (signed) => [
    ...Array.from({ length: CARRIER_COUNT + 2 }, (_, index) => ({
      outpointTransactionHash: Uint8Array.from(expected.outpoint.txid),
      outpointIndex: index === CARRIER_COUNT + 1 ? 0 : index + 1,
      sequenceNumber: 0,
      unlockingBytecode: index === CARRIER_COUNT ? bindingUnlock : Uint8Array.of(0x51),
    })),
    { outpointTransactionHash: Uint8Array.from(operation.intent.funding.txid), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: signed ? fundingUnlock : new Uint8Array() },
  ];
  const outputs = (change) => [
    { valueSatoshis: BigInt(postState.reserveSats) + 1_000n, lockingBytecode: Uint8Array.of(0x51), token: { category: Uint8Array.from(Buffer.from(INSTANCE_ID).reverse()), amount: 0n, nft: { capability: 'mutable', commitment: encodeStateNftCommitment(postState, STATE_CONTEXT) } } },
    ...Array.from({ length: CARRIER_COUNT }, (_, index) => ({ valueSatoshis: 1_000n + BigInt(index), lockingBytecode: Uint8Array.of(0x51) })),
    { valueSatoshis: 2_000n, lockingBytecode: Uint8Array.of(0x51) },
    { valueSatoshis: change, lockingBytecode: CHANGE_LOCK },
  ];
  const encode = (signed, change) => Buffer.from(encodeTransaction({ version: 2, inputs: inputs(signed), outputs: outputs(change), locktime: 0 }));
  const change = 10_200_000n - BigInt(DENOMINATION_SATS) - BigInt(encode(true, 546n).length);
  return { unsignedTx: encode(false, change), signedTx: encode(true, change), change };
}

function advance(store, operationId, marker, phase = 'confirmed') {
  const prepared = createReserved(store, operationId);
  if (phase === 'funding_selected') return prepared;
  store.transitionOperation({ operationId, to: 'tip_synced', reason: null });
  if (phase === 'tip_synced') return prepared;
  store.transitionOperation({ operationId, to: 'proving', reason: null });
  const packet = packetFor(store, prepared.expected, marker);
  const transactions = transactionFor(prepared.expected, prepared.operation, packet);
  store.updateOperationArtifacts({ operationId, packet, proof: b(marker + 1), unsignedTx: transactions.unsignedTx, signedTx: null, localVmEvidence: null });
  store.transitionOperation({ operationId, to: 'proved', reason: null });
  if (phase === 'proved') return { ...prepared, packet, transactions };
  store.updateOperationArtifacts({ operationId, packet, proof: b(marker + 1), unsignedTx: transactions.unsignedTx, signedTx: transactions.signedTx, localVmEvidence: b(marker + 2) });
  store.transitionOperation({ operationId, to: 'signed', reason: null });
  if (phase === 'signed') return { ...prepared, packet, transactions };
  store.transitionOperation({ operationId, to: 'broadcast', reason: null });
  if (phase === 'broadcast') return { ...prepared, packet, transactions };
  const parsed = parseV2RawTransaction(transactions.signedTx.toString('hex'));
  const decoded = decodeActionPacket(packet, STATE_CONTEXT);
  store.applyConfirmed({
    operationId,
    expected: { state: prepared.expected.state, outpoint: prepared.expected.outpoint, actionSequence: prepared.expected.actionSequence },
    next: { state: encodeStateNftCommitment(decoded.postState, STATE_CONTEXT), outpoint: { txid: Buffer.from(parsed.txid, 'hex'), vout: 0 }, actionSequence: prepared.expected.actionSequence + 1, height: prepared.expected.height + 1, blockHash: b((marker + 3) & 0xff) },
    records: [{ recordId: `${operationId}-record`, record: Buffer.from(decoded.encryptedRecord) }],
    notes: { insert: [], spend: [] },
    funding: { spend: { txid: prepared.source.txid, vout: 0 }, change: [{ txid: Buffer.from(parsed.txid, 'hex'), vout: CARRIER_COUNT + 2, valueSats: transactions.change.toString() }] },
    undo: b(marker + 4, 8), crashAt: null,
  });
  return { ...prepared, packet, transactions };
}

test('[unit-only] crash after applyConfirmed never settles an orphaned action after 1/2/10/100-deep rollback', (t) => {
  for (const depth of [1, 2, 10, 100]) t.test(`depth ${depth}`, () => {
    const environment = fixture(t);
    let { store } = environment;
    let last;
    for (let index = 0; index < depth; index += 1) last = advance(store, `orphan-${depth}-${index}`, 10 + index);
    store.close(); // crash boundary: applyConfirmed committed; settlement was never called.
    store = openV2DirectStore({ path: environment.path, ...environment.initial });
    assert.equal(store.operation(last.operation.operationId).journalState, 'confirmed');
    store.rollbackReorg({ commonAncestorHeight: environment.initial.height, commonAncestorBlockHash: environment.initial.blockHash });
    assert.equal(store.operation(last.operation.operationId).journalState, 'reorged');
    assert.throws(
      () => store.settleConfirmedOperation({ operationId: last.operation.operationId, crashAt: null }),
      V2StoreError,
    );
    assert.equal(store.operation(last.operation.operationId).journalState, 'reorged');
    store.close();
  });
});

test('[unit-only] externally advanced canonical successor makes every pending phase recoverable and releases its actual reservation', (t) => {
  for (const phase of ['funding_selected', 'tip_synced', 'proved', 'signed', 'broadcast']) t.test(phase, () => {
    const { store } = fixture(t);
    const pending = advance(store, `pending-${phase}`, 120, phase);
    // A separately assembled, confirmed action represents the newly observed
    // canonical successor. The assertion below reads the durable reservation;
    // it does not fake a release through test-only state manipulation.
    advance(store, `external-successor-${phase}`, 121);
    const conflicted = store.recordConflictAndMaybeRetry({ operationId: pending.operation.operationId, reason: 'external canonical successor', crashAt: null });
    assert.equal(conflicted.journalState, 'needs_reproof');
    assert.equal(conflicted.retryCount, 1);
    assert.equal(store.fundingUtxo({ txid: pending.source.txid, vout: 0 }).reservationOperationId, null);
    store.close();
  });
});

test('[unit-only] externally advanced-tip retry cap is durable: two recoverable reproofs, then terminal conflict with no reservation', (t) => {
  const { store } = fixture(t);
  assert.equal(V2_OPERATION_MAX_AUTOMATIC_CONFLICTS, 3);
  const pending = advance(store, 'retry-cap-pending', 140, 'proved');
  for (let attempt = 1; attempt <= V2_OPERATION_MAX_AUTOMATIC_CONFLICTS; attempt += 1) {
    advance(store, `retry-cap-successor-${attempt}`, 140 + attempt);
    const operation = store.recordConflictAndMaybeRetry({ operationId: pending.operation.operationId, reason: `external successor ${attempt}`, crashAt: null });
    assert.equal(operation.retryCount, attempt);
    assert.equal(operation.journalState, attempt === V2_OPERATION_MAX_AUTOMATIC_CONFLICTS ? 'conflicted' : 'needs_reproof');
    if (attempt === V2_OPERATION_MAX_AUTOMATIC_CONFLICTS) continue;
    const live = store.canonicalState();
    const rebased = store.rebaseOperation({
      operationId: pending.operation.operationId,
      expectedState: live.state,
      expectedOutpoint: live.outpoint,
      expectedActionSequence: live.actionSequence,
      expectedHeight: live.height,
      expectedBlockHash: live.blockHash,
      actionMaterialSha256: b(0xa8),
      privateActionRecordSha256: b(0xa9),
      crashAt: null,
    });
    assert.deepEqual(rebased.actionMaterialSha256, b(0xa8));
    assert.deepEqual(rebased.privateActionRecordSha256, b(0xa9));
  }
  assert.equal(store.fundingUtxo({ txid: pending.source.txid, vout: 0 }).reservationOperationId, null);
  assert.throws(
    () => store.recordConflictAndMaybeRetry({ operationId: pending.operation.operationId, reason: 'retry budget exhausted', crashAt: null }),
    V2StoreError,
  );
  store.close();
});
