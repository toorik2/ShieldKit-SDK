import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { encodeDirectV2Address } from '../../action/v2/address.mjs';
import { deriveDirectV2Address } from '../../action/v2/notes.mjs';
import { encodeStateNftCommitment } from '../../action/v2/state.mjs';
import { createDirectV2PoolModel } from '../../action/v2/transition.mjs';
import { parseV2RawTransaction } from '../../kit/v2/transaction-policy.mjs';
import { openV2DirectStore } from './store.mjs';

const PROFILE_ID = Buffer.alloc(32, 0x91);
const INSTANCE_ID = Buffer.alloc(32, 0x92);
const RUNTIME_MATERIALS_SHA256 = Buffer.alloc(32, 0x93);
const NETWORK_ID = 2;
const DENOMINATION_SATS = '10000000';
const CARRIER_COUNT = 10;
const FUNDING_PUBLIC_KEY = Buffer.from(
  '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  'hex',
);

const p2pkh = (publicKey) => {
  const sha = createHash('sha256').update(publicKey).digest();
  const hash = createHash('ripemd160').update(sha).digest();
  return Buffer.concat([
    Buffer.from([0x76, 0xa9, 0x14]),
    hash,
    Buffer.from([0x88, 0xac]),
  ]);
};

const FUNDING_LOCK = p2pkh(FUNDING_PUBLIC_KEY);
const CHANGE_LOCK = Buffer.from(
  '76a914111111111111111111111111111111111111111188ac',
  'hex',
);

const b = (byte, length = 32) => Buffer.alloc(length, byte);
const fr = (value) =>
  Buffer.from(value.toString(16).padStart(64, '0'), 'hex');

function seed() {
  const model = createDirectV2PoolModel({
    profileId: PROFILE_ID.toString('hex'),
    maximumLiveNotes: '32',
    denominationSats: DENOMINATION_SATS,
  });
  return Object.freeze({
    profileId: PROFILE_ID,
    instanceId: INSTANCE_ID,
    networkId: NETWORK_ID,
    denominationSats: DENOMINATION_SATS,
    carrierCount: CARRIER_COUNT,
    runtimeMaterialsSha256: RUNTIME_MATERIALS_SHA256,
    state: encodeStateNftCommitment(model.state, {
      denominationSats: DENOMINATION_SATS,
    }),
    outpoint: Object.freeze({ txid: Buffer.alloc(32, 0x94), vout: 0 }),
    actionSequence: 0,
    height: 100,
    blockHash: Buffer.alloc(32, 0x95),
  });
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

function shieldAddress() {
  return encodeDirectV2Address(deriveDirectV2Address({
    networkId: NETWORK_ID,
    profileId: PROFILE_ID.toString('hex'),
    instanceId: INSTANCE_ID.toString('hex'),
    spendSecret: fr(1n).toString('hex'),
    incomingViewSecret: fr(2n).toString('hex'),
  }));
}

function snapshotFromStore(store) {
  const binding = store.binding();
  const canonical = store.canonicalState();
  return Object.freeze({
    binding,
    canonical,
    noteNodes: [Object.freeze({
      depth: 32,
      nodeIndex: 0,
      nodeHash: store.noteNode({ depth: 32, nodeIndex: 0 }),
    })],
    noteFrontier: [],
    noteLeaves: [],
    nullifierNodes: [
      Object.freeze({
        depth: 0,
        nodeIndex: 0,
        nodeHash: store.nullifierNode({ depth: 0, nodeIndex: 0 }),
      }),
      Object.freeze({
        depth: 0,
        nodeIndex: 1,
        nodeHash: store.nullifierNode({ depth: 0, nodeIndex: 1 }),
      }),
      ...Array.from({ length: 32 }, (_, offset) => {
        const depth = offset + 1;
        return Object.freeze({
          depth,
          nodeIndex: 0,
          nodeHash: store.nullifierNode({ depth, nodeIndex: 0 }),
        });
      }),
    ],
    nullifierLeaves: [
      store.nullifierLeaf({ physicalIndex: 0 }),
      store.nullifierLeaf({ physicalIndex: 1 }),
    ],
    crashAt: null,
  });
}

async function fixture(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-v2-canonical-reconcile-'));
  t.after(async () => await rm(directory, { recursive: true, force: true }));
  const initial = seed();
  return Object.freeze({
    initial,
    store: openV2DirectStore({
      path: path.join(directory, 'pool.sqlite'),
      ...initial,
    }),
  });
}

function createReservedOperation(store, operationId) {
  const expected = store.canonicalState();
  const funding = fundingSource(operationId, '10200000');
  store.createOperation({
    operationId,
    kind: 'deposit',
    expectedState: expected.state,
    expectedOutpoint: expected.outpoint,
    expectedActionSequence: expected.actionSequence,
    expectedHeight: expected.height,
    expectedBlockHash: expected.blockHash,
    runtimeMaterialsSha256: RUNTIME_MATERIALS_SHA256,
    actionMaterialSha256: b(0xa6),
    privateActionRecordSha256: b(0xa7),
    intent: {
      kind: 'deposit',
      target: { type: 'shield_address', bytes: shieldAddress() },
      selectedNoteId: null,
      funding,
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
  store.putFundingUtxo({
    txid: funding.txid,
    vout: funding.vout,
    valueSats: funding.valueSats,
  });
  store.reserveResources({
    operationId,
    noteId: null,
    utxoTxid: funding.txid,
    utxoVout: funding.vout,
    crashAt: null,
  });
  return funding;
}

/**
 * Required API contract for the implementation work that follows this
 * failing-first test. `canonicalSettlementTxids` is the authenticated set
 * reconstructed from the unique canonical chain lineage; a local operation id
 * is deliberately not treated as chain authority. `fundingInventory` is one
 * freshly authenticated, complete inventory of the wallet's tokenless P2PKH
 * outputs, not a delta and not a locally inferred change set.
 */
function reconcile(store, value) {
  assert.equal(
    typeof store.reconcileAuthenticatedCanonicalSnapshot,
    'function',
    'V2DirectStore must expose authoritative canonical snapshot reconciliation',
  );
  return store.reconcileAuthenticatedCanonicalSnapshot(value);
}

test('canonical replacement removes orphaned local reservations and never resurrects funding without fresh authenticated inventory', async (t) => {
  const { store } = await fixture(t);
  t.after(() => store.close());
  const funding = createReservedOperation(store, 'orphaned-reservation');
  const snapshot = snapshotFromStore(store);

  reconcile(store, {
    snapshot,
    canonicalSettlementTxids: [],
    fundingInventory: [],
    crashAt: null,
  });

  assert.equal(store.operation('orphaned-reservation').journalState, 'reorged');
  assert.equal(
    store.fundingUtxo({ txid: funding.txid, vout: funding.vout }),
    null,
    'an orphaned locally spent/reserved output must remain absent until an authenticated inventory includes it again',
  );
  assert.equal(store.undoStatistics().count, 0);
});

test('canonical replacement admits only the exact fresh wallet inventory and removes orphaned change outputs', async (t) => {
  const { store } = await fixture(t);
  t.after(() => store.close());
  const staleFunding = createReservedOperation(store, 'orphaned-change');
  const freshFunding = fundingSource('fresh-wallet-inventory', '10200001');
  const snapshot = snapshotFromStore(store);

  reconcile(store, {
    snapshot,
    canonicalSettlementTxids: [],
    fundingInventory: [{
      txid: freshFunding.txid,
      vout: freshFunding.vout,
      valueSats: freshFunding.valueSats,
    }],
    crashAt: null,
  });

  assert.equal(store.operation('orphaned-change').journalState, 'reorged');
  assert.equal(store.fundingUtxo({
    txid: staleFunding.txid,
    vout: staleFunding.vout,
  }), null);
  assert.deepEqual(store.fundingUtxo({
    txid: freshFunding.txid,
    vout: freshFunding.vout,
  }), {
    valueSats: freshFunding.valueSats,
    reservationOperationId: null,
    spent: false,
  });
});

test('reconciliation is atomic: malformed authoritative replacement leaves canonical state, operations, reservations, and undo rows untouched', async (t) => {
  const { store } = await fixture(t);
  t.after(() => store.close());
  const funding = createReservedOperation(store, 'atomic-reconcile');
  const before = store.canonicalState();
  const snapshot = snapshotFromStore(store);

  assert.equal(
    typeof store.reconcileAuthenticatedCanonicalSnapshot,
    'function',
    'V2DirectStore must expose authoritative canonical snapshot reconciliation',
  );

  assert.throws(
    () => store.reconcileAuthenticatedCanonicalSnapshot({
      snapshot: { ...snapshot, canonical: { ...snapshot.canonical, actionSequence: 1 } },
      canonicalSettlementTxids: [],
      fundingInventory: [],
      crashAt: null,
    }),
  );
  assert.deepEqual(store.canonicalState(), before);
  assert.equal(store.operation('atomic-reconcile').journalState, 'funding_selected');
  assert.deepEqual(store.fundingUtxo({ txid: funding.txid, vout: funding.vout }), {
    valueSats: funding.valueSats,
    reservationOperationId: 'atomic-reconcile',
    spent: false,
  });
});
