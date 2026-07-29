#!/usr/bin/env node

/**
 * Deterministic, local-only Q-06 qualification of the production V2 Direct
 * SQLite state machine. This runner deliberately exercises real durable
 * operations, confirmation, undo, reorg rollback, and authenticated snapshot
 * installation. It has no chain transport, broadcast, prover, or signer.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';
import { encodeTransaction } from '@bitauth/libauth';

import { encodeDirectV2Address } from '../packages/action/v2/address.mjs';
import { deriveDirectV2Address } from '../packages/action/v2/notes.mjs';
import { decodeActionPacket, encodeActionPacket } from '../packages/action/v2/packet.mjs';
import {
  decodeStateNftCommitment,
  encodeStateNftCommitment,
} from '../packages/action/v2/state.mjs';
import { createDirectV2PoolModel } from '../packages/action/v2/transition.mjs';
import { parseV2RawTransaction } from '../packages/kit/v2/transaction-policy.mjs';
import { openV2DirectStore } from '../packages/pool/v2/store.mjs';

const SEED = 'shieldkit-v2-reorg-concurrency-qualification-20260729';
const REORG_DEPTHS = Object.freeze([1, 2, 10, 100]);
const WALLET_COUNTS = Object.freeze([2, 4, 8, 16]);
const b = (byte, length = 32) => Buffer.alloc(length, byte);
const fr = (value) => Buffer.from(value.toString(16).padStart(64, '0'), 'hex');
const PROFILE_ID = b(0x91);
const INSTANCE_ID = b(0x92);
const RUNTIME_MATERIALS_SHA256 = b(0x93);
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
const FUNDING_LOCK = p2pkhForPublicKey(FUNDING_PUBLIC_KEY);
const SHIELD_ADDRESS = encodeDirectV2Address(deriveDirectV2Address({
  networkId: NETWORK_ID,
  profileId: PROFILE_ID.toString('hex'),
  instanceId: INSTANCE_ID.toString('hex'),
  spendSecret: fr(7n).toString('hex'),
  incomingViewSecret: fr(8n).toString('hex'),
}));

export class V2ReorgConcurrencyQualificationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2ReorgConcurrencyQualificationError';
  }
}

const fail = (message) => { throw new V2ReorgConcurrencyQualificationError(message); };

export function parseV2ReorgConcurrencyQualificationArguments(argv, cwd = process.cwd()) {
  if (!Array.isArray(argv) || argv.length !== 2 || argv[0] !== '--output') {
    fail('usage: v2-reorg-concurrency-qualification.mjs --output <new-evidence.json>');
  }
  const value = argv[1];
  if (typeof value !== 'string' || value.length === 0 || value.startsWith('--')) {
    fail('--output must name a new evidence file');
  }
  return Object.freeze({ output: resolve(cwd, value) });
}

function digest(label) {
  return createHash('sha256').update(`${SEED}/${label}`).digest();
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
    outpoint: { txid: digest('genesis-outpoint'), vout: 0 },
    actionSequence: 0,
    height: 100,
    blockHash: digest('genesis-block'),
  });
}

function canonical(point) {
  return Object.freeze({
    state: Buffer.from(point.state),
    outpoint: Object.freeze({ txid: Buffer.from(point.outpoint.txid), vout: point.outpoint.vout }),
    actionSequence: point.actionSequence,
    height: point.height,
    blockHash: Buffer.from(point.blockHash),
  });
}

function assertSameCanonical(actual, expected, label) {
  assert.deepEqual(canonical(actual), canonical(expected), label);
}

function safeNullifier(label) {
  const value = digest(`nullifier/${label}`);
  value[0] = 0;
  if (value.equals(Buffer.alloc(32))) value[31] = 1;
  return value;
}

function fundingSource(tag, kind) {
  const valueSats = kind === 'deposit' ? '10200000' : '200000';
  const value = Buffer.alloc(8);
  value.writeBigUInt64LE(BigInt(valueSats));
  const rawSourceTransaction = Buffer.concat([
    Buffer.from('0200000001', 'hex'),
    digest(`funding-source/${tag}`),
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

function operationRequest(store, operationId, kind, { selectedNoteId = null } = {}) {
  const expected = store.canonicalState();
  const funding = fundingSource(operationId, kind);
  return Object.freeze({
    operationId,
    kind,
    expectedState: expected.state,
    expectedOutpoint: expected.outpoint,
    expectedActionSequence: expected.actionSequence,
    expectedHeight: expected.height,
    expectedBlockHash: expected.blockHash,
    runtimeMaterialsSha256: RUNTIME_MATERIALS_SHA256,
    actionMaterialSha256: digest(`action-material/${operationId}`),
    privateActionRecordSha256:
      digest(`private-action-record/${operationId}`),
    intent: {
      kind,
      target: { type: 'shield_address', bytes: SHIELD_ADDRESS },
      selectedNoteId,
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
}

function packetFixture(store, expected, kind, marker, publicNullifier) {
  const derived = store.derivePacketPostState({
    kind,
    publicNullifier: publicNullifier ?? Buffer.alloc(32),
    outputNoteLeaf: fr(BigInt(marker + 2)),
  });
  assertSameCanonical(store.canonicalState(), expected, 'packet derivation must retain the supplied canonical tip');
  const decodedStoreState = decodeStateNftCommitment(
    store.canonicalState().state,
    STATE_CONTEXT,
  );
  return Buffer.from(encodeActionPacket({
    kind,
    networkId: NETWORK_ID,
    instanceId: INSTANCE_ID.toString('hex'),
    preState: decodedStoreState,
    postState: derived.state,
    publicNullifier: (publicNullifier ?? Buffer.alloc(32)).toString('hex'),
    outputNoteLeaf: fr(BigInt(marker + 2)).toString('hex'),
    encryptedRecord: b((marker + 17) & 0xff, 128),
    withdrawalLockingBytecodeHash: Buffer.alloc(32).toString('hex'),
    transactionContextHash: digest(`packet-context/${marker}`).toString('hex'),
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
  const boundary = operation.kind === 'deposit' ? BigInt(DENOMINATION_SATS) : 0n;
  const change = fundingValue - boundary - fee;
  assert.ok(change >= 546n, 'constructed funding change must remain non-dust');
  return Object.freeze({ unsigned: encode(false, change), signed: encode(true, change), change });
}

function prepareOperation(store, request) {
  const operation = store.createOperation(request);
  store.putFundingUtxo({
    txid: operation.intent.funding.txid,
    vout: operation.intent.funding.vout,
    valueSats: operation.intent.funding.valueSats,
  });
  store.reserveResources({
    operationId: operation.operationId,
    noteId: operation.intent.selectedNoteId,
    utxoTxid: operation.intent.funding.txid,
    utxoVout: operation.intent.funding.vout,
    crashAt: null,
  });
  return store.operation(operation.operationId);
}

function confirmPreparedOperation(store, operationId, marker, {
  publicNullifier = null,
  insertOwnedNote = null,
  height = null,
} = {}) {
  const before = store.canonicalState();
  let operation = store.operation(operationId);
  assert.equal(operation.journalState, 'funding_selected');
  operation = store.transitionOperation({ operationId, to: 'tip_synced', reason: null });
  operation = store.transitionOperation({ operationId, to: 'proving', reason: null });
  const packet = packetFixture(store, before, operation.kind, marker, publicNullifier);
  const transactions = operationTransactions(before, operation, packet);
  store.updateOperationArtifacts({
    operationId,
    packet,
    proof: b((marker + 1) & 0xff),
    unsignedTx: transactions.unsigned,
    signedTx: null,
    localVmEvidence: null,
  });
  store.transitionOperation({ operationId, to: 'proved', reason: null });
  const proved = store.operation(operationId);
  store.updateOperationArtifacts({
    operationId,
    packet,
    proof: proved.proof,
    unsignedTx: transactions.unsigned,
    signedTx: transactions.signed,
    localVmEvidence: b(0x99),
  });
  store.transitionOperation({ operationId, to: 'signed', reason: null });
  store.transitionOperation({ operationId, to: 'broadcast', reason: null });
  assertSameCanonical(store.canonicalState(), before, 'canonical state changed before authenticated confirmation');
  const decoded = decodeActionPacket(packet, STATE_CONTEXT);
  const parsed = parseV2RawTransaction(transactions.signed.toString('hex'));
  const next = {
    state: encodeStateNftCommitment(decoded.postState, STATE_CONTEXT),
    outpoint: { txid: Buffer.from(parsed.txid, 'hex'), vout: 0 },
    actionSequence: before.actionSequence + 1,
    height: height ?? before.height + 1,
    blockHash: digest(`block/${height ?? before.height + 1}`),
  };
  const changeIndex = CARRIER_COUNT + 2;
  store.applyConfirmed({
    operationId,
    expected: { state: before.state, outpoint: before.outpoint, actionSequence: before.actionSequence },
    next,
    records: [{ recordId: `${operationId}-record`, record: Buffer.from(decoded.encryptedRecord) }],
    notes: { insert: insertOwnedNote === null ? [] : [insertOwnedNote], spend: operation.intent.selectedNoteId === null ? [] : [operation.intent.selectedNoteId] },
    funding: {
      spend: { txid: operation.intent.funding.txid, vout: operation.intent.funding.vout },
      change: [{ txid: Buffer.from(parsed.txid, 'hex'), vout: changeIndex, valueSats: transactions.change.toString() }],
    },
    undo: Buffer.from(`q06/${operationId}/${marker}`, 'utf8'),
    crashAt: null,
  });
  assert.equal(store.operation(operationId).journalState, 'confirmed');
  return Object.freeze({ before, next, packet, parsed, operation: store.operation(operationId) });
}

function reopen(path, store) {
  store.close();
  return openV2DirectStore({ path, ...initialStore() });
}

function makeStore(workspace, label) {
  const directory = join(workspace, label, 'private');
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  return Object.freeze({ path: join(directory, 'pool.sqlite'), store: openV2DirectStore({ path: join(directory, 'pool.sqlite'), ...initialStore() }) });
}

function runReorgDepth(workspace, depth, invariants) {
  let { path, store } = makeStore(workspace, `reorg-${depth}`);
  const initial = store.canonicalState();
  const ids = [];
  try {
    for (let index = 0; index < depth; index += 1) {
      const id = `reorg-${depth}-${index}`;
      const request = operationRequest(store, id, 'deposit');
      prepareOperation(store, request);
      confirmPreparedOperation(store, id, 1_000 + index, { height: initial.height + index + 1 });
      ids.push({ id, funding: request.intent.funding });
      invariants.noPrematureConfirmedCommit += 1;
      store = reopen(path, store);
    }
    assert.equal(store.canonicalState().actionSequence, depth);
    assert.equal(store.undoStatistics().count, depth);
    store.rollbackReorg({ commonAncestorHeight: initial.height, commonAncestorBlockHash: initial.blockHash });
    assertSameCanonical(store.canonicalState(), initial, `reorg depth ${depth} must restore ancestor`);
    for (const { id, funding } of ids) {
      assert.equal(store.operation(id).journalState, 'reorged');
      assert.equal(
        store.fundingUtxo({ txid: funding.txid, vout: 0 }).reservationOperationId,
        id,
        'reorged operation retains its exact funding reservation until explicit rebase or abandon',
      );
      store.abandonOperation({ operationId: id, reason: 'qualification reorg release', crashAt: null });
      assert.deepEqual(store.fundingUtxo({ txid: funding.txid, vout: 0 }), {
        valueSats: funding.valueSats, reservationOperationId: null, spent: false,
      });
    }
    assert.equal(store.undoStatistics().count, 0);
    invariants.noNoteOrValueLoss += ids.length;
    invariants.noDoubleCommitmentOrNullifier += ids.length;
    return Object.freeze({ depth, actions: ids.length, reopenedAfterEveryConfirmation: true });
  } finally {
    store.close();
  }
}

function snapshotMaterial(path, binding, canonicalState) {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    const rows = (sql) => db.prepare(sql).all();
    const noteNodes = rows('SELECT depth,node_index,node_hash FROM note_nodes ORDER BY depth,node_index')
      .map((v) => ({ depth: v.depth, nodeIndex: v.node_index, nodeHash: Buffer.from(v.node_hash) }));
    const nodeByCoordinate = new Map(noteNodes.map((v) => [`${v.depth}:${v.nodeIndex}`, v]));
    const noteCount = Number(decodeStateNftCommitment(canonicalState.state, STATE_CONTEXT).noteCount);
    const noteFrontier = [];
    for (let depth = 0; depth < 32; depth += 1) {
      if (((BigInt(noteCount) >> BigInt(depth)) & 1n) === 0n) continue;
      const node = nodeByCoordinate.get(`${depth}:${Math.floor(noteCount / (2 ** depth)) - 1}`);
      if (!node) fail(`snapshot source lacks materialized note frontier node at depth ${depth}`);
      noteFrontier.push({ depth, nodeHash: Buffer.from(node.nodeHash) });
    }
    const persistedFrontier = new Map(rows('SELECT depth,node_hash FROM note_frontier ORDER BY depth')
      .map((v) => [v.depth, Buffer.from(v.node_hash)]));
    // The live store keeps a complete append frontier cache; the recovery
    // snapshot contract serializes only the bit-decomposed frontier required
    // by its exact note count. Validate the exported subset against both the
    // cache and materialized node tree rather than confusing cache width with
    // recovery wire format.
    for (const entry of noteFrontier) {
      assert.ok(persistedFrontier.has(entry.depth), `live note frontier lacks depth ${entry.depth}`);
      assert.deepEqual(persistedFrontier.get(entry.depth), entry.nodeHash, `live note frontier differs at depth ${entry.depth}`);
    }
    return Object.freeze({
      binding,
      canonical: canonicalState,
      noteNodes,
      noteFrontier,
      noteLeaves: rows('SELECT note_index,leaf_hash,encrypted_record,action_sequence,transaction_id FROM note_leaves ORDER BY note_index').map((v) => ({ noteIndex: v.note_index, leafHash: Buffer.from(v.leaf_hash), encryptedRecord: Buffer.from(v.encrypted_record), actionSequence: v.action_sequence, transactionId: Buffer.from(v.transaction_id) })),
      nullifierNodes: rows('SELECT depth,node_index,node_hash FROM nullifier_nodes ORDER BY depth,node_index').map((v) => ({ depth: v.depth, nodeIndex: v.node_index, nodeHash: Buffer.from(v.node_hash) })),
      nullifierLeaves: rows('SELECT physical_index,leaf_type,leaf_hash,key_be,successor_index,successor_key_be FROM nullifier_leaves ORDER BY physical_index').map((v) => ({ physicalIndex: v.physical_index, leafType: v.leaf_type, leafHash: Buffer.from(v.leaf_hash), key: Buffer.from(v.key_be), successorIndex: v.successor_index, successorKey: Buffer.from(v.successor_key_be) })),
      crashAt: null,
    });
  } finally {
    db.close();
  }
}

function buildDepositChain(store, count, label, { insertFirstOwned = false } = {}) {
  const entries = [];
  for (let index = 0; index < count; index += 1) {
    const id = `${label}-${index}`;
    const request = operationRequest(store, id, 'deposit');
    prepareOperation(store, request);
    const owned = insertFirstOwned && index === 0
      ? { noteId: `${id}-owned`, recordId: `${id}-record`, noteIndex: 0, nullifier: safeNullifier(`${id}-owned`) }
      : null;
    const result = confirmPreparedOperation(store, id, 2_000 + index, { insertOwnedNote: owned, height: 101 + index });
    entries.push(Object.freeze({ id, request, result, owned }));
  }
  return Object.freeze(entries);
}

function runDeepWipeReplay(workspace, invariants, count = 16) {
  let { path, store } = makeStore(workspace, 'deep-wipe-source');
  // The separate 100-block reorg case below already covers the retained undo
  // boundary. Sixteen linked actions make this a genuine deep materialized
  // replay while keeping the normal local campaign practical on CI hardware.
  if (!Number.isSafeInteger(count) || count < 1 || count > 16) {
    fail('deep wipe/replay action count must be an integer from 1 through 16');
  }
  let expected;
  let material;
  try {
    const actions = buildDepositChain(store, count, 'deep-replay');
    expected = store.canonicalState();
    material = snapshotMaterial(path, store.binding(), expected);
    store.close();
    store = null;
    const sourceSize = statSync(path).size;
    const recovered = makeStore(workspace, 'deep-wipe-recovered');
    try {
      recovered.store.installAuthenticatedSnapshot(material);
      assertSameCanonical(recovered.store.canonicalState(), expected, 'authenticated snapshot recovery must preserve the exact canonical tip');
      assert.equal(recovered.store.recoveryCheckpoint(), null, 'compact snapshot installation intentionally does not assert external chain authentication');
      invariants.deepWipeRecoveryInstall += 1;
    } finally {
      recovered.store.close();
    }
    // This is an explicit local chain-log replay after the source database is
    // wiped. It reconstructs every transition through applyConfirmed again.
    for (const candidate of [path, `${path}-wal`, `${path}-shm`]) rmSync(candidate, { force: true });
    store = openV2DirectStore({ path, ...initialStore() });
    buildDepositChain(store, count, 'deep-replay');
    assertSameCanonical(store.canonicalState(), expected, 'deep wipe/replay canonical tip must be deterministic');
    assert.equal(store.canonicalState().actionSequence, count);
    invariants.deepWipeReplay += count;
    return Object.freeze({ actions: count, sourceDatabaseBytes: sourceSize, authenticatedSnapshotInstalled: true, localLogReplayMatched: true, actionIds: actions.length });
  } finally {
    store?.close();
  }
}

function runContention(workspace, wallets, invariants) {
  let { path, store } = makeStore(workspace, `contention-${wallets}`);
  const initial = store.canonicalState();
  const operations = [];
  try {
    for (let wallet = 0; wallet < wallets; wallet += 1) {
      const id = `wallet-${wallets}-${wallet}`;
      const request = operationRequest(store, id, 'deposit');
      prepareOperation(store, request);
      operations.push(Object.freeze({ id, request }));
    }
    for (const { id } of operations) assert.equal(store.operation(id).journalState, 'funding_selected');
    const winner = operations[wallets - 1];
    confirmPreparedOperation(store, winner.id, 4_000 + wallets, { height: initial.height + 1 });
    const winnerTip = store.canonicalState();
    for (const loser of operations.slice(0, -1)) {
      assert.throws(
        () => store.transitionOperation({ operationId: loser.id, to: 'tip_synced', reason: null }),
        /stale/,
      );
      assertSameCanonical(store.canonicalState(), winnerTip, 'lost sibling must not commit a canonical tip');
      const retried = store.recordConflictAndMaybeRetry({ operationId: loser.id, reason: 'parent lost to deterministic sibling', crashAt: null });
      assert.equal(retried.journalState, 'needs_reproof');
      assert.equal(
        store.fundingUtxo({
          txid: loser.request.intent.funding.txid,
          vout: 0,
        }).reservationOperationId,
        null,
        'a parent conflict must release stale funding before authenticated sync',
      );
      invariants.conflictReservationRelease += 1;
      const rebased = store.rebaseOperation({
        operationId: loser.id,
        expectedState: winnerTip.state,
        expectedOutpoint: winnerTip.outpoint,
        expectedActionSequence: winnerTip.actionSequence,
        expectedHeight: winnerTip.height,
        expectedBlockHash: winnerTip.blockHash,
        actionMaterialSha256: digest(`contention-rebase/action/${loser.id}`),
        privateActionRecordSha256: digest(
          `contention-rebase/private/${loser.id}`,
        ),
        crashAt: null,
      });
      assert.equal(rebased.journalState, 'tip_synced');
      assert.equal(
        store.fundingUtxo({
          txid: loser.request.intent.funding.txid,
          vout: 0,
        }).reservationOperationId,
        loser.id,
        'rebase must atomically reacquire the immutable funding intent',
      );
      invariants.rebaseReservationReacquire += 1;
      const abandoned = store.abandonOperation({ operationId: loser.id, reason: 'qualification deterministic sibling loss', crashAt: null });
      assert.equal(abandoned.journalState, 'abandoned');
      assert.deepEqual(store.fundingUtxo({ txid: loser.request.intent.funding.txid, vout: 0 }), {
        valueSats: loser.request.intent.funding.valueSats, reservationOperationId: null, spent: false,
      });
      invariants.noBadReservation += 1;
    }
    store = reopen(path, store);
    assertSameCanonical(store.canonicalState(), winnerTip, 'reopen after sibling contention must retain only winner canonical commit');
    invariants.parentLoss += wallets - 1;
    invariants.conflictingSiblings += wallets - 1;
    invariants.noPrematureConfirmedCommit += wallets;
    return Object.freeze({ wallets, siblingOperations: wallets, losers: wallets - 1, winner: winner.id, reopened: true });
  } finally {
    store.close();
  }
}

function runMaliciousSelfTransfer(workspace, invariants) {
  let { path, store } = makeStore(workspace, 'malicious-self-transfer');
  try {
    const depositId = 'self-deposit';
    const deposit = operationRequest(store, depositId, 'deposit');
    prepareOperation(store, deposit);
    const note = { noteId: 'self-note-0', recordId: `${depositId}-record`, noteIndex: 0, nullifier: safeNullifier('self-note-0') };
    confirmPreparedOperation(store, depositId, 5_001, { insertOwnedNote: note, height: 101 });
    assert.deepEqual(store.ownedNoteStatistics(), { total: 1, unspent: 1, spent: 0 });
    const transferId = 'self-transfer';
    const transfer = operationRequest(store, transferId, 'transfer', { selectedNoteId: note.noteId });
    prepareOperation(store, transfer);
    const replacement = { noteId: 'self-note-1', recordId: `${transferId}-record`, noteIndex: 1, nullifier: safeNullifier('self-note-1') };
    const beforeTransfer = store.canonicalState();
    confirmPreparedOperation(store, transferId, 5_002, { publicNullifier: note.nullifier, insertOwnedNote: replacement, height: 102 });
    const afterTransfer = store.canonicalState();
    assert.equal(afterTransfer.actionSequence, beforeTransfer.actionSequence + 1);
    assert.equal(store.ownedNote(note.noteId).spent, true);
    assert.equal(store.ownedNote(replacement.noteId).spent, false);
    assert.deepEqual(store.ownedNoteStatistics(), { total: 2, unspent: 1, spent: 1 });
    assert.throws(
      () => store.derivePacketPostState({ kind: 'transfer', publicNullifier: note.nullifier, outputNoteLeaf: fr(5_003n) }),
      /already exists/,
    );
    const duplicate = operationRequest(store, 'self-transfer-double-spend', 'transfer', { selectedNoteId: note.noteId });
    store.createOperation(duplicate);
    store.putFundingUtxo({ txid: duplicate.intent.funding.txid, vout: 0, valueSats: duplicate.intent.funding.valueSats });
    assert.throws(
      () => store.reserveResources({ operationId: duplicate.operationId, noteId: note.noteId, utxoTxid: duplicate.intent.funding.txid, utxoVout: 0, crashAt: null }),
      /unavailable/,
    );
    assert.equal(store.fundingUtxo({ txid: duplicate.intent.funding.txid, vout: 0 }).reservationOperationId, null);
    assertSameCanonical(store.canonicalState(), afterTransfer, 'malicious self transfer attempt must not mutate canonical tip');
    store = reopen(path, store);
    assert.equal(store.ownedNote(note.noteId).spent, true);
    assert.equal(store.ownedNote(replacement.noteId).spent, false);
    invariants.maliciousSelfTransfer += 1;
    invariants.noDoubleCommitmentOrNullifier += 1;
    invariants.noBadReservation += 1;
    return Object.freeze({ selfTarget: true, duplicateNullifierRejected: true, duplicateReservationRejected: true, reopened: true });
  } finally {
    store.close();
  }
}

export function runV2ReorgConcurrencyQualification({
  output,
  reorgDepths = REORG_DEPTHS,
  walletCounts = WALLET_COUNTS,
  deepReplayActions = 16,
} = {}) {
  if (typeof output !== 'string' || existsSync(output)) fail('output evidence path must not already exist');
  if (!Array.isArray(reorgDepths) || reorgDepths.length === 0 || reorgDepths.some((value) => !REORG_DEPTHS.includes(value))) fail('reorg depths must be a nonempty subset of the fixed Q-06 depths');
  if (!Array.isArray(walletCounts) || walletCounts.length === 0 || walletCounts.some((value) => !WALLET_COUNTS.includes(value))) fail('wallet counts must be a nonempty subset of the fixed Q-06 wallet counts');
  const base = join(tmpdir(), 'shieldkit-v2-reorg-concurrency-qualification');
  mkdirSync(base, { recursive: true, mode: 0o700 });
  const workspace = mkdtempSync(join(base, 'run-'));
  const started = performance.now();
  const invariants = {
    noNoteOrValueLoss: 0,
    noDoubleCommitmentOrNullifier: 0,
    noBadReservation: 0,
    conflictReservationRelease: 0,
    rebaseReservationReacquire: 0,
    noPrematureConfirmedCommit: 0,
    parentLoss: 0,
    conflictingSiblings: 0,
    maliciousSelfTransfer: 0,
    deepWipeRecoveryInstall: 0,
    deepWipeReplay: 0,
  };
  try {
    const reorgs = reorgDepths.map((depth) => runReorgDepth(workspace, depth, invariants));
    const contention = walletCounts.map((wallets) => runContention(workspace, wallets, invariants));
    const maliciousSelfTransfer = runMaliciousSelfTransfer(workspace, invariants);
    const deepWipeReplay = runDeepWipeReplay(workspace, invariants, deepReplayActions);
    const evidence = Object.freeze({
      schema: 'shieldkit-v2-direct-reorg-concurrency-qualification-v1',
      qualification: 'development-only-local-durability',
      seed: SEED,
      reorgDepths: reorgs,
      walletContention: contention,
      maliciousSelfTransfer,
      deepWipeReplay,
      invariantCounts: invariants,
      storage: 'node:sqlite production V2 Direct store, durable operation lifecycle, retained undo rollback, and authenticated snapshot installer',
      elapsedMs: Math.round(performance.now() - started),
      discrepancies: [],
      limitations: [
        'Deterministic local BCH transaction construction exercises store admission and durable state transitions; it is not chain broadcast, mined confirmation, a real Schnorr signature check, or a proof-system qualification.',
        'The authenticated snapshot installer validates exact materialized tree/state consistency but does not establish an external chain-authentication boundary; native recovery, live reorg observation, and clean-host qualification remain separate gates.',
        'Logical wallet contention is deterministic single-process scheduling over one SQLite database; it is not a distributed multi-device or adversarial filesystem concurrency campaign.',
      ],
    });
    mkdirSync(dirname(output), { recursive: true, mode: 0o700 });
    writeFileSync(output, `${JSON.stringify(evidence, null, 2)}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    return evidence;
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const { output } = parseV2ReorgConcurrencyQualificationArguments(process.argv.slice(2));
    const evidence = runV2ReorgConcurrencyQualification({ output });
    process.stdout.write(`${JSON.stringify({ schema: 'shieldkit-v2-direct-reorg-concurrency-qualification-command-result-v1', output, elapsedMs: evidence.elapsedMs, discrepancies: evidence.discrepancies.length })}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
    process.exitCode = 1;
  }
}
