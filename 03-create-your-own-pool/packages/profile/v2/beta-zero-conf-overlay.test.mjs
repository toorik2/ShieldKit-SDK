import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { serialize } from 'node:v8';

import { createDirectV2PoolModel } from '../../action/v2/transition.mjs';
import { encodeStateNftCommitment } from '../../action/v2/state.mjs';
import { append as appendNote } from '../../action/v2/note-tree.mjs';
import { materializeV2BetaZeroConfTreeMaterial } from './beta-zero-conf-material.mjs';
import {
  V2BetaZeroConfOverlayError,
  openV2BetaZeroConfOverlay,
} from './beta-zero-conf-overlay.mjs';

const bytes = (seed, size) => Uint8Array.from({ length: size }, (_, index) => (seed + index) & 0xff);
const digest = (value) => createHash('sha256').update(value).digest('hex');
const txid = (seed) => bytes(seed, 32);
const PROFILE_ID = txid(2);
const treeState = (noteCount) => {
  const model = createDirectV2PoolModel({ profileId: Buffer.from(PROFILE_ID).toString('hex'), maximumLiveNotes: '32' });
  let noteTree = model.noteTree;
  for (let index = 0; index < noteCount; index += 1) noteTree = appendNote(noteTree, BigInt(index + 1)).tree;
  const state = encodeStateNftCommitment({ ...model.state, noteRoot: noteTree.root.toString(16).padStart(64, '0'), noteCount: String(noteCount), reserveSats: String(noteCount * 10_000_000), actionSequence: String(noteCount) }, { denominationSats: '10000000' });
  return Object.freeze({ state, treeMaterial: materializeV2BetaZeroConfTreeMaterial({ maximumLiveNotes: '32', noteTree, nullifierTree: model.nullifierTree }) });
};
const material = (seed, treeMaterial) => Object.freeze({
  noteNodes: Object.freeze([{ depth: 0, nodeIndex: 0, nodeHash: bytes(seed, 32) }, { depth: 32, nodeIndex: 0, nodeHash: Buffer.from(treeState(0).state).subarray(36, 68) }]),
  noteFrontier: Object.freeze([{ depth: 0, nodeHash: bytes(seed + 1, 32) }]),
  noteLeaves: Object.freeze([]), nullifierNodes: Object.freeze([{ depth: 32, nodeIndex: 0, nodeHash: Buffer.from(treeState(0).state).subarray(68, 100) }]), nullifierLeaves: Object.freeze([]),
  records: Object.freeze([]), ownedNotes: Object.freeze([]),
  fundingUtxos: Object.freeze([{ txid: txid(seed + 2), vout: 0, valueSats: '1000', spent: false }]),
  treeMaterial,
});

async function fixture(t) {
  const directory = await mkdtemp(path.join(tmpdir(), 'shieldkit-beta-zero-conf-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const overlay = openV2BetaZeroConfOverlay({ filename: path.join(directory, 'overlay.sqlite') });
  t.after(() => overlay.close());
  const initial = treeState(0);
  // Capability issuance is exercised in the deployment module. This low-level
  // material test installs only an already-authenticated anchor fixture.
  const db = new DatabaseSync(path.join(directory, 'overlay.sqlite'));
  db.prepare(`INSERT INTO beta_zero_conf_anchor(
    singleton,profile_id,instance_id,genesis_txid,genesis_vout,initial_state,material_bytes,
    initial_state_sha256,zero_conf_evidence_sha256,status,eligibility,evicted,evicted_reason
  ) VALUES(1,?,?,?,?,?,?,?,?,?,?,0,NULL)`).run(
    Buffer.from(PROFILE_ID), Buffer.from(txid(3)), Buffer.from(txid(4)), 0, Buffer.from(initial.state),
    Buffer.from(serialize(material(10, initial.treeMaterial))), digest(initial.state), digest(bytes(5, 64)),
    'accepted-zero-conf', 'beta-single-contributor-unqualified',
  );
  db.close();
  return { overlay, initial: initial.state, filename: path.join(directory, 'overlay.sqlite') };
}

function ready(overlay, operationId, kind = 'deposit') {
  overlay.prepareBetaAction({ operationId, kind, intent: {
    target: { type: kind === 'withdrawal' ? 'withdrawal_locking_bytecode' : 'shield_address', bytes: bytes(0x70, 16) }, selectedNoteId: null,
    funding: { rawTransaction: bytes(0x71, 16), txid: txid(0x72), vout: 0, valueSats: '1000', lockingBytecode: bytes(0x73, 25), publicKey: bytes(0x02, 33) },
    changeLockingBytecode: bytes(0x74, 25), feeRateSatsPerByte: '1', maximumFeeSats: '1000', runtimeMaterialSha256: digest(bytes(0x75, 32)),
  }, actionMaterialSha256: digest(bytes(0x76, 32)), privateActionRecordSha256: digest(bytes(0x77, 32)) });
  overlay.transitionBetaAction({ operationId, to: 'proving' });
  overlay.updateBetaActionArtifacts({
    operationId, packet: bytes(1, 1), proof: bytes(2, 1), unsignedTx: bytes(3, 1),
    signedTx: bytes(4, 1), localVmEvidence: bytes(5, 1),
  });
  overlay.transitionBetaAction({ operationId, to: 'proved' });
  overlay.transitionBetaAction({ operationId, to: 'signed' });
}

test('authenticated zero-conf material exposes no fabricated confirmed metadata', async (t) => {
  const { overlay, initial, filename } = await fixture(t);
  assert.equal(typeof overlay.anchorAcceptedGenesis, 'undefined');
  const anchored = overlay.anchor();
  assert.equal(anchored.status, 'accepted-zero-conf');
  assert.equal(anchored.evicted, false);
  assert.deepEqual(Buffer.from(anchored.initialState), Buffer.from(initial));
  const optimistic = overlay.optimisticTip();
  assert.equal(optimistic.confirmed, false);
  assert.equal(optimistic.tip.actionSequence, 0);
  assert.equal(Object.hasOwn(optimistic.tip, 'height'), false);
  assert.equal(Object.hasOwn(optimistic.tip, 'blockHash'), false);
  assert.equal(overlay.optimisticMaterial().noteNodes[0].nodeHash[0], 10);
  const view = overlay.optimisticWitnessView();
  assert.equal(view.noteNode({ depth: 0, nodeIndex: 0 })[0], 10);
  assert.equal(view.fundingUtxo({ txid: txid(12), vout: 0 }).valueSats, '1000');
  const transition = overlay.optimisticTransitionView();
  assert.equal(transition.tip.actionSequence, 0);
  assert.equal(transition.noteTree.nextIndex, 0);
  assert.equal(transition.nullifierTree.nextIndex, 2);
  overlay.close();
  const reopened = openV2BetaZeroConfOverlay({ filename });
  assert.equal(reopened.optimisticTransitionView().tip.actionSequence, 0);
  reopened.close();
});

test('applies a deterministic materialized ordered overlay and exposes its next-action tip', async (t) => {
  const { overlay, initial } = await fixture(t);
  ready(overlay, 'action-1');
  const firstTree = treeState(1); const firstState = firstTree.state; const firstTxid = txid(21);
  const first = overlay.appendMempoolAction({
    operationId: 'action-1', transactionId: firstTxid,
    predecessor: { state: initial, outpoint: { txid: txid(4), vout: 0 }, actionSequence: 0 },
    successor: { state: firstState, outpoint: { txid: firstTxid, vout: 0 }, actionSequence: 1 },
    material: material(30, firstTree.treeMaterial),
  });
  assert.equal(first.tip.actionSequence, 1);
  assert.deepEqual(first.tip.outpoint.txid, firstTxid);
  assert.equal(overlay.operation('action-1').journalState, 'mempool');
  assert.equal(overlay.optimisticMaterial().noteNodes[0].nodeHash[0], 30);
  ready(overlay, 'action-2');
  const secondTxid = txid(41);
  const second = treeState(2); overlay.appendMempoolAction({
    operationId: 'action-2', transactionId: secondTxid,
    predecessor: { state: firstState, outpoint: { txid: firstTxid, vout: 0 }, actionSequence: 1 },
    successor: { state: second.state, outpoint: { txid: secondTxid, vout: 0 }, actionSequence: 2 },
    material: material(50, second.treeMaterial),
  });
  assert.equal(overlay.optimisticTip().tip.actionSequence, 2);
  assert.equal(overlay.optimisticMaterial().noteNodes[0].nodeHash[0], 50);
  assert.equal(overlay.optimisticWitnessView().noteFrontier({ depth: 0 })[0], 51);
  assert.throws(() => overlay.appendMempoolAction({
    operationId: 'action-3', transactionId: txid(51),
    predecessor: { state: initial, outpoint: { txid: txid(4), vout: 0 }, actionSequence: 0 },
    successor: { state: firstTree.state, outpoint: { txid: txid(51), vout: 0 }, actionSequence: 1 }, material: material(51, firstTree.treeMaterial),
  }), (error) => error instanceof V2BetaZeroConfOverlayError && error.code === 'ZERO_CONF_OVERLAY_SIGNED_OPERATION_REQUIRED');
});

test('reconciliation rejects non-prefix observations and evicts descendants with their material rollback', async (t) => {
  const { overlay, initial } = await fixture(t);
  ready(overlay, 'action-1'); const firstTxid = txid(21); const first = treeState(1); const firstState = first.state;
  overlay.appendMempoolAction({ operationId: 'action-1', transactionId: firstTxid, predecessor: { state: initial, outpoint: { txid: txid(4), vout: 0 }, actionSequence: 0 }, successor: { state: firstState, outpoint: { txid: firstTxid, vout: 0 }, actionSequence: 1 }, material: material(30, first.treeMaterial) });
  ready(overlay, 'action-2'); const secondTxid = txid(41);
  const second = treeState(2); overlay.appendMempoolAction({ operationId: 'action-2', transactionId: secondTxid, predecessor: { state: firstState, outpoint: { txid: firstTxid, vout: 0 }, actionSequence: 1 }, successor: { state: second.state, outpoint: { txid: secondTxid, vout: 0 }, actionSequence: 2 }, material: material(50, second.treeMaterial) });
  assert.throws(() => overlay.reconcileMempool({ anchorPresent: true, observedOperationIds: ['action-2'] }), (error) => error instanceof V2BetaZeroConfOverlayError && error.code === 'ZERO_CONF_OVERLAY_RECONCILIATION_CONFLICT');
  const reconciled = overlay.reconcileMempool({ anchorPresent: true, observedOperationIds: ['action-1'] });
  assert.equal(reconciled.tip.actionSequence, 1);
  assert.equal(overlay.operation('action-2').journalState, 'evicted');
  assert.equal(overlay.optimisticMaterial().noteNodes[0].nodeHash[0], 30);
  const evicted = overlay.reconcileMempool({ anchorPresent: false, observedOperationIds: [] });
  assert.equal(evicted.tip, null);
  assert.equal(overlay.anchor().evicted, true);
});
