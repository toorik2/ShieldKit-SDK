import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createNoteWallet,
  importEncryptedNoteWallet,
  rebuildPublicTip,
  mergeTipForestForAct,
  publicTipToWitnessForest,
} from './index.mjs';

const PROFILE = '11'.repeat(32);
const INSTANCE = '22'.repeat(32);

function st(seq, live, cm, nextLeaf = seq) {
  return {
    profileId: PROFILE,
    instanceId: INSTANCE,
    noteRoot: 'aa'.repeat(32),
    nullifierRoot: 'bb'.repeat(32),
    nextLeafIndex: String(nextLeaf),
    actionSequence: String(seq),
    liveNoteCount: String(live),
    reserveSats: String(live * 10_000_000),
    maximumReserve: '160000000',
    stateCommitment: cm,
  };
}

/** Full spend secrets (canonical Fr hex) as deposit residual would produce. */
function spendableNoteFields() {
  return {
    noteIndex: 0,
    leaf: '0a'.padStart(64, '0'), // domain-tagged tree leaf
    key1: '999',
    nfLeaf1: '0b'.padStart(64, '0'),
    note1: {
      sk: '01'.padStart(64, '0'),
      recoveryPublicKey: '02'.padStart(64, '0'),
      rho: '03'.padStart(64, '0'),
      r: '04'.padStart(64, '0'),
    },
    witnessSeed: '0e'.padStart(64, '0'),
    depositDigest: '0f'.padStart(64, '0'),
    createdSeq: '1',
  };
}

test('after backup restore + tip wipe replay, merge from restored wallet only (no residual secretMeta)', async () => {
  const s0 = st(0, 0, 'c0'.repeat(32), 0);
  const s1 = st(1, 1, 'c1'.repeat(32), 1);
  // Public packet stores raw commitment; wallet stores domain leaf separately.
  const commitment = '0d'.padStart(64, '0');
  const events = [{
    kind: 'deposit',
    preState: s0,
    postState: s1,
    outputCommitment: commitment,
    inputNullifier: '00'.repeat(32),
    inputCommitment: '00'.repeat(32),
  }];

  const owned = spendableNoteFields();

  let tip = rebuildPublicTip({
    initialState: s0,
    events,
    tipNft: { stateCommitment: s1.stateCommitment, actionSequence: '1' },
  });

  const w = createNoteWallet({ profileId: PROFILE, instanceId: INSTANCE });
  // Deposit writes full secrets into wallet (product path)
  w.addOpenNote(owned);

  const backup = w.exportEncrypted('backup-pass-9');
  // Wipe tip cache + in-memory wallet
  tip = null;
  const restored = importEncryptedNoteWallet(backup, 'backup-pass-9');
  assert.equal(restored.privateBalanceNotes(), 1);
  assert.equal(restored.listOpen()[0].note1.sk, owned.note1.sk);
  assert.equal(restored.listOpen()[0].key1, owned.key1);
  assert.equal(restored.listOpen()[0].nfLeaf1, owned.nfLeaf1);

  // Full chain-as-log replay of public events (no private residual)
  tip = rebuildPublicTip({
    initialState: s0,
    events,
    tipNft: { stateCommitment: s1.stateCommitment, actionSequence: '1' },
  });
  assert.equal(tip.noteCommitments[0], commitment);

  // Spend path: merge public tip + restored wallet ONLY — empty secretMetaByIndex
  const forest = await mergeTipForestForAct(tip, restored.listOpen(), {});
  assert.equal(forest.schema, 'shieldkit/tip-forest/v1');
  assert.equal(forest.noteLeaves.length, 1);
  assert.equal(forest.openNoteMeta.length, 1);
  assert.equal(forest.openNoteMeta[0].witnessSeed, owned.witnessSeed);
  assert.equal(forest.openNoteMeta[0].note1.sk, owned.note1.sk);
  assert.equal(forest.openNoteMeta[0].note1.rho, owned.note1.rho);
  assert.equal(forest.openNoteMeta[0].key1, owned.key1);
  assert.equal(forest.openNoteMeta[0].nfLeaf1, owned.nfLeaf1);
  assert.equal(forest.openNoteMeta[0].leaf, owned.leaf);
  assert.equal(forest.state.liveNoteCount, '1');
  assert.equal(forest.state.actionSequence, '1');

  const bare = await publicTipToWitnessForest(tip);
  assert.equal(bare.openNoteMeta.length, 0);
  assert.notEqual(bare.noteLeaves[0], commitment);
  assert.equal(Number(forest.openNoteMeta[0].noteIndex), 0);
  assert.ok(forest.openNoteMeta[0].note1?.sk, 'restored note secrets present for withdraw');
});
