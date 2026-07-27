import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rebuildPublicTip, mergeTipForestForAct, assertNoGlobalOpenSetGate } from './index.mjs';

const PROFILE = '11'.repeat(32);
const INSTANCE = '22'.repeat(32);
const Z = '00'.repeat(32);
// Poseidon requires canonical Fr (< BN254 r); keep high bytes zero.
const CM1 = '01'.padStart(64, '0');
const CM2 = '02'.padStart(64, '0');

function st(seq, live, cm) {
  return {
    profileId: PROFILE,
    instanceId: INSTANCE,
    noteRoot: 'aa'.repeat(32),
    nullifierRoot: 'bb'.repeat(32),
    nextLeafIndex: String(seq),
    actionSequence: String(seq),
    liveNoteCount: String(live),
    reserveSats: String(live * 10_000_000),
    maximumReserve: '160000000',
    stateCommitment: cm,
  };
}

test('multi-user tip + wallet with only my notes: act merge from wallet secrets only', async () => {
  const s0 = st(0, 0, 'c0'.repeat(32));
  const s1 = st(1, 1, 'c1'.repeat(32));
  const s2 = st(2, 2, 'c2'.repeat(32));
  const tip = rebuildPublicTip({
    initialState: s0,
    events: [
      {
        kind: 'deposit', preState: s0, postState: s1,
        outputCommitment: CM1, inputNullifier: Z, inputCommitment: Z,
      },
      {
        kind: 'deposit', preState: s1, postState: s2,
        outputCommitment: CM2, inputNullifier: Z, inputCommitment: Z,
      },
    ],
    tipNft: { stateCommitment: s2.stateCommitment, actionSequence: '2' },
  });

  assert.equal(tip.state.liveNoteCount, '2');
  assert.equal(tip.noteLeaves.length, 2);

  // Wallet note for user B only — full secrets embedded (no residual secretMeta)
  const myNotes = [{
    noteIndex: 1,
    leaf: '0a'.padStart(64, '0'),
    key1: '123',
    nfLeaf1: '0b'.padStart(64, '0'),
    note1: {
      sk: '01'.padStart(64, '0'),
      recoveryPublicKey: '02'.padStart(64, '0'),
      rho: '03'.padStart(64, '0'),
      r: '04'.padStart(64, '0'),
    },
    witnessSeed: '0e'.padStart(64, '0'),
    depositDigest: '0f'.padStart(64, '0'),
  }];

  assert.equal(assertNoGlobalOpenSetGate(myNotes.length, Number(tip.state.liveNoteCount)).ok, true);

  const forest = await mergeTipForestForAct(tip, myNotes, {});
  assert.equal(forest.schema, 'shieldkit/tip-forest/v1');
  assert.equal(forest.noteLeaves.length, 2);
  assert.notEqual(forest.noteLeaves[0], CM1);
  assert.equal(forest.openNoteMeta.length, 1);
  assert.equal(forest.openNoteMeta[0].noteIndex, 1);
  assert.equal(forest.openNoteMeta[0].witnessSeed, myNotes[0].witnessSeed);
  assert.equal(forest.openNoteMeta[0].note1.sk, myNotes[0].note1.sk);
  assert.equal(forest.openNoteMeta[0].key1, '123');
  assert.equal(forest.state.liveNoteCount, '2');
});

test('mergeTipForestForAct rejects incomplete wallet secrets', async () => {
  const s0 = st(0, 0, 'c0'.repeat(32));
  const s1 = st(1, 1, 'c1'.repeat(32));
  const tip = rebuildPublicTip({
    initialState: s0,
    events: [{
      kind: 'deposit', preState: s0, postState: s1,
      outputCommitment: CM1, inputNullifier: Z, inputCommitment: Z,
    }],
    tipNft: { stateCommitment: s1.stateCommitment, actionSequence: '1' },
  });
  await assert.rejects(
    () => mergeTipForestForAct(tip, [{
      noteIndex: 0,
      leaf: '0a'.padStart(64, '0'),
      witnessSeed: '0e'.padStart(64, '0'),
      // missing note1/key1/nfLeaf1
    }], {}),
    (e) => e.code === 'INCOMPLETE_NOTE_SECRETS',
  );
});
