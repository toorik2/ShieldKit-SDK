import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  rebuildPublicTip,
  publicTipEventFromPacket,
  emptyPublicTip,
  decodeTipNftFields,
  TipRebuildError,
  PUBLIC_TIP_SCHEMA,
} from './tip-rebuild.mjs';
import { encodeStateNftCommitment } from '../action/state.mjs';
import { NETWORK_CHIPNET } from '../action/network.mjs';

const PROFILE = '11'.repeat(32);
const INSTANCE = '22'.repeat(32);
const EMPTY_NOTE = '33'.repeat(32);
const EMPTY_NF = '44'.repeat(32);
const MAX_RES = '160000000';

function st(seq, live, reserve, cm, noteRoot = EMPTY_NOTE, nfRoot = EMPTY_NF, nextLeaf = '0') {
  return {
    profileId: PROFILE,
    instanceId: INSTANCE,
    noteRoot,
    nullifierRoot: nfRoot,
    nextLeafIndex: String(nextLeaf),
    actionSequence: String(seq),
    liveNoteCount: String(live),
    reserveSats: String(reserve),
    maximumReserve: MAX_RES,
    stateCommitment: cm,
  };
}

function depEvent(pre, post, cm) {
  return {
    kind: 'deposit',
    preState: pre,
    postState: post,
    outputCommitment: cm,
    inputNullifier: '0'.repeat(64),
    inputCommitment: '0'.repeat(64),
  };
}

function wdrEvent(pre, post, nf) {
  return {
    kind: 'withdrawal',
    preState: pre,
    postState: post,
    outputCommitment: '0'.repeat(64),
    inputNullifier: nf,
    inputCommitment: '0'.repeat(64),
  };
}

test('empty tip schema', () => {
  const tip = emptyPublicTip({
    profileId: PROFILE,
    instanceId: INSTANCE,
    maximumReserve: MAX_RES,
    emptyNoteRoot: EMPTY_NOTE,
    emptyNullifierRoot: EMPTY_NF,
  });
  assert.equal(tip.schema, PUBLIC_TIP_SCHEMA);
  assert.equal(tip.state.liveNoteCount, '0');
  assert.equal(tip.noteLeaves.length, 0);
});

test('rebuild two deposits then one withdraw; match tip NFT', () => {
  const s0 = st(0, 0, 0, 'a1'.repeat(32), EMPTY_NOTE, EMPTY_NF, 0);
  const s1 = st(1, 1, 10_000_000, 'b1'.repeat(32), 'c1'.repeat(32), EMPTY_NF, 1);
  const s2 = st(2, 2, 20_000_000, 'b2'.repeat(32), 'c2'.repeat(32), EMPTY_NF, 2);
  const s3 = st(3, 1, 10_000_000, 'b3'.repeat(32), 'c2'.repeat(32), 'd3'.repeat(32), 2);
  const cm1 = 'e1'.repeat(32);
  const cm2 = 'e2'.repeat(32);
  const nf1 = 'f1'.repeat(32);

  const tip = rebuildPublicTip({
    initialState: s0,
    events: [
      depEvent(s0, s1, cm1),
      depEvent(s1, s2, cm2),
      wdrEvent(s2, s3, nf1),
    ],
    tipNft: {
      stateCommitment: s3.stateCommitment,
      actionSequence: s3.actionSequence,
      instanceId: INSTANCE,
    },
  });

  assert.equal(tip.eventCount, 3);
  assert.equal(tip.noteLeaves.length, 2);
  assert.equal(tip.noteLeaves[0], cm1);
  assert.equal(tip.noteLeaves[1], cm2);
  assert.equal(tip.nullifierLeaves.length, 1);
  assert.equal(tip.state.liveNoteCount, '1');
  assert.equal(tip.state.actionSequence, '3');
});

test('reject truncated / discontinuous history', () => {
  const s0 = st(0, 0, 0, 'a1'.repeat(32));
  const s1 = st(1, 1, 10_000_000, 'b1'.repeat(32), 'c1'.repeat(32), EMPTY_NF, 1);
  const s2 = st(2, 2, 20_000_000, 'b2'.repeat(32), 'c2'.repeat(32), EMPTY_NF, 2);
  assert.throws(
    () => rebuildPublicTip({
      initialState: s0,
      events: [depEvent(s1, s2, 'e2'.repeat(32))], // wrong preState
    }),
    (e) => e instanceof TipRebuildError && e.code === 'STATE_CONTINUITY',
  );
});

test('reject tip NFT commitment mismatch', () => {
  const s0 = st(0, 0, 0, 'a1'.repeat(32));
  const s1 = st(1, 1, 10_000_000, 'b1'.repeat(32), 'c1'.repeat(32), EMPTY_NF, 1);
  assert.throws(
    () => rebuildPublicTip({
      initialState: s0,
      events: [depEvent(s0, s1, 'e1'.repeat(32))],
      tipNft: { stateCommitment: 'ff'.repeat(32), actionSequence: '1' },
    }),
    (e) => e instanceof TipRebuildError && e.code === 'TIP_NFT_MISMATCH',
  );
});

test('reject tip NFT sequence mismatch', () => {
  const s0 = st(0, 0, 0, 'a1'.repeat(32));
  const s1 = st(1, 1, 10_000_000, 'b1'.repeat(32), 'c1'.repeat(32), EMPTY_NF, 1);
  assert.throws(
    () => rebuildPublicTip({
      initialState: s0,
      events: [depEvent(s0, s1, 'e1'.repeat(32))],
      tipNft: { stateCommitment: s1.stateCommitment, actionSequence: '99' },
    }),
    (e) => e instanceof TipRebuildError && e.code === 'TIP_NFT_MISMATCH',
  );
});

test('decodeTipNftFields matches encodeStateNftCommitment', () => {
  const cmt = encodeStateNftCommitment({
    networkId: NETWORK_CHIPNET,
    instanceId: INSTANCE,
    stateCommitment: 'ab'.repeat(32),
    actionSequence: '7',
  });
  const fields = decodeTipNftFields(cmt);
  assert.equal(fields.instanceId, INSTANCE);
  assert.equal(fields.stateCommitment, 'ab'.repeat(32));
  assert.equal(fields.actionSequence, '7');
});

test('publicTipEventFromPacket maps deposit fields', () => {
  const pre = st(0, 0, 0, 'a1'.repeat(32));
  const post = st(1, 1, 10_000_000, 'b1'.repeat(32), 'c1'.repeat(32), EMPTY_NF, 1);
  const ev = publicTipEventFromPacket({
    kind: 'deposit',
    preState: pre,
    postState: post,
    outputCommitment: 'ee'.repeat(32),
    inputNullifier: '0'.repeat(64),
    inputCommitment: '0'.repeat(64),
  });
  assert.equal(ev.kind, 'deposit');
  assert.equal(ev.outputCommitment, 'ee'.repeat(32));
});
