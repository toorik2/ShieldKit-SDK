// Multi-note passive red-team: consensus-visible spend packets must not carry
// the spent note commitment. Drives the real transition + packet encode path.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import {
  createShieldedTransitionReference,
  DENOMINATION_SATS,
  DOMAIN_TAGS,
  frToHex,
  NULLIFIER_TREE_DEPTH,
  NOTE_TREE_DEPTH,
  OUTPUT_RECORD_BYTES,
} from './transition.mjs';
import { decodeActionPacket } from './packet.mjs';
import { rebuildPublicTip } from '../pool/tip-rebuild.mjs';
import { BABYJUB_BASE8, babyJubMul, bytesToHex, packBabyJubPoint } from '../recover/portable-core.mjs';

const digest = (text) => createHash('sha256').update(text).digest('hex');
const field = (number) => frToHex(BigInt(number));
const recoveryKey = (scalar) => bytesToHex(packBabyJubPoint(babyJubMul(BABYJUB_BASE8, BigInt(scalar))));
const ZERO32 = '0'.repeat(64);

function rootFromPath(reference, leaf, index, siblings, tag) {
  let current = leaf;
  for (let level = 0; level < siblings.length; level += 1) {
    current = ((index >> BigInt(level)) & 1n) === 0n
      ? reference.poseidon(tag, current, siblings[level])
      : reference.poseidon(tag, siblings[level], current);
  }
  return current;
}

function emptySiblings(reference, depth, emptyTag, nodeTag) {
  const siblings = [];
  let empty = reference.poseidon(emptyTag, 0n);
  for (let level = 0; level < depth; level += 1) {
    siblings.push(empty);
    empty = reference.poseidon(nodeTag, empty, empty);
  }
  return siblings;
}

/** Merkle siblings for dense note tree at `index` given contiguous leaf Fr values. */
function noteTreeSiblings(reference, leafFrs, index) {
  let empty = reference.poseidon(DOMAIN_TAGS.NOTE_TREE_EMPTY, 0n);
  let layer = new Map();
  for (let i = 0; i < leafFrs.length; i += 1) {
    if (leafFrs[i] !== undefined && leafFrs[i] !== null) layer.set(BigInt(i), leafFrs[i]);
  }
  const siblings = [];
  let idx = BigInt(index);
  for (let level = 0; level < NOTE_TREE_DEPTH; level += 1) {
    siblings.push(layer.get(idx ^ 1n) ?? empty);
    const parents = new Map();
    const parentKeys = new Set([...layer.keys()].map((entry) => (entry >> 1n).toString()));
    for (const parent of parentKeys) {
      const base = BigInt(parent) << 1n;
      parents.set(
        BigInt(parent),
        reference.poseidon(
          DOMAIN_TAGS.NOTE_TREE_NODE,
          layer.get(base) ?? empty,
          layer.get(base | 1n) ?? empty,
        ),
      );
    }
    layer = parents;
    idx >>= 1n;
    empty = reference.poseidon(DOMAIN_TAGS.NOTE_TREE_NODE, empty, empty);
  }
  return siblings;
}

function bindPublic(reference, action) {
  const prepared = reference.prepareTransition(action);
  return { ...action, publicInputs: prepared.publicInputs };
}

async function twoDepositThenSpend({ spendKind }) {
  const reference = await createShieldedTransitionReference();
  const profileId = digest(`privacy-${spendKind}-profile`);
  const instanceId = digest(`privacy-${spendKind}-instance`);
  const max = '30000000';
  const initial = reference.emptyState({ profileId, instanceId, maximumReserve: max });
  const notePathEmpty = emptySiblings(reference, NOTE_TREE_DEPTH, DOMAIN_TAGS.NOTE_TREE_EMPTY, DOMAIN_TAGS.NOTE_TREE_NODE);
  const nullifierPathEmpty = emptySiblings(reference, NULLIFIER_TREE_DEPTH, DOMAIN_TAGS.NULLIFIER_TREE_EMPTY, DOMAIN_TAGS.NULLIFIER_TREE_NODE);

  const noteA = { sk: field(101), recoveryPublicKey: recoveryKey(201), rho: field(102), r: field(103) };
  const noteB = { sk: field(111), recoveryPublicKey: recoveryKey(211), rho: field(112), r: field(113) };
  const noteC = { sk: field(121), recoveryPublicKey: recoveryKey(221), rho: field(122), r: field(123) };
  const derivedA = reference.deriveNote({ ...noteA, profileId, instanceId });
  const derivedB = reference.deriveNote({ ...noteB, profileId, instanceId });
  const derivedC = reference.deriveNote({ ...noteC, profileId, instanceId });

  const leafA = reference.poseidon(DOMAIN_TAGS.NOTE_TREE_LEAF, BigInt(`0x${derivedA.cm}`));
  const rootAfterA = frToHex(rootFromPath(reference, leafA, 0n, notePathEmpty, DOMAIN_TAGS.NOTE_TREE_NODE));
  const postA = reference.buildState({
    ...initial, noteRoot: rootAfterA, nextLeafIndex: '1', actionSequence: '1',
    liveNoteCount: '1', reserveSats: DENOMINATION_SATS.toString(),
  });
  const depositA = {
    kind: 'deposit', networkId: 2, profileId, instanceId, preState: initial, postState: postA,
    depositSats: DENOMINATION_SATS.toString(),
    outputNote: { ak: derivedA.ak, rho: noteA.rho, r: noteA.r },
    noteAppendPath: { siblings: notePathEmpty.map(frToHex) },
    outputRecord: Buffer.alloc(OUTPUT_RECORD_BYTES, 1),
    transactionContextDigest: digest(`privacy-${spendKind}-deposit-a`),
  };

  const appendForB = noteTreeSiblings(reference, [leafA], 1n);
  const leafB = reference.poseidon(DOMAIN_TAGS.NOTE_TREE_LEAF, BigInt(`0x${derivedB.cm}`));
  const rootAfterB = frToHex(rootFromPath(reference, leafB, 1n, appendForB, DOMAIN_TAGS.NOTE_TREE_NODE));
  const postB = reference.buildState({
    ...postA, noteRoot: rootAfterB, nextLeafIndex: '2', actionSequence: '2',
    liveNoteCount: '2', reserveSats: (2n * DENOMINATION_SATS).toString(),
  });
  const depositB = {
    kind: 'deposit', networkId: 2, profileId, instanceId, preState: postA, postState: postB,
    depositSats: DENOMINATION_SATS.toString(),
    outputNote: { ak: derivedB.ak, rho: noteB.rho, r: noteB.r },
    noteAppendPath: { siblings: appendForB.map(frToHex) },
    outputRecord: Buffer.alloc(OUTPUT_RECORD_BYTES, 2),
    transactionContextDigest: digest(`privacy-${spendKind}-deposit-b`),
  };

  // Membership path for note A after both deposits exist in the tree.
  const membershipA = noteTreeSiblings(reference, [leafA, leafB], 0n);
  const nfA = BigInt(`0x${derivedA.nf}`);
  const keyA = BigInt(`0x${Buffer.from(derivedA.nf, 'hex').subarray(16, 32).toString('hex')}`);
  const nfLeafA = reference.poseidon(DOMAIN_TAGS.NULLIFIER_TREE_LEAF, nfA);
  const nullRootAfter = frToHex(rootFromPath(reference, nfLeafA, keyA, nullifierPathEmpty, DOMAIN_TAGS.NULLIFIER_TREE_NODE));

  let spendAction;
  if (spendKind === 'transfer') {
    const appendForC = noteTreeSiblings(reference, [leafA, leafB], 2n);
    const leafC = reference.poseidon(DOMAIN_TAGS.NOTE_TREE_LEAF, BigInt(`0x${derivedC.cm}`));
    const rootAfterTransfer = frToHex(rootFromPath(reference, leafC, 2n, appendForC, DOMAIN_TAGS.NOTE_TREE_NODE));
    const postTransfer = reference.buildState({
      ...postB,
      noteRoot: rootAfterTransfer,
      nullifierRoot: nullRootAfter,
      nextLeafIndex: '3',
      actionSequence: '3',
      liveNoteCount: '2',
      reserveSats: (2n * DENOMINATION_SATS).toString(),
    });
    spendAction = {
      kind: 'transfer', networkId: 2, profileId, instanceId, preState: postB, postState: postTransfer,
      spend: {
        note: noteA,
        noteIndex: '0',
        noteSiblings: membershipA.map(frToHex),
        nullifierSiblings: nullifierPathEmpty.map(frToHex),
      },
      outputNote: { ak: derivedC.ak, rho: noteC.rho, r: noteC.r },
      noteAppendPath: { siblings: appendForC.map(frToHex) },
      outputRecord: Buffer.alloc(OUTPUT_RECORD_BYTES, 3),
      transactionContextDigest: digest('privacy-transfer-spend-a'),
    };
  } else {
    const postWithdraw = reference.buildState({
      ...postB,
      nullifierRoot: nullRootAfter,
      actionSequence: '3',
      liveNoteCount: '1',
      reserveSats: DENOMINATION_SATS.toString(),
    });
    spendAction = {
      kind: 'withdrawal', networkId: 2, profileId, instanceId, preState: postB, postState: postWithdraw,
      spend: {
        note: noteA,
        noteIndex: '0',
        noteSiblings: membershipA.map(frToHex),
        nullifierSiblings: nullifierPathEmpty.map(frToHex),
      },
      withdrawal: { amountSats: DENOMINATION_SATS.toString(), scriptHash: digest('privacy-wdr-script') },
      outputRecord: Buffer.alloc(OUTPUT_RECORD_BYTES),
      transactionContextDigest: digest('privacy-wdr-spend-a'),
    };
  }

  const acceptedA = reference.transition(bindPublic(reference, depositA));
  const acceptedB = reference.transition(bindPublic(reference, depositB));
  const acceptedSpend = reference.transition(bindPublic(reference, spendAction));
  return {
    reference, profileId, instanceId, initial, derivedA, derivedB, derivedC,
    acceptedA, acceptedB, acceptedSpend,
  };
}

test('multi-note transfer: passive observer cannot equality-link spent note via inputCommitment', async () => {
  const { derivedA, derivedB, acceptedA, acceptedB, acceptedSpend } = await twoDepositThenSpend({ spendKind: 'transfer' });

  const priorOutputCommitments = new Set([
    decodeActionPacket(acceptedA.actionPacket).outputCommitment,
    decodeActionPacket(acceptedB.actionPacket).outputCommitment,
  ]);
  assert.equal(priorOutputCommitments.size, 2);
  assert.ok(priorOutputCommitments.has(derivedA.cm));
  assert.ok(priorOutputCommitments.has(derivedB.cm));

  const spendPacket = decodeActionPacket(acceptedSpend.actionPacket);
  assert.equal(spendPacket.kind, 'transfer');
  assert.equal(spendPacket.inputCommitment, ZERO32);
  assert.notEqual(spendPacket.inputNullifier, ZERO32);
  assert.equal(spendPacket.inputNullifier, derivedA.nf);
  assert.notEqual(spendPacket.outputCommitment, ZERO32);

  // Pre-fix exact equality link must fail.
  assert.equal(priorOutputCommitments.has(spendPacket.inputCommitment), false);
  assert.notEqual(spendPacket.inputCommitment, derivedA.cm);
  assert.notEqual(spendPacket.inputCommitment, derivedB.cm);

  assert.equal(acceptedSpend.spentCm, derivedA.cm);
  assert.equal(acceptedSpend.inputCm, ZERO32);
});

test('multi-note withdrawal: zero inputCommitment, public nullifier, tip rebuild accepts', async () => {
  const {
    profileId, instanceId, initial, derivedA, acceptedA, acceptedB, acceptedSpend,
  } = await twoDepositThenSpend({ spendKind: 'withdrawal' });

  const prior = [
    decodeActionPacket(acceptedA.actionPacket).outputCommitment,
    decodeActionPacket(acceptedB.actionPacket).outputCommitment,
  ];
  const spend = decodeActionPacket(acceptedSpend.actionPacket);
  assert.equal(spend.kind, 'withdrawal');
  assert.equal(spend.inputCommitment, ZERO32);
  assert.equal(spend.inputNullifier, derivedA.nf);
  assert.ok(!prior.includes(spend.inputCommitment));
  assert.notEqual(spend.inputCommitment, derivedA.cm);

  const tip = rebuildPublicTip({
    initialState: initial,
    events: [
      {
        kind: 'deposit',
        preState: acceptedA.preState,
        postState: acceptedA.postState,
        outputCommitment: prior[0],
        inputNullifier: ZERO32,
        inputCommitment: ZERO32,
      },
      {
        kind: 'deposit',
        preState: acceptedB.preState,
        postState: acceptedB.postState,
        outputCommitment: prior[1],
        inputNullifier: ZERO32,
        inputCommitment: ZERO32,
      },
      {
        kind: 'withdrawal',
        preState: acceptedSpend.preState,
        postState: acceptedSpend.postState,
        outputCommitment: ZERO32,
        inputNullifier: spend.inputNullifier,
        inputCommitment: spend.inputCommitment,
      },
    ],
    tipNft: {
      stateCommitment: acceptedSpend.postState.stateCommitment,
      actionSequence: acceptedSpend.postState.actionSequence,
      instanceId,
    },
  });
  assert.equal(tip.state.liveNoteCount, '1');
  assert.equal(tip.noteCommitments.length, 2);
  assert.equal(tip.nullifierLeaves.length, 1);
  assert.equal(tip.state.profileId, profileId);
});
