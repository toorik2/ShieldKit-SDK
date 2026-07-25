// Deterministic G1 relation-reference tests. These are not circuit, proof,
// BCH VM, relay, or production-qualification evidence.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  createShieldedTransitionReference, DENOMINATION_SATS, DOMAIN_TAGS, FR_MODULUS,
  frToHex, MAX_BCH_SUPPLY_SATS, NULLIFIER_TREE_DEPTH, NOTE_TREE_DEPTH, OUTPUT_RECORD_BYTES,
  RelationValidationError,
} from './transition.mjs';
import { BABYJUB_BASE8, babyJubMul, bytesToHex, packBabyJubPoint } from '../recover/portable-core.mjs';

const digest = (text) => createHash('sha256').update(text).digest('hex');
const field = (number) => frToHex(BigInt(number));
const recoveryKey = (scalar) => bytesToHex(packBabyJubPoint(babyJubMul(BABYJUB_BASE8, BigInt(scalar))));
const vectors = JSON.parse(readFileSync(new URL('./vectors/g1-relation-v2.json', import.meta.url)));

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

function bindPublic(reference, action) {
  const prepared = reference.prepareTransition(action);
  return { ...action, publicInputs: prepared.publicInputs };
}

async function fixture() {
  const reference = await createShieldedTransitionReference();
  const profileId = digest('g1-reference-profile'); const instanceId = digest('g1-reference-instance');
  assert.equal(profileId, vectors.fixture.profileId); assert.equal(instanceId, vectors.fixture.instanceId);
  const max = '30000000';
  const initial = reference.emptyState({ profileId, instanceId, maximumReserve: max });
  const notePathEmpty = emptySiblings(reference, NOTE_TREE_DEPTH, DOMAIN_TAGS.NOTE_TREE_EMPTY, DOMAIN_TAGS.NOTE_TREE_NODE);
  const nullifierPathEmpty = emptySiblings(reference, NULLIFIER_TREE_DEPTH, DOMAIN_TAGS.NULLIFIER_TREE_EMPTY, DOMAIN_TAGS.NULLIFIER_TREE_NODE);
  const note1 = { sk: field(11), recoveryPublicKey: recoveryKey(31), rho: field(12), r: field(13) };
  const note2 = { sk: field(21), recoveryPublicKey: recoveryKey(41), rho: field(22), r: field(23) };
  const derived1 = reference.deriveNote({ ...note1, profileId, instanceId });
  const derived2 = reference.deriveNote({ ...note2, profileId, instanceId });
  const leaf1 = reference.poseidon(DOMAIN_TAGS.NOTE_TREE_LEAF, BigInt(`0x${derived1.cm}`));
  const rootAfterDeposit = frToHex(rootFromPath(reference, leaf1, 0n, notePathEmpty, DOMAIN_TAGS.NOTE_TREE_NODE));
  const depositPost = reference.buildState({ ...initial, noteRoot: rootAfterDeposit, nextLeafIndex: '1', actionSequence: '1', liveNoteCount: '1', reserveSats: DENOMINATION_SATS.toString() });
  const deposit = {
    kind: 'deposit', networkId: 2, profileId, instanceId, preState: initial, postState: depositPost,
    depositSats: DENOMINATION_SATS.toString(), outputNote: { ak: derived1.ak, rho: note1.rho, r: note1.r }, noteAppendPath: { siblings: notePathEmpty.map(frToHex) },
    outputRecord: Buffer.alloc(OUTPUT_RECORD_BYTES, 1), transactionContextDigest: digest('deposit-context'),
  };
  const appendForIndex1 = [leaf1, ...notePathEmpty.slice(1)];
  const leaf2 = reference.poseidon(DOMAIN_TAGS.NOTE_TREE_LEAF, BigInt(`0x${derived2.cm}`));
  const rootAfterTransfer = frToHex(rootFromPath(reference, leaf2, 1n, appendForIndex1, DOMAIN_TAGS.NOTE_TREE_NODE));
  const nf1 = BigInt(`0x${derived1.nf}`); const key1 = BigInt(`0x${Buffer.from(derived1.nf, 'hex').subarray(16, 32).toString('hex')}`);
  const nfLeaf1 = reference.poseidon(DOMAIN_TAGS.NULLIFIER_TREE_LEAF, nf1);
  const nullRootAfterFirstSpend = frToHex(rootFromPath(reference, nfLeaf1, key1, nullifierPathEmpty, DOMAIN_TAGS.NULLIFIER_TREE_NODE));
  const transferPost = reference.buildState({ ...depositPost, noteRoot: rootAfterTransfer, nullifierRoot: nullRootAfterFirstSpend, nextLeafIndex: '2', actionSequence: '2' });
  const transfer = {
    kind: 'transfer', networkId: 2, profileId, instanceId, preState: depositPost, postState: transferPost,
    spend: { note: note1, noteIndex: '0', noteSiblings: notePathEmpty.map(frToHex), nullifierSiblings: nullifierPathEmpty.map(frToHex) },
    outputNote: { ak: derived2.ak, rho: note2.rho, r: note2.r }, noteAppendPath: { siblings: appendForIndex1.map(frToHex) }, outputRecord: Buffer.alloc(OUTPUT_RECORD_BYTES, 2), transactionContextDigest: digest('transfer-context'),
  };
  const withdrawalPost = reference.buildState({ ...depositPost, nullifierRoot: nullRootAfterFirstSpend, actionSequence: '2', liveNoteCount: '0', reserveSats: '0' });
  const withdrawal = {
    kind: 'withdrawal', networkId: 2, profileId, instanceId, preState: depositPost, postState: withdrawalPost,
    spend: { note: note1, noteIndex: '0', noteSiblings: notePathEmpty.map(frToHex), nullifierSiblings: nullifierPathEmpty.map(frToHex) },
    withdrawal: { amountSats: DENOMINATION_SATS.toString(), scriptHash: digest('withdrawal-script') }, outputRecord: Buffer.alloc(OUTPUT_RECORD_BYTES), transactionContextDigest: digest('withdrawal-context'),
  };
  return { reference, profileId, instanceId, initial, deposit, transfer, withdrawal, depositPost, transferPost, withdrawalPost };
}

test('real circomlibjs Poseidon reference executes deterministic deposit, transfer, and withdrawal vectors', async () => {
  const { reference, initial, deposit, transfer, withdrawal } = await fixture();
  const acceptedDeposit = reference.transition(bindPublic(reference, deposit));
  const acceptedTransfer = reference.transition(bindPublic(reference, transfer));
  const acceptedWithdrawal = reference.transition(bindPublic(reference, withdrawal));
  for (const [name, accepted] of Object.entries({ deposit: acceptedDeposit, transfer: acceptedTransfer, withdrawal: acceptedWithdrawal })) {
    assert.equal(accepted.actionDigest, vectors.actions[name].digest);
    assert.deepEqual(accepted.publicInputs, vectors.actions[name].publicInputs);
    assert.equal(accepted.postState.stateCommitment, vectors.actions[name].stateCommitment);
  }
  assert.equal(acceptedDeposit.postState.reserveSats, '10000000');
  assert.equal(acceptedTransfer.postState.liveNoteCount, '1');
  assert.equal(acceptedWithdrawal.postState.reserveSats, '0');
  assert.equal(acceptedWithdrawal.postState.noteRoot, acceptedDeposit.postState.noteRoot);
  assert.equal(initial.noteRoot, reference.emptyNoteRoot);
  assert.deepEqual(acceptedDeposit.publicInputs.map((value) => value.length), [64, 64]);
  assert.equal(reference.stateNftCommitment({ networkId: 2, instanceId: initial.instanceId, stateCommitment: acceptedWithdrawal.postState.stateCommitment, actionSequence: '3' }).length, 80);
});

test('reference fails closed on field codecs, paths, membership/nullifier reuse, state deltas, identifiers, capacity, and digest limbs', async () => {
  const { reference, profileId, instanceId, initial, deposit, transfer, withdrawal, depositPost, transferPost, withdrawalPost } = await fixture();
  assert.throws(() => reference.deriveNote({ profileId, instanceId, sk: FR_MODULUS.toString(16), recoveryPublicKey: recoveryKey(1), rho: field(1), r: field(2) }), /noncanonical Fr encoding/);
  const badPath = { ...deposit, noteAppendPath: { siblings: [...deposit.noteAppendPath.siblings] } }; badPath.noteAppendPath.siblings[0] = field(7);
  await assert.rejects(async () => reference.transition(bindPublic(reference, badPath)), RelationValidationError);
  const wrongMembership = { ...transfer, spend: { ...transfer.spend, note: { ...transfer.spend.note, rho: field(99) } } };
  await assert.rejects(async () => reference.transition(bindPublic(reference, wrongMembership)), /input note membership path is invalid/);
  const repeatedNullifier = { ...withdrawal, preState: withdrawalPost, postState: withdrawalPost };
  await assert.rejects(async () => reference.transition(bindPublic(reference, repeatedNullifier)), /nullifier is duplicate or collides/);
  const wrongReserve = { ...deposit, postState: { ...depositPost, reserveSats: '0' } };
  await assert.rejects(async () => reference.transition(bindPublic(reference, wrongReserve)), /reserve does not equal/);
  const wrongIndex = { ...deposit, postState: reference.buildState({ ...depositPost, nextLeafIndex: '0' }) };
  await assert.rejects(async () => reference.transition(bindPublic(reference, wrongIndex)), /post-state mismatch: nextLeafIndex/);
  const wrongSequence = { ...deposit, postState: reference.buildState({ ...depositPost, actionSequence: '2' }) };
  await assert.rejects(async () => reference.transition(bindPublic(reference, wrongSequence)), /post-state mismatch: actionSequence/);
  const wrongId = { ...deposit, profileId: digest('wrong-profile') };
  await assert.rejects(async () => reference.transition(bindPublic(reference, wrongId)), /identifiers do not match/);
  const exhaustedPre = reference.buildState({ ...initial, nextLeafIndex: '4294967295' });
  const exhausted = { ...deposit, preState: exhaustedPre };
  await assert.rejects(
    async () => reference.prepareTransition(exhausted),
    /note tree has no representable successor index/,
  );
  assert.throws(
    () => reference.emptyState({ profileId, instanceId, maximumReserve: '0' }),
    /maximum reserve must be a nonzero denomination multiple within BCH supply/,
  );
  assert.throws(
    () => reference.emptyState({ profileId, instanceId, maximumReserve: '10000001' }),
    /maximum reserve must be a nonzero denomination multiple within BCH supply/,
  );
  assert.throws(
    () => reference.emptyState({
      profileId,
      instanceId,
      maximumReserve: (MAX_BCH_SUPPLY_SATS + DENOMINATION_SATS).toString(),
    }),
    /maximum reserve must be a nonzero denomination multiple within BCH supply/,
  );
  const boundDeposit = bindPublic(reference, deposit); const wrongLimbs = { ...boundDeposit, publicInputs: [...boundDeposit.publicInputs] }; wrongLimbs.publicInputs[0] = field(0);
  assert.throws(() => reference.transition(wrongLimbs), /public SHA-256 digest limbs mismatch/);
  assert.equal(initial.actionSequence, '0');
});
