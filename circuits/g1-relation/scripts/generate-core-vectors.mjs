// Non-production witness-input generator. Core is authoritative for the exact
// 752-byte packet; this script asserts the checked-in JS vectors before writing.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import {
  createShieldedTransitionReference, DOMAIN_TAGS, frToHex, OUTPUT_RECORD_BYTES,
} from '../../../packages/core/shielded-transition.mjs';
import vectors from '../../../packages/core/vectors/g1-relation-v1.json' with { type: 'json' };

const target = process.argv[2];
if (!target) throw new Error('usage: generate-core-vectors.mjs OUTPUT_DIRECTORY');
const reference = await createShieldedTransitionReference();
const { profileId, instanceId } = vectors.fixture;
const D = '10000000';
const toDec = (hex) => BigInt(`0x${hex}`).toString();
const idLimbs = (hex) => [BigInt(`0x${hex.slice(0, 32)}`).toString(), BigInt(`0x${hex.slice(32)}`).toString()];
const digest = (text) => createHash('sha256').update(text).digest('hex');
const emptySiblings = (depth, emptyTag, nodeTag) => {
  const result = []; let empty = reference.poseidon(emptyTag, 0n);
  for (let level = 0; level < depth; level += 1) { result.push(frToHex(empty)); empty = reference.poseidon(nodeTag, empty, empty); }
  return result;
};
const root = (leaf, index, siblings, tag) => {
  let current = leaf;
  for (let level = 0; level < siblings.length; level += 1) current = ((index >> BigInt(level)) & 1n) === 0n ? reference.poseidon(tag, current, BigInt(`0x${siblings[level]}`)) : reference.poseidon(tag, BigInt(`0x${siblings[level]}`), current);
  return current;
};
const notePathEmpty = emptySiblings(32, DOMAIN_TAGS.NOTE_TREE_EMPTY, DOMAIN_TAGS.NOTE_TREE_NODE);
const nullifierPathEmpty = emptySiblings(128, DOMAIN_TAGS.NULLIFIER_TREE_EMPTY, DOMAIN_TAGS.NULLIFIER_TREE_NODE);
const note1 = { sk: '000000000000000000000000000000000000000000000000000000000000000b', rho: '000000000000000000000000000000000000000000000000000000000000000c', r: '000000000000000000000000000000000000000000000000000000000000000d' };
const note2 = { sk: '0000000000000000000000000000000000000000000000000000000000000015', rho: '0000000000000000000000000000000000000000000000000000000000000016', r: '0000000000000000000000000000000000000000000000000000000000000017' };
const derived1 = reference.deriveNote({ ...note1, profileId, instanceId });
const derived2 = reference.deriveNote({ ...note2, profileId, instanceId });
const initial = reference.emptyState({ profileId, instanceId, maximumReserve: '30000000' });
const leaf1 = reference.poseidon(DOMAIN_TAGS.NOTE_TREE_LEAF, BigInt(`0x${derived1.cm}`));
const depositPost = reference.buildState({ ...initial, noteRoot: frToHex(root(leaf1, 0n, notePathEmpty, DOMAIN_TAGS.NOTE_TREE_NODE)), nextLeafIndex: '1', actionSequence: '1', liveNoteCount: '1', reserveSats: D });
const deposit = { kind: 'deposit', networkId: 2, profileId, instanceId, preState: initial, postState: depositPost, depositSats: D, outputNote: { ak: derived1.ak, rho: note1.rho, r: note1.r }, noteAppendPath: { siblings: notePathEmpty }, outputRecord: Buffer.alloc(OUTPUT_RECORD_BYTES, 1), transactionContextDigest: digest('deposit-context') };
const appendIndex1 = [frToHex(leaf1), ...notePathEmpty.slice(1)];
const leaf2 = reference.poseidon(DOMAIN_TAGS.NOTE_TREE_LEAF, BigInt(`0x${derived2.cm}`));
const nf1 = BigInt(`0x${derived1.nf}`); const key1 = BigInt(`0x${Buffer.from(derived1.nf, 'hex').subarray(16, 32).toString('hex')}`);
const nullLeaf1 = reference.poseidon(DOMAIN_TAGS.NULLIFIER_TREE_LEAF, nf1);
const transferPost = reference.buildState({ ...depositPost, noteRoot: frToHex(root(leaf2, 1n, appendIndex1, DOMAIN_TAGS.NOTE_TREE_NODE)), nullifierRoot: frToHex(root(nullLeaf1, key1, nullifierPathEmpty, DOMAIN_TAGS.NULLIFIER_TREE_NODE)), nextLeafIndex: '2', actionSequence: '2' });
const transfer = { kind: 'transfer', networkId: 2, profileId, instanceId, preState: depositPost, postState: transferPost, spend: { note: note1, noteIndex: '0', noteSiblings: notePathEmpty, nullifierSiblings: nullifierPathEmpty }, outputNote: { ak: derived2.ak, rho: note2.rho, r: note2.r }, noteAppendPath: { siblings: appendIndex1 }, outputRecord: Buffer.alloc(OUTPUT_RECORD_BYTES, 2), transactionContextDigest: digest('transfer-context') };
const withdrawalPost = reference.buildState({ ...depositPost, nullifierRoot: frToHex(root(nullLeaf1, key1, nullifierPathEmpty, DOMAIN_TAGS.NULLIFIER_TREE_NODE)), actionSequence: '2', liveNoteCount: '0', reserveSats: '0' });
const withdrawal = { kind: 'withdrawal', networkId: 2, profileId, instanceId, preState: depositPost, postState: withdrawalPost, spend: { note: note1, noteIndex: '0', noteSiblings: notePathEmpty, nullifierSiblings: nullifierPathEmpty }, withdrawal: { amountSats: D, scriptHash: digest('withdrawal-script') }, outputRecord: Buffer.alloc(OUTPUT_RECORD_BYTES), transactionContextDigest: digest('withdrawal-context') };
const prepared = Object.fromEntries(Object.entries({ deposit, transfer, withdrawal }).map(([kind, action]) => [kind, reference.prepareTransition(action)]));
for (const [kind, result] of Object.entries(prepared)) {
  assert.equal(result.actionDigest, vectors.actions[kind].digest, `${kind} SHA-256 vector drift`);
  assert.deepEqual(result.publicInputs, vectors.actions[kind].publicInputs, `${kind} public limb vector drift`);
}
const zero = '0';
const recordBits = (record) => Array.from(record, (byte) => Array.from({ length: 8 }, (_, bit) => String((byte >> (7 - bit)) & 1))).flat();
const inputFor = (kind, action, result) => {
  const pre = result.preState; const post = result.postState;
  const [profileHi, profileLo] = idLimbs(profileId); const [instanceHi, instanceLo] = idLimbs(instanceId);
  const spend = action.spend ? reference.deriveNote({ ...action.spend.note, profileId, instanceId }) : null;
  const output = action.outputNote ? reference.deriveOutputNote({ ...action.outputNote, profileId, instanceId }) : null;
  const withdrawalBoundary = action.withdrawal;
  return {
    publicDigestHi: BigInt(`0x${result.publicInputs[0]}`).toString(), publicDigestLo: BigInt(`0x${result.publicInputs[1]}`).toString(),
    isDeposit: kind === 'deposit' ? '1' : '0', isTransfer: kind === 'transfer' ? '1' : '0', isWithdrawal: kind === 'withdrawal' ? '1' : '0', profileHi, profileLo, instanceHi, instanceLo,
    preNoteRoot: toDec(pre.noteRoot), preNullifierRoot: toDec(pre.nullifierRoot), preNextLeafIndex: pre.nextLeafIndex, preActionSequence: pre.actionSequence, preLiveNoteCount: pre.liveNoteCount, preReserveSats: pre.reserveSats, preMaximumReserve: pre.maximumReserve, preStateCommitment: toDec(pre.stateCommitment),
    postNoteRoot: toDec(post.noteRoot), postNullifierRoot: toDec(post.nullifierRoot), postNextLeafIndex: post.nextLeafIndex, postActionSequence: post.actionSequence, postLiveNoteCount: post.liveNoteCount, postReserveSats: post.reserveSats, postMaximumReserve: post.maximumReserve, postStateCommitment: toDec(post.stateCommitment), maximumLiveNotes: '3',
    inSk: spend ? toDec(spend.sk) : zero, inRho: spend ? toDec(spend.rho) : zero, inR: spend ? toDec(spend.r) : zero, inputAk: spend ? toDec(spend.ak) : zero, inputCm: spend ? toDec(spend.cm) : zero, inputNf: spend ? toDec(spend.nf) : zero,
    outputAk: output ? toDec(output.ak) : zero, outputRho: output ? toDec(output.rho) : zero, outputR: output ? toDec(output.r) : zero, outputCm: output ? toDec(output.cm) : zero,
    appendSiblings: (action.noteAppendPath?.siblings ?? Array(32).fill('0')).map(toDec), noteSiblings: (action.spend?.noteSiblings ?? Array(32).fill('0')).map(toDec), noteIndex: action.spend?.noteIndex ?? zero, nullifierSiblings: (action.spend?.nullifierSiblings ?? Array(128).fill('0')).map(toDec),
    boundaryAmount: kind === 'transfer' ? zero : D, withdrawalScriptHi: withdrawalBoundary ? idLimbs(withdrawalBoundary.scriptHash)[0] : zero, withdrawalScriptLo: withdrawalBoundary ? idLimbs(withdrawalBoundary.scriptHash)[1] : zero,
    recordBits: recordBits(action.outputRecord), transactionContextHi: idLimbs(action.transactionContextDigest)[0], transactionContextLo: idLimbs(action.transactionContextDigest)[1],
  };
};
await mkdir(target, { recursive: true });
for (const [kind, action] of Object.entries({ deposit, transfer, withdrawal })) await writeFile(path.join(target, `${kind}.json`), `${JSON.stringify(inputFor(kind, action, prepared[kind]))}\n`);
await writeFile(path.join(target, 'summary.json'), `${JSON.stringify(Object.fromEntries(Object.entries(prepared).map(([kind, result]) => [kind, { digest: result.actionDigest, publicInputs: result.publicInputs, packetBytes: result.actionPacket.length }])))}\n`);
console.log(JSON.stringify({ target, actions: Object.keys(prepared), packetBytes: 752 }));
