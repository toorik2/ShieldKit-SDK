// Generates a non-production valid witness input for the compiling subset.
// It does not create a proof and intentionally does not claim packet parity
// with packages/core's 752-byte reference packet.
import { createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import {
  createShieldedTransitionReference, DOMAIN_TAGS, frToHex, OUTPUT_RECORD_BYTES,
} from '../../../packages/core/shielded-transition.mjs';
import { BABYJUB_BASE8, babyJubMul, bytesToHex, packBabyJubPoint } from '../../../packages/recovery/portable-core.mjs';

const output = process.argv[2];
if (!output) throw new Error('usage: generate-deposit-input.mjs OUTPUT.json');
const reference = await createShieldedTransitionReference();
const profileId = '8f153701118a339f1d1fd41f7c0c5afc4c15f505f74631a3264647f6d1f7e39b';
const instanceId = '3f5aa57b81dd8e4f8be305dbef75c5265baf9a24f0d746e75bfd49f2a990a3ff';
const toDec = (hex) => BigInt(`0x${hex}`).toString();
const limbs = (hex) => [BigInt(`0x${hex.slice(0, 32)}`).toString(), BigInt(`0x${hex.slice(32)}`).toString()];
const emptySiblings = (depth, emptyTag, nodeTag) => {
  const result = []; let empty = reference.poseidon(emptyTag, 0n);
  for (let level = 0; level < depth; level += 1) { result.push(frToHex(empty)); empty = reference.poseidon(nodeTag, empty, empty); }
  return result;
};
const pre = reference.emptyState({ profileId, instanceId, maximumReserve: '30000000' });
const outputNote = {
  sk: '000000000000000000000000000000000000000000000000000000000000000b',
  recoveryPublicKey: bytesToHex(packBabyJubPoint(babyJubMul(BABYJUB_BASE8, 31n))),
  rho: '000000000000000000000000000000000000000000000000000000000000000c',
  r: '000000000000000000000000000000000000000000000000000000000000000d',
};
const derived = reference.deriveNote({ ...outputNote, profileId, instanceId });
const appendSiblings = emptySiblings(32, DOMAIN_TAGS.NOTE_TREE_EMPTY, DOMAIN_TAGS.NOTE_TREE_NODE);
let appendedRoot = reference.poseidon(DOMAIN_TAGS.NOTE_TREE_LEAF, BigInt(`0x${derived.cm}`));
for (let level = 0; level < 32; level += 1) appendedRoot = reference.poseidon(DOMAIN_TAGS.NOTE_TREE_NODE, appendedRoot, BigInt(`0x${appendSiblings[level]}`));
const post = reference.buildState({
  ...pre, noteRoot: frToHex(appendedRoot), nextLeafIndex: '1', actionSequence: '1', liveNoteCount: '1', reserveSats: '10000000',
});
const action = {
  kind: 'deposit', networkId: 2, profileId, instanceId, preState: pre,
  postState: post, depositSats: '10000000', outputNote,
  noteAppendPath: { siblings: appendSiblings }, outputRecord: Buffer.alloc(OUTPUT_RECORD_BYTES, 1),
  transactionContextDigest: createHash('sha256').update('g1-circuit-deposit-context').digest('hex'),
};
const [profileHi, profileLo] = limbs(profileId); const [instanceHi, instanceLo] = limbs(instanceId);
const packet = Buffer.concat([
  Buffer.from([1, 2, 1, 0]), Buffer.from(profileId, 'hex'), Buffer.from(instanceId, 'hex'),
  Buffer.from(pre.noteRoot, 'hex'), Buffer.from(pre.nullifierRoot, 'hex'),
  Buffer.from(BigInt(pre.nextLeafIndex).toString(16).padStart(8, '0'), 'hex'),
  Buffer.from(BigInt(pre.actionSequence).toString(16).padStart(16, '0'), 'hex'),
  Buffer.from(BigInt(pre.liveNoteCount).toString(16).padStart(8, '0'), 'hex'),
  Buffer.from(BigInt(pre.reserveSats).toString(16).padStart(16, '0'), 'hex'),
  Buffer.from(BigInt(pre.maximumReserve).toString(16).padStart(16, '0'), 'hex'),
  Buffer.alloc(684 - 164),
]);
if (packet.length !== 684) throw new Error(`typed prefix length ${packet.length}`);
const digest = createHash('sha256').update(packet).digest();
const input = {
  publicDigestHi: BigInt(`0x${digest.subarray(0, 16).toString('hex')}`).toString(),
  publicDigestLo: BigInt(`0x${digest.subarray(16).toString('hex')}`).toString(),
  isDeposit: '1', isTransfer: '0', isWithdrawal: '0', profileHi, profileLo, instanceHi, instanceLo,
  preNoteRoot: toDec(pre.noteRoot), preNullifierRoot: toDec(pre.nullifierRoot), preNextLeafIndex: pre.nextLeafIndex,
  preActionSequence: pre.actionSequence, preLiveNoteCount: pre.liveNoteCount, preReserveSats: pre.reserveSats,
  preMaximumReserve: pre.maximumReserve, preStateCommitment: toDec(pre.stateCommitment),
  postNoteRoot: toDec(post.noteRoot), postNullifierRoot: toDec(post.nullifierRoot), postNextLeafIndex: post.nextLeafIndex,
  postActionSequence: post.actionSequence, postLiveNoteCount: post.liveNoteCount, postReserveSats: post.reserveSats,
  postMaximumReserve: post.maximumReserve, postStateCommitment: toDec(post.stateCommitment), maximumLiveNotes: '3',
  inSk: '0', inRho: '0', inR: '0', inputAk: '0', inputCm: '0', inputNf: '0', inputViewX: '0', inputViewY: '0',
  outputAk: toDec(derived.ak), outputRho: toDec(derived.rho), outputR: toDec(derived.r), outputCm: toDec(derived.cm),
  appendSiblings: appendSiblings.map(toDec), noteSiblings: Array(32).fill('0'), noteIndex: '0', nullifierSiblings: Array(128).fill('0'),
  boundaryAmount: '10000000', withdrawalScriptHi: '0', withdrawalScriptLo: '0',
  recordBits: Array.from(Buffer.alloc(OUTPUT_RECORD_BYTES, 1), (byte) => Array.from({ length: 8 }, (_, bit) => String((byte >> (7 - bit)) & 1))).flat(),
  transactionContextHi: BigInt(`0x${action.transactionContextDigest.slice(0, 32)}`).toString(),
  transactionContextLo: BigInt(`0x${action.transactionContextDigest.slice(32)}`).toString(),
};
await writeFile(output, `${JSON.stringify(input)}\n`);
console.log(JSON.stringify({ output, digest: digest.toString('hex'), packetBytes: packet.length, postStateCommitment: post.stateCommitment }));
