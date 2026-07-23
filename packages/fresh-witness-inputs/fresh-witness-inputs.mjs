// Typed, local witness material for the pinned low128 G1 relation. This is
// deliberately profile-bound and does not initialize setup, make proofs, or
// construct BCH transactions.
import { createHash } from 'node:crypto';
import {
  DENOMINATION_SATS, DOMAIN_TAGS, NULLIFIER_TREE_DEPTH, NOTE_TREE_DEPTH,
  OUTPUT_RECORD_BYTES, createShieldedTransitionReference, frToHex,
} from '../core/shielded-transition.mjs';
import { loadVerifierProfileBundle } from '../core/verifier-profile.mjs';
import { constructRecipientOutput, deriveRecipientWallet } from '../recovery/recovery.mjs';

const HEX_32 = /^[0-9a-f]{64}$/;
const KINDS = Object.freeze(['deposit', 'transfer', 'withdrawal']);

export class FreshWitnessInputsError extends Error {
  constructor(message) { super(message); this.name = 'FreshWitnessInputsError'; }
}
const fail = (message) => { throw new FreshWitnessInputsError(message); };
const hex32 = (value, label) => {
  if (typeof value !== 'string' || !HEX_32.test(value)) fail(`${label} must be 32 lowercase hexadecimal bytes`);
  return value;
};
const exactKeys = (value, label, expected) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`);
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail(`${label} has missing or unknown properties`);
};
const idHex = (value, label) => {
  if (typeof value !== 'string' || !value.startsWith('sha256:')) fail(`${label} must be a sha256 identifier`);
  return hex32(value.slice('sha256:'.length), label);
};
const toDec = (hex) => BigInt(`0x${hex}`).toString();
const idLimbs = (hex) => [BigInt(`0x${hex.slice(0, 32)}`).toString(), BigInt(`0x${hex.slice(32)}`).toString()];
const recordBits = (record) => Array.from(record, (byte) => Array.from({ length: 8 }, (_, bit) => String((byte >> (7 - bit)) & 1))).flat();
const sha256 = (...parts) => {
  const hash = createHash('sha256'); for (const part of parts) hash.update(part); return hash.digest();
};

function deterministicRng(seed, label) {
  let counter = 0;
  return Object.freeze({ bytes(length) {
    const chunks = [];
    while (Buffer.concat(chunks).length < length) {
      const count = Buffer.alloc(4); count.writeUInt32BE(counter++);
      chunks.push(sha256(Buffer.from('shield.cash/fresh-witness-rng/v1\\0', 'utf8'), seed, Buffer.from(label, 'utf8'), count));
    }
    return Buffer.concat(chunks).subarray(0, length);
  } });
}

function emptySiblings(reference, depth, emptyTag, nodeTag) {
  const siblings = []; let empty = reference.poseidon(emptyTag, 0n);
  for (let level = 0; level < depth; level += 1) { siblings.push(frToHex(empty)); empty = reference.poseidon(nodeTag, empty, empty); }
  return siblings;
}
function rootFromPath(reference, leaf, index, siblings, tag) {
  let current = leaf;
  for (let level = 0; level < siblings.length; level += 1) {
    const sibling = BigInt(`0x${siblings[level]}`);
    current = ((index >> BigInt(level)) & 1n) === 0n ? reference.poseidon(tag, current, sibling) : reference.poseidon(tag, sibling, current);
  }
  return current;
}
/** Return the pre-insertion sparse path for `target`, where `leaves` is a map of occupied u128 keys to Fr leaves. */
function sparsePath(reference, target, leaves) {
  let nodes = new Map(leaves); let key = target; const siblings = [];
  let empty = reference.poseidon(DOMAIN_TAGS.NULLIFIER_TREE_EMPTY, 0n);
  for (let level = 0; level < NULLIFIER_TREE_DEPTH; level += 1) {
    siblings.push(frToHex(nodes.get((key ^ 1n).toString()) ?? empty));
    const parents = new Map(); const parentKeys = new Set([...nodes.keys()].map((entry) => (BigInt(entry) >> 1n).toString()));
    for (const parent of parentKeys) {
      const base = BigInt(parent) << 1n;
      parents.set(parent, reference.poseidon(DOMAIN_TAGS.NULLIFIER_TREE_NODE, nodes.get(base.toString()) ?? empty, nodes.get((base | 1n).toString()) ?? empty));
    }
    nodes = parents; key >>= 1n; empty = reference.poseidon(DOMAIN_TAGS.NULLIFIER_TREE_NODE, empty, empty);
  }
  return siblings;
}
function noteKey(note) { return BigInt(`0x${Buffer.from(note.nf, 'hex').subarray(16).toString('hex')}`); }
function circuitInput({ kind, action, prepared, reference, maximumLiveNotes, recoveryEphemeralScalar = '0' }) {
  const pre = prepared.preState; const post = prepared.postState; const profileId = pre.profileId; const instanceId = pre.instanceId;
  const spend = action.spend ? reference.deriveNote({ ...action.spend.note, profileId, instanceId }) : undefined;
  const output = action.outputNote ? reference.deriveOutputNote({ ...action.outputNote, profileId, instanceId }) : undefined;
  const zero = '0'; const withdrawal = action.withdrawal;
  return Object.freeze({
    publicDigestHi: BigInt(`0x${prepared.publicInputs[0]}`).toString(), publicDigestLo: BigInt(`0x${prepared.publicInputs[1]}`).toString(),
    isDeposit: kind === 'deposit' ? '1' : '0', isTransfer: kind === 'transfer' ? '1' : '0', isWithdrawal: kind === 'withdrawal' ? '1' : '0',
    profileHi: idLimbs(profileId)[0], profileLo: idLimbs(profileId)[1], instanceHi: idLimbs(instanceId)[0], instanceLo: idLimbs(instanceId)[1],
    preNoteRoot: toDec(pre.noteRoot), preNullifierRoot: toDec(pre.nullifierRoot), preNextLeafIndex: pre.nextLeafIndex, preActionSequence: pre.actionSequence, preLiveNoteCount: pre.liveNoteCount, preReserveSats: pre.reserveSats, preMaximumReserve: pre.maximumReserve, preStateCommitment: toDec(pre.stateCommitment),
    postNoteRoot: toDec(post.noteRoot), postNullifierRoot: toDec(post.nullifierRoot), postNextLeafIndex: post.nextLeafIndex, postActionSequence: post.actionSequence, postLiveNoteCount: post.liveNoteCount, postReserveSats: post.reserveSats, postMaximumReserve: post.maximumReserve, postStateCommitment: toDec(post.stateCommitment), maximumLiveNotes: maximumLiveNotes.toString(),
    inSk: spend ? toDec(spend.sk) : zero, inRho: spend ? toDec(spend.rho) : zero, inR: spend ? toDec(spend.r) : zero, inputAk: spend ? toDec(spend.ak) : zero, inputCm: spend ? toDec(spend.cm) : zero, inputNf: spend ? toDec(spend.nf) : zero,
    outputAk: output ? toDec(output.ak) : zero, outputRho: output ? toDec(output.rho) : zero, outputR: output ? toDec(output.r) : zero, outputCm: output ? toDec(output.cm) : zero,
    appendSiblings: (action.noteAppendPath?.siblings ?? Array(NOTE_TREE_DEPTH).fill('0'.repeat(64))).map(toDec), noteSiblings: (action.spend?.noteSiblings ?? Array(NOTE_TREE_DEPTH).fill('0'.repeat(64))).map(toDec), noteIndex: action.spend?.noteIndex ?? zero, nullifierSiblings: (action.spend?.nullifierSiblings ?? Array(NULLIFIER_TREE_DEPTH).fill('0'.repeat(64))).map(toDec),
    boundaryAmount: kind === 'transfer' ? zero : DENOMINATION_SATS.toString(), withdrawalScriptHi: withdrawal ? idLimbs(withdrawal.scriptHash)[0] : zero, withdrawalScriptLo: withdrawal ? idLimbs(withdrawal.scriptHash)[1] : zero,
    recordBits: recordBits(action.outputRecord), recoveryEphemeralScalar, transactionContextHi: idLimbs(action.transactionContextDigest)[0], transactionContextLo: idLimbs(action.transactionContextDigest)[1],
  });
}

/**
 * Generate a valid, deterministic three-action chain for one authenticated
 * development-only bundle. `transactionContextDigests` are supplied by the
 * fixed-point settlement builder and are never fabricated here.
 */
export async function generateFreshWitnessInputs(input) {
  exactKeys(input, 'fresh witness input', ['bundleDirectory', 'expectedProfile', 'transactionContextDigests', 'withdrawalScriptHash', 'witnessSeed']);
  if (typeof input.bundleDirectory !== 'string' || input.bundleDirectory.length === 0) fail('bundleDirectory must be non-empty');
  exactKeys(input.expectedProfile, 'expectedProfile', ['instanceId', 'network', 'profileId']);
  if (input.expectedProfile.network !== 'chipnet') fail('expectedProfile network must be chipnet');
  idHex(input.expectedProfile.profileId, 'expectedProfile profileId'); idHex(input.expectedProfile.instanceId, 'expectedProfile instanceId');
  exactKeys(input.transactionContextDigests, 'transactionContextDigests', KINDS);
  for (const kind of KINDS) hex32(input.transactionContextDigests[kind], `${kind} transactionContextDigest`);
  hex32(input.withdrawalScriptHash, 'withdrawalScriptHash'); hex32(input.witnessSeed, 'witnessSeed');
  const bundle = await loadVerifierProfileBundle(input.bundleDirectory, input.expectedProfile);
  if (bundle.manifest.setup.mode !== 'development-only' || bundle.manifest.setup.provenance.method !== 'local-initialization') fail('fresh witness pipeline accepts only authenticated development-only local profiles');
  if (bundle.manifest.network.name !== 'chipnet' || bundle.manifest.profile.relation.id !== 'shielded-action-v1' || bundle.manifest.profile.publicInputAbi.id !== 'shielded-action-public-input-v1') fail('bundle does not select the pinned Chipnet low128 relation ABI');
  const profileId = idHex(bundle.profileId, 'bundle profileId'); const instanceId = idHex(bundle.instanceId, 'bundle instanceId'); const maximumReserve = bundle.manifest.genesis.reserveCapSatoshis;
  const maximumLiveNotes = BigInt(maximumReserve) / DENOMINATION_SATS;
  const reference = await createShieldedTransitionReference(); const seed = Buffer.from(input.witnessSeed, 'hex');
  // The deterministic chain uses two separately domain-derived local wallets,
  // exercising the same public-recipient path as a cross-wallet sender.
  const recipient1Seed = sha256(Buffer.from('shield.cash/fresh-witness-wallet/deposit/v1\\0', 'utf8'), seed);
  const recipient2Seed = sha256(Buffer.from('shield.cash/fresh-witness-wallet/transfer/v1\\0', 'utf8'), seed);
  const recipient1 = await deriveRecipientWallet({ seed: recipient1Seed, profileId, instanceId });
  const recipient2 = await deriveRecipientWallet({ seed: recipient2Seed, profileId, instanceId });
  const depositOutput = await constructRecipientOutput({ address: recipient1.address, kind: 'deposit', slot: 0, rng: deterministicRng(seed, 'deposit') });
  const transferOutput = await constructRecipientOutput({ address: recipient2.address, kind: 'transfer', slot: 0, rng: deterministicRng(seed, 'transfer') });
  const note1 = { sk: recipient1.spendSecret, rho: depositOutput.output.rho, r: depositOutput.output.r };
  const note2 = { sk: recipient2.spendSecret, rho: transferOutput.output.rho, r: transferOutput.output.r };
  const outputNote1 = { ak: depositOutput.output.ak, rho: depositOutput.output.rho, r: depositOutput.output.r };
  const outputNote2 = { ak: transferOutput.output.ak, rho: transferOutput.output.rho, r: transferOutput.output.r };
  const derived1 = reference.deriveNote({ ...note1, profileId, instanceId }); const derived2 = reference.deriveNote({ ...note2, profileId, instanceId });
  if (derived1.cm !== depositOutput.output.cm || derived2.cm !== transferOutput.output.cm) fail('public recipient output commitment mismatch');
  const noteEmpty = emptySiblings(reference, NOTE_TREE_DEPTH, DOMAIN_TAGS.NOTE_TREE_EMPTY, DOMAIN_TAGS.NOTE_TREE_NODE);
  const nullifierEmpty = emptySiblings(reference, NULLIFIER_TREE_DEPTH, DOMAIN_TAGS.NULLIFIER_TREE_EMPTY, DOMAIN_TAGS.NULLIFIER_TREE_NODE);
  const initial = reference.emptyState({ profileId, instanceId, maximumReserve });
  const leaf1 = reference.poseidon(DOMAIN_TAGS.NOTE_TREE_LEAF, BigInt(`0x${derived1.cm}`));
  const depositPost = reference.buildState({ ...initial, noteRoot: frToHex(rootFromPath(reference, leaf1, 0n, noteEmpty, DOMAIN_TAGS.NOTE_TREE_NODE)), nextLeafIndex: '1', actionSequence: '1', liveNoteCount: '1', reserveSats: DENOMINATION_SATS.toString() });
  const deposit = { kind: 'deposit', networkId: 2, profileId, instanceId, preState: initial, postState: depositPost, depositSats: DENOMINATION_SATS.toString(), outputNote: outputNote1, noteAppendPath: { siblings: noteEmpty }, outputRecord: depositOutput.record, transactionContextDigest: input.transactionContextDigests.deposit };
  const appendIndex1 = [frToHex(leaf1), ...noteEmpty.slice(1)]; const leaf2 = reference.poseidon(DOMAIN_TAGS.NOTE_TREE_LEAF, BigInt(`0x${derived2.cm}`));
  const key1 = noteKey(derived1); const nfLeaf1 = reference.poseidon(DOMAIN_TAGS.NULLIFIER_TREE_LEAF, BigInt(`0x${derived1.nf}`));
  const transferPost = reference.buildState({ ...depositPost, noteRoot: frToHex(rootFromPath(reference, leaf2, 1n, appendIndex1, DOMAIN_TAGS.NOTE_TREE_NODE)), nullifierRoot: frToHex(rootFromPath(reference, nfLeaf1, key1, nullifierEmpty, DOMAIN_TAGS.NULLIFIER_TREE_NODE)), nextLeafIndex: '2', actionSequence: '2' });
  const transfer = { kind: 'transfer', networkId: 2, profileId, instanceId, preState: depositPost, postState: transferPost, spend: { note: note1, noteIndex: '0', noteSiblings: noteEmpty, nullifierSiblings: nullifierEmpty }, outputNote: outputNote2, noteAppendPath: { siblings: appendIndex1 }, outputRecord: transferOutput.record, transactionContextDigest: input.transactionContextDigests.transfer };
  const key2 = noteKey(derived2); const nfLeaf2 = reference.poseidon(DOMAIN_TAGS.NULLIFIER_TREE_LEAF, BigInt(`0x${derived2.nf}`)); const withdrawalNullifierPath = sparsePath(reference, key2, new Map([[key1.toString(), nfLeaf1]]));
  const withdrawalPost = reference.buildState({ ...transferPost, nullifierRoot: frToHex(rootFromPath(reference, nfLeaf2, key2, withdrawalNullifierPath, DOMAIN_TAGS.NULLIFIER_TREE_NODE)), actionSequence: '3', liveNoteCount: '0', reserveSats: '0' });
  const withdrawal = { kind: 'withdrawal', networkId: 2, profileId, instanceId, preState: transferPost, postState: withdrawalPost, spend: { note: note2, noteIndex: '1', noteSiblings: appendIndex1, nullifierSiblings: withdrawalNullifierPath }, withdrawal: { amountSats: DENOMINATION_SATS.toString(), scriptHash: input.withdrawalScriptHash }, outputRecord: Buffer.alloc(OUTPUT_RECORD_BYTES), transactionContextDigest: input.transactionContextDigests.withdrawal };
  const actions = { deposit, transfer, withdrawal }; const result = {};
  for (const kind of KINDS) {
    const prepared = reference.transition({ ...actions[kind], publicInputs: reference.prepareTransition(actions[kind]).publicInputs });
    const recoveryEphemeralScalar = kind === 'deposit' ? depositOutput.recoveryWitness.ephemeralScalar : kind === 'transfer' ? transferOutput.recoveryWitness.ephemeralScalar : '0';
    result[kind] = Object.freeze({ action: actions[kind], actionPacket: prepared.actionPacket, actionPacketHex: prepared.actionPacket.toString('hex'), actionDigest: prepared.actionDigest, publicInputs: prepared.publicInputs, circuitInput: circuitInput({ kind, action: actions[kind], prepared, reference, maximumLiveNotes, recoveryEphemeralScalar }) });
  }
  return Object.freeze({ schema: 'shield.cash/fresh-witness-inputs/v1', qualification: 'development-only relation witness material; no proof, PF7 verification, G2 settlement, Chipnet, or privacy claim', profile: Object.freeze({ profileId, instanceId, stateNftCategory: bundle.manifest.genesis.stateNftCategory, reserveCapSatoshis: maximumReserve, setupMode: bundle.manifest.setup.mode }), actions: Object.freeze(result) });
}
