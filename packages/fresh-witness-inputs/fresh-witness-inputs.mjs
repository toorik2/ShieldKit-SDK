// Typed, local witness material for the pinned low128 G1 relation. This is
// deliberately profile-bound and does not initialize setup, make proofs, or
// construct BCH transactions.
import {
  createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey,
  diffieHellman, hkdfSync,
} from 'node:crypto';
import {
  DENOMINATION_SATS, DOMAIN_TAGS, FR_MODULUS, NULLIFIER_TREE_DEPTH, NOTE_TREE_DEPTH,
  OUTPUT_RECORD_BYTES, createShieldedTransitionReference, frToHex,
} from '../core/shielded-transition.mjs';
import { loadVerifierProfileBundle } from '../core/verifier-profile.mjs';

const HEX_32 = /^[0-9a-f]{64}$/;
const KINDS = Object.freeze(['deposit', 'transfer', 'withdrawal']);
const KIND_CODE = Object.freeze({ deposit: 1, transfer: 2, withdrawal: 3 });
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const RECORD_VERSION = 1;
const RECORD_CIPHERTEXT_BYTES = 128;

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

function deriveField(seed, label) {
  const reduced = BigInt(`0x${sha256(Buffer.from('shield.cash/fresh-witness-inputs/v1\\0', 'utf8'), seed, Buffer.from(label, 'utf8')).toString('hex')}`) % (FR_MODULUS - 1n);
  return frToHex(reduced + 1n);
}

function rawPrivateKey(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length !== 32) fail('X25519 private material must contain exactly 32 bytes');
  return createPrivateKey({ key: Buffer.concat([X25519_PKCS8_PREFIX, bytes]), format: 'der', type: 'pkcs8' });
}
function rawPublicKey(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length !== 32) fail('X25519 public material must contain exactly 32 bytes');
  return createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, bytes]), format: 'der', type: 'spki' });
}
function publicRaw(privateKey) {
  const encoded = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  return Buffer.from(encoded).subarray(-32);
}
function recoveryPrivate(noteSecret) {
  return rawPrivateKey(sha256(Buffer.from('shield.cash/recovery-x25519/v1\\0', 'utf8'), Buffer.from(noteSecret, 'hex')));
}
function recordAad({ kind, slot, profileId, instanceId, outputCm }) {
  return Buffer.concat([
    Buffer.from('shield.cash/recovery-record/v1\\0SCAR', 'utf8'), Buffer.of(1, 2, KIND_CODE[kind], 0, slot),
    Buffer.from(profileId, 'hex'), Buffer.from(instanceId, 'hex'), Buffer.from(outputCm, 'hex'),
  ]);
}

/**
 * Create the 192-byte X25519/HKDF-SHA256/ChaCha20-Poly1305 recovery record
 * described by the G1 candidate. Circuit G1 only binds these bytes: it does
 * not yet prove AEAD correctness, so callers must decrypt and recompute note
 * material before accepting a discovered record.
 */
export function encryptRecoveryRecord({ kind, slot, profileId, instanceId, outputNote, outputCm, witnessSeed }) {
  if (!KINDS.includes(kind)) fail('record kind is unsupported');
  if (!Number.isInteger(slot) || slot < 0 || slot > 0xff) fail('record slot must be a byte');
  hex32(profileId, 'record profileId'); hex32(instanceId, 'record instanceId'); hex32(outputCm, 'record output commitment'); hex32(witnessSeed, 'witnessSeed');
  exactKeys(outputNote, 'output note', ['ak', 'cm', 'nf', 'r', 'rho', 'sk']);
  for (const key of ['ak', 'cm', 'nf', 'r', 'rho', 'sk']) hex32(outputNote[key], `output note ${key}`);
  const recipient = recoveryPrivate(outputNote.sk);
  const ephemeral = rawPrivateKey(sha256(Buffer.from('shield.cash/recovery-ephemeral/v1\\0', 'utf8'), Buffer.from(witnessSeed, 'hex'), Buffer.from(kind, 'utf8')));
  const shared = diffieHellman({ privateKey: ephemeral, publicKey: createPublicKey(recipient) });
  const nonce = sha256(Buffer.from('shield.cash/recovery-nonce/v1\\0', 'utf8'), Buffer.from(witnessSeed, 'hex'), Buffer.from(kind, 'utf8')).subarray(0, 12);
  const key = Buffer.from(hkdfSync('sha256', shared, Buffer.from(profileId, 'hex'), recordAad({ kind, slot, profileId, instanceId, outputCm }), 32));
  const plaintext = Buffer.concat([Buffer.from(profileId, 'hex'), Buffer.from(instanceId, 'hex'), Buffer.from(outputNote.rho, 'hex'), Buffer.from(outputNote.r, 'hex')]);
  if (plaintext.length !== RECORD_CIPHERTEXT_BYTES) fail('internal recovery plaintext size mismatch');
  const cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  cipher.setAAD(recordAad({ kind, slot, profileId, instanceId, outputCm }), { plaintextLength: plaintext.length });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const record = Buffer.concat([Buffer.of(RECORD_VERSION, slot), publicRaw(ephemeral), nonce, cipher.getAuthTag(), ciphertext, Buffer.alloc(2)]);
  if (record.length !== OUTPUT_RECORD_BYTES) fail('internal recovery record size mismatch');
  return record;
}

export function decryptRecoveryRecord({ kind, slot, profileId, instanceId, outputCm, recipientNoteSecret, record }) {
  if (!KINDS.includes(kind)) fail('record kind is unsupported');
  if (!Number.isInteger(slot) || slot < 0 || slot > 0xff) fail('record slot must be a byte');
  hex32(profileId, 'record profileId'); hex32(instanceId, 'record instanceId'); hex32(outputCm, 'record output commitment'); hex32(recipientNoteSecret, 'recipient note secret');
  if (!Buffer.isBuffer(record) || record.length !== OUTPUT_RECORD_BYTES) fail('record must contain exactly 192 bytes');
  if (record[0] !== RECORD_VERSION || record[1] !== slot) fail('record version or output slot mismatch');
  if (!record.subarray(190, 192).equals(Buffer.alloc(2))) fail('record padding must be zero');
  const ephemeral = rawPublicKey(record.subarray(2, 34)); const nonce = record.subarray(34, 46); const tag = record.subarray(46, 62); const ciphertext = record.subarray(62, 190);
  const recipient = recoveryPrivate(recipientNoteSecret); const shared = diffieHellman({ privateKey: recipient, publicKey: ephemeral });
  const key = Buffer.from(hkdfSync('sha256', shared, Buffer.from(profileId, 'hex'), recordAad({ kind, slot, profileId, instanceId, outputCm }), 32));
  const decipher = createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  decipher.setAAD(recordAad({ kind, slot, profileId, instanceId, outputCm }), { plaintextLength: ciphertext.length }); decipher.setAuthTag(tag);
  let plaintext;
  try { plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]); } catch { fail('record authentication failed'); }
  if (plaintext.length !== RECORD_CIPHERTEXT_BYTES) fail('record plaintext length is invalid');
  const decoded = Object.freeze({ profileId: plaintext.subarray(0, 32).toString('hex'), instanceId: plaintext.subarray(32, 64).toString('hex'), rho: plaintext.subarray(64, 96).toString('hex'), r: plaintext.subarray(96, 128).toString('hex') });
  if (decoded.profileId !== profileId || decoded.instanceId !== instanceId) fail('record plaintext identity mismatch');
  return decoded;
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
function circuitInput({ kind, action, prepared, reference, maximumLiveNotes }) {
  const pre = prepared.preState; const post = prepared.postState; const profileId = pre.profileId; const instanceId = pre.instanceId;
  const spend = action.spend ? reference.deriveNote({ ...action.spend.note, profileId, instanceId }) : undefined;
  const output = action.outputNote ? reference.deriveNote({ ...action.outputNote, profileId, instanceId }) : undefined;
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
    recordBits: recordBits(action.outputRecord), transactionContextHi: idLimbs(action.transactionContextDigest)[0], transactionContextLo: idLimbs(action.transactionContextDigest)[1],
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
  const note1 = { sk: deriveField(seed, 'note-1/sk'), rho: deriveField(seed, 'note-1/rho'), r: deriveField(seed, 'note-1/r') };
  const note2 = { sk: deriveField(seed, 'note-2/sk'), rho: deriveField(seed, 'note-2/rho'), r: deriveField(seed, 'note-2/r') };
  const derived1 = reference.deriveNote({ ...note1, profileId, instanceId }); const derived2 = reference.deriveNote({ ...note2, profileId, instanceId });
  const noteEmpty = emptySiblings(reference, NOTE_TREE_DEPTH, DOMAIN_TAGS.NOTE_TREE_EMPTY, DOMAIN_TAGS.NOTE_TREE_NODE);
  const nullifierEmpty = emptySiblings(reference, NULLIFIER_TREE_DEPTH, DOMAIN_TAGS.NULLIFIER_TREE_EMPTY, DOMAIN_TAGS.NULLIFIER_TREE_NODE);
  const initial = reference.emptyState({ profileId, instanceId, maximumReserve });
  const leaf1 = reference.poseidon(DOMAIN_TAGS.NOTE_TREE_LEAF, BigInt(`0x${derived1.cm}`));
  const depositPost = reference.buildState({ ...initial, noteRoot: frToHex(rootFromPath(reference, leaf1, 0n, noteEmpty, DOMAIN_TAGS.NOTE_TREE_NODE)), nextLeafIndex: '1', actionSequence: '1', liveNoteCount: '1', reserveSats: DENOMINATION_SATS.toString() });
  const depositRecord = encryptRecoveryRecord({ kind: 'deposit', slot: 0, profileId, instanceId, outputNote: derived1, outputCm: derived1.cm, witnessSeed: input.witnessSeed });
  const deposit = { kind: 'deposit', networkId: 2, profileId, instanceId, preState: initial, postState: depositPost, depositSats: DENOMINATION_SATS.toString(), outputNote: note1, noteAppendPath: { siblings: noteEmpty }, outputRecord: depositRecord, transactionContextDigest: input.transactionContextDigests.deposit };
  const appendIndex1 = [frToHex(leaf1), ...noteEmpty.slice(1)]; const leaf2 = reference.poseidon(DOMAIN_TAGS.NOTE_TREE_LEAF, BigInt(`0x${derived2.cm}`));
  const key1 = noteKey(derived1); const nfLeaf1 = reference.poseidon(DOMAIN_TAGS.NULLIFIER_TREE_LEAF, BigInt(`0x${derived1.nf}`));
  const transferPost = reference.buildState({ ...depositPost, noteRoot: frToHex(rootFromPath(reference, leaf2, 1n, appendIndex1, DOMAIN_TAGS.NOTE_TREE_NODE)), nullifierRoot: frToHex(rootFromPath(reference, nfLeaf1, key1, nullifierEmpty, DOMAIN_TAGS.NULLIFIER_TREE_NODE)), nextLeafIndex: '2', actionSequence: '2' });
  const transferRecord = encryptRecoveryRecord({ kind: 'transfer', slot: 0, profileId, instanceId, outputNote: derived2, outputCm: derived2.cm, witnessSeed: input.witnessSeed });
  const transfer = { kind: 'transfer', networkId: 2, profileId, instanceId, preState: depositPost, postState: transferPost, spend: { note: note1, noteIndex: '0', noteSiblings: noteEmpty, nullifierSiblings: nullifierEmpty }, outputNote: note2, noteAppendPath: { siblings: appendIndex1 }, outputRecord: transferRecord, transactionContextDigest: input.transactionContextDigests.transfer };
  const key2 = noteKey(derived2); const nfLeaf2 = reference.poseidon(DOMAIN_TAGS.NULLIFIER_TREE_LEAF, BigInt(`0x${derived2.nf}`)); const withdrawalNullifierPath = sparsePath(reference, key2, new Map([[key1.toString(), nfLeaf1]]));
  const withdrawalPost = reference.buildState({ ...transferPost, nullifierRoot: frToHex(rootFromPath(reference, nfLeaf2, key2, withdrawalNullifierPath, DOMAIN_TAGS.NULLIFIER_TREE_NODE)), actionSequence: '3', liveNoteCount: '0', reserveSats: '0' });
  const withdrawal = { kind: 'withdrawal', networkId: 2, profileId, instanceId, preState: transferPost, postState: withdrawalPost, spend: { note: note2, noteIndex: '1', noteSiblings: appendIndex1, nullifierSiblings: withdrawalNullifierPath }, withdrawal: { amountSats: DENOMINATION_SATS.toString(), scriptHash: input.withdrawalScriptHash }, outputRecord: Buffer.alloc(OUTPUT_RECORD_BYTES), transactionContextDigest: input.transactionContextDigests.withdrawal };
  const actions = { deposit, transfer, withdrawal }; const result = {};
  for (const kind of KINDS) {
    const prepared = reference.transition({ ...actions[kind], publicInputs: reference.prepareTransition(actions[kind]).publicInputs });
    result[kind] = Object.freeze({ action: actions[kind], actionPacket: prepared.actionPacket, actionPacketHex: prepared.actionPacket.toString('hex'), actionDigest: prepared.actionDigest, publicInputs: prepared.publicInputs, circuitInput: circuitInput({ kind, action: actions[kind], prepared, reference, maximumLiveNotes }) });
  }
  return Object.freeze({ schema: 'shield.cash/fresh-witness-inputs/v1', qualification: 'development-only relation witness material; no proof, PF7 verification, G2 settlement, Chipnet, or privacy claim', profile: Object.freeze({ profileId, instanceId, stateNftCategory: bundle.manifest.genesis.stateNftCategory, reserveCapSatoshis: maximumReserve, setupMode: bundle.manifest.setup.mode }), actions: Object.freeze(result) });
}
