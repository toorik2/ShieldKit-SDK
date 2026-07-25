// G1 feasibility reference model. This code computes deterministic witnesses
// and rejects malformed transitions; it neither generates nor accepts proofs.
import { createHash } from 'node:crypto';
import { buildPoseidon } from 'circomlibjs';
import { encodeActionPacket } from './packet.mjs';
import { encodeStateNftCommitment } from './state.mjs';
import {
  BABYJUB_BASE8, BABYJUB_SUBGROUP_ORDER, babyJubMul, hexToBytes, unpackBabyJubPoint,
} from '../recover/portable-core.mjs';

export const FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const DENOMINATION_SATS = 10_000_000n;
export const MAX_BCH_SUPPLY_SATS = 2_100_000_000_000_000n;
export const NOTE_TREE_DEPTH = 32;
export const NULLIFIER_TREE_DEPTH = 128;
export const OUTPUT_RECORD_BYTES = 192;
export const NETWORK_CHIPNET = 2;

// Concrete candidate tags, encoded as canonical Fr integer literals.
export const DOMAIN_TAGS = Object.freeze({
  SPEND_AUTHORITY: 1004n,
  NOTE: 1002n,
  NULLIFIER: 1003n,
  NOTE_TREE_LEAF: 1010n,
  NOTE_TREE_NODE: 1011n,
  NOTE_TREE_EMPTY: 1012n,
  NULLIFIER_TREE_LEAF: 1020n,
  NULLIFIER_TREE_NODE: 1021n,
  NULLIFIER_TREE_EMPTY: 1022n,
  POOL_STATE: 1030n,
});

export class RelationValidationError extends Error {
  constructor(message) { super(message); this.name = 'RelationValidationError'; }
}

const fail = (message) => { throw new RelationValidationError(message); };
const HEX_32 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const ZERO_FR = '0'.repeat(64);
const ZERO_DIGEST = '0'.repeat(64);

function requireObject(value, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`);
  return value;
}

function exactKeys(value, label, keys) {
  requireObject(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown properties`);
}

function parseUint(value, bits, label) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) fail(`${label} must be a canonical unsigned decimal string`);
  const parsed = BigInt(value);
  if (parsed >= (1n << BigInt(bits))) fail(`${label} exceeds u${bits}`);
  return parsed;
}

function parseIndex(value, label) {
  const parsed = parseUint(value, 32, label);
  return Number(parsed);
}

function parseIdentifier(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) fail(`${label} must be 32 lowercase hex bytes`);
  return value;
}

export function frFromBytes(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length !== 32) fail('Fr encoding must contain exactly 32 bytes');
  const value = BigInt(`0x${bytes.toString('hex')}`);
  if (value >= FR_MODULUS) fail('noncanonical Fr encoding');
  return value;
}

export function frToBytes(value) {
  if (typeof value !== 'bigint' || value < 0n || value >= FR_MODULUS) fail('Fr value is not canonical');
  return Buffer.from(value.toString(16).padStart(64, '0'), 'hex');
}

export function frFromHex(value, label = 'Fr') {
  if (typeof value !== 'string' || !HEX_32.test(value)) fail(`${label} must be a 32-byte lowercase hex Fr encoding`);
  return frFromBytes(Buffer.from(value, 'hex'));
}

export function frToHex(value) {
  return frToBytes(value).toString('hex');
}

export function sha256DigestLimbs(digest) {
  if (!Buffer.isBuffer(digest) || digest.length !== 32) fail('SHA-256 digest must contain exactly 32 bytes');
  return [BigInt(`0x${digest.subarray(0, 16).toString('hex')}`), BigInt(`0x${digest.subarray(16, 32).toString('hex')}`)];
}

function identifierLimbs(identifier, label) {
  return sha256DigestLimbs(Buffer.from(parseIdentifier(identifier, label), 'hex'));
}

function u32le(value) {
  const out = Buffer.alloc(4); out.writeUInt32LE(Number(value)); return out;
}

function u64le(value) {
  const out = Buffer.alloc(8); out.writeBigUInt64LE(value); return out;
}

function recordBytes(record, active) {
  if (!(record instanceof Uint8Array) || record.length !== OUTPUT_RECORD_BYTES) fail(`output record must contain exactly ${OUTPUT_RECORD_BYTES} bytes`);
  const normalized = Buffer.from(record);
  if (!active && !normalized.equals(Buffer.alloc(OUTPUT_RECORD_BYTES))) fail('inactive output record must be all zero');
  return normalized;
}

function assertArray(value, length, label) {
  if (!Array.isArray(value) || value.length !== length) fail(`${label} must contain exactly ${length} siblings`);
  return value;
}

function compareStates(actual, expected) {
  for (const key of Object.keys(expected)) if (actual[key] !== expected[key]) fail(`post-state mismatch: ${key}`);
}

/** Build the real pinned circomlibjs BN254 Poseidon implementation. */
export async function createShieldedTransitionReference() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const hash = (tag, ...values) => {
    const inputs = [tag, ...values];
    for (const value of inputs) if (typeof value !== 'bigint' || value < 0n || value >= FR_MODULUS) fail('Poseidon input is not canonical Fr');
    return F.toObject(poseidon(inputs));
  };
  const noteEmpty = [hash(DOMAIN_TAGS.NOTE_TREE_EMPTY, 0n)];
  const nullifierEmpty = [hash(DOMAIN_TAGS.NULLIFIER_TREE_EMPTY, 0n)];
  for (let level = 0; level < NOTE_TREE_DEPTH; level += 1) noteEmpty.push(hash(DOMAIN_TAGS.NOTE_TREE_NODE, noteEmpty[level], noteEmpty[level]));
  for (let level = 0; level < NULLIFIER_TREE_DEPTH; level += 1) nullifierEmpty.push(hash(DOMAIN_TAGS.NULLIFIER_TREE_NODE, nullifierEmpty[level], nullifierEmpty[level]));

  const rootFromPath = (leaf, index, siblings, depth, nodeTag, label) => {
    let current = leaf;
    for (let level = 0; level < depth; level += 1) {
      const sibling = frFromHex(siblings[level], `${label} sibling ${level}`);
      current = ((index >> BigInt(level)) & 1n) === 0n
        ? hash(nodeTag, current, sibling)
        : hash(nodeTag, sibling, current);
    }
    return current;
  };

  const computeStateCommitment = (state) => {
    const profile = identifierLimbs(state.profileId, 'state profileId');
    const instance = identifierLimbs(state.instanceId, 'state instanceId');
    return hash(
      DOMAIN_TAGS.POOL_STATE, ...profile, ...instance,
      frFromHex(state.noteRoot, 'state noteRoot'), frFromHex(state.nullifierRoot, 'state nullifierRoot'),
      parseUint(state.nextLeafIndex, 32, 'state nextLeafIndex'), parseUint(state.actionSequence, 64, 'state actionSequence'),
      parseUint(state.liveNoteCount, 32, 'state liveNoteCount'), parseUint(state.reserveSats, 64, 'state reserveSats'),
      parseUint(state.maximumReserve, 64, 'state maximumReserve'),
    );
  };

  const normalizeState = (state, label) => {
    exactKeys(state, label, ['profileId', 'instanceId', 'noteRoot', 'nullifierRoot', 'nextLeafIndex', 'actionSequence', 'liveNoteCount', 'reserveSats', 'maximumReserve', 'stateCommitment']);
    const normalized = {
      profileId: parseIdentifier(state.profileId, `${label} profileId`),
      instanceId: parseIdentifier(state.instanceId, `${label} instanceId`),
      noteRoot: frToHex(frFromHex(state.noteRoot, `${label} noteRoot`)),
      nullifierRoot: frToHex(frFromHex(state.nullifierRoot, `${label} nullifierRoot`)),
      nextLeafIndex: parseUint(state.nextLeafIndex, 32, `${label} nextLeafIndex`).toString(),
      actionSequence: parseUint(state.actionSequence, 64, `${label} actionSequence`).toString(),
      liveNoteCount: parseUint(state.liveNoteCount, 32, `${label} liveNoteCount`).toString(),
      reserveSats: parseUint(state.reserveSats, 64, `${label} reserveSats`).toString(),
      maximumReserve: parseUint(state.maximumReserve, 64, `${label} maximumReserve`).toString(),
      stateCommitment: frToHex(frFromHex(state.stateCommitment, `${label} stateCommitment`)),
    };
    const live = BigInt(normalized.liveNoteCount);
    const reserve = BigInt(normalized.reserveSats);
    const maximum = BigInt(normalized.maximumReserve);
    if (
      maximum < DENOMINATION_SATS
      || maximum > MAX_BCH_SUPPLY_SATS
      || maximum % DENOMINATION_SATS !== 0n
    ) {
      fail(`${label} maximum reserve must be a nonzero denomination multiple within BCH supply`);
    }
    if (reserve !== live * DENOMINATION_SATS) fail(`${label} reserve does not equal live note count times denomination`);
    if (reserve > maximum) fail(`${label} reserve exceeds maximum reserve`);
    if (BigInt(normalized.nextLeafIndex) > (1n << 32n)) fail(`${label} next leaf index exceeds note tree capacity`);
    if (frToHex(computeStateCommitment(normalized)) !== normalized.stateCommitment) fail(`${label} state commitment mismatch`);
    return normalized;
  };

  const buildState = (raw) => {
    const interim = {
      profileId: parseIdentifier(raw.profileId, 'state profileId'), instanceId: parseIdentifier(raw.instanceId, 'state instanceId'),
      noteRoot: frToHex(frFromHex(raw.noteRoot, 'state noteRoot')), nullifierRoot: frToHex(frFromHex(raw.nullifierRoot, 'state nullifierRoot')),
      nextLeafIndex: parseUint(raw.nextLeafIndex, 32, 'state nextLeafIndex').toString(), actionSequence: parseUint(raw.actionSequence, 64, 'state actionSequence').toString(),
      liveNoteCount: parseUint(raw.liveNoteCount, 32, 'state liveNoteCount').toString(), reserveSats: parseUint(raw.reserveSats, 64, 'state reserveSats').toString(),
      maximumReserve: parseUint(raw.maximumReserve, 64, 'state maximumReserve').toString(),
    };
    return normalizeState({ ...interim, stateCommitment: frToHex(computeStateCommitment(interim)) }, 'constructed state');
  };

  const deriveNote = (noteWitness) => {
    exactKeys(noteWitness, 'note witness', ['profileId', 'instanceId', 'recoveryPublicKey', 'sk', 'rho', 'r']);
    const { profileId, instanceId, recoveryPublicKey, sk, rho, r } = noteWitness;
    const profile = identifierLimbs(profileId, 'note profileId'); const instance = identifierLimbs(instanceId, 'note instanceId');
    const secret = frFromHex(sk, 'note sk'); const nonce = frFromHex(rho, 'note rho'); const randomness = frFromHex(r, 'note r');
    if (secret === 0n || secret >= BABYJUB_SUBGROUP_ORDER || nonce === 0n || randomness === 0n) fail('note sk must be a canonical BabyJubJub scalar and rho/r must be nonzero');
    const spendPoint = babyJubMul(BABYJUB_BASE8, secret);
    let recoveryPoint;
    try { recoveryPoint = unpackBabyJubPoint(hexToBytes(parseIdentifier(recoveryPublicKey, 'note recovery public key'))); } catch { fail('note recovery public key is invalid'); }
    const ak = hash(DOMAIN_TAGS.SPEND_AUTHORITY, ...profile, ...instance, spendPoint[0], spendPoint[1], recoveryPoint[0], recoveryPoint[1]);
    const cm = hash(DOMAIN_TAGS.NOTE, ...profile, ...instance, DENOMINATION_SATS, ak, nonce, randomness);
    const nf = hash(DOMAIN_TAGS.NULLIFIER, ...profile, ...instance, secret, nonce);
    if (cm === 0n || nf === 0n) fail('derived note commitment or nullifier is zero');
    return Object.freeze({ ak: frToHex(ak), cm: frToHex(cm), nf: frToHex(nf), recoveryPublicKey, sk: frToHex(secret), rho: frToHex(nonce), r: frToHex(randomness) });
  };

  // Output construction deliberately accepts a recipient authority key, not a
  // recipient spend secret. A sender can therefore create a note for a public
  // recipient address; only a later spend needs `sk` to derive its nullifier.
  const deriveOutputNote = (output) => {
    exactKeys(output, 'output note', ['profileId', 'instanceId', 'ak', 'rho', 'r']);
    const profile = identifierLimbs(output.profileId, 'output note profileId');
    const instance = identifierLimbs(output.instanceId, 'output note instanceId');
    const authority = frFromHex(output.ak, 'output note ak');
    const nonce = frFromHex(output.rho, 'output note rho');
    const randomness = frFromHex(output.r, 'output note r');
    if (authority === 0n || nonce === 0n || randomness === 0n) fail('output note ak, rho, and r must be nonzero');
    const cm = hash(DOMAIN_TAGS.NOTE, ...profile, ...instance, DENOMINATION_SATS, authority, nonce, randomness);
    if (cm === 0n) fail('derived output note commitment is zero');
    return Object.freeze({ ak: frToHex(authority), cm: frToHex(cm), rho: frToHex(nonce), r: frToHex(randomness) });
  };

  const appendNote = (pre, cm, path) => {
    exactKeys(path, 'note append path', ['siblings']);
    const siblings = assertArray(path.siblings, NOTE_TREE_DEPTH, 'note append path');
    const index = BigInt(pre.nextLeafIndex);
    // nextLeafIndex is u32, so the successor must remain representable. This
    // G1 candidate intentionally leaves index 2^32-1 unused; G2 may instead
    // widen the counter and regenerate all dependent artifacts.
    if (index >= (1n << 32n) - 1n) fail('note tree has no representable successor index');
    const preRoot = rootFromPath(noteEmpty[0], index, siblings, NOTE_TREE_DEPTH, DOMAIN_TAGS.NOTE_TREE_NODE, 'note append path');
    if (preRoot !== frFromHex(pre.noteRoot, 'pre-state note root')) fail('note append path does not prove an empty next leaf');
    return frToHex(rootFromPath(hash(DOMAIN_TAGS.NOTE_TREE_LEAF, frFromHex(cm, 'output note commitment')), index, siblings, NOTE_TREE_DEPTH, DOMAIN_TAGS.NOTE_TREE_NODE, 'note append path'));
  };

  const spendNote = (pre, spend) => {
    exactKeys(spend, 'spend', ['note', 'noteIndex', 'noteSiblings', 'nullifierSiblings']);
    const note = deriveNote({ ...spend.note, profileId: pre.profileId, instanceId: pre.instanceId });
    const noteIndex = BigInt(parseIndex(spend.noteIndex, 'spend noteIndex'));
    const noteSiblings = assertArray(spend.noteSiblings, NOTE_TREE_DEPTH, 'note membership path');
    if (rootFromPath(hash(DOMAIN_TAGS.NOTE_TREE_LEAF, frFromHex(note.cm, 'input note commitment')), noteIndex, noteSiblings, NOTE_TREE_DEPTH, DOMAIN_TAGS.NOTE_TREE_NODE, 'note membership path') !== frFromHex(pre.noteRoot, 'pre-state note root')) fail('input note membership path is invalid');
    // Use the least-significant 128 bits. The two most-significant bits of a
    // canonical BN254 Fr encoding are structurally zero, so taking the first
    // 16 bytes would provide only 126 variable index bits.
    const key = BigInt(`0x${frToBytes(frFromHex(note.nf, 'input nullifier')).subarray(16, 32).toString('hex')}`);
    const nullifierSiblings = assertArray(spend.nullifierSiblings, NULLIFIER_TREE_DEPTH, 'nullifier path');
    if (rootFromPath(nullifierEmpty[0], key, nullifierSiblings, NULLIFIER_TREE_DEPTH, DOMAIN_TAGS.NULLIFIER_TREE_NODE, 'nullifier path') !== frFromHex(pre.nullifierRoot, 'pre-state nullifier root')) fail('nullifier is duplicate or collides with an occupied sparse leaf');
    const postNullifierRoot = rootFromPath(hash(DOMAIN_TAGS.NULLIFIER_TREE_LEAF, frFromHex(note.nf, 'input nullifier')), key, nullifierSiblings, NULLIFIER_TREE_DEPTH, DOMAIN_TAGS.NULLIFIER_TREE_NODE, 'nullifier path');
    return { note, postNullifierRoot: frToHex(postNullifierRoot) };
  };

  const serializeActionPacket = ({ kind, networkId, preState, postState, inputCm, inputNf, outputCm, outputRecord, boundaryAmount, withdrawalScriptHash, transactionContextDigest }) => {
    return encodeActionPacket({
      kind,
      networkId,
      preState,
      postState,
      inputCommitment: inputCm,
      inputNullifier: inputNf,
      outputCommitment: outputCm,
      outputRecord,
      boundaryAmount: boundaryAmount.toString(),
      withdrawalScriptHash,
      transactionContextDigest,
    });
  };

  const checkPublicInputs = (packet, supplied) => {
    if (!Array.isArray(supplied) || supplied.length !== 2) fail('publicInputs must contain exactly two SHA-256 limbs');
    const expected = sha256DigestLimbs(createHash('sha256').update(packet).digest());
    const actual = supplied.map((limb, index) => frFromHex(limb, `public input ${index}`));
    if (actual[0] !== expected[0] || actual[1] !== expected[1]) fail('public SHA-256 digest limbs mismatch');
    return Object.freeze(actual.map(frToHex));
  };

  const evaluateTransition = (action, requirePublicInputs) => {
    requireObject(action, 'action');
    const kind = action.kind;
    if (!['deposit', 'transfer', 'withdrawal'].includes(kind)) fail('unknown action kind');
    const required = kind === 'deposit'
      ? ['kind', 'networkId', 'profileId', 'instanceId', 'preState', 'postState', 'depositSats', 'outputNote', 'noteAppendPath', 'outputRecord', 'transactionContextDigest']
      : kind === 'transfer'
        ? ['kind', 'networkId', 'profileId', 'instanceId', 'preState', 'postState', 'spend', 'outputNote', 'noteAppendPath', 'outputRecord', 'transactionContextDigest']
        : ['kind', 'networkId', 'profileId', 'instanceId', 'preState', 'postState', 'spend', 'withdrawal', 'outputRecord', 'transactionContextDigest'];
    const allowed = new Set([...required, 'publicInputs']);
    if (Object.keys(action).some((key) => !allowed.has(key)) || required.some((key) => action[key] === undefined) || (requirePublicInputs && action.publicInputs === undefined)) fail('action has missing or unconstrained properties');
    if (action.networkId !== NETWORK_CHIPNET) fail('wrong network identifier');
    const pre = normalizeState(action.preState, 'pre-state');
    if (parseIdentifier(action.profileId, 'action profileId') !== pre.profileId || parseIdentifier(action.instanceId, 'action instanceId') !== pre.instanceId) fail('action identifiers do not match pre-state');
    if (BigInt(pre.actionSequence) === (1n << 64n) - 1n) fail('action sequence overflow');
    let noteRoot = pre.noteRoot; let nullifierRoot = pre.nullifierRoot;
    let live = BigInt(pre.liveNoteCount); let reserve = BigInt(pre.reserveSats);
    let inputCm = ZERO_FR; let inputNf = ZERO_FR; let outputCm = ZERO_FR;
    let outputRecord; let boundaryAmount = 0n; let withdrawalScriptHash = ZERO_DIGEST;
    if (kind === 'deposit') {
      if (parseUint(action.depositSats, 64, 'deposit contribution') !== DENOMINATION_SATS) fail('deposit contribution must equal denomination');
      const output = deriveOutputNote({ ...action.outputNote, profileId: pre.profileId, instanceId: pre.instanceId }); outputCm = output.cm;
      noteRoot = appendNote(pre, output.cm, action.noteAppendPath); outputRecord = recordBytes(action.outputRecord, true); boundaryAmount = DENOMINATION_SATS;
      live += 1n; reserve += DENOMINATION_SATS;
    } else if (kind === 'transfer') {
      const spent = spendNote(pre, action.spend); inputCm = spent.note.cm; inputNf = spent.note.nf; nullifierRoot = spent.postNullifierRoot;
      const output = deriveOutputNote({ ...action.outputNote, profileId: pre.profileId, instanceId: pre.instanceId }); outputCm = output.cm;
      noteRoot = appendNote(pre, output.cm, action.noteAppendPath); outputRecord = recordBytes(action.outputRecord, true);
    } else {
      const spent = spendNote(pre, action.spend); inputCm = spent.note.cm; inputNf = spent.note.nf; nullifierRoot = spent.postNullifierRoot;
      exactKeys(action.withdrawal, 'withdrawal boundary', ['amountSats', 'scriptHash']);
      if (parseUint(action.withdrawal.amountSats, 64, 'withdrawal amount') !== DENOMINATION_SATS) fail('withdrawal amount must equal denomination');
      withdrawalScriptHash = parseIdentifier(action.withdrawal.scriptHash, 'withdrawal script hash'); outputRecord = recordBytes(action.outputRecord, false); boundaryAmount = DENOMINATION_SATS;
      if (live === 0n || reserve < DENOMINATION_SATS) fail('withdrawal underflows live note count or reserve');
      live -= 1n; reserve -= DENOMINATION_SATS;
    }
    const maximum = BigInt(pre.maximumReserve);
    if (reserve > maximum) fail('post-state reserve exceeds maximum reserve');
    const post = buildState({ profileId: pre.profileId, instanceId: pre.instanceId, noteRoot, nullifierRoot, nextLeafIndex: (BigInt(pre.nextLeafIndex) + (kind === 'withdrawal' ? 0n : 1n)).toString(), actionSequence: (BigInt(pre.actionSequence) + 1n).toString(), liveNoteCount: live.toString(), reserveSats: reserve.toString(), maximumReserve: maximum.toString() });
    const suppliedPost = normalizeState(action.postState, 'post-state'); compareStates(suppliedPost, post);
    const packet = serializeActionPacket({ kind, networkId: action.networkId, preState: pre, postState: post, inputCm, inputNf, outputCm, outputRecord, boundaryAmount, withdrawalScriptHash, transactionContextDigest: action.transactionContextDigest });
    const publicInputs = action.publicInputs === undefined && !requirePublicInputs
      ? Object.freeze(sha256DigestLimbs(createHash('sha256').update(packet).digest()).map(frToHex))
      : checkPublicInputs(packet, action.publicInputs);
    return Object.freeze({ kind, preState: pre, postState: post, actionPacket: packet, actionDigest: createHash('sha256').update(packet).digest('hex'), publicInputs, inputCm, inputNf, outputCm });
  };

  const emptyState = ({ profileId, instanceId, maximumReserve }) => buildState({ profileId, instanceId, noteRoot: frToHex(noteEmpty[NOTE_TREE_DEPTH]), nullifierRoot: frToHex(nullifierEmpty[NULLIFIER_TREE_DEPTH]), nextLeafIndex: '0', actionSequence: '0', liveNoteCount: '0', reserveSats: '0', maximumReserve });
  const stateNftCommitment = ({ networkId, instanceId, stateCommitment, actionSequence }) => {
    if (networkId !== NETWORK_CHIPNET) fail('wrong network identifier');
    return encodeStateNftCommitment({
      networkId,
      instanceId: parseIdentifier(instanceId, 'instanceId'),
      stateCommitment: frToHex(frFromHex(stateCommitment, 'state commitment')),
      actionSequence: parseUint(actionSequence, 64, 'action sequence').toString(),
    });
  };

  return Object.freeze({
    constants: Object.freeze({
      DENOMINATION_SATS, MAX_BCH_SUPPLY_SATS, NOTE_TREE_DEPTH,
      NULLIFIER_TREE_DEPTH, OUTPUT_RECORD_BYTES, NETWORK_CHIPNET,
    }),
    poseidon: hash, deriveNote, deriveOutputNote, emptyState, buildState,
    // Preparation computes deterministic packet limbs but is not an acceptance API.
    prepareTransition: (action) => evaluateTransition(action, false),
    transition: (action) => evaluateTransition(action, true), stateNftCommitment,
    emptyNoteRoot: frToHex(noteEmpty[NOTE_TREE_DEPTH]), emptyNullifierRoot: frToHex(nullifierEmpty[NULLIFIER_TREE_DEPTH]),
  });
}
