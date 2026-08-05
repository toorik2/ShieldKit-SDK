/** Strict V2 Direct native state-NFT commitment codec. */

export const STATE_NFT_COMMITMENT_BYTES = 128;
export const STATE_NFT_COMMITMENT_LIMIT_BYTES = 128;
export const STATE_BYTES = STATE_NFT_COMMITMENT_BYTES;
export const MAX_MONEY_SATS = 2_100_000_000_000_000n;
export const BN254_FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export const STATE_NFT_OFFSETS = Object.freeze({
  magic: 0,
  profileId: 4,
  noteRoot: 36,
  nullifierRoot: 68,
  noteCount: 100,
  nullifierCount: 104,
  maximumLiveNotes: 108,
  reserveSats: 112,
  actionSequence: 120,
  end: 128,
});

const HEX_32 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_U32 = 0xffff_ffffn;
const MAX_NULLIFIER_COUNT = 0xffff_fffen;
const MAX_ACTION_SEQUENCE = 1n << 33n;
const STATE_KEYS = Object.freeze([
  'profileId',
  'noteRoot',
  'nullifierRoot',
  'noteCount',
  'nullifierCount',
  'maximumLiveNotes',
  'reserveSats',
  'actionSequence',
]);

export class StateNftError extends Error {
  constructor(message) {
    super(message);
    this.name = 'StateNftError';
  }
}

const fail = (message) => { throw new StateNftError(message); };

function exactKeys(value, label, expected) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail(`${label} has missing or unknown properties`);
  }
}

function uint(value, maximum, label) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) {
    fail(`${label} must be a canonical unsigned decimal string`);
  }
  const parsed = BigInt(value);
  if (parsed > maximum) fail(`${label} exceeds its range`);
  return parsed;
}

function hex32(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail(`${label} must be 32 lowercase hexadecimal bytes`);
  }
  return Buffer.from(value, 'hex');
}

export function canonicalFrHex(value, label = 'Fr') {
  const bytes = hex32(value, label);
  if (BigInt(`0x${bytes.toString('hex')}`) >= BN254_FR_MODULUS) {
    fail(`${label} must be a canonical BN254 Fr element`);
  }
  return bytes.toString('hex');
}

function denominationSats(context) {
  exactKeys(context, 'state context', ['denominationSats']);
  const denomination = uint(context.denominationSats, MAX_MONEY_SATS, 'denominationSats');
  if (denomination === 0n) fail('denominationSats must be nonzero');
  return denomination;
}

function exactBytes(value, length, label) {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    fail(`${label} must contain exactly ${length} bytes`);
  }
  return Buffer.from(value);
}

function normaliseState(value, context, label) {
  exactKeys(value, label, STATE_KEYS);
  const denomination = denominationSats(context);
  const noteCount = uint(value.noteCount, MAX_U32, `${label}.noteCount`);
  const nullifierCount = uint(value.nullifierCount, MAX_NULLIFIER_COUNT, `${label}.nullifierCount`);
  const maximumLiveNotes = uint(value.maximumLiveNotes, MAX_U32, `${label}.maximumLiveNotes`);
  const reserveSats = uint(value.reserveSats, MAX_MONEY_SATS, `${label}.reserveSats`);
  const actionSequence = uint(value.actionSequence, MAX_ACTION_SEQUENCE - 1n, `${label}.actionSequence`);
  if (nullifierCount > noteCount) fail(`${label}.nullifierCount exceeds noteCount`);
  const liveNoteCount = noteCount - nullifierCount;
  if (maximumLiveNotes === 0n) fail(`${label}.maximumLiveNotes must be at least one`);
  if (maximumLiveNotes > MAX_MONEY_SATS / denomination) {
    fail(`${label}.maximumLiveNotes exceeds MAX_MONEY_SATS for denominationSats`);
  }
  if (liveNoteCount > maximumLiveNotes) fail(`${label}.liveNoteCount exceeds maximumLiveNotes`);
  if (reserveSats !== liveNoteCount * denomination) {
    fail(`${label}.reserveSats must equal liveNoteCount times denominationSats`);
  }
  if (actionSequence < (noteCount > nullifierCount ? noteCount : nullifierCount)) {
    fail(`${label}.actionSequence is below the counter floor`);
  }
  if (actionSequence > noteCount + nullifierCount) {
    fail(`${label}.actionSequence exceeds the counter ceiling`);
  }

  return Object.freeze({
    profileId: hex32(value.profileId, `${label}.profileId`).toString('hex'),
    noteRoot: canonicalFrHex(value.noteRoot, `${label}.noteRoot`),
    nullifierRoot: canonicalFrHex(value.nullifierRoot, `${label}.nullifierRoot`),
    noteCount: noteCount.toString(),
    nullifierCount: nullifierCount.toString(),
    maximumLiveNotes: maximumLiveNotes.toString(),
    reserveSats: reserveSats.toString(),
    actionSequence: actionSequence.toString(),
  });
}

/** Validate a decoded state using the profile-pinned denomination context. */
export function validateStateNftCommitment(value, context) {
  return normaliseState(value, context, 'state NFT commitment');
}

export function encodeStateNftCommitment(value, context) {
  const state = normaliseState(value, context, 'state NFT commitment');
  const bytes = Buffer.alloc(STATE_NFT_COMMITMENT_BYTES);
  Buffer.from('SKS2', 'ascii').copy(bytes, STATE_NFT_OFFSETS.magic);
  Buffer.from(state.profileId, 'hex').copy(bytes, STATE_NFT_OFFSETS.profileId);
  Buffer.from(state.noteRoot, 'hex').copy(bytes, STATE_NFT_OFFSETS.noteRoot);
  Buffer.from(state.nullifierRoot, 'hex').copy(bytes, STATE_NFT_OFFSETS.nullifierRoot);
  bytes.writeUInt32LE(Number(state.noteCount), STATE_NFT_OFFSETS.noteCount);
  bytes.writeUInt32LE(Number(state.nullifierCount), STATE_NFT_OFFSETS.nullifierCount);
  bytes.writeUInt32LE(Number(state.maximumLiveNotes), STATE_NFT_OFFSETS.maximumLiveNotes);
  bytes.writeBigUInt64LE(BigInt(state.reserveSats), STATE_NFT_OFFSETS.reserveSats);
  bytes.writeBigUInt64LE(BigInt(state.actionSequence), STATE_NFT_OFFSETS.actionSequence);
  return bytes;
}

export function decodeStateNftCommitment(value, context) {
  const bytes = exactBytes(value, STATE_NFT_COMMITMENT_BYTES, 'state NFT commitment');
  if (!bytes.subarray(0, 4).equals(Buffer.from('SKS2', 'ascii'))) {
    fail('state NFT commitment magic is invalid');
  }
  return normaliseState({
    profileId: bytes.subarray(4, 36).toString('hex'),
    noteRoot: bytes.subarray(36, 68).toString('hex'),
    nullifierRoot: bytes.subarray(68, 100).toString('hex'),
    noteCount: bytes.readUInt32LE(100).toString(),
    nullifierCount: bytes.readUInt32LE(104).toString(),
    maximumLiveNotes: bytes.readUInt32LE(108).toString(),
    reserveSats: bytes.readBigUInt64LE(112).toString(),
    actionSequence: bytes.readBigUInt64LE(120).toString(),
  }, context, 'state NFT commitment');
}
