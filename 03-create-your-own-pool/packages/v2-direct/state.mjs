/**
 * SKS2 — native 128-byte pool state NFT commitment.
 * Layout from IMPLEMENTATION_PLAN.md §2.
 */
import {
  DENOMINATION_SATS,
  MAX_MONEY_SATS,
  POOL_STATE_BYTES,
  STATE_MAGIC,
  ZERO_32_HEX,
} from './constants.mjs';
import { frFromHex, frToHex } from './crypto/fr.mjs';

export class PoolStateV2Error extends Error {
  constructor(message) {
    super(message);
    this.name = 'PoolStateV2Error';
  }
}

const fail = (message) => {
  throw new PoolStateV2Error(message);
};

const HEX_32 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;

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

function exactKeys(value, label, expected) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((k, i) => k !== wanted[i])) {
    fail(`${label} has missing or unknown properties`);
  }
}

function hex32(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail(`${label} must be 32 lowercase hexadecimal bytes`);
  }
  return Buffer.from(value, 'hex');
}

function parseU32(value, label) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) {
    fail(`${label} must be a canonical unsigned decimal string`);
  }
  const n = BigInt(value);
  if (n > 0xffff_ffffn) fail(`${label} exceeds u32`);
  return n;
}

function parseU64(value, label) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) {
    fail(`${label} must be a canonical unsigned decimal string`);
  }
  const n = BigInt(value);
  if (n > 0xffff_ffff_ffff_ffffn) fail(`${label} exceeds u64`);
  return n;
}

/**
 * Validate logical state invariants (not just wire encoding).
 * Accepts wire fields plus optional derived `liveNoteCount` (ignored on input).
 * @returns {object} normalized frozen state (decimal strings + hex roots + liveNoteCount)
 */
export function normalizePoolStateV2(value, label = 'pool state') {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail(`${label} must be an object`);
  }
  // Allow derived liveNoteCount on input; reject any other unknown keys.
  const allowed = new Set([...STATE_KEYS, 'liveNoteCount']);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail(`${label} has missing or unknown properties`);
  }
  for (const key of STATE_KEYS) {
    if (value[key] === undefined) fail(`${label} has missing or unknown properties`);
  }
  const profileId = hex32(value.profileId, `${label}.profileId`).toString('hex');
  // Roots are canonical BN254 field elements as 32-byte big-endian.
  const noteRoot = frToHex(frFromHex(value.noteRoot, `${label}.noteRoot`));
  const nullifierRoot = frToHex(frFromHex(value.nullifierRoot, `${label}.nullifierRoot`));
  const noteCount = parseU32(value.noteCount, `${label}.noteCount`);
  const nullifierCount = parseU32(value.nullifierCount, `${label}.nullifierCount`);
  const maximumLiveNotes = parseU32(value.maximumLiveNotes, `${label}.maximumLiveNotes`);
  const reserveSats = parseU64(value.reserveSats, `${label}.reserveSats`);
  const actionSequence = parseU64(value.actionSequence, `${label}.actionSequence`);

  if (nullifierCount > noteCount) {
    fail(`${label}: nullifierCount must be ≤ noteCount`);
  }
  const liveNoteCount = noteCount - nullifierCount;
  if (maximumLiveNotes < 1n) {
    fail(`${label}: maximumLiveNotes must be ≥ 1`);
  }
  const maxByDenom = MAX_MONEY_SATS / DENOMINATION_SATS;
  if (maximumLiveNotes > maxByDenom) {
    fail(`${label}: maximumLiveNotes exceeds floor(MAX_MONEY/denomination)`);
  }
  if (liveNoteCount > maximumLiveNotes) {
    fail(`${label}: liveNoteCount exceeds maximumLiveNotes`);
  }
  if (reserveSats !== liveNoteCount * DENOMINATION_SATS) {
    fail(`${label}: reserveSats must equal liveNoteCount × denomination`);
  }
  // max(noteCount, nullifierCount) ≤ actionSequence ≤ noteCount + nullifierCount
  const lo = noteCount > nullifierCount ? noteCount : nullifierCount;
  const hi = noteCount + nullifierCount;
  if (actionSequence < lo || actionSequence > hi) {
    fail(`${label}: actionSequence out of range for counters`);
  }
  // actionSequence < 2^33
  if (actionSequence >= (1n << 33n)) {
    fail(`${label}: actionSequence must be < 2^33`);
  }
  // nullifierCount ≤ 0xfffffffe (sentinels occupy physical 0,1)
  if (nullifierCount > 0xfffffffen) {
    fail(`${label}: nullifierCount exceeds 0xfffffffe`);
  }

  return Object.freeze({
    profileId,
    noteRoot,
    nullifierRoot,
    noteCount: noteCount.toString(),
    nullifierCount: nullifierCount.toString(),
    maximumLiveNotes: maximumLiveNotes.toString(),
    reserveSats: reserveSats.toString(),
    actionSequence: actionSequence.toString(),
    liveNoteCount: liveNoteCount.toString(),
  });
}

/** Pick only wire fields (ignore derived liveNoteCount etc.). */
export function wirePoolStateFields(value) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail('pool state must be an object');
  }
  const out = {};
  for (const key of STATE_KEYS) {
    if (value[key] === undefined) fail(`pool state missing ${key}`);
    out[key] = value[key];
  }
  return out;
}

export function encodePoolStateV2(value) {
  const s = normalizePoolStateV2(wirePoolStateFields(value), 'pool state');
  const out = Buffer.alloc(POOL_STATE_BYTES);
  STATE_MAGIC.copy(out, 0);
  Buffer.from(s.profileId, 'hex').copy(out, 4);
  Buffer.from(s.noteRoot, 'hex').copy(out, 36);
  Buffer.from(s.nullifierRoot, 'hex').copy(out, 68);
  out.writeUInt32LE(Number(BigInt(s.noteCount)), 100);
  out.writeUInt32LE(Number(BigInt(s.nullifierCount)), 104);
  out.writeUInt32LE(Number(BigInt(s.maximumLiveNotes)), 108);
  out.writeBigUInt64LE(BigInt(s.reserveSats), 112);
  out.writeBigUInt64LE(BigInt(s.actionSequence), 120);
  if (out.length !== POOL_STATE_BYTES) fail('internal state length mismatch');
  return out;
}

export function decodePoolStateV2(value) {
  if (!(value instanceof Uint8Array) || value.length !== POOL_STATE_BYTES) {
    fail(`pool state must contain exactly ${POOL_STATE_BYTES} bytes`);
  }
  const bytes = Buffer.from(value);
  if (!bytes.subarray(0, 4).equals(STATE_MAGIC)) {
    fail('pool state magic is invalid (expected SKS2)');
  }
  const decoded = {
    profileId: bytes.subarray(4, 36).toString('hex'),
    noteRoot: bytes.subarray(36, 68).toString('hex'),
    nullifierRoot: bytes.subarray(68, 100).toString('hex'),
    noteCount: BigInt(bytes.readUInt32LE(100)).toString(),
    nullifierCount: BigInt(bytes.readUInt32LE(104)).toString(),
    maximumLiveNotes: BigInt(bytes.readUInt32LE(108)).toString(),
    reserveSats: bytes.readBigUInt64LE(112).toString(),
    actionSequence: bytes.readBigUInt64LE(120).toString(),
  };
  return normalizePoolStateV2(decoded, 'decoded pool state');
}

/** Compare two normalized states for equality on wire fields. */
export function poolStatesEqual(a, b) {
  for (const key of STATE_KEYS) {
    if (a[key] !== b[key]) return false;
  }
  return true;
}

export function emptyGenesisStateFields({
  profileId,
  noteRoot = ZERO_32_HEX,
  nullifierRoot = ZERO_32_HEX,
  maximumLiveNotes,
}) {
  // Empty pool: noteCount=0, nullifierCount=0, actionSequence=0, reserve=0
  // Roots must be supplied as empty-tree roots from the tree module.
  return normalizePoolStateV2({
    profileId,
    noteRoot,
    nullifierRoot,
    noteCount: '0',
    nullifierCount: '0',
    maximumLiveNotes: String(maximumLiveNotes),
    reserveSats: '0',
    actionSequence: '0',
  });
}
