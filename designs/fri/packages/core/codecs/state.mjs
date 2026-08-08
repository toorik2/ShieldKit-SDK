/**
 * SFS1 — native 128-byte state NFT commitment.
 * Normative: FRI_STARK_REPLACEMENT_PLAN.md
 */
import { createHash } from 'node:crypto';
import { digest4FromHex, digest4ToHex, ZERO_DIGEST4_HEX } from '../crypto/h4.mjs';

export const STATE_BYTES = 128;
export const STATE_MAGIC = Buffer.from('SFS1');
export const DENOMINATION_SATS = 10_000_000n;
export const DEFAULT_MAX_LIVE = 100_000;

function u32le(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(Number(n) >>> 0, 0);
  return b;
}
function u64le(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n), 0);
  return b;
}
function hex32(h, label) {
  if (typeof h !== 'string' || !/^[0-9a-f]{64}$/i.test(h)) {
    throw new Error(`bad 32-byte hex ${label}`);
  }
  return Buffer.from(h.toLowerCase(), 'hex');
}

export function assertStateInvariants(state, denomination = DENOMINATION_SATS) {
  const noteCount = Number(state.noteCount);
  const nullifierCount = Number(state.nullifierCount);
  const maximumLiveNotes = Number(state.maximumLiveNotes);
  const reserveSats = BigInt(state.reserveSats);
  const actionSequence = BigInt(state.actionSequence);
  if (!Number.isInteger(noteCount) || noteCount < 0) throw new Error('bad noteCount');
  if (!Number.isInteger(nullifierCount) || nullifierCount < 0) throw new Error('bad nullifierCount');
  if (nullifierCount > noteCount) throw new Error('nullifierCount > noteCount');
  if (nullifierCount > 0xfffffffe) throw new Error('nullifierCount overflow');
  const live = noteCount - nullifierCount;
  if (reserveSats !== BigInt(live) * denomination) throw new Error('reserveSats mismatch');
  if (maximumLiveNotes < 1) throw new Error('maximumLiveNotes < 1');
  if (live > maximumLiveNotes) throw new Error('live exceeds maximumLiveNotes');
  if (actionSequence < BigInt(Math.max(noteCount, nullifierCount))) {
    throw new Error('actionSequence too small');
  }
  if (actionSequence > BigInt(noteCount + nullifierCount)) {
    throw new Error('actionSequence too large');
  }
  digest4FromHex(state.noteRoot);
  digest4FromHex(state.nullifierRoot);
  if (!/^[0-9a-f]{64}$/i.test(state.profileId)) throw new Error('bad profileId');
}

export function encodeState(state) {
  assertStateInvariants(state);
  const buf = Buffer.concat([
    STATE_MAGIC,
    hex32(state.profileId, 'profileId'),
    hex32(state.noteRoot, 'noteRoot'),
    hex32(state.nullifierRoot, 'nullifierRoot'),
    u32le(state.noteCount),
    u32le(state.nullifierCount),
    u32le(state.maximumLiveNotes),
    u64le(state.reserveSats),
    u64le(state.actionSequence),
  ]);
  if (buf.length !== STATE_BYTES) throw new Error(`SFS1 length ${buf.length}`);
  return buf;
}

export function decodeState(bytes) {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (buf.length !== STATE_BYTES) throw new Error(`SFS1 must be ${STATE_BYTES} bytes`);
  if (!buf.subarray(0, 4).equals(STATE_MAGIC)) throw new Error('bad SFS1 magic');
  const state = {
    profileId: buf.subarray(4, 36).toString('hex'),
    noteRoot: buf.subarray(36, 68).toString('hex'),
    nullifierRoot: buf.subarray(68, 100).toString('hex'),
    noteCount: buf.readUInt32LE(100),
    nullifierCount: buf.readUInt32LE(104),
    maximumLiveNotes: buf.readUInt32LE(108),
    reserveSats: buf.readBigUInt64LE(112).toString(),
    actionSequence: buf.readBigUInt64LE(120).toString(),
  };
  assertStateInvariants(state);
  return state;
}

/** NFT commitment is exactly the 128-byte state (no hash pointer). */
export function nftCommitmentFromState(state) {
  return encodeState(state);
}

export function genesisState({ profileId, maximumLiveNotes = DEFAULT_MAX_LIVE }) {
  return {
    profileId: profileId.toLowerCase(),
    noteRoot: ZERO_DIGEST4_HEX,
    nullifierRoot: ZERO_DIGEST4_HEX,
    noteCount: 0,
    nullifierCount: 0,
    maximumLiveNotes,
    reserveSats: '0',
    actionSequence: '0',
  };
}

export function profileIdFromManifest(manifestObject) {
  // JCS-like: stable JSON key order for our manifests
  const json = JSON.stringify(manifestObject);
  return createHash('sha256').update(json).digest('hex');
}

export { digest4ToHex, ZERO_DIGEST4_HEX };
