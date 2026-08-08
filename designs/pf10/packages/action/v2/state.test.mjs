import assert from 'node:assert/strict';
import test from 'node:test';

import {
  BN254_FR_MODULUS,
  decodeStateNftCommitment,
  encodeStateNftCommitment,
  MAX_MONEY_SATS,
  STATE_NFT_COMMITMENT_BYTES,
  STATE_NFT_COMMITMENT_LIMIT_BYTES,
  STATE_NFT_OFFSETS,
} from './state.mjs';

const context = Object.freeze({ denominationSats: '10000000' });
const fr = (value) => value.toString(16).padStart(64, '0');
const state = Object.freeze({
  profileId: '11'.repeat(32),
  noteRoot: fr(1n),
  nullifierRoot: fr(2n),
  noteCount: '3',
  nullifierCount: '1',
  maximumLiveNotes: '7',
  reserveSats: '20000000',
  actionSequence: '3',
});

test('encodes the exact 128-byte SKS2 layout and round-trips it', () => {
  const encoded = encodeStateNftCommitment(state, context);
  const golden = [
    '534b5332',
    '11'.repeat(32),
    fr(1n),
    fr(2n),
    '03000000',
    '01000000',
    '07000000',
    '002d310100000000',
    '0300000000000000',
  ].join('');
  assert.equal(encoded.length, STATE_NFT_COMMITMENT_BYTES);
  assert.equal(STATE_NFT_COMMITMENT_BYTES, 128);
  assert.equal(STATE_NFT_COMMITMENT_LIMIT_BYTES, 128);
  assert.equal(encoded.toString('hex'), golden);
  assert.equal(encoded.subarray(STATE_NFT_OFFSETS.noteCount, STATE_NFT_OFFSETS.noteCount + 4).toString('hex'), '03000000');
  assert.equal(encoded.subarray(STATE_NFT_OFFSETS.reserveSats, STATE_NFT_OFFSETS.reserveSats + 8).toString('hex'), '002d310100000000');
  assert.deepEqual(decodeStateNftCommitment(encoded, context), state);
});

test('requires explicit denomination context and all state invariants', () => {
  assert.throws(() => encodeStateNftCommitment(state), /state context/);
  assert.throws(() => encodeStateNftCommitment(state, { denominationSats: '01' }), /canonical unsigned decimal/);
  assert.throws(() => encodeStateNftCommitment(state, { denominationSats: '0' }), /nonzero/);
  assert.throws(() => encodeStateNftCommitment({ ...state, nullifierCount: '4' }, context), /exceeds noteCount/);
  assert.throws(() => encodeStateNftCommitment({ ...state, maximumLiveNotes: '0' }, context), /at least one/);
  assert.throws(() => encodeStateNftCommitment({ ...state, maximumLiveNotes: (MAX_MONEY_SATS / 10_000_000n + 1n).toString() }, context), /MAX_MONEY/);
  assert.throws(() => encodeStateNftCommitment({ ...state, maximumLiveNotes: '1' }, context), /exceeds maximumLiveNotes/);
  assert.throws(() => encodeStateNftCommitment({ ...state, reserveSats: '1' }, context), /must equal/);
  assert.throws(() => encodeStateNftCommitment({ ...state, actionSequence: '2' }, context), /counter floor/);
  assert.throws(() => encodeStateNftCommitment({ ...state, actionSequence: '5' }, context), /counter ceiling/);
  assert.throws(() => encodeStateNftCommitment({ ...state, actionSequence: (1n << 33n).toString() }, context), /exceeds its range/);
  assert.throws(() => encodeStateNftCommitment({ ...state, nullifierCount: '4294967295' }, context), /exceeds its range/);
});

test('rejects malformed keys, noncanonical encodings, sizes, and header mutations', () => {
  assert.throws(() => encodeStateNftCommitment({ ...state, extra: true }, context), /missing or unknown/);
  assert.throws(() => encodeStateNftCommitment({ ...state, noteCount: '03' }, context), /canonical unsigned decimal/);
  assert.throws(() => encodeStateNftCommitment({ ...state, profileId: 'AA'.repeat(32) }, context), /lowercase/);
  assert.throws(() => encodeStateNftCommitment({ ...state, noteRoot: fr(BN254_FR_MODULUS) }, context), /canonical BN254/);
  const encoded = encodeStateNftCommitment(state, context);
  for (const length of [127, 129]) {
    const malformed = Buffer.alloc(length);
    encoded.copy(malformed, 0, 0, Math.min(encoded.length, malformed.length));
    assert.throws(() => decodeStateNftCommitment(malformed, context), /exactly 128 bytes/);
  }
  for (let offset = 0; offset < 4; offset += 1) {
    const mutated = Buffer.from(encoded);
    mutated[offset] ^= 1;
    assert.throws(() => decodeStateNftCommitment(mutated, context), /magic/);
  }
});

test('refuses a V1 SHST state rather than migrating or relabeling it as V2', () => {
  const legacyState = Buffer.alloc(80);
  Buffer.from('SHST', 'ascii').copy(legacyState, 0);
  legacyState[4] = 1;
  legacyState[5] = 2;
  assert.throws(
    () => decodeStateNftCommitment(legacyState, context),
    /exactly 128 bytes/,
  );
});
