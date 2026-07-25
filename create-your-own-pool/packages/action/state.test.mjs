import assert from 'node:assert/strict';
import test from 'node:test';
import {
  decodeStateNftCommitment,
  encodeStateNftCommitment,
  STATE_NFT_COMMITMENT_BYTES,
  STATE_NFT_COMMITMENT_LIMIT_BYTES,
} from './state.mjs';

const value = {
  networkId: 2,
  instanceId: '11'.repeat(32),
  stateCommitment: '22'.repeat(32),
  actionSequence: '18446744073709551615',
};

test('round-trips the exact 80-byte SHST commitment', () => {
  const encoded = encodeStateNftCommitment(value);
  assert.equal(encoded.length, STATE_NFT_COMMITMENT_BYTES);
  assert.ok(encoded.length <= STATE_NFT_COMMITMENT_LIMIT_BYTES);
  assert.equal(encoded.subarray(0, 8).toString('hex'), '5348535401020000');
  assert.deepEqual(decodeStateNftCommitment(encoded), value);
});

test('rejects malformed, noncanonical, and unsupported commitments', () => {
  assert.throws(
    () => encodeStateNftCommitment({ ...value, actionSequence: '01' }),
    /canonical unsigned decimal/,
  );
  assert.throws(
    () => encodeStateNftCommitment({ ...value, networkId: 1 }),
    /network is unsupported/,
  );
  const encoded = encodeStateNftCommitment(value);
  for (const [offset, pattern] of [
    [0, /magic/],
    [4, /version/],
    [5, /network/],
    [6, /reserved/],
  ]) {
    const mutated = Buffer.from(encoded);
    mutated[offset] ^= 1;
    assert.throws(() => decodeStateNftCommitment(mutated), pattern);
  }
  assert.throws(() => decodeStateNftCommitment(encoded.subarray(1)), /exactly 80 bytes/);
});
