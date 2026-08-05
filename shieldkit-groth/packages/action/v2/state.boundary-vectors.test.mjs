import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { decodeStateNftCommitment, encodeStateNftCommitment } from './state.mjs';

const vectorPath = fileURLToPath(new URL('./vectors/q01-state-boundary-vectors.jsonl', import.meta.url));
const expectedIds = Object.freeze([
  'zero-roots-empty-live-set', 'minimum-nonzero-roots-one-live', 'maximum-canonical-roots-empty-live-set',
  'noncanonical-note-root-modulus', 'noncanonical-nullifier-root-modulus', 'count-and-nullifier-maximums',
  'nullifier-count-u32-maximum-rejected', 'nullifier-count-exceeds-note-count', 'maximum-live-notes-one-live-one',
  'live-count-exceeds-maximum-live-notes', 'maximum-live-notes-210000000-and-maximum-reserve',
  'maximum-live-notes-above-denomination-cap', 'maximum-live-notes-zero', 'reserve-zero-empty-live-set',
  'reserve-mismatch-one-satoshi', 'action-sequence-counter-floor', 'action-sequence-counter-ceiling',
  'action-sequence-below-counter-floor', 'action-sequence-above-counter-ceiling',
  'action-sequence-absolute-maximum-rejected-by-counter-ceiling', 'action-sequence-absolute-range-limit',
  'u32-little-endian-pattern', 'u64-reserve-little-endian-pattern', 'u64-action-sequence-little-endian-pattern',
  'state-length-127', 'state-length-129',
]);
const stateKeys = Object.freeze(['actionSequence', 'maximumLiveNotes', 'noteCount', 'noteRoot', 'nullifierCount', 'nullifierRoot', 'profileId', 'reserveSats']);
const keys = (value) => Object.keys(value).sort();

test('Q01 state boundary vector matrix exactly validates the JavaScript SKS2 codec', () => {
  const records = readFileSync(vectorPath, 'utf8').trimEnd().split('\n').map((line) => JSON.parse(line));
  const [header, ...vectors] = records;
  assert.deepEqual(keys(header), ['defaultState', 'denominationSats', 'schema', 'stateBytes', 'vectorCount']);
  assert.equal(header.schema, 'shieldkit/v2-direct-q01-state-boundary-vectors/v1');
  assert.equal(header.denominationSats, '10000000');
  assert.equal(header.stateBytes, 128);
  assert.deepEqual(keys(header.defaultState), stateKeys);
  assert.equal(header.vectorCount, vectors.length);
  assert.deepEqual(vectors.map((vector) => vector.id), expectedIds);

  let accepted = 0;
  let rejected = 0;
  for (const vector of vectors) {
    const hasState = Object.hasOwn(vector, 'state');
    assert.deepEqual(keys(vector), hasState ? ['expect', 'id', 'state', 'stateHex'] : ['expect', 'id', 'stateHex']);
    assert.ok(vector.expect === 'accept' || vector.expect === 'reject');
    assert.match(vector.stateHex, /^[0-9a-f]*$/);
    const bytes = Buffer.from(vector.stateHex, 'hex');
    if (!hasState) {
      assert.equal(vector.expect, 'reject');
      assert.notEqual(bytes.length, header.stateBytes);
      assert.throws(() => decodeStateNftCommitment(bytes, { denominationSats: header.denominationSats }), /exactly 128 bytes/);
      rejected += 1;
      continue;
    }
    assert.deepEqual(keys(vector.state), keys(vector.state).filter((key) => stateKeys.includes(key)));
    const state = { ...header.defaultState, ...vector.state };
    assert.equal(bytes.length, header.stateBytes);
    if (vector.expect === 'accept') {
      assert.equal(encodeStateNftCommitment(state, { denominationSats: header.denominationSats }).toString('hex'), vector.stateHex, vector.id);
      assert.deepEqual(decodeStateNftCommitment(bytes, { denominationSats: header.denominationSats }), state, vector.id);
      accepted += 1;
    } else {
      assert.throws(() => encodeStateNftCommitment(state, { denominationSats: header.denominationSats }), undefined, vector.id);
      assert.throws(() => decodeStateNftCommitment(bytes, { denominationSats: header.denominationSats }), undefined, vector.id);
      rejected += 1;
    }
  }
  assert.equal(accepted, 10);
  assert.equal(rejected, 16);
});
