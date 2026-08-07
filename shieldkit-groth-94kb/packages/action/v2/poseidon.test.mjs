import assert from 'node:assert/strict';
import test from 'node:test';

import { BN254_SCALAR_FIELD_MODULUS } from './domains.mjs';
import {
  frFromCanonicalHex,
  frToCanonicalHex,
  hashEmptyNoteLeaf,
  hashIndexedNullifierLeaf,
  hashIndexedNullifierNode,
  hashNoteTreeNode,
  hashOutputNoteLeaf,
  identifierToU128Limbs,
  poseidonHash,
  V2PoseidonError,
} from './poseidon.mjs';

test('implements canonical field and raw-SHA identifier codecs', () => {
  assert.equal(frFromCanonicalHex('0'.repeat(64)), 0n);
  assert.equal(frToCanonicalHex(BN254_SCALAR_FIELD_MODULUS - 1n),
    (BN254_SCALAR_FIELD_MODULUS - 1n).toString(16).padStart(64, '0'));
  assert.deepEqual(identifierToU128Limbs(`${'01'.repeat(16)}${'fe'.repeat(16)}`), [
    BigInt(`0x${'01'.repeat(16)}`),
    BigInt(`0x${'fe'.repeat(16)}`),
  ]);
  assert.throws(
    () => frFromCanonicalHex(BN254_SCALAR_FIELD_MODULUS.toString(16).padStart(64, '0')),
    V2PoseidonError,
  );
});

test('pins the V2 tree and authenticated-tag leaf Poseidon known-answer values', () => {
  const emptyNote = hashEmptyNoteLeaf();
  const noteParent = hashNoteTreeNode(emptyNote, emptyNote);
  const emptyNullifier = hashIndexedNullifierLeaf([0n, 0n, 0n, 0n, 0n]);
  const minSentinel = hashIndexedNullifierLeaf([1n, 0n, 0n, 1n, 0n]);
  const nullifierParent = hashIndexedNullifierNode(minSentinel, emptyNullifier);
  const recordTag = 11n;
  const outputLeaf = hashOutputNoteLeaf(7n, recordTag);
  assert.deepEqual({
    emptyNote: frToCanonicalHex(emptyNote),
    noteParent: frToCanonicalHex(noteParent),
    emptyNullifier: frToCanonicalHex(emptyNullifier),
    minSentinel: frToCanonicalHex(minSentinel),
    nullifierParent: frToCanonicalHex(nullifierParent),
    recordTag: frToCanonicalHex(recordTag),
    outputLeaf: frToCanonicalHex(outputLeaf),
  }, {
    emptyNote: '24fda6f2c3c9b7492e55e47bc6adc8041391570282c3c6cf97329abd31128081',
    noteParent: '265399a22fcc1a8f382ddeec66cc3b4fee4e52a4352d5209fcad526fd21e769c',
    emptyNullifier: '18df533689e5101f3e88e6e91339f278f68a84c86f22997b1bb28be7dec598a6',
    minSentinel: '04b96bcec386361928f02ccd62ed02446db3d900d3ce3083f6dbd5007b8d20e5',
    nullifierParent: '1fd573ef8ff8f6825abec3fe3b725941e4035344df59e31ee23a9766de8a9221',
    recordTag: '000000000000000000000000000000000000000000000000000000000000000b',
    outputLeaf: '0cda43a183b48956f4e64cb87efdcd9a716e8ad1354640895240cc3f2ffb6f09',
  });
});

test('rejects malformed arities, noncanonical leaf inputs, and empty-leaf aliases', () => {
  assert.throws(() => poseidonHash(), /arity/);
  assert.throws(() => poseidonHash(BN254_SCALAR_FIELD_MODULUS), /canonical/);
  assert.throws(
    () => hashOutputNoteLeaf(1n, BN254_SCALAR_FIELD_MODULUS),
    /record tag/,
  );
  assert.throws(
    () => hashIndexedNullifierLeaf([0n, 1n, 0n, 0n, 0n]),
    /all be zero/,
  );
});
