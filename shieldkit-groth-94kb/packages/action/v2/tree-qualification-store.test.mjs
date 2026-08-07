import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import * as notes from './note-tree.mjs';
import * as nullifiers from './indexed-nullifier-tree.mjs';
import { createIndexedNullifierQualificationStore, createNoteQualificationStore } from './tree-qualification-store.mjs';

const encode = (value) => value.toString(16).padStart(64, '0');
const key = (value) => Buffer.from(encode(value), 'hex');
const hash = (label, values) => BigInt(`0x${createHash('sha256').update(label).update(values.map(encode).join('')).digest('hex')}`) % notes.BN254_FR_MODULUS;
const noteHash = Object.freeze({ emptyLeafHash: hash('note-empty', [0n]), hashNode: (left, right) => hash('note-node', [left, right]) });
const nullifierHash = Object.freeze({ hashLeaf: (inputs) => hash('nullifier-leaf', inputs), hashNode: (left, right) => hash('nullifier-node', [left, right]) });

test('logarithmic note substrate agrees with frozen reference roots on every small prefix', () => {
  let reference = notes.create({ depth: 4, ...noteHash });
  const store = createNoteQualificationStore({ depth: 4, ...noteHash });
  for (const value of [0n, 3n, 5n, notes.BN254_FR_MODULUS - 1n, 9n, 12n]) {
    reference = notes.append(reference, value).tree;
    const result = store.append(value);
    assert.equal(result.root, reference.root);
    assert.equal(result.work, 4);
    assert.equal(store.snapshot().root, reference.root);
  }
  assert.equal(Object.isFrozen(store.snapshot()), true);
});

test('logarithmic indexed substrate matches frozen reference topology/root and fixed work', () => {
  let reference = nullifiers.create({ depth: 4, ...nullifierHash });
  const store = createIndexedNullifierQualificationStore({ depth: 4, maximumInserts: 14, ...nullifierHash });
  for (const value of [19n, 0n, 7n, nullifiers.BN254_FR_MODULUS - 1n, 2n]) {
    reference = nullifiers.insert(reference, key(value)).tree;
    const result = store.insert(value);
    assert.equal(result.root, reference.root);
    assert.equal(result.work, 8);
    assert.equal(store.snapshot().root, reference.root);
  }
  assert.throws(() => store.insert(7n), /already present/);
  assert.equal(store.snapshot().normalCount, 5);
});

test('AVL predecessor index withstands the former deterministic-priority spine sequence', () => {
  // The former treap used SplitMix32(index) as a predictable priority. Mapping
  // each physical insertion index to its priority rank made the resulting
  // Cartesian tree a linear spine and overflowed Node around 10,430 inserts.
  const oldPriority = (index) => {
    let value = (index + 0x9e3779b9) >>> 0;
    value = Math.imul(value ^ (value >>> 16), 0x85ebca6b) >>> 0;
    value = Math.imul(value ^ (value >>> 13), 0xc2b2ae35) >>> 0;
    return (value ^ (value >>> 16)) >>> 0;
  };
  const count = 10_430;
  const ranks = new Map(
    Array.from({ length: count }, (_, index) => ({ index, priority: oldPriority(index + 2) }))
      .sort((left, right) => left.priority - right.priority || left.index - right.index)
      .map((entry, rank) => [entry.index, BigInt(rank)]),
  );
  const store = createIndexedNullifierQualificationStore({ depth: 32, maximumInserts: count, ...nullifierHash });
  let maximumOperationWork = 0;
  for (let index = 0; index < count; index += 1) {
    const result = store.insert(ranks.get(index));
    maximumOperationWork = Math.max(maximumOperationWork, result.indexWork);
  }
  const snapshot = store.snapshot();
  assert.equal(snapshot.normalCount, count);
  assert.ok(snapshot.indexHeight <= Math.ceil(1.45 * Math.log2(count + 2)) + 1);
  assert.ok(snapshot.maxSearchDepth <= snapshot.indexHeight);
  assert.ok(snapshot.maxIndexDepth <= Math.ceil(2 * Math.log2(count + 2)));
  assert.ok(maximumOperationWork <= Math.ceil(3 * Math.log2(count + 2)));
  assert.ok(snapshot.indexWork > 0);
});
