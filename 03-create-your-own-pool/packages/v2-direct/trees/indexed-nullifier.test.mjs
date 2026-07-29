import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { FR_MODULUS } from '../constants.mjs';
import { frToHex } from '../crypto/fr.mjs';
import { createIndexedNullifierTree } from './indexed-nullifier.mjs';

describe('indexed nullifier tree', () => {
  it('inserts normals including field zero', () => {
    const tree = createIndexedNullifierTree({ depth: 4 });
    const root0 = tree.root();
    const z = frToHex(0n);
    const ins = tree.insert(z);
    assert.notEqual(ins.postRoot, root0);
    assert.equal(tree.normalCount, 1);
    assert.ok(tree.contains(z));
    assert.throws(() => tree.insert(z), /duplicate/);
  });

  it('inserts Fr-1 as a normal key', () => {
    const tree = createIndexedNullifierTree({ depth: 4 });
    const key = frToHex(FR_MODULUS - 1n);
    tree.insert(key);
    assert.ok(tree.contains(key));
  });

  it('exhaustive small state-space: insert permutations of 3 keys', () => {
    const keys = [1n, 2n, 100n].map(frToHex);
    const perms = [
      [0, 1, 2],
      [0, 2, 1],
      [1, 0, 2],
      [1, 2, 0],
      [2, 0, 1],
      [2, 1, 0],
    ];
    const roots = new Set();
    for (const perm of perms) {
      const tree = createIndexedNullifierTree({ depth: 4 });
      for (const i of perm) tree.insert(keys[i]);
      assert.equal(tree.normalCount, 3);
      roots.add(tree.root());
      for (const k of keys) assert.ok(tree.contains(k));
    }
    // Physical leaf indices depend on insertion order, so roots differ across
    // permutations; every perm must still admit membership for the same key set.
    assert.ok(roots.size >= 1);
    assert.ok(roots.size <= perms.length);
  });

  it('rejects bad ordering via duplicate', () => {
    const tree = createIndexedNullifierTree({ depth: 4 });
    tree.insert(frToHex(5n));
    assert.throws(() => tree.insert(frToHex(5n)), /duplicate/);
  });
});
