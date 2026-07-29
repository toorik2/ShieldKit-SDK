import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import {
  BN254_FR_MODULUS, NoteTreeError, append, audit, create, membershipPath, rebuild, restore, snapshot, verifyAppendWitness, verifyMembershipPath,
} from './note-tree.mjs';

const encode = (value) => value.toString(16).padStart(64, '0');
const hash = (left, right) => BigInt(`0x${createHash('sha256').update(encode(left)).update(encode(right)).digest('hex')}`) % BN254_FR_MODULUS;
const empty = BigInt(`0x${createHash('sha256').update('test empty leaf').digest('hex')}`) % BN254_FR_MODULUS;
const hasher = Object.freeze({ emptyLeafHash: empty, hashNode: hash });

function independentRoot(depth, leaves) {
  const defaults = [empty];
  for (let level = 0; level < depth; level += 1) defaults.push(hash(defaults[level], defaults[level]));
  let layer = new Map(leaves.map((value, index) => [index, value]));
  for (let level = 0; level < depth; level += 1) {
    const parents = new Set([...layer.keys()].map((index) => Math.floor(index / 2)));
    const next = new Map();
    for (const parent of parents) next.set(parent, hash(layer.get(parent * 2) ?? defaults[level], layer.get((parent * 2) + 1) ?? defaults[level]));
    layer = next;
  }
  return layer.get(0) ?? defaults[depth];
}

test('depth-4 append paths match independently rebuilt roots and preserve the old tree', () => {
  let tree = create({ depth: 4, ...hasher });
  const initialRoot = tree.root;
  assert.equal(audit(tree).root, initialRoot);
  for (const leaf of [0n, 9n, BN254_FR_MODULUS - 1n, 42n]) {
    const before = tree;
    const result = append(tree, leaf);
    assert.equal(before.root, tree.root);
    assert.equal(verifyAppendWitness(tree, result.witness), true);
    tree = result.tree;
    assert.equal(verifyMembershipPath(tree, result.witness.index, leaf, result.witness.membershipPath), true);
    assert.equal(tree.root, independentRoot(tree.depth, tree.leaves));
    assert.equal(rebuild(tree), tree.root);
  }
  for (let index = 0; index < tree.nextIndex; index += 1) {
    assert.equal(verifyMembershipPath(tree, index, tree.leaves[index], membershipPath(tree, index)), true);
  }
  assert.equal(Object.isFrozen(tree.nodes[0]), true);
});

test('depth-4 exhausts every reachable append count and transition, including Fr boundaries', () => {
  let tree = create({ depth: 4, ...hasher });
  const leaves = Array.from({ length: tree.capacity }, (_, index) => {
    if (index === 0) return 0n;
    if (index === tree.capacity - 1) return BN254_FR_MODULUS - 1n;
    return BigInt(index * 97);
  });
  for (let index = 0; index < leaves.length; index += 1) {
    // This loop visits the sole structural note-tree state at each reachable
    // append count, then its only append transition for the declared leaf.
    assert.equal(tree.nextIndex, index);
    assert.equal(audit(tree).root, independentRoot(4, leaves.slice(0, index)));
    const result = append(tree, leaves[index]);
    assert.equal(verifyAppendWitness(tree, result.witness), true);
    tree = result.tree;
    assert.equal(tree.root, independentRoot(4, leaves.slice(0, index + 1)));
    for (let member = 0; member <= index; member += 1) {
      assert.equal(verifyMembershipPath(tree, member, leaves[member], membershipPath(tree, member)), true);
    }
  }
  assert.equal(tree.nextIndex, tree.capacity);
  assert.throws(() => append(tree, 1n), /tree is full/);
});

test('mutated paths, noncanonical leaves, and overwrite-shaped state are rejected', () => {
  const tree = create({ depth: 4, ...hasher });
  const result = append(tree, 7n);
  const badPath = { ...result.witness, membershipPath: [...result.witness.membershipPath.slice(0, -1), 0n] };
  assert.throws(() => verifyAppendWitness(tree, badPath), /membership path/);
  assert.throws(() => append(tree, BN254_FR_MODULUS), /canonical BN254 Fr/);
  const overwrite = { ...result.tree, nextIndex: 0 };
  assert.throws(() => audit(overwrite), /tree leaves are invalid/);
  assert.throws(() => append(overwrite, 8n), /trusted note-tree capability/);
});

test('plain cloned tree objects cannot append or derive paths, while audit can authenticate them', () => {
  const tree = append(create({ depth: 4, ...hasher }), 11n).tree;
  const clone = { ...tree };
  assert.doesNotThrow(() => audit(clone));
  assert.throws(() => append(clone, 12n), /trusted note-tree capability/);
  assert.throws(() => membershipPath(clone, 0), /trusted note-tree capability/);
  assert.equal(verifyMembershipPath(tree, 0, 11n, membershipPath(tree, 0)), true);
});

test('depth-32 remains sparse, supports edge leaves, and appends exactly depth node hashes', () => {
  let calls = 0;
  const counted = { emptyLeafHash: empty, hashNode: (left, right) => { calls += 1; return hash(left, right); } };
  let tree = create({ depth: 32, ...counted });
  assert.equal(calls, 32);
  assert.equal(tree.leaves.length, 0);
  assert.equal(tree.nodes.length, 0);
  calls = 0;
  let result = append(tree, 0n);
  assert.equal(calls, 32);
  assert.equal(verifyAppendWitness(tree, result.witness), true);
  tree = result.tree;
  calls = 0;
  result = append(tree, BN254_FR_MODULUS - 1n);
  assert.equal(calls, 32);
  assert.equal(tree.leaves.length, 1);
  assert.equal(result.tree.leaves.length, 2);
});

test('depth-2 full tree and deterministic snapshot restore reject tampering', () => {
  let tree = create({ depth: 2, ...hasher });
  for (const leaf of [1n, 2n, 3n, 4n]) tree = append(tree, leaf).tree;
  assert.throws(() => append(tree, 5n), /tree is full/);
  const saved = snapshot(tree);
  const restored = restore(saved, hasher);
  assert.deepEqual(snapshot(restored), saved);
  const corruptRoot = { ...saved, root: encode(0n) };
  assert.throws(() => restore(corruptRoot, hasher), /authenticated sparse state/);
  const corruptNode = { ...saved, nodes: [...saved.nodes.slice(0, -1), { ...saved.nodes.at(-1), key: '0:0' }] };
  assert.throws(() => restore(corruptNode, hasher), /authenticated sparse state/);
});
