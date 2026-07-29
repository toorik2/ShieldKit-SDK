import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import {
  BN254_FR_MODULUS, IndexedNullifierTreeError, audit, create, insert, rebuild, verifyInsertionWitness,
} from './indexed-nullifier-tree.mjs';

const encode = (value) => value.toString(16).padStart(64, '0');
const key = (value) => Buffer.from(encode(value), 'hex');
const hashValues = (label, values) => BigInt(`0x${createHash('sha256').update(label).update(values.map(encode).join('')).digest('hex')}`) % BN254_FR_MODULUS;
const hashes = Object.freeze({ hashLeaf: (inputs) => hashValues('leaf', inputs), hashNode: (left, right) => hashValues('node', [left, right]) });

function independentLeafHash(leaf) {
  const codes = { empty: 0n, min: 1n, normal: 2n, max: 3n };
  return leaf.type === 'empty'
    ? hashValues('leaf', [0n, 0n, 0n, 0n, 0n])
    : hashValues('leaf', [codes[leaf.type], BigInt(leaf.index), BigInt(`0x${leaf.key}`), BigInt(leaf.successorIndex), BigInt(`0x${leaf.successorKey}`)]);
}

function independentRoot(tree) {
  const defaults = [independentLeafHash({ type: 'empty', index: 0, key: encode(0n), successorIndex: 0, successorKey: encode(0n) })];
  for (let level = 0; level < tree.depth; level += 1) defaults.push(hashValues('node', [defaults[level], defaults[level]]));
  let layer = new Map(tree.leaves.map((leaf) => [leaf.index, independentLeafHash(leaf)]).filter(([, value]) => value !== defaults[0]));
  for (let level = 0; level < tree.depth; level += 1) {
    const parents = new Set([...layer.keys()].map((index) => Math.floor(index / 2)));
    const next = new Map();
    for (const parent of parents) {
      const value = hashValues('node', [layer.get(parent * 2) ?? defaults[level], layer.get((parent * 2) + 1) ?? defaults[level]]);
      if (value !== defaults[level + 1]) next.set(parent, value);
    }
    layer = next;
  }
  return layer.get(0) ?? defaults[tree.depth];
}

function permutations(values) {
  if (values.length < 2) return [values];
  return values.flatMap((value, index) => permutations([...values.slice(0, index), ...values.slice(index + 1)]).map((tail) => [value, ...tail]));
}

test('depth-4 tree exhausts every insertion order with independent roots and sequential witnesses', () => {
  const values = [0n, 2n, 19n, BN254_FR_MODULUS - 1n];
  for (const order of permutations(values)) {
    let tree = create({ depth: 4, ...hashes });
    assert.equal(rebuild(tree), independentRoot(tree));
    for (const value of order) {
      const result = insert(tree, key(value));
      assert.equal(verifyInsertionWitness(tree, result.witness), true);
      tree = result.tree;
      assert.equal(tree.root, independentRoot(tree));
      assert.equal(rebuild(tree), independentRoot(tree));
      assert.equal(audit(tree).normalCount, tree.nextIndex - 2);
    }
    const sorted = tree.leaves.filter((leaf) => leaf.type === 'normal').map((leaf) => BigInt(`0x${leaf.key}`)).sort((a, b) => (a < b ? -1 : 1));
    assert.deepEqual(sorted, [...values].sort((a, b) => (a < b ? -1 : 1)));
  }
});

test('depth-4 exhaustively enumerates finite-domain reachable states and legal transitions', () => {
  // These are all reachable prefix states and all legal next-key transitions
  // for this declared adversarial domain: boundaries, adjacent values, and
  // values straddling several predecessor positions. This is exhaustive over
  // the domain, not a random sample of the full Fr key space.
  const domain = [0n, 1n, 2n, 19n, BN254_FR_MODULUS - 1n];
  let states = [{ tree: create({ depth: 4, ...hashes }), remaining: domain }];
  let stateCount = 0;
  let transitionCount = 0;
  while (states.length > 0) {
    const next = [];
    for (const state of states) {
      stateCount += 1;
      assert.equal(audit(state.tree).root, independentRoot(state.tree));
      for (const value of state.remaining) {
        const result = insert(state.tree, key(value));
        transitionCount += 1;
        assert.equal(verifyInsertionWitness(state.tree, result.witness), true);
        assert.equal(audit(result.tree).root, independentRoot(result.tree));
        assert.throws(() => insert(result.tree, key(value)), /already present/);
        next.push({ tree: result.tree, remaining: state.remaining.filter((candidate) => candidate !== value) });
      }
    }
    states = next;
  }
  // sum(P(5, k), k=0..5) states; each nonterminal state has every legal edge.
  assert.equal(stateCount, 326);
  assert.equal(transitionCount, 325);
});

test('rejects duplicate and noncanonical encodings, accepts Uint8Array, and never aliases caller bytes', () => {
  let tree = create({ depth: 4, ...hashes });
  const callerBytes = new Uint8Array(key(0n));
  tree = insert(tree, callerBytes).tree;
  callerBytes.fill(0xff);
  assert.equal(tree.leaves[2].key, encode(0n));
  assert.throws(() => insert(tree, key(0n)), IndexedNullifierTreeError);
  assert.throws(() => insert(tree, key(BN254_FR_MODULUS)), /canonical BN254 Fr/);
  assert.throws(() => insert(tree, new Uint8Array(31)), /32-byte Uint8Array/);
  const hi = BN254_FR_MODULUS - 1n;
  const updated = insert(tree, key(hi)).tree;
  assert.equal(updated.leaves.filter((leaf) => leaf.type === 'normal').some((leaf) => leaf.key === encode(hi)), true);
});

test('depth-32 creation is sparse and edge keys retain normative sentinel and empty encodings', () => {
  const emptyInputs = [];
  const recordingHashes = {
    hashLeaf: (inputs) => {
      if (inputs.every((value) => value === 0n)) emptyInputs.push(inputs);
      return hashValues('leaf', inputs);
    },
    hashNode: hashes.hashNode,
  };
  let tree = create({ depth: 32, ...recordingHashes });
  assert.equal(tree.capacity, 2 ** 32);
  assert.equal(tree.leaves.length, 2);
  assert.deepEqual(tree.leaves[0], { type: 'min', index: 0, key: encode(0n), successorIndex: 1, successorKey: encode(0n) });
  assert.deepEqual(tree.leaves[1], { type: 'max', index: 1, key: encode(0n), successorIndex: 1, successorKey: encode(0n) });
  assert.equal(emptyInputs.length > 0, true);
  assert.deepEqual(emptyInputs[0], [0n, 0n, 0n, 0n, 0n]);
  const low = insert(tree, key(0n));
  assert.equal(verifyInsertionWitness(tree, low.witness), true);
  tree = low.tree;
  const high = insert(tree, key(BN254_FR_MODULUS - 1n));
  assert.equal(verifyInsertionWitness(tree, high.witness), true);
  tree = high.tree;
  assert.equal(tree.leaves.length, 4);
  assert.equal(tree.root, independentRoot(tree));
});

test('rejects a full tree and detects corrupted successor topology', () => {
  let tree = create({ depth: 2, ...hashes });
  tree = insert(tree, key(3n)).tree;
  tree = insert(tree, key(7n)).tree;
  assert.throws(() => insert(tree, key(11n)), /tree is full/);
  const leaves = [...tree.leaves];
  leaves[0] = { ...leaves[0], successorKey: encode(99n) };
  const corrupt = { ...tree, leaves };
  assert.throws(() => audit(corrupt), /successor pointer key/);
});

test('rejects bad successor order, cycles, aliases, and noncanonical stored encodings', () => {
  let tree = create({ depth: 4, ...hashes });
  for (const value of [0n, 7n, 19n]) tree = insert(tree, key(value)).tree;
  const badOrderLeaves = tree.leaves.map((leaf) => ({ ...leaf }));
  // The physical append order is 0, 7, 19; make 7 point backwards to 0.
  badOrderLeaves[3].successorIndex = 2;
  badOrderLeaves[3].successorKey = encode(0n);
  assert.throws(() => audit({ ...tree, leaves: badOrderLeaves }), /strictly ordered|cycle/);

  const cycleLeaves = tree.leaves.map((leaf) => ({ ...leaf }));
  cycleLeaves[2].successorIndex = 2;
  cycleLeaves[2].successorKey = cycleLeaves[2].key;
  assert.throws(() => audit({ ...tree, leaves: cycleLeaves }), /cycle|strictly ordered/);

  const aliasLeaves = tree.leaves.map((leaf) => ({ ...leaf }));
  aliasLeaves[3].index = 2;
  assert.throws(() => audit({ ...tree, leaves: aliasLeaves }), /append prefix/);

  const noncanonicalLeaves = tree.leaves.map((leaf) => ({ ...leaf }));
  noncanonicalLeaves[2].key = encode(BN254_FR_MODULUS);
  assert.throws(() => audit({ ...tree, leaves: noncanonicalLeaves }), /canonical BN254 Fr/);
});

test('witness mutations are rejected and model outputs are immutable', () => {
  const tree = create({ depth: 4, ...hashes });
  const result = insert(tree, key(9n));
  assert.equal(Object.isFrozen(result.tree), true);
  assert.equal(Object.isFrozen(result.tree.leaves), true);
  assert.equal(Object.isFrozen(result.witness), true);
  assert.equal(Object.isFrozen(result.witness.append), true);
  assert.throws(() => { result.tree.leaves[2] = result.tree.leaves[0]; }, TypeError);
  const badRoot = { ...result.witness, postRoot: result.witness.postRoot + 1n };
  assert.throws(() => verifyInsertionWitness(tree, badRoot), /post-root/);
  const badPath = { ...result.witness, predecessorPath: [...result.witness.predecessorPath.slice(0, -1), 0n] };
  assert.throws(() => verifyInsertionWitness(tree, badPath), /predecessor path/);
  const badPointer = { ...result.witness, updatedPredecessor: { ...result.witness.updatedPredecessor, successorKey: encode(8n) } };
  assert.throws(() => verifyInsertionWitness(tree, badPointer), /pointer/);
  const badAppend = { ...result.witness, append: { ...result.witness.append, index: 3 } };
  assert.throws(() => verifyInsertionWitness(tree, badAppend), /append index/);
});
