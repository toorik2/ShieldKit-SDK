#!/usr/bin/env node
// Bounded, exhaustive structural qualification for the V2 indexed-nullifier
// tree algorithm under one deterministic non-production hash backend.
//
// Exhaustive means every ordered, duplicate-free subset of BOUNDARY_KEYS is
// exercised at depth four: sum(P(7, k), k = 0..7) = 13,700 traces. This is
// deliberately not a claim to enumerate BN254 Fr or to replace the separate
// explicitly-invoked large-store campaign. It also does not qualify the
// production Poseidon implementation: existing Poseidon vectors are a
// separate evidence obligation.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as nullifiers from './indexed-nullifier-tree.mjs';
import { createIndexedNullifierQualificationStore } from './tree-qualification-store.mjs';

const { BN254_FR_MODULUS: FR } = nullifiers;
const DEPTH = 4;
const CAPACITY = 2 ** DEPTH;
const ZERO = 0n;
const encode = (value) => value.toString(16).padStart(64, '0');
const keyBytes = (value) => Buffer.from(encode(value), 'hex');
const hash = (label, values) => BigInt(`0x${createHash('sha256').update(label).update(values.map(encode).join('')).digest('hex')}`) % FR;
const leafHashCache = new Map();
const nodeHashCache = new Map();

// These fixed keys deliberately occupy both canonical field edges and five
// strictly ordered interior positions. Every insertion order is covered.
export const BOUNDARY_KEYS = Object.freeze([
  0n, 1n, 2n, (FR / 3n), (FR / 2n), FR - 2n, FR - 1n,
]);

export const DEPTH4_HASHES = Object.freeze({
  hashLeaf: (inputs) => {
    const cacheKey = inputs.map(encode).join('');
    if (!leafHashCache.has(cacheKey)) leafHashCache.set(cacheKey, hash('shieldkit-v2-depth4-nullifier-leaf', inputs));
    return leafHashCache.get(cacheKey);
  },
  hashNode: (left, right) => {
    const cacheKey = `${encode(left)}${encode(right)}`;
    if (!nodeHashCache.has(cacheKey)) nodeHashCache.set(cacheKey, hash('shieldkit-v2-depth4-nullifier-node', [left, right]));
    return nodeHashCache.get(cacheKey);
  },
});

const emptyLeaf = (index) => ({ type: 'empty', index, key: encode(ZERO), successorIndex: 0, successorKey: encode(ZERO) });
const maxLeaf = () => ({ type: 'max', index: 1, key: encode(ZERO), successorIndex: 1, successorKey: encode(ZERO) });
const normalLeaf = (index, value, successorIndex, successorValue) => ({ type: 'normal', index, key: encode(value), successorIndex, successorKey: encode(successorValue) });
const minLeaf = (successorIndex, successorValue) => ({ type: 'min', index: 0, key: encode(ZERO), successorIndex, successorKey: encode(successorValue) });

function canonical(value, label) {
  if (typeof value !== 'bigint' || value < ZERO || value >= FR) throw new TypeError(`${label} must be a canonical BN254 Fr bigint`);
  return value;
}

function referenceLeaves(entries) {
  const sorted = [...entries].sort((left, right) => left.value < right.value ? -1 : left.value > right.value ? 1 : 0);
  const successorFor = new Map(sorted.map((entry, index) => [entry.index, sorted[index + 1] ?? null]));
  const leaves = Array.from({ length: CAPACITY }, (_, index) => emptyLeaf(index));
  const first = sorted[0] ?? null;
  leaves[0] = minLeaf(first?.index ?? 1, first?.value ?? ZERO);
  leaves[1] = maxLeaf();
  for (const entry of entries) {
    const successor = successorFor.get(entry.index);
    leaves[entry.index] = normalLeaf(entry.index, entry.value, successor?.index ?? 1, successor?.value ?? ZERO);
  }
  return { leaves, sorted };
}

// This oracle intentionally has no dependency on indexed-nullifier-tree.mjs:
// it materializes all 16 leaves and every Merkle layer from sorted keys plus
// physical append positions, then derives paths by direct array indexing.
function referenceBuild(entries) {
  const { leaves, sorted } = referenceLeaves(entries);
  return referenceBuildFromLeaves(leaves, entries, sorted);
}

function referenceInsert(before, value) {
  canonical(value, 'reference key');
  if (before.entries.length >= CAPACITY - 2) throw new RangeError('reference tree is full');
  if (before.entries.some((entry) => entry.value === value)) throw new Error('reference nullifier key is already present');
  const predecessor = [...before.sorted].reverse().find((entry) => entry.value < value) ?? { index: 0, value: ZERO };
  const appendIndex = before.entries.length + 2;
  const intermediateLeaves = before.leaves.map((leaf) => ({ ...leaf }));
  intermediateLeaves[predecessor.index] = predecessor.index === 0
    ? minLeaf(appendIndex, value)
    : normalLeaf(predecessor.index, predecessor.value, appendIndex, value);
  const intermediate = referenceBuildFromLeaves(intermediateLeaves, before.entries, before.sorted);
  const entries = [...before.entries, { index: appendIndex, value }];
  const after = referenceBuild(entries);
  return {
    after,
    expectedWitness: {
      key: encode(value), preRoot: before.root, intermediateRoot: intermediate.root, postRoot: after.root,
      predecessor: before.leaves[predecessor.index],
      updatedPredecessor: intermediate.leaves[predecessor.index], predecessorPath: before.paths[predecessor.index],
      append: { index: appendIndex, emptyLeaf: before.leaves[appendIndex], newLeaf: after.leaves[appendIndex], path: intermediate.paths[appendIndex] },
    },
  };
}

function referenceBuildFromLeaves(leaves, entries, sorted) {
  const levels = [leaves.map((leaf) => DEPTH4_HASHES.hashLeaf(leaf.type === 'empty'
    ? [0n, 0n, 0n, 0n, 0n]
    : [leaf.type === 'min' ? 1n : leaf.type === 'normal' ? 2n : 3n, BigInt(leaf.index), BigInt(`0x${leaf.key}`), BigInt(leaf.successorIndex), BigInt(`0x${leaf.successorKey}`)]))];
  for (let level = 0; level < DEPTH; level += 1) {
    const previous = levels[level];
    levels.push(Array.from({ length: previous.length / 2 }, (_, index) => DEPTH4_HASHES.hashNode(previous[index * 2], previous[(index * 2) + 1])));
  }
  const paths = Array.from({ length: CAPACITY }, (_, index) => {
    const siblings = [];
    let cursor = index;
    for (let level = 0; level < DEPTH; level += 1) { siblings.push(levels[level][cursor ^ 1]); cursor = Math.floor(cursor / 2); }
    return siblings;
  });
  return { entries, sorted, leaves, levels, paths, root: levels[DEPTH][0] };
}

function allocatedLeaves(reference) { return reference.leaves.slice(0, reference.entries.length + 2); }

function assertState(tree, reference, label) {
  assert.equal(tree.root, reference.root, `${label}: real-tree root differs from independent oracle`);
  assert.deepEqual(tree.leaves, allocatedLeaves(reference), `${label}: successor topology differs from independent oracle`);
  assert.equal(nullifiers.audit(tree).root, reference.root, `${label}: real-tree audit root differs from oracle`);
  const ordered = reference.sorted.map((entry) => entry.value);
  assert.deepEqual(ordered, [...ordered].sort((left, right) => left < right ? -1 : left > right ? 1 : 0), `${label}: oracle successor order is not strict`);
}

function assertWitness(tree, actual, expected, label) {
  assert.equal(nullifiers.verifyInsertionWitness(tree, actual), true, `${label}: real insertion witness is invalid`);
  assert.equal(actual.key, expected.key, `${label}: witness key differs`);
  assert.equal(actual.preRoot, expected.preRoot, `${label}: witness pre-root differs`);
  assert.equal(actual.intermediateRoot, expected.intermediateRoot, `${label}: witness intermediate root differs`);
  assert.equal(actual.postRoot, expected.postRoot, `${label}: witness post-root differs`);
  assert.deepEqual(actual.predecessor, expected.predecessor, `${label}: witness predecessor differs`);
  assert.deepEqual(actual.updatedPredecessor, expected.updatedPredecessor, `${label}: witness predecessor update differs`);
  assert.deepEqual(actual.predecessorPath, expected.predecessorPath, `${label}: witness predecessor path differs`);
  assert.deepEqual(actual.append, expected.append, `${label}: witness append update/path differs`);
}

function replayStore(sequence, expectedRoots, counters, digest) {
  const store = createIndexedNullifierQualificationStore({ depth: DEPTH, maximumInserts: CAPACITY - 2, ...DEPTH4_HASHES });
  for (let index = 0; index < sequence.length; index += 1) {
    const result = store.insert(sequence[index]);
    assert.equal(result.root, expectedRoots[index], `store replay ${sequence.join(',')} step ${index}: root differs from oracle`);
    assert.equal(result.work, DEPTH * 2, `store replay ${sequence.join(',')} step ${index}: work differs`);
    counters.storeInsertions += 1;
    digest.update(encode(result.root));
  }
  if (sequence.length > 0) {
    assert.throws(() => store.insert(sequence.at(-1)), /already present/, 'store must reject a duplicate at every non-empty exhaustive state');
    counters.duplicateRejections += 1;
  }
}

function boundaryFailures(counters) {
  let tree = nullifiers.create({ depth: DEPTH, ...DEPTH4_HASHES });
  let reference = referenceBuild([]);
  const store = createIndexedNullifierQualificationStore({ depth: DEPTH, maximumInserts: CAPACITY - 2, ...DEPTH4_HASHES });
  const fill = [0n, ...Array.from({ length: CAPACITY - 4 }, (_, index) => BigInt(index + 1)), FR - 1n];
  for (const value of fill) {
    const expected = referenceInsert(reference, value);
    const actual = nullifiers.insert(tree, keyBytes(value));
    assertWitness(tree, actual.witness, expected.expectedWitness, 'capacity boundary');
    tree = actual.tree;
    reference = expected.after;
    assert.equal(store.insert(value).root, reference.root, 'full-tree store root differs');
  }
  assert.equal(reference.entries.length, CAPACITY - 2, 'full-tree reference must consume all normal slots');
  assert.throws(() => nullifiers.insert(tree, keyBytes(FR - 2n)), /tree is full/);
  assert.throws(() => store.insert(FR - 2n), /tree is full/);
  assert.throws(() => referenceInsert(reference, FR - 2n), /full/);
  assert.throws(() => nullifiers.insert(tree, keyBytes(FR)), /canonical BN254 Fr/);
  assert.throws(() => store.insert(FR), /canonical BN254 Fr/);
  assert.throws(() => referenceInsert(reference, FR), /canonical BN254 Fr/);
  assert.throws(() => nullifiers.insert(tree, Buffer.alloc(31)), /32-byte/);
  counters.boundaryRejections += 7;
}

/** Run the fixed, finite depth-4 structural campaign and return stable JSON-safe evidence. */
export function runDepth4ExhaustiveQualification() {
  const counters = { traces: 0, treeInsertions: 0, storeInsertions: 0, duplicateRejections: 0, boundaryRejections: 0 };
  const digest = createHash('sha256').update('shieldkit-v2-depth4-indexed-nullifier-state-space-v1');
  const visit = (sequence, tree, reference, expectedRoots) => {
    counters.traces += 1;
    assertState(tree, reference, `trace ${sequence.join(',') || 'empty'}`);
    replayStore(sequence, expectedRoots, counters, digest);
    if (sequence.length > 0) {
      const duplicate = sequence.at(-1);
      assert.throws(() => nullifiers.insert(tree, keyBytes(duplicate)), /already present/, 'real tree must reject a duplicate at every non-empty exhaustive state');
      assert.throws(() => referenceInsert(reference, duplicate), /already present/, 'independent oracle must reject a duplicate at every non-empty exhaustive state');
    }
    for (const value of BOUNDARY_KEYS) {
      if (sequence.includes(value)) continue;
      const label = `trace ${[...sequence, value].join(',')}`;
      const expected = referenceInsert(reference, value);
      const actual = nullifiers.insert(tree, keyBytes(value));
      assertWitness(tree, actual.witness, expected.expectedWitness, label);
      counters.treeInsertions += 1;
      visit([...sequence, value], actual.tree, expected.after, [...expectedRoots, expected.after.root]);
    }
  };
  visit([], nullifiers.create({ depth: DEPTH, ...DEPTH4_HASHES }), referenceBuild([]), []);
  boundaryFailures(counters);
  assert.equal(counters.traces, 13_700, 'exhaustive trace count changed');
  assert.equal(counters.treeInsertions, 13_699, 'exhaustive transition count changed');
  assert.equal(counters.storeInsertions, 82_201, 'store replay count changed');
  return Object.freeze({
    schema: 'shieldkit-v2-indexed-nullifier-depth4-exhaustive-v1',
    status: 'completed-bounded-structural-campaign',
    claims: Object.freeze({
      realV2TreeAlgorithmCompared: true,
      realV2StoreAlgorithmCompared: true,
      independentTreeAssemblyOracle: true,
      independentHashOracle: false,
      deterministicNonProductionHashBackend: true,
      productionPoseidonHashBackend: false,
      exhaustiveOverFixedCorpus: true,
      exhaustiveOverBn254Field: false,
      exhaustiveThroughFullDepth4Capacity: false,
      millionEntryCampaignRun: false,
      productionQualification: false,
    }),
    exhaustiveDefinition: Object.freeze({
      depth: DEPTH,
      normalLeafCapacity: CAPACITY - 2,
      corpus: 'all ordered duplicate-free subsets of the fixed seven-key canonical boundary corpus',
      corpusKeys: BOUNDARY_KEYS.map(encode),
      traces: counters.traces,
      treeInsertionTransitions: counters.treeInsertions,
      storeReplayInsertions: counters.storeInsertions,
      comparedAfterEveryInsertion: Object.freeze(['root', 'witness predecessor path', 'witness append path', 'successor ordering', 'store root']),
    }),
    failures: Object.freeze({ duplicateRejectionStates: counters.duplicateRejections, boundaryAndEncodingRejections: counters.boundaryRejections }),
    evidenceDigestSha256: digest.digest('hex'),
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.argv.length !== 3 || process.argv[2] !== '--json') throw new Error('usage: node tree-qualification-depth4.mjs --json');
  console.log(JSON.stringify(runDepth4ExhaustiveQualification(), null, 2));
}
