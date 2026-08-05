// Dependency-injected reference model for the V2 indexed nullifier tree.
// It selects neither a hash implementation nor hash-domain constants.

export const BN254_FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const ZERO_KEY = '0'.repeat(64);
const TYPE_CODE = Object.freeze({ empty: 0n, min: 1n, normal: 2n, max: 3n });

export class IndexedNullifierTreeError extends Error {
  constructor(message) { super(message); this.name = 'IndexedNullifierTreeError'; }
}

const fail = (message) => { throw new IndexedNullifierTreeError(message); };
const freeze = (value) => Object.freeze(value);
const isObject = (value) => value !== null && !Array.isArray(value) && typeof value === 'object';

function canonicalFr(value, label) {
  if (typeof value !== 'bigint' || value < 0n || value >= BN254_FR_MODULUS) fail(`${label} must be a canonical BN254 Fr bigint`);
  return value;
}

function canonicalKey(value, label) {
  if (!(value instanceof Uint8Array) || value.length !== 32) fail(`${label} must be a 32-byte Uint8Array`);
  const copy = Buffer.from(value); // Copy before validation: caller mutation cannot alias model state.
  const hex = copy.toString('hex');
  const parsed = BigInt(`0x${hex}`);
  if (parsed >= BN254_FR_MODULUS) fail(`${label} is not a canonical BN254 Fr encoding`);
  return freeze({ hex, value: parsed });
}

function parseKeyHex(value, label) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail(`${label} must be lowercase 32-byte hex`);
  const parsed = BigInt(`0x${value}`);
  if (parsed >= BN254_FR_MODULUS) fail(`${label} is not a canonical BN254 Fr encoding`);
  return parsed;
}

function assertDepth(depth) {
  if (!Number.isInteger(depth) || depth < 2 || depth > 32) fail('depth must be an integer from 2 to 32');
  return depth;
}

function emptyLeaf(index) {
  return freeze({ type: 'empty', index, key: ZERO_KEY, successorIndex: 0, successorKey: ZERO_KEY });
}

function minLeaf(successorIndex = 1, successorKey = ZERO_KEY) {
  return freeze({ type: 'min', index: 0, key: ZERO_KEY, successorIndex, successorKey });
}

function maxLeaf() {
  return freeze({ type: 'max', index: 1, key: ZERO_KEY, successorIndex: 1, successorKey: ZERO_KEY });
}

function normalLeaf(index, key, successorIndex, successorKey) {
  return freeze({ type: 'normal', index, key, successorIndex, successorKey });
}

function cloneLeaf(leaf) { return freeze({ ...leaf }); }

function assertLeaf(leaf, capacity, label) {
  if (!isObject(leaf) || typeof leaf.type !== 'string' || !Number.isInteger(leaf.index) || !Number.isInteger(leaf.successorIndex)) fail(`${label} is malformed`);
  if (!Object.hasOwn(TYPE_CODE, leaf.type)) fail(`${label}.type is invalid`);
  parseKeyHex(leaf.key, `${label}.key`);
  parseKeyHex(leaf.successorKey, `${label}.successorKey`);
  if (leaf.index < 0 || leaf.index >= capacity || leaf.successorIndex < 0 || leaf.successorIndex >= capacity) fail(`${label} index is out of range`);
  if (leaf.type === 'empty') {
    if (leaf.key !== ZERO_KEY || leaf.successorIndex !== 0 || leaf.successorKey !== ZERO_KEY) fail(`${label} empty encoding is invalid`);
  } else if (leaf.type === 'min') {
    if (leaf.index !== 0 || leaf.key !== ZERO_KEY) fail(`${label} min encoding is invalid`);
  } else if (leaf.type === 'max') {
    if (leaf.index !== 1 || leaf.key !== ZERO_KEY || leaf.successorIndex !== 1 || leaf.successorKey !== ZERO_KEY) fail(`${label} max encoding is invalid`);
  } else if (leaf.index < 2) fail(`${label} normal index is reserved`);
  return leaf;
}

function hashLeaf(tree, leaf) {
  assertLeaf(leaf, tree.capacity, 'leaf');
  // Normative empty-leaf encoding is independent of its physical slot.
  const inputs = leaf.type === 'empty'
    ? freeze([0n, 0n, 0n, 0n, 0n])
    : freeze([TYPE_CODE[leaf.type], BigInt(leaf.index), parseKeyHex(leaf.key, 'leaf.key'), BigInt(leaf.successorIndex), parseKeyHex(leaf.successorKey, 'leaf.successorKey')]);
  return canonicalFr(tree.hashLeaf(inputs), 'hashLeaf output');
}

function hashNode(tree, left, right) {
  return canonicalFr(tree.hashNode(canonicalFr(left, 'left node'), canonicalFr(right, 'right node')), 'hashNode output');
}

function leafMap(tree, leaves = tree.leaves) {
  return new Map(leaves.map((leaf) => [leaf.index, leaf]));
}

function defaultHashes(tree) {
  const defaults = [hashLeaf(tree, emptyLeaf(0))];
  for (let level = 0; level < tree.depth; level += 1) defaults.push(hashNode(tree, defaults[level], defaults[level]));
  return defaults;
}

// Each layer contains only values that differ from that level's default hash.
function sparseLevels(tree, leaves = tree.leaves) {
  const defaults = defaultHashes(tree);
  let layer = new Map();
  for (const leaf of leaves) {
    const value = hashLeaf(tree, leaf);
    if (value !== defaults[0]) layer.set(leaf.index, value);
  }
  const levels = [layer];
  for (let level = 0; level < tree.depth; level += 1) {
    const parents = new Set([...layer.keys()].map((index) => Math.floor(index / 2)));
    const next = new Map();
    for (const parent of parents) {
      const value = hashNode(tree, layer.get(parent * 2) ?? defaults[level], layer.get((parent * 2) + 1) ?? defaults[level]);
      if (value !== defaults[level + 1]) next.set(parent, value);
    }
    layer = next;
    levels.push(layer);
  }
  return freeze({ defaults: freeze(defaults), levels: freeze(levels) });
}

function pathFor(tree, sparse, index) {
  const siblings = [];
  let cursor = index;
  for (let level = 0; level < tree.depth; level += 1) {
    siblings.push(sparse.levels[level].get(cursor ^ 1) ?? sparse.defaults[level]);
    cursor = Math.floor(cursor / 2);
  }
  return freeze(siblings);
}

function rootFromPath(tree, leaf, index, siblings, label) {
  if (!Number.isInteger(index) || index < 0 || index >= tree.capacity) fail(`${label} index is out of range`);
  if (!Array.isArray(siblings) || siblings.length !== tree.depth) fail(`${label} path has wrong depth`);
  let node = hashLeaf(tree, leaf);
  let cursor = index;
  for (let level = 0; level < tree.depth; level += 1) {
    const sibling = canonicalFr(siblings[level], `${label} sibling ${level}`);
    node = (cursor & 1) === 0 ? hashNode(tree, node, sibling) : hashNode(tree, sibling, node);
    cursor = Math.floor(cursor / 2);
  }
  return node;
}

function checkTreeShape(tree) {
  if (!isObject(tree) || typeof tree.hashLeaf !== 'function' || typeof tree.hashNode !== 'function') fail('tree must be a model created by create');
  assertDepth(tree.depth);
  const capacity = 2 ** tree.depth;
  if (tree.capacity !== capacity || !Number.isInteger(tree.nextIndex) || tree.nextIndex < 2 || tree.nextIndex > capacity) fail('tree metadata is invalid');
  if (!Array.isArray(tree.leaves) || tree.leaves.length !== tree.nextIndex) fail('tree must retain only sentinels and allocated normal leaves');
  for (let position = 0; position < tree.leaves.length; position += 1) {
    const leaf = assertLeaf(tree.leaves[position], capacity, `leaves[${position}]`);
    if (position === 0 && leaf.type !== 'min') fail('first stored leaf must be min sentinel');
    if (position === 1 && leaf.type !== 'max') fail('second stored leaf must be max sentinel');
    if (position >= 2 && (leaf.type !== 'normal' || leaf.index !== position)) fail('normal leaves must occupy the append prefix');
  }
  canonicalFr(tree.root, 'tree root');
}

function checkTopology(tree) {
  const byIndex = leafMap(tree);
  let current = byIndex.get(0);
  const seen = new Set();
  let normalCount = 0;
  while (current.type !== 'max') {
    if (seen.has(current.index)) fail('successor list contains a cycle');
    seen.add(current.index);
    const successor = byIndex.get(current.successorIndex);
    if (!successor || (successor.type !== 'normal' && successor.type !== 'max')) fail('successor pointer does not target a normal leaf or max sentinel');
    if (successor.type === 'max') {
      if (current.successorKey !== ZERO_KEY) fail('max successor pointer must encode successorKey zero');
    } else {
      if (successor.key !== current.successorKey) fail('successor pointer key does not match target leaf');
      if (current.type === 'normal' && parseKeyHex(current.key, 'normal key') >= parseKeyHex(successor.key, 'successor key')) fail('normal successor keys are not strictly ordered');
    }
    current = successor;
    if (current.type === 'normal') normalCount += 1;
  }
  if (normalCount !== tree.nextIndex - 2 || seen.size !== normalCount + 1) fail('successor list does not cover every normal leaf exactly once');
}

function predecessorForKey(tree, keyValue) {
  const byIndex = leafMap(tree);
  let current = byIndex.get(0);
  while (current.type !== 'max') {
    const successor = byIndex.get(current.successorIndex);
    if (successor.type === 'max' || keyValue < parseKeyHex(successor.key, 'successor key')) return current;
    if (keyValue === parseKeyHex(successor.key, 'successor key')) fail('nullifier key is already present');
    current = successor;
  }
  fail('indexed successor list is invalid');
}

function contextFromTree(tree) {
  return freeze({ depth: tree.depth, capacity: tree.capacity, hashLeaf: tree.hashLeaf, hashNode: tree.hashNode });
}

/** Create an empty sparse tree. hashLeaf receives [type, index, key, successorIndex, successorKey]. */
export function create({ depth, hashLeaf: leafHasher, hashNode: nodeHasher } = {}) {
  assertDepth(depth);
  if (typeof leafHasher !== 'function' || typeof nodeHasher !== 'function') fail('create requires explicit hashLeaf and hashNode callbacks');
  const capacity = 2 ** depth;
  const draft = { depth, capacity, nextIndex: 2, leaves: freeze([minLeaf(), maxLeaf()]), hashLeaf: leafHasher, hashNode: nodeHasher, root: 0n };
  return freeze({ ...draft, root: sparseLevels(draft).levels[depth].get(0) ?? defaultHashes(draft)[depth] });
}

/** Recompute the root from stored leaves and sparse defaults, without trusting tree.root. */
export function rebuild(tree) {
  checkTreeShape(tree);
  const sparse = sparseLevels(tree);
  return sparse.levels[tree.depth].get(0) ?? sparse.defaults[tree.depth];
}

/** Validate storage shape, sorted successor topology, and the committed root. */
export function audit(tree) {
  checkTreeShape(tree);
  checkTopology(tree);
  const rebuiltRoot = rebuild(tree);
  if (rebuiltRoot !== tree.root) fail('tree root does not match stored leaves');
  return freeze({ root: rebuiltRoot, normalCount: tree.nextIndex - 2, nextIndex: tree.nextIndex, capacity: tree.capacity });
}

/** Insert one canonical 32-byte key, yielding a new tree and a sequential two-update witness. */
export function insert(tree, key) {
  audit(tree);
  const parsedKey = canonicalKey(key, 'key');
  if (tree.nextIndex >= tree.capacity) fail('tree is full');
  const predecessor = predecessorForKey(tree, parsedKey.value);
  const appendIndex = tree.nextIndex;
  const newLeaf = normalLeaf(appendIndex, parsedKey.hex, predecessor.successorIndex, predecessor.successorKey);
  const updatedPredecessor = predecessor.type === 'min'
    ? minLeaf(appendIndex, parsedKey.hex)
    : normalLeaf(predecessor.index, predecessor.key, appendIndex, parsedKey.hex);
  const preSparse = sparseLevels(tree);
  const predecessorPath = pathFor(tree, preSparse, predecessor.index);
  const intermediateRoot = rootFromPath(tree, updatedPredecessor, predecessor.index, predecessorPath, 'predecessor update');
  const intermediateLeaves = tree.leaves.map((leaf) => leaf.index === predecessor.index ? updatedPredecessor : leaf);
  const intermediateTree = { ...tree, leaves: freeze(intermediateLeaves), root: intermediateRoot };
  const intermediateSparse = sparseLevels(intermediateTree);
  if ((intermediateSparse.levels[tree.depth].get(0) ?? intermediateSparse.defaults[tree.depth]) !== intermediateRoot) fail('internal predecessor update mismatch');
  const appendPath = pathFor(tree, intermediateSparse, appendIndex);
  const empty = emptyLeaf(appendIndex);
  if (rootFromPath(tree, empty, appendIndex, appendPath, 'append empty proof') !== intermediateRoot) fail('append position is not proven empty');
  const postRoot = rootFromPath(tree, newLeaf, appendIndex, appendPath, 'append update');
  const postLeaves = [...intermediateLeaves, newLeaf];
  const nextTree = freeze({ ...tree, nextIndex: appendIndex + 1, leaves: freeze(postLeaves), root: postRoot });
  const witness = freeze({
    depth: tree.depth, key: parsedKey.hex, preRoot: tree.root, intermediateRoot, postRoot,
    predecessor: cloneLeaf(predecessor), updatedPredecessor: cloneLeaf(updatedPredecessor), predecessorPath,
    append: freeze({ index: appendIndex, emptyLeaf: empty, newLeaf: cloneLeaf(newLeaf), path: appendPath }),
  });
  audit(nextTree);
  return freeze({ tree: nextTree, witness });
}

/** Verify the ordered predecessor update followed by the append update; throws on mutation or semantic mismatch. */
export function verifyInsertionWitness(tree, witness) {
  audit(tree);
  const context = contextFromTree(tree);
  if (!isObject(witness) || witness.depth !== context.depth || typeof witness.key !== 'string' || !isObject(witness.append)) fail('witness is malformed');
  const keyValue = parseKeyHex(witness.key, 'witness key');
  canonicalFr(witness.preRoot, 'witness preRoot');
  canonicalFr(witness.intermediateRoot, 'witness intermediateRoot');
  canonicalFr(witness.postRoot, 'witness postRoot');
  if (witness.preRoot !== tree.root) fail('witness pre-root does not match tree root');
  const predecessor = assertLeaf(witness.predecessor, context.capacity, 'witness predecessor');
  const updated = assertLeaf(witness.updatedPredecessor, context.capacity, 'witness updated predecessor');
  const append = witness.append;
  const empty = assertLeaf(append.emptyLeaf, context.capacity, 'witness empty append leaf');
  const newLeaf = assertLeaf(append.newLeaf, context.capacity, 'witness new leaf');
  if (!Number.isInteger(append.index) || append.index !== tree.nextIndex || append.index !== empty.index || append.index !== newLeaf.index || append.index < 2) fail('witness append index is invalid');
  if (empty.type !== 'empty' || newLeaf.type !== 'normal' || newLeaf.key !== witness.key) fail('witness append leaf types or key are invalid');
  if (predecessor.type !== 'min' && predecessor.type !== 'normal') fail('witness predecessor type is invalid');
  if (updated.type !== predecessor.type || updated.index !== predecessor.index || updated.key !== predecessor.key) fail('witness predecessor identity changed');
  if (updated.successorIndex !== append.index || updated.successorKey !== witness.key) fail('witness predecessor pointer does not point to new leaf');
  if (newLeaf.successorIndex !== predecessor.successorIndex || newLeaf.successorKey !== predecessor.successorKey) fail('witness new leaf did not inherit old successor');
  if (predecessor.index === append.index || (predecessor.type === 'normal' && keyValue <= parseKeyHex(predecessor.key, 'predecessor key'))) fail('witness key is not greater than predecessor');
  if (predecessor.successorIndex === 1) {
    if (predecessor.successorKey !== ZERO_KEY) fail('witness max successor encoding is invalid');
  } else if (keyValue >= parseKeyHex(predecessor.successorKey, 'old successor key')) fail('witness key is not less than successor');
  if (rootFromPath(context, predecessor, predecessor.index, witness.predecessorPath, 'witness predecessor pre-path') !== witness.preRoot) fail('witness predecessor path does not prove pre-root');
  if (rootFromPath(context, updated, updated.index, witness.predecessorPath, 'witness predecessor intermediate-path') !== witness.intermediateRoot) fail('witness predecessor update does not prove intermediate root');
  if (rootFromPath(context, empty, append.index, append.path, 'witness append empty-path') !== witness.intermediateRoot) fail('witness append path does not prove an empty leaf at intermediate root');
  if (rootFromPath(context, newLeaf, append.index, append.path, 'witness append post-path') !== witness.postRoot) fail('witness append update does not prove post-root');
  return true;
}
