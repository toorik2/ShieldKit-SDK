// Sparse, append-only V2 note-tree reference model. Output note leaves are
// already commitments: this module never hashes them as leaves.

export const BN254_FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export class NoteTreeError extends Error {
  constructor(message) { super(message); this.name = 'NoteTreeError'; }
}

const fail = (message) => { throw new NoteTreeError(message); };
const freeze = (value) => Object.freeze(value);
const isObject = (value) => value !== null && !Array.isArray(value) && typeof value === 'object';
const frHex = (value) => value.toString(16).padStart(64, '0');
// Only state emitted by this module may advance. Audit deliberately remains
// capability-free so callers can authenticate decoded snapshot-shaped data.
const trustedTrees = new WeakSet();

function requireTrusted(tree) {
  if (!isObject(tree) || !trustedTrees.has(tree)) fail('tree is not a trusted note-tree capability');
}

function canonicalFr(value, label) {
  if (typeof value !== 'bigint' || value < 0n || value >= BN254_FR_MODULUS) fail(`${label} must be a canonical BN254 Fr bigint`);
  return value;
}

function parseFrHex(value, label) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail(`${label} must be lowercase 32-byte Fr hex`);
  return canonicalFr(BigInt(`0x${value}`), label);
}

function assertDepth(depth) {
  if (!Number.isInteger(depth) || depth < 2 || depth > 32) fail('depth must be an integer from 2 to 32');
  return depth;
}

function hashNode(tree, left, right) {
  return canonicalFr(tree.hashNode(canonicalFr(left, 'left node'), canonicalFr(right, 'right node')), 'hashNode output');
}

function defaultsFor(depth, emptyLeafHash, nodeHasher) {
  const defaults = [canonicalFr(emptyLeafHash, 'emptyLeafHash')];
  const context = { hashNode: nodeHasher };
  for (let level = 0; level < depth; level += 1) defaults.push(hashNode(context, defaults[level], defaults[level]));
  return freeze(defaults);
}

function nodeKey(level, index) { return `${level}:${index}`; }

function rowsToMap(rows) {
  return new Map(rows.map((row) => [nodeKey(row.level, row.index), row.value]));
}

function sortedRows(nodes) {
  return freeze([...nodes.entries()].map(([key, value]) => {
    const [level, index] = key.split(':').map(Number);
    return freeze({ level, index, value });
  }).sort((a, b) => a.level - b.level || a.index - b.index));
}

function checkTreeShape(tree) {
  if (!isObject(tree) || typeof tree.hashNode !== 'function') fail('tree must be a model created by create');
  assertDepth(tree.depth);
  const capacity = 2 ** tree.depth;
  if (tree.capacity !== capacity || !Number.isInteger(tree.nextIndex) || tree.nextIndex < 0 || tree.nextIndex > capacity) fail('tree metadata is invalid');
  canonicalFr(tree.emptyLeafHash, 'tree emptyLeafHash');
  if (!Array.isArray(tree.defaults) || tree.defaults.length !== tree.depth + 1) fail('tree defaults are invalid');
  for (const value of tree.defaults) canonicalFr(value, 'tree default');
  if (!Array.isArray(tree.frontier) || tree.frontier.length !== tree.depth) fail('tree frontier is invalid');
  for (const value of tree.frontier) if (value !== null) canonicalFr(value, 'tree frontier value');
  if (!Array.isArray(tree.leaves) || tree.leaves.length !== tree.nextIndex) fail('tree leaves are invalid');
  for (let index = 0; index < tree.leaves.length; index += 1) canonicalFr(tree.leaves[index], `leaf ${index}`);
  if (!Array.isArray(tree.nodes)) fail('tree sparse nodes are invalid');
  const seen = new Set();
  for (const row of tree.nodes) {
    if (!isObject(row) || !Number.isInteger(row.level) || !Number.isInteger(row.index)) fail('tree sparse node is malformed');
    if (row.level < 0 || row.level > tree.depth || row.index < 0 || row.index >= 2 ** (tree.depth - row.level)) fail('tree sparse node address is invalid');
    canonicalFr(row.value, 'tree sparse node value');
    const key = nodeKey(row.level, row.index);
    if (seen.has(key)) fail('tree sparse nodes contain duplicate keys');
    seen.add(key);
  }
  canonicalFr(tree.root, 'tree root');
}

function advance(state, outputNoteLeaf) {
  const index = state.nextIndex;
  if (index >= state.capacity) fail('tree is full');
  const value = canonicalFr(outputNoteLeaf, 'outputNoteLeaf');
  const siblings = [];
  let node = value;
  state.nodes.set(nodeKey(0, index), node);
  for (let level = 0; level < state.depth; level += 1) {
    const bit = Math.floor(index / (2 ** level)) % 2;
    const sibling = bit === 0 ? state.defaults[level] : state.frontier[level];
    if (sibling === null) fail(`frontier is missing left sibling at level ${level}`);
    siblings.push(sibling);
    // Retain the most recent completed left subtree. It is consumed for this
    // right child and then overwritten when the next left subtree begins.
    if (bit === 0) state.frontier[level] = node;
    node = bit === 0 ? hashNode(state, node, sibling) : hashNode(state, sibling, node);
    state.nodes.set(nodeKey(level + 1, Math.floor(index / (2 ** (level + 1)))), node);
  }
  state.leaves.push(value);
  state.nextIndex += 1;
  state.root = node;
  return freeze(siblings);
}

function buildFromLeaves({ depth, emptyLeafHash, hashNode: nodeHasher, leaves }) {
  const capacity = 2 ** depth;
  const state = {
    depth, capacity, emptyLeafHash, hashNode: nodeHasher,
    defaults: defaultsFor(depth, emptyLeafHash, nodeHasher), frontier: Array(depth).fill(null),
    nodes: new Map(), leaves: [], nextIndex: 0, root: 0n,
  };
  state.root = state.defaults[depth];
  for (const leaf of leaves) advance(state, leaf);
  return state;
}

function pathRoot(tree, leafValue, index, siblings, label) {
  if (!Number.isInteger(index) || index < 0 || index >= tree.capacity) fail(`${label} index is invalid`);
  if (!Array.isArray(siblings) || siblings.length !== tree.depth) fail(`${label} path has wrong depth`);
  let node = canonicalFr(leafValue, `${label} leaf`);
  for (let level = 0; level < tree.depth; level += 1) {
    const sibling = canonicalFr(siblings[level], `${label} sibling ${level}`);
    const bit = Math.floor(index / (2 ** level)) % 2;
    node = bit === 0 ? hashNode(tree, node, sibling) : hashNode(tree, sibling, node);
  }
  return node;
}

function sameRows(actual, expected) {
  if (actual.length !== expected.length) return false;
  return actual.every((row, index) => row.level === expected[index].level && row.index === expected[index].index && row.value === expected[index].value);
}

/** Create an empty sparse note tree. `emptyLeafHash` is already a canonical Fr leaf hash. */
export function create({ depth, emptyLeafHash, hashNode: nodeHasher } = {}) {
  assertDepth(depth);
  if (typeof nodeHasher !== 'function') fail('create requires hashNode(left, right)');
  const defaults = defaultsFor(depth, emptyLeafHash, nodeHasher);
  const tree = freeze({
    depth, capacity: 2 ** depth, emptyLeafHash: canonicalFr(emptyLeafHash, 'emptyLeafHash'), hashNode: nodeHasher,
    defaults, frontier: freeze(Array(depth).fill(null)), nodes: freeze([]), leaves: freeze([]), nextIndex: 0, root: defaults[depth],
  });
  trustedTrees.add(tree);
  return tree;
}

/** Append an already-committed note leaf. Exactly `depth` hashNode invocations are made. */
export function append(tree, outputNoteLeaf) {
  requireTrusted(tree);
  checkTreeShape(tree);
  const state = {
    ...tree, frontier: [...tree.frontier], nodes: rowsToMap(tree.nodes), leaves: [...tree.leaves],
  };
  const index = state.nextIndex;
  const preRoot = state.root;
  const path = advance(state, outputNoteLeaf);
  const witness = freeze({
    depth: tree.depth, index, outputNoteLeaf: canonicalFr(outputNoteLeaf, 'outputNoteLeaf'), preRoot, postRoot: state.root,
    emptyAppendPath: path, membershipPath: freeze([...path]),
  });
  const nextTree = freeze({
    ...tree, frontier: freeze(state.frontier), nodes: sortedRows(state.nodes), leaves: freeze(state.leaves), nextIndex: state.nextIndex, root: state.root,
  });
  trustedTrees.add(nextTree);
  return freeze({ tree: nextTree, witness });
}

/** Independently recompute root and sparse state from append-ordered leaves. */
export function rebuild(tree) {
  checkTreeShape(tree);
  const rebuilt = buildFromLeaves({ depth: tree.depth, emptyLeafHash: tree.emptyLeafHash, hashNode: tree.hashNode, leaves: tree.leaves });
  return rebuilt.root;
}

/** Validate every stored frontier/node value against a rebuild from canonical append leaves. */
export function audit(tree) {
  checkTreeShape(tree);
  const rebuilt = buildFromLeaves({ depth: tree.depth, emptyLeafHash: tree.emptyLeafHash, hashNode: tree.hashNode, leaves: tree.leaves });
  if (tree.root !== rebuilt.root) fail('tree root does not match append leaves');
  if (tree.defaults.length !== rebuilt.defaults.length || tree.defaults.some((value, index) => value !== rebuilt.defaults[index])) fail('tree defaults do not match empty leaf hash');
  if (tree.frontier.some((value, index) => value !== rebuilt.frontier[index])) fail('tree frontier does not match append leaves');
  if (!sameRows(tree.nodes, sortedRows(rebuilt.nodes))) fail('tree sparse nodes do not match append leaves');
  return freeze({ root: tree.root, nextIndex: tree.nextIndex, capacity: tree.capacity });
}

/** Verify an append witness against its pre-append tree, including the post-append membership proof. */
export function verifyAppendWitness(tree, witness) {
  audit(tree);
  if (!isObject(witness) || witness.depth !== tree.depth || !Number.isInteger(witness.index)) fail('witness is malformed');
  if (witness.index !== tree.nextIndex || witness.index >= tree.capacity) fail('witness append index is invalid');
  canonicalFr(witness.outputNoteLeaf, 'witness outputNoteLeaf');
  canonicalFr(witness.preRoot, 'witness preRoot');
  canonicalFr(witness.postRoot, 'witness postRoot');
  if (witness.preRoot !== tree.root) fail('witness pre-root does not match tree root');
  if (pathRoot(tree, tree.emptyLeafHash, witness.index, witness.emptyAppendPath, 'empty append path') !== witness.preRoot) fail('empty append path does not prove pre-root');
  if (pathRoot(tree, witness.outputNoteLeaf, witness.index, witness.membershipPath, 'membership path') !== witness.postRoot) fail('membership path does not prove post-root');
  for (let level = 0; level < tree.depth; level += 1) if (witness.emptyAppendPath[level] !== witness.membershipPath[level]) fail('append and membership paths disagree');
  return true;
}

/** Verify a current membership path for an already-appended note leaf. */
export function verifyMembershipPath(tree, index, outputNoteLeaf, siblings) {
  audit(tree);
  if (!Number.isInteger(index) || index < 0 || index >= tree.nextIndex) fail('membership index is not occupied');
  if (canonicalFr(outputNoteLeaf, 'outputNoteLeaf') !== tree.leaves[index]) fail('membership leaf does not match stored leaf');
  if (pathRoot(tree, outputNoteLeaf, index, siblings, 'membership path') !== tree.root) fail('membership path does not prove tree root');
  return true;
}

/** Derive a current membership path from sparse nodes/defaults for an occupied index. */
export function membershipPath(tree, index) {
  requireTrusted(tree);
  checkTreeShape(tree);
  if (!Number.isInteger(index) || index < 0 || index >= tree.nextIndex) fail('membership index is not occupied');
  const nodes = rowsToMap(tree.nodes);
  const siblings = [];
  for (let level = 0; level < tree.depth; level += 1) {
    const siblingIndex = (Math.floor(index / (2 ** level))) ^ 1;
    siblings.push(nodes.get(nodeKey(level, siblingIndex)) ?? tree.defaults[level]);
  }
  return freeze(siblings);
}

/** Deterministic transport form: all sparse keys are sorted and values are canonical hex. */
export function snapshot(tree) {
  audit(tree);
  return freeze({
    version: 1, depth: tree.depth, nextIndex: tree.nextIndex, root: frHex(tree.root), emptyLeafHash: frHex(tree.emptyLeafHash),
    frontier: freeze(tree.frontier.map((value) => value === null ? null : frHex(value))),
    leaves: freeze(tree.leaves.map((value, index) => freeze({ key: String(index), value: frHex(value) }))),
    nodes: freeze(tree.nodes.map((row) => freeze({ key: nodeKey(row.level, row.index), value: frHex(row.value) }))),
  });
}

/** Restore and fully authenticate a deterministic snapshot with injected hashing. */
export function restore(snapshotValue, { emptyLeafHash, hashNode: nodeHasher } = {}) {
  if (!isObject(snapshotValue) || Object.keys(snapshotValue).sort().join(',') !== 'depth,emptyLeafHash,frontier,leaves,nextIndex,nodes,root,version') fail('snapshot has missing or unknown properties');
  if (snapshotValue.version !== 1 || !Number.isInteger(snapshotValue.nextIndex)) fail('snapshot metadata is invalid');
  assertDepth(snapshotValue.depth);
  if (!Array.isArray(snapshotValue.leaves) || snapshotValue.leaves.length !== snapshotValue.nextIndex) fail('snapshot leaves are invalid');
  const leaves = snapshotValue.leaves.map((entry, index) => {
    if (!isObject(entry) || entry.key !== String(index)) fail('snapshot leaf keys are not canonical and sorted');
    return parseFrHex(entry.value, `snapshot leaf ${index}`);
  });
  const tree = create({ depth: snapshotValue.depth, emptyLeafHash, hashNode: nodeHasher });
  if (snapshotValue.emptyLeafHash !== frHex(tree.emptyLeafHash)) fail('snapshot empty leaf hash does not match injected hash');
  let restored = tree;
  for (const leaf of leaves) restored = append(restored, leaf).tree;
  const expected = snapshot(restored);
  if (JSON.stringify(snapshotValue) !== JSON.stringify(expected)) fail('snapshot does not match authenticated sparse state');
  trustedTrees.add(restored);
  return restored;
}
