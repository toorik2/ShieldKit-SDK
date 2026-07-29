// Mutable, in-memory qualification substrate for the immutable V2 references.
// It is not a protocol persistence implementation. Its only role is to retain
// authenticated Merkle/frontier and indexed-successor state while making the
// reference topology executable at scale with O(depth) tree work per update.

export const BN254_FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const freeze = (value) => Object.freeze(value);
const keyOf = (level, index) => (level * 0x1_0000_0000) + index;
const canonical = (value, label) => {
  if (typeof value !== 'bigint' || value < 0n || value >= BN254_FR_MODULUS) throw new TypeError(`${label} must be canonical BN254 Fr`);
  return value;
};
const bit = (index, level) => Math.floor(index / (2 ** level)) % 2;

function defaults(depth, empty, hashNode) {
  const values = [canonical(empty, 'empty leaf hash')];
  for (let level = 0; level < depth; level += 1) values.push(canonical(hashNode(values[level], values[level]), 'hashNode output'));
  return values;
}

/** O(depth) append store. Snapshot results are frozen; internals never escape. */
export function createNoteQualificationStore({ depth = 32, emptyLeafHash, hashNode } = {}) {
  if (!Number.isInteger(depth) || depth < 2 || depth > 32 || typeof hashNode !== 'function') throw new TypeError('invalid note qualification configuration');
  const empty = defaults(depth, emptyLeafHash, hashNode);
  const frontier = Array(depth).fill(null);
  let root = empty[depth];
  let nextIndex = 0;
  let work = 0;
  return freeze({
    append(leaf) {
      canonical(leaf, 'note leaf');
      if (nextIndex >= 2 ** depth) throw new RangeError('note tree is full');
      let node = leaf;
      const index = nextIndex;
      for (let level = 0; level < depth; level += 1) {
        const isRight = bit(index, level) === 1;
        const sibling = isRight ? frontier[level] : empty[level];
        if (sibling === null) throw new Error(`frontier missing at level ${level}`);
        if (!isRight) frontier[level] = node;
        node = isRight ? canonical(hashNode(sibling, node), 'hashNode output') : canonical(hashNode(node, sibling), 'hashNode output');
        work += 1;
      }
      root = node;
      nextIndex += 1;
      return freeze({ index, root, work: depth });
    },
    snapshot() { return freeze({ depth, root, nextIndex, work, frontier: freeze([...frontier]) }); },
  });
}

/**
 * O(depth) authenticated indexed-nullifier store. A deterministic AVL index
 * gives worst-case O(log history) predecessor work; a sparse node map holds
 * only non-default Merkle nodes.
 */
export function createIndexedNullifierQualificationStore({ depth = 32, hashLeaf, hashNode, maximumInserts = 1_000_000 } = {}) {
  if (!Number.isInteger(depth) || depth < 2 || depth > 32 || typeof hashLeaf !== 'function' || typeof hashNode !== 'function') throw new TypeError('invalid nullifier qualification configuration');
  if (!Number.isSafeInteger(maximumInserts) || maximumInserts < 1 || maximumInserts > (2 ** depth) - 2) throw new RangeError('invalid maximumInserts');
  const capacity = 2 ** depth;
  const leafHash = (type, index, key, successorIndex, successorKey) => canonical(hashLeaf(type === 0 ? [0n, 0n, 0n, 0n, 0n] : [BigInt(type), BigInt(index), key, BigInt(successorIndex), successorKey]), 'hashLeaf output');
  const emptyLeaf = leafHash(0, 0, 0n, 0, 0n);
  const empty = defaults(depth, emptyLeaf, hashNode);
  const nodes = new Map();
  const slots = maximumInserts + 2;
  const keys = new Array(slots).fill(0n);
  const successors = new Uint32Array(slots);
  const left = new Int32Array(slots).fill(-1);
  const right = new Int32Array(slots).fill(-1);
  const heights = new Uint8Array(slots);
  successors[0] = 1;
  successors[1] = 1;
  let treapRoot = -1;
  let nextIndex = 2;
  let root = empty[depth];
  let work = 0;
  let indexWork = 0;
  let maxSearchDepth = 0;
  let maxIndexDepth = 0;

  const nodeValue = (level, index) => nodes.get(keyOf(level, index)) ?? empty[level];
  const putNode = (level, index, value) => {
    const address = keyOf(level, index);
    if (value === empty[level]) nodes.delete(address); else nodes.set(address, value);
  };
  const leafAt = (index) => {
    if (index === 0) return [1, 0, 0n, successors[0], successors[0] === 1 ? 0n : keys[successors[0]]];
    if (index === 1) return [3, 1, 0n, 1, 0n];
    return [2, index, keys[index], successors[index], successors[index] === 1 ? 0n : keys[successors[index]]];
  };
  const updateLeaf = (index) => {
    let value = leafHash(...leafAt(index));
    putNode(0, index, value);
    for (let level = 0; level < depth; level += 1) {
      const sibling = nodeValue(level, (Math.floor(index / (2 ** level))) ^ 1);
      value = bit(index, level) === 0 ? canonical(hashNode(value, sibling), 'hashNode output') : canonical(hashNode(sibling, value), 'hashNode output');
      putNode(level + 1, Math.floor(index / (2 ** (level + 1))), value);
      work += 1;
    }
    root = value;
  };
  const height = (node) => node === -1 ? 0 : heights[node];
  const setHeight = (node) => { heights[node] = Math.max(height(left[node]), height(right[node])) + 1; };
  const rotateRight = (node) => {
    const child = left[node]; left[node] = right[child]; right[child] = node;
    setHeight(node); setHeight(child); return child;
  };
  const rotateLeft = (node) => {
    const child = right[node]; right[node] = left[child]; left[child] = node;
    setHeight(node); setHeight(child); return child;
  };
  const avlInsert = (node, index, stats) => {
    stats.steps += 1;
    if (node === -1) { heights[index] = 1; return index; }
    if (keys[index] < keys[node]) left[node] = avlInsert(left[node], index, stats);
    else right[node] = avlInsert(right[node], index, stats);
    setHeight(node);
    const balance = height(left[node]) - height(right[node]);
    if (balance > 1) {
      if (keys[index] > keys[left[node]]) left[node] = rotateLeft(left[node]);
      return rotateRight(node);
    }
    if (balance < -1) {
      if (keys[index] < keys[right[node]]) right[node] = rotateRight(right[node]);
      return rotateLeft(node);
    }
    return node;
  };
  const predecessor = (key) => {
    let cursor = treapRoot;
    let result = 0;
    let steps = 0;
    while (cursor !== -1) {
      steps += 1;
      if (key <= keys[cursor]) cursor = left[cursor]; else { result = cursor; cursor = right[cursor]; }
    }
    return { index: result, steps };
  };
  const auditIndex = () => {
    const seen = new Set();
    const visit = (node, lower, upper) => {
      if (node === -1) return 0;
      if (node < 2 || node >= nextIndex || seen.has(node)) throw new Error('AVL index has an invalid node topology');
      if ((lower !== null && keys[node] <= lower) || (upper !== null && keys[node] >= upper)) throw new Error('AVL index violates strict key ordering');
      seen.add(node);
      const leftHeight = visit(left[node], lower, keys[node]);
      const rightHeight = visit(right[node], keys[node], upper);
      const observed = Math.max(leftHeight, rightHeight) + 1;
      if (Math.abs(leftHeight - rightHeight) > 1 || heights[node] !== observed) throw new Error('AVL index height invariant failed');
      return observed;
    };
    const indexHeight = visit(treapRoot, null, null);
    if (seen.size !== nextIndex - 2) throw new Error('AVL index does not cover every inserted nullifier');
    return indexHeight;
  };
  // The indexed tree is not an all-empty tree: its authenticated base state
  // includes min/max sentinels at physical indices 0 and 1.
  updateLeaf(0);
  updateLeaf(1);
  work = 0;
  return freeze({
    insert(key) {
      canonical(key, 'nullifier key');
      if (nextIndex >= capacity || nextIndex >= slots) throw new RangeError('indexed nullifier tree is full');
      const predecessorSearch = predecessor(key);
      const predecessorIndex = predecessorSearch.index;
      const successorIndex = successors[predecessorIndex];
      if (successorIndex !== 1 && keys[successorIndex] === key) throw new Error('nullifier key is already present');
      const index = nextIndex;
      keys[index] = key;
      successors[index] = successorIndex;
      successors[predecessorIndex] = index;
      updateLeaf(predecessorIndex);
      updateLeaf(index);
      const insertion = { steps: 0 };
      treapRoot = avlInsert(treapRoot, index, insertion);
      nextIndex += 1;
      const indexOperationWork = predecessorSearch.steps + insertion.steps;
      indexWork += indexOperationWork;
      maxSearchDepth = Math.max(maxSearchDepth, predecessorSearch.steps);
      maxIndexDepth = Math.max(maxIndexDepth, insertion.steps);
      return freeze({ index, predecessorIndex, root, work: depth * 2, predecessorSearchSteps: predecessorSearch.steps, indexInsertSteps: insertion.steps, indexWork: indexOperationWork });
    },
    snapshot() {
      const indexHeight = auditIndex();
      return freeze({ depth, root, nextIndex, normalCount: nextIndex - 2, work, nodeCount: nodes.size, indexWork, maxSearchDepth, maxIndexDepth, indexHeight });
    },
  });
}
