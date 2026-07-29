/**
 * Indexed nullifier Merkle tree (depth 32).
 * Full canonical BN254 field keys; sentinels at physical leaves 0 and 1.
 *
 * Leaf types: empty | minSentinel | normal | maxSentinel
 * Normal leaf commits to (type, physicalIndex, key, successorIndex, successorKey).
 */
import { DOMAIN, FR_MODULUS, NF_LEAF_TYPE, NULLIFIER_TREE_DEPTH } from '../constants.mjs';
import { frFromHex, frToHex } from '../crypto/fr.mjs';
import { poseidon } from '../crypto/poseidon.mjs';

export class IndexedNullifierError extends Error {
  constructor(message) {
    super(message);
    this.name = 'IndexedNullifierError';
  }
}

const fail = (m) => {
  throw new IndexedNullifierError(m);
};

const MIN_KEY = 0n; // conceptual MIN is below all normals; sentinel key marker
const MAX_KEY = FR_MODULUS - 1n; // conceptual MAX above all normals — use r-1 as sentinel key encoding

function emptyLayers(depth) {
  const empty = [poseidon(DOMAIN.NULLIFIER_EMPTY, 0n)];
  for (let level = 0; level < depth; level += 1) {
    empty.push(poseidon(DOMAIN.NULLIFIER_NODE, empty[level], empty[level]));
  }
  return empty;
}

function commitLeaf({ type, physicalIndex, key, successorIndex, successorKey }) {
  return poseidon(
    DOMAIN.NULLIFIER_LEAF,
    type,
    physicalIndex,
    key,
    successorIndex,
    successorKey,
  );
}

/**
 * Create an indexed nullifier tree.
 * Physical layout:
 *   leaf 0 = MIN sentinel (successor initially points to MAX at leaf 1)
 *   leaf 1 = MAX sentinel
 *   leaf 2+ = normal leaves appended in insertion order
 */
export function createIndexedNullifierTree({ depth = NULLIFIER_TREE_DEPTH } = {}) {
  const empty = emptyLayers(depth);
  /** @type {Map<string, bigint>} */
  const nodes = new Map();
  /** @type {Array<{type:bigint, physicalIndex:bigint, key:bigint, successorIndex:bigint, successorKey:bigint}>} */
  const leaves = [];
  /** Ordered normal keys for predecessor lookup: { key, physicalIndex }[] */
  let ordered = [];
  let nextPhysical = 0n;

  const nodeKey = (level, index) => `${level}:${index}`;
  function getNode(level, index) {
    return nodes.get(nodeKey(level, index)) ?? empty[level];
  }
  function setNode(level, index, value) {
    nodes.set(nodeKey(level, index), value);
  }

  function writeLeaf(physicalIndex, leaf) {
    while (leaves.length <= Number(physicalIndex)) {
      leaves.push(null);
    }
    leaves[Number(physicalIndex)] = leaf;
    let current = commitLeaf(leaf);
    let idx = physicalIndex;
    setNode(0, idx, current);
    for (let level = 0; level < depth; level += 1) {
      const siblingIndex = idx ^ 1n;
      const sibling = getNode(level, siblingIndex);
      const parent = (idx & 1n) === 0n
        ? poseidon(DOMAIN.NULLIFIER_NODE, current, sibling)
        : poseidon(DOMAIN.NULLIFIER_NODE, sibling, current);
      idx >>= 1n;
      setNode(level + 1, idx, parent);
      current = parent;
    }
  }

  function root() {
    return getNode(depth, 0n);
  }

  function pathFor(physicalIndex) {
    const siblings = [];
    let idx = physicalIndex;
    for (let level = 0; level < depth; level += 1) {
      siblings.push(frToHex(getNode(level, idx ^ 1n)));
      idx >>= 1n;
    }
    return Object.freeze({
      index: physicalIndex.toString(),
      siblings: Object.freeze(siblings),
    });
  }

  // Initialize sentinels
  // MIN at 0: successor = MAX (index 1), successorKey = conceptual max marker
  // MAX at 1: successor = self-ish; successorKey unused high
  writeLeaf(0n, {
    type: NF_LEAF_TYPE.minSentinel,
    physicalIndex: 0n,
    key: MIN_KEY,
    successorIndex: 1n,
    successorKey: MAX_KEY,
  });
  writeLeaf(1n, {
    type: NF_LEAF_TYPE.maxSentinel,
    physicalIndex: 1n,
    key: MAX_KEY,
    successorIndex: 1n,
    successorKey: MAX_KEY,
  });
  nextPhysical = 2n;

  function findPredecessor(key) {
    // Conceptual: MIN < every normal < MAX
    // ordered is sorted by key ascending
    let pred = {
      type: NF_LEAF_TYPE.minSentinel,
      physicalIndex: 0n,
      key: MIN_KEY,
      successorIndex: 1n,
      successorKey: MAX_KEY,
    };
    // Refresh pred from live leaf 0
    pred = leaves[0];
    for (const entry of ordered) {
      if (entry.key < key) {
        pred = leaves[Number(entry.physicalIndex)];
      } else if (entry.key === key) {
        fail('duplicate nullifier');
      } else {
        break;
      }
    }
    return pred;
  }

  /**
   * Insert a normal nullifier key (full Fr).
   * Returns proof material for circuit/reference checks.
   */
  function insert(nullifierHex) {
    const key = frFromHex(nullifierHex, 'nullifier');
    // Normal zero and Fr-1 are valid normal keys conceptually, but Fr-1 collides with MAX sentinel key encoding.
    // Plan: "normal zero and Fr−1 remain valid" with conceptual ordering MIN < normals < MAX.
    // We encode MAX sentinel with key = r-1 for field placement; normal Fr-1 is still allowed
    // by ordering against successor pointers rather than raw key equality with MAX.
    // For simplicity and safety: reject key that equals an existing normal; allow 0 and r-1 as normals
    // by using separate type tags — predecessor check uses conceptual order:
    //   MIN < all normals (including 0 and r-1) < MAX
    // Implementation: ordered only contains normals; MIN always pred of first; MAX always succ of last.

    const pred = findPredecessor(key);
    // Strict conceptual ordering: pred.key < key < pred.successorKey when pred is normal/min
    // For min sentinel, key can be 0; for max, successorKey is MAX_KEY.
    // When inserting normal with key k:
    //   pred is greatest leaf with conceptual value < k
    //   For normals, comparison is numeric on Fr
    //   MIN is < all; MAX is > all
    const predKey = pred.type === NF_LEAF_TYPE.minSentinel ? -1n : pred.key;
    const succKey = pred.type === NF_LEAF_TYPE.maxSentinel
      ? FR_MODULUS
      : (pred.successorKey === MAX_KEY && pred.successorIndex === 1n && leaves[1]?.type === NF_LEAF_TYPE.maxSentinel
        ? FR_MODULUS
        : pred.successorKey);

    // Map successor of MIN to conceptual +inf if it points at MAX
    let conceptualSucc = pred.successorKey;
    if (pred.successorIndex === 1n && leaves[1]?.type === NF_LEAF_TYPE.maxSentinel) {
      conceptualSucc = FR_MODULUS; // +inf
    }
    let conceptualPred = pred.key;
    if (pred.type === NF_LEAF_TYPE.minSentinel) conceptualPred = -1n;

    if (!(conceptualPred < key && key < conceptualSucc)) {
      if (key === pred.key && pred.type === NF_LEAF_TYPE.normal) fail('duplicate nullifier');
      fail('nullifier ordering check failed');
    }

    const newIndex = nextPhysical;
    if (newIndex >= (1n << BigInt(depth))) fail('nullifier tree is full');

    const predBefore = { ...pred };
    const predPathBefore = pathFor(pred.physicalIndex);
    const emptyPathPre = pathFor(newIndex);

    // Update predecessor successor pointer
    const predAfter = {
      ...pred,
      successorIndex: newIndex,
      successorKey: key,
    };
    writeLeaf(pred.physicalIndex, predAfter);

    // Empty-slot path under mid-root (after pred update, before new leaf).
    // Circuit needs this for sequential insert proof.
    const emptyPathAfterPred = pathFor(newIndex);

    const newLeaf = {
      type: NF_LEAF_TYPE.normal,
      physicalIndex: newIndex,
      key,
      successorIndex: predBefore.successorIndex,
      successorKey: predBefore.successorKey,
    };
    writeLeaf(newIndex, newLeaf);

    // Maintain ordered index
    ordered.push({ key, physicalIndex: newIndex });
    ordered.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));

    nextPhysical += 1n;

    return Object.freeze({
      postRoot: frToHex(root()),
      insertedIndex: newIndex.toString(),
      key: frToHex(key),
      predecessor: Object.freeze({
        before: Object.freeze({
          type: predBefore.type.toString(),
          physicalIndex: predBefore.physicalIndex.toString(),
          key: frToHex(predBefore.key),
          successorIndex: predBefore.successorIndex.toString(),
          successorKey: frToHex(predBefore.successorKey),
        }),
        after: Object.freeze({
          type: predAfter.type.toString(),
          physicalIndex: predAfter.physicalIndex.toString(),
          key: frToHex(predAfter.key),
          successorIndex: predAfter.successorIndex.toString(),
          successorKey: frToHex(predAfter.successorKey),
        }),
        pathBefore: predPathBefore,
      }),
      newLeaf: Object.freeze({
        type: newLeaf.type.toString(),
        physicalIndex: newLeaf.physicalIndex.toString(),
        key: frToHex(newLeaf.key),
        successorIndex: newLeaf.successorIndex.toString(),
        successorKey: frToHex(newLeaf.successorKey),
      }),
      emptyAppendPath: emptyPathPre,
      emptyPathAfterPred,
      newLeafPath: pathFor(newIndex),
    });
  }

  function contains(nullifierHex) {
    const key = frFromHex(nullifierHex, 'nullifier');
    return ordered.some((e) => e.key === key);
  }

  return Object.freeze({
    depth,
    emptyRoot: frToHex(empty[depth]),
    get nextPhysicalIndex() {
      return nextPhysical.toString();
    },
    /** Normal nullifier count (excludes sentinels). */
    get normalCount() {
      return ordered.length;
    },
    root: () => frToHex(root()),
    insert,
    contains,
    pathFor: (indexStr) => pathFor(BigInt(indexStr)),
    serialize() {
      return {
        depth,
        nextPhysical: nextPhysical.toString(),
        ordered: ordered.map((e) => ({ key: frToHex(e.key), physicalIndex: e.physicalIndex.toString() })),
        leaves: leaves.map((leaf) => (leaf ? {
          type: leaf.type.toString(),
          physicalIndex: leaf.physicalIndex.toString(),
          key: frToHex(leaf.key),
          successorIndex: leaf.successorIndex.toString(),
          successorKey: frToHex(leaf.successorKey),
        } : null)),
        nodes: [...nodes.entries()].map(([k, v]) => [k, frToHex(v)]),
      };
    },
    load(snapshot) {
      if (snapshot.depth !== depth) fail('depth mismatch');
      nodes.clear();
      for (const [k, hex] of snapshot.nodes) nodes.set(k, frFromHex(hex));
      leaves.length = 0;
      for (const leaf of snapshot.leaves) {
        if (!leaf) {
          leaves.push(null);
          continue;
        }
        leaves.push({
          type: BigInt(leaf.type),
          physicalIndex: BigInt(leaf.physicalIndex),
          key: frFromHex(leaf.key),
          successorIndex: BigInt(leaf.successorIndex),
          successorKey: frFromHex(leaf.successorKey),
        });
      }
      ordered = snapshot.ordered.map((e) => ({
        key: frFromHex(e.key),
        physicalIndex: BigInt(e.physicalIndex),
      }));
      nextPhysical = BigInt(snapshot.nextPhysical);
    },
  });
}

export function emptyNullifierRoot(depth = NULLIFIER_TREE_DEPTH) {
  // Root of tree with only two sentinels initialized
  return createIndexedNullifierTree({ depth }).root();
}
