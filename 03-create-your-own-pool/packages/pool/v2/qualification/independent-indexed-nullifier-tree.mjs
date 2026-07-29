import { createHash } from "node:crypto";

export const INDEPENDENT_NULLIFIER_TREE_DEPTH = 32;
export const INDEPENDENT_NULLIFIER_FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const INDEPENDENT_NULLIFIER_LEAF_TYPES = Object.freeze({
  minimum: 1,
  normal: 2,
  maximum: 3,
});

const ZERO = Buffer.alloc(32);
const MAX_NORMAL_COUNT = 0xffff_fffd;
const PRIORITY_DOMAIN =
  "ShieldKit/PoolActionV2Direct/Q04/oracle-treap-priority/v1\0";

export class IndependentIndexedNullifierTreeError extends Error {
  constructor(message) {
    super(message);
    this.name = "IndependentIndexedNullifierTreeError";
  }
}

const fail = (message) => {
  throw new IndependentIndexedNullifierTreeError(message);
};
const freeze = (value) => Object.freeze(value);
const same = (left, right) =>
  Buffer.from(left).equals(Buffer.from(right));
const exactKeys = (value, expected, label) => {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) fail(`${label} has missing or unknown properties`);
  return value;
};
const canonicalKey = (value, label) => {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    fail(`${label} must contain exactly 32 bytes`);
  }
  const bytes = Buffer.from(value);
  const field = BigInt(`0x${bytes.toString("hex")}`);
  if (field >= INDEPENDENT_NULLIFIER_FR_MODULUS) {
    fail(`${label} must be a canonical BN254 Fr`);
  }
  return freeze({ bytes, field });
};
const encodedFr = (value, label) => {
  if (
    typeof value !== "bigint" ||
    value < 0n ||
    value >= INDEPENDENT_NULLIFIER_FR_MODULUS
  ) fail(`${label} must be a canonical BN254 Fr bigint`);
  return Buffer.from(value.toString(16).padStart(64, "0"), "hex");
};
const leafTypeName = (leafType) => {
  if (leafType === INDEPENDENT_NULLIFIER_LEAF_TYPES.minimum) return "min";
  if (leafType === INDEPENDENT_NULLIFIER_LEAF_TYPES.normal) return "normal";
  if (leafType === INDEPENDENT_NULLIFIER_LEAF_TYPES.maximum) return "max";
  fail("independent indexed-nullifier leaf type is unsupported");
};

function treapPriority(keyBytes) {
  return BigInt(`0x${createHash("sha256")
    .update(PRIORITY_DOMAIN, "ascii")
    .update(keyBytes)
    .digest("hex")}`);
}

function priorityBefore(left, right) {
  return left.priority < right.priority ||
    (left.priority === right.priority && left.key < right.key);
}

function rotateLeft(root) {
  const replacement = root.right;
  root.right = replacement.left;
  replacement.left = root;
  return replacement;
}

function rotateRight(root) {
  const replacement = root.left;
  root.left = replacement.right;
  replacement.right = root;
  return replacement;
}

function treapInsert(root, inserted) {
  if (root === null) return inserted;
  if (inserted.key < root.key) {
    root.left = treapInsert(root.left, inserted);
    return priorityBefore(root.left, root) ? rotateRight(root) : root;
  }
  if (inserted.key > root.key) {
    root.right = treapInsert(root.right, inserted);
    return priorityBefore(root.right, root) ? rotateLeft(root) : root;
  }
  fail("independent indexed nullifier already exists");
}

function treapFind(root, key) {
  let cursor = root;
  while (cursor !== null) {
    if (key === cursor.key) return cursor;
    cursor = key < cursor.key ? cursor.left : cursor.right;
  }
  return null;
}

function treapPredecessor(root, key) {
  let cursor = root;
  let predecessor = null;
  while (cursor !== null) {
    if (cursor.key < key) {
      predecessor = cursor;
      cursor = cursor.right;
    } else {
      cursor = cursor.left;
    }
  }
  return predecessor;
}

function witnessLeaf(leaf) {
  return freeze({
    type: leafTypeName(leaf.leafType),
    index: leaf.physicalIndex,
    key: leaf.key.toString(16).padStart(64, "0"),
    successorIndex: leaf.successorIndex,
    successorKey: leaf.successorKey.toString(16).padStart(64, "0"),
  });
}

function copyLeaf(leaf) {
  return freeze({
    physicalIndex: leaf.physicalIndex,
    leafType: leaf.leafType,
    key: leaf.key,
    successorIndex: leaf.successorIndex,
    successorKey: leaf.successorKey,
    leafHash: leaf.leafHash,
  });
}

export function createIndependentIndexedNullifierTree(value) {
  const input = exactKeys(value, ["oracle"], "independent nullifier tree");
  const oracle = input.oracle;
  if (
    oracle === null ||
    Array.isArray(oracle) ||
    typeof oracle !== "object" ||
    typeof oracle.hashIndexedNullifierLeaf !== "function" ||
    typeof oracle.hashIndexedNullifierNode !== "function"
  ) fail("independent nullifier tree requires a compatible Poseidon oracle");

  const defaults = [
    oracle.hashIndexedNullifierLeaf([0n, 0n, 0n, 0n, 0n]),
  ];
  for (let depth = 0; depth < INDEPENDENT_NULLIFIER_TREE_DEPTH; depth += 1) {
    defaults.push(
      oracle.hashIndexedNullifierNode(defaults[depth], defaults[depth]),
    );
  }
  defaults.forEach((entry, index) => {
    if (
      typeof entry !== "bigint" ||
      entry < 0n ||
      entry >= INDEPENDENT_NULLIFIER_FR_MODULUS
    ) fail(`independent oracle default ${index} is not a canonical Fr`);
  });

  const layers = Array.from(
    { length: INDEPENDENT_NULLIFIER_TREE_DEPTH + 1 },
    () => new Map(),
  );
  const leaves = new Map();
  let orderedRoot = null;
  let normalCount = 0;

  const readNode = (depth, nodeIndex) =>
    layers[depth].get(nodeIndex) ?? defaults[depth];
  const writeNode = (depth, nodeIndex, nodeHash) => {
    if (nodeHash === defaults[depth]) layers[depth].delete(nodeIndex);
    else layers[depth].set(nodeIndex, nodeHash);
  };
  const hashLeaf = (leaf) =>
    oracle.hashIndexedNullifierLeaf([
      BigInt(leaf.leafType),
      BigInt(leaf.physicalIndex),
      leaf.key,
      BigInt(leaf.successorIndex),
      leaf.successorKey,
    ]);
  const replaceLeaf = (leaf, metrics = null) => {
    const leafHash = hashLeaf(leaf);
    if (metrics !== null) metrics.leafHashCalls += 1;
    const stored = freeze({ ...leaf, leafHash });
    leaves.set(leaf.physicalIndex, stored);
    let node = leafHash;
    let cursor = leaf.physicalIndex;
    writeNode(0, cursor, node);
    for (
      let depth = 0;
      depth < INDEPENDENT_NULLIFIER_TREE_DEPTH;
      depth += 1
    ) {
      const sibling = readNode(depth, cursor ^ 1);
      node = (cursor & 1) === 0
        ? oracle.hashIndexedNullifierNode(node, sibling)
        : oracle.hashIndexedNullifierNode(sibling, node);
      if (metrics !== null) metrics.nodeHashCalls += 1;
      cursor = Math.floor(cursor / 2);
      writeNode(depth + 1, cursor, node);
    }
    return stored;
  };
  const calculatePath = (physicalIndex, leafHash, metrics = null) => {
    let cursor = physicalIndex;
    let node = leafHash;
    const siblings = [];
    for (
      let depth = 0;
      depth < INDEPENDENT_NULLIFIER_TREE_DEPTH;
      depth += 1
    ) {
      const sibling = readNode(depth, cursor ^ 1);
      siblings.push(sibling);
      node = (cursor & 1) === 0
        ? oracle.hashIndexedNullifierNode(node, sibling)
        : oracle.hashIndexedNullifierNode(sibling, node);
      if (metrics !== null) metrics.nodeHashCalls += 1;
      cursor = Math.floor(cursor / 2);
    }
    return freeze({ root: node, siblings: freeze(siblings) });
  };

  replaceLeaf({
    physicalIndex: 0,
    leafType: INDEPENDENT_NULLIFIER_LEAF_TYPES.minimum,
    key: 0n,
    successorIndex: 1,
    successorKey: 0n,
  });
  replaceLeaf({
    physicalIndex: 1,
    leafType: INDEPENDENT_NULLIFIER_LEAF_TYPES.maximum,
    key: 0n,
    successorIndex: 1,
    successorKey: 0n,
  });

  const state = () => {
    const root = readNode(INDEPENDENT_NULLIFIER_TREE_DEPTH, 0);
    return freeze({
      normalCount,
      root,
      rootBytes: encodedFr(root, "independent nullifier root"),
    });
  };

  const membershipPath = (physicalIndex) => {
    if (
      !Number.isSafeInteger(physicalIndex) ||
      physicalIndex < 0 ||
      physicalIndex >= normalCount + 2
    ) fail("independent membership index is not allocated");
    const leaf = leaves.get(physicalIndex);
    if (leaf === undefined) fail("independent membership leaf is absent");
    const path = calculatePath(physicalIndex, leaf.leafHash);
    if (path.root !== state().root) {
      fail("independent membership path does not prove the current root");
    }
    return freeze({
      leaf: witnessLeaf(leaf),
      leafHash: leaf.leafHash,
      root: path.root,
      siblings: path.siblings,
    });
  };

  const insert = (keyValue) => {
    if (normalCount >= MAX_NORMAL_COUNT) {
      fail("independent indexed-nullifier tree is at capacity");
    }
    const key = canonicalKey(keyValue, "independent nullifier key");
    if (treapFind(orderedRoot, key.field) !== null) {
      fail("independent indexed nullifier already exists");
    }
    const predecessorNode = treapPredecessor(orderedRoot, key.field);
    const predecessorIndex = predecessorNode?.physicalIndex ?? 0;
    const predecessor = leaves.get(predecessorIndex);
    if (predecessor === undefined) {
      fail("independent predecessor leaf is absent");
    }
    if (
      predecessor.leafType === INDEPENDENT_NULLIFIER_LEAF_TYPES.maximum ||
      (
        predecessor.leafType === INDEPENDENT_NULLIFIER_LEAF_TYPES.normal &&
        predecessor.key >= key.field
      ) ||
      (
        predecessor.successorIndex >= 2 &&
        predecessor.successorKey <= key.field
      )
    ) fail("independent predecessor does not bracket the new key");

    const appendIndex = normalCount + 2;
    if (leaves.has(appendIndex)) {
      fail("independent append position is already allocated");
    }
    const metrics = {
      leafHashCalls: 0,
      nodeHashCalls: 0,
      membershipPathComputations: 3,
      stateUpdatePaths: 2,
      treeDepth: INDEPENDENT_NULLIFIER_TREE_DEPTH,
    };
    const preRoot = state().root;
    const predecessorPath = calculatePath(
      predecessor.physicalIndex,
      predecessor.leafHash,
      metrics,
    );
    if (predecessorPath.root !== preRoot) {
      fail("independent predecessor path does not prove the pre-root");
    }

    const updatedPredecessor = replaceLeaf({
      physicalIndex: predecessor.physicalIndex,
      leafType: predecessor.leafType,
      key: predecessor.key,
      successorIndex: appendIndex,
      successorKey: key.field,
    }, metrics);
    const intermediateRoot = state().root;
    const appendEmptyPath = calculatePath(
      appendIndex,
      defaults[0],
      metrics,
    );
    if (appendEmptyPath.root !== intermediateRoot) {
      fail("independent append non-membership path is inconsistent");
    }

    const appended = replaceLeaf({
      physicalIndex: appendIndex,
      leafType: INDEPENDENT_NULLIFIER_LEAF_TYPES.normal,
      key: key.field,
      successorIndex: predecessor.successorIndex,
      successorKey: predecessor.successorKey,
    }, metrics);
    normalCount += 1;
    orderedRoot = treapInsert(orderedRoot, {
      key: key.field,
      physicalIndex: appendIndex,
      priority: treapPriority(key.bytes),
      left: null,
      right: null,
    });
    const postMembership = calculatePath(
      appendIndex,
      appended.leafHash,
      metrics,
    );
    const postRoot = state().root;
    if (postMembership.root !== postRoot) {
      fail("independent post-insertion path does not prove the post-root");
    }
    if (
      metrics.leafHashCalls !== 2 ||
      metrics.nodeHashCalls !== 160
    ) fail("independent fixed-depth operation count differs");

    return freeze({
      key: key.bytes.toString("hex"),
      preRoot,
      intermediateRoot,
      postRoot,
      predecessor: witnessLeaf(predecessor),
      updatedPredecessor: witnessLeaf(updatedPredecessor),
      predecessorPath: predecessorPath.siblings,
      append: freeze({
        index: appendIndex,
        emptyPath: appendEmptyPath.siblings,
        newLeaf: witnessLeaf(appended),
      }),
      postMembershipPath: postMembership.siblings,
      metrics: freeze(metrics),
    });
  };

  return freeze({
    metadata: freeze({
      implementation:
        "independent-treap-sparse-depth32-indexed-nullifier-oracle-v1",
      depth: INDEPENDENT_NULLIFIER_TREE_DEPTH,
      frModulusHex:
        INDEPENDENT_NULLIFIER_FR_MODULUS.toString(16).padStart(64, "0"),
      orderedSet: "sha256-priority-treap",
    }),
    defaults: freeze([...defaults]),
    insert,
    leaf: (physicalIndex) => {
      if (!Number.isSafeInteger(physicalIndex) || physicalIndex < 0) {
        fail("independent leaf index must be a nonnegative integer");
      }
      const leaf = leaves.get(physicalIndex);
      return leaf === undefined ? null : copyLeaf(leaf);
    },
    membershipPath,
    state,
  });
}
