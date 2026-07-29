/**
 * Append-only note Merkle tree (Poseidon, depth 32).
 * Persistent frontier for fixed-depth append/path work.
 */
import { DOMAIN, NOTE_TREE_DEPTH } from '../constants.mjs';
import { frFromHex, frToHex } from '../crypto/fr.mjs';
import { poseidon } from '../crypto/poseidon.mjs';

export class NoteTreeError extends Error {
  constructor(message) {
    super(message);
    this.name = 'NoteTreeError';
  }
}

const fail = (m) => {
  throw new NoteTreeError(m);
};

function emptyLayers(depth) {
  const empty = [poseidon(DOMAIN.NOTE_EMPTY, 0n)];
  for (let level = 0; level < depth; level += 1) {
    empty.push(poseidon(DOMAIN.NOTE_NODE, empty[level], empty[level]));
  }
  return empty;
}

export function createNoteTree({ depth = NOTE_TREE_DEPTH } = {}) {
  const empty = emptyLayers(depth);
  /** @type {Map<string, bigint>} key = `${level}:${index}` */
  const nodes = new Map();
  let nextLeafIndex = 0n;

  const nodeKey = (level, index) => `${level}:${index}`;

  function getNode(level, index) {
    const cached = nodes.get(nodeKey(level, index));
    if (cached !== undefined) return cached;
    return empty[level];
  }

  function setNode(level, index, value) {
    nodes.set(nodeKey(level, index), value);
  }

  function root() {
    return getNode(depth, 0n);
  }

  function leafHash(leafFr) {
    return poseidon(DOMAIN.NOTE_LEAF, leafFr);
  }

  /**
   * Append a note leaf (already the note-leaf preimage field: outputNoteLeaf).
   * Returns { postRoot, path: { index, siblings } }.
   */
  function append(leafHex) {
    const leafFr = frFromHex(leafHex, 'note leaf');
    const index = nextLeafIndex;
    if (index >= (1n << BigInt(depth))) fail('note tree is full');
    // Plan: deposit/transfer requires pre.noteCount < 0xffffffff — enforced by transition.

    const siblings = [];
    let current = leafHash(leafFr);
    let idx = index;
    setNode(0, idx, current);

    for (let level = 0; level < depth; level += 1) {
      const siblingIndex = idx ^ 1n;
      const sibling = getNode(level, siblingIndex);
      siblings.push(frToHex(sibling));
      const parent = (idx & 1n) === 0n
        ? poseidon(DOMAIN.NOTE_NODE, current, sibling)
        : poseidon(DOMAIN.NOTE_NODE, sibling, current);
      idx >>= 1n;
      setNode(level + 1, idx, parent);
      current = parent;
    }

    nextLeafIndex += 1n;
    return Object.freeze({
      postRoot: frToHex(root()),
      index: index.toString(),
      path: Object.freeze({
        index: index.toString(),
        siblings: Object.freeze([...siblings]),
      }),
    });
  }

  /** Membership path for an existing leaf at index. */
  function membershipPath(indexStr) {
    const index = BigInt(indexStr);
    if (index < 0n || index >= nextLeafIndex) fail('note index out of range');
    const siblings = [];
    let idx = index;
    for (let level = 0; level < depth; level += 1) {
      const siblingIndex = idx ^ 1n;
      siblings.push(frToHex(getNode(level, siblingIndex)));
      idx >>= 1n;
    }
    return Object.freeze({
      index: index.toString(),
      siblings: Object.freeze(siblings),
    });
  }

  function verifyMembership(leafHex, path, expectedRootHex) {
    const leafFr = frFromHex(leafHex, 'note leaf');
    let current = leafHash(leafFr);
    let idx = BigInt(path.index);
    for (let level = 0; level < depth; level += 1) {
      const sibling = frFromHex(path.siblings[level], `sibling ${level}`);
      current = ((idx >> BigInt(level)) & 1n) === 0n
        ? poseidon(DOMAIN.NOTE_NODE, current, sibling)
        : poseidon(DOMAIN.NOTE_NODE, sibling, current);
    }
    return frToHex(current) === frFromHex(expectedRootHex, 'root') && true
      ? frToHex(current) === expectedRootHex || frToHex(current) === frToHex(frFromHex(expectedRootHex))
      : false;
  }

  function computeRootFromPath(leafHex, path) {
    const leafFr = frFromHex(leafHex, 'note leaf');
    let current = leafHash(leafFr);
    const index = BigInt(path.index);
    for (let level = 0; level < depth; level += 1) {
      const sibling = frFromHex(path.siblings[level], `sibling ${level}`);
      current = ((index >> BigInt(level)) & 1n) === 0n
        ? poseidon(DOMAIN.NOTE_NODE, current, sibling)
        : poseidon(DOMAIN.NOTE_NODE, sibling, current);
    }
    return frToHex(current);
  }

  /** Empty leaf path at nextLeafIndex (for append pre-check). */
  function emptyAppendPath() {
    const index = nextLeafIndex;
    const siblings = [];
    let idx = index;
    for (let level = 0; level < depth; level += 1) {
      const siblingIndex = idx ^ 1n;
      siblings.push(frToHex(getNode(level, siblingIndex)));
      idx >>= 1n;
    }
    return Object.freeze({
      index: index.toString(),
      siblings: Object.freeze(siblings),
    });
  }

  return Object.freeze({
    depth,
    emptyRoot: frToHex(empty[depth]),
    get nextLeafIndex() {
      return nextLeafIndex.toString();
    },
    root: () => frToHex(root()),
    append,
    membershipPath,
    emptyAppendPath,
    verifyMembership: (leafHex, path, expectedRootHex) => {
      try {
        return computeRootFromPath(leafHex, path) === frToHex(frFromHex(expectedRootHex, 'root'));
      } catch {
        return false;
      }
    },
    computeRootFromPath,
    /** Snapshot for persistence */
    serialize() {
      const entries = [];
      for (const [k, v] of nodes) entries.push([k, frToHex(v)]);
      return {
        depth,
        nextLeafIndex: nextLeafIndex.toString(),
        nodes: entries,
      };
    },
    load(snapshot) {
      if (snapshot.depth !== depth) fail('depth mismatch on load');
      nodes.clear();
      for (const [k, hex] of snapshot.nodes) nodes.set(k, frFromHex(hex));
      nextLeafIndex = BigInt(snapshot.nextLeafIndex);
    },
  });
}

export function emptyNoteRoot(depth = NOTE_TREE_DEPTH) {
  return createNoteTree({ depth }).emptyRoot;
}
