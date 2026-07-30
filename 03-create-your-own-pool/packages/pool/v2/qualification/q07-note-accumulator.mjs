/**
 * Qualification-only incremental note accumulator for Q07.
 *
 * This is deliberately separate from the immutable reference `note-tree.mjs`:
 * the reference model copies its sparse rows on every append, which is ideal
 * for transition review but the wrong cost model for a 100,000-action replay.
 * This capability keeps the same depth-32 tree, canonical Fr encoding, and
 * production Poseidon functions while retaining nodes in private mutable
 * maps.  It is not a consensus implementation and it never reports a Q07
 * qualification verdict.
 */
import {
  hashEmptyNoteLeaf,
  hashNoteTreeNode,
} from '../../../action/v2/poseidon.mjs';
import { BN254_SCALAR_FIELD_MODULUS as BN254_FR_MODULUS } from '../../../action/v2/domains.mjs';

export const Q07_NOTE_TREE_DEPTH = 32;
export const Q07_NOTE_ACCUMULATOR_SNAPSHOT_VERSION = 1;
export const Q07_NOTE_ACCUMULATOR_SCHEMA =
  'shieldkit-v2-q07-note-accumulator-v1';

export class Q07NoteAccumulatorError extends Error {
  constructor(message) {
    super(message);
    this.name = 'Q07NoteAccumulatorError';
  }
}

const fail = (message) => { throw new Q07NoteAccumulatorError(message); };
const privateStates = new WeakMap();
const capacity = 2 ** Q07_NOTE_TREE_DEPTH;
const HEX_32 = /^[0-9a-f]{64}$/;

function copyBytes(value) {
  return Buffer.from(value);
}

function immutableBytes(value) {
  return Buffer.from(value);
}

function freezeBytes(values) {
  return Object.freeze(values.map((value) => immutableBytes(value)));
}

function toBigInt(value, label) {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    fail(`${label} must be a Uint8Array containing exactly 32 bytes`);
  }
  const copied = copyBytes(value);
  const fieldElement = BigInt(`0x${copied.toString('hex')}`);
  if (fieldElement >= BN254_FR_MODULUS) {
    fail(`${label} must be a canonical BN254 Fr encoding`);
  }
  return Object.freeze({ bytes: copied, fieldElement });
}

function fromBigInt(value, label) {
  if (typeof value !== 'bigint' || value < 0n || value >= BN254_FR_MODULUS) {
    fail(`${label} must be a canonical BN254 Fr`);
  }
  return Buffer.from(value.toString(16).padStart(64, '0'), 'hex');
}

function fromHex(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail(`${label} must be lowercase 32-byte hexadecimal`);
  }
  return toBigInt(Buffer.from(value, 'hex'), label);
}

function stateFor(accumulator) {
  const state = privateStates.get(accumulator);
  if (state === undefined) fail('accumulator is not a Q07 note-accumulator capability');
  return state;
}

function nodeHash(state, left, right, origin) {
  const leftFr = toBigInt(left, 'left note-tree node').fieldElement;
  const rightFr = toBigInt(right, 'right note-tree node').fieldElement;
  const result = fromBigInt(hashNoteTreeNode(leftFr, rightFr), 'note-tree node hash');
  state.operationCounters.nodeHashCalls += 1;
  state.operationCounters[origin] += 1;
  return result;
}

function emptyDefaults(state) {
  const defaults = [fromBigInt(hashEmptyNoteLeaf(), 'empty note leaf')];
  for (let level = 0; level < Q07_NOTE_TREE_DEPTH; level += 1) {
    defaults.push(nodeHash(state, defaults[level], defaults[level], 'defaultNodeHashCalls'));
  }
  return defaults;
}

function bitAt(index, level) {
  return Math.floor(index / (2 ** level)) % 2;
}

function expectedNodeCount(leafCount, level) {
  return Math.ceil(leafCount / (2 ** level));
}

function publicCounters(state) {
  return Object.freeze({ ...state.operationCounters });
}

function immutableAudit(state) {
  return Object.freeze({
    schema: Q07_NOTE_ACCUMULATOR_SCHEMA,
    depth: Q07_NOTE_TREE_DEPTH,
    capacity,
    leafCount: state.leafCount,
    root: immutableBytes(state.root),
    rootHex: state.root.toString('hex'),
    operationCounters: publicCounters(state),
    // This module is a data-structure component, never a qualification result.
    q07Qualified: false,
  });
}

function exactObject(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} has missing or unknown properties`);
  }
}

function row(value, level, index) {
  return Object.freeze({ level, index, value: value.toString('hex') });
}

function snapshotUnchecked(state) {
  const defaults = Object.freeze(state.defaults.map((value, level) => row(value, level, 0)));
  const frontier = Object.freeze(state.frontier.map((value, level) => Object.freeze({
    level,
    value: value === null ? null : value.toString('hex'),
  })));
  const nodes = [];
  for (let level = 0; level <= Q07_NOTE_TREE_DEPTH; level += 1) {
    const values = state.nodes[level];
    for (const index of [...values.keys()].sort((left, right) => left - right)) {
      nodes.push(row(values.get(index), level, index));
    }
  }
  return Object.freeze({
    schema: Q07_NOTE_ACCUMULATOR_SCHEMA,
    version: Q07_NOTE_ACCUMULATOR_SNAPSHOT_VERSION,
    depth: Q07_NOTE_TREE_DEPTH,
    leafCount: state.leafCount,
    root: state.root.toString('hex'),
    defaults,
    frontier,
    nodes: Object.freeze(nodes),
  });
}

/** Create an opaque, incremental, depth-32 production-Poseidon accumulator. */
export function createQ07NoteAccumulator() {
  const capability = Object.freeze({ type: Q07_NOTE_ACCUMULATOR_SCHEMA });
  const state = {
    defaults: [],
    frontier: Array(Q07_NOTE_TREE_DEPTH).fill(null),
    nodes: Array.from({ length: Q07_NOTE_TREE_DEPTH + 1 }, () => new Map()),
    leafCount: 0,
    root: null,
    operationCounters: {
      nodeHashCalls: 0,
      defaultNodeHashCalls: 0,
      appendNodeHashCalls: 0,
      auditNodeHashCalls: 0,
      appendCount: 0,
      membershipPathReads: 0,
      auditRuns: 0,
      snapshotExports: 0,
      restoreCount: 0,
    },
  };
  state.defaults = emptyDefaults(state);
  state.root = copyBytes(state.defaults[Q07_NOTE_TREE_DEPTH]);
  privateStates.set(capability, state);
  return capability;
}

/**
 * Append one canonical 32-byte Fr note leaf. The mutation performs exactly 32
 * production node hashes and O(32) map operations; returned bytes are copies.
 */
export function appendQ07Note(accumulator, outputNoteLeaf) {
  const state = stateFor(accumulator);
  const leaf = toBigInt(outputNoteLeaf, 'outputNoteLeaf').bytes;
  if (state.leafCount >= capacity) fail('note tree is full');
  const index = state.leafCount;
  const preRoot = copyBytes(state.root);
  const siblings = [];
  let node = leaf;
  state.nodes[0].set(index, copyBytes(node));
  for (let level = 0; level < Q07_NOTE_TREE_DEPTH; level += 1) {
    const bit = bitAt(index, level);
    const sibling = bit === 0 ? state.defaults[level] : state.frontier[level];
    if (sibling === null) fail(`frontier is missing left sibling at level ${level}`);
    siblings.push(copyBytes(sibling));
    if (bit === 0) state.frontier[level] = copyBytes(node);
    node = bit === 0
      ? nodeHash(state, node, sibling, 'appendNodeHashCalls')
      : nodeHash(state, sibling, node, 'appendNodeHashCalls');
    state.nodes[level + 1].set(Math.floor(index / (2 ** (level + 1))), copyBytes(node));
  }
  state.root = copyBytes(node);
  state.leafCount += 1;
  state.operationCounters.appendCount += 1;
  return Object.freeze({
    index,
    outputNoteLeaf: immutableBytes(leaf),
    preRoot: immutableBytes(preRoot),
    postRoot: immutableBytes(node),
    siblings: freezeBytes(siblings),
    operationCounters: publicCounters(state),
    q07Qualified: false,
  });
}

/** Return a copy-safe, bottom-up membership sibling array for an occupied leaf. */
export function q07NoteMembershipPath(accumulator, index) {
  const state = stateFor(accumulator);
  if (!Number.isSafeInteger(index) || index < 0 || index >= state.leafCount) {
    fail('membership index is not occupied');
  }
  const siblings = [];
  for (let level = 0; level < Q07_NOTE_TREE_DEPTH; level += 1) {
    const siblingIndex = Math.floor(index / (2 ** level)) ^ 1;
    siblings.push(copyBytes(state.nodes[level].get(siblingIndex) ?? state.defaults[level]));
  }
  state.operationCounters.membershipPathReads += 1;
  return freezeBytes(siblings);
}

/**
 * Verify every canonical stored node, its contiguous sparse shape, frontier,
 * defaults, and root. This is intentionally a full O(number of stored nodes)
 * audit rather than an append-time cost.
 */
export function auditQ07NoteAccumulator(accumulator) {
  const state = stateFor(accumulator);
  state.operationCounters.auditRuns += 1;
  if (!Number.isSafeInteger(state.leafCount) || state.leafCount < 0 || state.leafCount > capacity) {
    fail('accumulator leaf count is invalid');
  }
  const expectedDefaults = [fromBigInt(hashEmptyNoteLeaf(), 'empty note leaf')];
  for (let level = 0; level < Q07_NOTE_TREE_DEPTH; level += 1) {
    expectedDefaults.push(nodeHash(state, expectedDefaults[level], expectedDefaults[level], 'auditNodeHashCalls'));
  }
  if (state.defaults.length !== expectedDefaults.length || state.defaults.some((value, level) => !value.equals(expectedDefaults[level]))) {
    fail('accumulator defaults do not match production hashes');
  }
  for (let level = 0; level <= Q07_NOTE_TREE_DEPTH; level += 1) {
    const nodeMap = state.nodes[level];
    const count = expectedNodeCount(state.leafCount, level);
    if (nodeMap.size !== count) fail(`accumulator level ${level} has a noncanonical node count`);
    for (let index = 0; index < count; index += 1) {
      const value = nodeMap.get(index);
      if (value === undefined) fail(`accumulator level ${level} has a missing node`);
      toBigInt(value, `accumulator node ${level}:${index}`);
      if (level === 0) continue;
      const left = state.nodes[level - 1].get(index * 2) ?? state.defaults[level - 1];
      const right = state.nodes[level - 1].get((index * 2) + 1) ?? state.defaults[level - 1];
      const expected = nodeHash(state, left, right, 'auditNodeHashCalls');
      if (!value.equals(expected)) fail(`accumulator node ${level}:${index} does not match its children`);
    }
  }
  for (let level = 0; level < Q07_NOTE_TREE_DEPTH; level += 1) {
    const current = state.frontier[level];
    if (state.leafCount === 0) {
      if (current !== null) fail(`accumulator frontier ${level} is nonempty for empty tree`);
      continue;
    }
    const lastIndexAtLevel = Math.floor((state.leafCount - 1) / (2 ** level));
    const expectedIndex = lastIndexAtLevel % 2 === 0 ? lastIndexAtLevel : lastIndexAtLevel - 1;
    const expected = state.nodes[level].get(expectedIndex);
    if (expected === undefined || current === null || !current.equals(expected)) {
      fail(`accumulator frontier ${level} does not match append order`);
    }
  }
  const expectedRoot = state.leafCount === 0
    ? state.defaults[Q07_NOTE_TREE_DEPTH]
    : state.nodes[Q07_NOTE_TREE_DEPTH].get(0);
  if (expectedRoot === undefined || !state.root.equals(expectedRoot)) {
    fail('accumulator root does not match stored tree');
  }
  return immutableAudit(state);
}

/** Export canonical rows for an independent implementation (for example Rust) to cross-check. */
export function exportQ07NoteAccumulatorRows(accumulator) {
  const state = stateFor(accumulator);
  auditQ07NoteAccumulator(accumulator);
  state.operationCounters.snapshotExports += 1;
  return snapshotUnchecked(state);
}

export const snapshotQ07NoteAccumulator = exportQ07NoteAccumulatorRows;

/** Restore only an exact deterministic export; all stored rows are re-derived from leaves. */
export function restoreQ07NoteAccumulator(snapshotValue) {
  exactObject(snapshotValue, [
    'schema', 'version', 'depth', 'leafCount', 'root', 'defaults', 'frontier', 'nodes',
  ], 'snapshot');
  if (snapshotValue.schema !== Q07_NOTE_ACCUMULATOR_SCHEMA
    || snapshotValue.version !== Q07_NOTE_ACCUMULATOR_SNAPSHOT_VERSION
    || snapshotValue.depth !== Q07_NOTE_TREE_DEPTH
    || !Number.isSafeInteger(snapshotValue.leafCount)
    || snapshotValue.leafCount < 0
    || snapshotValue.leafCount > capacity) {
    fail('snapshot metadata is invalid');
  }
  fromHex(snapshotValue.root, 'snapshot root');
  if (!Array.isArray(snapshotValue.nodes)) fail('snapshot nodes must be an array');
  const leaves = snapshotValue.nodes.filter((entry) => entry?.level === 0);
  if (leaves.length !== snapshotValue.leafCount) fail('snapshot leaf rows do not match leaf count');
  const accumulator = createQ07NoteAccumulator();
  const orderedLeaves = [...leaves].sort((left, right) => left.index - right.index);
  for (let index = 0; index < orderedLeaves.length; index += 1) {
    const entry = orderedLeaves[index];
    exactObject(entry, ['level', 'index', 'value'], `snapshot node ${index}`);
    if (entry.level !== 0 || entry.index !== index) fail('snapshot leaf rows are not contiguous and sorted');
    appendQ07Note(accumulator, fromHex(entry.value, `snapshot leaf ${index}`).bytes);
  }
  const restored = exportQ07NoteAccumulatorRows(accumulator);
  if (JSON.stringify(restored) !== JSON.stringify(snapshotValue)) {
    fail('snapshot does not match authenticated accumulator state');
  }
  stateFor(accumulator).operationCounters.restoreCount += 1;
  return accumulator;
}
