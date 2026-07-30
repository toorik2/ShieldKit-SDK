import assert from 'node:assert/strict';
import test from 'node:test';

import {
  append,
  create,
  membershipPath,
  verifyMembershipPath,
} from '../../../action/v2/note-tree.mjs';
import {
  BN254_SCALAR_FIELD_MODULUS,
} from '../../../action/v2/domains.mjs';
import {
  hashEmptyNoteLeaf,
  hashNoteTreeNode,
} from '../../../action/v2/poseidon.mjs';
import {
  Q07NoteAccumulatorError,
  Q07_NOTE_TREE_DEPTH,
  appendQ07Note,
  auditQ07NoteAccumulator,
  createQ07NoteAccumulator,
  exportQ07NoteAccumulatorRows,
  q07NoteMembershipPath,
  restoreQ07NoteAccumulator,
  snapshotQ07NoteAccumulator,
} from './q07-note-accumulator.mjs';

const frBytes = (value) => Buffer.from(value.toString(16).padStart(64, '0'), 'hex');
const asFr = (bytes) => BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
const referenceHasher = Object.freeze({
  depth: Q07_NOTE_TREE_DEPTH,
  emptyLeafHash: hashEmptyNoteLeaf(),
  hashNode: hashNoteTreeNode,
});

function rootFromPath(leaf, index, siblings) {
  let node = asFr(leaf);
  for (let level = 0; level < Q07_NOTE_TREE_DEPTH; level += 1) {
    node = Math.floor(index / (2 ** level)) % 2 === 0
      ? hashNoteTreeNode(node, asFr(siblings[level]))
      : hashNoteTreeNode(asFr(siblings[level]), node);
  }
  return frBytes(node);
}

test('incremental Q07 accumulator matches production depth-32 note-tree roots and paths', () => {
  const accumulator = createQ07NoteAccumulator();
  let reference = create(referenceHasher);
  const leaves = [
    0n,
    1n,
    2n,
    37n,
    BN254_SCALAR_FIELD_MODULUS - 1n,
    117n,
    19n,
    883n,
  ];
  for (let index = 0; index < leaves.length; index += 1) {
    const before = auditQ07NoteAccumulator(accumulator);
    const result = appendQ07Note(accumulator, frBytes(leaves[index]));
    const referenceResult = append(reference, leaves[index]);
    reference = referenceResult.tree;
    const after = auditQ07NoteAccumulator(accumulator);
    assert.equal(result.index, index);
    assert.deepEqual(result.preRoot, before.root);
    assert.deepEqual(result.postRoot, after.root);
    assert.deepEqual(after.root, frBytes(reference.root));
    assert.equal(result.operationCounters.appendNodeHashCalls, (index + 1) * Q07_NOTE_TREE_DEPTH);
    assert.deepEqual(result.siblings, referenceResult.witness.membershipPath.map(frBytes));
    for (let member = 0; member <= index; member += 1) {
      const q07Path = q07NoteMembershipPath(accumulator, member);
      const productionPath = membershipPath(reference, member).map(frBytes);
      assert.deepEqual(q07Path, productionPath);
      assert.deepEqual(rootFromPath(frBytes(leaves[member]), member, q07Path), after.root);
      assert.equal(
        verifyMembershipPath(reference, member, leaves[member], productionPath.map(asFr)),
        true,
      );
    }
  }
  const finalAudit = auditQ07NoteAccumulator(accumulator);
  assert.equal(finalAudit.leafCount, leaves.length);
  assert.equal(finalAudit.q07Qualified, false);
  assert.equal(finalAudit.operationCounters.appendNodeHashCalls, leaves.length * Q07_NOTE_TREE_DEPTH);
});

test('canonical Fr input validation, malformed input, and caller mutation fail safely', () => {
  const accumulator = createQ07NoteAccumulator();
  const mutable = frBytes(17n);
  const result = appendQ07Note(accumulator, mutable);
  mutable.fill(0xff);
  assert.deepEqual(result.outputNoteLeaf, frBytes(17n));
  assert.deepEqual(auditQ07NoteAccumulator(accumulator).root, result.postRoot);
  assert.throws(
    () => appendQ07Note(accumulator, frBytes(BN254_SCALAR_FIELD_MODULUS)),
    Q07NoteAccumulatorError,
  );
  assert.throws(() => appendQ07Note(accumulator, new Uint8Array(31)), /exactly 32 bytes/);
  assert.throws(() => appendQ07Note(accumulator, '00'.repeat(32)), /Uint8Array/);
  assert.throws(() => q07NoteMembershipPath(accumulator, -1), /not occupied/);
  assert.throws(() => q07NoteMembershipPath(accumulator, 1), /not occupied/);

  const path = q07NoteMembershipPath(accumulator, 0);
  const rootBeforePathMutation = auditQ07NoteAccumulator(accumulator).root;
  path[0].fill(0xff);
  assert.deepEqual(auditQ07NoteAccumulator(accumulator).root, rootBeforePathMutation);
});

test('deterministic rows round-trip only if every exported production-Poseidon node matches', () => {
  const accumulator = createQ07NoteAccumulator();
  for (const leaf of [3n, 6n, 9n, 12n, 15n]) appendQ07Note(accumulator, frBytes(leaf));
  const snapshot = snapshotQ07NoteAccumulator(accumulator);
  assert.equal(Object.isFrozen(snapshot), true);
  assert.equal(snapshot.schema, 'shieldkit-v2-q07-note-accumulator-v1');
  assert.equal(snapshot.depth, 32);
  assert.equal(snapshot.leafCount, 5);
  assert.equal(snapshot.nodes.filter((entry) => entry.level === 0).length, 5);
  assert.deepEqual(exportQ07NoteAccumulatorRows(accumulator), snapshot);
  const restored = restoreQ07NoteAccumulator(JSON.parse(JSON.stringify(snapshot)));
  assert.deepEqual(snapshotQ07NoteAccumulator(restored), snapshot);
  assert.deepEqual(auditQ07NoteAccumulator(restored).root, auditQ07NoteAccumulator(accumulator).root);

  const altered = JSON.parse(JSON.stringify(snapshot));
  altered.nodes[0].value = frBytes(99n).toString('hex');
  assert.throws(() => restoreQ07NoteAccumulator(altered), /authenticated accumulator state/);
  const reordered = JSON.parse(JSON.stringify(snapshot));
  [reordered.nodes[0], reordered.nodes[1]] = [reordered.nodes[1], reordered.nodes[0]];
  assert.throws(() => restoreQ07NoteAccumulator(reordered), /authenticated accumulator state/);
});

test('empty accumulator exports a full-audited canonical root without a qualification claim', () => {
  const accumulator = createQ07NoteAccumulator();
  const audit = auditQ07NoteAccumulator(accumulator);
  const rows = exportQ07NoteAccumulatorRows(accumulator);
  assert.equal(audit.leafCount, 0);
  assert.equal(audit.rootHex, rows.root);
  assert.equal(audit.q07Qualified, false);
  assert.equal(rows.nodes.length, 0);
  assert.equal(rows.defaults.length, Q07_NOTE_TREE_DEPTH + 1);
  assert.equal(rows.frontier.every((entry) => entry.value === null), true);
});
