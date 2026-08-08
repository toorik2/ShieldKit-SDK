import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  createIndependentIndexedNullifierTree,
  INDEPENDENT_NULLIFIER_FR_MODULUS,
} from "./independent-indexed-nullifier-tree.mjs";
import {
  createIndependentPoseidonOracle,
} from "./independent-poseidon-oracle.mjs";
import {
  openQ04PersistentNullifierStore,
  Q04PersistentStoreError,
} from "./persistent-nullifier-store.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const workspace = resolve(here, "../../../../../..");
const temporaryRoot = join(workspace, ".tmp");
const parameterSourcePath = resolve(
  workspace,
  "node_modules/circomlib/circuits/poseidon_constants.circom",
);

const bytes = (value) =>
  Buffer.from(BigInt(value).toString(16).padStart(64, "0"), "hex");
const field = (value) =>
  BigInt(`0x${Buffer.from(value).toString("hex")}`);

function fixture(t) {
  mkdirSync(temporaryRoot, { recursive: true, mode: 0o700 });
  const parent = mkdtempSync(join(temporaryRoot, "q04-oracle-tree-"));
  chmodSync(parent, 0o700);
  const path = join(parent, "store.sqlite");
  const seed = createHash("sha256").update("q04-oracle-tree-test").digest();
  const store = openQ04PersistentNullifierStore({
    path,
    create: true,
    historyIndex: 0,
    seed,
  });
  const oracle = createIndependentPoseidonOracle({ parameterSourcePath });
  const tree = createIndependentIndexedNullifierTree({ oracle });
  t.after(() => {
    store.close();
    rmSync(parent, { recursive: true, force: true });
  });
  return { store, tree };
}

function deterministicKeys(count) {
  const selected = [0n, INDEPENDENT_NULLIFIER_FR_MODULUS - 1n];
  const seen = new Set(selected.map(String));
  for (let ordinal = 0; selected.length < count; ordinal += 1) {
    const digest = createHash("sha256")
      .update("ShieldKit/Q04/oracle-tree-test-key/v1\0", "ascii")
      .update(bytes(BigInt(ordinal)))
      .digest();
    const candidate = field(digest);
    if (
      candidate < INDEPENDENT_NULLIFIER_FR_MODULUS &&
      !seen.has(String(candidate))
    ) {
      seen.add(String(candidate));
      selected.push(candidate);
    }
  }
  return selected;
}

function insertAndCompare(store, tree, key) {
  const before = store.state();
  const actual = store.insert({
    expectedCount: before.normalCount,
    expectedRoot: before.root,
    key,
  });
  const expected = tree.insert(key);
  const postMembership = store.membershipPath(expected.append.index);

  assert.equal(actual.mutation.witness.preRoot, expected.preRoot);
  assert.equal(
    actual.mutation.witness.intermediateRoot,
    expected.intermediateRoot,
  );
  assert.equal(actual.mutation.witness.postRoot, expected.postRoot);
  assert.deepEqual(
    actual.mutation.witness.predecessor,
    expected.predecessor,
  );
  assert.deepEqual(
    actual.mutation.witness.updatedPredecessor,
    expected.updatedPredecessor,
  );
  assert.deepEqual(
    actual.mutation.witness.predecessorPath,
    expected.predecessorPath,
  );
  assert.equal(actual.mutation.witness.append.index, expected.append.index);
  assert.deepEqual(
    actual.mutation.witness.append.newLeaf,
    expected.append.newLeaf,
  );
  assert.deepEqual(
    actual.mutation.witness.append.path,
    expected.append.emptyPath,
  );
  assert.deepEqual(
    postMembership.siblings,
    expected.postMembershipPath,
  );
  assert.equal(field(postMembership.root), expected.postRoot);
  assert.equal(actual.mutation.metrics.leafHashCalls, 3);
  assert.equal(
    actual.mutation.metrics.predecessorValidationLeafHashCalls,
    1,
  );
  assert.equal(actual.mutation.metrics.mutationLeafHashCalls, 2);
  assert.equal(actual.mutation.metrics.nodeHashCalls, 128);
  assert.deepEqual(expected.metrics, {
    leafHashCalls: 2,
    nodeHashCalls: 160,
    membershipPathComputations: 3,
    stateUpdatePaths: 2,
    treeDepth: 32,
  });
  assert.deepEqual(store.state().root, tree.state().rootBytes);
  return { actual, expected };
}

test("independent state machine matches every production root and path over mixed order and Fr edges", (t) => {
  const { store, tree } = fixture(t);
  assert.deepEqual(store.state().root, tree.state().rootBytes);

  for (const key of deterministicKeys(50)) {
    insertAndCompare(store, tree, bytes(key));
  }
  const audit = store.audit();
  assert.equal(audit.normalCount, 50);
  assert.equal(tree.state().normalCount, 50);
  assert.deepEqual(audit.root, tree.state().rootBytes);
});

test("independent state machine and persistent store reject duplicates and noncanonical keys without drift", (t) => {
  const { store, tree } = fixture(t);
  const key = bytes(7n);
  insertAndCompare(store, tree, key);
  const actualBefore = store.audit();
  const oracleBefore = tree.state();

  assert.throws(
    () => store.insert({
      expectedCount: store.state().normalCount,
      expectedRoot: store.state().root,
      key,
    }),
    (error) =>
      error instanceof Q04PersistentStoreError &&
      /already exists/.test(error.message),
  );
  assert.throws(() => tree.insert(key), /already exists/);
  assert.throws(
    () => tree.insert(bytes(INDEPENDENT_NULLIFIER_FR_MODULUS)),
    /canonical BN254 Fr/,
  );
  assert.equal(store.audit().logicalDigestSha256, actualBefore.logicalDigestSha256);
  assert.deepEqual(tree.state(), oracleBefore);
});

test("both state machines own their key buffers and return non-aliased roots", (t) => {
  const { store, tree } = fixture(t);
  const key = bytes(0x1234n);
  const original = Buffer.from(key);
  insertAndCompare(store, tree, key);
  key.fill(0xff);
  assert.deepEqual(store.leaf(2).key, original);
  assert.equal(tree.leaf(2).key, field(original));

  const actualRoot = store.state().root;
  const oracleRoot = tree.state().rootBytes;
  actualRoot.fill(0);
  oracleRoot.fill(0);
  assert.notDeepEqual(store.state().root, actualRoot);
  assert.notDeepEqual(tree.state().rootBytes, oracleRoot);
});

test("independent tree source imports neither the production tree/store nor production Poseidon", () => {
  const source = readFileSync(
    resolve(here, "independent-indexed-nullifier-tree.mjs"),
    "utf8",
  );
  assert.doesNotMatch(source, /persistent-indexed-nullifier/);
  assert.doesNotMatch(source, /persistent-nullifier-store/);
  assert.doesNotMatch(source, /action\/v2\/(?:poseidon|domains)/);
  assert.doesNotMatch(source, /poseidon-lite/);
});
