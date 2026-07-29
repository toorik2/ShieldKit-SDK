import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

import {
  createDepth4PersistentIndexedNullifierQualificationKernel,
  PERSISTENT_NULLIFIER_FR_MODULUS,
  PERSISTENT_NULLIFIER_LEAF_TYPES,
} from "../persistent-indexed-nullifier.mjs";
import {
  openDepth4PersistentNullifierQualificationStore,
  openQ04PersistentNullifierStore,
  Q04PersistentStoreError,
} from "./persistent-nullifier-store.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const workspace = resolve(here, "../../../../..");
const temporaryRoot = join(workspace, ".tmp");

const field = (value) => Buffer.from(
  BigInt(value).toString(16).padStart(64, "0"),
  "hex",
);
const hex = (value) => Buffer.from(value).toString("hex");
const mode = (path) => lstatSync(path).mode & 0o777;

function fixture(
  t,
  {
    historyIndex = 2,
    openStore = openQ04PersistentNullifierStore,
    seed = field(0x91n),
  } = {},
) {
  mkdirSync(temporaryRoot, { recursive: true, mode: 0o700 });
  const parent = mkdtempSync(join(temporaryRoot, "q04-persistent-nullifier-"));
  chmodSync(parent, 0o700);
  const path = join(parent, "store.sqlite");
  const binding = { historyIndex, seed: Buffer.from(seed) };
  let store = openStore({
    path,
    create: true,
    ...binding,
  });
  t.after(() => {
    store?.close();
    rmSync(parent, { recursive: true, force: true });
  });
  return {
    binding,
    parent,
    path,
    get store() {
      return store;
    },
    reopen() {
      store.close();
      store = openStore({
        path,
        create: false,
        ...binding,
      });
      return store;
    },
  };
}

function insertCurrent(store, key) {
  const state = store.state();
  return store.insert({
    expectedCount: state.normalCount,
    expectedRoot: state.root,
    key,
  });
}

function persistentSnapshot(store) {
  const state = store.state();
  const audit = store.audit();
  return {
    state: {
      historyIndex: state.historyIndex,
      seed: hex(state.seed),
      normalCount: state.normalCount,
      root: hex(state.root),
      transcript: hex(state.transcriptChainSha256),
    },
    audit: {
      leafCount: audit.leafCount,
      nodeCount: audit.nodeCount,
      orderCount: audit.orderCount,
      root: hex(audit.root),
      transcript: hex(audit.transcriptChainSha256),
      logicalDigestSha256: audit.logicalDigestSha256,
      integrityCheck: audit.integrityCheck,
      foreignKeyViolations: audit.foreignKeyViolations,
    },
  };
}

test("Q-04 persistent store creates the production-Poseidon genesis and first insertion", (t) => {
  const subject = fixture(t, { historyIndex: 3, seed: field(0x1234n) });
  const { store } = subject;
  const initial = persistentSnapshot(store);

  assert.deepEqual(initial.state, {
    historyIndex: 3,
    seed: hex(field(0x1234n)),
    normalCount: 0,
    root: initial.audit.root,
    transcript: initial.audit.transcript,
  });
  assert.deepEqual(
    {
      leafCount: initial.audit.leafCount,
      nodeCount: initial.audit.nodeCount,
      orderCount: initial.audit.orderCount,
      integrityCheck: initial.audit.integrityCheck,
      foreignKeyViolations: initial.audit.foreignKeyViolations,
    },
    {
      leafCount: 2,
      nodeCount: 34,
      orderCount: 0,
      integrityCheck: "ok",
      foreignKeyViolations: 0,
    },
  );

  const key = field(0x20n);
  const inserted = insertCurrent(store, key);
  const after = persistentSnapshot(store);
  assert.equal(inserted.writes.leafWrites, 2);
  assert.ok(inserted.writes.nodeWrites >= 33);
  assert.equal(after.state.normalCount, 1);
  assert.equal(after.state.root, hex(inserted.writes.root));
  assert.equal(after.state.transcript, inserted.transcriptChainSha256);
  assert.notEqual(after.state.root, initial.state.root);
  assert.notEqual(after.state.transcript, initial.state.transcript);
  assert.equal(after.audit.leafCount, 3);
  assert.equal(after.audit.orderCount, 1);

  const minimum = store.leaf(0);
  const normal = store.leaf(2);
  const maximum = store.leaf(1);
  assert.deepEqual(
    {
      type: minimum.leafType,
      successorIndex: minimum.successorIndex,
      successorKey: hex(minimum.successorKey),
    },
    {
      type: PERSISTENT_NULLIFIER_LEAF_TYPES.minimum,
      successorIndex: 2,
      successorKey: hex(key),
    },
  );
  assert.deepEqual(
    {
      type: normal.leafType,
      key: hex(normal.key),
      successorIndex: normal.successorIndex,
      successorKey: hex(normal.successorKey),
    },
    {
      type: PERSISTENT_NULLIFIER_LEAF_TYPES.normal,
      key: hex(key),
      successorIndex: 1,
      successorKey: "00".repeat(32),
    },
  );
  assert.equal(maximum.leafType, PERSISTENT_NULLIFIER_LEAF_TYPES.maximum);
});

test("Q-04 read-only insertion derivation is exact and leaves no durable change", (t) => {
  const subject = fixture(t, {
    openStore: openDepth4PersistentNullifierQualificationStore,
  });
  const key = field(0x20n);
  const state = subject.store.state();
  const before = persistentSnapshot(subject.store);
  const derived = subject.store.deriveInsertion({
    expectedCount: state.normalCount,
    expectedRoot: state.root,
    key,
  });
  assert.deepEqual(persistentSnapshot(subject.store), before);

  const inserted = insertCurrent(subject.store, key);
  assert.deepEqual(derived.witness, inserted.mutation.witness);
  assert.deepEqual(derived.nullifierLeaves, inserted.mutation.nullifierLeaves);
  assert.deepEqual(derived.nullifierNodes, inserted.mutation.nullifierNodes);
  assert.deepEqual(derived.metrics, inserted.mutation.metrics);
  assert.equal(hex(derived.root), hex(inserted.mutation.root));
});

test("Q-04 persistent store orders multiple inserts and persists count/root/transcript across a fresh reopen", (t) => {
  const subject = fixture(t);
  const keys = [field(0x30n), field(0x10n), field(0x20n)];
  for (const key of keys) insertCurrent(subject.store, key);

  const before = persistentSnapshot(subject.store);
  assert.deepEqual(
    [
      subject.store.leaf(0).successorIndex,
      subject.store.leaf(3).successorIndex,
      subject.store.leaf(4).successorIndex,
      subject.store.leaf(2).successorIndex,
      subject.store.leaf(1).successorIndex,
    ],
    [3, 4, 2, 1, 1],
  );
  assert.deepEqual(
    [
      hex(subject.store.leaf(0).successorKey),
      hex(subject.store.leaf(3).successorKey),
      hex(subject.store.leaf(4).successorKey),
      hex(subject.store.leaf(2).successorKey),
    ],
    [hex(field(0x10n)), hex(field(0x20n)), hex(field(0x30n)), "00".repeat(32)],
  );
  assert.deepEqual(
    {
      normalCount: before.state.normalCount,
      leafCount: before.audit.leafCount,
      orderCount: before.audit.orderCount,
      integrityCheck: before.audit.integrityCheck,
      foreignKeyViolations: before.audit.foreignKeyViolations,
    },
    {
      normalCount: 3,
      leafCount: 5,
      orderCount: 3,
      integrityCheck: "ok",
      foreignKeyViolations: 0,
    },
  );

  const reopened = subject.reopen();
  assert.deepEqual(persistentSnapshot(reopened), before);
  assert.equal(hex(reopened.state().root), before.state.root);
  assert.equal(hex(reopened.state().transcriptChainSha256), before.state.transcript);
});

test("Q-04 persistent insertion rejects duplicate, noncanonical, and stale-root inputs without a durable change", (t) => {
  const subject = fixture(t);
  const firstState = subject.store.state();
  const key = field(0x55n);
  subject.store.insert({
    expectedCount: firstState.normalCount,
    expectedRoot: firstState.root,
    key,
  });
  const before = persistentSnapshot(subject.store);

  assert.throws(
    () => insertCurrent(subject.store, key),
    (error) =>
      error instanceof Error && /already exists/.test(error.message),
  );
  assert.deepEqual(persistentSnapshot(subject.store), before);

  assert.throws(
    () => insertCurrent(subject.store, field(PERSISTENT_NULLIFIER_FR_MODULUS)),
    (error) =>
      error instanceof Q04PersistentStoreError &&
      /canonical BN254 Fr/.test(error.message),
  );
  assert.deepEqual(persistentSnapshot(subject.store), before);

  assert.throws(
    () => subject.store.insert({
      expectedCount: before.state.normalCount,
      expectedRoot: field(0n),
      key: field(0x56n),
    }),
    (error) =>
      error instanceof Q04PersistentStoreError &&
      /expected state is stale/.test(error.message),
  );
  assert.deepEqual(persistentSnapshot(subject.store), before);
});

test("Q-04 persistent store copies caller and result buffers rather than retaining aliases", (t) => {
  const seed = field(0x777n);
  const subject = fixture(t, { seed });
  seed.fill(0);
  assert.equal(hex(subject.store.state().seed), hex(field(0x777n)));

  const expected = subject.store.state();
  const expectedRoot = Buffer.from(expected.root);
  const key = field(0x66n);
  const inserted = subject.store.insert({
    expectedCount: expected.normalCount,
    expectedRoot,
    key,
  });
  expected.root.fill(0);
  expectedRoot.fill(0);
  key.fill(0);
  inserted.writes.root.fill(0);

  const stateCopy = subject.store.state();
  const root = Buffer.from(stateCopy.root);
  stateCopy.seed.fill(0);
  stateCopy.root.fill(0);
  stateCopy.transcriptChainSha256.fill(0);
  assert.equal(hex(subject.store.state().seed), hex(field(0x777n)));
  assert.equal(hex(subject.store.state().root), hex(root));

  const leafCopy = subject.store.leaf(2);
  leafCopy.key.fill(0);
  leafCopy.leafHash.fill(0);
  leafCopy.successorKey.fill(0);
  assert.deepEqual(
    {
      key: hex(subject.store.leaf(2).key),
      root: hex(subject.store.state().root),
    },
    { key: hex(field(0x66n)), root: hex(root) },
  );
  assert.doesNotThrow(() => subject.store.audit());
});

test("Q-04 depth-32 schema admits the final persisted count but not a further count", (t) => {
  const subject = fixture(t);
  subject.store.close();
  const database = new DatabaseSync(subject.path);
  try {
    const finalCount = 4_294_967_294;
    assert.equal(
      database.prepare(
        "UPDATE metadata SET normal_count=? WHERE singleton=1",
      ).run(finalCount).changes,
      1,
    );
    assert.equal(
      database.prepare(
        "SELECT normal_count FROM metadata WHERE singleton=1",
      ).get().normal_count,
      finalCount,
    );
    assert.throws(
      () => database.prepare(
        "UPDATE metadata SET normal_count=? WHERE singleton=1",
      ).run(finalCount + 1),
      /CHECK constraint failed/u,
    );
  } finally {
    database.close();
  }
});

test("fixed depth-4 Q-04 qualification store persists its final legal count and rejects a further insertion before adapter reads", (t) => {
  const subject = fixture(t, {
    openStore: openDepth4PersistentNullifierQualificationStore,
  });
  for (let value = 1n; value <= 14n; value += 1n) {
    insertCurrent(subject.store, field(value));
  }
  const final = persistentSnapshot(subject.store);
  assert.equal(final.state.normalCount, 14);
  assert.equal(final.audit.leafCount, 16);
  assert.equal(final.audit.orderCount, 14);
  assert.equal(subject.store.membershipPath(15).metrics.treeDepth, 4);

  assert.throws(
    () => insertCurrent(subject.store, field(15n)),
    (error) =>
      error instanceof Q04PersistentStoreError &&
      /normalCount must be an integer from 0 through 13/u.test(error.message),
  );
  assert.deepEqual(persistentSnapshot(subject.store), final);

  const kernel = createDepth4PersistentIndexedNullifierQualificationKernel();
  const reads = [];
  assert.throws(
    () => kernel.derive({
      expectedPreRoot: field(0n),
      key: field(15n),
      normalCount: 14,
      adapter: {
        hasNormalKey() { reads.push("hasNormalKey"); return false; },
        predecessorIndex() { reads.push("predecessorIndex"); return 0; },
        readLeaf() { reads.push("readLeaf"); return null; },
        readNode() { reads.push("readNode"); return null; },
      },
    }),
    /normalCount must be an integer from 0 through 13/u,
  );
  assert.deepEqual(reads, []);
});

test("fixed depth-4 Q-04 qualification store enforces depth-derived node bounds and exposes no caller-selected depth", (t) => {
  const subject = fixture(t, {
    openStore: openDepth4PersistentNullifierQualificationStore,
  });
  assert.throws(
    () => subject.store.leaf(16),
    /physicalIndex must be an integer from 0 through 15/u,
  );
  assert.throws(
    () => subject.store.membershipPath(16),
    /membership physicalIndex must be an integer from 0 through 15/u,
  );

  subject.store.close();
  const database = new DatabaseSync(subject.path);
  try {
    assert.throws(
      () => database.prepare(
        "INSERT INTO nodes(depth,node_index,node_hash) VALUES(?,?,?)",
      ).run(0, 16, field(1n)),
      /CHECK constraint failed/u,
    );
    assert.throws(
      () => database.prepare(
        "INSERT INTO nodes(depth,node_index,node_hash) VALUES(?,?,?)",
      ).run(5, 0, field(1n)),
      /CHECK constraint failed/u,
    );
  } finally {
    database.close();
  }

  const fixedBinding = {
    create: false,
    historyIndex: subject.binding.historyIndex,
    path: subject.path,
    seed: subject.binding.seed,
  };
  for (const openStore of [
    openQ04PersistentNullifierStore,
    openDepth4PersistentNullifierQualificationStore,
  ]) {
    assert.throws(
      () => openStore({ ...fixedBinding, depth: 4 }),
      /missing or unknown properties/u,
    );
  }
});

test("Q-04 persistent corruption probes reject ordering and successor-pointer damage and roll it back", (t) => {
  const subject = fixture(t);
  for (const key of [field(0x30n), field(0x10n), field(0x20n)]) {
    insertCurrent(subject.store, key);
  }
  const before = persistentSnapshot(subject.store);
  for (const kind of ["ordering", "successor-pointer"]) {
    const result = subject.store.corruptionProbe(kind);
    assert.equal(result.kind, kind);
    assert.equal(result.rejected, true);
    assert.match(result.rejection, /^Q-04 /);
    assert.equal(
      result.unchangedLogicalDigestSha256,
      before.audit.logicalDigestSha256,
    );
    assert.deepEqual(persistentSnapshot(subject.store), before);
  }
});

test("Q-04 persistent store enforces exact database modes and rejects terminal or parent symlinks", (t) => {
  const subject = fixture(t);
  insertCurrent(subject.store, field(0x44n));
  assert.equal(mode(subject.parent), 0o700);
  assert.equal(mode(subject.path), 0o600);
  for (const sidecar of [`${subject.path}-wal`, `${subject.path}-shm`]) {
    if (existsSync(sidecar)) assert.equal(mode(sidecar), 0o600, sidecar);
  }

  subject.store.close();
  chmodSync(subject.path, 0o644);
  assert.throws(
    () => openQ04PersistentNullifierStore({
      path: subject.path,
      create: false,
      ...subject.binding,
    }),
    (error) =>
      error instanceof Q04PersistentStoreError && /mode-0600/.test(error.message),
  );
  chmodSync(subject.path, 0o600);

  const terminalSymlink = join(subject.parent, "terminal-symlink.sqlite");
  symlinkSync(subject.path, terminalSymlink);
  assert.throws(
    () => openQ04PersistentNullifierStore({
      path: terminalSymlink,
      create: false,
      ...subject.binding,
    }),
    (error) =>
      error instanceof Q04PersistentStoreError && /direct single-link/.test(error.message),
  );

  const parentSymlink = join(subject.parent, "parent-symlink");
  symlinkSync(subject.parent, parentSymlink);
  assert.throws(
    () => openQ04PersistentNullifierStore({
      path: join(parentSymlink, "new.sqlite"),
      create: true,
      ...subject.binding,
    }),
    (error) =>
      error instanceof Q04PersistentStoreError && /parent must be/.test(error.message),
  );
});
