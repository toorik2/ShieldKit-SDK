import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

import {
  createPersistentNullifierSqliteAccess,
  PERSISTENT_NULLIFIER_SQLITE_PROFILES,
} from "./persistent-indexed-nullifier-sqlite.mjs";

const key = (value) =>
  Buffer.from(BigInt(value).toString(16).padStart(64, "0"), "hex");
const hash = (value) => Buffer.alloc(32, value);
const raise = (message) => {
  throw new Error(message);
};
const leaf = ({
  index,
  leafType = 2,
  keyValue,
  successorIndex = 1,
  successorKey = 0,
}) => ({
  physicalIndex: index,
  leafType,
  leafHash: hash(index + 1),
  key: key(keyValue),
  successorIndex,
  successorKey: key(successorKey),
});

function qualificationDatabase() {
  const db = new DatabaseSync(":memory:");
  db.exec(`
    CREATE TABLE nodes(
      depth INTEGER NOT NULL,
      node_index INTEGER NOT NULL,
      node_hash BLOB NOT NULL,
      PRIMARY KEY(depth,node_index)
    ) STRICT;
    CREATE TABLE leaves(
      physical_index INTEGER PRIMARY KEY,
      leaf_type INTEGER NOT NULL,
      leaf_hash BLOB NOT NULL,
      key_be BLOB NOT NULL,
      successor_index INTEGER NOT NULL,
      successor_key_be BLOB NOT NULL
    ) STRICT;
    CREATE TABLE normal_order(
      key_be BLOB PRIMARY KEY,
      physical_index INTEGER NOT NULL UNIQUE
    ) STRICT;
  `);
  return db;
}

function productionDatabase() {
  const db = new DatabaseSync(":memory:");
  db.exec(`
    CREATE TABLE nullifier_nodes(
      depth INTEGER NOT NULL,
      node_index INTEGER NOT NULL,
      node_hash BLOB NOT NULL,
      PRIMARY KEY(depth,node_index)
    ) STRICT;
    CREATE TABLE nullifier_leaves(
      physical_index INTEGER PRIMARY KEY,
      leaf_type INTEGER NOT NULL,
      leaf_hash BLOB NOT NULL,
      key_be BLOB NOT NULL,
      successor_index INTEGER NOT NULL,
      successor_key_be BLOB NOT NULL
    ) STRICT;
    CREATE TABLE nullifier_order_keys(
      leaf_type INTEGER NOT NULL,
      key_be BLOB NOT NULL,
      physical_index INTEGER NOT NULL UNIQUE,
      PRIMARY KEY(leaf_type,key_be)
    ) STRICT;
  `);
  return db;
}

test("shared qualification adapter preserves sparse nodes and BE key order",
  () => {
    const db = qualificationDatabase();
    const defaults = Array.from({ length: 5 }, (_, index) => hash(0xa0 + index));
    const access = createPersistentNullifierSqliteAccess({
      db,
      defaults,
      profile: PERSISTENT_NULLIFIER_SQLITE_PROFILES.qualification,
      raise,
    });
    try {
      access.writeLeaf(leaf({ index: 0, leafType: 1, keyValue: 0 }));
      access.writeLeaf(leaf({ index: 1, leafType: 3, keyValue: 0 }));
      access.writeLeaf(leaf({ index: 2, keyValue: 0 }));
      access.writeLeaf(leaf({ index: 3, keyValue: 0x100 }));
      access.writeLeaf(leaf({ index: 4, keyValue: 0xff }));

      assert.equal(access.adapter.hasNormalKey(key(0)), true);
      assert.equal(access.adapter.hasNormalKey(key(7)), false);
      assert.equal(access.adapter.predecessorIndex(key(1)), 2);
      assert.equal(access.adapter.predecessorIndex(key(0x100)), 4);
      assert.equal(access.adapter.predecessorIndex(key(0)), 0);
      assert.equal(access.adapter.readLeaf(4).physicalIndex, 4);
      assert.equal(access.adapter.readLeaf(9), null);

      access.writeNode({ depth: 0, nodeIndex: 2, nodeHash: hash(7) });
      assert.deepEqual(Buffer.from(access.adapter.readNode(0, 2)), hash(7));
      access.writeNode({
        depth: 0,
        nodeIndex: 2,
        nodeHash: defaults[0],
      });
      assert.equal(access.adapter.readNode(0, 2), null);

      assert.throws(
        () => access.writeLeaf(leaf({ index: 4, keyValue: 9 })),
        /physical index\/key is immutable/u,
      );
      assert.throws(
        () => access.writeLeaf(leaf({ index: 5, keyValue: 0xff })),
        /another physical index/u,
      );
    } finally {
      db.close();
    }
  });

test("shared production adapter separates sentinel and normal zero keys",
  () => {
    const db = productionDatabase();
    const access = createPersistentNullifierSqliteAccess({
      db,
      profile: PERSISTENT_NULLIFIER_SQLITE_PROFILES.production,
      raise,
    });
    try {
      access.writeLeaf(leaf({ index: 0, leafType: 1, keyValue: 0 }));
      access.writeLeaf(leaf({ index: 1, leafType: 3, keyValue: 0 }));
      access.writeLeaf(leaf({ index: 2, keyValue: 0 }));
      access.writeLeaf(leaf({ index: 3, keyValue: 7 }));

      assert.equal(access.adapter.hasNormalKey(key(0)), true);
      assert.equal(access.adapter.predecessorIndex(key(1)), 2);
      assert.equal(access.adapter.predecessorIndex(key(7)), 2);
      assert.equal(access.adapter.predecessorIndex(key(8)), 3);
      assert.equal(
        db.prepare(
          "SELECT COUNT(*) AS count FROM nullifier_order_keys",
        ).get().count,
        4,
      );

      access.writeNode({ depth: 4, nodeIndex: 0, nodeHash: hash(0) });
      assert.deepEqual(Buffer.from(access.adapter.readNode(4, 0)), hash(0));
    } finally {
      db.close();
    }
  });

test("shared SQLite adapter rejects immutable conflicts without persisting a partial leaf",
  () => {
    const db = qualificationDatabase();
    const defaults = Array.from({ length: 5 }, (_, index) => hash(0xb0 + index));
    const access = createPersistentNullifierSqliteAccess({
      db,
      defaults,
      profile: PERSISTENT_NULLIFIER_SQLITE_PROFILES.qualification,
      raise,
    });
    try {
      access.writeLeaf(leaf({ index: 2, keyValue: 3 }));
      const before = db.prepare(
        "SELECT physical_index,leaf_type,hex(key_be) AS key_be FROM leaves ORDER BY physical_index",
      ).all();
      const beforeOrder = db.prepare(
        "SELECT physical_index,hex(key_be) AS key_be FROM normal_order ORDER BY physical_index",
      ).all();

      assert.throws(
        () => access.writeLeaf(leaf({ index: 2, keyValue: 4 })),
        /physical index\/key is immutable/u,
      );
      assert.deepEqual(
        db.prepare(
          "SELECT physical_index,leaf_type,hex(key_be) AS key_be FROM leaves ORDER BY physical_index",
        ).all(),
        before,
      );
      assert.deepEqual(
        db.prepare(
          "SELECT physical_index,hex(key_be) AS key_be FROM normal_order ORDER BY physical_index",
        ).all(),
        beforeOrder,
      );

      assert.throws(
        () => access.writeLeaf(leaf({ index: 3, keyValue: 3 })),
        /already assigned to another physical index/u,
      );
      assert.deepEqual(
        db.prepare(
          "SELECT physical_index,leaf_type,hex(key_be) AS key_be FROM leaves ORDER BY physical_index",
        ).all(),
        before,
      );
      assert.deepEqual(
        db.prepare(
          "SELECT physical_index,hex(key_be) AS key_be FROM normal_order ORDER BY physical_index",
        ).all(),
        beforeOrder,
      );
    } finally {
      db.close();
    }
  });

test("caller transaction rolls back all adapter writes after a later immutable conflict",
  () => {
    const db = qualificationDatabase();
    const defaults = Array.from({ length: 5 }, (_, index) => hash(0xc0 + index));
    const access = createPersistentNullifierSqliteAccess({
      db,
      defaults,
      profile: PERSISTENT_NULLIFIER_SQLITE_PROFILES.qualification,
      raise,
    });
    try {
      db.exec("BEGIN IMMEDIATE");
      try {
        access.writeNode({ depth: 0, nodeIndex: 2, nodeHash: hash(7) });
        access.writeLeaf(leaf({ index: 2, keyValue: 3 }));
        access.writeLeaf(leaf({ index: 3, keyValue: 3 }));
        assert.fail("duplicate normal key must reject the transaction");
      } catch (error) {
        assert.match(error.message, /already assigned to another physical index/u);
        db.exec("ROLLBACK");
      }
      assert.equal(db.prepare("SELECT COUNT(*) AS count FROM nodes").get().count, 0);
      assert.equal(db.prepare("SELECT COUNT(*) AS count FROM leaves").get().count, 0);
      assert.equal(
        db.prepare("SELECT COUNT(*) AS count FROM normal_order").get().count,
        0,
      );
      assert.equal(access.adapter.readNode(0, 2), null);
      assert.equal(access.adapter.readLeaf(2), null);
      assert.equal(access.adapter.hasNormalKey(key(3)), false);
    } finally {
      db.close();
    }
  });

test("caller transaction rolls back a partial qualification leaf write when order persistence faults",
  () => {
    const db = qualificationDatabase();
    const defaults = Array.from({ length: 5 }, (_, index) => hash(0xd0 + index));
    const access = createPersistentNullifierSqliteAccess({
      db,
      defaults,
      profile: PERSISTENT_NULLIFIER_SQLITE_PROFILES.qualification,
      raise,
    });
    try {
      db.exec(`
        CREATE TRIGGER fail_normal_order_insert
        BEFORE INSERT ON normal_order
        BEGIN
          SELECT RAISE(ABORT, 'injected normal-order write fault');
        END;
      `);
      db.exec("BEGIN IMMEDIATE");
      try {
        access.writeNode({ depth: 0, nodeIndex: 2, nodeHash: hash(9) });
        access.writeLeaf(leaf({ index: 2, keyValue: 9 }));
        assert.fail("normal-order trigger must reject the transaction");
      } catch (error) {
        assert.match(error.message, /injected normal-order write fault/u);
        db.exec("ROLLBACK");
      }
      assert.equal(db.prepare("SELECT COUNT(*) AS count FROM nodes").get().count, 0);
      assert.equal(db.prepare("SELECT COUNT(*) AS count FROM leaves").get().count, 0);
      assert.equal(
        db.prepare("SELECT COUNT(*) AS count FROM normal_order").get().count,
        0,
      );
      assert.equal(access.adapter.readNode(0, 2), null);
      assert.equal(access.adapter.readLeaf(2), null);
      assert.equal(access.adapter.hasNormalKey(key(9)), false);
    } finally {
      db.close();
    }
  });
