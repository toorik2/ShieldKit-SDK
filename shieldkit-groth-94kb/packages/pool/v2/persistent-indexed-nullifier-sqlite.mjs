export const PERSISTENT_NULLIFIER_SQLITE_PROFILES = Object.freeze({
  production: "v2-direct",
  qualification: "q04-qualification",
});

const PROFILES = Object.freeze({
  [PERSISTENT_NULLIFIER_SQLITE_PROFILES.production]: Object.freeze({
    leaves: "nullifier_leaves",
    nodes: "nullifier_nodes",
    order: "nullifier_order_keys",
    orderIncludesLeafType: true,
    sparseDefaults: false,
  }),
  [PERSISTENT_NULLIFIER_SQLITE_PROFILES.qualification]: Object.freeze({
    leaves: "leaves",
    nodes: "nodes",
    order: "normal_order",
    orderIncludesLeafType: false,
    sparseDefaults: true,
  }),
});

const NORMAL_LEAF_TYPE = 2;
const same = (left, right) =>
  Buffer.from(left).equals(Buffer.from(right));
const freeze = (value) => Object.freeze(value);

export class PersistentNullifierSqliteAdapterError extends Error {
  constructor(message) {
    super(message);
    this.name = "PersistentNullifierSqliteAdapterError";
  }
}

const fail = (message) => {
  throw new PersistentNullifierSqliteAdapterError(message);
};

function compatibleDatabase(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    typeof value.prepare !== "function"
  ) fail("persistent nullifier SQLite access requires a database");
  return value;
}

function compatibleRaise(value) {
  if (typeof value !== "function") {
    fail("persistent nullifier SQLite access requires a raise callback");
  }
  return value;
}

function validatedDefaults(value, profile) {
  if (!profile.sparseDefaults) {
    if (value !== undefined) {
      fail("production persistent nullifier SQLite access takes no defaults");
    }
    return null;
  }
  if (
    !Array.isArray(value) ||
    value.length < 3 ||
    value.some((entry) =>
      !(entry instanceof Uint8Array) || entry.length !== 32
    )
  ) fail("qualification persistent nullifier defaults are invalid");
  return freeze(value.map((entry) => Buffer.from(entry)));
}

export function createPersistentNullifierSqliteAccess({
  db,
  defaults = undefined,
  profile: profileName,
  raise,
} = {}) {
  const database = compatibleDatabase(db);
  const profile = PROFILES[profileName];
  if (profile === undefined) {
    fail("persistent nullifier SQLite profile is unsupported");
  }
  const reject = compatibleRaise(raise);
  const treeDefaults = validatedDefaults(defaults, profile);
  const normal = profile.orderIncludesLeafType
    ? database.prepare(
      `SELECT physical_index FROM ${profile.order} ` +
        "WHERE leaf_type=2 AND key_be=?",
    )
    : database.prepare(
      `SELECT physical_index FROM ${profile.order} WHERE key_be=?`,
    );
  const predecessor = profile.orderIncludesLeafType
    ? database.prepare(
      `SELECT physical_index FROM ${profile.order} ` +
        "WHERE leaf_type=2 AND key_be<? ORDER BY key_be DESC LIMIT 1",
    )
    : database.prepare(
      `SELECT physical_index FROM ${profile.order} ` +
        "WHERE key_be<? ORDER BY key_be DESC LIMIT 1",
    );
  const leaf = database.prepare(
    `SELECT * FROM ${profile.leaves} WHERE physical_index=?`,
  );
  const node = database.prepare(
    `SELECT node_hash FROM ${profile.nodes} ` +
      "WHERE depth=? AND node_index=?",
  );
  const upsertNode = database.prepare(
    `INSERT INTO ${profile.nodes}(depth,node_index,node_hash) VALUES(?,?,?) ` +
      "ON CONFLICT(depth,node_index) DO UPDATE SET " +
      "node_hash=excluded.node_hash",
  );
  const deleteNode = profile.sparseDefaults
    ? database.prepare(
      `DELETE FROM ${profile.nodes} WHERE depth=? AND node_index=?`,
    )
    : null;
  const existingLeaf = database.prepare(
    `SELECT leaf_type,key_be FROM ${profile.leaves} WHERE physical_index=?`,
  );
  const upsertLeaf = database.prepare(
    `INSERT INTO ${profile.leaves}(` +
      "physical_index,leaf_type,leaf_hash,key_be,successor_index," +
      "successor_key_be) VALUES(?,?,?,?,?,?) " +
      "ON CONFLICT(physical_index) DO UPDATE SET " +
      "leaf_hash=excluded.leaf_hash," +
      "successor_index=excluded.successor_index," +
      "successor_key_be=excluded.successor_key_be",
  );
  const orderAtKey = profile.orderIncludesLeafType
    ? database.prepare(
      `SELECT physical_index FROM ${profile.order} ` +
        "WHERE leaf_type=? AND key_be=?",
    )
    : database.prepare(
      `SELECT physical_index FROM ${profile.order} WHERE key_be=?`,
    );
  const insertOrder = profile.orderIncludesLeafType
    ? database.prepare(
      `INSERT INTO ${profile.order}` +
        "(leaf_type,key_be,physical_index) VALUES(?,?,?) " +
        "ON CONFLICT(leaf_type,key_be) DO NOTHING",
    )
    : database.prepare(
      `INSERT INTO ${profile.order}(key_be,physical_index) VALUES(?,?)`,
    );

  const adapter = freeze({
    hasNormalKey(key) {
      return normal.get(key) !== undefined;
    },
    predecessorIndex(key) {
      return predecessor.get(key)?.physical_index ?? 0;
    },
    readLeaf(physicalIndex) {
      const row = leaf.get(physicalIndex);
      return row === undefined
        ? null
        : {
          physicalIndex: row.physical_index,
          leafType: row.leaf_type,
          leafHash: row.leaf_hash,
          key: row.key_be,
          successorIndex: row.successor_index,
          successorKey: row.successor_key_be,
        };
    },
    readNode(depth, nodeIndex) {
      return node.get(depth, nodeIndex)?.node_hash ?? null;
    },
  });

  const writeNode = (value) => {
    if (
      profile.sparseDefaults &&
      same(value.nodeHash, treeDefaults[value.depth])
    ) {
      deleteNode.run(value.depth, value.nodeIndex);
    } else {
      upsertNode.run(value.depth, value.nodeIndex, value.nodeHash);
    }
  };

  const writeLeaf = (value) => {
    const existing = existingLeaf.get(value.physicalIndex);
    if (
      existing !== undefined &&
      (
        existing.leaf_type !== value.leafType ||
        !same(existing.key_be, value.key)
      )
    ) reject("persistent nullifier leaf physical index/key is immutable");
    const order = profile.orderIncludesLeafType
      ? orderAtKey.get(value.leafType, value.key)
      : orderAtKey.get(value.key);
    if (
      order !== undefined &&
      order.physical_index !== value.physicalIndex
    ) reject(
      "persistent nullifier key is already assigned to another physical index",
    );
    if (profile.orderIncludesLeafType) {
      insertOrder.run(value.leafType, value.key, value.physicalIndex);
    }
    upsertLeaf.run(
      value.physicalIndex,
      value.leafType,
      value.leafHash,
      value.key,
      value.successorIndex,
      value.successorKey,
    );
    if (
      !profile.orderIncludesLeafType &&
      value.leafType === NORMAL_LEAF_TYPE &&
      existing === undefined
    ) {
      insertOrder.run(value.key, value.physicalIndex);
    }
  };

  return freeze({
    profile: profileName,
    adapter,
    writeLeaf,
    writeNode,
    applyMutation(mutation) {
      for (const value of mutation.nullifierNodes) writeNode(value);
      for (const value of mutation.nullifierLeaves) writeLeaf(value);
      return freeze({
        nodeWrites: mutation.nullifierNodes.length,
        leafWrites: mutation.nullifierLeaves.length,
      });
    },
  });
}
