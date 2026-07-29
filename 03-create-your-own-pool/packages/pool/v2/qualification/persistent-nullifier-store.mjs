import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  lstatSync,
  openSync,
  realpathSync,
  statSync,
} from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import {
  hashIndexedNullifierLeaf,
  hashIndexedNullifierNode,
} from "../../../action/v2/poseidon.mjs";
import {
  applyPersistentIndexedNullifierMutation,
  createDepth4PersistentIndexedNullifierQualificationKernel,
  derivePersistentIndexedNullifierInsertion,
  PersistentIndexedNullifierError,
  PERSISTENT_NULLIFIER_FR_MODULUS,
  PERSISTENT_NULLIFIER_LEAF_TYPES,
  persistentNullifierDefaults,
  persistentNullifierLeafHash,
} from "../persistent-indexed-nullifier.mjs";
import {
  createPersistentNullifierSqliteAccess,
  PERSISTENT_NULLIFIER_SQLITE_PROFILES,
} from "../persistent-indexed-nullifier-sqlite.mjs";

export const Q04_STORE_SCHEMA_VERSION = 2;
export const Q04_STORE_TRANSCRIPT_DOMAIN =
  "ShieldKit/PoolActionV2Direct/Q04/persistent-transition/v1\0";
export const Q04_STORE_INITIAL_DOMAIN =
  "ShieldKit/PoolActionV2Direct/Q04/persistent-store/v1\0";

const ZERO = Buffer.alloc(32);
const MAX_U32 = 0xffff_ffff;
const DEFAULTS = persistentNullifierDefaults();
const PRODUCTION_STORE_CONFIG = Object.freeze({
  depth: 32,
  maximumPhysicalIndex: MAX_U32,
  maximumNormalCount: MAX_U32 - 1,
  defaults: DEFAULTS,
  derive: derivePersistentIndexedNullifierInsertion,
  apply: applyPersistentIndexedNullifierMutation,
});
const DEPTH4_QUALIFICATION_KERNEL =
  createDepth4PersistentIndexedNullifierQualificationKernel();
const DEPTH4_QUALIFICATION_STORE_CONFIG = Object.freeze({
  depth: DEPTH4_QUALIFICATION_KERNEL.depth,
  maximumPhysicalIndex: DEPTH4_QUALIFICATION_KERNEL.capacity - 1,
  maximumNormalCount: DEPTH4_QUALIFICATION_KERNEL.maximumNormalCount,
  defaults: DEPTH4_QUALIFICATION_KERNEL.defaults(),
  derive: DEPTH4_QUALIFICATION_KERNEL.derive,
  apply: DEPTH4_QUALIFICATION_KERNEL.apply,
});

function schemaFor(config) {
  return `
CREATE TABLE metadata (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  schema_version INTEGER NOT NULL CHECK(schema_version=${Q04_STORE_SCHEMA_VERSION}),
  tree_depth INTEGER NOT NULL CHECK(tree_depth=${config.depth}),
  history_index INTEGER NOT NULL CHECK(history_index BETWEEN 0 AND 3),
  seed BLOB NOT NULL CHECK(length(seed)=32),
  normal_count INTEGER NOT NULL CHECK(normal_count BETWEEN 0 AND ${config.maximumNormalCount}),
  root BLOB NOT NULL CHECK(length(root)=32),
  transcript_chain_sha256 BLOB NOT NULL CHECK(length(transcript_chain_sha256)=32)
) STRICT;
CREATE TABLE nodes (
  depth INTEGER NOT NULL CHECK(depth BETWEEN 0 AND ${config.depth}),
  node_index INTEGER NOT NULL CHECK(
    node_index>=0 AND node_index<(1 << (${config.depth}-depth))
  ),
  node_hash BLOB NOT NULL CHECK(length(node_hash)=32),
  PRIMARY KEY(depth,node_index)
) STRICT;
CREATE TABLE leaves (
  physical_index INTEGER PRIMARY KEY CHECK(
    physical_index BETWEEN 0 AND ${config.maximumPhysicalIndex}
  ),
  leaf_type INTEGER NOT NULL CHECK(leaf_type IN(1,2,3)),
  leaf_hash BLOB NOT NULL CHECK(length(leaf_hash)=32),
  key_be BLOB NOT NULL CHECK(length(key_be)=32),
  successor_index INTEGER NOT NULL CHECK(
    successor_index BETWEEN 0 AND ${config.maximumPhysicalIndex}
  ),
  successor_key_be BLOB NOT NULL CHECK(length(successor_key_be)=32)
) STRICT;
CREATE TABLE normal_order (
  key_be BLOB PRIMARY KEY CHECK(length(key_be)=32),
  physical_index INTEGER NOT NULL UNIQUE CHECK(
    physical_index BETWEEN 2 AND ${config.maximumPhysicalIndex}
  ),
  FOREIGN KEY(physical_index) REFERENCES leaves(physical_index)
) STRICT, WITHOUT ROWID;
`;
}

export class Q04PersistentStoreError extends Error {
  constructor(message) {
    super(message);
    this.name = "Q04PersistentStoreError";
  }
}

const fail = (message) => {
  throw new Q04PersistentStoreError(message);
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
const integer = (value, low, high, label) => {
  if (!Number.isSafeInteger(value) || value < low || value > high) {
    fail(`${label} must be an integer from ${low} through ${high}`);
  }
  return value;
};
const bytes32 = (value, label, { field = false } = {}) => {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    fail(`${label} must contain exactly 32 bytes`);
  }
  const copy = Buffer.from(value);
  if (
    field &&
    BigInt(`0x${copy.toString("hex")}`) >=
      PERSISTENT_NULLIFIER_FR_MODULUS
  ) fail(`${label} must be a canonical BN254 Fr`);
  return copy;
};
const fr = (value) =>
  BigInt(`0x${bytes32(value, "field bytes", { field: true }).toString("hex")}`);
const encodedFr = (value) =>
  Buffer.from(value.toString(16).padStart(64, "0"), "hex");
const u32be = (value) => {
  const output = Buffer.alloc(4);
  output.writeUInt32BE(value);
  return output;
};

function ensurePrivateParent(path) {
  if (typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path) {
    fail("Q-04 database path must be absolute and normalized");
  }
  const parent = dirname(path);
  const observed = lstatSync(parent);
  if (
    !observed.isDirectory() ||
    observed.isSymbolicLink() ||
    realpathSync(parent) !== parent ||
    (observed.mode & 0o777) !== 0o700 ||
    (
      typeof process.getuid === "function" &&
      observed.uid !== process.getuid()
    )
  ) {
    fail("Q-04 database parent must be a direct user-owned mode-0700 directory");
  }
  return path;
}

function assertPrivateFile(path) {
  const observed = lstatSync(path);
  if (
    !observed.isFile() ||
    observed.isSymbolicLink() ||
    realpathSync(path) !== path ||
    observed.nlink !== 1 ||
    (observed.mode & 0o777) !== 0o600 ||
    (
      typeof process.getuid === "function" &&
      observed.uid !== process.getuid()
    )
  ) fail("Q-04 database must be a direct single-link user-owned mode-0600 file");
}

function assertSidecars(path, { absent }) {
  for (const candidate of [`${path}-wal`, `${path}-shm`]) {
    try {
      lstatSync(candidate);
      if (absent) {
        fail("new Q-04 database must not have pre-existing SQLite sidecars");
      }
      assertPrivateFile(candidate);
    } catch (error) {
      if (error && error.code === "ENOENT") continue;
      throw error;
    }
  }
}

function secureFiles(path) {
  for (const candidate of [path, `${path}-wal`, `${path}-shm`]) {
    try {
      const observed = lstatSync(candidate);
      if (
        !observed.isFile() ||
        observed.isSymbolicLink() ||
        realpathSync(candidate) !== candidate ||
        observed.nlink !== 1 ||
        (
          typeof process.getuid === "function" &&
          observed.uid !== process.getuid()
        )
      ) {
        fail(
          "Q-04 SQLite file or sidecar must be a direct single-link " +
            "user-owned regular file",
        );
      }
      chmodSync(candidate, 0o600);
      if ((lstatSync(candidate).mode & 0o777) !== 0o600) {
        fail("Q-04 SQLite file or sidecar mode differs from 0600");
      }
    } catch (error) {
      if (!(error && error.code === "ENOENT")) throw error;
    }
  }
}

function createPrivateFile(path) {
  const noFollow = constants.O_NOFOLLOW ?? 0;
  const descriptor = openSync(
    path,
    constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | noFollow,
    0o600,
  );
  closeSync(descriptor);
  assertPrivateFile(path);
}

function rawLeafHash({
  physicalIndex,
  leafType,
  key,
  successorIndex,
  successorKey,
}) {
  return encodedFr(hashIndexedNullifierLeaf([
    BigInt(leafType),
    BigInt(physicalIndex),
    fr(key),
    BigInt(successorIndex),
    fr(successorKey),
  ]));
}

function parentHash(left, right) {
  return encodedFr(hashIndexedNullifierNode(fr(left), fr(right)));
}

function initialTranscript(historyIndex, seed) {
  return createHash("sha256")
    .update(Q04_STORE_INITIAL_DOMAIN, "ascii")
    .update(u32be(historyIndex))
    .update(seed)
    .digest();
}

function transitionDigest({
  count,
  key,
  mutation,
}) {
  const hash = createHash("sha256")
    .update(Q04_STORE_TRANSCRIPT_DOMAIN, "ascii")
    .update(u32be(count))
    .update(key)
    .update(encodedFr(mutation.witness.preRoot))
    .update(encodedFr(mutation.witness.intermediateRoot))
    .update(encodedFr(mutation.witness.postRoot))
    .update(u32be(mutation.witness.predecessor.index))
    .update(Buffer.from(mutation.witness.predecessor.key, "hex"))
    .update(u32be(mutation.witness.predecessor.successorIndex))
    .update(Buffer.from(mutation.witness.predecessor.successorKey, "hex"))
    .update(u32be(mutation.witness.append.index));
  for (const value of mutation.witness.predecessorPath) {
    hash.update(encodedFr(value));
  }
  for (const value of mutation.witness.append.path) {
    hash.update(encodedFr(value));
  }
  return hash.digest();
}

function logicalDigest({ metadata, leaves, nodes, order }) {
  const hash = createHash("sha256")
    .update("ShieldKit/PoolActionV2Direct/Q04/logical-store/v1\0", "ascii")
    .update(u32be(metadata.tree_depth))
    .update(u32be(metadata.history_index))
    .update(metadata.seed)
    .update(u32be(metadata.normal_count))
    .update(metadata.root)
    .update(metadata.transcript_chain_sha256);
  for (const row of leaves) {
    hash.update(u32be(row.physical_index))
      .update(Buffer.from([row.leaf_type]))
      .update(row.leaf_hash)
      .update(row.key_be)
      .update(u32be(row.successor_index))
      .update(row.successor_key_be);
  }
  for (const row of nodes) {
    hash.update(Buffer.from([row.depth]))
      .update(u32be(row.node_index))
      .update(row.node_hash);
  }
  for (const row of order) {
    hash.update(row.key_be).update(u32be(row.physical_index));
  }
  return hash.digest("hex");
}

class PersistentNullifierStore {
  #access;
  #db;
  #path;
  #statements;
  #config;

  constructor(config, { path, create, historyIndex, seed }) {
    this.#config = config;
    const databasePath = ensurePrivateParent(path);
    const shouldCreate = create === true;
    if (create !== true && create !== false) {
      fail("Q-04 store create must be exactly true or false");
    }
    const boundHistory = integer(historyIndex, 0, 3, "Q-04 historyIndex");
    const boundSeed = bytes32(seed, "Q-04 seed");
    if (shouldCreate) {
      assertSidecars(databasePath, { absent: true });
      createPrivateFile(databasePath);
    } else {
      assertPrivateFile(databasePath);
      assertSidecars(databasePath, { absent: false });
    }
    this.#path = databasePath;
    this.#db = new DatabaseSync(databasePath);
    try {
      this.#db.exec(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; " +
          "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; " +
          "PRAGMA temp_store=FILE; PRAGMA cache_size=-8192;",
      );
      if (shouldCreate) {
        const existing = this.#db.prepare(
          "SELECT COUNT(*) AS count FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'",
        ).get().count;
        if (existing !== 0) fail("new Q-04 store is not empty");
        this.#db.exec(schemaFor(this.#config));
        this.#db.exec(`PRAGMA user_version=${Q04_STORE_SCHEMA_VERSION}`);
      } else {
        if (
          this.#db.prepare("PRAGMA user_version").get().user_version !==
            Q04_STORE_SCHEMA_VERSION
        ) fail("Q-04 store schema version differs");
        const tables = this.#db.prepare(
          "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        ).all().map(({ name }) => name);
        if (tables.join(",") !== "leaves,metadata,nodes,normal_order") {
          fail("Q-04 store schema tables differ");
        }
      }
      this.#prepare();
      if (shouldCreate) this.#initialize(boundHistory, boundSeed);
      const metadata = this.#statements.metadata.get();
      if (
        metadata === undefined ||
        metadata.schema_version !== Q04_STORE_SCHEMA_VERSION ||
        metadata.tree_depth !== this.#config.depth ||
        metadata.history_index !== boundHistory ||
        !same(metadata.seed, boundSeed)
      ) fail("Q-04 store binding differs");
      secureFiles(this.#path);
    } catch (error) {
      try {
        this.#db.close();
      } catch {}
      this.#db = null;
      secureFiles(this.#path);
      throw error;
    }
  }

  #prepare() {
    const db = this.#db;
    this.#statements = {
      metadata: db.prepare("SELECT * FROM metadata WHERE singleton=1"),
      updateMetadata: db.prepare(
        "UPDATE metadata SET normal_count=?,root=?,transcript_chain_sha256=? WHERE singleton=1",
      ),
    };
    this.#access = createPersistentNullifierSqliteAccess({
      db,
      defaults: this.#config.defaults,
      profile: PERSISTENT_NULLIFIER_SQLITE_PROFILES.qualification,
      raise: fail,
    });
  }

  #tx(fn) {
    if (!this.#db) fail("Q-04 store is closed");
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      const result = fn();
      this.#db.exec("COMMIT");
      secureFiles(this.#path);
      return result;
    } catch (error) {
      try {
        this.#db.exec("ROLLBACK");
      } catch {}
      secureFiles(this.#path);
      throw error;
    }
  }

  #writeNode({ depth, nodeIndex, nodeHash }) {
    integer(depth, 0, this.#config.depth, "Q-04 node depth");
    integer(
      nodeIndex,
      0,
      (2 ** (this.#config.depth - depth)) - 1,
      "Q-04 node index",
    );
    const value = bytes32(nodeHash, "Q-04 nodeHash", { field: true });
    this.#access.writeNode({ depth, nodeIndex, nodeHash: value });
  }

  #writeLeaf(leaf) {
    this.#access.writeLeaf(leaf);
  }

  #replaceGenesisLeaf(leaf) {
    this.#writeLeaf(leaf);
    let cursor = leaf.physicalIndex;
    let node = leaf.leafHash;
    this.#writeNode({ depth: 0, nodeIndex: cursor, nodeHash: node });
    for (let depth = 0; depth < this.#config.depth; depth += 1) {
      const sibling = this.#access.adapter.readNode(depth, cursor ^ 1) ??
        this.#config.defaults[depth];
      node = (cursor & 1) === 0
        ? parentHash(node, sibling)
        : parentHash(sibling, node);
      cursor = Math.floor(cursor / 2);
      this.#writeNode({ depth: depth + 1, nodeIndex: cursor, nodeHash: node });
    }
    return node;
  }

  #initialize(historyIndex, seed) {
    this.#tx(() => {
      const sentinels = [
        {
          physicalIndex: 0,
          leafType: PERSISTENT_NULLIFIER_LEAF_TYPES.minimum,
          key: ZERO,
          successorIndex: 1,
          successorKey: ZERO,
        },
        {
          physicalIndex: 1,
          leafType: PERSISTENT_NULLIFIER_LEAF_TYPES.maximum,
          key: ZERO,
          successorIndex: 1,
          successorKey: ZERO,
        },
      ].map((leaf) => ({
        ...leaf,
        leafHash: persistentNullifierLeafHash(leaf),
      }));
      this.#replaceGenesisLeaf(sentinels[0]);
      const root = this.#replaceGenesisLeaf(sentinels[1]);
      this.#db.prepare(
        "INSERT INTO metadata(singleton,schema_version,tree_depth,history_index,seed,normal_count,root,transcript_chain_sha256) VALUES(1,?,?,?,?,?,?,?)",
      ).run(
        Q04_STORE_SCHEMA_VERSION,
        this.#config.depth,
        historyIndex,
        seed,
        0,
        root,
        initialTranscript(historyIndex, seed),
      );
    });
  }

  get path() {
    return this.#path;
  }

  state() {
    if (!this.#db) fail("Q-04 store is closed");
    const row = this.#statements.metadata.get();
    return freeze({
      historyIndex: row.history_index,
      seed: Buffer.from(row.seed),
      normalCount: row.normal_count,
      root: Buffer.from(row.root),
      transcriptChainSha256: Buffer.from(row.transcript_chain_sha256),
    });
  }

  deriveInsertion(value) {
    const input = exactKeys(value, [
      "expectedCount",
      "expectedRoot",
      "key",
    ], "Q-04 persistent insertion derivation");
    const expectedCount = integer(
      input.expectedCount,
      0,
      this.#config.maximumNormalCount,
      "Q-04 expectedCount",
    );
    const expectedRoot = bytes32(
      input.expectedRoot,
      "Q-04 expectedRoot",
      { field: true },
    );
    const publicNullifier = bytes32(
      input.key,
      "Q-04 public nullifier",
      { field: true },
    );
    return this.#tx(() => {
      const metadata = this.#statements.metadata.get();
      if (
        metadata.normal_count !== expectedCount ||
        !same(metadata.root, expectedRoot)
      ) fail("Q-04 insertion derivation expected state is stale");
      try {
        return this.#config.derive({
          expectedPreRoot: metadata.root,
          key: publicNullifier,
          normalCount: metadata.normal_count,
          adapter: this.#access.adapter,
        });
      } catch (error) {
        if (error instanceof PersistentIndexedNullifierError) {
          fail(error.message);
        }
        throw error;
      }
    });
  }

  insert(value) {
    const input = exactKeys(value, [
      "expectedCount",
      "expectedRoot",
      "key",
    ], "Q-04 persistent insertion");
    const expectedCount = integer(
      input.expectedCount,
      0,
      this.#config.maximumNormalCount,
      "Q-04 expectedCount",
    );
    const expectedRoot = bytes32(
      input.expectedRoot,
      "Q-04 expectedRoot",
      { field: true },
    );
    const publicNullifier = bytes32(
      input.key,
      "Q-04 public nullifier",
      { field: true },
    );
    return this.#tx(() => {
      const metadata = this.#statements.metadata.get();
      if (
        metadata.normal_count !== expectedCount ||
        !same(metadata.root, expectedRoot)
      ) fail("Q-04 insertion expected state is stale");
      let mutation;
      try {
        mutation = this.#config.derive({
          expectedPreRoot: metadata.root,
          key: publicNullifier,
          normalCount: metadata.normal_count,
          adapter: this.#access.adapter,
        });
      } catch (error) {
        if (error instanceof PersistentIndexedNullifierError) {
          fail(error.message);
        }
        throw error;
      }
      const writes = this.#config.apply({
        mutation,
        writeNode: this.#access.writeNode,
        writeLeaf: this.#access.writeLeaf,
      });
      const ordinal = metadata.normal_count + 1;
      const digest = transitionDigest({
        count: ordinal,
        key: publicNullifier,
        mutation,
      });
      const chain = createHash("sha256")
        .update(metadata.transcript_chain_sha256)
        .update(digest)
        .digest();
      const updated = this.#statements.updateMetadata.run(
        ordinal,
        mutation.root,
        chain,
      );
      if (updated.changes !== 1) fail("Q-04 metadata update failed");
      return freeze({
        mutation,
        writes,
        transitionDigestSha256: digest.toString("hex"),
        transcriptChainSha256: chain.toString("hex"),
      });
    });
  }

  leaf(physicalIndex) {
    if (!this.#db) fail("Q-04 store is closed");
    integer(
      physicalIndex,
      0,
      this.#config.maximumPhysicalIndex,
      "Q-04 physicalIndex",
    );
    const leaf = this.#access.adapter.readLeaf(physicalIndex);
    return leaf === null
      ? null
      : freeze({
        physicalIndex: leaf.physicalIndex,
        leafType: leaf.leafType,
        leafHash: Buffer.from(leaf.leafHash),
        key: Buffer.from(leaf.key),
        successorIndex: leaf.successorIndex,
        successorKey: Buffer.from(leaf.successorKey),
      });
  }

  membershipPath(physicalIndex) {
    if (!this.#db) fail("Q-04 store is closed");
    integer(
      physicalIndex,
      0,
      this.#config.maximumPhysicalIndex,
      "Q-04 membership physicalIndex",
    );
    const metadata = this.#statements.metadata.get();
    if (physicalIndex >= metadata.normal_count + 2) {
      fail("Q-04 membership physicalIndex is not allocated");
    }
    const leaf = this.#access.adapter.readLeaf(physicalIndex);
    if (leaf === null) fail("Q-04 membership leaf is absent");
    let cursor = physicalIndex;
    let node = Buffer.from(leaf.leafHash);
    const siblings = [];
    for (let depth = 0; depth < this.#config.depth; depth += 1) {
      const sibling = this.#access.adapter.readNode(
        depth,
        cursor ^ 1,
      ) ?? this.#config.defaults[depth];
      siblings.push(fr(sibling));
      node = (cursor & 1) === 0
        ? parentHash(node, sibling)
        : parentHash(sibling, node);
      cursor = Math.floor(cursor / 2);
    }
    if (!same(node, metadata.root)) {
      fail("Q-04 membership path does not prove the persistent root");
    }
    return freeze({
      physicalIndex,
      leafHash: Buffer.from(leaf.leafHash),
      root: Buffer.from(node),
      siblings: freeze(siblings),
      metrics: freeze({
        nodeHashCalls: this.#config.depth,
        nodeReads: this.#config.depth,
        treeDepth: this.#config.depth,
      }),
    });
  }

  audit() {
    if (!this.#db) fail("Q-04 store is closed");
    const integrity = this.#db.prepare("PRAGMA integrity_check").get()
      .integrity_check;
    const foreign = this.#db.prepare("PRAGMA foreign_key_check").all();
    if (integrity !== "ok" || foreign.length !== 0) {
      fail("Q-04 SQLite integrity or foreign-key check failed");
    }
    const metadata = this.#statements.metadata.get();
    const leaves = this.#db.prepare(
      "SELECT * FROM leaves ORDER BY physical_index",
    ).all();
    const nodes = this.#db.prepare(
      "SELECT * FROM nodes ORDER BY depth,node_index",
    ).all();
    const order = this.#db.prepare(
      "SELECT * FROM normal_order ORDER BY key_be",
    ).all();
    if (
      leaves.length !== metadata.normal_count + 2 ||
      order.length !== metadata.normal_count
    ) fail("Q-04 allocated leaf/order counts differ");
    const byIndex = new Map();
    for (let index = 0; index < leaves.length; index += 1) {
      const row = leaves[index];
      if (row.physical_index !== index) {
        fail("Q-04 physical leaves are not an allocated prefix");
      }
      const expected = rawLeafHash({
        physicalIndex: row.physical_index,
        leafType: row.leaf_type,
        key: row.key_be,
        successorIndex: row.successor_index,
        successorKey: row.successor_key_be,
      });
      if (!same(expected, row.leaf_hash)) {
        fail("Q-04 leaf hash differs from stored semantic fields");
      }
      if (
        row.leaf_type === PERSISTENT_NULLIFIER_LEAF_TYPES.minimum &&
        (
          row.physical_index !== 0 ||
          !same(row.key_be, ZERO) ||
          row.successor_index === 0
        )
      ) fail("Q-04 minimum sentinel is malformed");
      if (
        row.leaf_type === PERSISTENT_NULLIFIER_LEAF_TYPES.maximum &&
        (
          row.physical_index !== 1 ||
          !same(row.key_be, ZERO) ||
          row.successor_index !== 1 ||
          !same(row.successor_key_be, ZERO)
        )
      ) fail("Q-04 maximum sentinel is malformed");
      if (
        row.leaf_type === PERSISTENT_NULLIFIER_LEAF_TYPES.normal &&
        (
          row.physical_index < 2 ||
          row.successor_index === 0 ||
          row.successor_index === row.physical_index ||
          (
            row.successor_index >= 2 &&
            fr(row.successor_key_be) <= fr(row.key_be)
          )
        )
      ) fail("Q-04 normal leaf ordering is malformed");
      byIndex.set(row.physical_index, row);
    }
    let cursor = byIndex.get(0);
    const visited = new Set();
    while (cursor.leaf_type !== PERSISTENT_NULLIFIER_LEAF_TYPES.maximum) {
      if (visited.has(cursor.physical_index)) {
        fail("Q-04 successor topology contains a cycle");
      }
      visited.add(cursor.physical_index);
      const successor = byIndex.get(cursor.successor_index);
      if (
        successor === undefined ||
        !same(cursor.successor_key_be, successor.key_be)
      ) fail("Q-04 successor pointer/key does not resolve");
      cursor = successor;
    }
    if (visited.size !== metadata.normal_count + 1) {
      fail("Q-04 successor topology does not cover every allocated leaf");
    }
    for (let index = 0; index < order.length; index += 1) {
      const row = order[index];
      const leaf = byIndex.get(row.physical_index);
      if (
        leaf === undefined ||
        leaf.leaf_type !== PERSISTENT_NULLIFIER_LEAF_TYPES.normal ||
        !same(leaf.key_be, row.key_be) ||
        (index > 0 && Buffer.compare(order[index - 1].key_be, row.key_be) >= 0)
      ) fail("Q-04 big-endian order index differs from normal leaves");
    }

    const expectedNodes = new Map();
    let layer = new Map(
      leaves.map((leaf) => [leaf.physical_index, Buffer.from(leaf.leaf_hash)]),
    );
    for (let depth = 0; depth <= this.#config.depth; depth += 1) {
      for (const [nodeIndex, nodeHash] of layer) {
        if (!same(nodeHash, this.#config.defaults[depth])) {
          expectedNodes.set(`${depth}:${nodeIndex}`, nodeHash);
        }
      }
      if (depth === this.#config.depth) break;
      const parents = new Set(
        [...layer.keys()].map((nodeIndex) => Math.floor(nodeIndex / 2)),
      );
      const next = new Map();
      for (const parent of parents) {
        const value = parentHash(
          layer.get(parent * 2) ?? this.#config.defaults[depth],
          layer.get((parent * 2) + 1) ?? this.#config.defaults[depth],
        );
        if (!same(value, this.#config.defaults[depth + 1])) next.set(parent, value);
      }
      layer = next;
    }
    if (nodes.length !== expectedNodes.size) {
      fail("Q-04 stored authenticated node cardinality differs");
    }
    for (const row of nodes) {
      const expected = expectedNodes.get(`${row.depth}:${row.node_index}`);
      if (expected === undefined || !same(expected, row.node_hash)) {
        fail("Q-04 stored authenticated node differs from rebuilt tree");
      }
    }
    const rebuiltRoot = expectedNodes.get(`${this.#config.depth}:0`) ??
      this.#config.defaults[this.#config.depth];
    if (!same(rebuiltRoot, metadata.root)) {
      fail("Q-04 rebuilt root differs from metadata");
    }
    return freeze({
      historyIndex: metadata.history_index,
      normalCount: metadata.normal_count,
      root: Buffer.from(metadata.root),
      transcriptChainSha256:
        Buffer.from(metadata.transcript_chain_sha256),
      leafCount: leaves.length,
      nodeCount: nodes.length,
      orderCount: order.length,
      logicalDigestSha256: logicalDigest({
        metadata,
        leaves,
        nodes,
        order,
      }),
      integrityCheck: integrity,
      foreignKeyViolations: foreign.length,
    });
  }

  corruptionProbe(kind) {
    if (!["ordering", "successor-pointer"].includes(kind)) {
      fail("Q-04 corruption probe kind is unsupported");
    }
    const before = this.audit();
    this.#db.exec("SAVEPOINT q04_corruption_probe");
    let rejected = false;
    let message = null;
    try {
      if (kind === "ordering") {
        const row = this.#db.prepare(
          "SELECT * FROM leaves WHERE leaf_type=2 AND successor_index>=2 ORDER BY physical_index LIMIT 1",
        ).get();
        if (row === undefined) fail("Q-04 ordering probe has no eligible leaf");
        const malformed = {
          physicalIndex: row.physical_index,
          leafType: row.leaf_type,
          key: row.key_be,
          successorIndex: row.successor_index,
          successorKey: row.key_be,
        };
        this.#db.prepare(
          "UPDATE leaves SET leaf_hash=?,successor_key_be=? WHERE physical_index=?",
        ).run(
          rawLeafHash(malformed),
          malformed.successorKey,
          malformed.physicalIndex,
        );
      } else {
        const replacement = {
          physicalIndex: 0,
          leafType: PERSISTENT_NULLIFIER_LEAF_TYPES.minimum,
          key: ZERO,
          successorIndex: 1,
          successorKey: ZERO,
        };
        this.#db.prepare(
          "UPDATE leaves SET leaf_hash=?,successor_index=1,successor_key_be=? WHERE physical_index=0",
        ).run(persistentNullifierLeafHash(replacement), ZERO);
      }
      try {
        this.audit();
      } catch (error) {
        rejected = true;
        message = error instanceof Error ? error.message : String(error);
      }
    } finally {
      this.#db.exec("ROLLBACK TO q04_corruption_probe");
      this.#db.exec("RELEASE q04_corruption_probe");
    }
    if (!rejected) fail(`Q-04 ${kind} corruption was unexpectedly accepted`);
    const after = this.audit();
    if (after.logicalDigestSha256 !== before.logicalDigestSha256) {
      fail(`Q-04 ${kind} corruption probe changed durable state`);
    }
    return freeze({
      kind,
      rejected,
      rejection: message,
      unchangedLogicalDigestSha256: after.logicalDigestSha256,
    });
  }

  storageMetrics() {
    if (!this.#db) fail("Q-04 store is closed");
    const fileBytes = {};
    for (const [name, path] of [
      ["database", this.#path],
      ["wal", `${this.#path}-wal`],
      ["shm", `${this.#path}-shm`],
    ]) {
      try {
        fileBytes[name] = statSync(path).size;
      } catch (error) {
        if (error && error.code === "ENOENT") fileBytes[name] = 0;
        else throw error;
      }
    }
    return freeze({
      fileBytes: freeze(fileBytes),
      totalFileBytes: Object.values(fileBytes).reduce(
        (sum, value) => sum + value,
        0,
      ),
      pageCount: this.#db.prepare("PRAGMA page_count").get().page_count,
      pageSize: this.#db.prepare("PRAGMA page_size").get().page_size,
      freeListCount:
        this.#db.prepare("PRAGMA freelist_count").get().freelist_count,
      journalMode:
        this.#db.prepare("PRAGMA journal_mode").get().journal_mode,
      synchronous:
        this.#db.prepare("PRAGMA synchronous").get().synchronous,
    });
  }

  close() {
    if (this.#db) {
      secureFiles(this.#path);
      this.#db.close();
      this.#db = null;
      secureFiles(this.#path);
    }
  }
}

export class Q04PersistentNullifierStore extends PersistentNullifierStore {
  constructor(value) {
    super(
      PRODUCTION_STORE_CONFIG,
      exactKeys(value, [
        "create",
        "historyIndex",
        "path",
        "seed",
      ], "Q-04 persistent nullifier store"),
    );
  }
}

/**
 * Qualification-only fixed-depth store. This deliberately exposes no depth
 * parameter: ordinary Q-04 remains pinned to the production depth of 32.
 */
export class Q04Depth4PersistentNullifierQualificationStore extends
  PersistentNullifierStore {
  constructor(value) {
    super(
      DEPTH4_QUALIFICATION_STORE_CONFIG,
      exactKeys(value, [
        "create",
        "historyIndex",
        "path",
        "seed",
      ], "open depth-4 Q-04 persistent nullifier qualification store"),
    );
  }
}

export function openQ04PersistentNullifierStore(value) {
  return new Q04PersistentNullifierStore(value);
}

export function openDepth4PersistentNullifierQualificationStore(value) {
  return new Q04Depth4PersistentNullifierQualificationStore(value);
}
