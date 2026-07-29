/**
 * V2 Direct local SQLite durability foundation. It is intentionally not a
 * covenant, scanner, network gate, or production-qualification result.
 *
 * Reopen-by-path boundary: Node exposes filesystem paths, not directory FDs.
 * We reject symlink ancestry and re-check terminal files before every open, but
 * cannot make a later hostile path replacement impossible after this process
 * closes its database descriptor. Deployments must keep the 0700 parent owned
 * by the wallet user; reopening re-runs every available path check.
 */
import { DatabaseSync } from "node:sqlite";
import { createHash, ECDH } from "node:crypto";
import { chmodSync, closeSync, lstatSync, mkdirSync, openSync } from "node:fs";
import { dirname, isAbsolute, join, parse, relative, resolve } from "node:path";
import { deserialize, serialize } from "node:v8";

import {
  decodeDirectV2Address,
} from "../../action/v2/address.mjs";
import {
  actionPacketPublicLimbs,
  decodeActionPacket,
  digestActionPacket,
  encodeActionPacket,
} from "../../action/v2/packet.mjs";
import {
  decodeStateNftCommitment,
  encodeStateNftCommitment,
} from "../../action/v2/state.mjs";
import {
  createDirectV2PoolModel,
} from "../../action/v2/transition.mjs";
import {
  isSupportedDirectV2NetworkId,
} from "../../action/v2/network.mjs";
import {
  DIRECT_V2_PERSISTENT_PROVING_TRANSITION_SCHEMA,
} from "../../action/v2/proving-transition.mjs";
import {
  hashEmptyNoteLeaf,
  hashIndexedNullifierLeaf,
  hashIndexedNullifierNode,
  hashNoteTreeNode,
} from "../../action/v2/poseidon.mjs";
import {
  assertV2StandardTransactionEnvelope,
  parseSerializedSourceOutput,
  parseV2RawTransaction,
  V2_MAX_TRANSACTION_BYTES,
} from "../../kit/v2/transaction-policy.mjs";
import {
  derivePersistentIndexedNullifierInsertion,
  PERSISTENT_NULLIFIER_LEAF_TYPES,
  PersistentIndexedNullifierError,
} from "./persistent-indexed-nullifier.mjs";
import {
  createPersistentNullifierSqliteAccess,
  PERSISTENT_NULLIFIER_SQLITE_PROFILES,
} from "./persistent-indexed-nullifier-sqlite.mjs";

export const V2_STORE_SCHEMA_VERSION = 12;
export const V2_PROVING_TRANSITION_SCHEMA =
  DIRECT_V2_PERSISTENT_PROVING_TRANSITION_SCHEMA;
export const V2_STORE_UNDO_BLOCKS = 100;
export const V2_OPERATION_CREATE_CRASH_STAGES = Object.freeze([
  "operation.after_pending",
  "operation.after_intent",
  "operation.before_commit",
]);
export const V2_OPERATION_PREPARE_CRASH_STAGES = Object.freeze([
  "prepare.after_pending",
  "prepare.after_intent",
  "prepare.after_note",
  "prepare.after_utxo",
  "prepare.before_commit",
]);
export const V2_OPERATION_REBASE_CRASH_STAGES = Object.freeze([
  "rebase.after_artifacts",
  "rebase.before_commit",
]);
export const V2_OPERATION_ABANDON_CRASH_STAGES = Object.freeze([
  "abandon.after_reservations",
  "abandon.after_overlay",
  "abandon.before_commit",
]);
export const V2_OPERATION_CONFLICT_CRASH_STAGES = Object.freeze([
  "conflict.after_counter",
  "conflict.after_resources",
  "conflict.before_commit",
]);
export const V2_OPERATION_MANUAL_RETRY_CRASH_STAGES = Object.freeze([
  "manual_retry.after_counter",
  "manual_retry.after_resources",
  "manual_retry.before_commit",
]);
export const V2_OPERATION_SETTLE_CRASH_STAGES = Object.freeze([
  "settle.before_commit",
]);
export const V2_OPERATION_MAX_AUTOMATIC_CONFLICTS = 3;
export const V2_OPERATION_STATES = Object.freeze([
  "draft",
  "funding_selected",
  "tip_synced",
  "proving",
  "proved",
  "needs_reproof",
  "signed",
  "broadcast",
  "mempool",
  "confirmed",
  "settled",
  "conflicted",
  "reorged",
  "abandoned",
]);
export const V2_ACTION_KINDS = Object.freeze([
  "deposit",
  "transfer",
  "withdrawal",
]);
export const V2_NULLIFIER_LEAF_TYPES = PERSISTENT_NULLIFIER_LEAF_TYPES;
export const V2_AUTHENTICATED_SNAPSHOT_CRASH_STAGES = Object.freeze([
  "snapshot.before_mutation",
  "snapshot.during_note_nodes",
  "snapshot.during_note_frontier",
  "snapshot.during_note_leaves",
  "snapshot.during_nullifier_nodes",
  "snapshot.during_nullifier_order",
  "snapshot.during_nullifier_leaves",
  "snapshot.before_canonical_state",
  "snapshot.before_commit",
]);
export const V2_AUTHENTICATED_STREAM_CRASH_STAGES = Object.freeze([
  "stream.after_header",
  "stream.during_actions",
  "stream.during_note_nodes",
  "stream.during_note_frontier",
  "stream.during_note_leaves",
  "stream.during_nullifier_nodes",
  "stream.during_nullifier_leaves",
  "stream.after_end",
  "stream.before_live_mutation",
  "stream.during_live_copy",
  "stream.before_canonical_state",
  "stream.before_commit",
]);

const TRANSITIONS = Object.freeze({
  draft: new Set(["funding_selected", "abandoned"]),
  funding_selected: new Set([
    "tip_synced",
    "needs_reproof",
    "conflicted",
    "abandoned",
  ]),
  tip_synced: new Set(["proving", "needs_reproof", "conflicted", "abandoned"]),
  proving: new Set(["proved", "needs_reproof", "conflicted", "abandoned"]),
  proved: new Set(["signed", "needs_reproof", "conflicted", "abandoned"]),
  needs_reproof: new Set(["tip_synced", "conflicted", "abandoned"]),
  signed: new Set(["broadcast", "needs_reproof", "conflicted"]),
  broadcast: new Set(["mempool", "confirmed", "conflicted", "reorged"]),
  mempool: new Set(["confirmed", "conflicted", "reorged"]),
  confirmed: new Set(["settled", "reorged"]),
  settled: new Set(["reorged"]),
  conflicted: new Set(["needs_reproof", "abandoned"]),
  reorged: new Set(["tip_synced", "needs_reproof", "conflicted", "abandoned"]),
  abandoned: new Set(),
});
const MAX_U32 = 0xffff_ffff;
const MAX_MONEY_SATS = 2_100_000_000_000_000n;
const P2PKH_DUST_SATS = 546n;
const SIGHASH_ALL_UTXOS_FORKID = 0x61;
const BN254_FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const TREE_DEPTH = 32;

function frBuffer(value, label) {
  const result = bytes(value, 32, label);
  if (BigInt(`0x${result.toString("hex")}`) >= BN254_FR_MODULUS) {
    fail(`${label} must be a canonical BN254 Fr`);
  }
  return result;
}
function frBigInt(value, label) {
  return BigInt(`0x${frBuffer(value, label).toString("hex")}`);
}
function encodedFr(value) {
  return Buffer.from(value.toString(16).padStart(64, "0"), "hex");
}
function treeDefaults(emptyLeaf, nodeHasher) {
  const values = [encodedFr(emptyLeaf)];
  for (let depth = 0; depth < TREE_DEPTH; depth += 1) {
    values.push(encodedFr(nodeHasher(
      frBigInt(values[depth], "tree default"),
      frBigInt(values[depth], "tree default"),
    )));
  }
  return Object.freeze(values);
}
const NOTE_DEFAULTS = treeDefaults(hashEmptyNoteLeaf(), hashNoteTreeNode);
const NULLIFIER_DEFAULTS = treeDefaults(
  hashIndexedNullifierLeaf([0n, 0n, 0n, 0n, 0n]),
  hashIndexedNullifierNode,
);

export class V2StoreError extends Error {
  constructor(message) {
    super(message);
    this.name = "V2StoreError";
  }
}
export class V2StoreCrashInjection extends Error {
  constructor(stage) {
    super(`injected store crash at ${stage}`);
    this.name = "V2StoreCrashInjection";
  }
}
const fail = (message) => {
  throw new V2StoreError(message);
};
const productionNullifierSqliteAccess = (db) =>
  createPersistentNullifierSqliteAccess({
    db,
    profile: PERSISTENT_NULLIFIER_SQLITE_PROFILES.production,
    raise: fail,
  });
const object = (value) =>
  value !== null && !Array.isArray(value) && typeof value === "object";
function exactKeys(value, expected, label) {
  if (!object(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) fail(`${label} has missing or unknown properties`);
  return value;
}
function bytes(value, length, label) {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    fail(`${label} must contain exactly ${length} bytes`);
  }
  return Buffer.from(value);
}
function variableBytes(value, label) {
  if (!(value instanceof Uint8Array)) fail(`${label} must be a Uint8Array`);
  return Buffer.from(value);
}
function boundedBytes(value, minimum, maximum, label) {
  const result = variableBytes(value, label);
  if (result.length < minimum || result.length > maximum) {
    fail(`${label} must contain from ${minimum} through ${maximum} bytes`);
  }
  return result;
}
function nullableBytes(value, length, label) {
  return value === null ? null : bytes(value, length, label);
}
function nullableVariableBytes(value, label) {
  return value === null ? null : variableBytes(value, label);
}
function integer(value, low, high, label) {
  if (!Number.isSafeInteger(value) || value < low || value > high) {
    fail(`${label} is outside its integer range`);
  }
  return value;
}
function requiredText(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${label} must be a nonempty string`);
  }
  return value;
}
function canonicalMoneyText(value, label, { nonzero = false } = {}) {
  const parsed = requiredText(value, label);
  if (
    !/^(0|[1-9][0-9]*)$/.test(parsed)
    || BigInt(parsed) > MAX_MONEY_SATS
    || (nonzero && BigInt(parsed) === 0n)
  ) {
    fail(`${label} must be ${nonzero ? "nonzero " : ""}canonical money`);
  }
  return parsed;
}
function networkId(value, label) {
  const parsed = integer(value, 0, 0xff, label);
  if (!isSupportedDirectV2NetworkId(parsed)) fail(`${label} is unsupported`);
  return parsed;
}
function nullableText(value, label) {
  return value === null ? null : requiredText(value, label);
}
function txid(value, label) {
  return bytes(value, 32, label);
}
function state(value, label) {
  return bytes(value, 128, label);
}
function outpoint(value, label) {
  const input = exactKeys(value, ["txid", "vout"], label);
  return Object.freeze({
    txid: txid(input.txid, `${label}.txid`),
    vout: integer(input.vout, 0, 0xffff_ffff, `${label}.vout`),
  });
}
function actionKind(value, label) {
  if (!V2_ACTION_KINDS.includes(value)) fail(`${label} is unsupported`);
  return value;
}
function same(left, right) {
  return Buffer.from(left).equals(Buffer.from(right));
}
function copy(value) {
  return Buffer.from(value);
}
function crash(requested, stage) {
  if (requested === stage) throw new V2StoreCrashInjection(stage);
}
function crashStage(value, allowed, label) {
  if (value !== null && !allowed.includes(value)) {
    fail(`${label} is unsupported`);
  }
  return value;
}
function p2pkh(value, label) {
  const result = bytes(value, 25, label);
  if (
    result[0] !== 0x76 || result[1] !== 0xa9 || result[2] !== 0x14 ||
    result[23] !== 0x88 || result[24] !== 0xac
  ) fail(`${label} must be canonical P2PKH locking bytecode`);
  return result;
}
function compressedPublicKey(value, label) {
  const result = bytes(value, 33, label);
  if (![0x02, 0x03].includes(result[0])) {
    fail(`${label} must be a compressed secp256k1 public key`);
  }
  try {
    if (!same(
      ECDH.convertKey(result, "secp256k1", undefined, undefined, "compressed"),
      result,
    )) fail(`${label} is not canonical`);
  } catch {
    fail(`${label} must be a valid compressed secp256k1 public key`);
  }
  return result;
}
function p2pkhForPublicKey(publicKey) {
  const sha = createHash("sha256").update(publicKey).digest();
  const hash = createHash("ripemd160").update(sha).digest();
  return Buffer.concat([
    Buffer.from([0x76, 0xa9, 0x14]),
    hash,
    Buffer.from([0x88, 0xac]),
  ]);
}

function ensureTrustedParent(databasePath) {
  if (typeof databasePath !== "string" || databasePath.length === 0) {
    fail("path must be a nonempty string");
  }
  const absolute = isAbsolute(databasePath)
    ? databasePath
    : resolve(databasePath);
  const parent = dirname(absolute);
  const root = parse(parent).root;
  if (parent === root) {
    fail("database must be placed in a dedicated 0700 parent directory");
  }
  const segments = relative(root, parent).split("/").filter(Boolean);
  let createdParent = false;
  let current = root;
  for (const [index, segment] of segments.entries()) {
    const next = join(current, segment);
    try {
      const stat = lstatSync(next);
      if (stat.isSymbolicLink() || !stat.isDirectory()) {
        fail("database parent traversal contains a symlink or non-directory");
      }
    } catch (error) {
      if (!(error && error.code === "ENOENT")) throw error;
      if (index !== segments.length - 1) {
        fail("database parent ancestor does not exist");
      }
      mkdirSync(next, { mode: 0o700 });
      createdParent = true;
      const stat = lstatSync(next);
      if (stat.isSymbolicLink() || !stat.isDirectory()) {
        fail("database parent creation was replaced");
      }
    }
    current = next;
  }
  if (createdParent) chmodSync(parent, 0o700);
  const parentStat = lstatSync(parent);
  if (
    parentStat.isSymbolicLink() || !parentStat.isDirectory() ||
    (parentStat.mode & 0o777) !== 0o700
  ) fail("database parent must be a real 0700 directory");
  if (
    typeof process.getuid === "function" && parentStat.uid !== process.getuid()
  ) fail("database parent must be owned by the effective UID");
  return absolute;
}
function assertRegular(path, label) {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile()) {
    fail(`${label} must be a non-symlink regular file`);
  }
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
    fail(`${label} must be owned by the effective UID`);
  }
  return stat;
}
function createCheckedDatabase(path) {
  try {
    assertRegular(path, "existing database");
  } catch (error) {
    if (!(error && error.code === "ENOENT")) throw error;
    try {
      closeSync(openSync(path, "wx", 0o600));
    } catch (openError) {
      if (!(openError && openError.code === "EEXIST")) throw openError;
      assertRegular(path, "existing database");
    }
  }
  chmodSync(path, 0o600);
  if ((assertRegular(path, "database").mode & 0o777) !== 0o600) {
    fail("database mode must be 0600");
  }
}
function secureSidecars(path) {
  for (const candidate of [path, `${path}-wal`, `${path}-shm`]) {
    try {
      assertRegular(candidate, "database sidecar");
      chmodSync(candidate, 0o600);
      if (
        (assertRegular(candidate, "database sidecar").mode & 0o777) !== 0o600
      ) {
        fail("database sidecar mode must be 0600");
      }
    } catch (error) {
      if (!(error && error.code === "ENOENT")) throw error;
    }
  }
}

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL, profile_id BLOB NOT NULL CHECK(length(profile_id)=32), instance_id BLOB NOT NULL CHECK(length(instance_id)=32), network_id INTEGER NOT NULL CHECK(network_id IN(1,2)), denomination_sats TEXT NOT NULL, carrier_count INTEGER NOT NULL CHECK(carrier_count BETWEEN 1 AND 255), runtime_materials_sha256 BLOB NOT NULL CHECK(length(runtime_materials_sha256)=32), genesis_state_bytes BLOB NOT NULL CHECK(length(genesis_state_bytes)=128), genesis_txid BLOB NOT NULL CHECK(length(genesis_txid)=32), genesis_vout INTEGER NOT NULL CHECK(genesis_vout BETWEEN 0 AND 4294967295), genesis_sequence INTEGER NOT NULL, genesis_height INTEGER NOT NULL, genesis_block_hash BLOB NOT NULL CHECK(length(genesis_block_hash)=32)) STRICT;
CREATE TABLE IF NOT EXISTS canonical_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), state_bytes BLOB NOT NULL CHECK(length(state_bytes)=128), txid BLOB NOT NULL CHECK(length(txid)=32), vout INTEGER NOT NULL CHECK(vout>=0), action_sequence INTEGER NOT NULL CHECK(action_sequence>=0), height INTEGER NOT NULL CHECK(height>=0), block_hash BLOB NOT NULL CHECK(length(block_hash)=32)) STRICT;
CREATE TABLE IF NOT EXISTS note_nodes (depth INTEGER NOT NULL CHECK(depth BETWEEN 0 AND 32), node_index INTEGER NOT NULL CHECK(node_index>=0 AND node_index<(1 << (32-depth))), node_hash BLOB NOT NULL CHECK(length(node_hash)=32), PRIMARY KEY(depth,node_index)) STRICT;
CREATE TABLE IF NOT EXISTS note_frontier (depth INTEGER PRIMARY KEY CHECK(depth BETWEEN 0 AND 31), node_hash BLOB NOT NULL CHECK(length(node_hash)=32)) STRICT;
CREATE TABLE IF NOT EXISTS note_leaves (note_index INTEGER PRIMARY KEY CHECK(note_index BETWEEN 0 AND 4294967295), leaf_hash BLOB NOT NULL CHECK(length(leaf_hash)=32), encrypted_record BLOB NOT NULL CHECK(length(encrypted_record)=128), action_sequence INTEGER NOT NULL UNIQUE CHECK(action_sequence>=1), transaction_id BLOB NOT NULL CHECK(length(transaction_id)=32)) STRICT;
CREATE TABLE IF NOT EXISTS nullifier_nodes (depth INTEGER NOT NULL CHECK(depth BETWEEN 0 AND 32), node_index INTEGER NOT NULL CHECK(node_index>=0 AND node_index<(1 << (32-depth))), node_hash BLOB NOT NULL CHECK(length(node_hash)=32), PRIMARY KEY(depth,node_index)) STRICT;
CREATE TABLE IF NOT EXISTS nullifier_order_keys (leaf_type INTEGER NOT NULL CHECK(leaf_type IN(1,2,3)), key_be BLOB NOT NULL CHECK(length(key_be)=32), physical_index INTEGER NOT NULL UNIQUE CHECK(physical_index BETWEEN 0 AND 4294967295), PRIMARY KEY(leaf_type,key_be), UNIQUE(leaf_type,key_be,physical_index)) STRICT, WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS nullifier_leaves (physical_index INTEGER PRIMARY KEY CHECK(physical_index BETWEEN 0 AND 4294967295), leaf_type INTEGER NOT NULL CHECK(leaf_type IN(1,2,3)), leaf_hash BLOB NOT NULL CHECK(length(leaf_hash)=32), key_be BLOB NOT NULL CHECK(length(key_be)=32), successor_index INTEGER NOT NULL CHECK(successor_index BETWEEN 0 AND 4294967295), successor_key_be BLOB NOT NULL CHECK(length(successor_key_be)=32), FOREIGN KEY(leaf_type,key_be,physical_index) REFERENCES nullifier_order_keys(leaf_type,key_be,physical_index)) STRICT;
CREATE TABLE IF NOT EXISTS encrypted_note_records (record_id TEXT PRIMARY KEY, record_bytes BLOB NOT NULL CHECK(length(record_bytes)=128)) STRICT;
CREATE TABLE IF NOT EXISTS owned_notes (note_id TEXT PRIMARY KEY, record_id TEXT NOT NULL REFERENCES encrypted_note_records(record_id), note_index INTEGER NOT NULL UNIQUE CHECK(note_index BETWEEN 0 AND 4294967295), nullifier_key BLOB NOT NULL UNIQUE CHECK(length(nullifier_key)=32), reservation_operation_id TEXT UNIQUE, spent INTEGER NOT NULL DEFAULT 0 CHECK(spent IN(0,1))) STRICT;
CREATE TABLE IF NOT EXISTS funding_utxos (txid BLOB NOT NULL CHECK(length(txid)=32), vout INTEGER NOT NULL CHECK(vout BETWEEN 0 AND 4294967295), value_sats TEXT NOT NULL, reservation_operation_id TEXT UNIQUE, spent INTEGER NOT NULL DEFAULT 0 CHECK(spent IN(0,1)), PRIMARY KEY(txid,vout)) STRICT, WITHOUT ROWID;
  CREATE TABLE IF NOT EXISTS pending_operations (operation_id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN('deposit','transfer','withdrawal')), journal_state TEXT NOT NULL CHECK(journal_state IN('draft','funding_selected','tip_synced','proving','proved','needs_reproof','signed','broadcast','mempool','confirmed','settled','conflicted','reorged','abandoned')), expected_state_bytes BLOB NOT NULL CHECK(length(expected_state_bytes)=128), expected_txid BLOB NOT NULL CHECK(length(expected_txid)=32), expected_vout INTEGER NOT NULL CHECK(expected_vout BETWEEN 0 AND 4294967295), expected_action_sequence INTEGER NOT NULL CHECK(expected_action_sequence>=0), expected_height INTEGER NOT NULL CHECK(expected_height>=0), expected_block_hash BLOB NOT NULL CHECK(length(expected_block_hash)=32), runtime_materials_sha256 BLOB NOT NULL CHECK(length(runtime_materials_sha256)=32), action_material_sha256 BLOB NOT NULL CHECK(length(action_material_sha256)=32), private_action_record_sha256 BLOB NOT NULL CHECK(length(private_action_record_sha256)=32), packet_bytes BLOB CHECK(packet_bytes IS NULL OR length(packet_bytes)=552), proof_bytes BLOB, unsigned_tx_bytes BLOB, signed_tx_bytes BLOB, local_vm_evidence BLOB, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL, reason TEXT) STRICT;
  CREATE TABLE IF NOT EXISTS operation_intents (operation_id TEXT PRIMARY KEY REFERENCES pending_operations(operation_id) ON DELETE CASCADE, kind TEXT NOT NULL CHECK(kind IN('deposit','transfer','withdrawal')), target_type TEXT NOT NULL CHECK(target_type IN('shield_address','withdrawal_locking_bytecode')), target_bytes BLOB NOT NULL, selected_note_id TEXT, funding_raw_transaction BLOB NOT NULL CHECK(length(funding_raw_transaction) BETWEEN 1 AND 100000), funding_txid BLOB NOT NULL CHECK(length(funding_txid)=32), funding_vout INTEGER NOT NULL CHECK(funding_vout BETWEEN 0 AND 4294967295), funding_value_sats TEXT NOT NULL, funding_locking_bytecode BLOB NOT NULL, funding_compressed_public_key BLOB NOT NULL CHECK(length(funding_compressed_public_key)=33), change_locking_bytecode BLOB NOT NULL, fee_rate_sats_per_byte TEXT NOT NULL, maximum_fee_sats TEXT NOT NULL, retry_count INTEGER NOT NULL DEFAULT 0 CHECK(retry_count BETWEEN 0 AND 3)) STRICT;
  CREATE TRIGGER IF NOT EXISTS immutable_operation_intent BEFORE UPDATE OF kind,target_type,target_bytes,selected_note_id,funding_raw_transaction,funding_txid,funding_vout,funding_value_sats,funding_locking_bytecode,funding_compressed_public_key,change_locking_bytecode,fee_rate_sats_per_byte,maximum_fee_sats ON operation_intents BEGIN SELECT RAISE(ABORT,'operation intent is immutable'); END;
  CREATE TRIGGER IF NOT EXISTS immutable_store_runtime_materials BEFORE UPDATE OF runtime_materials_sha256 ON metadata BEGIN SELECT RAISE(ABORT,'store runtime materials are immutable'); END;
  CREATE TRIGGER IF NOT EXISTS immutable_operation_runtime_materials BEFORE UPDATE OF runtime_materials_sha256 ON pending_operations BEGIN SELECT RAISE(ABORT,'operation runtime materials are immutable'); END;
  CREATE TRIGGER IF NOT EXISTS immutable_operation_action_material BEFORE UPDATE OF action_material_sha256 ON pending_operations WHEN NOT (OLD.journal_state IN('needs_reproof','reorged') AND NEW.journal_state='tip_synced') BEGIN SELECT RAISE(ABORT,'operation action material commitment is immutable outside explicit rebase'); END;
  CREATE TRIGGER IF NOT EXISTS immutable_private_action_record BEFORE UPDATE OF private_action_record_sha256 ON pending_operations WHEN NOT (OLD.journal_state IN('needs_reproof','reorged') AND NEW.journal_state='tip_synced') BEGIN SELECT RAISE(ABORT,'private action record commitment is immutable outside explicit rebase'); END;
CREATE TRIGGER IF NOT EXISTS immutable_signed_operation_artifacts BEFORE UPDATE OF packet_bytes,proof_bytes,unsigned_tx_bytes,signed_tx_bytes,local_vm_evidence ON pending_operations WHEN OLD.journal_state IN('signed','broadcast','mempool','confirmed','settled') AND NOT (NEW.journal_state IN('needs_reproof','conflicted','reorged') AND NEW.packet_bytes IS NULL AND NEW.proof_bytes IS NULL AND NEW.unsigned_tx_bytes IS NULL AND NEW.signed_tx_bytes IS NULL AND NEW.local_vm_evidence IS NULL) BEGIN SELECT RAISE(ABORT,'signed operation artifacts are immutable'); END;
CREATE TABLE IF NOT EXISTS mempool_overlay (operation_id TEXT PRIMARY KEY REFERENCES pending_operations(operation_id), overlay_bytes BLOB NOT NULL, created_at_ms INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS undo_records (height INTEGER NOT NULL, block_hash BLOB NOT NULL CHECK(length(block_hash)=32), action_ordinal INTEGER NOT NULL CHECK(action_ordinal>=0), operation_id TEXT NOT NULL REFERENCES pending_operations(operation_id), predecessor_state_bytes BLOB NOT NULL CHECK(length(predecessor_state_bytes)=128), predecessor_txid BLOB NOT NULL CHECK(length(predecessor_txid)=32), predecessor_vout INTEGER NOT NULL, predecessor_sequence INTEGER NOT NULL, predecessor_height INTEGER NOT NULL, predecessor_block_hash BLOB NOT NULL CHECK(length(predecessor_block_hash)=32), successor_txid BLOB NOT NULL CHECK(length(successor_txid)=32), successor_vout INTEGER NOT NULL, successor_sequence INTEGER NOT NULL, undo_delta_bytes BLOB NOT NULL, undo_bytes BLOB NOT NULL, PRIMARY KEY(height,block_hash,action_ordinal)) STRICT;
CREATE INDEX IF NOT EXISTS undo_by_height ON undo_records(height,action_ordinal);
CREATE TABLE IF NOT EXISTS recovery_actions (action_sequence INTEGER PRIMARY KEY CHECK(action_sequence>=1), transaction_id BLOB NOT NULL UNIQUE CHECK(length(transaction_id)=32), height INTEGER NOT NULL CHECK(height>=0), block_hash BLOB NOT NULL CHECK(length(block_hash)=32), kind TEXT NOT NULL CHECK(kind IN('deposit','transfer','withdrawal')), packet_bytes BLOB NOT NULL CHECK(length(packet_bytes)=552), transaction_context_hash BLOB NOT NULL CHECK(length(transaction_context_hash)=32), output_note_leaf BLOB CHECK(output_note_leaf IS NULL OR length(output_note_leaf)=32), encrypted_record BLOB CHECK(encrypted_record IS NULL OR length(encrypted_record)=128), public_nullifier BLOB CHECK(public_nullifier IS NULL OR length(public_nullifier)=32)) STRICT;
CREATE TABLE IF NOT EXISTS recovery_checkpoint (singleton INTEGER PRIMARY KEY CHECK(singleton=1), content_sha256 BLOB NOT NULL CHECK(length(content_sha256)=32), history_sha256 BLOB NOT NULL CHECK(length(history_sha256)=32), action_count INTEGER NOT NULL CHECK(action_count>=0), note_count INTEGER NOT NULL CHECK(note_count BETWEEN 0 AND 4294967295), nullifier_count INTEGER NOT NULL CHECK(nullifier_count BETWEEN 0 AND 4294967295), external_authentication_boundary TEXT NOT NULL) STRICT;
`;
const V2_SCHEMA_TABLES = Object.freeze([
  "metadata",
  "canonical_state",
  "note_nodes",
  "note_frontier",
  "note_leaves",
  "nullifier_nodes",
  "nullifier_order_keys",
  "nullifier_leaves",
  "encrypted_note_records",
  "owned_notes",
  "funding_utxos",
  "pending_operations",
  "operation_intents",
  "mempool_overlay",
  "undo_records",
  "recovery_actions",
  "recovery_checkpoint",
]);
const PENDING_OPERATION_COLUMNS = Object.freeze([
  "operation_id",
  "kind",
  "journal_state",
  "expected_state_bytes",
  "expected_txid",
  "expected_vout",
  "expected_action_sequence",
  "expected_height",
  "expected_block_hash",
  "runtime_materials_sha256",
  "action_material_sha256",
  "private_action_record_sha256",
  "packet_bytes",
  "proof_bytes",
  "unsigned_tx_bytes",
  "signed_tx_bytes",
  "local_vm_evidence",
  "created_at_ms",
  "updated_at_ms",
  "reason",
]);
const OPERATION_INTENT_COLUMNS = Object.freeze([
  "operation_id",
  "kind",
  "target_type",
  "target_bytes",
  "selected_note_id",
  "funding_raw_transaction",
  "funding_txid",
  "funding_vout",
  "funding_value_sats",
  "funding_locking_bytecode",
  "funding_compressed_public_key",
  "change_locking_bytecode",
  "fee_rate_sats_per_byte",
  "maximum_fee_sats",
  "retry_count",
]);
function schemaFingerprint(db) {
  const rows = db.prepare(
    `SELECT type,name,tbl_name,sql
     FROM sqlite_schema
     WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL
     ORDER BY type,name`,
  ).all();
  return createHash("sha256").update(JSON.stringify(rows)).digest("hex");
}
let requiredSchemaFingerprint;
function v2SchemaFingerprint() {
  if (requiredSchemaFingerprint !== undefined) {
    return requiredSchemaFingerprint;
  }
  const expected = new DatabaseSync(":memory:");
  try {
    expected.exec(SCHEMA);
    requiredSchemaFingerprint = schemaFingerprint(expected);
    return requiredSchemaFingerprint;
  } finally {
    expected.close();
  }
}
function sameStrings(actual, expected) {
  return actual.length === expected.length &&
    actual.every((value, index) => value === expected[index]);
}
function requireV2SchemaLayout(db) {
  const rows = db.prepare("PRAGMA table_list").all();
  const tables = new Map(
    rows.filter(({ schema }) => schema === "main")
      .map((row) => [row.name, row]),
  );
  if (
    V2_SCHEMA_TABLES.some((name) =>
      !tables.has(name) || tables.get(name).strict !== 1
    ) ||
    !sameStrings(
      db.prepare("PRAGMA table_info(pending_operations)").all()
        .map(({ name }) => name),
      PENDING_OPERATION_COLUMNS,
    ) ||
    !sameStrings(
      db.prepare("PRAGMA table_info(operation_intents)").all()
        .map(({ name }) => name),
      OPERATION_INTENT_COLUMNS,
    ) ||
    db.prepare(
        "SELECT 1 FROM sqlite_schema WHERE type='index' AND name='undo_by_height'",
      ).get() === undefined ||
    db.prepare(
        "SELECT 1 FROM sqlite_schema WHERE type='trigger' AND name='immutable_operation_intent'",
      ).get() === undefined ||
    db.prepare(
        "SELECT 1 FROM sqlite_schema WHERE type='trigger' AND name='immutable_store_runtime_materials'",
      ).get() === undefined ||
    db.prepare(
        "SELECT 1 FROM sqlite_schema WHERE type='trigger' AND name='immutable_operation_runtime_materials'",
      ).get() === undefined ||
    db.prepare(
        "SELECT 1 FROM sqlite_schema WHERE type='trigger' AND name='immutable_operation_action_material'",
      ).get() === undefined ||
    db.prepare(
        "SELECT 1 FROM sqlite_schema WHERE type='trigger' AND name='immutable_private_action_record'",
      ).get() === undefined ||
    db.prepare(
        "SELECT 1 FROM sqlite_schema WHERE type='trigger' AND name='immutable_signed_operation_artifacts'",
      ).get() === undefined ||
    schemaFingerprint(db) !== v2SchemaFingerprint()
  ) {
    fail(
      `store schema layout is incompatible with required version ${V2_STORE_SCHEMA_VERSION}; automatic migration is not supported`,
    );
  }
}

function validateNode(value, label) {
  const input = exactKeys(value, ["depth", "nodeIndex", "nodeHash"], label);
  const depth = integer(input.depth, 0, 32, `${label}.depth`);
  return Object.freeze({
    depth,
    nodeIndex: integer(
      input.nodeIndex,
      0,
      (2 ** (32 - depth)) - 1,
      `${label}.nodeIndex`,
    ),
    nodeHash: txid(input.nodeHash, `${label}.nodeHash`),
  });
}
function validateFrontier(value, label) {
  const input = exactKeys(value, ["depth", "nodeHash"], label);
  return Object.freeze({
    depth: integer(input.depth, 0, 31, `${label}.depth`),
    nodeHash: txid(input.nodeHash, `${label}.nodeHash`),
  });
}
function indexedNullifierLeafHash({
  leafType,
  physicalIndex,
  key,
  successorIndex,
  successorKey,
}) {
  return Buffer.from(
    hashIndexedNullifierLeaf([
      BigInt(leafType),
      BigInt(physicalIndex),
      BigInt(`0x${Buffer.from(key).toString("hex")}`),
      BigInt(successorIndex),
      BigInt(`0x${Buffer.from(successorKey).toString("hex")}`),
    ]).toString(16).padStart(64, "0"),
    "hex",
  );
}
function validateLeaf(value, label) {
  const input = exactKeys(value, [
    "physicalIndex",
    "leafType",
    "leafHash",
    "key",
    "successorIndex",
    "successorKey",
  ], label);
  const leafType = integer(input.leafType, 1, 3, `${label}.leafType`);
  const physicalIndex = integer(
    input.physicalIndex,
    0,
    MAX_U32,
    `${label}.physicalIndex`,
  );
  const key = txid(input.key, `${label}.key`);
  const successorIndex = integer(
    input.successorIndex,
    0,
    MAX_U32,
    `${label}.successorIndex`,
  );
  const successorKey = txid(input.successorKey, `${label}.successorKey`);
  const zero = Buffer.alloc(32);
  if (
    (leafType === 1 &&
      (physicalIndex !== 0 || !key.equals(zero) || successorIndex === 0 ||
        (successorIndex === 1 && !successorKey.equals(zero)) ||
        (successorIndex >= 2 &&
          BigInt(`0x${successorKey.toString("hex")}`) >= BN254_FR_MODULUS))) ||
    (leafType === 3 &&
      (physicalIndex !== 1 || !key.equals(zero) || successorIndex !== 1 ||
        !successorKey.equals(zero))) ||
    (leafType === 2 &&
      (physicalIndex < 2 || successorIndex === 0 ||
        successorIndex === physicalIndex ||
        (successorIndex === 1 && !successorKey.equals(zero)) ||
        (successorIndex >= 2 &&
          BigInt(`0x${successorKey.toString("hex")}`) >= BN254_FR_MODULUS) ||
        BigInt(`0x${key.toString("hex")}`) >= BN254_FR_MODULUS))
  ) fail(`${label} violates indexed-nullifier sentinel ordering`);
  if (
    leafType === V2_NULLIFIER_LEAF_TYPES.normal &&
    successorIndex >= 2 &&
    BigInt(`0x${successorKey.toString("hex")}`) <=
      BigInt(`0x${key.toString("hex")}`)
  ) {
    fail(`${label} normal successor must have a strictly greater key`);
  }
  const expectedHash = indexedNullifierLeafHash({
    leafType,
    physicalIndex,
    key,
    successorIndex,
    successorKey,
  });
  const leafHash = txid(input.leafHash, `${label}.leafHash`);
  if (!same(leafHash, expectedHash)) {
    fail(`${label}.leafHash does not match the profile-pinned Poseidon leaf`);
  }
  return Object.freeze({
    physicalIndex,
    leafType,
    leafHash,
    key,
    successorIndex,
    successorKey,
  });
}
function validateSnapshotNode(value, label) {
  const node = validateNode(value, label);
  return Object.freeze({
    ...node,
    nodeHash: frBuffer(node.nodeHash, `${label}.nodeHash`),
  });
}
function validateSnapshotFrontier(value, label) {
  const frontier = validateFrontier(value, label);
  return Object.freeze({
    ...frontier,
    nodeHash: frBuffer(frontier.nodeHash, `${label}.nodeHash`),
  });
}
function validateSnapshotNoteLeaf(value, label) {
  const input = exactKeys(value, [
    "noteIndex",
    "leafHash",
    "encryptedRecord",
    "actionSequence",
    "transactionId",
  ], label);
  return Object.freeze({
    noteIndex: integer(input.noteIndex, 0, MAX_U32, `${label}.noteIndex`),
    leafHash: frBuffer(input.leafHash, `${label}.leafHash`),
    encryptedRecord: bytes(
      input.encryptedRecord,
      128,
      `${label}.encryptedRecord`,
    ),
    actionSequence: integer(
      input.actionSequence,
      1,
      0x1_ffff_ffff,
      `${label}.actionSequence`,
    ),
    transactionId: txid(input.transactionId, `${label}.transactionId`),
  });
}
function validatedArray(value, validator, label) {
  if (!Array.isArray(value)) fail(`${label} must be an array`);
  return Object.freeze(
    value.map((entry, index) => validator(entry, `${label}[${index}]`)),
  );
}
function validateSnapshotBinding(value) {
  const input = exactKeys(value, [
    "profileId",
    "instanceId",
    "networkId",
    "denominationSats",
    "carrierCount",
    "runtimeMaterialsSha256",
  ], "authenticated snapshot.binding");
  return Object.freeze({
    profileId: txid(
      input.profileId,
      "authenticated snapshot.binding.profileId",
    ),
    instanceId: txid(
      input.instanceId,
      "authenticated snapshot.binding.instanceId",
    ),
    networkId: networkId(
      input.networkId,
      "authenticated snapshot.binding.networkId",
    ),
    denominationSats: canonicalMoneyText(
      input.denominationSats,
      "authenticated snapshot.binding.denominationSats",
      { nonzero: true },
    ),
    carrierCount: integer(
      input.carrierCount,
      1,
      0xff,
      "authenticated snapshot.binding.carrierCount",
    ),
    runtimeMaterialsSha256: bytes(
      input.runtimeMaterialsSha256,
      32,
      "authenticated snapshot.binding.runtimeMaterialsSha256",
    ),
  });
}
function validateSnapshotCanonical(value) {
  const input = exactKeys(value, [
    "state",
    "outpoint",
    "actionSequence",
    "height",
    "blockHash",
  ], "authenticated snapshot.canonical");
  return Object.freeze({
    state: state(input.state, "authenticated snapshot.canonical.state"),
    outpoint: outpoint(
      input.outpoint,
      "authenticated snapshot.canonical.outpoint",
    ),
    actionSequence: integer(
      input.actionSequence,
      0,
      0x1_ffff_ffff,
      "authenticated snapshot.canonical.actionSequence",
    ),
    height: integer(
      input.height,
      0,
      Number.MAX_SAFE_INTEGER,
      "authenticated snapshot.canonical.height",
    ),
    blockHash: txid(
      input.blockHash,
      "authenticated snapshot.canonical.blockHash",
    ),
  });
}
function validateAuthenticatedSnapshot(value) {
  const input = exactKeys(value, [
    "binding",
    "canonical",
    "noteNodes",
    "noteFrontier",
    "noteLeaves",
    "nullifierNodes",
    "nullifierLeaves",
    "crashAt",
  ], "authenticated snapshot");
  if (
    input.crashAt !== null &&
    !V2_AUTHENTICATED_SNAPSHOT_CRASH_STAGES.includes(input.crashAt)
  ) {
    fail("authenticated snapshot.crashAt is unsupported");
  }
  return Object.freeze({
    binding: validateSnapshotBinding(input.binding),
    canonical: validateSnapshotCanonical(input.canonical),
    noteNodes: validatedArray(
      input.noteNodes,
      validateSnapshotNode,
      "authenticated snapshot.noteNodes",
    ),
    noteFrontier: validatedArray(
      input.noteFrontier,
      validateSnapshotFrontier,
      "authenticated snapshot.noteFrontier",
    ),
    noteLeaves: validatedArray(
      input.noteLeaves,
      validateSnapshotNoteLeaf,
      "authenticated snapshot.noteLeaves",
    ),
    nullifierNodes: validatedArray(
      input.nullifierNodes,
      validateSnapshotNode,
      "authenticated snapshot.nullifierNodes",
    ),
    nullifierLeaves: validatedArray(
      input.nullifierLeaves,
      validateLeaf,
      "authenticated snapshot.nullifierLeaves",
    ),
    crashAt: input.crashAt,
  });
}
function lowercaseHexBytes(value, length, label) {
  if (
    typeof value !== "string" ||
    !new RegExp(`^[0-9a-f]{${length * 2}}$`).test(value)
  ) {
    fail(`${label} must be exactly ${length} lowercase hexadecimal bytes`);
  }
  return Buffer.from(value, "hex");
}
function canonicalCountText(value, maximum, label) {
  if (
    typeof value !== "string" ||
    !/^(0|[1-9][0-9]*)$/.test(value)
  ) {
    fail(`${label} must be a canonical unsigned decimal integer`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > maximum) {
    fail(`${label} exceeds its protocol range`);
  }
  return parsed;
}
function streamCounts(value, label) {
  const input = exactKeys(value, [
    "action",
    "noteNode",
    "noteFrontier",
    "noteLeaf",
    "nullifierNode",
    "nullifierLeaf",
  ], label);
  return Object.freeze({
    action: integer(
      input.action,
      0,
      0x1_ffff_ffff,
      `${label}.action`,
    ),
    noteNode: integer(
      input.noteNode,
      1,
      Number.MAX_SAFE_INTEGER,
      `${label}.noteNode`,
    ),
    noteFrontier: integer(
      input.noteFrontier,
      0,
      TREE_DEPTH,
      `${label}.noteFrontier`,
    ),
    noteLeaf: integer(
      input.noteLeaf,
      0,
      MAX_U32,
      `${label}.noteLeaf`,
    ),
    nullifierNode: integer(
      input.nullifierNode,
      1,
      Number.MAX_SAFE_INTEGER,
      `${label}.nullifierNode`,
    ),
    nullifierLeaf: integer(
      input.nullifierLeaf,
      2,
      Number.MAX_SAFE_INTEGER,
      `${label}.nullifierLeaf`,
    ),
  });
}
function sameStreamCounts(left, right) {
  return Object.keys(left).every((key) => left[key] === right[key]);
}
function validateStreamPoint(value, label) {
  const input = exactKeys(value, [
    "transactionId",
    "outputIndex",
    "height",
    "blockHash",
    "stateHex",
  ], label);
  return Object.freeze({
    transactionId: lowercaseHexBytes(
      input.transactionId,
      32,
      `${label}.transactionId`,
    ),
    outputIndex: integer(
      input.outputIndex,
      0,
      MAX_U32,
      `${label}.outputIndex`,
    ),
    height: integer(
      input.height,
      0,
      Number.MAX_SAFE_INTEGER,
      `${label}.height`,
    ),
    blockHash: lowercaseHexBytes(
      input.blockHash,
      32,
      `${label}.blockHash`,
    ),
    state: lowercaseHexBytes(input.stateHex, 128, `${label}.stateHex`),
  });
}
function validateStreamTree(value, label) {
  const input = exactKeys(value, ["depth", "count", "root"], label);
  if (input.depth !== TREE_DEPTH) fail(`${label}.depth must be 32`);
  return Object.freeze({
    depth: TREE_DEPTH,
    count: canonicalCountText(input.count, MAX_U32, `${label}.count`),
    root: frBuffer(
      lowercaseHexBytes(input.root, 32, `${label}.root`),
      `${label}.root`,
    ),
  });
}
function validateStreamSnapshot(value) {
  const input = exactKeys(value, [
    "schema",
    "version",
    "networkId",
    "profileId",
    "instanceId",
    "denominationSats",
    "carrierCount",
    "runtimeMaterialsSha256",
    "poseidonProfile",
    "genesis",
    "tip",
    "actionCount",
    "historySha256",
    "stateHex",
    "noteTree",
    "nullifierTree",
    "externalAuthenticationBoundary",
    "contentSha256",
  ], "authenticated stream snapshot");
  if (
    input.schema !== "shieldkit-v2-recovery-snapshot-v2" ||
    input.version !== 2 ||
    input.poseidonProfile !==
      "shieldkit-pool-action-v2-direct-poseidon-v1"
  ) {
    fail("authenticated stream snapshot schema or profile is unsupported");
  }
  const boundary = requiredText(
    input.externalAuthenticationBoundary,
    "authenticated stream snapshot.externalAuthenticationBoundary",
  );
  if (Buffer.byteLength(boundary, "utf8") > 16 * 1024) {
    fail("authenticated stream snapshot authentication boundary is too large");
  }
  return Object.freeze({
    raw: input,
    binding: Object.freeze({
      profileId: lowercaseHexBytes(
        input.profileId,
        32,
        "authenticated stream snapshot.profileId",
      ),
      instanceId: lowercaseHexBytes(
        input.instanceId,
        32,
        "authenticated stream snapshot.instanceId",
      ),
      networkId: networkId(
        input.networkId,
        "authenticated stream snapshot.networkId",
      ),
      denominationSats: canonicalMoneyText(
        input.denominationSats,
        "authenticated stream snapshot.denominationSats",
        { nonzero: true },
      ),
      carrierCount: integer(
        input.carrierCount,
        1,
        0xff,
        "authenticated stream snapshot.carrierCount",
      ),
      runtimeMaterialsSha256: lowercaseHexBytes(
        input.runtimeMaterialsSha256,
        32,
        "authenticated stream snapshot.runtimeMaterialsSha256",
      ),
    }),
    genesis: validateStreamPoint(
      input.genesis,
      "authenticated stream snapshot.genesis",
    ),
    tip: validateStreamPoint(input.tip, "authenticated stream snapshot.tip"),
    actionCount: canonicalCountText(
      input.actionCount,
      0x1_ffff_ffff,
      "authenticated stream snapshot.actionCount",
    ),
    historySha256: lowercaseHexBytes(
      input.historySha256,
      32,
      "authenticated stream snapshot.historySha256",
    ),
    state: lowercaseHexBytes(
      input.stateHex,
      128,
      "authenticated stream snapshot.stateHex",
    ),
    noteTree: validateStreamTree(
      input.noteTree,
      "authenticated stream snapshot.noteTree",
    ),
    nullifierTree: validateStreamTree(
      input.nullifierTree,
      "authenticated stream snapshot.nullifierTree",
    ),
    externalAuthenticationBoundary: boundary,
    contentSha256: lowercaseHexBytes(
      input.contentSha256,
      32,
      "authenticated stream snapshot.contentSha256",
    ),
  });
}
function validateStreamHeader(value) {
  const input = exactKeys(value, ["type", "counts"], "stream header frame");
  if (input.type !== "header") fail("stream must begin with a header frame");
  return streamCounts(input.counts, "stream header counts");
}
function validateStreamSnapshotFrame(value, counts) {
  const input = exactKeys(
    value,
    ["type", "snapshot", "material"],
    "stream snapshot frame",
  );
  if (input.type !== "snapshot") {
    fail("stream header must be followed by a snapshot frame");
  }
  const snapshot = validateStreamSnapshot(input.snapshot);
  const materialInput = exactKeys(input.material, [
    "schema",
    "contentSha256",
    "binding",
    "canonical",
  ], "stream material header");
  if (
    materialInput.schema !==
      "shieldkit-v2-recovery-authenticated-material-v2"
  ) {
    fail("stream material schema is unsupported");
  }
  const materialContent = lowercaseHexBytes(
    materialInput.contentSha256,
    32,
    "stream material.contentSha256",
  );
  const binding = validateSnapshotBinding(materialInput.binding);
  const canonical = validateSnapshotCanonical(materialInput.canonical);
  if (
    !same(materialContent, snapshot.contentSha256) ||
    !same(binding.profileId, snapshot.binding.profileId) ||
    !same(binding.instanceId, snapshot.binding.instanceId) ||
    binding.networkId !== snapshot.binding.networkId ||
    binding.denominationSats !== snapshot.binding.denominationSats ||
    binding.carrierCount !== snapshot.binding.carrierCount ||
    !same(
      binding.runtimeMaterialsSha256,
      snapshot.binding.runtimeMaterialsSha256,
    ) ||
    !same(canonical.state, snapshot.state) ||
    !same(canonical.state, snapshot.tip.state) ||
    !same(canonical.outpoint.txid, snapshot.tip.transactionId) ||
    canonical.outpoint.vout !== snapshot.tip.outputIndex ||
    canonical.height !== snapshot.tip.height ||
    !same(canonical.blockHash, snapshot.tip.blockHash) ||
    canonical.actionSequence !== snapshot.actionCount ||
    counts.action !== snapshot.actionCount ||
    counts.noteLeaf !== snapshot.noteTree.count ||
    counts.nullifierLeaf !== snapshot.nullifierTree.count + 2
  ) {
    fail("stream material, snapshot, canonical tip, or counts differ");
  }
  return Object.freeze({ snapshot, binding, canonical });
}
function validateStreamRecordEnvelope(value, expectedType, expectedIndex) {
  const input = exactKeys(
    value,
    ["type", "index", "value"],
    `stream ${expectedType} frame`,
  );
  if (
    input.type !== expectedType ||
    input.index !== expectedIndex
  ) {
    fail(`stream ${expectedType} frame is reordered or duplicated`);
  }
  return input.value;
}
function validateStreamEnd(value, counts) {
  const input = exactKeys(
    value,
    ["type", "counts", "frameCount", "digest"],
    "stream end frame",
  );
  if (
    input.type !== "end" ||
    !sameStreamCounts(
      streamCounts(input.counts, "stream end counts"),
      counts,
    ) ||
    !Number.isSafeInteger(input.frameCount) ||
    input.frameCount < 2 ||
    typeof input.digest !== "string" ||
    !/^[0-9a-f]{64}$/.test(input.digest)
  ) {
    fail("stream end frame is invalid or differs from its header");
  }
  return Object.freeze({
    frameCount: input.frameCount,
    digest: Buffer.from(input.digest, "hex"),
  });
}

function validateCanonicalReconciliation(value) {
  const input = exactKeys(value, [
    "canonicalSettlementTxids",
    "fundingInventory",
  ], "authenticated canonical reconciliation");
  if (
    !Array.isArray(input.canonicalSettlementTxids)
    || input.canonicalSettlementTxids.length > MAX_U32
  ) {
    fail(
      "authenticated canonical settlement transaction IDs must be a bounded array",
    );
  }
  const transactionIds = [];
  const seenTransactions = new Set();
  for (
    let index = 0;
    index < input.canonicalSettlementTxids.length;
    index += 1
  ) {
    const transactionId = txid(
      input.canonicalSettlementTxids[index],
      `authenticated canonical settlement transaction ID[${index}]`,
    );
    const key = transactionId.toString("hex");
    if (seenTransactions.has(key)) {
      fail(
        "authenticated canonical settlement transaction IDs contain a duplicate",
      );
    }
    seenTransactions.add(key);
    transactionIds.push(transactionId);
  }
  if (
    !Array.isArray(input.fundingInventory)
    || input.fundingInventory.length > 100_000
  ) {
    fail(
      "authenticated funding inventory must be a bounded complete array",
    );
  }
  const fundingInventory = [];
  const seenFunding = new Set();
  for (let index = 0; index < input.fundingInventory.length; index += 1) {
    const entry = exactKeys(
      input.fundingInventory[index],
      ["txid", "vout", "valueSats"],
      `authenticated funding inventory[${index}]`,
    );
    const transactionId = txid(
      entry.txid,
      `authenticated funding inventory[${index}].txid`,
    );
    const vout = integer(
      entry.vout,
      0,
      MAX_U32,
      `authenticated funding inventory[${index}].vout`,
    );
    const valueSats = canonicalMoneyText(
      entry.valueSats,
      `authenticated funding inventory[${index}].valueSats`,
      { nonzero: true },
    );
    const key = `${transactionId.toString("hex")}:${vout}`;
    if (seenFunding.has(key)) {
      fail("authenticated funding inventory contains a duplicate outpoint");
    }
    seenFunding.add(key);
    fundingInventory.push(Object.freeze({
      txid: transactionId,
      vout,
      valueSats,
    }));
  }
  fundingInventory.sort((left, right) =>
    Buffer.compare(left.txid, right.txid) || left.vout - right.vout
  );
  return Object.freeze({
    canonicalSettlementTxids: Object.freeze(transactionIds),
    canonicalSettlementTxidSet: new Set(seenTransactions),
    fundingInventory: Object.freeze(fundingInventory),
  });
}

function expectedMaterializedWidth(allocatedLeaves, depth) {
  return depth === TREE_DEPTH
    ? 1
    : Math.ceil(allocatedLeaves / (2 ** depth));
}
function validateMaterializedTree({
  nodes,
  allocatedLeaves,
  leafHashes,
  expectedRoot,
  label,
}) {
  const widths = [];
  let expectedNodeCount = 0;
  for (let depth = 0; depth <= TREE_DEPTH; depth += 1) {
    const width = expectedMaterializedWidth(allocatedLeaves, depth);
    widths.push(width);
    expectedNodeCount += width;
  }
  if (nodes.length !== expectedNodeCount) {
    fail(`${label} node count differs from the allocated prefix`);
  }
  const byCoordinate = new Map();
  for (const node of nodes) {
    const key = `${node.depth}:${node.nodeIndex}`;
    if (byCoordinate.has(key)) {
      fail(`${label} contains a duplicate node coordinate`);
    }
    const width = widths[node.depth];
    if (node.nodeIndex >= width) {
      fail(`${label} contains a node outside the allocated prefix`);
    }
    byCoordinate.set(key, node);
  }
  for (let depth = 0; depth <= TREE_DEPTH; depth += 1) {
    const width = widths[depth];
    for (let nodeIndex = 0; nodeIndex < width; nodeIndex += 1) {
      if (!byCoordinate.has(`${depth}:${nodeIndex}`)) {
        fail(`${label} is missing an allocated node`);
      }
    }
  }
  const root = byCoordinate.get(`${TREE_DEPTH}:0`);
  if (!root || !same(root.nodeHash, expectedRoot)) {
    fail(`${label} terminal root node differs from the canonical state`);
  }
  for (let index = 0; index < leafHashes.length; index += 1) {
    const node = byCoordinate.get(`0:${index}`);
    if (!node || !same(node.nodeHash, leafHashes[index])) {
      fail(`${label} depth-0 node differs from its materialized leaf`);
    }
  }
  return Object.freeze({ byCoordinate, root: copy(root.nodeHash) });
}
function validateSnapshotNoteMaterial({
  nodes,
  frontier,
  leaves,
  noteCount,
  actionSequence,
  expectedRoot,
}) {
  if (leaves.length !== noteCount) {
    fail("authenticated snapshot note leaves differ from state.noteCount");
  }
  const actionSequences = new Set();
  const transactionIds = new Set();
  for (let index = 0; index < leaves.length; index += 1) {
    const leaf = leaves[index];
    if (leaf.noteIndex !== index) {
      fail(
        "authenticated snapshot note leaves must cover the exact append prefix",
      );
    }
    if (
      leaf.actionSequence > actionSequence ||
      (index > 0 && leaf.actionSequence <= leaves[index - 1].actionSequence)
    ) {
      fail("authenticated snapshot note action sequences are not canonical");
    }
    if (actionSequences.has(leaf.actionSequence)) {
      fail("authenticated snapshot note action sequence is duplicated");
    }
    actionSequences.add(leaf.actionSequence);
    const transactionId = leaf.transactionId.toString("hex");
    if (transactionIds.has(transactionId)) {
      fail("authenticated snapshot note transaction ID is duplicated");
    }
    transactionIds.add(transactionId);
  }
  const tree = validateMaterializedTree({
    nodes,
    allocatedLeaves: noteCount,
    leafHashes: leaves.map((leaf) => leaf.leafHash),
    expectedRoot,
    label: "authenticated snapshot note tree",
  });
  const byDepth = new Map();
  for (const entry of frontier) {
    if (byDepth.has(entry.depth)) {
      fail("authenticated snapshot note frontier depth is duplicated");
    }
    byDepth.set(entry.depth, entry);
  }
  const expectedDepths = [];
  const count = BigInt(noteCount);
  for (let depth = 0; depth < TREE_DEPTH; depth += 1) {
    if (((count >> BigInt(depth)) & 1n) === 1n) expectedDepths.push(depth);
  }
  if (
    frontier.length !== expectedDepths.length ||
    expectedDepths.some((depth) => !byDepth.has(depth))
  ) {
    fail("authenticated snapshot note frontier shape differs from noteCount");
  }
  for (const depth of expectedDepths) {
    const nodeIndex = Math.floor(noteCount / (2 ** depth)) - 1;
    const node = tree.byCoordinate.get(`${depth}:${nodeIndex}`);
    if (!node || !same(node.nodeHash, byDepth.get(depth).nodeHash)) {
      fail("authenticated snapshot note frontier differs from its tree node");
    }
  }
  return tree;
}
function validateSnapshotNullifierMaterial({
  nodes,
  leaves,
  nullifierCount,
  expectedRoot,
}) {
  const allocatedLeaves = nullifierCount + 2;
  if (leaves.length !== allocatedLeaves) {
    fail(
      "authenticated snapshot nullifier leaves differ from state.nullifierCount",
    );
  }
  const byPhysicalIndex = new Map();
  const normalByKey = new Map();
  for (const leaf of leaves) {
    if (byPhysicalIndex.has(leaf.physicalIndex)) {
      fail("authenticated snapshot nullifier physical index is duplicated");
    }
    byPhysicalIndex.set(leaf.physicalIndex, leaf);
    if (leaf.leafType === V2_NULLIFIER_LEAF_TYPES.normal) {
      const key = leaf.key.toString("hex");
      if (normalByKey.has(key)) {
        fail("authenticated snapshot normal nullifier key is duplicated");
      }
      normalByKey.set(key, leaf);
    }
  }
  for (
    let physicalIndex = 0;
    physicalIndex < allocatedLeaves;
    physicalIndex += 1
  ) {
    const leaf = byPhysicalIndex.get(physicalIndex);
    if (
      !leaf ||
      (physicalIndex === 0 &&
        leaf.leafType !== V2_NULLIFIER_LEAF_TYPES.minimum) ||
      (physicalIndex === 1 &&
        leaf.leafType !== V2_NULLIFIER_LEAF_TYPES.maximum) ||
      (physicalIndex >= 2 &&
        leaf.leafType !== V2_NULLIFIER_LEAF_TYPES.normal)
    ) {
      fail(
        "authenticated snapshot nullifier leaves must cover the exact physical prefix",
      );
    }
  }
  if (normalByKey.size !== nullifierCount) {
    fail("authenticated snapshot normal nullifier count differs from state");
  }
  const ordered = [...normalByKey.values()].sort((left, right) =>
    Buffer.compare(left.key, right.key)
  );
  const maximum = byPhysicalIndex.get(1);
  const chain = [byPhysicalIndex.get(0), ...ordered];
  for (let index = 0; index < chain.length; index += 1) {
    const current = chain[index];
    const successor = index + 1 < chain.length ? chain[index + 1] : maximum;
    if (
      current.successorIndex !== successor.physicalIndex ||
      !same(current.successorKey, successor.key)
    ) {
      fail(
        "authenticated snapshot nullifier successor chain is not exact key order",
      );
    }
  }
  const tree = validateMaterializedTree({
    nodes,
    allocatedLeaves,
    leafHashes: Array.from(
      { length: allocatedLeaves },
      (_, index) => byPhysicalIndex.get(index).leafHash,
    ),
    expectedRoot,
    label: "authenticated snapshot nullifier tree",
  });
  return Object.freeze({ ...tree, orderedLeaves: Object.freeze(leaves) });
}
function replaceSnapshotTable({
  db,
  deleteSql,
  insertSql,
  rows,
  values,
  crashAt,
  crashStage,
}) {
  db.exec(deleteSql);
  const insert = db.prepare(insertSql);
  if (rows.length === 0) crash(crashAt, crashStage);
  const injectionIndex = Math.floor(rows.length / 2);
  for (const [index, row] of rows.entries()) {
    insert.run(...values(row));
    if (index === injectionIndex) crash(crashAt, crashStage);
  }
}
function nullableArtifact(value, length, label) {
  return length === null
    ? nullableVariableBytes(value, label)
    : nullableBytes(value, length, label);
}
function operationIntent(value, operationKind, label) {
  const input = exactKeys(value, [
    "kind",
    "target",
    "selectedNoteId",
    "funding",
    "changeLockingBytecode",
    "feePolicy",
  ], label);
  const kind = actionKind(input.kind, `${label}.kind`);
  if (kind !== operationKind) fail(`${label}.kind must match operation.kind`);
  const targetInput = exactKeys(
    input.target,
    ["type", "bytes"],
    `${label}.target`,
  );
  const targetType = requiredText(
    targetInput.type,
    `${label}.target.type`,
  );
  let targetBytes;
  let decodedShieldAddress = null;
  if (kind === "withdrawal") {
    if (targetType !== "withdrawal_locking_bytecode") {
      fail(`${label}.target.type does not match withdrawal`);
    }
    targetBytes = p2pkh(
      targetInput.bytes,
      `${label}.target.bytes`,
    );
  } else {
    if (targetType !== "shield_address") {
      fail(`${label}.target.type does not match ${kind}`);
    }
    try {
      targetBytes = Buffer.from(targetInput.bytes);
      decodedShieldAddress = decodeDirectV2Address(targetInput.bytes);
    } catch (error) {
      fail(
        `${label}.target.bytes is not a valid V2 shield address: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }
  const selectedNoteId = input.selectedNoteId === null
    ? null
    : requiredText(input.selectedNoteId, `${label}.selectedNoteId`);
  if (
    (kind === "deposit" && selectedNoteId !== null) ||
    (kind !== "deposit" && selectedNoteId === null)
  ) fail(`${label}.selectedNoteId does not match action kind`);

  const fundingInput = exactKeys(input.funding, [
    "rawSourceTransaction",
    "txid",
    "vout",
    "valueSats",
    "lockingBytecode",
    "compressedPublicKey",
  ], `${label}.funding`);
  const rawSourceTransaction = boundedBytes(
    fundingInput.rawSourceTransaction,
    1,
    V2_MAX_TRANSACTION_BYTES,
    `${label}.funding.rawSourceTransaction`,
  );
  const fundingTxid = txid(fundingInput.txid, `${label}.funding.txid`);
  const fundingVout = integer(
    fundingInput.vout,
    0,
    MAX_U32,
    `${label}.funding.vout`,
  );
  const fundingValueSats = canonicalMoneyText(
    fundingInput.valueSats,
    `${label}.funding.valueSats`,
    { nonzero: true },
  );
  const fundingLockingBytecode = p2pkh(
    fundingInput.lockingBytecode,
    `${label}.funding.lockingBytecode`,
  );
  const fundingCompressedPublicKey = compressedPublicKey(
    fundingInput.compressedPublicKey,
    `${label}.funding.compressedPublicKey`,
  );
  if (!same(
    fundingLockingBytecode,
    p2pkhForPublicKey(fundingCompressedPublicKey),
  )) {
    fail(`${label}.funding locking bytecode does not match its public key`);
  }
  let source;
  try {
    source = parseV2RawTransaction(rawSourceTransaction.toString("hex"));
  } catch (error) {
    fail(
      `${label}.funding.rawSourceTransaction is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  const sourceOutput = source.outputs[fundingVout];
  if (
    source.txid !== fundingTxid.toString("hex") ||
    sourceOutput === undefined ||
    sourceOutput.valueSatoshis.toString() !== fundingValueSats ||
    !same(sourceOutput.lockingBytecode, fundingLockingBytecode)
  ) {
    fail(`${label}.funding fields do not exactly match the source transaction`);
  }

  const changeLockingBytecode = p2pkh(
    input.changeLockingBytecode,
    `${label}.changeLockingBytecode`,
  );
  const feeInput = exactKeys(
    input.feePolicy,
    ["feeRateSatsPerByte", "maximumFeeSats"],
    `${label}.feePolicy`,
  );
  const feeRateSatsPerByte = canonicalMoneyText(
    feeInput.feeRateSatsPerByte,
    `${label}.feePolicy.feeRateSatsPerByte`,
    { nonzero: true },
  );
  const maximumFeeSats = canonicalMoneyText(
    feeInput.maximumFeeSats,
    `${label}.feePolicy.maximumFeeSats`,
    { nonzero: true },
  );
  if (BigInt(maximumFeeSats) > BigInt(fundingValueSats)) {
    fail(`${label}.feePolicy.maximumFeeSats exceeds funding value`);
  }
  return Object.freeze({
    kind,
    targetType,
    targetBytes,
    decodedShieldAddress,
    selectedNoteId,
    funding: Object.freeze({
      rawSourceTransaction,
      txid: fundingTxid,
      vout: fundingVout,
      valueSats: fundingValueSats,
      lockingBytecode: fundingLockingBytecode,
      compressedPublicKey: fundingCompressedPublicKey,
    }),
    changeLockingBytecode,
    feePolicy: Object.freeze({
      feeRateSatsPerByte,
      maximumFeeSats,
    }),
  });
}
function operationInput(
  value,
  label,
  crashStages = V2_OPERATION_CREATE_CRASH_STAGES,
) {
  const input = exactKeys(value, [
    "operationId",
    "kind",
    "expectedState",
    "expectedOutpoint",
    "expectedActionSequence",
    "expectedHeight",
    "expectedBlockHash",
    "runtimeMaterialsSha256",
    "actionMaterialSha256",
    "privateActionRecordSha256",
    "intent",
    "packet",
    "proof",
    "unsignedTx",
    "signedTx",
    "localVmEvidence",
    "crashAt",
  ], label);
  const kind = actionKind(input.kind, `${label}.kind`);
  return Object.freeze({
    operationId: requiredText(input.operationId, `${label}.operationId`),
    kind,
    expectedState: state(input.expectedState, `${label}.expectedState`),
    expectedOutpoint: outpoint(
      input.expectedOutpoint,
      `${label}.expectedOutpoint`,
    ),
    expectedActionSequence: integer(
      input.expectedActionSequence,
      0,
      0x1_ffff_ffff,
      `${label}.expectedActionSequence`,
    ),
    expectedHeight: integer(
      input.expectedHeight,
      0,
      Number.MAX_SAFE_INTEGER,
      `${label}.expectedHeight`,
    ),
    expectedBlockHash: txid(
      input.expectedBlockHash,
      `${label}.expectedBlockHash`,
    ),
    runtimeMaterialsSha256: bytes(
      input.runtimeMaterialsSha256,
      32,
      `${label}.runtimeMaterialsSha256`,
    ),
    actionMaterialSha256: bytes(
      input.actionMaterialSha256,
      32,
      `${label}.actionMaterialSha256`,
    ),
    privateActionRecordSha256: bytes(
      input.privateActionRecordSha256,
      32,
      `${label}.privateActionRecordSha256`,
    ),
    intent: operationIntent(input.intent, kind, `${label}.intent`),
    packet: nullableArtifact(input.packet, 552, `${label}.packet`),
    proof: nullableArtifact(input.proof, null, `${label}.proof`),
    unsignedTx: nullableArtifact(input.unsignedTx, null, `${label}.unsignedTx`),
    signedTx: nullableArtifact(input.signedTx, null, `${label}.signedTx`),
    localVmEvidence: nullableArtifact(
      input.localVmEvidence,
      null,
      `${label}.localVmEvidence`,
    ),
    crashAt: crashStage(
      input.crashAt,
      crashStages,
      `${label}.crashAt`,
    ),
  });
}
function operationAndIntent(db, operationId) {
  return db.prepare(
    `SELECT p.*,i.kind AS intent_kind,i.target_type,i.target_bytes,
      i.selected_note_id,i.funding_raw_transaction,i.funding_txid,
      i.funding_vout,i.funding_value_sats,i.funding_locking_bytecode,
      i.funding_compressed_public_key,i.change_locking_bytecode,
      i.fee_rate_sats_per_byte,i.maximum_fee_sats,i.retry_count
    FROM pending_operations AS p
    JOIN operation_intents AS i ON i.operation_id=p.operation_id
    WHERE p.operation_id=?`,
  ).get(operationId);
}
function releaseOperationResources(db, operationId) {
  db.prepare(
    "UPDATE owned_notes SET reservation_operation_id=NULL WHERE reservation_operation_id=?",
  ).run(operationId);
  db.prepare(
    "UPDATE funding_utxos SET reservation_operation_id=NULL WHERE reservation_operation_id=?",
  ).run(operationId);
}
function operationReservationsAreExact(db, row) {
  const funding = db.prepare(
    "SELECT txid,vout,value_sats,spent FROM funding_utxos WHERE reservation_operation_id=?",
  ).all(row.operation_id);
  if (
    funding.length !== 1 || funding[0].spent !== 0 ||
    !same(funding[0].txid, row.funding_txid) ||
    funding[0].vout !== row.funding_vout ||
    funding[0].value_sats !== row.funding_value_sats
  ) return false;
  const notes = db.prepare(
    "SELECT note_id,spent FROM owned_notes WHERE reservation_operation_id=?",
  ).all(row.operation_id);
  if (row.selected_note_id === null) return notes.length === 0;
  return notes.length === 1 &&
    notes[0].note_id === row.selected_note_id &&
    notes[0].spent === 0;
}
function requireExactOperationReservations(db, row) {
  if (!operationReservationsAreExact(db, row)) {
    fail("operation retained reservations do not exactly match immutable intent");
  }
}
function parseOperationTransaction(value, carrierCount, label) {
  const raw = variableBytes(value, label);
  let parsed;
  try {
    parsed = assertV2StandardTransactionEnvelope(
      parseV2RawTransaction(raw.toString("hex")),
      { carrierCount },
    );
  } catch (error) {
    fail(
      `${label} is not one standard V2 transaction: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  return parsed;
}
function sameTransactionSkeleton(left, right, fundingInputIndex) {
  return (
    left.version === right.version
    && left.locktime === right.locktime
    && left.inputs.length === right.inputs.length
    && left.outputs.length === right.outputs.length
    && left.inputs.every((input, index) => {
      const other = right.inputs[index];
      return (
        input.outpoint.txid === other.outpoint.txid
        && input.outpoint.vout === other.outpoint.vout
        && input.sequence === other.sequence
        && (
          index === fundingInputIndex
          || same(input.unlockingBytecode, other.unlockingBytecode)
        )
      );
    })
    && left.outputs.every(
      (output, index) =>
        output.serializedHex === right.outputs[index].serializedHex,
    )
  );
}
function operationExpectedTipIsExact(row, current) {
  return current !== undefined &&
    same(row.expected_state_bytes, current.state_bytes) &&
    same(row.expected_txid, current.txid) &&
    row.expected_vout === current.vout &&
    row.expected_action_sequence === current.action_sequence &&
    row.expected_height === current.height &&
    same(row.expected_block_hash, current.block_hash);
}
function rowOrNull(row) {
  return row === undefined ? null : row;
}
function unique(values, key, label) {
  const seen = new Set();
  for (const value of values) {
    const id = key(value);
    if (seen.has(id)) fail(`${label} contains a duplicate mutation target`);
    seen.add(id);
  }
}
function hashTreePair(nodeHasher, left, right, label) {
  try {
    return encodedFr(nodeHasher(
      frBigInt(left, `${label} left`),
      frBigInt(right, `${label} right`),
    ));
  } catch (error) {
    fail(
      `${label} failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}
function storedNode(db, table, depth, nodeIndex, defaults, overrides = null) {
  const key = `${depth}:${nodeIndex}`;
  const overridden = overrides?.get(key);
  if (overridden !== undefined) return overridden.nodeHash;
  const row = db.prepare(
    `SELECT node_hash FROM ${table} WHERE depth=? AND node_index=?`,
  ).get(depth, nodeIndex);
  return row ? frBuffer(row.node_hash, `${table} node`) : defaults[depth];
}
function assertStoredRoot(db, table, expected, label) {
  const row = db.prepare(
    `SELECT node_hash FROM ${table} WHERE depth=32 AND node_index=0`,
  ).get();
  if (!row || !same(row.node_hash, expected)) {
    fail(`${label} stored root does not match the canonical pre-state`);
  }
}
function deriveNoteAppendMutation(db, packet, { verifyPostRoot = true } = {}) {
  const index = Number(packet.preState.noteCount);
  if (
    db.prepare(
      "SELECT node_hash FROM note_nodes WHERE depth=0 AND node_index=?",
    ).get(index)
  ) {
    fail("note append position is already occupied");
  }
  assertStoredRoot(
    db,
    "note_nodes",
    Buffer.from(packet.preState.noteRoot, "hex"),
    "note tree",
  );
  let cursor = index;
  let node = frBuffer(
    Buffer.from(packet.outputNoteLeaf, "hex"),
    "packet output note leaf",
  );
  const noteNodes = [];
  const noteFrontier = [];
  const siblings = [];
  for (let depth = 0; depth < TREE_DEPTH; depth += 1) {
    noteNodes.push({
      depth,
      nodeIndex: cursor,
      nodeHash: node,
    });
    const bit = cursor & 1;
    const sibling = storedNode(
      db,
      "note_nodes",
      depth,
      cursor ^ 1,
      NOTE_DEFAULTS,
    );
    siblings.push(frBigInt(sibling, `note append sibling ${depth}`));
    if (bit === 0) {
      noteFrontier.push({ depth, nodeHash: node });
    } else {
      const frontier = db.prepare(
        "SELECT node_hash FROM note_frontier WHERE depth=?",
      ).get(depth);
      if (!frontier || !same(frontier.node_hash, sibling)) {
        fail("note frontier does not authenticate the sequential append path");
      }
    }
    node = bit === 0
      ? hashTreePair(hashNoteTreeNode, node, sibling, "note tree")
      : hashTreePair(hashNoteTreeNode, sibling, node, "note tree");
    cursor = Math.floor(cursor / 2);
  }
  noteNodes.push({ depth: TREE_DEPTH, nodeIndex: 0, nodeHash: node });
  if (
    verifyPostRoot &&
    !same(node, Buffer.from(packet.postState.noteRoot, "hex"))
  ) {
    fail("derived note append root does not match the packet post-state");
  }
  return Object.freeze({
    noteNodes: Object.freeze(noteNodes),
    noteFrontier: Object.freeze(noteFrontier),
    root: node,
    witness: Object.freeze({
      depth: TREE_DEPTH,
      index,
      outputNoteLeaf: frBigInt(
        Buffer.from(packet.outputNoteLeaf, "hex"),
        "packet output note leaf",
      ),
      preRoot: frBigInt(
        Buffer.from(packet.preState.noteRoot, "hex"),
        "packet note pre-root",
      ),
      postRoot: frBigInt(node, "derived note post-root"),
      emptyAppendPath: Object.freeze(siblings),
      membershipPath: Object.freeze([...siblings]),
    }),
  });
}
function pathRootFromStored({
  db,
  table,
  defaults,
  nodeHasher,
  index,
  leafHash,
  overrides = null,
  record = false,
  siblings = null,
  label,
}) {
  if (siblings !== null && (!Array.isArray(siblings) || siblings.length !== 0)) {
    fail(`${label} sibling capture must be an empty array`);
  }
  let cursor = index;
  let node = frBuffer(leafHash, `${label} leaf`);
  if (record) {
    overrides.set(`0:${cursor}`, {
      depth: 0,
      nodeIndex: cursor,
      nodeHash: node,
    });
  }
  for (let depth = 0; depth < TREE_DEPTH; depth += 1) {
    const bit = cursor & 1;
    const sibling = storedNode(
      db,
      table,
      depth,
      cursor ^ 1,
      defaults,
      overrides,
    );
    if (siblings !== null) {
      siblings.push(frBigInt(sibling, `${label} sibling ${depth}`));
    }
    node = bit === 0
      ? hashTreePair(nodeHasher, node, sibling, label)
      : hashTreePair(nodeHasher, sibling, node, label);
    cursor = Math.floor(cursor / 2);
    if (record) {
      overrides.set(`${depth + 1}:${cursor}`, {
        depth: depth + 1,
        nodeIndex: cursor,
        nodeHash: node,
      });
    }
  }
  return node;
}
function witnessNullifierLeaf(leaf) {
  const type = leaf.leafType === V2_NULLIFIER_LEAF_TYPES.minimum
    ? "min"
    : leaf.leafType === V2_NULLIFIER_LEAF_TYPES.normal
    ? "normal"
    : leaf.leafType === V2_NULLIFIER_LEAF_TYPES.maximum
    ? "max"
    : null;
  if (type === null) fail("nullifier witness leaf type is unsupported");
  return Object.freeze({
    type,
    index: leaf.physicalIndex,
    key: leaf.key.toString("hex"),
    successorIndex: leaf.successorIndex,
    successorKey: leaf.successorKey.toString("hex"),
  });
}
function deriveNoteMembershipWitness(db, {
  noteIndex,
  inputNoteLeaf,
  expectedRoot,
}) {
  const storedLeaf = db.prepare(
    "SELECT node_hash FROM note_nodes WHERE depth=0 AND node_index=?",
  ).get(noteIndex);
  if (!storedLeaf || !same(storedLeaf.node_hash, inputNoteLeaf)) {
    fail("selected note leaf differs from the persistent note tree");
  }
  const siblings = [];
  const root = pathRootFromStored({
    db,
    table: "note_nodes",
    defaults: NOTE_DEFAULTS,
    nodeHasher: hashNoteTreeNode,
    index: noteIndex,
    leafHash: inputNoteLeaf,
    siblings,
    label: "selected note membership path",
  });
  if (!same(root, expectedRoot)) {
    fail("selected note membership path does not prove the canonical note root");
  }
  return Object.freeze({
    noteMembershipPath: Object.freeze(siblings),
    root,
  });
}
function deriveNullifierInsertionMutation(
  db,
  packet,
  { verifyPostRoot = true } = {},
) {
  const publicNullifier = Buffer.from(packet.publicNullifier, "hex");
  const sqliteAccess = productionNullifierSqliteAccess(db);
  let mutation;
  try {
    mutation = derivePersistentIndexedNullifierInsertion({
      expectedPreRoot: Buffer.from(packet.preState.nullifierRoot, "hex"),
      key: publicNullifier,
      normalCount: Number(packet.preState.nullifierCount),
      adapter: sqliteAccess.adapter,
    });
  } catch (error) {
    if (error instanceof PersistentIndexedNullifierError) {
      fail(error.message);
    }
    throw error;
  }
  if (
    verifyPostRoot &&
    !same(
      mutation.root,
      Buffer.from(packet.postState.nullifierRoot, "hex"),
    )
  ) {
    fail("derived nullifier insertion root does not match the packet post-state");
  }
  return mutation;
}
function restoreDelta(db, encoded) {
  const delta = deserialize(Buffer.from(encoded));
  const upsertNode = (table, row) =>
    db.prepare(
      `INSERT INTO ${table}(depth,node_index,node_hash) VALUES(?,?,?) ON CONFLICT(depth,node_index) DO UPDATE SET node_hash=excluded.node_hash`,
    ).run(row.depth, row.node_index, row.node_hash);
  const restoreNode = (table, entry) => {
    if (entry.before === null) {
      db.prepare(`DELETE FROM ${table} WHERE depth=? AND node_index=?`).run(
        entry.depth,
        entry.nodeIndex,
      );
    } else upsertNode(table, entry.before);
  };
  for (const entry of [...delta.notes].reverse()) {
    if (entry.before === null) {
      db.prepare("DELETE FROM owned_notes WHERE note_id=?").run(entry.noteId);
    } else {db.prepare(
        "INSERT INTO owned_notes(note_id,record_id,note_index,nullifier_key,reservation_operation_id,spent) VALUES(?,?,?,?,?,?) ON CONFLICT(note_id) DO UPDATE SET record_id=excluded.record_id,note_index=excluded.note_index,nullifier_key=excluded.nullifier_key,reservation_operation_id=excluded.reservation_operation_id,spent=excluded.spent",
      ).run(
        entry.before.note_id,
        entry.before.record_id,
        entry.before.note_index,
        entry.before.nullifier_key,
        entry.before.reservation_operation_id,
        entry.before.spent,
      );}
  }
  for (const entry of [...delta.records].reverse()) {
    if (entry.before === null) {
      db.prepare("DELETE FROM encrypted_note_records WHERE record_id=?").run(
        entry.recordId,
      );
    } else {db.prepare(
        "INSERT INTO encrypted_note_records(record_id,record_bytes) VALUES(?,?) ON CONFLICT(record_id) DO UPDATE SET record_bytes=excluded.record_bytes",
      ).run(entry.before.record_id, entry.before.record_bytes);}
  }
  for (const entry of [...delta.noteLeaves].reverse()) {
    if (entry.before === null) {
      db.prepare("DELETE FROM note_leaves WHERE note_index=?").run(
        entry.noteIndex,
      );
    } else {
      db.prepare(
        "INSERT INTO note_leaves(note_index,leaf_hash,encrypted_record,action_sequence,transaction_id) VALUES(?,?,?,?,?) ON CONFLICT(note_index) DO UPDATE SET leaf_hash=excluded.leaf_hash,encrypted_record=excluded.encrypted_record,action_sequence=excluded.action_sequence,transaction_id=excluded.transaction_id",
      ).run(
        entry.before.note_index,
        entry.before.leaf_hash,
        entry.before.encrypted_record,
        entry.before.action_sequence,
        entry.before.transaction_id,
      );
    }
  }
  for (const entry of [...delta.utxos].reverse()) {
    if (entry.before === null) {
      db.prepare("DELETE FROM funding_utxos WHERE txid=? AND vout=?").run(
        entry.txid,
        entry.vout,
      );
    } else {db.prepare(
        "INSERT INTO funding_utxos(txid,vout,value_sats,reservation_operation_id,spent) VALUES(?,?,?,?,?) ON CONFLICT(txid,vout) DO UPDATE SET value_sats=excluded.value_sats,reservation_operation_id=excluded.reservation_operation_id,spent=excluded.spent",
      ).run(
        entry.before.txid,
        entry.before.vout,
        entry.before.value_sats,
        entry.before.reservation_operation_id,
        entry.before.spent,
      );}
  }
  for (const entry of [...delta.leaves].reverse()) {
    if (entry.leafBefore === null) {
      db.prepare("DELETE FROM nullifier_leaves WHERE physical_index=?").run(
        entry.physicalIndex,
      );
    }
  }
  for (const entry of [...delta.leaves].reverse()) {
    if (entry.orderBefore === null) {
      db.prepare(
        "DELETE FROM nullifier_order_keys WHERE leaf_type=? AND key_be=?",
      ).run(entry.leafType, entry.key);
    }
  }
  for (const entry of delta.leaves) {
    if (entry.orderBefore !== null) {
      db.prepare(
        "INSERT INTO nullifier_order_keys(leaf_type,key_be,physical_index) VALUES(?,?,?) ON CONFLICT(leaf_type,key_be) DO UPDATE SET physical_index=excluded.physical_index",
      ).run(
        entry.orderBefore.leaf_type,
        entry.orderBefore.key_be,
        entry.orderBefore.physical_index,
      );
    }
  }
  for (const entry of delta.leaves) {
    if (entry.leafBefore !== null) {
      const row = entry.leafBefore;
      db.prepare(
        "INSERT INTO nullifier_leaves(physical_index,leaf_type,leaf_hash,key_be,successor_index,successor_key_be) VALUES(?,?,?,?,?,?) ON CONFLICT(physical_index) DO UPDATE SET leaf_type=excluded.leaf_type,leaf_hash=excluded.leaf_hash,key_be=excluded.key_be,successor_index=excluded.successor_index,successor_key_be=excluded.successor_key_be",
      ).run(
        row.physical_index,
        row.leaf_type,
        row.leaf_hash,
        row.key_be,
        row.successor_index,
        row.successor_key_be,
      );
    }
  }
  for (const entry of [...delta.nullifierNodes].reverse()) {
    restoreNode("nullifier_nodes", entry);
  }
  for (const entry of [...delta.noteFrontier].reverse()) {
    if (entry.before === null) {
      db.prepare("DELETE FROM note_frontier WHERE depth=?").run(entry.depth);
    } else {db.prepare(
        "INSERT INTO note_frontier(depth,node_hash) VALUES(?,?) ON CONFLICT(depth) DO UPDATE SET node_hash=excluded.node_hash",
      ).run(entry.before.depth, entry.before.node_hash);}
  }
  for (const entry of [...delta.noteNodes].reverse()) {
    restoreNode("note_nodes", entry);
  }
  if (delta.overlayBefore === null) {
    db.prepare("DELETE FROM mempool_overlay WHERE operation_id=?").run(
      delta.operationBefore.operation_id,
    );
  } else {db.prepare(
      "INSERT INTO mempool_overlay(operation_id,overlay_bytes,created_at_ms) VALUES(?,?,?) ON CONFLICT(operation_id) DO UPDATE SET overlay_bytes=excluded.overlay_bytes,created_at_ms=excluded.created_at_ms",
    ).run(
      delta.overlayBefore.operation_id,
      delta.overlayBefore.overlay_bytes,
      delta.overlayBefore.created_at_ms,
    );}
  db.prepare(
    "UPDATE pending_operations SET journal_state=?,reason=?,updated_at_ms=? WHERE operation_id=?",
  ).run(
    delta.operationBefore.journal_state,
    delta.operationBefore.reason,
    delta.operationBefore.updated_at_ms,
    delta.operationBefore.operation_id,
  );
}

const STREAM_STAGE_SCHEMA = `
DROP TABLE IF EXISTS temp.v2_stream_actions;
DROP TABLE IF EXISTS temp.v2_stream_note_nodes;
DROP TABLE IF EXISTS temp.v2_stream_note_frontier;
DROP TABLE IF EXISTS temp.v2_stream_note_leaves;
DROP TABLE IF EXISTS temp.v2_stream_nullifier_nodes;
DROP TABLE IF EXISTS temp.v2_stream_nullifier_leaves;
DROP TABLE IF EXISTS temp.v2_stream_owned_notes;
CREATE TEMP TABLE v2_stream_actions (action_sequence INTEGER PRIMARY KEY, transaction_id BLOB NOT NULL UNIQUE, height INTEGER NOT NULL, block_hash BLOB NOT NULL, kind TEXT NOT NULL, packet_bytes BLOB NOT NULL, transaction_context_hash BLOB NOT NULL, output_note_leaf BLOB, encrypted_record BLOB, public_nullifier BLOB) STRICT;
CREATE TEMP TABLE v2_stream_note_nodes (depth INTEGER NOT NULL, node_index INTEGER NOT NULL, node_hash BLOB NOT NULL, PRIMARY KEY(depth,node_index)) STRICT;
CREATE TEMP TABLE v2_stream_note_frontier (depth INTEGER PRIMARY KEY, node_hash BLOB NOT NULL) STRICT;
CREATE TEMP TABLE v2_stream_note_leaves (note_index INTEGER PRIMARY KEY, leaf_hash BLOB NOT NULL, encrypted_record BLOB NOT NULL, action_sequence INTEGER NOT NULL UNIQUE, transaction_id BLOB NOT NULL UNIQUE) STRICT;
CREATE TEMP TABLE v2_stream_nullifier_nodes (depth INTEGER NOT NULL, node_index INTEGER NOT NULL, node_hash BLOB NOT NULL, PRIMARY KEY(depth,node_index)) STRICT;
CREATE TEMP TABLE v2_stream_nullifier_leaves (physical_index INTEGER PRIMARY KEY, leaf_type INTEGER NOT NULL, leaf_hash BLOB NOT NULL, key_be BLOB NOT NULL, successor_index INTEGER NOT NULL, successor_key_be BLOB NOT NULL, UNIQUE(leaf_type,key_be)) STRICT;
CREATE TEMP TABLE v2_stream_owned_notes (note_id TEXT PRIMARY KEY, record_id TEXT NOT NULL UNIQUE, note_index INTEGER NOT NULL UNIQUE, record_bytes BLOB NOT NULL, nullifier_key BLOB NOT NULL UNIQUE) STRICT;
`;
const DROP_STREAM_STAGE = `
DROP TABLE IF EXISTS temp.v2_stream_owned_notes;
DROP TABLE IF EXISTS temp.v2_stream_nullifier_leaves;
DROP TABLE IF EXISTS temp.v2_stream_nullifier_nodes;
DROP TABLE IF EXISTS temp.v2_stream_note_leaves;
DROP TABLE IF EXISTS temp.v2_stream_note_frontier;
DROP TABLE IF EXISTS temp.v2_stream_note_nodes;
DROP TABLE IF EXISTS temp.v2_stream_actions;
`;
function validateStreamAction(value, index, binding, expectedPreState) {
  const input = exactKeys(value, [
    "transactionId",
    "height",
    "blockHash",
    "kind",
    "packet",
    "transactionContextHash",
  ], `stream action[${index}]`);
  const transactionId = txid(
    input.transactionId,
    `stream action[${index}].transactionId`,
  );
  const height = integer(
    input.height,
    0,
    Number.MAX_SAFE_INTEGER,
    `stream action[${index}].height`,
  );
  const blockHash = txid(
    input.blockHash,
    `stream action[${index}].blockHash`,
  );
  const kind = actionKind(input.kind, `stream action[${index}].kind`);
  const packetBytes = bytes(
    input.packet,
    552,
    `stream action[${index}].packet`,
  );
  const transactionContextHash = txid(
    input.transactionContextHash,
    `stream action[${index}].transactionContextHash`,
  );
  let packet;
  try {
    packet = decodeActionPacket(packetBytes, {
      denominationSats: binding.denominationSats,
    });
  } catch (error) {
    fail(
      `stream action[${index}] packet is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  const preState = encodeStateNftCommitment(packet.preState, {
    denominationSats: binding.denominationSats,
  });
  const postState = encodeStateNftCommitment(packet.postState, {
    denominationSats: binding.denominationSats,
  });
  const preNoteCount = BigInt(packet.preState.noteCount);
  const preNullifierCount = BigInt(packet.preState.nullifierCount);
  const preReserve = BigInt(packet.preState.reserveSats);
  const preSequence = BigInt(packet.preState.actionSequence);
  const postNoteCount = BigInt(packet.postState.noteCount);
  const postNullifierCount = BigInt(packet.postState.nullifierCount);
  const postReserve = BigInt(packet.postState.reserveSats);
  const postSequence = BigInt(packet.postState.actionSequence);
  const denomination = BigInt(binding.denominationSats);
  const expected = kind === "deposit"
    ? {
      noteCount: preNoteCount + 1n,
      nullifierCount: preNullifierCount,
      reserve: preReserve + denomination,
    }
    : kind === "transfer"
    ? {
      noteCount: preNoteCount + 1n,
      nullifierCount: preNullifierCount + 1n,
      reserve: preReserve,
    }
    : {
      noteCount: preNoteCount,
      nullifierCount: preNullifierCount + 1n,
      reserve: preReserve - denomination,
    };
  if (
    kind !== packet.kind ||
    packet.networkId !== binding.networkId ||
    packet.instanceId !== binding.instanceId.toString("hex") ||
    packet.preState.profileId !== binding.profileId.toString("hex") ||
    packet.postState.profileId !== binding.profileId.toString("hex") ||
    !same(
      transactionContextHash,
      Buffer.from(packet.transactionContextHash, "hex"),
    ) ||
    !same(preState, expectedPreState) ||
    preSequence !== BigInt(index) ||
    postSequence !== preSequence + 1n ||
    postNoteCount !== expected.noteCount ||
    postNullifierCount !== expected.nullifierCount ||
    postReserve !== expected.reserve ||
    (kind === "deposit" &&
      packet.postState.nullifierRoot !== packet.preState.nullifierRoot) ||
    (kind === "withdrawal" &&
      packet.postState.noteRoot !== packet.preState.noteRoot)
  ) {
    fail(`stream action[${index}] does not form the exact bound state lineage`);
  }
  return Object.freeze({
    actionSequence: index + 1,
    transactionId,
    height,
    blockHash,
    kind,
    packetBytes,
    transactionContextHash,
    outputNoteLeaf: kind === "withdrawal"
      ? null
      : Buffer.from(packet.outputNoteLeaf, "hex"),
    encryptedRecord: kind === "withdrawal"
      ? null
      : Buffer.from(packet.encryptedRecord),
    publicNullifier: kind === "deposit"
      ? null
      : Buffer.from(packet.publicNullifier, "hex"),
    postState,
  });
}
function validateRecoveredOwnedNote(value, leaf, label) {
  if (value === null || value === undefined) return null;
  const input = exactKeys(value, [
    "noteId",
    "recordId",
    "record",
    "nullifier",
  ], label);
  const record = bytes(input.record, 128, `${label}.record`);
  if (!same(record, leaf.encryptedRecord)) {
    fail(`${label}.record differs from the authenticated note leaf`);
  }
  return Object.freeze({
    noteId: requiredText(input.noteId, `${label}.noteId`),
    recordId: requiredText(input.recordId, `${label}.recordId`),
    noteIndex: leaf.noteIndex,
    record,
    nullifier: frBuffer(input.nullifier, `${label}.nullifier`),
  });
}
function validateStagedTree(
  db,
  {
    nodeTable,
    leafTable,
    leafIndex,
    leafHash,
    allocatedLeaves,
    expectedRoot,
    label,
  },
) {
  let expectedNodes = 0;
  for (let depth = 0; depth <= TREE_DEPTH; depth += 1) {
    const width = expectedMaterializedWidth(allocatedLeaves, depth);
    expectedNodes += width;
    const row = db.prepare(
      `SELECT COUNT(*) AS count,MIN(node_index) AS minimum,MAX(node_index) AS maximum
       FROM temp.${nodeTable} WHERE depth=?`,
    ).get(depth);
    if (
      row.count !== width ||
      (width !== 0 && (row.minimum !== 0 || row.maximum !== width - 1))
    ) {
      fail(`${label} nodes do not cover the exact allocated prefix`);
    }
  }
  const root = db.prepare(
    `SELECT node_hash FROM temp.${nodeTable} WHERE depth=32 AND node_index=0`,
  ).get();
  if (!root || !same(root.node_hash, expectedRoot)) {
    fail(`${label} terminal root differs from the canonical state`);
  }
  const mismatch = db.prepare(
    `SELECT COUNT(*) AS count
     FROM temp.${leafTable} AS leaf
     LEFT JOIN temp.${nodeTable} AS node
       ON node.depth=0 AND node.node_index=leaf.${leafIndex}
     WHERE node.node_hash IS NULL OR node.node_hash<>leaf.${leafHash}`,
  ).get().count;
  if (mismatch !== 0) {
    fail(`${label} depth-0 nodes differ from authenticated leaves`);
  }
  return Object.freeze({ nodeCount: expectedNodes, root: copy(root.node_hash) });
}
function validateStagedMaterial(db, snapshotFrame) {
  const { snapshot, canonical } = snapshotFrame;
  let decoded;
  try {
    decoded = decodeStateNftCommitment(canonical.state, {
      denominationSats: snapshot.binding.denominationSats,
    });
  } catch (error) {
    fail(
      `stream canonical state is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  const noteCount = Number(decoded.noteCount);
  const nullifierCount = Number(decoded.nullifierCount);
  const actionSequence = Number(decoded.actionSequence);
  if (
    actionSequence !== snapshot.actionCount ||
    noteCount !== snapshot.noteTree.count ||
    nullifierCount !== snapshot.nullifierTree.count ||
    !same(Buffer.from(decoded.noteRoot, "hex"), snapshot.noteTree.root) ||
    !same(
      Buffer.from(decoded.nullifierRoot, "hex"),
      snapshot.nullifierTree.root,
    )
  ) {
    fail("stream snapshot counts or roots differ from its canonical state");
  }
  const actions = db.prepare(
    `SELECT COUNT(*) AS count,
      SUM(CASE WHEN kind IN('deposit','transfer') THEN 1 ELSE 0 END) AS notes,
      SUM(CASE WHEN kind IN('transfer','withdrawal') THEN 1 ELSE 0 END) AS nullifiers
     FROM temp.v2_stream_actions`,
  ).get();
  if (
    actions.count !== actionSequence ||
    Number(actions.notes ?? 0) !== noteCount ||
    Number(actions.nullifiers ?? 0) !== nullifierCount
  ) {
    fail("stream action kinds differ from canonical note/nullifier counts");
  }
  const noteLeaves = db.prepare(
    "SELECT COUNT(*) AS count,MIN(note_index) AS minimum,MAX(note_index) AS maximum FROM temp.v2_stream_note_leaves",
  ).get();
  if (
    noteLeaves.count !== noteCount ||
    (noteCount !== 0 &&
      (noteLeaves.minimum !== 0 || noteLeaves.maximum !== noteCount - 1))
  ) {
    fail("stream note leaves do not cover the exact append prefix");
  }
  const noteActionMismatch = db.prepare(
    `SELECT COUNT(*) AS count
     FROM temp.v2_stream_note_leaves AS leaf
     LEFT JOIN temp.v2_stream_actions AS action
       ON action.action_sequence=leaf.action_sequence
     WHERE action.action_sequence IS NULL
       OR action.kind='withdrawal'
       OR action.transaction_id<>leaf.transaction_id
       OR action.output_note_leaf<>leaf.leaf_hash
       OR action.encrypted_record<>leaf.encrypted_record`,
  ).get().count;
  if (noteActionMismatch !== 0) {
    fail("stream note leaves differ from their authenticated action packets");
  }
  const noteOrderMismatch = db.prepare(
    `SELECT COUNT(*) AS count
     FROM temp.v2_stream_note_leaves AS current
     JOIN temp.v2_stream_note_leaves AS previous
       ON previous.note_index=current.note_index-1
     WHERE current.action_sequence<=previous.action_sequence`,
  ).get().count;
  if (noteOrderMismatch !== 0) {
    fail("stream note leaves are not in append-time action order");
  }
  const noteTree = validateStagedTree(db, {
    nodeTable: "v2_stream_note_nodes",
    leafTable: "v2_stream_note_leaves",
    leafIndex: "note_index",
    leafHash: "leaf_hash",
    allocatedLeaves: noteCount,
    expectedRoot: snapshot.noteTree.root,
    label: "stream note tree",
  });
  const frontier = db.prepare(
    "SELECT depth,node_hash FROM temp.v2_stream_note_frontier ORDER BY depth",
  ).all();
  const expectedFrontierDepths = [];
  for (let depth = 0; depth < TREE_DEPTH; depth += 1) {
    if (((BigInt(noteCount) >> BigInt(depth)) & 1n) === 1n) {
      expectedFrontierDepths.push(depth);
    }
  }
  if (
    frontier.length !== expectedFrontierDepths.length ||
    frontier.some((entry, index) =>
      entry.depth !== expectedFrontierDepths[index]
    )
  ) {
    fail("stream note frontier shape differs from noteCount");
  }
  for (const entry of frontier) {
    const nodeIndex = Math.floor(noteCount / (2 ** entry.depth)) - 1;
    const node = db.prepare(
      "SELECT node_hash FROM temp.v2_stream_note_nodes WHERE depth=? AND node_index=?",
    ).get(entry.depth, nodeIndex);
    if (!node || !same(node.node_hash, entry.node_hash)) {
      fail("stream note frontier differs from its materialized tree node");
    }
  }
  const allocatedNullifierLeaves = nullifierCount + 2;
  const nullifierLeaves = db.prepare(
    "SELECT COUNT(*) AS count,MIN(physical_index) AS minimum,MAX(physical_index) AS maximum FROM temp.v2_stream_nullifier_leaves",
  ).get();
  if (
    nullifierLeaves.count !== allocatedNullifierLeaves ||
    nullifierLeaves.minimum !== 0 ||
    nullifierLeaves.maximum !== allocatedNullifierLeaves - 1
  ) {
    fail("stream nullifier leaves do not cover the exact physical prefix");
  }
  const typeMismatch = db.prepare(
    `SELECT COUNT(*) AS count FROM temp.v2_stream_nullifier_leaves
     WHERE (physical_index=0 AND leaf_type<>1)
        OR (physical_index=1 AND leaf_type<>3)
        OR (physical_index>=2 AND leaf_type<>2)`,
  ).get().count;
  if (typeMismatch !== 0) {
    fail("stream nullifier sentinel or normal leaf types are invalid");
  }
  const nullifierActionMismatch = db.prepare(
    `SELECT COUNT(*) AS count
     FROM temp.v2_stream_actions AS action
     LEFT JOIN temp.v2_stream_nullifier_leaves AS leaf
       ON leaf.leaf_type=2 AND leaf.key_be=action.public_nullifier
     WHERE action.kind<>'deposit' AND leaf.physical_index IS NULL`,
  ).get().count;
  if (nullifierActionMismatch !== 0) {
    fail("stream nullifier leaves differ from authenticated action packets");
  }
  const nullifierOrderMismatch = db.prepare(
    `SELECT COUNT(*) AS count
     FROM (
       SELECT public_nullifier,
         ROW_NUMBER() OVER (ORDER BY action_sequence)+1 AS physical_index
       FROM temp.v2_stream_actions WHERE kind<>'deposit'
     ) AS action
     LEFT JOIN temp.v2_stream_nullifier_leaves AS leaf
       ON leaf.leaf_type=2 AND leaf.key_be=action.public_nullifier
     WHERE leaf.physical_index<>action.physical_index`,
  ).get().count;
  if (nullifierOrderMismatch !== 0) {
    fail("stream nullifier leaves are not in insertion-time action order");
  }
  const maximum = db.prepare(
    "SELECT physical_index,key_be FROM temp.v2_stream_nullifier_leaves WHERE physical_index=1",
  ).get();
  let previous = db.prepare(
    "SELECT physical_index,key_be,successor_index,successor_key_be FROM temp.v2_stream_nullifier_leaves WHERE physical_index=0",
  ).get();
  for (const current of db.prepare(
    "SELECT physical_index,key_be,successor_index,successor_key_be FROM temp.v2_stream_nullifier_leaves WHERE leaf_type=2 ORDER BY key_be",
  ).iterate()) {
    if (
      previous.successor_index !== current.physical_index ||
      !same(previous.successor_key_be, current.key_be)
    ) {
      fail("stream nullifier successor chain is not exact key order");
    }
    previous = current;
  }
  if (
    previous.successor_index !== maximum.physical_index ||
    !same(previous.successor_key_be, maximum.key_be)
  ) {
    fail("stream nullifier successor chain does not end at maximum sentinel");
  }
  const nullifierTree = validateStagedTree(db, {
    nodeTable: "v2_stream_nullifier_nodes",
    leafTable: "v2_stream_nullifier_leaves",
    leafIndex: "physical_index",
    leafHash: "leaf_hash",
    allocatedLeaves: allocatedNullifierLeaves,
    expectedRoot: snapshot.nullifierTree.root,
    label: "stream nullifier tree",
  });
  return Object.freeze({
    decoded,
    actionSequence,
    noteCount,
    nullifierCount,
    noteTree,
    nullifierTree,
    frontierCount: frontier.length,
  });
}

export class V2DirectStore {
  #db;
  #path;
  #streamInstallActive = false;
  constructor(path) {
    this.#path = ensureTrustedParent(path);
    createCheckedDatabase(this.#path);
    this.#db = new DatabaseSync(this.#path);
    try {
      this.#db.exec(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA temp_store=FILE; PRAGMA cache_size=-8192;",
      );
      const existing = this.#db.prepare(
        "SELECT count(*) AS count FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'",
      ).get().count;
      if (existing !== 0) {
        const metadata = this.#db.prepare(
          "SELECT count(*) AS count FROM sqlite_schema WHERE type='table' AND name='metadata'",
        ).get().count;
        let stored;
        try {
          stored = metadata === 1
            ? this.#db.prepare(
              "SELECT schema_version FROM metadata WHERE singleton=1",
            ).get()
            : undefined;
        } catch {
          fail(
            `store schema is incompatible with required version ${V2_STORE_SCHEMA_VERSION}; automatic migration is not supported`,
          );
        }
        const userVersion = this.#db.prepare("PRAGMA user_version").get()
          .user_version;
        if (
          metadata !== 1 ||
          userVersion !== V2_STORE_SCHEMA_VERSION ||
          (stored !== undefined &&
            stored.schema_version !== V2_STORE_SCHEMA_VERSION)
        ) {
          const found = stored?.schema_version ?? userVersion;
          fail(
            `store schema version ${found} is incompatible with required version ${V2_STORE_SCHEMA_VERSION}; automatic migration is not supported`,
          );
        }
        requireV2SchemaLayout(this.#db);
      } else {
        this.#db.exec(SCHEMA);
        this.#db.exec(`PRAGMA user_version=${V2_STORE_SCHEMA_VERSION}`);
      }
      secureSidecars(this.#path);
    } catch (error) {
      try {
        this.#db.close();
      } catch {}
      this.#db = null;
      secureSidecars(this.#path);
      throw error;
    }
  }
  get path() {
    return this.#path;
  }
  #open() {
    if (!this.#db) fail("store is closed");
    return this.#db;
  }
  #tx(fn) {
    const db = this.#open();
    db.exec("BEGIN IMMEDIATE");
    try {
      const result = fn(db);
      db.exec("COMMIT");
      secureSidecars(this.#path);
      return result;
    } catch (error) {
      try {
        db.exec("ROLLBACK");
      } catch {}
      secureSidecars(this.#path);
      throw error;
    }
  }
  close() {
    if (this.#streamInstallActive) {
      fail("cannot close store during authenticated stream installation");
    }
    if (this.#db) {
      secureSidecars(this.#path);
      this.#db.close();
      this.#db = null;
      secureSidecars(this.#path);
    }
  }
  pragmas() {
    const db = this.#open();
    return Object.freeze({
      journalMode: db.prepare("PRAGMA journal_mode").get().journal_mode,
      synchronous: db.prepare("PRAGMA synchronous").get().synchronous,
      foreignKeys: db.prepare("PRAGMA foreign_keys").get().foreign_keys,
      busyTimeout: db.prepare("PRAGMA busy_timeout").get().timeout,
    });
  }
  initialize(value) {
    const input = exactKeys(value, [
      "profileId",
      "instanceId",
      "networkId",
      "denominationSats",
      "carrierCount",
      "runtimeMaterialsSha256",
      "state",
      "outpoint",
      "actionSequence",
      "height",
      "blockHash",
    ], "initialize");
    const profileId = txid(input.profileId, "initialize.profileId");
    const instanceId = txid(input.instanceId, "initialize.instanceId");
    const network = networkId(input.networkId, "initialize.networkId");
    const denominationSats = canonicalMoneyText(
      input.denominationSats,
      "initialize.denominationSats",
      { nonzero: true },
    );
    const carrierCount = integer(
      input.carrierCount,
      1,
      0xff,
      "initialize.carrierCount",
    );
    const runtimeMaterialsSha256 = bytes(
      input.runtimeMaterialsSha256,
      32,
      "initialize.runtimeMaterialsSha256",
    );
    const initialState = state(input.state, "initialize.state");
    const point = outpoint(input.outpoint, "initialize.outpoint");
    const sequence = integer(
      input.actionSequence,
      0,
      0x1_ffff_ffff,
      "initialize.actionSequence",
    );
    const height = integer(
      input.height,
      0,
      Number.MAX_SAFE_INTEGER,
      "initialize.height",
    );
    const blockHash = txid(input.blockHash, "initialize.blockHash");
    let decodedInitialState;
    let canonicalInitialState;
    try {
      decodedInitialState = decodeStateNftCommitment(initialState, {
        denominationSats,
      });
      canonicalInitialState = encodeStateNftCommitment(
        createDirectV2PoolModel({
          profileId: profileId.toString("hex"),
          maximumLiveNotes: decodedInitialState.maximumLiveNotes,
          denominationSats,
        }).state,
        { denominationSats },
      );
    } catch (error) {
      fail(
        `initialize.state is not a valid V2 genesis: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
    if (
      decodedInitialState.profileId !== profileId.toString("hex")
      || !same(initialState, canonicalInitialState)
      || sequence !== 0
      || decodedInitialState.actionSequence !== "0"
    ) {
      fail(
        "initialize.state must be the exact empty genesis for the bound profile",
      );
    }
    return this.#tx((db) => {
      const current = db.prepare("SELECT * FROM metadata WHERE singleton=1")
        .get();
      if (current !== undefined) {
        if (current.schema_version !== V2_STORE_SCHEMA_VERSION) {
          fail(
            `store schema version ${current.schema_version} is incompatible with required version ${V2_STORE_SCHEMA_VERSION}; automatic migration is not supported`,
          );
        }
        if (
          !same(current.profile_id, profileId) ||
          !same(current.instance_id, instanceId) ||
          current.network_id !== network ||
          current.denomination_sats !== denominationSats ||
          current.carrier_count !== carrierCount ||
          !same(current.runtime_materials_sha256, runtimeMaterialsSha256) ||
          !same(current.genesis_state_bytes, initialState) ||
          !same(current.genesis_txid, point.txid) ||
          current.genesis_vout !== point.vout ||
          current.genesis_sequence !== sequence ||
          current.genesis_height !== height ||
          !same(current.genesis_block_hash, blockHash)
        ) fail("store binding does not match requested profile and instance");
        return this.binding();
      }
      db.prepare(
        "INSERT INTO metadata(singleton,schema_version,profile_id,instance_id,network_id,denomination_sats,carrier_count,runtime_materials_sha256,genesis_state_bytes,genesis_txid,genesis_vout,genesis_sequence,genesis_height,genesis_block_hash) VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?,?)",
      ).run(
        V2_STORE_SCHEMA_VERSION,
        profileId,
        instanceId,
        network,
        denominationSats,
        carrierCount,
        runtimeMaterialsSha256,
        initialState,
        point.txid,
        point.vout,
        sequence,
        height,
        blockHash,
      );
      db.prepare(
        "INSERT INTO canonical_state(singleton,state_bytes,txid,vout,action_sequence,height,block_hash) VALUES(1,?,?,?,?,?,?)",
      ).run(initialState, point.txid, point.vout, sequence, height, blockHash);
      db.prepare(
        "INSERT INTO note_nodes(depth,node_index,node_hash) VALUES(32,0,?)",
      ).run(Buffer.from(decodedInitialState.noteRoot, "hex"));
      const zero = Buffer.alloc(32);
      const sentinels = [
        {
          physicalIndex: 0,
          leafType: V2_NULLIFIER_LEAF_TYPES.minimum,
          key: zero,
          successorIndex: 1,
          successorKey: zero,
        },
        {
          physicalIndex: 1,
          leafType: V2_NULLIFIER_LEAF_TYPES.maximum,
          key: zero,
          successorIndex: 1,
          successorKey: zero,
        },
      ].map((sentinel) => ({
          ...sentinel,
          leafHash: indexedNullifierLeafHash(sentinel),
      }));
      for (const sentinel of sentinels) {
        this.#putLeaf(db, sentinel);
        db.prepare(
          "INSERT INTO nullifier_nodes(depth,node_index,node_hash) VALUES(0,?,?)",
        ).run(sentinel.physicalIndex, sentinel.leafHash);
      }
      let nullifierNode = hashTreePair(
        hashIndexedNullifierNode,
        sentinels[0].leafHash,
        sentinels[1].leafHash,
        "genesis nullifier tree",
      );
      db.prepare(
        "INSERT INTO nullifier_nodes(depth,node_index,node_hash) VALUES(1,0,?)",
      ).run(nullifierNode);
      for (let depth = 1; depth < TREE_DEPTH; depth += 1) {
        nullifierNode = hashTreePair(
          hashIndexedNullifierNode,
          nullifierNode,
          NULLIFIER_DEFAULTS[depth],
          "genesis nullifier tree",
        );
        db.prepare(
          "INSERT INTO nullifier_nodes(depth,node_index,node_hash) VALUES(?,0,?)",
        ).run(depth + 1, nullifierNode);
      }
      if (
        !same(
          nullifierNode,
          Buffer.from(decodedInitialState.nullifierRoot, "hex"),
        )
      ) {
        fail("derived genesis nullifier root differs from initial state");
      }
      return this.binding();
    });
  }
  binding() {
    const row = this.#open().prepare(
      "SELECT schema_version,profile_id,instance_id,network_id,denomination_sats,carrier_count,runtime_materials_sha256 FROM metadata WHERE singleton=1",
    ).get();
    if (!row) fail("store is not initialized");
    if (row.schema_version !== V2_STORE_SCHEMA_VERSION) {
      fail(
        `store schema version ${row.schema_version} is incompatible with required version ${V2_STORE_SCHEMA_VERSION}; automatic migration is not supported`,
      );
    }
    return Object.freeze({
      profileId: copy(row.profile_id),
      instanceId: copy(row.instance_id),
      networkId: row.network_id,
      denominationSats: row.denomination_sats,
      carrierCount: row.carrier_count,
      runtimeMaterialsSha256: copy(row.runtime_materials_sha256),
    });
  }
  genesisAnchor() {
    const row = this.#open().prepare(
      "SELECT genesis_state_bytes,genesis_txid,genesis_vout,genesis_sequence,genesis_height,genesis_block_hash FROM metadata WHERE singleton=1",
    ).get();
    if (!row) fail("store is not initialized");
    return Object.freeze({
      state: copy(row.genesis_state_bytes),
      outpoint: Object.freeze({
        txid: copy(row.genesis_txid),
        vout: row.genesis_vout,
      }),
      actionSequence: row.genesis_sequence,
      height: row.genesis_height,
      blockHash: copy(row.genesis_block_hash),
    });
  }
  assertBinding(value) {
    const input = exactKeys(
      value,
      [
        "profileId",
        "instanceId",
        "networkId",
        "denominationSats",
        "carrierCount",
        "runtimeMaterialsSha256",
      ],
      "binding",
    );
    const bound = this.binding();
    if (
      !same(bound.profileId, txid(input.profileId, "binding.profileId")) ||
      !same(bound.instanceId, txid(input.instanceId, "binding.instanceId")) ||
      bound.networkId !== networkId(input.networkId, "binding.networkId") ||
      bound.denominationSats !== canonicalMoneyText(
        input.denominationSats,
        "binding.denominationSats",
        { nonzero: true },
      ) ||
      bound.carrierCount !== integer(
        input.carrierCount,
        1,
        0xff,
        "binding.carrierCount",
      )
      || !same(
        bound.runtimeMaterialsSha256,
        bytes(
          input.runtimeMaterialsSha256,
          32,
          "binding.runtimeMaterialsSha256",
        ),
      )
    ) fail("store binding does not match requested profile and instance");
    return bound;
  }
  canonicalState() {
    const row = this.#open().prepare(
      "SELECT state_bytes,txid,vout,action_sequence,height,block_hash FROM canonical_state WHERE singleton=1",
    ).get();
    if (!row) fail("store is not initialized");
    return Object.freeze({
      state: copy(row.state_bytes),
      outpoint: Object.freeze({ txid: copy(row.txid), vout: row.vout }),
      actionSequence: row.action_sequence,
      height: row.height,
      blockHash: copy(row.block_hash),
    });
  }
  reconcileAuthenticatedFundingInventory(value) {
    const input = exactKeys(
      value,
      ["canonical", "fundingInventory"],
      "authenticated funding reconciliation",
    );
    const canonical = exactKeys(
      input.canonical,
      [
        "state",
        "outpoint",
        "actionSequence",
        "height",
        "blockHash",
      ],
      "authenticated funding reconciliation.canonical",
    );
    const canonicalOutpoint = outpoint(
      canonical.outpoint,
      "authenticated funding reconciliation.canonical.outpoint",
    );
    const expected = Object.freeze({
      state: bytes(
        canonical.state,
        128,
        "authenticated funding reconciliation.canonical.state",
      ),
      outpoint: canonicalOutpoint,
      actionSequence: integer(
        canonical.actionSequence,
        0,
        Number.MAX_SAFE_INTEGER,
        "authenticated funding reconciliation.canonical.actionSequence",
      ),
      height: integer(
        canonical.height,
        0,
        MAX_U32,
        "authenticated funding reconciliation.canonical.height",
      ),
      blockHash: txid(
        canonical.blockHash,
        "authenticated funding reconciliation.canonical.blockHash",
      ),
    });
    const fundingInventory = validateCanonicalReconciliation({
      canonicalSettlementTxids: [],
      fundingInventory: input.fundingInventory,
    }).fundingInventory;
    return this.#tx((db) => {
      const current = db.prepare(
        "SELECT state_bytes,txid,vout,action_sequence,height,block_hash FROM canonical_state WHERE singleton=1",
      ).get();
      if (
        !current
        || !same(current.state_bytes, expected.state)
        || !same(current.txid, expected.outpoint.txid)
        || current.vout !== expected.outpoint.vout
        || current.action_sequence !== expected.actionSequence
        || current.height !== expected.height
        || !same(current.block_hash, expected.blockHash)
      ) {
        fail(
          "authenticated funding inventory does not bind the exact durable canonical tip",
        );
      }
      const activity = db.prepare(
        `SELECT
          EXISTS(
            SELECT 1 FROM funding_utxos
            WHERE reservation_operation_id IS NOT NULL
          ) AS funding_reservations,
          EXISTS(
            SELECT 1 FROM pending_operations
            WHERE journal_state NOT IN(
              'needs_reproof','conflicted','reorged','abandoned','settled'
            )
          ) AS active_operations`,
      ).get();
      if (activity.funding_reservations || activity.active_operations) {
        fail(
          "authenticated funding reconciliation requires no active operation or reserved funding UTXO",
        );
      }
      db.prepare("DELETE FROM funding_utxos").run();
      const insert = db.prepare(
        `INSERT INTO funding_utxos(
          txid,vout,value_sats,reservation_operation_id,spent
        ) VALUES(?,?,?,NULL,0)`,
      );
      for (const entry of fundingInventory) {
        insert.run(entry.txid, entry.vout, entry.valueSats);
      }
      return Object.freeze(fundingInventory.map((entry) =>
        Object.freeze({
          txid: copy(entry.txid),
          vout: entry.vout,
          valueSats: entry.valueSats,
        })
      ));
    });
  }
  recoveryCheckpoint() {
    const row = this.#open().prepare(
      "SELECT content_sha256,history_sha256,action_count,note_count,nullifier_count,external_authentication_boundary FROM recovery_checkpoint WHERE singleton=1",
    ).get();
    return row === undefined
      ? null
      : Object.freeze({
        contentSha256: copy(row.content_sha256),
        historySha256: copy(row.history_sha256),
        actionCount: row.action_count,
        noteCount: row.note_count,
        nullifierCount: row.nullifier_count,
        externalAuthenticationBoundary:
          row.external_authentication_boundary,
      });
  }
  recoveryAction(actionSequence) {
    const sequence = integer(
      actionSequence,
      1,
      0x1_ffff_ffff,
      "recovery action sequence",
    );
    const row = this.#open().prepare(
      "SELECT action_sequence,transaction_id,height,block_hash,kind,packet_bytes,transaction_context_hash,output_note_leaf,encrypted_record,public_nullifier FROM recovery_actions WHERE action_sequence=?",
    ).get(sequence);
    return row === undefined
      ? null
      : Object.freeze({
        actionSequence: row.action_sequence,
        transactionId: copy(row.transaction_id),
        height: row.height,
        blockHash: copy(row.block_hash),
        kind: row.kind,
        packet: copy(row.packet_bytes),
        transactionContextHash: copy(row.transaction_context_hash),
        outputNoteLeaf: row.output_note_leaf === null
          ? null
          : copy(row.output_note_leaf),
        encryptedRecord: row.encrypted_record === null
          ? null
          : copy(row.encrypted_record),
        publicNullifier: row.public_nullifier === null
          ? null
          : copy(row.public_nullifier),
      });
  }

  #reconcileCanonicalReplacement(db, reconciliation, actionSequence) {
    if (
      reconciliation.canonicalSettlementTxids.length !== actionSequence
    ) {
      fail(
        "authenticated canonical settlement transaction IDs do not cover the exact action sequence",
      );
    }
    db.prepare("DELETE FROM undo_records").run();
    db.prepare("DELETE FROM mempool_overlay").run();
    db.prepare(
      "UPDATE owned_notes SET reservation_operation_id=NULL WHERE reservation_operation_id IS NOT NULL",
    ).run();
    db.prepare(
      "UPDATE funding_utxos SET reservation_operation_id=NULL WHERE reservation_operation_id IS NOT NULL",
    ).run();

    const operations = db.prepare(
      `SELECT p.*,i.kind AS intent_kind,i.target_type,i.target_bytes,
        i.selected_note_id,i.funding_raw_transaction,i.funding_txid,
        i.funding_vout,i.funding_value_sats,i.funding_locking_bytecode,
        i.funding_compressed_public_key,i.change_locking_bytecode,
        i.fee_rate_sats_per_byte,i.maximum_fee_sats,i.retry_count
       FROM pending_operations AS p
       JOIN operation_intents AS i ON i.operation_id=p.operation_id
       ORDER BY p.operation_id`,
    ).all();
    const now = Date.now();
    for (const row of operations) {
      if (["abandoned", "conflicted"].includes(row.journal_state)) continue;
      let canonical = false;
      if (row.signed_tx_bytes !== null) {
        const inspected = this.#inspectSignedOperation(row);
        canonical = reconciliation.canonicalSettlementTxidSet.has(
          inspected.signed.txid,
        );
      }
      if (canonical) {
        db.prepare(
          `UPDATE pending_operations
           SET journal_state=?,reason=NULL,updated_at_ms=?
           WHERE operation_id=?`,
        ).run(
          row.journal_state === "settled" ? "settled" : "confirmed",
          now,
          row.operation_id,
        );
      } else {
        db.prepare(
          `UPDATE pending_operations
           SET journal_state='reorged',
             reason='operation absent from authenticated canonical history',
             updated_at_ms=?
           WHERE operation_id=?`,
        ).run(now, row.operation_id);
      }
    }

    db.prepare("DELETE FROM funding_utxos").run();
    const insertFunding = db.prepare(
      `INSERT INTO funding_utxos(
        txid,vout,value_sats,reservation_operation_id,spent
      ) VALUES(?,?,?,NULL,0)`,
    );
    for (const entry of reconciliation.fundingInventory) {
      insertFunding.run(entry.txid, entry.vout, entry.valueSats);
    }
  }

  /**
   * Atomically installs terminal tree material which a caller has already
   * authenticated against a canonical chain tip. This method validates exact
   * store binding and materialized-store consistency; it does not establish
   * block inclusion, unspent status, snapshot authority, or historical action
   * validity, and intentionally does not rehash already-authenticated internal
   * node relations.
   */
  installAuthenticatedSnapshot(value) {
    const snapshot = validateAuthenticatedSnapshot(value);
    return this.#installAuthenticatedSnapshot(snapshot, null);
  }

  reconcileAuthenticatedCanonicalSnapshot(value) {
    const input = exactKeys(value, [
      "snapshot",
      "canonicalSettlementTxids",
      "fundingInventory",
      "crashAt",
    ], "authenticated canonical snapshot reconciliation");
    const snapshot = validateAuthenticatedSnapshot(input.snapshot);
    if (snapshot.crashAt !== input.crashAt) {
      fail(
        "authenticated canonical reconciliation crashAt must equal snapshot.crashAt",
      );
    }
    const reconciliation = validateCanonicalReconciliation({
      canonicalSettlementTxids: input.canonicalSettlementTxids,
      fundingInventory: input.fundingInventory,
    });
    if (
      reconciliation.canonicalSettlementTxids.length
        !== snapshot.canonical.actionSequence
      || (
        snapshot.canonical.actionSequence > 0
        && !same(
          reconciliation.canonicalSettlementTxids[
            snapshot.canonical.actionSequence - 1
          ],
          snapshot.canonical.outpoint.txid,
        )
      )
    ) {
      fail(
        "authenticated canonical settlement transaction IDs do not bind the replacement tip",
      );
    }
    return this.#installAuthenticatedSnapshot(snapshot, reconciliation);
  }

  #installAuthenticatedSnapshot(snapshot, reconciliation) {
    this.assertBinding(snapshot.binding);
    const decoded = this.#decodeBoundState(
      snapshot.canonical.state,
      "authenticated snapshot canonical state",
    );
    const actionSequence = Number(decoded.actionSequence);
    const noteCount = Number(decoded.noteCount);
    const nullifierCount = Number(decoded.nullifierCount);
    if (snapshot.canonical.actionSequence !== actionSequence) {
      fail(
        "authenticated snapshot canonical actionSequence differs from its state",
      );
    }
    const noteRoot = Buffer.from(decoded.noteRoot, "hex");
    const nullifierRoot = Buffer.from(decoded.nullifierRoot, "hex");
    validateSnapshotNoteMaterial({
      nodes: snapshot.noteNodes,
      frontier: snapshot.noteFrontier,
      leaves: snapshot.noteLeaves,
      noteCount,
      actionSequence,
      expectedRoot: noteRoot,
    });
    validateSnapshotNullifierMaterial({
      nodes: snapshot.nullifierNodes,
      leaves: snapshot.nullifierLeaves,
      nullifierCount,
      expectedRoot: nullifierRoot,
    });
    const noteNodes = [...snapshot.noteNodes].sort((left, right) =>
      left.depth - right.depth || left.nodeIndex - right.nodeIndex
    );
    const noteFrontier = [...snapshot.noteFrontier].sort((left, right) =>
      left.depth - right.depth
    );
    const nullifierNodes = [...snapshot.nullifierNodes].sort((left, right) =>
      left.depth - right.depth || left.nodeIndex - right.nodeIndex
    );
    const nullifierLeaves = [...snapshot.nullifierLeaves].sort((left, right) =>
      left.physicalIndex - right.physicalIndex
    );
    return this.#tx((db) => {
      this.assertBinding(snapshot.binding);
      const metadata = db.prepare(
        "SELECT genesis_state_bytes,genesis_txid,genesis_vout,genesis_sequence,genesis_height,genesis_block_hash FROM metadata WHERE singleton=1",
      ).get();
      if (!metadata) fail("store is not initialized");
      let genesis;
      try {
        genesis = decodeStateNftCommitment(metadata.genesis_state_bytes, {
          denominationSats: snapshot.binding.denominationSats,
        });
      } catch (error) {
        fail(
          `stored genesis state is invalid: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
      }
      if (
        decoded.maximumLiveNotes !== genesis.maximumLiveNotes ||
        snapshot.canonical.height < metadata.genesis_height
      ) {
        fail(
          "authenticated snapshot canonical state is outside the bound genesis lineage",
        );
      }
      if (
        actionSequence === 0 &&
        (!same(snapshot.canonical.state, metadata.genesis_state_bytes) ||
          !same(snapshot.canonical.outpoint.txid, metadata.genesis_txid) ||
          snapshot.canonical.outpoint.vout !== metadata.genesis_vout ||
          snapshot.canonical.actionSequence !== metadata.genesis_sequence ||
          snapshot.canonical.height !== metadata.genesis_height ||
          !same(snapshot.canonical.blockHash, metadata.genesis_block_hash))
      ) {
        fail(
          "zero-sequence authenticated snapshot must be the exact bound genesis",
        );
      }
      const activity = db.prepare(
        `SELECT
          EXISTS(
            SELECT 1 FROM pending_operations
            WHERE journal_state NOT IN(
              'needs_reproof','conflicted','reorged','abandoned','settled'
            )
          ) AS operations,
          EXISTS(SELECT 1 FROM owned_notes WHERE reservation_operation_id IS NOT NULL) AS note_reservations,
          EXISTS(SELECT 1 FROM funding_utxos WHERE reservation_operation_id IS NOT NULL) AS funding_reservations,
          EXISTS(SELECT 1 FROM mempool_overlay) AS overlays`,
      ).get();
      if (
        reconciliation === null
        && (
          activity.operations || activity.note_reservations ||
          activity.funding_reservations || activity.overlays
        )
      ) {
        fail(
          "authenticated snapshot install requires no pending operations, reservations, or mempool overlay",
        );
      }
      crash(snapshot.crashAt, "snapshot.before_mutation");

      replaceSnapshotTable({
        db,
        deleteSql: "DELETE FROM note_nodes",
        insertSql:
          "INSERT INTO note_nodes(depth,node_index,node_hash) VALUES(?,?,?)",
        rows: noteNodes,
        values: (node) => [node.depth, node.nodeIndex, node.nodeHash],
        crashAt: snapshot.crashAt,
        crashStage: "snapshot.during_note_nodes",
      });
      replaceSnapshotTable({
        db,
        deleteSql: "DELETE FROM note_frontier",
        insertSql:
          "INSERT INTO note_frontier(depth,node_hash) VALUES(?,?)",
        rows: noteFrontier,
        values: (entry) => [entry.depth, entry.nodeHash],
        crashAt: snapshot.crashAt,
        crashStage: "snapshot.during_note_frontier",
      });
      replaceSnapshotTable({
        db,
        deleteSql: "DELETE FROM note_leaves",
        insertSql:
          "INSERT INTO note_leaves(note_index,leaf_hash,encrypted_record,action_sequence,transaction_id) VALUES(?,?,?,?,?)",
        rows: snapshot.noteLeaves,
        values: (leaf) => [
          leaf.noteIndex,
          leaf.leafHash,
          leaf.encryptedRecord,
          leaf.actionSequence,
          leaf.transactionId,
        ],
        crashAt: snapshot.crashAt,
        crashStage: "snapshot.during_note_leaves",
      });
      replaceSnapshotTable({
        db,
        deleteSql: "DELETE FROM nullifier_nodes",
        insertSql:
          "INSERT INTO nullifier_nodes(depth,node_index,node_hash) VALUES(?,?,?)",
        rows: nullifierNodes,
        values: (node) => [node.depth, node.nodeIndex, node.nodeHash],
        crashAt: snapshot.crashAt,
        crashStage: "snapshot.during_nullifier_nodes",
      });
      db.exec("DELETE FROM nullifier_leaves");
      replaceSnapshotTable({
        db,
        deleteSql: "DELETE FROM nullifier_order_keys",
        insertSql:
          "INSERT INTO nullifier_order_keys(leaf_type,key_be,physical_index) VALUES(?,?,?)",
        rows: nullifierLeaves,
        values: (leaf) => [leaf.leafType, leaf.key, leaf.physicalIndex],
        crashAt: snapshot.crashAt,
        crashStage: "snapshot.during_nullifier_order",
      });
      replaceSnapshotTable({
        db,
        deleteSql: "DELETE FROM nullifier_leaves",
        insertSql:
          "INSERT INTO nullifier_leaves(physical_index,leaf_type,leaf_hash,key_be,successor_index,successor_key_be) VALUES(?,?,?,?,?,?)",
        rows: nullifierLeaves,
        values: (leaf) => [
          leaf.physicalIndex,
          leaf.leafType,
          leaf.leafHash,
          leaf.key,
          leaf.successorIndex,
          leaf.successorKey,
        ],
        crashAt: snapshot.crashAt,
        crashStage: "snapshot.during_nullifier_leaves",
      });
      const installed = db.prepare(
        `SELECT
          (SELECT COUNT(*) FROM note_nodes) AS note_nodes,
          (SELECT COUNT(*) FROM note_frontier) AS note_frontier,
          (SELECT COUNT(*) FROM note_leaves) AS note_leaves,
          (SELECT COUNT(*) FROM nullifier_nodes) AS nullifier_nodes,
          (SELECT COUNT(*) FROM nullifier_order_keys) AS nullifier_order,
          (SELECT COUNT(*) FROM nullifier_leaves) AS nullifier_leaves`,
      ).get();
      if (
        installed.note_nodes !== noteNodes.length ||
        installed.note_frontier !== noteFrontier.length ||
        installed.note_leaves !== snapshot.noteLeaves.length ||
        installed.nullifier_nodes !== nullifierNodes.length ||
        installed.nullifier_order !== nullifierLeaves.length ||
        installed.nullifier_leaves !== nullifierLeaves.length
      ) fail("authenticated snapshot installed table counts differ");

      if (reconciliation !== null) {
        this.#reconcileCanonicalReplacement(
          db,
          reconciliation,
          actionSequence,
        );
      }
      crash(snapshot.crashAt, "snapshot.before_canonical_state");
      const switched = db.prepare(
        "UPDATE canonical_state SET state_bytes=?,txid=?,vout=?,action_sequence=?,height=?,block_hash=? WHERE singleton=1",
      ).run(
        snapshot.canonical.state,
        snapshot.canonical.outpoint.txid,
        snapshot.canonical.outpoint.vout,
        snapshot.canonical.actionSequence,
        snapshot.canonical.height,
        snapshot.canonical.blockHash,
      );
      if (switched.changes !== 1) {
        fail("authenticated snapshot canonical-state switch failed");
      }
      crash(snapshot.crashAt, "snapshot.before_commit");
      return Object.freeze({
        canonical: Object.freeze({
          state: copy(snapshot.canonical.state),
          outpoint: Object.freeze({
            txid: copy(snapshot.canonical.outpoint.txid),
            vout: snapshot.canonical.outpoint.vout,
          }),
          actionSequence: snapshot.canonical.actionSequence,
          height: snapshot.canonical.height,
          blockHash: copy(snapshot.canonical.blockHash),
        }),
        note: Object.freeze({
          nodeCount: installed.note_nodes,
          frontierCount: installed.note_frontier,
          leafCount: installed.note_leaves,
          root: copy(noteRoot),
        }),
        nullifier: Object.freeze({
          nodeCount: installed.nullifier_nodes,
          leafCount: installed.nullifier_leaves,
          orderKeyCount: installed.nullifier_order,
          root: copy(nullifierRoot),
        }),
      });
    });
  }
  /**
   * Incrementally stages one already-authenticated recovery stream in SQLite's
   * file-backed TEMP database. Live canonical tables are replaced in one short
   * transaction only after the iterator yields its authenticated end frame.
   * A producer error, early EOF, trailing frame, validation failure, crash
   * injection, or process interruption leaves the live checkpoint unchanged.
   */
  async installAuthenticatedSnapshotStream(value) {
    const input = exactKeys(value, [
      "authenticateTerminal",
      "frames",
      "fundingInventory",
      "recoverOwnedNote",
      "crashAt",
    ], "authenticated snapshot stream");
    const validatedFunding = validateCanonicalReconciliation({
      canonicalSettlementTxids: [],
      fundingInventory: input.fundingInventory,
    }).fundingInventory;
    const frames = input.frames;
    if (
      frames === null ||
      (
        typeof frames?.[Symbol.iterator] !== "function" &&
        typeof frames?.[Symbol.asyncIterator] !== "function"
      )
    ) {
      fail("authenticated snapshot stream.frames must be iterable");
    }
    if (
      input.recoverOwnedNote !== null &&
      typeof input.recoverOwnedNote !== "function"
    ) {
      fail(
        "authenticated snapshot stream.recoverOwnedNote must be a function or null",
      );
    }
    if (
      input.authenticateTerminal !== null &&
      typeof input.authenticateTerminal !== "function"
    ) {
      fail(
        "authenticated snapshot stream.authenticateTerminal must be a function or null",
      );
    }
    if (
      input.crashAt !== null &&
      !V2_AUTHENTICATED_STREAM_CRASH_STAGES.includes(input.crashAt)
    ) {
      fail("authenticated snapshot stream.crashAt is unsupported");
    }
    if (this.#streamInstallActive) {
      fail("an authenticated snapshot stream installation is already active");
    }
    const db = this.#open();
    this.#streamInstallActive = true;
    let counts = null;
    let snapshotFrame = null;
    let terminal = null;
    let expectedPreState = null;
    let previousAction = null;
    const positions = {
      action: 0,
      noteNode: 0,
      noteFrontier: 0,
      noteLeaf: 0,
      nullifierNode: 0,
      nullifierLeaf: 0,
    };
    const phases = [
      ["action", "action"],
      ["note-node", "noteNode"],
      ["note-frontier", "noteFrontier"],
      ["note-leaf", "noteLeaf"],
      ["nullifier-node", "nullifierNode"],
      ["nullifier-leaf", "nullifierLeaf"],
    ];
    const advancePhase = () => {
      for (const phase of phases) {
        if (positions[phase[1]] < counts[phase[1]]) return phase;
      }
      return null;
    };
    try {
      db.exec(STREAM_STAGE_SCHEMA);
      const insertAction = db.prepare(
        "INSERT INTO temp.v2_stream_actions(action_sequence,transaction_id,height,block_hash,kind,packet_bytes,transaction_context_hash,output_note_leaf,encrypted_record,public_nullifier) VALUES(?,?,?,?,?,?,?,?,?,?)",
      );
      const insertNoteNode = db.prepare(
        "INSERT INTO temp.v2_stream_note_nodes(depth,node_index,node_hash) VALUES(?,?,?)",
      );
      const insertFrontier = db.prepare(
        "INSERT INTO temp.v2_stream_note_frontier(depth,node_hash) VALUES(?,?)",
      );
      const insertNoteLeaf = db.prepare(
        "INSERT INTO temp.v2_stream_note_leaves(note_index,leaf_hash,encrypted_record,action_sequence,transaction_id) VALUES(?,?,?,?,?)",
      );
      const insertNullifierNode = db.prepare(
        "INSERT INTO temp.v2_stream_nullifier_nodes(depth,node_index,node_hash) VALUES(?,?,?)",
      );
      const insertNullifierLeaf = db.prepare(
        "INSERT INTO temp.v2_stream_nullifier_leaves(physical_index,leaf_type,leaf_hash,key_be,successor_index,successor_key_be) VALUES(?,?,?,?,?,?)",
      );
      const insertOwnedNote = db.prepare(
        "INSERT INTO temp.v2_stream_owned_notes(note_id,record_id,note_index,record_bytes,nullifier_key) VALUES(?,?,?,?,?)",
      );
      for await (const frame of frames) {
        if (terminal !== null) {
          fail("authenticated snapshot stream has trailing frames");
        }
        if (counts === null) {
          counts = validateStreamHeader(frame);
          crash(input.crashAt, "stream.after_header");
          continue;
        }
        if (snapshotFrame === null) {
          snapshotFrame = validateStreamSnapshotFrame(frame, counts);
          this.assertBinding(snapshotFrame.binding);
          const metadata = db.prepare(
            "SELECT genesis_state_bytes,genesis_txid,genesis_vout,genesis_sequence,genesis_height,genesis_block_hash FROM metadata WHERE singleton=1",
          ).get();
          if (
            !metadata ||
            !same(
              snapshotFrame.snapshot.genesis.state,
              metadata.genesis_state_bytes,
            ) ||
            !same(
              snapshotFrame.snapshot.genesis.transactionId,
              metadata.genesis_txid,
            ) ||
            snapshotFrame.snapshot.genesis.outputIndex !==
              metadata.genesis_vout ||
            snapshotFrame.snapshot.genesis.height !==
              metadata.genesis_height ||
            !same(
              snapshotFrame.snapshot.genesis.blockHash,
              metadata.genesis_block_hash,
            ) ||
            metadata.genesis_sequence !== 0
          ) {
            fail(
              "authenticated stream genesis differs from the bound store genesis",
            );
          }
          expectedPreState = copy(metadata.genesis_state_bytes);
          continue;
        }
        const phase = advancePhase();
        if (phase === null) {
          terminal = validateStreamEnd(frame, counts);
          const expectedFrameCount = 2 +
            Object.values(counts).reduce((sum, count) => sum + count, 0);
          if (terminal.frameCount !== expectedFrameCount) {
            fail(
              "authenticated snapshot stream end frame count is not exact",
            );
          }
          crash(input.crashAt, "stream.after_end");
          continue;
        }
        const [type, countKey] = phase;
        const index = positions[countKey];
        const record = validateStreamRecordEnvelope(frame, type, index);
        if (type === "action") {
          const action = validateStreamAction(
            record,
            index,
            snapshotFrame.binding,
            expectedPreState,
          );
          if (
            previousAction !== null &&
            (
              action.height < previousAction.height ||
              (
                action.height === previousAction.height &&
                !same(action.blockHash, previousAction.blockHash)
              )
            )
          ) {
            fail("authenticated stream action chain is not in best-chain order");
          }
          insertAction.run(
            action.actionSequence,
            action.transactionId,
            action.height,
            action.blockHash,
            action.kind,
            action.packetBytes,
            action.transactionContextHash,
            action.outputNoteLeaf,
            action.encryptedRecord,
            action.publicNullifier,
          );
          expectedPreState = action.postState;
          previousAction = action;
          crash(input.crashAt, "stream.during_actions");
        } else if (type === "note-node") {
          const node = validateSnapshotNode(
            record,
            `stream note-node[${index}]`,
          );
          insertNoteNode.run(node.depth, node.nodeIndex, node.nodeHash);
          crash(input.crashAt, "stream.during_note_nodes");
        } else if (type === "note-frontier") {
          const frontier = validateSnapshotFrontier(
            record,
            `stream note-frontier[${index}]`,
          );
          insertFrontier.run(frontier.depth, frontier.nodeHash);
          crash(input.crashAt, "stream.during_note_frontier");
        } else if (type === "note-leaf") {
          const leaf = validateSnapshotNoteLeaf(
            record,
            `stream note-leaf[${index}]`,
          );
          if (leaf.noteIndex !== index) {
            fail("stream note leaves do not cover the exact append prefix");
          }
          insertNoteLeaf.run(
            leaf.noteIndex,
            leaf.leafHash,
            leaf.encryptedRecord,
            leaf.actionSequence,
            leaf.transactionId,
          );
          if (input.recoverOwnedNote !== null) {
            const owned = validateRecoveredOwnedNote(
              input.recoverOwnedNote(Object.freeze({
                noteIndex: leaf.noteIndex,
                outputNoteLeaf: copy(leaf.leafHash),
                encryptedRecord: copy(leaf.encryptedRecord),
                actionSequence: leaf.actionSequence,
                transactionId: copy(leaf.transactionId),
              })),
              leaf,
              `stream recovered note[${index}]`,
            );
            if (owned !== null) {
              insertOwnedNote.run(
                owned.noteId,
                owned.recordId,
                owned.noteIndex,
                owned.record,
                owned.nullifier,
              );
            }
          }
          crash(input.crashAt, "stream.during_note_leaves");
        } else if (type === "nullifier-node") {
          const node = validateSnapshotNode(
            record,
            `stream nullifier-node[${index}]`,
          );
          insertNullifierNode.run(node.depth, node.nodeIndex, node.nodeHash);
          crash(input.crashAt, "stream.during_nullifier_nodes");
        } else {
          const leaf = validateLeaf(
            record,
            `stream nullifier-leaf[${index}]`,
          );
          if (leaf.physicalIndex !== index) {
            fail(
              "stream nullifier leaves do not cover the exact physical prefix",
            );
          }
          insertNullifierLeaf.run(
            leaf.physicalIndex,
            leaf.leafType,
            leaf.leafHash,
            leaf.key,
            leaf.successorIndex,
            leaf.successorKey,
          );
          crash(input.crashAt, "stream.during_nullifier_leaves");
        }
        positions[countKey] += 1;
      }
      if (counts === null || snapshotFrame === null || terminal === null) {
        fail("authenticated snapshot stream ended before its verified end frame");
      }
      if (
        advancePhase() !== null ||
        !same(expectedPreState, snapshotFrame.canonical.state) ||
        (
          counts.action === 0 &&
          (
            !same(
              snapshotFrame.canonical.outpoint.txid,
              snapshotFrame.snapshot.genesis.transactionId,
            ) ||
            snapshotFrame.canonical.outpoint.vout !==
              snapshotFrame.snapshot.genesis.outputIndex
          )
        ) ||
        (
          counts.action !== 0 &&
          (
            !same(
              snapshotFrame.canonical.outpoint.txid,
              previousAction.transactionId,
            ) ||
            snapshotFrame.canonical.outpoint.vout !== 0 ||
            snapshotFrame.canonical.height < previousAction.height ||
            (
              snapshotFrame.canonical.height === previousAction.height &&
              !same(
                snapshotFrame.canonical.blockHash,
                previousAction.blockHash,
              )
            )
          )
        )
      ) {
        fail(
          "authenticated snapshot stream action lineage does not end at its canonical tip",
        );
      }
      const staged = validateStagedMaterial(db, snapshotFrame);
      if (input.authenticateTerminal !== null) {
        const authenticated = await input.authenticateTerminal(Object.freeze({
          snapshot: snapshotFrame.snapshot.raw,
          canonical: Object.freeze({
            state: copy(snapshotFrame.canonical.state),
            outpoint: Object.freeze({
              txid: copy(snapshotFrame.canonical.outpoint.txid),
              vout: snapshotFrame.canonical.outpoint.vout,
            }),
            actionSequence: snapshotFrame.canonical.actionSequence,
            height: snapshotFrame.canonical.height,
            blockHash: copy(snapshotFrame.canonical.blockHash),
          }),
          fundingInventory: validatedFunding,
        }));
        if (authenticated !== true) {
          fail(
            "authenticated snapshot stream terminal authentication did not return true",
          );
        }
      }
      crash(input.crashAt, "stream.before_live_mutation");
      const installed = this.#tx((transaction) => {
        this.assertBinding(snapshotFrame.binding);
        const metadata = transaction.prepare(
          "SELECT genesis_state_bytes,genesis_height FROM metadata WHERE singleton=1",
        ).get();
        if (
          !metadata ||
          staged.decoded.maximumLiveNotes !==
            decodeStateNftCommitment(metadata.genesis_state_bytes, {
              denominationSats: snapshotFrame.binding.denominationSats,
            }).maximumLiveNotes ||
          snapshotFrame.canonical.height < metadata.genesis_height
        ) {
          fail(
            "authenticated stream canonical state is outside the bound genesis lineage",
          );
        }
        transaction.exec(`
          DELETE FROM owned_notes;
          DELETE FROM encrypted_note_records;
          DELETE FROM note_nodes;
          DELETE FROM note_frontier;
          DELETE FROM note_leaves;
          DELETE FROM nullifier_leaves;
          DELETE FROM nullifier_order_keys;
          DELETE FROM nullifier_nodes;
          DELETE FROM recovery_actions;
          DELETE FROM recovery_checkpoint;
          INSERT INTO note_nodes(depth,node_index,node_hash)
            SELECT depth,node_index,node_hash FROM temp.v2_stream_note_nodes;
          INSERT INTO note_frontier(depth,node_hash)
            SELECT depth,node_hash FROM temp.v2_stream_note_frontier;
          INSERT INTO note_leaves(note_index,leaf_hash,encrypted_record,action_sequence,transaction_id)
            SELECT note_index,leaf_hash,encrypted_record,action_sequence,transaction_id FROM temp.v2_stream_note_leaves;
        `);
        crash(input.crashAt, "stream.during_live_copy");
        transaction.exec(`
          INSERT INTO nullifier_nodes(depth,node_index,node_hash)
            SELECT depth,node_index,node_hash FROM temp.v2_stream_nullifier_nodes;
          INSERT INTO nullifier_order_keys(leaf_type,key_be,physical_index)
            SELECT leaf_type,key_be,physical_index FROM temp.v2_stream_nullifier_leaves;
          INSERT INTO nullifier_leaves(physical_index,leaf_type,leaf_hash,key_be,successor_index,successor_key_be)
            SELECT physical_index,leaf_type,leaf_hash,key_be,successor_index,successor_key_be FROM temp.v2_stream_nullifier_leaves;
          INSERT INTO encrypted_note_records(record_id,record_bytes)
            SELECT record_id,record_bytes FROM temp.v2_stream_owned_notes;
          INSERT INTO owned_notes(note_id,record_id,note_index,nullifier_key,reservation_operation_id,spent)
            SELECT owned.note_id,owned.record_id,owned.note_index,
              owned.nullifier_key,NULL,
              CASE WHEN EXISTS(
                SELECT 1 FROM temp.v2_stream_nullifier_leaves AS leaf
                WHERE leaf.leaf_type=2 AND leaf.key_be=owned.nullifier_key
              ) THEN 1 ELSE 0 END
            FROM temp.v2_stream_owned_notes AS owned;
          INSERT INTO recovery_actions(action_sequence,transaction_id,height,block_hash,kind,packet_bytes,transaction_context_hash,output_note_leaf,encrypted_record,public_nullifier)
            SELECT action_sequence,transaction_id,height,block_hash,kind,packet_bytes,transaction_context_hash,output_note_leaf,encrypted_record,public_nullifier
            FROM temp.v2_stream_actions;
        `);
        transaction.prepare(
          "INSERT INTO recovery_checkpoint(singleton,content_sha256,history_sha256,action_count,note_count,nullifier_count,external_authentication_boundary) VALUES(1,?,?,?,?,?,?)",
        ).run(
          snapshotFrame.snapshot.contentSha256,
          snapshotFrame.snapshot.historySha256,
          staged.actionSequence,
          staged.noteCount,
          staged.nullifierCount,
          snapshotFrame.snapshot.externalAuthenticationBoundary,
        );
        const tableCounts = transaction.prepare(
          `SELECT
            (SELECT COUNT(*) FROM note_nodes) AS note_nodes,
            (SELECT COUNT(*) FROM note_frontier) AS note_frontier,
            (SELECT COUNT(*) FROM note_leaves) AS note_leaves,
            (SELECT COUNT(*) FROM nullifier_nodes) AS nullifier_nodes,
            (SELECT COUNT(*) FROM nullifier_order_keys) AS nullifier_order,
            (SELECT COUNT(*) FROM nullifier_leaves) AS nullifier_leaves,
            (SELECT COUNT(*) FROM recovery_actions) AS actions,
            (SELECT COUNT(*) FROM owned_notes) AS owned_notes`,
        ).get();
        if (
          tableCounts.note_nodes !== counts.noteNode ||
          tableCounts.note_frontier !== counts.noteFrontier ||
          tableCounts.note_leaves !== counts.noteLeaf ||
          tableCounts.nullifier_nodes !== counts.nullifierNode ||
          tableCounts.nullifier_order !== counts.nullifierLeaf ||
          tableCounts.nullifier_leaves !== counts.nullifierLeaf ||
          tableCounts.actions !== counts.action
        ) {
          fail("authenticated stream installed table counts differ");
        }
        const canonicalSettlementTxids = transaction.prepare(
          `SELECT transaction_id
           FROM recovery_actions
           ORDER BY action_sequence`,
        ).all().map((row) => row.transaction_id);
        const reconciliation = validateCanonicalReconciliation({
          canonicalSettlementTxids,
          fundingInventory: validatedFunding,
        });
        if (
          reconciliation.canonicalSettlementTxids.length
            !== snapshotFrame.canonical.actionSequence
          || (
            snapshotFrame.canonical.actionSequence > 0
            && !same(
              reconciliation.canonicalSettlementTxids[
                snapshotFrame.canonical.actionSequence - 1
              ],
              snapshotFrame.canonical.outpoint.txid,
            )
          )
        ) {
          fail(
            "authenticated stream action transactions do not bind the replacement tip",
          );
        }
        this.#reconcileCanonicalReplacement(
          transaction,
          reconciliation,
          snapshotFrame.canonical.actionSequence,
        );
        crash(input.crashAt, "stream.before_canonical_state");
        if (transaction.prepare(
          "UPDATE canonical_state SET state_bytes=?,txid=?,vout=?,action_sequence=?,height=?,block_hash=? WHERE singleton=1",
        ).run(
          snapshotFrame.canonical.state,
          snapshotFrame.canonical.outpoint.txid,
          snapshotFrame.canonical.outpoint.vout,
          snapshotFrame.canonical.actionSequence,
          snapshotFrame.canonical.height,
          snapshotFrame.canonical.blockHash,
        ).changes !== 1) {
          fail("authenticated stream canonical-state switch failed");
        }
        crash(input.crashAt, "stream.before_commit");
        return Object.freeze({
          canonical: Object.freeze({
            state: copy(snapshotFrame.canonical.state),
            outpoint: Object.freeze({
              txid: copy(snapshotFrame.canonical.outpoint.txid),
              vout: snapshotFrame.canonical.outpoint.vout,
            }),
            actionSequence: snapshotFrame.canonical.actionSequence,
            height: snapshotFrame.canonical.height,
            blockHash: copy(snapshotFrame.canonical.blockHash),
          }),
          note: Object.freeze({
            nodeCount: tableCounts.note_nodes,
            frontierCount: tableCounts.note_frontier,
            leafCount: tableCounts.note_leaves,
            root: copy(staged.noteTree.root),
          }),
          nullifier: Object.freeze({
            nodeCount: tableCounts.nullifier_nodes,
            leafCount: tableCounts.nullifier_leaves,
            orderKeyCount: tableCounts.nullifier_order,
            root: copy(staged.nullifierTree.root),
          }),
          actionCount: tableCounts.actions,
          ownedNoteCount: tableCounts.owned_notes,
          snapshot: snapshotFrame.snapshot.raw,
          streamDigest: terminal.digest.toString("hex"),
        });
      });
      return installed;
    } finally {
      try {
        if (this.#db) db.exec(DROP_STREAM_STAGE);
      } finally {
        this.#streamInstallActive = false;
      }
    }
  }
  #derivePacketPostStateRow(
    db,
    {
      kind,
      publicNullifier,
      outputNoteLeaf,
    },
  ) {
    const binding = this.binding();
    const canonical = this.canonicalState();
    const preState = this.#decodeBoundState(
      canonical.state,
      "canonical pre-state",
    );
    const packet = {
      kind,
      preState,
      publicNullifier: publicNullifier.toString("hex"),
      outputNoteLeaf: outputNoteLeaf.toString("hex"),
    };
    const note = kind === "withdrawal"
      ? {
        root: Buffer.from(preState.noteRoot, "hex"),
        witness: undefined,
      }
      : deriveNoteAppendMutation(db, packet, { verifyPostRoot: false });
    const nullifier = kind === "deposit"
      ? {
        root: Buffer.from(preState.nullifierRoot, "hex"),
        witness: undefined,
      }
      : deriveNullifierInsertionMutation(
        db,
        packet,
        { verifyPostRoot: false },
      );
    const denomination = BigInt(binding.denominationSats);
    const reserve = BigInt(preState.reserveSats) +
      (kind === "deposit"
        ? denomination
        : kind === "withdrawal"
        ? -denomination
        : 0n);
    if (reserve < 0n) fail("withdrawal exceeds the canonical pool reserve");
    const postState = {
      ...preState,
      noteRoot: note.root.toString("hex"),
      nullifierRoot: nullifier.root.toString("hex"),
      noteCount:
        (BigInt(preState.noteCount) + (kind === "withdrawal" ? 0n : 1n))
          .toString(),
      nullifierCount:
        (BigInt(preState.nullifierCount) + (kind === "deposit" ? 0n : 1n))
          .toString(),
      reserveSats: reserve.toString(),
      actionSequence: (BigInt(preState.actionSequence) + 1n).toString(),
    };
    let stateBytes;
    try {
      stateBytes = encodeStateNftCommitment(postState, {
        denominationSats: binding.denominationSats,
      });
    } catch (error) {
      fail(
        `derived packet post-state is invalid: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
    return Object.freeze({
      binding,
      canonical,
      preState,
      postState: Object.freeze(postState),
      stateBytes,
      note,
      nullifier,
    });
  }
  derivePacketPostState(value) {
    const input = exactKeys(
      value,
      ["kind", "publicNullifier", "outputNoteLeaf"],
      "packet post-state derivation",
    );
    const kind = actionKind(input.kind, "packet post-state derivation.kind");
    const publicNullifier = frBuffer(
      input.publicNullifier,
      "packet post-state derivation.publicNullifier",
    );
    const outputNoteLeaf = frBuffer(
      input.outputNoteLeaf,
      "packet post-state derivation.outputNoteLeaf",
    );
    const zero = Buffer.alloc(32);
    if (
      (kind === "deposit" && !same(publicNullifier, zero))
      || (kind === "withdrawal" && !same(outputNoteLeaf, zero))
    ) {
      fail("packet post-state derivation has nonzero inactive fields");
    }
    return this.#tx((db) => {
      const derived = this.#derivePacketPostStateRow(db, {
        kind,
        publicNullifier,
        outputNoteLeaf,
      });
      return Object.freeze({
        state: derived.postState,
        stateBytes: copy(derived.stateBytes),
      });
    });
  }
  deriveProvingTransition(value) {
    const input = exactKeys(
      value,
      [
        "operationId",
        "outputNoteLeaf",
        "encryptedRecord",
        "publicNullifier",
        "transactionContextHash",
      ],
      "proving transition derivation",
    );
    const operationId = requiredText(
      input.operationId,
      "proving transition derivation.operationId",
    );
    const outputNoteLeaf = input.outputNoteLeaf === null
      ? null
      : frBuffer(
        input.outputNoteLeaf,
        "proving transition derivation.outputNoteLeaf",
      );
    const encryptedRecord = input.encryptedRecord === null
      ? null
      : bytes(
        input.encryptedRecord,
        128,
        "proving transition derivation.encryptedRecord",
      );
    const publicNullifier = input.publicNullifier === null
      ? null
      : frBuffer(
        input.publicNullifier,
        "proving transition derivation.publicNullifier",
      );
    const transactionContextHash = txid(
      input.transactionContextHash,
      "proving transition derivation.transactionContextHash",
    );
    return this.#tx((db) => {
      const operation = operationAndIntent(db, operationId);
      if (!operation || operation.journal_state !== "proving") {
        fail("proving transition requires an operation in proving state");
      }
      const outputActive =
        operation.kind === "deposit" || operation.kind === "transfer";
      const spendActive =
        operation.kind === "transfer" || operation.kind === "withdrawal";
      if (
        outputActive !==
          (outputNoteLeaf !== null && encryptedRecord !== null)
        || (!outputActive &&
          (outputNoteLeaf !== null || encryptedRecord !== null))
        || spendActive !== (publicNullifier !== null)
      ) {
        fail("proving transition active fields do not match the action kind");
      }
      const current = db.prepare(
        "SELECT * FROM canonical_state WHERE singleton=1",
      ).get();
      if (!operationExpectedTipIsExact(operation, current)) {
        fail("proving transition expected canonical tip is stale");
      }
      requireExactOperationReservations(db, operation);
      const zero = Buffer.alloc(32);
      const derived = this.#derivePacketPostStateRow(db, {
        kind: operation.kind,
        publicNullifier: publicNullifier ?? zero,
        outputNoteLeaf: outputNoteLeaf ?? zero,
      });
      let spend;
      if (spendActive) {
        if (operation.selected_note_id === null) {
          fail("proving transition has no selected note");
        }
        const owned = db.prepare(
          `SELECT owned.record_id,owned.note_index,owned.nullifier_key,
             record.record_bytes
           FROM owned_notes AS owned
           JOIN encrypted_note_records AS record
             ON record.record_id=owned.record_id
           WHERE owned.note_id=?
             AND owned.reservation_operation_id=?
             AND owned.spent=0`,
        ).get(operation.selected_note_id, operationId);
        const leaf = owned === undefined
          ? undefined
          : db.prepare(
            "SELECT leaf_hash,encrypted_record FROM note_leaves WHERE note_index=?",
          ).get(owned.note_index);
        if (
          !owned || !leaf
          || !same(owned.record_bytes, leaf.encrypted_record)
          || !same(owned.nullifier_key, publicNullifier)
        ) {
          fail(
            "selected owned note does not match the requested persistent note leaf",
          );
        }
        const membership = deriveNoteMembershipWitness(db, {
          noteIndex: owned.note_index,
          inputNoteLeaf: leaf.leaf_hash,
          expectedRoot: Buffer.from(derived.preState.noteRoot, "hex"),
        });
        spend = Object.freeze({
          inputNoteLeaf: Buffer.from(leaf.leaf_hash).toString("hex"),
          noteIndex: BigInt(owned.note_index),
          noteMembershipPath: membership.noteMembershipPath,
          publicNullifier: publicNullifier.toString("hex"),
          encryptedRecord: copy(owned.record_bytes),
        });
      }
      const withdrawalLockingBytecodeHash =
        operation.kind === "withdrawal"
          ? createHash("sha256").update(operation.target_bytes).digest("hex")
          : zero.toString("hex");
      let packet;
      try {
        packet = encodeActionPacket({
          kind: operation.kind,
          networkId: derived.binding.networkId,
          instanceId: derived.binding.instanceId.toString("hex"),
          preState: derived.preState,
          postState: derived.postState,
          publicNullifier: (publicNullifier ?? zero).toString("hex"),
          outputNoteLeaf: (outputNoteLeaf ?? zero).toString("hex"),
          encryptedRecord: encryptedRecord ?? Buffer.alloc(128),
          withdrawalLockingBytecodeHash,
          transactionContextHash: transactionContextHash.toString("hex"),
        }, {
          denominationSats: derived.binding.denominationSats,
        });
      } catch (error) {
        fail(
          `proving transition packet construction failed: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
      }
      const packetContext = {
        denominationSats: derived.binding.denominationSats,
      };
      const packetDigest = digestActionPacket(packet, packetContext);
      return Object.freeze({
        schema: V2_PROVING_TRANSITION_SCHEMA,
        state: derived.postState,
        packet,
        packetDigest: packetDigest.toString("hex"),
        publicInputs: actionPacketPublicLimbs(packet, packetContext),
        witness: Object.freeze({
          note: derived.note.witness,
          nullifier: derived.nullifier.witness,
          spend,
        }),
        expectedTip: Object.freeze({
          state: copy(derived.canonical.state),
          outpoint: Object.freeze({
            txid: copy(derived.canonical.outpoint.txid),
            vout: derived.canonical.outpoint.vout,
          }),
          actionSequence: derived.canonical.actionSequence,
          height: derived.canonical.height,
          blockHash: copy(derived.canonical.blockHash),
        }),
      });
    });
  }
  #decodeBoundState(value, label) {
    const binding = this.binding();
    let decoded;
    try {
      decoded = decodeStateNftCommitment(value, {
        denominationSats: binding.denominationSats,
      });
    } catch (error) {
      fail(
        `${label} is invalid: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
    if (decoded.profileId !== binding.profileId.toString("hex")) {
      fail(`${label} profileId does not match the store binding`);
    }
    return decoded;
  }
  #validateOperationPacket(row, value) {
    const packetBytes = bytes(value, 552, "operation packet");
    const binding = this.binding();
    let packet;
    try {
      packet = decodeActionPacket(packetBytes, {
        denominationSats: binding.denominationSats,
      });
    } catch (error) {
      fail(
        `operation packet is invalid: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
    if (
      packet.networkId !== binding.networkId
      || packet.instanceId !== binding.instanceId.toString("hex")
      || packet.preState.profileId !== binding.profileId.toString("hex")
      || packet.kind !== row.kind
    ) {
      fail(
        "operation packet does not match the bound network, profile, instance, and action",
      );
    }
    const context = { denominationSats: binding.denominationSats };
    const preBytes = encodeStateNftCommitment(packet.preState, context);
    const postBytes = encodeStateNftCommitment(packet.postState, context);
    if (
      !same(preBytes, row.expected_state_bytes)
      || Number(packet.preState.actionSequence) !==
        row.expected_action_sequence
    ) {
      fail("operation packet preState does not match the expected tip");
    }
    const preNoteCount = BigInt(packet.preState.noteCount);
    const preNullifierCount = BigInt(packet.preState.nullifierCount);
    const preReserve = BigInt(packet.preState.reserveSats);
    const preSequence = BigInt(packet.preState.actionSequence);
    const postNoteCount = BigInt(packet.postState.noteCount);
    const postNullifierCount = BigInt(packet.postState.nullifierCount);
    const postReserve = BigInt(packet.postState.reserveSats);
    const postSequence = BigInt(packet.postState.actionSequence);
    const denomination = BigInt(binding.denominationSats);
    const expected = packet.kind === "deposit"
      ? {
        noteCount: preNoteCount + 1n,
        nullifierCount: preNullifierCount,
        reserve: preReserve + denomination,
      }
      : packet.kind === "transfer"
      ? {
        noteCount: preNoteCount + 1n,
        nullifierCount: preNullifierCount + 1n,
        reserve: preReserve,
      }
      : {
        noteCount: preNoteCount,
        nullifierCount: preNullifierCount + 1n,
        reserve: preReserve - denomination,
      };
    if (
      postSequence !== preSequence + 1n
      || postNoteCount !== expected.noteCount
      || postNullifierCount !== expected.nullifierCount
      || postReserve !== expected.reserve
      || (packet.kind === "deposit" &&
        packet.postState.nullifierRoot !== packet.preState.nullifierRoot)
      || (packet.kind === "withdrawal" &&
        packet.postState.noteRoot !== packet.preState.noteRoot)
    ) {
      fail("operation packet does not encode the exact action state transition");
    }
    return Object.freeze({
      packet,
      bytes: packetBytes,
      preBytes,
      postBytes,
    });
  }
  #inspectSignedOperation(row) {
    if (
      row.packet_bytes === null
      || row.proof_bytes === null
      || row.unsigned_tx_bytes === null
      || row.signed_tx_bytes === null
      || row.local_vm_evidence === null
      || row.local_vm_evidence.length === 0
    ) {
      fail("signed operation inspection requires every immutable artifact");
    }
    const binding = this.binding();
    const carrierCount = binding.carrierCount;
    const bindingInputIndex = carrierCount;
    const stateInputIndex = carrierCount + 1;
    const fundingInputIndex = carrierCount + 2;
    const unsigned = parseOperationTransaction(
      row.unsigned_tx_bytes,
      carrierCount,
      "operation unsigned transaction",
    );
    const signed = parseOperationTransaction(
      row.signed_tx_bytes,
      carrierCount,
      "operation signed transaction",
    );
    if (!sameTransactionSkeleton(unsigned, signed, fundingInputIndex)) {
      fail(
        "signed transaction must differ from the proved unsigned transaction only at the funding unlock",
      );
    }
    if (
      unsigned.version !== 2
      || unsigned.locktime !== 0
      || unsigned.inputs.some(({ sequence }) => sequence !== 0)
    ) {
      fail("operation transaction version, locktime, or sequence is noncanonical");
    }
    if (unsigned.inputs[fundingInputIndex].unlockingBytecode.length !== 0) {
      fail("proved unsigned transaction must leave the funding unlock empty");
    }
    const fundingUnlock =
      signed.inputs[fundingInputIndex].unlockingBytecode;
    if (
      fundingUnlock.length !== 100
      || fundingUnlock[0] !== 0x41
      || fundingUnlock[65] !== SIGHASH_ALL_UTXOS_FORKID
      || fundingUnlock[66] !== 0x21
      || !same(
        fundingUnlock.subarray(67),
        row.funding_compressed_public_key,
      )
    ) {
      fail(
        "funding unlock must be one canonical 64-byte Schnorr signature with sighash 0x61 and the immutable compressed public key",
      );
    }
    const expectedParent = Buffer.from(row.expected_txid).toString("hex");
    for (let index = 0; index <= stateInputIndex; index += 1) {
      const input = signed.inputs[index];
      const expectedVout = index === stateInputIndex ? 0 : index + 1;
      if (
        input.outpoint.txid !== expectedParent
        || input.outpoint.vout !== expectedVout
      ) {
        fail(
          "rolling verifier, binding, and state inputs must consume the exact expected parent bundle",
        );
      }
    }
    const fundingInput = signed.inputs[fundingInputIndex];
    if (
      fundingInput.outpoint.txid !==
        Buffer.from(row.funding_txid).toString("hex")
      || fundingInput.outpoint.vout !== row.funding_vout
    ) {
      fail("funding input must consume the immutable intent outpoint");
    }
    const operationPacket = this.#validateOperationPacket(
      row,
      row.packet_bytes,
    );
    const bindingUnlock = signed.inputs[bindingInputIndex].unlockingBytecode;
    if (
      bindingUnlock.length <= 555
      || bindingUnlock[0] !== 0x4d
      || bindingUnlock[1] !== 0x28
      || bindingUnlock[2] !== 0x02
      || !same(bindingUnlock.subarray(3, 555), operationPacket.bytes)
    ) {
      fail(
        "binding unlock must begin with the canonical push of the persisted action packet",
      );
    }
    const expectedOutputCount = carrierCount +
      (row.kind === "withdrawal" ? 4 : 3);
    if (signed.outputs.length !== expectedOutputCount) {
      fail("signed operation has the wrong action-specific output count");
    }
    let stateOutput;
    try {
      stateOutput = parseSerializedSourceOutput(
        signed.outputs[0].serializedHex,
      );
    } catch (error) {
      fail(
        `signed state output is invalid: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
    const stateToken = stateOutput.token;
    if (
      stateToken === null
      || stateToken.categoryWire !== binding.instanceId.toString("hex")
      || stateToken.amount !== "0"
      || stateToken.nft === null
      || stateToken.nft.capability !== "mutable"
      || stateToken.nft.commitmentHex !==
        operationPacket.postBytes.toString("hex")
      || stateOutput.valueSatoshis <=
        BigInt(operationPacket.packet.postState.reserveSats)
    ) {
      fail(
        "state output must carry the exact mutable instance NFT, post-state commitment, and positive covenant base value",
      );
    }
    for (let index = 1; index <= carrierCount + 1; index += 1) {
      let output;
      try {
        output = parseSerializedSourceOutput(
          signed.outputs[index].serializedHex,
        );
      } catch (error) {
        fail(
          `signed rolling output ${index} is invalid: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
      }
      if (output.token !== null) {
        fail("verifier and binding successor outputs must be tokenless");
      }
    }
    const payoutIndex = carrierCount + 2;
    const changeIndex = row.kind === "withdrawal"
      ? carrierCount + 3
      : carrierCount + 2;
    if (row.kind === "withdrawal") {
      let payout;
      try {
        payout = parseSerializedSourceOutput(
          signed.outputs[payoutIndex].serializedHex,
        );
      } catch (error) {
        fail(
          `signed withdrawal output is invalid: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
      }
      if (
        payout.token !== null
        || payout.valueSatoshis !== BigInt(binding.denominationSats)
        || !same(payout.lockingBytecode, row.target_bytes)
        || createHash("sha256").update(row.target_bytes).digest("hex") !==
          operationPacket.packet.withdrawalLockingBytecodeHash
      ) {
        fail(
          "withdrawal output must pay the immutable target and exact denomination committed by the packet",
        );
      }
    }
    let change;
    try {
      change = parseSerializedSourceOutput(
        signed.outputs[changeIndex].serializedHex,
      );
    } catch (error) {
      fail(
        `signed change output is invalid: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
    if (
      change.token !== null
      || !same(change.lockingBytecode, row.change_locking_bytecode)
      || change.valueSatoshis < P2PKH_DUST_SATS
    ) {
      fail(
        "change output must be tokenless, non-dust, and pay the immutable P2PKH lock",
      );
    }
    const boundarySats = row.kind === "deposit"
      ? BigInt(binding.denominationSats)
      : 0n;
    const fundingValueSats = BigInt(row.funding_value_sats);
    if (fundingValueSats <= boundarySats + change.valueSatoshis) {
      fail("signed transaction does not leave a positive action fee");
    }
    const feeSats =
      fundingValueSats - boundarySats - change.valueSatoshis;
    const requiredFeeSats =
      BigInt(signed.sizeBytes) * BigInt(row.fee_rate_sats_per_byte);
    if (
      feeSats !== requiredFeeSats
      || feeSats > BigInt(row.maximum_fee_sats)
    ) {
      fail(
        "signed transaction fee must exactly match immutable rate and maximum-fee policy",
      );
    }
    return Object.freeze({
      operationPacket,
      unsigned,
      signed,
      changeIndex,
      changeValueSats: change.valueSatoshis,
      feeSats,
    });
  }
  #assertNewOperation(db, op) {
    const current = db.prepare(
      "SELECT * FROM canonical_state WHERE singleton=1",
    ).get();
    const metadata = db.prepare(
      "SELECT network_id,profile_id,instance_id,runtime_materials_sha256 FROM metadata WHERE singleton=1",
    ).get();
    const decodedExpected = this.#decodeBoundState(
      op.expectedState,
      "operation expectedState",
    );
    if (
      !current
      || !same(current.state_bytes, op.expectedState)
      || !same(current.txid, op.expectedOutpoint.txid)
      || current.vout !== op.expectedOutpoint.vout
      || current.action_sequence !== op.expectedActionSequence
      || current.height !== op.expectedHeight
      || !same(current.block_hash, op.expectedBlockHash)
      || Number(decodedExpected.actionSequence) !==
        op.expectedActionSequence
    ) {
      fail("new operation must bind the exact current canonical tip");
    }
    if (!metadata) fail("store is not initialized");
    if (op.intent.decodedShieldAddress !== null && (
      op.intent.decodedShieldAddress.networkId !== metadata.network_id ||
      op.intent.decodedShieldAddress.profileId !==
        Buffer.from(metadata.profile_id).toString("hex") ||
      op.intent.decodedShieldAddress.instanceId !==
        Buffer.from(metadata.instance_id).toString("hex")
    )) {
      fail("operation intent shield address is not bound to this pool");
    }
    if (!same(op.runtimeMaterialsSha256, metadata.runtime_materials_sha256)) {
      fail("operation runtime materials do not match the store binding");
    }
    if (db.prepare(
      "SELECT 1 FROM pending_operations WHERE operation_id=?",
    ).get(op.operationId)) fail("operation already exists");
  }
  #insertOperationRows(db, op, now, crashPrefix) {
    db.prepare(
      "INSERT INTO pending_operations(operation_id,kind,journal_state,expected_state_bytes,expected_txid,expected_vout,expected_action_sequence,expected_height,expected_block_hash,runtime_materials_sha256,action_material_sha256,private_action_record_sha256,packet_bytes,proof_bytes,unsigned_tx_bytes,signed_tx_bytes,local_vm_evidence,created_at_ms,updated_at_ms,reason) VALUES(?,?,'draft',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
    ).run(
      op.operationId,
      op.kind,
      op.expectedState,
      op.expectedOutpoint.txid,
      op.expectedOutpoint.vout,
      op.expectedActionSequence,
      op.expectedHeight,
      op.expectedBlockHash,
      op.runtimeMaterialsSha256,
      op.actionMaterialSha256,
      op.privateActionRecordSha256,
      op.packet,
      op.proof,
      op.unsignedTx,
      op.signedTx,
      op.localVmEvidence,
      now,
      now,
    );
    crash(op.crashAt, `${crashPrefix}.after_pending`);
    db.prepare(
      "INSERT INTO operation_intents(operation_id,kind,target_type,target_bytes,selected_note_id,funding_raw_transaction,funding_txid,funding_vout,funding_value_sats,funding_locking_bytecode,funding_compressed_public_key,change_locking_bytecode,fee_rate_sats_per_byte,maximum_fee_sats,retry_count) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
    ).run(
      op.operationId,
      op.intent.kind,
      op.intent.targetType,
      op.intent.targetBytes,
      op.intent.selectedNoteId,
      op.intent.funding.rawSourceTransaction,
      op.intent.funding.txid,
      op.intent.funding.vout,
      op.intent.funding.valueSats,
      op.intent.funding.lockingBytecode,
      op.intent.funding.compressedPublicKey,
      op.intent.changeLockingBytecode,
      op.intent.feePolicy.feeRateSatsPerByte,
      op.intent.feePolicy.maximumFeeSats,
    );
    crash(op.crashAt, `${crashPrefix}.after_intent`);
  }
  #reserveOperationRows(
    db,
    row,
    crashAt,
    crashPrefix,
    { transitionToFundingSelected = true } = {},
  ) {
    const id = row.operation_id;
    const noteId = row.selected_note_id;
    if (noteId !== null) {
      if (
        db.prepare(
          "UPDATE owned_notes SET reservation_operation_id=? WHERE note_id=? AND reservation_operation_id IS NULL AND spent=0",
        ).run(id, noteId).changes !== 1
      ) fail("note is unavailable for reservation");
    }
    crash(crashAt, `${crashPrefix}.after_note`);
    const fundingRow = db.prepare(
      "SELECT value_sats FROM funding_utxos WHERE txid=? AND vout=? AND reservation_operation_id IS NULL AND spent=0",
    ).get(row.funding_txid, row.funding_vout);
    if (!fundingRow || fundingRow.value_sats !== row.funding_value_sats) {
      fail("funding UTXO does not exactly match immutable operation intent");
    }
    if (
      db.prepare(
        "UPDATE funding_utxos SET reservation_operation_id=? WHERE txid=? AND vout=? AND reservation_operation_id IS NULL AND spent=0",
      ).run(id, row.funding_txid, row.funding_vout).changes !== 1
    ) fail("funding UTXO is unavailable for reservation");
    crash(crashAt, `${crashPrefix}.after_utxo`);
    if (transitionToFundingSelected) {
      db.prepare(
        "UPDATE pending_operations SET journal_state='funding_selected',updated_at_ms=? WHERE operation_id=?",
      ).run(Date.now(), id);
    }
  }
  createOperation(value) {
    const op = operationInput(value, "operation");
    if (
      op.packet !== null || op.proof !== null || op.unsignedTx !== null ||
      op.signedTx !== null || op.localVmEvidence !== null
    ) fail("new operation artifacts must be null");
    return this.#tx((db) => {
      this.#assertNewOperation(db, op);
      this.#insertOperationRows(db, op, Date.now(), "operation");
      crash(op.crashAt, "operation.before_commit");
      return this.operation(op.operationId);
    });
  }
  prepareAction(value) {
    const op = operationInput(
      value,
      "prepared action",
      V2_OPERATION_PREPARE_CRASH_STAGES,
    );
    if (
      op.packet !== null || op.proof !== null || op.unsignedTx !== null ||
      op.signedTx !== null || op.localVmEvidence !== null
    ) fail("new operation artifacts must be null");
    return this.#tx((db) => {
      this.#assertNewOperation(db, op);
      this.#insertOperationRows(db, op, Date.now(), "prepare");
      const row = operationAndIntent(db, op.operationId);
      if (!row) fail("prepared action has no durable intent");
      this.#reserveOperationRows(db, row, op.crashAt, "prepare");
      crash(op.crashAt, "prepare.before_commit");
      return this.operation(op.operationId);
    });
  }
  operation(operationId) {
    const id = requiredText(operationId, "operationId");
    const db = this.#open();
    const row = operationAndIntent(db, id);
    if (!row) {
      if (db.prepare(
        "SELECT 1 FROM pending_operations WHERE operation_id=?",
      ).get(id)) fail("operation has no durable intent");
      fail("operation does not exist");
    }
    if (row.kind !== row.intent_kind) {
      fail("operation kind differs from immutable intent");
    }
    const intent = operationIntent({
      kind: row.intent_kind,
      target: {
        type: row.target_type,
        bytes: row.target_bytes,
      },
      selectedNoteId: row.selected_note_id,
      funding: {
        rawSourceTransaction: row.funding_raw_transaction,
        txid: row.funding_txid,
        vout: row.funding_vout,
        valueSats: row.funding_value_sats,
        lockingBytecode: row.funding_locking_bytecode,
        compressedPublicKey: row.funding_compressed_public_key,
      },
      changeLockingBytecode: row.change_locking_bytecode,
      feePolicy: {
        feeRateSatsPerByte: row.fee_rate_sats_per_byte,
        maximumFeeSats: row.maximum_fee_sats,
      },
    }, row.kind, "stored operation intent");
    if (intent.decodedShieldAddress !== null) {
      const metadata = db.prepare(
        "SELECT network_id,profile_id,instance_id FROM metadata WHERE singleton=1",
      ).get();
      if (
        !metadata ||
        intent.decodedShieldAddress.networkId !== metadata.network_id ||
        intent.decodedShieldAddress.profileId !==
          Buffer.from(metadata.profile_id).toString("hex") ||
        intent.decodedShieldAddress.instanceId !==
          Buffer.from(metadata.instance_id).toString("hex")
      ) fail("stored operation intent shield address is not bound to this pool");
    }
    return Object.freeze({
      operationId: row.operation_id,
      kind: row.kind,
      journalState: row.journal_state,
      expectedState: copy(row.expected_state_bytes),
      expectedOutpoint: Object.freeze({
        txid: copy(row.expected_txid),
        vout: row.expected_vout,
      }),
      expectedActionSequence: row.expected_action_sequence,
      expectedHeight: row.expected_height,
      expectedBlockHash: copy(row.expected_block_hash),
      runtimeMaterialsSha256: copy(row.runtime_materials_sha256),
      actionMaterialSha256: copy(row.action_material_sha256),
      privateActionRecordSha256:
        copy(row.private_action_record_sha256),
      intent: Object.freeze({
        kind: intent.kind,
        target: Object.freeze({
          type: intent.targetType,
          bytes: copy(intent.targetBytes),
        }),
        selectedNoteId: intent.selectedNoteId,
        funding: Object.freeze({
          rawSourceTransaction: copy(intent.funding.rawSourceTransaction),
          txid: copy(intent.funding.txid),
          vout: intent.funding.vout,
          valueSats: intent.funding.valueSats,
          lockingBytecode: copy(intent.funding.lockingBytecode),
          compressedPublicKey: copy(intent.funding.compressedPublicKey),
        }),
        changeLockingBytecode: copy(intent.changeLockingBytecode),
        feePolicy: Object.freeze({
          feeRateSatsPerByte: intent.feePolicy.feeRateSatsPerByte,
          maximumFeeSats: intent.feePolicy.maximumFeeSats,
        }),
      }),
      retryCount: row.retry_count,
      packet: row.packet_bytes === null ? null : copy(row.packet_bytes),
      proof: row.proof_bytes === null ? null : copy(row.proof_bytes),
      unsignedTx: row.unsigned_tx_bytes === null
        ? null
        : copy(row.unsigned_tx_bytes),
      signedTx: row.signed_tx_bytes === null ? null : copy(row.signed_tx_bytes),
      localVmEvidence: row.local_vm_evidence === null
        ? null
        : copy(row.local_vm_evidence),
      reason: row.reason,
    });
  }
  listOperations(value) {
    const input = exactKeys(value, ["states"], "operation list");
    if (
      !Array.isArray(input.states)
      || input.states.length === 0
      || input.states.some((entry) => !V2_OPERATION_STATES.includes(entry))
      || new Set(input.states).size !== input.states.length
    ) {
      fail(
        "operation list.states must be a nonempty unique array of supported states",
      );
    }
    const placeholders = input.states.map(() => "?").join(",");
    const rows = this.#open().prepare(
      `SELECT operation_id FROM pending_operations
       WHERE journal_state IN (${placeholders})
       ORDER BY operation_id`,
    ).all(...input.states);
    return Object.freeze(rows.map((row) => this.operation(row.operation_id)));
  }
  updateOperationArtifacts(value) {
    const input = exactKeys(value, [
      "operationId",
      "packet",
      "proof",
      "unsignedTx",
      "signedTx",
      "localVmEvidence",
    ], "operation artifacts");
    const id = requiredText(
      input.operationId,
      "operation artifacts.operationId",
    );
    const values = [
      nullableArtifact(input.packet, 552, "operation artifacts.packet"),
      nullableArtifact(input.proof, null, "operation artifacts.proof"),
      nullableArtifact(
        input.unsignedTx,
        null,
        "operation artifacts.unsignedTx",
      ),
      nullableArtifact(input.signedTx, null, "operation artifacts.signedTx"),
      nullableArtifact(
        input.localVmEvidence,
        null,
        "operation artifacts.localVmEvidence",
      ),
    ];
    this.#tx((db) => {
      const row = operationAndIntent(db, id);
      if (!row) fail("operation does not exist");
      if (
        ["signed", "broadcast", "mempool", "confirmed", "settled"].includes(
          row.journal_state,
        )
      ) fail("operation artifacts are immutable after signing");
      if (values[0] !== null) {
        this.#validateOperationPacket(row, values[0]);
      }
      const old = [
        row.packet_bytes,
        row.proof_bytes,
        row.unsigned_tx_bytes,
        row.signed_tx_bytes,
        row.local_vm_evidence,
      ];
      const sameNullable = (left, right) =>
        left === null ? right === null : right !== null && same(left, right);
      const appendOnly = (left, right) =>
        left === null ? true : right !== null && same(left, right);
      const [packet, proof, unsignedTx, signedTx, localVmEvidence] = values;
      const proofSet = [packet, proof, unsignedTx];
      if (
        ["draft", "funding_selected", "tip_synced"].includes(row.journal_state)
      ) {
        if (
          proofSet.some((entry) => entry !== null) || signedTx !== null ||
          localVmEvidence !== null
        ) {
          fail("proof artifacts may first be written only while proving");
        }
      } else if (row.journal_state === "proving") {
        if (
          !appendOnly(old[0], packet) || !appendOnly(old[1], proof) ||
          !appendOnly(old[2], unsignedTx) || signedTx !== null ||
          localVmEvidence !== null
        ) {
          fail(
            "proving may only append packet, proof, and unsigned transaction",
          );
        }
      } else if (row.journal_state === "proved") {
        if (
          !sameNullable(old[0], packet) || !sameNullable(old[1], proof) ||
          !sameNullable(old[2], unsignedTx) || !appendOnly(old[3], signedTx) ||
          !appendOnly(old[4], localVmEvidence)
        ) {
          fail(
            "proved artifacts are immutable except first signed transaction and local VM evidence",
          );
        }
      } else if (row.journal_state === "needs_reproof") {
        if (values.some((entry) => entry !== null)) {
          fail("needs_reproof artifacts must remain cleared until proving");
        }
      } else fail("operation state cannot accept artifacts");
      db.prepare(
        "UPDATE pending_operations SET packet_bytes=?,proof_bytes=?,unsigned_tx_bytes=?,signed_tx_bytes=?,local_vm_evidence=?,updated_at_ms=? WHERE operation_id=?",
      ).run(...values, Date.now(), id);
    });
  }
  transitionOperation(value) {
    const input = exactKeys(
      value,
      ["operationId", "to", "reason"],
      "operation transition",
    );
    const id = requiredText(
      input.operationId,
      "operation transition.operationId",
    );
    const to = requiredText(input.to, "operation transition.to");
    const reason = nullableText(input.reason, "operation transition.reason");
    if (!V2_OPERATION_STATES.includes(to)) {
      fail("operation transition target is unsupported");
    }
    return this.#tx((db) => {
      const row = operationAndIntent(db, id);
      if (!row) fail("operation does not exist");
      if (!(TRANSITIONS[row.journal_state] ?? new Set()).has(to)) {
        fail(
          `operation transition ${row.journal_state} -> ${to} is not allowed`,
        );
      }
      if (to === "needs_reproof") {
        fail("use recordConflictAndMaybeRetry to enter needs_reproof");
      }
      if (to === "conflicted") {
        fail("use a conflict lifecycle method to enter conflicted");
      }
      if (to === "abandoned") {
        fail("use abandonOperation to enter abandoned");
      }
      if (to === "reorged") {
        fail("use rollbackReorg to enter reorged");
      }
      if (to === "confirmed") {
        fail("use applyConfirmed to enter confirmed");
      }
      if (to === "settled") {
        fail("use settleConfirmedOperation to enter settled");
      }
      if (
        to === "tip_synced" &&
        ["needs_reproof", "reorged"].includes(row.journal_state)
      ) fail("use rebaseOperation to bind a replacement canonical tip");
      if (
        ["tip_synced", "proving", "proved", "signed", "broadcast"].includes(to)
      ) {
        const current = db.prepare(
          "SELECT * FROM canonical_state WHERE singleton=1",
        ).get();
        if (!operationExpectedTipIsExact(row, current)) {
          fail("operation expected canonical tip is stale");
        }
        requireExactOperationReservations(db, row);
      }
      if (
        to === "proved" &&
        (!row.packet_bytes || !row.proof_bytes || !row.unsigned_tx_bytes ||
          row.signed_tx_bytes !== null || row.local_vm_evidence !== null)
      ) fail("proved requires packet, proof, and unsigned transaction");
      if (
        to === "signed" &&
        (!row.signed_tx_bytes || !row.local_vm_evidence ||
          row.local_vm_evidence.length === 0)
      ) {
        fail("signed requires signed transaction and local VM evidence");
      }
      if (to === "signed" || to === "broadcast") {
        this.#inspectSignedOperation(row);
      }
      if (
        to === "broadcast" &&
        (!row.local_vm_evidence || row.local_vm_evidence.length === 0)
      ) fail("broadcast requires successful local VM evidence");
      db.prepare(
        "UPDATE pending_operations SET journal_state=?,reason=?,updated_at_ms=? WHERE operation_id=?",
      ).run(to, reason, Date.now(), id);
      return this.operation(id);
    });
  }
  rebaseOperation(value) {
    const input = exactKeys(value, [
      "operationId",
      "expectedState",
      "expectedOutpoint",
      "expectedActionSequence",
      "expectedHeight",
      "expectedBlockHash",
      "actionMaterialSha256",
      "privateActionRecordSha256",
      "crashAt",
    ], "operation rebase");
    const id = requiredText(input.operationId, "operation rebase.operationId");
    const expectedState = state(
      input.expectedState,
      "operation rebase.expectedState",
    );
    const expectedOutpoint = outpoint(
      input.expectedOutpoint,
      "operation rebase.expectedOutpoint",
    );
    const expectedActionSequence = integer(
      input.expectedActionSequence,
      0,
      0x1_ffff_ffff,
      "operation rebase.expectedActionSequence",
    );
    const expectedHeight = integer(
      input.expectedHeight,
      0,
      Number.MAX_SAFE_INTEGER,
      "operation rebase.expectedHeight",
    );
    const expectedBlockHash = txid(
      input.expectedBlockHash,
      "operation rebase.expectedBlockHash",
    );
    const actionMaterialSha256 = bytes(
      input.actionMaterialSha256,
      32,
      "operation rebase.actionMaterialSha256",
    );
    const privateActionRecordSha256 = bytes(
      input.privateActionRecordSha256,
      32,
      "operation rebase.privateActionRecordSha256",
    );
    const crashAt = crashStage(
      input.crashAt,
      V2_OPERATION_REBASE_CRASH_STAGES,
      "operation rebase.crashAt",
    );
    return this.#tx((db) => {
      const row = operationAndIntent(db, id);
      if (!row || !["needs_reproof", "reorged"].includes(row.journal_state)) {
        fail("operation rebase requires needs_reproof or reorged");
      }
      const current = db.prepare(
        "SELECT * FROM canonical_state WHERE singleton=1",
      ).get();
      const decoded = this.#decodeBoundState(
        expectedState,
        "operation rebase expectedState",
      );
      if (
        !current ||
        !same(current.state_bytes, expectedState) ||
        !same(current.txid, expectedOutpoint.txid) ||
        current.vout !== expectedOutpoint.vout ||
        current.action_sequence !== expectedActionSequence ||
        current.height !== expectedHeight ||
        !same(current.block_hash, expectedBlockHash) ||
        Number(decoded.actionSequence) !== expectedActionSequence
      ) fail("operation rebase must equal the exact current canonical tip");
      if (!operationReservationsAreExact(db, row)) {
        this.#reserveOperationRows(
          db,
          row,
          crashAt,
          "rebase.reservation",
          { transitionToFundingSelected: false },
        );
      }
      requireExactOperationReservations(db, row);
      db.prepare(
        `UPDATE pending_operations SET
          expected_state_bytes=?,expected_txid=?,expected_vout=?,
          expected_action_sequence=?,expected_height=?,expected_block_hash=?,
          action_material_sha256=?,private_action_record_sha256=?,
          packet_bytes=NULL,proof_bytes=NULL,unsigned_tx_bytes=NULL,
          signed_tx_bytes=NULL,local_vm_evidence=NULL,journal_state='tip_synced',
          reason=NULL,updated_at_ms=? WHERE operation_id=?`,
      ).run(
        expectedState,
        expectedOutpoint.txid,
        expectedOutpoint.vout,
        expectedActionSequence,
        expectedHeight,
        expectedBlockHash,
        actionMaterialSha256,
        privateActionRecordSha256,
        Date.now(),
        id,
      );
      db.prepare("DELETE FROM mempool_overlay WHERE operation_id=?").run(id);
      crash(crashAt, "rebase.after_artifacts");
      crash(crashAt, "rebase.before_commit");
      return this.operation(id);
    });
  }
  releaseOperationForCanonicalSync(value) {
    const input = exactKeys(
      value,
      ["operationId"],
      "operation canonical-sync release",
    );
    const id = requiredText(
      input.operationId,
      "operation canonical-sync release.operationId",
    );
    return this.#tx((db) => {
      const row = operationAndIntent(db, id);
      if (
        !row
        || !["needs_reproof", "conflicted", "reorged"].includes(
          row.journal_state,
        )
      ) {
        fail(
          "operation canonical-sync release requires a dormant conflicted or reproof state",
        );
      }
      releaseOperationResources(db, id);
      db.prepare("DELETE FROM mempool_overlay WHERE operation_id=?").run(id);
      return this.operation(id);
    });
  }
  abandonOperation(value) {
    const input = exactKeys(
      value,
      ["operationId", "reason", "crashAt"],
      "operation abandon",
    );
    const id = requiredText(input.operationId, "operation abandon.operationId");
    const reason = requiredText(input.reason, "operation abandon.reason");
    const crashAt = crashStage(
      input.crashAt,
      V2_OPERATION_ABANDON_CRASH_STAGES,
      "operation abandon.crashAt",
    );
    return this.#tx((db) => {
      const row = operationAndIntent(db, id);
      if (
        !row ||
        !(TRANSITIONS[row.journal_state] ?? new Set()).has("abandoned")
      ) fail("operation cannot be abandoned from its current state");
      releaseOperationResources(db, id);
      crash(crashAt, "abandon.after_reservations");
      db.prepare("DELETE FROM mempool_overlay WHERE operation_id=?").run(id);
      crash(crashAt, "abandon.after_overlay");
      db.prepare(
        "UPDATE pending_operations SET journal_state='abandoned',reason=?,updated_at_ms=? WHERE operation_id=?",
      ).run(reason, Date.now(), id);
      crash(crashAt, "abandon.before_commit");
      return this.operation(id);
    });
  }
  authorizeManualRetry(value) {
    const input = exactKeys(
      value,
      ["operationId", "crashAt"],
      "operation manual retry",
    );
    const id = requiredText(
      input.operationId,
      "operation manual retry.operationId",
    );
    const crashAt = crashStage(
      input.crashAt,
      V2_OPERATION_MANUAL_RETRY_CRASH_STAGES,
      "operation manual retry.crashAt",
    );
    return this.#tx((db) => {
      const row = operationAndIntent(db, id);
      if (!row || row.journal_state !== "conflicted") {
        fail("manual retry requires a conflicted operation");
      }
      db.prepare(
        "UPDATE operation_intents SET retry_count=0 WHERE operation_id=?",
      ).run(id);
      crash(crashAt, "manual_retry.after_counter");
      releaseOperationResources(db, id);
      db.prepare("DELETE FROM mempool_overlay WHERE operation_id=?").run(id);
      crash(crashAt, "manual_retry.after_resources");
      db.prepare(
        `UPDATE pending_operations SET journal_state='needs_reproof',
          reason='explicit manual retry authorized',
          packet_bytes=NULL,proof_bytes=NULL,unsigned_tx_bytes=NULL,
          signed_tx_bytes=NULL,local_vm_evidence=NULL,updated_at_ms=?
        WHERE operation_id=?`,
      ).run(Date.now(), id);
      crash(crashAt, "manual_retry.before_commit");
      return this.operation(id);
    });
  }
  recordConflictAndMaybeRetry(value) {
    const input = exactKeys(
      value,
      ["operationId", "reason", "crashAt"],
      "operation conflict",
    );
    const id = requiredText(input.operationId, "operation conflict.operationId");
    const reason = requiredText(input.reason, "operation conflict.reason");
    const crashAt = crashStage(
      input.crashAt,
      V2_OPERATION_CONFLICT_CRASH_STAGES,
      "operation conflict.crashAt",
    );
    return this.#tx((db) => {
      const row = operationAndIntent(db, id);
      if (
        !row ||
        ![
          "funding_selected",
          "tip_synced",
          "proving",
          "proved",
          "signed",
          "broadcast",
          "mempool",
        ].includes(row.journal_state)
      ) fail("operation cannot automatically retry from its current state");
      const retryCount = row.retry_count + 1;
      if (retryCount > V2_OPERATION_MAX_AUTOMATIC_CONFLICTS) {
        fail("operation automatic conflict retry limit is already exhausted");
      }
      db.prepare(
        "UPDATE operation_intents SET retry_count=? WHERE operation_id=?",
      ).run(retryCount, id);
      crash(crashAt, "conflict.after_counter");
      const terminal =
        retryCount >= V2_OPERATION_MAX_AUTOMATIC_CONFLICTS ||
        !operationReservationsAreExact(db, row);
      // A canonical-tip conflict invalidates every retained proof artifact and
      // reservation, even when the bounded retry remains automatic. Rebase
      // performs a fresh authenticated history install first, then atomically
      // reacquires the immutable intent's note and funding rows. Keeping either
      // reservation here deadlocks canonical replacement and risks rebasing
      // against stale wallet inventory.
      releaseOperationResources(db, id);
      db.prepare("DELETE FROM mempool_overlay WHERE operation_id=?").run(id);
      crash(crashAt, "conflict.after_resources");
      db.prepare(
        `UPDATE pending_operations SET journal_state=?,reason=?,
          packet_bytes=NULL,proof_bytes=NULL,unsigned_tx_bytes=NULL,
          signed_tx_bytes=NULL,local_vm_evidence=NULL,updated_at_ms=?
        WHERE operation_id=?`,
      ).run(
        terminal ? "conflicted" : "needs_reproof",
        reason,
        Date.now(),
        id,
      );
      crash(crashAt, "conflict.before_commit");
      return this.operation(id);
    });
  }
  putNoteNode(value) {
    const node = validateNode(value, "note node");
    this.#tx((db) =>
      db.prepare(
        "INSERT INTO note_nodes(depth,node_index,node_hash) VALUES(?,?,?) ON CONFLICT(depth,node_index) DO UPDATE SET node_hash=excluded.node_hash",
      ).run(node.depth, node.nodeIndex, node.nodeHash)
    );
  }
  noteNode(value) {
    const input = exactKeys(value, ["depth", "nodeIndex"], "note node query");
    const depth = integer(input.depth, 0, 32, "note node query.depth");
    const row = this.#open().prepare(
      "SELECT node_hash FROM note_nodes WHERE depth=? AND node_index=?",
    ).get(
      depth,
      integer(
        input.nodeIndex,
        0,
        (2 ** (32 - depth)) - 1,
        "note node query.nodeIndex",
      ),
    );
    return row ? copy(row.node_hash) : null;
  }
  putNoteFrontier(value) {
    const entry = validateFrontier(value, "note frontier");
    this.#tx((db) =>
      db.prepare(
        "INSERT INTO note_frontier(depth,node_hash) VALUES(?,?) ON CONFLICT(depth) DO UPDATE SET node_hash=excluded.node_hash",
      ).run(entry.depth, entry.nodeHash)
    );
  }
  noteFrontier(value) {
    const input = exactKeys(value, ["depth"], "note frontier query");
    const row = this.#open().prepare(
      "SELECT node_hash FROM note_frontier WHERE depth=?",
    ).get(integer(input.depth, 0, 31, "note frontier query.depth"));
    return row ? copy(row.node_hash) : null;
  }
  noteLeaf(value) {
    const input = exactKeys(value, ["noteIndex"], "note leaf query");
    const noteIndex = integer(
      input.noteIndex,
      0,
      MAX_U32,
      "note leaf query.noteIndex",
    );
    const row = this.#open().prepare(
      "SELECT * FROM note_leaves WHERE note_index=?",
    ).get(noteIndex);
    return row
      ? Object.freeze({
        noteIndex: row.note_index,
        leafHash: copy(row.leaf_hash),
        encryptedRecord: copy(row.encrypted_record),
        actionSequence: row.action_sequence,
        transactionId: copy(row.transaction_id),
      })
      : null;
  }
  putNullifierNode(value) {
    const node = validateNode(value, "nullifier node");
    this.#tx((db) =>
      productionNullifierSqliteAccess(db).writeNode(node)
    );
  }
  nullifierNode(value) {
    const input = exactKeys(
      value,
      ["depth", "nodeIndex"],
      "nullifier node query",
    );
    const depth = integer(input.depth, 0, 32, "nullifier node query.depth");
    const row = this.#open().prepare(
      "SELECT node_hash FROM nullifier_nodes WHERE depth=? AND node_index=?",
    ).get(
      depth,
      integer(
        input.nodeIndex,
        0,
        (2 ** (32 - depth)) - 1,
        "nullifier node query.nodeIndex",
      ),
    );
    return row ? copy(row.node_hash) : null;
  }
  #putLeaf(db, leaf) {
    productionNullifierSqliteAccess(db).writeLeaf(leaf);
  }
  putNullifierLeaf(value) {
    const leaf = validateLeaf(value, "nullifier leaf");
    this.#tx((db) => this.#putLeaf(db, leaf));
  }
  nullifierLeaf(value) {
    const input = exactKeys(value, ["physicalIndex"], "nullifier leaf query");
    const row = this.#open().prepare(
      "SELECT * FROM nullifier_leaves WHERE physical_index=?",
    ).get(
      integer(
        input.physicalIndex,
        0,
        MAX_U32,
        "nullifier leaf query.physicalIndex",
      ),
    );
    return row
      ? Object.freeze({
        physicalIndex: row.physical_index,
        leafType: row.leaf_type,
        leafHash: copy(row.leaf_hash),
        key: copy(row.key_be),
        successorIndex: row.successor_index,
        successorKey: copy(row.successor_key_be),
      })
      : null;
  }
  normalKeyPredecessor(value) {
    const input = exactKeys(value, ["key"], "normal key predecessor");
    const key = txid(input.key, "normal key predecessor.key");
    if (BigInt(`0x${key.toString("hex")}`) >= BN254_FR_MODULUS) {
      fail("normal key predecessor.key must be canonical BN254 Fr");
    }
    const db = this.#open();
    if (
      db.prepare(
        "SELECT physical_index FROM nullifier_order_keys WHERE leaf_type=2 AND key_be=?",
      ).get(key)
    ) fail("normal nullifier key already exists");
    const row = db.prepare(
      "SELECT physical_index FROM nullifier_order_keys WHERE leaf_type=2 AND key_be<? ORDER BY key_be DESC LIMIT 1",
    ).get(key);
    const leaf = db.prepare(
      "SELECT * FROM nullifier_leaves WHERE physical_index=?",
    ).get(row ? row.physical_index : 0);
    if (!leaf) fail("minimum nullifier sentinel is missing");
    return Object.freeze({
      physicalIndex: leaf.physical_index,
      leafType: leaf.leaf_type,
      leafHash: copy(leaf.leaf_hash),
      key: copy(leaf.key_be),
      successorIndex: leaf.successor_index,
      successorKey: copy(leaf.successor_key_be),
    });
  }
  #putRecord(db, recordId, record) {
    const existing = db.prepare(
      "SELECT record_bytes FROM encrypted_note_records WHERE record_id=?",
    ).get(recordId);
    if (existing) {
      if (!same(existing.record_bytes, record)) {
        fail("encrypted record ID is immutable and differs");
      }
      return;
    }
    db.prepare(
      "INSERT INTO encrypted_note_records(record_id,record_bytes) VALUES(?,?)",
    ).run(recordId, record);
  }
  putEncryptedRecord(value) {
    const input = exactKeys(value, ["recordId", "record"], "encrypted record");
    const id = requiredText(input.recordId, "encrypted record.recordId");
    const record = bytes(input.record, 128, "encrypted record.record");
    this.#tx((db) => this.#putRecord(db, id, record));
  }
  encryptedRecord(recordId) {
    const row = this.#open().prepare(
      "SELECT record_bytes FROM encrypted_note_records WHERE record_id=?",
    ).get(requiredText(recordId, "recordId"));
    return row ? copy(row.record_bytes) : null;
  }
  putOwnedNote(value) {
    const input = exactKeys(
      value,
      ["noteId", "recordId", "noteIndex", "nullifier"],
      "owned note",
    );
    const noteId = requiredText(input.noteId, "owned note.noteId");
    const recordId = requiredText(input.recordId, "owned note.recordId");
    const noteIndex = integer(
      input.noteIndex,
      0,
      MAX_U32,
      "owned note.noteIndex",
    );
    const nullifier = frBuffer(input.nullifier, "owned note.nullifier");
    this.#tx((db) => {
      const existing = db.prepare(
        "SELECT record_id,note_index,nullifier_key FROM owned_notes WHERE note_id=?",
      ).get(noteId);
      if (existing) {
        if (
          existing.record_id !== recordId
          || existing.note_index !== noteIndex
          || !same(existing.nullifier_key, nullifier)
        ) {
          fail("owned note ID is immutable and differs");
        }
        return;
      }
      db.prepare(
        "INSERT INTO owned_notes(note_id,record_id,note_index,nullifier_key,reservation_operation_id,spent) VALUES(?,?,?,?,NULL,0)",
      ).run(noteId, recordId, noteIndex, nullifier);
    });
  }
  ownedNote(noteId) {
    const row = this.#open().prepare(
      "SELECT record_id,note_index,nullifier_key,reservation_operation_id,spent FROM owned_notes WHERE note_id=?",
    ).get(requiredText(noteId, "noteId"));
    return row
      ? Object.freeze({
        recordId: row.record_id,
        noteIndex: row.note_index,
        nullifier: copy(row.nullifier_key),
        reservationOperationId: row.reservation_operation_id,
        spent: Boolean(row.spent),
      })
      : null;
  }
  ownedNoteStatistics() {
    const row = this.#open().prepare(
      `SELECT COUNT(*) AS total,
        SUM(CASE WHEN spent=0 THEN 1 ELSE 0 END) AS unspent,
        SUM(CASE WHEN spent=1 THEN 1 ELSE 0 END) AS spent
       FROM owned_notes`,
    ).get();
    return Object.freeze({
      total: row.total,
      unspent: Number(row.unspent ?? 0),
      spent: Number(row.spent ?? 0),
    });
  }
  putFundingUtxo(value) {
    const input = exactKeys(
      value,
      ["txid", "vout", "valueSats"],
      "funding UTXO",
    );
    const id = txid(input.txid, "funding UTXO.txid");
    const vout = integer(input.vout, 0, MAX_U32, "funding UTXO.vout");
    const valueSats = requiredText(input.valueSats, "funding UTXO.valueSats");
    if (
      !/^(0|[1-9][0-9]*)$/.test(valueSats) || BigInt(valueSats) === 0n ||
      BigInt(valueSats) > MAX_MONEY_SATS
    ) fail("funding UTXO.valueSats must be nonzero canonical money");
    this.#tx((db) => {
      const existing = db.prepare(
        "SELECT value_sats FROM funding_utxos WHERE txid=? AND vout=?",
      ).get(id, vout);
      if (existing) {
        if (existing.value_sats !== valueSats) {
          fail("funding UTXO is immutable and differs");
        }
        return;
      }
      db.prepare(
        "INSERT INTO funding_utxos(txid,vout,value_sats,reservation_operation_id,spent) VALUES(?,?,?,NULL,0)",
      ).run(id, vout, valueSats);
    });
  }
  fundingUtxo(value) {
    const input = exactKeys(value, ["txid", "vout"], "funding UTXO query");
    const id = txid(input.txid, "funding UTXO query.txid");
    const vout = integer(input.vout, 0, MAX_U32, "funding UTXO query.vout");
    const row = this.#open().prepare(
      "SELECT value_sats,reservation_operation_id,spent FROM funding_utxos WHERE txid=? AND vout=?",
    ).get(id, vout);
    return row
      ? Object.freeze({
        valueSats: row.value_sats,
        reservationOperationId: row.reservation_operation_id,
        spent: Boolean(row.spent),
      })
      : null;
  }
  reserveResources(value) {
    const input = exactKeys(value, [
      "operationId",
      "noteId",
      "utxoTxid",
      "utxoVout",
      "crashAt",
    ], "reservation");
    const id = requiredText(input.operationId, "reservation.operationId");
    const noteId = input.noteId === null
      ? null
      : requiredText(input.noteId, "reservation.noteId");
    const funding = outpoint(
      { txid: input.utxoTxid, vout: input.utxoVout },
      "reservation funding",
    );
    if (input.crashAt !== null && typeof input.crashAt !== "string") {
      fail("reservation.crashAt must be a string or null");
    }
    return this.#tx((db) => {
      const op = operationAndIntent(db, id);
      if (!op || op.journal_state !== "draft") {
        fail("reservation requires a draft operation");
      }
      if (
        noteId !== op.selected_note_id ||
        !same(funding.txid, op.funding_txid) ||
        funding.vout !== op.funding_vout
      ) fail("reservation must exactly match immutable operation intent");
      this.#reserveOperationRows(db, op, input.crashAt, "reservation");
      crash(input.crashAt, "reservation.before_commit");
      return this.operation(id);
    });
  }
  recordMempoolOverlay(value) {
    const input = exactKeys(
      value,
      ["operationId", "overlay"],
      "mempool overlay",
    );
    const id = requiredText(input.operationId, "mempool overlay.operationId");
    const overlay = variableBytes(input.overlay, "mempool overlay.overlay");
    this.#tx((db) => {
      const row = db.prepare(
        "SELECT journal_state FROM pending_operations WHERE operation_id=?",
      ).get(id);
      if (!row || !["broadcast", "mempool"].includes(row.journal_state)) {
        fail("mempool overlay requires broadcast or mempool operation");
      }
      if (row.journal_state === "broadcast") {
        db.prepare(
          "UPDATE pending_operations SET journal_state='mempool',updated_at_ms=? WHERE operation_id=?",
        ).run(Date.now(), id);
      }
      db.prepare(
        "INSERT INTO mempool_overlay(operation_id,overlay_bytes,created_at_ms) VALUES(?,?,?) ON CONFLICT(operation_id) DO UPDATE SET overlay_bytes=excluded.overlay_bytes,created_at_ms=excluded.created_at_ms",
      ).run(id, overlay, Date.now());
    });
  }
  applyConfirmed(value) {
    return this.#applyConfirmedRowDelta(value);
  }
  #applyConfirmedRowDelta(value) {
    const input = exactKeys(value, [
      "operationId",
      "expected",
      "next",
      "records",
      "notes",
      "funding",
      "undo",
      "crashAt",
    ], "confirmed apply");
    const id = requiredText(input.operationId, "confirmed apply.operationId");
    const expected = exactKeys(input.expected, [
      "state",
      "outpoint",
      "actionSequence",
    ], "confirmed apply.expected");
    const next = exactKeys(input.next, [
      "state",
      "outpoint",
      "actionSequence",
      "height",
      "blockHash",
    ], "confirmed apply.next");
    const expectedState = state(expected.state, "expected state");
    const expectedOutpoint = outpoint(expected.outpoint, "expected outpoint");
    const expectedSequence = integer(
      expected.actionSequence,
      0,
      0x1_ffff_ffff,
      "expected sequence",
    );
    const nextState = state(next.state, "next state");
    const nextOutpoint = outpoint(next.outpoint, "next outpoint");
    const nextSequence = integer(
      next.actionSequence,
      0,
      0x1_ffff_ffff,
      "next sequence",
    );
    const height = integer(
      next.height,
      0,
      Number.MAX_SAFE_INTEGER,
      "next height",
    );
    const blockHash = txid(next.blockHash, "next block hash");
    const notes = exactKeys(input.notes, ["insert", "spend"], "notes");
    const funding = exactKeys(input.funding, ["spend", "change"], "funding");
    if (
      ![
        input.records,
        notes.insert,
        notes.spend,
        funding.change,
      ].every(Array.isArray)
    ) fail("confirmed collections must be arrays");
    const records = input.records.map((v) => {
      const r = exactKeys(v, ["recordId", "record"], "record");
      return {
        recordId: requiredText(r.recordId, "record ID"),
        record: bytes(r.record, 128, "record"),
      };
    });
    unique(records, (v) => v.recordId, "records");
    const inserts = notes.insert.map((v) => {
      const n = exactKeys(
        v,
        ["noteId", "recordId", "noteIndex", "nullifier"],
        "note insert",
      );
      return {
        noteId: requiredText(n.noteId, "note ID"),
        recordId: requiredText(n.recordId, "note record ID"),
        noteIndex: integer(
          n.noteIndex,
          0,
          MAX_U32,
          "note insert.noteIndex",
        ),
        nullifier: frBuffer(n.nullifier, "note insert.nullifier"),
      };
    });
    const spends = notes.spend.map((v) => requiredText(v, "note spend"));
    unique(inserts, (v) => v.noteId, "note inserts");
    unique(spends, (v) => v, "note spends");
    const spendOutpoint = outpoint(funding.spend, "funding spend");
    if (funding.change.length !== 1) {
      fail("confirmed apply requires exactly one change UTXO");
    }
    const change = funding.change.map((v) => {
      const u = exactKeys(v, ["txid", "vout", "valueSats"], "change");
      const valueSats = requiredText(u.valueSats, "change value");
      if (
        !/^(0|[1-9][0-9]*)$/.test(valueSats) ||
        BigInt(valueSats) === 0n ||
        BigInt(valueSats) > MAX_MONEY_SATS
      ) fail("change value must be nonzero canonical money");
      return {
        txid: txid(u.txid, "change txid"),
        vout: integer(u.vout, 0, MAX_U32, "change vout"),
        valueSats,
      };
    })[0];
    const undo = variableBytes(input.undo, "undo");
    if (input.crashAt !== null && typeof input.crashAt !== "string") {
      fail("crashAt must be a string or null");
    }
    return this.#tx((db) => {
      const op = operationAndIntent(db, id);
      const current = db.prepare(
        "SELECT * FROM canonical_state WHERE singleton=1",
      ).get();
      if (!op || !["broadcast", "mempool"].includes(op.journal_state)) {
        fail("confirmed apply requires broadcast or mempool operation");
      }
      if (op.packet_bytes === null) {
        fail("confirmed apply requires the persisted action packet");
      }
      const operationPacket = this.#validateOperationPacket(
        op,
        op.packet_bytes,
      );
      const inspected = this.#inspectSignedOperation(op);
      if (
        !same(current.state_bytes, expectedState) ||
        !same(current.txid, expectedOutpoint.txid) ||
        current.vout !== expectedOutpoint.vout ||
        current.action_sequence !== expectedSequence ||
        !same(op.expected_state_bytes, expectedState) ||
        !same(op.expected_txid, expectedOutpoint.txid) ||
        op.expected_vout !== expectedOutpoint.vout ||
        op.expected_action_sequence !== expectedSequence ||
        op.expected_height !== current.height ||
        !same(op.expected_block_hash, current.block_hash)
      ) {
        fail(
          "confirmed apply expected canonical state/outpoint/sequence is stale",
        );
      }
      if (
        !same(expectedState, operationPacket.preBytes)
        || !same(nextState, operationPacket.postBytes)
        || nextSequence !==
          Number(operationPacket.packet.postState.actionSequence)
      ) {
        fail(
          "confirmed state must exactly match the persisted action packet transition",
        );
      }
      if (nextSequence !== expectedSequence + 1) {
        fail("successor sequence must increment by one");
      }
      const signedTxid = Buffer.from(inspected.signed.txid, "hex");
      if (
        !same(nextOutpoint.txid, signedTxid)
        || nextOutpoint.vout !== 0
      ) {
        fail(
          "confirmed successor must be output zero of the exact persisted signed transaction",
        );
      }
      if (
        height < current.height ||
        (height === current.height && !same(blockHash, current.block_hash))
      ) fail("same-height successors must share the block hash");
      if (
        !same(spendOutpoint.txid, op.funding_txid)
        || spendOutpoint.vout !== op.funding_vout
      ) {
        fail("confirmed funding spend must equal the immutable intent outpoint");
      }
      if (
        !same(change.txid, signedTxid)
        || change.vout !== inspected.changeIndex
        || change.valueSats !== inspected.changeValueSats.toString()
      ) {
        fail(
          "confirmed change must equal the exact output of the persisted signed transaction",
        );
      }
      if (same(signedTxid, spendOutpoint.txid)) {
        fail(
          "change transaction must differ from spent funding outpoint transaction",
        );
      }
      const isDeposit = op.kind === "deposit",
        isWithdrawal = op.kind === "withdrawal";
      const noteMutation = isWithdrawal
        ? { noteNodes: [], noteFrontier: [] }
        : deriveNoteAppendMutation(db, operationPacket.packet);
      const nullifierMutation = isDeposit
        ? { nullifierNodes: [], nullifierLeaves: [] }
        : deriveNullifierInsertionMutation(db, operationPacket.packet);
      if (isWithdrawal) {
        assertStoredRoot(
          db,
          "note_nodes",
          Buffer.from(operationPacket.packet.preState.noteRoot, "hex"),
          "note tree",
        );
      }
      if (isDeposit) {
        assertStoredRoot(
          db,
          "nullifier_nodes",
          Buffer.from(operationPacket.packet.preState.nullifierRoot, "hex"),
          "nullifier tree",
        );
      }
      const noteNodes = noteMutation.noteNodes;
      const frontier = noteMutation.noteFrontier;
      const nullifierNodes = nullifierMutation.nullifierNodes;
      const leaves = nullifierMutation.nullifierLeaves;
      const hasNoteTree = noteNodes.length > 0 && frontier.length > 0;
      const hasNullifierTree = nullifierNodes.length > 0 && leaves.length === 2;
      const depositShape = records.length === 1 && inserts.length <= 1 &&
        spends.length === 0 && hasNoteTree && nullifierNodes.length === 0 &&
        leaves.length === 0;
      const transferShape = records.length === 1 && inserts.length <= 1 &&
        spends.length === 1 && hasNoteTree && hasNullifierTree;
      const withdrawalShape = records.length === 0 && inserts.length === 0 &&
        spends.length === 1 && noteNodes.length === 0 &&
        frontier.length === 0 &&
        hasNullifierTree;
      if (
        (isDeposit && !depositShape) ||
        (!isDeposit && !isWithdrawal && !transferShape) ||
        (isWithdrawal && !withdrawalShape)
      ) fail("confirmed mutations do not match action kind");
      const outputNoteIndex = Number(
        operationPacket.packet.preState.noteCount,
      );
      if (
        !isWithdrawal
        && inserts.length === 1
        && (
          records[0].recordId !== inserts[0].recordId
          || inserts[0].noteIndex !== outputNoteIndex
        )
      ) {
        fail(
          "owned output note must reference the exact output record and append index",
        );
      }
      if (
        !isWithdrawal &&
        !same(
          records[0].record,
          operationPacket.packet.encryptedRecord,
        )
      ) {
        fail("output record must equal the exact encrypted record in the packet");
      }
      if (
        !isWithdrawal &&
        db.prepare(
          "SELECT note_index FROM note_leaves WHERE note_index=?",
        ).get(outputNoteIndex)
      ) {
        fail("public note leaf append position is already occupied");
      }
      const reservedFunding = db.prepare(
        "SELECT * FROM funding_utxos WHERE txid=? AND vout=? AND reservation_operation_id=? AND spent=0",
      ).get(spendOutpoint.txid, spendOutpoint.vout, id);
      if (!reservedFunding) {
        fail("confirmed funding UTXO is not reserved by this operation");
      }
      const reservedNote = isDeposit ? null : db.prepare(
        "SELECT * FROM owned_notes WHERE note_id=? AND reservation_operation_id=? AND spent=0",
      ).get(spends[0], id);
      if (
        !isDeposit
        && (
          spends[0] !== op.selected_note_id
          || !reservedNote
          || !same(
            reservedNote.nullifier_key,
            Buffer.from(operationPacket.packet.publicNullifier, "hex"),
          )
        )
      ) {
        fail(
          "confirmed note/nullifier is not the exact note reserved by this operation",
        );
      }
      const ordinal = db.prepare(
        "SELECT COALESCE(MAX(action_ordinal),-1) AS ordinal FROM undo_records WHERE height=? AND block_hash=?",
      ).get(height, blockHash).ordinal + 1;
      const delta = {
        noteNodes: noteNodes.map((v) => ({
          depth: v.depth,
          nodeIndex: v.nodeIndex,
          before: rowOrNull(
            db.prepare(
              "SELECT * FROM note_nodes WHERE depth=? AND node_index=?",
            ).get(v.depth, v.nodeIndex),
          ),
        })),
        noteFrontier: frontier.map((v) => ({
          depth: v.depth,
          before: rowOrNull(
            db.prepare("SELECT * FROM note_frontier WHERE depth=?").get(
              v.depth,
            ),
          ),
        })),
        noteLeaves: isWithdrawal
          ? []
          : [{
            noteIndex: Number(
              operationPacket.packet.preState.noteCount,
            ),
            before: rowOrNull(
              db.prepare(
                "SELECT * FROM note_leaves WHERE note_index=?",
              ).get(Number(operationPacket.packet.preState.noteCount)),
            ),
          }],
        nullifierNodes: nullifierNodes.map((v) => ({
          depth: v.depth,
          nodeIndex: v.nodeIndex,
          before: rowOrNull(
            db.prepare(
              "SELECT * FROM nullifier_nodes WHERE depth=? AND node_index=?",
            ).get(v.depth, v.nodeIndex),
          ),
        })),
        leaves: leaves.map((v) => ({
          physicalIndex: v.physicalIndex,
          leafType: v.leafType,
          key: v.key,
          leafBefore: rowOrNull(
            db.prepare("SELECT * FROM nullifier_leaves WHERE physical_index=?")
              .get(v.physicalIndex),
          ),
          orderBefore: rowOrNull(
            db.prepare(
              "SELECT * FROM nullifier_order_keys WHERE leaf_type=? AND key_be=?",
            ).get(v.leafType, v.key),
          ),
        })),
        records: records.map((v) => ({
          recordId: v.recordId,
          before: rowOrNull(
            db.prepare("SELECT * FROM encrypted_note_records WHERE record_id=?")
              .get(v.recordId),
          ),
        })),
        notes: [
          ...inserts.map((v) => ({
            noteId: v.noteId,
            before: rowOrNull(
              db.prepare("SELECT * FROM owned_notes WHERE note_id=?").get(
                v.noteId,
              ),
            ),
          })),
          ...spends.map((noteId) => ({
            noteId,
            before: rowOrNull(
              db.prepare("SELECT * FROM owned_notes WHERE note_id=?").get(
                noteId,
              ),
            ),
          })),
        ],
        utxos: [{
          txid: spendOutpoint.txid,
          vout: spendOutpoint.vout,
          before: reservedFunding,
        }, {
          txid: change.txid,
          vout: change.vout,
          before: rowOrNull(
            db.prepare("SELECT * FROM funding_utxos WHERE txid=? AND vout=?")
              .get(change.txid, change.vout),
          ),
        }],
        operationBefore: {
          operation_id: op.operation_id,
          journal_state: op.journal_state,
          reason: op.reason,
          updated_at_ms: op.updated_at_ms,
        },
        overlayBefore: rowOrNull(
          db.prepare("SELECT * FROM mempool_overlay WHERE operation_id=?").get(
            id,
          ),
        ),
      };
      db.prepare(
        "INSERT INTO undo_records(height,block_hash,action_ordinal,operation_id,predecessor_state_bytes,predecessor_txid,predecessor_vout,predecessor_sequence,predecessor_height,predecessor_block_hash,successor_txid,successor_vout,successor_sequence,undo_delta_bytes,undo_bytes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
      ).run(
        height,
        blockHash,
        ordinal,
        id,
        current.state_bytes,
        current.txid,
        current.vout,
        current.action_sequence,
        current.height,
        current.block_hash,
        nextOutpoint.txid,
        nextOutpoint.vout,
        nextSequence,
        Buffer.from(serialize(delta)),
        undo,
      );
      crash(input.crashAt, "confirmed.after_undo");
      for (const v of noteNodes) {
        db.prepare(
          "INSERT INTO note_nodes(depth,node_index,node_hash) VALUES(?,?,?) ON CONFLICT(depth,node_index) DO UPDATE SET node_hash=excluded.node_hash",
        ).run(v.depth, v.nodeIndex, v.nodeHash);
      }
      for (const v of frontier) {
        db.prepare(
          "INSERT INTO note_frontier(depth,node_hash) VALUES(?,?) ON CONFLICT(depth) DO UPDATE SET node_hash=excluded.node_hash",
        ).run(v.depth, v.nodeHash);
      }
      if (!isWithdrawal) {
        db.prepare(
          "INSERT INTO note_leaves(note_index,leaf_hash,encrypted_record,action_sequence,transaction_id) VALUES(?,?,?,?,?)",
        ).run(
          Number(operationPacket.packet.preState.noteCount),
          Buffer.from(operationPacket.packet.outputNoteLeaf, "hex"),
          operationPacket.packet.encryptedRecord,
          nextSequence,
          nextOutpoint.txid,
        );
      }
      const nullifierAccess = productionNullifierSqliteAccess(db);
      for (const v of nullifierNodes) nullifierAccess.writeNode(v);
      for (const v of leaves) nullifierAccess.writeLeaf(v);
      for (const v of records) this.#putRecord(db, v.recordId, v.record);
      for (const v of inserts) {
        db.prepare(
          `INSERT INTO owned_notes(
            note_id,record_id,note_index,nullifier_key,
            reservation_operation_id,spent
          ) VALUES(?,?,?,?,NULL,CASE WHEN EXISTS(
            SELECT 1 FROM nullifier_order_keys
            WHERE leaf_type=2 AND key_be=?
          ) THEN 1 ELSE 0 END)`,
        ).run(
          v.noteId,
          v.recordId,
          v.noteIndex,
          v.nullifier,
          v.nullifier,
        );
      }
      for (const v of spends) {
        db.prepare(
          "UPDATE owned_notes SET spent=1,reservation_operation_id=NULL WHERE note_id=?",
        ).run(v);
      }
      db.prepare(
        "UPDATE funding_utxos SET spent=1,reservation_operation_id=NULL WHERE txid=? AND vout=?",
      ).run(spendOutpoint.txid, spendOutpoint.vout);
      db.prepare(
        "INSERT INTO funding_utxos(txid,vout,value_sats,reservation_operation_id,spent) VALUES(?,?,?,NULL,0)",
      ).run(change.txid, change.vout, change.valueSats);
      db.prepare(
        "UPDATE canonical_state SET state_bytes=?,txid=?,vout=?,action_sequence=?,height=?,block_hash=? WHERE singleton=1",
      ).run(
        nextState,
        nextOutpoint.txid,
        nextOutpoint.vout,
        nextSequence,
        height,
        blockHash,
      );
      db.prepare(
        "UPDATE pending_operations SET journal_state='confirmed',updated_at_ms=? WHERE operation_id=?",
      ).run(Date.now(), id);
      db.prepare("DELETE FROM mempool_overlay WHERE operation_id=?").run(id);
      db.prepare("DELETE FROM undo_records WHERE height<?").run(
        height - (V2_STORE_UNDO_BLOCKS - 1),
      );
      crash(input.crashAt, "confirmed.before_commit");
      return this.canonicalState();
    });
  }
  settleConfirmedOperation(value) {
    const input = exactKeys(
      value,
      ["operationId", "crashAt"],
      "confirmed settlement",
    );
    const id = requiredText(
      input.operationId,
      "confirmed settlement.operationId",
    );
    const crashAt = crashStage(
      input.crashAt,
      V2_OPERATION_SETTLE_CRASH_STAGES,
      "confirmed settlement.crashAt",
    );
    return this.#tx((db) => {
      const row = operationAndIntent(db, id);
      if (!row) fail("confirmed settlement operation does not exist");
      if (row.journal_state === "settled") return this.operation(id);
      if (row.journal_state !== "confirmed") {
        fail("only a confirmed operation can become settled");
      }
      const inspected = this.#inspectSignedOperation(row);
      const undoRows = db.prepare(
        `SELECT predecessor_txid,predecessor_vout,predecessor_sequence,
          successor_txid,successor_vout,successor_sequence
         FROM undo_records WHERE operation_id=?`,
      ).all(id);
      const signedTxid = Buffer.from(inspected.signed.txid, "hex");
      if (undoRows.length === 1) {
        const undo = undoRows[0];
        if (
          !same(undo.predecessor_txid, row.expected_txid)
          || undo.predecessor_vout !== row.expected_vout
          || undo.predecessor_sequence !== row.expected_action_sequence
          || !same(undo.successor_txid, signedTxid)
          || undo.successor_vout !== 0
          || undo.successor_sequence !== row.expected_action_sequence + 1
        ) {
          fail(
            "confirmed settlement undo record does not bind the exact operation lineage",
          );
        }
      } else if (undoRows.length === 0) {
        const recovered = db.prepare(
          `SELECT action_sequence,kind,packet_bytes
           FROM recovery_actions WHERE transaction_id=?`,
        ).all(signedTxid);
        const canonical = db.prepare(
          "SELECT action_sequence FROM canonical_state WHERE singleton=1",
        ).get();
        const checkpoint = db.prepare(
          "SELECT action_count FROM recovery_checkpoint WHERE singleton=1",
        ).get();
        if (
          recovered.length !== 1
          || recovered[0].action_sequence
            !== row.expected_action_sequence + 1
          || recovered[0].kind !== row.kind
          || !same(recovered[0].packet_bytes, row.packet_bytes)
          || !canonical
          || canonical.action_sequence < recovered[0].action_sequence
          || !checkpoint
          || checkpoint.action_count !== canonical.action_sequence
        ) {
          fail(
            "confirmed settlement lacks an exact authenticated canonical recovery action",
          );
        }
      } else {
        fail(
          "confirmed settlement has duplicate retained canonical undo records",
        );
      }
      db.prepare(
        "UPDATE pending_operations SET journal_state='settled',reason=NULL,updated_at_ms=? WHERE operation_id=? AND journal_state='confirmed'",
      ).run(Date.now(), id);
      crash(crashAt, "settle.before_commit");
      return this.operation(id);
    });
  }
  markConflict(value) {
    const input = exactKeys(value, ["operationId", "reason"], "conflict");
    const id = requiredText(input.operationId, "conflict.operationId");
    const reason = requiredText(input.reason, "conflict.reason");
    return this.#tx((db) => {
      const row = db.prepare(
        "SELECT journal_state FROM pending_operations WHERE operation_id=?",
      ).get(id);
      if (
        !row || !(TRANSITIONS[row.journal_state] ?? new Set()).has("conflicted")
      ) fail("operation cannot be conflicted from its current state");
      releaseOperationResources(db, id);
      db.prepare("DELETE FROM mempool_overlay WHERE operation_id=?").run(id);
      db.prepare(
        "UPDATE pending_operations SET journal_state='conflicted',reason=?,updated_at_ms=? WHERE operation_id=?",
      ).run(reason, Date.now(), id);
      return this.operation(id);
    });
  }
  rollbackReorg(value) {
    const input = exactKeys(value, [
      "commonAncestorHeight",
      "commonAncestorBlockHash",
    ], "reorg rollback");
    const height = integer(
      input.commonAncestorHeight,
      0,
      Number.MAX_SAFE_INTEGER,
      "reorg common ancestor height",
    );
    const hash = txid(
      input.commonAncestorBlockHash,
      "reorg common ancestor block hash",
    );
    return this.#tx((db) => {
      const earliest = db.prepare(
        "SELECT predecessor_height FROM undo_records ORDER BY height,action_ordinal LIMIT 1",
      ).get();
      if (earliest && height < earliest.predecessor_height) {
        fail("reorg exceeds retained undo window; wipe and replay required");
      }
      const rows = db.prepare(
        "SELECT * FROM undo_records WHERE height>? ORDER BY height DESC,action_ordinal DESC",
      ).all(height);
      for (const undo of rows) {
        const tip = db.prepare(
          "SELECT * FROM canonical_state WHERE singleton=1",
        ).get();
        if (
          !same(tip.txid, undo.successor_txid) ||
          tip.vout !== undo.successor_vout ||
          tip.action_sequence !== undo.successor_sequence
        ) fail("undo lineage does not match canonical successor outpoint");
        restoreDelta(db, undo.undo_delta_bytes);
        db.prepare(
          "UPDATE canonical_state SET state_bytes=?,txid=?,vout=?,action_sequence=?,height=?,block_hash=? WHERE singleton=1",
        ).run(
          undo.predecessor_state_bytes,
          undo.predecessor_txid,
          undo.predecessor_vout,
          undo.predecessor_sequence,
          undo.predecessor_height,
          undo.predecessor_block_hash,
        );
        db.prepare(
          "DELETE FROM undo_records WHERE height=? AND block_hash=? AND action_ordinal=?",
        ).run(undo.height, undo.block_hash, undo.action_ordinal);
        db.prepare(
          "UPDATE pending_operations SET journal_state='reorged',reason='confirmed state reorged',updated_at_ms=? WHERE operation_id=?",
        ).run(Date.now(), undo.operation_id);
      }
      const anchor = this.canonicalState();
      if (anchor.height !== height || !same(anchor.blockHash, hash)) {
        fail("reorg rollback did not restore the requested common ancestor");
      }
      return anchor;
    });
  }
  undoStatistics() {
    const row = this.#open().prepare(
      "SELECT COUNT(*) AS count,COALESCE(SUM(length(undo_delta_bytes)),0) AS bytes FROM undo_records",
    ).get();
    return Object.freeze({ count: row.count, bytes: row.bytes });
  }
}

export function openV2DirectStore(value) {
  const input = exactKeys(value, [
    "path",
    "profileId",
    "instanceId",
    "networkId",
    "denominationSats",
    "carrierCount",
    "runtimeMaterialsSha256",
    "state",
    "outpoint",
    "actionSequence",
    "height",
    "blockHash",
  ], "open store");
  const store = new V2DirectStore(input.path);
  try {
    store.initialize({
      profileId: input.profileId,
      instanceId: input.instanceId,
      networkId: input.networkId,
      denominationSats: input.denominationSats,
      carrierCount: input.carrierCount,
      runtimeMaterialsSha256: input.runtimeMaterialsSha256,
      state: input.state,
      outpoint: input.outpoint,
      actionSequence: input.actionSequence,
      height: input.height,
      blockHash: input.blockHash,
    });
    return store;
  } catch (error) {
    store.close();
    throw error;
  }
}

/**
 * Open an existing durable store without asking an offline caller to repeat
 * the genesis block height/hash. The signed descriptor identity, complete
 * runtime binding, and exact genesis state outpoint are still rechecked before
 * any canonical or wallet data is returned.
 */
export function openExistingV2DirectStore(value) {
  const input = exactKeys(value, [
    "path",
    "profileId",
    "instanceId",
    "networkId",
    "denominationSats",
    "carrierCount",
    "runtimeMaterialsSha256",
    "state",
    "outpoint",
    "actionSequence",
  ], "open existing store");
  const store = new V2DirectStore(input.path);
  try {
    store.assertBinding({
      profileId: input.profileId,
      instanceId: input.instanceId,
      networkId: input.networkId,
      denominationSats: input.denominationSats,
      carrierCount: input.carrierCount,
      runtimeMaterialsSha256: input.runtimeMaterialsSha256,
    });
    const genesis = store.genesisAnchor();
    const expectedState = state(input.state, "open existing store.state");
    const expectedOutpoint = outpoint(
      input.outpoint,
      "open existing store.outpoint",
    );
    const expectedSequence = integer(
      input.actionSequence,
      0,
      0x1_ffff_ffff,
      "open existing store.actionSequence",
    );
    if (
      !same(genesis.state, expectedState)
      || !same(genesis.outpoint.txid, expectedOutpoint.txid)
      || genesis.outpoint.vout !== expectedOutpoint.vout
      || genesis.actionSequence !== expectedSequence
    ) {
      fail("existing store genesis does not match the signed instance descriptor");
    }
    return store;
  } catch (error) {
    store.close();
    throw error;
  }
}
