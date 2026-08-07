/**
 * Private, unqualified beta persistence lane for direct V2 state. It follows
 * only a locally accepted zero-conf successor chain: it is not a scanner,
 * finality tracker, or production wallet store.
 */
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { chmodSync, lstatSync, mkdirSync, openSync, closeSync } from "node:fs";
import { dirname, isAbsolute, join, parse, relative, resolve } from "node:path";

import { decodeActionPacket } from "../../action/v2/packet.mjs";
import { DIRECT_V2_PERSISTENT_PROVING_TRANSITION_SCHEMA } from "../../action/v2/proving-transition.mjs";
import { decodeStateNftCommitment, encodeStateNftCommitment } from "../../action/v2/state.mjs";
import { createDirectV2PoolModel } from "../../action/v2/transition.mjs";
import { isSupportedDirectV2NetworkId } from "../../action/v2/network.mjs";
import { hashIndexedNullifierLeaf, hashIndexedNullifierNode } from "../../action/v2/poseidon.mjs";
import {
  assemblePersistentProvingTransition,
  derivePersistentNoteMembershipWitness,
  derivePersistentPacketPostState,
  PersistentTreeEngineError,
  PERSISTENT_TREE_DEPTH,
} from "../../pool/v2/persistent-tree-engine.mjs";
import {
  createPersistentNullifierSqliteAccess,
  PERSISTENT_NULLIFIER_SQLITE_PROFILES,
} from "../../pool/v2/persistent-indexed-nullifier-sqlite.mjs";

export const V2_BETA_INCREMENTAL_STORE_SCHEMA = 4;
export const V2_BETA_INCREMENTAL_STORE_STATES = Object.freeze([
  "reserved", "staged", "accepted_zero_conf", "rejected",
]);
const FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export class V2BetaIncrementalStoreError extends Error {
  constructor(message) { super(message); this.name = "V2BetaIncrementalStoreError"; }
}
const fail = (message) => { throw new V2BetaIncrementalStoreError(message); };
const same = (left, right) => Buffer.from(left).equals(Buffer.from(right));
const copy = (value) => Buffer.from(value);
const hash = (value) => createHash("sha256").update(value).digest();
function exact(value, keys, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} has unsupported or missing fields`);
  }
  return value;
}
function text(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.length > 256) fail(`${label} must be nonempty text`);
  return value;
}
function integer(value, min, max, label) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail(`${label} is out of range`);
  return value;
}
function blob(value, length, label) {
  if (!(value instanceof Uint8Array) || value.length !== length) fail(`${label} must be exactly ${length} bytes`);
  return Buffer.from(value);
}
function fr(value, label) {
  const result = blob(value, 32, label);
  if (BigInt(`0x${result.toString("hex")}`) >= FR_MODULUS) fail(`${label} must be canonical BN254 Fr`);
  return result;
}
function money(value, label) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) fail(`${label} must be canonical money text`);
  if (BigInt(value) > 2_100_000_000_000_000n) fail(`${label} exceeds the BCH monetary range`);
  return value;
}
function bootstrapFundingDigest(sourceTransactionId, entries) {
  const digest = createHash("sha256");
  digest.update(Buffer.from("ShieldKit/V2Beta/bootstrap-funding/v1\0", "utf8"));
  digest.update(sourceTransactionId);
  for (const entry of entries) {
    const frame = Buffer.alloc(12);
    frame.writeUInt32LE(entry.vout, 0);
    frame.writeBigUInt64LE(BigInt(entry.valueSats), 4);
    digest.update(frame);
  }
  return digest.digest();
}
function safePrivatePath(value) {
  if (typeof value !== "string" || value.length === 0) fail("databasePath must be a nonempty path");
  const path = isAbsolute(value) ? value : resolve(value);
  const parent = dirname(path); const root = parse(parent).root;
  if (parent === root) fail("database must be placed in a dedicated private directory");
  const segments = relative(root, parent).split("/").filter(Boolean); let current = root; let created = false;
  for (const [index, segment] of segments.entries()) {
    const next = join(current, segment);
    try { const stat = lstatSync(next); if (stat.isSymbolicLink() || !stat.isDirectory()) fail("database parent ancestry contains a symlink or non-directory"); }
    catch (error) { if (!(error && error.code === "ENOENT")) throw error; if (index !== segments.length - 1) fail("database parent ancestor does not exist"); mkdirSync(next, { mode: 0o700 }); created = true; const stat = lstatSync(next); if (stat.isSymbolicLink() || !stat.isDirectory()) fail("database parent creation was replaced"); }
    current = next;
  }
  if (created) chmodSync(parent, 0o700);
  const stat = lstatSync(parent);
  if (stat.isSymbolicLink() || !stat.isDirectory() || (stat.mode & 0o777) !== 0o700) fail("database parent must be a real 0700 directory");
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) fail("database parent must be owned by the effective UID");
  return path;
}
function assertPrivateRegular(path, label) {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1) fail(`${label} must be a non-symlink, non-hardlinked regular file`);
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) fail(`${label} must be owned by the effective UID`);
  return stat;
}
function securePrivateFile(path, label) {
  try { assertPrivateRegular(path, label); }
  catch (error) { if (!(error && error.code === "ENOENT")) throw error; try { closeSync(openSync(path, "wx", 0o600)); } catch (openError) { if (!(openError && openError.code === "EEXIST")) throw openError; assertPrivateRegular(path, label); } }
  chmodSync(path, 0o600);
  if ((assertPrivateRegular(path, label).mode & 0o777) !== 0o600) fail(`${label} mode must be 0600`);
}
function secureSidecars(path) {
  for (const candidate of [path, `${path}-wal`, `${path}-shm`]) {
    try { chmodSync(candidate, 0o600); if ((assertPrivateRegular(candidate, "database sidecar").mode & 0o777) !== 0o600) fail("database sidecar mode must be 0600"); }
    catch (error) { if (!(error && error.code === "ENOENT")) throw error; }
  }
}
function telemetryFileBytes(path, label, optional = false) {
  let stat;
  try { stat = lstatSync(path); }
  catch (error) {
    if (optional && error?.code === "ENOENT") return 0;
    throw error;
  }
  if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1
    || !Number.isSafeInteger(stat.size) || stat.size < 0) {
    fail(`${label} is not a measurable private regular file`);
  }
  return stat.size;
}
function openPrivateDatabase(path) {
  securePrivateFile(path, "database");
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA busy_timeout=5000;");
  secureSidecars(path);
  return db;
}
function encodedFr(value) { return Buffer.from(value.toString(16).padStart(64, "0"), "hex"); }
function nullifierLeaf({ leafType, physicalIndex, key, successorIndex, successorKey }) {
  return encodedFr(hashIndexedNullifierLeaf([
    BigInt(leafType), BigInt(physicalIndex), BigInt(`0x${key.toString("hex")}`),
    BigInt(successorIndex), BigInt(`0x${successorKey.toString("hex")}`),
  ]));
}
function pair(left, right) {
  return encodedFr(hashIndexedNullifierNode(
    BigInt(`0x${left.toString("hex")}`), BigInt(`0x${right.toString("hex")}`),
  ));
}
function nullifierDefaults() {
  const values = [encodedFr(hashIndexedNullifierLeaf([0n, 0n, 0n, 0n, 0n]))];
  for (let depth = 0; depth < PERSISTENT_TREE_DEPTH; depth += 1) values.push(pair(values[depth], values[depth]));
  return values;
}
const NULLIFIER_DEFAULTS = Object.freeze(nullifierDefaults());
// A derived successor is intentionally process-local. It carries authenticated
// tree work between transaction preparation and final packet binding, but no
// unbound packet is ever written to SQLite.
const DERIVED_SUCCESSORS = new WeakMap();

const SCHEMA = `
CREATE TABLE IF NOT EXISTS metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL, profile_id BLOB NOT NULL CHECK(length(profile_id)=32), instance_id BLOB NOT NULL CHECK(length(instance_id)=32), network_id INTEGER NOT NULL, denomination_sats TEXT NOT NULL, genesis_state BLOB NOT NULL CHECK(length(genesis_state)=128), genesis_txid BLOB NOT NULL CHECK(length(genesis_txid)=32), genesis_vout INTEGER NOT NULL, genesis_acceptance_id BLOB NOT NULL CHECK(length(genesis_acceptance_id)=32), runtime_material_sha256 BLOB NOT NULL CHECK(length(runtime_material_sha256)=32), runtime_manifest_sha256 BLOB NOT NULL CHECK(length(runtime_manifest_sha256)=32), deployment_zero_conf_evidence_sha256 BLOB NOT NULL CHECK(length(deployment_zero_conf_evidence_sha256)=32)) STRICT;
CREATE TABLE IF NOT EXISTS accepted_zero_conf_tip (singleton INTEGER PRIMARY KEY CHECK(singleton=1), state_bytes BLOB NOT NULL CHECK(length(state_bytes)=128), txid BLOB NOT NULL CHECK(length(txid)=32), vout INTEGER NOT NULL, action_sequence INTEGER NOT NULL, acceptance_id BLOB NOT NULL CHECK(length(acceptance_id)=32)) STRICT;
CREATE TABLE IF NOT EXISTS note_nodes (depth INTEGER NOT NULL CHECK(depth BETWEEN 0 AND 32), node_index INTEGER NOT NULL, node_hash BLOB NOT NULL CHECK(length(node_hash)=32), PRIMARY KEY(depth,node_index)) STRICT;
CREATE TABLE IF NOT EXISTS note_frontier (depth INTEGER PRIMARY KEY CHECK(depth BETWEEN 0 AND 31), node_hash BLOB NOT NULL CHECK(length(node_hash)=32)) STRICT;
CREATE TABLE IF NOT EXISTS note_leaves (note_index INTEGER PRIMARY KEY, leaf_hash BLOB NOT NULL CHECK(length(leaf_hash)=32), encrypted_record BLOB NOT NULL CHECK(length(encrypted_record)=128), action_sequence INTEGER NOT NULL, transaction_id BLOB NOT NULL CHECK(length(transaction_id)=32)) STRICT;
CREATE TABLE IF NOT EXISTS nullifier_nodes (depth INTEGER NOT NULL CHECK(depth BETWEEN 0 AND 32), node_index INTEGER NOT NULL, node_hash BLOB NOT NULL CHECK(length(node_hash)=32), PRIMARY KEY(depth,node_index)) STRICT;
CREATE TABLE IF NOT EXISTS nullifier_leaves (physical_index INTEGER PRIMARY KEY, leaf_type INTEGER NOT NULL, leaf_hash BLOB NOT NULL CHECK(length(leaf_hash)=32), key_be BLOB NOT NULL CHECK(length(key_be)=32), successor_index INTEGER NOT NULL, successor_key_be BLOB NOT NULL CHECK(length(successor_key_be)=32)) STRICT;
CREATE TABLE IF NOT EXISTS nullifier_order_keys (leaf_type INTEGER NOT NULL, key_be BLOB NOT NULL CHECK(length(key_be)=32), physical_index INTEGER NOT NULL, PRIMARY KEY(leaf_type,key_be)) STRICT;
CREATE TABLE IF NOT EXISTS encrypted_note_records (record_id TEXT PRIMARY KEY, record_bytes BLOB NOT NULL CHECK(length(record_bytes)=128)) STRICT;
CREATE TABLE IF NOT EXISTS owned_notes (note_id TEXT PRIMARY KEY, record_id TEXT NOT NULL REFERENCES encrypted_note_records(record_id), note_index INTEGER NOT NULL UNIQUE, nullifier_key BLOB NOT NULL CHECK(length(nullifier_key)=32), reservation_operation_id TEXT, spent INTEGER NOT NULL CHECK(spent IN(0,1))) STRICT;
CREATE TABLE IF NOT EXISTS funding_utxos (txid BLOB NOT NULL CHECK(length(txid)=32), vout INTEGER NOT NULL, value_sats TEXT NOT NULL, reservation_operation_id TEXT, spent INTEGER NOT NULL CHECK(spent IN(0,1)), PRIMARY KEY(txid,vout)) STRICT;
CREATE TABLE IF NOT EXISTS bootstrap_funding_set (singleton INTEGER PRIMARY KEY CHECK(singleton=1), source_txid BLOB NOT NULL CHECK(length(source_txid)=32), output_count INTEGER NOT NULL CHECK(output_count=10), set_sha256 BLOB NOT NULL CHECK(length(set_sha256)=32)) STRICT;
CREATE TABLE IF NOT EXISTS operations (operation_id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN('deposit','transfer','withdrawal')), state TEXT NOT NULL CHECK(state IN('reserved','staged','accepted_zero_conf','rejected')), expected_state BLOB NOT NULL CHECK(length(expected_state)=128), expected_txid BLOB NOT NULL CHECK(length(expected_txid)=32), expected_vout INTEGER NOT NULL, expected_sequence INTEGER NOT NULL, expected_acceptance_id BLOB NOT NULL CHECK(length(expected_acceptance_id)=32), selected_note_id TEXT, funding_txid BLOB, funding_vout INTEGER, packet BLOB, proof_artifact BLOB, proof_artifact_sha256 BLOB, transaction_artifact BLOB, transaction_artifact_sha256 BLOB, local_wallet_commit_complete INTEGER NOT NULL DEFAULT 0 CHECK(local_wallet_commit_complete IN(0,1)), accepted_txid BLOB CHECK(accepted_txid IS NULL OR length(accepted_txid)=32), accepted_vout INTEGER, accepted_acceptance_id BLOB CHECK(accepted_acceptance_id IS NULL OR length(accepted_acceptance_id)=32), safe_pre_send_abort_reason TEXT) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS one_active_beta_operation ON operations(state) WHERE state IN('reserved','staged');
`;

const BETA_STORE_TABLES = Object.freeze([
  "metadata", "accepted_zero_conf_tip", "note_nodes", "note_frontier", "note_leaves",
  "nullifier_nodes", "nullifier_leaves", "nullifier_order_keys", "encrypted_note_records",
  "owned_notes", "funding_utxos", "bootstrap_funding_set", "operations",
]);

function tableColumns(db, table) {
  return new Set(db.prepare(`PRAGMA table_info(${table})`).all().map((row) => row.name));
}

function assertUninitializedForMigration(db) {
  const tables = new Set(db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((row) => row.name));
  for (const table of tables) {
    if (!table.startsWith("sqlite_") && !BETA_STORE_TABLES.includes(table)) {
      fail("beta store schema layout includes an unknown table and cannot be migrated safely");
    }
  }
  for (const table of BETA_STORE_TABLES) {
    if (db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get().count !== 0) {
      fail("beta store has initialized state and cannot safely infer runtime/deployment provenance; export and initialize a fresh beta store");
    }
  }
}

function ensureBetaStoreSchema(db) {
  const metadata = db.prepare("SELECT schema_version FROM metadata WHERE singleton=1").get();
  const operationColumns = tableColumns(db, "operations");
  const metadataColumns = tableColumns(db, "metadata");
  const requiredOperationColumns = ["local_wallet_commit_complete", "accepted_txid", "accepted_vout", "accepted_acceptance_id", "safe_pre_send_abort_reason"];
  const requiredMetadataColumns = ["runtime_material_sha256", "runtime_manifest_sha256", "deployment_zero_conf_evidence_sha256"];
  const layoutCurrent = requiredOperationColumns.every((name) => operationColumns.has(name))
    && requiredMetadataColumns.every((name) => metadataColumns.has(name));
  if (layoutCurrent) {
    if (metadata && metadata.schema_version !== V2_BETA_INCREMENTAL_STORE_SCHEMA) {
      fail("beta store schema version is incompatible; initialized legacy stores must be exported and reinitialized");
    }
    if (!metadata) assertUninitializedForMigration(db);
    return;
  }
  assertUninitializedForMigration(db);
  db.exec("BEGIN IMMEDIATE");
  try {
    if (!operationColumns.has("local_wallet_commit_complete")) db.exec("ALTER TABLE operations ADD COLUMN local_wallet_commit_complete INTEGER NOT NULL DEFAULT 0 CHECK(local_wallet_commit_complete IN(0,1));");
    if (!operationColumns.has("accepted_txid")) db.exec("ALTER TABLE operations ADD COLUMN accepted_txid BLOB CHECK(accepted_txid IS NULL OR length(accepted_txid)=32);");
    if (!operationColumns.has("accepted_vout")) db.exec("ALTER TABLE operations ADD COLUMN accepted_vout INTEGER;");
    if (!operationColumns.has("safe_pre_send_abort_reason")) db.exec("ALTER TABLE operations ADD COLUMN safe_pre_send_abort_reason TEXT;");
    if (!operationColumns.has("accepted_acceptance_id")) db.exec("ALTER TABLE operations ADD COLUMN accepted_acceptance_id BLOB CHECK(accepted_acceptance_id IS NULL OR length(accepted_acceptance_id)=32);");
    // SQLite cannot add a NOT NULL column without a default. The table is
    // proven empty above; initialize() writes all three immutable bindings.
    if (!metadataColumns.has("runtime_material_sha256")) db.exec("ALTER TABLE metadata ADD COLUMN runtime_material_sha256 BLOB;");
    if (!metadataColumns.has("runtime_manifest_sha256")) db.exec("ALTER TABLE metadata ADD COLUMN runtime_manifest_sha256 BLOB;");
    if (!metadataColumns.has("deployment_zero_conf_evidence_sha256")) db.exec("ALTER TABLE metadata ADD COLUMN deployment_zero_conf_evidence_sha256 BLOB;");
    db.exec("COMMIT");
  } catch (error) { try { db.exec("ROLLBACK"); } catch {} throw error; }
}

export class V2BetaIncrementalStore {
  #path; #db;
  constructor({ databasePath }) { this.#path = safePrivatePath(databasePath); this.#db = openPrivateDatabase(this.#path); this.#db.exec(SCHEMA); ensureBetaStoreSchema(this.#db); }
  close() { if (this.#db) { this.#db.close(); this.#db = null; } }
  #open() { if (!this.#db) fail("beta incremental store is closed"); return this.#db; }
  #tx(fn) { const db = this.#open(); db.exec("BEGIN IMMEDIATE"); try { const out = fn(db); db.exec("COMMIT"); return out; } catch (error) { try { db.exec("ROLLBACK"); } catch {} throw error; } }
  initialize(value) {
    const input = exact(value, ["profileId", "instanceId", "networkId", "denominationSats", "state", "outpoint", "acceptanceId", "runtimeMaterialSha256", "runtimeManifestSha256", "deploymentZeroConfEvidenceSha256"], "beta initialize");
    const profileId = blob(input.profileId, 32, "beta initialize.profileId");
    const instanceId = blob(input.instanceId, 32, "beta initialize.instanceId");
    const networkId = integer(input.networkId, 0, 255, "beta initialize.networkId");
    if (!isSupportedDirectV2NetworkId(networkId)) fail("beta initialize.networkId is unsupported");
    const denominationSats = money(input.denominationSats, "beta initialize.denominationSats");
    const stateBytes = blob(input.state, 128, "beta initialize.state");
    const outpoint = exact(input.outpoint, ["txid", "vout"], "beta initialize.outpoint");
    const txid = blob(outpoint.txid, 32, "beta initialize.outpoint.txid");
    const vout = integer(outpoint.vout, 0, 0xffff_ffff, "beta initialize.outpoint.vout");
    const acceptanceId = blob(input.acceptanceId, 32, "beta initialize.acceptanceId");
    const runtimeMaterialSha256 = blob(input.runtimeMaterialSha256, 32, "beta initialize.runtimeMaterialSha256");
    const runtimeManifestSha256 = blob(input.runtimeManifestSha256, 32, "beta initialize.runtimeManifestSha256");
    const deploymentZeroConfEvidenceSha256 = blob(input.deploymentZeroConfEvidenceSha256, 32, "beta initialize.deploymentZeroConfEvidenceSha256");
    let decoded;
    try { decoded = decodeStateNftCommitment(stateBytes, { denominationSats }); } catch (error) { fail(`beta initialize.state is invalid: ${error.message}`); }
    let expected;
    try { expected = encodeStateNftCommitment(createDirectV2PoolModel({ profileId: profileId.toString("hex"), maximumLiveNotes: decoded.maximumLiveNotes, denominationSats }).state, { denominationSats }); } catch (error) { fail(`beta initialize.state cannot form exact genesis: ${error.message}`); }
    if (decoded.profileId !== profileId.toString("hex") || !same(stateBytes, expected) || decoded.actionSequence !== "0") fail("beta initialize.state must be the exact accepted empty genesis");
    return this.#tx((db) => {
      const old = db.prepare("SELECT * FROM metadata WHERE singleton=1").get();
      if (old) {
        if (old.schema_version !== V2_BETA_INCREMENTAL_STORE_SCHEMA || !same(old.profile_id, profileId) || !same(old.instance_id, instanceId) || old.network_id !== networkId || old.denomination_sats !== denominationSats || !same(old.genesis_state, stateBytes) || !same(old.genesis_txid, txid) || old.genesis_vout !== vout || !same(old.genesis_acceptance_id, acceptanceId) || !same(old.runtime_material_sha256, runtimeMaterialSha256) || !same(old.runtime_manifest_sha256, runtimeManifestSha256) || !same(old.deployment_zero_conf_evidence_sha256, deploymentZeroConfEvidenceSha256)) fail("beta store binding differs from its accepted genesis/runtime/deployment provenance");
        return this.binding();
      }
      db.prepare("INSERT INTO metadata VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?)").run(V2_BETA_INCREMENTAL_STORE_SCHEMA, profileId, instanceId, networkId, denominationSats, stateBytes, txid, vout, acceptanceId, runtimeMaterialSha256, runtimeManifestSha256, deploymentZeroConfEvidenceSha256);
      db.prepare("INSERT INTO accepted_zero_conf_tip VALUES(1,?,?,?,?,?)").run(stateBytes, txid, vout, 0, acceptanceId);
      db.prepare("INSERT INTO note_nodes VALUES(32,0,?)").run(Buffer.from(decoded.noteRoot, "hex"));
      const zero = Buffer.alloc(32);
      const leaves = [{ physicalIndex: 0, leafType: 1, key: zero, successorIndex: 1, successorKey: zero }, { physicalIndex: 1, leafType: 3, key: zero, successorIndex: 1, successorKey: zero }];
      for (const leaf of leaves) { const leafHash = nullifierLeaf(leaf); db.prepare("INSERT INTO nullifier_order_keys VALUES(?,?,?)").run(leaf.leafType, leaf.key, leaf.physicalIndex); db.prepare("INSERT INTO nullifier_leaves VALUES(?,?,?,?,?,?)").run(leaf.physicalIndex, leaf.leafType, leafHash, leaf.key, leaf.successorIndex, leaf.successorKey); db.prepare("INSERT INTO nullifier_nodes VALUES(0,?,?)").run(leaf.physicalIndex, leafHash); }
      let node = pair(nullifierLeaf(leaves[0]), nullifierLeaf(leaves[1])); db.prepare("INSERT INTO nullifier_nodes VALUES(1,0,?)").run(node);
      for (let depth = 1; depth < PERSISTENT_TREE_DEPTH; depth += 1) { node = pair(node, NULLIFIER_DEFAULTS[depth]); db.prepare("INSERT INTO nullifier_nodes VALUES(?,0,?)").run(depth + 1, node); }
      if (!same(node, Buffer.from(decoded.nullifierRoot, "hex"))) fail("beta genesis indexed-nullifier root differs from state");
      return this.binding();
    });
  }
  binding() { const row = this.#open().prepare("SELECT * FROM metadata WHERE singleton=1").get(); if (!row || !(row.runtime_material_sha256 instanceof Uint8Array) || !(row.runtime_manifest_sha256 instanceof Uint8Array) || !(row.deployment_zero_conf_evidence_sha256 instanceof Uint8Array) || row.runtime_material_sha256.length !== 32 || row.runtime_manifest_sha256.length !== 32 || row.deployment_zero_conf_evidence_sha256.length !== 32) fail("beta incremental store has incomplete immutable runtime/deployment provenance"); return Object.freeze({ profileId: copy(row.profile_id), instanceId: copy(row.instance_id), networkId: row.network_id, denominationSats: row.denomination_sats, runtimeMaterialSha256: copy(row.runtime_material_sha256), runtimeManifestSha256: copy(row.runtime_manifest_sha256), deploymentZeroConfEvidenceSha256: copy(row.deployment_zero_conf_evidence_sha256) }); }
  optimisticTip() { const row = this.#open().prepare("SELECT * FROM accepted_zero_conf_tip WHERE singleton=1").get(); if (!row) fail("beta incremental store is not initialized"); return Object.freeze({ state: copy(row.state_bytes), outpoint: Object.freeze({ txid: copy(row.txid), vout: row.vout }), actionSequence: row.action_sequence, acceptanceId: copy(row.acceptance_id) }); }
  telemetry() {
    const db = this.#open();
    const tip = this.optimisticTip();
    const state = decodeStateNftCommitment(tip.state, { denominationSats: this.binding().denominationSats });
    const noteCount = db.prepare("SELECT COUNT(*) AS count FROM note_leaves").get().count;
    const nullifierCount = db.prepare("SELECT COUNT(*) AS count FROM nullifier_leaves WHERE leaf_type=2").get().count;
    if (!Number.isSafeInteger(noteCount) || !Number.isSafeInteger(nullifierCount)
      || String(noteCount) !== state.noteCount || String(nullifierCount) !== state.nullifierCount) {
      fail("beta incremental store telemetry does not match authenticated state counters");
    }
    return Object.freeze({
      schema: "shieldkit-v2-beta-incremental-store-telemetry-v1",
      databaseBytes: telemetryFileBytes(this.#path, "database"),
      walBytes: telemetryFileBytes(`${this.#path}-wal`, "database WAL", true),
      noteCount,
      nullifierCount,
      liveCount: noteCount - nullifierCount,
    });
  }
  putEncryptedRecord({ recordId, record }) { return this.#tx((db) => { const id = text(recordId, "recordId"); const bytes = blob(record, 128, "record"); const old = db.prepare("SELECT record_bytes FROM encrypted_note_records WHERE record_id=?").get(id); if (old && !same(old.record_bytes, bytes)) fail("encrypted record id is immutable"); db.prepare("INSERT INTO encrypted_note_records VALUES(?,?) ON CONFLICT(record_id) DO NOTHING").run(id, bytes); }); }
  putOwnedNote({ noteId, recordId, noteIndex, nullifier }) { return this.#tx((db) => { const id = text(noteId, "noteId"); const record = text(recordId, "recordId"); if (!db.prepare("SELECT 1 FROM encrypted_note_records WHERE record_id=?").get(record)) fail("owned note record is absent"); const index = integer(noteIndex, 0, 0xffff_ffff, "noteIndex"); const key = fr(nullifier, "nullifier"); const old = db.prepare("SELECT * FROM owned_notes WHERE note_id=?").get(id); if (old && (old.record_id !== record || old.note_index !== index || !same(old.nullifier_key, key))) fail("owned note is immutable"); db.prepare("INSERT INTO owned_notes VALUES(?,?,?,?,NULL,0) ON CONFLICT(note_id) DO NOTHING").run(id, record, index, key); }); }
  putFundingUtxo({ txid, vout, valueSats }) { return this.#tx((db) => { const id = blob(txid, 32, "funding txid"); const output = integer(vout, 0, 0xffff_ffff, "funding vout"); const value = money(valueSats, "funding valueSats"); const old = db.prepare("SELECT * FROM funding_utxos WHERE txid=? AND vout=?").get(id, output); if (old && old.value_sats !== value) fail("funding UTXO is immutable"); db.prepare("INSERT INTO funding_utxos VALUES(?,?,?,NULL,0) ON CONFLICT(txid,vout) DO NOTHING").run(id, output, value); }); }
  admitAvailableFundingUtxo({ txid, vout, valueSats }) {
    return this.#tx((db) => {
      const id = blob(txid, 32, "funding txid");
      const output = integer(vout, 0, 0xffff_ffff, "funding vout");
      const value = money(valueSats, "funding valueSats");
      if (db.prepare("SELECT 1 FROM operations WHERE state IN('reserved','staged') OR (state='accepted_zero_conf' AND local_wallet_commit_complete=0)").get()) {
        fail("funding inventory cannot change while a beta operation is active");
      }
      const old = db.prepare("SELECT * FROM funding_utxos WHERE txid=? AND vout=?").get(id, output);
      if (old && old.value_sats !== value) fail("funding UTXO is immutable");
      if (old && (old.spent !== 0 || old.reservation_operation_id !== null)) {
        fail("funding UTXO is already spent or reserved");
      }
      if (!old) db.prepare("INSERT INTO funding_utxos VALUES(?,?,?,NULL,0)").run(id, output, value);
      return Object.freeze({ added: old === undefined });
    });
  }
  initializeBootstrapFunding(value) {
    const input = exact(value, ["sourceTransactionId", "utxos"], "bootstrap funding initialization");
    const sourceTransactionId = blob(input.sourceTransactionId, 32, "bootstrap funding sourceTransactionId");
    if (!Array.isArray(input.utxos) || input.utxos.length !== 10) {
      fail("bootstrap funding initialization requires exactly ten UTXOs");
    }
    const entries = input.utxos.map((candidate, index) => {
      const entry = exact(candidate, ["txid", "valueSats", "vout"], `bootstrap funding UTXO ${index}`);
      const txid = blob(entry.txid, 32, `bootstrap funding UTXO ${index}.txid`);
      const vout = integer(entry.vout, 1, 10, `bootstrap funding UTXO ${index}.vout`);
      const valueSats = money(entry.valueSats, `bootstrap funding UTXO ${index}.valueSats`);
      if (!same(txid, sourceTransactionId)) fail("bootstrap funding UTXO source transaction differs");
      return Object.freeze({ txid, vout, valueSats });
    }).sort((left, right) => left.vout - right.vout);
    if (entries.some((entry, index) => entry.vout !== index + 1)) {
      fail("bootstrap funding UTXOs must cover each output from 1 through 10 exactly once");
    }
    const setSha256 = bootstrapFundingDigest(sourceTransactionId, entries);
    return this.#tx((db) => {
      if (!db.prepare("SELECT 1 FROM metadata WHERE singleton=1").get()) {
        fail("bootstrap funding requires an initialized accepted genesis");
      }
      const marker = db.prepare("SELECT * FROM bootstrap_funding_set WHERE singleton=1").get();
      if (marker && (!same(marker.source_txid, sourceTransactionId)
        || marker.output_count !== entries.length || !same(marker.set_sha256, setSha256))) {
        fail("bootstrap funding set is immutable and differs from its committed marker");
      }
      for (const entry of entries) {
        const old = db.prepare("SELECT * FROM funding_utxos WHERE txid=? AND vout=?").get(entry.txid, entry.vout);
        if (old && old.value_sats !== entry.valueSats) fail("bootstrap funding UTXO is immutable");
        db.prepare("INSERT INTO funding_utxos VALUES(?,?,?,NULL,0) ON CONFLICT(txid,vout) DO NOTHING")
          .run(entry.txid, entry.vout, entry.valueSats);
      }
      const persisted = db.prepare("SELECT txid,vout,value_sats FROM funding_utxos WHERE txid=? AND vout BETWEEN 1 AND 10 ORDER BY vout").all(sourceTransactionId);
      if (persisted.length !== entries.length || persisted.some((row, index) =>
        !same(row.txid, entries[index].txid) || row.vout !== entries[index].vout
          || row.value_sats !== entries[index].valueSats)) {
        fail("persisted bootstrap funding set differs before publication");
      }
      if (!marker) db.prepare("INSERT INTO bootstrap_funding_set VALUES(1,?,?,?)")
        .run(sourceTransactionId, entries.length, setSha256);
      return Object.freeze({
        sourceTransactionId: copy(sourceTransactionId),
        outputCount: entries.length,
        setSha256: copy(setSha256),
      });
    });
  }
  assertBootstrapFundingComplete() {
    const db = this.#open();
    const marker = db.prepare("SELECT * FROM bootstrap_funding_set WHERE singleton=1").get();
    if (!marker || marker.output_count !== 10) fail("beta bootstrap funding set is incomplete");
    const persisted = db.prepare("SELECT txid,vout,value_sats FROM funding_utxos WHERE txid=? AND vout BETWEEN 1 AND 10 ORDER BY vout").all(marker.source_txid);
    if (persisted.length !== 10 || persisted.some((row, index) => row.vout !== index + 1)) {
      fail("beta bootstrap funding rows are incomplete");
    }
    const entries = persisted.map((row) => Object.freeze({ txid: copy(row.txid), vout: row.vout, valueSats: row.value_sats }));
    const digest = bootstrapFundingDigest(Buffer.from(marker.source_txid), entries);
    if (!same(digest, marker.set_sha256)) fail("beta bootstrap funding rows differ from their committed marker");
    return Object.freeze({
      sourceTransactionId: copy(marker.source_txid),
      outputCount: marker.output_count,
      setSha256: copy(marker.set_sha256),
    });
  }
  reserveOperation(value) {
    const input = exact(value, ["operationId", "kind", "selectedNoteId", "funding"], "beta operation reservation");
    const operationId = text(input.operationId, "operationId"); const kind = text(input.kind, "kind"); if (!["deposit", "transfer", "withdrawal"].includes(kind)) fail("operation kind is unsupported");
    const selectedNoteId = input.selectedNoteId === null ? null : text(input.selectedNoteId, "selectedNoteId");
    const funding = input.funding === null ? null : exact(input.funding, ["txid", "vout"], "funding");
    if (
      funding === null ||
      (kind === "transfer" || kind === "withdrawal") !== (selectedNoteId !== null)
    ) fail("every beta action requires its independent funding UTXO and spend actions require one owned note");
    return this.#tx((db) => { const tip = db.prepare("SELECT * FROM accepted_zero_conf_tip WHERE singleton=1").get(); if (!tip) fail("beta incremental store is not initialized"); if (db.prepare("SELECT 1 FROM operations WHERE state IN('reserved','staged')").get()) fail("exactly one beta operation may be active"); let ftxid = null; let fvout = null; if (selectedNoteId) { const note = db.prepare("SELECT * FROM owned_notes WHERE note_id=? AND spent=0 AND reservation_operation_id IS NULL").get(selectedNoteId); if (!note) fail("selected owned note is unavailable"); db.prepare("UPDATE owned_notes SET reservation_operation_id=? WHERE note_id=?").run(operationId, selectedNoteId); } if (funding) { ftxid = blob(funding.txid, 32, "funding.txid"); fvout = integer(funding.vout, 0, 0xffff_ffff, "funding.vout"); const row = db.prepare("SELECT 1 FROM funding_utxos WHERE txid=? AND vout=? AND spent=0 AND reservation_operation_id IS NULL").get(ftxid, fvout); if (!row) fail("selected funding UTXO is unavailable"); db.prepare("UPDATE funding_utxos SET reservation_operation_id=? WHERE txid=? AND vout=?").run(operationId, ftxid, fvout); } db.prepare("INSERT INTO operations(operation_id,kind,state,expected_state,expected_txid,expected_vout,expected_sequence,expected_acceptance_id,selected_note_id,funding_txid,funding_vout) VALUES(?,?, 'reserved',?,?,?,?,?,?,?,?)").run(operationId, kind, tip.state_bytes, tip.txid, tip.vout, tip.action_sequence, tip.acceptance_id, selectedNoteId, ftxid, fvout); return this.operation(operationId); });
  }
  operation(operationId) { const row = this.#open().prepare("SELECT * FROM operations WHERE operation_id=?").get(text(operationId, "operationId")); if (!row) return null; return Object.freeze({ operationId: row.operation_id, kind: row.kind, state: row.state, packet: row.packet === null ? null : copy(row.packet) }); }
  availableFundingUtxos() {
    return Object.freeze(this.#open().prepare(
      "SELECT txid,vout,value_sats FROM funding_utxos WHERE spent=0 AND reservation_operation_id IS NULL ORDER BY txid,vout",
    ).all().map((row) => Object.freeze({ txid: copy(row.txid), vout: row.vout, valueSats: row.value_sats })));
  }
  availableOwnedNotes() {
    return Object.freeze(this.#open().prepare(
      "SELECT note_id,note_index FROM owned_notes WHERE spent=0 AND reservation_operation_id IS NULL ORDER BY note_index,note_id",
    ).all().map((row) => Object.freeze({ noteId: row.note_id, noteIndex: row.note_index })));
  }
  activeOperation() {
    const row = this.#open().prepare(
      "SELECT operation_id,kind,state,selected_note_id,funding_txid,funding_vout,local_wallet_commit_complete FROM operations WHERE state IN('reserved','staged') OR (state='accepted_zero_conf' AND local_wallet_commit_complete=0) ORDER BY operation_id",
    ).get();
    if (!row) return null;
    return Object.freeze({
      operationId: row.operation_id,
      kind: row.kind,
      state: row.state,
      localWalletCommitPending: row.state === "accepted_zero_conf" && row.local_wallet_commit_complete === 0,
      selectedNoteId: row.selected_note_id,
      funding: row.funding_txid === null ? null : Object.freeze({ txid: copy(row.funding_txid), vout: row.funding_vout }),
    });
  }
  stagedOperation(operationId) {
    const row = this.#open().prepare(
      "SELECT * FROM operations WHERE operation_id=? AND state IN('staged','accepted_zero_conf')",
    ).get(text(operationId, "operationId"));
    if (!row) return null;
    if (!row.packet || !row.proof_artifact || !row.proof_artifact_sha256 || !row.transaction_artifact || !row.transaction_artifact_sha256) {
      fail("staged beta operation is missing immutable resume artifacts");
    }
    if (!same(hash(row.proof_artifact), row.proof_artifact_sha256) || !same(hash(row.transaction_artifact), row.transaction_artifact_sha256)) {
      fail("staged beta operation artifact hash does not match persisted bytes");
    }
    return Object.freeze({
      operationId: row.operation_id,
      kind: row.kind,
      state: row.state,
      localWalletCommitComplete: row.local_wallet_commit_complete === 1,
      packet: copy(row.packet),
      proofArtifact: copy(row.proof_artifact),
      proofArtifactSha256: copy(row.proof_artifact_sha256),
      transactionArtifact: copy(row.transaction_artifact),
      transactionArtifactSha256: copy(row.transaction_artifact_sha256),
      expectedTip: Object.freeze({
        state: copy(row.expected_state),
        outpoint: Object.freeze({ txid: copy(row.expected_txid), vout: row.expected_vout }),
        actionSequence: row.expected_sequence,
        acceptanceId: copy(row.expected_acceptance_id),
      }),
      resources: Object.freeze({
        selectedNoteId: row.selected_note_id,
        funding: (() => {
          if (row.funding_txid === null) return null;
          const funding = this.#open().prepare(
            "SELECT value_sats FROM funding_utxos WHERE txid=? AND vout=?",
          ).get(row.funding_txid, row.funding_vout);
          if (!funding) fail("staged beta operation funding resource is absent");
          return Object.freeze({ txid: copy(row.funding_txid), vout: row.funding_vout, valueSats: funding.value_sats });
        })(),
      }),
    });
  }
  markLocalWalletCommitComplete({ operationId, transactionId, transactionArtifactSha256 }) {
    return this.#tx((db) => {
      const id = text(operationId, "operationId");
      const txid = blob(transactionId, 32, "transactionId");
      const artifactHash = blob(transactionArtifactSha256, 32, "transactionArtifactSha256");
      const op = db.prepare("SELECT * FROM operations WHERE operation_id=?").get(id);
      if (!op || op.state !== "accepted_zero_conf" || !op.accepted_txid || !op.transaction_artifact_sha256) {
        fail("local wallet commit requires an accepted beta operation with immutable artifacts");
      }
      if (!same(op.accepted_txid, txid) || !same(op.transaction_artifact_sha256, artifactHash)) {
        fail("local wallet commit evidence differs from the accepted successor or immutable transaction artifact");
      }
      if (op.local_wallet_commit_complete === 1) return this.stagedOperation(id);
      db.prepare("UPDATE operations SET local_wallet_commit_complete=1 WHERE operation_id=? AND local_wallet_commit_complete=0").run(id);
      return this.stagedOperation(id);
    });
  }
  deriveProvingSuccessor(value) {
    const input = exact(value, ["operationId", "outputNoteLeaf", "encryptedRecord", "publicNullifier", "withdrawalLockingBytecodeHash"], "beta proving successor"); const operationId = text(input.operationId, "operationId"); const output = input.outputNoteLeaf === null ? null : fr(input.outputNoteLeaf, "outputNoteLeaf"); const record = input.encryptedRecord === null ? null : blob(input.encryptedRecord, 128, "encryptedRecord"); const nullifier = input.publicNullifier === null ? null : fr(input.publicNullifier, "publicNullifier"); const withdrawalLockingBytecodeHash = input.withdrawalLockingBytecodeHash === null ? null : blob(input.withdrawalLockingBytecodeHash, 32, "withdrawalLockingBytecodeHash");
    return this.#tx((db) => { const op = db.prepare("SELECT * FROM operations WHERE operation_id=?").get(operationId); if (!op || op.state !== "reserved") fail("beta proving successor requires the active reserved operation"); const tip = db.prepare("SELECT * FROM accepted_zero_conf_tip WHERE singleton=1").get(); if (!tip || !same(tip.state_bytes, op.expected_state) || !same(tip.txid, op.expected_txid) || tip.vout !== op.expected_vout || tip.action_sequence !== op.expected_sequence || !same(tip.acceptance_id, op.expected_acceptance_id)) fail("beta proving successor accepted tip is stale"); const outputActive = op.kind !== "withdrawal"; const spendActive = op.kind !== "deposit"; if (outputActive !== (output !== null && record !== null) || spendActive !== (nullifier !== null) || (op.kind === "withdrawal") !== (withdrawalLockingBytecodeHash !== null)) fail("beta proving successor active fields do not match operation kind"); const binding = this.binding(); const preState = decodeStateNftCommitment(tip.state_bytes, { denominationSats: binding.denominationSats }); let derived; try { derived = derivePersistentPacketPostState(db, { binding, preState, kind: op.kind, publicNullifier: nullifier ?? Buffer.alloc(32), outputNoteLeaf: output ?? Buffer.alloc(32) }); } catch (error) { if (error instanceof PersistentTreeEngineError) fail(error.message); throw error; } let spend = undefined; if (spendActive) { const owned = db.prepare("SELECT owned.*,record.record_bytes FROM owned_notes AS owned JOIN encrypted_note_records AS record ON record.record_id=owned.record_id WHERE owned.note_id=? AND owned.reservation_operation_id=? AND owned.spent=0").get(op.selected_note_id, operationId); const leaf = owned && db.prepare("SELECT * FROM note_leaves WHERE note_index=?").get(owned.note_index); if (!owned || !leaf || !same(owned.nullifier_key, nullifier) || !same(owned.record_bytes, leaf.encrypted_record)) fail("selected beta owned note differs from authenticated tree material"); let membership; try { membership = derivePersistentNoteMembershipWitness(db, { noteIndex: owned.note_index, inputNoteLeaf: leaf.leaf_hash, expectedRoot: Buffer.from(preState.noteRoot, "hex") }); } catch (error) { if (error instanceof PersistentTreeEngineError) fail(error.message); throw error; } spend = Object.freeze({ inputNoteLeaf: Buffer.from(leaf.leaf_hash).toString("hex"), noteIndex: BigInt(owned.note_index), noteMembershipPath: membership.noteMembershipPath, publicNullifier: nullifier.toString("hex"), encryptedRecord: copy(owned.record_bytes) }); }
      const successor = Object.freeze({ schema: "shieldkit-v2-beta-derived-successor-v1", operationId, state: structuredClone(derived.postState) });
      DERIVED_SUCCESSORS.set(successor, Object.freeze({ store: this, operationId, kind: op.kind, binding, derived, publicNullifier: nullifier, outputNoteLeaf: output, encryptedRecord: record, withdrawalLockingBytecodeHash, spend, expectedTip: Object.freeze({ state: copy(tip.state_bytes), outpoint: Object.freeze({ txid: copy(tip.txid), vout: tip.vout }), actionSequence: tip.action_sequence, acceptanceId: copy(tip.acceptance_id) }) }));
      return successor;
    });
  }
  finalizeProvingTransition(value) {
    const input = exact(value, ["derivedSuccessor", "operationId", "transactionContextHash"], "beta proving transition finalization"); const operationId = text(input.operationId, "operationId"); const context = blob(input.transactionContextHash, 32, "transactionContextHash"); const capability = DERIVED_SUCCESSORS.get(input.derivedSuccessor); if (capability === undefined) fail("beta proving transition requires an unused store-issued derived successor"); if (capability.store !== this) fail("beta proving transition derived successor belongs to another store"); if (capability.operationId !== operationId) fail("beta proving transition derived successor belongs to another operation");
    const transition = this.#tx((db) => { const op = db.prepare("SELECT * FROM operations WHERE operation_id=?").get(operationId); const tip = db.prepare("SELECT * FROM accepted_zero_conf_tip WHERE singleton=1").get(); if (!op || op.state !== "reserved" || op.kind !== capability.kind || !same(op.expected_state, capability.expectedTip.state) || !same(op.expected_txid, capability.expectedTip.outpoint.txid) || op.expected_vout !== capability.expectedTip.outpoint.vout || op.expected_sequence !== capability.expectedTip.actionSequence || !same(op.expected_acceptance_id, capability.expectedTip.acceptanceId) || !tip || !same(tip.state_bytes, capability.expectedTip.state) || !same(tip.txid, capability.expectedTip.outpoint.txid) || tip.vout !== capability.expectedTip.outpoint.vout || tip.action_sequence !== capability.expectedTip.actionSequence || !same(tip.acceptance_id, capability.expectedTip.acceptanceId)) fail("beta proving transition derived successor is stale"); let assembled; try { assembled = assemblePersistentProvingTransition({ binding: capability.binding, derived: capability.derived, kind: capability.kind, publicNullifier: capability.publicNullifier, outputNoteLeaf: capability.outputNoteLeaf, encryptedRecord: capability.encryptedRecord, withdrawalLockingBytecodeHash: (capability.withdrawalLockingBytecodeHash ?? Buffer.alloc(32)).toString("hex"), transactionContextHash: context, spend: capability.spend, expectedTip: capability.expectedTip }); } catch (error) { if (error instanceof PersistentTreeEngineError) fail(error.message); throw error; }
      db.prepare("UPDATE operations SET packet=? WHERE operation_id=?").run(assembled.packet, operationId); return Object.freeze({ schema: DIRECT_V2_PERSISTENT_PROVING_TRANSITION_SCHEMA, state: structuredClone(capability.derived.postState), ...assembled });
    });
    DERIVED_SUCCESSORS.delete(input.derivedSuccessor);
    return transition;
  }
  deriveProvingTransition(value) {
    const input = exact(value, ["operationId", "outputNoteLeaf", "encryptedRecord", "publicNullifier", "withdrawalLockingBytecodeHash", "transactionContextHash"], "beta proving transition"); const successor = this.deriveProvingSuccessor({ operationId: input.operationId, outputNoteLeaf: input.outputNoteLeaf, encryptedRecord: input.encryptedRecord, publicNullifier: input.publicNullifier, withdrawalLockingBytecodeHash: input.withdrawalLockingBytecodeHash }); return this.finalizeProvingTransition({ derivedSuccessor: successor, operationId: input.operationId, transactionContextHash: input.transactionContextHash });
  }
  stageOperationArtifacts({ operationId, packet, proofArtifact, transactionArtifact }) { return this.#tx((db) => { const id = text(operationId, "operationId"); const op = db.prepare("SELECT * FROM operations WHERE operation_id=?").get(id); const exactPacket = blob(packet, 552, "packet"); const proof = blob(proofArtifact, proofArtifact.length, "proofArtifact"); const transaction = blob(transactionArtifact, transactionArtifact.length, "transactionArtifact"); if (!op || op.state !== "reserved" || !op.packet || !same(op.packet, exactPacket)) fail("beta stage requires the exact derived active packet"); db.prepare("UPDATE operations SET state='staged',proof_artifact=?,proof_artifact_sha256=?,transaction_artifact=?,transaction_artifact_sha256=? WHERE operation_id=?").run(proof, hash(proof), transaction, hash(transaction), id); return this.operation(id); }); }
  applyAcceptedZeroConfSuccessor(value) {
    const input = exact(value, ["operationId", "successor", "change", "ownedOutputNoteId", "ownedOutputRecordId", "ownedOutputNullifier"], "beta accepted successor"); const operationId = text(input.operationId, "operationId"); const successor = exact(input.successor, ["txid", "vout", "acceptanceId"], "successor"); const txid = blob(successor.txid, 32, "successor.txid"); const vout = integer(successor.vout, 0, 0xffff_ffff, "successor.vout"); const acceptanceId = blob(successor.acceptanceId, 32, "successor.acceptanceId"); const change = input.change === null ? null : exact(input.change, ["txid", "vout", "valueSats"], "change"); const ownedOutputNoteId = input.ownedOutputNoteId === null ? null : text(input.ownedOutputNoteId, "ownedOutputNoteId"); const ownedOutputRecordId = input.ownedOutputRecordId === null ? null : text(input.ownedOutputRecordId, "ownedOutputRecordId"); const ownedOutputNullifier = input.ownedOutputNullifier === null ? null : fr(input.ownedOutputNullifier, "ownedOutputNullifier");
    return this.#tx((db) => { const op = db.prepare("SELECT * FROM operations WHERE operation_id=?").get(operationId); if (!op || op.state !== "staged" || !op.packet || !op.proof_artifact || !op.transaction_artifact || !same(hash(op.proof_artifact), op.proof_artifact_sha256) || !same(hash(op.transaction_artifact), op.transaction_artifact_sha256)) fail("beta accepted successor requires exact staged immutable artifacts"); const tip = db.prepare("SELECT * FROM accepted_zero_conf_tip WHERE singleton=1").get(); if (!tip || !same(tip.state_bytes, op.expected_state) || !same(tip.txid, op.expected_txid) || tip.vout !== op.expected_vout || tip.action_sequence !== op.expected_sequence || !same(tip.acceptance_id, op.expected_acceptance_id)) fail("beta accepted successor tip is stale"); const binding = this.binding(); let packet; try { packet = decodeActionPacket(op.packet, { denominationSats: binding.denominationSats }); } catch (error) { fail(`beta staged packet is invalid: ${error.message}`); } if (packet.kind !== op.kind || !same(encodeStateNftCommitment(packet.preState, { denominationSats: binding.denominationSats }), tip.state_bytes)) fail("beta staged packet no longer binds the accepted tip"); let derived; try { derived = derivePersistentPacketPostState(db, { binding, preState: packet.preState, kind: packet.kind, publicNullifier: Buffer.from(packet.publicNullifier, "hex"), outputNoteLeaf: Buffer.from(packet.outputNoteLeaf, "hex") }); } catch (error) { if (error instanceof PersistentTreeEngineError) fail(error.message); throw error; } const postBytes = encodeStateNftCommitment(derived.postState, { denominationSats: binding.denominationSats }); if (!same(postBytes, encodeStateNftCommitment(packet.postState, { denominationSats: binding.denominationSats }))) fail("beta staged packet post-state is not the persistent O(depth) successor"); if (derived.note.noteNodes) for (const node of derived.note.noteNodes) db.prepare("INSERT INTO note_nodes VALUES(?,?,?) ON CONFLICT(depth,node_index) DO UPDATE SET node_hash=excluded.node_hash").run(node.depth, node.nodeIndex, node.nodeHash); if (derived.note.noteFrontier) for (const node of derived.note.noteFrontier) db.prepare("INSERT INTO note_frontier VALUES(?,?) ON CONFLICT(depth) DO UPDATE SET node_hash=excluded.node_hash").run(node.depth, node.nodeHash); if (derived.note.noteNodes) db.prepare("INSERT INTO note_leaves VALUES(?,?,?,?,?)").run(Number(packet.preState.noteCount), Buffer.from(packet.outputNoteLeaf, "hex"), Buffer.from(packet.encryptedRecord, "hex"), Number(packet.postState.actionSequence), txid); if (derived.nullifier.nullifierNodes) createPersistentNullifierSqliteAccess({ db, profile: PERSISTENT_NULLIFIER_SQLITE_PROFILES.production, raise: fail }).applyMutation(derived.nullifier); if (op.selected_note_id) db.prepare("UPDATE owned_notes SET spent=1,reservation_operation_id=NULL WHERE note_id=?").run(op.selected_note_id); if (op.funding_txid) db.prepare("UPDATE funding_utxos SET spent=1,reservation_operation_id=NULL WHERE txid=? AND vout=?").run(op.funding_txid, op.funding_vout); if (change) db.prepare("INSERT INTO funding_utxos VALUES(?,?,?,NULL,0)").run(blob(change.txid, 32, "change.txid"), integer(change.vout, 0, 0xffff_ffff, "change.vout"), money(change.valueSats, "change.valueSats")); if (ownedOutputNoteId !== null || ownedOutputRecordId !== null || ownedOutputNullifier !== null) { if (packet.kind === "withdrawal" || !ownedOutputNoteId || !ownedOutputRecordId || !ownedOutputNullifier) fail("beta owned output assignment does not match operation kind"); const record = db.prepare("SELECT record_bytes FROM encrypted_note_records WHERE record_id=?").get(ownedOutputRecordId); if (!record || !same(record.record_bytes, Buffer.from(packet.encryptedRecord, "hex"))) fail("beta owned output record is not the exact packet record"); db.prepare("INSERT INTO owned_notes VALUES(?,?,?,?,NULL,0)").run(ownedOutputNoteId, ownedOutputRecordId, Number(packet.preState.noteCount), ownedOutputNullifier); }
      db.prepare("UPDATE accepted_zero_conf_tip SET state_bytes=?,txid=?,vout=?,action_sequence=?,acceptance_id=? WHERE singleton=1").run(postBytes, txid, vout, Number(packet.postState.actionSequence), acceptanceId); db.prepare("UPDATE operations SET state='accepted_zero_conf',local_wallet_commit_complete=0,accepted_txid=?,accepted_vout=?,accepted_acceptance_id=? WHERE operation_id=?").run(txid, vout, acceptanceId, operationId); return this.optimisticTip();
    });
  }
  markSafePreSendAbort({ operationId, kind, reason }) {
    return this.#tx((db) => {
      const id = text(operationId, "operationId"); const actionKind = text(kind, "kind"); const why = text(reason, "reason");
      const op = db.prepare("SELECT * FROM operations WHERE operation_id=?").get(id);
      if (!op || !["reserved", "staged", "rejected"].includes(op.state) || op.kind !== actionKind) fail("safe pre-send abort does not match an active or exactly rejected operation");
      if (op.safe_pre_send_abort_reason !== why && op.safe_pre_send_abort_reason !== null) fail("safe pre-send abort reason differs from the durable operation marker");
      if (op.state === "rejected") {
        if (op.safe_pre_send_abort_reason !== why) fail("safe pre-send abort does not match the exactly rejected operation");
        return this.safePreSendAbortMarker(id);
      }
      if (op.safe_pre_send_abort_reason === null) db.prepare("UPDATE operations SET safe_pre_send_abort_reason=? WHERE operation_id=? AND safe_pre_send_abort_reason IS NULL").run(why, id);
      return this.safePreSendAbortMarker(id);
    });
  }
  safePreSendAbortMarker(operationId) { const id = text(operationId, "operationId"); const op = this.#open().prepare("SELECT operation_id,kind,state,safe_pre_send_abort_reason FROM operations WHERE operation_id=?").get(id); if (!op || !["reserved", "staged", "rejected"].includes(op.state) || op.safe_pre_send_abort_reason === null) return null; return Object.freeze({ operationId: op.operation_id, kind: op.kind, reason: op.safe_pre_send_abort_reason }); }
  finalizeSafePreSendAbort({ operationId, kind, reason }) {
    return this.#tx((db) => {
      const id = text(operationId, "operationId"); const actionKind = text(kind, "kind"); const why = text(reason, "reason");
      const op = db.prepare("SELECT * FROM operations WHERE operation_id=?").get(id);
      if (!op || !["reserved", "staged", "rejected"].includes(op.state) || op.kind !== actionKind || op.safe_pre_send_abort_reason !== why) fail("safe pre-send abort marker does not match the active or exactly rejected operation");
      if (op.state === "rejected") return this.operation(id);
      if (op.selected_note_id) db.prepare("UPDATE owned_notes SET reservation_operation_id=NULL WHERE note_id=? AND reservation_operation_id=?").run(op.selected_note_id, id);
      if (op.funding_txid) db.prepare("UPDATE funding_utxos SET reservation_operation_id=NULL WHERE txid=? AND vout=? AND reservation_operation_id=?").run(op.funding_txid, op.funding_vout, id);
      db.prepare("UPDATE operations SET state='rejected' WHERE operation_id=?").run(id);
      return this.operation(id);
    });
  }
  rollbackActiveSuffix({ operationId }) { return this.#tx((db) => { const id = text(operationId, "operationId"); const op = db.prepare("SELECT * FROM operations WHERE operation_id=?").get(id); if (!op || !["reserved", "staged"].includes(op.state) || op.safe_pre_send_abort_reason !== null) fail("only an unmarked active beta suffix may be rolled back"); if (op.selected_note_id) db.prepare("UPDATE owned_notes SET reservation_operation_id=NULL WHERE note_id=? AND reservation_operation_id=?").run(op.selected_note_id, id); if (op.funding_txid) db.prepare("UPDATE funding_utxos SET reservation_operation_id=NULL WHERE txid=? AND vout=? AND reservation_operation_id=?").run(op.funding_txid, op.funding_vout, id); db.prepare("UPDATE operations SET state='rejected' WHERE operation_id=?").run(id); return this.operation(id); }); }
}
export function openV2BetaIncrementalStore(value) { return new V2BetaIncrementalStore(value); }
