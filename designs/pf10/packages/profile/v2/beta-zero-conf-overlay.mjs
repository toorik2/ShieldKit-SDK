/**
 * Durable, explicitly unqualified zero-confirmation state for the V2 beta.
 *
 * This is deliberately separate from `packages/pool/v2/store.mjs`: a BCHN
 * mempool observation is not a block and must never be represented as a
 * confirmed height/hash or passed to V2Store.applyConfirmed.
 */
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { chmodSync, lstatSync, mkdirSync } from 'node:fs';
import { dirname, parse, resolve } from 'node:path';
import { deserialize, serialize } from 'node:v8';

import { decodeStateNftCommitment } from '../../action/v2/state.mjs';
import {
  restoreV2BetaZeroConfTreeMaterial,
} from './beta-zero-conf-material.mjs';
import {
  assertV2BetaChipnetDeploymentCapability,
} from './beta-chipnet-deployment.mjs';

export const V2_BETA_ZERO_CONF_OVERLAY_SCHEMA =
  'shieldkit-v2-beta-zero-conf-overlay-v1';
export const V2_BETA_ZERO_CONF_ELIGIBILITY =
  'beta-single-contributor-unqualified';
export const V2_BETA_ZERO_CONF_ANCHOR_STATUS = 'accepted-zero-conf';
export const V2_BETA_ZERO_CONF_OPTIMISTIC_STATUS =
  'zero-conf-optimistic-beta-unqualified';

const HASH_HEX = /^[0-9a-f]{64}$/u;
const OPERATION_ID = /^[a-z0-9][a-z0-9._:-]{0,127}$/u;
const MAX_U32 = 0xffff_ffff;
const MAX_MONEY_SATS = 2_100_000_000_000_000n;

export class V2BetaZeroConfOverlayError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options);
    this.name = 'V2BetaZeroConfOverlayError';
    this.code = code;
  }
}

const fail = (code, message) => {
  throw new V2BetaZeroConfOverlayError(code, message);
};
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const copy = (bytes) => Uint8Array.from(bytes);
const hex = (bytes) => Buffer.from(bytes).toString('hex');

function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('ZERO_CONF_OVERLAY_INVALID', `${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])) {
    fail('ZERO_CONF_OVERLAY_INVALID', `${label} has missing or unknown properties`);
  }
  return value;
}

function bytes(value, size, label) {
  if (!(value instanceof Uint8Array) || value.length !== size) {
    fail('ZERO_CONF_OVERLAY_INVALID', `${label} must contain exactly ${size} bytes`);
  }
  return Buffer.from(value);
}
function boundedBytes(value, minimum, maximum, label) {
  if (!(value instanceof Uint8Array) || value.length < minimum || value.length > maximum) {
    fail('ZERO_CONF_OVERLAY_INVALID', `${label} must contain from ${minimum} through ${maximum} bytes`);
  }
  return Buffer.from(value);
}

function txid(value, label) {
  return bytes(value, 32, label);
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH_HEX.test(value)) {
    fail('ZERO_CONF_OVERLAY_INVALID', `${label} must be a 32-byte lowercase hexadecimal hash`);
  }
  return value;
}

function text(value, label) {
  if (typeof value !== 'string' || value.length === 0 || !OPERATION_ID.test(value)) {
    fail('ZERO_CONF_OVERLAY_INVALID', `${label} must be a lowercase bounded operation identifier`);
  }
  return value;
}

function u32(value, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_U32) {
    fail('ZERO_CONF_OVERLAY_INVALID', `${label} must be a u32`);
  }
  return value;
}

function sequence(value, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) {
    fail('ZERO_CONF_OVERLAY_INVALID', `${label} must be a nonnegative safe integer`);
  }
  return value;
}

function money(value, label) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/u.test(value)
    || BigInt(value) === 0n || BigInt(value) > MAX_MONEY_SATS) {
    fail('ZERO_CONF_OVERLAY_INVALID', `${label} must be nonzero canonical money`);
  }
  return value;
}

function reason(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 512) {
    fail('ZERO_CONF_OVERLAY_INVALID', `${label} must be a nonempty bounded reason`);
  }
  return value;
}

function normalizedOutpoint(value, label) {
  exact(value, ['txid', 'vout'], label);
  return Object.freeze({ txid: txid(value.txid, `${label}.txid`), vout: u32(value.vout, `${label}.vout`) });
}

function same(left, right) {
  return Buffer.from(left).equals(Buffer.from(right));
}

function sameOutpoint(left, right) {
  return left.vout === right.vout && same(left.txid, right.txid);
}

function sortedUnique(entries, key, label) {
  for (let index = 1; index < entries.length; index += 1) {
    if (key(entries[index - 1]) >= key(entries[index])) {
      fail('ZERO_CONF_OVERLAY_INVALID', `${label} must be strictly sorted and unique`);
    }
  }
  return entries;
}

function material(value, label) {
  const input = exact(value, [
    'fundingUtxos', 'noteFrontier', 'noteLeaves', 'noteNodes', 'nullifierLeaves',
    'nullifierNodes', 'ownedNotes', 'records', 'treeMaterial',
  ], label);
  const node = (entry, entryLabel) => {
    const row = exact(entry, ['depth', 'nodeHash', 'nodeIndex'], entryLabel);
    return Object.freeze({
      depth: u32(row.depth, `${entryLabel}.depth`),
      nodeIndex: u32(row.nodeIndex, `${entryLabel}.nodeIndex`),
      nodeHash: bytes(row.nodeHash, 32, `${entryLabel}.nodeHash`),
    });
  };
  const noteNodes = input.noteNodes.map((entry, index) => node(entry, `${label}.noteNodes[${index}]`));
  sortedUnique(noteNodes, (entry) => `${entry.depth.toString().padStart(2, '0')}:${entry.nodeIndex.toString().padStart(10, '0')}`, `${label}.noteNodes`);
  const nullifierNodes = input.nullifierNodes.map((entry, index) => node(entry, `${label}.nullifierNodes[${index}]`));
  sortedUnique(nullifierNodes, (entry) => `${entry.depth.toString().padStart(2, '0')}:${entry.nodeIndex.toString().padStart(10, '0')}`, `${label}.nullifierNodes`);
  const noteFrontier = input.noteFrontier.map((entry, index) => {
    const row = exact(entry, ['depth', 'nodeHash'], `${label}.noteFrontier[${index}]`);
    return Object.freeze({ depth: u32(row.depth, `${label}.noteFrontier[${index}].depth`), nodeHash: bytes(row.nodeHash, 32, `${label}.noteFrontier[${index}].nodeHash`) });
  });
  sortedUnique(noteFrontier, (entry) => entry.depth.toString().padStart(2, '0'), `${label}.noteFrontier`);
  const noteLeaves = input.noteLeaves.map((entry, index) => {
    const row = exact(entry, ['actionSequence', 'encryptedRecord', 'leafHash', 'noteIndex', 'transactionId'], `${label}.noteLeaves[${index}]`);
    return Object.freeze({ noteIndex: u32(row.noteIndex, `${label}.noteLeaves[${index}].noteIndex`), leafHash: bytes(row.leafHash, 32, `${label}.noteLeaves[${index}].leafHash`), encryptedRecord: bytes(row.encryptedRecord, 128, `${label}.noteLeaves[${index}].encryptedRecord`), actionSequence: sequence(row.actionSequence, `${label}.noteLeaves[${index}].actionSequence`), transactionId: txid(row.transactionId, `${label}.noteLeaves[${index}].transactionId`) });
  });
  sortedUnique(noteLeaves, (entry) => entry.noteIndex.toString().padStart(10, '0'), `${label}.noteLeaves`);
  const nullifierLeaves = input.nullifierLeaves.map((entry, index) => {
    const row = exact(entry, ['key', 'leafHash', 'leafType', 'physicalIndex', 'successorIndex', 'successorKey'], `${label}.nullifierLeaves[${index}]`);
    if (!Number.isSafeInteger(row.leafType) || ![1, 2, 3].includes(row.leafType)) fail('ZERO_CONF_OVERLAY_INVALID', `${label}.nullifierLeaves[${index}].leafType is unsupported`);
    return Object.freeze({ physicalIndex: u32(row.physicalIndex, `${label}.nullifierLeaves[${index}].physicalIndex`), leafType: row.leafType, leafHash: bytes(row.leafHash, 32, `${label}.nullifierLeaves[${index}].leafHash`), key: bytes(row.key, 32, `${label}.nullifierLeaves[${index}].key`), successorIndex: u32(row.successorIndex, `${label}.nullifierLeaves[${index}].successorIndex`), successorKey: bytes(row.successorKey, 32, `${label}.nullifierLeaves[${index}].successorKey`) });
  });
  sortedUnique(nullifierLeaves, (entry) => entry.physicalIndex.toString().padStart(10, '0'), `${label}.nullifierLeaves`);
  const records = input.records.map((entry, index) => {
    const row = exact(entry, ['record', 'recordId'], `${label}.records[${index}]`);
    return Object.freeze({ recordId: text(row.recordId, `${label}.records[${index}].recordId`), record: bytes(row.record, 128, `${label}.records[${index}].record`) });
  });
  sortedUnique(records, (entry) => entry.recordId, `${label}.records`);
  const ownedNotes = input.ownedNotes.map((entry, index) => {
    const row = exact(entry, ['noteId', 'noteIndex', 'nullifier', 'recordId', 'spent'], `${label}.ownedNotes[${index}]`);
    if (typeof row.spent !== 'boolean') fail('ZERO_CONF_OVERLAY_INVALID', `${label}.ownedNotes[${index}].spent must be boolean`);
    return Object.freeze({ noteId: text(row.noteId, `${label}.ownedNotes[${index}].noteId`), recordId: text(row.recordId, `${label}.ownedNotes[${index}].recordId`), noteIndex: u32(row.noteIndex, `${label}.ownedNotes[${index}].noteIndex`), nullifier: bytes(row.nullifier, 32, `${label}.ownedNotes[${index}].nullifier`), spent: row.spent });
  });
  sortedUnique(ownedNotes, (entry) => entry.noteId, `${label}.ownedNotes`);
  if (ownedNotes.some((entry) => !records.some((record) => record.recordId === entry.recordId))) fail('ZERO_CONF_OVERLAY_INVALID', `${label}.ownedNotes references a missing encrypted record`);
  const fundingUtxos = input.fundingUtxos.map((entry, index) => {
    const row = exact(entry, ['spent', 'txid', 'valueSats', 'vout'], `${label}.fundingUtxos[${index}]`);
    if (typeof row.spent !== 'boolean') fail('ZERO_CONF_OVERLAY_INVALID', `${label}.fundingUtxos[${index}].spent must be boolean`);
    return Object.freeze({ txid: txid(row.txid, `${label}.fundingUtxos[${index}].txid`), vout: u32(row.vout, `${label}.fundingUtxos[${index}].vout`), valueSats: money(row.valueSats, `${label}.fundingUtxos[${index}].valueSats`), spent: row.spent });
  });
  sortedUnique(fundingUtxos, (entry) => `${hex(entry.txid)}:${entry.vout.toString().padStart(10, '0')}`, `${label}.fundingUtxos`);
  return Object.freeze({
    noteNodes: Object.freeze(noteNodes), noteFrontier: Object.freeze(noteFrontier), noteLeaves: Object.freeze(noteLeaves),
    nullifierNodes: Object.freeze(nullifierNodes), nullifierLeaves: Object.freeze(nullifierLeaves),
    records: Object.freeze(records), ownedNotes: Object.freeze(ownedNotes), fundingUtxos: Object.freeze(fundingUtxos), treeMaterial: input.treeMaterial,
  });
}

function materialBytes(value, label) { return Buffer.from(serialize(material(value, label))); }
function materialFromBytes(value) { return material(deserialize(value), 'persisted beta overlay material'); }

function betaIntent(value, label) {
  const input = exact(value, [
    'changeLockingBytecode', 'feeRateSatsPerByte', 'funding', 'maximumFeeSats',
    'runtimeMaterialSha256', 'selectedNoteId', 'target',
  ], label);
  const target = exact(input.target, ['bytes', 'type'], `${label}.target`);
  if (!['shield_address', 'withdrawal_locking_bytecode'].includes(target.type)) fail('ZERO_CONF_OVERLAY_INVALID', `${label}.target.type is unsupported`);
  const funding = exact(input.funding, ['lockingBytecode', 'publicKey', 'rawTransaction', 'txid', 'valueSats', 'vout'], `${label}.funding`);
  const selectedNoteId = input.selectedNoteId === null ? null : text(input.selectedNoteId, `${label}.selectedNoteId`);
  return Object.freeze({
    target: Object.freeze({ type: target.type, bytes: boundedBytes(target.bytes, 1, 10_000, `${label}.target.bytes`) }),
    selectedNoteId,
    funding: Object.freeze({
      rawTransaction: boundedBytes(funding.rawTransaction, 1, 100_000, `${label}.funding.rawTransaction`),
      txid: txid(funding.txid, `${label}.funding.txid`), vout: u32(funding.vout, `${label}.funding.vout`),
      valueSats: money(funding.valueSats, `${label}.funding.valueSats`),
      lockingBytecode: boundedBytes(funding.lockingBytecode, 1, 10_000, `${label}.funding.lockingBytecode`),
      publicKey: bytes(funding.publicKey, 33, `${label}.funding.publicKey`),
    }),
    changeLockingBytecode: boundedBytes(input.changeLockingBytecode, 1, 10_000, `${label}.changeLockingBytecode`),
    feeRateSatsPerByte: money(input.feeRateSatsPerByte, `${label}.feeRateSatsPerByte`),
    maximumFeeSats: money(input.maximumFeeSats, `${label}.maximumFeeSats`),
    runtimeMaterialSha256: hash(input.runtimeMaterialSha256, `${label}.runtimeMaterialSha256`),
  });
}

function assertMaterialMatchesState(materialValue, stateBytes, profileId, label) {
  let state;
  try { state = decodeStateNftCommitment(stateBytes, { denominationSats: '10000000' }); }
  catch (error) { fail('ZERO_CONF_OVERLAY_MATERIAL_INVALID', `${label} is not a valid V2 beta state commitment: ${error instanceof Error ? error.message : String(error)}`); }
  if (state.profileId !== hex(profileId)) fail('ZERO_CONF_OVERLAY_MATERIAL_INVALID', `${label} profileId differs from the anchored V2 beta profile`);
  try {
    restoreV2BetaZeroConfTreeMaterial({ material: materialValue.treeMaterial, profileId: hex(profileId), state: stateBytes });
  } catch (error) {
    fail('ZERO_CONF_OVERLAY_MATERIAL_INVALID', `${label} tree material is not a complete authenticated reconstruction: ${error instanceof Error ? error.message : String(error)}`);
  }
  return state;
}

function privateFile(filename) {
  if (typeof filename !== 'string' || filename.length === 0) {
    fail('ZERO_CONF_OVERLAY_PATH_REJECTED', 'filename is required');
  }
  const resolved = resolve(filename);
  const parent = dirname(resolved);
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  chmodSync(parent, 0o700);
  for (let cursor = parent;; cursor = dirname(cursor)) {
    const metadata = lstatSync(cursor);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()
      || (cursor === parent && (metadata.mode & 0o077) !== 0)) {
      fail('ZERO_CONF_OVERLAY_PATH_REJECTED', 'overlay database requires a private real parent and symlink-free ancestry');
    }
    if (cursor === parse(cursor).root) break;
  }
  let metadata;
  try { metadata = lstatSync(resolved); } catch { return resolved; }
  if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0) {
    fail('ZERO_CONF_OVERLAY_PATH_REJECTED', 'overlay database must be a private regular file');
  }
  return resolved;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS beta_zero_conf_anchor (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  profile_id BLOB NOT NULL CHECK(length(profile_id)=32),
  instance_id BLOB NOT NULL CHECK(length(instance_id)=32),
  genesis_txid BLOB NOT NULL CHECK(length(genesis_txid)=32),
  genesis_vout INTEGER NOT NULL CHECK(genesis_vout=0),
  initial_state BLOB NOT NULL CHECK(length(initial_state)=128),
  material_bytes BLOB NOT NULL,
  initial_state_sha256 TEXT NOT NULL CHECK(length(initial_state_sha256)=64),
  zero_conf_evidence_sha256 TEXT NOT NULL CHECK(length(zero_conf_evidence_sha256)=64),
  status TEXT NOT NULL CHECK(status='accepted-zero-conf'),
  eligibility TEXT NOT NULL CHECK(eligibility='beta-single-contributor-unqualified'),
  evicted INTEGER NOT NULL DEFAULT 0 CHECK(evicted IN(0,1)),
  evicted_reason TEXT
) STRICT;
CREATE TABLE IF NOT EXISTS beta_zero_conf_actions (
  ordinal INTEGER PRIMARY KEY CHECK(ordinal>=1),
  operation_id TEXT NOT NULL UNIQUE,
  transaction_id BLOB NOT NULL UNIQUE CHECK(length(transaction_id)=32),
  predecessor_state BLOB NOT NULL CHECK(length(predecessor_state)=128),
  predecessor_txid BLOB NOT NULL CHECK(length(predecessor_txid)=32),
  predecessor_vout INTEGER NOT NULL CHECK(predecessor_vout>=0),
  predecessor_sequence INTEGER NOT NULL CHECK(predecessor_sequence>=0),
  successor_state BLOB NOT NULL CHECK(length(successor_state)=128),
  successor_txid BLOB NOT NULL CHECK(length(successor_txid)=32),
  successor_vout INTEGER NOT NULL CHECK(successor_vout=0),
  successor_sequence INTEGER NOT NULL CHECK(successor_sequence>=1),
  material_before_bytes BLOB NOT NULL,
  material_after_bytes BLOB NOT NULL,
  status TEXT NOT NULL CHECK(status IN('active','evicted','rejected')),
  reason TEXT
) STRICT;
CREATE TABLE IF NOT EXISTS beta_zero_conf_operations (
  operation_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN('deposit','transfer','withdrawal')),
  journal_state TEXT NOT NULL CHECK(journal_state IN('prepared','proving','proved','signed','mempool','rejected','evicted')),
  expected_state BLOB NOT NULL CHECK(length(expected_state)=128),
  expected_txid BLOB NOT NULL CHECK(length(expected_txid)=32),
  expected_vout INTEGER NOT NULL CHECK(expected_vout>=0),
  expected_sequence INTEGER NOT NULL CHECK(expected_sequence>=0),
  intent_bytes BLOB NOT NULL CHECK(length(intent_bytes)>=1),
  action_material_sha256 TEXT NOT NULL CHECK(length(action_material_sha256)=64),
  private_action_record_sha256 TEXT NOT NULL CHECK(length(private_action_record_sha256)=64),
  expected_material_sha256 TEXT NOT NULL CHECK(length(expected_material_sha256)=64),
  packet BLOB,
  proof BLOB,
  unsigned_tx BLOB,
  signed_tx BLOB,
  local_vm_evidence BLOB,
  reason TEXT
) STRICT;
`;

function anchorRow(db) {
  return db.prepare('SELECT * FROM beta_zero_conf_anchor WHERE singleton=1').get();
}

function actionRows(db) {
  return db.prepare('SELECT * FROM beta_zero_conf_actions ORDER BY ordinal ASC').all();
}

function outputAnchor(row) {
  if (!row) return null;
  return Object.freeze({
    profileId: copy(row.profile_id),
    instanceId: copy(row.instance_id),
    genesisOutpoint: Object.freeze({ txid: copy(row.genesis_txid), vout: row.genesis_vout }),
    initialState: copy(row.initial_state),
    initialStateSha256: row.initial_state_sha256,
    zeroConfEvidenceSha256: row.zero_conf_evidence_sha256,
    status: row.status,
    eligibility: row.eligibility,
    evicted: Boolean(row.evicted),
    ...(row.evicted_reason === null ? {} : { evictionReason: row.evicted_reason }),
  });
}

function outputAction(row) {
  return Object.freeze({
    ordinal: row.ordinal,
    operationId: row.operation_id,
    transactionId: copy(row.transaction_id),
    predecessor: Object.freeze({
      state: copy(row.predecessor_state),
      outpoint: Object.freeze({ txid: copy(row.predecessor_txid), vout: row.predecessor_vout }),
      actionSequence: row.predecessor_sequence,
    }),
    successor: Object.freeze({
      state: copy(row.successor_state),
      outpoint: Object.freeze({ txid: copy(row.successor_txid), vout: row.successor_vout }),
      actionSequence: row.successor_sequence,
    }),
    status: row.status,
    ...(row.reason === null ? {} : { reason: row.reason }),
  });
}

function activeTip(db) {
  const anchor = anchorRow(db);
  if (!anchor || anchor.evicted) return null;
  const active = db.prepare(
    "SELECT * FROM beta_zero_conf_actions WHERE status='active' ORDER BY ordinal DESC LIMIT 1",
  ).get();
  if (!active) {
    return Object.freeze({
      state: copy(anchor.initial_state),
      outpoint: Object.freeze({ txid: copy(anchor.genesis_txid), vout: anchor.genesis_vout }),
      actionSequence: 0,
      source: 'accepted-zero-conf-genesis',
    });
  }
  return Object.freeze({
    state: copy(active.successor_state),
    outpoint: Object.freeze({ txid: copy(active.successor_txid), vout: active.successor_vout }),
    actionSequence: active.successor_sequence,
    source: 'mempool-overlay',
  });
}

function activeMaterial(db) {
  const anchor = anchorRow(db);
  if (!anchor || anchor.evicted) return null;
  const active = db.prepare(
    "SELECT material_after_bytes FROM beta_zero_conf_actions WHERE status='active' ORDER BY ordinal DESC LIMIT 1",
  ).get();
  return materialFromBytes(active ? active.material_after_bytes : anchor.material_bytes);
}

function outputOperation(row) {
  if (!row) return null;
  return Object.freeze({
    operationId: row.operation_id,
    kind: row.kind,
    journalState: row.journal_state,
    expectedOptimisticTip: Object.freeze({
      state: copy(row.expected_state),
      outpoint: Object.freeze({ txid: copy(row.expected_txid), vout: row.expected_vout }),
      actionSequence: row.expected_sequence,
    }),
    intent: betaIntent(deserialize(row.intent_bytes), 'persisted beta operation intent'),
    actionMaterialSha256: row.action_material_sha256,
    privateActionRecordSha256: row.private_action_record_sha256,
    expectedMaterialSha256: row.expected_material_sha256,
    artifacts: Object.freeze({
      packet: row.packet === null ? null : copy(row.packet),
      proof: row.proof === null ? null : copy(row.proof),
      unsignedTx: row.unsigned_tx === null ? null : copy(row.unsigned_tx),
      signedTx: row.signed_tx === null ? null : copy(row.signed_tx),
      localVmEvidence: row.local_vm_evidence === null ? null : copy(row.local_vm_evidence),
    }),
    ...(row.reason === null ? {} : { reason: row.reason }),
  });
}

function assertTipMatch(actual, expected, label) {
  if (!same(actual.state, expected.state)
    || !sameOutpoint(actual.outpoint, expected.outpoint)
    || actual.actionSequence !== expected.actionSequence) {
    fail('ZERO_CONF_OVERLAY_STALE_PREDECESSOR', `${label} does not equal the current optimistic tip`);
  }
}

export class V2BetaZeroConfOverlay {
  #db;

  constructor({ filename } = {}) {
    const trusted = privateFile(filename);
    this.#db = new DatabaseSync(trusted);
    try {
      this.#db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;');
      this.#db.exec(SCHEMA);
      const integrity = this.#db.prepare('PRAGMA integrity_check').get();
      if (integrity.integrity_check !== 'ok') fail('ZERO_CONF_OVERLAY_CORRUPT', 'overlay database integrity check failed');
      chmodSync(trusted, 0o600);
    } catch (error) {
      this.#db.close();
      throw error;
    }
  }

  close() {
    if (this.#db !== undefined) {
      this.#db.close();
      this.#db = undefined;
    }
  }

  anchor() { return outputAnchor(anchorRow(this.#db)); }

  /**
   * Typed materialized rows for beta witness construction. These rows are
   * separate from confirmed V2Store tables and are selected only from the
   * active ordered zero-conf prefix.
   */
  optimisticMaterial() {
    const current = activeMaterial(this.#db);
    return current === null ? null : current;
  }

  /**
   * Read-only query adapter for beta witness builders. It always reads the
   * same active materialized prefix as `optimisticTip`; it has no confirmed
   * height/hash surface and cannot mutate either the overlay or V2Store.
   */
  optimisticWitnessView() {
    const materialValue = this.optimisticMaterial();
    const need = () => {
      if (materialValue === null) fail('ZERO_CONF_OVERLAY_ANCHOR_REQUIRED', 'no active beta optimistic material exists');
      return materialValue;
    };
    return Object.freeze({
      tip: this.optimisticTip().tip,
      noteNode: ({ depth, nodeIndex } = {}) => {
        const entry = need().noteNodes.find((row) => row.depth === u32(depth, 'beta witness noteNode.depth') && row.nodeIndex === u32(nodeIndex, 'beta witness noteNode.nodeIndex'));
        return entry === undefined ? null : copy(entry.nodeHash);
      },
      noteFrontier: ({ depth } = {}) => {
        const entry = need().noteFrontier.find((row) => row.depth === u32(depth, 'beta witness noteFrontier.depth'));
        return entry === undefined ? null : copy(entry.nodeHash);
      },
      noteLeaf: ({ noteIndex } = {}) => {
        const entry = need().noteLeaves.find((row) => row.noteIndex === u32(noteIndex, 'beta witness noteLeaf.noteIndex'));
        return entry === undefined ? null : Object.freeze({ ...entry, leafHash: copy(entry.leafHash), encryptedRecord: copy(entry.encryptedRecord), transactionId: copy(entry.transactionId) });
      },
      nullifierNode: ({ depth, nodeIndex } = {}) => {
        const entry = need().nullifierNodes.find((row) => row.depth === u32(depth, 'beta witness nullifierNode.depth') && row.nodeIndex === u32(nodeIndex, 'beta witness nullifierNode.nodeIndex'));
        return entry === undefined ? null : copy(entry.nodeHash);
      },
      nullifierLeaf: ({ physicalIndex } = {}) => {
        const entry = need().nullifierLeaves.find((row) => row.physicalIndex === u32(physicalIndex, 'beta witness nullifierLeaf.physicalIndex'));
        return entry === undefined ? null : Object.freeze({ ...entry, leafHash: copy(entry.leafHash), key: copy(entry.key), successorKey: copy(entry.successorKey) });
      },
      normalKeyPredecessor: ({ key } = {}) => {
        const target = bytes(key, 32, 'beta witness normalKeyPredecessor.key');
        const normal = need().nullifierLeaves
          .filter((row) => row.leafType === 2 && Buffer.compare(row.key, target) < 0)
          .sort((left, right) => Buffer.compare(left.key, right.key));
        const entry = normal.length === 0
          ? need().nullifierLeaves.find((row) => row.leafType === 1)
          : normal[normal.length - 1];
        if (entry === undefined) fail('ZERO_CONF_OVERLAY_MATERIAL_INVALID', 'beta material has no nullifier minimum sentinel');
        return Object.freeze({ ...entry, leafHash: copy(entry.leafHash), key: copy(entry.key), successorKey: copy(entry.successorKey) });
      },
      encryptedRecord: ({ recordId } = {}) => {
        const entry = need().records.find((row) => row.recordId === text(recordId, 'beta witness encryptedRecord.recordId'));
        return entry === undefined ? null : copy(entry.record);
      },
      ownedNote: ({ noteId } = {}) => {
        const entry = need().ownedNotes.find((row) => row.noteId === text(noteId, 'beta witness ownedNote.noteId'));
        return entry === undefined ? null : Object.freeze({ ...entry, nullifier: copy(entry.nullifier) });
      },
      fundingUtxo: ({ txid: queryTxid, vout } = {}) => {
        const id = txid(queryTxid, 'beta witness fundingUtxo.txid'); const index = u32(vout, 'beta witness fundingUtxo.vout');
        const entry = need().fundingUtxos.find((row) => same(row.txid, id) && row.vout === index);
        return entry === undefined ? null : Object.freeze({ ...entry, txid: copy(entry.txid) });
      },
    });
  }

  /**
   * Fully restored/authenticated tree capability for `applyDirectV2Transition`.
   * It is beta-only and intentionally reports no confirmed block metadata.
   */
  optimisticTransitionView() {
    const anchor = anchorRow(this.#db);
    const tip = activeTip(this.#db);
    const materialValue = activeMaterial(this.#db);
    if (!anchor || !tip || !materialValue) return null;
    let restored;
    try {
      restored = restoreV2BetaZeroConfTreeMaterial({
        material: materialValue.treeMaterial,
        profileId: hex(anchor.profile_id),
        state: tip.state,
      });
    } catch (error) {
      fail('ZERO_CONF_OVERLAY_MATERIAL_INVALID', `active beta transition material cannot be restored: ${error instanceof Error ? error.message : String(error)}`);
    }
    return Object.freeze({
      tip: Object.freeze({ state: copy(tip.state), outpoint: Object.freeze({ txid: copy(tip.outpoint.txid), vout: tip.outpoint.vout }), actionSequence: tip.actionSequence }),
      material: materialValue,
      noteTree: restored.noteTree,
      nullifierTree: restored.nullifierTree,
      state: restored.state,
    });
  }

  /** The only tip usable for a subsequent beta action. It is never confirmed. */
  optimisticTip() {
    const anchor = anchorRow(this.#db);
    const tip = activeTip(this.#db);
    return Object.freeze({
      schema: V2_BETA_ZERO_CONF_OVERLAY_SCHEMA,
      status: V2_BETA_ZERO_CONF_OPTIMISTIC_STATUS,
      confirmed: false,
      anchor: outputAnchor(anchor),
      tip,
      actions: Object.freeze(actionRows(this.#db).map(outputAction)),
    });
  }

  /**
   * Durably records a BCHN zero-conf observation. It accepts no height or
   * block hash, and rejects any later attempt to rewrite the anchor.
   */
  #anchorAcceptedGenesis(value) {
    const input = exact(value, [
      'eligibility', 'genesisOutpoint', 'initialState', 'initialStateSha256',
      'instanceId', 'material', 'profileId', 'status', 'zeroConfEvidenceSha256',
    ], 'zero-conf genesis anchor');
    if (input.status !== V2_BETA_ZERO_CONF_ANCHOR_STATUS
      || input.eligibility !== V2_BETA_ZERO_CONF_ELIGIBILITY) {
      fail('ZERO_CONF_OVERLAY_INVALID', 'anchor must be explicitly accepted-zero-conf and beta-single-contributor-unqualified');
    }
    const profileId = txid(input.profileId, 'zero-conf genesis anchor.profileId');
    const instanceId = txid(input.instanceId, 'zero-conf genesis anchor.instanceId');
    const genesisOutpoint = normalizedOutpoint(input.genesisOutpoint, 'zero-conf genesis anchor.genesisOutpoint');
    if (genesisOutpoint.vout !== 0) fail('ZERO_CONF_OVERLAY_INVALID', 'beta genesis state outpoint must be vout 0');
    const initialState = bytes(input.initialState, 128, 'zero-conf genesis anchor.initialState');
    const initialStateSha256 = hash(input.initialStateSha256, 'zero-conf genesis anchor.initialStateSha256');
    const zeroConfEvidenceSha256 = hash(input.zeroConfEvidenceSha256, 'zero-conf genesis anchor.zeroConfEvidenceSha256');
    const initialMaterialValue = material(input.material, 'zero-conf genesis anchor.material');
    const initialMaterial = Buffer.from(serialize(initialMaterialValue));
    if (sha256(initialState) !== initialStateSha256) {
      fail('ZERO_CONF_OVERLAY_INVALID', 'initialStateSha256 does not authenticate initialState');
    }
    assertMaterialMatchesState(initialMaterialValue, initialState, profileId, 'zero-conf genesis anchor material');
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const previous = anchorRow(this.#db);
      if (previous) {
        const sameAnchor = same(previous.profile_id, profileId)
          && same(previous.instance_id, instanceId)
          && same(previous.genesis_txid, genesisOutpoint.txid)
          && previous.genesis_vout === genesisOutpoint.vout
          && same(previous.initial_state, initialState)
          && same(previous.material_bytes, initialMaterial)
          && previous.initial_state_sha256 === initialStateSha256
          && previous.zero_conf_evidence_sha256 === zeroConfEvidenceSha256
          && previous.status === input.status && previous.eligibility === input.eligibility;
        if (!sameAnchor) fail('ZERO_CONF_OVERLAY_ANCHOR_IMMUTABLE', 'zero-conf genesis anchor already exists with different evidence');
      } else {
        this.#db.prepare(`INSERT INTO beta_zero_conf_anchor(
          singleton,profile_id,instance_id,genesis_txid,genesis_vout,initial_state,material_bytes,
          initial_state_sha256,zero_conf_evidence_sha256,status,eligibility,evicted,evicted_reason
        ) VALUES(1,?,?,?,?,?,?,?,?,?,?,0,NULL)`).run(
          profileId, instanceId, genesisOutpoint.txid, genesisOutpoint.vout,
          initialState, initialMaterial, initialStateSha256, zeroConfEvidenceSha256,
          input.status, input.eligibility,
        );
      }
      this.#db.exec('COMMIT');
    } catch (error) {
      this.#db.exec('ROLLBACK');
      throw error;
    }
    return this.anchor();
  }

  /**
   * Production-facing beta entrypoint. The identity/evidence values come only
   * from the locally derived, clone-resistant deployment capability; callers
   * supply state bytes solely to match its pinned state hash.
   */
  anchorAcceptedDeployment(value) {
    const input = exact(value, ['deploymentBinding', 'initialState', 'material'], 'zero-conf deployment anchor');
    let binding;
    try { binding = assertV2BetaChipnetDeploymentCapability(input.deploymentBinding); }
    catch (error) { fail('ZERO_CONF_OVERLAY_DEPLOYMENT_CAPABILITY_REJECTED', error instanceof Error ? error.message : 'accepted beta deployment capability is required'); }
    const initialState = bytes(input.initialState, 128, 'zero-conf deployment anchor.initialState');
    if (sha256(initialState) !== binding.initialStateSha256) {
      fail('ZERO_CONF_OVERLAY_DEPLOYMENT_CAPABILITY_REJECTED', 'initialState differs from the accepted deployment capability');
    }
    return this.#anchorAcceptedGenesis({
      profileId: Buffer.from(binding.profileId, 'hex'),
      instanceId: Buffer.from(binding.instanceId, 'hex'),
      genesisOutpoint: { txid: Buffer.from(binding.genesisOutpoint.txid, 'hex'), vout: binding.genesisOutpoint.vout },
      initialState,
      initialStateSha256: binding.initialStateSha256,
      zeroConfEvidenceSha256: binding.zeroConfEvidenceSha256,
      status: V2_BETA_ZERO_CONF_ANCHOR_STATUS,
      eligibility: binding.eligibility,
      material: input.material,
    });
  }

  operation(operationId) {
    return outputOperation(this.#db.prepare('SELECT * FROM beta_zero_conf_operations WHERE operation_id=?').get(text(operationId, 'beta operationId')));
  }

  /** Capture the current zero-conf tip for one beta-only action. */
  prepareBetaAction(value) {
    const input = exact(value, ['actionMaterialSha256', 'intent', 'kind', 'operationId', 'privateActionRecordSha256'], 'beta action prepare');
    const operationId = text(input.operationId, 'beta action prepare.operationId');
    if (!['deposit', 'transfer', 'withdrawal'].includes(input.kind)) fail('ZERO_CONF_OVERLAY_INVALID', 'beta action prepare.kind is unsupported');
    const intent = Buffer.from(serialize(betaIntent(input.intent, 'beta action prepare.intent')));
    const actionMaterialSha256 = hash(input.actionMaterialSha256, 'beta action prepare.actionMaterialSha256');
    const privateActionRecordSha256 = hash(input.privateActionRecordSha256, 'beta action prepare.privateActionRecordSha256');
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this.#db.prepare('SELECT * FROM beta_zero_conf_operations WHERE operation_id=?').get(operationId);
      if (existing) {
        if (existing.kind !== input.kind || !same(existing.intent_bytes, intent)
          || existing.action_material_sha256 !== actionMaterialSha256
          || existing.private_action_record_sha256 !== privateActionRecordSha256) {
          fail('ZERO_CONF_OVERLAY_OPERATION_IMMUTABLE', 'operationId already exists with a different immutable beta intent');
        }
      } else {
        const inFlight = this.#db.prepare("SELECT operation_id FROM beta_zero_conf_operations WHERE journal_state IN('prepared','proving','proved','signed') LIMIT 1").get();
        if (inFlight) fail('ZERO_CONF_OVERLAY_ACTION_IN_FLIGHT', 'one beta action must finish or be rejected before preparing another');
        const tip = activeTip(this.#db);
        if (!tip) fail('ZERO_CONF_OVERLAY_ANCHOR_REQUIRED', 'an active accepted zero-conf genesis anchor is required');
        this.#db.prepare(`INSERT INTO beta_zero_conf_operations(
          operation_id,kind,journal_state,expected_state,expected_txid,expected_vout,expected_sequence,intent_bytes,
          action_material_sha256,private_action_record_sha256,expected_material_sha256,
          packet,proof,unsigned_tx,signed_tx,local_vm_evidence,reason
        ) VALUES(?,?, 'prepared',?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,NULL,NULL)`).run(
          operationId, input.kind, tip.state, tip.outpoint.txid, tip.outpoint.vout, tip.actionSequence, intent,
          actionMaterialSha256, privateActionRecordSha256, sha256(Buffer.from(serialize(activeMaterial(this.#db)))),
        );
      }
      this.#db.exec('COMMIT');
    } catch (error) {
      this.#db.exec('ROLLBACK');
      throw error;
    }
    return this.operation(operationId);
  }

  transitionBetaAction(value) {
    const input = exact(value, ['operationId', 'to'], 'beta action transition');
    const operationId = text(input.operationId, 'beta action transition.operationId');
    const to = input.to;
    const allowed = Object.freeze({
      prepared: new Set(['proving', 'rejected']), proving: new Set(['proved', 'rejected']),
      proved: new Set(['signed', 'rejected']), signed: new Set(['mempool', 'rejected']),
      mempool: new Set(['evicted', 'rejected']), rejected: new Set(), evicted: new Set(),
    });
    if (typeof to !== 'string' || !Object.hasOwn(allowed, to)) fail('ZERO_CONF_OVERLAY_INVALID', 'beta action transition target is unsupported');
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.#db.prepare('SELECT * FROM beta_zero_conf_operations WHERE operation_id=?').get(operationId);
      if (!row) fail('ZERO_CONF_OVERLAY_UNKNOWN_OPERATION', 'beta operation does not exist');
      if (!allowed[row.journal_state].has(to)) fail('ZERO_CONF_OVERLAY_TRANSITION_REJECTED', `beta action transition ${row.journal_state} -> ${to} is not allowed`);
      if (to === 'proved' && (row.packet === null || row.proof === null || row.unsigned_tx === null)) fail('ZERO_CONF_OVERLAY_ARTIFACTS_REQUIRED', 'proved beta action requires packet, proof, and unsigned transaction');
      if (to === 'signed' && (row.signed_tx === null || row.local_vm_evidence === null)) fail('ZERO_CONF_OVERLAY_ARTIFACTS_REQUIRED', 'signed beta action requires signed transaction and local VM evidence');
      this.#db.prepare('UPDATE beta_zero_conf_operations SET journal_state=? WHERE operation_id=?').run(to, operationId);
      this.#db.exec('COMMIT');
    } catch (error) {
      this.#db.exec('ROLLBACK');
      throw error;
    }
    return this.operation(operationId);
  }

  updateBetaActionArtifacts(value) {
    const input = exact(value, ['localVmEvidence', 'operationId', 'packet', 'proof', 'signedTx', 'unsignedTx'], 'beta action artifacts');
    const operationId = text(input.operationId, 'beta action artifacts.operationId');
    const artifact = (entry, label) => entry === null ? null : bytes(entry, entry.length, label);
    const artifacts = [
      artifact(input.packet, 'beta action artifacts.packet'), artifact(input.proof, 'beta action artifacts.proof'),
      artifact(input.unsignedTx, 'beta action artifacts.unsignedTx'), artifact(input.signedTx, 'beta action artifacts.signedTx'),
      artifact(input.localVmEvidence, 'beta action artifacts.localVmEvidence'),
    ];
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.#db.prepare('SELECT * FROM beta_zero_conf_operations WHERE operation_id=?').get(operationId);
      if (!row || !['prepared', 'proving', 'proved'].includes(row.journal_state)) fail('ZERO_CONF_OVERLAY_ARTIFACTS_REJECTED', 'beta action artifacts are unavailable after signing or terminal state');
      const immutable = (prior, next) => prior === null || (next !== null && same(prior, next));
      if (!immutable(row.packet, artifacts[0]) || !immutable(row.proof, artifacts[1]) || !immutable(row.unsigned_tx, artifacts[2]) || !immutable(row.signed_tx, artifacts[3]) || !immutable(row.local_vm_evidence, artifacts[4])) fail('ZERO_CONF_OVERLAY_OPERATION_IMMUTABLE', 'beta action artifact rewrite is rejected');
      this.#db.prepare('UPDATE beta_zero_conf_operations SET packet=?,proof=?,unsigned_tx=?,signed_tx=?,local_vm_evidence=? WHERE operation_id=?').run(...artifacts, operationId);
      this.#db.exec('COMMIT');
    } catch (error) {
      this.#db.exec('ROLLBACK');
      throw error;
    }
    return this.operation(operationId);
  }

  /** Append one exact descendant. The predecessor must be the active tip. */
  appendMempoolAction(value) {
    const input = exact(value, ['material', 'operationId', 'predecessor', 'successor', 'transactionId'], 'zero-conf overlay action');
    const operationId = text(input.operationId, 'zero-conf overlay action.operationId');
    const transactionId = txid(input.transactionId, 'zero-conf overlay action.transactionId');
    const predecessor = exact(input.predecessor, ['actionSequence', 'outpoint', 'state'], 'zero-conf overlay action.predecessor');
    const successor = exact(input.successor, ['actionSequence', 'outpoint', 'state'], 'zero-conf overlay action.successor');
    const expected = Object.freeze({
      state: bytes(predecessor.state, 128, 'zero-conf overlay action.predecessor.state'),
      outpoint: normalizedOutpoint(predecessor.outpoint, 'zero-conf overlay action.predecessor.outpoint'),
      actionSequence: sequence(predecessor.actionSequence, 'zero-conf overlay action.predecessor.actionSequence'),
    });
    const next = Object.freeze({
      state: bytes(successor.state, 128, 'zero-conf overlay action.successor.state'),
      outpoint: normalizedOutpoint(successor.outpoint, 'zero-conf overlay action.successor.outpoint'),
      actionSequence: sequence(successor.actionSequence, 'zero-conf overlay action.successor.actionSequence'),
    });
    const nextMaterialValue = material(input.material, 'zero-conf overlay action.material');
    const nextMaterial = Buffer.from(serialize(nextMaterialValue));
    if (!same(next.outpoint.txid, transactionId) || next.outpoint.vout !== 0) {
      fail('ZERO_CONF_OVERLAY_INVALID', 'successor must be the action transaction state output at vout 0');
    }
    if (next.actionSequence !== expected.actionSequence + 1) {
      fail('ZERO_CONF_OVERLAY_INVALID', 'successor actionSequence must increase by exactly one');
    }
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const anchor = anchorRow(this.#db);
      if (!anchor) fail('ZERO_CONF_OVERLAY_ANCHOR_REQUIRED', 'accepted zero-conf genesis anchor is required');
      if (anchor.evicted) fail('ZERO_CONF_OVERLAY_ANCHOR_EVICTED', 'accepted zero-conf genesis was evicted; no optimistic action is allowed');
      assertMaterialMatchesState(nextMaterialValue, next.state, anchor.profile_id, 'zero-conf overlay successor material');
      const operation = this.#db.prepare('SELECT * FROM beta_zero_conf_operations WHERE operation_id=?').get(operationId);
      if (!operation || !['signed', 'mempool'].includes(operation.journal_state)) {
        fail('ZERO_CONF_OVERLAY_SIGNED_OPERATION_REQUIRED', 'a signed beta operation is required before accepting its mempool overlay');
      }
      const operationExpected = Object.freeze({
        state: copy(operation.expected_state),
        outpoint: Object.freeze({ txid: copy(operation.expected_txid), vout: operation.expected_vout }),
        actionSequence: operation.expected_sequence,
      });
      assertTipMatch(operationExpected, expected, 'operation expected optimistic tip');
      const existing = this.#db.prepare('SELECT * FROM beta_zero_conf_actions WHERE operation_id=?').get(operationId);
      if (existing) {
        const sameAction = same(existing.transaction_id, transactionId)
          && same(existing.predecessor_state, expected.state)
          && same(existing.predecessor_txid, expected.outpoint.txid)
          && existing.predecessor_vout === expected.outpoint.vout
          && existing.predecessor_sequence === expected.actionSequence
          && same(existing.successor_state, next.state)
          && same(existing.successor_txid, next.outpoint.txid)
          && existing.successor_vout === next.outpoint.vout
          && existing.successor_sequence === next.actionSequence
          && same(existing.material_after_bytes, nextMaterial);
        if (!sameAction) fail('ZERO_CONF_OVERLAY_OPERATION_IMMUTABLE', 'operationId already exists with different overlay bytes');
      } else {
        const tip = activeTip(this.#db);
        assertTipMatch(tip, expected, 'action predecessor');
        const priorMaterial = activeMaterial(this.#db);
        const ordinal = this.#db.prepare('SELECT COALESCE(MAX(ordinal),0)+1 AS ordinal FROM beta_zero_conf_actions').get().ordinal;
        this.#db.prepare(`INSERT INTO beta_zero_conf_actions(
          ordinal,operation_id,transaction_id,predecessor_state,predecessor_txid,
          predecessor_vout,predecessor_sequence,successor_state,successor_txid,
          successor_vout,successor_sequence,material_before_bytes,material_after_bytes,status,reason
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'active',NULL)`).run(
          ordinal, operationId, transactionId, expected.state, expected.outpoint.txid,
          expected.outpoint.vout, expected.actionSequence, next.state, next.outpoint.txid,
          next.outpoint.vout, next.actionSequence, Buffer.from(serialize(priorMaterial)), nextMaterial,
        );
        this.#db.prepare("UPDATE beta_zero_conf_operations SET journal_state='mempool' WHERE operation_id=?").run(operationId);
      }
      this.#db.exec('COMMIT');
    } catch (error) {
      this.#db.exec('ROLLBACK');
      throw error;
    }
    return this.optimisticTip();
  }

  /** Explicitly rejects one action and deterministically invalidates descendants. */
  rejectMempoolAction(value) {
    const input = exact(value, ['operationId', 'reason'], 'zero-conf overlay reject');
    const operationId = text(input.operationId, 'zero-conf overlay reject.operationId');
    const rejectionReason = reason(input.reason, 'zero-conf overlay reject.reason');
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.#db.prepare('SELECT ordinal,status FROM beta_zero_conf_actions WHERE operation_id=?').get(operationId);
      if (!row) fail('ZERO_CONF_OVERLAY_UNKNOWN_OPERATION', 'overlay operation does not exist');
      if (row.status !== 'active') fail('ZERO_CONF_OVERLAY_NOT_ACTIVE', 'only an active overlay action can be rejected');
      this.#db.prepare("UPDATE beta_zero_conf_actions SET status='rejected',reason=? WHERE ordinal>=? AND status='active'")
        .run(rejectionReason, row.ordinal);
      this.#db.prepare("UPDATE beta_zero_conf_operations SET journal_state='rejected',reason=? WHERE operation_id IN (SELECT operation_id FROM beta_zero_conf_actions WHERE ordinal>=? AND status='rejected')")
        .run(rejectionReason, row.ordinal);
      this.#db.exec('COMMIT');
    } catch (error) {
      this.#db.exec('ROLLBACK');
      throw error;
    }
    return this.optimisticTip();
  }

  /**
   * Reconcile a BCHN mempool observation. `observedOperationIds` must be the
   * exact active-prefix seen by the caller; missing actions are marked evicted
   * with every descendant. This method cannot promote anything to confirmed.
   */
  reconcileMempool(value) {
    const input = exact(value, ['anchorPresent', 'observedOperationIds'], 'zero-conf overlay reconciliation');
    if (typeof input.anchorPresent !== 'boolean' || !Array.isArray(input.observedOperationIds)) {
      fail('ZERO_CONF_OVERLAY_INVALID', 'reconciliation must contain boolean anchorPresent and an operation-id array');
    }
    const observed = input.observedOperationIds.map((entry, index) => text(entry, `reconciliation.observedOperationIds[${index}]`));
    if (new Set(observed).size !== observed.length) fail('ZERO_CONF_OVERLAY_INVALID', 'reconciliation operation IDs must be unique');
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const anchor = anchorRow(this.#db);
      if (!anchor) fail('ZERO_CONF_OVERLAY_ANCHOR_REQUIRED', 'accepted zero-conf genesis anchor is required');
      const active = this.#db.prepare("SELECT ordinal,operation_id FROM beta_zero_conf_actions WHERE status='active' ORDER BY ordinal ASC").all();
      const expectedPrefix = active.slice(0, observed.length).map((row) => row.operation_id);
      if (observed.length > active.length || expectedPrefix.some((id, index) => id !== observed[index])) {
        fail('ZERO_CONF_OVERLAY_RECONCILIATION_CONFLICT', 'observed actions are not the exact ordered active prefix');
      }
      if (!input.anchorPresent) {
        this.#db.prepare('UPDATE beta_zero_conf_anchor SET evicted=1,evicted_reason=? WHERE singleton=1 AND evicted=0')
          .run('BCHN zero-conf reconciliation did not find genesis state outpoint');
        this.#db.prepare("UPDATE beta_zero_conf_actions SET status='evicted',reason=? WHERE status='active'")
          .run('ancestor genesis state outpoint was evicted from the BCHN mempool view');
        this.#db.prepare("UPDATE beta_zero_conf_operations SET journal_state='evicted',reason=? WHERE journal_state='mempool'")
          .run('ancestor genesis state outpoint was evicted from the BCHN mempool view');
      } else if (observed.length < active.length) {
        const firstEvicted = active[observed.length].ordinal;
        this.#db.prepare("UPDATE beta_zero_conf_actions SET status='evicted',reason=? WHERE ordinal>=? AND status='active'")
          .run('BCHN zero-conf reconciliation no longer observed this ordered action chain', firstEvicted);
        this.#db.prepare("UPDATE beta_zero_conf_operations SET journal_state='evicted',reason=? WHERE operation_id IN (SELECT operation_id FROM beta_zero_conf_actions WHERE ordinal>=? AND status='evicted')")
          .run('BCHN zero-conf reconciliation no longer observed this ordered action chain', firstEvicted);
      }
      this.#db.exec('COMMIT');
    } catch (error) {
      this.#db.exec('ROLLBACK');
      throw error;
    }
    return this.optimisticTip();
  }
}

export function openV2BetaZeroConfOverlay(value) {
  return new V2BetaZeroConfOverlay(value);
}
