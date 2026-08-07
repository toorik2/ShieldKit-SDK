/**
 * Durable, transactional operation state.
 *
 * A JSON-file-per-operation journal cannot make a compare-and-swap claim: two
 * processes can both read the same file and both write a successful update.
 * The kernel therefore uses a small SQLite database with FULL synchronous WAL
 * transactions.  This is the authority for operation state *and* reservations.
 */

import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
} from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { readHomeManifest } from '../home/resolve.mjs';
import { ERROR_CODES, cliFail } from '../contracts/errors.mjs';

export const JOURNAL_SCHEMA = 'shieldkit-operation-journal/v2';

const OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

function assertOperationId(operationId) {
  if (typeof operationId !== 'string' || !OPERATION_ID.test(operationId)) {
    throw new Error('operationId must use 1-128 safe identifier characters');
  }
}

function ownUid(stat) {
  return typeof process.getuid !== 'function' || stat.uid === process.getuid();
}

function assertPrivateDirectory(directory, { create = false } = {}) {
  if (create && !existsSync(directory)) mkdirSync(directory, { mode: 0o700 });
  const stat = lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || !ownUid(stat) || (stat.mode & 0o077) !== 0) {
    cliFail(ERROR_CODES.DURABILITY_REQUIRED, `operation store directory must be private, owner-controlled, and non-symlink: ${directory}`);
  }
}

function preparePrivateDatabase(filename) {
  if (existsSync(filename)) {
    const stat = lstatSync(filename);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || !ownUid(stat) || (stat.mode & 0o077) !== 0) {
      cliFail(ERROR_CODES.DURABILITY_REQUIRED, `operation database must be a private owner-controlled single-link file: ${filename}`);
    }
    return;
  }
  let fd;
  try {
    fd = openSync(filename, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    fsyncSync(fd);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
  let parent;
  try {
    parent = openSync(path.dirname(filename), constants.O_RDONLY | constants.O_NOFOLLOW);
    fsyncSync(parent);
  } finally {
    if (parent !== undefined) closeSync(parent);
  }
}

function tightenSqliteFiles(databasePath) {
  for (const filename of [databasePath, `${databasePath}-wal`, `${databasePath}-shm`]) {
    if (existsSync(filename)) chmodSync(filename, 0o600);
  }
}

function canonicalRecord(op) {
  const record = {
    schema: JOURNAL_SCHEMA,
    ...op,
    history: [...(op.history || [])],
    persistedAt: Date.now(),
    contentSha256: null,
  };
  record.contentSha256 = createHash('sha256')
    .update(JSON.stringify({ ...record, contentSha256: null }))
    .digest('hex');
  return record;
}

function parseRow(row) {
  if (!row) return null;
  const payload = JSON.parse(row.payload);
  if (payload.schema !== JOURNAL_SCHEMA) throw new Error(`unsupported journal schema: ${payload.schema}`);
  const actual = createHash('sha256')
    .update(JSON.stringify({ ...payload, contentSha256: null }))
    .digest('hex');
  if (payload.contentSha256 !== actual) throw new Error('durable operation integrity hash mismatch');
  return Object.freeze({ ...payload, storeVersion: Number(row.version) });
}

export class DurableOperationStore {
  constructor(homePath) {
    if (typeof homePath !== 'string' || !path.isAbsolute(homePath)) {
      throw new Error('DurableOperationStore requires absolute homePath');
    }
    const home = readHomeManifest(homePath);
    if (!home) cliFail(ERROR_CODES.DURABILITY_REQUIRED, 'operation store requires a validated bound home manifest');
    this.home = home;
    this.homePath = home.path;
    const stateDirectory = path.join(this.homePath, 'state');
    assertPrivateDirectory(stateDirectory);
    this.dir = path.join(stateDirectory, 'operations');
    assertPrivateDirectory(this.dir, { create: true });
    this.path = path.join(this.dir, 'journal.sqlite');
    preparePrivateDatabase(this.path);
    this.db = new DatabaseSync(this.path);
    this.db.exec(`
      PRAGMA journal_mode=WAL;
      PRAGMA synchronous=FULL;
      PRAGMA foreign_keys=ON;
      PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS operations (
        operation_id TEXT PRIMARY KEY NOT NULL,
        version INTEGER NOT NULL,
        payload TEXT NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS reservations (
        kind TEXT NOT NULL,
        reservation_key TEXT NOT NULL,
        operation_id TEXT NOT NULL REFERENCES operations(operation_id),
        value TEXT NOT NULL,
        PRIMARY KEY(kind, reservation_key)
      ) STRICT;
      CREATE INDEX IF NOT EXISTS reservations_by_operation ON reservations(operation_id);
    `);
    tightenSqliteFiles(this.path);
  }

  _transaction(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = fn();
      this.db.exec('COMMIT');
      return result;
    } catch (error) {
      try { this.db.exec('ROLLBACK'); } catch { /* no open transaction */ }
      throw error;
    }
  }

  load(operationId) {
    assertOperationId(operationId);
    return parseRow(this.db.prepare('SELECT version, payload FROM operations WHERE operation_id = ?').get(operationId));
  }

  list() {
    return this.db.prepare('SELECT version, payload FROM operations ORDER BY operation_id').all().map(parseRow);
  }

  /** Insert a new operation. Existing ids are never overwritten. */
  create(op) {
    assertOperationId(op?.operationId);
    const record = canonicalRecord(op);
    return this._transaction(() => {
      const existing = this.db.prepare('SELECT 1 FROM operations WHERE operation_id = ?').get(op.operationId);
      if (existing) throw new Error(`operation already exists: ${op.operationId}`);
      this.db.prepare('INSERT INTO operations(operation_id, version, payload) VALUES (?, 1, ?)')
        .run(op.operationId, JSON.stringify(record));
      return Object.freeze({ ...record, storeVersion: 1 });
    });
  }

  /**
   * Atomic read/validate/mutate/write. The predicate and mutator execute under
   * BEGIN IMMEDIATE, so another coordinator cannot consume the same send or CAS.
   */
  update(operationId, { predicate = null, mutate }) {
    assertOperationId(operationId);
    if (typeof mutate !== 'function') throw new Error('transactional mutator required');
    return this._transaction(() => {
      const current = parseRow(this.db.prepare('SELECT version, payload FROM operations WHERE operation_id = ?').get(operationId));
      if (!current) throw new Error(`unknown operation ${operationId}`);
      if (predicate && predicate(current) !== true) return { applied: false, current };
      const next = { ...current, history: [...(current.history || [])] };
      delete next.storeVersion;
      mutate(next);
      const record = canonicalRecord(next);
      const version = current.storeVersion + 1;
      this.db.prepare('UPDATE operations SET version = ?, payload = ? WHERE operation_id = ? AND version = ?')
        .run(version, JSON.stringify(record), operationId, current.storeVersion);
      return { applied: true, current, next: Object.freeze({ ...record, storeVersion: version }) };
    });
  }

  /** Compatibility write, intentionally refuses blind updates of existing ops. */
  save(op) {
    if (!op?.storeVersion) return this.create(op);
    const version = op.storeVersion;
    const result = this.update(op.operationId, {
      predicate: (current) => current.storeVersion === version,
      mutate: (next) => Object.assign(next, op, { storeVersion: undefined }),
    });
    if (!result.applied) throw new Error('durable operation version conflict');
    return result.next;
  }

  remove(operationId) {
    assertOperationId(operationId);
    return this._transaction(() => this.db.prepare('DELETE FROM operations WHERE operation_id = ?').run(operationId));
  }

  loadAllIntoMap(map) {
    for (const op of this.list()) map.set(op.operationId, op);
    return map;
  }

  reserve(operationId, { noteId = null, fundingOutpoint = null, destinationAddress = null, forbiddenDestinations = [] } = {}) {
    return this._transaction(() => {
      const current = parseRow(this.db.prepare('SELECT version, payload FROM operations WHERE operation_id = ?').get(operationId));
      if (!current) throw new Error(`unknown operation ${operationId}`);
      const held = { ...(current.reservations || {}) };
      const claim = (kind, key, value) => {
        const found = this.db.prepare('SELECT operation_id FROM reservations WHERE kind = ? AND reservation_key = ?').get(kind, key);
        if (found && found.operation_id !== operationId) {
          const error = new Error(`${kind} ${key} reserved by ${found.operation_id}`);
          error.code = 'RESERVATION_HELD';
          throw error;
        }
        this.db.prepare('INSERT OR IGNORE INTO reservations(kind, reservation_key, operation_id, value) VALUES (?, ?, ?, ?)')
          .run(kind, key, operationId, JSON.stringify(value));
      };
      if (noteId) { claim('note', noteId, { at: Date.now() }); held.note = { operationId, at: Date.now() }; }
      if (fundingOutpoint) { claim('funding', fundingOutpoint, { at: Date.now() }); held.funding = { operationId, at: Date.now() }; }
      if (destinationAddress) {
        if (forbiddenDestinations.includes(destinationAddress)) {
          const error = new Error('destination binding rejects fee/change/self wallet address'); error.code = 'DESTINATION_BINDING_FAILED'; throw error;
        }
        const found = this.db.prepare("SELECT value FROM reservations WHERE kind = 'destination' AND reservation_key = ?").get(operationId);
        if (found && JSON.parse(found.value).address !== destinationAddress) {
          const error = new Error('destination already bound to a different address for this operation'); error.code = 'DESTINATION_BINDING_FAILED'; throw error;
        }
        claim('destination', operationId, { address: destinationAddress, at: Date.now() });
        held.destination = { operationId, address: destinationAddress, at: Date.now() };
      }
      const next = { ...current, history: [...current.history], reservations: held, destination: destinationAddress || current.destination };
      delete next.storeVersion;
      const record = canonicalRecord(next);
      this.db.prepare('UPDATE operations SET version = ?, payload = ? WHERE operation_id = ? AND version = ?')
        .run(current.storeVersion + 1, JSON.stringify(record), operationId, current.storeVersion);
      return Object.freeze({ ...record, storeVersion: current.storeVersion + 1 });
    });
  }

  releaseOperation(operationId) {
    return this._transaction(() => this.db.prepare('DELETE FROM reservations WHERE operation_id = ?').run(operationId));
  }

  /** Atomically mark a successfully idempotent local commit and release inputs. */
  finalizeCommit(operationId, transition) {
    return this._transaction(() => {
      const current = parseRow(this.db.prepare('SELECT version, payload FROM operations WHERE operation_id = ?').get(operationId));
      if (!current || current.state !== 'local-commit-pending') return { applied: false, current };
      const next = { ...current, history: [...current.history] }; delete next.storeVersion;
      transition(next);
      const record = canonicalRecord(next);
      this.db.prepare('UPDATE operations SET version = ?, payload = ? WHERE operation_id = ? AND version = ?')
        .run(current.storeVersion + 1, JSON.stringify(record), operationId, current.storeVersion);
      this.db.prepare('DELETE FROM reservations WHERE operation_id = ?').run(operationId);
      return { applied: true, next: Object.freeze({ ...record, storeVersion: current.storeVersion + 1 }) };
    });
  }

  reservationSnapshot() {
    const out = { schema: 'shieldkit-reservations/v2', notes: {}, funding: {}, destinations: {} };
    for (const row of this.db.prepare('SELECT kind, reservation_key, operation_id, value FROM reservations').all()) {
      const value = JSON.parse(row.value);
      if (row.kind === 'note') out.notes[row.reservation_key] = { operationId: row.operation_id, ...value };
      if (row.kind === 'funding') out.funding[row.reservation_key] = { operationId: row.operation_id, ...value };
      if (row.kind === 'destination') out.destinations[row.reservation_key] = { operationId: row.operation_id, ...value };
    }
    return out;
  }
}

/** Compatibility facade. Coordinators always route through DurableOperationStore. */
export class ReservationLedger {
  constructor(homePath, store = null) { this.store = store || new DurableOperationStore(homePath); }
  reserveNote(noteId, operationId) { return this.store.reserve(operationId, { noteId }).reservations.note; }
  reserveFunding(outpoint, operationId) { return this.store.reserve(operationId, { fundingOutpoint: outpoint }).reservations.funding; }
  bindDestination(operationId, address, options) { return this.store.reserve(operationId, { destinationAddress: address, forbiddenDestinations: options?.forbiddenAddresses || [] }).reservations.destination; }
  releaseOperation(operationId) { return this.store.releaseOperation(operationId); }
  snapshot() { return this.store.reservationSnapshot(); }
}
