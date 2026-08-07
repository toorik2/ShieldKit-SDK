/**
 * The operator-owned source registry is the only authority for beta funding
 * outpoint lifecycle. It is intentionally a single canonical SQLite database
 * below an explicitly selected private operator root; commands accept a root,
 * never a caller-selected collection of historical ledgers.
 */
import { createHash, randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { chmodSync, existsSync, lstatSync, mkdirSync, realpathSync } from 'node:fs';
import path from 'node:path';

export const V2_BETA_OPERATOR_SOURCE_REGISTRY_SCHEMA =
  'shieldkit-v2-beta-operator-source-registry-v2';
export const V2_BETA_OPERATOR_SOURCE_REGISTRY_FILENAME =
  'shieldkit-v2-beta-operator-source-registry.sqlite';
export const V2_BETA_OPERATOR_SOURCE_STATES = Object.freeze([
  'available', 'semantic-claimed', 'performance-reserved',
  'send-attempted', 'indeterminate', 'spent', 'reconciled', 'explicitly-released',
]);

const HASH = /^[0-9a-f]{64}$/u;
const OUTPOINT = /^([0-9a-f]{64}):(0|[1-9][0-9]*)$/u;
const P2PKH = /^76a914[0-9a-f]{40}88ac$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
const REGISTRY_DIRECTORY = 'source-registry-v1';
const CURRENT_UID = typeof process.getuid === 'function' ? process.getuid() : null;

export class V2BetaOperatorSourceRegistryError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'V2BetaOperatorSourceRegistryError'; this.code = code;
  }
}
const fail = (code, message, options = undefined) => { throw new V2BetaOperatorSourceRegistryError(code, message, options); };
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const nowMs = () => Date.now();

function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) fail('SOURCE_REGISTRY_INVALID', `${label} must be a plain object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail('SOURCE_REGISTRY_INVALID', `${label} has missing or unknown fields`);
  return value;
}
function absolute(value, label) {
  if (typeof value !== 'string' || value.includes('\0') || !path.isAbsolute(value) || path.normalize(value) !== value) fail('SOURCE_REGISTRY_PATH_REJECTED', `${label} must be a normalized absolute path`);
  return value;
}
function canonicalAncestry(directory, label) {
  let current = directory;
  for (;;) {
    let stat;
    try { stat = lstatSync(current); }
    catch (error) { fail('SOURCE_REGISTRY_PATH_REJECTED', `${label} ancestry is unavailable`, { cause: error }); }
    if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(current) !== current) {
      fail('SOURCE_REGISTRY_PATH_REJECTED', `${label} ancestry must contain only canonical directories`);
    }
    const parent = path.dirname(current);
    if (parent === current) return;
    current = parent;
  }
}
function canonicalPrivateDataHome(value, label) {
  const target = absolute(value, label);
  canonicalAncestry(target, label);
  const stat = lstatSync(target);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700
    || (CURRENT_UID !== null && stat.uid !== CURRENT_UID) || realpathSync(target) !== target) {
    fail('SOURCE_REGISTRY_PATH_REJECTED', `${label} must be a current-user canonical private 0700 directory`);
  }
  return target;
}
function sourceOutpoint(value, label) {
  if (typeof value !== 'string') fail('SOURCE_REGISTRY_INVALID', `${label} must be a canonical outpoint`);
  const match = OUTPOINT.exec(value);
  if (match === null || !Number.isSafeInteger(Number(match[2])) || Number(match[2]) > 0xffff_ffff) fail('SOURCE_REGISTRY_INVALID', `${label} must be a canonical outpoint`);
  return Object.freeze({ text: value, txid: match[1], vout: Number(match[2]) });
}
function requireHash(value, label) { if (typeof value !== 'string' || !HASH.test(value)) fail('SOURCE_REGISTRY_INVALID', `${label} must be lowercase SHA-256`); return value; }
function requireLease(value, label) { if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value)) fail('SOURCE_REGISTRY_INVALID', `${label} is invalid`); return value; }
function sourceProvenance(outpoint) { return sha256(`shieldkit-v2-beta-operator-source-provenance-v1:${outpoint}`); }
export const v2BetaOperatorSourceProvenanceSha256 = (outpoint) => sourceProvenance(sourceOutpoint(outpoint, 'outpoint').text);

function strictDirectory(directory, { create = false } = {}) {
  const target = absolute(directory, 'operator root');
  const parent = path.dirname(target);
  const parentStat = lstatSync(parent);
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink() || realpathSync(parent) !== parent) fail('SOURCE_REGISTRY_PATH_REJECTED', 'operator root parent must be canonical');
  if (create && !existsSync(target)) {
    if ((parentStat.mode & 0o022) !== 0 || (CURRENT_UID !== null && parentStat.uid !== CURRENT_UID)) fail('SOURCE_REGISTRY_PATH_REJECTED', 'creating an operator root requires an owner-controlled parent');
    mkdirSync(target, { mode: 0o700 });
  }
  const stat = lstatSync(target);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700 || (CURRENT_UID !== null && stat.uid !== CURRENT_UID) || realpathSync(target) !== target) fail('SOURCE_REGISTRY_PATH_REJECTED', 'operator root must be canonical mode 0700 and current-user owned');
  return target;
}

/** Canonical database location: no command may override the filename. */
export function v2BetaOperatorSourceRegistryLocation({ operatorRoot } = {}) {
  const root = strictDirectory(operatorRoot, { create: true });
  const directory = path.join(root, REGISTRY_DIRECTORY);
  if (!existsSync(directory)) mkdirSync(directory, { mode: 0o700 });
  const safeDirectory = strictDirectory(directory);
  return Object.freeze({ operatorRoot: root, directory: safeDirectory, filename: path.join(safeDirectory, V2_BETA_OPERATOR_SOURCE_REGISTRY_FILENAME) });
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS registry_metadata (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema TEXT NOT NULL, owner_binding TEXT NOT NULL, created_at_ms INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS sources (
 outpoint TEXT PRIMARY KEY, provenance_sha256 TEXT NOT NULL UNIQUE, wallet_locking_bytecode_hex TEXT NOT NULL,
 value_sats TEXT NOT NULL, fanout_transaction_id TEXT NOT NULL, fanout_output_index INTEGER NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('fanout-performance','semantic')),
 state TEXT NOT NULL CHECK(state IN ('available','semantic-claimed','performance-reserved','send-attempted','indeterminate','spent','reconciled','explicitly-released')),
 release_id TEXT, release_manifest_sha256 TEXT, data_home TEXT UNIQUE, installation_receipt_sha256 TEXT,
 lease_id TEXT, run_id TEXT, evidence_sha256 TEXT, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS source_transitions (
 transition_id INTEGER PRIMARY KEY, outpoint TEXT NOT NULL REFERENCES sources(outpoint), from_state TEXT, to_state TEXT NOT NULL,
 reason TEXT NOT NULL, release_id TEXT, release_manifest_sha256 TEXT, data_home TEXT,
 installation_receipt_sha256 TEXT, lease_id TEXT, run_id TEXT, evidence_sha256 TEXT, created_at_ms INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS source_transitions_by_outpoint ON source_transitions(outpoint, transition_id);
CREATE TABLE IF NOT EXISTS fanout_operations (
 run_id TEXT PRIMARY KEY, transaction_id TEXT NOT NULL UNIQUE, raw_transaction_sha256 TEXT NOT NULL,
 journal_sha256 TEXT NOT NULL, input_count INTEGER NOT NULL CHECK(input_count BETWEEN 2 AND 512), input_set_sha256 TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('prepared','send-attempted','indeterminate','reconciled')),
 created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS fanout_input_reservations (
 outpoint TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES fanout_operations(run_id), transaction_id TEXT NOT NULL,
 raw_transaction_sha256 TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('prepared','send-attempted','indeterminate','reconciled')),
 created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL,
 UNIQUE(run_id,outpoint)
) STRICT;
CREATE INDEX IF NOT EXISTS fanout_input_reservations_by_run ON fanout_input_reservations(run_id, outpoint);
`;

const EXPECTED_SCHEMA_FACTS = Object.freeze([
  Object.freeze(['index', 'fanout_input_reservations_by_run', 'fanout_input_reservations', 'CREATE INDEX fanout_input_reservations_by_run ON fanout_input_reservations(run_id, outpoint)']),
  Object.freeze(['index', 'source_transitions_by_outpoint', 'source_transitions', 'CREATE INDEX source_transitions_by_outpoint ON source_transitions(outpoint, transition_id)']),
  Object.freeze(['table', 'fanout_input_reservations', 'fanout_input_reservations', "CREATE TABLE fanout_input_reservations ( outpoint TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES fanout_operations(run_id), transaction_id TEXT NOT NULL, raw_transaction_sha256 TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('prepared','send-attempted','indeterminate','reconciled')), created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL, UNIQUE(run_id,outpoint) ) STRICT"]),
  Object.freeze(['table', 'fanout_operations', 'fanout_operations', "CREATE TABLE fanout_operations ( run_id TEXT PRIMARY KEY, transaction_id TEXT NOT NULL UNIQUE, raw_transaction_sha256 TEXT NOT NULL, journal_sha256 TEXT NOT NULL, input_count INTEGER NOT NULL CHECK(input_count BETWEEN 2 AND 512), input_set_sha256 TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('prepared','send-attempted','indeterminate','reconciled')), created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL ) STRICT"]),
  Object.freeze(['table', 'registry_metadata', 'registry_metadata', 'CREATE TABLE registry_metadata ( singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema TEXT NOT NULL, owner_binding TEXT NOT NULL, created_at_ms INTEGER NOT NULL ) STRICT']),
  Object.freeze(['table', 'source_transitions', 'source_transitions', 'CREATE TABLE source_transitions ( transition_id INTEGER PRIMARY KEY, outpoint TEXT NOT NULL REFERENCES sources(outpoint), from_state TEXT, to_state TEXT NOT NULL, reason TEXT NOT NULL, release_id TEXT, release_manifest_sha256 TEXT, data_home TEXT, installation_receipt_sha256 TEXT, lease_id TEXT, run_id TEXT, evidence_sha256 TEXT, created_at_ms INTEGER NOT NULL ) STRICT']),
  Object.freeze(['table', 'sources', 'sources', "CREATE TABLE sources ( outpoint TEXT PRIMARY KEY, provenance_sha256 TEXT NOT NULL UNIQUE, wallet_locking_bytecode_hex TEXT NOT NULL, value_sats TEXT NOT NULL, fanout_transaction_id TEXT NOT NULL, fanout_output_index INTEGER NOT NULL, role TEXT NOT NULL CHECK(role IN ('fanout-performance','semantic')), state TEXT NOT NULL CHECK(state IN ('available','semantic-claimed','performance-reserved','send-attempted','indeterminate','spent','reconciled','explicitly-released')), release_id TEXT, release_manifest_sha256 TEXT, data_home TEXT UNIQUE, installation_receipt_sha256 TEXT, lease_id TEXT, run_id TEXT, evidence_sha256 TEXT, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL ) STRICT"]),
]);

function normalizedSql(value) {
  if (typeof value !== 'string') fail('SOURCE_REGISTRY_TAMPERED', 'registry schema object has no SQL definition');
  return value.trim().replace(/\s+/gu, ' ');
}

function assertPinnedSchema(database) {
  const facts = database.prepare(`SELECT type,name,tbl_name,sql FROM sqlite_master
    WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%' ORDER BY type,name`).all()
    .map((row) => [row.type, row.name, row.tbl_name, normalizedSql(row.sql)]);
  if (JSON.stringify(facts) !== JSON.stringify(EXPECTED_SCHEMA_FACTS)) {
    fail('SOURCE_REGISTRY_TAMPERED', 'registry SQLite schema differs from the pinned v2 DDL facts');
  }
  const foreignKeyViolations = database.prepare('PRAGMA foreign_key_check').all();
  if (foreignKeyViolations.length !== 0) {
    fail('SOURCE_REGISTRY_TAMPERED', 'registry foreign_key_check reported violations');
  }
}

function openRegistry({ operatorRoot } = {}) {
  const location = v2BetaOperatorSourceRegistryLocation({ operatorRoot });
  if (existsSync(location.filename)) {
    const stat = lstatSync(location.filename);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600 || (CURRENT_UID !== null && stat.uid !== CURRENT_UID) || realpathSync(location.filename) !== location.filename) fail('SOURCE_REGISTRY_PATH_REJECTED', 'registry must be a canonical 0600 unlinked regular file');
  }
  let database;
  try { database = new DatabaseSync(location.filename); }
  catch (error) { fail('SOURCE_REGISTRY_OPEN_REJECTED', 'could not open canonical source registry', { cause: error }); }
  try {
    chmodSync(location.filename, 0o600); database.exec('PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;');
    for (const filename of [location.filename, `${location.filename}-wal`, `${location.filename}-shm`]) {
      if (!existsSync(filename)) continue;
      const stat = lstatSync(filename);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (CURRENT_UID !== null && stat.uid !== CURRENT_UID)) fail('SOURCE_REGISTRY_PATH_REJECTED', 'registry database and sidecars must be private unlinked regular files');
      chmodSync(filename, 0o600);
    }
    database.exec(SCHEMA);
    assertPinnedSchema(database);
    const binding = sha256(`shieldkit-v2-beta-operator-source-owner-v1:${CURRENT_UID ?? 'unknown'}:${location.directory}`);
    const old = database.prepare('SELECT schema,owner_binding FROM registry_metadata WHERE singleton=1').get();
    if (old === undefined) database.prepare('INSERT INTO registry_metadata(singleton,schema,owner_binding,created_at_ms) VALUES(1,?,?,?)').run(V2_BETA_OPERATOR_SOURCE_REGISTRY_SCHEMA, binding, nowMs());
    else if (old.schema !== V2_BETA_OPERATOR_SOURCE_REGISTRY_SCHEMA || old.owner_binding !== binding) fail('SOURCE_REGISTRY_TAMPERED', 'registry schema or owner binding differs');
    return Object.freeze({ database, location });
  } catch (error) { database.close(); if (error instanceof V2BetaOperatorSourceRegistryError) throw error; fail('SOURCE_REGISTRY_OPEN_REJECTED', 'could not initialize canonical source registry', { cause: error }); }
}
function close(opened) { try { opened?.database.close(); } catch { /* close only */ } }
function transition(db, source, toState, reason, fields, stamp) {
  const fromState = source.state;
  db.prepare(`UPDATE sources SET state=?,release_id=?,release_manifest_sha256=?,data_home=?,installation_receipt_sha256=?,lease_id=?,run_id=?,evidence_sha256=?,updated_at_ms=? WHERE outpoint=? AND state=?`).run(toState, fields.releaseId, fields.releaseManifestSha256, fields.dataHome, fields.installationReceiptSha256, fields.leaseId, fields.runId, fields.evidenceSha256, stamp, source.outpoint, fromState);
  if (db.prepare('SELECT changes() AS count').get().count !== 1) fail('SOURCE_REGISTRY_CAS_CONFLICT', 'source changed during transition');
  db.prepare(`INSERT INTO source_transitions(outpoint,from_state,to_state,reason,release_id,release_manifest_sha256,data_home,installation_receipt_sha256,lease_id,run_id,evidence_sha256,created_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).run(source.outpoint, fromState, toState, reason, fields.releaseId, fields.releaseManifestSha256, fields.dataHome, fields.installationReceiptSha256, fields.leaseId, fields.runId, fields.evidenceSha256, stamp);
}
function normalSource(value, label = 'source') {
  exact(value, ['fanoutTransactionId', 'fanoutVout', 'lockingBytecodeHex', 'outpoint', 'valueSats'], label);
  const parsed = sourceOutpoint(value.outpoint, `${label}.outpoint`);
  if (!HASH.test(value.fanoutTransactionId) || value.fanoutTransactionId !== parsed.txid || !Number.isSafeInteger(value.fanoutVout) || value.fanoutVout !== parsed.vout || !P2PKH.test(value.lockingBytecodeHex) || typeof value.valueSats !== 'string' || !DECIMAL.test(value.valueSats) || BigInt(value.valueSats) < 546n) fail('SOURCE_REGISTRY_INVALID', `${label} is malformed`);
  return Object.freeze({ ...value, outpoint: parsed.text, provenanceSha256: sourceProvenance(parsed.text) });
}
function normalClaim(value, expectedCount, kind) {
  exact(value, ['evidenceSha256', 'leaseId', 'release', 'runId', 'sources'], `${kind} claim`);
  exact(value.release, ['releaseId', 'releaseManifestSha256'], `${kind} claim.release`);
  if (typeof value.release.releaseId !== 'string' || value.release.releaseId.length === 0 || !HASH.test(value.release.releaseManifestSha256) || !Array.isArray(value.sources) || value.sources.length !== expectedCount) fail('SOURCE_REGISTRY_INVALID', `${kind} claim is malformed`);
  const sources = value.sources.map((entry, index) => {
    exact(entry, ['dataHome', 'installationReceiptSha256', 'outpoint'], `${kind} claim.sources[${index}]`);
    if (!HASH.test(entry.installationReceiptSha256)) fail('SOURCE_REGISTRY_INVALID', `${kind} claim source is malformed`);
    return Object.freeze({ outpoint: sourceOutpoint(entry.outpoint, `${kind} claim source.outpoint`).text, dataHome: canonicalPrivateDataHome(entry.dataHome, `${kind} claim source.dataHome`), installationReceiptSha256: entry.installationReceiptSha256 });
  });
  if (new Set(sources.map((entry) => entry.outpoint)).size !== sources.length || new Set(sources.map((entry) => entry.dataHome)).size !== sources.length || new Set(sources.map((entry) => entry.installationReceiptSha256)).size !== sources.length) fail('SOURCE_REGISTRY_INVALID', `${kind} claim has duplicates`);
  return Object.freeze({ releaseId: value.release.releaseId, releaseManifestSha256: value.release.releaseManifestSha256, leaseId: requireLease(value.leaseId, 'leaseId'), runId: requireLease(value.runId, 'runId'), evidenceSha256: requireHash(value.evidenceSha256, 'evidenceSha256'), sources });
}
function normalImmutableTransitionBinding(value) {
  exact(value, ['dataHome', 'evidenceSha256', 'installationReceiptSha256', 'leaseId', 'lockingBytecodeHex', 'outpoint', 'releaseId', 'releaseManifestSha256', 'role', 'runId', 'valueSats'], 'immutable transition binding');
  if (!['fanout-performance', 'semantic'].includes(value.role)
    || typeof value.releaseId !== 'string' || value.releaseId.length === 0
    || !HASH.test(value.releaseManifestSha256) || !HASH.test(value.installationReceiptSha256)
    || !P2PKH.test(value.lockingBytecodeHex) || typeof value.valueSats !== 'string' || !DECIMAL.test(value.valueSats)
    || typeof value.dataHome !== 'string' || !path.isAbsolute(value.dataHome) || path.normalize(value.dataHome) !== value.dataHome) {
    fail('SOURCE_REGISTRY_INVALID', 'immutable transition binding is malformed');
  }
  return Object.freeze({
    outpoint: sourceOutpoint(value.outpoint, 'immutable transition binding.outpoint').text,
    dataHome: value.dataHome, evidenceSha256: requireHash(value.evidenceSha256, 'immutable transition binding.evidenceSha256'),
    installationReceiptSha256: value.installationReceiptSha256, leaseId: requireLease(value.leaseId, 'immutable transition binding.leaseId'),
    lockingBytecodeHex: value.lockingBytecodeHex, releaseId: value.releaseId,
    releaseManifestSha256: value.releaseManifestSha256, role: value.role,
    runId: requireLease(value.runId, 'immutable transition binding.runId'), valueSats: value.valueSats,
  });
}

export function v2BetaOperatorFanoutInputSetSha256(inputs) {
  return sha256(`shieldkit-v2-beta-operator-fanout-input-set-v1:${JSON.stringify([...inputs].sort((left, right) => left.localeCompare(right)))}`);
}

function registerSources({ operatorRoot, transactionId, normalized, role, transitionReason, now = nowMs }) {
  if (!HASH.test(transactionId) || !Array.isArray(normalized) || normalized.length === 0 || typeof now !== 'function') fail('SOURCE_REGISTRY_INVALID', 'source registration is malformed');
  if (!['fanout-performance', 'semantic'].includes(role)) fail('SOURCE_REGISTRY_INVALID', 'source registration role is malformed');
  if (new Set(normalized.map((entry) => entry.outpoint)).size !== normalized.length) fail('SOURCE_REGISTRY_INVALID', 'fanout source registration duplicates an outpoint');
  const opened = openRegistry({ operatorRoot }); const stamp = now();
  try {
    opened.database.exec('BEGIN IMMEDIATE');
    for (const source of normalized) {
      const existing = opened.database.prepare('SELECT outpoint FROM sources WHERE outpoint=? OR provenance_sha256=?').get(source.outpoint, source.provenanceSha256);
      if (existing !== undefined) {
        const prior = opened.database.prepare('SELECT outpoint,wallet_locking_bytecode_hex,value_sats,fanout_transaction_id,fanout_output_index,role FROM sources WHERE outpoint=?').get(source.outpoint);
        if (prior?.wallet_locking_bytecode_hex !== source.lockingBytecodeHex || prior.value_sats !== source.valueSats || prior.fanout_transaction_id !== transactionId || prior.fanout_output_index !== source.fanoutVout || prior.role !== role) fail('SOURCE_REGISTRY_DUPLICATE_SOURCE', 'source identity or immutable role conflicts with canonical registry');
        continue;
      }
      opened.database.prepare(`INSERT INTO sources(outpoint,provenance_sha256,wallet_locking_bytecode_hex,value_sats,fanout_transaction_id,fanout_output_index,role,state,release_id,release_manifest_sha256,data_home,installation_receipt_sha256,lease_id,run_id,evidence_sha256,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,?,'available',NULL,NULL,NULL,NULL,NULL,NULL,NULL,?,?)`).run(source.outpoint, source.provenanceSha256, source.lockingBytecodeHex, source.valueSats, transactionId, source.fanoutVout, role, stamp, stamp);
      opened.database.prepare(`INSERT INTO source_transitions(outpoint,from_state,to_state,reason,release_id,release_manifest_sha256,data_home,installation_receipt_sha256,lease_id,run_id,evidence_sha256,created_at_ms) VALUES(?,NULL,'available',?,NULL,NULL,NULL,NULL,NULL,NULL,NULL,?)`).run(source.outpoint, transitionReason, stamp);
    }
    opened.database.exec('COMMIT');
    return Object.freeze({ sourceCount: normalized.length });
  } catch (error) { try { opened.database.exec('ROLLBACK'); } catch {} throw error; } finally { close(opened); }
}

/** Register exactly the 20 outputs of an already exact-reconciled fanout. */
export function registerV2BetaOperatorFanoutSources({ operatorRoot, fanoutTransactionId, sources, now = nowMs } = {}) {
  if (!HASH.test(fanoutTransactionId) || !Array.isArray(sources) || sources.length !== 20 || typeof now !== 'function') fail('SOURCE_REGISTRY_INVALID', 'fanout must register exactly twenty performance sources');
  const normalized = sources.map((entry, index) => normalSource(entry, `fanout source ${index + 1}`));
  if (normalized.some((source) => source.fanoutTransactionId !== fanoutTransactionId)) fail('SOURCE_REGISTRY_INVALID', 'fanout source does not bind the reconciled transaction');
  return registerSources({ operatorRoot, transactionId: fanoutTransactionId, normalized, role: 'fanout-performance', transitionReason: 'fanout-reconciled', now });
}

/**
 * Record the one separately-funded semantic source before its evidence claim.
 * It is intentionally not a fanout recipient, so it can never be selected by
 * the exact-20 performance reservation flow. The caller supplies the already
 * attested source identity; the next semantic claim irreversibly consumes it.
 */
export function registerV2BetaOperatorSemanticSource({ operatorRoot, source, now = nowMs } = {}) {
  exact(source, ['lockingBytecodeHex', 'outpoint', 'valueSats'], 'semantic source');
  const parsed = sourceOutpoint(source.outpoint, 'semantic source.outpoint');
  const normalized = [normalSource({ ...source, outpoint: parsed.text, fanoutTransactionId: parsed.txid, fanoutVout: parsed.vout }, 'semantic source')];
  return registerSources({ operatorRoot, transactionId: parsed.txid, normalized, role: 'semantic', transitionReason: 'semantic-source-recorded', now });
}

function claimSources({ operatorRoot, claim, count, role, state, reason, now = nowMs }) {
  const normalized = normalClaim(claim, count, reason); const opened = openRegistry({ operatorRoot }); const stamp = now();
  try {
    opened.database.exec('BEGIN IMMEDIATE');
    const records = normalized.sources.map((item) => {
      const record = opened.database.prepare('SELECT * FROM sources WHERE outpoint=?').get(item.outpoint);
      if (record === undefined) fail('SOURCE_REGISTRY_SOURCE_UNAVAILABLE', 'requested source is not canonically available');
      if (record.role !== role) fail('SOURCE_REGISTRY_ROLE_CONFLICT', 'source immutable role is incompatible with this claim');
      // A durable reservation/journal can be resumed after a crash. It is
      // idempotent only for the byte-for-byte same claim; any changed lease,
      // run, release, receipt, home, or evidence remains a hard conflict.
      if (record.state === state
        && record.release_id === normalized.releaseId
        && record.release_manifest_sha256 === normalized.releaseManifestSha256
        && record.data_home === item.dataHome
        && record.installation_receipt_sha256 === item.installationReceiptSha256
        && record.lease_id === normalized.leaseId
        && record.run_id === normalized.runId
        && record.evidence_sha256 === normalized.evidenceSha256) return { ...record, item, resumed: true };
      if (record.state !== 'available') fail('SOURCE_REGISTRY_SOURCE_UNAVAILABLE', 'requested source is not canonically available');
      return { ...record, item };
    });
    for (const record of records) if (!record.resumed) transition(opened.database, record, state, reason, { releaseId: normalized.releaseId, releaseManifestSha256: normalized.releaseManifestSha256, dataHome: record.item.dataHome, installationReceiptSha256: record.item.installationReceiptSha256, leaseId: normalized.leaseId, runId: normalized.runId, evidenceSha256: normalized.evidenceSha256 }, stamp);
    opened.database.exec('COMMIT');
    return Object.freeze({ leaseId: normalized.leaseId, runId: normalized.runId, evidenceSha256: normalized.evidenceSha256, sourceCount: records.length, sources: Object.freeze(records.map((record) => Object.freeze({ outpoint: record.outpoint, provenanceSha256: record.provenance_sha256, valueSats: record.value_sats, walletLockingBytecodeHex: record.wallet_locking_bytecode_hex }))) });
  } catch (error) { try { opened.database.exec('ROLLBACK'); } catch {} if (String(error?.message ?? '').includes('sources.data_home')) fail('SOURCE_REGISTRY_DATA_HOME_CONFLICT', 'pool data home is already bound to another canonical source', { cause: error }); throw error; } finally { close(opened); }
}
export function claimV2BetaSemanticSource(value = {}) { return claimSources({ ...value, claim: value.claim, count: 1, role: 'semantic', state: 'semantic-claimed', reason: 'semantic-evidence-claim' }); }
export function reserveV2BetaPerformanceSourcesInRegistry(value = {}) { return claimSources({ ...value, claim: value.claim, count: 20, role: 'fanout-performance', state: 'performance-reserved', reason: 'performance-qualification-reservation' }); }

/** Record a durable send boundary or an operator-inspected exact outcome. No transition permits a resend. */
export function transitionV2BetaOperatorSources({ operatorRoot, outpoints, fromState, toState, reason, leaseId, runId, evidenceSha256, immutableBindings = undefined, now = nowMs } = {}) {
  if (!V2_BETA_OPERATOR_SOURCE_STATES.includes(fromState) || !V2_BETA_OPERATOR_SOURCE_STATES.includes(toState) || !['send-boundary', 'send-indeterminate', 'chain-reconciled', 'explicit-release'].includes(reason) || !Array.isArray(outpoints) || outpoints.length === 0 || typeof now !== 'function') fail('SOURCE_REGISTRY_INVALID', 'source transition request is malformed');
  const parsed = outpoints.map((entry) => sourceOutpoint(entry, 'outpoint').text); if (new Set(parsed).size !== parsed.length) fail('SOURCE_REGISTRY_INVALID', 'source transition has duplicates');
  let bindings;
  if (immutableBindings !== undefined) {
    if (!Array.isArray(immutableBindings) || immutableBindings.length !== parsed.length) fail('SOURCE_REGISTRY_INVALID', 'source transition immutable bindings are malformed');
    bindings = new Map(immutableBindings.map(normalImmutableTransitionBinding).map((binding) => [binding.outpoint, binding]));
    if (bindings.size !== parsed.length || parsed.some((outpoint) => !bindings.has(outpoint))) fail('SOURCE_REGISTRY_INVALID', 'source transition immutable bindings do not exactly cover its outpoints');
  }
  const permitted = new Set([
    'performance-reserved:send-attempted:send-boundary',
    'performance-reserved:explicitly-released:explicit-release',
    'send-attempted:indeterminate:send-indeterminate',
    'send-attempted:spent:chain-reconciled',
    'indeterminate:spent:chain-reconciled',
    'spent:reconciled:chain-reconciled',
  ]);
  if (!permitted.has(`${fromState}:${toState}:${reason}`)) fail('SOURCE_REGISTRY_INVALID', 'source state transition is not in the irreversible canonical lifecycle');
  const fields = { releaseId: null, releaseManifestSha256: null, dataHome: null, installationReceiptSha256: null, leaseId: leaseId === undefined ? null : requireLease(leaseId, 'leaseId'), runId: runId === undefined ? null : requireLease(runId, 'runId'), evidenceSha256: evidenceSha256 === undefined ? null : requireHash(evidenceSha256, 'evidenceSha256') };
  const opened = openRegistry({ operatorRoot }); const stamp = now();
  try { opened.database.exec('BEGIN IMMEDIATE'); for (const outpoint of parsed) { const source = opened.database.prepare('SELECT * FROM sources WHERE outpoint=?').get(outpoint); const binding = bindings?.get(outpoint); if (source === undefined || source.state !== fromState || (fields.leaseId !== null && source.lease_id !== fields.leaseId) || (fields.runId !== null && source.run_id !== fields.runId) || (fields.evidenceSha256 !== null && source.evidence_sha256 !== fields.evidenceSha256) || (binding !== undefined && (source.role !== binding.role || source.release_id !== binding.releaseId || source.release_manifest_sha256 !== binding.releaseManifestSha256 || source.data_home !== binding.dataHome || source.installation_receipt_sha256 !== binding.installationReceiptSha256 || source.wallet_locking_bytecode_hex !== binding.lockingBytecodeHex || source.value_sats !== binding.valueSats || source.lease_id !== binding.leaseId || source.run_id !== binding.runId || source.evidence_sha256 !== binding.evidenceSha256))) fail('SOURCE_REGISTRY_CAS_CONFLICT', 'source state or immutable binding differs from explicit transition'); transition(opened.database, source, toState, reason, { ...fields, releaseId: source.release_id, releaseManifestSha256: source.release_manifest_sha256, dataHome: source.data_home, installationReceiptSha256: source.installation_receipt_sha256, leaseId: source.lease_id, runId: source.run_id, evidenceSha256: source.evidence_sha256 }, stamp); } opened.database.exec('COMMIT'); return Object.freeze({ sourceCount: parsed.length, toState }); } catch (error) { try { opened.database.exec('ROLLBACK'); } catch {} throw error; } finally { close(opened); }
}

export function inspectV2BetaOperatorSourceRegistry({ operatorRoot } = {}) {
  const opened = openRegistry({ operatorRoot });
  try {
    const sources = opened.database.prepare('SELECT outpoint,provenance_sha256,wallet_locking_bytecode_hex,value_sats,fanout_transaction_id,fanout_output_index,role,state,release_id,release_manifest_sha256,data_home,installation_receipt_sha256,lease_id,run_id,evidence_sha256,created_at_ms,updated_at_ms FROM sources ORDER BY outpoint').all().map((row) => Object.freeze({ outpoint: row.outpoint, provenanceSha256: row.provenance_sha256, walletLockingBytecodeHex: row.wallet_locking_bytecode_hex, valueSats: row.value_sats, fanoutTransactionId: row.fanout_transaction_id, fanoutVout: row.fanout_output_index, role: row.role, state: row.state, releaseId: row.release_id, releaseManifestSha256: row.release_manifest_sha256, dataHome: row.data_home, installationReceiptSha256: row.installation_receipt_sha256, leaseId: row.lease_id, runId: row.run_id, evidenceSha256: row.evidence_sha256, createdAtUnixMs: row.created_at_ms, updatedAtUnixMs: row.updated_at_ms }));
    const transitions = opened.database.prepare('SELECT outpoint,from_state,to_state,reason,lease_id,run_id,evidence_sha256,created_at_ms FROM source_transitions ORDER BY transition_id').all().map((row) => Object.freeze({ outpoint: row.outpoint, fromState: row.from_state, toState: row.to_state, reason: row.reason, leaseId: row.lease_id, runId: row.run_id, evidenceSha256: row.evidence_sha256, createdAtUnixMs: row.created_at_ms }));
    const fanoutOperations = opened.database.prepare('SELECT run_id,transaction_id,raw_transaction_sha256,journal_sha256,input_count,input_set_sha256,state,created_at_ms,updated_at_ms FROM fanout_operations ORDER BY run_id').all().map((row) => Object.freeze({ runId: row.run_id, transactionId: row.transaction_id, rawTransactionSha256: row.raw_transaction_sha256, journalSha256: row.journal_sha256, inputCount: row.input_count, inputSetSha256: row.input_set_sha256, state: row.state, createdAtUnixMs: row.created_at_ms, updatedAtUnixMs: row.updated_at_ms }));
    const fanoutInputReservations = opened.database.prepare('SELECT outpoint,run_id,transaction_id,raw_transaction_sha256,state,created_at_ms,updated_at_ms FROM fanout_input_reservations ORDER BY outpoint').all().map((row) => Object.freeze({ outpoint: row.outpoint, runId: row.run_id, transactionId: row.transaction_id, rawTransactionSha256: row.raw_transaction_sha256, state: row.state, createdAtUnixMs: row.created_at_ms, updatedAtUnixMs: row.updated_at_ms }));
    return Object.freeze({ schema: V2_BETA_OPERATOR_SOURCE_REGISTRY_SCHEMA, sourceCount: sources.length, sources: Object.freeze(sources), transitions: Object.freeze(transitions), fanoutOperations: Object.freeze(fanoutOperations), fanoutInputReservations: Object.freeze(fanoutInputReservations) });
  } finally { close(opened); }
}

/**
 * Atomically reserve every fanout input and create its one operation record.
 * Registry sources are never eligible fanout inputs: their lifecycle already
 * belongs to a semantic/performance campaign and must not be silently spent.
 */
export function createV2BetaOperatorFanoutOperation({ operatorRoot, runId, transactionId, rawTransactionSha256, journalSha256, inputOutpoints, now = nowMs } = {}) {
  requireLease(runId, 'runId'); requireHash(transactionId, 'transactionId'); requireHash(rawTransactionSha256, 'rawTransactionSha256'); requireHash(journalSha256, 'journalSha256');
  if (!Array.isArray(inputOutpoints) || inputOutpoints.length < 2 || inputOutpoints.length > 512) fail('SOURCE_REGISTRY_INVALID', 'fanout input reservation requires 2..512 canonical outpoints');
  const inputs = inputOutpoints.map((entry) => sourceOutpoint(entry, 'fanout input outpoint').text);
  if (new Set(inputs).size !== inputs.length) fail('SOURCE_REGISTRY_INVALID', 'fanout input reservation duplicates an outpoint');
  const inputSetSha256 = v2BetaOperatorFanoutInputSetSha256(inputs);
  const opened = openRegistry({ operatorRoot }); const stamp = now();
  try {
    opened.database.exec('BEGIN IMMEDIATE');
    for (const outpoint of inputs) {
      if (opened.database.prepare('SELECT 1 FROM sources WHERE outpoint=?').get(outpoint) !== undefined) {
        fail('SOURCE_REGISTRY_FANOUT_INPUT_UNAVAILABLE', 'fanout input is already governed by the canonical source registry');
      }
      if (opened.database.prepare('SELECT 1 FROM fanout_input_reservations WHERE outpoint=?').get(outpoint) !== undefined) {
        fail('SOURCE_REGISTRY_FANOUT_INPUT_UNAVAILABLE', 'fanout input is already durably reserved by a fanout operation');
      }
    }
    opened.database.prepare(`INSERT INTO fanout_operations(run_id,transaction_id,raw_transaction_sha256,journal_sha256,input_count,input_set_sha256,state,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,'prepared',?,?)`).run(runId, transactionId, rawTransactionSha256, journalSha256, inputs.length, inputSetSha256, stamp, stamp);
    const insertInput = opened.database.prepare(`INSERT INTO fanout_input_reservations(outpoint,run_id,transaction_id,raw_transaction_sha256,state,created_at_ms,updated_at_ms) VALUES(?,?,?,?, 'prepared',?,?)`);
    for (const outpoint of inputs) insertInput.run(outpoint, runId, transactionId, rawTransactionSha256, stamp, stamp);
    opened.database.exec('COMMIT'); return Object.freeze({ runId, state: 'prepared', inputCount: inputs.length, inputSetSha256 });
  }
  catch (error) { try { opened.database.exec('ROLLBACK'); } catch {} if (error?.code?.startsWith('SQLITE_CONSTRAINT')) fail('SOURCE_REGISTRY_CAS_CONFLICT', 'fanout run or transaction is already registered', { cause: error }); throw error; } finally { close(opened); }
}

export function casV2BetaOperatorFanoutOperation({ operatorRoot, runId, transactionId, rawTransactionSha256, journalSha256, fromState, toState, now = nowMs } = {}) {
  requireLease(runId, 'runId'); requireHash(transactionId, 'transactionId'); requireHash(rawTransactionSha256, 'rawTransactionSha256'); requireHash(journalSha256, 'journalSha256');
  if (!['prepared','send-attempted','indeterminate','reconciled'].includes(fromState) || !['send-attempted','indeterminate','reconciled'].includes(toState)) fail('SOURCE_REGISTRY_INVALID', 'fanout state transition is invalid');
  const permitted = new Set([
    'prepared:send-attempted',
    'send-attempted:indeterminate',
    'send-attempted:reconciled',
    'indeterminate:reconciled',
  ]);
  if (!permitted.has(`${fromState}:${toState}`)) fail('SOURCE_REGISTRY_INVALID', 'fanout state transition is not in the irreversible lifecycle');
  const opened = openRegistry({ operatorRoot }); const stamp = now();
  try {
    opened.database.exec('BEGIN IMMEDIATE');
    const operation = opened.database.prepare(`SELECT input_count,input_set_sha256 FROM fanout_operations WHERE run_id=? AND transaction_id=? AND raw_transaction_sha256=? AND journal_sha256=? AND state=?`).get(runId, transactionId, rawTransactionSha256, journalSha256, fromState);
    if (operation === undefined || !Number.isSafeInteger(operation.input_count)
      || operation.input_count < 2 || operation.input_count > 512 || !HASH.test(operation.input_set_sha256)) {
      fail('SOURCE_REGISTRY_CAS_CONFLICT', 'fanout operation differs from explicit CAS precondition');
    }
    const reservations = opened.database.prepare(`SELECT outpoint FROM fanout_input_reservations WHERE run_id=? AND transaction_id=? AND raw_transaction_sha256=? AND state=? ORDER BY outpoint`).all(runId, transactionId, rawTransactionSha256, fromState).map((row) => row.outpoint);
    if (reservations.length !== operation.input_count || v2BetaOperatorFanoutInputSetSha256(reservations) !== operation.input_set_sha256) {
      fail('SOURCE_REGISTRY_CAS_CONFLICT', 'fanout input reservations differ from the exact canonical input set');
    }
    const result = opened.database.prepare(`UPDATE fanout_operations SET state=?,updated_at_ms=? WHERE run_id=? AND transaction_id=? AND raw_transaction_sha256=? AND journal_sha256=? AND state=?`).run(toState, stamp, runId, transactionId, rawTransactionSha256, journalSha256, fromState);
    if (result.changes !== 1) fail('SOURCE_REGISTRY_CAS_CONFLICT', 'fanout operation differs from explicit CAS precondition');
    const inputs = opened.database.prepare(`UPDATE fanout_input_reservations SET state=?,updated_at_ms=? WHERE run_id=? AND transaction_id=? AND raw_transaction_sha256=? AND state=?`).run(toState, stamp, runId, transactionId, rawTransactionSha256, fromState);
    if (inputs.changes !== operation.input_count) fail('SOURCE_REGISTRY_CAS_CONFLICT', 'fanout input reservations differ from exact operation lifecycle');
    opened.database.exec('COMMIT'); return Object.freeze({ runId, state: toState, inputCount: inputs.changes, inputSetSha256: operation.input_set_sha256 });
  } catch (error) { try { opened.database.exec('ROLLBACK'); } catch {} throw error; } finally { close(opened); }
}

export const createV2BetaOperatorSourceLeaseId = () => `lease-${randomUUID()}`;
