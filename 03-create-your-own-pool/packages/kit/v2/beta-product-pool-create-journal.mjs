/**
 * Durable single-writer state machine for one V2 beta pool creation.
 *
 * SQLite's BEGIN IMMEDIATE is the cross-process compare-and-swap boundary.
 * A process identity includes Linux /proc start ticks, preventing PID reuse
 * from being mistaken for the original owner. Once a send is attempted, a
 * recovered claimant is restricted to read-only reconciliation until exact
 * zero-conf evidence is observed.
 */
import { randomUUID } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
  readFileSync,
  realpathSync,
} from 'node:fs';
import {
  dirname,
  isAbsolute,
  parse,
  relative,
  resolve,
} from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export const V2_BETA_PRODUCT_POOL_CREATE_JOURNAL_SCHEMA =
  'shieldkit-v2-beta-product-pool-create-journal-v1';

const HEX_32 = /^[0-9a-f]{64}$/u;
const OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SIDE_CARS = Object.freeze(['-wal', '-shm', '-journal']);
const JOURNALS = new WeakSet();
const CLAIMS = new WeakMap();

const SCHEMA = `
CREATE TABLE IF NOT EXISTS pool_create_journal_metadata (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  schema_version INTEGER NOT NULL CHECK(schema_version=1)
) STRICT;
INSERT INTO pool_create_journal_metadata(singleton,schema_version)
VALUES(1,1) ON CONFLICT(singleton) DO NOTHING;
CREATE TABLE IF NOT EXISTS pool_create_operations (
  operation_id TEXT PRIMARY KEY,
  profile_id TEXT NOT NULL CHECK(length(profile_id)=64),
  instance_id TEXT NOT NULL CHECK(length(instance_id)=64),
  source_transaction_id TEXT NOT NULL CHECK(length(source_transaction_id)=64),
  bootstrap_raw_sha256 TEXT NOT NULL CHECK(length(bootstrap_raw_sha256)=64),
  funding_outpoint_transaction_id TEXT NOT NULL CHECK(length(funding_outpoint_transaction_id)=64),
  funding_outpoint_vout INTEGER NOT NULL CHECK(funding_outpoint_vout >= 0 AND funding_outpoint_vout <= 4294967295),
  funding_locking_bytecode_sha256 TEXT NOT NULL CHECK(length(funding_locking_bytecode_sha256)=64),
  state TEXT NOT NULL CHECK(state IN (
    'claimed-pre-send','send-attempted','accepted-zero-conf','committed'
  )),
  claim_token TEXT NOT NULL,
  owner_pid INTEGER NOT NULL CHECK(owner_pid >= 0),
  owner_start_ticks TEXT NOT NULL,
  claim_count INTEGER NOT NULL CHECK(claim_count >= 1),
  genesis_transaction_id TEXT CHECK(
    genesis_transaction_id IS NULL OR length(genesis_transaction_id)=64
  ),
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  CHECK(
    (state='claimed-pre-send' AND genesis_transaction_id IS NULL)
    OR
    (state IN ('send-attempted','accepted-zero-conf','committed')
      AND genesis_transaction_id IS NOT NULL)
  )
) STRICT;
`;

export class V2BetaProductPoolCreateJournalError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'V2BetaProductPoolCreateJournalError';
    this.code = code;
    this.recoverable = options?.recoverable === true;
  }
}

const fail = (code, message, options = undefined) => {
  throw new V2BetaProductPoolCreateJournalError(code, message, options);
};
const now = () => Date.now();

function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('POOL_CREATE_JOURNAL_INVALID', `${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])) {
    fail('POOL_CREATE_JOURNAL_INVALID', `${label} has missing or unknown fields`);
  }
  return value;
}

function identifier(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail('POOL_CREATE_JOURNAL_INVALID', `${label} must be lowercase 32-byte hex`);
  }
  return value;
}

function operationId(value) {
  if (typeof value !== 'string' || !OPERATION_ID.test(value)) {
    fail('POOL_CREATE_JOURNAL_INVALID', 'operationId is invalid');
  }
  return value;
}

function processStartTicks(pid) {
  if (process.platform !== 'linux' || !Number.isSafeInteger(pid) || pid < 1) return null;
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
    const close = stat.lastIndexOf(') ');
    if (close < 0) return null;
    // Fields after the command begin with field 3 (state); starttime is field
    // 22, therefore index 19 in this tail.
    const fields = stat.slice(close + 2).trim().split(/\s+/u);
    const ticks = fields[19];
    return typeof ticks === 'string' && /^[0-9]+$/u.test(ticks) ? ticks : null;
  } catch { return null; }
}

function productionOwner() {
  const startTicks = processStartTicks(process.pid);
  if (startTicks === null) {
    fail(
      'POOL_CREATE_JOURNAL_PROCESS_IDENTITY_UNAVAILABLE',
      'an exact process start identity is required for crash-safe pool creation',
    );
  }
  return Object.freeze({ pid: process.pid, startTicks });
}

function productionOwnerAlive(pid, startTicks) {
  return processStartTicks(pid) === startTicks;
}

function trustedDatabasePath(databasePath) {
  if (typeof databasePath !== 'string' || !isAbsolute(databasePath)
    || resolve(databasePath) !== databasePath) {
    fail('POOL_CREATE_JOURNAL_PATH_REJECTED', 'databasePath must be normalized and absolute');
  }
  const parent = dirname(databasePath);
  if (parent === parse(parent).root) {
    fail('POOL_CREATE_JOURNAL_PATH_REJECTED', 'journal requires a dedicated private parent');
  }
  const root = parse(parent).root;
  let current = root;
  for (const segment of relative(root, parent).split('/').filter(Boolean)) {
    current = resolve(current, segment);
    let stat;
    try { stat = lstatSync(current); }
    catch (error) {
      fail('POOL_CREATE_JOURNAL_PATH_REJECTED', 'journal parent ancestry must already exist', { cause: error });
    }
    if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(current) !== current) {
      fail('POOL_CREATE_JOURNAL_PATH_REJECTED', 'journal parent ancestry is not canonical');
    }
  }
  const parentStat = lstatSync(parent);
  if ((parentStat.mode & 0o777) !== 0o700
    || (typeof process.getuid === 'function' && parentStat.uid !== process.getuid())) {
    fail('POOL_CREATE_JOURNAL_PATH_REJECTED', 'journal parent must be owner-controlled mode 0700');
  }
  for (const filename of [databasePath, ...SIDE_CARS.map((suffix) => `${databasePath}${suffix}`)]) {
    if (!existsSync(filename)) continue;
    const stat = lstatSync(filename);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
      fail('POOL_CREATE_JOURNAL_PATH_REJECTED', 'journal database and sidecars must be private regular files');
    }
    chmodSync(filename, 0o600);
  }
  return databasePath;
}

function binding(value) {
  exact(value, [
    'bootstrapRawSha256', 'fundingLockingBytecodeSha256',
    'fundingOutpointTransactionId', 'fundingOutpointVout', 'instanceId',
    'operationId', 'profileId', 'sourceTransactionId',
  ], 'pool-create binding');
  return Object.freeze({
    operationId: operationId(value.operationId),
    profileId: identifier(value.profileId, 'profileId'),
    instanceId: identifier(value.instanceId, 'instanceId'),
    sourceTransactionId: identifier(value.sourceTransactionId, 'sourceTransactionId'),
    bootstrapRawSha256: identifier(value.bootstrapRawSha256, 'bootstrapRawSha256'),
    fundingOutpointTransactionId: identifier(value.fundingOutpointTransactionId, 'fundingOutpointTransactionId'),
    fundingOutpointVout: Number.isSafeInteger(value.fundingOutpointVout)
      && value.fundingOutpointVout >= 0 && value.fundingOutpointVout <= 0xffff_ffff
      ? value.fundingOutpointVout : fail('POOL_CREATE_JOURNAL_INVALID', 'fundingOutpointVout must be uint32'),
    fundingLockingBytecodeSha256: identifier(value.fundingLockingBytecodeSha256, 'fundingLockingBytecodeSha256'),
  });
}

function publicRecord(row) {
  return Object.freeze({
    schema: V2_BETA_PRODUCT_POOL_CREATE_JOURNAL_SCHEMA,
    operationId: row.operation_id,
    profileId: row.profile_id,
    instanceId: row.instance_id,
    sourceTransactionId: row.source_transaction_id,
    bootstrapRawSha256: row.bootstrap_raw_sha256,
    fundingOutpointTransactionId: row.funding_outpoint_transaction_id,
    fundingOutpointVout: row.funding_outpoint_vout,
    fundingLockingBytecodeSha256: row.funding_locking_bytecode_sha256,
    state: row.state,
    claimCount: row.claim_count,
    genesisTransactionId: row.genesis_transaction_id,
  });
}

function sameOwner(row, owner) {
  return row.owner_pid === owner.pid && row.owner_start_ticks === owner.startTicks;
}

function sameBinding(row, expected) {
  return row.operation_id === expected.operationId
    && row.profile_id === expected.profileId
    && row.instance_id === expected.instanceId
    && row.source_transaction_id === expected.sourceTransactionId
    && row.bootstrap_raw_sha256 === expected.bootstrapRawSha256
    && row.funding_outpoint_transaction_id === expected.fundingOutpointTransactionId
    && row.funding_outpoint_vout === expected.fundingOutpointVout
    && row.funding_locking_bytecode_sha256 === expected.fundingLockingBytecodeSha256;
}

function issueClaim(journal, row, token, mode) {
  const claim = Object.freeze({
    schema: V2_BETA_PRODUCT_POOL_CREATE_JOURNAL_SCHEMA,
    operationId: row.operation_id,
    mode,
    record: publicRecord(row),
  });
  CLAIMS.set(claim, Object.freeze({ journal, token, operationId: row.operation_id }));
  return claim;
}

function claimContext(journal, claim) {
  const context = CLAIMS.get(claim);
  if (context === undefined || context.journal !== journal) {
    fail('POOL_CREATE_JOURNAL_CLAIM_REJECTED', 'a live claim from this exact journal is required');
  }
  return context;
}

class V2BetaProductPoolCreateJournal {
  #db;
  #owner;
  #ownerAlive;
  #closed = false;

  constructor({ databasePath, owner, ownerAlive }) {
    const filename = trustedDatabasePath(databasePath);
    this.#owner = owner;
    this.#ownerAlive = ownerAlive;
    this.#db = new DatabaseSync(filename);
    try {
      this.#db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;');
      for (const candidate of [filename, ...SIDE_CARS.map((suffix) => `${filename}${suffix}`)]) {
        if (existsSync(candidate)) chmodSync(candidate, 0o600);
      }
      this.#db.exec(SCHEMA);
      const integrity = this.#db.prepare('PRAGMA integrity_check').all();
      if (integrity.length !== 1 || integrity[0].integrity_check !== 'ok') {
        fail('POOL_CREATE_JOURNAL_INTEGRITY_REJECTED', 'SQLite integrity_check did not return ok');
      }
      JOURNALS.add(this);
    } catch (error) {
      try { this.#db.close(); } catch { /* best effort */ }
      throw error;
    }
  }

  #assertOpen() {
    if (this.#closed) fail('POOL_CREATE_JOURNAL_CLOSED', 'pool-create journal is closed');
  }

  claimOrRecover(value) {
    this.#assertOpen();
    const expected = binding(value);
    const token = randomUUID();
    const stamp = now();
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      let row = this.#db.prepare('SELECT * FROM pool_create_operations WHERE operation_id=?').get(expected.operationId);
      if (row === undefined) {
        this.#db.prepare(`INSERT INTO pool_create_operations(
          operation_id,profile_id,instance_id,source_transaction_id,bootstrap_raw_sha256,
          funding_outpoint_transaction_id,funding_outpoint_vout,funding_locking_bytecode_sha256,
          state,claim_token,owner_pid,owner_start_ticks,claim_count,genesis_transaction_id,
          created_at_ms,updated_at_ms
        ) VALUES(?,?,?,?,?,?,?,?,'claimed-pre-send',?,?,?,?,NULL,?,?)`).run(
          expected.operationId, expected.profileId, expected.instanceId,
          expected.sourceTransactionId, expected.bootstrapRawSha256,
          expected.fundingOutpointTransactionId, expected.fundingOutpointVout,
          expected.fundingLockingBytecodeSha256,
          token, this.#owner.pid, this.#owner.startTicks, 1, stamp, stamp,
        );
        row = this.#db.prepare('SELECT * FROM pool_create_operations WHERE operation_id=?').get(expected.operationId);
        this.#db.exec('COMMIT');
        return issueClaim(this, row, token, 'send-allowed');
      }
      if (!sameBinding(row, expected)) {
        fail('POOL_CREATE_JOURNAL_BINDING_REUSE', 'operationId is already bound to different pool-create bytes');
      }
      if (row.state === 'committed') {
        this.#db.exec('COMMIT');
        return Object.freeze({
          schema: V2_BETA_PRODUCT_POOL_CREATE_JOURNAL_SCHEMA,
          operationId: row.operation_id,
          mode: 'completed',
          record: publicRecord(row),
        });
      }
      if (sameOwner(row, this.#owner) || this.#ownerAlive(row.owner_pid, row.owner_start_ticks)) {
        fail('POOL_CREATE_JOURNAL_BUSY', 'another live process owns this exact pool creation', { recoverable: true });
      }
      this.#db.prepare(`UPDATE pool_create_operations
        SET claim_token=?,owner_pid=?,owner_start_ticks=?,claim_count=claim_count+1,updated_at_ms=?
        WHERE operation_id=?`).run(token, this.#owner.pid, this.#owner.startTicks, stamp, expected.operationId);
      row = this.#db.prepare('SELECT * FROM pool_create_operations WHERE operation_id=?').get(expected.operationId);
      this.#db.exec('COMMIT');
      const mode = row.state === 'claimed-pre-send'
        ? 'send-allowed'
        : row.state === 'send-attempted' ? 'reconcile-only' : 'commit-only';
      return issueClaim(this, row, token, mode);
    } catch (error) {
      try { this.#db.exec('ROLLBACK'); } catch { /* already committed */ }
      throw error;
    }
  }

  #transition(claim, expectedStates, nextState, genesisTransactionId = undefined) {
    this.#assertOpen();
    const context = claimContext(this, claim);
    const genesis = genesisTransactionId === undefined
      ? undefined : identifier(genesisTransactionId, 'genesisTransactionId');
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.#db.prepare('SELECT * FROM pool_create_operations WHERE operation_id=?').get(context.operationId);
      if (row === undefined || row.claim_token !== context.token
        || !sameOwner(row, this.#owner)) {
        fail('POOL_CREATE_JOURNAL_CLAIM_LOST', 'pool-create claim is no longer current');
      }
      if (!expectedStates.includes(row.state)) {
        fail('POOL_CREATE_JOURNAL_STATE_REJECTED', `cannot transition pool creation from ${row.state} to ${nextState}`);
      }
      if (genesis !== undefined && row.genesis_transaction_id !== null
        && row.genesis_transaction_id !== genesis) {
        fail('POOL_CREATE_JOURNAL_BINDING_REUSE', 'genesis transaction differs from the claimed operation');
      }
      this.#db.prepare(`UPDATE pool_create_operations
        SET state=?,genesis_transaction_id=COALESCE(genesis_transaction_id,?),updated_at_ms=?
        WHERE operation_id=?`).run(nextState, genesis ?? null, now(), context.operationId);
      const updated = this.#db.prepare('SELECT * FROM pool_create_operations WHERE operation_id=?').get(context.operationId);
      this.#db.exec('COMMIT');
      return publicRecord(updated);
    } catch (error) {
      try { this.#db.exec('ROLLBACK'); } catch { /* already committed */ }
      throw error;
    }
  }

  markSendAttempt({ claim, genesisTransactionId } = {}) {
    exact({ claim, genesisTransactionId }, ['claim', 'genesisTransactionId'], 'send-attempt transition');
    if (claim?.mode !== 'send-allowed') {
      fail('POOL_CREATE_JOURNAL_RECONCILE_ONLY', 'recovered post-send claims cannot authorize another send');
    }
    return this.#transition(claim, ['claimed-pre-send'], 'send-attempted', genesisTransactionId);
  }

  markAccepted({ claim, genesisTransactionId } = {}) {
    exact({ claim, genesisTransactionId }, ['claim', 'genesisTransactionId'], 'accepted transition');
    return this.#transition(claim, ['send-attempted', 'accepted-zero-conf'], 'accepted-zero-conf', genesisTransactionId);
  }

  markCommitted({ claim, genesisTransactionId } = {}) {
    exact({ claim, genesisTransactionId }, ['claim', 'genesisTransactionId'], 'committed transition');
    return this.#transition(claim, ['accepted-zero-conf', 'committed'], 'committed', genesisTransactionId);
  }

  releaseSafePreSend({ claim } = {}) {
    exact({ claim }, ['claim'], 'safe pre-send release');
    this.#assertOpen();
    const context = claimContext(this, claim);
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.#db.prepare('SELECT * FROM pool_create_operations WHERE operation_id=?').get(context.operationId);
      if (row === undefined || row.claim_token !== context.token || !sameOwner(row, this.#owner)
        || row.state !== 'claimed-pre-send') {
        fail('POOL_CREATE_JOURNAL_NOT_PRE_SEND', 'only the current definitely pre-send claim may be released');
      }
      this.#db.prepare(`UPDATE pool_create_operations
        SET owner_pid=0,owner_start_ticks='released',updated_at_ms=? WHERE operation_id=?`).run(now(), context.operationId);
      const released = this.#db.prepare('SELECT * FROM pool_create_operations WHERE operation_id=?').get(context.operationId);
      this.#db.exec('COMMIT');
      return publicRecord(released);
    } catch (error) {
      try { this.#db.exec('ROLLBACK'); } catch { /* already committed */ }
      throw error;
    }
  }

  record(operation) {
    this.#assertOpen();
    const row = this.#db.prepare('SELECT * FROM pool_create_operations WHERE operation_id=?').get(operationId(operation));
    return row === undefined ? null : publicRecord(row);
  }

  close() {
    if (!this.#closed) { this.#db.close(); this.#closed = true; }
  }
}

export function openV2BetaProductPoolCreateJournal({ databasePath } = {}) {
  return new V2BetaProductPoolCreateJournal({
    databasePath,
    owner: productionOwner(),
    ownerAlive: productionOwnerAlive,
  });
}

/** Test-only deterministic process-identity seam. */
export function openV2BetaProductPoolCreateJournalForTest(
  { databasePath } = {},
  { owner, ownerAlive } = {},
) {
  exact(owner, ['pid', 'startTicks'], 'test owner');
  if (!Number.isSafeInteger(owner.pid) || owner.pid < 1
    || typeof owner.startTicks !== 'string' || !/^[0-9]+$/u.test(owner.startTicks)
    || typeof ownerAlive !== 'function') {
    fail('POOL_CREATE_JOURNAL_INVALID', 'test process identity seam is invalid');
  }
  return new V2BetaProductPoolCreateJournal({ databasePath, owner: Object.freeze({ ...owner }), ownerAlive });
}

export function assertV2BetaProductPoolCreateJournal(value) {
  if (!JOURNALS.has(value) || typeof value.claimOrRecover !== 'function'
    || typeof value.markSendAttempt !== 'function'
    || typeof value.markAccepted !== 'function'
    || typeof value.markCommitted !== 'function') {
    fail('POOL_CREATE_JOURNAL_CAPABILITY_REQUIRED', 'a branded pool-create journal is required');
  }
  return value;
}
