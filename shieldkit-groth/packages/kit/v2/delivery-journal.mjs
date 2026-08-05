import { randomUUID } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  lstatSync,
  mkdirSync,
  openSync,
} from 'node:fs';
import {
  dirname,
  isAbsolute,
  join,
  parse,
  relative,
  resolve,
} from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const HEX_32 = /^[0-9a-f]{64}$/;
const OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ATTEMPT_TOKEN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const OBSERVATION_KINDS = new Set([
  'authenticated-transaction-read',
  'rpc-accepted',
]);
const DELIVERY_JOURNAL_BRAND = Symbol('V2DeliveryJournal');

export const V2_DELIVERY_JOURNAL_CRASH_STAGES = Object.freeze([
  'delivery.claim-or-create.after_insert',
  'delivery.recovery-claim.after_update',
  'delivery.submitted.after_update',
  'delivery.indeterminate.after_update',
  'delivery.observed.after_update',
  'delivery.locally-reconciled.after_update',
]);

const SCHEMA = `
CREATE TABLE IF NOT EXISTS delivery_journal_metadata (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  schema_version INTEGER NOT NULL CHECK(schema_version=3)
) STRICT;
INSERT INTO delivery_journal_metadata(singleton,schema_version)
VALUES(1,3) ON CONFLICT(singleton) DO NOTHING;
CREATE TABLE IF NOT EXISTS delivery_records (
  operation_id TEXT PRIMARY KEY,
  txid TEXT NOT NULL UNIQUE CHECK(length(txid)=64),
  metadata_hash TEXT NOT NULL CHECK(length(metadata_hash)=64),
  evidence_hash TEXT NOT NULL CHECK(length(evidence_hash)=64),
  carrier_count INTEGER NOT NULL CHECK(carrier_count BETWEEN 1 AND 255),
  role_layout_hash TEXT NOT NULL CHECK(length(role_layout_hash)=64),
  state TEXT NOT NULL CHECK(
    state IN ('attempted','submitted','locally_reconciled','indeterminate')
  ),
  attempt_token TEXT NOT NULL,
  attempt_count INTEGER NOT NULL CHECK(attempt_count >= 1),
  reason TEXT,
  submission_kind TEXT CHECK(
    submission_kind IN (
      'authenticated-transaction-read',
      'rpc-accepted'
    )
  ),
  observed_raw_sha256 TEXT CHECK(
    observed_raw_sha256 IS NULL OR length(observed_raw_sha256)=64
  ),
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  attempted_at_ms INTEGER NOT NULL,
  submitted_at_ms INTEGER,
  locally_reconciled_at_ms INTEGER,
  CHECK(
    (
      state IN ('submitted','locally_reconciled')
      AND submitted_at_ms IS NOT NULL
      AND submission_kind IS NOT NULL
      AND observed_raw_sha256 IS NOT NULL
    )
    OR (
      state IN ('attempted','indeterminate')
      AND submitted_at_ms IS NULL
      AND submission_kind IS NULL
      AND observed_raw_sha256 IS NULL
    )
  ),
  CHECK(
    (state='locally_reconciled' AND locally_reconciled_at_ms IS NOT NULL)
    OR
    (state!='locally_reconciled' AND locally_reconciled_at_ms IS NULL)
  ),
  CHECK(
    (state='indeterminate' AND reason IS NOT NULL)
    OR
    (state!='indeterminate' AND reason IS NULL)
  )
) STRICT;
CREATE TABLE IF NOT EXISTS safe_pre_send_abort_markers (
  operation_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('deposit','withdrawal')),
  reason TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL
) STRICT;
`;

export class V2DeliveryJournalError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'V2DeliveryJournalError';
    this.code = code;
  }
}

/**
 * Test-only deterministic interruption at a point before the SQLite
 * transaction commits. The public constructor option is deliberately narrow:
 * callers cannot inject arbitrary SQL or alter the persisted record.
 */
export class V2DeliveryJournalCrash extends Error {
  constructor(stage) {
    super(`injected V2 delivery journal crash at ${stage}`);
    this.name = 'V2DeliveryJournalCrash';
    this.stage = stage;
  }
}

const fail = (code, message) => {
  throw new V2DeliveryJournalError(code, message);
};

function crashStage(value) {
  if (value === null) return null;
  if (
    typeof value !== 'string'
    || !V2_DELIVERY_JOURNAL_CRASH_STAGES.includes(value)
  ) {
    fail(
      'INVALID_CRASH_STAGE',
      'crashAt must be null or a supported delivery journal crash stage',
    );
  }
  return value;
}

function crash(requested, stage) {
  if (requested === stage) throw new V2DeliveryJournalCrash(stage);
}

function plain(value, label) {
  if (
    value === null ||
    Array.isArray(value) ||
    typeof value !== 'object' ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('INVALID_DELIVERY_RECORD', `${label} must be a plain object`);
  }
  return value;
}

function exact(value, keys, label) {
  plain(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    fail(
      'INVALID_DELIVERY_RECORD',
      `${label} has missing or unknown fields`,
    );
  }
  return value;
}

function operationId(value) {
  if (typeof value !== 'string' || !OPERATION_ID.test(value)) {
    fail('INVALID_DELIVERY_RECORD', 'operationId is invalid');
  }
  return value;
}

function hash(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail(
      'INVALID_DELIVERY_RECORD',
      `${label} must be lowercase 32-byte hex`,
    );
  }
  return value;
}

function token(value) {
  if (typeof value !== 'string' || !ATTEMPT_TOKEN.test(value)) {
    fail('INVALID_DELIVERY_RECORD', 'attemptToken is invalid');
  }
  return value;
}

function carrierCount(value, label) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 255) {
    fail(
      'INVALID_DELIVERY_RECORD',
      `${label} must be an integer from 1 through 255`,
    );
  }
  return value;
}

function reason(value) {
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > 256 ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    fail(
      'INVALID_DELIVERY_RECORD',
      'indeterminate reason must be 1 to 256 printable characters',
    );
  }
  return value;
}

function observationKind(value) {
  if (!OBSERVATION_KINDS.has(value)) {
    fail(
      'INVALID_DELIVERY_RECORD',
      'observationKind is not an authenticated delivery observation',
    );
  }
  return value;
}

function normalizeIdentity(value, label) {
  exact(
    value,
    [
      'carrierCount',
      'evidenceHash',
      'metadataHash',
      'operationId',
      'roleLayoutHash',
      'txid',
    ],
    label,
  );
  return Object.freeze({
    operationId: operationId(value.operationId),
    txid: hash(value.txid, `${label}.txid`),
    metadataHash: hash(value.metadataHash, `${label}.metadataHash`),
    evidenceHash: hash(value.evidenceHash, `${label}.evidenceHash`),
    carrierCount: carrierCount(value.carrierCount, `${label}.carrierCount`),
    roleLayoutHash: hash(
      value.roleLayoutHash,
      `${label}.roleLayoutHash`,
    ),
  });
}

function ensureTrustedParent(databasePath) {
  if (typeof databasePath !== 'string' || databasePath.length === 0) {
    fail('UNSAFE_JOURNAL_PATH', 'database path must be a nonempty string');
  }
  const absolute = isAbsolute(databasePath)
    ? databasePath
    : resolve(databasePath);
  const parent = dirname(absolute);
  const root = parse(parent).root;
  if (parent === root) {
    fail(
      'UNSAFE_JOURNAL_PATH',
      'database must be placed in a dedicated 0700 parent directory',
    );
  }
  const segments = relative(root, parent).split('/').filter(Boolean);
  let createdParent = false;
  let current = root;
  for (const [index, segment] of segments.entries()) {
    const next = join(current, segment);
    try {
      const stat = lstatSync(next);
      if (stat.isSymbolicLink() || !stat.isDirectory()) {
        fail(
          'UNSAFE_JOURNAL_PATH',
          'database parent traversal contains a symlink or non-directory',
        );
      }
    } catch (error) {
      if (!(error && error.code === 'ENOENT')) throw error;
      if (index !== segments.length - 1) {
        fail(
          'UNSAFE_JOURNAL_PATH',
          'database parent ancestor does not exist',
        );
      }
      mkdirSync(next, { mode: 0o700 });
      createdParent = true;
      const stat = lstatSync(next);
      if (stat.isSymbolicLink() || !stat.isDirectory()) {
        fail(
          'UNSAFE_JOURNAL_PATH',
          'database parent creation was replaced',
        );
      }
    }
    current = next;
  }
  if (createdParent) chmodSync(parent, 0o700);
  const parentStat = lstatSync(parent);
  if (
    parentStat.isSymbolicLink() ||
    !parentStat.isDirectory() ||
    (parentStat.mode & 0o777) !== 0o700
  ) {
    fail(
      'UNSAFE_JOURNAL_PATH',
      'database parent must be a real 0700 directory',
    );
  }
  if (
    typeof process.getuid === 'function' &&
    parentStat.uid !== process.getuid()
  ) {
    fail(
      'UNSAFE_JOURNAL_PATH',
      'database parent must be owned by the effective UID',
    );
  }
  return absolute;
}

function assertRegular(path, label) {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile()) {
    fail(
      'UNSAFE_JOURNAL_PATH',
      `${label} must be a non-symlink regular file`,
    );
  }
  if (
    typeof process.getuid === 'function' &&
    stat.uid !== process.getuid()
  ) {
    fail(
      'UNSAFE_JOURNAL_PATH',
      `${label} must be owned by the effective UID`,
    );
  }
  return stat;
}

function createCheckedDatabase(path) {
  try {
    assertRegular(path, 'existing database');
  } catch (error) {
    if (!(error && error.code === 'ENOENT')) throw error;
    try {
      closeSync(openSync(path, 'wx', 0o600));
    } catch (openError) {
      if (!(openError && openError.code === 'EEXIST')) throw openError;
      assertRegular(path, 'existing database');
    }
  }
  chmodSync(path, 0o600);
  if ((assertRegular(path, 'database').mode & 0o777) !== 0o600) {
    fail('UNSAFE_JOURNAL_PATH', 'database mode must be 0600');
  }
}

function secureSidecars(path) {
  for (const candidate of [path, `${path}-wal`, `${path}-shm`]) {
    try {
      assertRegular(candidate, 'database sidecar');
      chmodSync(candidate, 0o600);
      if ((assertRegular(candidate, 'database sidecar').mode & 0o777) !== 0o600) {
        fail('UNSAFE_JOURNAL_PATH', 'database sidecar mode must be 0600');
      }
    } catch (error) {
      if (!(error && error.code === 'ENOENT')) throw error;
    }
  }
}

function normalizeRow(row) {
  if (row === undefined) return null;
  return Object.freeze({
    operationId: row.operation_id,
    txid: row.txid,
    metadataHash: row.metadata_hash,
    evidenceHash: row.evidence_hash,
    carrierCount: row.carrier_count,
    roleLayoutHash: row.role_layout_hash,
    state: row.state,
    attemptToken: row.attempt_token,
    attemptCount: row.attempt_count,
    reason: row.reason,
    submissionKind: row.submission_kind,
    observedRawSha256: row.observed_raw_sha256,
    createdAtMs: row.created_at_ms,
    updatedAtMs: row.updated_at_ms,
    attemptedAtMs: row.attempted_at_ms,
    submittedAtMs: row.submitted_at_ms,
    locallyReconciledAtMs: row.locally_reconciled_at_ms,
  });
}

function assertSameIdentity(row, identity) {
  if (
    row.operation_id !== identity.operationId ||
    row.txid !== identity.txid ||
    row.metadata_hash !== identity.metadataHash ||
    row.evidence_hash !== identity.evidenceHash ||
    row.carrier_count !== identity.carrierCount ||
    row.role_layout_hash !== identity.roleLayoutHash
  ) {
    fail(
      'DIVERGENT_DELIVERY_RECORD',
      'delivery operation or transaction identity diverges from the journal',
    );
  }
}

export class V2DeliveryJournal {
  #db;
  #path;
  #crashAt;

  constructor(path, { crashAt = null } = {}) {
    this.#path = ensureTrustedParent(path);
    this.#crashAt = crashStage(crashAt);
    createCheckedDatabase(this.#path);
    this.#db = new DatabaseSync(this.#path);
    this.#db.exec(
      'PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;',
    );
    this.#db.exec(SCHEMA);
    const metadata = this.#db
      .prepare(
        'SELECT schema_version FROM delivery_journal_metadata WHERE singleton=1',
      )
      .get();
    if (metadata?.schema_version !== 3) {
      this.#db.close();
      this.#db = null;
      fail(
        'DELIVERY_SCHEMA_MISMATCH',
        'delivery journal schema version is unsupported',
      );
    }
    this.#db.exec('PRAGMA user_version=3');
    secureSidecars(this.#path);
    Object.defineProperty(this, DELIVERY_JOURNAL_BRAND, { value: true });
  }

  get path() {
    return this.#path;
  }

  #open() {
    if (!this.#db) {
      fail('DELIVERY_JOURNAL_CLOSED', 'delivery journal is closed');
    }
    return this.#db;
  }

  #transaction(callback) {
    const db = this.#open();
    db.exec('BEGIN IMMEDIATE');
    try {
      const value = callback(db);
      db.exec('COMMIT');
      secureSidecars(this.#path);
      return value;
    } catch (error) {
      try {
        db.exec('ROLLBACK');
      } catch {}
      secureSidecars(this.#path);
      throw error;
    }
  }

  record(requestedOperationId) {
    const id = operationId(requestedOperationId);
    return normalizeRow(
      this.#open()
        .prepare(
          'SELECT * FROM delivery_records WHERE operation_id=?',
        )
        .get(id),
    );
  }

  markSafePreSendAbort(value) {
    exact(value, ['kind', 'operationId', 'reason'], 'markSafePreSendAbort');
    const id = operationId(value.operationId);
    if (!['deposit', 'withdrawal'].includes(value.kind)) fail('INVALID_DELIVERY_RECORD', 'safe pre-send abort kind is invalid');
    const why = reason(value.reason);
    return this.#transaction((db) => {
      if (db.prepare('SELECT 1 FROM delivery_records WHERE operation_id=?').get(id)) {
        fail('DELIVERY_STATE_MISMATCH', 'an operation with a delivery claim cannot become a safe pre-send abort');
      }
      const prior = db.prepare('SELECT * FROM safe_pre_send_abort_markers WHERE operation_id=?').get(id);
      if (prior) {
        if (prior.kind !== value.kind || prior.reason !== why) fail('DIVERGENT_DELIVERY_RECORD', 'safe pre-send abort marker differs from its prior value');
        return Object.freeze({ operationId: id, kind: prior.kind, reason: prior.reason });
      }
      db.prepare('INSERT INTO safe_pre_send_abort_markers VALUES(?,?,?,?)').run(id, value.kind, why, Date.now());
      return Object.freeze({ operationId: id, kind: value.kind, reason: why });
    });
  }

  safePreSendAbortMarker(requestedOperationId) {
    const id = operationId(requestedOperationId);
    const row = this.#open().prepare('SELECT * FROM safe_pre_send_abort_markers WHERE operation_id=?').get(id);
    return row === undefined ? null : Object.freeze({ operationId: id, kind: row.kind, reason: row.reason });
  }

  claimOrCreate(value) {
    const identity = normalizeIdentity(value, 'claimOrCreate');
    return this.#transaction((db) => {
      if (db.prepare('SELECT 1 FROM safe_pre_send_abort_markers WHERE operation_id=?').get(identity.operationId)) {
        fail('DELIVERY_STATE_MISMATCH', 'a safe pre-send abort marker permanently forbids a send claim');
      }
      const byOperation = db
        .prepare(
          'SELECT * FROM delivery_records WHERE operation_id=?',
        )
        .get(identity.operationId);
      if (byOperation !== undefined) {
        assertSameIdentity(byOperation, identity);
        fail(
          'SEND_ALREADY_CLAIMED',
          `delivery state ${byOperation.state} cannot claim another send`,
        );
      }
      const byTransaction = db
        .prepare('SELECT * FROM delivery_records WHERE txid=?')
        .get(identity.txid);
      if (byTransaction !== undefined) {
        fail(
          'DIVERGENT_DELIVERY_RECORD',
          'transaction is already assigned to another operation',
        );
      }
      const now = Date.now();
      const attemptToken = randomUUID();
      db.prepare(
        `INSERT INTO delivery_records(
          operation_id,txid,metadata_hash,evidence_hash,
          carrier_count,role_layout_hash,state,attempt_token,attempt_count,
          created_at_ms,updated_at_ms,attempted_at_ms
        ) VALUES(?,?,?,?,?,?,'attempted',?,1,?,?,?)`,
      ).run(
        identity.operationId,
        identity.txid,
        identity.metadataHash,
        identity.evidenceHash,
        identity.carrierCount,
        identity.roleLayoutHash,
        attemptToken,
        now,
        now,
        now,
      );
      crash(this.#crashAt, 'delivery.claim-or-create.after_insert');
      return normalizeRow(
        db
          .prepare(
            'SELECT * FROM delivery_records WHERE operation_id=?',
          )
          .get(identity.operationId),
      );
    });
  }

  claimExactResubmission(value) {
    exact(
      value,
      ['identity', 'priorAttemptToken'],
      'claimExactResubmission',
    );
    const identity = normalizeIdentity(
      value.identity,
      'claimExactResubmission.identity',
    );
    const priorAttemptToken = token(value.priorAttemptToken);
    return this.#transaction((db) => {
      const row = db
        .prepare(
          'SELECT * FROM delivery_records WHERE operation_id=?',
        )
        .get(identity.operationId);
      if (row === undefined) {
        fail(
          'DELIVERY_NOT_CLAIMED',
          'delivery operation must have an unresolved prior claim',
        );
      }
      assertSameIdentity(row, identity);
      if (
        !['attempted', 'indeterminate'].includes(row.state)
        || row.attempt_token !== priorAttemptToken
      ) {
        fail(
          'DELIVERY_STATE_MISMATCH',
          `delivery state ${row.state} cannot claim an exact-byte recovery send`,
        );
      }
      const attemptToken = randomUUID();
      const now = Date.now();
      const changed = db
        .prepare(
          `UPDATE delivery_records
           SET state='attempted',attempt_token=?,
               attempt_count=attempt_count+1,attempted_at_ms=?,
               updated_at_ms=?,reason=NULL
           WHERE operation_id=? AND state IN ('attempted','indeterminate')
             AND attempt_token=?`,
        )
        .run(
          attemptToken,
          now,
          now,
          identity.operationId,
          priorAttemptToken,
        );
      if (changed.changes !== 1) {
        fail(
          'DELIVERY_STATE_MISMATCH',
          'another process resolved or changed this delivery claim',
        );
      }
      crash(this.#crashAt, 'delivery.recovery-claim.after_update');
      return normalizeRow(
        db
          .prepare(
            'SELECT * FROM delivery_records WHERE operation_id=?',
          )
          .get(identity.operationId),
      );
    });
  }

  markSubmitted(value) {
    exact(
      value,
      [
        'attemptToken',
        'operationId',
        'rawTransactionSha256',
        'txid',
      ],
      'markSubmitted',
    );
    const id = operationId(value.operationId);
    const txid = hash(value.txid, 'markSubmitted.txid');
    const rawTransactionSha256 = hash(
      value.rawTransactionSha256,
      'markSubmitted.rawTransactionSha256',
    );
    const attemptToken = token(value.attemptToken);
    return this.#transaction((db) => {
      const row = db
        .prepare(
          'SELECT * FROM delivery_records WHERE operation_id=?',
        )
        .get(id);
      if (row === undefined || row.txid !== txid) {
        fail(
          'DIVERGENT_DELIVERY_RECORD',
          'submitted transaction differs from its delivery operation',
        );
      }
      if (
        ['submitted', 'locally_reconciled'].includes(row.state) &&
        row.attempt_token === attemptToken &&
        row.submission_kind === 'rpc-accepted' &&
        row.observed_raw_sha256 === rawTransactionSha256
      ) {
        return normalizeRow(row);
      }
      if (row.state !== 'attempted' || row.attempt_token !== attemptToken) {
        fail(
          'DELIVERY_STATE_MISMATCH',
          'only the exact attempted send can become submitted',
        );
      }
      const now = Date.now();
      db.prepare(
        `UPDATE delivery_records
         SET state='submitted',submitted_at_ms=?,updated_at_ms=?,
             submission_kind='rpc-accepted',observed_raw_sha256=?
         WHERE operation_id=? AND state='attempted' AND attempt_token=?`,
      ).run(
        now,
        now,
        rawTransactionSha256,
        id,
        attemptToken,
      );
      crash(this.#crashAt, 'delivery.submitted.after_update');
      return normalizeRow(
        db
          .prepare(
            'SELECT * FROM delivery_records WHERE operation_id=?',
          )
          .get(id),
      );
    });
  }

  markIndeterminate(value) {
    exact(
      value,
      ['attemptToken', 'operationId', 'reason'],
      'markIndeterminate',
    );
    const id = operationId(value.operationId);
    const attemptToken = token(value.attemptToken);
    const failureReason = reason(value.reason);
    return this.#transaction((db) => {
      const row = db
        .prepare(
          'SELECT * FROM delivery_records WHERE operation_id=?',
        )
        .get(id);
      if (
        row !== undefined &&
        row.state === 'indeterminate' &&
        row.attempt_token === attemptToken &&
        row.reason === failureReason
      ) {
        return normalizeRow(row);
      }
      if (
        row === undefined ||
        row.state !== 'attempted' ||
        row.attempt_token !== attemptToken
      ) {
        fail(
          'DELIVERY_STATE_MISMATCH',
          'only the exact attempted send can become indeterminate',
        );
      }
      const now = Date.now();
      db.prepare(
        `UPDATE delivery_records
         SET state='indeterminate',reason=?,updated_at_ms=?
         WHERE operation_id=? AND state='attempted' AND attempt_token=?`,
      ).run(failureReason, now, id, attemptToken);
      crash(this.#crashAt, 'delivery.indeterminate.after_update');
      return normalizeRow(
        db
          .prepare(
            'SELECT * FROM delivery_records WHERE operation_id=?',
          )
          .get(id),
      );
    });
  }

  reconcileObserved(value) {
    exact(
      value,
      [
        'operationId',
        'rawTransactionSha256',
        'txid',
      ],
      'reconcileObserved',
    );
    const id = operationId(value.operationId);
    const txid = hash(value.txid, 'reconcileObserved.txid');
    const observedRawSha256 = hash(
      value.rawTransactionSha256,
      'reconcileObserved.rawTransactionSha256',
    );
    const kind = observationKind('authenticated-transaction-read');
    return this.#transaction((db) => {
      const row = db
        .prepare(
          'SELECT * FROM delivery_records WHERE operation_id=?',
        )
        .get(id);
      if (row === undefined || row.txid !== txid) {
        fail(
          'DIVERGENT_DELIVERY_RECORD',
          'observed transaction differs from its delivery operation',
        );
      }
      if (row.state === 'locally_reconciled') {
        if (row.observed_raw_sha256 !== observedRawSha256) {
          fail(
            'DIVERGENT_DELIVERY_RECORD',
            'observed raw transaction differs from the reconciled delivery',
          );
        }
        return normalizeRow(row);
      }
      if (row.state === 'submitted') {
        if (row.observed_raw_sha256 !== observedRawSha256) {
          fail(
            'DIVERGENT_DELIVERY_RECORD',
            'observed raw transaction differs from the submitted delivery',
          );
        }
        return normalizeRow(row);
      }
      if (!['attempted', 'indeterminate'].includes(row.state)) {
        fail(
          'DELIVERY_STATE_MISMATCH',
          'only an unresolved exact send can be reconciled by observation',
        );
      }
      const now = Date.now();
      db.prepare(
        `UPDATE delivery_records
         SET state='submitted',submitted_at_ms=?,updated_at_ms=?,
             submission_kind=?,observed_raw_sha256=?,reason=NULL
         WHERE operation_id=? AND state IN ('attempted','indeterminate')`,
      ).run(now, now, kind, observedRawSha256, id);
      crash(this.#crashAt, 'delivery.observed.after_update');
      return normalizeRow(
        db
          .prepare(
            'SELECT * FROM delivery_records WHERE operation_id=?',
          )
          .get(id),
      );
    });
  }

  markLocallyReconciled(value) {
    exact(
      value,
      ['operationId', 'rawTransactionSha256', 'txid'],
      'markLocallyReconciled',
    );
    const id = operationId(value.operationId);
    const txid = hash(value.txid, 'markLocallyReconciled.txid');
    const rawTransactionSha256 = hash(
      value.rawTransactionSha256,
      'markLocallyReconciled.rawTransactionSha256',
    );
    return this.#transaction((db) => {
      const row = db
        .prepare(
          'SELECT * FROM delivery_records WHERE operation_id=?',
        )
        .get(id);
      if (
        row === undefined
        || row.txid !== txid
        || row.observed_raw_sha256 !== rawTransactionSha256
      ) {
        fail(
          'DIVERGENT_DELIVERY_RECORD',
          'locally reconciled transaction differs from its submitted delivery',
        );
      }
      if (row.state === 'locally_reconciled') return normalizeRow(row);
      if (row.state !== 'submitted') {
        fail(
          'DELIVERY_STATE_MISMATCH',
          'only a submitted exact send can become locally reconciled',
        );
      }
      const now = Date.now();
      db.prepare(
        `UPDATE delivery_records
         SET state='locally_reconciled',
             locally_reconciled_at_ms=?,updated_at_ms=?
         WHERE operation_id=? AND state='submitted'`,
      ).run(now, now, id);
      crash(
        this.#crashAt,
        'delivery.locally-reconciled.after_update',
      );
      return normalizeRow(
        db
          .prepare(
            'SELECT * FROM delivery_records WHERE operation_id=?',
          )
          .get(id),
      );
    });
  }

  pragmas() {
    const db = this.#open();
    return Object.freeze({
      journalMode: db.prepare('PRAGMA journal_mode').get().journal_mode,
      synchronous: db.prepare('PRAGMA synchronous').get().synchronous,
      foreignKeys: db.prepare('PRAGMA foreign_keys').get().foreign_keys,
      busyTimeout: db.prepare('PRAGMA busy_timeout').get().timeout,
    });
  }

  close() {
    if (this.#db) {
      secureSidecars(this.#path);
      this.#db.close();
      this.#db = null;
      secureSidecars(this.#path);
    }
  }
}

export function openV2DeliveryJournal(path, options = undefined) {
  return new V2DeliveryJournal(path, options);
}

export function assertV2DeliveryJournal(value) {
  if (
    !value ||
    value[DELIVERY_JOURNAL_BRAND] !== true ||
    typeof value.claimOrCreate !== 'function' ||
    typeof value.claimExactResubmission !== 'function' ||
    typeof value.record !== 'function' ||
    typeof value.markSafePreSendAbort !== 'function' ||
    typeof value.safePreSendAbortMarker !== 'function' ||
    typeof value.markSubmitted !== 'function' ||
    typeof value.markIndeterminate !== 'function' ||
    typeof value.reconcileObserved !== 'function' ||
    typeof value.markLocallyReconciled !== 'function'
  ) {
    fail(
      'PERSISTENCE_REQUIRED',
      'a branded durable V2 SQLite delivery journal is required',
    );
  }
  return value;
}
