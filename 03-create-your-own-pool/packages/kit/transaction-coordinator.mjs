import { createHash, randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import {
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
} from 'node:fs';
import path from 'node:path';
import { assertBroadcastAllowed } from './network.mjs';
import {
  appendPrivateJsonLine,
  atomicWriteJson,
  PRIVATE_DIRECTORY_MODE,
  PRIVATE_FILE_MODE,
  readJsonFile,
} from './secure-files.mjs';

export class OperationJournalError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'OperationJournalError';
    this.code = code;
  }
}

export class ExactTransactionBroadcastError extends Error {
  constructor(code, message, { cause = undefined, sendAttempted = false } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'ExactTransactionBroadcastError';
    this.code = code;
    this.sendAttempted = sendAttempted;
  }
}

const fail = (code, message) => {
  throw new OperationJournalError(code, message);
};

const HEX = /^[0-9a-f]+$/;
const TXID = /^[0-9a-f]{64}$/;
const ATTEMPT_TOKEN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const broadcastFail = (code, message, options = undefined) => {
  throw new ExactTransactionBroadcastError(code, message, options);
};

function attemptToken(value, label) {
  if (typeof value !== 'string' || !ATTEMPT_TOKEN.test(value)) {
    fail('DELIVERY_ATTEMPT_TOKEN_INVALID', `${label} must be a current delivery attempt token`);
  }
  return value;
}

function operationLockPath(journalPath) {
  if (typeof journalPath !== 'string' || journalPath.length === 0) {
    fail('OPERATION_LOCK_INVALID', 'journalPath must be a nonempty string');
  }
  return `${path.resolve(journalPath)}.send-lock.sqlite`;
}

const CURRENT_UID = typeof process.getuid === 'function' ? BigInt(process.getuid()) : null;

function lstatPrivate(filename, label, type, mode) {
  let stat;
  try { stat = lstatSync(filename, { bigint: true }); }
  catch (error) {
    if (error?.code === 'ENOENT') return null;
    fail('OPERATION_DIRECTORY_INVALID', `${label} is inaccessible`);
  }
  if ((type === 'directory' && !stat.isDirectory()) || (type === 'file' && !stat.isFile())
    || stat.isSymbolicLink() || (type === 'file' && stat.nlink !== 1n)
    || CURRENT_UID === null || stat.uid !== CURRENT_UID
    || (stat.mode & 0o777n) !== BigInt(mode)) {
    fail('OPERATION_DIRECTORY_INVALID', `${label} must be an owner-only non-symlink ${type}`);
  }
  return stat;
}

function operationPathParts(journalPath) {
  if (typeof journalPath !== 'string' || journalPath.length === 0) {
    fail('OPERATION_DIRECTORY_INVALID', 'journalPath must be a nonempty string');
  }
  const journal = path.resolve(journalPath);
  const directory = path.dirname(journal);
  const shieldkit = path.dirname(directory);
  const pool = path.dirname(shieldkit);
  if (path.basename(journal) !== 'pending.json' || path.basename(directory) !== 'operations'
    || path.basename(shieldkit) !== '.shieldkit') {
    fail('OPERATION_DIRECTORY_INVALID', 'journalPath must be the canonical pending operation journal');
  }
  return Object.freeze({ journal, directory, pool, shieldkit });
}

function ensurePrivateDirectory(filename, label) {
  const existing = lstatPrivate(filename, label, 'directory', PRIVATE_DIRECTORY_MODE);
  if (existing !== null) return;
  try { mkdirSync(filename, { mode: PRIVATE_DIRECTORY_MODE }); }
  catch (error) {
    if (error?.code !== 'EEXIST') fail('OPERATION_DIRECTORY_INVALID', `${label} cannot be created`);
  }
  if (lstatPrivate(filename, label, 'directory', PRIVATE_DIRECTORY_MODE) === null) {
    fail('OPERATION_DIRECTORY_INVALID', `${label} disappeared during creation`);
  }
}

function assertTrustedOperationDirectory(journalPath, { create = false } = {}) {
  const parts = operationPathParts(journalPath);
  if (lstatPrivate(parts.pool, 'operation pool directory', 'directory', PRIVATE_DIRECTORY_MODE) === null) {
    fail('OPERATION_DIRECTORY_INVALID', 'operation pool directory is missing');
  }
  if (create) {
    ensurePrivateDirectory(parts.shieldkit, 'operation metadata directory');
    ensurePrivateDirectory(parts.directory, 'operation directory');
    return parts;
  }
  if (lstatPrivate(parts.shieldkit, 'operation metadata directory', 'directory', PRIVATE_DIRECTORY_MODE) === null
    || lstatPrivate(parts.directory, 'operation directory', 'directory', PRIVATE_DIRECTORY_MODE) === null) return null;
  return parts;
}

function assertPrivateOperationJournal(journalPath, { allowAbsent = false } = {}) {
  const stat = lstatPrivate(journalPath, 'operation journal', 'file', PRIVATE_FILE_MODE);
  if (stat === null && !allowAbsent) fail('OPERATION_JOURNAL_INVALID', 'operation journal is missing');
  return stat !== null;
}

function assertPrivateOperationLockDatabase(filename) {
  const stat = lstatPrivate(filename, 'send lock database', 'file', PRIVATE_FILE_MODE);
  if (stat === null) fail('OPERATION_LOCK_INVALID', 'send lock database is missing');
}

function ensurePrivateOperationLockDatabase(filename) {
  if (lstatPrivate(filename, 'send lock database', 'file', PRIVATE_FILE_MODE) !== null) return;
  let descriptor;
  try { descriptor = openSync(filename, 'wx', PRIVATE_FILE_MODE); }
  catch (error) {
    if (error?.code !== 'EEXIST') fail('OPERATION_LOCK_INVALID', 'send lock database cannot be created');
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
  assertPrivateOperationLockDatabase(filename);
}

function acquireOperationLock(journalPath) {
  const parts = assertTrustedOperationDirectory(journalPath, { create: true });
  const filename = operationLockPath(parts.journal);
  ensurePrivateOperationLockDatabase(filename);
  let database;
  try {
    database = new DatabaseSync(filename);
    database.exec(
      'PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; '
      + 'PRAGMA trusted_schema=OFF; PRAGMA busy_timeout=0; BEGIN IMMEDIATE;',
    );
    assertPrivateOperationLockDatabase(filename);
    return Object.freeze({ database, filename });
  } catch (error) {
    try { database?.close(); } catch {}
    if (/database is (?:locked|busy)/iu.test(String(error?.message ?? ''))) {
      fail('OPERATION_LOCK_HELD', 'another process owns this staged operation lifecycle');
    }
    throw error;
  }
}

function releaseOperationLock(lock) {
  try { lock.database.exec('COMMIT;'); }
  finally { lock.database.close(); }
}

async function withOperationLock(journalPath, callback) {
  const lock = acquireOperationLock(journalPath);
  try { return await callback(); }
  finally { releaseOperationLock(lock); }
}

function withOperationLockSync(journalPath, callback) {
  const lock = acquireOperationLock(journalPath);
  try { return callback(); }
  finally { releaseOperationLock(lock); }
}

export function transactionIdFromHex(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !HEX.test(hex)) {
    fail('MALFORMED_HEX', 'transaction hex must be non-empty even-length lowercase hex');
  }
  const first = createHash('sha256').update(Buffer.from(hex, 'hex')).digest();
  return createHash('sha256').update(first).digest().reverse().toString('hex');
}

/**
 * Mandatory network-mutation boundary for one already-durable immutable
 * transaction. The caller-owned callback must commit its final pre-send state;
 * only after that callback returns can this function invoke sendrawtransaction.
 *
 * This helper deliberately performs no retry and treats every exception after
 * the send begins as indeterminate. Callers must reconcile exact bytes
 * read-only before any separately acknowledged rebroadcast.
 */
export async function admitAndSendExactTransactionOnce({
  rpc,
  rawTransactionHex,
  expectedTransactionId,
  network,
  setupMode,
  mainnetAcknowledged = false,
  allowDevelopmentOnMainnet = false,
  beforeSendAttempt,
}) {
  if (typeof expectedTransactionId !== 'string' || !TXID.test(expectedTransactionId)) {
    broadcastFail('EXACT_BROADCAST_INVALID', 'expectedTransactionId must be a lowercase 32-byte transaction ID');
  }
  let computedTransactionId;
  try {
    computedTransactionId = transactionIdFromHex(rawTransactionHex);
  } catch (error) {
    broadcastFail('EXACT_BROADCAST_INVALID', 'rawTransactionHex is not a canonical serialized transaction', { cause: error });
  }
  if (computedTransactionId !== expectedTransactionId) {
    broadcastFail('EXACT_BROADCAST_TXID_MISMATCH', 'expectedTransactionId does not match the exact serialized transaction');
  }
  const publicSinglePass = rpc !== null && typeof rpc === 'object'
    && typeof rpc.submitExactTransaction === 'function';
  if (rpc === null || typeof rpc !== 'object'
    || (!publicSinglePass && (typeof rpc.testmempoolaccept !== 'function'
      || typeof rpc.sendrawtransaction !== 'function'
      || typeof rpc.getrawtransaction !== 'function'))) {
    broadcastFail('EXACT_BROADCAST_RPC_REQUIRED', 'an exact single-pass capability or BCHN preflight/send/readback capabilities are required');
  }
  if (typeof beforeSendAttempt !== 'function') {
    broadcastFail('EXACT_BROADCAST_DURABILITY_REQUIRED', 'beforeSendAttempt must durably commit the pre-send boundary');
  }
  try {
    assertBroadcastAllowed({
      network,
      setupMode,
      mainnetAcknowledged,
      allowDevelopmentOnMainnet,
    });
  } catch (error) {
    broadcastFail('EXACT_BROADCAST_NETWORK_REJECTED', 'the mandatory network/broadcast gate rejected this transaction', { cause: error });
  }

  if (publicSinglePass) {
    try {
      await beforeSendAttempt(Object.freeze({
        transactionId: expectedTransactionId,
        rawTransactionHex,
      }));
    } catch (error) {
      broadcastFail('EXACT_BROADCAST_DURABILITY_FAILED', 'the durable pre-send callback failed before any network mutation', { cause: error });
    }
    let observed;
    try {
      observed = await rpc.submitExactTransaction(rawTransactionHex, expectedTransactionId);
    } catch (error) {
      broadcastFail('EXACT_BROADCAST_SEND_INDETERMINATE', 'public Chipnet send outcome is indeterminate', {
        cause: error,
        sendAttempted: true,
      });
    }
    const raw = observed?.rawTransaction;
    if (observed?.transactionId !== expectedTransactionId
      || raw?.txid !== expectedTransactionId || raw?.hex !== rawTransactionHex) {
      broadcastFail('EXACT_BROADCAST_READBACK_INVALID', 'public Chipnet exact raw-transaction readback differs after send', {
        sendAttempted: true,
      });
    }
    return Object.freeze({
      admission: Object.freeze({ allowed: true, txid: expectedTransactionId }),
      transactionId: expectedTransactionId,
      readback: Object.freeze({ transactionId: expectedTransactionId, rawTransactionHex: raw.hex }),
    });
  }

  let mempool;
  try {
    mempool = await rpc.testmempoolaccept(rawTransactionHex);
  } catch (error) {
    broadcastFail('EXACT_BROADCAST_MEMPOOL_FAILED', 'BCHN testmempoolaccept failed before any send attempt', { cause: error });
  }
  if (!Array.isArray(mempool) || mempool.length !== 1
    || mempool[0] === null || typeof mempool[0] !== 'object'
    || mempool[0].allowed !== true
    || mempool[0].txid !== expectedTransactionId) {
    broadcastFail('EXACT_BROADCAST_MEMPOOL_REJECTED', 'BCHN testmempoolaccept did not return the exact accepted transaction');
  }

  try {
    await beforeSendAttempt(Object.freeze({
      transactionId: expectedTransactionId,
      rawTransactionHex,
    }));
  } catch (error) {
    broadcastFail('EXACT_BROADCAST_DURABILITY_FAILED', 'the durable pre-send callback failed before any network mutation', { cause: error });
  }

  let returnedTransactionId;
  try {
    returnedTransactionId = await rpc.sendrawtransaction(rawTransactionHex);
  } catch (error) {
    broadcastFail('EXACT_BROADCAST_SEND_INDETERMINATE', 'BCHN send outcome is indeterminate', {
      cause: error,
      sendAttempted: true,
    });
  }
  if (typeof returnedTransactionId !== 'string'
    || returnedTransactionId.toLowerCase() !== expectedTransactionId) {
    broadcastFail('EXACT_BROADCAST_SEND_INDETERMINATE', 'BCHN send returned a mismatched or missing transaction ID', {
      sendAttempted: true,
    });
  }
  let observed;
  try {
    observed = await rpc.getrawtransaction(expectedTransactionId, true);
  } catch (error) {
    broadcastFail('EXACT_BROADCAST_READBACK_FAILED', 'BCHN exact raw-transaction readback failed after send', {
      cause: error,
      sendAttempted: true,
    });
  }
  const raw = typeof observed === 'string' ? observed : observed?.hex;
  const reportedTransactionId = typeof observed === 'object' && observed !== null
    ? observed.txid
    : expectedTransactionId;
  if (typeof raw !== 'string' || raw !== rawTransactionHex
    || typeof reportedTransactionId !== 'string'
    || reportedTransactionId.toLowerCase() !== expectedTransactionId) {
    broadcastFail('EXACT_BROADCAST_READBACK_INVALID', 'BCHN exact raw-transaction readback differs after send', {
      sendAttempted: true,
    });
  }
  return Object.freeze({
    admission: Object.freeze({ allowed: true, txid: expectedTransactionId }),
    transactionId: expectedTransactionId,
    readback: Object.freeze({ transactionId: expectedTransactionId, rawTransactionHex: raw }),
  });
}

/**
 * Action-only BCHN mutation boundary. After the caller durably commits its
 * final pre-send state, one branded RPC operation performs sendrawtransaction
 * followed by exact raw and output readback over one transport. There is no
 * testmempoolaccept preflight, so BCHN receives one admission request.
 *
 * Any exception after the durable callback begins the remote operation is
 * indeterminate. Callers must reconcile the exact transaction read-only and
 * must never automatically retry it.
 */
export async function sendAndReadbackExactTransactionOnce({
  rpc,
  rawTransactionHex,
  expectedTransactionId,
  stateOutputIndex = 0,
  network,
  setupMode,
  mainnetAcknowledged = false,
  allowDevelopmentOnMainnet = false,
  beforeSendAttempt,
}) {
  if (typeof expectedTransactionId !== 'string' || !TXID.test(expectedTransactionId)) {
    broadcastFail('EXACT_BROADCAST_INVALID', 'expectedTransactionId must be a lowercase 32-byte transaction ID');
  }
  let computedTransactionId;
  try {
    computedTransactionId = transactionIdFromHex(rawTransactionHex);
  } catch (error) {
    broadcastFail('EXACT_BROADCAST_INVALID', 'rawTransactionHex is not a canonical serialized transaction', { cause: error });
  }
  if (computedTransactionId !== expectedTransactionId) {
    broadcastFail('EXACT_BROADCAST_TXID_MISMATCH', 'expectedTransactionId does not match the exact serialized transaction');
  }
  if (!Number.isSafeInteger(stateOutputIndex) || stateOutputIndex < 0) {
    broadcastFail('EXACT_BROADCAST_INVALID', 'stateOutputIndex must be a nonnegative safe integer');
  }
  if (rpc === null || typeof rpc !== 'object'
    || typeof rpc.submitV2SinglePassAdmission !== 'function') {
    broadcastFail(
      'EXACT_BROADCAST_RPC_REQUIRED',
      'a branded single-pass BCHN send and readback capability is required',
    );
  }
  if (typeof beforeSendAttempt !== 'function') {
    broadcastFail('EXACT_BROADCAST_DURABILITY_REQUIRED', 'beforeSendAttempt must durably commit the pre-send boundary');
  }
  try {
    assertBroadcastAllowed({
      network,
      setupMode,
      mainnetAcknowledged,
      allowDevelopmentOnMainnet,
    });
  } catch (error) {
    broadcastFail('EXACT_BROADCAST_NETWORK_REJECTED', 'the mandatory network/broadcast gate rejected this transaction', { cause: error });
  }

  try {
    await beforeSendAttempt(Object.freeze({
      transactionId: expectedTransactionId,
      rawTransactionHex,
    }));
  } catch (error) {
    broadcastFail('EXACT_BROADCAST_DURABILITY_FAILED', 'the durable pre-send callback failed before any network mutation', { cause: error });
  }

  let observed;
  try {
    observed = await rpc.submitV2SinglePassAdmission(
      rawTransactionHex,
      expectedTransactionId,
      stateOutputIndex,
    );
  } catch (error) {
    broadcastFail('EXACT_BROADCAST_SEND_INDETERMINATE', 'BCHN send and readback outcome is indeterminate', {
      cause: error,
      sendAttempted: true,
    });
  }
  const raw = observed?.rawTransaction;
  if (observed === null || typeof observed !== 'object' || Array.isArray(observed)
    || observed.transactionId !== expectedTransactionId
    || raw === null || typeof raw !== 'object' || Array.isArray(raw)
    || raw.txid !== expectedTransactionId || raw.hex !== rawTransactionHex
    || (observed.stateOutput !== null
      && (typeof observed.stateOutput !== 'object'
        || Array.isArray(observed.stateOutput)))) {
    broadcastFail(
      'EXACT_BROADCAST_READBACK_INVALID',
      'BCHN single-pass exact transaction or state readback is malformed or differs',
      { sendAttempted: true },
    );
  }
  return Object.freeze({
    admission: Object.freeze({ allowed: true, txid: expectedTransactionId }),
    transactionId: expectedTransactionId,
    readback: Object.freeze({
      transactionId: expectedTransactionId,
      rawTransactionHex: raw.hex,
      stateOutput: observed.stateOutput,
    }),
  });
}

export function operationDirectory(poolDirectory) {
  return path.join(path.resolve(poolDirectory), '.shieldkit', 'operations');
}

export function pendingOperationPath(poolDirectory) {
  return path.join(operationDirectory(poolDirectory), 'pending.json');
}

function validateTransaction(transaction, index) {
  if (!transaction || typeof transaction !== 'object') {
    fail('INVALID_TRANSACTION', `transaction ${index} must be an object`);
  }
  if (typeof transaction.role !== 'string' || !/^[a-z][a-z0-9-]*$/.test(transaction.role)) {
    fail('INVALID_TRANSACTION', `transaction ${index} role is invalid`);
  }
  const computed = transactionIdFromHex(transaction.hex);
  if (transaction.txid !== computed) {
    fail('TXID_MISMATCH', `transaction ${index} txid does not match serialized bytes`);
  }
  if (!Number.isSafeInteger(transaction.attempts) || transaction.attempts < 0) {
    fail('INVALID_JOURNAL', `transaction ${index} attempts must be a nonnegative safe integer`);
  }
  if (!Object.hasOwn(transaction, 'attemptToken')) {
    if (transaction.status !== 'prepared') {
      fail('LEGACY_DELIVERY_TOKEN_REQUIRED', `transaction ${index} has an unresolved legacy send without an attempt token`);
    }
    transaction.attemptToken = null;
  }
  if (transaction.attemptToken !== null) attemptToken(transaction.attemptToken, `transaction ${index} attemptToken`);
  if (Object.hasOwn(transaction, 'readback')) {
    const readback = transaction.readback;
    if (readback === null || Array.isArray(readback) || typeof readback !== 'object'
      || Object.getPrototypeOf(readback) !== Object.prototype
      || Object.keys(readback).sort().join(',') !== 'observedAt,rawTransactionSha256'
      || typeof readback.observedAt !== 'string' || !Number.isFinite(Date.parse(readback.observedAt))
      || typeof readback.rawTransactionSha256 !== 'string' || !/^[0-9a-f]{64}$/u.test(readback.rawTransactionSha256)) {
      fail('INVALID_JOURNAL', `transaction ${index} readback evidence is invalid`);
    }
  }
}

function validateJournal(journal) {
  if (!journal || journal.schema !== 'shieldkit/operation-journal/v1') {
    fail('INVALID_JOURNAL', 'unsupported operation journal');
  }
  if (!Array.isArray(journal.transactions) || journal.transactions.length === 0) {
    fail('INVALID_JOURNAL', 'journal must contain at least one transaction');
  }
  journal.transactions.forEach(validateTransaction);
  if (!['prepared', 'broadcasting', 'ambiguous', 'broadcast', 'committing', 'committed', 'failed'].includes(journal.status)) {
    fail('INVALID_JOURNAL', `invalid operation status ${journal.status}`);
  }
  for (const transaction of journal.transactions) {
    if (!['prepared', 'sending', 'indeterminate', 'broadcast'].includes(transaction.status)) {
      fail('INVALID_JOURNAL', `invalid transaction delivery state ${transaction.status}`);
    }
  }
  return journal;
}

function writeJournal(journalPath, journal) {
  assertTrustedOperationDirectory(journalPath, { create: true });
  assertPrivateOperationJournal(journalPath, { allowAbsent: true });
  journal.updatedAt = new Date().toISOString();
  atomicWriteJson(journalPath, journal, {
    mode: PRIVATE_FILE_MODE,
    directoryMode: PRIVATE_DIRECTORY_MODE,
  });
}

export function loadPendingOperation(poolDirectory) {
  const journalPath = pendingOperationPath(poolDirectory);
  if (assertTrustedOperationDirectory(journalPath) === null) return null;
  if (!assertPrivateOperationJournal(journalPath, { allowAbsent: true })) return null;
  return { journalPath, journal: validateJournal(readJsonFile(journalPath)) };
}

/**
 * Persist all transaction bytes and the exact post-broadcast state before any send.
 */
function stageOperationLocked({
  poolDirectory,
  kind,
  network,
  setupMode,
  transactions,
  nextState,
  ledgerRecord,
  publicResult = {},
}) {
  const journalPath = pendingOperationPath(poolDirectory);
  if (assertPrivateOperationJournal(journalPath, { allowAbsent: true })) {
    const current = validateJournal(readJsonFile(journalPath));
    if (current.status !== 'committed') {
      fail(
        'PENDING_OPERATION',
        `unfinished ${current.kind} operation ${current.operationId}; resume it before preparing another`,
      );
    }
  }
  const operationId = randomUUID();
  const createdAt = new Date().toISOString();
  const journal = {
    schema: 'shieldkit/operation-journal/v1',
    operationId,
    kind,
    network,
    setupMode,
    status: 'prepared',
    createdAt,
    updatedAt: createdAt,
    transactions: transactions.map((transaction) => ({
      ...transaction,
      status: 'prepared',
      attempts: 0,
      attemptToken: null,
    })),
    nextState,
    ledgerRecord: { ...ledgerRecord, operationId },
    publicResult,
  };
  validateJournal(journal);
  writeJournal(journalPath, journal);
  return { journalPath, journal };
}

export function stageOperation(options) {
  const journalPath = pendingOperationPath(options?.poolDirectory);
  return withOperationLockSync(journalPath, () => stageOperationLocked(options));
}

function hasAmbiguousDelivery(journal) {
  return journal.transactions.some((transaction) =>
    ['sending', 'indeterminate'].includes(transaction.status),
  );
}

async function exactObservedTransaction(rpc, transaction) {
  if (!rpc || typeof rpc.getrawtransaction !== 'function') {
    fail('RPC_READ_REQUIRED', 'RPC getrawtransaction capability is required for ambiguous delivery reconciliation');
  }
  let observed;
  try {
    observed = await rpc.getrawtransaction(transaction.txid, true);
  } catch {
    return null;
  }
  const raw = typeof observed === 'string' ? observed : observed?.hex;
  const reportedTxid = typeof observed === 'object' && observed !== null
    ? observed.txid
    : transaction.txid;
  if (typeof raw !== 'string' || typeof reportedTxid !== 'string'
    || reportedTxid.toLowerCase() !== transaction.txid) return null;
  try {
    if (transactionIdFromHex(raw) !== transaction.txid || raw !== transaction.hex) return null;
  } catch {
    return null;
  }
  return raw;
}

/**
 * Read-only RPC reconciliation for a send which may already have reached the
 * node. It never calls sendrawtransaction. Only exact bytes/txid readback can
 * move an ambiguous transaction to broadcast.
 */
async function reconcileStagedOperationLocked({ journalPath, rpc }) {
  assertTrustedOperationDirectory(journalPath); assertPrivateOperationJournal(journalPath);
  const journal = validateJournal(readJsonFile(journalPath));
  if (!hasAmbiguousDelivery(journal)) return journal;
  for (const transaction of journal.transactions) {
    if (!['sending', 'indeterminate'].includes(transaction.status)) continue;
    const raw = await exactObservedTransaction(rpc, transaction);
    if (raw === null) continue;
    transaction.status = 'broadcast';
    transaction.broadcastAt = new Date().toISOString();
    transaction.rpcTxid = transaction.txid;
    transaction.reconciledAt = transaction.broadcastAt;
    transaction.readback = Object.freeze({
      rawTransactionSha256: createHash('sha256').update(Buffer.from(raw, 'hex')).digest('hex'),
      observedAt: transaction.reconciledAt,
    });
    delete transaction.error;
  }
  if (hasAmbiguousDelivery(journal)) {
    journal.status = 'ambiguous';
  } else if (journal.transactions.every((transaction) => transaction.status === 'broadcast')) {
    journal.status = 'broadcast';
    journal.broadcastAt ??= new Date().toISOString();
  } else {
    // No send was durably in flight; a restart may continue the remaining
    // prepared transactions without repeating a known/ambiguous send.
    journal.status = 'prepared';
  }
  writeJournal(journalPath, journal);
  return journal;
}

export async function reconcileStagedOperation({ journalPath, rpc }) {
  return withOperationLock(
    journalPath,
    () => reconcileStagedOperationLocked({ journalPath, rpc }),
  );
}

/**
 * The sole production transaction-send path. Every transaction is journaled first and
 * every invocation executes the mainnet/development-profile authorization gate.
 */
async function broadcastStagedOperationLocked({
  journalPath,
  rpc,
  mainnetAcknowledged = false,
  allowDevelopmentOnMainnet = false,
  afterTransactionBroadcast = undefined,
  exactRebroadcast = undefined,
}) {
  assertTrustedOperationDirectory(journalPath); assertPrivateOperationJournal(journalPath);
  const journal = validateJournal(readJsonFile(journalPath));
  if (journal.status === 'committed' || journal.status === 'broadcast') return journal;
  if (hasAmbiguousDelivery(journal)) {
    if (exactRebroadcast === undefined) {
      const reconciled = await reconcileStagedOperationLocked({ journalPath, rpc });
      if (reconciled.status === 'broadcast') return reconciled;
      fail('RECONCILIATION_REQUIRED', 'an ambiguous send remains unresolved; use explicit acknowledged exact rebroadcast only after read-only reconciliation');
    }
    const unresolved = journal.transactions.filter((transaction) =>
      ['sending', 'indeterminate'].includes(transaction.status),
    );
    if (unresolved.length !== 1 || unresolved[0].txid !== exactRebroadcast.txid
      || unresolved[0].attemptToken !== exactRebroadcast.priorAttemptToken) {
      fail('RECOVERY_TOKEN_MISMATCH', 'exact rebroadcast requires the current unresolved transaction attempt token');
    }
  }
  if (!['prepared', 'broadcasting', 'failed', 'ambiguous'].includes(journal.status)) {
    fail('INVALID_STATE', `cannot broadcast operation in state ${journal.status}`);
  }
  assertBroadcastAllowed({
    network: journal.network,
    setupMode: journal.setupMode,
    mainnetAcknowledged,
    allowDevelopmentOnMainnet,
  });
  const publicExactSend = rpc !== null && typeof rpc === 'object'
    && typeof rpc.submitExactTransaction === 'function';
  if (!rpc || (!publicExactSend
    && (typeof rpc.testmempoolaccept !== 'function'
      || typeof rpc.sendrawtransaction !== 'function'
      || typeof rpc.getrawtransaction !== 'function'))) {
    fail('RPC_REQUIRED', 'an exact public send/readback capability or BCHN preflight/send/readback capabilities are required');
  }
  if (afterTransactionBroadcast !== undefined && typeof afterTransactionBroadcast !== 'function') {
    fail('INVALID_CALLBACK', 'afterTransactionBroadcast must be a function when supplied');
  }

  journal.status = 'broadcasting';
  writeJournal(journalPath, journal);
  for (const transaction of journal.transactions) {
    if (transaction.status === 'broadcast') {
      if (afterTransactionBroadcast !== undefined) {
        await afterTransactionBroadcast(Object.freeze({
          journalPath,
          operationId: journal.operationId,
          transaction: Object.freeze({ ...transaction }),
          readback: Object.freeze({
            transactionId: transaction.txid,
            rawTransactionHex: transaction.hex,
          }),
        }));
      }
      continue;
    }
    try {
      const sent = await admitAndSendExactTransactionOnce({
        rpc,
        rawTransactionHex: transaction.hex,
        expectedTransactionId: transaction.txid,
        network: journal.network,
        setupMode: journal.setupMode,
        mainnetAcknowledged,
        allowDevelopmentOnMainnet,
        beforeSendAttempt: async () => {
          // This is the durable per-attempt CAS immediately before the sole
          // network mutation. The operation lock keeps a second process from
          // racing the in-memory journal copy between preflight and send.
          if (exactRebroadcast !== undefined) {
            if (transaction.txid !== exactRebroadcast.txid
              || !['sending', 'indeterminate'].includes(transaction.status)
              || transaction.attemptToken !== exactRebroadcast.priorAttemptToken) {
              fail('RECOVERY_TOKEN_MISMATCH', 'exact rebroadcast attempt token changed before send');
            }
          } else if (transaction.status !== 'prepared') {
            fail('RECONCILIATION_REQUIRED', 'a non-prepared transaction cannot begin a new send attempt');
          }
          transaction.status = 'sending';
          transaction.attemptToken = randomUUID();
          transaction.attempts += 1;
          transaction.lastAttemptAt = new Date().toISOString();
          writeJournal(journalPath, journal);
        },
      });
      const returned = sent.transactionId;
      // A node response means the request may have been accepted even if the
      // process now crashes during validation/readback. Persist ambiguity
      // before any post-send callback so restart cannot silently resend.
      transaction.status = 'indeterminate';
      journal.status = 'ambiguous';
      transaction.sentAt = new Date().toISOString();
      transaction.readback = Object.freeze({
        rawTransactionSha256: createHash('sha256').update(Buffer.from(sent.readback.rawTransactionHex, 'hex')).digest('hex'),
        observedAt: new Date().toISOString(),
      });
      writeJournal(journalPath, journal);
      if (typeof returned === 'string' && TXID.test(returned.toLowerCase())
        && returned.toLowerCase() !== transaction.txid) {
        fail('RPC_TXID_MISMATCH', `${transaction.role} RPC txid does not match serialized bytes`);
      }
      const broadcastTransaction = {
        ...transaction,
        status: 'broadcast',
        broadcastAt: new Date().toISOString(),
        rpcTxid: typeof returned === 'string' ? returned.toLowerCase() : transaction.txid,
      };
      delete broadcastTransaction.error;
      if (afterTransactionBroadcast !== undefined) {
        await afterTransactionBroadcast(Object.freeze({
          journalPath,
          operationId: journal.operationId,
          transaction: Object.freeze({ ...broadcastTransaction }),
          readback: Object.freeze({ ...sent.readback }),
        }));
      }
      Object.assign(transaction, broadcastTransaction);
      delete transaction.error;
      writeJournal(journalPath, journal);
    } catch (error) {
      if (['sending', 'indeterminate'].includes(transaction.status)) {
        transaction.status = 'indeterminate';
        journal.status = 'ambiguous';
      } else {
        transaction.status = 'prepared';
        journal.status = 'failed';
      }
      transaction.error = String(error?.message || error).slice(0, 1000);
      writeJournal(journalPath, journal);
      throw error;
    }
  }
  journal.status = 'broadcast';
  journal.broadcastAt = new Date().toISOString();
  writeJournal(journalPath, journal);
  return journal;
}

export async function broadcastStagedOperation(options) {
  return withOperationLock(
    options?.journalPath,
    () => broadcastStagedOperationLocked(options),
  );
}

/**
 * Intentionally repeat only exact staged bytes after an operator acknowledges
 * the unresolved send. This path first performs read-only reconciliation and
 * never runs automatically during ordinary restart/resume.
 */
export async function rebroadcastStagedOperation({
  journalPath,
  rpc,
  acknowledgedExactRebroadcast = false,
  priorAttemptToken,
  mainnetAcknowledged = false,
  allowDevelopmentOnMainnet = false,
  afterTransactionBroadcast = undefined,
}) {
  if (acknowledgedExactRebroadcast !== true) {
    fail('EXACT_REBROADCAST_ACK_REQUIRED', 'exact rebroadcast requires acknowledgedExactRebroadcast: true');
  }
  attemptToken(priorAttemptToken, 'priorAttemptToken');
  return withOperationLock(journalPath, async () => {
    const journal = await reconcileStagedOperationLocked({ journalPath, rpc });
    if (journal.status === 'broadcast' || journal.status === 'committed') return journal;
    const unresolved = journal.transactions.filter((transaction) =>
      ['sending', 'indeterminate'].includes(transaction.status),
    );
    if (unresolved.length !== 1 || unresolved[0].attemptToken !== priorAttemptToken) {
      fail('RECOVERY_TOKEN_MISMATCH', 'exact rebroadcast requires the current unresolved transaction attempt token');
    }
    return broadcastStagedOperationLocked({
      journalPath,
      rpc,
      mainnetAcknowledged,
      allowDevelopmentOnMainnet,
      afterTransactionBroadcast,
      exactRebroadcast: Object.freeze({
        txid: unresolved[0].txid,
        priorAttemptToken,
      }),
    });
  });
}

function ledgerContainsOperation(ledgerPath, operationId) {
  if (!existsSync(ledgerPath)) return false;
  return readFileSync(ledgerPath, 'utf8')
    .split('\n')
    .some((line) => {
      if (!line) return false;
      try { return JSON.parse(line).operationId === operationId; } catch { return false; }
    });
}

/**
 * Idempotently commit state after all sends. State carries the operation ID so a crash
 * between the atomic state rename and ledger append can be safely resumed.
 */
function commitStagedOperationLocked({ journalPath, statePath, ledgerPath }) {
  assertTrustedOperationDirectory(journalPath); assertPrivateOperationJournal(journalPath);
  const journal = validateJournal(readJsonFile(journalPath));
  if (journal.status === 'committed') return journal;
  if (!['broadcast', 'committing'].includes(journal.status)) {
    fail('NOT_BROADCAST', `operation must be fully broadcast before commit, got ${journal.status}`);
  }
  journal.status = 'committing';
  writeJournal(journalPath, journal);

  const committedState = {
    ...journal.nextState,
    lastCommittedOperation: {
      operationId: journal.operationId,
      kind: journal.kind,
      committedAt: new Date().toISOString(),
    },
  };
  const existing = existsSync(statePath) ? readJsonFile(statePath) : null;
  if (existing?.lastCommittedOperation?.operationId !== journal.operationId) {
    atomicWriteJson(statePath, committedState);
  }
  if (!ledgerContainsOperation(ledgerPath, journal.operationId)) {
    appendPrivateJsonLine(ledgerPath, journal.ledgerRecord);
  }
  journal.status = 'committed';
  journal.committedAt = new Date().toISOString();
  delete journal.nextState;
  writeJournal(journalPath, journal);
  return journal;
}

export function commitStagedOperation(options) {
  return withOperationLockSync(
    options?.journalPath,
    () => commitStagedOperationLocked(options),
  );
}
