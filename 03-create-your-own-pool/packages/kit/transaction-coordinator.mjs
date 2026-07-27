import { createHash, randomUUID } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
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

const fail = (code, message) => {
  throw new OperationJournalError(code, message);
};

const HEX = /^[0-9a-f]+$/;
const TXID = /^[0-9a-f]{64}$/;

export function transactionIdFromHex(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !HEX.test(hex)) {
    fail('MALFORMED_HEX', 'transaction hex must be non-empty even-length lowercase hex');
  }
  const first = createHash('sha256').update(Buffer.from(hex, 'hex')).digest();
  return createHash('sha256').update(first).digest().reverse().toString('hex');
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
}

function validateJournal(journal) {
  if (!journal || journal.schema !== 'shieldkit/operation-journal/v1') {
    fail('INVALID_JOURNAL', 'unsupported operation journal');
  }
  if (!Array.isArray(journal.transactions) || journal.transactions.length === 0) {
    fail('INVALID_JOURNAL', 'journal must contain at least one transaction');
  }
  journal.transactions.forEach(validateTransaction);
  if (!['prepared', 'broadcasting', 'broadcast', 'committing', 'committed', 'failed'].includes(journal.status)) {
    fail('INVALID_JOURNAL', `invalid operation status ${journal.status}`);
  }
  return journal;
}

function writeJournal(journalPath, journal) {
  journal.updatedAt = new Date().toISOString();
  atomicWriteJson(journalPath, journal, {
    mode: PRIVATE_FILE_MODE,
    directoryMode: PRIVATE_DIRECTORY_MODE,
  });
}

export function loadPendingOperation(poolDirectory) {
  const journalPath = pendingOperationPath(poolDirectory);
  if (!existsSync(journalPath)) return null;
  return { journalPath, journal: validateJournal(readJsonFile(journalPath)) };
}

/**
 * Persist all transaction bytes and the exact post-broadcast state before any send.
 */
export function stageOperation({
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
  if (existsSync(journalPath)) {
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
    })),
    nextState,
    ledgerRecord: { ...ledgerRecord, operationId },
    publicResult,
  };
  validateJournal(journal);
  writeJournal(journalPath, journal);
  return { journalPath, journal };
}

function mempoolRejected(result) {
  return Array.isArray(result) && result[0]?.allowed === false;
}

function alreadyKnown(error) {
  return /already (?:in (?:the )?mempool|known)|txn-already-known|transaction already exists/i
    .test(String(error?.message || error));
}

/**
 * The sole production transaction-send path. Every transaction is journaled first and
 * every invocation executes the mainnet/development-profile authorization gate.
 */
export async function broadcastStagedOperation({
  journalPath,
  rpc,
  mainnetAcknowledged = false,
  allowDevelopmentOnMainnet = false,
}) {
  const journal = validateJournal(readJsonFile(journalPath));
  if (journal.status === 'committed' || journal.status === 'broadcast') return journal;
  if (!['prepared', 'broadcasting', 'failed'].includes(journal.status)) {
    fail('INVALID_STATE', `cannot broadcast operation in state ${journal.status}`);
  }
  assertBroadcastAllowed({
    network: journal.network,
    setupMode: journal.setupMode,
    mainnetAcknowledged,
    allowDevelopmentOnMainnet,
  });
  if (!rpc || typeof rpc.sendrawtransaction !== 'function') {
    fail('RPC_REQUIRED', 'RPC sendrawtransaction capability is required');
  }

  journal.status = 'broadcasting';
  writeJournal(journalPath, journal);
  for (const transaction of journal.transactions) {
    if (transaction.status === 'broadcast') continue;
    transaction.attempts += 1;
    transaction.lastAttemptAt = new Date().toISOString();
    writeJournal(journalPath, journal);
    try {
      if (typeof rpc.testmempoolaccept === 'function') {
        const acceptance = await rpc.testmempoolaccept(transaction.hex);
        if (mempoolRejected(acceptance)) {
          throw new OperationJournalError(
            'MEMPOOL_REJECTED',
            `${transaction.role} rejected: ${JSON.stringify(acceptance)}`,
          );
        }
      }
      let returned;
      try {
        returned = await rpc.sendrawtransaction(transaction.hex);
      } catch (error) {
        if (!alreadyKnown(error)) throw error;
        returned = transaction.txid;
      }
      if (typeof returned === 'string' && TXID.test(returned.toLowerCase())
        && returned.toLowerCase() !== transaction.txid) {
        fail('RPC_TXID_MISMATCH', `${transaction.role} RPC txid does not match serialized bytes`);
      }
      transaction.status = 'broadcast';
      transaction.broadcastAt = new Date().toISOString();
      transaction.rpcTxid = typeof returned === 'string' ? returned.toLowerCase() : transaction.txid;
      delete transaction.error;
      writeJournal(journalPath, journal);
    } catch (error) {
      journal.status = 'failed';
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
export function commitStagedOperation({ journalPath, statePath, ledgerPath }) {
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
