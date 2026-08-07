/**
 * Plan-normative admission coordinator helpers.
 *
 * Acceptance = exact mempool membership after sendrawtransaction.
 * testmempoolaccept is optional policy preflight only — never labelled acceptance.
 *
 * @see BENCHMARK_PLAN.md § Terminal Event / Phase 4
 */

import { createHash } from 'node:crypto';

const TXID = /^[0-9a-f]{64}$/;
const HEX = /^[0-9a-f]+$/;

export class AdmissionError extends Error {
  constructor(code, message, { cause, sendAttempted = false } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'AdmissionError';
    this.code = code;
    this.sendAttempted = sendAttempted;
  }
}

export function transactionIdFromHex(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !HEX.test(hex)) {
    throw new AdmissionError('MALFORMED_HEX', 'transaction hex must be even-length lowercase hex');
  }
  const first = createHash('sha256').update(Buffer.from(hex, 'hex')).digest();
  return createHash('sha256').update(first).digest().reverse().toString('hex');
}

function requireTxid(value, label) {
  if (typeof value !== 'string' || !TXID.test(value)) {
    throw new AdmissionError('INVALID_TXID', `${label} must be a full 64-char lowercase hex txid`);
  }
  return value;
}

/**
 * Optional policy preflight. Never counts as acceptance.
 * @returns {{ preflight: 'tma', allowed: boolean, raw: unknown }}
 */
export async function optionalTmaPreflight(rpc, rawTransactionHex) {
  if (rpc === null || typeof rpc !== 'object' || typeof rpc.testmempoolaccept !== 'function') {
    throw new AdmissionError('TMA_RPC_REQUIRED', 'testmempoolaccept capability required for optional preflight');
  }
  const raw = await rpc.testmempoolaccept(rawTransactionHex);
  const allowed = Array.isArray(raw) && raw[0]?.allowed === true;
  return Object.freeze({
    preflight: 'tma',
    allowed,
    // Explicitly not acceptance
    acceptance: false,
    label: 'policy_preflight_only',
    raw,
  });
}

/**
 * Observe whether an exact txid is currently in the target node's mempool.
 * Prefer getmempoolentry; fall back to getrawmempool includes.
 */
export async function observeMempoolMembership(rpc, txid) {
  const id = requireTxid(txid, 'txid');
  if (rpc === null || typeof rpc !== 'object') {
    throw new AdmissionError('RPC_REQUIRED', 'rpc required for mempool observation');
  }
  if (typeof rpc.getmempoolentry === 'function') {
    try {
      const entry = await rpc.getmempoolentry(id);
      if (entry && typeof entry === 'object') {
        return Object.freeze({
          present: true,
          method: 'getmempoolentry',
          entry: Object.freeze({
            size: entry.size ?? entry.vsize ?? null,
            fee: entry.fee ?? null,
            time: entry.time ?? null,
          }),
        });
      }
    } catch {
      // not in mempool or unsupported
    }
  }
  if (typeof rpc.getrawmempool === 'function') {
    const pool = await rpc.getrawmempool();
    const list = Array.isArray(pool) ? pool : [];
    const present = list.some((x) => String(x).toLowerCase() === id);
    return Object.freeze({ present, method: 'getrawmempool', entry: null });
  }
  throw new AdmissionError(
    'MEMPOOL_OBSERVE_UNSUPPORTED',
    'rpc must support getmempoolentry or getrawmempool for acceptance observation',
  );
}

/**
 * Exact raw + optional state readback after send.
 */
export async function readbackExactTransaction(rpc, txid, expectedHex) {
  const id = requireTxid(txid, 'txid');
  if (typeof rpc.getrawtransaction !== 'function') {
    throw new AdmissionError('READBACK_RPC_REQUIRED', 'getrawtransaction required for readback');
  }
  const observed = await rpc.getrawtransaction(id, true);
  const hex = typeof observed === 'string' ? observed : observed?.hex;
  const reported = typeof observed === 'object' && observed !== null
    ? String(observed.txid ?? '').toLowerCase()
    : id;
  if (typeof hex !== 'string' || hex !== expectedHex || reported !== id) {
    throw new AdmissionError(
      'READBACK_MISMATCH',
      'exact raw-transaction readback differs from submitted bytes',
      { sendAttempted: true },
    );
  }
  return Object.freeze({
    transactionId: id,
    rawTransactionHex: hex,
    match: true,
  });
}

/**
 * Plan admission sequence:
 * 1. assert txid absent from mempool
 * 2. optional TMA (never acceptance)
 * 3. sendrawtransaction exact bytes
 * 4. observe exact mempool membership (acceptance)
 * 5. raw readback
 *
 * Does NOT invent retries. One send attempt only.
 *
 * @param {object} args
 * @param {object} args.rpc
 * @param {string} args.rawTransactionHex
 * @param {string} args.expectedTransactionId
 * @param {boolean} [args.runTmaPreflight=false]
 * @param {() => Promise<void>|void} [args.beforeSendAttempt]
 * @param {() => Promise<object|null>|object|null} [args.stateReadback] optional expected state outputs check
 */
export async function admitExactTransactionToMempool({
  rpc,
  rawTransactionHex,
  expectedTransactionId,
  runTmaPreflight = false,
  beforeSendAttempt = null,
  stateReadback = null,
}) {
  const expected = requireTxid(expectedTransactionId, 'expectedTransactionId');
  let computed;
  try {
    computed = transactionIdFromHex(rawTransactionHex);
  } catch (error) {
    throw new AdmissionError('MALFORMED_HEX', 'rawTransactionHex is not a canonical transaction', { cause: error });
  }
  if (computed !== expected) {
    throw new AdmissionError('TXID_MISMATCH', 'expectedTransactionId does not match serialized transaction');
  }
  if (rpc === null || typeof rpc !== 'object' || typeof rpc.sendrawtransaction !== 'function') {
    throw new AdmissionError('SEND_RPC_REQUIRED', 'sendrawtransaction required');
  }

  const absent = await observeMempoolMembership(rpc, expected);
  if (absent.present) {
    throw new AdmissionError(
      'TXID_ALREADY_IN_MEMPOOL',
      'fresh txid already present in mempool before send — not a fresh action',
    );
  }

  let tma = null;
  if (runTmaPreflight) {
    tma = await optionalTmaPreflight(rpc, rawTransactionHex);
    if (!tma.allowed) {
      throw new AdmissionError('TMA_REJECTED', 'optional TMA preflight rejected transaction (not acceptance)');
    }
  }

  if (typeof beforeSendAttempt === 'function') {
    await beforeSendAttempt(Object.freeze({
      transactionId: expected,
      rawTransactionHex,
    }));
  }

  let returned;
  try {
    returned = await rpc.sendrawtransaction(rawTransactionHex);
  } catch (error) {
    throw new AdmissionError('SEND_INDETERMINATE', 'sendrawtransaction outcome indeterminate', {
      cause: error,
      sendAttempted: true,
    });
  }
  const returnedId = typeof returned === 'string' ? returned.toLowerCase() : '';
  if (returnedId !== expected) {
    throw new AdmissionError('SEND_INDETERMINATE', 'send returned mismatched or missing txid', {
      sendAttempted: true,
    });
  }

  const membership = await observeMempoolMembership(rpc, expected);
  if (!membership.present) {
    throw new AdmissionError(
      'MEMPOOL_NOT_OBSERVED',
      'txid not observed in mempool after send — not accepted under plan semantics',
      { sendAttempted: true },
    );
  }

  const readback = await readbackExactTransaction(rpc, expected, rawTransactionHex);

  let state = null;
  if (typeof stateReadback === 'function') {
    state = await stateReadback({ transactionId: expected, rawTransactionHex, readback });
  }

  // Plan: acceptance is mempool observation — not TMA.
  return Object.freeze({
    accepted: true,
    acceptanceMethod: 'mempool_membership',
    acceptance: Object.freeze({
      txid: expected,
      // full 64-char guaranteed by requireTxid
      observed: true,
      observeMethod: membership.method,
      entry: membership.entry,
    }),
    tmaPreflight: tma,
    readback,
    stateReadback: state,
    // Explicit: TMA is never acceptance
    tmaIsAcceptance: false,
  });
}

/**
 * Build acceptance evidence block for a v2 run record from an admit result or failure.
 */
export function acceptanceEvidenceFromAdmit(admitResult) {
  if (!admitResult || admitResult.accepted !== true) {
    return Object.freeze({
      accepted: false,
      acceptanceMethod: null,
      txid: null,
      mempoolObserved: false,
      tmaIsAcceptance: false,
      readback: null,
    });
  }
  return Object.freeze({
    accepted: true,
    acceptanceMethod: 'mempool_membership',
    txid: admitResult.acceptance.txid,
    mempoolObserved: true,
    observeMethod: admitResult.acceptance.observeMethod,
    tmaIsAcceptance: false,
    tmaPreflight: admitResult.tmaPreflight,
    readback: admitResult.readback,
    stateReadback: admitResult.stateReadback ?? null,
  });
}
