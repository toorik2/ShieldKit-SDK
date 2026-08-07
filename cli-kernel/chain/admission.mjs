/**
 * Branded SingleSendAdmission + ChainReader capabilities.
 * Maintainer SSH excluded from supported product paths.
 *
 * Rejection vs indeterminate classification (plan AC2):
 * - rejected: deterministic policy/node refusal before or without ambiguous send
 *   (reject codes, policy errors, TMA allowed:false with reject reason)
 * - send-indeterminate: send may have been attempted / network blip / no evidence
 */

import { createHash } from 'node:crypto';
import { ERROR_CODES, cliFail } from '../contracts/errors.mjs';

const TXID = /^[0-9a-f]{64}$/;
const HEX = /^[0-9a-f]+$/;
export const CHIPNET_GENESIS_HASH = '000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b';

/** Node/policy reject patterns that are deterministic rejections (not indeterminate). */
const REJECT_PATTERNS = [
  /reject/i,
  /policy/i,
  /dust/i,
  /min relay/i,
  /fee too low/i,
  /insufficient/i,
  /script.*fail/i,
  /mandatory-script-verify/i,
  /txn-mempool-conflict/i,
  /bad-txns/i,
  /non-BIP68/i,
  /too-long-mempool-chain/i,
  /absurdly-high-fee/i,
];

export function transactionIdFromHex(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !HEX.test(hex)) {
    throw new Error('invalid transaction hex');
  }
  const first = createHash('sha256').update(Buffer.from(hex, 'hex')).digest();
  return createHash('sha256').update(first).digest().reverse().toString('hex');
}

/**
 * Classify an error/message from sendrawtransaction or TMA.
 * @returns {'rejected'|'indeterminate'}
 */
export function classifySendFailure(errorOrMessage, { sendAttempted = false } = {}) {
  const msg = errorOrMessage instanceof Error
    ? errorOrMessage.message
    : String(errorOrMessage ?? '');
  const code = errorOrMessage?.code;

  // Explicit reject codes from RPC layers
  if (code === 'RPC_TRANSACTION_REJECTED'
    || code === 'TRANSACTION_REJECTED'
    || code === 'POLICY_REJECTED'
    || code === -26 /* RPC_VERIFY_REJECTED */
    || code === -25 /* RPC_VERIFY_ALREADY_IN_CHAIN treated carefully */) {
    if (code === -25) return 'indeterminate'; // already in chain / ambiguous
    return 'rejected';
  }

  // After a send is in flight, network errors are indeterminate
  if (sendAttempted) {
    if (/ECONN|ETIMEDOUT|socket|network|EPIPE|ECONNRESET/i.test(msg)) {
      return 'indeterminate';
    }
  }

  for (const re of REJECT_PATTERNS) {
    if (re.test(msg)) return 'rejected';
  }

  // Unknown failure after send → indeterminate; before send with no reject pattern → indeterminate
  // (cannot invent rejection)
  return 'indeterminate';
}

/**
 * Assert transport is not a maintainer SSH route.
 */
export function assertProductTransport(transport) {
  if (!transport || typeof transport !== 'object') {
    cliFail(ERROR_CODES.AMBIENT_CONFIG_FORBIDDEN, 'transport required');
  }
  if (transport.kind === 'ssh' || transport.maintainer === true) {
    cliFail(
      ERROR_CODES.MAINTAINER_PATH_FORBIDDEN,
      'maintainer SSH transports are not supported product paths',
    );
  }
  if (transport.kind === 'ambient-env') {
    cliFail(
      ERROR_CODES.AMBIENT_CONFIG_FORBIDDEN,
      'generic environment-selected transports are developer-only',
    );
  }
  return transport;
}

/**
 * Create a SingleSendAdmission capability over a product RPC.
 *
 * Preflight (optional TMA) is NOT a network mutation and never sets sendAttempted.
 * sendOnce with skipPreflight=true is used after coordinator has recorded send-attempted.
 */
export function createSingleSendAdmission(rpc, { transport = { kind: 'product-rpc' } } = {}) {
  assertProductTransport(transport);
  if (!rpc || typeof rpc.sendrawtransaction !== 'function') {
    throw new Error('rpc.sendrawtransaction required');
  }

  async function runPreflight(rawTransactionHex, expectedTransactionId) {
    if (typeof expectedTransactionId !== 'string' || !TXID.test(expectedTransactionId)) {
      throw new Error('expectedTransactionId must be 64-char hex');
    }
    const computed = transactionIdFromHex(rawTransactionHex);
    if (computed !== expectedTransactionId) {
      throw new Error('txid mismatch vs exact bytes');
    }
    if (typeof rpc.testmempoolaccept !== 'function') {
      return Object.freeze({
        allowed: true,
        rejected: false,
        sendAttempted: false,
        mutationCrossed: false,
        tmaIsAcceptance: false,
        preflight: 'none',
      });
    }
    try {
      const tma = await rpc.testmempoolaccept(rawTransactionHex);
      const row = Array.isArray(tma) ? tma[0] : null;
      if (row && row.allowed === false) {
        const reason = row['reject-reason'] || row.rejectReason || 'tma rejected';
        return Object.freeze({
          allowed: false,
          accepted: false,
          rejected: true,
          indeterminate: false,
          sendAttempted: false,
          mutationCrossed: false,
          tmaIsAcceptance: false,
          preflight: 'tma',
          rejectReason: reason,
          error: reason,
        });
      }
      return Object.freeze({
        allowed: true,
        rejected: false,
        sendAttempted: false,
        mutationCrossed: false,
        tmaIsAcceptance: false,
        preflight: 'tma',
      });
    } catch (error) {
      const kind = classifySendFailure(error, { sendAttempted: false });
      if (kind === 'rejected') {
        return Object.freeze({
          allowed: false,
          accepted: false,
          rejected: true,
          indeterminate: false,
          sendAttempted: false,
          mutationCrossed: false,
          tmaIsAcceptance: false,
          preflight: 'tma',
          error: error instanceof Error ? error.message : String(error),
        });
      }
      // Transport blip on optional preflight → allow proceeding to send
      return Object.freeze({
        allowed: true,
        rejected: false,
        sendAttempted: false,
        mutationCrossed: false,
        tmaIsAcceptance: false,
        preflight: 'tma-unavailable',
        preflightError: error instanceof Error ? error.message : String(error),
      });
    }
  }

  return {
    kind: 'SingleSendAdmission',
    transport: Object.freeze({ ...transport }),
    /** Optional policy preflight — never a mutation; never acceptance. */
    preflight: runPreflight,
    async sendOnce({
      rawTransactionHex,
      expectedTransactionId,
      explicitRebroadcast = false,
      skipPreflight = false,
    }) {
      if (typeof expectedTransactionId !== 'string' || !TXID.test(expectedTransactionId)) {
        throw new Error('expectedTransactionId must be 64-char hex');
      }
      const computed = transactionIdFromHex(rawTransactionHex);
      if (computed !== expectedTransactionId) {
        throw new Error('txid mismatch vs exact bytes');
      }

      // Optional deterministic preflight: TMA is never acceptance, never mutation
      if (!skipPreflight) {
        const pre = await runPreflight(rawTransactionHex, expectedTransactionId);
        if (pre.rejected === true) {
          return Object.freeze({
            ...pre,
            accepted: false,
            explicitRebroadcast: explicitRebroadcast === true,
          });
        }
      }

      let returned;
      try {
        // Crossing the mutation boundary
        returned = await rpc.sendrawtransaction(rawTransactionHex);
      } catch (error) {
        const kind = classifySendFailure(error, { sendAttempted: true });
        if (kind === 'rejected') {
          return Object.freeze({
            accepted: false,
            rejected: true,
            indeterminate: false,
            explicitRebroadcast: explicitRebroadcast === true,
            sendAttempted: true,
            mutationCrossed: true,
            error: error instanceof Error ? error.message : String(error),
            rejectReason: error instanceof Error ? error.message : String(error),
          });
        }
        return Object.freeze({
          accepted: false,
          rejected: false,
          indeterminate: true,
          explicitRebroadcast: explicitRebroadcast === true,
          sendAttempted: true,
          mutationCrossed: true,
          error: error instanceof Error ? error.message : String(error),
        });
      }

      const id = typeof returned === 'string' ? returned.toLowerCase() : '';
      if (id !== expectedTransactionId) {
        return Object.freeze({
          accepted: false,
          rejected: false,
          indeterminate: true,
          explicitRebroadcast: explicitRebroadcast === true,
          sendAttempted: true,
          mutationCrossed: true,
          error: 'send returned mismatched txid',
        });
      }

      // Observe mempool membership (acceptance)
      let present = false;
      let observeMethod = null;
      if (typeof rpc.getmempoolentry === 'function') {
        try {
          await rpc.getmempoolentry(expectedTransactionId);
          present = true;
          observeMethod = 'getmempoolentry';
        } catch { /* absent */ }
      }
      if (!present && typeof rpc.getrawmempool === 'function') {
        const pool = await rpc.getrawmempool();
        present = Array.isArray(pool)
          && pool.some((x) => String(x).toLowerCase() === expectedTransactionId);
        observeMethod = 'getrawmempool';
      }
      if (!present) {
        // Send returned txid but not in mempool → indeterminate (not invent rejection)
        return Object.freeze({
          accepted: false,
          rejected: false,
          indeterminate: true,
          explicitRebroadcast: explicitRebroadcast === true,
          sendAttempted: true,
          mutationCrossed: true,
          error: 'txid not observed in mempool',
        });
      }

      // Mempool membership alone is not enough: acceptance is only qualified
      // after RPC returns the exact bytes which crossed the mutation boundary.
      if (typeof rpc.getrawtransaction !== 'function') {
        return Object.freeze({
          accepted: false, rejected: false, indeterminate: true,
          explicitRebroadcast: explicitRebroadcast === true,
          sendAttempted: true, mutationCrossed: true,
          error: 'exact readback capability unavailable', readback: null,
        });
      }
      let observed;
      try { observed = await rpc.getrawtransaction(expectedTransactionId, true); } catch (error) {
        return Object.freeze({
          accepted: false, rejected: false, indeterminate: true,
          explicitRebroadcast: explicitRebroadcast === true,
          sendAttempted: true, mutationCrossed: true,
          error: `exact readback unavailable: ${error instanceof Error ? error.message : String(error)}`,
          readback: null,
        });
      }
      const hex = typeof observed === 'string' ? observed : observed?.hex;
      const readback = Object.freeze({ transactionId: expectedTransactionId, rawTransactionHex: hex, match: hex === rawTransactionHex });
      if (!readback.match) return Object.freeze({
        accepted: false, rejected: false, indeterminate: true,
        explicitRebroadcast: explicitRebroadcast === true,
        sendAttempted: true, mutationCrossed: true, readback, error: 'exact readback mismatch',
      });

      return Object.freeze({
        accepted: true,
        rejected: false,
        indeterminate: false,
        acceptanceMethod: 'mempool_membership',
        txid: expectedTransactionId,
        observeMethod,
        readback,
        explicitRebroadcast: explicitRebroadcast === true,
        tmaIsAcceptance: false,
        sendAttempted: true,
        mutationCrossed: true,
      });
    },
  };
}

/**
 * ChainReader branded capability (read-only).
 */
export function createChainReader(rpc, { transport = { kind: 'product-rpc' }, genesisHash = CHIPNET_GENESIS_HASH } = {}) {
  assertProductTransport(transport);
  if (genesisHash !== CHIPNET_GENESIS_HASH) throw new Error('ChainReader only supports the canonical Chipnet genesis identity');
  if (!rpc || typeof rpc.getblockhash !== 'function') throw new Error('rpc.getblockhash required for active Chipnet authentication');
  let authenticated = false;
  async function authenticate() {
    if (authenticated) return;
    const [block0, info] = await Promise.all([
      rpc.getblockhash(0),
      typeof rpc.getblockchaininfo === 'function' ? rpc.getblockchaininfo() : Promise.resolve(null),
    ]);
    if (String(block0).toLowerCase() !== CHIPNET_GENESIS_HASH) throw new Error('GENESIS_MISMATCH: RPC block 0 is not canonical Chipnet');
    if (info?.chain && String(info.chain).toLowerCase() !== 'chipnet') throw new Error(`CHAIN_MISMATCH: expected chipnet, got ${info.chain}`);
    authenticated = true;
  }
  return {
    kind: 'ChainReader',
    transport: Object.freeze({ ...transport }),
    genesisHash: CHIPNET_GENESIS_HASH,
    authenticate,
    async getTip() {
      await authenticate();
      // Tip is observation, not identity
      if (typeof rpc.getblockchaininfo === 'function') {
        const info = await rpc.getblockchaininfo();
        return Object.freeze({
          kind: 'tip',
          height: info.blocks ?? info.headers ?? null,
          bestHash: info.bestblockhash ?? null,
          chain: info.chain ?? null,
        });
      }
      if (typeof rpc.getblockcount === 'function') {
        const height = await rpc.getblockcount();
        return Object.freeze({ kind: 'tip', height, bestHash: null, chain: null });
      }
      throw new Error('rpc cannot observe tip');
    },
    async getRawTransaction(txid, verbose = true) {
      await authenticate();
      return rpc.getrawtransaction(txid, verbose);
    },
  };
}
