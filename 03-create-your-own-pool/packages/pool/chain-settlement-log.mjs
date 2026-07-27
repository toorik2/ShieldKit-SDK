/**
 * Fetch ordered public settlement history from chain (tip → genesis walk).
 *
 * Blank machines have no residual tipForest. Product path must rebuild public
 * tip trees from genesis + settles before deposit/transfer/withdraw on a
 * multi-history tip (shared playground or restored pool).
 *
 * Uses Electrum verbose get when available (vin[8].txid); falls back to hex
 * decode via caller-provided decodeTx if needed.
 */

export class SettlementLogFetchError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.name = 'SettlementLogFetchError';
    this.code = code;
    Object.assign(this, extra);
  }
}

const fail = (code, message, extra) => {
  throw new SettlementLogFetchError(code, message, extra);
};

const HEX64 = /^[0-9a-f]{64}$/i;

function normTxid(id) {
  if (typeof id !== 'string') return '';
  return id.replace(/^sha256:/i, '').toLowerCase();
}

/**
 * @param {object} rpc — createChainRpc result (needs _electrumCall or getrawtransaction)
 * @param {string} txid
 * @returns {Promise<{ hex: string, verbose: object|null }>}
 */
async function fetchTx(rpc, txid) {
  const id = normTxid(txid);
  if (!HEX64.test(id)) fail('TXID', `invalid txid ${txid}`);

  // Prefer Electrum verbose (has vin[].txid display order).
  if (typeof rpc._electrumCall === 'function') {
    try {
      const verbose = await rpc._electrumCall('blockchain.transaction.get', [id, true]);
      if (verbose && typeof verbose === 'object' && verbose.hex) {
        return { hex: verbose.hex, verbose };
      }
      if (typeof verbose === 'string') {
        return { hex: verbose, verbose: null };
      }
    } catch {
      // fall through
    }
    const hex = await rpc._electrumCall('blockchain.transaction.get', [id, false]);
    if (typeof hex !== 'string') fail('FETCH', `no hex for ${id}`);
    return { hex, verbose: null };
  }

  if (typeof rpc.getrawtransaction === 'function') {
    try {
      const verbose = await rpc.getrawtransaction(id, true);
      if (verbose?.hex) return { hex: verbose.hex, verbose };
    } catch {
      // fall through
    }
    const hex = await rpc.getrawtransaction(id, false);
    if (typeof hex !== 'string') fail('FETCH', `no hex for ${id}`);
    return { hex, verbose: null };
  }

  fail('RPC', 'rpc must support Electrum get or getrawtransaction');
}

/**
 * Parent state tip outpoint from a 10-input settlement (input index 8).
 * @returns {{ parentTxid: string, vout: number } | null}
 */
function parentFromVerbose(verbose) {
  const vin = verbose?.vin;
  if (!Array.isArray(vin) || vin.length !== 10) return null;
  const st = vin[8];
  const parentTxid = normTxid(st?.txid);
  if (!HEX64.test(parentTxid)) return null;
  const vout = Number(st.vout);
  return { parentTxid, vout: Number.isFinite(vout) ? vout : 0 };
}

/**
 * Fallback: decode hex with libauth-style decoder (outpoint hash already display order
 * when using @bitauth/libauth decodeTransaction on Electrum hex).
 *
 * @param {string} hex
 * @param {(bin: Uint8Array) => object|string} decodeTransaction
 * @param {(bytes: Uint8Array) => string} binToHex
 */
function parentFromHex(hex, decodeTransaction, binToHex) {
  if (!decodeTransaction || !binToHex) return null;
  const bin = Uint8Array.from(Buffer.from(hex, 'hex'));
  const tx = decodeTransaction(bin);
  if (typeof tx === 'string' || !tx?.inputs || tx.inputs.length !== 10) return null;
  const st = tx.inputs[8];
  const parentTxid = normTxid(binToHex(st.outpointTransactionHash));
  if (!HEX64.test(parentTxid)) return null;
  return { parentTxid, vout: Number(st.outpointIndex) || 0 };
}

/**
 * Walk tip → … → genesis collecting settlement hexes (chronological order out).
 *
 * @param {{
 *   rpc: object,
 *   tipTxid: string,
 *   genesisTxid: string,
 *   maxDepth?: number,
 *   decodeTransaction?: Function,
 *   binToHex?: Function,
 * }} opts
 * @returns {Promise<{
 *   genesisTxid: string,
 *   genesisHex: string,
 *   settles: string[],
 *   settleTxids: string[],
 *   depth: number,
 * }>}
 */
export async function fetchSettlementLogFromTip(opts) {
  const tipTxid = normTxid(opts.tipTxid);
  const genesisTxid = normTxid(opts.genesisTxid);
  if (!HEX64.test(tipTxid)) fail('TIP', 'tipTxid required');
  if (!HEX64.test(genesisTxid)) fail('GENESIS', 'genesisTxid required');

  const maxDepth = Number(opts.maxDepth) > 0 ? Number(opts.maxDepth) : 128;
  const chain = []; // tip-first {txid, hex}
  let cur = tipTxid;
  const seen = new Set();

  // Tip itself may be genesis (empty pool after birth, no settles).
  if (cur === genesisTxid) {
    const { hex: genesisHex } = await fetchTx(opts.rpc, genesisTxid);
    return {
      genesisTxid,
      genesisHex,
      settles: [],
      settleTxids: [],
      depth: 0,
    };
  }

  while (cur !== genesisTxid) {
    if (seen.has(cur)) fail('CYCLE', `cycle walking tip ancestry at ${cur}`);
    seen.add(cur);
    if (chain.length >= maxDepth) {
      fail('DEPTH', `exceeded maxDepth ${maxDepth} before genesis`, { last: cur });
    }

    const { hex, verbose } = await fetchTx(opts.rpc, cur);
    let parent = verbose ? parentFromVerbose(verbose) : null;
    if (!parent) {
      parent = parentFromHex(hex, opts.decodeTransaction, opts.binToHex);
    }
    if (!parent) {
      // Non-settle (or decode miss). If we reached something that isn't genesis, fail closed.
      fail('ANCESTRY', `cannot resolve state parent of ${cur} (not a 10-input settle?)`);
    }

    chain.push({ txid: cur, hex });
    cur = parent.parentTxid;
  }

  const { hex: genesisHex } = await fetchTx(opts.rpc, genesisTxid);
  const chronological = chain.reverse();
  return {
    genesisTxid,
    genesisHex,
    settles: chronological.map((r) => r.hex),
    settleTxids: chronological.map((r) => r.txid),
    depth: chronological.length,
  };
}

/**
 * True when local settlementLog can cover tip actionSequence (has ≥ seq settles).
 * Soft heuristic: incomplete log if tip seq > settles length, or missing genesis hex.
 */
export function settlementLogLooksComplete(settlementLog, tipActionSequence) {
  if (!settlementLog?.genesisHex || !Array.isArray(settlementLog.settles)) return false;
  if (settlementLog.settles.length === 0) {
    // Empty settles only valid for genesis tip (seq 0).
    return tipActionSequence == null || String(tipActionSequence) === '0';
  }
  if (tipActionSequence == null) return settlementLog.settles.length > 0;
  try {
    const seq = BigInt(tipActionSequence);
    // Each settle advances actionSequence by 1 from 0.
    return BigInt(settlementLog.settles.length) >= seq;
  } catch {
    return settlementLog.settles.length > 0;
  }
}

/**
 * Merge fetched log into state.settlementLog (replace when chain walk is authoritative).
 */
export function applySettlementLog(state, log) {
  const next = state && typeof state === 'object' ? state : {};
  next.settlementLog = {
    genesisTxid: log.genesisTxid,
    genesisHex: log.genesisHex,
    settles: log.settles,
    settleTxids: log.settleTxids || undefined,
    fetchedAt: new Date().toISOString(),
    depth: log.depth,
  };
  return next;
}
