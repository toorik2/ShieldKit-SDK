/**
 * Discover the live State NFT tip for an instance from chain.
 *
 * Tip moves every SETTLE. Local state.json only caches it.
 *
 * Strategy (fast → slow):
 *  1. Electrum `listunspent` on the state lock (usually 1 UTXO)
 *  2. Prefer `preferredStateTxid` if still a matching unspent tip
 *  3. History window (newest-first decode) as fallback
 */
import { decodeTransaction, hexToBin, binToHex } from '@bitauth/libauth';
import { electrumScriptHash } from './chipnet-rpc.mjs';

function stripSha(id) {
  if (typeof id !== 'string') return '';
  return id.startsWith('sha256:') ? id.slice(7) : id;
}

function revHex(hex) {
  return Buffer.from(hex, 'hex').reverse().toString('hex');
}

function lockToBytes(lock) {
  if (lock instanceof Uint8Array) return Buffer.from(lock);
  if (typeof lock === 'string') return Buffer.from(lock, 'hex');
  throw new Error('stateLockingBytecode must be hex string or bytes');
}

/** Fulcrum uses height -1 (or 0) for mempool — treat as newer than any confirmed. */
function rankHeight(height) {
  const h = Number(height);
  if (!Number.isFinite(h) || h <= 0) return Number.MAX_SAFE_INTEGER;
  return h;
}

function parseActionSequence(commitmentHex) {
  // SHST: magic(4)+ver(1)+net(1)+pad(2)+instanceId(32)+stateCommitment(32)+actionSequence(8)
  if (typeof commitmentHex !== 'string' || commitmentHex.length < 160) return null;
  return BigInt(`0x${Buffer.from(commitmentHex.slice(144, 160), 'hex').reverse().toString('hex')}`).toString();
}

function matchInstanceCommitment(commitmentHex, instanceId) {
  if (typeof commitmentHex !== 'string' || commitmentHex.length < 160) return false;
  return commitmentHex.slice(16, 80) === instanceId;
}

function categoryMatches(tokenCategoryHex, wantCategory) {
  if (!tokenCategoryHex) return false;
  const cat = tokenCategoryHex.toLowerCase();
  return cat === wantCategory || revHex(cat) === wantCategory;
}

/**
 * Decode a single tx for a state-NFT output matching lock/category/instance.
 * @returns {null | {txid,vout,height,valueSatoshis,actionSequence}}
 */
function extractTipFromTx(txid, height, tx, stateLockHex, category, instanceId) {
  if (!tx || typeof tx === 'string') return null;
  for (let i = 0; i < tx.outputs.length; i += 1) {
    const o = tx.outputs[i];
    if (binToHex(o.lockingBytecode) !== stateLockHex) continue;
    if (!o.token?.category || !o.token?.nft?.commitment) continue;
    if (!categoryMatches(binToHex(o.token.category), category)) continue;
    const cmt = binToHex(o.token.nft.commitment);
    if (!matchInstanceCommitment(cmt, instanceId)) continue;
    const actionSequence = parseActionSequence(cmt);
    if (actionSequence == null) continue;
    return {
      txid,
      vout: i,
      height: Number(height),
      valueSatoshis: Number(o.valueSatoshis),
      actionSequence,
    };
  }
  return null;
}

function pickBestTip(tips) {
  if (!tips.length) return null;
  const sorted = [...tips].sort((a, b) => {
    const ha = rankHeight(a.height);
    const hb = rankHeight(b.height);
    if (ha !== hb) return hb - ha;
    const sa = BigInt(a.actionSequence);
    const sb = BigInt(b.actionSequence);
    if (sa === sb) return 0;
    return sb > sa ? 1 : -1;
  });
  return sorted[0];
}

function freezeTip(tip, extra = {}) {
  return Object.freeze({
    stateTxid: tip.txid,
    vout: tip.vout,
    height: tip.height,
    valueSatoshis: tip.valueSatoshis,
    actionSequence: tip.actionSequence,
    ...extra,
  });
}

/**
 * @param {object} opts
 * @param {object} opts.rpc
 * @param {string|Uint8Array} opts.stateLockingBytecode
 * @param {string} opts.stateNftCategory
 * @param {string} opts.instanceId
 * @param {number} [opts.historyWindow=32] - max recent history txs (fallback path)
 * @param {string} [opts.preferredStateTxid] - local cache tip to re-validate first
 */
export async function discoverStateTip(opts) {
  const category = String(opts.stateNftCategory || '').toLowerCase();
  const instanceId = stripSha(opts.instanceId).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(category)) throw new Error('discoverStateTip: stateNftCategory must be 32-byte hex');
  if (!/^[0-9a-f]{64}$/.test(instanceId)) throw new Error('discoverStateTip: instanceId must be 32-byte hex');

  const lockBytes = lockToBytes(opts.stateLockingBytecode);
  const stateLockHex = lockBytes.toString('hex');
  const window = Math.max(8, Number(opts.historyWindow || 32));
  const rpc = opts.rpc;
  if (!rpc) throw new Error('discoverStateTip: rpc required');

  const preferred = typeof opts.preferredStateTxid === 'string'
    && /^[0-9a-f]{64}$/i.test(opts.preferredStateTxid)
    ? opts.preferredStateTxid.toLowerCase()
    : null;

  // --- Electrum path ---
  if (rpc.backend === 'electrum' && typeof rpc._electrumCall === 'function') {
    const call = rpc._electrumCall;
    const getHex = (txid) => call('blockchain.transaction.get', [txid, false]);

    // 1) listunspent on state lock — O(1) UTXOs, not O(history)×57KB
    if (typeof rpc.listScriptUnspent === 'function') {
      try {
        const utxos = await rpc.listScriptUnspent(stateLockHex);
        if (Array.isArray(utxos) && utxos.length > 0) {
          const tips = [];
          for (const u of utxos) {
            const txid = (u.txid || u.tx_hash || '').toLowerCase();
            if (!/^[0-9a-f]{64}$/.test(txid)) continue;
            const hex = await getHex(txid);
            if (typeof hex !== 'string') continue;
            const tx = decodeTransaction(hexToBin(hex));
            const tip = extractTipFromTx(
              txid,
              u.height ?? -1,
              tx,
              stateLockHex,
              category,
              instanceId,
            );
            // Prefer vout from listunspent when it matches a state output
            if (tip && (u.vout === undefined || u.vout === tip.vout || u.tx_pos === tip.vout)) {
              tips.push(tip);
            } else if (tip) {
              tips.push(tip);
            }
          }
          const best = pickBestTip(tips);
          if (best) {
            return freezeTip(best, {
              source: 'listunspent',
              candidates: tips.length,
              unspentMatches: tips.length,
            });
          }
        }
      } catch {
        // fall through to preferred / history
      }
    }

    // 2) History fallback — small window, newest-first download, order-independent spent set.
    // preferredStateTxid is force-included so a just-broadcast settle is not dropped.
    const sh = electrumScriptHash(lockBytes);
    const hist = await call('blockchain.scripthash.get_history', [sh]);
    return discoverViaHistory(
      {
        history: (hist || []).map((h) => ({
          txid: h.tx_hash,
          // preserve -1 mempool; do NOT coerce with `|| 0`
          height: Number(h.height),
        })),
        getHex,
        preferred,
      },
      stateLockHex,
      category,
      instanceId,
      window,
    );
  }

  throw new Error(
    'discoverStateTip: need Electrum/public Fulcrum (or pass --state-txid). '
    + `backend=${rpc.backend}`,
  );
}

/**
 * Scan recent history. Builds spent-set from ALL inputs in the window (order-independent),
 * then picks unspent state NFT with best (height, actionSequence).
 */
async function discoverViaHistory(
  { history, getHex, preferred },
  stateLockHex,
  category,
  instanceId,
  window,
) {
  // Newest first for download order (latency); final tip pick is global over window.
  const rows = [...(history || [])].sort((a, b) => {
    const ha = rankHeight(a.height);
    const hb = rankHeight(b.height);
    if (ha !== hb) return hb - ha;
    return 0; // stable: preserve electrum relative order for same height
  });
  const slice = rows.slice(0, window);

  // Ensure preferred is included even if outside window ranking edge
  if (preferred && !slice.some((r) => (r.txid || r.tx_hash) === preferred)) {
    const prefRow = rows.find((r) => (r.txid || r.tx_hash) === preferred);
    if (prefRow) slice.push(prefRow);
  }

  const spent = new Set();
  /** @type {Array<{txid:string,vout:number,height:number,valueSatoshis:number,actionSequence:string}>} */
  const candidates = [];

  // Parallel-ish batches of 4 to cut wall time without hammering Fulcrum
  const batchSize = 4;
  for (let i = 0; i < slice.length; i += batchSize) {
    const batch = slice.slice(i, i + batchSize);
    const hexes = await Promise.all(
      batch.map(async (h) => {
        const txid = (h.txid || h.tx_hash || '').toLowerCase();
        try {
          const hex = await getHex(txid);
          return { h, txid, hex };
        } catch {
          return { h, txid, hex: null };
        }
      }),
    );

    for (const { h, txid, hex } of hexes) {
      if (typeof hex !== 'string' || hex.length < 20) continue;
      const tx = decodeTransaction(hexToBin(hex));
      if (typeof tx === 'string') continue;

      for (const inp of tx.inputs) {
        const prevLe = binToHex(inp.outpointTransactionHash);
        spent.add(`${prevLe}:${inp.outpointIndex}`);
        spent.add(`${revHex(prevLe)}:${inp.outpointIndex}`);
      }

      const tip = extractTipFromTx(txid, h.height, tx, stateLockHex, category, instanceId);
      if (tip) candidates.push(tip);
    }
  }

  const tips = candidates.filter(
    (c) => !spent.has(`${c.txid}:${c.vout}`) && !spent.has(`${revHex(c.txid)}:${c.vout}`),
  );
  if (tips.length === 0) {
    throw new Error(
      `no live State NFT tip found for instance ${instanceId.slice(0, 12)}… `
      + `(scanned ${slice.length} txs, ${candidates.length} matching outputs). `
      + 'Pass --state-txid if the tip is older than the history window.',
    );
  }

  const best = pickBestTip(tips);
  return freezeTip(best, {
    source: 'history',
    candidates: candidates.length,
    unspentMatches: tips.length,
    scanned: slice.length,
  });
}
