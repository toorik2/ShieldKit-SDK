/**
 * Discover the live State NFT tip for an instance from chain history.
 *
 * The tip is not a kit constant — it moves every SETTLE. Local state.json only
 * caches the last known tip; discovery re-derives the unspent tip from:
 *   stateLock scripthash history → outputs matching category + instanceId → not spent.
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

/**
 * @param {object} opts
 * @param {object} opts.rpc - from createChipnetRpc (needs electrum-style or listScriptUnspent)
 * @param {string|Uint8Array} opts.stateLockingBytecode - exact state trampoline lock
 * @param {string} opts.stateNftCategory - 64 hex (display order)
 * @param {string} opts.instanceId - 64 hex or sha256:…
 * @param {number} [opts.historyWindow=100] - max recent history txs to scan
 */
export async function discoverStateTip(opts) {
  const category = String(opts.stateNftCategory || '').toLowerCase();
  const instanceId = stripSha(opts.instanceId).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(category)) throw new Error('discoverStateTip: stateNftCategory must be 32-byte hex');
  if (!/^[0-9a-f]{64}$/.test(instanceId)) throw new Error('discoverStateTip: instanceId must be 32-byte hex');

  const lockBytes = opts.stateLockingBytecode instanceof Uint8Array
    ? opts.stateLockingBytecode
    : Buffer.from(opts.stateLockingBytecode, 'hex');
  const stateLockHex = Buffer.from(lockBytes).toString('hex');
  const window = Math.max(10, Number(opts.historyWindow || 100));
  const rpc = opts.rpc;
  if (!rpc) throw new Error('discoverStateTip: rpc required');

  // Electrum/Fulcrum: history on state lock, filter category + instanceId in SHST commitment.
  if (rpc.backend === 'electrum' && typeof rpc._electrumCall === 'function') {
    const call = rpc._electrumCall;
    const sh = electrumScriptHash(lockBytes);
    const hist = await call('blockchain.scripthash.get_history', [sh]);
    return discoverViaHistory(
      {
        history: (hist || []).map((h) => ({ txid: h.tx_hash, height: h.height })),
        getHex: (txid) => call('blockchain.transaction.get', [txid, false]),
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

async function discoverViaHistory({ history, getHex }, stateLockHex, category, instanceId, window) {
  const rows = [...(history || [])].sort((a, b) => (a.height || 0) - (b.height || 0));
  const slice = rows.slice(-window);
  const spent = new Set();
  /** @type {Array<{txid:string,vout:number,height:number,valueSatoshis:number,actionSequence:string}>} */
  const candidates = [];

  for (const h of slice) {
    const txid = h.txid || h.tx_hash;
    const hex = await getHex(txid);
    if (typeof hex !== 'string' || hex.length < 20) continue;
    const tx = decodeTransaction(hexToBin(hex));
    if (typeof tx === 'string') continue;

    for (const inp of tx.inputs) {
      const prevLe = binToHex(inp.outpointTransactionHash);
      const prevBe = revHex(prevLe);
      spent.add(`${prevLe}:${inp.outpointIndex}`);
      spent.add(`${prevBe}:${inp.outpointIndex}`);
    }

    for (let i = 0; i < tx.outputs.length; i += 1) {
      const o = tx.outputs[i];
      if (binToHex(o.lockingBytecode) !== stateLockHex) continue;
      if (!o.token?.category || !o.token?.nft?.commitment) continue;
      const cat = binToHex(o.token.category);
      const catRev = revHex(cat);
      if (cat !== category && catRev !== category) continue;
      const cmt = binToHex(o.token.nft.commitment);
      // SHST: magic(4)+ver(1)+net(1)+pad(2)+instanceId(32)+stateCommitment(32)+actionSequence(8)
      if (cmt.length < 160) continue; // hex chars
      const inst = cmt.slice(16, 80);
      if (inst !== instanceId) continue;
      const actionSequence = BigInt(`0x${Buffer.from(cmt.slice(144, 160), 'hex').reverse().toString('hex')}`).toString();
      candidates.push({
        txid,
        vout: i,
        height: h.height || 0,
        valueSatoshis: Number(o.valueSatoshis),
        actionSequence,
      });
    }
  }

  const tips = candidates.filter((c) => !spent.has(`${c.txid}:${c.vout}`));
  if (tips.length === 0) {
    throw new Error(
      `no live State NFT tip found for instance ${instanceId.slice(0, 12)}… `
      + `(scanned ${slice.length} txs, ${candidates.length} matching outputs). `
      + 'Pass --state-txid if the tip is older than the history window.',
    );
  }
  // Prefer highest height, then highest actionSequence
  tips.sort((a, b) => {
    if (a.height !== b.height) return b.height - a.height;
    return Number(BigInt(b.actionSequence) - BigInt(a.actionSequence));
  });
  const tip = tips[0];
  return Object.freeze({
    stateTxid: tip.txid,
    vout: tip.vout,
    height: tip.height,
    valueSatoshis: tip.valueSatoshis,
    actionSequence: tip.actionSequence,
    candidates: candidates.length,
    unspentMatches: tips.length,
  });
}
