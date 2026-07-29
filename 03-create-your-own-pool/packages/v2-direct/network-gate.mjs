/**
 * Single mandatory network send gate for all broadcasts.
 * No alternate broadcast path may exist in the V2 Direct operator surface.
 */
export class NetworkGateError extends Error {
  constructor(message) {
    super(message);
    this.name = 'NetworkGateError';
  }
}

/**
 * @param {object} rpc — { sendrawtransaction(hex), testmempoolaccept(hexes) }
 */
export function createNetworkGate(rpc) {
  if (!rpc || typeof rpc.sendrawtransaction !== 'function') {
    throw new NetworkGateError('rpc.sendrawtransaction required');
  }

  let lastTxid = null;

  async function broadcastRawTransaction(txHex, { testFirst = true } = {}) {
    if (typeof txHex !== 'string' || !/^[0-9a-f]+$/i.test(txHex)) {
      throw new NetworkGateError('tx hex invalid');
    }
    if (testFirst && typeof rpc.testmempoolaccept === 'function') {
      const result = await rpc.testmempoolaccept([txHex]);
      const row = Array.isArray(result) ? result[0] : result;
      if (row && row.allowed === false) {
        throw new NetworkGateError(`testmempoolaccept rejected: ${row['reject-reason'] || JSON.stringify(row)}`);
      }
    }
    const txid = await rpc.sendrawtransaction(txHex);
    if (typeof txid !== 'string' || !/^[0-9a-f]{64}$/i.test(txid)) {
      throw new NetworkGateError('sendrawtransaction did not return full 64-char txid');
    }
    lastTxid = txid.toLowerCase();
    return lastTxid;
  }

  return Object.freeze({
    broadcastRawTransaction,
    lastTxid: () => lastTxid,
  });
}
