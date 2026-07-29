/**
 * Live chain access for V2 Direct (blank-machine friendly).
 *
 * Defaults to public Chipnet Fulcrum (Electrum TLS) via @shieldkit kit RPC —
 * no bitcoind and no SSH required for average users.
 *
 * Resolution (see kit/chipnet-rpc.mjs):
 *   1) SHIELDKIT_RPC_URL / BCH_RPC_URL
 *   2) SHIELDKIT_ELECTRUM=host:port
 *   3) Public Fulcrum TLS (chipnet.bch.ninja, …)
 *   4) Lab SSH layer1-node (if available)
 *
 * Live broadcast still requires V2_CHIPNET_LIVE=1.
 */
import { createChainRpc } from '../../kit/chipnet-rpc.mjs';
import { createNetworkGate } from '../network-gate.mjs';

export class ChipnetRpcError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ChipnetRpcError';
  }
}

/**
 * @param {{ network?: 'chipnet'|'mainnet' }} [opts]
 * @returns {Promise<import('../../kit/chipnet-rpc.mjs').createChainRpc extends Function ? any : never>}
 */
export async function createChipnetRpc(opts = {}) {
  const network = opts.network === 'mainnet' ? 'mainnet' : 'chipnet';
  try {
    return await createChainRpc({ network, preferLayer1: opts.preferLayer1 });
  } catch (e) {
    throw new ChipnetRpcError(e.message || String(e));
  }
}

/**
 * Network gate for live product broadcast.
 * @returns {Promise<{
 *   rpc: object,
 *   broadcastRawTransaction: (hex: string) => Promise<string>,
 *   scanAddress: (address: string, lockingBytecodeHex?: string) => Promise<Array>,
 *   backend: string,
 *   label: string,
 * }>}
 */
export async function createLiveNetworkGate(opts = {}) {
  if (process.env.V2_CHIPNET_LIVE !== '1' && process.env.V2_CHIPNET_LIVE !== 'true') {
    throw new ChipnetRpcError(
      'Live broadcast requires V2_CHIPNET_LIVE=1 (refusing silent always-allow / fake gate)',
    );
  }
  const network = opts.network === 'mainnet' ? 'mainnet' : 'chipnet';
  const rpc = await createChipnetRpc({ network, preferLayer1: opts.preferLayer1 });

  // Adapt kit RPC shape → network-gate (sendrawtransaction + testmempoolaccept)
  const adapted = {
    async testmempoolaccept(hexes) {
      const hex = Array.isArray(hexes) ? hexes[0] : hexes;
      const res = await rpc.testmempoolaccept(hex);
      return Array.isArray(res) ? res : [res];
    },
    async sendrawtransaction(hex) {
      const txid = await rpc.sendrawtransaction(hex);
      if (typeof txid !== 'string' || !/^[0-9a-fA-F]{64}$/.test(txid)) {
        throw new ChipnetRpcError(`sendrawtransaction bad txid: ${txid}`);
      }
      return txid.toLowerCase();
    },
  };

  const gate = createNetworkGate(adapted);
  return Object.freeze({
    rpc,
    backend: rpc.backend,
    label: rpc.label,
    async broadcastRawTransaction(txHex) {
      return gate.broadcastRawTransaction(txHex, { testFirst: true });
    },
    async scanAddress(address, lockingBytecodeHex) {
      return rpc.scanAddress(address, lockingBytecodeHex);
    },
    async getblockcount() {
      return rpc.getblockcount();
    },
  });
}
