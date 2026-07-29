/**
 * Real Chipnet RPC via layer1-node (no mock). Single network-send companion.
 */
import { execFileSync } from 'node:child_process';

export class ChipnetRpcError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ChipnetRpcError';
  }
}

function shellQuote(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}

/**
 * @returns {{ call, testmempoolaccept, sendrawtransaction, getrawtransaction, getblockcount }}
 */
export function createChipnetRpc({
  host = 'layer1-node',
  conf = '/etc/bchn/bitcoin.conf',
} = {}) {
  function call(method, params = []) {
    const tokens = params.map((p) => (
      typeof p === 'string' || typeof p === 'number' || typeof p === 'boolean'
        ? shellQuote(String(p))
        : shellQuote(JSON.stringify(p))
    ));
    const remote = [
      'sudo -n -u bchn /usr/local/bin/bitcoin-cli',
      `-conf=${conf}`,
      method,
      ...tokens,
    ].join(' ');
    let out;
    try {
      out = execFileSync('ssh', ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=30', '-o', 'LogLevel=ERROR', host, remote], {
        encoding: 'utf8',
        maxBuffer: 32 * 1024 * 1024,
      });
    } catch (e) {
      throw new ChipnetRpcError(`${method} failed: ${e.stderr || e.message}`);
    }
    const t = out.trim();
    if (!t) return null;
    try { return JSON.parse(t); } catch { return t.replace(/^"|"$/g, ''); }
  }

  async function testmempoolaccept(hexes) {
    return call('testmempoolaccept', [hexes]);
  }

  async function sendrawtransaction(hex) {
    const txid = call('sendrawtransaction', [hex]);
    if (typeof txid !== 'string' || !/^[0-9a-f]{64}$/i.test(txid)) {
      throw new ChipnetRpcError(`sendrawtransaction bad txid: ${txid}`);
    }
    return txid.toLowerCase();
  }

  return Object.freeze({
    call,
    testmempoolaccept,
    sendrawtransaction,
    getrawtransaction: (txid, verbose = true) => call('getrawtransaction', [txid, verbose]),
    getblockcount: () => call('getblockcount'),
  });
}

/** Network gate bound to real Chipnet RPC (or throw if V2_CHIPNET_LIVE not set). */
export function createLiveNetworkGate() {
  if (process.env.V2_CHIPNET_LIVE !== '1' && process.env.V2_CHIPNET_LIVE !== 'true') {
    throw new ChipnetRpcError(
      'Live broadcast requires V2_CHIPNET_LIVE=1 (refusing fake/local always-allow gate)',
    );
  }
  const rpc = createChipnetRpc();
  return Object.freeze({
    rpc,
    async broadcastRawTransaction(txHex) {
      const { createNetworkGate } = await import('../network-gate.mjs');
      const gate = createNetworkGate(rpc);
      return gate.broadcastRawTransaction(txHex, { testFirst: true });
    },
  });
}
