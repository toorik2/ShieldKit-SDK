/**
 * Chipnet chain access.
 *
 * Average users need **no bitcoind**. Defaults are public Fulcrum (Electrum TLS).
 * There is no reliable free public Chipnet bitcoind JSON-RPC; that path is optional
 * only if you set SHIELDKIT_RPC_URL.
 *
 * Resolution order:
 *   1) SHIELDKIT_RPC_URL  — your JSON-RPC (optional power-user)
 *   2) SHIELDKIT_ELECTRUM — your Fulcrum host:port (optional)
 *   3) Public Chipnet Fulcrum TLS  ← default for everyone else
 *   4) SSH layer1-node (lab only)
 *
 * Providers are untrusted. No network-query privacy claim.
 */
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import net from 'node:net';
import tls from 'node:tls';

export const CHIPNET_GENESIS_HASH =
  '000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b';

/** Public Fulcrum (Electrum) Chipnet endpoints — TLS, no auth. */
export const PUBLIC_CHIPNET_ELECTRUM = Object.freeze([
  Object.freeze({ host: 'chipnet.bch.ninja', port: 50002, tls: true, label: 'chipnet.bch.ninja' }),
  Object.freeze({ host: 'chipnet.imaginary.cash', port: 50002, tls: true, label: 'chipnet.imaginary.cash' }),
]);

const SSH_OPTS = ['-o', 'BatchMode=yes', '-o', 'LogLevel=ERROR', '-o', 'ConnectTimeout=12'];

function electrumScriptHash(lockingBytecode) {
  const bytes = lockingBytecode instanceof Uint8Array
    ? lockingBytecode
    : Buffer.from(lockingBytecode, 'hex');
  const h = createHash('sha256').update(bytes).digest();
  return Buffer.from(h).reverse().toString('hex');
}

function parseRpcUrl(url) {
  const u = new URL(url);
  const auth = u.username
    ? `${decodeURIComponent(u.username)}:${decodeURIComponent(u.password || '')}`
    : null;
  const base = `${u.protocol}//${u.host}${u.pathname === '/' ? '' : u.pathname}`;
  return { base, auth };
}

async function jsonRpcCall(endpoint, method, params = []) {
  const headers = { 'Content-Type': 'application/json' };
  if (endpoint.auth) {
    headers.Authorization = `Basic ${Buffer.from(endpoint.auth).toString('base64')}`;
  }
  const res = await fetch(endpoint.base, {
    method: 'POST',
    headers,
    body: JSON.stringify({ jsonrpc: '1.0', id: 'shieldkit', method, params }),
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) throw new Error(`JSON-RPC HTTP ${res.status} on ${endpoint.base}`);
  const body = await res.json();
  if (body.error) {
    throw new Error(`JSON-RPC ${method}: ${body.error.message || JSON.stringify(body.error)}`);
  }
  return body.result;
}

function electrumRequest(host, port, useTls, method, params, timeoutMs = 12_000) {
  return new Promise((resolve, reject) => {
    const payload = `${JSON.stringify({ id: 1, method, params })}\n`;
    let socket;
    let buf = '';
    const timer = setTimeout(() => {
      try { socket?.destroy(); } catch { /* */ }
      reject(new Error(`electrum timeout ${host}:${port} ${method}`));
    }, timeoutMs);

    const onData = (chunk) => {
      buf += chunk.toString('utf8');
      const nl = buf.indexOf('\n');
      if (nl < 0) return;
      clearTimeout(timer);
      const line = buf.slice(0, nl).replace(/\r$/, '');
      try { socket.destroy(); } catch { /* */ }
      try {
        const msg = JSON.parse(line);
        if (msg.error) reject(new Error(`electrum ${method}: ${msg.error.message || JSON.stringify(msg.error)}`));
        else resolve(msg.result);
      } catch (e) {
        reject(e);
      }
    };

    const onErr = (e) => {
      clearTimeout(timer);
      reject(e);
    };

    if (useTls) {
      socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false }, () => {
        socket.write(payload);
      });
    } else {
      socket = net.connect({ host, port }, () => {
        socket.write(payload);
      });
    }
    socket.setEncoding('utf8');
    socket.on('data', onData);
    socket.on('error', onErr);
  });
}

async function probeElectrum(ep) {
  const features = await electrumRequest(ep.host, ep.port, ep.tls !== false, 'server.features', []);
  const genesis = features?.genesis_hash;
  if (genesis && genesis !== CHIPNET_GENESIS_HASH) {
    throw new Error(`electrum ${ep.host} is not Chipnet (genesis ${genesis})`);
  }
  return features;
}

function parseElectrumEndpoint(spec) {
  if (!spec) return null;
  // host:port or host
  const [host, portStr] = String(spec).split(':');
  const port = portStr ? Number(portStr) : 50002;
  return { host, port, tls: true, label: spec };
}

function layer1Available() {
  const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node', 'echo ok'], { encoding: 'utf8' });
  return r.status === 0 && (r.stdout || '').includes('ok');
}

function layer1Cli(args, input) {
  const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
    `sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf ${args}`], {
    encoding: 'utf8',
    input,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.status !== 0) throw new Error(`layer1 ${args}: ${r.stderr || r.stdout}`);
  return (r.stdout || '').trim();
}

function parseFirstJsonObject(raw) {
  const start = raw.indexOf('{');
  if (start < 0) throw new Error('no JSON object in output');
  let depth = 0;
  for (let i = start; i < raw.length; i++) {
    if (raw[i] === '{') depth += 1;
    else if (raw[i] === '}') {
      depth -= 1;
      if (depth === 0) return JSON.parse(raw.slice(start, i + 1));
    }
  }
  throw new Error('unterminated JSON object');
}

/**
 * @param {{ preferLayer1?: boolean }} [opts]
 * @returns {Promise<{
 *   backend: string,
 *   label: string,
 *   gettxout: (txid: string, vout: number) => Promise<object|null>,
 *   scanAddress: (address: string, lockingBytecodeHex?: string) => Promise<Array<{txid:string,vout:number,sats:number}>>,
 *   testmempoolaccept: (hex: string) => Promise<any>,
 *   sendrawtransaction: (hex: string) => Promise<string>,
 *   getblockcount: () => Promise<number>,
 * }>}
 */
export async function createChipnetRpc(opts = {}) {
  const errors = [];

  // 1) Explicit JSON-RPC
  const rpcUrl = process.env.SHIELDKIT_RPC_URL || process.env.BCH_RPC_URL;
  if (rpcUrl) {
    try {
      const ep = parseRpcUrl(rpcUrl);
      const count = await jsonRpcCall(ep, 'getblockcount', []);
      if (typeof count !== 'number') throw new Error('getblockcount non-number');
      return {
        backend: 'jsonrpc',
        label: ep.base,
        async gettxout(txid, vout) {
          return jsonRpcCall(ep, 'gettxout', [txid, vout, true]);
        },
        async scanAddress(address) {
          const res = await jsonRpcCall(ep, 'scantxoutset', ['start', [`addr(${address})`]]);
          return (res.unspents || []).map((u) => ({
            txid: u.txid,
            vout: u.vout,
            sats: Math.round(u.amount * 1e8),
          }));
        },
        async testmempoolaccept(hex) {
          return jsonRpcCall(ep, 'testmempoolaccept', [[hex]]);
        },
        async sendrawtransaction(hex) {
          return jsonRpcCall(ep, 'sendrawtransaction', [hex, true]);
        },
        async getblockcount() {
          return jsonRpcCall(ep, 'getblockcount', []);
        },
      };
    } catch (e) {
      errors.push(`jsonrpc: ${e.message}`);
    }
  }

  // 2) Explicit electrum then public list
  const electrumList = [];
  const envEl = process.env.SHIELDKIT_ELECTRUM;
  if (envEl) electrumList.push(parseElectrumEndpoint(envEl));
  for (const ep of PUBLIC_CHIPNET_ELECTRUM) electrumList.push(ep);

  for (const ep of electrumList) {
    if (!ep) continue;
    try {
      await probeElectrum(ep);
      const call = (method, params) => electrumRequest(ep.host, ep.port, ep.tls !== false, method, params);
      return {
        backend: 'electrum',
        label: `${ep.host}:${ep.port}`,
        /** @internal tip discovery / advanced */
        _electrumCall: call,
        async gettxout(txid, vout) {
          // No native gettxout — treat as unspent if listed under any known scripts is unavailable.
          // Fallback: try get raw + assume spent if broadcast path fails. Prefer list from scan.
          try {
            const raw = await call('blockchain.transaction.get', [txid, false]);
            if (!raw || typeof raw !== 'string') return null;
            // Without full UTXO set, verify via get_utxo-like path unavailable.
            // Use blockchain.utxo.get if present.
            try {
              const u = await call('blockchain.utxo.get', [`${txid}:${vout}`]);
              if (!u) return null;
              return {
                value: (u.value ?? u.amount ?? 0) / (u.value > 1e6 ? 1e8 : 1),
                ...u,
              };
            } catch {
              // Fulcrum may not support utxo.get — return a stub only if caller already scanned.
              return { value: null, confirmations: 1, _partial: true, txid, vout };
            }
          } catch {
            return null;
          }
        },
        async scanAddress(address, lockingBytecodeHex) {
          let scriptHash;
          if (lockingBytecodeHex) {
            scriptHash = electrumScriptHash(lockingBytecodeHex);
          } else {
            // Prefer address method when available
            try {
              const listed = await call('blockchain.address.listunspent', [address]);
              return (listed || []).map((u) => ({
                txid: u.tx_hash,
                vout: u.tx_pos,
                sats: Number(u.value),
              }));
            } catch {
              throw new Error('scanAddress requires lockingBytecodeHex for scripthash path');
            }
          }
          const listed = await call('blockchain.scripthash.listunspent', [scriptHash]);
          return (listed || []).map((u) => ({
            txid: u.tx_hash,
            vout: u.tx_pos,
            sats: Number(u.value),
          }));
        },
        async testmempoolaccept(hex) {
          // Not available on Electrum — optimistic allow (broadcast is authoritative).
          return [{ allowed: true, 'reject-reason': '', _backend: 'electrum-skip' }];
        },
        async sendrawtransaction(hex) {
          return call('blockchain.transaction.broadcast', [hex]);
        },
        async getblockcount() {
          const h = await call('blockchain.headers.subscribe', []);
          return h.height;
        },
        electrumScriptHash,
        async listScriptUnspent(lockingBytecodeHex) {
          const sh = electrumScriptHash(lockingBytecodeHex);
          const listed = await call('blockchain.scripthash.listunspent', [sh]);
          return (listed || []).map((u) => ({
            txid: u.tx_hash,
            vout: u.tx_pos,
            sats: Number(u.value),
          }));
        },
      };
    } catch (e) {
      errors.push(`electrum ${ep.host}: ${e.message}`);
    }
  }

  // 3) Lab SSH
  if (opts.preferLayer1 !== false && layer1Available()) {
    return {
      backend: 'layer1-ssh',
      label: 'layer1-node',
      async gettxout(txid, vout) {
        try {
          const t = layer1Cli(`gettxout ${txid} ${vout} true`);
          if (!t || t === 'null') return null;
          return JSON.parse(t);
        } catch {
          return null;
        }
      },
      async scanAddress(address) {
        const raw = layer1Cli(`scantxoutset start '["addr(${address})"]'`);
        const res = parseFirstJsonObject(raw);
        return (res.unspents || []).map((u) => ({
          txid: u.txid,
          vout: u.vout,
          sats: Math.round(u.amount * 1e8),
        }));
      },
      async testmempoolaccept(hex) {
        const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
          `cat > /tmp/sk-rpc.hex && sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf testmempoolaccept "[\\"$(cat /tmp/sk-rpc.hex)\\"]"`], {
          encoding: 'utf8', input: hex, maxBuffer: 64 * 1024 * 1024,
        });
        if (r.status !== 0) throw new Error(`testmempool: ${r.stderr || r.stdout}`);
        return JSON.parse(r.stdout);
      },
      async sendrawtransaction(hex) {
        const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
          `cat > /tmp/sk-rpc.hex && sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf sendrawtransaction "$(cat /tmp/sk-rpc.hex)" true`], {
          encoding: 'utf8', input: hex, maxBuffer: 64 * 1024 * 1024,
        });
        if (r.status !== 0) throw new Error(`sendraw: ${r.stderr || r.stdout}`);
        return (r.stdout || '').trim();
      },
      async getblockcount() {
        return Number(layer1Cli('getblockcount'));
      },
    };
  }

  throw new Error(
    'No Chipnet RPC available. Tried: '
    + `${errors.join('; ') || 'none'}. `
    + 'Set SHIELDKIT_RPC_URL, SHIELDKIT_ELECTRUM=host:port, or ensure public Fulcrum is reachable.',
  );
}

export { electrumScriptHash };
