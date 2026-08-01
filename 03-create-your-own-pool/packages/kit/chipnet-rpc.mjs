/**
 * Chain access (chipnet default, mainnet via config).
 *
 * Average users need **no bitcoind**. Defaults are public Fulcrum (Electrum TLS).
 * JSON-RPC path optional via SHIELDKIT_RPC_URL.
 *
 * Resolution order:
 *   1) SHIELDKIT_RPC_URL  — your JSON-RPC (optional power-user)
 *   2) SHIELDKIT_ELECTRUM — your Fulcrum host:port (optional)
 *   3) Public Fulcrum TLS for the selected network  ← default
 *   4) SSH layer1-node (lab chipnet only)
 *
 * Providers are untrusted. No network-query privacy claim.
 */
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import {
  chmodSync, lstatSync, mkdirSync, realpathSync,
} from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import tls from 'node:tls';

export const CHIPNET_GENESIS_HASH =
  '000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b';

/** Bitcoin Cash mainnet genesis (Block 0). */
export const MAINNET_GENESIS_HASH =
  '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f';

/** Public Fulcrum (Electrum) Chipnet endpoints — TLS, no auth. */
export const PUBLIC_CHIPNET_ELECTRUM = Object.freeze([
  Object.freeze({ host: 'chipnet.bch.ninja', port: 50002, tls: true, label: 'chipnet.bch.ninja' }),
  Object.freeze({ host: 'chipnet.imaginary.cash', port: 50002, tls: true, label: 'chipnet.imaginary.cash' }),
]);

/** Public Fulcrum (Electrum) mainnet endpoints — TLS, no auth. */
export const PUBLIC_MAINNET_ELECTRUM = Object.freeze([
  Object.freeze({ host: 'electrum.imaginary.cash', port: 50002, tls: true, label: 'electrum.imaginary.cash' }),
  Object.freeze({ host: 'bch.imaginary.cash', port: 50002, tls: true, label: 'bch.imaginary.cash' }),
  Object.freeze({ host: 'fulcrum.greyh.at', port: 50002, tls: true, label: 'fulcrum.greyh.at' }),
]);

function expectedGenesis(network) {
  return network === 'mainnet' ? MAINNET_GENESIS_HASH : CHIPNET_GENESIS_HASH;
}

function publicElectrumFor(network) {
  return network === 'mainnet' ? PUBLIC_MAINNET_ELECTRUM : PUBLIC_CHIPNET_ELECTRUM;
}

function privateSshControlOptions() {
  if (typeof process.getuid !== 'function') return [];
  const uid = process.getuid();
  const candidates = [
    process.env.XDG_RUNTIME_DIR,
    `/run/user/${uid}`,
  ].filter((value, index, values) => typeof value === 'string'
    && path.isAbsolute(value) && values.indexOf(value) === index);
  for (const runtimeDirectory of candidates) {
    try {
      const root = lstatSync(runtimeDirectory);
      if (!root.isDirectory() || root.isSymbolicLink() || root.uid !== uid
        || (root.mode & 0o077) !== 0 || realpathSync(runtimeDirectory) !== runtimeDirectory) continue;
      const shieldkitDirectory = path.join(runtimeDirectory, 'shieldkit');
      const directory = path.join(shieldkitDirectory, 'ssh');
      for (const candidate of [shieldkitDirectory, directory]) {
        try { mkdirSync(candidate, { mode: 0o700 }); }
        catch (error) { if (error?.code !== 'EEXIST') throw error; }
        const beforeModeFix = lstatSync(candidate);
        if (!beforeModeFix.isDirectory() || beforeModeFix.isSymbolicLink()
          || beforeModeFix.uid !== uid || realpathSync(candidate) !== candidate) throw new Error('unsafe SSH control directory');
        if ((beforeModeFix.mode & 0o777) !== 0o700) chmodSync(candidate, 0o700);
        const inspected = lstatSync(candidate);
        if (!inspected.isDirectory() || inspected.isSymbolicLink()
          || inspected.uid !== uid || (inspected.mode & 0o077) !== 0
          || realpathSync(candidate) !== candidate) throw new Error('unsafe SSH control directory');
      }
      return [
        '-o', 'ControlMaster=auto',
        '-o', 'ControlPersist=120',
        '-o', `ControlPath=${path.join(directory, 'layer1-%C')}`,
      ];
    } catch { /* fall back to independent SSH connections */ }
  }
  return [];
}

const SSH_OPTS = [
  '-o', 'BatchMode=yes',
  '-o', 'LogLevel=ERROR',
  '-o', 'ConnectTimeout=12',
  ...privateSshControlOptions(),
];

function electrumScriptHash(lockingBytecode) {
  const bytes = lockingBytecode instanceof Uint8Array
    ? lockingBytecode
    : Buffer.from(lockingBytecode, 'hex');
  const h = createHash('sha256').update(bytes).digest();
  return Buffer.from(h).reverse().toString('hex');
}

function parseRpcUrl(url) {
  const u = new URL(url);
  const loopback = new Set(['127.0.0.1', '::1', 'localhost']);
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && loopback.has(u.hostname))) {
    throw new Error('SHIELDKIT_RPC_URL must use HTTPS unless it targets loopback');
  }
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
      socket = tls.connect({ host, port, servername: host, rejectUnauthorized: true }, () => {
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

async function probeElectrum(ep, network = 'chipnet') {
  const features = await electrumRequest(ep.host, ep.port, ep.tls !== false, 'server.features', []);
  const genesis = features?.genesis_hash;
  const want = expectedGenesis(network);
  if (genesis && genesis !== want) {
    throw new Error(
      `electrum ${ep.host} genesis ${genesis?.slice?.(0, 16) || genesis} ≠ ${network} (${want.slice(0, 16)}…)`,
    );
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

const LAYER1_METHODS = new Set([
  'getblockhash',
  // Generic createChainRpc compatibility only. The authenticated V2 product
  // capability below deliberately does not expose or call this method.
  'getblockcount',
  'getrawtransaction',
  'gettxout',
  'scantxoutset',
  'sendrawtransaction',
  'testmempoolaccept',
]);
const PRODUCT_RPC_METHODS = Object.freeze([
  'getblockhash', 'getrawtransaction', 'gettxout', 'scantxoutset',
  'sendrawtransaction', 'testmempoolaccept',
]);
const TXID = /^[0-9a-f]{64}$/;
const HEX = /^(?:[0-9a-f]{2})+$/;
const ADDRESS = /^(?:bitcoincash|bchtest):[a-z0-9]{20,120}$/;
const layer1BchnChipnetCapabilities = new WeakSet();

/** Exact backend label for the BCHN-only Chipnet capability. */
export const LAYER1_BCHN_CHIPNET_BACKEND = 'layer1-bchn-chipnet';

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\"'\"'")}'`;
}

function validateLayer1Arguments(method, args) {
  if (!LAYER1_METHODS.has(method)) throw new Error(`layer1 method refused: ${method}`);
  if (method === 'getblockhash') {
    if (args.length !== 1 || args[0] !== 0) {
      throw new Error('getblockhash accepts only Chipnet genesis height 0');
    }
    return;
  }
  if (method === 'getblockcount') {
    if (args.length !== 0) throw new Error('getblockcount accepts no arguments');
    return;
  }
  if (method === 'gettxout') {
    if (args.length !== 3 || !TXID.test(args[0])
      || !Number.isSafeInteger(Number(args[1])) || Number(args[1]) < 0
      || args[2] !== true) throw new Error('invalid gettxout arguments');
    return;
  }
  if (method === 'getrawtransaction') {
    if (args.length !== 2 || !TXID.test(args[0]) || typeof args[1] !== 'boolean') {
      throw new Error('invalid getrawtransaction arguments');
    }
    return;
  }
  if (method === 'scantxoutset') {
    if (args.length !== 2 || args[0] !== 'start' || !ADDRESS.test(args[1])) {
      throw new Error('invalid scantxoutset arguments');
    }
    return;
  }
  if (method === 'sendrawtransaction') {
    if (args.length !== 2 || !HEX.test(args[0]) || args[1] !== true) {
      throw new Error('invalid sendrawtransaction arguments');
    }
    return;
  }
  if (method === 'testmempoolaccept') {
    if (args.length !== 1 || !HEX.test(args[0])) throw new Error('invalid testmempoolaccept arguments');
  }
}

async function layer1Cli(method, args = []) {
  validateLayer1Arguments(method, args);
  const rpcArgs = method === 'scantxoutset'
    ? ['start', JSON.stringify([`addr(${args[1]})`])]
    : method === 'testmempoolaccept'
      ? [JSON.stringify([args[0]])]
      : args.map(String);
  // Linux limits each argv element to roughly 128 KiB. A standard V2 action
  // is almost 100 KiB, so its hex is almost 200 KiB and cannot safely be
  // embedded in the single SSH remote-command argument. bitcoin-cli -stdin
  // accepts one RPC argument per line and keeps those bytes out of argv.
  const streamRpcArgs = method === 'testmempoolaccept'
    || method === 'sendrawtransaction';
  const command = [
    'sudo', '-n', '-u', 'bchn',
    '/usr/local/bin/bitcoin-cli',
    '-conf=/etc/bchn/bitcoin.conf',
    ...(streamRpcArgs ? ['-stdin'] : []),
    method,
    ...(streamRpcArgs ? [] : rpcArgs),
  ].map(shellQuote).join(' ');
  const maximumOutputBytes = 64 * 1024 * 1024;
  const child = spawn('ssh', [...SSH_OPTS, 'layer1-node', command], {
    shell: false,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const stdout = [];
  const stderr = [];
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let outputExceeded = false;
  const collect = (target, chunk, kind) => {
    if (outputExceeded) return;
    if (kind === 'stdout') stdoutBytes += chunk.length;
    else stderrBytes += chunk.length;
    if (stdoutBytes > maximumOutputBytes || stderrBytes > maximumOutputBytes) {
      outputExceeded = true;
      child.kill('SIGKILL');
      return;
    }
    target.push(Buffer.from(chunk));
  };
  child.stdout.on('data', (chunk) => collect(stdout, chunk, 'stdout'));
  child.stderr.on('data', (chunk) => collect(stderr, chunk, 'stderr'));
  const timeout = setTimeout(() => child.kill('SIGKILL'), 30_000);
  if (streamRpcArgs) child.stdin.end(`${rpcArgs.join('\n')}\n`);
  else child.stdin.end();
  let terminal;
  try {
    terminal = await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (code, signal) => resolve({ code, signal }));
    });
  } catch (error) {
    throw new Error(`layer1 ${method} transport: ${error.message}`);
  } finally {
    clearTimeout(timeout);
  }
  const output = Buffer.concat(stdout).toString('utf8');
  const errorOutput = Buffer.concat(stderr).toString('utf8');
  if (outputExceeded) throw new Error(`layer1 ${method}: RPC output exceeded the 64 MiB limit`);
  if (terminal.code !== 0 || terminal.signal !== null) {
    throw new Error(`layer1 ${method}: ${String(errorOutput || output || `remote command failed (${terminal.signal ?? `exit ${terminal.code}`})`).slice(0, 2000)}`);
  }
  return output.trim();
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

function parseLayer1ChipnetGenesis(value) {
  const genesis = String(value).trim().toLowerCase();
  if (!TXID.test(genesis)) {
    throw new Error('layer1 BCHN getblockhash(0) returned a malformed hash');
  }
  if (genesis !== CHIPNET_GENESIS_HASH) {
    throw new Error(
      `layer1-node BCHN is not Chipnet: genesis ${genesis} differs from ${CHIPNET_GENESIS_HASH}`,
    );
  }
  return genesis;
}

function layer1BchnCall(executeLayer1Cli, method, args = []) {
  validateLayer1Arguments(method, args);
  return executeLayer1Cli(method, args);
}

async function createLayer1BchnChipnetRpcInternal({ executeLayer1Cli }) {
  if (typeof executeLayer1Cli !== 'function') {
    throw new Error('layer1 BCHN executor is required');
  }

  const methodCounts = Object.fromEntries(PRODUCT_RPC_METHODS.map((method) => [method, 0]));
  const call = async (method, args = []) => {
    if (!Object.hasOwn(methodCounts, method)) {
      throw new Error(`layer1 product method refused: ${method}`);
    }
    validateLayer1Arguments(method, args);
    methodCounts[method] += 1;
    return executeLayer1Cli(method, args);
  };

  // This is intentionally a direct BCHN network proof, rather than an SSH
  // availability probe. A reachable mainnet/regtest node must never acquire
  // this Chipnet capability.
  const genesis = parseLayer1ChipnetGenesis(
    await call('getblockhash', [0]),
  );
  const rpc = {
    backend: LAYER1_BCHN_CHIPNET_BACKEND,
    label: 'layer1-node BCHN Chipnet',
    network: 'chipnet',
    genesis,
    async getrawtransaction(txid, verbose = false) {
      const result = await call(
        'getrawtransaction',
        [String(txid).toLowerCase(), Boolean(verbose)],
      );
      return verbose ? JSON.parse(result) : String(result).trim();
    },
    async gettxout(txid, vout) {
      let result;
      try {
        result = await call(
          'gettxout',
          [String(txid).toLowerCase(), Number(vout), true],
        );
      } catch (error) {
        // BCHN returns null for a spent/missing output. Transport/RPC errors
        // remain errors so callers do not mistake an unavailable node for a
        // safely spent UTXO.
        throw error;
      }
      const text = String(result).trim();
      return text === 'null' ? null : JSON.parse(text);
    },
    async scanAddress(address) {
      const raw = await call(
        'scantxoutset',
        ['start', String(address)],
      );
      const result = parseFirstJsonObject(String(raw));
      if (!Array.isArray(result.unspents)) {
        throw new Error('layer1 BCHN scantxoutset returned no unspents array');
      }
      return result.unspents.map((entry, index) => {
        if (
          entry === null
          || typeof entry !== 'object'
          || !TXID.test(entry.txid)
          || !Number.isSafeInteger(entry.vout)
          || entry.vout < 0
          || typeof entry.amount !== 'number'
          || !Number.isFinite(entry.amount)
          || entry.amount < 0
        ) {
          throw new Error(`layer1 BCHN scantxoutset unspent ${index} is malformed`);
        }
        const sats = Math.round(entry.amount * 1e8);
        if (!Number.isSafeInteger(sats)) {
          throw new Error(`layer1 BCHN scantxoutset unspent ${index} amount is unsafe`);
        }
        return { txid: entry.txid, vout: entry.vout, sats };
      });
    },
    async testmempoolaccept(hex) {
      // This calls BCHN directly. Unlike the generic Electrum compatibility
      // handle, it never synthesizes an optimistic acceptance response.
      return JSON.parse(await call(
        'testmempoolaccept',
        [String(hex).toLowerCase()],
      ));
    },
    async sendrawtransaction(hex) {
      return String(await call(
        'sendrawtransaction',
        [String(hex).toLowerCase(), true],
      )).trim();
    },
    observation() {
      return Object.freeze({
        backend: LAYER1_BCHN_CHIPNET_BACKEND,
        genesis,
        methodCounts: Object.freeze({ ...methodCounts }),
      });
    },
  };
  Object.freeze(rpc);
  layer1BchnChipnetCapabilities.add(rpc);
  return rpc;
}

/**
 * Create the real BCHN-only Chipnet capability over the fixed `layer1-node`
 * SSH route. It neither reads SHIELDKIT_RPC_URL nor tries Electrum, and it
 * verifies BCHN's actual genesis hash before returning any send capability.
 */
export async function createLayer1BchnChipnetRpc() {
  return createLayer1BchnChipnetRpcInternal({
    executeLayer1Cli: layer1Cli,
  });
}

/**
 * Test-only seam for the BCHN-only capability. Production callers must use
 * createLayer1BchnChipnetRpc(), which fixes the transport to layer1-node.
 */
export async function createLayer1BchnChipnetRpcForTest({
  executeLayer1Cli,
} = {}) {
  return createLayer1BchnChipnetRpcInternal({ executeLayer1Cli });
}

/** Require a capability created by the fixed layer1-node BCHN constructor. */
export function assertLayer1BchnChipnetRpc(value) {
  if (value === null || typeof value !== 'object'
    || !layer1BchnChipnetCapabilities.has(value)) {
    throw new Error('a real layer1-node BCHN Chipnet RPC capability is required');
  }
  return value;
}

/** Return a frozen, secret-free exact transport observation for the branded product RPC. */
export function observeLayer1BchnChipnetRpc(value) {
  const rpc = assertLayer1BchnChipnetRpc(value);
  if (typeof rpc.observation !== 'function') {
    throw new Error('layer1 BCHN Chipnet observation capability is unavailable');
  }
  return rpc.observation();
}

/**
 * @param {{ preferLayer1?: boolean, network?: 'chipnet'|'mainnet' }} [opts]
 * @returns {Promise<{
 *   backend: string,
 *   label: string,
 *   network: string,
 *   getrawtransaction: (txid: string, verbose?: boolean) => Promise<string|object>,
 *   gettxout: (txid: string, vout: number) => Promise<object|null>,
 *   scanAddress: (address: string, lockingBytecodeHex?: string) => Promise<Array<{txid:string,vout:number,sats:number}>>,
 *   testmempoolaccept: (hex: string) => Promise<any>,
 *   sendrawtransaction: (hex: string) => Promise<string>,
 *   getblockcount: () => Promise<number>,
 * }>}
 */
export async function createChainRpc(opts = {}) {
  const network = opts.network === 'mainnet' ? 'mainnet' : 'chipnet';
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
        network,
        async getrawtransaction(txid, verbose = false) {
          return jsonRpcCall(ep, 'getrawtransaction', [txid, verbose]);
        },
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

  // 2) Explicit electrum then public list for selected network
  const electrumList = [];
  const envEl = process.env.SHIELDKIT_ELECTRUM;
  if (envEl) electrumList.push(parseElectrumEndpoint(envEl));
  for (const ep of publicElectrumFor(network)) electrumList.push(ep);

  for (const ep of electrumList) {
    if (!ep) continue;
    try {
      await probeElectrum(ep, network);
      const call = (method, params) => electrumRequest(ep.host, ep.port, ep.tls !== false, method, params);
      return {
        backend: 'electrum',
        label: `${ep.host}:${ep.port}`,
        network,
        /** @internal tip discovery / advanced */
        _electrumCall: call,
        async getrawtransaction(txid, verbose = false) {
          return call('blockchain.transaction.get', [txid, verbose]);
        },
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

  // 3) Lab SSH (chipnet only — layer1-node is Chipnet BCHN)
  if (network === 'chipnet' && opts.preferLayer1 !== false && layer1Available()) {
    return {
      backend: 'layer1-ssh',
      label: 'layer1-node',
      network: 'chipnet',
      async getrawtransaction(txid, verbose = false) {
        const result = await layer1Cli(
          'getrawtransaction',
          [String(txid).toLowerCase(), Boolean(verbose)],
        );
        return verbose ? JSON.parse(result) : result;
      },
      async gettxout(txid, vout) {
        try {
          const t = await layer1Cli('gettxout', [String(txid).toLowerCase(), Number(vout), true]);
          if (!t || t === 'null') return null;
          return JSON.parse(t);
        } catch {
          return null;
        }
      },
      async scanAddress(address) {
        const raw = await layer1Cli('scantxoutset', ['start', address]);
        const res = parseFirstJsonObject(raw);
        return (res.unspents || []).map((u) => ({
          txid: u.txid,
          vout: u.vout,
          sats: Math.round(u.amount * 1e8),
        }));
      },
      async testmempoolaccept(hex) {
        return JSON.parse(await layer1Cli('testmempoolaccept', [String(hex).toLowerCase()]));
      },
      async sendrawtransaction(hex) {
        return layer1Cli('sendrawtransaction', [String(hex).toLowerCase(), true]);
      },
      async getblockcount() {
        return Number(await layer1Cli('getblockcount', []));
      },
    };
  }

  throw new Error(
    `No ${network} RPC available. Tried: `
    + `${errors.join('; ') || 'none'}. `
    + 'Set SHIELDKIT_RPC_URL, SHIELDKIT_ELECTRUM=host:port, or ensure public Fulcrum is reachable.',
  );
}

/** @deprecated use createChainRpc({ network: 'chipnet' }) — alias kept for callers */
export async function createChipnetRpc(opts = {}) {
  return createChainRpc({ ...opts, network: opts.network || 'chipnet' });
}

export { electrumScriptHash };
