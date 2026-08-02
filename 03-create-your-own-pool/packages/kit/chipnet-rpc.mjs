/**
 * Chain access transports.
 *
 * The V2 beta end-user product is fixed to two pinned public Chipnet Fulcrum
 * TLS providers. It accepts no provider URL, username, password, or SSH option.
 * Providers are untrusted, every relevant response is checked against exact
 * transaction bytes locally, and no network-query privacy claim is made.
 *
 * The older `createChainRpc` compatibility API later in this module separately
 * supports optional operator JSON-RPC, custom Electrum, and lab-only SSH. None
 * of those resolution paths is reachable from the V2 beta product constructor.
 */
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import {
  chmodSync, lstatSync, mkdirSync, realpathSync,
} from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import tls from 'node:tls';

import {
  parseSerializedSourceOutput,
  parseV2RawTransaction,
} from './v2/transaction-policy.mjs';

export const CHIPNET_GENESIS_HASH =
  '000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b';

/** Bitcoin Cash mainnet genesis (Block 0). */
export const MAINNET_GENESIS_HASH =
  '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f';

/** Public Fulcrum (Electrum) Chipnet endpoints — TLS, no auth. */
export const PUBLIC_CHIPNET_ELECTRUM = Object.freeze([
  // Ordered roles: the first provider receives the sole broadcast; the
  // second independently attests exact raw bytes and the successor output.
  Object.freeze({ host: 'chipnet.imaginary.cash', port: 50002, tls: true, label: 'chipnet.imaginary.cash' }),
  Object.freeze({ host: 'chipnet.bch.ninja', port: 50002, tls: true, label: 'chipnet.bch.ninja' }),
]);

const PUBLIC_ELECTRUM_CONNECT_TIMEOUT_MS = 12_000;
const PUBLIC_ELECTRUM_MAX_INFLIGHT_REQUESTS = 32;
const PUBLIC_ELECTRUM_POST_BROADCAST_READBACK_ATTEMPTS = 25;
const PUBLIC_ELECTRUM_POST_BROADCAST_READBACK_DELAY_MS = 200;
// A standard V2 transaction is at most 100,000 bytes (200,000 hexadecimal
// characters). Keep ample JSON overhead without allowing an untrusted server
// to grow an unterminated response line without bound.
const PUBLIC_ELECTRUM_MAX_RESPONSE_LINE_CHARACTERS = 4 * 1024 * 1024;

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

const SSH_BASE_OPTIONS = Object.freeze([
  '-o', 'BatchMode=yes',
  '-o', 'LogLevel=ERROR',
  '-o', 'ConnectTimeout=12',
]);
let cachedLayer1SshOptions;

// Do not probe, create, or chmod an SSH control directory while loading the
// product's public-provider transport. This runs only at the point an explicit
// layer1 SSH call is about to be made, then keeps that private configuration
// stable for the process.
function layer1SshOptions() {
  if (cachedLayer1SshOptions === undefined) {
    cachedLayer1SshOptions = Object.freeze([
      ...SSH_BASE_OPTIONS,
      ...privateSshControlOptions(),
    ]);
  }
  return cachedLayer1SshOptions;
}

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
  const r = spawnSync('ssh', [...layer1SshOptions(), 'layer1-node', 'echo ok'], { encoding: 'utf8' });
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
// Exact on-the-wire requests made to the pinned public-provider transport.
// These are intentionally separate from PRODUCT_RPC_METHODS, which is a
// stable logical route vocabulary retained by the product journal/evidence.
export const PUBLIC_CHIPNET_ELECTRUM_METHODS = Object.freeze([
  'server.features',
  'server.version',
  'blockchain.transaction.broadcast',
  'blockchain.transaction.get',
  'blockchain.utxo.get_info',
  'blockchain.scripthash.listunspent',
]);
const TXID = /^[0-9a-f]{64}$/;
const HEX = /^(?:[0-9a-f]{2})+$/;

function transactionIdFromRawHex(rawTransactionHex) {
  const first = createHash('sha256')
    .update(Buffer.from(rawTransactionHex, 'hex'))
    .digest();
  return createHash('sha256')
    .update(first)
    .digest()
    .reverse()
    .toString('hex');
}
const ADDRESS = /^(?:bitcoincash|bchtest):[a-z0-9]{20,120}$/;
// Product callers accept only capabilities constructed here. The V2 product
// uses the public TLS constructor below; the layer1 SSH constructor remains a
// deliberately separate lab-qualification transport.
const bchnChipnetCapabilities = new WeakSet();

/** Exact backend label for the BCHN-only Chipnet capability. */
export const LAYER1_BCHN_CHIPNET_BACKEND = 'layer1-bchn-chipnet';
export const BCHN_CHIPNET_BACKEND = 'bchn-chipnet-jsonrpc';

export function isBchnChipnetBackend(value) {
  return value === BCHN_CHIPNET_BACKEND || value === LAYER1_BCHN_CHIPNET_BACKEND
    || value === 'public-chipnet-fulcrum-tls';
}

/** True for an authenticated V2 product transport, regardless of provider. */
export const isChipnetProductBackend = isBchnChipnetBackend;

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

async function runLayer1Remote(command, stdin, label) {
  const maximumOutputBytes = 64 * 1024 * 1024;
  const child = spawn('ssh', [...layer1SshOptions(), 'layer1-node', command], {
    shell: false,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const stdout = [];
  const stderr = [];
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let outputExceeded = false;
  let inputError = null;
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
  // A connection that fails before SSH consumes the large transaction can
  // otherwise surface EPIPE as an unhandled stream error and terminate the
  // CLI instead of entering the caller's indeterminate recovery path.
  child.stdin.once('error', (error) => { inputError = error; });
  const timeout = setTimeout(() => child.kill('SIGKILL'), 30_000);
  child.stdin.end(stdin);
  let terminal;
  try {
    terminal = await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (code, signal) => resolve({ code, signal }));
    });
  } catch (error) {
    throw new Error(`layer1 ${label} transport: ${error.message}`);
  } finally {
    clearTimeout(timeout);
  }
  const output = Buffer.concat(stdout).toString('utf8');
  const errorOutput = Buffer.concat(stderr).toString('utf8');
  if (inputError !== null) {
    throw new Error(`layer1 ${label} transport input: ${inputError.message}`);
  }
  if (outputExceeded) throw new Error(`layer1 ${label}: RPC output exceeded the 64 MiB limit`);
  if (terminal.code !== 0 || terminal.signal !== null) {
    throw new Error(`layer1 ${label}: ${String(errorOutput || output || `remote command failed (${terminal.signal ?? `exit ${terminal.code}`})`).slice(0, 2000)}`);
  }
  return output.trim();
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
  return runLayer1Remote(
    command,
    streamRpcArgs ? `${rpcArgs.join('\n')}\n` : '',
    method,
  );
}

const SINGLE_PASS_SEPARATOR = '\u001e';

/**
 * One fixed SSH transport: one BCHN admission request followed by exact raw
 * and state readback on the same node. The transaction travels only on stdin.
 */
async function layer1SinglePassAdmission({
  expectedTransactionId,
  outputIndex,
  rawTransactionHex,
}) {
  if (!TXID.test(expectedTransactionId)
    || !HEX.test(rawTransactionHex)
    || !Number.isSafeInteger(outputIndex) || outputIndex < 0) {
    throw new Error('invalid single-pass admission arguments');
  }
  const cli = [
    'sudo', '-n', '-u', 'bchn',
    '/usr/local/bin/bitcoin-cli',
    '-conf=/etc/bchn/bitcoin.conf',
  ].map(shellQuote).join(' ');
  const command = [
    'set -eu',
    'IFS= read -r raw',
    'IFS= read -r expected',
    'IFS= read -r vout',
    `sent=$(printf '%s\\n%s\\n' "$raw" true | ${cli} -stdin sendrawtransaction)`,
    '[ "$sent" = "$expected" ]',
    `raw_json=$(${cli} getrawtransaction "$expected" true)`,
    `state_json=$(${cli} gettxout "$expected" "$vout" true)`,
    `printf '%s\\036%s\\036%s' "$sent" "$raw_json" "$state_json"`,
  ].join('; ');
  const output = await runLayer1Remote(
    command,
    `${rawTransactionHex}\n${expectedTransactionId}\n${outputIndex}\n`,
    'single-pass-admission',
  );
  const fields = output.split(SINGLE_PASS_SEPARATOR);
  if (fields.length !== 3 || fields[0] !== expectedTransactionId) {
    throw new Error('layer1 single-pass admission returned a malformed frame');
  }
  let rawTransaction;
  let stateOutput;
  try {
    rawTransaction = JSON.parse(fields[1]);
    stateOutput = JSON.parse(fields[2]);
  } catch (error) {
    throw new Error('layer1 single-pass admission returned malformed JSON', { cause: error });
  }
  return Object.freeze({
    transactionId: fields[0],
    rawTransaction,
    stateOutput,
  });
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

function parseBchnChipnetGenesis(value, label = 'BCHN') {
  const genesis = String(value).trim().toLowerCase();
  if (!TXID.test(genesis)) {
    throw new Error(`${label} getblockhash(0) returned a malformed hash`);
  }
  if (genesis !== CHIPNET_GENESIS_HASH) {
    throw new Error(
      `${label} is not Chipnet: genesis ${genesis} differs from ${CHIPNET_GENESIS_HASH}`,
    );
  }
  return genesis;
}

function layer1BchnCall(executeLayer1Cli, method, args = []) {
  validateLayer1Arguments(method, args);
  return executeLayer1Cli(method, args);
}

async function createLayer1BchnChipnetRpcInternal({
  executeLayer1Admission = undefined,
  executeLayer1Cli,
  backend = LAYER1_BCHN_CHIPNET_BACKEND,
  label = 'layer1-node BCHN Chipnet',
}) {
  if (typeof executeLayer1Cli !== 'function') {
    throw new Error('layer1 BCHN executor is required');
  }
  if (executeLayer1Admission !== undefined
    && typeof executeLayer1Admission !== 'function') {
    throw new Error('layer1 BCHN single-pass admission executor must be a function');
  }
  const executeAdmission = executeLayer1Admission ?? (async ({
    expectedTransactionId,
    outputIndex,
    rawTransactionHex,
  }) => {
    const transactionId = String(await executeLayer1Cli(
      'sendrawtransaction',
      [rawTransactionHex, true],
    )).trim();
    const [rawText, stateText] = await Promise.all([
      executeLayer1Cli('getrawtransaction', [expectedTransactionId, true]),
      executeLayer1Cli('gettxout', [expectedTransactionId, outputIndex, true]),
    ]);
    const rawTransaction = JSON.parse(rawText);
    return Object.freeze({
      transactionId,
      rawTransaction,
      stateOutput: stateText === '' || stateText === 'null'
        ? null
        : JSON.parse(stateText),
    });
  });

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
  const genesis = parseBchnChipnetGenesis(
    await call('getblockhash', [0]),
    label,
  );
  const rpc = {
    backend,
    label,
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
      return text === '' || text === 'null' ? null : JSON.parse(text);
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
    async submitV2SinglePassAdmission(rawTransactionHex, expectedTransactionId, outputIndex = 0) {
      const request = {
        rawTransactionHex: String(rawTransactionHex).toLowerCase(),
        expectedTransactionId: String(expectedTransactionId).toLowerCase(),
        outputIndex: Number(outputIndex),
      };
      if (!HEX.test(request.rawTransactionHex)
        || !TXID.test(request.expectedTransactionId)
        || !Number.isSafeInteger(request.outputIndex) || request.outputIndex < 0) {
        throw new Error('invalid single-pass admission arguments');
      }
      if (transactionIdFromRawHex(request.rawTransactionHex)
        !== request.expectedTransactionId) {
        throw new Error('single-pass admission transaction ID does not match the exact bytes');
      }
      // These counters describe the three requested BCHN operations in this
      // fixed transport. Only a fully validated successful result is eligible
      // for accepted-action evidence; failure counters are not forensic proof
      // of which remote command completed before a transport failure.
      methodCounts.sendrawtransaction += 1;
      methodCounts.getrawtransaction += 1;
      methodCounts.gettxout += 1;
      const result = await executeAdmission(request);
      if (result === null || Array.isArray(result) || typeof result !== 'object'
        || Object.keys(result).sort().join(',') !== 'rawTransaction,stateOutput,transactionId'
        || result.transactionId !== request.expectedTransactionId
        || result.rawTransaction === null || Array.isArray(result.rawTransaction)
        || typeof result.rawTransaction !== 'object'
        || Object.getPrototypeOf(result.rawTransaction) !== Object.prototype
        || result.rawTransaction.txid !== request.expectedTransactionId
        || result.rawTransaction.hex !== request.rawTransactionHex
        || (result.stateOutput !== null
          && (Array.isArray(result.stateOutput)
            || typeof result.stateOutput !== 'object'
            || Object.getPrototypeOf(result.stateOutput) !== Object.prototype))) {
        throw new Error('single-pass admission result is malformed');
      }
      return Object.freeze({
        transactionId: result.transactionId,
        rawTransaction: Object.freeze({ ...result.rawTransaction }),
        stateOutput: result.stateOutput === null
          ? null
          : Object.freeze({ ...result.stateOutput }),
      });
    },
    observation() {
      return Object.freeze({
        backend,
        genesis,
        methodCounts: Object.freeze({ ...methodCounts }),
      });
    },
  };
  Object.freeze(rpc);
  bchnChipnetCapabilities.add(rpc);
  return rpc;
}

/**
 * Create the real BCHN-only Chipnet capability over the fixed `layer1-node`
 * SSH route. It neither reads SHIELDKIT_RPC_URL nor tries Electrum, and it
 * verifies BCHN's actual genesis hash before returning any send capability.
 */
export async function createLayer1BchnChipnetRpc() {
  return createLayer1BchnChipnetRpcInternal({
    executeLayer1Admission: layer1SinglePassAdmission,
    executeLayer1Cli: layer1Cli,
  });
}

/**
 * Test-only seam for the BCHN-only capability. Production callers must use
 * createLayer1BchnChipnetRpc(), which fixes the transport to layer1-node.
 */
export async function createLayer1BchnChipnetRpcForTest({
  executeLayer1Admission = undefined,
  executeLayer1Cli,
} = {}) {
  return createLayer1BchnChipnetRpcInternal({
    executeLayer1Admission,
    executeLayer1Cli,
  });
}

/** Require a capability created by the fixed layer1-node BCHN constructor. */
export function assertLayer1BchnChipnetRpc(value) {
  return assertBchnChipnetRpc(value);
}

/** Return a frozen, secret-free exact transport observation for the branded product RPC. */
export function observeLayer1BchnChipnetRpc(value) {
  return observeBchnChipnetRpc(value);
}

/** Require a branded authenticated BCHN Chipnet capability, independent of transport. */
export function assertBchnChipnetRpc(value) {
  if (value === null || typeof value !== 'object' || !bchnChipnetCapabilities.has(value)) {
    throw new Error('a branded BCHN Chipnet RPC capability is required');
  }
  return value;
}

/** Return secret-free logical product request counts for a branded BCHN capability. */
export function observeBchnChipnetRpc(value) {
  const rpc = assertBchnChipnetRpc(value);
  if (typeof rpc.observation !== 'function') {
    throw new Error('BCHN Chipnet observation capability is unavailable');
  }
  return rpc.observation();
}

// V2 product-facing names intentionally do not imply that a public Fulcrum
// provider is a direct BCHN JSON-RPC node. The established BCHN aliases above
// remain for lab callers and persisted compatibility fixtures.
export function assertChipnetProductRpc(value) {
  return assertBchnChipnetRpc(value);
}

export function observeChipnetProductRpc(value) {
  return observeBchnChipnetRpc(value);
}

function electrumScriptHashFromLockingBytecode(lockingBytecodeHex) {
  if (typeof lockingBytecodeHex !== 'string' || !HEX.test(lockingBytecodeHex)) {
    throw new Error('Electrum output locking bytecode is malformed');
  }
  return Buffer.from(createHash('sha256').update(Buffer.from(lockingBytecodeHex, 'hex')).digest())
    .reverse().toString('hex');
}

/** One verified-TLS Electrum session, kept open for serial product requests. */
function openPublicElectrumSession(endpoint, connectTls = tls.connect) {
  if (endpoint?.tls !== true || typeof endpoint.host !== 'string'
    || !Number.isSafeInteger(endpoint.port) || endpoint.port < 1 || endpoint.port > 65535) {
    throw new Error('public Chipnet Electrum endpoint is invalid');
  }
  return new Promise((resolve, reject) => {
    const socket = connectTls({
      host: endpoint.host, port: endpoint.port, servername: endpoint.host,
      rejectUnauthorized: true,
    });
    let settled = false;
    let closed = false;
    let nextId = 1;
    let buffer = '';
    const pending = new Map();
    const close = (error) => {
      if (closed) return;
      closed = true;
      clearTimeout(connectTimer);
      if (!settled) { settled = true; reject(error); }
      for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(error); }
      pending.clear();
      try { socket.destroy(); } catch {}
    };
    const connectTimer = setTimeout(() => {
      close(new Error('public Chipnet Electrum TLS connection timed out'));
    }, PUBLIC_ELECTRUM_CONNECT_TIMEOUT_MS);
    socket.setEncoding('utf8');
    // Keep this listener after the TLS handshake: a transport loss after the
    // durable send boundary must reject every pending read, never strand a
    // request and never trigger a cross-provider rebroadcast.
    socket.on('error', close);
    socket.on('end', () => close(new Error('public Chipnet Electrum connection ended')));
    socket.on('close', () => close(new Error('public Chipnet Electrum connection closed')));
    socket.once('secureConnect', () => {
      if (socket.authorized !== true) { close(new Error('public Chipnet Electrum TLS authentication failed')); return; }
      clearTimeout(connectTimer);
      settled = true;
      resolve(Object.freeze({
        async request(method, params) {
          if (typeof method !== 'string' || !Array.isArray(params)) throw new Error('Electrum request is malformed');
          if (closed || socket.destroyed) throw new Error('public Chipnet Electrum session is closed');
          if (pending.size >= PUBLIC_ELECTRUM_MAX_INFLIGHT_REQUESTS) {
            throw new Error('public Chipnet Electrum in-flight request limit exceeded');
          }
          const id = nextId; nextId += 1;
          return new Promise((resolveRequest, rejectRequest) => {
            const timer = setTimeout(() => {
              pending.delete(id); rejectRequest(new Error(`public Chipnet Electrum ${method} timed out`));
            }, 30_000);
            pending.set(id, { resolve: resolveRequest, reject: rejectRequest, timer });
            socket.write(`${JSON.stringify({ id, method, params })}\n`, (error) => {
              if (error !== undefined && error !== null) {
                const entry = pending.get(id); if (entry !== undefined) { clearTimeout(entry.timer); pending.delete(id); entry.reject(new Error(`public Chipnet Electrum ${method} transport failed`)); }
              }
            });
          });
        },
        close: () => close(new Error('public Chipnet Electrum session closed')),
      }));
    });
    socket.on('data', (chunk) => {
      buffer += chunk;
      for (;;) {
        const newline = buffer.indexOf('\n');
        if (newline < 0) {
          if (buffer.length > PUBLIC_ELECTRUM_MAX_RESPONSE_LINE_CHARACTERS) {
            close(new Error('public Chipnet Electrum response line exceeds the bounded maximum'));
          }
          return;
        }
        if (newline > PUBLIC_ELECTRUM_MAX_RESPONSE_LINE_CHARACTERS) {
          close(new Error('public Chipnet Electrum response line exceeds the bounded maximum'));
          return;
        }
        const line = buffer.slice(0, newline).replace(/\r$/u, ''); buffer = buffer.slice(newline + 1);
        let message;
        try { message = JSON.parse(line); } catch { close(new Error('public Chipnet Electrum returned malformed JSON')); return; }
        const entry = pending.get(message?.id); if (entry === undefined) continue;
        clearTimeout(entry.timer); pending.delete(message.id);
        if (message.error !== null && message.error !== undefined) entry.reject(new Error('public Chipnet Electrum rejected a request'));
        else entry.resolve(message.result);
      }
    });
  });
}

/** Test-only socket seam for bounded session-parser and lifecycle tests. */
export function openPublicElectrumSessionForTest(endpoint, { connectTls } = {}) {
  if (typeof connectTls !== 'function') throw new Error('test TLS connector is required');
  return openPublicElectrumSession(endpoint, connectTls);
}

function publicElectrumGenesis(features) {
  const genesis = typeof features?.genesis_hash === 'string'
    ? features.genesis_hash.toLowerCase() : '';
  return parseBchnChipnetGenesis(genesis, 'public Chipnet Fulcrum');
}

function electrumStateOutput(rawTransactionHex, transactionId, outputIndex, info) {
  let transaction;
  try { transaction = parseV2RawTransaction(rawTransactionHex); }
  catch (error) { throw new Error('public Chipnet Fulcrum returned malformed raw transaction', { cause: error }); }
  const serializedOutput = transaction.outputs[outputIndex];
  let output;
  try {
    output = serializedOutput === undefined
      ? undefined
      : parseSerializedSourceOutput(serializedOutput.serializedHex);
  } catch (error) {
    throw new Error('public Chipnet Fulcrum returned a malformed output serialization', { cause: error });
  }
  if (transaction.txid !== transactionId || output === undefined || info === null
    || info === undefined || typeof info !== 'object' || Array.isArray(info)) {
    throw new Error('public Chipnet Fulcrum raw transaction or output visibility is invalid');
  }
  const expectedScripthash = electrumScriptHashFromLockingBytecode(output.lockingBytecodeHex);
  if (!Number.isSafeInteger(info.value) || BigInt(info.value) !== output.valueSatoshis
    || info.scripthash !== expectedScripthash) {
    throw new Error('public Chipnet Fulcrum does not show the exact zero-conf output');
  }
  const token = output.token === null ? undefined : Object.freeze({
    // Transaction parsing retains the exact 32 category bytes serialized in
    // the token prefix. Electrum Cash (like BCHN JSON-RPC) presents token IDs
    // in canonical display order, so reverse only at this public API boundary.
    category: Buffer.from(output.token.categoryWire, 'hex').reverse().toString('hex'),
    amount: output.token.amount,
    nft: output.token.nft === null ? undefined : Object.freeze({
      capability: output.token.nft.capability,
      commitment: output.token.nft.commitmentHex,
    }),
  });
  // Provider token metadata is never a source of truth. If supplied, it must
  // nevertheless agree with locally parsed exact transaction bytes.
  if (info.token_data !== undefined) {
    const expectedCategory = token === undefined ? undefined : token.category;
    if (token === undefined || info.token_data === null || typeof info.token_data !== 'object'
      || info.token_data.category !== expectedCategory
      || String(info.token_data.amount) !== token.amount
      || (token.nft === undefined
        ? (info.token_data.nft !== undefined && info.token_data.nft !== null)
        : (info.token_data.nft?.capability !== token.nft.capability
          || info.token_data.nft?.commitment !== token.nft.commitment))) {
      throw new Error('public Chipnet Fulcrum token metadata disagrees with exact raw transaction bytes');
    }
  }
  return Object.freeze({
    valueSatoshis: output.valueSatoshis.toString(),
    scriptPubKey: Object.freeze({ hex: output.lockingBytecodeHex }),
    ...(token === undefined ? {} : { tokenData: token }),
  });
}

async function publicElectrumOutputReadback(entry, transactionId, outputIndex, rawTransactionHex = undefined) {
  // For modern Electrum providers, output visibility does not depend on
  // parsing the raw transaction. Start both independent reads together, then
  // bind the provider's visibility claim to locally parsed exact bytes below.
  // The legacy listunspent fallback needs the parsed locking bytecode, so it
  // deliberately remains after the raw read for negotiated protocol 1.4.
  const rawRequest = rawTransactionHex === undefined
    ? entry.request('blockchain.transaction.get', [transactionId])
    : Promise.resolve(rawTransactionHex);
  const infoRequest = entry.utxoGetInfo
    ? entry.request('blockchain.utxo.get_info', [transactionId, outputIndex])
    : undefined;
  const [raw, prefetchedInfo] = infoRequest === undefined
    ? [await rawRequest, undefined]
    : await Promise.all([rawRequest, infoRequest]);
  if (typeof raw !== 'string' || !HEX.test(raw)) throw new Error('public Chipnet Fulcrum returned malformed raw transaction bytes');
  let transaction;
  try { transaction = parseV2RawTransaction(raw); }
  catch (error) { throw new Error('public Chipnet Fulcrum returned malformed raw transaction', { cause: error }); }
  const serializedOutput = transaction.outputs[outputIndex];
  let output;
  try {
    output = serializedOutput === undefined
      ? undefined
      : parseSerializedSourceOutput(serializedOutput.serializedHex);
  } catch (error) {
    throw new Error('public Chipnet Fulcrum returned a malformed output serialization', { cause: error });
  }
  if (transaction.txid !== transactionId || output === undefined) throw new Error('public Chipnet Fulcrum raw transaction does not bind the requested output');
  const info = entry.utxoGetInfo
    ? prefetchedInfo
    : await (async () => {
      const scripthash = electrumScriptHashFromLockingBytecode(output.lockingBytecodeHex);
      const entries = await entry.request('blockchain.scripthash.listunspent', [scripthash]);
      if (!Array.isArray(entries)) throw new Error('public Chipnet Fulcrum listunspent response is malformed');
      const candidate = entries.find((entryValue) => entryValue !== null && typeof entryValue === 'object'
        && entryValue.tx_hash === transactionId && entryValue.tx_pos === outputIndex);
      return candidate === undefined ? null : { ...candidate, scripthash };
    })();
  return Object.freeze({ rawTransactionHex: raw, stateOutput: electrumStateOutput(raw, transactionId, outputIndex, info) });
}

async function publicElectrumRawReadback(entries, transactionId) {
  const rawTransactions = await Promise.all(entries.map(async (entry) => {
    const raw = await entry.request('blockchain.transaction.get', [transactionId]);
    if (typeof raw !== 'string' || !HEX.test(raw)) {
      throw new Error('public Chipnet Fulcrum returned malformed raw transaction bytes');
    }
    let transaction;
    try { transaction = parseV2RawTransaction(raw); }
    catch (error) { throw new Error('public Chipnet Fulcrum returned malformed raw transaction', { cause: error }); }
    if (transaction.txid !== transactionId) {
      throw new Error('public Chipnet Fulcrum raw transaction does not bind the requested transaction id');
    }
    return raw;
  }));
  if (rawTransactions.some((raw) => raw !== rawTransactions[0])) {
    throw new Error('public Chipnet Fulcrum providers disagree on exact raw transaction bytes');
  }
  return rawTransactions[0];
}

async function publicElectrumStateReadback(
  entries,
  transactionId,
  outputIndex,
  rawTransactionReadback = undefined,
) {
  const rawRequest = rawTransactionReadback === undefined
    ? publicElectrumRawReadback(entries, transactionId)
    : Promise.resolve(rawTransactionReadback);
  const readbacks = await Promise.all(entries.map(async (entry) => {
    if (!entry.utxoGetInfo) {
      // Protocol 1.4 can only locate the output by the script hash derived
      // from parsed exact bytes, so retain its required sequential fallback.
      return publicElectrumOutputReadback(
        entry,
        transactionId,
        outputIndex,
        await rawRequest,
      );
    }
    // `get_info` is keyed by outpoint, so it can start with the shared raw
    // consensus request. `electrumStateOutput` binds it to the exact parsed
    // bytes only after both promises settle.
    const [raw, info] = await Promise.all([
      rawRequest,
      entry.request('blockchain.utxo.get_info', [transactionId, outputIndex]),
    ]);
    return Object.freeze({
      rawTransactionHex: raw,
      stateOutput: electrumStateOutput(raw, transactionId, outputIndex, info),
    });
  }));
  if (readbacks.some((readback) => readback.rawTransactionHex !== readbacks[0].rawTransactionHex
    || JSON.stringify(readback.stateOutput) !== JSON.stringify(readbacks[0].stateOutput))) {
    throw new Error('public Chipnet Fulcrum providers disagree on the exact zero-conf output');
  }
  return readbacks[0];
}

async function createPublicBchnChipnetRpcInternal({
  endpoints,
  openSession,
  postBroadcastReadbackAttempts = PUBLIC_ELECTRUM_POST_BROADCAST_READBACK_ATTEMPTS,
  postBroadcastReadbackDelayMs = PUBLIC_ELECTRUM_POST_BROADCAST_READBACK_DELAY_MS,
}) {
  if (!Array.isArray(endpoints) || endpoints.length < 2 || typeof openSession !== 'function') {
    throw new Error('at least two public Chipnet Fulcrum TLS endpoints are required');
  }
  if (!Number.isSafeInteger(postBroadcastReadbackAttempts)
    || postBroadcastReadbackAttempts < 1 || postBroadcastReadbackAttempts > 100
    || !Number.isSafeInteger(postBroadcastReadbackDelayMs)
    || postBroadcastReadbackDelayMs < 0 || postBroadcastReadbackDelayMs > 1_000) {
    throw new Error('public Chipnet post-broadcast readback policy is invalid');
  }
  const endpointKeys = new Set(endpoints.map((endpoint) =>
    endpoint !== null && typeof endpoint === 'object'
      ? `${endpoint.host ?? ''}:${endpoint.port ?? ''}` : ''));
  if (endpointKeys.size < 2 || endpointKeys.has(':')) {
    throw new Error('two distinct public Chipnet Fulcrum TLS endpoints are required');
  }
  const physicalMethodCounts = Object.fromEntries(
    PUBLIC_CHIPNET_ELECTRUM_METHODS.map((method) => [method, 0]),
  );
  const connect = async (endpoint) => {
    let session;
    try {
      session = await openSession(endpoint);
      const request = async (method, params) => {
        if (!Object.hasOwn(physicalMethodCounts, method)) {
          throw new Error(`public Chipnet Electrum method refused: ${method}`);
        }
        physicalMethodCounts[method] += 1;
        return session.request(method, params);
      };
      // A lower negotiated protocol version is the only listunspent fallback.
      // A malformed/rejected/transport-failed negotiation rejects this provider
      // before the durable send boundary rather than silently weakening it.
      const [negotiated, features] = await Promise.all([
        // Write the protocol negotiation as the first request on the session.
        request('server.version', ['ShieldKit', '1.5']),
        request('server.features', []),
      ]);
      publicElectrumGenesis(features);
      const version = Array.isArray(negotiated) ? negotiated[1] : undefined;
      const matchedVersion = typeof version === 'string'
        ? /^1\.(4|5|6)(?:\.[0-9]+)?$/u.exec(version) : null;
      if (matchedVersion === null) {
        throw new Error('public Chipnet Fulcrum negotiated an unsupported protocol version');
      }
      const utxoGetInfo = Number(matchedVersion[1]) >= 5;
      return Object.freeze({ endpoint, request, session, utxoGetInfo });
    } catch (error) {
      try { session?.close?.(); } catch {}
      throw error;
    }
  };
  // Establish and genesis-check all pinned candidates concurrently. This is
  // entirely before any durable send boundary and removes serial TLS latency
  // from every CLI invocation without permitting send-side failover.
  const connected = await Promise.allSettled(endpoints.map(connect));
  const sessions = connected
    .filter((result) => result.status === 'fulfilled')
    .map((result) => result.value)
    .filter((entry, index, entries) => entries.findIndex((candidate) =>
      candidate.endpoint.host === entry.endpoint.host) === index)
    .slice(0, 2);
  for (const result of connected) {
    if (result.status === 'fulfilled' && !sessions.includes(result.value)) {
      try { result.value.session.close?.(); } catch {}
    }
  }
  if (sessions.length < 2 || sessions[0].endpoint.host === sessions[1].endpoint.host) {
    for (const entry of sessions) entry.session.close?.();
    throw new Error('two distinct public Chipnet Fulcrum TLS endpoints with Chipnet genesis are required');
  }
  const [broadcast, attestation] = sessions;
  let closed = false;
  const requireOpen = () => {
    if (closed) throw new Error('public Chipnet Fulcrum capability is closed');
  };
  const methodCounts = Object.fromEntries(PRODUCT_RPC_METHODS.map((method) => [method, 0]));
  const rawReadbacks = new Map();
  const exactRawFromBoth = (transactionId) => {
    const retained = rawReadbacks.get(transactionId);
    if (retained !== undefined) return retained;
    const pending = publicElectrumRawReadback(sessions, transactionId).catch((error) => {
      rawReadbacks.delete(transactionId);
      throw error;
    });
    // CLI invocations are short-lived, but retain a strict bound for library
    // callers which reuse one capability for many immutable transactions.
    if (rawReadbacks.size >= 64) rawReadbacks.delete(rawReadbacks.keys().next().value);
    rawReadbacks.set(transactionId, pending);
    return pending;
  };
  const resolvePostBroadcast = async (readback) => {
    let lastError;
    for (let attempt = 0; attempt < postBroadcastReadbackAttempts; attempt += 1) {
      try { return await readback(); }
      catch (error) { lastError = error; }
      if (attempt + 1 < postBroadcastReadbackAttempts
        && postBroadcastReadbackDelayMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, postBroadcastReadbackDelayMs));
      }
    }
    throw lastError;
  };
  const rpc = {
    backend: 'public-chipnet-fulcrum-tls', label: 'public Chipnet Fulcrum TLS', network: 'chipnet', genesis: CHIPNET_GENESIS_HASH,
    async getrawtransaction(txid, verbose = false) {
      requireOpen();
      if (!TXID.test(String(txid).toLowerCase())) throw new Error('invalid public Chipnet raw transaction id');
      methodCounts.getrawtransaction += 1;
      const raw = await exactRawFromBoth(String(txid).toLowerCase());
      return verbose ? Object.freeze({ txid: String(txid).toLowerCase(), hex: raw }) : raw;
    },
    async gettxout(txid, vout) {
      requireOpen();
      if (!TXID.test(String(txid).toLowerCase()) || !Number.isSafeInteger(vout) || vout < 0) throw new Error('invalid public Chipnet output request');
      methodCounts.gettxout += 1;
      const transactionId = String(txid).toLowerCase();
      return (await publicElectrumStateReadback(
        sessions,
        transactionId,
        vout,
        exactRawFromBoth(transactionId),
      )).stateOutput;
    },
    async scanAddress() { requireOpen(); throw new Error('public Chipnet product RPC requires an explicit funding outpoint'); },
    async submitExactTransaction(rawTransactionHex, expectedTransactionId) {
      requireOpen();
      if (!HEX.test(rawTransactionHex) || !TXID.test(expectedTransactionId)
        || transactionIdFromRawHex(rawTransactionHex) !== expectedTransactionId) {
        throw new Error('invalid public exact transaction request');
      }
      methodCounts.sendrawtransaction += 1;
      let transactionId;
      try {
        transactionId = await broadcast.request(
          'blockchain.transaction.broadcast', [rawTransactionHex],
        );
      } catch (error) {
        // Fulcrum can report a broadcast error even after its backing node has
        // accepted and propagated the transaction. Two independent exact-byte
        // readbacks are stronger evidence than that response: resolve the
        // attempt as successful only when both pre-verified providers expose
        // the identical expected transaction. Never send through the second
        // provider and remain indeterminate on any missing/divergent readback.
        methodCounts.getrawtransaction += 1;
        try {
          const raw = await resolvePostBroadcast(() =>
            publicElectrumRawReadback(sessions, expectedTransactionId));
          if (raw === rawTransactionHex) {
            return Object.freeze({
              transactionId: expectedTransactionId,
              rawTransaction: Object.freeze({ txid: expectedTransactionId, hex: raw }),
            });
          }
        } catch { /* preserve the indeterminate send boundary below */ }
        throw new Error('public Chipnet broadcast outcome is indeterminate', { cause: error });
      }
      if (typeof transactionId !== 'string'
        || transactionId.toLowerCase() !== expectedTransactionId) {
        throw new Error('public Chipnet broadcast returned a mismatched transaction id');
      }
      methodCounts.getrawtransaction += 1;
      const raw = await publicElectrumRawReadback([attestation], expectedTransactionId);
      if (raw !== rawTransactionHex) {
        throw new Error('independent public Chipnet raw readback differs from broadcast bytes');
      }
      return Object.freeze({
        transactionId: expectedTransactionId,
        rawTransaction: Object.freeze({ txid: expectedTransactionId, hex: raw }),
      });
    },
    async submitV2SinglePassAdmission(rawTransactionHex, expectedTransactionId, outputIndex = 0) {
      requireOpen();
      if (!HEX.test(rawTransactionHex) || !TXID.test(expectedTransactionId)
        || !Number.isSafeInteger(outputIndex) || outputIndex < 0
        || transactionIdFromRawHex(rawTransactionHex) !== expectedTransactionId) throw new Error('invalid public single-pass admission request');
      methodCounts.sendrawtransaction += 1;
      let transactionId;
      try { transactionId = await broadcast.request('blockchain.transaction.broadcast', [rawTransactionHex]); }
      catch (error) {
        // The bytes may already have reached the primary. Reconcile using only
        // reads from both pre-verified providers, then let the existing
        // token-bound recovery path decide whether an explicit resend is safe.
        // Count the one logical admission readback attempt separately from
        // the physical provider requests below; recovery will add its own
        // explicit read-only route count.
        methodCounts.getrawtransaction += 1;
        methodCounts.gettxout += 1;
        try {
          const readback = await resolvePostBroadcast(async () => {
            // Preserve two-provider exact-raw consensus, then use the distinct
            // non-broadcasting provider for the output attestation. This is
            // the same trust split as the ordinary successful-response path;
            // requiring the broadcasting provider's UTXO index as well only
            // adds lag without adding an independent party.
            const raw = await publicElectrumRawReadback(
              sessions,
              expectedTransactionId,
            );
            return publicElectrumOutputReadback(
              attestation,
              expectedTransactionId,
              outputIndex,
              raw,
            );
          });
          if (readback.rawTransactionHex === rawTransactionHex) {
            return Object.freeze({
              transactionId: expectedTransactionId,
              rawTransaction: Object.freeze({
                txid: expectedTransactionId,
                hex: readback.rawTransactionHex,
              }),
              stateOutput: readback.stateOutput,
            });
          }
        } catch { /* preserve the indeterminate send boundary below */ }
        throw new Error('public Chipnet broadcast outcome is indeterminate', { cause: error });
      }
      if (typeof transactionId !== 'string' || transactionId.toLowerCase() !== expectedTransactionId) throw new Error('public Chipnet broadcast returned a mismatched transaction id');
      methodCounts.getrawtransaction += 1; methodCounts.gettxout += 1;
      const readback = await publicElectrumOutputReadback(attestation, expectedTransactionId, outputIndex);
      if (readback.rawTransactionHex !== rawTransactionHex) throw new Error('independent public Chipnet raw readback differs from broadcast bytes');
      return Object.freeze({ transactionId: expectedTransactionId, rawTransaction: Object.freeze({ txid: expectedTransactionId, hex: readback.rawTransactionHex }), stateOutput: readback.stateOutput });
    },
    observation() {
      return Object.freeze({
        backend: 'public-chipnet-fulcrum-tls',
        genesis: CHIPNET_GENESIS_HASH,
        // Stable logical route counts: retained for delivery-route contracts.
        methodCounts: Object.freeze({ ...methodCounts }),
        // Actual public-provider JSON-RPC method names: never BCHN aliases.
        physicalMethodCounts: Object.freeze({ ...physicalMethodCounts }),
      });
    },
    close() {
      if (closed) return;
      closed = true;
      for (const entry of sessions) {
        try { entry.session.close?.(); } catch { /* best-effort socket cleanup */ }
      }
    },
  };
  Object.freeze(rpc); bchnChipnetCapabilities.add(rpc); return rpc;
}

/** End-user product transport: two pinned, TLS-verified public Chipnet Fulcrum endpoints. */
export async function createPublicChipnetFulcrumRpc() {
  return createPublicBchnChipnetRpcInternal({ endpoints: PUBLIC_CHIPNET_ELECTRUM, openSession: openPublicElectrumSession });
}

/** Test-only public-transport seam; production never accepts provider URLs or credentials. */
export async function createPublicChipnetFulcrumRpcForTest({
  endpoints,
  openSession,
  postBroadcastReadbackAttempts = 1,
  postBroadcastReadbackDelayMs = 0,
} = {}) {
  return createPublicBchnChipnetRpcInternal({
    endpoints,
    openSession,
    postBroadcastReadbackAttempts,
    postBroadcastReadbackDelayMs,
  });
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
