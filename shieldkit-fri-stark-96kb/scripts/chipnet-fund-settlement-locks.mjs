#!/usr/bin/env node
/**
 * Live Chipnet: fund P2SH32 outputs for a production sound settlement assembly,
 * then attempt testmempoolaccept / broadcast of fund tx (first try only).
 *
 * Does NOT broadcast placeholder toys. Requires SETTLEMENT_ARTIFACT with real locks.
 *
 * Env:
 *   SETTLEMENT_ARTIFACT — path to assemble-*-d4-b32.json (materialized)
 *   CHIPNET_WALLET_PRIVATE — path to wallet-private.json (hex privkey)
 *   CHIPNET_SSH — default layer1-node
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import {
  encodeTransaction,
  decodeTransaction,
  encodeDataPush,
  secp256k1,
  hash256,
  hexToBin,
  binToHex,
  flattenBinArray,
} from '@bitauth/libauth';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'evidence/settlement-prod');
const ART =
  process.env.SETTLEMENT_ARTIFACT ||
  path.join(OUT, 'assemble-transfer-latest.json');
const WALLET =
  process.env.CHIPNET_WALLET_PRIVATE ||
  '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4/wallet-private.json';
const SSH = process.env.CHIPNET_SSH || 'layer1-node';
const CLI = 'sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf';
const DUST = 1000n; // sats per verifier lock
const FEE = 5000n;

mkdirSync(OUT, { recursive: true });

function ssh(args, timeout = 120000) {
  const r = spawnSync(
    'ssh',
    ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15', SSH, `${CLI} ${args}`],
    { encoding: 'utf8', timeout, maxBuffer: 32 * 1024 * 1024 },
  );
  return r;
}

function rpcRaw(args, timeout) {
  const r = ssh(args, timeout);
  if (r.status !== 0) {
    throw new Error(`rpc fail: ${r.stderr || r.stdout}`);
  }
  // strip ssh fingerprint banners
  const lines = (r.stdout || '').split('\n').filter((l) => l.trim() && !l.includes('SHA256:') && !l.startsWith('+--') && !l.startsWith('|'));
  return lines.join('\n').trim();
}

function rpcJson(args, timeout) {
  const text = rpcRaw(args, timeout);
  try {
    return JSON.parse(text);
  } catch {
    return text; // plain string results (e.g. sendrawtransaction txid)
  }
}

const assembly = JSON.parse(readFileSync(ART, 'utf8'));
if (assembly.placeholder || !assembly.productionVerifiers) {
  console.error('REFUSE: artifact is placeholder / not production');
  process.exit(2);
}
const locks = (assembly.roleHex || []).map((r) => r.lockingHex);
if (locks.length < 10) {
  console.error('REFUSE: missing roleHex lockings');
  process.exit(2);
}

const wallet = JSON.parse(readFileSync(WALLET, 'utf8'));
const priv = hexToBin(wallet.privateKeyHex);
const pub = hexToBin(wallet.publicKeyHex);
const addr = wallet.address;
const lockHex = wallet.lockingBytecodeHex;

// scantxoutset for funding UTXO
const scan = rpcJson(
  `scantxoutset start "[\\"addr(${addr})\\"]"`,
  300000,
);
const utxos = (scan.unspents || [])
  .map((u) => ({
    txid: u.txid,
    vout: u.vout,
    amount: BigInt(Math.round(Number(u.amount) * 1e8)),
    scriptPubKey: u.scriptPubKey,
  }))
  .filter((u) => u.amount > 50_000n)
  .sort((a, b) => Number(b.amount - a.amount));

if (!utxos.length) {
  writeFileSync(
    path.join(OUT, 'CHIPNET_FUND.json'),
    JSON.stringify({ ok: false, reason: 'no funded UTXO' }, null, 2),
  );
  process.exit(3);
}

const vin = utxos[0];
const n = locks.length;
const totalOut = DUST * BigInt(n) + FEE;
if (vin.amount < totalOut + 1000n) {
  writeFileSync(
    path.join(OUT, 'CHIPNET_FUND.json'),
    JSON.stringify({ ok: false, reason: 'UTXO too small', vin }, null, 2),
  );
  process.exit(3);
}
const change = vin.amount - totalOut;

// Build unsigned fund tx (version 2)
const tx = {
  version: 2,
  inputs: [
    {
      // libauth encodeTransaction expects the 32-byte hash in UI byte order (big-endian hex as-is);
      // do not reverse — bitcoin-cli signrawtransactionwithkey matches standard wire after encode.
      outpointTransactionHash: hexToBin(vin.txid),
      outpointIndex: vin.vout,
      sequenceNumber: 0xfffffffe,
      unlockingBytecode: new Uint8Array(0),
    },
  ],
  outputs: [
    ...locks.map((h) => ({
      lockingBytecode: hexToBin(h),
      valueSatoshis: DUST,
    })),
    {
      lockingBytecode: hexToBin(lockHex),
      valueSatoshis: change,
    },
  ],
  locktime: 0,
};

// Sign P2PKH input with ALL|FORKID (0x41) — simplified: use bitcoin-cli signrawtransactionwithkey
const unsignedHex = binToHex(encodeTransaction(tx));
const prev = [
  {
    txid: vin.txid,
    vout: vin.vout,
    scriptPubKey: vin.scriptPubKey,
    amount: Number(vin.amount) / 1e8,
  },
];

// Export WIF for bitcoin-cli — use signrawtransactionwithkey with hex key if supported
// BCHN accepts private keys as WIF; convert compressed WIF from hex.
function hexToWif(hex, compressed = true) {
  const payload = Buffer.concat([
    Buffer.from([0xef]), // bchtest
    Buffer.from(hex, 'hex'),
    compressed ? Buffer.from([0x01]) : Buffer.alloc(0),
  ]);
  const c1 = createHash('sha256').update(payload).digest();
  const c2 = createHash('sha256').update(c1).digest();
  const full = Buffer.concat([payload, c2.subarray(0, 4)]);
  // base58
  const ALPH = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let x = BigInt('0x' + full.toString('hex'));
  let s = '';
  while (x > 0n) {
    const r = Number(x % 58n);
    x /= 58n;
    s = ALPH[r] + s;
  }
  for (const b of full) {
    if (b === 0) s = '1' + s;
    else break;
  }
  return s;
}

const wif = hexToWif(wallet.privateKeyHex, true);
const prevJson = JSON.stringify(prev).replace(/"/g, '\\"');
const keysJson = JSON.stringify([wif]).replace(/"/g, '\\"');

// Write unsigned to remote via stdin is hard; use local file and scp-less approach: pass hex
const signCmd = `signrawtransactionwithkey ${unsignedHex} "${keysJson}" "${prevJson}"`;
const signedR = ssh(signCmd, 60000);
let signed;
try {
  signed = JSON.parse(signedR.stdout);
} catch {
  signed = { complete: false, error: signedR.stderr || signedR.stdout };
}

const report = {
  schema: 'shieldkit-fri-chipnet-fund-locks-v1',
  ok: false,
  productionVerifiers: true,
  placeholder: false,
  nLocks: n,
  fundingVin: { txid: vin.txid, vout: vin.vout, amountSats: vin.amount.toString() },
  unsignedHexLen: unsignedHex.length / 2,
  signedComplete: !!signed.complete,
  signedError: signed.errors || signed.error || null,
  testmempoolaccept: null,
  broadcast: null,
  fundTxid: null,
  note: null,
};

if (!signed.complete || !signed.hex) {
  report.note = 'signrawtransactionwithkey failed — cannot fund locks on Chipnet this run';
  report.rpcStdout = (signedR.stdout || '').slice(0, 2000);
  report.rpcStderr = (signedR.stderr || '').slice(0, 1000);
  writeFileSync(path.join(OUT, 'CHIPNET_FUND.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report, null, 2));
  process.exit(4);
}

const accept = rpcJson(`testmempoolaccept '["${signed.hex}"]'`);
report.testmempoolaccept = accept;
const okAccept = Array.isArray(accept) && accept[0]?.allowed === true;
if (!okAccept) {
  report.note = 'testmempoolaccept rejected fund tx — stop (first try, no retry)';
  writeFileSync(path.join(OUT, 'CHIPNET_FUND.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report, null, 2));
  process.exit(5);
}

// Single broadcast
const txid = String(rpcJson(`sendrawtransaction ${signed.hex}`)).trim();
report.broadcast = { txid };
report.fundTxid = txid;
// exact readback
const raw = String(rpcJson(`getrawtransaction ${txid} false`)).trim();
report.readback = {
  rawMatch: raw.toLowerCase() === signed.hex.toLowerCase(),
  rawLen: raw.length / 2,
};
report.ok = report.readback.rawMatch === true;
report.note = report.ok
  ? 'Funded production FRI P2SH32 lock outputs on live Chipnet; spend (multi-input verify) is follow-up'
  : 'broadcast ok but raw readback mismatch';

writeFileSync(path.join(OUT, 'CHIPNET_FUND.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({
  ok: report.ok,
  fundTxid: report.fundTxid,
  nLocks: n,
  testmempoolaccept: okAccept,
  rawMatch: report.readback.rawMatch,
}, null, 2));
process.exit(report.ok ? 0 : 6);
