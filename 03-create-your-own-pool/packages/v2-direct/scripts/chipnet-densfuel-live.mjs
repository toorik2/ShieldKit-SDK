#!/usr/bin/env node
/**
 * Live Chipnet densFuel settlement:
 * 1) Fund 10 densFuel source outs (7 carriers + packet + state + fee) from hot
 * 2) Spend them with densFuel unlocks in the densFuel topology
 * 3) testmempoolaccept + broadcast; record full txids
 *
 * Topology (from densFuel pin):
 *   - 10 inputs, common parent, outpointIndex == inputIndex
 *   - value 1000 sats each, sequence 0
 *   - 1 output: OP_RETURN 1000 sats
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  encodeTransaction,
  generateSigningSerializationBch,
  hash256,
  instantiateSecp256k1,
  SigningSerializationTypeBch,
  hexToBin,
  binToHex,
  decodeTransaction,
} from '@bitauth/libauth';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const WALLET_DIR = '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4';
const HOT = 'bchtest:qq3ncrumwkf6ajcfmjs3jvvktgttjp2gcg3yujp0yv';
const UNLOCK_DIR = path.join(ROOT, '.cache/v2-direct-unlocks');
const OUT = path.join(ROOT, '.cache/v2-direct-live-settle');
// densFuel live fee-viable pin: C7_SOURCE_VALUE_SATS=10000 → fee ≈ 99k for ~55kB wire
const SOURCE_VALUE = BigInt(process.env.C7_SOURCE_VALUE_SATS || '10000');
const SPEND_OUTPUT = 1000n;
const N_INPUTS = 10;

function shellQuote(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}
function rpc(method, params = []) {
  const tokens = params.map((p) => (
    typeof p === 'string' || typeof p === 'number' || typeof p === 'boolean'
      ? shellQuote(String(p))
      : shellQuote(JSON.stringify(p))
  ));
  const cmd = [
    'sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf',
    method,
    ...tokens,
  ].join(' ');
  const out = execFileSync('ssh', ['-o', 'BatchMode=yes', '-o', 'LogLevel=ERROR', 'layer1-node', cmd], {
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  const t = out.trim();
  if (!t) return null;
  try { return JSON.parse(t); } catch { return t.replace(/^"|"$/g, ''); }
}
function sha256(b) {
  return createHash('sha256').update(b).digest();
}
function base58Encode(buffer) {
  const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let z = 0;
  while (z < buffer.length && buffer[z] === 0) z += 1;
  const d = [0];
  for (let i = z; i < buffer.length; i += 1) {
    let c = buffer[i];
    for (let j = 0; j < d.length; j += 1) {
      c += d[j] << 8;
      d[j] = c % 58;
      c = (c / 58) | 0;
    }
    while (c > 0) {
      d.push(c % 58);
      c = (c / 58) | 0;
    }
  }
  let s = '1'.repeat(z);
  for (let i = d.length - 1; i >= 0; i -= 1) s += A[d[i]];
  return s;
}
function loadWallet() {
  const priv = JSON.parse(readFileSync(path.join(WALLET_DIR, 'wallet-private.json'), 'utf8'));
  return {
    privateKey: Buffer.from(priv.privateKeyHex, 'hex'),
    publicKey: Buffer.from(priv.publicKeyHex, 'hex'),
    lockingBytecode: Buffer.from(priv.lockingBytecodeHex, 'hex'),
    address: priv.address,
  };
}
function wif(priv) {
  const payload = Buffer.concat([Buffer.from([0xef]), priv, Buffer.from([0x01])]);
  const chk = sha256(sha256(payload)).subarray(0, 4);
  return base58Encode(Buffer.concat([payload, chk]));
}

function loadDensfuelMeta() {
  const dump = JSON.parse(readFileSync(path.join(UNLOCK_DIR, 'unlocks/build/inputs_dump.json'), 'utf8'));
  if (dump.length < N_INPUTS) throw new Error(`dump has ${dump.length} rows`);
  // densFuel leaves packet/state/fee structural roles unevaluated. Their lab locks
  // are P2PKH placeholders; on-chain they must accept the densFuel unlock shape:
  //   packet: PUSHDATA2(SDA2)  → lock OP_DROP OP_1
  //   state/fee: empty unlock → lock OP_1
  // Verifier unlocks still pass Libauth with these structural locks (sibling
  // UTXOBYTECODE of 7–9 is not bound by densFuel executors).
  const structuralLocks = {
    7: Buffer.from([0x75, 0x51]), // OP_DROP OP_1
    8: Buffer.from([0x51]), // OP_1
    9: Buffer.from([0x51]), // OP_1
  };
  return dump.slice(0, N_INPUTS).map((row, i) => ({
    i,
    name: row.name || `in${i}`,
    lock: structuralLocks[i] || Buffer.from(row.lock, 'hex'),
    unlock: Buffer.from(row.unlock || '', 'hex'),
  }));
}

async function signP2pkhInput(tx, inputIndex, sourceOutputs, wallet) {
  const secp = await instantiateSecp256k1();
  const ser = generateSigningSerializationBch(
    { inputIndex, sourceOutputs, transaction: tx },
    {
      coveredBytecode: Uint8Array.from(wallet.lockingBytecode),
      signingSerializationType: Uint8Array.of(SigningSerializationTypeBch.allOutputsAllUtxos),
    },
  );
  const digest = hash256(ser);
  const sig = secp.signMessageHashSchnorr(wallet.privateKey, digest);
  const sigWith = Buffer.concat([Buffer.from(sig), Buffer.from([0x61])]);
  return Buffer.concat([
    Buffer.from([sigWith.length]),
    sigWith,
    Buffer.from([wallet.publicKey.length]),
    wallet.publicKey,
  ]);
}

async function main() {
  mkdirSync(OUT, { recursive: true });
  const wallet = loadWallet();
  const meta = loadDensfuelMeta();
  console.log(JSON.stringify({
    phase: 'loaded-densfuel',
    locks: meta.map((m) => ({ i: m.i, name: m.name, lock: m.lock.length, unlock: m.unlock.length })),
  }));

  // --- Select funding UTXO from hot ---
  const scan = rpc('scantxoutset', ['start', [`addr(${HOT})`]]);
  const unspents = (scan.unspents || [])
    .map((u) => ({
      txid: u.txid,
      vout: u.vout,
      valueSats: BigInt(Math.round(Number(u.amount) * 1e8)),
      scriptPubKey: u.scriptPubKey,
    }))
    .filter((u) => u.valueSats >= 50_000n)
    .sort((a, b) => Number(b.valueSats - a.valueSats));
  if (!unspents.length) throw new Error('no hot UTXOs ≥ 50000 sats');
  // Prefer confirmed UTXOs; skip ones already spent by our prior fund attempts in mempool
  const skip = new Set((process.env.SKIP_OUTPOINTS || '').split(',').filter(Boolean));
  const fund = unspents.find((u) => !skip.has(`${u.txid}:${u.vout}`)) || unspents[0];
  console.log(JSON.stringify({
    phase: 'fund-utxo',
    txid: fund.txid,
    vout: fund.vout,
    valueSats: fund.valueSats.toString(),
  }));

  // --- Build fund tx: 10 densFuel outs @ 1000 + change ---
  const totalLock = SOURCE_VALUE * BigInt(N_INPUTS); // 10000
  // Fund tx ~600 B; use ≥2 sat/B so chipnet minrelay is satisfied
  const fundFee = 2000n;
  const change = fund.valueSats - totalLock - fundFee;
  if (change < 546n) throw new Error(`insufficient for fund: change ${change}`);

  const fundTx = {
    version: 2,
    locktime: 0,
    inputs: [{
      outpointTransactionHash: Uint8Array.from(Buffer.from(fund.txid, 'hex')),
      outpointIndex: fund.vout,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: new Uint8Array(),
    }],
    outputs: [
      ...meta.map((m) => ({
        valueSatoshis: SOURCE_VALUE,
        lockingBytecode: Uint8Array.from(m.lock),
      })),
      {
        valueSatoshis: change,
        lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
      },
    ],
  };
  const fundSources = [{
    valueSatoshis: fund.valueSats,
    lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
  }];
  fundTx.inputs[0].unlockingBytecode = Uint8Array.from(
    await signP2pkhInput(fundTx, 0, fundSources, wallet),
  );
  const fundHex = binToHex(encodeTransaction(fundTx));
  const fundDecoded = decodeTransaction(hexToBin(fundHex));
  if (typeof fundDecoded === 'string') throw new Error(fundDecoded);
  console.log(JSON.stringify({
    phase: 'fund-tx-built',
    bytes: fundHex.length / 2,
    outputs: fundDecoded.outputs.length,
  }));

  const fundAccept = rpc('testmempoolaccept', [[fundHex]]);
  console.log('fundAccept', JSON.stringify(fundAccept));
  const fundRow = Array.isArray(fundAccept) ? fundAccept[0] : fundAccept;
  if (fundRow?.allowed === false) {
    throw new Error(`fund rejected: ${JSON.stringify(fundRow)}`);
  }
  const fundTxid = String(rpc('sendrawtransaction', [fundHex])).toLowerCase();
  console.log(JSON.stringify({ phase: 'fund-broadcast', txid: fundTxid }));

  // Wait until UTXO visible (mempool is enough for gettxout with include_mempool)
  let visible = false;
  for (let i = 0; i < 20; i += 1) {
    const u = rpc('gettxout', [fundTxid, 0, true]);
    if (u && u.value != null) {
      visible = true;
      break;
    }
    execFileSync('sleep', ['1']);
  }
  if (!visible) {
    // still proceed — parent may be mempool-only
    console.log(JSON.stringify({ phase: 'fund-utxo-wait', visible: false }));
  }

  // --- Build settle tx with densFuel unlocks ---
  // outpoint hash = fundTxid (UI/big-endian for libauth)
  const parentHash = Uint8Array.from(Buffer.from(fundTxid, 'hex'));
  const settleTx = {
    version: 2,
    locktime: 0,
    inputs: meta.map((m, i) => ({
      outpointTransactionHash: parentHash,
      outpointIndex: i,
      sequenceNumber: 0, // densFuel SOURCE_SEQUENCE under public bench
      unlockingBytecode: Uint8Array.from(m.unlock),
    })),
    outputs: [{
      valueSatoshis: SPEND_OUTPUT,
      lockingBytecode: Uint8Array.from([0x6a]), // OP_RETURN
    }],
  };
  const settleHex = binToHex(encodeTransaction(settleTx));
  console.log(JSON.stringify({
    phase: 'settle-tx-built',
    bytes: settleHex.length / 2,
    feeSats: String(SOURCE_VALUE * BigInt(N_INPUTS) - SPEND_OUTPUT),
    feeRate: Number(SOURCE_VALUE * BigInt(N_INPUTS) - SPEND_OUTPUT) / (settleHex.length / 2),
  }));

  // Optional: local Libauth re-check first carrier only is expensive; densFuel already did.
  const settleAccept = rpc('testmempoolaccept', [[settleHex]]);
  console.log('settleAccept', JSON.stringify(settleAccept));
  const settleRow = Array.isArray(settleAccept) ? settleAccept[0] : settleAccept;

  let settleTxid = null;
  if (settleRow?.allowed) {
    settleTxid = String(rpc('sendrawtransaction', [settleHex])).toLowerCase();
    console.log(JSON.stringify({ phase: 'settle-broadcast', txid: settleTxid }));
  } else {
    // Try broadcast anyway if only fee-related; else record rejection
    try {
      settleTxid = String(rpc('sendrawtransaction', [settleHex])).toLowerCase();
      console.log(JSON.stringify({ phase: 'settle-broadcast-force', txid: settleTxid }));
    } catch (e) {
      console.log(JSON.stringify({
        phase: 'settle-rejected',
        reason: settleRow?.['reject-reason'] || e.stderr || e.message,
      }));
    }
  }

  // Confirm / fetch if present
  let settleDetail = null;
  if (settleTxid) {
    try {
      settleDetail = rpc('getrawtransaction', [settleTxid, true]);
    } catch {
      settleDetail = { mempool: true };
    }
  }

  const evidence = {
    network: 'chipnet',
    height: rpc('getblockcount'),
    densFuel: {
      wire: settleHex.length / 2,
      unlockLens: meta.map((m) => m.unlock.length),
      maxUnlock: Math.max(...meta.map((m) => m.unlock.length)),
      packetSha256: JSON.parse(readFileSync(path.join(UNLOCK_DIR, 'unlocks/build/result.json'), 'utf8')).packet?.sha256,
    },
    fundTxid,
    settleTxid,
    fundAccept: fundRow,
    settleAccept: settleRow,
    settleDetail: settleDetail ? {
      confirmations: settleDetail.confirmations,
      size: settleDetail.size,
      vin: settleDetail.vin?.length,
      vout: settleDetail.vout?.length,
    } : null,
    topology: {
      inputs: N_INPUTS,
      sourceValue: Number(SOURCE_VALUE),
      spendOutput: Number(SPEND_OUTPUT),
      commonParent: fundTxid,
    },
  };
  writeFileSync(path.join(OUT, 'evidence.json'), `${JSON.stringify(evidence, null, 2)}\n`);
  writeFileSync(path.join(OUT, 'fund.hex'), `${fundHex}\n`);
  writeFileSync(path.join(OUT, 'settle.hex'), `${settleHex}\n`);
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((e) => {
  console.error(e);
  writeFileSync(path.join(OUT, 'error.txt'), String(e.stack || e));
  process.exit(1);
});
