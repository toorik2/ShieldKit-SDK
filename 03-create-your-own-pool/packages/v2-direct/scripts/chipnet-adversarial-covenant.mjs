#!/usr/bin/env node
/**
 * Honest adversarial on-chain probes against live V2 Direct covenants.
 *
 * Builds spends of *unspent* outputs with invalid unlocks and expects
 * testmempoolaccept rejection for script/covenant reasons — not merely
 * missing-inputs / mempool-conflict from already-spent outpoints.
 *
 * Requires a product tip with unspent carriers+binding+state (post G/D/T/W tip
 * still free, or deposit-only tip).
 *
 * Modes:
 *   V2_ADV_TIP_TXID — tip settle txid (defaults: product evidence withdraw/deposit)
 *   Or load from .cache/v2-direct-product-1tx/evidence.json
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  encodeTransaction,
  createVirtualMachineBch2026,
  binToHex,
} from '@bitauth/libauth';
import { productBindingLock } from '../covenant/binding-state.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const OUT = path.join(ROOT, '.cache/v2-direct-adversarial');

// Display-order outpoint hash (matches product settle encoding).
function outpointHash(txid) {
  return Uint8Array.from(Buffer.from(String(txid).toLowerCase(), 'hex'));
}

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
    method, ...tokens,
  ].join(' ');
  const out = execFileSync('ssh', ['-o', 'BatchMode=yes', '-o', 'LogLevel=ERROR', 'layer1-node', cmd], {
    encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
  });
  const t = out.trim();
  if (!t) return null;
  try { return JSON.parse(t); } catch { return t.replace(/^"|"$/g, ''); }
}

function isScriptReject(reason) {
  if (!reason) return false;
  const r = String(reason).toLowerCase();
  if (/missing-inputs|txn-mempool-conflict|txn-already|bad-txns-inputs-missingorspent/i.test(r)) {
    return false;
  }
  return /script|mandatory-script|non-mandatory|verify|equalverify|invalid|covenant|cleanstack|disabled|false\/empty/i.test(r);
}

/** Valid-shaped P2PKH change target (hot ops address). */
const HOT_P2PKH = Uint8Array.from(Buffer.from(
  '76a914233c0f9b7593aecb09dca11931965a16b90548c288ac',
  'hex',
));

/**
 * Invalid spend of an unspent outpoint with a garbage/empty unlock.
 * Output is a normal P2PKH change (not OP_RETURN-with-value) so BCHN reaches script eval.
 */
function buildInvalidUnlockSpend({
  txid, vout, valueSats, unlockingBytecode,
}) {
  const fee = 500n;
  const val = BigInt(valueSats);
  const outVal = val > fee + 546n ? val - fee : 546n;
  const tx = {
    version: 2,
    locktime: 0,
    inputs: [{
      outpointTransactionHash: outpointHash(txid),
      outpointIndex: Number(vout),
      sequenceNumber: 0xffffffff,
      unlockingBytecode: Uint8Array.from(unlockingBytecode),
    }],
    outputs: [{
      valueSatoshis: outVal,
      lockingBytecode: HOT_P2PKH,
    }],
  };
  return {
    txHex: binToHex(encodeTransaction(tx)),
    tx,
  };
}

/**
 * Invalid binding unlock: wrong magic packet against productBindingLock (Libauth).
 */
function buildBadBindingLibauth({ txid, vout, valueSats }) {
  const lock = Uint8Array.from(productBindingLock());
  const badPacket = Buffer.alloc(552, 0);
  const rawUnlock = Buffer.concat([Buffer.from([0x4d, 0x28, 0x02]), badPacket]);
  const tx = {
    version: 2,
    locktime: 0,
    inputs: [{
      outpointTransactionHash: outpointHash(txid),
      outpointIndex: vout,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: Uint8Array.from(rawUnlock),
    }],
    outputs: [{
      valueSatoshis: BigInt(valueSats) > 1000n ? BigInt(valueSats) - 500n : 546n,
      lockingBytecode: HOT_P2PKH,
    }],
  };
  const sourceOutputs = [{
    valueSatoshis: BigInt(valueSats),
    lockingBytecode: lock,
  }];
  return { tx, sourceOutputs, unlock: rawUnlock };
}

function libauthReject({ tx, sourceOutputs }) {
  const vm = createVirtualMachineBch2026(false);
  const result = vm.verify({ sourceOutputs, transaction: tx });
  return {
    ok: result === true,
    detail: result === true ? null : String(result),
  };
}

function probeMempool({ label, txid, vout, valueSats, unlock }) {
  const u = rpc('gettxout', [txid, vout, true]);
  if (!u) {
    return {
      probe: label,
      rejected: false,
      honest: false,
      skipped: true,
      detail: 'outpoint already spent — skipped (would be missing-inputs)',
      outpoint: `${txid}:${vout}`,
    };
  }
  const value = valueSats ?? Math.round(Number(u.value) * 1e8);
  const built = buildInvalidUnlockSpend({
    txid, vout, valueSats: value, unlockingBytecode: unlock,
  });
  const acc = rpc('testmempoolaccept', [[built.txHex]]);
  const row = Array.isArray(acc) ? acc[0] : acc;
  const reason = row?.['reject-reason'] || null;
  const allowed = row?.allowed === true;
  const scriptReject = allowed === false && isScriptReject(reason);
  const spentnessOnly = allowed === false && !isScriptReject(reason);
  return {
    probe: label,
    outpoint: `${txid}:${vout}`,
    allowed,
    rejectReason: reason,
    rejected: allowed === false,
    honest: scriptReject,
    skipped: spentnessOnly,
    detail: spentnessOnly
      ? `skipped: ${reason} (spentness, not covenant evidence)`
      : reason,
  };
}

function resolveTipTxid() {
  if (process.env.V2_ADV_TIP_TXID) return process.env.V2_ADV_TIP_TXID.toLowerCase();
  if (process.env.V2_ADV_STATE_TXID) return process.env.V2_ADV_STATE_TXID.toLowerCase();
  const evPath = path.join(ROOT, '.cache/v2-direct-product-1tx/evidence.json');
  if (existsSync(evPath)) {
    const ev = JSON.parse(readFileSync(evPath, 'utf8'));
    return (ev.withdraw?.settleTxid || ev.transfer?.settleTxid || ev.deposit?.settleTxid || '')
      .toLowerCase() || null;
  }
  return null;
}

function main() {
  mkdirSync(OUT, { recursive: true });
  const results = [];

  // Probe 1: invalid binding lock evaluation (local Libauth — no spentness issues)
  {
    const fakeTxid = '11'.repeat(32);
    const built = buildBadBindingLibauth({ txid: fakeTxid, vout: 7, valueSats: 10_000 });
    const la = libauthReject({ tx: built.tx, sourceOutputs: built.sourceOutputs });
    results.push({
      probe: 'binding-bad-magic-libauth',
      rejected: la.ok === false,
      detail: la.detail,
      honest: la.ok === false,
    });
  }

  // Probe 2: empty unlock vs binding lock (Libauth)
  {
    const fakeTxid = '22'.repeat(32);
    const lock = Uint8Array.from(productBindingLock());
    const tx = {
      version: 2,
      locktime: 0,
      inputs: [{
        outpointTransactionHash: outpointHash(fakeTxid),
        outpointIndex: 7,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: new Uint8Array(0),
      }],
      outputs: [{ valueSatoshis: 9500n, lockingBytecode: HOT_P2PKH }],
    };
    const la = libauthReject({
      tx,
      sourceOutputs: [{ valueSatoshis: 10_000n, lockingBytecode: lock }],
    });
    results.push({
      probe: 'binding-empty-unlock-libauth',
      rejected: la.ok === false,
      detail: la.detail,
      honest: la.ok === false,
    });
  }

  // Live on-chain probes against unspent tip (carriers@0, binding@7, state@8)
  const tipTxid = resolveTipTxid();
  if (tipTxid) {
    // garbage unlock (OP_1) — densFuel P2SH32 fails HASH256/EQUAL
    results.push(probeMempool({
      label: 'carrier0-garbage-unlock-mempool',
      txid: tipTxid,
      vout: 0,
      unlock: Uint8Array.from([0x51]),
    }));
    // binding bare: bad 552-byte zero packet
    const badPacket = Buffer.alloc(552, 0);
    const badBindUnlock = Buffer.concat([Buffer.from([0x4d, 0x28, 0x02]), badPacket]);
    results.push(probeMempool({
      label: 'binding-bad-magic-mempool',
      txid: tipTxid,
      vout: 7,
      unlock: badBindUnlock,
    }));
    // state P2SH32 empty-ish garbage unlock
    results.push(probeMempool({
      label: 'state-garbage-unlock-mempool',
      txid: tipTxid,
      vout: 8,
      unlock: Uint8Array.from([0x00]),
    }));
  } else {
    results.push({
      probe: 'live-tip-probes',
      skipped: true,
      detail: 'no product tip txid in env/evidence',
    });
  }

  const pass = results.filter((r) => r.honest === true).length;
  const fail = results.filter((r) => r.honest === false && !r.skipped).length;
  const liveHonest = results.filter(
    (r) => /mempool$/.test(r.probe) && r.honest === true,
  ).length;
  const report = {
    network: 'chipnet',
    height: rpc('getblockcount'),
    tipTxid,
    results,
    passCount: pass,
    failCount: fail,
    liveScriptRejects: liveHonest,
    // Need Libauth binding rejects + ≥1 honest live mempool script-reject
    ok: pass >= 3 && liveHonest >= 1 && fail === 0,
  };
  writeFileSync(path.join(OUT, 'adversarial-covenant.json'), `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(report, null, 2));
  if (!report.ok) process.exitCode = 2;
}

main();
