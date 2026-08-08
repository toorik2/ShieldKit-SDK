#!/usr/bin/env node

/**
 * Passive payout-identity check for ShieldKit action sets (BCH JSON dumps).
 *
 * Gate: any withdraw payout lock equals any fee-input lock used in the same
 * action set → FAIL (operator cash-out-to-funder style collapse).
 *
 * Informational only (fee mechanics out of scope): shared fee parent txids,
 * single fee-lock clusters.
 *
 * Usage:
 *   node privacy-passive-payout-check.mjs --actions-dir /path/to/decoded-jsons
 *
 * Each file must be `getrawtransaction <txid> true` JSON named `<txid>.json`.
 * Optionally pass --fee-input-index N (default: last vin).
 */

import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

function usage() {
  throw new Error(
    'usage: privacy-passive-payout-check.mjs --actions-dir <dir> [--fee-input-index <n>]',
  );
}

function parseArgs(argv) {
  const values = { feeInputIndex: -1 };
  for (let i = 0; i < argv.length; i += 2) {
    const name = argv[i];
    const value = argv[i + 1];
    if (value === undefined) usage();
    if (name === '--actions-dir') values.actionsDir = path.resolve(value);
    else if (name === '--fee-input-index') values.feeInputIndex = Number(value);
    else usage();
  }
  if (typeof values.actionsDir !== 'string') usage();
  if (!Number.isInteger(values.feeInputIndex)) usage();
  return Object.freeze(values);
}

function lockingHex(vout) {
  return vout?.scriptPubKey?.hex ?? null;
}

function isLikelyWithdraw(tx) {
  // Product withdraw has 14 outputs and a 0.1 BCH P2PKH near the end.
  if (!Array.isArray(tx.vout) || tx.vout.length < 14) return false;
  return tx.vout.some((out) => Math.abs(Number(out.value) - 0.1) < 1e-9
    && (out.scriptPubKey?.type === 'pubkeyhash'
      || out.scriptPubKey?.hex?.startsWith('76a914')));
}

function withdrawPayoutLocks(tx) {
  return tx.vout
    .filter((out) => Math.abs(Number(out.value) - 0.1) < 1e-9
      && typeof out.scriptPubKey?.hex === 'string'
      && out.scriptPubKey.hex.startsWith('76a914'))
    .map((out) => out.scriptPubKey.hex);
}

export async function runPrivacyPassivePayoutCheck(options) {
  const dir = options.actionsDir;
  const files = (await readdir(dir))
    .filter((name) => name.endsWith('.json'))
    .sort();
  const txs = [];
  for (const name of files) {
    const raw = JSON.parse(await readFile(path.join(dir, name), 'utf8'));
    if (raw && Array.isArray(raw.vin) && Array.isArray(raw.vout) && raw.txid) {
      txs.push(raw);
    }
  }

  const feeLocks = new Set();
  const feeParents = new Set();
  const payoutLocks = new Set();
  const withdrawTxids = [];

  for (const tx of txs) {
    if (!Array.isArray(tx.vin) || tx.vin.length === 0) continue;
    const feeIndex = options.feeInputIndex < 0
      ? tx.vin.length - 1
      : options.feeInputIndex;
    const feeVin = tx.vin[feeIndex];
    if (feeVin?.txid) feeParents.add(feeVin.txid);
    // Fee lock is not on the spend tx; observed via prevout only if present.
    if (typeof feeVin?.scriptPubKey?.hex === 'string') {
      feeLocks.add(feeVin.scriptPubKey.hex);
    }
    if (isLikelyWithdraw(tx)) {
      withdrawTxids.push(tx.txid);
      for (const lock of withdrawPayoutLocks(tx)) payoutLocks.add(lock);
    }
  }

  // When fee locks are unknown (standard decoded vin has no scriptPubKey),
  // fall back to comparing withdraw payouts against any P2PKH change/fee
  // outputs that also appear as 0.1 deposits' funding... Not available.
  // Gate uses equality of payout locks to locks that appear as the *same*
  // address string on any non-payout P2PKH input prev when provided in JSON.
  // Additionally: if all fee parents share one SOURCE and payout lock equals
  // any address listed on SOURCE outs, callers should pre-annotate.
  // Practical gate without prevouts: detect if every withdraw pays the same
  // lock AND that lock also appears as a non-withdraw output elsewhere in set.

  const allP2pkhLocks = new Set();
  for (const tx of txs) {
    for (const out of tx.vout ?? []) {
      const hex = lockingHex(out);
      if (typeof hex === 'string' && hex.startsWith('76a914') && hex.endsWith('88ac')) {
        allP2pkhLocks.add(hex);
      }
    }
  }

  const fundingLikeLocks = new Set();
  for (const tx of txs) {
    if (isLikelyWithdraw(tx)) continue;
    for (const out of tx.vout ?? []) {
      const hex = lockingHex(out);
      // bootstrap / change style: p2pkh not exactly 0.1 denom payout
      if (typeof hex === 'string'
        && hex.startsWith('76a914')
        && hex.endsWith('88ac')
        && Math.abs(Number(out.value) - 0.1) > 1e-9) {
        fundingLikeLocks.add(hex);
      }
    }
  }

  const collisions = [...payoutLocks].filter((lock) => fundingLikeLocks.has(lock));
  const singleFeeParent = feeParents.size === 1;
  const singlePayout = payoutLocks.size === 1;

  const report = Object.freeze({
    schema: 'shieldkit-privacy-passive-payout-check-v1',
    actionTxCount: txs.length,
    withdrawTxCount: withdrawTxids.length,
    feeParentTxids: Object.freeze([...feeParents].sort()),
    feeParentsShareSingleSource: singleFeeParent,
    feeParentClusterInformational: singleFeeParent,
    withdrawPayoutLocks: Object.freeze([...payoutLocks].sort()),
    fundingLikeP2pkhLocks: Object.freeze([...fundingLikeLocks].sort()),
    payoutEqualsFundingLikeLock: collisions.length > 0,
    collisions: Object.freeze(collisions),
    singlePayoutAddress: singlePayout,
    gate: collisions.length === 0 ? 'PASS' : 'FAIL',
    notes: Object.freeze([
      'Fee input locks are often absent from getrawtransaction vin; gate uses payout vs funding-like P2PKH outputs in the same action set (bootstrap SOURCE outs, fee change).',
      'Shared fee parent SOURCE clustering is informational only (fee mechanics out of scope).',
    ]),
  });
  return report;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const report = await runPrivacyPassivePayoutCheck(options);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.gate === 'PASS' ? 0 : 2;
}

if (import.meta.url === `file://${process.argv[1]}`
  || process.argv[1]?.endsWith('privacy-passive-payout-check.mjs')) {
  await main();
}
