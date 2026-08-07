#!/usr/bin/env node
/**
 * ZERO-CONF FUNDING SELF-TEST (policy guard, 2026-08-07).
 *
 * The product NEVER waits for confirmations: a just-created UTXO must be
 * immediately visible in the funding view AND immediately spendable.
 *
 * Steps (no blocks, no waits, bounded < 5 min):
 *   1. consolidate 2 plain wallet UTXOs -> one output (broadcast, zero-conf)
 *   2. IMMEDIATELY scan via the mempool-inclusive funding view
 *   3. assert the fresh UTXO is present (mempool=true)
 *   4. IMMEDIATELY build + testmempoolaccept a small spend of the fresh UTXO
 *   5. assert the spend is accepted (zero-conf usability)
 *
 * Fails closed if ANY step requires or waits for a confirmation.
 */
import { readFileSync } from 'node:fs';
import { binToHex, encodeTransaction, generateSigningSerializationBch, hash256,
         secp256k1, encodeDataPush, SigningSerializationTypeBch, hexToBin } from '@bitauth/libauth';
import { scantxoutsetHot, rpcStdin } from './lib/chipnet-fund-spend.mjs';

const WALLET = process.env.CHIPNET_WALLET_PRIVATE ||
  '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4/wallet-private.json';
const wallet = JSON.parse(readFileSync(WALLET, 'utf8'));
const t0 = Date.now();
const okJson = (body) => { console.log(JSON.stringify(body, null, 2)); process.exit(0); };
const failJson = (code, message, extra = {}) => {
  console.log(JSON.stringify({ ok: false, code, error: message, ...extra }, null, 2));
  process.exit(2);
};

const hexToBytes = (h) => { const a = new Uint8Array(h.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16); return a; };

// 1. ensure >= 2 plain UTXOs (gettxout-validated, mempool-inclusive view);
//    if only one exists, SPLIT it into two halves (zero-conf, no block wait).
const { unspents, mempoolCount } = scantxoutsetHot(wallet.address);
const plain = (unspents || []).filter((u) => !(u.tokenData || u.token_data)).sort((a, b) => b.amount - a.amount);
const valid = [];
for (const u of plain) {
  const g = rpcStdin('gettxout', [u.txid, u.vout, true], 30_000);
  if (!g.parsed || g.parsed.value == null) continue;
  if (g.parsed.tokenData || g.parsed.token_data) continue;
  valid.push({ txid: u.txid, vout: u.vout, valueSats: BigInt(Math.round(Number(u.amount) * 1e8)), scriptPubKey: u.scriptPubKey });
}
if (valid.length < 2 && valid.length === 1) {
  // split the single UTXO into two halves
  const one = valid[0];
  const half = one.valueSats / 2n;
  const splitBuild = (splitFee) => {
    const tx = { version: 2,
      inputs: [{ outpointTransactionHash: hexToBytes(one.txid), outpointIndex: one.vout, unlockingBytecode: new Uint8Array(0), sequenceNumber: 0xfffffffe }],
      outputs: [{ lockingBytecode: Uint8Array.from(locking), valueSatoshis: half },
                { lockingBytecode: Uint8Array.from(locking), valueSatoshis: one.valueSats - half - splitFee }],
      locktime: 0 };
    const ser = generateSigningSerializationBch({ transaction: tx, sourceOutputs: [{ lockingBytecode: hexToBytes(one.scriptPubKey), valueSatoshis: one.valueSats }], inputIndex: 0 },
      { coveredBytecode: hexToBytes(one.scriptPubKey), signingSerializationType: new Uint8Array([SigningSerializationTypeBch.allOutputs]) });
    if (typeof ser === 'string') failJson('SIGN_FAILED', ser);
    const sighash = hash256(ser);
    const sig = secp256k1.signMessageHashDER(priv, sighash);
    if (typeof sig === 'string') failJson('SIGN_FAILED', sig);
    tx.inputs[0].unlockingBytecode = Uint8Array.from([...encodeDataPush(Uint8Array.from([...sig, SigningSerializationTypeBch.allOutputs])), ...encodeDataPush(pub)]);
    return binToHex(encodeTransaction(tx));
  };
  let splitFee = 2000n;
  let splitHex = splitBuild(splitFee);
  for (let it = 0; it < 6; it++) {
    const sizeFee = BigInt(splitHex.length / 2 + 1);
    if (sizeFee === splitFee) break;
    splitFee = sizeFee; splitHex = splitBuild(splitFee);
  }
  let splitAcc = rpcStdin('testmempoolaccept', [[splitHex]], 60_000);
  let splitAllowed = Array.isArray(splitAcc.parsed) && splitAcc.parsed[0]?.allowed === true;
  for (let bump = 1n; !splitAllowed && bump <= 6n; bump++) { splitFee += 1n; splitHex = splitBuild(splitFee); splitAcc = rpcStdin('testmempoolaccept', [[splitHex]], 60_000); splitAllowed = Array.isArray(splitAcc.parsed) && splitAcc.parsed[0]?.allowed === true; }
  if (!splitAllowed) failJson('SPLIT_REJECTED', JSON.stringify(splitAcc.parsed));
  const splitTxid = String(rpcStdin('sendrawtransaction', [splitHex], 60_000).parsed).trim();
  // immediately re-scan (zero-conf: the halves must be visible now)
  const { unspents: afterSplit } = scantxoutsetHot(wallet.address);
  for (let v = 0; v < 2; v++) {
    const halfUtxo = afterSplit.find((u) => u.txid === splitTxid && u.vout === v);
    if (!halfUtxo) failJson('SPLIT_UTXO_INVISIBLE', `split ${splitTxid}:${v} not visible (confirmed-only scan would require a block wait)`);
  }
}
// re-collect the (now >= 2) plain UTXOs
const { unspents: unspents2 } = scantxoutsetHot(wallet.address);
const plain2 = (unspents2 || []).filter((u) => !(u.tokenData || u.token_data)).sort((a, b) => b.amount - a.amount);
const pick = [];
let sum = 0n;
for (const u of plain2) {
  if (pick.length >= 2) break;
  const g = rpcStdin('gettxout', [u.txid, u.vout, true], 30_000);
  if (!g.parsed || g.parsed.value == null) continue;
  if (g.parsed.tokenData || g.parsed.token_data) continue;
  pick.push({ txid: u.txid, vout: u.vout, valueSats: BigInt(Math.round(Number(u.amount) * 1e8)), scriptPubKey: u.scriptPubKey });
  sum += BigInt(Math.round(Number(u.amount) * 1e8));
}
if (pick.length < 2) failJson('NOT_ENOUGH_UTXOS', `need 2 plain UTXOs, got ${pick.length}`);

// 2. consolidate (fee = size+1 fixpoint with DER-sig 2-cycle fallback)
const locking = Buffer.from(wallet.lockingBytecodeHex, 'hex');
const pub = hexToBin(wallet.publicKeyHex);
const priv = hexToBin(wallet.privateKeyHex);
const sourceOutputs = pick.map((p) => ({ lockingBytecode: hexToBytes(p.scriptPubKey), valueSatoshis: p.valueSats }));
const build = (fee) => {
  const tx = { version: 2,
    inputs: pick.map((p) => ({ outpointTransactionHash: hexToBytes(p.txid), outpointIndex: p.vout,
                               unlockingBytecode: new Uint8Array(0), sequenceNumber: 0xfffffffe })),
    outputs: [{ lockingBytecode: Uint8Array.from(locking), valueSatoshis: sum - fee }], locktime: 0 };
  for (let i = 0; i < pick.length; i++) {
    const ser = generateSigningSerializationBch({ transaction: tx, sourceOutputs, inputIndex: i },
      { coveredBytecode: sourceOutputs[i].lockingBytecode, signingSerializationType: new Uint8Array([SigningSerializationTypeBch.allOutputs]) });
    if (typeof ser === 'string') failJson('SIGN_FAILED', ser);
    const sighash = hash256(ser);
    const sig = secp256k1.signMessageHashDER(priv, sighash);
    if (typeof sig === 'string') failJson('SIGN_FAILED', sig);
    tx.inputs[i].unlockingBytecode = Uint8Array.from([...encodeDataPush(Uint8Array.from([...sig, SigningSerializationTypeBch.allOutputs])), ...encodeDataPush(pub)]);
  }
  return binToHex(encodeTransaction(tx));
};
let fee = 2000n;
let hex = build(fee);
for (let it = 0; it < 6; it++) {
  const sizeFee = BigInt(hex.length / 2 + 1);
  if (sizeFee === fee) break;
  fee = sizeFee; hex = build(fee);
}
let converged = BigInt(hex.length / 2 + 1) === fee;
for (let delta = -5n; delta <= 5n && !converged; delta++) {
  const cand = fee + delta; if (cand <= 0n) continue;
  const h = build(cand);
  if (BigInt(h.length / 2 + 1) === cand) { fee = cand; hex = h; converged = true; }
}
let acc = rpcStdin('testmempoolaccept', [[hex]], 60_000);
let allowed = Array.isArray(acc.parsed) && acc.parsed[0]?.allowed === true;
for (let bump = 1n; !allowed && bump <= 6n; bump++) { fee += 1n; hex = build(fee); acc = rpcStdin('testmempoolaccept', [[hex]], 60_000); allowed = Array.isArray(acc.parsed) && acc.parsed[0]?.allowed === true; }
if (!allowed) failJson('CONSOLIDATE_REJECTED', JSON.stringify(acc.parsed));
const fundTxid = String(rpcStdin('sendrawtransaction', [hex], 60_000).parsed).trim();

// 3. IMMEDIATELY re-scan (zero-conf: no block, no wait)
const { unspents: fresh, mempoolCount: freshMempool } = scantxoutsetHot(wallet.address);
const freshUtxo = fresh.find((u) => u.txid === fundTxid && u.vout === 0);
if (!freshUtxo) {
  failJson('FRESH_UTXO_INVISIBLE', `consolidation ${fundTxid}:0 not visible in the mempool-inclusive view (confirmed-only scan would require a block wait)`, { fundTxid });
}

// 4. IMMEDIATELY spend the fresh UTXO (small self-send) — zero-conf usability
const spendBuild = (spendFee) => {
  const tx = { version: 2,
    inputs: [{ outpointTransactionHash: hexToBytes(fundTxid), outpointIndex: 0, unlockingBytecode: new Uint8Array(0), sequenceNumber: 0xfffffffe }],
    outputs: [{ lockingBytecode: Uint8Array.from(locking), valueSatoshis: freshUtxo.valueSats !== undefined ? BigInt(Math.round(freshUtxo.amount * 1e8)) - spendFee : sum - fee - spendFee }], locktime: 0 };
  const ser = generateSigningSerializationBch({ transaction: tx, sourceOutputs: [{ lockingBytecode: hexToBytes(freshUtxo.scriptPubKey), valueSatoshis: sum - fee }], inputIndex: 0 },
    { coveredBytecode: hexToBytes(freshUtxo.scriptPubKey), signingSerializationType: new Uint8Array([SigningSerializationTypeBch.allOutputs]) });
  if (typeof ser === 'string') failJson('SIGN_FAILED', ser);
  const sighash = hash256(ser);
  const sig = secp256k1.signMessageHashDER(priv, sighash);
  if (typeof sig === 'string') failJson('SIGN_FAILED', sig);
  tx.inputs[0].unlockingBytecode = Uint8Array.from([...encodeDataPush(Uint8Array.from([...sig, SigningSerializationTypeBch.allOutputs])), ...encodeDataPush(pub)]);
  return binToHex(encodeTransaction(tx));
};
let spendHex = spendBuild(2000n);
let spendFee = 2000n;
for (let it = 0; it < 6; it++) {
  const sizeFee = BigInt(spendHex.length / 2 + 1);
  if (sizeFee === spendFee) break;
  spendFee = sizeFee; spendHex = spendBuild(spendFee);
}
const spendAcc = rpcStdin('testmempoolaccept', [[spendHex]], 60_000);
const spendAllowed = Array.isArray(spendAcc.parsed) && spendAcc.parsed[0]?.allowed === true;
if (!spendAllowed) failJson('FRESH_UTXO_NOT_SPENDABLE', `fresh ${fundTxid}:0 spend rejected: ${JSON.stringify(spendAcc.parsed)}`, { fundTxid });

okJson({
  ok: true,
  schema: 'shieldkit-fri-zero-conf-funding-self-test-v1',
  wallSeconds: (Date.now() - t0) / 1000,
  confirmationsWaited: 0,
  fundTxid,
  freshUtxoVisible: true,
  freshUtxoSpendable: true,
  mempoolCountBefore: mempoolCount,
  mempoolCountAfter: freshMempool,
  note: 'zero-conf policy verified: a just-created UTXO is immediately visible and spendable; no block wait anywhere',
  timestamp: new Date().toISOString(),
});
