import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';

import {
  admitExactTransactionToMempool,
  optionalTmaPreflight,
  observeMempoolMembership,
  transactionIdFromHex,
  acceptanceEvidenceFromAdmit,
  AdmissionError,
} from './admission.mjs';

function fakeTxHex() {
  // Minimal even-length hex (not a real tx; only for id hashing tests)
  return '00'.repeat(100);
}

function makeRpc({
  mempool = new Set(),
  tmaAllowed = true,
  sendOk = true,
  readbackHex = null,
} = {}) {
  const calls = [];
  return {
    calls,
    async testmempoolaccept(hex) {
      calls.push(['tma', hex]);
      const txid = transactionIdFromHex(hex);
      return [{ allowed: tmaAllowed, txid }];
    },
    async sendrawtransaction(hex) {
      calls.push(['send', hex]);
      if (!sendOk) throw new Error('send failed');
      const txid = transactionIdFromHex(hex);
      mempool.add(txid);
      return txid;
    },
    async getmempoolentry(txid) {
      calls.push(['getmempoolentry', txid]);
      if (!mempool.has(txid)) throw new Error('not in mempool');
      return { size: 100, fee: 0.0001, time: 1 };
    },
    async getrawmempool() {
      calls.push(['getrawmempool']);
      return [...mempool];
    },
    async getrawtransaction(txid, verbose) {
      calls.push(['getrawtransaction', txid, verbose]);
      const hex = readbackHex ?? [...mempool].includes(txid) ? null : null;
      // find hex from last send
      const lastSend = [...calls].reverse().find((c) => c[0] === 'send');
      const h = readbackHex ?? lastSend?.[1];
      return { txid, hex: h };
    },
  };
}

test('transactionIdFromHex is deterministic double-sha256 LE', () => {
  const hex = fakeTxHex();
  const a = transactionIdFromHex(hex);
  const b = transactionIdFromHex(hex);
  assert.equal(a, b);
  assert.match(a, /^[0-9a-f]{64}$/);
  // manual
  const first = createHash('sha256').update(Buffer.from(hex, 'hex')).digest();
  const expected = createHash('sha256').update(first).digest().reverse().toString('hex');
  assert.equal(a, expected);
});

test('optionalTmaPreflight never labels acceptance', async () => {
  const hex = fakeTxHex();
  const rpc = makeRpc();
  const r = await optionalTmaPreflight(rpc, hex);
  assert.equal(r.preflight, 'tma');
  assert.equal(r.acceptance, false);
  assert.equal(r.label, 'policy_preflight_only');
  assert.equal(r.allowed, true);
});

test('admitExactTransactionToMempool: mempool membership is acceptance, TMA optional', async () => {
  const hex = fakeTxHex();
  const txid = transactionIdFromHex(hex);
  const mempool = new Set();
  const rpc = makeRpc({ mempool, tmaAllowed: true, readbackHex: hex });
  // force getrawtransaction to return exact hex
  rpc.getrawtransaction = async (id) => {
    assert.equal(id, txid);
    return { txid, hex };
  };

  const result = await admitExactTransactionToMempool({
    rpc,
    rawTransactionHex: hex,
    expectedTransactionId: txid,
    runTmaPreflight: true,
    beforeSendAttempt: async () => {},
  });

  assert.equal(result.accepted, true);
  assert.equal(result.acceptanceMethod, 'mempool_membership');
  assert.equal(result.tmaIsAcceptance, false);
  assert.equal(result.acceptance.txid, txid);
  assert.equal(result.acceptance.txid.length, 64);
  assert.equal(result.readback.match, true);
  assert.ok(rpc.calls.some((c) => c[0] === 'send'));
  assert.ok(rpc.calls.some((c) => c[0] === 'getmempoolentry' || c[0] === 'getrawmempool'));

  const evidence = acceptanceEvidenceFromAdmit(result);
  assert.equal(evidence.accepted, true);
  assert.equal(evidence.tmaIsAcceptance, false);
  assert.equal(evidence.txid.length, 64);
});

test('admit rejects when mempool not observed after send', async () => {
  const hex = fakeTxHex();
  const txid = transactionIdFromHex(hex);
  const rpc = makeRpc({ sendOk: true });
  // send does not add to mempool in this stub override
  rpc.sendrawtransaction = async () => txid;
  rpc.getmempoolentry = async () => {
    throw new Error('absent');
  };
  rpc.getrawmempool = async () => [];

  await assert.rejects(
    () => admitExactTransactionToMempool({
      rpc,
      rawTransactionHex: hex,
      expectedTransactionId: txid,
      beforeSendAttempt: async () => {},
    }),
    (err) => err instanceof AdmissionError && err.code === 'MEMPOOL_NOT_OBSERVED',
  );
});

test('observeMempoolMembership uses getmempoolentry when present', async () => {
  const txid = 'ab'.repeat(32);
  const rpc = {
    async getmempoolentry(id) {
      assert.equal(id, txid);
      return { size: 1 };
    },
  };
  const r = await observeMempoolMembership(rpc, txid);
  assert.equal(r.present, true);
  assert.equal(r.method, 'getmempoolentry');
});
