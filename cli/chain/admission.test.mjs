import assert from 'node:assert/strict';
import test from 'node:test';

import {
  assertProductTransport,
  createSingleSendAdmission,
  createChainReader,
  CHIPNET_GENESIS_HASH,
  transactionIdFromHex,
} from './admission.mjs';
import { CliError } from '../contracts/errors.mjs';

test('maintainer SSH transport forbidden on product path', () => {
  assert.throws(
    () => assertProductTransport({ kind: 'ssh', maintainer: true }),
    (e) => e instanceof CliError && e.code === 'MAINTAINER_PATH_FORBIDDEN',
  );
  assert.throws(
    () => assertProductTransport({ kind: 'ambient-env' }),
    (e) => e instanceof CliError && e.code === 'AMBIENT_CONFIG_FORBIDDEN',
  );
});

test('SingleSendAdmission accepts via mempool membership; tip observation separate', async () => {
  const hex = 'cd'.repeat(80);
  const txid = transactionIdFromHex(hex);
  const mempool = new Set();
  let last = null;
  const rpc = {
    async sendrawtransaction(h) {
      last = h;
      const id = transactionIdFromHex(h);
      mempool.add(id);
      return id;
    },
    async getmempoolentry(id) {
      if (!mempool.has(id)) throw new Error('x');
      return { size: 1 };
    },
    async getrawtransaction(id) {
      return { txid: id, hex: last };
    },
    async getblockchaininfo() {
      return { blocks: 100, bestblockhash: 'ff'.repeat(32), chain: 'chipnet' };
    },
    async getblockhash(height) { assert.equal(height, 0); return CHIPNET_GENESIS_HASH; },
  };
  const admission = createSingleSendAdmission(rpc);
  const r = await admission.sendOnce({
    rawTransactionHex: hex,
    expectedTransactionId: txid,
  });
  assert.equal(r.accepted, true);
  assert.equal(r.acceptanceMethod, 'mempool_membership');
  assert.equal(r.tmaIsAcceptance, false);
  assert.equal(r.txid.length, 64);

  const reader = createChainReader(rpc);
  const tip = await reader.getTip();
  assert.equal(tip.kind, 'tip');
  assert.equal(tip.height, 100);
});

test('SingleSendAdmission returns rejected:true for policy/TMA rejects without mutation', async () => {
  const hex = 'ab'.repeat(60);
  const txid = transactionIdFromHex(hex);
  let sendCalled = false;
  const rpc = {
    async testmempoolaccept() {
      return [{ allowed: false, txid, 'reject-reason': 'min relay fee not met' }];
    },
    async sendrawtransaction() {
      sendCalled = true;
      throw new Error('should not send after TMA reject');
    },
  };
  const admission = createSingleSendAdmission(rpc);
  const r = await admission.sendOnce({
    rawTransactionHex: hex,
    expectedTransactionId: txid,
  });
  assert.equal(r.rejected, true);
  assert.equal(r.accepted, false);
  assert.equal(r.indeterminate, false);
  assert.equal(r.tmaIsAcceptance, false);
  assert.equal(r.sendAttempted, false);
  assert.equal(r.mutationCrossed, false);
  assert.equal(sendCalled, false);

  const pre = await admission.preflight(hex, txid);
  assert.equal(pre.rejected, true);
  assert.equal(pre.sendAttempted, false);
  assert.equal(pre.mutationCrossed, false);
});

test('SingleSendAdmission returns indeterminate for network blip after send start', async () => {
  const hex = 'ef'.repeat(60);
  const txid = transactionIdFromHex(hex);
  const rpc = {
    async sendrawtransaction() {
      throw new Error('ECONNRESET');
    },
  };
  const admission = createSingleSendAdmission(rpc);
  const r = await admission.sendOnce({
    rawTransactionHex: hex,
    expectedTransactionId: txid,
  });
  assert.equal(r.indeterminate, true);
  assert.equal(r.rejected, false);
  assert.equal(r.accepted, false);
});

test('missing exact readback remains send-indeterminate, not accepted', async () => {
  const hex = 'ab'.repeat(61); const txid = transactionIdFromHex(hex); const mempool = new Set();
  const admission = createSingleSendAdmission({
    async sendrawtransaction(raw) { const id = transactionIdFromHex(raw); mempool.add(id); return id; },
    async getmempoolentry(id) { if (!mempool.has(id)) throw new Error('missing'); return {}; },
  });
  const result = await admission.sendOnce({ rawTransactionHex: hex, expectedTransactionId: txid });
  assert.equal(result.accepted, false); assert.equal(result.indeterminate, true); assert.match(result.error, /readback capability/);
});

test('ChainReader actively authenticates block zero and rejects non-Chipnet RPCs', async () => {
  const badGenesis = createChainReader({
    async getblockhash() { return '00'.repeat(32); },
    async getblockchaininfo() { return { chain: 'chipnet', blocks: 1 }; },
  });
  await assert.rejects(() => badGenesis.getTip(), /GENESIS_MISMATCH/);
  const main = createChainReader({
    async getblockhash() { return CHIPNET_GENESIS_HASH; },
    async getblockchaininfo() { return { chain: 'main', blocks: 1 }; },
  });
  await assert.rejects(() => main.getTip(), /CHAIN_MISMATCH/);
});
