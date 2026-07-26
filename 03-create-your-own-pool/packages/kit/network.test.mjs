import assert from 'node:assert/strict';
import test from 'node:test';
import {
  assertBroadcastAllowed,
  defaultNetworkName,
  explorerTxUrl,
  resolveNetwork,
  AppKitNetworkError,
  PRODUCT_STATUS,
  productWarnings,
} from './network.mjs';

test('default network is chipnet', () => {
  assert.equal(defaultNetworkName(), 'chipnet');
  assert.equal(resolveNetwork().name, 'chipnet');
  assert.equal(resolveNetwork('chipnet').networkId, 2);
});

test('mainnet resolves with distinct explorer template', () => {
  const m = resolveNetwork('mainnet');
  // Pin SCAR id matches chipnet (2) until circuit recompile; BCH chain is still mainnet.
  assert.equal(m.networkId, 2);
  assert.equal(m.cashAddrPrefix, 'bitcoincash');
  const txid = 'ab'.repeat(32);
  const url = explorerTxUrl('mainnet', txid);
  assert.ok(url.includes(txid));
  assert.ok(!url.includes('chipnet'));
});

test('chipnet explorer template', () => {
  const url = explorerTxUrl('chipnet', 'cd'.repeat(32));
  assert.match(url, /chipnet\.chaingraph\.cash/);
});

test('chipnet broadcast always allowed', () => {
  const r = assertBroadcastAllowed({ network: 'chipnet' });
  assert.equal(r.ok, true);
});

test('mainnet broadcast without ack refuses', () => {
  assert.throws(
    () => assertBroadcastAllowed({ network: 'mainnet' }),
    (e) => e instanceof AppKitNetworkError && e.code === 'MAINNET_ACK_REQUIRED',
  );
});

test('mainnet + development-only without lab override refuses', () => {
  assert.throws(
    () => assertBroadcastAllowed({
      network: 'mainnet',
      mainnetAcknowledged: true,
      setupMode: 'development-only',
    }),
    (e) => e instanceof AppKitNetworkError && e.code === 'DEVELOPMENT_PROFILE_ON_MAINNET',
  );
});

test('mainnet + development-only with lab override allowed', () => {
  const r = assertBroadcastAllowed({
    network: 'mainnet',
    mainnetAcknowledged: true,
    setupMode: 'development-only',
    allowDevelopmentOnMainnet: true,
  });
  assert.equal(r.ok, true);
  assert.equal(r.lab, true);
});

test('mainnet + ceremony profile with ack allowed', () => {
  const r = assertBroadcastAllowed({
    network: 'mainnet',
    mainnetAcknowledged: true,
    setupMode: 'ceremony-production',
  });
  assert.equal(r.ok, true);
});

test('unknown network fails', () => {
  assert.throws(() => resolveNetwork('tempnet'), AppKitNetworkError);
});

test('productWarnings always includes Unaudited WIP', () => {
  assert.match(PRODUCT_STATUS.status, /Unaudited/);
  const chip = productWarnings({ network: 'chipnet', setupMode: 'development-only' });
  assert.ok(chip.some((w) => /Unaudited/i.test(w)));
  const main = productWarnings({ network: 'mainnet', setupMode: 'ceremony-production' });
  assert.ok(main.some((w) => /MAINNET/i.test(w)));
  assert.ok(main.some((w) => /Work In Progress/i.test(w)));
});
