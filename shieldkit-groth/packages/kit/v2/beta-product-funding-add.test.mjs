import assert from 'node:assert/strict';
import test from 'node:test';

import {
  addV2BetaProductFundingUtxoForTest,
  V2BetaProductFundingAddError,
} from './beta-product-funding-add.mjs';

const TXID = '11'.repeat(32);
const LOCK = `76a914${'22'.repeat(20)}88ac`;

function subject(overrides = {}) {
  let clock = 0;
  let closed = 0;
  const available = [];
  const context = {
    identity: { profileId: '33'.repeat(32), instanceId: '44'.repeat(32) },
    rpc: {
      getrawtransaction: async () => ({ txid: TXID, hex: 'raw' }),
      gettxout: async () => ({ valueSatoshis: '12000000', scriptPubKey: { hex: LOCK } }),
    },
    store: {
      activeOperation: () => null,
      optimisticTip: () => ({ outpoint: { txid: Buffer.from('55'.repeat(32), 'hex'), vout: 0 } }),
      availableFundingUtxos: () => available,
      admitAvailableFundingUtxo: value => { available.push(value); return { added: true }; },
    },
    wallet: {
      spendableFundingWallets: () => [{
        source: 'funding-keyring', lockingBytecodeHex: LOCK,
        attachedOutpoint: null, attachedValueSats: null,
      }],
    },
    close: () => { closed += 1; },
    ...overrides.context,
  };
  const dependencies = {
    now: () => { clock += 1; return clock; },
    openContext: async () => context,
    parseRaw: () => ({ txid: TXID, outputs: [{}, { serializedHex: 'output' }] }),
    parseOutput: () => ({ valueSatoshis: 12000000n, token: null, lockingBytecodeHex: LOCK }),
    ...overrides.dependencies,
  };
  return { available, context, dependencies, get closed() { return closed; } };
}

test('authenticates, owns, and atomically admits one exact live tokenless UTXO without sending', async () => {
  const testSubject = subject();
  const result = await addV2BetaProductFundingUtxoForTest({
    config: {}, fundingUtxo: `${TXID}:1`, rpc: {},
  }, testSubject.dependencies);
  assert.equal(result.status, 'funding-utxo-registered-beta-unqualified');
  assert.deepEqual(result.fundingUtxo, { txid: TXID, vout: 1, valueSats: '12000000' });
  assert.equal(result.broadcasted, false);
  assert.equal(result.confirmed, false);
  assert.equal(result.productionQualified, false);
  assert.equal(testSubject.available.length, 1);
  assert.equal(testSubject.closed, 1);
});

test('rejects active operations, non-owned scripts, token outputs, spent rows, and the state tip', async () => {
  const cases = [
    subject({ context: { store: {
      activeOperation: () => ({ operationId: 'deposit.active' }),
      optimisticTip: () => ({ outpoint: { txid: Buffer.alloc(32), vout: 0 } }),
      availableFundingUtxos: () => [], admitAvailableFundingUtxo: () => ({ added: true }),
    } } }),
    subject({ context: { wallet: { spendableFundingWallets: () => [] } } }),
    subject({ dependencies: { parseOutput: () => ({ valueSatoshis: 12000000n, token: {}, lockingBytecodeHex: LOCK }) } }),
    subject({ context: { store: {
      activeOperation: () => null,
      optimisticTip: () => ({ outpoint: { txid: Buffer.from('55'.repeat(32), 'hex'), vout: 0 } }),
      availableFundingUtxos: () => [], admitAvailableFundingUtxo: () => { throw new Error('spent'); },
    } } }),
    subject({ context: { store: {
      activeOperation: () => null,
      optimisticTip: () => ({ outpoint: { txid: Buffer.from(TXID, 'hex'), vout: 1 } }),
      availableFundingUtxos: () => [], admitAvailableFundingUtxo: () => ({ added: true }),
    } } }),
  ];
  const expected = [
    'BETA_FUNDING_ADD_OPERATION_ACTIVE',
    'BETA_FUNDING_ADD_OWNERSHIP_REJECTED',
    'BETA_FUNDING_ADD_SOURCE_REJECTED',
    'BETA_FUNDING_ADD_COMMIT_REJECTED',
    'BETA_FUNDING_ADD_TIP_REJECTED',
  ];
  for (const [index, testSubject] of cases.entries()) {
    await assert.rejects(
      addV2BetaProductFundingUtxoForTest({
        config: {}, fundingUtxo: `${TXID}:1`, rpc: {},
      }, testSubject.dependencies),
      error => error instanceof V2BetaProductFundingAddError && error.code === expected[index],
    );
    assert.equal(testSubject.closed, 1);
  }
});

test('attached change ownership is outpoint- and value-specific and duplicate admission is idempotent', async () => {
  const attached = subject({ context: { wallet: { spendableFundingWallets: () => [{
    source: 'attached-change', lockingBytecodeHex: LOCK,
    attachedOutpoint: { txid: TXID, vout: 1 }, attachedValueSats: '12000000',
  }] } } });
  attached.available.push({ txid: Buffer.from(TXID, 'hex'), vout: 1, valueSats: '12000000' });
  attached.context.store.admitAvailableFundingUtxo = () => ({ added: false });
  const result = await addV2BetaProductFundingUtxoForTest({
    config: {}, fundingUtxo: `${TXID}:1`, rpc: {},
  }, attached.dependencies);
  assert.equal(result.status, 'funding-utxo-already-registered-beta-unqualified');

  const mismatch = subject({ context: { wallet: { spendableFundingWallets: () => [{
    source: 'attached-change', lockingBytecodeHex: LOCK,
    attachedOutpoint: { txid: TXID, vout: 2 }, attachedValueSats: '12000000',
  }] } } });
  await assert.rejects(
    addV2BetaProductFundingUtxoForTest({ config: {}, fundingUtxo: `${TXID}:1`, rpc: {} }, mismatch.dependencies),
    error => error.code === 'BETA_FUNDING_ADD_OWNERSHIP_REJECTED',
  );
});
