import assert from 'node:assert/strict';
import test from 'node:test';
import {
  settlementLogLooksComplete,
  applySettlementLog,
  SettlementLogFetchError,
} from './chain-settlement-log.mjs';

test('settlementLogLooksComplete: missing log', () => {
  assert.equal(settlementLogLooksComplete(null, '5'), false);
  assert.equal(settlementLogLooksComplete({}, '1'), false);
  assert.equal(settlementLogLooksComplete({ genesisHex: 'aa', settles: null }, '1'), false);
});

test('settlementLogLooksComplete: genesis tip seq 0 allows empty settles', () => {
  assert.equal(
    settlementLogLooksComplete({ genesisHex: '00', settles: [] }, '0'),
    true,
  );
  assert.equal(
    settlementLogLooksComplete({ genesisHex: '00', settles: [] }, 0),
    true,
  );
  assert.equal(
    settlementLogLooksComplete({ genesisHex: '00', settles: [] }, '3'),
    false,
  );
});

test('settlementLogLooksComplete: settles count ≥ tip seq', () => {
  const log = { genesisHex: '00', settles: ['a', 'b', 'c'] };
  assert.equal(settlementLogLooksComplete(log, '3'), true);
  assert.equal(settlementLogLooksComplete(log, '2'), true);
  assert.equal(settlementLogLooksComplete(log, '4'), false);
});

test('applySettlementLog writes fetchedAt + depth', () => {
  const state = applySettlementLog({}, {
    genesisTxid: '11'.repeat(32),
    genesisHex: 'dead',
    settles: ['aa', 'bb'],
    settleTxids: ['t1', 't2'],
    depth: 2,
  });
  assert.equal(state.settlementLog.depth, 2);
  assert.equal(state.settlementLog.settles.length, 2);
  assert.ok(state.settlementLog.fetchedAt);
  assert.equal(state.settlementLog.genesisTxid, '11'.repeat(32));
});

test('SettlementLogFetchError has code', () => {
  const e = new SettlementLogFetchError('DEPTH', 'too deep', { last: 'x' });
  assert.equal(e.code, 'DEPTH');
  assert.equal(e.last, 'x');
  assert.equal(e.name, 'SettlementLogFetchError');
});
