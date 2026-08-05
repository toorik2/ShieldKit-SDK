import assert from 'node:assert/strict';
import test from 'node:test';

import {
  inspectV2FundingUtxos,
  selectV2FundingUtxo,
  V2FundingUtxoSelectionError,
} from './funding-utxo-selector.mjs';

const FUNDING_LOCK = `76a914${'11'.repeat(20)}88ac`;

const rejectCode = (code) => (error) =>
  error instanceof V2FundingUtxoSelectionError && error.code === code;

function observedUtxo({
  lockingBytecodeHex = FUNDING_LOCK,
  token = null,
  txid = '00'.repeat(32),
  valueSats = '1000',
  vout = 0,
} = {}) {
  return Object.freeze({ lockingBytecodeHex, token, txid, valueSats, vout });
}

function request(utxos, requiredSats = '1000') {
  return { fundingLockingBytecodeHex: FUNDING_LOCK, requiredSats, utxos: Object.freeze(utxos) };
}

function inspectionRequest(utxos) {
  return { fundingLockingBytecodeHex: FUNDING_LOCK, utxos: Object.freeze(utxos) };
}

test('inspects every valid UTXO into an immutable canonical value/txid/vout order', () => {
  const observed = [
    observedUtxo({ txid: 'ff'.repeat(32), valueSats: '2', vout: 0 }),
    observedUtxo({ txid: 'bb'.repeat(32), valueSats: '1', vout: 9 }),
    observedUtxo({ txid: 'aa'.repeat(32), valueSats: '1', vout: 8 }),
    observedUtxo({ txid: 'aa'.repeat(32), valueSats: '1', vout: 2 }),
  ];
  const inspected = inspectV2FundingUtxos(inspectionRequest(observed));
  assert.deepEqual(inspected.map(({ valueSats, txid, vout }) => ({ valueSats, txid, vout })), [
    { valueSats: '1', txid: 'aa'.repeat(32), vout: 2 },
    { valueSats: '1', txid: 'aa'.repeat(32), vout: 8 },
    { valueSats: '1', txid: 'bb'.repeat(32), vout: 9 },
    { valueSats: '2', txid: 'ff'.repeat(32), vout: 0 },
  ]);
  assert.equal(Object.isFrozen(inspected), true);
  for (const utxo of inspected) {
    assert.equal(Object.isFrozen(utxo), true);
    assert.deepEqual(Object.keys(utxo).sort(), ['lockingBytecodeHex', 'token', 'txid', 'valueSats', 'vout']);
  }
  assert.throws(() => { inspected.push(observedUtxo()); }, TypeError);
  assert.throws(() => { inspected[0].valueSats = '999'; }, TypeError);
  assert.equal(inspected.some((utxo) => Object.hasOwn(utxo, 'value')), false);
});

test('inspection preserves selection rejection behavior and rejects inspection request widening', () => {
  const valid = observedUtxo({ txid: 'aa'.repeat(32), valueSats: '1000' });
  const invalidCases = [
    Object.freeze({ ...valid, token: { category: '00'.repeat(32) } }),
    Object.freeze({ ...valid, lockingBytecodeHex: `76a914${'22'.repeat(20)}88ac` }),
    Object.freeze({ ...valid, valueSats: '01000' }),
    Object.freeze({ ...valid, txid: 'AA'.repeat(32) }),
  ];
  for (const invalid of invalidCases) {
    assert.throws(
      () => inspectV2FundingUtxos(inspectionRequest([valid, invalid])),
      rejectCode('FUNDING_UTXO_OBSERVATION_INVALID'),
    );
    assert.throws(
      () => selectV2FundingUtxo(request([valid, invalid], '1')),
      rejectCode('FUNDING_UTXO_OBSERVATION_INVALID'),
    );
  }
  const duplicate = observedUtxo({ txid: valid.txid, vout: valid.vout, valueSats: '2000' });
  assert.throws(
    () => inspectV2FundingUtxos(inspectionRequest([valid, duplicate])),
    rejectCode('FUNDING_UTXO_OBSERVATION_INVALID'),
  );
  assert.throws(
    () => inspectV2FundingUtxos({ ...inspectionRequest([valid]), extra: true }),
    rejectCode('FUNDING_UTXO_OBSERVATION_INVALID'),
  );
});

test('selects exactly one smallest sufficient UTXO, then txid and vout deterministically', () => {
  const selected = selectV2FundingUtxo(request([
    observedUtxo({ txid: 'ff'.repeat(32), vout: 1, valueSats: '2000' }),
    observedUtxo({ txid: '22'.repeat(32), vout: 9, valueSats: '1500' }),
    observedUtxo({ txid: '11'.repeat(32), vout: 7, valueSats: '1500' }),
    observedUtxo({ txid: '11'.repeat(32), vout: 2, valueSats: '1500' }),
    observedUtxo({ txid: '01'.repeat(32), valueSats: '999' }),
  ], '1000'));
  assert.deepEqual(selected, {
    lockingBytecodeHex: FUNDING_LOCK,
    token: null,
    txid: '11'.repeat(32),
    valueSats: '1500',
    vout: 2,
  });
  assert.equal(Object.isFrozen(selected), true);
  assert.equal(Object.hasOwn(selected, 'privateKeyHex'), false);
  assert.throws(() => { selected.valueSats = '1'; }, TypeError);
});

test('does not accept mutable or structurally widened observations', () => {
  const mutableRecord = {
    lockingBytecodeHex: FUNDING_LOCK,
    token: null,
    txid: '00'.repeat(32),
    valueSats: '1000',
    vout: 0,
  };
  assert.throws(
    () => selectV2FundingUtxo({
      fundingLockingBytecodeHex: FUNDING_LOCK,
      requiredSats: '1',
      utxos: Object.freeze([mutableRecord]),
    }),
    rejectCode('FUNDING_UTXO_OBSERVATION_INVALID'),
  );
  const widened = Object.freeze({
    ...observedUtxo(),
    confirmations: 6,
  });
  assert.throws(
    () => selectV2FundingUtxo(request([widened], '1')),
    rejectCode('FUNDING_UTXO_OBSERVATION_INVALID'),
  );
  const withSymbol = observedUtxo();
  const symbolRecord = Object.freeze({ ...withSymbol, [Symbol('unsafe')]: true });
  assert.throws(
    () => selectV2FundingUtxo(request([symbolRecord], '1')),
    rejectCode('FUNDING_UTXO_OBSERVATION_INVALID'),
  );
});

test('fails closed on any malformed, wrong-lock, token, duplicate, or noncanonical list entry', () => {
  const valid = observedUtxo({ txid: 'aa'.repeat(32), valueSats: '1000' });
  const cases = [
    Object.freeze({ ...valid, txid: 'AA'.repeat(32) }),
    Object.freeze({ ...valid, vout: -1 }),
    Object.freeze({ ...valid, valueSats: '01000' }),
    Object.freeze({ ...valid, lockingBytecodeHex: `76a914${'22'.repeat(20)}88ac` }),
    Object.freeze({ ...valid, token: { category: '00'.repeat(32) } }),
    Object.freeze({ ...valid, valueSats: '2100000000000001' }),
  ];
  for (const invalid of cases) {
    assert.throws(
      () => selectV2FundingUtxo(request([valid, invalid], '1')),
      rejectCode('FUNDING_UTXO_OBSERVATION_INVALID'),
    );
  }
  assert.throws(
    () => selectV2FundingUtxo(request([
      valid,
      observedUtxo({ txid: valid.txid, vout: valid.vout, valueSats: '2000' }),
    ], '1')),
    rejectCode('FUNDING_UTXO_OBSERVATION_INVALID'),
  );
});

test('requires an exact positive canonical requirement and reports insufficient single-UTXO funding', () => {
  const available = [observedUtxo({ valueSats: '1000' })];
  for (const requiredSats of ['0', '01', '-1', '1.0', '2100000000000001']) {
    assert.throws(
      () => selectV2FundingUtxo(request(available, requiredSats)),
      rejectCode('FUNDING_UTXO_OBSERVATION_INVALID'),
    );
  }
  assert.throws(
    () => selectV2FundingUtxo(request(available, '1001')),
    rejectCode('FUNDING_UTXO_INSUFFICIENT'),
  );
});

test('rejects unsafe arrays, accessors, and outer request widening before selection', () => {
  const valid = observedUtxo();
  assert.throws(
    () => selectV2FundingUtxo({
      fundingLockingBytecodeHex: FUNDING_LOCK,
      requiredSats: '1',
      utxos: [valid],
    }),
    rejectCode('FUNDING_UTXO_OBSERVATION_INVALID'),
  );
  const accessor = {};
  Object.defineProperties(accessor, {
    lockingBytecodeHex: { enumerable: true, get: () => FUNDING_LOCK },
    token: { enumerable: true, value: null },
    txid: { enumerable: true, value: '00'.repeat(32) },
    valueSats: { enumerable: true, value: '1000' },
    vout: { enumerable: true, value: 0 },
  });
  assert.throws(
    () => selectV2FundingUtxo(request([Object.freeze(accessor)], '1')),
    rejectCode('FUNDING_UTXO_OBSERVATION_INVALID'),
  );
  assert.throws(
    () => selectV2FundingUtxo({ ...request([valid], '1'), extra: true }),
    rejectCode('FUNDING_UTXO_OBSERVATION_INVALID'),
  );
});
