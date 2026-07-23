import assert from 'node:assert/strict';
import test from 'node:test';
import {
  finalizePreparationTransaction,
  planPreparationTransaction,
  PreparationTransactionError,
} from './preparation-transaction.mjs';

const hex = (byte, bytes) => byte.toString(16).padStart(2, '0').repeat(bytes);
const base = (kind = 'deposit') => ({
  bindingCarrierBaseValueSatoshis: '1000',
  bindingLockingBytecode: '51',
  fundingOutpointIndex: '3',
  fundingOutpointTransactionHashWire: Buffer.from(
    Array.from({ length: 32 }, (_, index) => (index * 17 + 9) & 0xff),
  ).toString('hex'),
  fundingPublicKey: `02${hex(0x22, 32)}`,
  fundingSourceValueSatoshis: kind === 'deposit' ? '10200000' : '200000',
  kind,
  minimumFeeRateSatoshisPerByte: '1',
  settlementFeeFundingSatoshis: '100000',
});

test('plans and finalizes canonical sibling preparation outputs for all actions', () => {
  for (const kind of ['deposit', 'transfer', 'withdrawal']) {
    const value = base(kind);
    const plan = planPreparationTransaction(value);
    const result = finalizePreparationTransaction(value, hex(0x33, 64));
    assert.equal(plan.measurements.plannedSignedWireBytes, result.measurements.wireBytes);
    assert.equal(result.transaction.inputs[0].unlockingBytecode.length, 100);
    assert.equal(result.transaction.outputs.length, 3);
    assert.equal(
      result.outputValues.bindingSatoshis,
      kind === 'deposit' ? '10001000' : '1000',
    );
    assert.equal(
      BigInt(result.outputValues.preparationChangeSatoshis)
        + BigInt(result.outputValues.bindingSatoshis)
        + BigInt(result.outputValues.settlementFeeFundingSatoshis)
        + BigInt(result.measurements.feeSatoshis),
      BigInt(value.fundingSourceValueSatoshis),
    );
    assert.equal(result.settlementOutpoints.binding.outpointIndex, '0');
    assert.equal(result.settlementOutpoints.fee.outpointIndex, '1');
    assert.equal(
      result.settlementOutpoints.binding.outpointTransactionHashWire,
      result.settlementOutpoints.fee.outpointTransactionHashWire,
    );
    assert.equal(
      result.transactionId,
      Buffer.from(
        result.settlementOutpoints.binding.outpointTransactionHashWire,
        'hex',
      ).reverse().toString('hex'),
    );
    assert.deepEqual(
      result.transaction.outputs[1].lockingBytecode,
      result.transaction.outputs[2].lockingBytecode,
    );
  }
});

test('rejects malformed keys, outpoints, locks, amounts, and insufficient funding', () => {
  const mutations = [
    (value) => { value.kind = 'mint'; },
    (value) => { value.bindingCarrierBaseValueSatoshis = '0'; },
    (value) => { value.bindingLockingBytecode = ''; },
    (value) => { value.bindingLockingBytecode = hex(0x51, 191); },
    (value) => { value.fundingOutpointTransactionHashWire = hex(1, 31); },
    (value) => { value.fundingOutpointIndex = '01'; },
    (value) => { value.fundingPublicKey = `04${hex(2, 32)}`; },
    (value) => { value.settlementFeeFundingSatoshis = '545'; },
    (value) => { value.minimumFeeRateSatoshisPerByte = '0'; },
    (value) => { value.fundingSourceValueSatoshis = '100'; },
  ];
  for (const mutate of mutations) {
    const value = structuredClone(base());
    mutate(value);
    assert.throws(() => planPreparationTransaction(value), PreparationTransactionError);
  }
  assert.throws(
    () => finalizePreparationTransaction(base(), hex(1, 63)),
    PreparationTransactionError,
  );
});

test('charges exactly one satoshi per byte without reserve use or dust burn', () => {
  const value = base('transfer');
  const result = finalizePreparationTransaction(value, hex(0x44, 64));
  assert.equal(
    result.measurements.feeSatoshis,
    BigInt(result.measurements.wireBytes).toString(),
  );
  assert.ok(BigInt(result.outputValues.preparationChangeSatoshis) >= 546n);
  assert.equal(result.measurements.percentageHeadroomRequired, false);
});
