import assert from 'node:assert/strict';
import test from 'node:test';

import {
  DIRECT_V2_CONTEXT_HEADER_BYTES,
  DIRECT_V2_CONTEXT_INPUT_BYTES,
  DIRECT_V2_CONTEXT_OUTPUT_BYTES,
  DirectV2ContextError,
  encodeDirectV2TransactionContext,
  hashDirectV2TransactionContext,
  validateDirectV2RoleTopology,
} from './context.mjs';

const role = (kind, ordinal = 0) => ({ kind, ordinal: String(ordinal) });
const input = (kind, ordinal, byte, token = false) => ({
  role: role(kind, ordinal),
  outpointTransactionHash: byte.repeat(32),
  outpointIndex: String(ordinal),
  sequence: '4294967295',
  valueSats: '1000',
  lockingBytecode: Uint8Array.of(Number.parseInt(byte, 16)),
  tokenPrefix: token ? Uint8Array.of(0xef, Number.parseInt(byte, 16)) : new Uint8Array(),
});
const output = (kind, ordinal, byte, token = false) => ({
  role: role(kind, ordinal),
  valueSats: '1000',
  lockingBytecode: Uint8Array.of(Number.parseInt(byte, 16)),
  tokenPrefix: token ? Uint8Array.of(0xef, Number.parseInt(byte, 16)) : new Uint8Array(),
});

function fixture(kind = 'deposit', carrierCount = 2) {
  const inputs = [
    ...Array.from({ length: carrierCount }, (_, index) => input('verifier', index, `0${index + 1}`)),
    input('binding', 0, '0a'),
    input('state', 0, '0b', true),
    input('funding', 0, '0c'),
  ];
  const outputs = [
    output('state', 0, '1a', true),
    ...Array.from({ length: carrierCount }, (_, index) => output('verifier', index, `1${index + 1}`)),
    output('binding', 0, '1d'),
    ...(kind === 'withdrawal' ? [output('withdrawal', 0, '1e')] : []),
    output('change', 0, '1f'),
  ];
  return {
    networkId: 2,
    kind,
    profileId: '11'.repeat(32),
    instanceId: '22'.repeat(32),
    transactionVersion: '2',
    locktime: '0',
    preActionSequence: '7',
    postActionSequence: '8',
    inputs,
    outputs,
  };
}

test('pins the canonical context size and SHA-256 for ordered rolling roles', () => {
  const context = fixture('deposit', 2);
  const encoded = encodeDirectV2TransactionContext(context, { carrierCount: 2 });
  assert.equal(encoded.length,
    DIRECT_V2_CONTEXT_HEADER_BYTES
      + (5 * DIRECT_V2_CONTEXT_INPUT_BYTES)
      + (5 * DIRECT_V2_CONTEXT_OUTPUT_BYTES));
  assert.equal(encoded.subarray(0, 8).toString('hex'), '5344433202010000');
  assert.equal(encoded.subarray(80, 84).toString('hex'), '05000500');
  assert.equal(
    hashDirectV2TransactionContext(context, { carrierCount: 2 }).toString('hex'),
    '9ce7bda7814769a8c9131e104174c01cad150c449a982a3d39c0e2335e12da5d',
  );
});

test('withdrawal topology has one additional exact tokenless payout role', () => {
  const context = fixture('withdrawal', 2);
  assert.equal(validateDirectV2RoleTopology(context, 2).outputs.length, 6);
  assert.equal(
    encodeDirectV2TransactionContext(context, { carrierCount: 2 }).length,
    DIRECT_V2_CONTEXT_HEADER_BYTES
      + (5 * DIRECT_V2_CONTEXT_INPUT_BYTES)
      + (6 * DIRECT_V2_CONTEXT_OUTPUT_BYTES),
  );
});

test('every bound transaction field changes the context hash', () => {
  const base = fixture('deposit', 2);
  const baseline = hashDirectV2TransactionContext(base, { carrierCount: 2 });
  const mutations = [
    { ...base, networkId: 1 },
    { ...base, kind: 'transfer' },
    { ...base, profileId: '12'.repeat(32) },
    { ...base, instanceId: '23'.repeat(32) },
    { ...base, transactionVersion: '3' },
    { ...base, locktime: '1' },
    { ...base, preActionSequence: '8', postActionSequence: '9' },
    { ...base, inputs: base.inputs.map((value, index) => index === 0 ? { ...value, outpointTransactionHash: '02'.repeat(32) } : value) },
    { ...base, inputs: base.inputs.map((value, index) => index === 0 ? { ...value, outpointIndex: '9' } : value) },
    { ...base, inputs: base.inputs.map((value, index) => index === 0 ? { ...value, sequence: '1' } : value) },
    { ...base, inputs: base.inputs.map((value, index) => index === 0 ? { ...value, valueSats: '1001' } : value) },
    { ...base, inputs: base.inputs.map((value, index) => index === 0 ? { ...value, lockingBytecode: Uint8Array.of(9) } : value) },
    { ...base, outputs: base.outputs.map((value, index) => index === 0 ? { ...value, valueSats: '1001' } : value) },
    { ...base, outputs: base.outputs.map((value, index) => index === 0 ? { ...value, lockingBytecode: Uint8Array.of(9) } : value) },
  ];
  for (const mutation of mutations) {
    assert.notDeepEqual(
      hashDirectV2TransactionContext(mutation, { carrierCount: 2 }),
      baseline,
    );
  }
});

test('rejects role/order/count/token/sequence and encoding ambiguity', () => {
  const base = fixture('deposit', 2);
  assert.throws(
    () => validateDirectV2RoleTopology({
      ...base,
      inputs: [base.inputs[1], base.inputs[0], ...base.inputs.slice(2)],
    }, 2),
    /wrong role/,
  );
  assert.throws(
    () => validateDirectV2RoleTopology({
      ...base,
      inputs: base.inputs.slice(0, -1),
    }, 2),
    /input count/,
  );
  assert.throws(
    () => validateDirectV2RoleTopology({
      ...base,
      inputs: base.inputs.map((value, index) => index === 4
        ? { ...value, tokenPrefix: Uint8Array.of(1) }
        : value),
    }, 2),
    /tokenless/,
  );
  assert.throws(
    () => encodeDirectV2TransactionContext({
      ...base,
      postActionSequence: '9',
    }),
    /increment/,
  );
  assert.throws(
    () => encodeDirectV2TransactionContext({
      ...base,
      transactionVersion: '02',
    }),
    /canonical/,
  );
  assert.throws(
    () => encodeDirectV2TransactionContext({
      ...base,
      inputs: base.inputs.map((value, index) => index === 0
        ? { ...value, extra: true }
        : value),
    }),
    DirectV2ContextError,
  );
});
