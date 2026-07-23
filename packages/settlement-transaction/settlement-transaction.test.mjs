// Structural builder tests use compact accepting-looking fixture scripts only
// to test serialization and fail-closed policy. They are not BCH VM or G2
// acceptance evidence.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { encodeActionPacket } from '../action-packet/action-packet.mjs';
import { encodeSettlementContext, INPUT_ROLES } from '../settlement-context/settlement-context.mjs';
import { encodeStateNftCommitment } from '../state-nft/state-nft.mjs';
import {
  buildSettlementTransaction,
  SettlementTransactionError,
} from './settlement-transaction.mjs';

const hex = (byte, bytes) => byte.toString(16).padStart(2, '0').repeat(bytes);
const profileId = hex(0x11, 32);
const instanceId = hex(0x22, 32);
const category = hex(0x33, 32);
const verifierLock = (index) => `aa20${hex(index + 1, 32)}87`;
const p2s = (opcode) => opcode.toString(16).padStart(2, '0');
const feePublicKey = `02${hex(0xbc, 32)}`;
const feePublicKeyHash = createHash('ripemd160')
  .update(createHash('sha256').update(Buffer.from(feePublicKey, 'hex')).digest())
  .digest('hex');
const feeLock = `76a914${feePublicKeyHash}88ac`;
const feeUnlock = `41${hex(0xcd, 64)}4121${feePublicKey}`;
const outpoint = (index) => Buffer.from(
  Array.from({ length: 32 }, (_, offset) => (index * 37 + offset * 11 + 3) & 0xff),
).toString('hex');
const state = (sequence, reserve, commitment) => ({
  profileId,
  instanceId,
  noteRoot: hex(0x44, 32),
  nullifierRoot: hex(0x55, 32),
  nextLeafIndex: sequence,
  actionSequence: sequence,
  liveNoteCount: reserve === '0' ? '0' : '1',
  reserveSats: reserve,
  maximumReserve: '30000000',
  stateCommitment: hex(commitment, 32),
});
const stateToken = (stateValue) => ({
  category,
  amount: '0',
  nft: {
    capability: 'mutable',
    commitment: encodeStateNftCommitment({
      networkId: 2,
      profileId,
      stateCommitment: stateValue.stateCommitment,
      actionSequence: stateValue.actionSequence,
    }).toString('hex'),
  },
});
const output = (lockingBytecode, valueSatoshis, token = null) => ({
  lockingBytecode,
  valueSatoshis,
  token,
});

function fixture(kind = 'deposit') {
  const pre = state('0', kind === 'withdrawal' ? '10000000' : '0', 0x66);
  const post = state('1', kind === 'deposit' ? '10000000' : '0', 0x77);
  if (kind === 'transfer') {
    pre.reserveSats = '10000000';
    pre.liveNoteCount = '1';
    post.reserveSats = '10000000';
    post.liveNoteCount = '1';
  }
  const withdrawalLock = '76a914' + hex(0xaa, 20) + '88ac';
  const outputs = kind === 'withdrawal'
    ? [
        output(p2s(0x51), '1000', stateToken(post)),
        output(withdrawalLock, '10000000'),
        output(feeLock, '40000'),
      ]
    : [
        output(p2s(0x51), kind === 'deposit' ? '10001000' : '10001000', stateToken(post)),
        output(feeLock, '40000'),
      ];
  const sourceOutputs = INPUT_ROLES.map((_, index) => {
    if (index < 7) return output(verifierLock(index), '1000');
    if (index === 7) return output(p2s(0x51), kind === 'deposit' ? '10001000' : '1000');
    if (index === 8) return output(p2s(0x51), (1000n + BigInt(pre.reserveSats)).toString(), stateToken(pre));
    return output(feeLock, '100000');
  });
  const inputMetadata = INPUT_ROLES.map((_, index) => ({
    outpointTransactionHashWire: [7, 9].includes(index) ? outpoint(7) : outpoint(index),
    outpointIndex: index === 7 ? '0' : index === 9 ? '1' : String(index),
    sequenceNumber: '0',
  }));
  const context = encodeSettlementContext({
    kind,
    profileId,
    instanceId,
    transaction: {
      version: '2',
      locktime: '0',
      inputs: inputMetadata,
      outputs,
    },
    sourceOutputs,
  });
  const actionPacket = encodeActionPacket({
    kind,
    networkId: 2,
    preState: pre,
    postState: post,
    inputCommitment: kind === 'deposit' ? hex(0, 32) : hex(0x88, 32),
    inputNullifier: kind === 'deposit' ? hex(0, 32) : hex(0x99, 32),
    outputCommitment: kind === 'withdrawal' ? hex(0, 32) : hex(0xaa, 32),
    outputRecord: Buffer.alloc(192, kind === 'withdrawal' ? 0 : 1),
    boundaryAmount: kind === 'transfer' ? '0' : '10000000',
    withdrawalScriptHash: kind === 'withdrawal'
      ? createHash('sha256').update(Buffer.from(withdrawalLock, 'hex')).digest('hex')
      : hex(0, 32),
    transactionContextDigest: context.digestHex,
  });
  const inputs = inputMetadata.map((input, index) => ({
    ...input,
    unlockingBytecode: index === 7
      ? `4df002${actionPacket.toString('hex')}`
      : index === 9 ? feeUnlock : '51',
  }));
  return {
    actionPacket: actionPacket.toString('hex'),
    bindingCarrierBaseValueSatoshis: '1000',
    inputs,
    instanceId,
    kind,
    minimumFeeRateSatoshisPerByte: '1',
    outputs,
    profileId,
    sourceOutputs,
    stateCarrierBaseValueSatoshis: '1000',
  };
}

test('constructs canonical deposit, transfer, and withdrawal transactions', () => {
  for (const kind of ['deposit', 'transfer', 'withdrawal']) {
    const result = buildSettlementTransaction(fixture(kind));
    assert.equal(result.kind, kind);
    assert.equal(result.transaction.inputs.length, 10);
    assert.equal(result.transaction.outputs.length, kind === 'withdrawal' ? 3 : 2);
    assert.equal(result.transactionHex.slice(10, 74), outpoint(0));
    assert.ok(result.measurements.wireBytes < 59_000);
    assert.ok(result.measurements.maximumUnlockingBytes < 10_000);
    assert.equal(result.measurements.stateHelperUnlockingLimitBytes, 3_286);
    assert.equal(result.measurements.percentageHeadroomRequired, false);
    assert.equal(result.context.digestHex, fixture(kind).actionPacket.slice(-64));
  }
});

test('rejects context, packet, role, state, withdrawal, fee, and size mutations', () => {
  const mutations = [
    (value) => { value.actionPacket = `${value.actionPacket.slice(0, -2)}00`; },
    (value) => { value.inputs[0].sequenceNumber = '1'; },
    (value) => { value.sourceOutputs[0].lockingBytecode = '51'; },
    (value) => { value.inputs[7].unlockingBytecode += '00'; },
    (value) => { value.sourceOutputs[8].token.nft.capability = 'minting'; },
    (value) => { value.outputs[0].lockingBytecode = '52'; },
    (value) => { value.outputs.at(-1).valueSatoshis = '0'; },
    (value) => { value.inputs[9].outpointTransactionHashWire = outpoint(9); },
    (value) => { value.inputs[9].outpointIndex = '2'; },
    (value) => { value.inputs[9].unlockingBytecode = '51'; },
    (value) => {
      value.inputs[9].unlockingBytecode = `${feeUnlock.slice(0, 130)}01${feeUnlock.slice(132)}`;
    },
    (value) => { value.sourceOutputs[9].lockingBytecode = `76a914${hex(0xee, 20)}88ac`; },
    (value) => { value.outputs.at(-1).lockingBytecode = '51'; },
    (value) => { value.inputs[0].unlockingBytecode = hex(1, 10_001); },
  ];
  for (const mutate of mutations) {
    const value = structuredClone(fixture());
    mutate(value);
    assert.throws(() => buildSettlementTransaction(value), SettlementTransactionError);
  }
  const withdrawal = structuredClone(fixture('withdrawal'));
  withdrawal.outputs[1].lockingBytecode = '51';
  assert.throws(() => buildSettlementTransaction(withdrawal), /withdrawal reserve or recipient/);

  const oversizedTransaction = structuredClone(fixture());
  for (let index = 0; index < 7; index += 1) {
    oversizedTransaction.inputs[index].unlockingBytecode = hex(index + 1, 9_000);
  }
  assert.throws(
    () => buildSettlementTransaction(oversizedTransaction),
    /complete transaction is .* exceeding 59000/,
  );
  const oversizedHelper = structuredClone(fixture());
  oversizedHelper.inputs[8].unlockingBytecode = hex(0xaa, 3_287);
  assert.throws(
    () => buildSettlementTransaction(oversizedHelper),
    /state helper unlocking bytecode is 3287 bytes, exceeding 3286/,
  );
});

test('separates the 54739-byte reference from the active 59000-byte gate', () => {
  const result = buildSettlementTransaction(fixture());
  assert.equal(result.measurements.completeTransactionWireLimitBytes, 59_000);
  assert.equal(result.measurements.inputUnlockingLimitBytes, 10_000);
  assert.equal(result.measurements.stateHelperUnlockingLimitBytes, 3_286);
  assert.equal('baselineWireLimitBytes' in result.measurements, false);
});
