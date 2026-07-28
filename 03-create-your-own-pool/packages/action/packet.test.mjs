import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ACTION_PACKET_BYTES,
  ACTION_PACKET_OFFSETS,
  actionPacketPublicLimbs,
  decodeActionPacket,
  digestActionPacket,
  encodeActionPacket,
  OUTPUT_RECORD_BYTES,
  STATE_BYTES,
} from './packet.mjs';

const hex = (byte) => byte.repeat(32);
const state = (sequence, reserve, commitment) => ({
  profileId: hex('11'),
  instanceId: hex('22'),
  noteRoot: hex('33'),
  nullifierRoot: hex('44'),
  nextLeafIndex: '1',
  actionSequence: sequence,
  liveNoteCount: reserve === '0' ? '0' : '1',
  reserveSats: reserve,
  maximumReserve: '30000000',
  stateCommitment: hex(commitment),
});

const base = {
  kind: 'deposit',
  networkId: 2,
  preState: state('0', '0', '55'),
  postState: state('1', '10000000', '66'),
  inputCommitment: hex('00'),
  inputNullifier: hex('00'),
  outputCommitment: hex('77'),
  outputRecord: Buffer.alloc(OUTPUT_RECORD_BYTES, 0x88),
  boundaryAmount: '10000000',
  withdrawalScriptHash: hex('00'),
  transactionContextDigest: hex('99'),
};

test('encodes and decodes the exact 752-byte SCAR layout', () => {
  const packet = encodeActionPacket(base);
  const decoded = decodeActionPacket(packet);
  assert.equal(packet.length, ACTION_PACKET_BYTES);
  assert.equal(STATE_BYTES, 192);
  assert.equal(ACTION_PACKET_OFFSETS.transactionContextDigest, 720);
  assert.equal(decoded.kind, 'deposit');
  assert.equal(decoded.preState.profileId, base.preState.profileId);
  assert.equal(decoded.postState.reserveSats, '10000000');
  assert.equal(decoded.transactionContextDigest, base.transactionContextDigest);
  assert.deepEqual(encodeActionPacket({
    ...base,
    preState: decoded.preState,
    postState: decoded.postState,
    outputRecord: decoded.outputRecord,
  }), packet);
});

test('derives SHA-256 and exact unsigned big-endian u128 limbs', () => {
  const packet = encodeActionPacket(base);
  const digest = digestActionPacket(packet);
  const limbs = actionPacketPublicLimbs(packet);
  assert.equal(digest.length, 32);
  assert.deepEqual(limbs, [
    BigInt(`0x${digest.subarray(0, 16).toString('hex')}`).toString(),
    BigInt(`0x${digest.subarray(16).toString('hex')}`).toString(),
  ]);
});

test('rejects noncanonical headers, sizes, action fields, and immutable-state drift', () => {
  const valid = encodeActionPacket(base);
  for (const [offset, value, pattern] of [
    [0, 0, /magic/],
    [4, 2, /version/],
    [5, 99, /network/],
    [6, 9, /kind/],
    [7, 1, /reserved/],
  ]) {
    const mutated = Buffer.from(valid);
    mutated[offset] = value;
    assert.throws(() => decodeActionPacket(mutated), pattern);
  }
  assert.throws(() => decodeActionPacket(valid.subarray(1)), /752 bytes/);
  assert.throws(
    () => encodeActionPacket({ ...base, inputNullifier: hex('01') }),
    /deposit packet contains noncanonical action fields/,
  );
  assert.throws(
    () => encodeActionPacket({
      ...base,
      postState: { ...base.postState, instanceId: hex('aa') },
    }),
    /immutable state field/,
  );
});

test('enforces canonical transfer and withdrawal inactive fields', () => {
  const transfer = {
    ...base,
    kind: 'transfer',
    inputCommitment: hex('00'),
    inputNullifier: hex('bb'),
    boundaryAmount: '0',
  };
  assert.equal(decodeActionPacket(encodeActionPacket(transfer)).kind, 'transfer');
  assert.throws(
    () => encodeActionPacket({ ...transfer, inputCommitment: hex('aa') }),
    /transfer packet contains noncanonical action fields/,
  );
  const withdrawal = {
    ...base,
    kind: 'withdrawal',
    inputCommitment: hex('00'),
    inputNullifier: hex('bb'),
    outputCommitment: hex('00'),
    outputRecord: Buffer.alloc(OUTPUT_RECORD_BYTES),
    withdrawalScriptHash: hex('cc'),
  };
  assert.equal(decodeActionPacket(encodeActionPacket(withdrawal)).kind, 'withdrawal');
  assert.throws(
    () => encodeActionPacket({ ...withdrawal, inputCommitment: hex('aa') }),
    /withdrawal packet contains noncanonical action fields/,
  );
  assert.throws(
    () => encodeActionPacket({ ...withdrawal, outputRecord: Buffer.alloc(OUTPUT_RECORD_BYTES, 1) }),
    /withdrawal packet contains noncanonical action fields/,
  );
});
