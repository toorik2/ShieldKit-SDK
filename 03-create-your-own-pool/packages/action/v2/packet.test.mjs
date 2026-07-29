import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ACTION_PACKET_BYTES,
  ACTION_PACKET_OFFSETS,
  actionPacketPublicLimbs,
  decodeActionPacket,
  digestActionPacket,
  ENCRYPTED_RECORD_BYTES,
  encodeActionPacket,
  STATE_BYTES,
} from './packet.mjs';
import { encodeStateNftCommitment } from './state.mjs';

const context = Object.freeze({ denominationSats: '10000000' });
const hex = (byte) => byte.repeat(32);
const fr = (value) => value.toString(16).padStart(64, '0');
const state = (noteCount, nullifierCount, sequence, root, reserveSats) => ({
  profileId: hex('11'),
  noteRoot: fr(root),
  nullifierRoot: fr(2n),
  noteCount,
  nullifierCount,
  maximumLiveNotes: '7',
  reserveSats,
  actionSequence: sequence,
});
const base = Object.freeze({
  kind: 'deposit',
  networkId: 2,
  instanceId: hex('22'),
  preState: state('0', '0', '0', 1n, '0'),
  postState: state('1', '0', '1', 3n, '10000000'),
  publicNullifier: hex('00'),
  outputNoteLeaf: fr(5n),
  encryptedRecord: Buffer.alloc(ENCRYPTED_RECORD_BYTES, 0x44),
  withdrawalLockingBytecodeHash: hex('00'),
  transactionContextHash: hex('55'),
});

test('encodes exact SDA2 offsets and round-trips the 552-byte packet', () => {
  const packet = encodeActionPacket(base, context);
  assert.equal(packet.length, ACTION_PACKET_BYTES);
  assert.equal(ACTION_PACKET_BYTES, 552);
  assert.equal(STATE_BYTES, 128);
  assert.equal(packet.subarray(0, 8).toString('hex'), '5344413202010000');
  assert.equal(packet.subarray(ACTION_PACKET_OFFSETS.instanceId, ACTION_PACKET_OFFSETS.preState).toString('hex'), base.instanceId);
  assert.deepEqual(packet.subarray(ACTION_PACKET_OFFSETS.preState, ACTION_PACKET_OFFSETS.postState), encodeStateNftCommitment(base.preState, context));
  assert.deepEqual(packet.subarray(ACTION_PACKET_OFFSETS.postState, ACTION_PACKET_OFFSETS.publicNullifier), encodeStateNftCommitment(base.postState, context));
  assert.equal(packet.subarray(ACTION_PACKET_OFFSETS.publicNullifier, ACTION_PACKET_OFFSETS.outputNoteLeaf).toString('hex'), base.publicNullifier);
  assert.equal(packet.subarray(ACTION_PACKET_OFFSETS.outputNoteLeaf, ACTION_PACKET_OFFSETS.encryptedRecord).toString('hex'), base.outputNoteLeaf);
  assert.deepEqual(packet.subarray(ACTION_PACKET_OFFSETS.encryptedRecord, ACTION_PACKET_OFFSETS.withdrawalLockingBytecodeHash), base.encryptedRecord);
  assert.equal(packet.subarray(ACTION_PACKET_OFFSETS.withdrawalLockingBytecodeHash, ACTION_PACKET_OFFSETS.transactionContextHash).toString('hex'), base.withdrawalLockingBytecodeHash);
  assert.equal(packet.subarray(ACTION_PACKET_OFFSETS.transactionContextHash).toString('hex'), base.transactionContextHash);
  const decoded = decodeActionPacket(packet, context);
  assert.equal(decoded.kind, 'deposit');
  assert.equal(decoded.instanceId, base.instanceId);
  assert.deepEqual(encodeActionPacket(decoded, context), packet);
});

test('uses SHA-256 over every packet byte and two unsigned big-endian u128 limbs', () => {
  const packet = encodeActionPacket(base, context);
  const digest = digestActionPacket(packet, context);
  assert.equal(digest.toString('hex'), 'ded42d09831ea2f39e521ce62b5faf474cf70946a76e934b6d6abe2280559a18');
  assert.deepEqual(actionPacketPublicLimbs(packet, context), [
    '296190295460325907773963638825346379591',
    '102304013143187191688059162453337283096',
  ]);
  const changed = Buffer.from(packet);
  changed[ACTION_PACKET_OFFSETS.transactionContextHash] ^= 1;
  assert.notDeepEqual(digestActionPacket(changed, context), digest);
});

test('permits all-zero active fields but rejects nonzero inactive fields', () => {
  const zeroDeposit = { ...base, outputNoteLeaf: hex('00'), encryptedRecord: Buffer.alloc(ENCRYPTED_RECORD_BYTES) };
  assert.equal(decodeActionPacket(encodeActionPacket(zeroDeposit, context), context).kind, 'deposit');
  const zeroTransfer = {
    ...base,
    kind: 'transfer',
    preState: state('1', '0', '1', 3n, '10000000'),
    postState: state('2', '1', '2', 4n, '10000000'),
    publicNullifier: hex('00'),
    outputNoteLeaf: hex('00'),
    encryptedRecord: Buffer.alloc(ENCRYPTED_RECORD_BYTES),
  };
  assert.equal(decodeActionPacket(encodeActionPacket(zeroTransfer, context), context).kind, 'transfer');
  const zeroWithdrawal = {
    ...base,
    kind: 'withdrawal',
    preState: state('1', '0', '1', 3n, '10000000'),
    postState: state('1', '1', '2', 3n, '0'),
    publicNullifier: hex('00'),
    outputNoteLeaf: hex('00'),
    encryptedRecord: Buffer.alloc(ENCRYPTED_RECORD_BYTES),
    withdrawalLockingBytecodeHash: hex('00'),
  };
  assert.equal(decodeActionPacket(encodeActionPacket(zeroWithdrawal, context), context).kind, 'withdrawal');
  assert.throws(() => encodeActionPacket({ ...base, publicNullifier: hex('01') }, context), /inactive/);
  assert.throws(() => encodeActionPacket({ ...base, withdrawalLockingBytecodeHash: hex('01') }, context), /inactive/);
  assert.throws(() => encodeActionPacket({ ...zeroTransfer, withdrawalLockingBytecodeHash: hex('01') }, context), /inactive/);
  assert.throws(() => encodeActionPacket({ ...zeroWithdrawal, outputNoteLeaf: hex('01') }, context), /inactive/);
  assert.throws(() => encodeActionPacket({ ...zeroWithdrawal, encryptedRecord: Buffer.alloc(ENCRYPTED_RECORD_BYTES, 1) }, context), /inactive/);
});

test('rejects malformed headers, flags, sizes, state continuity, and field types', () => {
  const valid = encodeActionPacket(base, context);
  for (const [offset, value, pattern] of [
    [0, 0, /magic/],
    [4, 99, /network/],
    [5, 99, /kind/],
    [6, 1, /flags/],
    [7, 1, /flags/],
  ]) {
    const mutated = Buffer.from(valid);
    mutated[offset] = value;
    assert.throws(() => decodeActionPacket(mutated, context), pattern);
  }
  for (const length of [551, 553]) {
    const malformed = Buffer.alloc(length);
    valid.copy(malformed, 0, 0, Math.min(valid.length, malformed.length));
    assert.throws(() => decodeActionPacket(malformed, context), /exactly 552 bytes/);
  }
  assert.throws(() => encodeActionPacket({ ...base, postState: { ...base.postState, profileId: hex('99') } }, context), /profileId/);
  assert.throws(() => encodeActionPacket({ ...base, postState: { ...base.postState, maximumLiveNotes: '6' } }, context), /maximumLiveNotes/);
  assert.throws(() => encodeActionPacket({ ...base, encryptedRecord: '44'.repeat(128) }, context), /exactly 128 bytes/);
  assert.throws(() => encodeActionPacket({ ...base, transactionContextHash: 'AA'.repeat(32) }, context), /lowercase/);
  assert.throws(() => encodeActionPacket({ ...base, publicNullifier: 'ff'.repeat(32) }, context), /canonical BN254/);
  assert.throws(() => encodeActionPacket({ ...base, outputNoteLeaf: 'ff'.repeat(32) }, context), /canonical BN254/);
  assert.throws(() => encodeActionPacket({ ...base, extra: true }, context), /missing or unknown/);
});

test('refuses a V1 SCAR packet rather than migrating or relabeling it as V2', () => {
  const legacyPacket = Buffer.alloc(752);
  Buffer.from('SCAR', 'ascii').copy(legacyPacket, 0);
  legacyPacket[4] = 1;
  legacyPacket[5] = 2;
  assert.throws(
    () => decodeActionPacket(legacyPacket, context),
    /exactly 552 bytes/,
  );
});
