import assert from 'node:assert/strict';
import test from 'node:test';
import {
  actionPacketPublicLimbs,
  encodeActionPacket,
  OUTPUT_RECORD_BYTES,
} from '../../../packages/action-packet/action-packet.mjs';
import { actionPacketFromCircuitVector } from './export-action-packet.mjs';

const bits = (value) => Array.from(value, (byte) => Array.from(
  { length: 8 },
  (_, index) => String((byte >> (7 - index)) & 1),
)).flat();
const decimal = (hex) => BigInt(`0x${hex}`).toString();
const split = (hex) => [decimal(hex.slice(0, 32)), decimal(hex.slice(32))];

function fixture() {
  const profileId = '11'.repeat(32);
  const instanceId = '22'.repeat(32);
  const preState = {
    profileId, instanceId, noteRoot: '01'.padStart(64, '0'), nullifierRoot: '02'.padStart(64, '0'),
    nextLeafIndex: '0', actionSequence: '0', liveNoteCount: '0', reserveSats: '0',
    maximumReserve: '10000000', stateCommitment: '03'.padStart(64, '0'),
  };
  const postState = {
    ...preState, noteRoot: '04'.padStart(64, '0'), nextLeafIndex: '1', actionSequence: '1',
    liveNoteCount: '1', reserveSats: '10000000', stateCommitment: '05'.padStart(64, '0'),
  };
  const outputRecord = Buffer.alloc(OUTPUT_RECORD_BYTES, 0x5a);
  const expected = encodeActionPacket({
    kind: 'deposit', networkId: 2, preState, postState,
    inputCommitment: '0'.repeat(64), inputNullifier: '0'.repeat(64),
    outputCommitment: '06'.padStart(64, '0'), outputRecord,
    boundaryAmount: '10000000', withdrawalScriptHash: '0'.repeat(64),
    transactionContextDigest: '33'.repeat(32),
  });
  const [profileHi, profileLo] = split(profileId);
  const [instanceHi, instanceLo] = split(instanceId);
  const [withdrawalScriptHi, withdrawalScriptLo] = split('0'.repeat(64));
  const [transactionContextHi, transactionContextLo] = split('33'.repeat(32));
  const [publicDigestHi, publicDigestLo] = actionPacketPublicLimbs(expected);
  const state = (prefix, value) => ({
    [`${prefix}NoteRoot`]: decimal(value.noteRoot),
    [`${prefix}NullifierRoot`]: decimal(value.nullifierRoot),
    [`${prefix}NextLeafIndex`]: value.nextLeafIndex,
    [`${prefix}ActionSequence`]: value.actionSequence,
    [`${prefix}LiveNoteCount`]: value.liveNoteCount,
    [`${prefix}ReserveSats`]: value.reserveSats,
    [`${prefix}MaximumReserve`]: value.maximumReserve,
    [`${prefix}StateCommitment`]: decimal(value.stateCommitment),
  });
  return {
    expected,
    vector: {
      publicDigestHi, publicDigestLo,
      isDeposit: '1', isTransfer: '0', isWithdrawal: '0',
      profileHi, profileLo, instanceHi, instanceLo,
      ...state('pre', preState), ...state('post', postState),
      inputCm: '0', inputNf: '0', outputCm: decimal('06'.padStart(64, '0')),
      recordBits: bits(outputRecord), boundaryAmount: '10000000',
      withdrawalScriptHi, withdrawalScriptLo, transactionContextHi, transactionContextLo,
    },
  };
}

test('reconstructs the exact canonical packet and verifies its public limbs', () => {
  const { expected, vector } = fixture();
  assert.deepEqual(actionPacketFromCircuitVector(vector), expected);
});

test('rejects selector and public-digest drift', () => {
  const { vector } = fixture();
  assert.throws(() => actionPacketFromCircuitVector({ ...vector, isTransfer: '1' }), /one-hot/);
  assert.throws(() => actionPacketFromCircuitVector({ ...vector, publicDigestLo: '0' }), /public digest/);
});
