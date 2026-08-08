import assert from 'node:assert/strict';
import test from 'node:test';

import {
  decodeActionPacketV2,
  decodePoolStateV2,
  encodeActionPacketV2,
  encodePoolStateV2,
} from '@shieldkit/action/v2';

const context = Object.freeze({ denominationSats: '10000000' });
const fr = (value) => value.toString(16).padStart(64, '0');
const state = Object.freeze({
  profileId: '11'.repeat(32),
  noteRoot: fr(1n),
  nullifierRoot: fr(2n),
  noteCount: '0',
  nullifierCount: '0',
  maximumLiveNotes: '7',
  reserveSats: '0',
  actionSequence: '0',
});

test('@shieldkit/action/v2 exposes only the named V2 codecs', () => {
  const encodedState = encodePoolStateV2(state, context);
  assert.equal(encodedState.length, 128);
  assert.deepEqual(decodePoolStateV2(encodedState, context), state);

  const packet = {
    kind: 'deposit',
    networkId: 2,
    instanceId: '22'.repeat(32),
    preState: state,
    postState: {
      ...state,
      noteRoot: fr(3n),
      noteCount: '1',
      reserveSats: '10000000',
      actionSequence: '1',
    },
    publicNullifier: '00'.repeat(32),
    outputNoteLeaf: fr(5n),
    encryptedRecord: Buffer.alloc(128, 0x44),
    withdrawalLockingBytecodeHash: '00'.repeat(32),
    transactionContextHash: '55'.repeat(32),
  };
  const encodedPacket = encodeActionPacketV2(packet, context);
  assert.equal(encodedPacket.length, 552);
  assert.deepEqual(encodeActionPacketV2(
    decodeActionPacketV2(encodedPacket, context),
    context,
  ), encodedPacket);
});
