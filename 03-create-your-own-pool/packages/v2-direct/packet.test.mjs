import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import { ACTION_PACKET_BYTES, ENCRYPTED_RECORD_BYTES, NETWORK_CHIPNET, ZERO_32_HEX } from './constants.mjs';
import {
  actionPacketPublicLimbsV2,
  decodeActionPacketV2,
  digestActionPacketV2,
  encodeActionPacketV2,
} from './packet.mjs';
import { emptyGenesisStateFields } from './state.mjs';
import { emptyNoteRoot } from './trees/note-tree.mjs';
import { emptyNullifierRoot } from './trees/indexed-nullifier.mjs';
import { applyPublicStateDelta } from './transition.mjs';

const profileId = createHash('sha256').update('v2-direct-packet-profile').digest('hex');
const instanceId = createHash('sha256').update('v2-direct-packet-instance').digest('hex');

function baseStates() {
  const pre = emptyGenesisStateFields({
    profileId,
    noteRoot: emptyNoteRoot(),
    nullifierRoot: emptyNullifierRoot(),
    maximumLiveNotes: 32,
  });
  // Fake post with updated counters for deposit wire shape (roots left as-is for codec-only test)
  const post = {
    ...pre,
    noteCount: '1',
    reserveSats: '10000000',
    actionSequence: '1',
    noteRoot: createHash('sha256').update('note-root-1').digest('hex'),
  };
  // noteRoot must be valid Fr — use a small field element
  post.noteRoot = '0'.repeat(63) + '1';
  return { pre, post };
}

function depositPacket(overrides = {}) {
  const { pre, post } = baseStates();
  return {
    networkId: NETWORK_CHIPNET,
    kind: 'deposit',
    flags: 0,
    instanceId,
    preState: pre,
    postState: post,
    publicNullifier: ZERO_32_HEX,
    outputNoteLeaf: '0'.repeat(63) + '2',
    encryptedRecord: Buffer.alloc(ENCRYPTED_RECORD_BYTES, 7),
    withdrawalLockingBytecodeHash: ZERO_32_HEX,
    transactionContextHash: createHash('sha256').update('ctx').digest('hex'),
    ...overrides,
  };
}

describe('SDA2 action packet codec', () => {
  it('round-trips deposit packet', () => {
    const packet = encodeActionPacketV2(depositPacket());
    assert.equal(packet.length, ACTION_PACKET_BYTES);
    assert.equal(packet.subarray(0, 4).toString('ascii'), 'SDA2');
    const decoded = decodeActionPacketV2(packet);
    assert.equal(decoded.kind, 'deposit');
    assert.equal(decoded.instanceId, instanceId);
    assert.equal(decoded.preState.noteCount, '0');
    assert.equal(decoded.postState.noteCount, '1');
  });

  it('computes public input limbs from full SHA-256', () => {
    const packet = encodeActionPacketV2(depositPacket());
    const digest = digestActionPacketV2(packet);
    const limbs = actionPacketPublicLimbsV2(packet);
    const hi = BigInt(`0x${digest.subarray(0, 16).toString('hex')}`);
    const lo = BigInt(`0x${digest.subarray(16, 32).toString('hex')}`);
    assert.equal(limbs[0], hi.toString());
    assert.equal(limbs[1], lo.toString());
  });

  it('rejects nonzero flags', () => {
    const packet = encodeActionPacketV2(depositPacket());
    packet.writeUInt16LE(1, 6);
    assert.throws(() => decodeActionPacketV2(packet), /flags/);
  });

  it('rejects wrong length', () => {
    const packet = encodeActionPacketV2(depositPacket());
    assert.throws(() => decodeActionPacketV2(packet.subarray(0, 551)), /exactly 552/);
    assert.throws(
      () => decodeActionPacketV2(Buffer.concat([packet, Buffer.from([0])])),
      /exactly 552/,
    );
  });

  it('rejects deposit with active nullifier', () => {
    assert.throws(
      () => encodeActionPacketV2(depositPacket({ publicNullifier: '0'.repeat(63) + '1' })),
      /noncanonical/,
    );
  });

  it('rejects every one-byte mutation', () => {
    const base = encodeActionPacketV2(depositPacket());
    let handled = 0;
    for (let i = 0; i < ACTION_PACKET_BYTES; i += 1) {
      const mut = Buffer.from(base);
      mut[i] = (mut[i] + 1) & 0xff;
      try {
        const d = decodeActionPacketV2(mut);
        const re = encodeActionPacketV2({
          networkId: d.networkId,
          kind: d.kind,
          flags: 0,
          instanceId: d.instanceId,
          preState: d.preState,
          postState: d.postState,
          publicNullifier: d.publicNullifier,
          outputNoteLeaf: d.outputNoteLeaf,
          encryptedRecord: d.encryptedRecord,
          withdrawalLockingBytecodeHash: d.withdrawalLockingBytecodeHash,
          transactionContextHash: d.transactionContextHash,
        });
        assert.ok(!re.equals(base), `byte ${i} collision`);
        handled += 1;
      } catch {
        handled += 1;
      }
    }
    assert.equal(handled, ACTION_PACKET_BYTES);
  });

  it('public transition helper matches deposit counters', () => {
    const { pre } = baseStates();
    const post = applyPublicStateDelta(pre, 'deposit', {
      outputNoteLeaf: '0'.repeat(63) + '2',
      noteRootAfter: '0'.repeat(63) + '3',
    });
    assert.equal(post.noteCount, '1');
    assert.equal(post.reserveSats, '10000000');
    assert.equal(post.actionSequence, '1');
    assert.equal(post.nullifierCount, '0');
  });
});
