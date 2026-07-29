import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  createVirtualMachineBch2026,
  encodeTransaction,
} from '@bitauth/libauth';
import {
  productBindingLock,
  packetUnlockFromSda2,
  evaluateBindingUnlock,
  evaluateStateTransition,
  SDA2_MAGIC,
  SKS2_MAGIC,
} from './binding-state.mjs';
import { encodePoolStateV2 } from '../state.mjs';
import { NETWORK_CHIPNET, PLAYGROUND_MAXIMUM_LIVE_NOTES } from '../constants.mjs';
import { createPoolEngineV2 } from '../transition.mjs';
import {
  createAccountKeys, freshOutputNote, frFromHex, shieldAddress,
} from '../crypto/note.mjs';

describe('binding-state covenants', () => {
  it('binding lock accepts densFuel-shaped packet unlock on Libauth', () => {
    const profileId = createHash('sha256').update('bind-p').digest('hex');
    const instanceId = createHash('sha256').update('bind-i').digest('hex');
    const engine = createPoolEngineV2({
      profileId,
      instanceId,
      maximumLiveNotes: PLAYGROUND_MAXIMUM_LIVE_NOTES,
      noteDepth: 8,
      nullifierDepth: 8,
    });
    const alice = createAccountKeys();
    const addr = shieldAddress({
      networkId: NETWORK_CHIPNET, profileId, instanceId, account: alice,
    });
    const note = freshOutputNote({
      profileId,
      instanceId,
      authority: addr.authority,
      postActionSequence: 1,
      viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
    });
    const d = engine.deposit({
      outputNoteLeaf: note.outputNoteLeaf,
      encryptedRecord: note.encryptedRecord,
    });
    const unlock = packetUnlockFromSda2(d.packet);
    const lock = productBindingLock();
    assert.equal(evaluateBindingUnlock(unlock, d.packet).ok, true);

    const vm = createVirtualMachineBch2026(false);
    const tx = {
      version: 2,
      locktime: 0,
      inputs: [{
        outpointTransactionHash: new Uint8Array(32),
        outpointIndex: 0,
        sequenceNumber: 0,
        unlockingBytecode: Uint8Array.from(unlock),
      }],
      outputs: [{ valueSatoshis: 1000n, lockingBytecode: Uint8Array.from([0x6a]) }],
    };
    const sourceOutputs = [{
      valueSatoshis: 1000n,
      lockingBytecode: Uint8Array.from(lock),
    }];
    // densFuel packet unlock is a push script — VM runs unlock then lock
    const result = vm.verify({ sourceOutputs, transaction: tx });
    assert.equal(result, true, String(result));
  });

  it('state transition evaluator binds packet pre/post SKS2', () => {
    const profileId = createHash('sha256').update('st-p').digest('hex');
    const instanceId = createHash('sha256').update('st-i').digest('hex');
    const engine = createPoolEngineV2({
      profileId,
      instanceId,
      maximumLiveNotes: 32,
      noteDepth: 8,
      nullifierDepth: 8,
    });
    const alice = createAccountKeys();
    const addr = shieldAddress({
      networkId: NETWORK_CHIPNET, profileId, instanceId, account: alice,
    });
    const note = freshOutputNote({
      profileId,
      instanceId,
      authority: addr.authority,
      postActionSequence: 1,
      viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
    });
    const d = engine.deposit({
      outputNoteLeaf: note.outputNoteLeaf,
      encryptedRecord: note.encryptedRecord,
    });
    const pre = encodePoolStateV2(d.preState);
    const post = encodePoolStateV2(d.postState);
    const base = 10_000n;
    const ev = evaluateStateTransition({
      preCommitment: pre,
      postCommitment: post,
      preValue: base + BigInt(d.preState.reserveSats),
      postValue: base + BigInt(d.postState.reserveSats),
      stateBaseSats: base,
      packetBytes: d.packet,
    });
    assert.equal(ev.ok, true, ev.reason);
    assert.equal(pre.subarray(0, 4).equals(SKS2_MAGIC), true);
    assert.equal(d.packet.subarray(0, 4).equals(SDA2_MAGIC), true);
  });

  it('rejects forged post commitment', () => {
    const profileId = createHash('sha256').update('fg-p').digest('hex');
    const instanceId = createHash('sha256').update('fg-i').digest('hex');
    const engine = createPoolEngineV2({
      profileId, instanceId, maximumLiveNotes: 32, noteDepth: 8, nullifierDepth: 8,
    });
    const alice = createAccountKeys();
    const addr = shieldAddress({
      networkId: NETWORK_CHIPNET, profileId, instanceId, account: alice,
    });
    const note = freshOutputNote({
      profileId, instanceId, authority: addr.authority, postActionSequence: 1,
      viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
    });
    const d = engine.deposit({
      outputNoteLeaf: note.outputNoteLeaf, encryptedRecord: note.encryptedRecord,
    });
    const pre = encodePoolStateV2(d.preState);
    const post = Buffer.from(encodePoolStateV2(d.postState));
    post[10] ^= 0xff;
    const base = 10_000n;
    const ev = evaluateStateTransition({
      preCommitment: pre,
      postCommitment: post,
      preValue: base,
      postValue: base + 10_000_000n,
      stateBaseSats: base,
      packetBytes: d.packet,
    });
    assert.equal(ev.ok, false);
  });
});
