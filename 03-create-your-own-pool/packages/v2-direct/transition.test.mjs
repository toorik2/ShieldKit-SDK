import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  createAccountKeys,
  freshOutputNote,
  frFromHex,
  shieldAddress,
} from './crypto/note.mjs';
import { decodeActionPacketV2 } from './packet.mjs';
import { createPoolEngineV2 } from './transition.mjs';
import { NETWORK_CHIPNET, PLAYGROUND_MAXIMUM_LIVE_NOTES, ZERO_32_HEX } from './constants.mjs';

const profileId = createHash('sha256').update('v2-engine-profile').digest('hex');
const instanceId = createHash('sha256').update('v2-engine-instance').digest('hex');

describe('V2 pool engine transitions', () => {
  it('deposit → transfer → withdraw conserves value and counters', () => {
    const engine = createPoolEngineV2({
      profileId,
      instanceId,
      networkId: NETWORK_CHIPNET,
      maximumLiveNotes: PLAYGROUND_MAXIMUM_LIVE_NOTES,
      noteDepth: 8,
      nullifierDepth: 8,
    });
    const alice = createAccountKeys();
    const bob = createAccountKeys();
    const aliceAddr = shieldAddress({
      networkId: NETWORK_CHIPNET, profileId, instanceId, account: alice,
    });
    const bobAddr = shieldAddress({
      networkId: NETWORK_CHIPNET, profileId, instanceId, account: bob,
    });

    const out1 = freshOutputNote({
      profileId,
      instanceId,
      authority: aliceAddr.authority,
      postActionSequence: 1,
      viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
    });
    const d = engine.deposit({
      outputNoteLeaf: out1.outputNoteLeaf,
      encryptedRecord: out1.encryptedRecord,
      transactionContextHash: createHash('sha256').update('d1').digest('hex'),
    });
    assert.equal(d.postState.liveNoteCount, '1');
    assert.equal(d.postState.reserveSats, '10000000');
    assert.equal(decodeActionPacketV2(d.packet).kind, 'deposit');

    const out2 = freshOutputNote({
      profileId,
      instanceId,
      authority: bobAddr.authority,
      postActionSequence: 2,
      viewPoint: [frFromHex(bob.V[0]), frFromHex(bob.V[1])],
    });
    const t = engine.transfer({
      spendSk: alice.sk,
      spendRho: out1.rho,
      spendCm: out1.cm,
      outputNoteLeaf: out2.outputNoteLeaf,
      encryptedRecord: out2.encryptedRecord,
      transactionContextHash: createHash('sha256').update('t1').digest('hex'),
    });
    assert.equal(t.postState.liveNoteCount, '1');
    assert.equal(t.postState.reserveSats, '10000000');
    assert.equal(t.postState.noteCount, '2');
    assert.equal(t.postState.nullifierCount, '1');
    assert.notEqual(t.publicNullifier, ZERO_32_HEX);

    const w = engine.withdraw({
      spendSk: bob.sk,
      spendRho: out2.rho,
      spendCm: out2.cm,
      withdrawalLockingBytecodeHash: createHash('sha256').update('p2pkh').digest('hex'),
      transactionContextHash: createHash('sha256').update('w1').digest('hex'),
    });
    assert.equal(w.postState.liveNoteCount, '0');
    assert.equal(w.postState.reserveSats, '0');
    assert.equal(w.postState.noteCount, '2');
    assert.equal(w.postState.nullifierCount, '2');

    // Double-spend fails (nullifier already spent; may also surface as no live notes)
    assert.throws(() => engine.withdraw({
      spendSk: bob.sk,
      spendRho: out2.rho,
      spendCm: out2.cm,
      withdrawalLockingBytecodeHash: createHash('sha256').update('p2pkh').digest('hex'),
    }), /duplicate|no live notes/);
  });

  it('rejects deposit at capacity before mutating trees', () => {
    const engine = createPoolEngineV2({
      profileId,
      instanceId,
      maximumLiveNotes: 1,
      noteDepth: 6,
      nullifierDepth: 6,
    });
    const alice = createAccountKeys();
    const aliceAddr = shieldAddress({
      networkId: NETWORK_CHIPNET, profileId, instanceId, account: alice,
    });
    const out1 = freshOutputNote({
      profileId,
      instanceId,
      authority: aliceAddr.authority,
      postActionSequence: 1,
      viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
    });
    engine.deposit({
      outputNoteLeaf: out1.outputNoteLeaf,
      encryptedRecord: out1.encryptedRecord,
    });
    const out2 = freshOutputNote({
      profileId,
      instanceId,
      authority: aliceAddr.authority,
      postActionSequence: 2,
      viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
    });
    assert.throws(() => engine.deposit({
      outputNoteLeaf: out2.outputNoteLeaf,
      encryptedRecord: out2.encryptedRecord,
    }), /maximumLiveNotes|CAPACITY/);
    assert.equal(engine.tip().liveNoteCount, '1');
  });
});
