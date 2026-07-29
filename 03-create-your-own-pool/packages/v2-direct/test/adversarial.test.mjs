import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  assertBundleSecurityInvariants,
  planRollingAction,
  selectCarrierCandidate,
} from '../covenant/bundle.mjs';
import {
  createAccountKeys, freshOutputNote, frFromHex, shieldAddress,
} from '../crypto/note.mjs';
import { decodeActionPacketV2, encodeActionPacketV2 } from '../packet.mjs';
import { createPoolEngineV2 } from '../transition.mjs';
import { NETWORK_CHIPNET, ZERO_32_HEX } from '../constants.mjs';
import { emptyGenesisStateFields } from '../state.mjs';
import { emptyNoteRoot } from '../trees/note-tree.mjs';
import { emptyNullifierRoot } from '../trees/indexed-nullifier.mjs';
import { applyPublicStateDelta } from '../transition.mjs';

const profileId = createHash('sha256').update('adv-p').digest('hex');
const instanceId = createHash('sha256').update('adv-i').digest('hex');

describe('adversarial / mutation matrices', () => {
  it('rejects standalone carrier burn style topology (missing state successor)', () => {
    assert.throws(() => assertBundleSecurityInvariants({
      category: instanceId,
      outputs: [
        { role: 'carrier:0', token: undefined },
        { role: 'binding', token: undefined },
      ],
      carrierCount: 1,
    }), /exactly one successor state/);
  });

  it('rejects fake category on state output', () => {
    assert.throws(() => assertBundleSecurityInvariants({
      category: instanceId,
      outputs: [{
        role: 'state',
        token: { category: 'ff'.repeat(32), commitment: Buffer.alloc(128) },
      }],
      carrierCount: 0,
    }), /category mismatch/);
  });

  it('rejects minting authority leftover', () => {
    assert.throws(() => assertBundleSecurityInvariants({
      category: instanceId,
      outputs: [{
        role: 'state',
        token: { category: instanceId, commitment: Buffer.alloc(128) },
      }],
      mintingAuthorityPresent: true,
      carrierCount: 0,
    }), /minting/);
  });

  it('carrier selection rejects oversize unlocks and VM overuse', () => {
    // Full-VM product limits (LIMITS.max*); soft plan 90%/9.5k are measurement-only.
    assert.equal(selectCarrierCandidate([
      {
        id: 'bad-unlock', txBytes: 10_000, maxUnlockBytes: 200_000,
        vmResourceFraction: 0.1, vmCost: 1,
      },
      {
        id: 'bad-vm', txBytes: 10_000, maxUnlockBytes: 1000,
        vmResourceFraction: 1.01, vmCost: 1,
      },
    ]), null);
  });

  it('double-spend nullifier fails closed', () => {
    const engine = createPoolEngineV2({
      profileId, instanceId, maximumLiveNotes: 8, noteDepth: 6, nullifierDepth: 6,
    });
    const alice = createAccountKeys();
    const addr = shieldAddress({
      networkId: NETWORK_CHIPNET, profileId, instanceId, account: alice,
    });
    const out = freshOutputNote({
      profileId,
      instanceId,
      authority: addr.authority,
      postActionSequence: 1,
      viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
    });
    engine.deposit({ outputNoteLeaf: out.outputNoteLeaf, encryptedRecord: out.encryptedRecord });
    engine.withdraw({
      spendSk: alice.sk,
      spendRho: out.rho,
      spendCm: out.cm,
      withdrawalLockingBytecodeHash: createHash('sha256').update('x').digest('hex'),
    });
    assert.throws(() => engine.withdraw({
      spendSk: alice.sk,
      spendRho: out.rho,
      spendCm: out.cm,
      withdrawalLockingBytecodeHash: createHash('sha256').update('x').digest('hex'),
    }), /duplicate/);
  });

  it('packet public nullifier mutation breaks decode or kind rules for deposit', () => {
    const pre = emptyGenesisStateFields({
      profileId,
      noteRoot: emptyNoteRoot(),
      nullifierRoot: emptyNullifierRoot(),
      maximumLiveNotes: 32,
    });
    const post = applyPublicStateDelta(pre, 'deposit', {
      outputNoteLeaf: '0'.repeat(63) + '1',
      noteRootAfter: '0'.repeat(63) + '2',
    });
    const packet = encodeActionPacketV2({
      networkId: NETWORK_CHIPNET,
      kind: 'deposit',
      flags: 0,
      instanceId,
      preState: pre,
      postState: post,
      publicNullifier: ZERO_32_HEX,
      outputNoteLeaf: '0'.repeat(63) + '1',
      encryptedRecord: Buffer.alloc(128, 1),
      withdrawalLockingBytecodeHash: ZERO_32_HEX,
      transactionContextHash: createHash('sha256').update('m').digest('hex'),
    });
    // Force non-zero nullifier on deposit
    packet[296] = 0x01;
    assert.throws(() => decodeActionPacketV2(packet), /noncanonical|magic|state|flags|kind|Fr|nullifier|canonical/i);
  });
});
