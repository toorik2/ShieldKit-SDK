import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  assertBundleSecurityInvariants,
  planRollingAction,
  selectCarrierCandidate,
  FUNDING_UTXO_REQUIRED,
} from './bundle.mjs';
import { emptyGenesisStateFields } from '../state.mjs';
import { emptyNoteRoot } from '../trees/note-tree.mjs';
import { emptyNullifierRoot } from '../trees/indexed-nullifier.mjs';
import { applyPublicStateDelta } from '../transition.mjs';

const profileId = createHash('sha256').update('bundle-p').digest('hex');
const instanceId = createHash('sha256').update('bundle-i').digest('hex');

describe('rolling bundle', () => {
  it('plans deposit with funding and rejects missing funding', () => {
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
    assert.throws(() => planRollingAction({
      kind: 'deposit',
      carrierCount: 2,
      preState: pre,
      postState: post,
      instanceIdCategory: instanceId,
      sourceOutpoints: {
        state: { txid: '11'.repeat(32), vout: 0, value: '1000' },
        carriers: [
          { txid: '11'.repeat(32), vout: 1, value: '1000' },
          { txid: '11'.repeat(32), vout: 2, value: '1000' },
        ],
        binding: { txid: '11'.repeat(32), vout: 3, value: '1000' },
      },
      fundingUtxo: null,
      changeLockingBytecode: Buffer.alloc(25),
      stateBaseSats: 1000,
      carrierBaseSats: 1000,
      bindingBaseSats: 1000,
    }), new RegExp(FUNDING_UTXO_REQUIRED));

    const plan = planRollingAction({
      kind: 'deposit',
      carrierCount: 2,
      preState: pre,
      postState: post,
      instanceIdCategory: instanceId,
      sourceOutpoints: {
        state: { txid: '11'.repeat(32), vout: 0, value: String(1000n + 0n) },
        carriers: [
          { txid: '11'.repeat(32), vout: 1, value: '1000' },
          { txid: '11'.repeat(32), vout: 2, value: '1000' },
        ],
        binding: { txid: '11'.repeat(32), vout: 3, value: '1000' },
      },
      fundingUtxo: {
        txid: '22'.repeat(32), vout: 0, value: '20000000', lockingBytecode: Buffer.alloc(25),
      },
      changeLockingBytecode: Buffer.alloc(25),
      stateBaseSats: 1000,
      carrierBaseSats: 1000,
      bindingBaseSats: 1000,
      estimatedTxBytes: 5000,
    });
    assert.equal(plan.outputs[0].role, 'state');
    assert.equal(plan.outputs[0].value, 1000n + 10_000_000n);
    assert.ok(plan.fee > 0n);
  });

  it('selects smallest passing carrier candidate', () => {
    const chosen = selectCarrierCandidate([
      { id: 'big', txBytes: 80_000, maxUnlockBytes: 9000, vmResourceFraction: 0.5, vmCost: 10 },
      { id: 'small', txBytes: 40_000, maxUnlockBytes: 8000, vmResourceFraction: 0.4, vmCost: 5 },
      { id: 'fail', txBytes: 2_000_000, maxUnlockBytes: 1000, vmResourceFraction: 0.1, vmCost: 1 },
    ]);
    assert.equal(chosen.id, 'small');
  });

  it('rejects minting authority and duplicate state', () => {
    assert.throws(() => assertBundleSecurityInvariants({
      category: instanceId,
      outputs: [{ role: 'state', token: { category: instanceId, commitment: Buffer.alloc(128) } }],
      mintingAuthorityPresent: true,
      carrierCount: 0,
    }), /minting/);
  });
});
