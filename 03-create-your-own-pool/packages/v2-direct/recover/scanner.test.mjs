import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import { encodePoolStateV2, emptyGenesisStateFields } from '../state.mjs';
import { emptyNoteRoot } from '../trees/note-tree.mjs';
import { emptyNullifierRoot } from '../trees/indexed-nullifier.mjs';
import { applyReorgUndo, recoverFromGenesisLineage } from './scanner.mjs';
import { applyPublicStateDelta } from '../transition.mjs';

const profileId = createHash('sha256').update('rec-p').digest('hex');
const instanceId = createHash('sha256').update('rec-i').digest('hex');

describe('recovery scanner', () => {
  it('follows genesis lineage only', () => {
    const genesisState = emptyGenesisStateFields({
      profileId,
      noteRoot: emptyNoteRoot(),
      nullifierRoot: emptyNullifierRoot(),
      maximumLiveNotes: 32,
    });
    const post = applyPublicStateDelta(genesisState, 'deposit', {
      outputNoteLeaf: '0'.repeat(63) + '1',
      noteRootAfter: '0'.repeat(63) + '2',
    });
    const recovered = recoverFromGenesisLineage({
      genesisStateOutpoint: {
        txid: 'ab'.repeat(32),
        vout: 0,
        commitment: encodePoolStateV2(genesisState),
        category: instanceId,
      },
      instanceCategory: instanceId,
      chainTxs: [{
        txid: 'cd'.repeat(32),
        vin: [{ txid: 'ab'.repeat(32), vout: 0 }],
        vout: [{
          n: 0,
          category: instanceId,
          commitment: encodePoolStateV2(post),
        }],
      }],
    });
    assert.equal(recovered.tipState.noteCount, '1');
    assert.equal(recovered.tipOutpoint.txid, 'cd'.repeat(32));
  });

  it('rejects lineage break', () => {
    assert.throws(() => recoverFromGenesisLineage({
      genesisStateOutpoint: { txid: 'ab'.repeat(32), vout: 0 },
      chainTxs: [{
        txid: 'cd'.repeat(32),
        vin: [{ txid: 'ff'.repeat(32), vout: 0 }],
        vout: [],
      }],
    }), /lineage break/);
  });

  it('wipes on deep reorg', () => {
    const r = applyReorgUndo({ states: [1, 2, 3], packets: [1, 2] }, 101);
    assert.equal(r.wiped, true);
  });
});
