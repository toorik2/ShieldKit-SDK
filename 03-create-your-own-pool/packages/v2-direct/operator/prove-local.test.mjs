import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import { NETWORK_CHIPNET, PLAYGROUND_MAXIMUM_LIVE_NOTES } from '../constants.mjs';
import {
  createAccountKeys, freshOutputNote, frFromHex, shieldAddress,
} from '../crypto/note.mjs';
import { createPoolEngineV2 } from '../transition.mjs';
import {
  CIRCUIT_TREE_DEPTH, provePoolAction, resolveCircuitArtifacts,
} from './prove-local.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../../');
const ARTIFACT = path.join(root, '.cache/v2-direct-circuit');

describe('operator prove-local (real Groth16)', () => {
  it('uses CIRCUIT_TREE_DEPTH 32 and proves deposit against shipped circuit', async () => {
    assert.equal(CIRCUIT_TREE_DEPTH, 32);
    if (!existsSync(path.join(ARTIFACT, 'circuit_final.zkey'))) {
      console.log('SKIP: no circuit artifacts');
      return;
    }
    const arts = resolveCircuitArtifacts(ARTIFACT);
    assert.equal(arts.treeDepth, 32);

    const profileId = createHash('sha256').update('op-prove-p').digest('hex');
    const instanceId = createHash('sha256').update('op-prove-i').digest('hex');
    const eng = createPoolEngineV2({
      profileId, instanceId, maximumLiveNotes: PLAYGROUND_MAXIMUM_LIVE_NOTES,
      noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
    });
    const alice = createAccountKeys();
    const addr = shieldAddress({
      networkId: NETWORK_CHIPNET, profileId, instanceId, account: alice,
    });
    const out = freshOutputNote({
      profileId, instanceId, authority: addr.authority, postActionSequence: 1,
      viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
    });
    const d = eng.deposit({
      outputNoteLeaf: out.outputNoteLeaf, encryptedRecord: out.encryptedRecord,
    });
    assert.equal(d.noteAppend.path.siblings.length, 32);

    const proved = await provePoolAction({
      packetBytes: d.packet,
      artifactDir: ARTIFACT,
      expanded: {
        note: {
          authority: addr.authority, rho: out.rho, r: out.r, cm: out.cm,
        },
        path: { index: d.noteAppend.index, siblings: d.noteAppend.path.siblings },
        encryption: {
          esk: out.esk,
          viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
          encryptedRecord: out.encryptedRecord,
        },
        recordCommitmentHex: out.recordCommitment,
        preNoteRoot: d.preState.noteRoot,
        postNoteRoot: d.postState.noteRoot,
        preNullifierRoot: d.preState.nullifierRoot,
        postNullifierRoot: d.postState.nullifierRoot,
      },
    });
    assert.equal(proved.publicSignals.length, 2);
    assert.ok(proved.ms < 60_000);
    assert.equal(proved.treeDepth, 32);
  });

  it('rejects wrong path depth before prove', async () => {
    if (!existsSync(path.join(ARTIFACT, 'circuit_final.zkey'))) return;
    await assert.rejects(
      () => provePoolAction({
        packetBytes: Buffer.alloc(552),
        expanded: {
          note: { authority: '00'.repeat(32), rho: '11'.repeat(32), r: '22'.repeat(32), cm: '33'.repeat(32) },
          path: { index: '0', siblings: Array.from({ length: 16 }, () => '00'.repeat(32)) },
        },
      }),
      /path depth/,
    );
  });
});
