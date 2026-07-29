import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import { NETWORK_CHIPNET, PLAYGROUND_MAXIMUM_LIVE_NOTES } from '../constants.mjs';
import {
  createAccountKeys, freshOutputNote, frFromHex, shieldAddress, recordCommitment,
} from '../crypto/note.mjs';
import { createPoolEngineV2 } from '../transition.mjs';
import { CIRCUIT_TREE_DEPTH } from './witness.mjs';
import { proveActionV2, verifyActionV2 } from './prove.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const artifactDir = path.resolve(here, '../../../../.cache/v2-direct-circuit');
const profileId = createHash('sha256').update('exp-prove-p').digest('hex');
const instanceId = createHash('sha256').update('exp-prove-i').digest('hex');

describe('expanded PoolActionV2Direct (trees+crypto)', () => {
  it('proves deposit with note path and Poseidon binding', async () => {
    if (!existsSync(path.join(artifactDir, 'circuit_final.zkey'))) {
      console.log('SKIP: artifacts missing');
      return;
    }
    const engine = createPoolEngineV2({
      profileId,
      instanceId,
      maximumLiveNotes: PLAYGROUND_MAXIMUM_LIVE_NOTES,
      noteDepth: CIRCUIT_TREE_DEPTH,
      nullifierDepth: CIRCUIT_TREE_DEPTH,
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
    // Capture empty append path BEFORE deposit (same as circuit needs for append proof)
    // Engine deposit appends internally; use path from result
    const d = engine.deposit({
      outputNoteLeaf: out.outputNoteLeaf,
      encryptedRecord: out.encryptedRecord,
    });
    const pathObj = {
      index: d.noteAppend.index,
      siblings: d.noteAppend.path.siblings,
    };
    assert.equal(pathObj.siblings.length, CIRCUIT_TREE_DEPTH);

    const proved = await proveActionV2({
      packetBytes: d.packet,
      zkeyPath: path.join(artifactDir, 'circuit_final.zkey'),
      wasmPath: path.join(artifactDir, 'circuit.wasm'),
      expanded: {
        note: {
          authority: addr.authority,
          rho: out.rho,
          r: out.r,
          cm: out.cm,
        },
        path: pathObj,
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
    await verifyActionV2({
      proof: proved.proof,
      publicSignals: proved.publicSignals,
      verificationKeyPath: path.join(artifactDir, 'verification_key.json'),
    });
    assert.equal(proved.publicSignals.length, 2);
  });
});
