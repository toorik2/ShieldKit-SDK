import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import { NETWORK_CHIPNET, PLAYGROUND_MAXIMUM_LIVE_NOTES } from '../constants.mjs';
import {
  createAccountKeys, freshOutputNote, frFromHex, shieldAddress,
} from '../crypto/note.mjs';
import { createPoolEngineV2 } from '../transition.mjs';
import {
  buildCircuitInputFromPacket, proveActionV2, verifyActionV2,
} from './prove.mjs';
import { setupPoolActionV2DirectDevelopment } from './setup.mjs';

const profileId = createHash('sha256').update('prove-p').digest('hex');
const instanceId = createHash('sha256').update('prove-i').digest('hex');
const here = path.dirname(fileURLToPath(import.meta.url));
const artifactDir = path.resolve(here, '../../../../.cache/v2-direct-circuit');

function findPtau() {
  const candidates = [
    process.env.SHIELDKIT_PTAU,
    path.resolve(process.cwd(), 'powersOfTau28_hez_final_12.ptau'),
    path.resolve(process.cwd(), '.cache/ptau/powersOfTau28_hez_final_12.ptau'),
    path.join(process.env.HOME || '', '.cache/ptau/powersOfTau28_hez_final_12.ptau'),
    '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/ptau/powersOfTau28_hez_final_12.ptau',
    '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/powersOfTau28_hez_final_12.ptau',
  ].filter(Boolean);
  for (const c of candidates) {
    if (c && existsSync(c)) return c;
  }
  return null;
}

describe('PoolActionV2Direct prove path', () => {
  it('builds circuit input matching packet limbs and counters', () => {
    const engine = createPoolEngineV2({
      profileId, instanceId, maximumLiveNotes: 32, noteDepth: 6, nullifierDepth: 6,
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
    const d = engine.deposit({
      outputNoteLeaf: out.outputNoteLeaf,
      encryptedRecord: out.encryptedRecord,
    });
    const input = buildCircuitInputFromPacket(d.packet);
    assert.equal(input.kind, '1');
    assert.equal(input.preNoteCount, '0');
    assert.equal(input.postNoteCount, '1');
    assert.equal(input.publicInput0, input.limb0);
  });

  it('generates and verifies a real Groth16 proof when ptau is available', async () => {
    const ptau = findPtau();
    if (!ptau) {
      console.log('SKIP prove: no ptau found — run with SHIELDKIT_PTAU=...');
      return;
    }
    mkdirSync(artifactDir, { recursive: true });
    if (!existsSync(path.join(artifactDir, 'manifest.json'))) {
      await setupPoolActionV2DirectDevelopment({ outDir: artifactDir, ptauPath: ptau });
    }
    const engine = createPoolEngineV2({
      profileId, instanceId, maximumLiveNotes: PLAYGROUND_MAXIMUM_LIVE_NOTES,
      noteDepth: 6, nullifierDepth: 6,
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
    const d = engine.deposit({
      outputNoteLeaf: out.outputNoteLeaf,
      encryptedRecord: out.encryptedRecord,
    });
    const proved = await proveActionV2({
      packetBytes: d.packet,
      zkeyPath: path.join(artifactDir, 'circuit_final.zkey'),
      wasmPath: path.join(artifactDir, 'circuit.wasm'),
    });
    assert.ok(proved.proof);
    assert.equal(proved.publicSignals.length, 2);
    await verifyActionV2({
      proof: proved.proof,
      publicSignals: proved.publicSignals,
      verificationKeyPath: path.join(artifactDir, 'verification_key.json'),
    });
  });
});
