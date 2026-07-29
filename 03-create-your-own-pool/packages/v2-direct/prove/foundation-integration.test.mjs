/**
 * Foundation integration: real prove for D/T/W + rolling plan + local VM measure.
 * Does not claim complete on-chain verifier-carrier settlement.
 */
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
import { planRollingAction, selectCarrierCandidate } from '../covenant/bundle.mjs';
import { measureCandidate } from '../covenant/local-vm.mjs';
import { createPoolEngineV2 } from '../transition.mjs';
import { proveActionV2, verifyActionV2 } from './prove.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const artifactDir = path.resolve(here, '../../../../.cache/v2-direct-circuit');
const profileId = createHash('sha256').update('found-int-p').digest('hex');
const instanceId = createHash('sha256').update('found-int-i').digest('hex');

describe('foundation integration D/T/W', () => {
  it('proves deposit, transfer, withdraw and plans rolling bundles under size gates', async () => {
    if (!existsSync(path.join(artifactDir, 'circuit_final.zkey'))) {
      console.log('SKIP: circuit artifacts missing');
      return;
    }
    const engine = createPoolEngineV2({
      profileId,
      instanceId,
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

    const zkey = path.join(artifactDir, 'circuit_final.zkey');
    const wasm = path.join(artifactDir, 'circuit.wasm');
    const vkey = path.join(artifactDir, 'verification_key.json');

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
    });
    const pd = await proveActionV2({ packetBytes: d.packet, zkeyPath: zkey, wasmPath: wasm });
    await verifyActionV2({ proof: pd.proof, publicSignals: pd.publicSignals, verificationKeyPath: vkey });

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
    });
    const pt = await proveActionV2({ packetBytes: t.packet, zkeyPath: zkey, wasmPath: wasm });
    await verifyActionV2({ proof: pt.proof, publicSignals: pt.publicSignals, verificationKeyPath: vkey });

    const w = engine.withdraw({
      spendSk: bob.sk,
      spendRho: out2.rho,
      spendCm: out2.cm,
      withdrawalLockingBytecodeHash: createHash('sha256').update('payout').digest('hex'),
    });
    const pw = await proveActionV2({ packetBytes: w.packet, zkeyPath: zkey, wasmPath: wasm });
    await verifyActionV2({ proof: pw.proof, publicSignals: pw.publicSignals, verificationKeyPath: vkey });

    // Plan rolling deposit-shaped bundle with funding
    const plan = planRollingAction({
      kind: 'deposit',
      carrierCount: 2,
      preState: d.preState,
      postState: d.postState,
      instanceIdCategory: instanceId,
      sourceOutpoints: {
        state: { txid: '11'.repeat(32), vout: 0, value: '1000' },
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
      estimatedTxBytes: 12_000,
    });
    assert.equal(plan.inputs.funding.value, '20000000');
    const meas = measureCandidate({
      txBytes: 12_000,
      unlockBytesList: [8_000, 8_000, 4_000],
      vmOpsUsed: 70,
      vmOpsLimit: 100,
    });
    assert.equal(meas.passes, true);

    const chosen = selectCarrierCandidate([
      {
        id: 'n2', txBytes: 12_000, maxUnlockBytes: 8_000, vmResourceFraction: 0.7, vmCost: 70,
      },
    ]);
    assert.equal(chosen.id, 'n2');

    assert.ok(pd.publicSignals.length === 2);
    assert.ok(pt.publicSignals.length === 2);
    assert.ok(pw.publicSignals.length === 2);
  });
});
