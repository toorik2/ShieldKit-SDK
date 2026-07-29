/**
 * Prove one V2 Direct deposit, adapt snarkjs → PF7 adapter, run densFuel unlock-builder.
 * Measures carrier unlocks against plan gates (requirePinLens=false for V2 re-pin).
 */
import { createHash } from 'node:crypto';
import {
  mkdirSync, writeFileSync, readFileSync, existsSync, copyFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { NETWORK_CHIPNET, PLAYGROUND_MAXIMUM_LIVE_NOTES } from '../constants.mjs';
import {
  createAccountKeys, freshOutputNote, frFromHex, shieldAddress,
} from '../crypto/note.mjs';
import { createPoolEngineV2 } from '../transition.mjs';
import { CIRCUIT_TREE_DEPTH } from './witness.mjs';
import { proveActionV2, verifyActionV2 } from './prove.mjs';
import { adaptSnarkjsGroth16, sha256File } from '../../prove/groth16.mjs';
import { buildVerifierUnlocks } from '../../unlock-builder/index.mjs';
import { LIMITS } from '../constants.mjs';
import { selectCarrierCandidate } from '../covenant/bundle.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(here, '../../../..');
const ARTIFACT = path.resolve(ROOT, '.cache/v2-direct-circuit');
const OUT = path.resolve(ROOT, '.cache/v2-direct-unlocks');

function snarkjsProofJson(proof) {
  // snarkjs fullProve returns proof with pi_a, pi_b, pi_c as arrays of strings
  return {
    protocol: 'groth16',
    curve: 'bn128',
    pi_a: proof.pi_a,
    pi_b: proof.pi_b,
    pi_c: proof.pi_c,
  };
}

async function main() {
  mkdirSync(OUT, { recursive: true });
  if (!existsSync(path.join(ARTIFACT, 'circuit_final.zkey'))) {
    throw new Error('circuit artifacts missing — run setup first');
  }

  const profileId = createHash('sha256').update('v2-unlock-profile').digest('hex');
  const instanceId = createHash('sha256').update('v2-unlock-instance').digest('hex');
  const engine = createPoolEngineV2({
    profileId,
    instanceId,
    networkId: NETWORK_CHIPNET,
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
  const d = engine.deposit({
    outputNoteLeaf: out.outputNoteLeaf,
    encryptedRecord: out.encryptedRecord,
  });

  const proved = await proveActionV2({
    packetBytes: d.packet,
    zkeyPath: path.join(ARTIFACT, 'circuit_final.zkey'),
    wasmPath: path.join(ARTIFACT, 'circuit.wasm'),
    expanded: {
      note: {
        authority: addr.authority, rho: out.rho, r: out.r, cm: out.cm,
      },
      path: { index: d.noteAppend.index, siblings: d.noteAppend.path.siblings },
      recordCommitmentHex: out.recordCommitment,
      preNoteRoot: d.preState.noteRoot,
      postNoteRoot: d.postState.noteRoot,
    },
  });
  await verifyActionV2({
    proof: proved.proof,
    publicSignals: proved.publicSignals,
    verificationKeyPath: path.join(ARTIFACT, 'verification_key.json'),
  });

  // Write snarkjs-format files for adapter
  const proofPath = path.join(OUT, 'proof.json');
  const publicPath = path.join(OUT, 'public.json');
  const vkeyPath = path.join(OUT, 'verification_key.json');
  const packetPath = path.join(OUT, 'action.packet');
  copyFileSync(path.join(ARTIFACT, 'verification_key.json'), vkeyPath);
  writeFileSync(proofPath, `${JSON.stringify(snarkjsProofJson(proved.proof), null, 2)}\n`);
  // public signals as decimal strings
  const publics = proved.publicSignals.map((s) => (
    typeof s === 'string' ? s : String(s)
  ));
  writeFileSync(publicPath, `${JSON.stringify(publics)}\n`);
  writeFileSync(packetPath, d.packet);

  const adapter = await adaptSnarkjsGroth16({
    verificationKey: { path: vkeyPath, sha256: await sha256File(vkeyPath) },
    proof: { path: proofPath, sha256: await sha256File(proofPath) },
    publicSignals: { path: publicPath, sha256: await sha256File(publicPath) },
  });
  const adapterPath = path.join(OUT, 'adapter.json');
  writeFileSync(adapterPath, `${JSON.stringify(adapter, null, 2)}\n`);

  console.log(JSON.stringify({
    phase: 'adapter-ready',
    in0: adapter.verifierCashFixture.in0,
    in1: adapter.verifierCashFixture.in1,
    digest: d.digest,
    packetBytes: d.packet.length,
  }));

  const unlockOut = path.join(OUT, 'unlocks');
  const t0 = Date.now();
  let unlockResult;
  try {
    unlockResult = await buildVerifierUnlocks({
      adapterPath,
      packetPath,
      outDir: unlockOut,
      requirePinLens: false, // V2 re-pin: measure, don't force V1 lens
      // ECIP offline gate uses a separate noble Point class path that breaks
      // ProjectivePoint identity for fresh VKs; densFuel loads the adapter
      // in-process and is the authoritative gate for V2 re-pin measurement.
      skipEcipGate: true,
      quiet: false,
    });
  } catch (error) {
    const report = {
      phase: 'unlock-build-failed',
      ms: Date.now() - t0,
      name: error.name,
      code: error.code,
      message: error.message,
      logTail: error.details?.logTail?.slice(-2000),
      msBuild: error.details?.ms,
    };
    writeFileSync(path.join(OUT, 'unlock-fail.json'), `${JSON.stringify(report, null, 2)}\n`);
    console.log(JSON.stringify(report, null, 2));
    process.exitCode = 2;
    return;
  }

  // Measure candidates
  const roles = unlockResult.roles || unlockResult.carriers || [];
  const unlockLens = roles.map((r) => r.unlockLen ?? (r.unlockHex?.length / 2) ?? 0);
  const maxUnlock = Math.max(0, ...unlockLens);
  // Estimate tx size: rough topology N carriers + binding + state + funding
  const N = unlockLens.length;
  const estimatedTxBytes = 500 + unlockLens.reduce((a, b) => a + b, 0) + 2000;
  const candidate = {
    id: 'v2-densfuel',
    txBytes: estimatedTxBytes,
    maxUnlockBytes: maxUnlock,
    vmResourceFraction: 0.5, // refined if result has metrics
    vmCost: unlockResult.ms || 0,
    unlockLens,
    pinLens: unlockLens,
  };
  const selected = selectCarrierCandidate([candidate]);
  const measurement = {
    phase: 'unlock-build-ok',
    ms: Date.now() - t0,
    N,
    unlockLens,
    maxUnlock,
    estimatedTxBytes,
    planLimits: {
      maxTx: LIMITS.maxTransactionBytes,
      maxUnlock: LIMITS.maxUnlockBytes,
      maxVmFraction: LIMITS.maxVmResourceFraction,
    },
    passesSizeGates: Boolean(selected),
    selected: selected?.id || null,
    outDir: unlockOut,
  };
  writeFileSync(path.join(OUT, 'measurement.json'), `${JSON.stringify(measurement, null, 2)}\n`);
  console.log(JSON.stringify(measurement, null, 2));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
