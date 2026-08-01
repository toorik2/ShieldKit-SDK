import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import {
  buildDeterministicDirectV2Chain,
  compileDirectV2Circuit,
  runDirectV2CircuitModelQualification,
} from '../../../scripts/v2-circuit-model.mjs';
import {
  verifyCircuitBuildAttestationAgainstRepository,
} from '../../profile/v2/build-attestation.mjs';
import {
  parseV2RelationSourceManifest,
  verifyV2RelationSourceManifest,
} from '../../profile/v2/relation-source-manifest.mjs';
import {
  decodeActionPacket,
} from './packet.mjs';

const repositoryRoot = path.resolve(import.meta.dirname, '../../../..');
const temporaryRoot = path.join(repositoryRoot, '.codex-build/test-tmp');
const sha256 = (bytes) =>
  createHash('sha256').update(bytes).digest('hex');

test('constructs the exact deterministic deposit-transfer-withdrawal model chain', () => {
  const chain = buildDeterministicDirectV2Chain();
  assert.equal(chain.fixtureClass, 'deterministic-circuit-model-test-evidence');
  const packets = Object.fromEntries(Object.entries(chain.actions).map(
    ([kind, action]) => [kind, decodeActionPacket(action.transition.packet, {
      denominationSats: '10000000',
    })],
  ));
  assert.equal(
    chain.preparedActions.deposit.output.public.outputNoteLeaf,
    packets.deposit.outputNoteLeaf,
  );
  assert.equal(
    chain.preparedActions.transfer.output.public.outputNoteLeaf,
    packets.transfer.outputNoteLeaf,
  );
  assert.equal(
    chain.preparedActions.transfer.publicNullifier,
    packets.transfer.publicNullifier,
  );
  assert.equal(
    chain.preparedActions.withdrawal.publicNullifier,
    packets.withdrawal.publicNullifier,
  );
  assert.equal(chain.preparedActions.withdrawal.output, null);
  assert.deepEqual(
    Object.fromEntries(Object.entries(chain.actions).map(([name, action]) => [
      name,
      {
        noteCount: action.transition.state.noteCount,
        nullifierCount: action.transition.state.nullifierCount,
        reserveSats: action.transition.state.reserveSats,
        actionSequence: action.transition.state.actionSequence,
        packetBytes: action.transition.packet.length,
      },
    ])),
    {
      deposit: {
        noteCount: '1',
        nullifierCount: '0',
        reserveSats: '10000000',
        actionSequence: '1',
        packetBytes: 552,
      },
      transfer: {
        noteCount: '2',
        nullifierCount: '1',
        reserveSats: '10000000',
        actionSequence: '2',
        packetBytes: 552,
      },
      withdrawal: {
        noteCount: '2',
        nullifierCount: '2',
        reserveSats: '0',
        actionSequence: '3',
        packetBytes: 552,
      },
    },
  );
});

test('compiles the pinned circuit, attests exact inputs/outputs, calculates all witnesses, and rejects mutations', {
  timeout: 120_000,
}, async (t) => {
  await mkdir(temporaryRoot, { recursive: true, mode: 0o700 });
  const testRoot = await mkdtemp(path.join(
    temporaryRoot,
    'v2-circuit-model-test-',
  ));
  t.after(async () => {
    await rm(testRoot, { recursive: true, force: true, maxRetries: 1 });
  });
  const buildDirectory = path.join(testRoot, 'build');
  const result = await runDirectV2CircuitModelQualification({
    buildDirectory,
  });
  assert.equal(result.evidenceClass, 'deterministic-circuit-model-test-evidence-only');
  assert.deepEqual(result.qualificationClaims, {
    finalKey: false,
    bchVm: false,
    production: false,
  });
  assert.deepEqual(result.compilation.compiler, {
    npmPackage: '0.2.23',
    circom: '2.2.3',
    optimization: 'O1',
    sanityCheck: 2,
  });
  assert.deepEqual(result.compilation.command, {
    executable: 'process.execPath',
    argv: [
      'node_modules/circom2/cli.js',
      '03-create-your-own-pool/circuits/v2-direct/main-chipnet.circom',
      '--r1cs',
      '--wasm',
      '--sym',
      '--O1',
      '--sanity_check',
      '2',
      '--output',
      '$BUILD_OUTPUT',
    ],
    resolver: 'direct-pinned-npm-closure',
  });
  assert.equal(JSON.stringify(result.compilation.command).includes('npx'), false);
  assert.deepEqual(result.compilation.constraints, {
    nonlinear: 362004,
    linear: 96724,
    total: 458728,
    publicInputs: 2,
    privateInputs: 705,
    publicOutputs: 0,
    wires: 454978,
    labels: 2154164,
  });
  assert.deepEqual(result.witnesses.map(({ name, witnessSignals }) => ({
    name,
    witnessSignals,
  })), [
    { name: 'deposit', witnessSignals: 454978 },
    { name: 'transfer', witnessSignals: 454978 },
    { name: 'withdrawal', witnessSignals: 454978 },
  ]);
  assert.deepEqual(
    result.mutations.map(({ name, rejected }) => ({ name, rejected })),
    [
      { name: 'deposit-output-rho-blind', rejected: true },
      { name: 'transfer-spend-secret', rejected: true },
      { name: 'transfer-spend-record-tag', rejected: true },
      {
        name: 'transfer-nullifier-successor-index-fr-alias',
        rejected: true,
      },
      { name: 'withdrawal-public-input', rejected: true },
      {
        name: 'deposit-noncanonical-pre-note-root-with-rebound-digest',
        rejected: true,
      },
      {
        name: 'deposit-noncanonical-output-leaf-with-rebound-digest',
        rejected: true,
      },
      {
        name: 'deposit-ephemeral-byte-with-rebound-digest',
        rejected: true,
      },
      {
        name: 'deposit-record-tag-byte-with-rebound-digest',
        rejected: true,
      },
    ],
  );
  const buildAttestationBytes = await readFile(
    result.compilation.buildAttestation.path,
  );
  const relationManifestBytes = await readFile(
    result.compilation.relationSourceManifest.path,
  );
  assert.equal(
    Boolean(result.compilation.reproduction),
    true,
    'the emitted V2 build must have independently reproduced',
  );
  const buildAttestation =
    await verifyCircuitBuildAttestationAgainstRepository(
      buildAttestationBytes,
      { repositoryRoot, sourceManifestBytes: relationManifestBytes },
    );
  assert.equal(
    buildAttestation.artifacts.r1cs.sha256,
    sha256(await readFile(result.compilation.r1cs)),
  );
  assert.equal(
    buildAttestation.artifacts.wasm.sha256,
    sha256(await readFile(result.compilation.wasm)),
  );
  assert.equal(
    buildAttestation.artifacts.sym.sha256,
    sha256(await readFile(result.compilation.sym)),
  );
  const relationManifest = parseV2RelationSourceManifest(
    relationManifestBytes,
  );
  await verifyV2RelationSourceManifest(relationManifest, {
    repositoryRoot,
  });
  assert.equal(
    buildAttestation.sourceManifest.sha256,
    sha256(relationManifestBytes),
  );
  const emittedArtifacts = await Promise.all([
    ['r1cs', result.compilation.r1cs],
    ['sym', result.compilation.sym],
    ['wasm', result.compilation.wasm],
  ].map(async ([name, filename]) => {
    const data = await readFile(filename);
    return [name, {
      bytes: data.byteLength,
      sha256: sha256(data),
    }];
  }));
  for (const [name, evidence] of emittedArtifacts) {
    assert.deepEqual(
      {
        bytes: buildAttestation.artifacts[name].bytes,
        sha256: buildAttestation.artifacts[name].sha256,
      },
      evidence,
      `${name} artifact must match its build attestation`,
    );
    assert.deepEqual(
      {
        bytes: result.compilation.reproduction.reproduced[name].bytes,
        sha256: result.compilation.reproduction.reproduced[name].sha256,
      },
      evidence,
      `${name} artifact must match independent reproduction`,
    );
  }
  assert.deepEqual(
    result.compilation.reproduction.r1csAbi,
    buildAttestation.r1csAbi,
    'independent reproduction must report the attested R1CS ABI',
  );
  assert.equal(
    result.compilation.reproduction.sourceManifestSha256,
    sha256(relationManifestBytes),
    'independent reproduction must bind the emitted canonical relation manifest',
  );
  await assert.rejects(
    () => compileDirectV2Circuit({ buildDirectory }),
    /already exists; refusing stale overwrite/,
  );
});
