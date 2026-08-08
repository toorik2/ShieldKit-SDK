import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';

import {
  createDevelopmentEvidenceManifest,
  DevelopmentProofQualificationError,
  parseQualificationArguments,
  proverEvidence,
  snarkjsGroth16ProveArguments,
  snarkjsVersion,
  stringifyJsonWithBigInts,
} from './v2-development-proof-qualification.mjs';

const file = (name) => ({
  path: `/evidence/${name}`,
  bytes: 1,
  sha256: '0'.repeat(64),
});

const action = (name) => ({
  packetDigest: '0'.repeat(64),
  publicInputs: ['0', '1'],
  witnessValid: true,
  proofVerified: true,
  files: {
    packet: {
      ...file(`${name}-packet`),
      bytes: 552,
    },
    input: file(`${name}-input`),
    witness: file(`${name}-witness`),
    proof: file(`${name}-proof`),
    publicSignals: file(`${name}-public`),
    v2DirectGroth16Adapter: file(`${name}-v2-direct-groth16-adapter`),
  },
});

test('requires every explicit artifact/output path and rejects CLI ambiguity', () => {
  const parsed = parseQualificationArguments([
    '--profile-core', 'profile-core.json',
    '--r1cs', 'model.r1cs',
    '--wasm', 'model.wasm',
    '--zkey', 'development.zkey',
    '--verification-key', 'verification_key.json',
    '--output', 'evidence',
    '--instance-id', 'ab'.repeat(32),
    '--maximum-live-notes', '32',
  ], '/qualification');
  assert.deepEqual(parsed, {
    profileCore: path.resolve('/qualification/profile-core.json'),
    r1cs: path.resolve('/qualification/model.r1cs'),
    wasm: path.resolve('/qualification/model.wasm'),
    zkey: path.resolve('/qualification/development.zkey'),
    verificationKey: path.resolve('/qualification/verification_key.json'),
    outputDirectory: path.resolve('/qualification/evidence'),
    instanceId: 'ab'.repeat(32),
    maximumLiveNotes: '32',
    singleThread: false,
  });
  const singleThread = parseQualificationArguments([
    '--single-thread',
    '--profile-core', 'profile-core.json',
    '--r1cs', 'model.r1cs',
    '--wasm', 'model.wasm',
    '--zkey', 'development.zkey',
    '--verification-key', 'verification_key.json',
    '--output', 'evidence',
    '--instance-id', 'ab'.repeat(32),
    '--maximum-live-notes', '32',
  ], '/qualification');
  assert.equal(singleThread.singleThread, true);
  assert.throws(
    () => parseQualificationArguments([
      '--single-thread', '--single-thread',
      '--r1cs', 'a', '--wasm', 'b', '--zkey', 'c',
      '--verification-key', 'd', '--output', 'e',
    ]),
    /duplicate CLI option: --single-thread/,
  );
  assert.throws(
    () => parseQualificationArguments(['--r1cs', 'only.r1cs']),
    /missing required CLI option/,
  );
  assert.throws(
    () => parseQualificationArguments([
      '--r1cs', 'a', '--r1cs', 'b',
      '--wasm', 'c', '--zkey', 'd',
      '--verification-key', 'e', '--output', 'f',
    ]),
    /duplicate CLI option/,
  );
  assert.throws(
    () => parseQualificationArguments(['--implicit-key', 'forbidden']),
    /unknown or positional/,
  );
});

test('selects the exact snarkjs single-thread prove invocation without fallback', () => {
  assert.deepEqual(
    snarkjsGroth16ProveArguments('/key.zkey', '/witness.wtns', true),
    ['/key.zkey', '/witness.wtns', undefined, { singleThread: true }],
  );
  assert.deepEqual(
    snarkjsGroth16ProveArguments('/key.zkey', '/witness.wtns', false),
    ['/key.zkey', '/witness.wtns'],
  );
  assert.deepEqual(proverEvidence(true), {
    backend: 'snarkjs',
    provingSystem: 'groth16',
    mode: 'single-thread',
  });
  assert.deepEqual(proverEvidence(false), {
    backend: 'snarkjs',
    provingSystem: 'groth16',
    mode: 'default',
  });
});

test('serializes BigInts as decimal strings and rejects lossy JSON values', () => {
  const shared = { field: 6n };
  assert.equal(
    stringifyJsonWithBigInts({
      field: 3n,
      nested: [4n, '5'],
      sharedA: shared,
      sharedB: shared,
    }),
    '{\n  "field": "3",\n  "nested": [\n    "4",\n    "5"\n  ],\n  "sharedA": {\n    "field": "6"\n  },\n  "sharedB": {\n    "field": "6"\n  }\n}\n',
  );
  for (const value of [
    { missing: undefined },
    { invalid: Number.NaN },
    { invalid: Symbol('x') },
  ]) {
    assert.throws(
      () => stringifyJsonWithBigInts(value),
      DevelopmentProofQualificationError,
    );
  }
});

test('constructs only fully verified development-key evidence with hard nonclaims', () => {
  const manifest = createDevelopmentEvidenceManifest({
    identity: {
      profileId: '1'.repeat(64),
      instanceId: '2'.repeat(64),
      maximumLiveNotes: '32',
      denominationSats: '10000000',
    },
    sourceArtifacts: {
      profileCore: file('profile-core'),
      r1cs: file('r1cs'),
      wasm: file('wasm'),
      developmentZkey: file('zkey'),
      verificationKey: file('verification-key'),
    },
    actions: {
      deposit: action('deposit'),
      transfer: action('transfer'),
      withdrawal: action('withdrawal'),
    },
    versions: { node: 'v25.9.0', snarkjs: '0.7.6' },
    prover: proverEvidence(true),
    totalWallMs: 12.5,
    peakRss: { available: true, bytes: 1024 },
  });
  assert.deepEqual(manifest.claims, {
    developmentKey: true,
    finalKey: false,
    bchVm: false,
    production: false,
  });
  assert.equal(manifest.schema, 'shieldkit-v2-direct-development-groth16-qualification-v4');
  assert.deepEqual(manifest.prover, proverEvidence(true));
  assert.throws(
    () => createDevelopmentEvidenceManifest({
      ...manifest,
      sourceArtifacts: manifest.sourceArtifacts,
      actions: {
        ...manifest.actions,
        transfer: { ...manifest.actions.transfer, proofVerified: false },
      },
      versions: manifest.versions,
      prover: manifest.prover,
      totalWallMs: 12.5,
      peakRss: manifest.measurements.peakRss,
    }),
    /not fully verified/,
  );
  assert.throws(
    () => createDevelopmentEvidenceManifest({
      ...manifest,
      sourceArtifacts: manifest.sourceArtifacts,
      actions: {
        ...manifest.actions,
        deposit: {
          ...manifest.actions.deposit,
          publicInputs: [(1n << 128n).toString(), '0'],
        },
      },
      versions: manifest.versions,
      prover: manifest.prover,
      totalWallMs: 12.5,
      peakRss: manifest.measurements.peakRss,
    }),
    /u128x2 ABI/,
  );
  assert.throws(
    () => createDevelopmentEvidenceManifest({
      ...manifest,
      sourceArtifacts: manifest.sourceArtifacts,
      actions: manifest.actions,
      versions: manifest.versions,
      prover: { backend: 'snarkjs', provingSystem: 'groth16', mode: 'implicit-fallback' },
      totalWallMs: 12.5,
      peakRss: manifest.measurements.peakRss,
    }),
    /prover backend or mode is invalid/,
  );
});

test('records the installed snarkjs version from its package root', async () => {
  assert.equal(await snarkjsVersion(), '0.7.6');
});
