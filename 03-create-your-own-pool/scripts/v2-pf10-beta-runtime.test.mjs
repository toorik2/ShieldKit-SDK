import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import {
  createV2Pf10BetaRuntimeLocalEvidence,
  parseV2Pf10BetaRuntimeArguments,
  parseV2Pf10BetaRuntimeVerifyArguments,
  V2Pf10BetaRuntimeError,
  V2_PF10_BETA_RUNTIME_BUNDLE_SCHEMA,
  V2_PF10_BETA_RUNTIME_MANIFEST,
} from './v2-pf10-beta-runtime.mjs';

const instanceId = 'ab'.repeat(32);
const required = () => [
  '--instance-id', instanceId,
  '--output', 'beta-runtime',
  '--profile-core', 'profile/profile-core.json',
  '--profile-package', 'profile/beta-profile-package.json',
  '--qualification-evidence', 'proof/beta-proof-evidence.json',
  '--temporary-root', 'temporary',
];

test('beta runtime CLI is an exact beta-only interface', () => {
  assert.equal(
    V2_PF10_BETA_RUNTIME_BUNDLE_SCHEMA,
    'shieldkit-v2-direct-pf10-beta-local-runtime-bundle-v2',
  );
  assert.equal(V2_PF10_BETA_RUNTIME_MANIFEST, 'beta-runtime-manifest.json');
  assert.deepEqual(parseV2Pf10BetaRuntimeArguments(required(), '/beta'), {
    instanceId,
    outputDirectory: '/beta/beta-runtime',
    profileCorePath: '/beta/profile/profile-core.json',
    profilePackagePath: '/beta/profile/beta-profile-package.json',
    qualificationEvidencePath: '/beta/proof/beta-proof-evidence.json',
    temporaryRoot: '/beta/temporary',
  });
  assert.deepEqual(
    parseV2Pf10BetaRuntimeVerifyArguments(
      ['--verify', 'beta-runtime', '--temporary-root', 'temporary'],
      '/beta',
    ),
    { outputDirectory: '/beta/beta-runtime', temporaryRoot: '/beta/temporary' },
  );
  for (const argv of [
    undefined,
    required().slice(0, -2),
    [...required(), '--libauth-evidence', 'forbidden.json'],
    ['--instance-id', 'AB'.repeat(32), ...required().slice(2)],
  ]) {
    assert.throws(
      () => parseV2Pf10BetaRuntimeArguments(argv, '/beta'),
      V2Pf10BetaRuntimeError,
    );
  }
  for (const argv of [
    ['--verify', 'beta-runtime'],
    ['--verify', 'beta-runtime', '--temporary-root'],
    ['--verify', 'beta-runtime', '--other', 'temporary'],
  ]) {
    assert.throws(
      () => parseV2Pf10BetaRuntimeVerifyArguments(argv, '/beta'),
      V2Pf10BetaRuntimeError,
    );
  }
});

test('local runtime proof evidence is location-independent and exact', () => {
  const artifact = (digit) => ({
    bytes: Number(digit) + 1,
    path: `/original/${digit}`,
    pathScope: 'absolute',
    sha256: digit.repeat(64),
  });
  const actionFiles = (offset) => Object.fromEntries([
    'packet', 'input', 'witness', 'proof', 'publicSignals',
    'v2DirectGroth16Adapter',
  ].map((name, index) => [name, artifact(String(offset + index))]));
  const evidence = {
    marker: 'retained',
    sourceArtifacts: {
      profileCore: artifact('0'),
      r1cs: artifact('1'),
      wasm: artifact('2'),
      betaProvingKey: artifact('3'),
      verificationKey: artifact('4'),
    },
    actions: {
      deposit: { files: actionFiles(1) },
      transfer: { files: actionFiles(2) },
      withdrawal: { files: actionFiles(3) },
    },
  };
  const first = createV2Pf10BetaRuntimeLocalEvidence(evidence, '/first/root');
  const second = createV2Pf10BetaRuntimeLocalEvidence(evidence, '/other/root');
  assert.deepEqual(first, second);
  assert.equal(first.marker, 'retained');
  const records = [
    ...Object.values(first.sourceArtifacts),
    ...Object.values(first.actions).flatMap((action) =>
      Object.values(action.files)),
  ];
  assert.equal(records.length, 23);
  assert.equal(records.every((record) =>
    record.pathScope === 'runtime-bundle'), true);
  assert.deepEqual(first.sourceArtifacts.r1cs, {
    bytes: 2,
    path: 'proof/main-chipnet.r1cs',
    pathScope: 'runtime-bundle',
    sha256: '1'.repeat(64),
  });
  assert.equal(
    first.actions.withdrawal.files.v2DirectGroth16Adapter.path,
    'qualification/actions/withdrawal/v2-direct-groth16-adapter.json',
  );
});

test('beta runtime source uses a private beta manifest and never imports a normal descriptor', async () => {
  const source = await readFile(
    new URL('./v2-pf10-beta-runtime.mjs', import.meta.url),
    'utf8',
  );
  assert.match(source, /buildDirectV2Pf10BetaRuntime/u);
  assert.match(source, /verifyBetaProofQualification/u);
  assert.match(source, /onVerifiedRuntime/u);
  assert.match(source, /privateOutputRoot/u);
  assert.match(source, /relativeWithin\(allowedRoot, output/u);
  assert.match(source, /allowedOutputRoot: path\.dirname\(options\.outputDirectory\)/u);
  assert.match(source, /allowedOutputRoot: options\.outputDirectory/u);
  assert.match(source, /pathScope: V2_BETA_RUNTIME_BUNDLE_PATH_SCOPE/u);
  assert.match(source, /0o700/u);
  assert.match(source, /0o600/u);
  assert.match(source, /assertSafeRuntime/u);
  assert.match(source, /O_NOFOLLOW/u);
  assert.match(source, /initial\.nlink !== 1n/u);
  assert.match(source, /initial\.mode & 0o077n/u);
  assert.match(source, /beta-runtime-manifest\.json/u);
  assert.match(source, /retained\.redeem = await put/u);
  assert.match(source, /retained redeem does not reproduce/u);
  assert.doesNotMatch(source, /instance-descriptor\.mjs/u);
  assert.doesNotMatch(source, /buildDirectV2Pf10DevelopmentRuntime/u);
  assert.doesNotMatch(source, /libauthEvidence/u);
});
