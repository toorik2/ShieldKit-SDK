/* TEST-ONLY: this exercises validators only; it never creates ceremony data. */
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';

import {
  parseV2D01Arguments,
  runV2D01FinalCeremonyQualification,
  validateV2D01CeremonyInventoryBindings,
  validateV2D01PostCeremonyBinding,
  V2_D01_POST_CEREMONY_BINDING_SCHEMA,
  V2_D01_REQUIRED_CEREMONY_FILES,
  V2D01FinalCeremonyQualificationError,
} from './v2-final-ceremony-qualification.mjs';

// Node has already initialized this test worker. Production D01 entrypoints
// require an empty loader/preload vector, so clear only the inherited
// node:test flags before exercising post-runtime validation.
process.execArgv.length = 0;

const hash = (letter) => letter.repeat(64);
const expected = () => ({
  profileId: hash('a'), instanceId: hash('b'), topologyId: 'pf10-fused',
  descriptorSha256: hash('c'), manifestSha256: hash('d'), releaseRootId: 'final-chipnet',
  sourceCommit: 'e'.repeat(40), sourceTree: 'f'.repeat(40), r1csSha256: hash('1'),
  ptauSha256: hash('2'), finalZkeySha256: hash('3'), verificationKeySha256: hash('4'),
  snarkjsToolchainSha256: hash('5'), contributorCount: 5, transcriptSha256: hash('6'),
  beaconSha256: hash('7'), transcriptVerificationSha256s: [hash('8'), hash('9')],
  reproductionSha256s: [hash('0'), hash('a')],
});
const binding = () => ({ schema: V2_D01_POST_CEREMONY_BINDING_SCHEMA, ...expected() });
const valid = () => [
  '--profile-core', '/tmp/d01/profile-core.json', '--descriptor', '/tmp/d01/descriptor.json',
  '--final-manifest', '/tmp/d01/manifest.json', '--release-root', 'final-chipnet',
  '--ceremony-dir', '/tmp/d01/ceremony', '--expected-commit', 'a'.repeat(40),
  '--expected-tree', 'b'.repeat(40), '--output-dir', '/tmp/d01/output',
];

test('D-01 accepts only the complete canonical public argument interface', () => {
  assert.equal(parseV2D01Arguments(valid()).releaseRootId, 'final-chipnet');
  assert.throws(() => parseV2D01Arguments([...valid(), '--test-only', 'true']), V2D01FinalCeremonyQualificationError);
  assert.throws(() => parseV2D01Arguments(valid().map((value) => value === '/tmp/d01/ceremony' ? 'relative' : value)), /absolute normalized/u);
});

const invalidInvocation = (outputDirectory = '/this/must/not-be-created/output') =>
  runV2D01FinalCeremonyQualification({
    ceremonyDirectory: '/this/must/not/be-opened/ceremony',
    descriptorPath: '/this/must/not/be-opened/descriptor.json',
    expectedCommit: 'a'.repeat(40),
    expectedTree: 'b'.repeat(40),
    finalManifestPath: '/this/must/not/be-opened/manifest.json',
    outputDirectory,
    profileCorePath: '/this/must/not/be-opened/profile-core.json',
    releaseRootId: '../injected-root',
  });

test('D-01 rejects ambient loader controls before resolving any release root', async () => {
  process.execArgv.push('--import=/tmp/attacker.mjs');
  try {
    await assert.rejects(invalidInvocation, /refuses Node loaders, preloads, exec arguments, module-path injection, or dynamic-loader controls/u);
  } finally {
    process.execArgv.length = 0;
  }
  const priorNodeOptions = process.env.NODE_OPTIONS;
  process.env.NODE_OPTIONS = '--import=/tmp/attacker.mjs';
  try {
    await assert.rejects(invalidInvocation, /refuses Node loaders, preloads, exec arguments, module-path injection, or dynamic-loader controls/u);
  } finally {
    if (priorNodeOptions === undefined) delete process.env.NODE_OPTIONS;
    else process.env.NODE_OPTIONS = priorNodeOptions;
  }
});

test('D-01 resolves the compiled release root before caller-selected paths', async () => {
  await assert.rejects(invalidInvocation, /root id is malformed/u);
});

test('D-01 records one 0600 failure result only in a fresh caller-selected output directory', async () => {
  const parent = mkdtempSync(resolve(tmpdir(), 'shieldkit-d01-test-'));
  const outputDirectory = resolve(parent, 'result');
  try {
    await assert.rejects(() => invalidInvocation(outputDirectory), /root id is malformed/u);
    const failure = JSON.parse(readFileSync(resolve(outputDirectory, 'failure.json')));
    assert.equal(failure.d01Qualified, false);
    assert.equal(statSync(resolve(outputDirectory, 'failure.json')).mode & 0o777, 0o600);
  } finally { rmSync(parent, { force: true, recursive: true }); }
});

test('D-01 post-ceremony binding has the final-key-only success shape', () => {
  const result = validateV2D01PostCeremonyBinding(binding(), expected());
  assert.equal(result.finalZkeySha256, hash('3'));
  for (const mutate of [
    (value) => { value.contributorCount = 4; },
    (value) => { value.beaconSha256 = hash('f'); },
    (value) => { value.transcriptVerificationSha256s = [hash('8')]; },
    (value) => { value.reproductionSha256s = [hash('0'), hash('a'), hash('b')]; },
  ]) {
    const invalid = binding(); mutate(invalid);
    assert.throws(() => validateV2D01PostCeremonyBinding(invalid, expected()), V2D01FinalCeremonyQualificationError);
  }
});

test('D-01 ceremony custody requires every exact signed final-runtime record', () => {
  const finalEvidence = {
    schema: 'shieldkit-v2-direct-final-runtime-evidence-resolution-v2',
    policySha256: hash('1'),
    contributorRegistrySha256: hash('2'),
    transcriptSha256: hash('3'),
    beaconSha256: hash('4'),
    snarkjsToolchainSha256: hash('5'),
    contributorCount: 5,
    transcriptVerificationSha256s: [hash('6'), hash('7')],
    reproductionSha256s: [hash('8'), hash('9')],
    sourceCommit: 'a'.repeat(40),
    sourceTree: 'b'.repeat(40),
    lockfileSha256: hash('0'),
  };
  const pins = new Map([
    [
      V2_D01_REQUIRED_CEREMONY_FILES.contributorRegistry,
      finalEvidence.contributorRegistrySha256,
    ],
    [
      V2_D01_REQUIRED_CEREMONY_FILES.transcript,
      finalEvidence.transcriptSha256,
    ],
    [
      V2_D01_REQUIRED_CEREMONY_FILES.beacon,
      finalEvidence.beaconSha256,
    ],
    ...V2_D01_REQUIRED_CEREMONY_FILES.transcriptVerifications.map(
      (path, index) => [
        path,
        finalEvidence.transcriptVerificationSha256s[index],
      ],
    ),
    ...V2_D01_REQUIRED_CEREMONY_FILES.reproductions.map(
      (path, index) => [
        path,
        finalEvidence.reproductionSha256s[index],
      ],
    ),
  ]);
  assert.equal(
    validateV2D01CeremonyInventoryBindings(pins, finalEvidence).length,
    7,
  );

  const missing = new Map(pins);
  missing.delete(V2_D01_REQUIRED_CEREMONY_FILES.transcript);
  assert.throws(
    () => validateV2D01CeremonyInventoryBindings(missing, finalEvidence),
    /does not retain exact signed artifact transcript\.json/u,
  );

  const swapped = new Map(pins);
  swapped.set(
    V2_D01_REQUIRED_CEREMONY_FILES.transcriptVerifications[0],
    finalEvidence.transcriptVerificationSha256s[1],
  );
  assert.throws(
    () => validateV2D01CeremonyInventoryBindings(swapped, finalEvidence),
    /verify-host-a\.json/u,
  );
});

test('D-01 relies on the production final-runtime evidence red-team corpus', async () => {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const testPath = resolve(root, 'packages/profile/v2/final-runtime-evidence.test.mjs');
  const { NODE_TEST_CONTEXT: _testContext, ...environment } = process.env;
  const result = await new Promise((resolveResult, reject) => execFile(process.execPath, ['--test', testPath], { encoding: 'utf8', env: environment }, (error, stdout, stderr) => error ? reject(new Error(`${stdout}\n${stderr}`)) : resolveResult(`${stdout}\n${stderr}`)));
  assert.match(result, /insufficient\/duplicate contributors/u);
  assert.match(result, /broken zkey chain, beacon mismatch, and shared verifier machine/u);
  assert.match(result, /unknown or duplicate evidence references/u);
  assert.match(result, /substituted bytes for a nested manifest-referenced artifact/u);
});
