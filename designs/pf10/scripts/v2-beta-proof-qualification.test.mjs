import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';

import {
  BetaProofQualificationError,
  createBetaProofEvidenceManifest,
  createV2BetaLocalProvenancePin,
  parseBetaProofQualificationArguments,
  parseBetaProofVerificationArguments,
  resolveV2BetaEvidenceFilePath,
  serializeV2BetaCanonicalJson,
  validateV2BetaLocalProvenancePin,
  V2_BETA_PROOF_EVIDENCE_CLASS,
  V2_BETA_PROOF_QUALIFICATION_SCHEMA,
  V2_BETA_PROVENANCE_PIN_SCHEMA,
  V2_BETA_PROVENANCE_PIN_STATUS,
  V2_BETA_RUNTIME_BUNDLE_PATH_SCOPE,
} from './v2-beta-proof-qualification.mjs';
import {
  V2_BETA_LOCAL_ELIGIBILITY,
  V2_BETA_LOCAL_FALSE_CLAIMS,
} from '../packages/profile/v2/beta-local-profile.mjs';
import {
  createDevelopmentEvidenceManifest,
  proverEvidence,
} from './v2-development-proof-qualification.mjs';

const hash = (digit) => digit.repeat(64);
const prefixed = (digit) => `sha256:${hash(digit)}`;
const file = (name, digit = '0') => ({
  path: `evidence/${name}`,
  bytes: 1,
  sha256: hash(digit),
});

test('repository-scoped beta evidence resolves from the ShieldKit root', () => {
  const repositoryRoot = path.resolve(import.meta.dirname, '../../..');
  assert.equal(
    resolveV2BetaEvidenceFilePath(
      { path: '.codex-build/beta/actions/deposit/packet.bin' },
      'packet',
    ),
    path.join(
      repositoryRoot,
      '.codex-build/beta/actions/deposit/packet.bin',
    ),
  );
});

test('runtime-bundle evidence resolves only strict paths from its fixed location', () => {
  const evidencePath = '/private/runtime/qualification/beta-proof-evidence.json';
  const record = {
    path: 'proof/main-chipnet.r1cs',
    pathScope: V2_BETA_RUNTIME_BUNDLE_PATH_SCOPE,
  };
  assert.equal(
    resolveV2BetaEvidenceFilePath(record, 'r1cs', { evidencePath }),
    '/private/runtime/proof/main-chipnet.r1cs',
  );
  for (const invalidPath of [
    '/proof/main-chipnet.r1cs',
    '../proof/main-chipnet.r1cs',
    'proof/../main-chipnet.r1cs',
    'proof/./main-chipnet.r1cs',
    'proof//main-chipnet.r1cs',
    'proof\\main-chipnet.r1cs',
    'proof/main chipnet.r1cs',
    'proof/main-chipnet.r1cs\0suffix',
    'C:/proof/main-chipnet.r1cs',
  ]) {
    assert.throws(
      () => resolveV2BetaEvidenceFilePath(
        { ...record, path: invalidPath },
        'r1cs',
        { evidencePath },
      ),
      BetaProofQualificationError,
    );
  }
  for (const invalidEvidencePath of [
    undefined,
    'runtime/qualification/beta-proof-evidence.json',
    '/private/runtime/evidence/beta-proof-evidence.json',
    '/private/runtime/qualification/renamed.json',
  ]) {
    assert.throws(
      () => resolveV2BetaEvidenceFilePath(
        record,
        'r1cs',
        { evidencePath: invalidEvidencePath },
      ),
      BetaProofQualificationError,
    );
  }
});

const action = (name) => ({
  packetDigest: hash('0'),
  publicInputs: ['0', '1'],
  witnessValid: true,
  proofVerified: true,
  files: {
    packet: { ...file(`${name}-packet`), bytes: 552 },
    input: file(`${name}-input`),
    witness: file(`${name}-witness`),
    proof: file(`${name}-proof`),
    publicSignals: file(`${name}-public`),
    v2DirectGroth16Adapter: file(`${name}-adapter`),
  },
});

const provenance = Object.freeze({
  schema: V2_BETA_PROVENANCE_PIN_SCHEMA,
  status: V2_BETA_PROVENANCE_PIN_STATUS,
  eligibility: V2_BETA_LOCAL_ELIGIBILITY,
  assuranceClass: 'beta-single-contributor',
  ceremonyId: 'local-r3',
  claims: V2_BETA_LOCAL_FALSE_CLAIMS,
  source: { gitCommit: '1'.repeat(40), gitTree: '2'.repeat(40) },
  b01ManifestSha256: prefixed('3'),
  betaProvingKeySha256: prefixed('4'),
  verificationKeySha256: prefixed('5'),
  entropyPolicySha256: prefixed('6'),
  implementationSha256: prefixed('7'),
  initialZkeySha256: prefixed('0'),
  powersOfTauSha256: prefixed('f'),
  preparationSha256: prefixed('8'),
  r1csSha256: prefixed('2'),
  resultSha256: prefixed('9'),
  transcriptFileSha256: prefixed('a'),
  transcriptSha256: prefixed('b'),
});

const common = Object.freeze({
  identity: {
    profileId: hash('1'),
    instanceId: hash('2'),
    maximumLiveNotes: '32',
    denominationSats: '10000000',
  },
  sourceArtifacts: {
    profileCore: file('profile', '1'),
    r1cs: file('r1cs', '2'),
    wasm: file('wasm', '3'),
    betaProvingKey: file('beta.zkey', '4'),
    verificationKey: file('vk.json', '5'),
  },
  actions: {
    deposit: action('deposit'),
    transfer: action('transfer'),
    withdrawal: action('withdrawal'),
  },
  versions: { node: 'v25.9.0', snarkjs: '0.7.6' },
  prover: proverEvidence(true),
  totalWallMs: 1,
  peakRss: { available: true, bytes: 1 },
  betaProvenance: {
    bytes: 7,
    file: 'beta-provenance.json',
    record: provenance,
    sha256: hash('c'),
  },
});

test('derives provenance from an explicit ceremony and has no free-form pin alias', () => {
  const parsed = parseBetaProofQualificationArguments([
    '--profile-core', 'profile.json',
    '--r1cs', 'main.r1cs',
    '--wasm', 'main.wasm',
    '--beta-zkey', 'r3.zkey',
    '--verification-key', 'vk.json',
    '--ceremony-dir', 'r3-ceremony',
    '--instance-id', 'ab'.repeat(32),
    '--maximum-live-notes', '32',
    '--output', 'beta-evidence',
    '--single-thread',
  ], '/beta');
  assert.deepEqual(parsed, {
    profileCore: path.resolve('/beta/profile.json'),
    r1cs: path.resolve('/beta/main.r1cs'),
    wasm: path.resolve('/beta/main.wasm'),
    zkey: path.resolve('/beta/r3.zkey'),
    verificationKey: path.resolve('/beta/vk.json'),
    ceremonyDirectory: path.resolve('/beta/r3-ceremony'),
    instanceId: 'ab'.repeat(32),
    maximumLiveNotes: '32',
    outputDirectory: path.resolve('/beta/beta-evidence'),
    singleThread: true,
  });
  assert.throws(
    () => parseBetaProofQualificationArguments([
      '--zkey', 'development.zkey',
    ]),
    /unknown or positional argument: --zkey/,
  );
  assert.throws(
    () => parseBetaProofQualificationArguments([
      '--beta-provenance', 'self-authored.json',
    ]),
    /unknown or positional argument: --beta-provenance/,
  );
  assert.deepEqual(
    parseBetaProofVerificationArguments(['--verify', 'evidence.json'], '/beta'),
    { evidencePath: path.resolve('/beta/evidence.json') },
  );
});

test('emits beta-only claims and cannot be accepted as development evidence', () => {
  const manifest = createBetaProofEvidenceManifest(common);
  assert.equal(manifest.schema, V2_BETA_PROOF_QUALIFICATION_SCHEMA);
  assert.equal(manifest.evidenceClass, V2_BETA_PROOF_EVIDENCE_CLASS);
  assert.equal(manifest.eligibility, V2_BETA_LOCAL_ELIGIBILITY);
  assert.equal(manifest.claims.betaSingleContributor, true);
  assert.equal(manifest.claims.developmentKey, false);
  assert.equal(manifest.claims.finalKey, false);
  assert.equal(manifest.claims.q07Qualified, false);
  assert.throws(
    () => createDevelopmentEvidenceManifest({
      ...common,
      sourceArtifacts: common.sourceArtifacts,
    }),
    /sourceArtifacts\.developmentZkey has invalid file evidence/,
  );
  assert.throws(
    () => createBetaProofEvidenceManifest({
      ...common,
      betaProvenance: {
        ...common.betaProvenance,
        record: {
          ...provenance,
          verificationKeySha256: prefixed('d'),
        },
      },
    }),
    BetaProofQualificationError,
  );
});

test('historical ceremony resolution reduces to an exact portable provenance pin', () => {
  const resolution = {
    schema: 'shieldkit-v2-beta-single-contributor-historical-resolution-v1',
    status: 'beta-single-contributor-historical-source-reverified-unqualified',
    assuranceClass: 'beta-single-contributor',
    claims: Object.fromEntries(
      Object.entries(V2_BETA_LOCAL_FALSE_CLAIMS)
        .filter(([, value]) => value === false),
    ),
    ceremonyId: provenance.ceremonyId,
    source: provenance.source,
    b01ManifestSha256: provenance.b01ManifestSha256,
    preparationSha256: provenance.preparationSha256,
    resultSha256: provenance.resultSha256,
    betaProvingKeySha256: provenance.betaProvingKeySha256,
    verificationKeySha256: provenance.verificationKeySha256,
    entropyPolicySha256: provenance.entropyPolicySha256,
    implementationSha256: provenance.implementationSha256,
    transcriptFileSha256: provenance.transcriptFileSha256,
    transcriptSha256: provenance.transcriptSha256,
    artifacts: {
      betaProvingKey: { sha256: provenance.betaProvingKeySha256 },
      initialZkey: { sha256: provenance.initialZkeySha256 },
      powersOfTau: { sha256: provenance.powersOfTauSha256 },
      r1cs: { sha256: provenance.r1csSha256 },
      verificationKey: { sha256: provenance.verificationKeySha256 },
    },
  };
  const pin = createV2BetaLocalProvenancePin(resolution);
  assert.deepEqual(validateV2BetaLocalProvenancePin(pin), pin);
  assert.deepEqual(pin, provenance);
});

test('beta proof files use verifier-compatible exact JCS without a trailing newline', () => {
  const serialized = serializeV2BetaCanonicalJson({
    z: 1n,
    a: Object.freeze(['2', true]),
  });
  assert.equal(serialized, '{"a":["2",true],"z":"1"}');
  assert.equal(serialized.endsWith('\n'), false);
  assert.deepEqual(JSON.parse(serialized), { a: ['2', true], z: '1' });
});
