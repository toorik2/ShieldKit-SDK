// These are explicitly non-cryptographic parser fixtures. They only exercise
// manifest identity and file-integrity checks; no proof is generated, accepted,
// or represented as valid by this test.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  BundleValidationError, canonicalJson, deriveInstanceId, deriveProfileId,
  loadVerifierProfileBundle,
} from './verifier-profile.mjs';

const digest = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const fixtureBytes = (name, seed) => Buffer.from(`NON-CRYPTOGRAPHIC MANIFEST FIXTURE: ${name}: ${seed}\n`, 'utf8');

async function makeDevelopmentBundle(seed, mutation) {
  const directory = await mkdtemp(path.join(tmpdir(), 'shield-cash-profile-fixture-'));
  const files = {
    'artifacts/relation.json': fixtureBytes('relation-v1', 'shared-abi-semantics'),
    'artifacts/constraints.r1cs': fixtureBytes('constraint-v1', 'shared-abi-semantics'),
    'artifacts/public-input-abi.json': fixtureBytes('public-input-abi-v1', 'shared-abi-semantics'),
    'artifacts/vk.bin': fixtureBytes('verification-key', seed),
    'artifacts/pk.bin': fixtureBytes('proving-key', seed),
    'artifacts/verifier.cash': fixtureBytes('bch-verifier-script', seed),
  };
  for (const [relative, bytes] of Object.entries(files)) {
    await mkdir(path.dirname(path.join(directory, relative)), { recursive: true });
    await writeFile(path.join(directory, relative), bytes);
  }
  const artifact = (id, kind, file) => ({ id, kind, path: file, sha256: digest(files[file]) });
  const manifest = {
    schema: 'shield.cash/verifier-profile-manifest/v1',
    standard: { id: 'shield.cash', version: '1' },
    profile: {
      proofSystem: 'groth16', curve: 'bn254',
      relation: { id: 'shielded-action-v1', sha256: digest(files['artifacts/relation.json']) },
      constraintSystemHash: digest(files['artifacts/constraints.r1cs']),
      publicInputAbi: { id: 'shielded-action-public-input-v1', sha256: digest(files['artifacts/public-input-abi.json']) },
    },
    setup: {
      mode: 'development-only',
      provenance: { method: 'local-initialization', initializerCommitment: digest(`initializer-${seed}`) },
      transcript: { status: 'not-applicable' }, contributions: [],
    },
    toolchain: {
      compiler: { name: 'fixture-compiler', version: '0.0.0-noncryptographic', sha256: digest('fixture-compiler') },
      generator: { name: 'fixture-generator', version: '0.0.0-noncryptographic', sha256: digest('fixture-generator') },
    },
    network: { name: 'chipnet' },
    artifacts: [
      artifact('relation', 'relation-definition', 'artifacts/relation.json'),
      artifact('constraints', 'constraint-system', 'artifacts/constraints.r1cs'),
      artifact('public-input-abi', 'public-input-abi', 'artifacts/public-input-abi.json'),
      artifact('verification-key', 'verification-key', 'artifacts/vk.bin'),
      artifact('proving-key', 'proving-key', 'artifacts/pk.bin'),
      artifact('bch-verifier-script', 'bch-verifier-script', 'artifacts/verifier.cash'),
    ],
    identity: { profileId: '' },
    genesis: {
      profileId: '', instanceId: '', network: 'chipnet',
      genesisOutpoint: { txid: digest(`outpoint-${seed}`).slice('sha256:'.length), vout: '0' },
      reserveCapSatoshis: '10000000',
    },
  };
  if (mutation) mutation(manifest, files);
  manifest.identity.profileId = deriveProfileId(manifest);
  manifest.genesis.profileId = manifest.identity.profileId;
  manifest.genesis.instanceId = deriveInstanceId(manifest.genesis);
  await writeFile(path.join(directory, 'manifest.json'), canonicalJson(manifest));
  return { directory, manifest };
}

test('two independently initialized development bundles keep ABI semantics but derive distinct profile and genesis identities', async () => {
  const first = await makeDevelopmentBundle('independent-a');
  const second = await makeDevelopmentBundle('independent-b');
  const left = await loadVerifierProfileBundle(first.directory);
  const right = await loadVerifierProfileBundle(second.directory);
  assert.equal(left.manifest.profile.relation.sha256, right.manifest.profile.relation.sha256);
  assert.equal(left.manifest.profile.constraintSystemHash, right.manifest.profile.constraintSystemHash);
  assert.equal(left.manifest.profile.publicInputAbi.sha256, right.manifest.profile.publicInputAbi.sha256);
  assert.notEqual(left.profileId, right.profileId);
  assert.notEqual(left.instanceId, right.instanceId);
  assert.equal(left.manifest.setup.mode, 'development-only');
  assert.equal(Object.isFrozen(left.manifest), true);
});

test('production mode rejects an incomplete ceremony transcript rather than accepting a development setup label', async () => {
  const bundle = await makeDevelopmentBundle('missing-transcript', (manifest) => {
    manifest.setup = {
      mode: 'ceremony-production',
      provenance: { method: 'multi-party-randomness', initializerCommitment: digest('ceremony-init') },
      transcript: { status: 'complete', artifactPath: 'artifacts/transcript.json', sha256: digest('absent'), verifier: { name: 'fixture-verifier', version: '0', sha256: digest('verifier') } },
      contributions: [
        { sequence: '1', participantCommitment: digest('participant-1'), contributionHash: digest('contribution-1'), verification: { status: 'verified', verifier: { name: 'fixture-verifier', version: '0', sha256: digest('verifier') } } },
        { sequence: '2', participantCommitment: digest('participant-2'), contributionHash: digest('contribution-2'), verification: { status: 'verified', verifier: { name: 'fixture-verifier', version: '0', sha256: digest('verifier') } } },
      ],
    };
  });
  await assert.rejects(() => loadVerifierProfileBundle(bundle.directory), /ceremony transcript artifact is missing/);
});

test('loader fails closed on duplicate JSON names, traversal, missing artifacts, hash drift, and pinned-instance hot swaps', async () => {
  const bundle = await makeDevelopmentBundle('rejection-cases');
  await assert.rejects(() => loadVerifierProfileBundle(bundle.directory, { profileId: digest('different-profile') }), /refusing hot swap/);
  bundle.manifest.artifacts[0].path = '../escape';
  bundle.manifest.identity.profileId = deriveProfileId(bundle.manifest);
  bundle.manifest.genesis.profileId = bundle.manifest.identity.profileId;
  bundle.manifest.genesis.instanceId = deriveInstanceId(bundle.manifest.genesis);
  await writeFile(path.join(bundle.directory, 'manifest.json'), canonicalJson(bundle.manifest));
  await assert.rejects(() => loadVerifierProfileBundle(bundle.directory), /safe relative POSIX path|traversal/);
  await writeFile(path.join(bundle.directory, 'manifest.json'), '{"schema":"x","schema":"x"}');
  await assert.rejects(() => loadVerifierProfileBundle(bundle.directory), BundleValidationError);

  const missing = await makeDevelopmentBundle('missing-required-artifact', (manifest) => {
    manifest.artifacts = manifest.artifacts.filter((artifact) => artifact.kind !== 'proving-key');
  });
  await assert.rejects(() => loadVerifierProfileBundle(missing.directory), /required artifact is missing: proving-key/);

  const drifted = await makeDevelopmentBundle('artifact-hash-drift');
  await writeFile(path.join(drifted.directory, 'artifacts/vk.bin'), fixtureBytes('verification-key', 'mutated-after-manifest'));
  await assert.rejects(() => loadVerifierProfileBundle(drifted.directory), /artifact hash mismatch/);
});
