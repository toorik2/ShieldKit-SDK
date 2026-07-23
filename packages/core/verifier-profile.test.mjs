// These are explicitly non-cryptographic parser fixtures. They only exercise
// manifest identity and file-integrity checks; no proof is generated, accepted,
// or represented as valid by this test.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  BundleValidationError, canonicalJson, deriveInstanceId, deriveProfileId,
  deriveStateNftCategory, loadVerifierProfileBundle,
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
    'artifacts/witness-generator.bin': fixtureBytes('witness-generator', seed),
    'artifacts/verifier-set.json': fixtureBytes('bch-verifier-set', seed),
  };
  const artifact = (id, kind, file) => ({ id, kind, path: file, sha256: digest(files[file]) });
  const manifest = {
    schema: 'shield.cash/verifier-profile-manifest/v1',
    standard: { id: 'shield.cash', version: '1' },
    profile: {
      proofSystem: 'groth16', curve: 'bn254',
      relation: { id: 'shielded-action-v1', sha256: digest(files['artifacts/relation.json']) },
      constraintSystemHash: digest(files['artifacts/constraints.r1cs']),
      publicInputAbi: { id: 'shielded-action-public-input-v1', sha256: digest(files['artifacts/public-input-abi.json']) },
      bchVerifierSetHash: digest(files['artifacts/verifier-set.json']),
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
      artifact('bch-verifier-set', 'bch-verifier-set', 'artifacts/verifier-set.json'),
      artifact('constraint-system', 'constraint-system', 'artifacts/constraints.r1cs'),
      artifact('proving-key', 'proving-key', 'artifacts/pk.bin'),
      artifact('public-input-abi', 'public-input-abi', 'artifacts/public-input-abi.json'),
      artifact('relation-definition', 'relation-definition', 'artifacts/relation.json'),
      artifact('verification-key', 'verification-key', 'artifacts/vk.bin'),
      artifact('witness-generator', 'witness-generator', 'artifacts/witness-generator.bin'),
    ],
    identity: { profileId: '' },
    genesis: {
      profileId: '', instanceId: '', network: 'chipnet',
      categoryInputOutpoint: { txid: digest(`category-input-${seed}`).slice('sha256:'.length), vout: '0' },
      stateNftCategory: digest(`category-input-${seed}`).slice('sha256:'.length),
      reserveCapSatoshis: '10000000',
    },
  };
  if (mutation) mutation(manifest, files, artifact);
  for (const [relative, bytes] of Object.entries(files)) {
    await mkdir(path.dirname(path.join(directory, relative)), { recursive: true });
    await writeFile(path.join(directory, relative), bytes);
  }
  manifest.identity.profileId = deriveProfileId(manifest);
  manifest.genesis.profileId = manifest.identity.profileId;
  manifest.genesis.instanceId = deriveInstanceId(manifest.genesis);
  await writeFile(path.join(directory, 'manifest.json'), canonicalJson(manifest));
  return { directory, manifest };
}

async function writeBoundManifest(bundle) {
  bundle.manifest.identity.profileId = deriveProfileId(bundle.manifest);
  bundle.manifest.genesis.profileId = bundle.manifest.identity.profileId;
  bundle.manifest.genesis.instanceId = deriveInstanceId(bundle.manifest.genesis);
  await writeFile(path.join(bundle.directory, 'manifest.json'), canonicalJson(bundle.manifest));
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

test('state NFT category is a circularity-free CashToken category binding from the pre-existing output-0 input', async () => {
  const bundle = await makeDevelopmentBundle('category-binding');
  const { categoryInputOutpoint, stateNftCategory } = bundle.manifest.genesis;
  assert.equal(stateNftCategory, deriveStateNftCategory(categoryInputOutpoint));
  assert.equal(stateNftCategory, categoryInputOutpoint.txid);
  assert.equal(categoryInputOutpoint.vout, '0');
  bundle.manifest.genesis.stateNftCategory = digest('wrong-category').slice('sha256:'.length);
  await writeBoundManifest(bundle);
  await assert.rejects(() => loadVerifierProfileBundle(bundle.directory), /state NFT category must equal/);
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

test('loader rejects unordered artifacts and unordered numeric ceremony contributions', async () => {
  const unorderedArtifacts = await makeDevelopmentBundle('unordered-artifacts', (manifest) => {
    manifest.artifacts.reverse();
  });
  await assert.rejects(() => loadVerifierProfileBundle(unorderedArtifacts.directory), /artifacts must be strictly sorted by id/);

  const unorderedContributions = await makeDevelopmentBundle('unordered-contributions', (manifest, files, artifact) => {
    files['artifacts/transcript.json'] = fixtureBytes('ceremony-transcript', 'complete-fixture');
    manifest.artifacts.splice(1, 0, artifact('ceremony-transcript', 'ceremony-transcript', 'artifacts/transcript.json'));
    const verifier = { name: 'fixture-verifier', version: '0', sha256: digest('fixture-verifier') };
    manifest.setup = {
      mode: 'ceremony-production',
      provenance: { method: 'multi-party-randomness', initializerCommitment: digest('ceremony-init') },
      transcript: { status: 'complete', artifactPath: 'artifacts/transcript.json', sha256: digest(files['artifacts/transcript.json']), verifier },
      contributions: [
        { sequence: '2', participantCommitment: digest('participant-2'), contributionHash: digest('contribution-2'), verification: { status: 'verified', verifier } },
        { sequence: '1', participantCommitment: digest('participant-1'), contributionHash: digest('contribution-1'), verification: { status: 'verified', verifier } },
      ],
    };
  });
  await assert.rejects(() => loadVerifierProfileBundle(unorderedContributions.directory), /ceremony contributions must be strictly sorted/);
});

test('loader rejects parent-directory symlink escapes plus BOM, noncanonical, and oversized manifests', async () => {
  const symlinked = await makeDevelopmentBundle('parent-symlink-escape');
  const outside = await mkdtemp(path.join(tmpdir(), 'shield-cash-outside-fixture-'));
  const outsideBytes = fixtureBytes('verification-key', 'outside-root');
  await writeFile(path.join(outside, 'vk.bin'), outsideBytes);
  await symlink(outside, path.join(symlinked.directory, 'linked'), 'dir');
  const verificationKey = symlinked.manifest.artifacts.find((artifact) => artifact.kind === 'verification-key');
  verificationKey.path = 'linked/vk.bin';
  verificationKey.sha256 = digest(outsideBytes);
  await writeBoundManifest(symlinked);
  await assert.rejects(() => loadVerifierProfileBundle(symlinked.directory), /resolves outside bundle root/);

  const malformed = await makeDevelopmentBundle('manifest-encoding');
  const canonical = canonicalJson(malformed.manifest);
  await writeFile(path.join(malformed.directory, 'manifest.json'), `\ufeff${canonical}`);
  await assert.rejects(() => loadVerifierProfileBundle(malformed.directory), /UTF-8 BOM/);
  await writeFile(path.join(malformed.directory, 'manifest.json'), JSON.stringify(malformed.manifest));
  await assert.rejects(() => loadVerifierProfileBundle(malformed.directory), /not canonical JSON/);
  await writeFile(path.join(malformed.directory, 'manifest.json'), ' '.repeat((1024 * 1024) + 1));
  await assert.rejects(() => loadVerifierProfileBundle(malformed.directory), /1 MiB maximum size/);
});
