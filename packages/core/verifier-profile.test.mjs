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
  deriveStateNftCategory, compareDevelopmentVerifierProfileBundles, loadVerifierProfileBundle,
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
      material: {
        phase1: { ptauSource: 'noncryptographic-test-ptau', ptauSha256: digest(`ptau-${seed}`) },
        phase2: {
          initializationCommand: { argv: ['fixture-zkey', 'new', 'circuit.r1cs', 'ptau'] },
          contributionCommand: { argv: ['fixture-zkey', 'contribute', 'initial.zkey', 'final.zkey'] },
          randomnessCommitment: digest(`randomness-${seed}`), finalZkeySha256: digest(files['artifacts/pk.bin']),
        },
      },
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

async function makeReplacementBundle(seed) {
  return makeDevelopmentBundle(seed, (manifest, files) => {
    files['artifacts/witness-generator.bin'] = fixtureBytes('witness-generator', 'shared-replacement-interface');
    manifest.artifacts.find((artifact) => artifact.kind === 'witness-generator').sha256 = digest(files['artifacts/witness-generator.bin']);
  });
}

async function makeCeremonyBundle(seed) {
  return makeDevelopmentBundle(seed, (manifest, files, artifact) => {
    files['artifacts/transcript.json'] = fixtureBytes('ceremony-transcript', 'complete-fixture');
    manifest.artifacts.splice(1, 0, artifact('ceremony-transcript', 'ceremony-transcript', 'artifacts/transcript.json'));
    const verifier = { name: 'fixture-verifier', version: '0', sha256: digest('fixture-verifier') };
    const contributions = [
      { sequence: '1', participantCommitment: digest('participant-1'), contributionHash: digest('contribution-1'), verification: { status: 'verified', verifier } },
      { sequence: '2', participantCommitment: digest('participant-2'), contributionHash: digest('contribution-2'), verification: { status: 'verified', verifier } },
    ];
    manifest.setup = {
      mode: 'ceremony-production',
      provenance: { method: 'multi-party-randomness', initializerCommitment: digest(`ceremony-init-${seed}`) },
      material: {
        phase1: { ptauSource: 'noncryptographic-test-ptau', ptauSha256: digest(`ptau-${seed}`) },
        phase2: {
          initializationCommand: { argv: ['fixture-zkey', 'new'] },
          finalZkeySha256: digest(files['artifacts/pk.bin']),
          finalZkeyVerification: { status: 'verified', verifier },
          contributionChainSha256: digest(canonicalJson(contributions)),
        },
      },
      transcript: { status: 'complete', artifactPath: 'artifacts/transcript.json', sha256: digest(files['artifacts/transcript.json']), verifier },
      contributions,
    };
  });
}

test('same relation and ABI with different local setup/key material derives a new profile and loads as a new instance', async () => {
  const first = await makeDevelopmentBundle('independent-a');
  const second = await makeDevelopmentBundle('independent-b');
  const left = await loadVerifierProfileBundle(first.directory);
  const right = await loadVerifierProfileBundle(second.directory);
  assert.equal(left.manifest.profile.relation.sha256, right.manifest.profile.relation.sha256);
  assert.equal(left.manifest.profile.constraintSystemHash, right.manifest.profile.constraintSystemHash);
  assert.equal(left.manifest.profile.publicInputAbi.sha256, right.manifest.profile.publicInputAbi.sha256);
  assert.notEqual(
    left.manifest.artifacts.find((artifact) => artifact.kind === 'verification-key').sha256,
    right.manifest.artifacts.find((artifact) => artifact.kind === 'verification-key').sha256,
  );
  assert.notEqual(
    left.manifest.setup.provenance.initializerCommitment,
    right.manifest.setup.provenance.initializerCommitment,
  );
  assert.notEqual(left.profileId, right.profileId);
  assert.notEqual(left.instanceId, right.instanceId);
  assert.equal(left.manifest.setup.mode, 'development-only');
  assert.equal(Object.isFrozen(left.manifest), true);

  await assert.rejects(
    () => loadVerifierProfileBundle(second.directory, {
      network: left.manifest.network.name,
      profileId: left.profileId,
      instanceId: left.instanceId,
    }),
    /expected profile binding mismatch: refusing hot swap/,
  );
  const newInstance = await loadVerifierProfileBundle(second.directory, {
    network: right.manifest.network.name,
    profileId: right.profileId,
    instanceId: right.instanceId,
  });
  assert.equal(newInstance.profileId, right.profileId);
  assert.equal(newInstance.instanceId, right.instanceId);
});

test('replacement comparator proves only the local-development interface property and fails closed', async () => {
  const first = await makeReplacementBundle('replacement-a');
  const second = await makeReplacementBundle('replacement-b');
  const comparisonBytes = await compareDevelopmentVerifierProfileBundles({ leftDirectory: first.directory, rightDirectory: second.directory });
  const comparison = JSON.parse(comparisonBytes);
  assert.equal(canonicalJson(comparison), comparisonBytes);
  assert.equal(comparison.scope, 'interface-replacement-only');
  assert.equal(comparison.replacementProperty, 'satisfied');
  assert.equal(comparison.shared.witnessGeneratorHash, first.manifest.artifacts.find((artifact) => artifact.kind === 'witness-generator').sha256);
  assert.notEqual(comparison.replacements.left.profileId, comparison.replacements.right.profileId);
  assert.notDeepEqual(comparison.replacements.left.categoryInputOutpoint, comparison.replacements.right.categoryInputOutpoint);

  await assert.rejects(
    () => compareDevelopmentVerifierProfileBundles({ leftDirectory: first.directory, rightDirectory: second.directory, profileId: first.manifest.identity.profileId }),
    /replacement comparison input has missing or unknown properties/,
  );
  await assert.rejects(
    () => compareDevelopmentVerifierProfileBundles({ leftDirectory: first.directory, rightDirectory: first.directory }),
    /requires distinct bundle directories/,
  );
  const reusedSetup = await makeReplacementBundle('replacement-a');
  await assert.rejects(
    () => compareDevelopmentVerifierProfileBundles({ leftDirectory: first.directory, rightDirectory: reusedSetup.directory }),
    /requires distinct initializer commitments/,
  );
  const changedReserve = await makeReplacementBundle('replacement-reserve');
  changedReserve.manifest.genesis.reserveCapSatoshis = '20000000';
  await writeBoundManifest(changedReserve);
  await assert.rejects(
    () => compareDevelopmentVerifierProfileBundles({ leftDirectory: first.directory, rightDirectory: changedReserve.directory }),
    /requires equal denomination-relevant reserve-cap semantics/,
  );

  const alias = path.join(first.directory, 'bundle-alias');
  await symlink(first.directory, alias, 'dir');
  await assert.rejects(
    () => compareDevelopmentVerifierProfileBundles({ leftDirectory: alias, rightDirectory: second.directory }),
    /bundle directory must be a real non-symlink directory/,
  );

  await writeFile(path.join(second.directory, 'artifacts/vk.bin'), fixtureBytes('verification-key', 'drifted-after-comparison'));
  await assert.rejects(
    () => compareDevelopmentVerifierProfileBundles({ leftDirectory: first.directory, rightDirectory: second.directory }),
    /artifact hash mismatch: artifacts\/vk.bin/,
  );

  const ceremony = await makeCeremonyBundle('replacement-ceremony');
  await assert.rejects(
    () => compareDevelopmentVerifierProfileBundles({ leftDirectory: first.directory, rightDirectory: ceremony.directory }),
    /replacement comparison requires right development-only setup/,
  );
});

test('setup mode and setup provenance cannot be relabeled in place', async () => {
  const modeRelabeled = await makeDevelopmentBundle('mode-relabel');
  modeRelabeled.manifest.setup.mode = 'ceremony-production';
  await writeBoundManifest(modeRelabeled);
  await assert.rejects(
    () => loadVerifierProfileBundle(modeRelabeled.directory),
    /ceremony setup requires multi-party-randomness provenance/,
  );

  const provenanceRelabeled = await makeDevelopmentBundle('provenance-relabel');
  provenanceRelabeled.manifest.setup.provenance.method = 'multi-party-randomness';
  await writeBoundManifest(provenanceRelabeled);
  await assert.rejects(
    () => loadVerifierProfileBundle(provenanceRelabeled.directory),
    /development setup requires local-initialization provenance/,
  );
});

test('setup material binds Phase 1 provenance and the final zkey to the proving-key artifact', async () => {
  const wrongFinalZkey = await makeDevelopmentBundle('wrong-final-zkey');
  wrongFinalZkey.manifest.setup.material.phase2.finalZkeySha256 = digest('different-final-zkey');
  await writeBoundManifest(wrongFinalZkey);
  await assert.rejects(
    () => loadVerifierProfileBundle(wrongFinalZkey.directory),
    /setup material final zkey hash does not bind proving-key artifact/,
  );

  const missingPtau = await makeDevelopmentBundle('missing-ptau');
  delete missingPtau.manifest.setup.material.phase1.ptauSha256;
  await writeBoundManifest(missingPtau);
  await assert.rejects(
    () => loadVerifierProfileBundle(missingPtau.directory),
    /setup material phase1 has missing or unknown properties/,
  );

  const emptyPtauSource = await makeDevelopmentBundle('empty-ptau-source');
  emptyPtauSource.manifest.setup.material.phase1.ptauSource = '';
  await writeBoundManifest(emptyPtauSource);
  await assert.rejects(
    () => loadVerifierProfileBundle(emptyPtauSource.directory),
    /ptau source must contain 1 to 1024 characters without NUL/,
  );

  const emptyArgument = await makeDevelopmentBundle('empty-command-argument');
  emptyArgument.manifest.setup.material.phase2.initializationCommand.argv[0] = '';
  await writeBoundManifest(emptyArgument);
  await assert.rejects(
    () => loadVerifierProfileBundle(emptyArgument.directory),
    /argv 0 must be a non-empty argument without NUL/,
  );
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

test('genesis rejects a zero category and reserve caps outside fixed-note BCH bounds', async () => {
  const zeroCategory = await makeDevelopmentBundle('zero-category');
  zeroCategory.manifest.genesis.categoryInputOutpoint.txid = '0'.repeat(64);
  zeroCategory.manifest.genesis.stateNftCategory = '0'.repeat(64);
  await writeBoundManifest(zeroCategory);
  await assert.rejects(
    () => loadVerifierProfileBundle(zeroCategory.directory),
    /category input outpoint txid must be nonzero/,
  );

  const fractionalReserve = await makeDevelopmentBundle('fractional-reserve');
  fractionalReserve.manifest.genesis.reserveCapSatoshis = '10000001';
  await writeBoundManifest(fractionalReserve);
  await assert.rejects(
    () => loadVerifierProfileBundle(fractionalReserve.directory),
    /nonzero denomination multiple within BCH supply/,
  );

  const excessiveReserve = await makeDevelopmentBundle('excessive-reserve');
  excessiveReserve.manifest.genesis.reserveCapSatoshis = '2110000000000000';
  await writeBoundManifest(excessiveReserve);
  await assert.rejects(
    () => loadVerifierProfileBundle(excessiveReserve.directory),
    /nonzero denomination multiple within BCH supply/,
  );
});

test('production mode rejects an incomplete ceremony transcript rather than accepting a development setup label', async () => {
  const bundle = await makeDevelopmentBundle('missing-transcript', (manifest) => {
    manifest.setup = {
      mode: 'ceremony-production',
      provenance: { method: 'multi-party-randomness', initializerCommitment: digest('ceremony-init') },
      material: {
        phase1: { ptauSource: 'noncryptographic-test-ptau', ptauSha256: digest('ptau') },
        phase2: { initializationCommand: { argv: ['fixture-zkey', 'new'] }, finalZkeySha256: digest('absent'), finalZkeyVerification: { status: 'verified', verifier: { name: 'fixture-verifier', version: '0', sha256: digest('verifier') } }, contributionChainSha256: digest(canonicalJson([{ sequence: '1', participantCommitment: digest('participant-1'), contributionHash: digest('contribution-1'), verification: { status: 'verified', verifier: { name: 'fixture-verifier', version: '0', sha256: digest('verifier') } } }, { sequence: '2', participantCommitment: digest('participant-2'), contributionHash: digest('contribution-2'), verification: { status: 'verified', verifier: { name: 'fixture-verifier', version: '0', sha256: digest('verifier') } } }])) },
      },
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
      material: {
        phase1: { ptauSource: 'noncryptographic-test-ptau', ptauSha256: digest('ptau') },
        phase2: { initializationCommand: { argv: ['fixture-zkey', 'new'] }, finalZkeySha256: digest(files['artifacts/pk.bin']), finalZkeyVerification: { status: 'verified', verifier }, contributionChainSha256: digest(canonicalJson([{ sequence: '2', participantCommitment: digest('participant-2'), contributionHash: digest('contribution-2'), verification: { status: 'verified', verifier } }, { sequence: '1', participantCommitment: digest('participant-1'), contributionHash: digest('contribution-1'), verification: { status: 'verified', verifier } }])) },
      },
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
  const internalSymlink = await makeDevelopmentBundle('internal-parent-symlink');
  await symlink(
    path.join(internalSymlink.directory, 'artifacts'),
    path.join(internalSymlink.directory, 'alias'),
    'dir',
  );
  const internalVerificationKey = internalSymlink.manifest.artifacts.find(
    (artifact) => artifact.kind === 'verification-key',
  );
  internalVerificationKey.path = 'alias/vk.bin';
  await writeBoundManifest(internalSymlink);
  await assert.rejects(
    () => loadVerifierProfileBundle(internalSymlink.directory),
    /artifact path contains a symlink/,
  );

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
