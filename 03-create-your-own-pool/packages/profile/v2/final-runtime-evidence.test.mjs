import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  sign,
} from 'node:crypto';
import test from 'node:test';

import { canonicalizeJcs } from './profile-core.mjs';
import {
  V2_FINAL_CEREMONY_BEACON_SCHEMA,
  V2_FINAL_CEREMONY_CONTRIBUTION_SCHEMA,
  V2_FINAL_CEREMONY_TRANSCRIPT_SCHEMA,
  V2_FINAL_CONTRIBUTOR_REGISTRY_SCHEMA,
  V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID,
  V2_FINAL_EVIDENCE_POLICY_SCHEMA,
  V2_FINAL_EVIDENCE_SIGNATURE_DOMAIN,
  V2_FINAL_REPRODUCTION_SCHEMA,
  V2_FINAL_SIGNED_EVIDENCE_SCHEMA,
  V2_FINAL_TRANSCRIPT_VERIFICATION_SCHEMA,
  V2FinalRuntimeEvidenceError,
  verifyV2FinalRuntimeEvidence,
} from './final-runtime-evidence.mjs';

// Every object in this file is TEST-ONLY: freshly generated ephemeral keys,
// invented hashes, and no real circuit, ceremony, host, or release evidence.
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const canonicalBytes = (value) => Buffer.from(canonicalizeJcs(value), 'utf8');
const digest = (label) => sha256(`TEST-ONLY final runtime evidence: ${label}`);
const sourceCommit = digest('source-commit').slice(0, 40);
const sourceTree = digest('source-tree').slice(0, 40);

function authority(role, suffix) {
  const pair = generateKeyPairSync('ed25519');
  return {
    independenceDomain: `domain-${suffix}`,
    organizationId: `organization-${suffix}`,
    privateKey: pair.privateKey,
    publicKeySha256: sha256(pair.publicKey.export({ format: 'der', type: 'spki' })),
    publicKeyPem: pair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    role,
    signerId: `signer-${suffix}`,
  };
}

function policyAuthority(entry) {
  const {
    independenceDomain,
    organizationId,
    publicKeyPem,
    role,
    signerId,
  } = entry;
  return { independenceDomain, organizationId, publicKeyPem, role, signerId };
}

function signedEnvelope(entry, statement) {
  const statementBytes = canonicalBytes(statement);
  const signingBytes = Buffer.concat([
    Buffer.from(V2_FINAL_EVIDENCE_SIGNATURE_DOMAIN, 'utf8'),
    Buffer.from(entry.role, 'utf8'),
    Buffer.from([0]),
    statementBytes,
  ]);
  return {
    role: entry.role,
    schema: V2_FINAL_SIGNED_EVIDENCE_SCHEMA,
    signatureBase64: sign(null, signingBytes, entry.privateKey).toString('base64'),
    signerId: entry.signerId,
    statement,
    statementSha256: sha256(statementBytes),
  };
}

/** Build a complete, deliberately nonqualifying, in-memory evidence bundle. */
function testOnlyBundle() {
  const coordinator = authority('ceremony-coordinator', 'coordinator');
  const contributors = [1, 2, 3, 4, 5].map((index) =>
    authority('ceremony-contributor', `contributor-${index}`));
  const verifierA = authority('transcript-verifier-a', 'verifier-a');
  const verifierB = authority('transcript-verifier-b', 'verifier-b');
  const reproductionA = authority('reproduction-host-a', 'reproduction-a');
  const reproductionB = authority('reproduction-host-b', 'reproduction-b');
  const profileId = digest('profile');
  const instanceId = digest('instance');
  const finalLocksSha256 = digest('final-locks');
  const runtimeMaterialSha256 = digest('runtime-material');
  const toolchainSha256 = digest('toolchain');
  const entries = {};
  const blobs = new Map();
  const addStatic = (artifactId) => {
    const bytes = Buffer.from(
      `TEST-ONLY final runtime artifact: ${artifactId}`,
      'utf8',
    );
    blobs.set(artifactId, bytes);
    entries[artifactId] = { sha256: sha256(bytes) };
  };
  const addJson = (artifactId, value) => {
    const bytes = canonicalBytes(value);
    blobs.set(artifactId, bytes);
    entries[artifactId] = { sha256: sha256(bytes) };
  };
  for (const artifactId of [
    'contributor-registry', 'transcript', 'beacon',
    'transcript-verification-a', 'transcript-verification-b',
    'reproduction-a', 'reproduction-b', 'relation-source-manifest',
    'circuit-build-attestation', 'r1cs', 'witness-wasm', 'circuit-symbols',
    'powers-of-tau', 'initial-zkey', 'final-zkey', 'verification-key',
    'snarkjs-toolchain',
    'contribution-command-1', 'contribution-command-2',
    'contribution-command-3', 'contribution-command-4',
    'contribution-command-5', 'beacon-value', 'beacon-command',
    'verifier-command-a', 'verifier-command-b', 'verifier-machine-a',
    'verifier-machine-b', 'verification-log-a', 'verification-log-b',
    'reproduction-command-a', 'reproduction-command-b',
    'reproduction-lockfile',
    'reproduction-machine-a', 'reproduction-machine-b', 'different-lockfile',
  ]) addStatic(artifactId);
  const reference = (artifactId) => ({ artifactId, sha256: entries[artifactId].sha256 });

  const policy = {
    ceremony: {
      contributors: contributors.map(policyAuthority),
      coordinator: policyAuthority(coordinator),
      minimumContributors: 5,
      reproducibilityHosts: [
        policyAuthority(reproductionA), policyAuthority(reproductionB),
      ],
      transcriptVerifiers: [policyAuthority(verifierA), policyAuthority(verifierB)],
    },
    network: { id: 2, name: 'chipnet' },
    schema: V2_FINAL_EVIDENCE_POLICY_SCHEMA,
  };
  addJson(V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID, policy);

  const registryStatement = {
    contributors: contributors.map((entry, index) => ({
      independenceDomain: entry.independenceDomain,
      organizationId: entry.organizationId,
      publicKeySha256: entry.publicKeySha256,
      sequence: index + 1,
      signerId: entry.signerId,
    })),
    policy: reference(V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID),
    profileId,
    schema: V2_FINAL_CONTRIBUTOR_REGISTRY_SCHEMA,
  };
  addJson('contributor-registry', signedEnvelope(coordinator, registryStatement));

  const outputs = contributors.map((_, index) =>
    index === contributors.length - 1
      ? entries['final-zkey'].sha256
      : digest(`contribution-zkey-${index + 1}`));
  const contributionEnvelopes = contributors.map((entry, index) => {
    const statement = {
      commandTranscript: reference(`contribution-command-${index + 1}`),
      inputZkeySha256: index === 0
        ? entries['initial-zkey'].sha256
        : outputs[index - 1],
      outputZkeySha256: outputs[index],
      policy: reference(V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID),
      profileId,
      schema: V2_FINAL_CEREMONY_CONTRIBUTION_SCHEMA,
      sequence: index + 1,
      toolchainSha256,
    };
    return signedEnvelope(entry, statement);
  });
  const beaconStatement = {
    beaconValue: reference('beacon-value'),
    commandTranscript: reference('beacon-command'),
    finalZkey: reference('final-zkey'),
    inputZkeySha256: outputs.at(-1),
    iterations: 1,
    policy: reference(V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID),
    profileId,
    schema: V2_FINAL_CEREMONY_BEACON_SCHEMA,
    toolchainSha256,
  };
  addJson('beacon', signedEnvelope(coordinator, beaconStatement));
  const transcriptStatement = {
    beacon: reference('beacon'),
    circuitBuildAttestation: reference('circuit-build-attestation'),
    contributions: contributionEnvelopes,
    contributorRegistry: reference('contributor-registry'),
    finalZkey: reference('final-zkey'),
    initialZkey: reference('initial-zkey'),
    policy: reference(V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID),
    powersOfTau: reference('powers-of-tau'),
    profileId,
    r1cs: reference('r1cs'),
    relationSourceManifest: reference('relation-source-manifest'),
    schema: V2_FINAL_CEREMONY_TRANSCRIPT_SCHEMA,
    snarkjsToolchain: reference('snarkjs-toolchain'),
    verificationKey: reference('verification-key'),
  };
  addJson('transcript', signedEnvelope(coordinator, transcriptStatement));

  const verificationStatement = (suffix) => ({
    beacon: reference('beacon'),
    commandTranscript: reference(`verifier-command-${suffix}`),
    finalZkey: reference('final-zkey'),
    machineManifest: reference(`verifier-machine-${suffix}`),
    policy: reference(V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID),
    powersOfTau: reference('powers-of-tau'),
    profileId,
    r1cs: reference('r1cs'),
    result: 'verified',
    schema: V2_FINAL_TRANSCRIPT_VERIFICATION_SCHEMA,
    snarkjsToolchain: reference('snarkjs-toolchain'),
    toolchainSha256,
    transcript: reference('transcript'),
    verificationKey: reference('verification-key'),
    verificationLog: reference(`verification-log-${suffix}`),
  });
  addJson('transcript-verification-a', signedEnvelope(
    verifierA, verificationStatement('a'),
  ));
  addJson('transcript-verification-b', signedEnvelope(
    verifierB, verificationStatement('b'),
  ));

  const reproductionStatement = (suffix) => ({
    circuitBuildAttestation: reference('circuit-build-attestation'),
    circuitSymbols: reference('circuit-symbols'),
    commandTranscript: reference(`reproduction-command-${suffix}`),
    finalLocksSha256,
    finalZkey: reference('final-zkey'),
    instanceId,
    lockfile: reference('reproduction-lockfile'),
    machineManifest: reference(`reproduction-machine-${suffix}`),
    policy: reference(V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID),
    profileId,
    relationSourceManifest: reference('relation-source-manifest'),
    results: {
      circuitReproduced: true,
      finalZkeyVerified: true,
      runtimeReproduced: true,
      verificationKeyExported: true,
    },
    r1cs: reference('r1cs'),
    runtimeMaterialSha256,
    schema: V2_FINAL_REPRODUCTION_SCHEMA,
    snarkjsToolchain: reference('snarkjs-toolchain'),
    sourceCommit,
    sourceTree,
    toolchainSha256,
    transcript: reference('transcript'),
    verificationKey: reference('verification-key'),
    witnessWasm: reference('witness-wasm'),
  });
  addJson('reproduction-a', signedEnvelope(
    reproductionA, reproductionStatement('a'),
  ));
  addJson('reproduction-b', signedEnvelope(
    reproductionB, reproductionStatement('b'),
  ));

  const runtimeReferences = {
    beacon: 'beacon',
    circuitBuildAttestation: 'circuit-build-attestation',
    circuitSymbols: 'circuit-symbols',
    contributorRegistry: 'contributor-registry',
    finalZkey: 'final-zkey',
    initialZkey: 'initial-zkey',
    policy: V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID,
    powersOfTau: 'powers-of-tau',
    r1cs: 'r1cs',
    relationSourceManifest: 'relation-source-manifest',
    snarkjsToolchain: 'snarkjs-toolchain',
    reproductions: ['reproduction-a', 'reproduction-b'],
    transcript: 'transcript',
    transcriptVerifications: [
      'transcript-verification-a', 'transcript-verification-b',
    ],
    verificationKey: 'verification-key',
    witnessWasm: 'witness-wasm',
  };
  const profileBaseArtifacts = {
    [V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID]:
      entries[V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID].sha256,
  };
  const verify = () => verifyV2FinalRuntimeEvidence({
    artifactEntries: entries,
    finalLocksSha256,
    instanceId,
    profileBaseArtifacts,
    profileId,
    profileProof: {
      r1csSha256: entries.r1cs.sha256,
      verificationKeySha256: entries['verification-key'].sha256,
      witnessWasmSha256: entries['witness-wasm'].sha256,
    },
    profileToolchainSha256: toolchainSha256,
    readArtifactBytes: async (artifactId) => blobs.get(artifactId),
    runtimeMaterialSha256,
    runtimeReferences,
  });
  return {
    blobs, contributors, coordinator, entries, reproductionA, reproductionB,
    profileBaseArtifacts, runtimeReferences, verifierA, verifierB, verify,
  };
}

function envelope(bundle, artifactId) {
  return JSON.parse(bundle.blobs.get(artifactId).toString('utf8'));
}

function replaceEnvelope(bundle, artifactId, signer, mutate, {
  repin = true,
} = {}) {
  const value = envelope(bundle, artifactId);
  mutate(value.statement);
  const bytes = canonicalBytes(signedEnvelope(signer, value.statement));
  bundle.blobs.set(artifactId, bytes);
  if (repin) bundle.entries[artifactId].sha256 = sha256(bytes);
}

async function rejects(bundle, expression) {
  await assert.rejects(bundle.verify(), (error) => (
    error instanceof V2FinalRuntimeEvidenceError && expression.test(error.message)
  ));
}

test('accepts a complete TEST-ONLY five-contributor final-runtime evidence bundle', async () => {
  const bundle = testOnlyBundle();
  const result = await bundle.verify();
  assert.equal(result.contributorCount, 5);
  assert.equal(result.sourceCommit, sourceCommit);
  assert.equal(result.sourceTree, sourceTree);
  assert.equal(result.snarkjsToolchainSha256, bundle.entries['snarkjs-toolchain'].sha256);
});

test('rejects a canonical validly signed envelope substituted under a pinned evidence ID', async () => {
  const bundle = testOnlyBundle();
  replaceEnvelope(
    bundle,
    'transcript-verification-a',
    bundle.verifierA,
    (statement) => {
      // This remains a canonical, correctly signed, semantically valid
      // transcript-verifier-A statement. Only the pinned envelope bytes differ.
      statement.verificationLog = {
        artifactId: 'verification-log-b',
        sha256: bundle.entries['verification-log-b'].sha256,
      };
    },
    { repin: false },
  );
  await rejects(bundle, /transcript-verifier-a evidence sha256 does not match the signed artifact manifest/);
});

test('rejects substituted bytes for a nested manifest-referenced artifact', async () => {
  const bundle = testOnlyBundle();
  bundle.blobs.set('verifier-command-a', Buffer.from(
    'TEST-ONLY substituted verifier command transcript',
    'utf8',
  ));
  await rejects(bundle, /transcript-verifier-a evidence statement nested artifact\[1\] sha256 does not match the signed artifact manifest/);
});

test('rejects a signed transcript with a drifted snarkjs toolchain reference', async () => {
  const bundle = testOnlyBundle();
  replaceEnvelope(bundle, 'transcript', bundle.coordinator, (statement) => {
    statement.snarkjsToolchain = {
      artifactId: 'verification-key',
      sha256: bundle.entries['verification-key'].sha256,
    };
  });
  await rejects(bundle, /final ceremony transcript snarkjsToolchain differs from the final runtime artifact/);
});

test('rejects policy substitution, insufficient/duplicate contributors, and a tampered signature', async () => {
  let bundle = testOnlyBundle();
  bundle.profileBaseArtifacts[V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID] = digest('substituted-policy');
  await rejects(bundle, /not frozen in the profile core/);

  bundle = testOnlyBundle();
  replaceEnvelope(bundle, 'transcript', bundle.coordinator, (statement) => {
    statement.contributions.pop();
  });
  await rejects(bundle, /at least 5 contributions/);

  bundle = testOnlyBundle();
  replaceEnvelope(bundle, 'transcript', bundle.coordinator, (statement) => {
    statement.contributions[1] = structuredClone(statement.contributions[0]);
    statement.contributions[1].statement.sequence = 2;
    statement.contributions[1] = signedEnvelope(
      bundle.contributors[0], statement.contributions[1].statement,
    );
  });
  await rejects(bundle, /reuses a contributor identity/);

  bundle = testOnlyBundle();
  const registry = envelope(bundle, 'contributor-registry');
  registry.signatureBase64 = `${registry.signatureBase64.slice(0, -3)}AAA`;
  const bytes = canonicalBytes(registry);
  bundle.blobs.set('contributor-registry', bytes);
  bundle.entries['contributor-registry'].sha256 = sha256(bytes);
  await rejects(bundle, /signature/);
});

test('rejects an otherwise pinned one-contributor policy, registry, or transcript', async () => {
  let bundle = testOnlyBundle();
  const policy = JSON.parse(bundle.blobs.get(
    V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID,
  ).toString('utf8'));
  policy.ceremony.contributors = [policy.ceremony.contributors[0]];
  const policyBytes = canonicalBytes(policy);
  bundle.blobs.set(V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID, policyBytes);
  bundle.entries[V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID].sha256 = sha256(policyBytes);
  bundle.profileBaseArtifacts[V2_FINAL_EVIDENCE_POLICY_ARTIFACT_ID] = sha256(policyBytes);
  await rejects(bundle, /must authorize at least 5 contributors/);

  bundle = testOnlyBundle();
  replaceEnvelope(bundle, 'contributor-registry', bundle.coordinator, (statement) => {
    statement.contributors = [statement.contributors[0]];
  });
  await rejects(bundle, /registry requires at least 5 contributors/);

  bundle = testOnlyBundle();
  replaceEnvelope(bundle, 'transcript', bundle.coordinator, (statement) => {
    statement.contributions = [statement.contributions[0]];
  });
  await rejects(bundle, /transcript requires at least 5 contributions/);
});

test('rejects a broken zkey chain, beacon mismatch, and shared verifier machine', async () => {
  let bundle = testOnlyBundle();
  replaceEnvelope(bundle, 'transcript', bundle.coordinator, (statement) => {
    const contribution = statement.contributions[2];
    contribution.statement.inputZkeySha256 = digest('broken-zkey-chain');
    statement.contributions[2] = signedEnvelope(
      bundle.contributors[2], contribution.statement,
    );
  });
  await rejects(bundle, /contribution chain is discontinuous/);

  bundle = testOnlyBundle();
  replaceEnvelope(bundle, 'beacon', bundle.coordinator, (statement) => {
    statement.inputZkeySha256 = digest('wrong-beacon-input');
  });
  replaceEnvelope(bundle, 'transcript', bundle.coordinator, (statement) => {
    statement.beacon.sha256 = bundle.entries.beacon.sha256;
  });
  await rejects(bundle, /registry, contribution chain, beacon, and final zkey do not agree/);

  bundle = testOnlyBundle();
  replaceEnvelope(bundle, 'transcript-verification-b', bundle.verifierB, (statement) => {
    statement.machineManifest = {
      artifactId: 'verifier-machine-a',
      sha256: bundle.entries['verifier-machine-a'].sha256,
    };
  });
  await rejects(bundle, /verification hosts must have distinct machine manifests/);
});

test('rejects reproduction source/lockfile drift and unknown or duplicate evidence references', async () => {
  let bundle = testOnlyBundle();
  replaceEnvelope(bundle, 'reproduction-b', bundle.reproductionB, (statement) => {
    statement.sourceCommit = digest('different-source').slice(0, 40);
  });
  await rejects(bundle, /did not reproduce identical source and lockfile inputs/);

  bundle = testOnlyBundle();
  replaceEnvelope(bundle, 'reproduction-b', bundle.reproductionB, (statement) => {
    statement.lockfile = {
      artifactId: 'different-lockfile',
      sha256: bundle.entries['different-lockfile'].sha256,
    };
  });
  await rejects(bundle, /did not reproduce identical source and lockfile inputs/);

  bundle = testOnlyBundle();
  bundle.runtimeReferences.reproductions[1] = 'unknown-evidence';
  await rejects(bundle, /is not a signed manifest artifact/);

  bundle = testOnlyBundle();
  bundle.runtimeReferences.transcriptVerifications[1] = 'transcript-verification-a';
  await rejects(bundle, /signed-evidence schema or role is invalid/);
});

test('rejects noncanonical signed-evidence bytes', async () => {
  const bundle = testOnlyBundle();
  const registry = envelope(bundle, 'contributor-registry');
  const bytes = Buffer.from(
    JSON.stringify(registry, null, 2), 'utf8',
  );
  bundle.blobs.set('contributor-registry', bytes);
  bundle.entries['contributor-registry'].sha256 = sha256(bytes);
  await rejects(bundle, /exact RFC8785\/JCS bytes/);
});
