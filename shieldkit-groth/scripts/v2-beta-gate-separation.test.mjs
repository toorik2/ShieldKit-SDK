/*
 * Rejection-only regression coverage for the single-contributor beta custody
 * lane. These records intentionally cannot represent successful final or
 * release evidence: every assertion below requires a consumer to reject.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  V2_BETA_SINGLE_CONTRIBUTOR_RESULT_SCHEMA,
  V2_BETA_SINGLE_CONTRIBUTOR_VERIFICATION_SCHEMA,
} from './v2-beta-single-contributor-ceremony.mjs';
import {
  V2_D01_POST_CEREMONY_BINDING_SCHEMA,
  validateV2D01PostCeremonyBinding,
  verifyV2D01FinalCeremonyEvidence,
} from './v2-final-ceremony-qualification.mjs';
import {
  revalidateV2Q01FinalArtifactReplayResult,
  runV2Q01FinalArtifactReplay,
} from './v2-q01-final-artifact-replay.mjs';
import {
  revalidateV2B02FinalVmResult,
  runV2B02FinalVm,
} from './v2-b02-final-vm.mjs';
import {
  verifyV2Q02FinalKeyCorpus,
} from './v2-q02-final-key-corpus.mjs';
import {
  revalidateV2Q03FinalLockAttacks,
  verifyV2Q03FinalLockAttacks,
} from './v2-q03-final-lock-attacks.mjs';
import {
  v2Q03AttackMatrixSha256,
} from './v2-q03-attack-matrix.mjs';
import {
  validateV2Q07AuthorityForTestOnly,
  verifyV2Q07FinalPerformance,
} from './v2-q07-final-performance.mjs';
import {
  normalizeV2Q08HostStateEvidenceReference,
  runV2Q08CleanMachineQualification,
} from './v2-clean-machine-qualification.mjs';
import {
  assertV2Q09Q08PairBinding,
} from './v2-chipnet-soak.mjs';
import {
  verifyV2FinalRuntimeEvidence,
} from '../packages/profile/v2/final-runtime-evidence.mjs';
import {
  assertV2FinalReleaseRoot,
  resolveV2FinalReleaseRoot,
} from '../packages/profile/v2/release-bootstrap.mjs';
import {
  deriveV2Pf10RuntimeFromValidatedDescriptor,
  validateV2UnsignedPf10RuntimeArtifactReferences,
} from '../packages/profile/v2/instance-descriptor.mjs';
import {
  DIRECT_V2_PF10_BETA_ELIGIBILITY,
  DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA,
} from '../packages/unlock-builder/v2/pf10-beta-runtime.mjs';
import {
  validateDirectV2Pf10RuntimeMaterial,
} from '../packages/unlock-builder/v2/pf10-action-witness.mjs';
import {
  canonicalizeJcs,
} from '../packages/profile/v2/profile-core.mjs';

// Final-gate modules require an unmodified Node 22 process. node:test has
// consumed its flags before this test module is evaluated.
process.execArgv.length = 0;

const hash = (label) => createHash('sha256').update(label).digest('hex');
const git = (label) => createHash('sha1').update(label).digest('hex');
const absolute = (name) => `/tmp/shieldkit-beta-gate-separation/${name}`;
const claims = Object.freeze({
  b02Qualified: false,
  ceremonyQualified: false,
  d01Qualified: false,
  d02Qualified: false,
  finalKey: false,
  participantIndependenceEstablished: false,
  production: false,
  q01FinalReplayQualified: false,
  q02Qualified: false,
  q03Qualified: false,
  q07Qualified: false,
  q08Qualified: false,
  q09Qualified: false,
  releaseQualified: false,
});

const betaProvingKey = Object.freeze({
  artifactId: 'beta-proving-key-r3',
  sha256: hash('beta-proving-key-r3'),
});
const betaVerificationKey = Object.freeze({
  artifactId: 'beta-verification-key-r3',
  sha256: hash('beta-verification-key-r3'),
});
const betaResult = Object.freeze({
  schema: V2_BETA_SINGLE_CONTRIBUTOR_RESULT_SCHEMA,
  status: 'beta-single-contributor-cryptographically-verified-unqualified',
  assuranceClass: 'beta-single-contributor',
  artifacts: Object.freeze({
    betaProvingKey: Object.freeze({ bytes: '1', file: 'beta-proving-key.zkey', sha256: `sha256:${betaProvingKey.sha256}` }),
    verificationKey: Object.freeze({ bytes: '1', file: 'verification-key.json', sha256: `sha256:${betaVerificationKey.sha256}` }),
  }),
  b01ManifestSha256: `sha256:${hash('b01')}`,
  ceremonyId: 'shieldkit-v2-beta-r3',
  claims,
  entropyCommitment: `sha256:${hash('entropy')}`,
  entropyPolicySha256: `sha256:${hash('entropy-policy')}`,
  implementationSha256: `sha256:${hash('implementation')}`,
  participant: Object.freeze({ id: 'beta-operator', publicKeySpkiBase64: 'AA==' }),
  preparationSha256: `sha256:${hash('preparation')}`,
  receiptSha256: `sha256:${hash('receipt')}`,
  requestSha256: `sha256:${hash('request')}`,
  source: Object.freeze({ gitCommit: git('beta-commit'), gitTree: git('beta-tree') }),
  toolchainSha256: `sha256:${hash('toolchain')}`,
  transcriptFileSha256: `sha256:${hash('transcript-file')}`,
  transcriptSha256: `sha256:${hash('transcript')}`,
  verification: Object.freeze({
    entropyTransport: 'child-stdin-after-pinned-snarkjs-prompt',
    pinnedToolchainCheckedBeforeAndAfter: true,
    verificationKeyExportedAndCanonicalized: true,
    zkeyVerify: true,
  }),
});
const betaVerification = Object.freeze({
  schema: V2_BETA_SINGLE_CONTRIBUTOR_VERIFICATION_SCHEMA,
  status: 'beta-single-contributor-reverified-unqualified',
  claims,
  ceremonyId: betaResult.ceremonyId,
  preparationSha256: betaResult.preparationSha256,
  resultSha256: `sha256:${hash('result')}`,
  betaProvingKeySha256: betaResult.artifacts.betaProvingKey.sha256,
  entropyPolicySha256: betaResult.entropyPolicySha256,
  implementationSha256: betaResult.implementationSha256,
  verificationKeySha256: betaResult.artifacts.verificationKey.sha256,
  transcriptFileSha256: betaResult.transcriptFileSha256,
  transcriptSha256: betaResult.transcriptSha256,
});
const betaRuntime = Object.freeze({
  schema: DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA,
  status: 'beta-single-contributor-runtime-cryptographically-verified-unqualified',
  eligibility: DIRECT_V2_PF10_BETA_ELIGIBILITY,
  profileId: hash('beta-profile'),
  instanceId: hash('beta-instance'),
  provingKey: betaProvingKey,
  verificationKey: betaVerificationKey,
  ceremonyResult: betaResult,
  ceremonyVerification: betaVerification,
  claims,
});
const betaProfile = Object.freeze({
  schema: 'shieldkit-v2-direct-beta-single-contributor-profile-v1',
  status: 'beta-single-contributor-profile-unqualified',
  network: Object.freeze({ id: 2, name: 'chipnet' }),
  runtime: betaRuntime,
  claims,
});

const identity = Object.freeze({
  descriptorSha256: hash('descriptor'),
  finalLocksSha256: hash('final-locks'),
  instanceId: hash('instance'),
  manifestSha256: hash('manifest'),
  profileId: hash('profile'),
  profileSha256: hash('profile-core'),
  releaseBootstrapSha256: hash('bootstrap'),
  releaseRootId: 'final-root-r1',
  runtimeMaterialSha256: hash('runtime-material'),
  sourceCommit: git('source-commit'),
  sourceTree: git('source-tree'),
  topologyId: 'pf10-fused-q-genesis-v1',
});
const q03Roots = Object.freeze({
  authorityArtifactSha256: hash('authority'),
  b02ResultSha256: hash('b02'),
  corpusInventorySha256: hash('corpus-inventory'),
  corpusSha256: hash('corpus'),
  identity,
  laneInventorySha256: hash('lane-inventory'),
  matrixSha256: v2Q03AttackMatrixSha256,
  transactionsManifestSha256: hash('transactions'),
});

function reject(fn, expression = /(?:invalid|missing|unsupported|exact|root|schema|properties|qualified)/iu) {
  assert.throws(fn, expression);
}

test('beta result, verification, claim relabels, and added final fields fail every pure final-result parser', () => {
  const relabelled = { ...betaResult, schema: V2_D01_POST_CEREMONY_BINDING_SCHEMA, status: 'd01-qualified-final-key-not-production-or-release', d01Qualified: true };
  const extraFinalField = { ...betaResult, finalZkeySha256: hash('forbidden-final-zkey') };
  const nestedBetaBlob = { beta: betaResult };

  for (const candidate of [betaResult, betaVerification, relabelled, extraFinalField, nestedBetaBlob]) {
    reject(() => validateV2D01PostCeremonyBinding(candidate, {}));
    reject(() => revalidateV2Q01FinalArtifactReplayResult(candidate));
    reject(() => revalidateV2B02FinalVmResult(candidate));
    reject(() => revalidateV2Q03FinalLockAttacks(candidate, q03Roots));
    reject(() => validateV2Q07AuthorityForTestOnly(candidate));
    reject(() => normalizeV2Q08HostStateEvidenceReference(candidate));
    reject(() => assertV2Q09Q08PairBinding(candidate, identity));
  }
});

test('final-runtime evidence rejects a beta profile even when beta zkey/VK bytes are manifest-pinned', async () => {
  const policyId = 'final-evidence-policy';
  const betaBytes = Buffer.from(canonicalizeJcs(betaProfile), 'utf8');
  const betaSha256 = hash(betaBytes);
  const artifactEntries = Object.freeze({
    [policyId]: Object.freeze({ sha256: betaSha256 }),
    'beta-payload-r3': Object.freeze({ sha256: betaSha256 }),
  });
  const references = Object.freeze({
    policy: policyId,
    contributorRegistry: 'beta-payload-r3',
    transcript: 'beta-payload-r3',
    beacon: 'beta-payload-r3',
    relationSourceManifest: 'beta-payload-r3',
    circuitBuildAttestation: 'beta-payload-r3',
    r1cs: 'beta-payload-r3',
    witnessWasm: 'beta-payload-r3',
    circuitSymbols: 'beta-payload-r3',
    powersOfTau: 'beta-payload-r3',
    initialZkey: 'beta-payload-r3',
    finalZkey: 'beta-payload-r3',
    verificationKey: 'beta-payload-r3',
    snarkjsToolchain: 'beta-payload-r3',
    transcriptVerifications: ['beta-payload-r3', 'beta-payload-r3'],
    reproductions: ['beta-payload-r3', 'beta-payload-r3'],
  });
  await assert.rejects(
    verifyV2FinalRuntimeEvidence({
      artifactEntries,
      finalLocksSha256: hash('locks'),
      instanceId: hash('instance'),
      profileBaseArtifacts: { [policyId]: betaSha256 },
      profileId: hash('profile'),
      profileProof: {
        r1csSha256: betaSha256,
        verificationKeySha256: betaSha256,
        witnessWasmSha256: betaSha256,
      },
      profileToolchainSha256: betaSha256,
      readArtifactBytes: async () => betaBytes,
      runtimeMaterialSha256: hash('material'),
      runtimeReferences: references,
    }),
    /final evidence policy|schema|properties/iu,
  );
});

test('beta and unknown runtime schemas cannot enter the development-runtime parser or a validated descriptor capability', async () => {
  reject(() => validateDirectV2Pf10RuntimeMaterial(betaRuntime));
  for (const runtimeArtifact of [
    betaRuntime,
    { ...betaRuntime, schema: 'shieldkit-v2-direct-pf10-unknown-runtime-artifact-v1', eligibility: 'unknown-kind' },
  ]) {
    reject(() => validateV2UnsignedPf10RuntimeArtifactReferences({
      artifactEntries: {},
      instanceId: hash('instance'),
      profileId: hash('profile'),
      runtimeArtifact,
    }));
  }
  await assert.rejects(
    deriveV2Pf10RuntimeFromValidatedDescriptor(betaRuntime),
    /validated by loadV2InstanceDescriptor/iu,
  );
});

test('compiled-root consumers reject beta-root/profile paths before they can become qualification evidence', async () => {
  reject(() => resolveV2FinalReleaseRoot('beta-single-contributor-r3'));
  reject(() => assertV2FinalReleaseRoot(betaProfile));

  const finalInputs = {
    descriptorPath: absolute('beta-descriptor.json'),
    expectedCommit: git('expected-commit'),
    expectedTree: git('expected-tree'),
    finalManifestPath: absolute('beta-manifest.json'),
    profileCorePath: absolute('beta-profile.json'),
    releaseRootId: 'beta-single-contributor-r3',
  };
  await assert.rejects(verifyV2D01FinalCeremonyEvidence({ ...finalInputs, ceremonyDirectory: absolute('beta-ceremony') }), /no approved V2 Direct final release roots/iu);
  await assert.rejects(runV2Q01FinalArtifactReplay({ ...finalInputs, d01ResultPath: absolute('beta-result.json'), ceremonyDirectory: absolute('beta-ceremony'), outputDirectory: absolute('q01-output'), q01PreBundle: absolute('q01-pre') }), /no approved V2 Direct final release roots/iu);
  await assert.rejects(runV2B02FinalVm({ descriptorPath: finalInputs.descriptorPath, expectedCommit: finalInputs.expectedCommit, expectedTree: finalInputs.expectedTree, finalManifestPath: finalInputs.finalManifestPath, laneEvidenceDirectory: absolute('b02-lanes'), outputDirectory: absolute('b02-output'), profileCorePath: finalInputs.profileCorePath, releaseRootId: finalInputs.releaseRootId, transactionsPath: absolute('b02-transactions.json') }), /no approved V2 Direct final release roots/iu);
  await assert.rejects(verifyV2Q02FinalKeyCorpus({ corpusPath: absolute('beta-q02-corpus.json'), descriptorPath: finalInputs.descriptorPath, profileCorePath: finalInputs.profileCorePath, releaseRootId: finalInputs.releaseRootId }), /no approved V2 Direct final release roots/iu);
  await assert.rejects(verifyV2Q03FinalLockAttacks({ attackCorpusPath: absolute('beta-q03-corpus.json'), b02ResultPath: absolute('beta-b02.json'), descriptorPath: finalInputs.descriptorPath, expectedCommit: finalInputs.expectedCommit, expectedTree: finalInputs.expectedTree, finalManifestPath: finalInputs.finalManifestPath, laneEvidenceDirectory: absolute('q03-lanes'), outputDirectory: absolute('q03-output'), profileCorePath: finalInputs.profileCorePath, releaseRootId: finalInputs.releaseRootId }), /no approved V2 Direct final release roots/iu);
  await assert.rejects(verifyV2Q07FinalPerformance({ b02ResultPath: absolute('beta-b02.json'), descriptorPath: finalInputs.descriptorPath, evidenceDirectory: absolute('q07-evidence'), expectedCommit: finalInputs.expectedCommit, expectedTree: finalInputs.expectedTree, finalManifestPath: finalInputs.finalManifestPath, outputDirectory: absolute('q07-output'), profileCorePath: finalInputs.profileCorePath, q02CorpusPath: absolute('beta-q02-corpus.json'), releaseRootId: finalInputs.releaseRootId }), /no approved V2 Direct final release roots/iu);
  await assert.rejects(runV2Q08CleanMachineQualification({ commandPlanPath: absolute('q08-plan.json'), d02ClosurePath: absolute('q08-d02.json'), descriptorPath: finalInputs.descriptorPath, expectedCommit: finalInputs.expectedCommit, expectedTree: finalInputs.expectedTree, finalManifestPath: finalInputs.finalManifestPath, fundingCheckpointPath: absolute('q08-funding.json'), hostIdentityPath: absolute('q08-host.json'), hostRole: 'clean-host-a', outputDirectory: absolute('q08-output'), profileCorePath: finalInputs.profileCorePath, releaseRootId: finalInputs.releaseRootId, hostSigningKeyPath: absolute('q08-key.pem') }), /no approved V2 Direct final release roots/iu);
});
