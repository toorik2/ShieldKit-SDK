/*
 * Canonical local Q-07 publication adapter. It converts real local Q-04,
 * dataset, reference-machine, and development PF10 artifacts into an honest
 * blocked Q-07 record. It never converts development evidence into a final
 * profile, action-history corpus, or performance measurement.
 */
import {
  V2_Q07_ACTION_KIND_COUNTS,
  V2_Q07_EVIDENCE_SCHEMA,
  V2_Q07_HISTORY_ACTIONS,
  buildQ07Evidence,
} from './v2-q07-evidence.mjs';
import {
  V2_Q07_BN254_FR_MODULUS,
  V2_Q07_DATASET_SCHEMA,
  V2_Q07_MAIN_HISTORY_COUNT,
  V2_Q07_WARM_SAMPLE_ORDINAL,
} from './v2-q07-dataset.mjs';

export const V2_Q07_LOCAL_BLOCKED_ADAPTER_SCHEMA =
  'shieldkit-v2-direct/q07-local-blocked-adapter-input/v1';

const HASH = /^[0-9a-f]{64}$/u;
const GIT_OBJECT = /^[0-9a-f]{40}$/u;
const ACTIONS = Object.freeze(['deposit', 'transfer', 'withdrawal']);

export class V2Q07LocalBlockedEvidenceError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2Q07LocalBlockedEvidenceError';
  }
}

const fail = (message) => {
  throw new V2Q07LocalBlockedEvidenceError(message);
};
const exactKeys = (value, keys, label) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    fail(`${label} has missing or unknown fields`);
  }
  return value;
};
const hash = (value, label) => {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail(`${label} must be lowercase SHA-256`);
  }
  return value;
};
const gitObject = (value, label) => {
  if (typeof value !== 'string' || !GIT_OBJECT.test(value)) {
    fail(`${label} must be lowercase 40-hex Git object`);
  }
  return value;
};
const unavailableReference = (reason) => Object.freeze({
  status: 'unavailable',
  sha256: null,
  reason,
});
const unavailableMeasurement = (reason) => Object.freeze({
  status: 'unavailable',
  evidence: null,
  reason,
});

function validateQ04(value) {
  if (
    value?.schema !== 'shieldkit-v2-direct/q04-evidence-verification-result/v3'
    || value.status !== 'verified'
    || value.gate !== 'Q-04'
    || value.q04GatePass !== true
    || value.q04Verdict !==
      'pass-bounded-100000-and-depth4-shared-kernel'
    || value.aggregateEntries !== 100_000
    || value.discrepancies !== 0
    || value.unexpectedAccepts !== 0
    || value.singleHistory100kMeasured !== false
    || value.largerHistoryClaim !== false
  ) {
    fail('Q04 verification is not the exact green bounded v3 result');
  }
  return value;
}

function validateDataset(value) {
  if (
    value?.schema !== V2_Q07_DATASET_SCHEMA
    || value.mainCount !== V2_Q07_MAIN_HISTORY_COUNT
    || value.count !== V2_Q07_WARM_SAMPLE_ORDINAL
    || value.warmSampleOrdinal !== V2_Q07_WARM_SAMPLE_ORDINAL
    || value.qualifyingShape !== true
    || value.qualification !==
      'dataset-shape-only-not-q07-performance-qualified'
    || value.edgeEvidence?.zeroOrdinal !== 1
    || value.edgeEvidence?.zeroKey !== '0'.repeat(64)
    || value.edgeEvidence?.frMinusOneOrdinal !== 2
    || value.edgeEvidence?.frMinusOneKey !==
      (V2_Q07_BN254_FR_MODULUS - 1n).toString(16).padStart(64, '0')
  ) {
    fail('Q07 dataset verification does not bind the full single-history key stream');
  }
  hash(value.sha256, 'datasetVerification.sha256');
  hash(value.transcriptSha256, 'datasetVerification.transcriptSha256');
  return value;
}

function pf10Action(value, index) {
  const kind = ACTIONS[index];
  if (
    value?.kind !== kind
    || value.inputCount !== 13
    || !Number.isSafeInteger(value.transactionBytes)
    || !Array.isArray(value.rows)
    || value.rows.length !== 13
  ) {
    fail(`development PF10 ${kind} action shape is invalid`);
  }
  return Object.freeze({
    kind,
    transactionBytes: value.transactionBytes,
    inputCount: value.inputCount,
    inputs: Object.freeze(value.rows.map((row, inputIndex) => {
      if (
        row?.index !== inputIndex
        || row.hardAccepted !== true
        || row.semanticAccepted !== true
      ) {
        fail(`development PF10 ${kind} input ${inputIndex} is not accepted`);
      }
      return Object.freeze({
        inputIndex,
        accepted: true,
        unlockBytes: row.unlockBytes,
        operationCost: row.operationCost,
        maximumOperationCost: row.maximumOperationCost,
        hashDigestIterations: row.hashDigestIterations,
        maximumHashDigestIterations: row.maximumHashDigestIterations,
        signatureCheckCount: row.signatureCheckCount,
        maximumSignatureChecks: row.maximumSignatureChecks,
      });
    })),
  });
}

function validatePf10(value) {
  if (
    value?.schema !== 'shieldkit-v2-direct-pf10-local-libauth-evidence-v2'
    || value.eligibility !== 'development-only'
    || value.claims?.production !== false
    || value.claims?.releaseQualified !== false
    || value.claims?.finalKey !== false
    || value.claims?.libauthBch2026 !== true
    || value.pf10FusedQGenesisActions?.actionCount !== 3
    || !Array.isArray(value.pf10FusedQGenesisActions.actions)
    || value.pf10FusedQGenesisActions.actions.length !== 3
  ) {
    fail('PF10 input must be canonical development-only local Libauth evidence');
  }
  const identity = value.identity;
  for (const key of ['profileId', 'instanceId', 'runtimeMaterialSha256']) {
    hash(identity?.[key], `PF10 identity.${key}`);
  }
  return Object.freeze({
    identity: Object.freeze({
      profileId: identity.profileId,
      instanceId: identity.instanceId,
      runtimeMaterialSha256: identity.runtimeMaterialSha256,
    }),
    actions: Object.freeze(
      value.pf10FusedQGenesisActions.actions.map(pf10Action),
    ),
  });
}

/**
 * Build an internally validated, development-only Q-07 blocked record.
 * Artifact byte hashes are supplied by the enclosing bundle publisher and are
 * independently re-read by the bundle verifier.
 */
export function buildLocalBlockedQ07Evidence(value) {
  exactKeys(value, [
    'cgroupV2',
    'datasetVerification',
    'datasetVerificationArtifactSha256',
    'gitCommit',
    'gitTree',
    'pf10Evidence',
    'pf10EvidenceArtifactSha256',
    'pf10GitCommit',
    'pf10GitTree',
    'pf10SourceSetSha256',
    'q04Verification',
    'q04VerificationArtifactSha256',
    'referenceMachineArtifactSha256',
    'schema',
    'sourceSetSha256',
  ], 'local blocked Q07 adapter input');
  if (value.schema !== V2_Q07_LOCAL_BLOCKED_ADAPTER_SCHEMA) {
    fail('local blocked Q07 adapter schema is unsupported');
  }
  if (value.cgroupV2 !== true && value.cgroupV2 !== false) {
    fail('cgroupV2 must be boolean');
  }
  gitObject(value.gitCommit, 'gitCommit');
  gitObject(value.gitTree, 'gitTree');
  gitObject(value.pf10GitCommit, 'pf10GitCommit');
  gitObject(value.pf10GitTree, 'pf10GitTree');
  for (const key of [
    'sourceSetSha256',
    'pf10SourceSetSha256',
    'q04VerificationArtifactSha256',
    'datasetVerificationArtifactSha256',
    'pf10EvidenceArtifactSha256',
    'referenceMachineArtifactSha256',
  ]) hash(value[key], key);

  const q04 = validateQ04(value.q04Verification);
  const dataset = validateDataset(value.datasetVerification);
  const pf10 = validatePf10(value.pf10Evidence);
  const noFinalCorpus =
    'No final-profile 100000-action raw transaction corpus and independent verifier artifact exist.';
  const noFinalPerformance =
    'Final-key full-V2 published-machine measurement is unavailable; indexed-nullifier microbenchmarks are auxiliary only.';
  const noFinalStore =
    'No authenticated full-V2 store produced from a verified final 100000-action corpus exists.';

  return buildQ07Evidence({
    schema: V2_Q07_EVIDENCE_SCHEMA,
    verdict: {
      status: 'blocked-external-prerequisites',
      reasons: [
        'Final profile, ceremony, and proving key are unavailable.',
        noFinalCorpus,
        noFinalPerformance,
        'Final PF10 still lacks BCHN, LeanBCH, maintainer-benchmark, and final-key evidence.',
      ],
    },
    subject: {
      eligibility: 'development-only',
      profileId: pf10.identity.profileId,
      instanceId: pf10.identity.instanceId,
      runtimeMaterialSha256: pf10.identity.runtimeMaterialSha256,
      sourceSetSha256: value.sourceSetSha256,
      gitCommit: value.gitCommit,
      gitTree: value.gitTree,
    },
    prerequisites: {
      q04Verification: {
        status: 'verified',
        sha256: value.q04VerificationArtifactSha256,
        reason: null,
      },
      finalProfile: unavailableReference(
        'Only a development profile exists; no audited final profile is frozen.',
      ),
      finalCeremony: unavailableReference(
        'The required five-contributor ceremony, beacon, and two-host transcript verification are incomplete.',
      ),
      finalKey: unavailableReference(
        'No final ceremony-derived proving and verification key exists.',
      ),
      finalPf10: unavailableReference(
        'PF10 evidence is development-only and is not final-key or externally qualified.',
      ),
    },
    referenceMachine: {
      attestation: 'local-unattested',
      cgroupV2: value.cgroupV2,
      manifestSha256: value.referenceMachineArtifactSha256,
    },
    dataset: {
      historyCount: 1,
      historyActions: V2_Q07_HISTORY_ACTIONS,
      mainCount: dataset.mainCount,
      keyCount: dataset.count,
      warmSampleOrdinal: dataset.warmSampleOrdinal,
      zeroEdgeOrdinal: dataset.edgeEvidence.zeroOrdinal,
      frMinusOneEdgeOrdinal: dataset.edgeEvidence.frMinusOneOrdinal,
      rawKeyStreamSha256: dataset.sha256,
      transcriptSha256: dataset.transcriptSha256,
      verificationArtifactSha256:
        value.datasetVerificationArtifactSha256,
      q04VerificationArtifactSha256:
        value.q04VerificationArtifactSha256,
      q04VerificationStatus: q04.status,
      q04GatePass: q04.q04GatePass,
    },
    actionHistory: {
      status: 'unavailable',
      evidence: null,
      reason: noFinalCorpus,
    },
    proofGeneration: unavailableMeasurement(noFinalPerformance),
    phases: {
      bottomUpSnapshotAuthentication:
        unavailableMeasurement(noFinalPerformance),
      rawFallback: unavailableMeasurement(noFinalPerformance),
      suffixReplay: unavailableMeasurement(noFinalPerformance),
      warmUpdate: unavailableMeasurement(noFinalPerformance),
      coldIo: unavailableMeasurement(noFinalPerformance),
    },
    store: unavailableMeasurement(noFinalStore),
    finalPf10: {
      eligibility: 'development-only',
      profileId: pf10.identity.profileId,
      instanceId: pf10.identity.instanceId,
      runtimeMaterialSha256: pf10.identity.runtimeMaterialSha256,
      sourceSetSha256: value.pf10SourceSetSha256,
      gitCommit: value.pf10GitCommit,
      gitTree: value.pf10GitTree,
      evidenceArtifactSha256: value.pf10EvidenceArtifactSha256,
      actions: pf10.actions,
    },
  });
}

// Exported for tests and downstream workload generators: the final corpus is
// deliberately frozen rather than selected after benchmark results are known.
export { V2_Q07_ACTION_KIND_COUNTS };
