import assert from 'node:assert/strict';
import test from 'node:test';

import {
  V2_Q07_LOCAL_BLOCKED_ADAPTER_SCHEMA,
  V2Q07LocalBlockedEvidenceError,
  buildLocalBlockedQ07Evidence,
} from './v2-q07-local-blocked-evidence.mjs';
import {
  V2_Q07_BN254_FR_MODULUS,
  V2_Q07_DATASET_SCHEMA,
} from './v2-q07-dataset.mjs';
import { verifyQ07Evidence } from './v2-q07-evidence.mjs';

const digest = (byte = 'a') => byte.repeat(64);
const gitObject = (byte = 'b') => byte.repeat(40);

function pf10Input(index) {
  return {
    index,
    hardAccepted: true,
    semanticAccepted: true,
    unlockBytes: 9_000 + index,
    operationCost: 7_000_000,
    maximumOperationCost: 7_561_600,
    hashDigestIterations: 200,
    maximumHashDigestIterations: 4_000,
    signatureCheckCount: 0,
    maximumSignatureChecks: 200,
  };
}

function input() {
  const profileId = digest('1');
  const instanceId = digest('2');
  const runtimeMaterialSha256 = digest('3');
  return {
    schema: V2_Q07_LOCAL_BLOCKED_ADAPTER_SCHEMA,
    gitCommit: gitObject('4'),
    gitTree: gitObject('5'),
    sourceSetSha256: digest('6'),
    q04VerificationArtifactSha256: digest('7'),
    datasetVerificationArtifactSha256: digest('8'),
    pf10EvidenceArtifactSha256: digest('9'),
    referenceMachineArtifactSha256: digest('a'),
    pf10GitCommit: gitObject('b'),
    pf10GitTree: gitObject('c'),
    pf10SourceSetSha256: digest('d'),
    cgroupV2: true,
    q04Verification: {
      schema: 'shieldkit-v2-direct/q04-evidence-verification-result/v3',
      status: 'verified',
      gate: 'Q-04',
      q04GatePass: true,
      q04Verdict: 'pass-bounded-100000-and-depth4-shared-kernel',
      aggregateEntries: 100_000,
      discrepancies: 0,
      unexpectedAccepts: 0,
      singleHistory100kMeasured: false,
      largerHistoryClaim: false,
    },
    datasetVerification: {
      schema: V2_Q07_DATASET_SCHEMA,
      path: '/private/q07-single-history-keys.ndjson',
      mainCount: 100_000,
      count: 100_001,
      warmSampleOrdinal: 100_001,
      sha256: digest('e'),
      transcriptSha256: digest('f'),
      edgeEvidence: {
        zeroOrdinal: 1,
        zeroKey: '0'.repeat(64),
        frMinusOneOrdinal: 2,
        frMinusOneKey:
          (V2_Q07_BN254_FR_MODULUS - 1n).toString(16).padStart(64, '0'),
      },
      qualifyingShape: true,
      qualification: 'dataset-shape-only-not-q07-performance-qualified',
    },
    pf10Evidence: {
      schema: 'shieldkit-v2-direct-pf10-local-libauth-evidence-v2',
      eligibility: 'development-only',
      claims: {
        production: false,
        releaseQualified: false,
        finalKey: false,
        libauthBch2026: true,
      },
      identity: { profileId, instanceId, runtimeMaterialSha256 },
      pf10FusedQGenesisActions: {
        actionCount: 3,
        actions: ['deposit', 'transfer', 'withdrawal'].map((kind, index) => ({
          kind,
          inputCount: 13,
          transactionBytes: index === 2 ? 97_886 : 97_852,
          rows: Array.from({ length: 13 }, (_, row) => pf10Input(row)),
        })),
      },
    },
  };
}

test('local adapter publishes real local inputs as an honest blocked Q07 record', () => {
  const evidence = buildLocalBlockedQ07Evidence(input());
  const result = verifyQ07Evidence(evidence);
  assert.equal(result.status, 'blocked-external-prerequisites');
  assert.equal(result.q07Qualified, false);
  assert.equal(result.proofP95Ms, null);
  assert.equal(result.fullRecoveryMs, null);
  assert.equal(result.storeBytes, null);
  assert.equal(evidence.actionHistory.status, 'unavailable');
  assert.equal(evidence.finalPf10.actions[0].inputs.length, 13);
});

test('local adapter rejects relabeled Q04, dataset, and PF10 inputs', () => {
  let value = input();
  value.q04Verification.singleHistory100kMeasured = true;
  assert.throws(
    () => buildLocalBlockedQ07Evidence(value),
    V2Q07LocalBlockedEvidenceError,
  );

  value = input();
  value.datasetVerification.count = 100_000;
  assert.throws(
    () => buildLocalBlockedQ07Evidence(value),
    /full single-history key stream/u,
  );

  value = input();
  value.pf10Evidence.pf10FusedQGenesisActions.actions[1].rows[5]
    .semanticAccepted = false;
  assert.throws(
    () => buildLocalBlockedQ07Evidence(value),
    /not accepted/u,
  );
});

test('Q07 core validator rejects a development PF10 resource overflow', () => {
  const value = input();
  value.pf10Evidence.pf10FusedQGenesisActions.actions[0].rows[0]
    .operationCost = 7_561_601;
  assert.throws(
    () => buildLocalBlockedQ07Evidence(value),
    /operationCost exceeds maximumOperationCost/u,
  );
});
