import assert from 'node:assert/strict';
import test from 'node:test';

import {
  V2_Q07_ACTION_KIND_COUNTS,
  V2_Q07_EVIDENCE_SCHEMA,
  V2_Q07_FIXED_DEPTH_COUNTER_KEYS,
  V2_Q07_HISTORY_ACTIONS,
  V2Q07EvidenceError,
  buildQ07Evidence,
  nearestRankP95,
  verifyQ07Evidence,
} from './v2-q07-evidence.mjs';

const digest = (character = 'a') => character.repeat(64);
const gitObject = (character = 'b') => character.repeat(40);
const counts = () => Object.fromEntries(V2_Q07_FIXED_DEPTH_COUNTER_KEYS.map((key) => [key, 0]));
const rss = (bytes = 1024) => ({ bytes, provenance: { kind: 'cgroup-v2', source: 'memory.peak', path: '/sys/fs/cgroup/q07/sample' } });
const endpoint = (count) => ({ count, stateCommitmentSha256: digest(), logicalDigestSha256: digest(), stateBytesLength: 128 });
const state = (startCount, endCount) => ({ start: endpoint(startCount), end: endpoint(endCount) });
const sample = (wallMs, startCount, endCount, rssValue = rss()) => ({
  artifactSha256: digest(), wallMs, rss: rssValue, fixedDepthOperationCounts: counts(), state: state(startCount, endCount),
});
const sampleSet = (start, startCount, endCount, rssValue = rss()) => {
  const samples = Array.from({ length: 32 }, (_, index) => sample(start + index, startCount, endCount, rssValue));
  return { samples, p95Ms: nearestRankP95(samples.map((entry) => entry.wallMs)) };
};
const reference = () => ({ status: 'verified', sha256: digest(), reason: null });
const unavailableReference = () => ({ status: 'unavailable', sha256: null, reason: 'final external qualification unavailable' });
const measured = (evidence) => ({ status: 'measured', reason: null, evidence });
const unavailable = () => ({ status: 'unavailable', reason: 'measurement cannot honestly be performed before final external prerequisites', evidence: null });
const actionAnchor = (actionSequence) => ({ actionSequence, stateCommitmentSha256: digest(), txid: digest(), vout: 0, height: 0, blockHash: digest() });
const verifiedActionHistory = () => ({
  status: 'verified', reason: null,
  evidence: {
    artifactSha256: digest(), verificationArtifactSha256: digest(), descriptorSha256: digest(), actionCount: 100000, rawTransactionBytes: 1,
    profileId: digest(), instanceId: digest(), runtimeMaterialSha256: digest(),
    genesisAnchor: actionAnchor(0), terminalAnchor: actionAnchor(100000),
    actionKindCounts: { ...V2_Q07_ACTION_KIND_COUNTS },
  },
});
const unavailableActionHistory = () => ({ status: 'unavailable', reason: 'the full V2 corpus is unavailable before external finalization', evidence: null });
const finalInputs = () => Array.from({ length: 13 }, (_, inputIndex) => ({
  inputIndex, accepted: true, unlockBytes: 10000,
  operationCost: 100, maximumOperationCost: 100,
  hashDigestIterations: 10, maximumHashDigestIterations: 10,
  signatureCheckCount: 1, maximumSignatureChecks: 1,
}));

function measuredRecords() {
  return {
    proofGeneration: measured(sampleSet(100, 100000, 100000)),
    store: measured({
      kind: 'full-v2-authenticated-store', authenticated: true, bytes: 1024, artifactSha256: digest(), terminalState: endpoint(100000),
    }),
    phases: {
      bottomUpSnapshotAuthentication: measured({ kind: 'bottom-up-snapshot-authentication', historyActions: 100000, sample: sample(400, 0, 100000) }),
      rawFallback: measured({ kind: 'raw-fallback', historyActions: 100000, sample: sample(500, 0, 100000) }),
      suffixReplay: measured({ kind: 'suffix-replay', historyActions: 1000, sample: sample(50, 99000, 100000) }),
      warmUpdate: measured({ kind: 'warm-fixed-depth-update', baseline1k: sampleSet(100, 1000, 1001), at100k: sampleSet(105, 100000, 100001), ratio: 135 / 130 }),
      coldIo: measured({ kind: 'cold-sqlite-io', historyActions: 100000, samples: sampleSet(20, 100000, 100000) }),
    },
  };
}

function evidence({ qualified = true } = {}) {
  const records = qualified ? measuredRecords() : { proofGeneration: unavailable(), store: unavailable(), phases: {
    bottomUpSnapshotAuthentication: unavailable(), rawFallback: unavailable(), suffixReplay: unavailable(), warmUpdate: unavailable(), coldIo: unavailable(),
  } };
  return {
    schema: V2_Q07_EVIDENCE_SCHEMA,
    verdict: { status: qualified ? 'qualified' : 'blocked-external-prerequisites', reasons: qualified ? [] : ['final ceremony unavailable'] },
    subject: {
      eligibility: qualified ? 'final' : 'development-only', profileId: digest(), instanceId: digest(), runtimeMaterialSha256: digest(), sourceSetSha256: digest(), gitCommit: gitObject(), gitTree: gitObject(),
    },
    actionHistory: qualified ? verifiedActionHistory() : unavailableActionHistory(),
    prerequisites: {
      q04Verification: reference(), finalProfile: qualified ? reference() : unavailableReference(), finalCeremony: qualified ? reference() : unavailableReference(), finalKey: qualified ? reference() : unavailableReference(), finalPf10: qualified ? reference() : unavailableReference(),
    },
    referenceMachine: { attestation: qualified ? 'published-reference-machine' : 'local-unattested', cgroupV2: qualified, manifestSha256: digest() },
    dataset: {
      historyCount: 1, historyActions: V2_Q07_HISTORY_ACTIONS, mainCount: V2_Q07_HISTORY_ACTIONS, keyCount: V2_Q07_HISTORY_ACTIONS + 1, warmSampleOrdinal: V2_Q07_HISTORY_ACTIONS + 1,
      zeroEdgeOrdinal: 1, frMinusOneEdgeOrdinal: 2,
      rawKeyStreamSha256: digest(), transcriptSha256: digest(), verificationArtifactSha256: digest(), q04VerificationArtifactSha256: digest(), q04VerificationStatus: 'verified', q04GatePass: true,
    },
    ...records,
    finalPf10: {
      eligibility: qualified ? 'final' : 'development-only', profileId: digest(), instanceId: digest(), runtimeMaterialSha256: digest(), sourceSetSha256: digest(), gitCommit: gitObject(), gitTree: gitObject(), evidenceArtifactSha256: digest(),
      actions: ['deposit', 'transfer', 'withdrawal'].map((kind) => ({ kind, transactionBytes: 100000, inputCount: 13, inputs: finalInputs() })),
    },
  };
}

function blockedMeasuredEvidence() {
  const value = evidence({ qualified: false });
  Object.assign(value, measuredRecords());
  value.actionHistory = verifiedActionHistory();
  return value;
}

function rejects(value, pattern) {
  assert.throws(() => buildQ07Evidence(value), (error) => error instanceof V2Q07EvidenceError && pattern.test(error.message));
}

test('Q07 pure evidence validation cannot self-authorize a qualifying result', () => {
  rejects(evidence(), /authoritative artifact-bundle verification/u);
  assert.throws(
    () => verifyQ07Evidence(evidence()),
    (error) => error instanceof V2Q07EvidenceError && /authoritative artifact-bundle verification/u.test(error.message),
  );
});

test('Q07 accepts blocked records with honestly unavailable performance phases and null metrics', () => {
  const result = verifyQ07Evidence(evidence({ qualified: false }));
  assert.equal(result.q07Qualified, false);
  assert.equal(result.status, 'blocked-external-prerequisites');
  assert.equal(result.proofP95Ms, null);
  assert.equal(result.warmBaselineP95Ms, null);
  assert.equal(result.fullRecoveryMs, null);
  assert.equal(result.storeBytes, null);
});

test('Q07 rejects fake unavailable/measured shapes and a qualified missing phase', () => {
  let value = evidence({ qualified: false });
  value.proofGeneration.evidence = sampleSet(100, 100000, 100000);
  rejects(value, /unavailable record is invalid/u);

  value = evidence({ qualified: false });
  value.phases.rawFallback = { status: 'measured', reason: null, evidence: null };
  rejects(value, /measured record is invalid/u);

  value = evidence();
  value.phases.coldIo = unavailable();
  rejects(value, /must be measured for qualified evidence/u);

  value = evidence();
  value.store = unavailable();
  rejects(value, /store must be measured for qualified evidence/u);

  value = evidence({ qualified: false });
  value.store.evidence = { bytes: 1024 };
  rejects(value, /store unavailable record is invalid/u);
});

test('Q07 rejects missing samples, p95 and threshold drift, and warm-ratio drift', () => {
  let value = evidence();
  value.proofGeneration.evidence.samples.pop();
  rejects(value, /exactly 32/u);

  value = evidence();
  value.proofGeneration.evidence.p95Ms += 0.001;
  rejects(value, /nearest-rank p95/u);

  value = blockedMeasuredEvidence();
  for (const item of value.proofGeneration.evidence.samples) item.wallMs = 60000;
  value.proofGeneration.evidence.p95Ms = 60000;
  assert.doesNotThrow(() => buildQ07Evidence(value));
  value.proofGeneration.evidence.samples[30].wallMs = 60000.001;
  value.proofGeneration.evidence.samples[31].wallMs = 60000.001;
  value.proofGeneration.evidence.p95Ms = 60000.001;
  rejects(value, /exceeds 60000ms/u);

  value = evidence();
  value.phases.warmUpdate.evidence.at100k = sampleSet(114, 100000, 100001);
  value.phases.warmUpdate.evidence.ratio = 144 / 130;
  rejects(value, /ratio exceeds 1.10/u);
});

test('Q07 rejects bad cgroup RSS in a blocked measured phase and relabeled phases', () => {
  let value = evidence({ qualified: false });
  value.actionHistory = verifiedActionHistory();
  value.proofGeneration = measured(sampleSet(100, 100000, 100000, null));
  rejects(value, /cgroup-v2 memory\.peak/u);

  value = evidence();
  value.phases.rawFallback.evidence.kind = 'cold-sqlite-io';
  rejects(value, /wrong phase identity/u);
});

test('Q07 rejects hash/state tampering, key-file truth drift, and non-green Q04 evidence', () => {
  let value = evidence();
  value.subject.gitCommit = 'g'.repeat(40);
  rejects(value, /40-hex Git object/u);

  value = evidence();
  value.proofGeneration.evidence.samples[0].artifactSha256 = 'x';
  rejects(value, /artifactSha256/u);

  value = evidence();
  value.phases.suffixReplay.evidence.sample.state.start.count = 0;
  rejects(value, /does not bind the phase state/u);

  value = evidence();
  value.phases.suffixReplay.evidence.sample.state.start.rootSha256 = digest();
  rejects(value, /missing or unknown fields/u);

  value = evidence();
  value.dataset.keyCount = 100000;
  rejects(value, /100001-key file truth/u);

  value = evidence();
  value.dataset.frMinusOneEdgeOrdinal = 3;
  rejects(value, /100001-key file truth/u);

  value = evidence();
  value.dataset.q04VerificationStatus = 'unavailable';
  rejects(value, /Q04 verifier evidence must be verified/u);

  value = evidence();
  value.dataset.q04GatePass = false;
  rejects(value, /Q04 gate must pass/u);

  value = evidence({ qualified: false });
  value.prerequisites.q04Verification = unavailableReference();
  rejects(value, /Q04 verifier reference must be verified/u);
});

test('Q07 requires a verified full-V2 action corpus for qualified or locally measured evidence', () => {
  let value = evidence();
  value.actionHistory = unavailableActionHistory();
  rejects(value, /actionHistory must be verified for qualified evidence/u);

  value = evidence({ qualified: false });
  value.proofGeneration = measured(sampleSet(100, 100000, 100000));
  rejects(value, /requires a verified actionHistory corpus/u);
});

test('Q07 rejects action-history count, canonical-anchor, and subject-binding tampering', () => {
  let value = evidence();
  value.actionHistory.evidence.actionKindCounts.withdrawal -= 1;
  rejects(value, /frozen Q07 workload/u);

  value = evidence();
  value.actionHistory.evidence.terminalAnchor.actionSequence = 99999;
  rejects(value, /canonical action boundary/u);

  value = evidence();
  value.actionHistory.evidence.profileId = digest('c');
  rejects(value, /profileId differs from subject/u);
});

test('Q07 rejects PF10 hard limits and contradictory blocked-versus-qualified verdicts', () => {
  let value = evidence();
  value.finalPf10.evidenceArtifactSha256 = 'x';
  rejects(value, /evidenceArtifactSha256/u);

  value = evidence();
  value.finalPf10.actions[0].transactionBytes = 100001;
  rejects(value, /transaction exceeds/u);

  value = evidence();
  value.finalPf10.actions[0].inputs[0].unlockBytes = 10001;
  rejects(value, /unlock exceeds/u);

  value = evidence();
  value.finalPf10.actions[0].inputs[1].inputIndex = 0;
  rejects(value, /canonical order/u);

  value = evidence();
  value.finalPf10.actions[0].inputs[0].maximumOperationCost = 0;
  rejects(value, /maximumOperationCost is invalid/u);

  value = evidence();
  delete value.finalPf10.actions[0].inputs[0].maximumSignatureChecks;
  rejects(value, /missing or unknown fields/u);

  value = evidence();
  value.finalPf10.actions[0].inputs[0].accepted = false;
  rejects(value, /accepted must be true/u);

  value = evidence();
  value.finalPf10.actions[0].inputs[0].signatureCheckCount = 2;
  rejects(value, /exceeds maximumSignatureChecks/u);

  value = evidence();
  value.store.evidence.terminalState.stateBytesLength = 127;
  rejects(value, /128 canonical state bytes/u);

  value = evidence();
  value.store.evidence.kind = 'partial-store';
  rejects(value, /full V2 store/u);

  value = evidence({ qualified: false });
  value.finalPf10.sourceSetSha256 = digest('c');
  value.finalPf10.gitCommit = gitObject('d');
  value.finalPf10.gitTree = gitObject('e');
  assert.doesNotThrow(() => buildQ07Evidence(value));

  value = evidence();
  value.finalPf10.sourceSetSha256 = digest('c');
  rejects(value, /sourceSetSha256 differs from subject/u);

  value = evidence({ qualified: false });
  value.subject.eligibility = 'final';
  value.finalPf10.eligibility = 'final';
  for (const key of Object.keys(value.prerequisites)) value.prerequisites[key] = reference();
  rejects(value, /must use a qualified verdict/u);
});
