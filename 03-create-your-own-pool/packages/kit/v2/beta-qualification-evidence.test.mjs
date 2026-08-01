import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import { transactionIdFromHex } from '../transaction-coordinator.mjs';
import {
  V2BetaProductQualificationEvidenceError,
  createV2BetaProductQualificationEvidence,
  verifyV2BetaProductQualificationEvidence,
} from './beta-qualification-evidence.mjs';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const H = (byte) => byte.repeat(64);
const METRICS = Object.freeze({ arithmeticCost: '1', definedFunctions: '1', densityControlLength: '1', evaluatedInstructionCount: '1', hashDigestIterations: '1', maximumHashDigestIterations: '1', maximumOperationCost: '1', maximumSignatureCheckCount: '1', operationCost: '1', signatureCheckCount: '1', stackPushedBytes: '1' });
const rawTransactionHex = '01000000000000000000';
const txid = transactionIdFromHex(rawTransactionHex);
const instanceId = '12'.repeat(32);

// This in-memory object is an explicitly TEST-ONLY fixture. It is never
// written, broadcast, or represented as a qualification artifact.
function testOnlyInput() {
  const stages = {}; let clock = 0;
  for (const name of ['stateRead', 'treePath', 'witness', 'proofGenerate', 'proofVerify', 'assemble', 'sign', 'vm', 'bchnAdmission', 'rawReadback', 'stateReadback', 'sqliteCommit']) {
    stages[name] = { startedAtMs: clock, finishedAtMs: clock + 1, durationMs: 1 }; clock += 1;
  }
  stages.total = { startedAtMs: 0, finishedAtMs: clock, durationMs: clock };
  const unlockBytesByInput = [{ index: 0, bytes: 0 }];
  return {
    schema: 'shieldkit-v2-beta-product-qualification-evidence-v1', status: 'accepted-zero-conf-beta-unqualified',
    claims: { broadcasted: true, confirmed: false, mined: false, productionQualified: false },
    run: { cleanWorktree: true, gitCommit: 'a'.repeat(40), gitTree: 'b'.repeat(40), lockfileSha256: H('c'), host: { architecture: 'x64', machineIdSha256: H('d'), platform: 'linux' }, toolPins: { bchn: '27.0.0', libauth: '3.0.0', node: '22.0.0' } },
    operation: { cache: 'warm', cacheReceiptSha256: H('e'), command: 'deposit', kind: 'deposit', ordinal: 1 },
    identity: { profileId: H('f'), instanceId, maximumLiveNotes: '100000' }, stages,
    proof: { system: 'groth16-bn254', verified: true, artifactHashes: { provingKey: H('1'), r1cs: H('2'), verificationKey: H('3'), wasm: H('4') }, workerThreads: 20, cpuUtilizationPercent: 99.5, peakRssBytes: 100, workspacePeakBytes: 200 },
    transaction: { rawTransactionHex, rawTransactionSha256: sha256(Buffer.from(rawTransactionHex, 'hex')), txid, bytes: rawTransactionHex.length / 2, feeSats: '10', feeRateSatsPerByte: '1', unlockBytesByInput },
    vm: { profile: 'BCH_2026_STANDARD', allInputsAccepted: true, inputs: [{ index: 0, role: 'funding', accepted: true, unlockingBytecodeBytes: 0, unlockingBytecodeSha256: H('5'), sourceOutputSha256: H('6'), metrics: { ...METRICS } }] },
    bchn: { backend: 'layer1-bchn-chipnet', genesis: H('7'), initialHeight: 1, methodCounts: { getblockcount: 1, getblockhash: 1, getrawtransaction: 1, gettxout: 1, sendrawtransaction: 1, testmempoolaccept: 1 }, admission: { testMempoolAccept: true, sendTransactionId: txid }, rawReadback: { exact: true, transactionId: txid, rawTransactionHex, rawTransactionSha256: sha256(Buffer.from(rawTransactionHex, 'hex')) }, stateReadback: { outpoint: { txid, vout: 0 }, category: Buffer.from(instanceId, 'hex').reverse().toString('hex'), capability: 'mutable', commitment: 'ab'.repeat(128), commitmentSha256: sha256(Buffer.from('ab'.repeat(128), 'hex')), tokenAmount: '0', valueSatoshis: '1000' } },
    store: { databaseBytes: 1, walBytes: 0, noteCount: 1, nullifierCount: 0 },
  };
}

const rejects = (code) => (error) => error instanceof V2BetaProductQualificationEvidenceError && error.code === code;

test('creates and independently verifies canonical secret-free beta evidence', () => {
  const evidence = createV2BetaProductQualificationEvidence(testOnlyInput());
  assert.match(evidence.evidenceSha256, /^[0-9a-f]{64}$/u);
  assert.deepEqual(verifyV2BetaProductQualificationEvidence(JSON.parse(JSON.stringify(evidence))), evidence);
});

test('rejects tampered canonical hash, transaction, readback, claims, and timing', () => {
  const evidence = createV2BetaProductQualificationEvidence(testOnlyInput());
  const mutate = (fn) => { const copy = JSON.parse(JSON.stringify(evidence)); fn(copy); return copy; };
  assert.throws(() => verifyV2BetaProductQualificationEvidence(mutate((x) => { x.evidenceSha256 = H('0'); })), rejects('EVIDENCE_HASH_MISMATCH'));
  assert.throws(() => verifyV2BetaProductQualificationEvidence(mutate((x) => { x.transaction.bytes += 1; })), rejects('EVIDENCE_TRANSACTION_MISMATCH'));
  assert.throws(() => verifyV2BetaProductQualificationEvidence(mutate((x) => { x.bchn.stateReadback.category = H('0'); })), rejects('EVIDENCE_BCHN_READBACK_INVALID'));
  assert.throws(() => verifyV2BetaProductQualificationEvidence(mutate((x) => { x.claims.confirmed = true; })), rejects('EVIDENCE_CLAIMS_INVALID'));
  assert.throws(() => verifyV2BetaProductQualificationEvidence(mutate((x) => { x.stages.sign.startedAtMs = -1; })), rejects('EVIDENCE_INVALID'));
});

test('rejects unknown and recursively secret-bearing fields before evidence creation', () => {
  const unknown = testOnlyInput(); unknown.extra = true;
  assert.throws(() => createV2BetaProductQualificationEvidence(unknown), rejects('EVIDENCE_UNKNOWN_FIELD'));
  const secret = testOnlyInput(); secret.proof.spendSecret = 'never-exported';
  assert.throws(() => createV2BetaProductQualificationEvidence(secret), rejects('EVIDENCE_SECRET_FIELD'));
});
