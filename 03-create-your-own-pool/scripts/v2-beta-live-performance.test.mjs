import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { deriveV2ChipnetFundingWallet } from '../packages/kit/v2/funding-wallet.mjs';
import { runV2BetaLivePerformanceForTest } from './v2-beta-live-performance.mjs';

const H = (byte) => byte.repeat(64);
const address = deriveV2ChipnetFundingWallet({ privateKeyHex: '01'.padStart(64, '0') }).cashAddress;
const timings = Object.freeze({ treeAndPreparation: 1, fundingRead: 1, witnessAssembly: 1, witnessCalculation: 1, proofGeneration: 1, proofVerification: 1, proofTotal: 1, signingAndVm: 1, localVm: 1, stateRead: 1, admission: 1, commit: 1, total: 100 });
const rpcObservation = Object.freeze({ backend: 'layer1-bchn-chipnet', genesis: '000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b', methodCounts: Object.freeze({ getblockhash: 0, getrawtransaction: 1, gettxout: 1, scantxoutset: 0, sendrawtransaction: 1, testmempoolaccept: 1 }) });
const hash = (value) => createHash('sha256').update(value).digest('hex');
const cores = availableParallelism();
const vmMetrics = Object.freeze({
  arithmeticCost: '1', definedFunctions: '1', densityControlLength: '100',
  evaluatedInstructionCount: '1', hashDigestIterations: '1',
  maximumHashDigestIterations: '1000', maximumOperationCost: '1000',
  maximumSignatureCheckCount: '100', operationCost: '1',
  signatureCheckCount: '1', stackPushedBytes: '1',
});
function actionTelemetry(kind, inputCount) {
  const pre = { schema: 'shieldkit-v2-beta-incremental-store-telemetry-v1', databaseBytes: 4096, walBytes: 8192, noteCount: 10, nullifierCount: 2, liveCount: 8 };
  const delta = kind === 'deposit'
    ? { databaseBytes: 0, walBytes: 4096, noteCount: 1, nullifierCount: 0, liveCount: 1 }
    : { databaseBytes: 0, walBytes: 4096, noteCount: 0, nullifierCount: 1, liveCount: -1 };
  const post = { schema: pre.schema, databaseBytes: pre.databaseBytes + delta.databaseBytes, walBytes: pre.walBytes + delta.walBytes, noteCount: pre.noteCount + delta.noteCount, nullifierCount: pre.nullifierCount + delta.nullifierCount, liveCount: pre.liveCount + delta.liveCount };
  return {
    schema: 'shieldkit-v2-beta-product-action-telemetry-v1',
    proof: { userTicks: 10, systemTicks: 5, totalTicks: 15, observedThreads: cores, activeCpuThreads: cores, ompThreads: cores, peakRssKiB: 1024, proofGenerationMs: 1, cpuTicksPerWallMillisecond: 15, containment: { backend: 'linux-systemd-cgroup-v2', memoryMaxBytes: '4294967296', memorySwapMaxBytes: '0', memoryPeakBytes: '1024', oomDelta: 0, oomKillDelta: 0, terminatedSuccessfully: true } },
    vm: { schema: 'shieldkit-v2-local-vm-telemetry-v1', allInputsAccepted: true, inputs: Array.from({ length: inputCount }, (_, index) => ({ index, accepted: true, metrics: { ...vmMetrics } })) },
    store: { pre, post, delta },
  };
}
const warmRuntimeWork = () => ({ schema: 'shieldkit-v2-beta-runtime-work-observation-v1', counts: { 'linked-runtime-cache-load': 1, 'cold-runtime-build': 0, 'full-runtime-verification': 0, 'compiler-child-spawn': 0, 'instance-specialization': 0 }, events: [{ type: 'linked-runtime-cache-load' }] });

function directories() {
  const root = mkdtempSync(path.join(process.cwd(), '.shieldkit-live-performance-')); chmodSync(root, 0o700);
  const evidenceDirectory = path.join(root, 'evidence'); mkdirSync(evidenceDirectory, { mode: 0o700 });
  const poolDataHomes = Array.from({ length: 4 }, (_, index) => { const value = path.join(root, `pool-${index + 1}`); mkdirSync(value, { mode: 0o700 }); return value; });
  return { root, evidenceDirectory, poolDataHomes };
}
function memoryJournal(initial = null) {
  let record = initial; const updates = [];
  return { journal: { load: () => record, async start(value) { record = value; updates.push(value); return record; }, async update(value) { record = value; updates.push(value); return record; }, close() {} }, record: () => record, updates };
}
function action(tokens, { duplicateTxid = false, rebuild = false, slow = false, legacySynthetic = false } = {}) {
  const kind = tokens[1]; const operationId = tokens[tokens.indexOf('--operation-id') + 1]; const transactionId = duplicateTxid ? H('d') : hash(operationId);
  const telemetry = actionTelemetry(kind, 10); const runtimeWork = warmRuntimeWork();
  const nested = {
    schema: 'shieldkit-v2-beta-product-action-result-v1', status: 'accepted-zero-conf-beta-unqualified', kind: kind === 'deposit' ? 'deposit' : 'withdrawal', operationId, transactionId,
    claims: { broadcasted: true, confirmed: false, mined: false, productionQualified: false }, cache: { runtimeManifestSha256: H('1'), runtimeMaterialSha256: H('2') },
    proof: { verified: true, resultSha256: H('3'), nativeBackend: 'rapidsnark', nativeProverSha256: H('4'), ompThreads: cores, observedThreads: cores, activeCpuThreads: cores, peakRssKiB: 1024, userCpuTicks: 10, systemCpuTicks: 5, totalCpuTicks: 15, cpuTicksPerWallMillisecond: 15, containment: telemetry.proof.containment }, vm: { allInputsAccepted: true, inputCount: 10, acceptedInputCount: 10, evidenceHash: H('4') }, telemetry,
    transaction: { bytes: 100, feeSats: '100', feeRateSatsPerByte: '1', changeVout: 1, changeValueSats: '1000' }, readback: { rawTransactionSha256: H('5'), stateOutpoint: { txid: transactionId, vout: 0 }, stateCommitmentSha256: H('6'), stateCategoryWire: H('7') }, rpcObservation, timingsMs: { ...timings, total: slow ? 11_000 : timings.total },
  };
  if (rebuild) { runtimeWork.counts['instance-specialization'] = 1; runtimeWork.events.push({ type: 'instance-specialization' }); }
  if (legacySynthetic) { nested.rpc = nested.rpcObservation; delete nested.rpcObservation; nested.runtime = { rebuilt: false }; }
  return { schema: 'shieldkit-v2-beta-product-command-result-v1', command: kind, status: nested.status, operationId, transactionId, claims: nested.claims, action: nested, telemetry: nested.telemetry, runtimeWork, timingsMs: { sessionOpen: 1, action: slow ? 11_000 : 100, commandTotal: slow ? 11_001 : 200 } };
}
function fixture(options = {}) {
  const holder = memoryJournal(options.initial); const calls = [];
  return {
    holder, calls,
    deps: {
      now: (() => { let value = 0; return () => ++value; })(),
      async openJournal() { return holder.journal; },
      async validateInstalledPool({ dataHome }) { return { dataDirectory: `${dataHome}/shieldkit/v2-beta-product`, receiptSha256: H('a') }; },
      async runCommand(request) { calls.push(request.literal); return { code: 0, stdout: JSON.stringify({ ok: true, confirmed: false, mined: false, productionQualified: false, result: action(request.literal, options) }) }; },
      async writeEvidence(directory, evidence) { return `${directory}/performance.json`; },
    },
  };
}
function options(subject) { return { evidenceDirectory: subject.evidenceDirectory, poolDataHomes: subject.poolDataHomes, withdrawalAddress: address }; }

test('collects 20 warm deposits and 20 warm withdrawals over four pre-created pools', async () => {
  const subject = directories(); const mocked = fixture();
  try {
    const result = await runV2BetaLivePerformanceForTest(options(subject), mocked.deps);
    assert.equal(result.evidence.samples.deposits.length, 20); assert.equal(result.evidence.samples.withdrawals.length, 20);
    assert.equal(result.evidence.metrics.deposits.commandTotalMs.p95, 200);
    assert.equal(mocked.calls.filter((entry) => entry[1] === 'deposit').length, 20);
    assert.equal(mocked.calls.filter((entry) => entry[1] === 'withdraw').length, 20);
    assert.equal(new Set(result.evidence.samples.deposits.map((entry) => entry.operationId)).size, 20);
    assert.equal(new Set([...result.evidence.samples.deposits, ...result.evidence.samples.withdrawals].map((entry) => entry.transactionId)).size, 40);
    assert.equal(JSON.stringify(result.evidence).includes(subject.poolDataHomes[0]), false);
  } finally { rmSync(subject.root, { recursive: true, force: true }); }
});

test('rejects runtime rebuild indicators and duplicate transaction ids', async () => {
  for (const case_ of [{ rebuild: true }, { duplicateTxid: true }]) {
    const subject = directories(); const mocked = fixture(case_);
    try { await assert.rejects(() => runV2BetaLivePerformanceForTest(options(subject), mocked.deps), { code: 'LIVE_PERFORMANCE_RESULT_REJECTED' }); }
    finally { rmSync(subject.root, { recursive: true, force: true }); }
  }
});

test('rejects the former synthetic rpc/runtime wrapper shape', async () => {
  const subject = directories(); const mocked = fixture({ legacySynthetic: true });
  try { await assert.rejects(() => runV2BetaLivePerformanceForTest(options(subject), mocked.deps), { code: 'LIVE_PERFORMANCE_RESULT_REJECTED' }); }
  finally { rmSync(subject.root, { recursive: true, force: true }); }
});

test('fails the performance gates rather than relabeling slow samples', async () => {
  const subject = directories(); const mocked = fixture({ slow: true });
  try { await assert.rejects(() => runV2BetaLivePerformanceForTest(options(subject), mocked.deps), { code: 'LIVE_PERFORMANCE_THRESHOLD_REJECTED' }); }
  finally { rmSync(subject.root, { recursive: true, force: true }); }
});

test('resumes one pending deterministic action through its exact CLI idempotency key', async () => {
  const subject = directories(); const pending = Object.freeze({ schema: 'shieldkit-v2-beta-live-performance-journal-v1', started: true, installReceipts: Object.freeze([H('a'), H('a'), H('a'), H('a')]), actions: Object.freeze([{ state: 'pending', kind: 'deposit', poolOrdinal: 0, ordinal: 1, operationId: 'warm.01.deposit.01' }]) }); const mocked = fixture({ initial: pending });
  try {
    const result = await runV2BetaLivePerformanceForTest(options(subject), mocked.deps);
    assert.equal(mocked.calls[0].join(' '), `shieldkit deposit --data-home ${subject.poolDataHomes[0]} --operation-id warm.01.deposit.01 --json`);
    assert.equal(result.evidence.samples.deposits.filter((entry) => entry.operationId === 'warm.01.deposit.01').length, 1);
    assert.equal(new Set(result.evidence.samples.deposits.map((entry) => entry.operationId)).size, 20);
  } finally { rmSync(subject.root, { recursive: true, force: true }); }
});

test('rejects a pending journal entry that does not bind a planned idempotency key', async () => {
  const subject = directories(); const pending = Object.freeze({ schema: 'shieldkit-v2-beta-live-performance-journal-v1', started: true, installReceipts: Object.freeze([H('a'), H('a'), H('a'), H('a')]), actions: Object.freeze([{ state: 'pending', kind: 'withdraw', poolOrdinal: 0, ordinal: 1, operationId: 'warm.01.deposit.01' }]) }); const mocked = fixture({ initial: pending });
  try {
    await assert.rejects(() => runV2BetaLivePerformanceForTest(options(subject), mocked.deps), { code: 'LIVE_PERFORMANCE_JOURNAL_REJECTED' });
    assert.equal(mocked.calls.length, 0);
  } finally { rmSync(subject.root, { recursive: true, force: true }); }
});
