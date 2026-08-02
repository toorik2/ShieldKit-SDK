import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { deriveV2ChipnetFundingWallet } from '../packages/kit/v2/funding-wallet.mjs';
import { runV2BetaLivePerformanceForTest } from './v2-beta-live-performance.mjs';

const H = (byte) => byte.repeat(64);
const RELEASE_ID = 'shieldkit-v2-beta-test-r1';
const RELEASE_MANIFEST_SHA256 = H('e');
const INSTALLATION_RECEIPTS = Object.freeze(['a', 'b', 'c', 'd'].map(H));
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
function poolIdentities({ duplicatePoolIdentity = false, duplicateReceipt = false } = {}) {
  return Object.freeze(Array.from({ length: 4 }, (_, poolOrdinal) => {
    const identityOrdinal = duplicatePoolIdentity && poolOrdinal === 3 ? 0 : poolOrdinal;
    return Object.freeze({
      poolOrdinal,
      installationReceiptSha256: INSTALLATION_RECEIPTS[duplicateReceipt && poolOrdinal === 3 ? 0 : poolOrdinal],
      instanceId: H(String(identityOrdinal + 1)),
      genesisTransactionId: H(String(identityOrdinal + 5)),
    });
  }));
}
function performanceJournal(actions, fixtureOptions = {}) {
  return Object.freeze({
    schema: 'shieldkit-v2-beta-live-performance-journal-v3',
    started: true,
    release: Object.freeze({
      releaseId: RELEASE_ID,
      releaseManifestSha256: RELEASE_MANIFEST_SHA256,
    }),
    pools: poolIdentities(fixtureOptions),
    actions: Object.freeze(actions),
  });
}
function action(tokens, { duplicateTxid = false, rebuild = false, slow = false, legacySynthetic = false, wrongPoolReadback = false } = {}) {
  const kind = tokens[1]; const operationId = tokens[tokens.indexOf('--operation-id') + 1]; const transactionId = duplicateTxid ? H('d') : hash(operationId);
  const poolOrdinal = Number.parseInt(operationId.split('.')[1], 10) - 1;
  const telemetry = actionTelemetry(kind, 10); const runtimeWork = warmRuntimeWork();
  const nested = {
    schema: 'shieldkit-v2-beta-product-action-result-v1', status: 'accepted-zero-conf-beta-unqualified', kind: kind === 'deposit' ? 'deposit' : 'withdrawal', operationId, transactionId,
    claims: { broadcasted: true, confirmed: false, mined: false, productionQualified: false }, cache: { runtimeManifestSha256: H('1'), runtimeMaterialSha256: H('2') },
    proof: { verified: true, resultSha256: H('3'), nativeBackend: 'rapidsnark', nativeProverSha256: H('4'), ompThreads: cores, observedThreads: cores, activeCpuThreads: cores, peakRssKiB: 1024, userCpuTicks: 10, systemCpuTicks: 5, totalCpuTicks: 15, cpuTicksPerWallMillisecond: 15, containment: telemetry.proof.containment }, vm: { allInputsAccepted: true, inputCount: 10, acceptedInputCount: 10, evidenceHash: H('4') }, telemetry,
    transaction: { bytes: 100, feeSats: '100', feeRateSatsPerByte: '1', changeVout: 1, changeValueSats: '1000' }, readback: { rawTransactionSha256: H('5'), stateOutpoint: { txid: transactionId, vout: 0 }, stateCommitmentSha256: H('6'), stateCategoryWire: H(String(wrongPoolReadback ? (poolOrdinal + 1) % 4 + 1 : poolOrdinal + 1)) }, rpcObservation, timingsMs: { ...timings, total: slow ? 11_000 : timings.total },
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
      async validateInstalledPool({ dataHome }) {
        const poolOrdinal = Number.parseInt(path.basename(dataHome).slice('pool-'.length), 10) - 1;
        const identityOrdinal = options.duplicatePoolIdentity && poolOrdinal === 3 ? 0 : poolOrdinal;
        return {
          dataDirectory: `${dataHome}/shieldkit/v2-beta-product`,
          installationReceiptSha256: INSTALLATION_RECEIPTS[options.duplicateReceipt && poolOrdinal === 3 ? 0 : poolOrdinal],
          releaseId: options.releaseMismatch === 'id' && poolOrdinal === 3
            ? 'shieldkit-v2-beta-test-r2'
            : RELEASE_ID,
          releaseManifestSha256: options.releaseMismatch === 'manifest' && poolOrdinal === 3
            ? H('f')
            : RELEASE_MANIFEST_SHA256,
          instanceId: H(String(identityOrdinal + 1)),
          genesisTransactionId: H(String(identityOrdinal + 5)),
        };
      },
      async runCommand(request) { calls.push(request.literal); return { code: 0, stdout: JSON.stringify({ ok: true, confirmed: false, mined: false, productionQualified: false, result: action(request.literal, options) }) }; },
      async writeEvidence(directory, evidence) { return `${directory}/performance.json`; },
    },
  };
}
function options(subject) { return { evidenceDirectory: subject.evidenceDirectory, poolDataHomes: subject.poolDataHomes, withdrawalAddress: address }; }

test('accepts distinct local installation receipts for one stable release and four committed pools', async () => {
  const subject = directories(); const mocked = fixture();
  try {
    const result = await runV2BetaLivePerformanceForTest(options(subject), mocked.deps);
    assert.equal(result.evidence.schema, 'shieldkit-v2-beta-live-performance-v2');
    assert.deepEqual(result.evidence.release, {
      releaseId: RELEASE_ID,
      releaseManifestSha256: RELEASE_MANIFEST_SHA256,
    });
    assert.deepEqual(result.evidence.pools, poolIdentities());
    assert.equal(new Set(result.evidence.pools.map((entry) => entry.installationReceiptSha256)).size, 4);
    assert.equal(result.evidence.samples.deposits.length, 20); assert.equal(result.evidence.samples.withdrawals.length, 20);
    assert.equal(result.evidence.metrics.deposits.commandTotalMs.p95, 200);
    assert.equal(mocked.calls.filter((entry) => entry[1] === 'deposit').length, 20);
    assert.equal(mocked.calls.filter((entry) => entry[1] === 'withdraw').length, 20);
    assert.equal(new Set(result.evidence.samples.deposits.map((entry) => entry.operationId)).size, 20);
    assert.equal(new Set([...result.evidence.samples.deposits, ...result.evidence.samples.withdrawals].map((entry) => entry.transactionId)).size, 40);
    const sample = result.evidence.samples.deposits[0];
    assert.deepEqual(Object.keys(sample).sort(), ['actionTotalMs', 'bytes', 'cache', 'claims', 'commandTotalMs', 'feeRateSatsPerByte', 'feeSats', 'kind', 'operationId', 'ordinal', 'poolOrdinal', 'proof', 'readback', 'rpcObservation', 'runtimeWork', 'state', 'store', 'timingsMs', 'transactionId', 'vm'].sort());
    assert.equal(sample.kind, 'deposit'); assert.equal(sample.ordinal, 1); assert.equal(sample.poolOrdinal, 0); assert.equal(sample.state, 'accepted');
    assert.equal(sample.readback.stateCategoryWire, Buffer.from(result.evidence.pools[sample.poolOrdinal].instanceId, 'hex').reverse().toString('hex'));
    assert.equal(JSON.stringify(result.evidence).includes(subject.poolDataHomes[0]), false);
  } finally { rmSync(subject.root, { recursive: true, force: true }); }
});

test('rejects release id or release manifest mismatches before collecting samples', async () => {
  for (const releaseMismatch of ['id', 'manifest']) {
    const subject = directories(); const mocked = fixture({ releaseMismatch });
    try {
      await assert.rejects(
        () => runV2BetaLivePerformanceForTest(options(subject), mocked.deps),
        { code: 'LIVE_PERFORMANCE_RELEASE_REJECTED' },
      );
      assert.equal(mocked.calls.length, 0);
    } finally { rmSync(subject.root, { recursive: true, force: true }); }
  }
});

test('rejects duplicate committed pool identity before collecting samples', async () => {
  const subject = directories(); const mocked = fixture({ duplicatePoolIdentity: true });
  try {
    await assert.rejects(
      () => runV2BetaLivePerformanceForTest(options(subject), mocked.deps),
      { code: 'LIVE_PERFORMANCE_POOL_REJECTED' },
    );
    assert.equal(mocked.calls.length, 0);
  } finally { rmSync(subject.root, { recursive: true, force: true }); }
});

test('rejects duplicate installation receipts before collecting samples', async () => {
  const subject = directories(); const mocked = fixture({ duplicateReceipt: true });
  try {
    await assert.rejects(
      () => runV2BetaLivePerformanceForTest(options(subject), mocked.deps),
      { code: 'LIVE_PERFORMANCE_POOL_REJECTED' },
    );
    assert.equal(mocked.calls.length, 0);
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

test('rejects an action readback bound to another warm pool', async () => {
  const subject = directories();
  const mocked = fixture({ wrongPoolReadback: true });
  try { await assert.rejects(() => runV2BetaLivePerformanceForTest(options(subject), mocked.deps), { code: 'LIVE_PERFORMANCE_RESULT_REJECTED' }); }
  finally { rmSync(subject.root, { recursive: true, force: true }); }
});

test('fails the performance gates rather than relabeling slow samples', async () => {
  const subject = directories(); const mocked = fixture({ slow: true });
  try { await assert.rejects(() => runV2BetaLivePerformanceForTest(options(subject), mocked.deps), { code: 'LIVE_PERFORMANCE_THRESHOLD_REJECTED' }); }
  finally { rmSync(subject.root, { recursive: true, force: true }); }
});

test('requires reconciliation for a pre-existing pending action and excludes it from timing samples', async () => {
  const subject = directories();
  const pending = performanceJournal([Object.freeze({
    state: 'pending',
    kind: 'deposit',
    poolOrdinal: 0,
    ordinal: 1,
    operationId: 'warm.01.deposit.01',
  })]);
  const mocked = fixture({ initial: pending });
  try {
    await assert.rejects(
      () => runV2BetaLivePerformanceForTest(options(subject), mocked.deps),
      { code: 'LIVE_PERFORMANCE_RECONCILIATION_REQUIRED' },
    );
    assert.equal(mocked.calls.length, 0);
    assert.equal(mocked.holder.updates.length, 0);
    assert.equal(mocked.holder.record().actions[0].state, 'pending');
  } finally { rmSync(subject.root, { recursive: true, force: true }); }
});

test('revalidates persisted accepted action results before timing them', async () => {
  const subject = directories();
  const operationId = 'warm.01.deposit.01';
  const accepted = performanceJournal([Object.freeze({
    state: 'accepted', kind: 'deposit', poolOrdinal: 0, ordinal: 1, operationId,
    result: action(['shieldkit', 'deposit', '--operation-id', operationId]),
  })]);
  const mocked = fixture({ initial: accepted });
  try {
    const result = await runV2BetaLivePerformanceForTest(options(subject), mocked.deps);
    assert.equal(mocked.calls.filter((entry) => entry[1] === 'deposit').length, 19);
    assert.equal(result.evidence.samples.deposits.length, 20);
    assert.equal(result.evidence.samples.deposits.some((entry) => entry.operationId === operationId), true);
  } finally { rmSync(subject.root, { recursive: true, force: true }); }
});

test('rejects malformed or forged persisted accepted action results before counting them', async () => {
  const operationId = 'warm.01.deposit.01';
  const cases = [
    {},
    (() => {
      const result = action(['shieldkit', 'deposit', '--operation-id', operationId]);
      result.action.readback.stateOutpoint.txid = H('f');
      return result;
    })(),
  ];
  for (const result of cases) {
    const subject = directories();
    const accepted = performanceJournal([Object.freeze({
      state: 'accepted', kind: 'deposit', poolOrdinal: 0, ordinal: 1, operationId, result,
    })]);
    const mocked = fixture({ initial: accepted });
    try {
      await assert.rejects(
        () => runV2BetaLivePerformanceForTest(options(subject), mocked.deps),
        { code: 'LIVE_PERFORMANCE_RESULT_REJECTED' },
      );
      assert.equal(mocked.calls.length, 0);
    } finally { rmSync(subject.root, { recursive: true, force: true }); }
  }
});

test('rejects a pending journal entry that does not bind a planned idempotency key', async () => {
  const subject = directories(); const pending = performanceJournal([{ state: 'pending', kind: 'withdraw', poolOrdinal: 0, ordinal: 1, operationId: 'warm.01.deposit.01' }]); const mocked = fixture({ initial: pending });
  try {
    await assert.rejects(() => runV2BetaLivePerformanceForTest(options(subject), mocked.deps), { code: 'LIVE_PERFORMANCE_JOURNAL_REJECTED' });
    assert.equal(mocked.calls.length, 0);
  } finally { rmSync(subject.root, { recursive: true, force: true }); }
});
