import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import {
  V2BetaLiveEvidenceBundleError,
  createV2BetaLiveEvidenceBundleManifest,
  verifyV2BetaLiveEvidenceBundleManifest,
} from './v2-beta-live-evidence-bundle-verify.mjs';

const H = (byte) => byte.repeat(64);
const sha = (value) => createHash('sha256').update(value).digest('hex');
const cores = 20;
const METRICS = Object.freeze({ arithmeticCost: '1', definedFunctions: '1', densityControlLength: '1', evaluatedInstructionCount: '1', hashDigestIterations: '1', maximumHashDigestIterations: '1', maximumOperationCost: '1', maximumSignatureCheckCount: '1', operationCost: '1', signatureCheckCount: '1', stackPushedBytes: '1' });
const RPC = Object.freeze({ getblockhash: 0, getrawtransaction: 1, gettxout: 1, scantxoutset: 0, sendrawtransaction: 1, testmempoolaccept: 1 });
const POOL_RPC = Object.freeze({ ...RPC, getrawtransaction: 2, sendrawtransaction: 2, testmempoolaccept: 2 });
const WORK = () => ({ schema: 'shieldkit-v2-beta-runtime-work-observation-v1', counts: { 'linked-runtime-cache-load': 1, 'cold-runtime-build': 0, 'full-runtime-verification': 0, 'compiler-child-spawn': 0, 'instance-specialization': 0 }, events: [{ type: 'linked-runtime-cache-load' }] });
const FRESH_POOL_WORK = () => ({ schema: 'shieldkit-v2-beta-runtime-work-observation-v1', counts: { 'linked-runtime-cache-load': 1, 'cold-runtime-build': 0, 'full-runtime-verification': 0, 'compiler-child-spawn': 0, 'instance-specialization': 1 }, events: [{ type: 'instance-specialization' }, { type: 'linked-runtime-cache-load' }] });
const TIMINGS = () => ({ admission: 1, commit: 1, fundingRead: 1, localVm: 1, proofGeneration: 1, proofTotal: 1, proofVerification: 1, signingAndVm: 1, stateRead: 1, total: 10, treeAndPreparation: 1, witnessAssembly: 1, witnessCalculation: 1 });
const CLAIMS = Object.freeze({ broadcasted: true, confirmed: false, mined: false, productionQualified: false });
const facts = () => ({ repository: { cleanWorktree: true, head: 'a'.repeat(40), tree: 'b'.repeat(40), packageLockSha256: H('c'), releasePinSha256: H('d'), releasePinTracked: true }, host: { nodeVersion: 'v22.23.1', platform: 'linux', architecture: 'x64', availableCores: cores } });
const canonicalBytes = (value) => Buffer.from(`${canonicalizeJcs(value)}\n`, 'utf8');

function action(kind, ordinal, txByte, poolOrdinal = undefined) {
  const txid = String(txByte).padStart(2, '0').slice(-2).repeat(32); const pre = { schema: 'shieldkit-v2-beta-incremental-store-telemetry-v1', databaseBytes: 4096, walBytes: 100, noteCount: kind === 'deposit' ? ordinal : ordinal + 5, nullifierCount: kind === 'deposit' ? 0 : ordinal, liveCount: kind === 'deposit' ? ordinal : 5 };
  const delta = kind === 'deposit' ? { databaseBytes: 0, walBytes: 1, noteCount: 1, nullifierCount: 0, liveCount: 1 } : { databaseBytes: 0, walBytes: 1, noteCount: 0, nullifierCount: 1, liveCount: -1 };
  const post = Object.fromEntries(Object.entries(pre).map(([key, value]) => [key, Object.hasOwn(delta, key) ? value + delta[key] : value]));
  const value = { kind, ordinal, operationId: `${poolOrdinal === undefined ? 'semantic' : `warm.${poolOrdinal}`}.${kind}.${ordinal}`, transactionId: txid, commandTotalMs: 100, actionTotalMs: 10, bytes: 100, feeSats: '100', feeRateSatsPerByte: '1', claims: { ...CLAIMS }, cache: { runtimeManifestSha256: H('1'), runtimeMaterialSha256: H('2') }, runtimeWork: WORK(), proof: { backend: 'rapidsnark', verified: true, resultSha256: H('3'), nativeProverSha256: H('4'), ompThreads: cores, observedThreads: cores, activeCpuThreads: cores, peakRssKiB: 1024, proofGenerationMs: 1, userTicks: 10, systemTicks: 5, totalTicks: 15, cpuTicksPerWallMillisecond: 15, containment: { backend: 'linux-systemd-cgroup-v2', memoryMaxBytes: '4294967296', memorySwapMaxBytes: '0', memoryPeakBytes: '1024', oomDelta: 0, oomKillDelta: 0, terminatedSuccessfully: true } }, vm: { evidenceHash: H('5'), inputCount: 1, allInputsAccepted: true, inputs: [{ index: 0, accepted: true, metrics: { ...METRICS } }] }, store: { pre, post, delta }, readback: { rawTransactionSha256: H('6'), stateCategoryWire: H('7'), stateCommitmentSha256: H('8'), stateOutpoint: { txid, vout: 0 } }, rpcObservation: { backend: 'layer1-bchn-chipnet', genesis: '000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b', methodCounts: { ...RPC } }, timingsMs: TIMINGS() };
  if (poolOrdinal !== undefined) Object.assign(value, { poolOrdinal, state: 'accepted' });
  return value;
}

function semantic() {
  const source = H('9'); const genesis = H('a');
  return { schema: 'shieldkit-v2-beta-live-qualification-v2', scope: 'semantic-five-by-five-only-not-performance-qualification', claims: { confirmed: false, mined: false, productionQualified: false }, capacity: '100000', install: { receiptSha256: H('b'), releaseId: 'shieldkit-v2-beta-20260801-r1', releaseManifestSha256: H('c') }, poolCreate: { commandDurationMs: 100, sourceOutpointProvenanceSha256: H('d') }, pool: { instanceId: H('1'), sourceTransactionId: source, genesisTransactionId: genesis, zeroConfEvidenceSha256: H('2'), actionFundingOutputs: 10, actionFundingSetSha256: H('3'), transactions: { source: { transactionId: source, serializedBytes: 100, rawTransactionSha256: H('4') }, genesis: { transactionId: genesis, serializedBytes: 100, feeSats: '100', feeRateSatsPerByte: '1', bch2026StandardVmAccepted: true, inputMetrics: [] } }, acceptance: { accepted: true, status: 'accepted-zero-conf', evidence: { status: 'accepted-zero-conf-beta-unqualified', claims: { ...CLAIMS } } }, rpcObservation: { backend: 'layer1-bchn-chipnet', genesis: '000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b', methodCounts: { ...POOL_RPC } }, runtime: { runtimeManifestSha256: H('5'), runtimeMaterialSha256: H('6'), linkedDuringCommand: false, work: WORK() }, timingsMs: { actionStoreBootstrap: 1, admissionAndBroadcast: 1, artifactLoad: 1, atomicCommit: 1, commandTotal: 1, durableStage: 1, exactReadback: 1, funding: 1, genesis: 1, instanceSpecialization: 0, runtimeCacheInstall: 0, runtimeLoad: 1, templateLoad: 0, templateReceiptAttestation: 0 }, claims: { ...CLAIMS } }, deposits: [1, 2, 3, 4, 5].map((ordinal) => action('deposit', ordinal, String(ordinal))), withdrawals: [1, 2, 3, 4, 5].map((ordinal) => action('withdraw', ordinal, String(ordinal + 5))), timingMs: 100 };
}

function performance() {
  const deposits = Array.from({ length: 20 }, (_, index) => action('deposit', index + 1, (index + 100).toString(16), Math.floor(index / 5)));
  const withdrawals = Array.from({ length: 20 }, (_, index) => action('withdraw', index + 1, (index + 140).toString(16), Math.floor(index / 5)));
  const metrics = (entries) => ({ sampleCount: entries.length, commandTotalMs: { p50: 100, p95: 100 }, actionTotalMs: { p50: 10, p95: 10 } });
  return { schema: 'shieldkit-v2-beta-live-performance-v1', scope: 'warm-performance-only-explicitly-unqualified', claims: { confirmed: false, mined: false, productionQualified: false }, pools: Array.from({ length: 4 }, () => ({ receiptSha256: H('b') })), samples: { deposits, withdrawals }, metrics: { deposits: metrics(deposits), withdrawals: metrics(withdrawals) }, elapsedMs: 500 };
}

function poolCreatePerformance() {
  const pools = Array.from({ length: 20 }, (_, index) => {
    const ordinal = index + 1;
    return {
      ordinal,
      commandDurationMs: 300 + ordinal,
      sourceOutpointProvenanceSha256: sha(`pool-source-outpoint-${ordinal}`),
      sourceTransactionId: sha(`pool-source-${ordinal}`),
      genesisTransactionId: sha(`pool-genesis-${ordinal}`),
      instanceId: sha(`pool-instance-${ordinal}`),
      actionFundingSetSha256: sha(`pool-action-set-${ordinal}`),
      runtimeWork: FRESH_POOL_WORK(),
      claims: { ...CLAIMS },
    };
  });
  const distribution = (field) => ({
    p50: pools[Math.ceil(pools.length * 0.5) - 1][field],
    p95: pools[Math.ceil(pools.length * 0.95) - 1][field],
    max: pools.at(-1)[field],
  });
  return {
    schema: 'shieldkit-v2-beta-live-pool-create-performance-v1',
    scope: 'fresh-pool-create-performance-explicitly-unqualified',
    claims: { confirmed: false, mined: false, productionQualified: false },
    pools,
    metrics: {
      sampleCount: pools.length,
      commandDurationMs: distribution('commandDurationMs'),
    },
    elapsedMs: 20_000,
  };
}

const rejects = (code) => (error) => error instanceof V2BetaLiveEvidenceBundleError && error.code === code;

test('creates and independently verifies a canonical secret-free semantic/performance manifest', () => {
  const files = { semanticBytes: canonicalBytes(semantic()), performanceBytes: canonicalBytes(performance()), poolCreatePerformanceBytes: canonicalBytes(poolCreatePerformance()) };
  const manifest = createV2BetaLiveEvidenceBundleManifest(files, facts());
  assert.match(manifest.manifestSha256, /^[0-9a-f]{64}$/u);
  assert.deepEqual(verifyV2BetaLiveEvidenceBundleManifest(structuredClone(manifest), files, facts()), manifest);
  assert.equal(manifest.semantic.sha256, sha(files.semanticBytes));
});

test('rejects noncanonical bytes, secret/path fields, dirty attestation, and promotion', () => {
  const base = semantic(); const perf = performance(); const poolCreate = poolCreatePerformance();
  assert.throws(() => createV2BetaLiveEvidenceBundleManifest({ semanticBytes: Buffer.from(JSON.stringify(base)), performanceBytes: canonicalBytes(perf), poolCreatePerformanceBytes: canonicalBytes(poolCreate) }, facts()), rejects('BUNDLE_FILE_NONCANONICAL'));
  const pathBearing = semantic(); pathBearing.install.dataDirectory = '/private/data';
  assert.throws(() => createV2BetaLiveEvidenceBundleManifest({ semanticBytes: canonicalBytes(pathBearing), performanceBytes: canonicalBytes(perf), poolCreatePerformanceBytes: canonicalBytes(poolCreate) }, facts()), rejects('BUNDLE_SECRET_OR_PATH'));
  const promoted = semantic(); promoted.claims.confirmed = true;
  assert.throws(() => createV2BetaLiveEvidenceBundleManifest({ semanticBytes: canonicalBytes(promoted), performanceBytes: canonicalBytes(perf), poolCreatePerformanceBytes: canonicalBytes(poolCreate) }, facts()), rejects('BUNDLE_PROMOTION_REJECTED'));
  const dirty = facts(); dirty.repository.cleanWorktree = false;
  assert.throws(() => createV2BetaLiveEvidenceBundleManifest({ semanticBytes: canonicalBytes(base), performanceBytes: canonicalBytes(perf), poolCreatePerformanceBytes: canonicalBytes(poolCreate) }, dirty), rejects('BUNDLE_DIRTY_TREE'));
});

test('rejects duplicate actions, telemetry/runtime tampering, bad percentiles, and stale manifest facts', () => {
  const base = semantic(); const perf = performance(); const poolCreate = poolCreatePerformance();
  perf.samples.deposits[1].transactionId = perf.samples.deposits[0].transactionId; perf.samples.deposits[1].readback.stateOutpoint.txid = perf.samples.deposits[0].transactionId;
  assert.throws(() => createV2BetaLiveEvidenceBundleManifest({ semanticBytes: canonicalBytes(base), performanceBytes: canonicalBytes(perf), poolCreatePerformanceBytes: canonicalBytes(poolCreate) }, facts()), rejects('BUNDLE_PERFORMANCE_INVALID'));
  const badRuntime = semantic(); badRuntime.deposits[0].runtimeWork.counts['cold-runtime-build'] = 1; badRuntime.deposits[0].runtimeWork.events.push({ type: 'cold-runtime-build' });
  assert.throws(() => createV2BetaLiveEvidenceBundleManifest({ semanticBytes: canonicalBytes(badRuntime), performanceBytes: canonicalBytes(performance()), poolCreatePerformanceBytes: canonicalBytes(poolCreatePerformance()) }, facts()), rejects('BUNDLE_RUNTIME_WORK_INVALID'));
  const badMetrics = performance(); badMetrics.metrics.deposits.actionTotalMs.p95 = 10_001;
  assert.throws(() => createV2BetaLiveEvidenceBundleManifest({ semanticBytes: canonicalBytes(semantic()), performanceBytes: canonicalBytes(badMetrics), poolCreatePerformanceBytes: canonicalBytes(poolCreatePerformance()) }, facts()), rejects('BUNDLE_PERFORMANCE_INVALID'));
  const badPoolCreate = poolCreatePerformance(); badPoolCreate.pools[0].runtimeWork.events.reverse();
  assert.throws(() => createV2BetaLiveEvidenceBundleManifest({ semanticBytes: canonicalBytes(semantic()), performanceBytes: canonicalBytes(performance()), poolCreatePerformanceBytes: canonicalBytes(badPoolCreate) }, facts()), rejects('BUNDLE_POOL_CREATE_RUNTIME_WORK_INVALID'));
  const legacyPoolCreate = poolCreatePerformance(); delete legacyPoolCreate.pools[0].commandDurationMs; delete legacyPoolCreate.pools[0].sourceOutpointProvenanceSha256; Object.assign(legacyPoolCreate.pools[0], { initialCliMs: 1, fundingAdmissionMs: 1, fundedCreateMs: 1, totalWorkflowMs: 3, fundingTxid: H('f') });
  assert.throws(() => createV2BetaLiveEvidenceBundleManifest({ semanticBytes: canonicalBytes(semantic()), performanceBytes: canonicalBytes(performance()), poolCreatePerformanceBytes: canonicalBytes(legacyPoolCreate) }, facts()), rejects('BUNDLE_UNKNOWN_FIELD'));
  const files = { semanticBytes: canonicalBytes(semantic()), performanceBytes: canonicalBytes(performance()), poolCreatePerformanceBytes: canonicalBytes(poolCreatePerformance()) }; const manifest = createV2BetaLiveEvidenceBundleManifest(files, facts()); const changedFacts = facts(); changedFacts.repository.tree = 'e'.repeat(40);
  assert.throws(() => verifyV2BetaLiveEvidenceBundleManifest(manifest, files, changedFacts), rejects('BUNDLE_MANIFEST_MISMATCH'));
});

test('manifest CLI requires the independent fresh pool-create evidence input', () => {
  const result = spawnSync(process.execPath, [
    fileURLToPath(new URL('./v2-beta-live-evidence-bundle-verify.mjs', import.meta.url)),
    '--create', '--semantic', 'semantic.json', '--performance', 'performance.json',
  ], { encoding: 'utf8' });
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}${result.stderr}`, /--pool-create-performance/u);
});
