import assert from 'node:assert/strict';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
} from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import {
  runV2BetaLivePoolCreatePerformanceForTest,
  writeV2BetaLivePoolCreatePerformanceEvidenceForTest,
} from './v2-beta-live-pool-create-performance.mjs';

const H = (value) => value.toString(16).padStart(64, '0');
const RELEASE_ID = 'shieldkit-v2-beta-test-release';
const RELEASE_MANIFEST_SHA256 = H(9000);
const receipt = (index) => H(10_000 + index);
function journal(initial = null) { let value = initial; return { load: () => value, async start(next) { value = next; return value; }, async update(next) { value = next; return value; }, close() {}, value: () => value }; }
function fixture({ initial = null, inspectDelayMs = 0, releaseManifestMismatchAt = undefined, releaseMismatchAt = undefined, slow = false } = {}) {
  const state = journal(initial); const calls = { commands: [], inspect: [] }; let tick = 0;
  const pool = (ordinal) => Object.freeze({ instanceId: H(400 + ordinal), sourceTransactionId: H(200 + ordinal), genesisTransactionId: H(300 + ordinal), actionFundingSetSha256: H(500 + ordinal), runtime: Object.freeze({ work: Object.freeze({ schema: 'shieldkit-v2-beta-runtime-work-observation-v1', counts: Object.freeze({ 'linked-runtime-cache-load': 1, 'cold-runtime-build': 0, 'full-runtime-verification': 0, 'compiler-child-spawn': 0, 'instance-specialization': 1 }), events: Object.freeze([Object.freeze({ type: 'instance-specialization' }), Object.freeze({ type: 'linked-runtime-cache-load' })]) }) }), claims: Object.freeze({ confirmed: false, mined: false, productionQualified: false }) });
  return { state, calls, deps: {
    inspectPool: async (_result, outpoint, _rpc, options) => { calls.inspect.push({ outpoint, options }); tick += inspectDelayMs; return pool(outpoint.vout + 1); },
    now: () => tick,
    openJournal: async () => state,
    rpc: { async getrawtransaction() { return 'unused'; } },
    runCommand: async (request) => { calls.commands.push(request.literal); tick += slow ? 6001 : 10; return { code: 0, stdout: JSON.stringify({ ok: true, confirmed: false, mined: false, productionQualified: false, result: { accepted: true } }) }; },
    validateInstall: async ({ dataHome }) => {
      const index = Number(dataHome.match(/pool-([0-9]+)$/u)?.[1]);
      return { dataDirectory: `${dataHome}/shieldkit`, receiptSha256: receipt(index), releaseId: index === releaseMismatchAt ? `${RELEASE_ID}-other` : RELEASE_ID, releaseManifestSha256: index === releaseManifestMismatchAt ? H(9001) : RELEASE_MANIFEST_SHA256 };
    },
    writeEvidence: async (_directory, evidence) => { calls.evidence = evidence; return '/private/evidence/result.json'; },
  } };
}
function options() { return { evidenceDirectory: '/private/evidence', poolDataHomes: Array.from({ length: 20 }, (_, index) => `/private/pool-${index + 1}`), fundingWallets: Array.from({ length: 20 }, (_, index) => `/private/wallet-${index + 1}.json`), fundingUtxos: Array.from({ length: 20 }, (_, index) => `${H(1000 + index)}:${index}`) }; }

test('measures twenty distinct installations of one stable release with secret-free provenance hashes', async () => {
  const subject = fixture(); const result = await runV2BetaLivePoolCreatePerformanceForTest(options(), subject.deps);
  assert.equal(result.evidence.pools.length, 20); assert.equal(result.evidence.metrics.sampleCount, 20);
  assert.equal(result.evidence.schema, 'shieldkit-v2-beta-live-pool-create-performance-v3');
  assert.deepEqual(result.evidence.release, { releaseId: RELEASE_ID, releaseManifestSha256: RELEASE_MANIFEST_SHA256 });
  assert.equal(Object.hasOwn(result.evidence, 'receiptSha256'), false);
  assert.deepEqual(Object.keys(result.evidence.metrics).sort(), ['commandDurationMs', 'sampleCount']);
  assert.equal(subject.calls.commands.length, 20); assert.equal(subject.calls.inspect.length, 20); assert.ok(subject.calls.inspect.every((value) => value.options.requireFreshLink === true));
  for (const literal of subject.calls.commands) assert.deepEqual(literal.slice(1), ['pool', 'create', '--data-home', literal[4], '--funding-wallet', literal[6], '--funding-utxo', literal[8], '--json']);
  assert.equal(subject.calls.commands.some((literal) => literal.includes('--funding-txid')), false);
  assert.equal(JSON.stringify(result.evidence).includes('/private'), false);
  assert.equal(new Set(result.evidence.pools.map((sample) => sample.installationReceiptSha256)).size, 20);
  assert.deepEqual(result.evidence.pools.map((sample) => sample.installationReceiptSha256), Array.from({ length: 20 }, (_, index) => receipt(index + 1)));
  assert.deepEqual(subject.state.value().installReceipts, Array.from({ length: 20 }, (_, index) => receipt(index + 1)));
  assert.equal(new Set(result.evidence.pools.map((sample) => sample.sourceOutpointProvenanceSha256)).size, 20);
});

test('rejects one mismatched stable release before invoking any pool-create command', async () => {
  for (const fixtureOptions of [{ releaseMismatchAt: 20 }, { releaseManifestMismatchAt: 20 }]) {
    const subject = fixture(fixtureOptions);
    await assert.rejects(
      () => runV2BetaLivePoolCreatePerformanceForTest(options(), subject.deps),
      { code: 'LIVE_POOL_PERFORMANCE_INSTALL_REJECTED' },
    );
    assert.equal(subject.calls.commands.length, 0);
    assert.equal(subject.calls.inspect.length, 0);
  }
});

test('excludes independent inspector delay from literal CLI command duration', async () => {
  const subject = fixture({ inspectDelayMs: 20_000 });
  const result = await runV2BetaLivePoolCreatePerformanceForTest(options(), subject.deps);
  assert.deepEqual(result.evidence.metrics.commandDurationMs, { p50: 10, p95: 10, max: 10 });
  assert.ok(result.evidence.elapsedMs >= 400_000);
  assert.ok(result.evidence.pools.every((sample) => sample.commandDurationMs === 10));
});

test('fails rather than relabeling slow create-command samples', async () => {
  const subject = fixture({ slow: true }); await assert.rejects(() => runV2BetaLivePoolCreatePerformanceForTest(options(), subject.deps), { code: 'LIVE_POOL_PERFORMANCE_THRESHOLD_REJECTED' });
});

test('never replays a create command after an interrupted sample', async () => {
  const samples = Array.from({ length: 20 }, (_, index) => index === 0 ? Object.freeze({ ordinal: 1, state: 'command-started', sourceOutpointProvenanceSha256: H(1) }) : Object.freeze({ ordinal: index + 1, state: 'planned' }));
  const initial = Object.freeze({ schema: 'shieldkit-v2-beta-live-pool-create-performance-journal-v2', release: Object.freeze({ releaseId: RELEASE_ID, releaseManifestSha256: RELEASE_MANIFEST_SHA256 }), installReceipts: Object.freeze(Array.from({ length: 20 }, (_, index) => receipt(index + 1))), samples: Object.freeze(samples) }); const subject = fixture({ initial });
  await assert.rejects(() => runV2BetaLivePoolCreatePerformanceForTest(options(), subject.deps), { code: 'LIVE_POOL_PERFORMANCE_RECONCILIATION_REQUIRED' }); assert.equal(subject.calls.commands.length, 0); assert.equal(subject.calls.inspect.length, 0); assert.equal(subject.calls.evidence, undefined);
});

test('production evidence writer returns the exact private file it writes', async () => {
  const root = mkdtempSync(path.join(process.cwd(), '.shieldkit-pool-performance-writer-'));
  chmodSync(root, 0o700);
  const directory = path.join(root, 'evidence');
  mkdirSync(directory, { mode: 0o700 });
  const evidence = Object.freeze({
    schema: 'writer-return-path-regression',
    release: Object.freeze({
      releaseId: RELEASE_ID,
      releaseManifestSha256: RELEASE_MANIFEST_SHA256,
    }),
  });
  try {
    const filename = await writeV2BetaLivePoolCreatePerformanceEvidenceForTest(
      directory,
      evidence,
    );
    assert.equal(path.dirname(filename), directory);
    assert.match(
      path.basename(filename),
      /^v2-beta-live-pool-create-performance-[0-9TZ-]+\.json$/u,
    );
    assert.deepEqual(readdirSync(directory), [path.basename(filename)]);
    assert.equal(readFileSync(filename, 'utf8'), `${canonicalizeJcs(evidence)}\n`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
