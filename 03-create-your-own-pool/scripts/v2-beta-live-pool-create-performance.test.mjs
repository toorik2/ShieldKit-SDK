import assert from 'node:assert/strict';
import test from 'node:test';

import { runV2BetaLivePoolCreatePerformanceForTest } from './v2-beta-live-pool-create-performance.mjs';

const H = (value) => value.toString(16).padStart(64, '0');
function journal(initial = null) { let value = initial; return { load: () => value, async start(next) { value = next; return value; }, async update(next) { value = next; return value; }, close() {}, value: () => value }; }
function fixture({ initial = null, slow = false } = {}) {
  const state = journal(initial); const calls = { commands: [], inspect: [] }; let tick = 0;
  const pool = (ordinal) => Object.freeze({ instanceId: H(400 + ordinal), sourceTransactionId: H(200 + ordinal), genesisTransactionId: H(300 + ordinal), actionFundingSetSha256: H(500 + ordinal), runtime: Object.freeze({ work: Object.freeze({ schema: 'shieldkit-v2-beta-runtime-work-observation-v1', counts: Object.freeze({ 'linked-runtime-cache-load': 1, 'cold-runtime-build': 0, 'full-runtime-verification': 0, 'compiler-child-spawn': 0, 'instance-specialization': 1 }), events: Object.freeze([Object.freeze({ type: 'instance-specialization' }), Object.freeze({ type: 'linked-runtime-cache-load' })]) }) }), claims: Object.freeze({ confirmed: false, mined: false, productionQualified: false }) });
  return { state, calls, deps: {
    inspectPool: async (_result, outpoint, _rpc, options) => { calls.inspect.push({ outpoint, options }); return pool(outpoint.vout + 1); },
    now: () => { tick += slow ? 6000 : 1; return tick; },
    openJournal: async () => state,
    rpc: { async getrawtransaction() { return 'unused'; } },
    runCommand: async (request) => { calls.commands.push(request.literal); return { code: 0, stdout: JSON.stringify({ ok: true, confirmed: false, mined: false, productionQualified: false, result: { accepted: true } }) }; },
    validateInstall: async ({ dataHome }) => ({ dataDirectory: `${dataHome}/shieldkit`, receiptSha256: H(1) }),
    writeEvidence: async (_directory, evidence) => { calls.evidence = evidence; return '/private/evidence/result.json'; },
  } };
}
function options() { return { evidenceDirectory: '/private/evidence', poolDataHomes: Array.from({ length: 20 }, (_, index) => `/private/pool-${index + 1}`), fundingWallets: Array.from({ length: 20 }, (_, index) => `/private/wallet-${index + 1}.json`), fundingUtxos: Array.from({ length: 20 }, (_, index) => `${H(1000 + index)}:${index}`) }; }

test('measures twenty single-command fresh pool creates with distinct secret-free provenance hashes', async () => {
  const subject = fixture(); const result = await runV2BetaLivePoolCreatePerformanceForTest(options(), subject.deps);
  assert.equal(result.evidence.pools.length, 20); assert.equal(result.evidence.metrics.sampleCount, 20);
  assert.deepEqual(Object.keys(result.evidence.metrics).sort(), ['commandDurationMs', 'sampleCount']);
  assert.equal(subject.calls.commands.length, 20); assert.equal(subject.calls.inspect.length, 20); assert.ok(subject.calls.inspect.every((value) => value.options.requireFreshLink === true));
  for (const literal of subject.calls.commands) assert.deepEqual(literal.slice(1), ['pool', 'create', '--data-home', literal[4], '--funding-wallet', literal[6], '--funding-utxo', literal[8], '--json']);
  assert.equal(subject.calls.commands.some((literal) => literal.includes('--funding-txid')), false);
  assert.equal(JSON.stringify(result.evidence).includes('/private'), false);
  assert.equal(new Set(result.evidence.pools.map((sample) => sample.sourceOutpointProvenanceSha256)).size, 20);
});

test('fails rather than relabeling slow create-command samples', async () => {
  const subject = fixture({ slow: true }); await assert.rejects(() => runV2BetaLivePoolCreatePerformanceForTest(options(), subject.deps), { code: 'LIVE_POOL_PERFORMANCE_THRESHOLD_REJECTED' });
});

test('never replays a create command after an interrupted sample', async () => {
  const samples = Array.from({ length: 20 }, (_, index) => index === 0 ? Object.freeze({ ordinal: 1, state: 'command-started', sourceOutpointProvenanceSha256: H(1) }) : Object.freeze({ ordinal: index + 1, state: 'planned' }));
  const initial = Object.freeze({ schema: 'shieldkit-v2-beta-live-pool-create-performance-journal-v1', installReceipts: Object.freeze(Array.from({ length: 20 }, () => H(1))), samples: Object.freeze(samples) }); const subject = fixture({ initial });
  await assert.rejects(() => runV2BetaLivePoolCreatePerformanceForTest(options(), subject.deps), { code: 'LIVE_POOL_PERFORMANCE_RECONCILIATION_REQUIRED' }); assert.equal(subject.calls.commands.length, 0);
});
