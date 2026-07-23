import assert from 'node:assert/strict';
import test from 'node:test';
import { NativeProverBenchmarkError, summarizeNativeProverBenchmark } from './benchmark-summary.mjs';

const run = (value) => ({ proving: { elapsedMs: value, memory: { peakRssKiB: value } }, verification: { elapsedMs: value } });
const fixture = () => ({ schema: 'shield.cash/native-prover-adapter-result/v1', qualification: 'test', profile: {}, nativeProver: { backend: 'rapidsnark' }, snarkjs: {}, artifacts: {}, repetitions: 20, actions: ['deposit', 'transfer', 'withdrawal'].map((kind) => ({ kind, runs: Array.from({ length: 20 }, (_, index) => run(index + 1)) })) });
test('uses empirical nearest-rank p95 and separates cold from warm samples', () => { const summary = summarizeNativeProverBenchmark(fixture(), 'linux-test'); assert.equal(summary.actions[0].cold.provingMs, 1); assert.equal(summary.actions[0].warm.provingMs.nearestRankP95, 20); assert.equal(summary.actions[0].allRuns.provingMs.nearestRankP95, 19); assert.equal(summary.verdict, 'PASS'); });
test('rejects non-fixed sample counts and unknown backends', () => { const badRuns = fixture(); badRuns.actions[0].runs.pop(); assert.throws(() => summarizeNativeProverBenchmark(badRuns, 'linux-test'), NativeProverBenchmarkError); const badBackend = fixture(); badBackend.nativeProver.backend = 'snarkjs'; assert.throws(() => summarizeNativeProverBenchmark(badBackend, 'linux-test'), /rapidsnark/); });
