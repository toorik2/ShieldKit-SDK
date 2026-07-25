// Summarize a fixed 20-run-per-action native-prover adapter result.
import { lstat, readFile, realpath, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import os from 'node:os';
import { canonicalJson, parseStrictJson } from '../../../packages/profile/load.mjs';

const kinds = ['deposit', 'transfer', 'withdrawal'];
const fail = (message) => { throw new NativeProverBenchmarkError(message); };
export class NativeProverBenchmarkError extends Error { constructor(message) { super(message); this.name = 'NativeProverBenchmarkError'; } }
const exactKeys = (value, label, keys) => { if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`); const actual = Object.keys(value).sort(), expected = [...keys].sort(); if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has unexpected keys`); };
const positive = (value, label) => { if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) fail(`${label} must be a finite non-negative number`); return value; };
const nearestRank95 = (samples) => [...samples].sort((a, b) => a - b)[Math.ceil(samples.length * 0.95) - 1];
const median = (samples) => { const sorted = [...samples].sort((a, b) => a - b); const middle = Math.floor(sorted.length / 2); return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2; };
const statistics = (samples) => ({ count: samples.length, min: Math.min(...samples), median: median(samples), nearestRankP95: nearestRank95(samples), max: Math.max(...samples) });

export function summarizeNativeProverBenchmark(result, host) {
  if (typeof host !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(host)) fail('host must be a short machine label');
  exactKeys(result, 'adapter result', ['actions', 'artifacts', 'nativeProver', 'profile', 'qualification', 'repetitions', 'schema', 'snarkjs']);
  if (result.schema !== 'shield.cash/native-prover-adapter-result/v1' || result.repetitions !== 20) fail('adapter result must be a 20-run native-prover-adapter result');
  if (!result.nativeProver || result.nativeProver.backend !== 'rapidsnark') fail('adapter result must identify rapidsnark');
  if (!Array.isArray(result.actions) || result.actions.length !== kinds.length) fail('adapter result must contain three actions');
  const seen = new Set(); const actions = [];
  for (const action of result.actions) {
    if (!action || !kinds.includes(action.kind) || seen.has(action.kind) || !Array.isArray(action.runs) || action.runs.length !== 20) fail('every action must have exactly 20 runs'); seen.add(action.kind);
    const provingMs = action.runs.map((run, index) => positive(run?.proving?.elapsedMs, `${action.kind} proving ${index}`));
    const rssKiB = action.runs.map((run, index) => positive(run?.proving?.memory?.peakRssKiB, `${action.kind} RSS ${index}`));
    const verificationMs = action.runs.map((run, index) => positive(run?.verification?.elapsedMs, `${action.kind} verification ${index}`));
    actions.push({ kind: action.kind, cold: { provingMs: provingMs[0], peakRssKiB: rssKiB[0], verificationMs: verificationMs[0] }, warm: { provingMs: statistics(provingMs.slice(1)), peakRssKiB: statistics(rssKiB.slice(1)), verificationMs: statistics(verificationMs.slice(1)) }, allRuns: { provingMs: statistics(provingMs), peakRssKiB: statistics(rssKiB), verificationMs: statistics(verificationMs) } });
  }
  const max = (field, metric) => Math.max(...actions.map((action) => action.allRuns[field][metric]));
  const budgets = { desktopProvingP95Ms: 30000, desktopPeakRssKiB: 4194304, desktopVerificationP95Ms: 2000 };
  const observed = { provingNearestRankP95Ms: max('provingMs', 'nearestRankP95'), peakRssKiB: max('peakRssKiB', 'max'), verificationNearestRankP95Ms: max('verificationMs', 'nearestRankP95') };
  return { schema: 'shield.cash/native-prover-benchmark/v1', qualification: 'one-host fixed-sample local feasibility evidence; not cross-hardware qualification', host: { label: host, architecture: os.arch(), cpuModel: os.cpus()[0]?.model ?? 'unavailable', logicalCpus: os.cpus().length, memoryBytes: os.totalmem(), kernel: os.release(), node: process.version }, profile: result.profile, nativeProver: result.nativeProver, snarkjs: result.snarkjs, runsPerAction: 20, actions, budgets, observed, verdict: observed.provingNearestRankP95Ms <= budgets.desktopProvingP95Ms && observed.peakRssKiB <= budgets.desktopPeakRssKiB && observed.verificationNearestRankP95Ms <= budgets.desktopVerificationP95Ms ? 'PASS' : 'FAIL' };
}

export async function writeNativeProverBenchmark({ input, output, host }) {
  if (typeof input !== 'string' || !isAbsolute(input) || typeof output !== 'string' || !isAbsolute(output)) fail('input and output must be absolute paths');
  const inputBytes = await readFile(input).catch(() => fail('input is unavailable')); let source; try { source = parseStrictJson(inputBytes); } catch (error) { fail(`input is invalid: ${error.message}`); }
  const parent = dirname(resolve(output)); const parentStat = await lstat(parent).catch(() => fail('output parent is unavailable')); if (!parentStat.isDirectory() || parentStat.isSymbolicLink() || await realpath(parent).catch(() => '') !== parent) fail('output parent must be a direct non-symlink directory'); if (await lstat(output).catch(() => undefined)) fail('output already exists');
  const summary = summarizeNativeProverBenchmark(source, host); await writeFile(output, `${canonicalJson(summary)}\n`, { flag: 'wx', mode: 0o600 }); return summary;
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const [flagIn, input, flagOut, output, flagHost, host] = process.argv.slice(2);
  if (flagIn !== '--input' || flagOut !== '--output' || flagHost !== '--host') { console.error('usage: benchmark-summary.mjs --input RESULT.json --output SUMMARY.json --host LABEL'); process.exitCode = 2; }
  else writeNativeProverBenchmark({ input, output, host }).then((summary) => console.log(canonicalJson({ verdict: summary.verdict, runsPerAction: summary.runsPerAction }))).catch((error) => { console.error(error.message); process.exitCode = 1; });
}
