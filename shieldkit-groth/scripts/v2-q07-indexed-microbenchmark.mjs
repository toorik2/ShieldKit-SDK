#!/usr/bin/env node
/*
 * Auxiliary Q-07 measurement for the production depth-32 indexed-nullifier
 * store. This is intentionally not a V2 recovery/performance phase and must
 * never be supplied to v2-q07-evidence.mjs.
 */
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  constants,
  copyFileSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  writeSync,
} from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseStrictJson, canonicalJson } from '../packages/profile/load.mjs';
import { runLinuxCgroupV2ProofWorker } from '../packages/prove/v2/linux-cgroup-v2-worker.mjs';
import { verifyQ04EvidenceFile } from './v2-q04-evidence-verify.mjs';
import {
  V2_Q07_MAIN_HISTORY_COUNT,
  verifyQ07SingleHistoryDataset,
  writeQ07SingleHistoryDataset,
} from './v2-q07-dataset.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const workspaceRoot = resolve(here, '../..');
const workerPath = resolve(here, 'v2-q07-store-worker.mjs');
const datasetPath = resolve(here, 'v2-q07-dataset.mjs');
const HASH = /^[0-9a-f]{64}$/u;
const GIT = /^[0-9a-f]{40}$/u;
const BUNDLE_SCHEMA = 'shieldkit-v2-direct/q07-indexed-nullifier-microbenchmark/v1';
const RESULT_SCHEMA = 'shieldkit-v2-direct/q07-indexed-nullifier-microbenchmark-result/v1';
const BOUNDARY = 'indexed-nullifier-store-microbenchmark-only';
const WARM_SAMPLES = 32;

export class V2Q07IndexedMicrobenchmarkError extends Error {
  constructor(message) { super(message); this.name = 'V2Q07IndexedMicrobenchmarkError'; }
}
const fail = (message) => { throw new V2Q07IndexedMicrobenchmarkError(message); };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const exactKeys = (value, keys, label) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown properties`);
  return value;
};
const integer = (value, low, high, label) => {
  if (!Number.isSafeInteger(value) || value < low || value > high) fail(`${label} is outside its allowed range`);
  return value;
};
const absolute = (value, label) => {
  if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value) fail(`${label} must be an absolute normalized path`);
  return value;
};

function privateDirectory(path, { create = false } = {}) {
  if (create) mkdirSync(path, { recursive: true, mode: 0o700 });
  const info = lstatSync(path);
  if (!info.isDirectory() || info.isSymbolicLink() || realpathSync(path) !== path || (info.mode & 0o777) !== 0o700 || (typeof process.getuid === 'function' && info.uid !== process.getuid())) {
    fail(`directory must be direct user-owned mode-0700: ${path}`);
  }
}

function directFile(path, label) {
  const info = lstatSync(path);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || realpathSync(path) !== path || (info.mode & 0o777) !== 0o600 || (typeof process.getuid === 'function' && info.uid !== process.getuid())) {
    fail(`${label} must be a direct single-link user-owned mode-0600 file`);
  }
  return info;
}

function writeFully(fd, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const written = writeSync(fd, bytes, offset, bytes.length - offset);
    if (written <= 0) fail('atomic artifact write made no progress');
    offset += written;
  }
}

function fsyncDirectory(path) {
  const descriptor = openSync(path, constants.O_RDONLY);
  try { fsyncSync(descriptor); }
  finally { closeSync(descriptor); }
}

function atomicJson(path, value) {
  const parent = dirname(path); privateDirectory(parent);
  if (lstatSync(path, { throwIfNoEntry: false }) !== undefined) fail(`refuses to overwrite artifact: ${path}`);
  const temporary = join(parent, `.${randomBytes(16).toString('hex')}.tmp`);
  const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
  try { writeFully(fd, Buffer.from(`${canonicalJson(value)}\n`, 'utf8')); fsyncSync(fd); }
  finally { closeSync(fd); }
  chmodSync(temporary, 0o600);
  renameSync(temporary, path);
  chmodSync(path, 0o600);
  directFile(path, 'published artifact');
  fsyncDirectory(parent);
  return reference(parent, path, 'json');
}

function copyAtomic(source, target, kind) {
  directFile(source, 'source artifact');
  const parent = dirname(target); privateDirectory(parent);
  if (lstatSync(target, { throwIfNoEntry: false }) !== undefined) fail(`refuses to overwrite artifact: ${target}`);
  const temporary = join(parent, `.${randomBytes(16).toString('hex')}.tmp`);
  copyFileSync(source, temporary, constants.COPYFILE_EXCL);
  chmodSync(temporary, 0o600);
  const descriptor = openSync(temporary, constants.O_RDONLY);
  try { fsyncSync(descriptor); }
  finally { closeSync(descriptor); }
  renameSync(temporary, target);
  chmodSync(target, 0o600);
  directFile(target, 'copied artifact');
  fsyncDirectory(parent);
  return reference(parent, target, kind);
}

function reference(bundle, path, kind) {
  const bytes = readFileSync(path);
  const relativePath = relative(bundle, path).split('\\').join('/');
  if (!relativePath || relativePath.startsWith('../') || relativePath.includes('/../')) fail('artifact escapes bundle');
  return Object.freeze({ id: relativePath, path: relativePath, kind, bytes: bytes.length, sha256: sha256(bytes) });
}

function currentGit() {
  const run = (args) => execFileSync('git', args, { cwd: workspaceRoot, encoding: 'utf8' }).trim();
  const commit = run(['rev-parse', 'HEAD^{commit}']); const tree = run(['rev-parse', 'HEAD^{tree}']);
  const status = run(['status', '--porcelain=v1', '--untracked-files=all']);
  if (!GIT.test(commit) || !GIT.test(tree) || status !== '') fail('Q-07 microbenchmark requires a clean committed source tree');
  return Object.freeze({ commit, tree });
}

function sourceSet() {
  const files = [workerPath, datasetPath];
  return Object.freeze(files.map((path) => Object.freeze({
    path: relative(workspaceRoot, path).split('\\').join('/'),
    sha256: sha256(readFileSync(path)),
  })));
}

function sourceSetHash(files) { return sha256(Buffer.from(canonicalJson(files), 'utf8')); }
function stateOf(result) {
  const value = result.finalAudit;
  if (value === undefined || typeof value.logicalDigestSha256 !== 'string') fail('worker result lacks a complete audited state boundary');
  return Object.freeze({ normalCount: value.normalCount, root: value.root, transcriptChainSha256: value.transcriptChainSha256, logicalDigestSha256: value.logicalDigestSha256 });
}
function visibleStateOf(result) {
  const value = result.finalAudit ?? result.postState;
  if (value === undefined) fail('worker result lacks a state boundary');
  return Object.freeze({ normalCount: value.normalCount, root: value.root, transcriptChainSha256: value.transcriptChainSha256 });
}
function statesEqual(left, right) { return canonicalJson(left) === canonicalJson(right); }
function countersEqual(left, right) { return canonicalJson(left) === canonicalJson(right); }
export function nearestRankP95(values, expectedSamples = WARM_SAMPLES) {
  if (!Number.isSafeInteger(expectedSamples) || expectedSamples < 1 || !Array.isArray(values) || values.length !== expectedSamples || values.some((value) => !Number.isFinite(value) || value < 0)) fail(`p95 requires exactly ${expectedSamples} non-negative samples`);
  const sorted = [...values].sort((a, b) => a - b); return sorted[Math.ceil(sorted.length * 0.95) - 1];
}

function fullCounts(options) {
  if (options?.testOnlyCounts === undefined) return Object.freeze({ baseline: 1_000, prefix: 99_000, full: V2_Q07_MAIN_HISTORY_COUNT, warmSamples: WARM_SAMPLES });
  const value = options.testOnlyCounts;
  exactKeys(value, ['baseline', 'full', 'prefix', 'warmSamples'], 'testOnlyCounts');
  const baseline = integer(value.baseline, 2, 999, 'testOnlyCounts.baseline');
  const prefix = integer(value.prefix, baseline + 1, 99_999, 'testOnlyCounts.prefix');
  const full = integer(value.full, prefix + 1, 99_999, 'testOnlyCounts.full');
  const warmSamples = integer(value.warmSamples, 1, WARM_SAMPLES, 'testOnlyCounts.warmSamples');
  return Object.freeze({ baseline, prefix, full, warmSamples });
}

function workerConfig({ mode, dataset, historyIndex, endOrdinal, databasePath, resultPath, ...extra }) {
  return Object.freeze({ schema: 'shieldkit-v2-direct/q07-store-worker-config/v1', mode, dataset, historyIndex, endOrdinal, databasePath, resultPath, ...extra });
}

function normalizeCgroup(value, testOnly) {
  exactKeys(value, ['backend', 'containment', 'termination'], 'contained worker result');
  if (testOnly) {
    if (value.backend !== 'test-only-cgroup-seam') fail('test runner backend differs');
  } else if (value.backend !== 'linux-systemd-cgroup-v2') fail('worker was not contained by Linux cgroup v2');
  exactKeys(value.containment, ['cgroup', 'memoryEvents', 'memoryMax', 'memoryPeak', 'memorySwapMax'], 'cgroup containment');
  exactKeys(value.containment.memoryEvents, ['oom', 'oomKill'], 'cgroup containment.memoryEvents');
  exactKeys(value.termination, ['exitCode', 'memoryEvents', 'memoryPeak', 'signal'], 'cgroup termination');
  exactKeys(value.termination.memoryEvents, ['oom', 'oomKill'], 'cgroup termination.memoryEvents');
  if (value.termination.exitCode !== 0 || value.termination.signal !== null || value.termination.memoryPeak !== value.containment.memoryPeak || value.termination.memoryEvents.oomKill !== value.containment.memoryEvents.oomKill) fail('cgroup termination is not a clean contained completion');
  for (const key of ['memoryMax', 'memoryPeak', 'memorySwapMax']) if (!/^(0|[1-9][0-9]*)$/u.test(value.containment[key])) fail(`cgroup containment ${key} is invalid`);
  if (!/^(0|[1-9][0-9]*)$/u.test(value.termination.memoryPeak)) fail('cgroup termination memoryPeak is invalid');
  return Object.freeze(value);
}

async function defaultRunner({ configPath }) {
  return runLinuxCgroupV2ProofWorker({ command: process.execPath, arguments: [workerPath, configPath] });
}

async function runOperation(bundle, refs, runner, config, { testOnly }) {
  const slug = `${String(refs.length).padStart(3, '0')}-${config.mode}`;
  const configPath = join(bundle, 'workers', `${slug}.config.json`);
  const resultPath = join(bundle, 'workers', `${slug}.result.json`);
  const complete = { ...config, resultPath };
  atomicJson(configPath, complete); refs.push(reference(bundle, configPath, 'worker-config'));
  const contained = normalizeCgroup(await runner({ config: complete, configPath, resultPath }), testOnly);
  const result = readStrictArtifact(resultPath, 'worker result');
  if (result.qualification !== 'not-qualified' || result.qualificationBoundary !== BOUNDARY || result.mode !== complete.mode) fail('worker result crossed the auxiliary qualification boundary');
  refs.push(reference(bundle, resultPath, 'worker-result'));
  const cgroupPath = join(bundle, 'workers', `${slug}.cgroup.json`);
  atomicJson(cgroupPath, contained); refs.push(reference(bundle, cgroupPath, 'worker-cgroup-report'));
  return Object.freeze({ result, cgroup: contained, configPath, resultPath });
}

function readStrictArtifact(path, label) {
  const bytes = readFileSync(path); let value;
  try { value = parseStrictJson(bytes); } catch (error) { fail(`${label} is invalid strict JSON: ${error instanceof Error ? error.message : String(error)}`); }
  return value;
}

function q04Result(result, original) {
  if (result?.status !== 'verified' || result.q04GatePass !== true || result.q04Verdict !== 'pass-bounded-100000-and-depth4-shared-kernel') fail('Q-04 verification is not a green v3 bounded result');
  return Object.freeze({ schema: 'shieldkit-v2-direct/q07-q04-verification-binding/v1', q04GatePass: true, q04Status: 'verified', q04Verdict: result.q04Verdict, originalSha256: sha256(readFileSync(original)) });
}

function assertWorkerFixedCounters(referenceResult, samples) {
  const referenceCounters = referenceResult.fixedDepthOperationCounts;
  for (const sample of samples) if (!countersEqual(referenceCounters, sample.result.fixedDepthOperationCounts)) fail('warm fixed-depth counters differ from reference insert');
  return referenceCounters;
}

function verifyMainManifest(manifest, counts) {
  exactKeys(manifest, ['boundaries', 'bundleSchema', 'counts', 'dataset', 'git', 'q04', 'q07Qualified', 'qualificationBoundary', 'references', 'sourceSet', 'sourceSetSha256', 'status', 'warm'], 'microbenchmark manifest');
  if (manifest.bundleSchema !== BUNDLE_SCHEMA || manifest.status !== 'indexed-nullifier-store-microbenchmark-only' || manifest.qualificationBoundary !== BOUNDARY || manifest.q07Qualified !== false) fail('manifest attempts to claim a Q07 V2 phase');
  if (canonicalJson(manifest.counts) !== canonicalJson(counts)) fail('manifest count plan differs');
  if (!Array.isArray(manifest.references) || manifest.references.length === 0) fail('manifest references are missing');
  if (manifest.warm.sampleCount !== counts.warmSamples) fail('manifest warm sample count differs');
}

function sameIds(left, right, label) {
  if (left.length !== right.length || left.some((id, index) => id !== right[index])) fail(`${label} references do not match`);
}

function workerId(id, suffix) {
  if (!id.startsWith('workers/') || !id.endsWith(suffix)) fail(`invalid worker artifact id: ${id}`);
  return id.slice('workers/'.length, -suffix.length);
}

/** Build an explicitly auxiliary, hash-bound indexed-nullifier microbenchmark bundle. */
export async function runQ07IndexedMicrobenchmark({
  outputParent,
  q04Verification,
  testOnlyCounts = undefined,
  runner = defaultRunner,
  verifyQ04 = verifyQ04EvidenceFile,
  testOnlySkipGit = false,
} = {}) {
  const counts = fullCounts({ testOnlyCounts }); const testOnly = testOnlyCounts !== undefined;
  if (typeof runner !== 'function' || typeof verifyQ04 !== 'function') fail('runner and verifyQ04 must be functions');
  absolute(outputParent, 'outputParent'); privateDirectory(outputParent, { create: false });
  absolute(q04Verification, 'q04Verification'); directFile(q04Verification, 'q04Verification');
  const git = testOnlySkipGit ? Object.freeze({ commit: '0'.repeat(40), tree: '1'.repeat(40) }) : currentGit();
  const q04 = q04Result(await verifyQ04(q04Verification), q04Verification);
  const bundle = mkdtempSync(join(outputParent, 'q07-indexed-')); chmodSync(bundle, 0o700);
  for (const directory of ['dataset', 'q04', 'workers']) { mkdirSync(join(bundle, directory), { mode: 0o700 }); chmodSync(join(bundle, directory), 0o700); }
  const refs = [];
  const copiedQ04Path = join(bundle, 'q04', 'evidence.json');
  copyAtomic(q04Verification, copiedQ04Path, 'q04-evidence'); const copiedQ04 = reference(bundle, copiedQ04Path, 'q04-evidence'); refs.push(copiedQ04);
  const q04BindingPath = join(bundle, 'q04', 'verification.json');
  atomicJson(q04BindingPath, q04); const q04Binding = reference(bundle, q04BindingPath, 'q04-verification'); refs.push(q04Binding);
  const datasetWritten = writeQ07SingleHistoryDataset({ outputDirectory: join(bundle, 'dataset'), ...(testOnly ? { testOnlyMainCount: counts.full } : {}) });
  const datasetVerified = verifyQ07SingleHistoryDataset({ path: datasetWritten.path, ...(testOnly ? { testOnlyMainCount: counts.full } : {}) });
  if (datasetWritten.sha256 !== datasetVerified.sha256 || datasetWritten.transcriptSha256 !== datasetVerified.transcriptSha256) fail('published dataset verification differs from writer result');
  refs.push(reference(bundle, datasetWritten.path, 'q07-key-dataset'));
  const datasetVerificationPath = join(bundle, 'dataset', 'verification.json');
  atomicJson(datasetVerificationPath, datasetVerified); refs.push(reference(bundle, datasetVerificationPath, 'q07-key-dataset-verification'));
  const dataset = Object.freeze({ path: datasetWritten.path, mainCount: datasetVerified.mainCount, sha256: datasetVerified.sha256, transcriptSha256: datasetVerified.transcriptSha256 });
  const make = (mode, name, endOrdinal, extra = {}) => workerConfig({ mode, dataset, historyIndex: 0, endOrdinal, databasePath: join(bundle, 'workers', `${name}.sqlite`), ...extra });
  const [built1k, built99k, built100k] = await Promise.all([
    runOperation(bundle, refs, runner, make('full-history-build', 'prepared-1k', counts.baseline), { testOnly }),
    runOperation(bundle, refs, runner, make('full-history-build', 'prepared-99k', counts.prefix), { testOnly }),
    runOperation(bundle, refs, runner, make('full-history-build', 'prepared-100k', counts.full), { testOnly }),
  ]);
  const state1k = stateOf(built1k.result); const state99k = stateOf(built99k.result); const state100k = stateOf(built100k.result);
  const ref1k = await runOperation(bundle, refs, runner, make('reference-insert', 'reference-1k', counts.baseline + 1, { expectedPreparedState: state1k, preparedStorePath: built1k.result.database.path, preparedDatabaseSha256: built1k.result.database.closedFileBytes.sha256 }), { testOnly });
  const ref100k = await runOperation(bundle, refs, runner, make('reference-insert', 'reference-100k', counts.full + 1, { expectedPreparedState: state100k, preparedStorePath: built100k.result.database.path, preparedDatabaseSha256: built100k.result.database.closedFileBytes.sha256 }), { testOnly });
  const reference1kState = stateOf(ref1k.result); const reference100kState = stateOf(ref100k.result);
  const warm1k = []; const warm100k = [];
  for (let index = 0; index < counts.warmSamples; index += 1) {
    warm1k.push(await runOperation(bundle, refs, runner, make('warm-insert', `warm-1k-${String(index).padStart(2, '0')}`, counts.baseline + 1, { expectedPreparedState: state1k, expectedPostState: reference1kState, preparedStorePath: built1k.result.database.path, preparedDatabaseSha256: built1k.result.database.closedFileBytes.sha256 }), { testOnly }));
  }
  for (let index = 0; index < counts.warmSamples; index += 1) {
    warm100k.push(await runOperation(bundle, refs, runner, make('warm-insert', `warm-100k-${String(index).padStart(2, '0')}`, counts.full + 1, { expectedPreparedState: state100k, expectedPostState: reference100kState, preparedStorePath: built100k.result.database.path, preparedDatabaseSha256: built100k.result.database.closedFileBytes.sha256 }), { testOnly }));
  }
  const counters1k = assertWorkerFixedCounters(ref1k.result, warm1k); const counters100k = assertWorkerFixedCounters(ref100k.result, warm100k);
  if (!countersEqual(counters1k, counters100k)) fail('1k and 100k fixed-depth counters differ');
  const suffix = await runOperation(bundle, refs, runner, make('suffix-insert', 'suffix-99k-to-100k', counts.full, { startOrdinal: counts.prefix + 1, expectedPreparedState: state99k, expectedPostState: state100k, preparedStorePath: built99k.result.database.path, preparedDatabaseSha256: built99k.result.database.closedFileBytes.sha256 }), { testOnly });
  const audit = await runOperation(bundle, refs, runner, workerConfig({ mode: 'full-store-audit', dataset, historyIndex: 0, endOrdinal: counts.full, databasePath: built100k.result.database.path, resultPath: join(bundle, 'workers', 'full-store-audit.result.json'), expectedPreparedState: state100k }), { testOnly });
  const reopenedHandles = [];
  for (let index = 0; index < counts.warmSamples; index += 1) {
    reopenedHandles.push(await runOperation(bundle, refs, runner, make('reopened-handle-path', `reopened-100k-${String(index).padStart(2, '0')}`, counts.full, { expectedPreparedState: state100k, preparedStorePath: built100k.result.database.path, preparedDatabaseSha256: built100k.result.database.closedFileBytes.sha256, readPhysicalIndex: 2 }), { testOnly }));
  }
  const warm1kP95 = nearestRankP95(warm1k.map((item) => item.result.measurement.wallMs), counts.warmSamples);
  const warm100kP95 = nearestRankP95(warm100k.map((item) => item.result.measurement.wallMs), counts.warmSamples);
  const reopenedHandleP95 = nearestRankP95(reopenedHandles.map((item) => item.result.measurement.wallMs), counts.warmSamples);
  const sourceFiles = sourceSet();
  const manifest = Object.freeze({
    bundleSchema: BUNDLE_SCHEMA,
    status: 'indexed-nullifier-store-microbenchmark-only', qualificationBoundary: BOUNDARY, q07Qualified: false,
    counts, git, sourceSet: sourceFiles, sourceSetSha256: sourceSetHash(sourceFiles),
    q04: Object.freeze({ evidenceSha256: copiedQ04.sha256, verificationSha256: q04Binding.sha256, status: q04.q04Status, gatePass: q04.q04GatePass }),
    dataset: Object.freeze({ sha256: datasetVerified.sha256, transcriptSha256: datasetVerified.transcriptSha256, mainCount: datasetVerified.mainCount, count: datasetVerified.count, warmSampleOrdinal: datasetVerified.warmSampleOrdinal }),
    warm: Object.freeze({ sampleCount: counts.warmSamples, baselineP95Ms: warm1kP95, atFullP95Ms: warm100kP95, ratio: warm100kP95 / warm1kP95, exactFixedDepthCounters: counters1k }),
    boundaries: Object.freeze({ prepared1k: visibleStateOf(built1k.result), prepared99k: visibleStateOf(built99k.result), prepared100k: visibleStateOf(built100k.result), reference1k: visibleStateOf(ref1k.result), reference100k: visibleStateOf(ref100k.result), suffixPost: visibleStateOf(suffix.result), audit: visibleStateOf(audit.result), reopenedHandleP95Ms: reopenedHandleP95, databaseBytes: built100k.result.database.closedFileBytes.total }),
    references: Object.freeze(refs),
  });
  const evidencePath = join(bundle, 'evidence.json');
  atomicJson(evidencePath, manifest);
  const verified = await verifyQ07IndexedMicrobenchmarkBundle(evidencePath, { testOnlyCounts, testOnlySkipGit });
  return Object.freeze({ ...verified, bundle, evidence: Object.freeze({ path: evidencePath, bytes: lstatSync(evidencePath).size, sha256: sha256(readFileSync(evidencePath)) }) });
}

function safeReferencePath(bundle, referenceValue) {
  exactKeys(referenceValue, ['bytes', 'id', 'kind', 'path', 'sha256'], 'artifact reference');
  if (typeof referenceValue.path !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._/-]*$/u.test(referenceValue.path) || referenceValue.path.includes('..')) fail('artifact reference path is unsafe');
  if (!Number.isSafeInteger(referenceValue.bytes) || referenceValue.bytes < 1 || !HASH.test(referenceValue.sha256)) fail('artifact reference metadata is invalid');
  const path = resolve(bundle, ...referenceValue.path.split('/'));
  if (!path.startsWith(`${bundle}/`)) fail('artifact reference escapes bundle');
  return path;
}

/** Reread every retained artifact and reject relabeling, drift, or fake cgroup records. */
export async function verifyQ07IndexedMicrobenchmarkBundle(evidencePath, { testOnlyCounts = undefined, testOnlySkipGit = false } = {}) {
  absolute(evidencePath, 'evidencePath'); directFile(evidencePath, 'evidencePath');
  const bundle = dirname(evidencePath); privateDirectory(bundle);
  const manifest = readStrictArtifact(evidencePath, 'microbenchmark evidence'); const counts = fullCounts({ testOnlyCounts }); verifyMainManifest(manifest, counts);
  if (!Array.isArray(manifest.sourceSet) || !HASH.test(manifest.sourceSetSha256) || sourceSetHash(manifest.sourceSet) !== manifest.sourceSetSha256) fail('manifest sourceSet binding drifted');
  if (!testOnlySkipGit) {
    const git = currentGit(); if (canonicalJson(git) !== canonicalJson(manifest.git)) fail('source git commit or tree drifted');
    const sources = sourceSet(); if (canonicalJson(sources) !== canonicalJson(manifest.sourceSet) || sourceSetHash(sources) !== manifest.sourceSetSha256) fail('worker or dataset source drifted');
  }
  const seen = new Set(); const parsed = new Map();
  for (const ref of manifest.references) {
    const path = safeReferencePath(bundle, ref); if (seen.has(ref.id)) fail('duplicate artifact reference id'); seen.add(ref.id);
    const info = directFile(path, `artifact ${ref.id}`); if (info.size !== ref.bytes) fail(`artifact ${ref.id} byte count drifted`);
    const bytes = readFileSync(path); if (sha256(bytes) !== ref.sha256) fail(`artifact ${ref.id} SHA-256 drifted`);
    if (ref.kind === 'q07-key-dataset') {
      const verified = verifyQ07SingleHistoryDataset({ path, ...(testOnlyCounts === undefined ? {} : { testOnlyMainCount: counts.full }) });
      if (verified.mainCount !== counts.full || verified.sha256 !== manifest.dataset.sha256 || verified.transcriptSha256 !== manifest.dataset.transcriptSha256) fail('Q07 dataset verification drifted');
    } else parsed.set(ref.id, readStrictArtifact(path, `artifact ${ref.id}`));
  }
  const q04Binding = [...parsed.entries()].find(([id]) => id === 'q04/verification.json')?.[1];
  if (q04Binding === undefined || q04Binding.q04GatePass !== true || q04Binding.q04Status !== 'verified' || q04Binding.q04Verdict !== 'pass-bounded-100000-and-depth4-shared-kernel') fail('Q04 verification binding is not green');
  if (manifest.q04.evidenceSha256 !== manifest.references.find((ref) => ref.id === 'q04/evidence.json')?.sha256 || manifest.q04.verificationSha256 !== manifest.references.find((ref) => ref.id === 'q04/verification.json')?.sha256) fail('Q04 artifact binding drifted');
  if (q04Binding.originalSha256 !== manifest.q04.evidenceSha256) fail('Q04 original artifact hash binding drifted');
  const workerConfigEntries = [...parsed.entries()].filter(([id]) => id.endsWith('.config.json'));
  const workerResultEntries = [...parsed.entries()].filter(([id]) => id.endsWith('.result.json'));
  const cgroupEntries = [...parsed.entries()].filter(([id]) => id.endsWith('.cgroup.json'));
  const workerResults = workerResultEntries.map(([, value]) => value);
  const cgroups = cgroupEntries.map(([, value]) => value);
  const expectedWorkers = 3 + 2 + counts.warmSamples * 2 + 1 + 1 + counts.warmSamples;
  if (workerConfigEntries.length !== expectedWorkers || workerResults.length !== expectedWorkers || cgroups.length !== expectedWorkers) fail('worker sample count is incomplete');
  const configIds = workerConfigEntries.map(([id]) => workerId(id, '.config.json')).sort();
  const resultIds = workerResultEntries.map(([id]) => workerId(id, '.result.json')).sort();
  const cgroupIds = cgroupEntries.map(([id]) => workerId(id, '.cgroup.json')).sort();
  sameIds(configIds, resultIds, 'worker configuration and result'); sameIds(configIds, cgroupIds, 'worker configuration and cgroup');
  for (const [id, config] of workerConfigEntries) {
    if (config?.schema !== 'shieldkit-v2-direct/q07-store-worker-config/v1' || typeof config.mode !== 'string' || config.resultPath !== join(bundle, 'workers', `${workerId(id, '.config.json')}.result.json`)) fail(`worker config is not bound to its result: ${id}`);
    const result = parsed.get(`workers/${workerId(id, '.config.json')}.result.json`);
    if (result?.mode !== config.mode) fail(`worker config mode differs from its result: ${id}`);
  }
  for (const result of workerResults) {
    if (result.qualification !== 'not-qualified' || result.qualificationBoundary !== BOUNDARY || result.productionStore !== 'Q04PersistentNullifierStore(depth=32)') fail('worker result was relabeled as a V2 Q07 phase');
  }
  for (const record of cgroups) normalizeCgroup(record, testOnlyCounts !== undefined);
  const warmResults = workerResults.filter((result) => result.mode === 'warm-insert');
  const reopenedHandleResults = workerResults.filter((result) => result.mode === 'reopened-handle-path');
  if (warmResults.length !== counts.warmSamples * 2 || reopenedHandleResults.length !== counts.warmSamples) fail('warm or reopened-handle sample count is incomplete');
  const warmBaseline = warmResults.filter((result) => result.endOrdinal === counts.baseline + 1);
  const warmFull = warmResults.filter((result) => result.endOrdinal === counts.full + 1);
  if (warmBaseline.length !== counts.warmSamples || warmFull.length !== counts.warmSamples) fail('warm samples are not bound to both history sizes');
  const fixed = manifest.warm.exactFixedDepthCounters;
  if (!warmResults.every((result) => countersEqual(result.fixedDepthOperationCounts, fixed))) fail('fixed-depth counters drifted across warm samples');
  if (manifest.warm.baselineP95Ms !== nearestRankP95(warmBaseline.map((result) => result.measurement.wallMs), counts.warmSamples) || manifest.warm.atFullP95Ms !== nearestRankP95(warmFull.map((result) => result.measurement.wallMs), counts.warmSamples)) fail('warm p95 evidence differs from raw samples');
  if (manifest.warm.ratio !== manifest.warm.atFullP95Ms / manifest.warm.baselineP95Ms) fail('warm ratio differs from raw p95 values');
  const buildFull = workerResults.find((result) => result.mode === 'full-history-build' && result.endOrdinal === counts.full);
  const suffix = workerResults.find((result) => result.mode === 'suffix-insert');
  const audit = workerResults.find((result) => result.mode === 'full-store-audit');
  if (buildFull === undefined || suffix === undefined || audit === undefined || !statesEqual(manifest.boundaries.prepared100k, visibleStateOf(buildFull)) || !statesEqual(manifest.boundaries.suffixPost, visibleStateOf(suffix)) || !statesEqual(manifest.boundaries.audit, visibleStateOf(audit)) || manifest.boundaries.databaseBytes !== buildFull.database?.closedFileBytes?.total) fail('stored state boundary evidence differs from raw worker results');
  if (!statesEqual(manifest.boundaries.prepared100k, manifest.boundaries.suffixPost) || !statesEqual(manifest.boundaries.prepared100k, manifest.boundaries.audit)) fail('suffix or audit terminal state differs from prepared full store');
  if (manifest.boundaries.reopenedHandleP95Ms !== nearestRankP95(reopenedHandleResults.map((result) => result.measurement.wallMs), counts.warmSamples)) fail('reopened-handle p95 evidence differs from raw samples');
  return Object.freeze({ schema: RESULT_SCHEMA, status: BOUNDARY, q07Qualified: false, bundle, evidencePath, warmBaselineP95Ms: manifest.warm.baselineP95Ms, warmAtFullP95Ms: manifest.warm.atFullP95Ms, reopenedHandleP95Ms: manifest.boundaries.reopenedHandleP95Ms, databaseBytes: manifest.boundaries.databaseBytes });
}

export function parseQ07IndexedMicrobenchmarkArguments(argv) {
  if (!Array.isArray(argv) || argv.length !== 4 || argv[0] !== '--output-parent' || argv[2] !== '--q04-verification') fail('usage: node v2-q07-indexed-microbenchmark.mjs --output-parent ABS --q04-verification ABS');
  return Object.freeze({ outputParent: absolute(argv[1], 'outputParent'), q04Verification: absolute(argv[3], 'q04Verification') });
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  try { process.stdout.write(`${canonicalJson(await runQ07IndexedMicrobenchmark(parseQ07IndexedMicrobenchmarkArguments(process.argv.slice(2))))}\n`); }
  catch (error) { process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; }
}
