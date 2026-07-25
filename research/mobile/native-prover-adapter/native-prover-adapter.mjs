// Fail-closed local adapter for a caller-hash-pinned native Groth16 prover.
// It neither creates witnesses nor performs setup, network, or BCH activity.
import { createHash, randomUUID } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, mkdir, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { loadLocalProverProfileBinding, parseLocalProverProfileBinding } from '../../../packages/profile/local-prover.mjs';

const kinds = new Set(['deposit', 'transfer', 'withdrawal']);
const scalarModulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const outputLimitBytes = 64 * 1024;
const childEnv = Object.freeze({ PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', TZ: 'UTC' });

export class NativeProverAdapterError extends Error { constructor(message) { super(message); this.name = 'NativeProverAdapterError'; } }
const fail = (message) => { throw new NativeProverAdapterError(message); };
const clipped = (value, limit = 512) => `${String(value).slice(0, limit)}${String(value).length > limit ? ' [truncated]' : ''}`;
const exactKeys = (value, label, keys) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has unexpected keys`);
};
const sha = async (filename) => new Promise((resolveSha, rejectSha) => {
  const hash = createHash('sha256');
  const stream = createReadStream(filename);
  stream.on('error', rejectSha); stream.on('data', (chunk) => hash.update(chunk)); stream.on('end', () => resolveSha(hash.digest('hex')));
});
const readStrictUtf8 = async (filename, label) => {
  let bytes;
  try { bytes = await readFile(filename); } catch { fail(`${label} is unavailable`); }
  try { const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); if (text.codePointAt(0) === 0xfeff) fail(`${label} must not include a UTF-8 BOM`); return text; } catch (error) { if (error instanceof NativeProverAdapterError) throw error; fail(`${label} is not valid UTF-8`); }
};
export function parseStrictJson(text, label) {
  let index = 0;
  const ws = () => { while (text[index] !== undefined && ' \t\r\n'.includes(text[index])) index += 1; };
  const parseString = () => {
    const start = index;
    if (text[index] !== '"') fail(`${label} has an invalid object key`);
    index += 1;
    while (index < text.length) {
      const char = text[index];
      if (char === '"') { index += 1; try { return JSON.parse(text.slice(start, index)); } catch { fail(`${label} has an invalid string`); } }
      if (char === '\\') { index += 1; if (index >= text.length) break; index += text[index] === 'u' ? 5 : 1; continue; }
      if (char.charCodeAt(0) < 0x20) fail(`${label} has a control character in a string`);
      index += 1;
    }
    fail(`${label} has an unterminated string`);
  };
  const value = () => {
    ws(); const char = text[index];
    if (char === '{') { index += 1; const object = {}; const seen = new Set(); ws(); if (text[index] === '}') { index += 1; return object; } while (true) { ws(); if (text[index] !== '"') fail(`${label} object key is invalid`); const key = parseString(); if (seen.has(key)) fail(`${label} contains duplicate key ${key}`); seen.add(key); ws(); if (text[index++] !== ':') fail(`${label} is missing a colon`); object[key] = value(); ws(); if (text[index] === '}') { index += 1; return object; } if (text[index++] !== ',') fail(`${label} is missing a comma`); } }
    if (char === '[') { index += 1; const array = []; ws(); if (text[index] === ']') { index += 1; return array; } while (true) { array.push(value()); ws(); if (text[index] === ']') { index += 1; return array; } if (text[index++] !== ',') fail(`${label} is missing an array comma`); } }
    if (char === '"') return parseString();
    const literal = /^(true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(index));
    if (!literal) fail(`${label} has invalid JSON`); index += literal[0].length;
    try { return JSON.parse(literal[0]); } catch { fail(`${label} has invalid JSON`); }
  };
  const parsed = value(); ws(); if (index !== text.length) fail(`${label} has trailing content`); return parsed;
}
const canonicalSignals = (value, label) => {
  if (!Array.isArray(value) || value.length !== 2) fail(`${label} must contain exactly two public signals`);
  for (const signal of value) if (typeof signal !== 'string' || !/^(0|[1-9][0-9]*)$/.test(signal) || BigInt(signal) >= scalarModulus) fail(`${label} must contain canonical BN254 scalar strings`);
  return value;
};
const pinnedShape = (record, label, extraKeys = []) => {
  exactKeys(record, label, ['path', 'sha256', ...extraKeys]);
  if (typeof record.path !== 'string' || !isAbsolute(record.path) || !/^[0-9a-f]{64}$/.test(record.sha256)) fail(`${label} must use an absolute path and lowercase SHA-256`);
};
const regular = async (record, label, extraKeys = []) => {
  pinnedShape(record, label, extraKeys); const path = resolve(record.path);
  const stat = await lstat(path).catch(() => fail(`${label} is unavailable`));
  if (!stat.isFile() || stat.isSymbolicLink() || await realpath(path).catch(() => '') !== path) fail(`${label} must be a direct regular non-symlink file`);
  const digest = await sha(path).catch(() => fail(`${label} cannot be hashed`));
  if (digest !== record.sha256) fail(`${label} SHA-256 mismatch`);
  return Object.freeze({ path, sha256: digest, bytes: stat.size, dev: String(stat.dev), ino: String(stat.ino) });
};
const assertStable = async (record, label) => {
  const stat = await lstat(record.path).catch(() => fail(`${label} changed or became unavailable`));
  if (!stat.isFile() || stat.isSymbolicLink() || await realpath(record.path).catch(() => '') !== record.path || stat.size !== record.bytes || String(stat.dev) !== record.dev || String(stat.ino) !== record.ino) fail(`${label} identity changed`);
  if (await sha(record.path).catch(() => fail(`${label} cannot be rehashed`)) !== record.sha256) fail(`${label} content changed`);
};
const assertAllStable = async (records) => { for (const [label, record] of records) await assertStable(record, label); };
const bounded = (stream) => {
  let value = ''; let bytes = 0; let truncated = false;
  stream.on('data', (chunk) => { const remaining = outputLimitBytes - bytes; if (remaining > 0) value += chunk.subarray(0, remaining).toString('utf8'); bytes += chunk.length; if (bytes > outputLimitBytes) truncated = true; });
  return () => ({ value, truncated });
};
// Sum a local prover's live process tree. This catches a launcher that forks
// the actual prover; sampling only the launcher would under-report RSS.
const processTreeRss = async (rootPid) => {
  const pending = [rootPid]; const seen = new Set(); let rssKiB = 0;
  while (pending.length) {
    const pid = pending.pop(); if (!Number.isInteger(pid) || pid < 1 || seen.has(pid)) continue; seen.add(pid);
    try {
      const status = await readFile(`/proc/${pid}/status`, 'utf8');
      const match = /^VmRSS:\s+(\d+)\s+kB$/m.exec(status); if (match) rssKiB += Number(match[1]);
      const children = await readFile(`/proc/${pid}/task/${pid}/children`, 'utf8');
      for (const child of children.trim().split(/\s+/)) if (/^[1-9][0-9]*$/.test(child)) pending.push(Number(child));
    } catch {}
  }
  return { rssKiB, processes: seen.size };
};
const run = (command, args, label, { measure = false, allowedExitCodes = new Set([0]) } = {}) => new Promise((resolveRun, rejectRun) => {
  const child = spawn(command, args, { env: childEnv, stdio: ['ignore', 'pipe', 'pipe'], shell: false });
  const stdout = bounded(child.stdout); const stderr = bounded(child.stderr); let peakRss = 0; let peakProcesses = 0; let samples = 0;
  const start = process.hrtime.bigint();
  const sample = async () => { if (!measure || !child.pid) return; const usage = await processTreeRss(child.pid); samples += 1; peakRss = Math.max(peakRss, usage.rssKiB); peakProcesses = Math.max(peakProcesses, usage.processes); };
  void sample(); const timer = setInterval(() => void sample(), 10);
  child.once('error', (error) => { clearInterval(timer); rejectRun(new NativeProverAdapterError(`${label} could not start: ${clipped(error.message)}`)); });
  child.once('close', async (code, signal) => { clearInterval(timer); await sample(); const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6; const capturedOut = stdout(); const capturedErr = stderr(); if (!allowedExitCodes.has(code)) return rejectRun(new NativeProverAdapterError(`${label} failed: exit=${code} signal=${signal ?? 'none'} stderr=${clipped(capturedErr.value)}${capturedErr.truncated ? ' [output truncated]' : ''}`)); resolveRun({ elapsedMs, stdout: capturedOut.value, stderr: capturedErr.value, stdoutTruncated: capturedOut.truncated, stderrTruncated: capturedErr.truncated, memory: measure ? { peakRssKiB: peakRss, peakProcesses, method: 'linux-proc-status-vmrss-process-tree-sampled', scope: 'local prover launcher and live descendants; excludes the adapter, verifier, and all unrelated processes', sampleIntervalMs: 10, samples } : undefined }); });
});
const absent = async (path, label) => { try { await lstat(path); fail(`${label} already exists`); } catch (error) { if (error instanceof NativeProverAdapterError) throw error; if (error?.code !== 'ENOENT') fail(`${label} cannot be inspected`); } };
const safeOutputParent = async (output) => {
  const parent = dirname(output); const stat = await lstat(parent).catch(() => fail('output parent is unavailable'));
  if (!stat.isDirectory() || stat.isSymbolicLink() || await realpath(parent).catch(() => '') !== parent) fail('output parent must be a direct non-symlink directory');
  await absent(output, 'output directory'); return Object.freeze({ path: parent, dev: String(stat.dev), ino: String(stat.ino) });
};
const assertDirectoryStable = async (record, label) => {
  const stat = await lstat(record.path).catch(() => fail(`${label} changed or became unavailable`));
  if (!stat.isDirectory() || stat.isSymbolicLink() || await realpath(record.path).catch(() => '') !== record.path || String(stat.dev) !== record.dev || String(stat.ino) !== record.ino) fail(`${label} identity changed`);
};

export function parseManifest(value) {
  exactKeys(value, 'manifest', ['actions', 'nativeProver', 'outputDirectory', 'profile', 'repetitions', 'schema', 'snarkjs']);
  if (value.schema !== 'shield.cash/native-prover-adapter/v1') fail('manifest schema mismatch');
  if (typeof value.outputDirectory !== 'string' || !isAbsolute(value.outputDirectory)) fail('outputDirectory must be an absolute path');
  if (!Number.isInteger(value.repetitions) || value.repetitions < 1 || value.repetitions > 20) fail('repetitions must be 1..20');
  try { parseLocalProverProfileBinding(value.profile); } catch (error) { fail(error.message); } exactKeys(value.nativeProver, 'nativeProver', ['backend', 'path', 'sha256']); if (value.nativeProver.backend !== 'rapidsnark') fail('nativeProver.backend must be rapidsnark'); pinnedShape(value.nativeProver, 'nativeProver', ['backend']);
  exactKeys(value.snarkjs, 'snarkjs', ['path', 'sha256', 'version']); if (typeof value.snarkjs.version !== 'string' || !/^\d+\.\d+\.\d+$/.test(value.snarkjs.version)) fail('snarkjs version is malformed'); pinnedShape(value.snarkjs, 'snarkjs', ['version']);
  if (!Array.isArray(value.actions) || value.actions.length !== 3) fail('actions must contain exactly three entries'); const seen = new Set();
  for (const action of value.actions) { exactKeys(action, 'action', ['expectedPublicSignals', 'kind', 'witness']); if (!kinds.has(action.kind) || seen.has(action.kind)) fail('actions must be unique deposit, transfer, withdrawal'); seen.add(action.kind); canonicalSignals(action.expectedPublicSignals, `${action.kind}.expectedPublicSignals`); pinnedShape(action.witness, `${action.kind}.witness`); }
  return value;
}

export async function runNativeProverAdapter(manifestFilename, { stagingId = randomUUID() } = {}) {
  if (typeof stagingId !== 'string' || !/^[a-zA-Z0-9_-]+$/.test(stagingId)) fail('stagingId is malformed');
  const manifest = parseManifest(parseStrictJson(await readStrictUtf8(manifestFilename, 'manifest'), 'manifest'));
  let profile; try { profile = await loadLocalProverProfileBinding(manifest.profile); } catch (error) { fail(error.message); } const nativeProver = Object.freeze({ ...await regular(manifest.nativeProver, 'nativeProver', ['backend']), backend: manifest.nativeProver.backend }); const snarkjs = await regular(manifest.snarkjs, 'snarkjs', ['version']); const zkey = await regular(profile.artifacts.zkey, 'profile.artifacts.zkey'); const verificationKey = await regular(profile.artifacts.verificationKey, 'profile.artifacts.verificationKey');
  const actions = []; for (const action of manifest.actions) actions.push({ ...action, witness: await regular(action.witness, `${action.kind}.witness`) });
  const inputs = [['nativeProver', nativeProver], ['snarkjs', snarkjs], ['artifacts.zkey', zkey], ['artifacts.verificationKey', verificationKey], ...actions.map((action) => [`${action.kind}.witness`, action.witness])];
  const output = resolve(manifest.outputDirectory); const parent = await safeOutputParent(output); const staging = join(parent.path, `.${basename(output)}.staging-${stagingId}`); let published = false; let stagingCreated = false; let stagingRecord;
  try {
    await mkdir(staging, { mode: 0o700 }); stagingCreated = true; const stagingStat = await lstat(staging); if (!stagingStat.isDirectory() || stagingStat.isSymbolicLink() || await realpath(staging) !== staging) fail('staging directory is unsafe'); stagingRecord = Object.freeze({ path: staging, dev: String(stagingStat.dev), ino: String(stagingStat.ino) });
    await assertAllStable(inputs); const version = await run(process.execPath, [snarkjs.path, '--version'], 'pinned snarkjs version', { allowedExitCodes: new Set([0, 99]) }); await assertAllStable(inputs);
    if (!version.stdout.includes(`snarkjs@${manifest.snarkjs.version}`)) fail('pinned snarkjs version mismatch');
    const result = { schema: 'shield.cash/native-prover-adapter-result/v1', qualification: 'initial feasibility only; not p95 hardware qualification', profile: profile.identity, nativeProver, snarkjs: { ...snarkjs, version: manifest.snarkjs.version }, artifacts: { zkey, verificationKey }, repetitions: manifest.repetitions, actions: [] };
    for (const action of actions) {
      const runs = [];
      for (let index = 1; index <= manifest.repetitions; index += 1) {
        const proof = join(staging, `${action.kind}-${index}.proof.json`); const publicSignals = join(staging, `${action.kind}-${index}.public.json`);
        await assertAllStable(inputs); const proving = await run(nativeProver.path, [zkey.path, action.witness.path, proof, publicSignals], `${action.kind} native proving`, { measure: true }); await assertAllStable(inputs);
        await assertAllStable(inputs); const verification = await run(process.execPath, [snarkjs.path, 'groth16', 'verify', verificationKey.path, publicSignals, proof], `${action.kind} pinned snarkjs verification`); await assertAllStable(inputs);
        const observed = canonicalSignals(parseStrictJson(await readStrictUtf8(publicSignals, `${action.kind} public signals`), `${action.kind} public signals`), `${action.kind} public signals`);
        if (JSON.stringify(observed) !== JSON.stringify(action.expectedPublicSignals)) fail(`${action.kind} public signals differ from manifest`);
        const proofStat = await lstat(proof).catch(() => fail(`${action.kind} proof is unavailable`)); const signalsStat = await lstat(publicSignals).catch(() => fail(`${action.kind} public signals are unavailable`));
        if (!proofStat.isFile() || proofStat.isSymbolicLink() || await realpath(proof).catch(() => '') !== proof || !signalsStat.isFile() || signalsStat.isSymbolicLink() || await realpath(publicSignals).catch(() => '') !== publicSignals) fail(`${action.kind} prover output is unsafe`);
        runs.push({ index, proving, verification: { elapsedMs: verification.elapsedMs, stdout: verification.stdout, stderr: verification.stderr, stdoutTruncated: verification.stdoutTruncated, stderrTruncated: verification.stderrTruncated }, outputs: { proof: { path: `${action.kind}-${index}.proof.json`, sha256: await sha(proof), bytes: proofStat.size }, publicSignals: { path: `${action.kind}-${index}.public.json`, sha256: await sha(publicSignals), bytes: signalsStat.size } } });
      }
      result.actions.push({ kind: action.kind, witness: action.witness, expectedPublicSignals: action.expectedPublicSignals, runs });
    }
    await assertAllStable(inputs); await assertDirectoryStable(parent, 'output parent'); await assertDirectoryStable(stagingRecord, 'staging directory'); const resultPath = join(staging, 'result.json'); await writeFile(resultPath, `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx', mode: 0o600 }); const resultStat = await lstat(resultPath); if (!resultStat.isFile() || resultStat.isSymbolicLink() || await realpath(resultPath).catch(() => '') !== resultPath) fail('result output is unsafe'); await assertDirectoryStable(parent, 'output parent'); await assertDirectoryStable(stagingRecord, 'staging directory'); await absent(output, 'output directory'); await rename(staging, output); published = true; return result;
  } catch (error) { if (error instanceof NativeProverAdapterError) throw error; fail(`native prover adapter failed: ${clipped(error?.message ?? error)}`); } finally {
    if (!published && stagingCreated && stagingRecord) {
      try { await assertDirectoryStable(stagingRecord, 'staging directory'); await rm(staging, { recursive: true, force: true }); } catch {}
    }
  }
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const manifest = process.argv[2]; if (!manifest) { console.error('usage: native-prover-adapter.mjs MANIFEST.json'); process.exitCode = 2; } else runNativeProverAdapter(manifest).then((result) => console.log(JSON.stringify({ actions: result.actions.map((action) => action.kind) }))).catch((error) => { console.error(error.message); process.exitCode = 1; });
}
