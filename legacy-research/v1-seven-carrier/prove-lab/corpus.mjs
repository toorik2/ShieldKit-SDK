// Fail-closed local Groth16 corpus executor. It consumes immutable caller
// artifacts only; it never runs setup or fetches network material.
import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createReadStream } from 'node:fs';
import { lstat, mkdir, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const actionKinds = new Set(['deposit', 'transfer', 'withdrawal']);
const decimal = /^(0|[1-9][0-9]*)$/;
const STDERR_LIMIT_BYTES = 64 * 1024;
const PROC_SAMPLE_INTERVAL_MS = 25;

export class ProofCorpusError extends Error {
  constructor(message) { super(message); this.name = 'ProofCorpusError'; }
}
const fail = (message) => { throw new ProofCorpusError(message); };
const now = () => process.hrtime.bigint();
const elapsed = (started) => Number(process.hrtime.bigint() - started) / 1e6;

// JSON.parse overwrites duplicate object keys. This small recursive parser
// rejects them at every nesting level before returning ordinary JSON values.
export function parseStrictJson(text, label = 'JSON') {
  let offset = 0;
  const whitespace = () => { while (offset < text.length && /[\t\n\r ]/.test(text[offset])) offset += 1; };
  const string = () => {
    const start = offset;
    if (text[offset] !== '"') fail(`${label}: expected JSON string at byte ${offset}`);
    offset += 1;
    while (offset < text.length) {
      const current = text[offset];
      if (current === '"') { offset += 1; try { return JSON.parse(text.slice(start, offset)); } catch (error) { fail(`${label}: invalid JSON string: ${error.message}`); } }
      if (current === '\\') { offset += 1; if (offset >= text.length) break; offset += text[offset] === 'u' ? 5 : 1; continue; }
      if (current.charCodeAt(0) < 0x20) fail(`${label}: control character in string`);
      offset += 1;
    }
    fail(`${label}: unterminated JSON string`);
  };
  const value = () => {
    whitespace();
    const current = text[offset];
    if (current === '{') {
      offset += 1; whitespace(); const result = {}; const keys = new Set();
      if (text[offset] === '}') { offset += 1; return result; }
      while (true) {
        whitespace(); const key = string(); if (keys.has(key)) fail(`${label}: duplicate key ${JSON.stringify(key)}`); keys.add(key);
        whitespace(); if (text[offset] !== ':') fail(`${label}: expected ':' at byte ${offset}`); offset += 1;
        result[key] = value(); whitespace();
        if (text[offset] === '}') { offset += 1; return result; }
        if (text[offset] !== ',') fail(`${label}: expected ',' or '}' at byte ${offset}`); offset += 1;
      }
    }
    if (current === '[') {
      offset += 1; whitespace(); const result = [];
      if (text[offset] === ']') { offset += 1; return result; }
      while (true) { result.push(value()); whitespace(); if (text[offset] === ']') { offset += 1; return result; } if (text[offset] !== ',') fail(`${label}: expected ',' or ']' at byte ${offset}`); offset += 1; }
    }
    if (current === '"') return string();
    for (const [literal, result] of [['true', true], ['false', false], ['null', null]]) if (text.startsWith(literal, offset)) { offset += literal.length; return result; }
    const match = text.slice(offset).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (!match) fail(`${label}: invalid JSON value at byte ${offset}`);
    offset += match[0].length;
    return Number(match[0]);
  };
  const result = value(); whitespace(); if (offset !== text.length) fail(`${label}: trailing bytes at ${offset}`); return result;
}

function canonicalDecimal(value, label) {
  if (typeof value !== 'string' || !decimal.test(value)) fail(`${label} must be a canonical nonnegative decimal string`);
  return value;
}
function exactKeys(value, label, keys) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown properties`);
}
export async function sha256File(filename) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(filename)) hash.update(chunk);
  return hash.digest('hex');
}
async function immutableFile(record, label) {
  exactKeys(record, label, ['path', 'sha256']);
  if (typeof record.path !== 'string' || record.path.length === 0) fail(`${label}.path must be a nonempty string`);
  if (!/^[0-9a-f]{64}$/.test(record.sha256)) fail(`${label}.sha256 must be lowercase SHA-256`);
  const resolved = path.resolve(record.path);
  const stats = await lstat(resolved).catch(() => fail(`${label} is missing: ${record.path}`));
  if (!stats.isFile() || stats.isSymbolicLink()) fail(`${label} must be a regular non-symlink file: ${record.path}`);
  if (await realpath(resolved) !== resolved) fail(`${label} resolves through a symlink: ${record.path}`);
  const sha256 = await sha256File(resolved);
  if (sha256 !== record.sha256) fail(`${label} SHA-256 mismatch: expected ${record.sha256}, got ${sha256}`);
  return Object.freeze({ path: resolved, sha256, bytes: stats.size });
}
async function pinnedTool(record) {
  exactKeys(record, 'snarkjs', ['path', 'sha256', 'version']);
  const tool = await immutableFile({ path: record.path, sha256: record.sha256 }, 'snarkjs');
  if (typeof record.version !== 'string' || !/^\d+\.\d+\.\d+$/.test(record.version)) fail('snarkjs.version must be an exact semver');
  const versionRun = await run(tool, ['--version'], 'pinned snarkjs --version', { allowedExitCodes: new Set([0, 99]), captureStdout: true });
  const stdout = versionRun.stdout;
  const observed = stdout.match(/snarkjs@([0-9]+\.[0-9]+\.[0-9]+)/)?.[1];
  if (observed !== record.version) fail(`pinned snarkjs version mismatch: expected ${record.version}, got ${observed ?? 'unrecognized output'}`);
  return Object.freeze({ ...tool, version: observed });
}
async function stable(artifacts) {
  for (const artifact of artifacts) {
    const stats = await lstat(artifact.path);
    if (!stats.isFile() || stats.isSymbolicLink() || await realpath(artifact.path) !== artifact.path || await sha256File(artifact.path) !== artifact.sha256) fail(`input artifact changed during execution: ${artifact.path}`);
  }
}
export function parseLinuxProcStatus(status) {
  const parse = (name) => {
    const match = status.match(new RegExp(`^${name}:\\s+(\\d+)\\s+kB$`, 'm'));
    return match ? Number(match[1]) : null;
  };
  return { vmHwmKiB: parse('VmHWM'), vmRssKiB: parse('VmRSS') };
}
export function memoryMeasurement({ sampleCount, peakVmHwmKiB, peakVmRssKiB, procfsAvailable }) {
  if (process.platform !== 'linux' || !procfsAvailable) return {
    peakRssKiB: null,
    method: 'unavailable',
    scope: 'direct snarkjs child process',
    sampleIntervalMs: PROC_SAMPLE_INTERVAL_MS,
    samples: sampleCount,
  };
  const peakRssKiB = peakVmHwmKiB ?? peakVmRssKiB;
  return {
    peakRssKiB,
    method: peakVmHwmKiB !== null ? 'linux-proc-status-vmhwm' : peakVmRssKiB !== null ? 'linux-proc-status-vmrss-sampled' : 'unavailable',
    scope: 'direct snarkjs child process; snarkjs workers are threads in this process',
    sampleIntervalMs: PROC_SAMPLE_INTERVAL_MS,
    samples: sampleCount,
  };
}
function boundedCapture(stream, limit) {
  const chunks = []; let bytes = 0; let truncated = false;
  stream.on('data', (chunk) => {
    if (bytes >= limit) { truncated = true; return; }
    const remaining = limit - bytes; const kept = chunk.subarray(0, remaining);
    chunks.push(kept); bytes += kept.length; if (kept.length !== chunk.length) truncated = true;
  });
  return () => ({ text: Buffer.concat(chunks).toString('utf8'), truncated });
}
async function run(tool, args, label, { allowedExitCodes = new Set([0]), captureStdout = false } = {}) {
  const started = now();
  const child = spawn(process.execPath, [tool.path, ...args], { stdio: ['ignore', captureStdout ? 'pipe' : 'ignore', 'pipe'] });
  const stderr = boundedCapture(child.stderr, STDERR_LIMIT_BYTES);
  const stdout = captureStdout ? boundedCapture(child.stdout, STDERR_LIMIT_BYTES) : () => ({ text: '', truncated: false });
  let samples = 0; let peakVmHwmKiB = null; let peakVmRssKiB = null; let procfsAvailable = process.platform === 'linux'; let sampling = false;
  const sample = async () => {
    if (!procfsAvailable || sampling || !child.pid) return;
    sampling = true;
    try {
      const status = parseLinuxProcStatus(await readFile(`/proc/${child.pid}/status`, 'utf8'));
      samples += 1;
      if (status.vmHwmKiB !== null) peakVmHwmKiB = Math.max(peakVmHwmKiB ?? 0, status.vmHwmKiB);
      if (status.vmRssKiB !== null) peakVmRssKiB = Math.max(peakVmRssKiB ?? 0, status.vmRssKiB);
    } catch { if (samples === 0) procfsAvailable = false; } finally { sampling = false; }
  };
  await sample();
  const interval = setInterval(() => { void sample(); }, PROC_SAMPLE_INTERVAL_MS);
  const result = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal }));
  }).finally(() => clearInterval(interval));
  await sample();
  const measured = memoryMeasurement({ sampleCount: samples, peakVmHwmKiB, peakVmRssKiB, procfsAvailable });
  const capturedStderr = stderr(); const capturedStdout = stdout();
  if (!allowedExitCodes.has(result.code)) fail(`${label} failed (exit ${result.code}${result.signal ? `, signal ${result.signal}` : ''})${capturedStderr.text.trim() ? `: ${capturedStderr.text.trim()}` : ''}${capturedStderr.truncated ? ' [stderr truncated]' : ''}`);
  return { elapsedMs: elapsed(started), memory: measured, stderrTruncated: capturedStderr.truncated, stdout: capturedStdout.text, stdoutTruncated: capturedStdout.truncated };
}
function digestLimbs(value, label) {
  if (!Array.isArray(value) || value.length !== 2) fail(`${label} must contain exactly two packet-digest limbs`);
  return value.map((limb, index) => canonicalDecimal(limb, `${label}[${index}]`));
}
async function parseManifest(filename) {
  let manifest;
  try { manifest = parseStrictJson(await readFile(filename, 'utf8'), 'manifest'); } catch (error) { if (error instanceof ProofCorpusError) throw error; fail(`manifest is invalid JSON: ${error.message}`); }
  exactKeys(manifest, 'manifest', ['schema', 'snarkjs', 'artifacts', 'actions', 'outputDirectory']);
  if (manifest.schema !== 'shield.cash/proof-corpus/v1') fail('unsupported manifest schema');
  exactKeys(manifest.artifacts, 'manifest.artifacts', ['r1cs', 'wasm', 'zkey', 'verificationKey']);
  if (!Array.isArray(manifest.actions) || manifest.actions.length !== 3) fail('manifest.actions must contain exactly deposit, transfer, and withdrawal');
  if (typeof manifest.outputDirectory !== 'string' || manifest.outputDirectory.length === 0) fail('manifest.outputDirectory must be a nonempty string');
  const actions = manifest.actions.map((action, index) => {
    exactKeys(action, `manifest.actions[${index}]`, ['kind', 'input', 'packetDigest']);
    if (!actionKinds.has(action.kind)) fail(`unknown action kind: ${action.kind}`);
    return { kind: action.kind, input: action.input, packetDigest: digestLimbs(action.packetDigest, `manifest.actions[${index}].packetDigest`) };
  });
  if (new Set(actions.map((action) => action.kind)).size !== 3) fail('action kinds must be unique');
  return { snarkjs: manifest.snarkjs, artifacts: manifest.artifacts, actions, outputDirectory: path.resolve(manifest.outputDirectory) };
}
async function privateDestination(destination) {
  const parent = path.dirname(destination);
  const stats = await lstat(parent).catch(() => fail(`output parent is missing: ${parent}`));
  if (!stats.isDirectory() || stats.isSymbolicLink() || await realpath(parent) !== parent) fail(`output parent must be a direct non-symlink directory: ${parent}`);
  if (await lstat(destination).catch(() => undefined)) fail(`refusing to overwrite output directory: ${destination}`);
  return path.join(parent, `.${path.basename(destination)}.staging-${randomUUID()}`);
}

export async function runProofCorpus(manifestFilename) {
  const manifest = await parseManifest(manifestFilename);
  const staging = await privateDestination(manifest.outputDirectory);
  const tool = await pinnedTool(manifest.snarkjs);
  const artifactRecords = await Promise.all(Object.entries(manifest.artifacts).map(async ([name, record]) => [name, await immutableFile(record, `artifacts.${name}`)]));
  const artifacts = Object.fromEntries(artifactRecords);
  const actions = [];
  for (const action of manifest.actions) actions.push({ ...action, input: await immutableFile(action.input, `actions.${action.kind}.input`) });
  const allInputs = [tool, ...Object.values(artifacts), ...actions.map((action) => action.input)];
  let published = false;
  try {
    await mkdir(staging, { mode: 0o700 });
    const report = { schema: 'shield.cash/proof-corpus-result/v1', qualification: 'non-qualification local execution only', snarkjs: tool, artifacts, actions: [] };
    for (const action of actions) {
      await stable(allInputs);
      const witness = path.join(staging, `${action.kind}.wtns`);
      const proof = path.join(staging, `${action.kind}.proof.json`);
      const publicSignals = path.join(staging, `${action.kind}.public.json`);
      const witnessGeneration = await run(tool, ['wtns', 'calculate', artifacts.wasm.path, action.input.path, witness], `${action.kind} witness generation`);
      const witnessCheck = await run(tool, ['wtns', 'check', artifacts.r1cs.path, witness], `${action.kind} witness check`);
      const proving = await run(tool, ['groth16', 'prove', artifacts.zkey.path, witness, proof, publicSignals], `${action.kind} proving`);
      const verification = await run(tool, ['groth16', 'verify', artifacts.verificationKey.path, publicSignals, proof], `${action.kind} local verification`);
      const normalizedPublic = digestLimbs(parseStrictJson(await readFile(publicSignals, 'utf8'), `${action.kind} public signals`), `${action.kind} public signals`);
      if (normalizedPublic[0] !== action.packetDigest[0] || normalizedPublic[1] !== action.packetDigest[1]) fail(`${action.kind} public limbs do not equal supplied packet digest`);
      await stable(allInputs);
      const outputs = await Promise.all([['witness', witness], ['proof', proof], ['publicSignals', publicSignals]].map(async ([name, filename]) => {
        const stats = await lstat(filename); if (!stats.isFile() || stats.isSymbolicLink()) fail(`${action.kind} generated a non-regular output: ${filename}`);
        return [name, { path: path.join(manifest.outputDirectory, path.basename(filename)), sha256: await sha256File(filename), bytes: stats.size }];
      }));
      report.actions.push({ kind: action.kind, packetDigest: action.packetDigest, witnessGeneration, witnessCheck, proving, verification, outputs: Object.fromEntries(outputs) });
    }
    await stable(allInputs);
    await writeFile(path.join(staging, 'result.json'), `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx' });
    if (await lstat(manifest.outputDirectory).catch(() => undefined)) fail(`refusing to overwrite output directory: ${manifest.outputDirectory}`);
    await rename(staging, manifest.outputDirectory); published = true;
    return report;
  } finally {
    if (!published) await rm(staging, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const manifest = process.argv[2];
  if (!manifest) { console.error('usage: proof-corpus.mjs MANIFEST.json'); process.exitCode = 2; }
  else runProofCorpus(manifest).then((result) => console.log(JSON.stringify({ outputActions: result.actions.map((action) => action.kind) }))).catch((error) => { console.error(error.message); process.exitCode = 1; });
}
