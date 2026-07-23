// Fail-closed local Groth16 corpus executor. It consumes immutable caller
// artifacts only; it never runs setup or fetches network material.
import { createHash } from 'node:crypto';
import { execFile as execFileCallback } from 'node:child_process';
import { lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFile = promisify(execFileCallback);
const here = path.dirname(fileURLToPath(import.meta.url));
const snarkjsCli = path.join(here, 'node_modules', 'snarkjs', 'build', 'cli.cjs');
const actionKinds = new Set(['deposit', 'transfer', 'withdrawal']);
const decimal = /^(0|[1-9][0-9]*)$/;

export class ProofCorpusError extends Error {
  constructor(message) { super(message); this.name = 'ProofCorpusError'; }
}
const fail = (message) => { throw new ProofCorpusError(message); };
const now = () => process.hrtime.bigint();
const elapsed = (started) => Number(process.hrtime.bigint() - started) / 1e6;

function canonicalDecimal(value, label) {
  if (typeof value !== 'string' || !decimal.test(value)) fail(`${label} must be a canonical nonnegative decimal string`);
  return value;
}
function exactKeys(value, label, keys) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown properties`);
}
async function sha256File(filename) {
  const bytes = await readFile(filename);
  return createHash('sha256').update(bytes).digest('hex');
}
async function immutableFile(record, label) {
  exactKeys(record, label, ['path', 'sha256']);
  if (typeof record.path !== 'string' || record.path.length === 0) fail(`${label}.path must be a nonempty string`);
  if (!/^[0-9a-f]{64}$/.test(record.sha256)) fail(`${label}.sha256 must be lowercase SHA-256`);
  const resolved = path.resolve(record.path);
  const stats = await lstat(resolved).catch(() => fail(`${label} is missing: ${record.path}`));
  if (!stats.isFile() || stats.isSymbolicLink()) fail(`${label} must be a regular non-symlink file: ${record.path}`);
  const canonical = await realpath(resolved);
  if (canonical !== resolved) fail(`${label} resolves through a symlink: ${record.path}`);
  const sha256 = await sha256File(resolved);
  if (sha256 !== record.sha256) fail(`${label} SHA-256 mismatch: expected ${record.sha256}, got ${sha256}`);
  return Object.freeze({ path: resolved, sha256, bytes: stats.size });
}
async function stable(artifacts) {
  for (const artifact of artifacts) {
    const stats = await lstat(artifact.path);
    if (!stats.isFile() || stats.isSymbolicLink() || await realpath(artifact.path) !== artifact.path || await sha256File(artifact.path) !== artifact.sha256) {
      fail(`input artifact changed during execution: ${artifact.path}`);
    }
  }
}
async function run(command, args, label) {
  const started = now();
  try {
    await execFile(command, args, { maxBuffer: 16 * 1024 * 1024 });
  } catch (error) {
    const stderr = typeof error.stderr === 'string' ? error.stderr.trim() : '';
    fail(`${label} failed${stderr ? `: ${stderr}` : ''}`);
  }
  return {
    elapsedMs: elapsed(started),
    // Node exposes only this runner's resource usage, not a portable child
    // max-RSS result. Do not report it as a proof/prover measurement.
    peakRssKiB: null,
    peakRssScope: 'unavailable for execFile child process',
  };
}
function digestLimbs(value, label) {
  if (!Array.isArray(value) || value.length !== 2) fail(`${label} must contain exactly two packet-digest limbs`);
  return value.map((limb, index) => canonicalDecimal(limb, `${label}[${index}]`));
}
async function parseManifest(filename) {
  let manifest;
  try { manifest = JSON.parse(await readFile(filename, 'utf8')); } catch (error) { fail(`manifest is invalid JSON: ${error.message}`); }
  exactKeys(manifest, 'manifest', ['schema', 'artifacts', 'actions', 'outputDirectory']);
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
  return { artifacts: manifest.artifacts, actions, outputDirectory: path.resolve(manifest.outputDirectory) };
}

export async function runProofCorpus(manifestFilename) {
  const manifest = await parseManifest(manifestFilename);
  const outputStats = await lstat(manifest.outputDirectory).catch(() => undefined);
  if (outputStats) fail(`refusing to overwrite output directory: ${manifest.outputDirectory}`);
  const artifactRecords = await Promise.all(Object.entries(manifest.artifacts).map(async ([name, record]) => [name, await immutableFile(record, `artifacts.${name}`)]));
  const artifacts = Object.fromEntries(artifactRecords);
  const actions = [];
  for (const action of manifest.actions) actions.push({ ...action, input: await immutableFile(action.input, `actions.${action.kind}.input`) });
  await mkdir(manifest.outputDirectory, { recursive: false });
  const allInputs = [...Object.values(artifacts), ...actions.map((action) => action.input)];
  const report = {
    schema: 'shield.cash/proof-corpus-result/v1',
    qualification: 'non-qualification local execution only',
    artifacts,
    actions: [],
  };
  for (const action of actions) {
    await stable(allInputs);
    const witness = path.join(manifest.outputDirectory, `${action.kind}.wtns`);
    const proof = path.join(manifest.outputDirectory, `${action.kind}.proof.json`);
    const publicSignals = path.join(manifest.outputDirectory, `${action.kind}.public.json`);
    const witnessGeneration = await run(process.execPath, [snarkjsCli, 'wtns', 'calculate', artifacts.wasm.path, action.input.path, witness], `${action.kind} witness generation`);
    const witnessCheck = await run(process.execPath, [snarkjsCli, 'wtns', 'check', artifacts.r1cs.path, witness], `${action.kind} witness check`);
    const proving = await run(process.execPath, [snarkjsCli, 'groth16', 'prove', artifacts.zkey.path, witness, proof, publicSignals], `${action.kind} proving`);
    const verification = await run(process.execPath, [snarkjsCli, 'groth16', 'verify', artifacts.verificationKey.path, publicSignals, proof], `${action.kind} local verification`);
    const publicValues = JSON.parse(await readFile(publicSignals, 'utf8'));
    const normalizedPublic = digestLimbs(publicValues, `${action.kind} public signals`);
    if (normalizedPublic[0] !== action.packetDigest[0] || normalizedPublic[1] !== action.packetDigest[1]) fail(`${action.kind} public limbs do not equal supplied packet digest`);
    await stable(allInputs);
    const outputs = await Promise.all([['witness', witness], ['proof', proof], ['publicSignals', publicSignals]].map(async ([name, filename]) => {
      const stats = await lstat(filename);
      if (!stats.isFile() || stats.isSymbolicLink()) fail(`${action.kind} generated a non-regular output: ${filename}`);
      return [name, { path: filename, sha256: await sha256File(filename), bytes: stats.size }];
    }));
    report.actions.push({ kind: action.kind, packetDigest: action.packetDigest, witnessGeneration, witnessCheck, proving, verification, outputs: Object.fromEntries(outputs) });
  }
  await writeFile(path.join(manifest.outputDirectory, 'result.json'), `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx' });
  return report;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const manifest = process.argv[2];
  if (!manifest) { console.error('usage: proof-corpus.mjs MANIFEST.json'); process.exitCode = 2; }
  else runProofCorpus(manifest).then((result) => console.log(JSON.stringify({ outputActions: result.actions.map((action) => action.kind) }))).catch((error) => { console.error(error.message); process.exitCode = 1; });
}
