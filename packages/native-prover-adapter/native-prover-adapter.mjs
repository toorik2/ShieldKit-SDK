// Fail-closed local adapter for a caller-hash-pinned native Groth16 prover.
// It neither creates witnesses nor performs setup, network, or BCH activity.
import { createHash, randomUUID } from 'node:crypto';
import { lstat, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { spawn } from 'node:child_process';

const kinds = new Set(['deposit', 'transfer', 'withdrawal']);
const fail = (message) => { throw new NativeProverAdapterError(message); };
const exactKeys = (value, label, keys) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i])) fail(`${label} has unexpected keys`);
};
const sha = async (filename) => createHash('sha256').update(await readFile(filename)).digest('hex');
const regular = async (record, label, extraKeys = []) => {
  exactKeys(record, label, ['path', 'sha256', ...extraKeys]);
  if (typeof record.path !== 'string' || !/^[0-9a-f]{64}$/.test(record.sha256)) fail(`${label} is malformed`);
  const path = resolve(record.path); const stat = await lstat(path).catch(() => fail(`${label} is unavailable`));
  if (!stat.isFile() || stat.isSymbolicLink()) fail(`${label} must be a regular non-symlink file`);
  if (await sha(path) !== record.sha256) fail(`${label} SHA-256 mismatch`);
  return { path, sha256: record.sha256, bytes: stat.size };
};
const run = (command, args, label, { measure = false, allowedExitCodes = new Set([0]) } = {}) => new Promise((resolveRun, rejectRun) => {
  const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = ''; let stderr = ''; let peakHwm = 0; let peakRss = 0; let samples = 0;
  child.stdout.on('data', (data) => { stdout += data; }); child.stderr.on('data', (data) => { stderr += data; });
  const start = process.hrtime.bigint();
  const sample = async () => {
    if (!measure) return;
    try {
      samples += 1;
      for (const line of (await readFile(`/proc/${child.pid}/status`, 'utf8')).split('\n')) {
        const match = /^(VmHWM|VmRSS):\s+(\d+)\s+kB$/.exec(line); if (!match) continue;
        if (match[1] === 'VmHWM') peakHwm = Math.max(peakHwm, Number(match[2])); else peakRss = Math.max(peakRss, Number(match[2]));
      }
    } catch {}
  };
  void sample(); const timer = setInterval(() => void sample(), 10);
  child.on('error', (error) => { clearInterval(timer); rejectRun(error); });
  child.on('close', async (code, signal) => {
    clearInterval(timer); await sample(); const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;
    if (!allowedExitCodes.has(code)) return rejectRun(new NativeProverAdapterError(`${label} failed: exit=${code} signal=${signal ?? 'none'} stderr=${stderr.slice(0, 500)}`));
    resolveRun({ elapsedMs, stdout, stderr, memory: measure ? { peakRssKiB: peakHwm || peakRss, method: peakHwm ? 'linux-proc-status-vmhwm' : 'linux-proc-status-vmrss-sampled', scope: 'direct native prover process; OpenMP workers are threads in this process', sampleIntervalMs: 10, samples } : undefined });
  });
});
const strings = (value, label) => {
  if (!Array.isArray(value) || !value.every((item) => typeof item === 'string' && /^\d+$/.test(item))) fail(`${label} must be decimal strings`);
  return value;
};
const pinnedShape = (record, label, extraKeys = []) => {
  exactKeys(record, label, ['path', 'sha256', ...extraKeys]);
  if (typeof record.path !== 'string' || !/^[0-9a-f]{64}$/.test(record.sha256)) fail(`${label} is malformed`);
};

export class NativeProverAdapterError extends Error { constructor(message) { super(message); this.name = 'NativeProverAdapterError'; } }

export function parseManifest(value) {
  exactKeys(value, 'manifest', ['actions', 'artifacts', 'nativeProver', 'outputDirectory', 'repetitions', 'schema', 'snarkjs']);
  if (value.schema !== 'shield.cash/native-prover-adapter/v1') fail('manifest schema mismatch');
  if (typeof value.outputDirectory !== 'string' || value.outputDirectory.length === 0) fail('outputDirectory is required');
  if (!Number.isInteger(value.repetitions) || value.repetitions < 1 || value.repetitions > 10) fail('repetitions must be 1..10');
  exactKeys(value.artifacts, 'artifacts', ['verificationKey', 'zkey']);
  pinnedShape(value.nativeProver, 'nativeProver'); pinnedShape(value.artifacts.zkey, 'artifacts.zkey'); pinnedShape(value.artifacts.verificationKey, 'artifacts.verificationKey');
  exactKeys(value.snarkjs, 'snarkjs', ['path', 'sha256', 'version']);
  if (typeof value.snarkjs.version !== 'string' || !/^\d+\.\d+\.\d+$/.test(value.snarkjs.version)) fail('snarkjs version is malformed');
  pinnedShape(value.snarkjs, 'snarkjs', ['version']);
  if (!Array.isArray(value.actions) || value.actions.length !== 3) fail('actions must contain exactly three entries');
  const seen = new Set();
  for (const action of value.actions) {
    exactKeys(action, 'action', ['expectedPublicSignals', 'kind', 'witness']);
    if (!kinds.has(action.kind) || seen.has(action.kind)) fail('actions must be unique deposit, transfer, withdrawal');
    seen.add(action.kind); strings(action.expectedPublicSignals, `${action.kind}.expectedPublicSignals`);
    pinnedShape(action.witness, `${action.kind}.witness`);
  }
  return value;
}

export async function runNativeProverAdapter(manifestFilename) {
  const manifest = parseManifest(JSON.parse(await readFile(manifestFilename, 'utf8')));
  const nativeProver = await regular(manifest.nativeProver, 'nativeProver');
  const snarkjs = await regular(manifest.snarkjs, 'snarkjs', ['version']);
  const zkey = await regular(manifest.artifacts.zkey, 'artifacts.zkey');
  const verificationKey = await regular(manifest.artifacts.verificationKey, 'artifacts.verificationKey');
  const version = await run(process.execPath, [snarkjs.path, '--version'], 'pinned snarkjs version', { allowedExitCodes: new Set([0, 99]) }).catch(() => fail('pinned snarkjs version command failed'));
  if (!version.stdout.includes(`snarkjs@${manifest.snarkjs.version}`)) fail('pinned snarkjs version mismatch');
  const actions = [];
  for (const action of manifest.actions) actions.push({ ...action, witness: await regular(action.witness, `${action.kind}.witness`) });
  const output = resolve(manifest.outputDirectory); const parent = dirname(output);
  const parentStat = await lstat(parent).catch(() => fail('output parent is unavailable'));
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink() || await lstat(output).catch(() => undefined)) fail('output directory is unsafe or already exists');
  const staging = join(parent, `.${output.split('/').at(-1)}.staging-${randomUUID()}`); await mkdir(staging, { mode: 0o700 });
  let published = false;
  try {
    const result = { schema: 'shield.cash/native-prover-adapter-result/v1', qualification: 'initial feasibility only; not p95 hardware qualification', nativeProver, snarkjs: { ...snarkjs, version: manifest.snarkjs.version }, artifacts: { zkey, verificationKey }, repetitions: manifest.repetitions, actions: [] };
    for (const action of actions) {
      const runs = [];
      for (let index = 1; index <= manifest.repetitions; index += 1) {
        const proof = join(staging, `${action.kind}-${index}.proof.json`); const publicSignals = join(staging, `${action.kind}-${index}.public.json`);
        const proving = await run(nativeProver.path, [zkey.path, action.witness.path, proof, publicSignals], `${action.kind} native proving`, { measure: true });
        const verification = await run(process.execPath, [snarkjs.path, 'groth16', 'verify', verificationKey.path, publicSignals, proof], `${action.kind} pinned snarkjs verification`);
        const observed = strings(JSON.parse(await readFile(publicSignals, 'utf8')), `${action.kind} public signals`);
        if (JSON.stringify(observed) !== JSON.stringify(action.expectedPublicSignals)) fail(`${action.kind} public signals differ from manifest`);
        runs.push({ index, proving, verification: { elapsedMs: verification.elapsedMs, stdout: verification.stdout, stderr: verification.stderr }, outputs: { proof: { path: `${action.kind}-${index}.proof.json`, sha256: await sha(proof), bytes: (await lstat(proof)).size }, publicSignals: { path: `${action.kind}-${index}.public.json`, sha256: await sha(publicSignals), bytes: (await lstat(publicSignals)).size } } });
      }
      result.actions.push({ kind: action.kind, witness: action.witness, expectedPublicSignals: action.expectedPublicSignals, runs });
    }
    await writeFile(join(staging, 'result.json'), `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx' }); await rename(staging, output); published = true; return result;
  } finally { if (!published) await rm(staging, { recursive: true, force: true }); }
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const manifest = process.argv[2]; if (!manifest) { console.error('usage: native-prover-adapter.mjs MANIFEST.json'); process.exitCode = 2; }
  else runNativeProverAdapter(manifest).then((result) => console.log(JSON.stringify({ actions: result.actions.map((action) => action.kind) }))).catch((error) => { console.error(error.message); process.exitCode = 1; });
}
