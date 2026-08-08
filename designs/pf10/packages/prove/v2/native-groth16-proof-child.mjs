import { spawn } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { availableParallelism } from 'node:os';
import { chmod, lstat, open, readFile, readdir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import * as snarkjs from 'snarkjs';

import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';
import { normalizeSnarkjsBn254Groth16Proof, parseStrictJson, sha256Bytes, sha256File } from '../groth16.mjs';

export const V2_NATIVE_GROTH16_PROOF_REQUEST_SCHEMA = 'shieldkit-v2-direct-native-groth16-proof-request-v1';
export const V2_NATIVE_GROTH16_PROOF_RESULT_SCHEMA = 'shieldkit-v2-direct-native-groth16-proof-result-v2';
const HASH = /^[0-9a-f]{64}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
const MAX_U128 = (1n << 128n) - 1n;
const ARTIFACTS = Object.freeze(['r1cs', 'wasm', 'provingKey', 'verificationKey']);
const RECEIPT_SCHEMA = 'shieldkit-v2-beta-receipt-bound-proof-artifacts-v1';
const MAX_NATIVE_OUTPUT = 64 * 1024;
const RAPIDSNARK_PROOF_KEYS = Object.freeze(['pi_a', 'pi_b', 'pi_c', 'protocol']);
const CANONICAL_PROOF_KEYS = Object.freeze([...RAPIDSNARK_PROOF_KEYS, 'curve']);

export class V2NativeGroth16ProofChildError extends Error { constructor(code, message, cause) { super(message, cause === undefined ? undefined : { cause }); this.name = 'V2NativeGroth16ProofChildError'; this.code = code; } }
export class V2NativeGroth16ProofShapeError extends Error { constructor(message) { super(message); this.name = 'V2NativeGroth16ProofShapeError'; } }
const fail = (code, message, cause) => { throw new V2NativeGroth16ProofChildError(code, message, cause); };
const object = (v, l) => { if (v === null || Array.isArray(v) || typeof v !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(v))) fail('NATIVE_PROVER_REQUEST_INVALID', `${l} must be an object`); return v; };
const exact = (v, keys, l) => { object(v, l); const a = Object.keys(v).sort(); const e = [...keys].sort(); if (a.length !== e.length || a.some((x, i) => x !== e[i])) fail('NATIVE_PROVER_REQUEST_INVALID', `${l} has missing or unknown properties`); return v; };
const absolute = (v, l) => { if (typeof v !== 'string' || !path.isAbsolute(v) || path.normalize(v) !== v || v.includes('\0')) fail('NATIVE_PROVER_REQUEST_INVALID', `${l} must be a normalized absolute path`); return v; };
const digest = (v, l) => { if (typeof v !== 'string' || !HASH.test(v)) fail('NATIVE_PROVER_REQUEST_INVALID', `${l} must be lowercase SHA-256`); return v; };
const inputs = (v, l = 'expectedPublicInputs') => { if (!Array.isArray(v) || v.length !== 2 || v.some((x) => typeof x !== 'string' || !DECIMAL.test(x) || BigInt(x) > MAX_U128)) fail('NATIVE_PROVER_REQUEST_INVALID', `${l} must contain exactly two canonical u128 strings`); return Object.freeze([...v]); };

const proofShapeFail = (message) => { throw new V2NativeGroth16ProofShapeError(message); };
const proofObject = (value, label) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) proofShapeFail(`${label} must be an object`);
  return value;
};
function proofRecord(value, { allowRapidsnarkCurveOmission }) {
  const raw = proofObject(value, 'native Groth16 proof');
  const actual = Object.keys(raw).sort();
  const rapid = [...RAPIDSNARK_PROOF_KEYS].sort();
  const canonical = [...CANONICAL_PROOF_KEYS].sort();
  const isRapidsnark = actual.length === rapid.length && actual.every((key, index) => key === rapid[index]);
  const isCanonical = actual.length === canonical.length && actual.every((key, index) => key === canonical[index]);
  if ((!allowRapidsnarkCurveOmission || !isRapidsnark) && !isCanonical) proofShapeFail('native Groth16 proof must have the exact pinned rapidsnark or canonical snarkjs shape');
  if (raw.protocol !== 'groth16') proofShapeFail('native Groth16 proof protocol must be groth16');
  if (isCanonical && raw.curve !== 'bn128') proofShapeFail('native Groth16 proof curve must be bn128');
  return normalizeSnarkjsBn254Groth16Proof({
    pi_a: raw.pi_a,
    pi_b: raw.pi_b,
    pi_c: raw.pi_c,
    protocol: 'groth16',
    curve: 'bn128',
  });
}

/** Canonicalize only the exact output shapes of the pinned rapidsnark/snarkjs toolchain. */
export function normalizeV2RapidsnarkGroth16Proof(value, verificationKey) {
  const key = proofObject(verificationKey, 'verification key');
  if (key.protocol !== 'groth16' || key.curve !== 'bn128') proofShapeFail('verification key must identify snarkjs BN254 Groth16');
  return proofRecord(value, { allowRapidsnarkCurveOmission: true });
}

/** Revalidate the exact canonical proof contract at the parent-process boundary. */
export function parseV2CanonicalNativeGroth16Proof(value) {
  return proofRecord(value, { allowRapidsnarkCurveOmission: false });
}

function fileIdentity(stat) { return Object.freeze({ dev: stat.dev.toString(), ino: stat.ino.toString(), mode: stat.mode.toString(), uid: stat.uid.toString(), gid: stat.gid.toString(), size: stat.size.toString(), nlink: stat.nlink.toString(), mtimeNs: stat.mtimeNs.toString(), ctimeNs: stat.ctimeNs.toString(), birthtimeNs: stat.birthtimeNs.toString() }); }
const same = (a, b) => ['dev', 'ino', 'mode', 'uid', 'gid', 'size', 'nlink', 'mtimeNs', 'ctimeNs', 'birthtimeNs'].every((name) => a[name] === b[name]);
function receiptIdentity(value, label) { exact(value, ['birthtimeNs', 'ctimeNs', 'dev', 'gid', 'ino', 'mode', 'mtimeNs', 'nlink', 'size', 'uid'], `${label}.identity`); if (Object.values(value).some((part) => typeof part !== 'string' || !/^[0-9]+$/u.test(part))) fail('NATIVE_PROVER_REQUEST_INVALID', `${label}.identity is invalid`); return Object.freeze({ ...value }); }
async function regular(filename, label, executable = false) {
  const before = await lstat(filename, { bigint: true }).catch((e) => fail('NATIVE_PROVER_ARTIFACT_UNAVAILABLE', `${label} is unavailable`, e));
  const owner = process.getuid === undefined || before.uid === BigInt(process.getuid()); const privateMode = executable ? (before.mode & 0o777n) === 0o700n : (before.mode & 0o777n) === 0o600n;
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || !owner || !privateMode || await realpath(filename) !== filename) fail('NATIVE_PROVER_ARTIFACT_UNAVAILABLE', `${label} must be a private owner-controlled canonical non-hardlinked regular${executable ? ' executable' : ''} file`);
  return fileIdentity(before);
}
async function receipt(record, label, executable = false) { exact(record, ['identity', 'path', 'sha256'], label); const filename = absolute(record.path, `${label}.path`); const expected = digest(record.sha256, `${label}.sha256`); const identity = receiptIdentity(record.identity, label); if (!same(identity, await regular(filename, label, executable))) fail('NATIVE_PROVER_ARTIFACT_CHANGED', `${label} differs from its verified warm receipt`); return Object.freeze({ path: filename, sha256: expected, identity, executable }); }
async function pin(record, label, executable = false) {
  exact(record, ['path', 'sha256'], label); const filename = absolute(record.path, `${label}.path`); const expected = digest(record.sha256, `${label}.sha256`); const identity = await regular(filename, label, executable); const measured = await sha256File(filename);
  if (measured !== expected || !same(identity, await regular(filename, label, executable))) fail('NATIVE_PROVER_ARTIFACT_HASH_MISMATCH', `${label} is not its exact pinned regular file`);
  return Object.freeze({ path: filename, sha256: measured, identity, executable });
}
async function unchanged(record, label, rehash = false) { if (!same(record.identity, await regular(record.path, label, record.executable)) || rehash && await sha256File(record.path) !== record.sha256) fail('NATIVE_PROVER_ARTIFACT_CHANGED', `${label} changed while proving`); }
function receiptBundle(value) { exact(value, ['artifacts', 'installationReceiptSha256', 'schema'], 'native proof request.artifacts'); if (value.schema !== RECEIPT_SCHEMA || typeof value.installationReceiptSha256 !== 'string' || !HASH.test(value.installationReceiptSha256)) fail('NATIVE_PROVER_REQUEST_INVALID', 'native proof request artifacts are not receipt-bound'); exact(value.artifacts, ARTIFACTS, 'native proof request.artifact entries'); return value; }

function request(value) {
  exact(value, ['artifacts', 'expectedPublicInputs', 'failurePath', 'input', 'nativeProver', 'nativeProofPath', 'nativePublicPath', 'outputPath', 'schema', 'witnessPath'], 'native proof request');
  if (value.schema !== V2_NATIVE_GROTH16_PROOF_REQUEST_SCHEMA) fail('NATIVE_PROVER_REQUEST_INVALID', 'native proof request schema is unsupported');
  const artifacts = receiptBundle(value.artifacts); exact(value.input, ['path', 'sha256'], 'native proof request.input'); exact(value.nativeProver, ['identity', 'path', 'sha256'], 'native proof request.nativeProver');
  return Object.freeze({ schema: value.schema, artifacts: Object.freeze({ schema: artifacts.schema, installationReceiptSha256: artifacts.installationReceiptSha256, artifacts: Object.freeze(Object.fromEntries(ARTIFACTS.map((name) => [name, artifacts.artifacts[name]]))) }), nativeProver: value.nativeProver, expectedPublicInputs: inputs(value.expectedPublicInputs), input: value.input, witnessPath: absolute(value.witnessPath, 'witnessPath'), nativeProofPath: absolute(value.nativeProofPath, 'nativeProofPath'), nativePublicPath: absolute(value.nativePublicPath, 'nativePublicPath'), outputPath: absolute(value.outputPath, 'outputPath'), failurePath: absolute(value.failurePath, 'failurePath') });
}
async function writeExclusive(filename, value) { const bytes = Buffer.from(canonicalizeJcs(value), 'utf8'); const h = await open(filename, 'wx', 0o600); try { await h.writeFile(bytes); await h.chmod(0o600); await h.sync(); } finally { await h.close(); } return sha256Bytes(bytes); }
function taskTicks(stat) { const fields = stat.slice(stat.lastIndexOf(')') + 2).trim().split(/\s+/u); const userTicks = Number(fields[11]); const systemTicks = Number(fields[12]); if (![userTicks, systemTicks].every(Number.isSafeInteger)) fail('NATIVE_PROVER_METRICS_UNAVAILABLE', 'native prover task /proc ticks are malformed'); return userTicks + systemTicks; }
async function procMetrics(pid) {
  try {
    const [status, stat, taskNames] = await Promise.all([
      readFile(`/proc/${pid}/status`, 'utf8'), readFile(`/proc/${pid}/stat`, 'utf8'), readdir(`/proc/${pid}/task`),
    ]);
    const taskEntries = (await Promise.all(taskNames.map(async (name) => {
      try { return [name, taskTicks(await readFile(`/proc/${pid}/task/${name}/stat`, 'utf8'))]; }
      catch (error) { if (error?.code === 'ENOENT') return null; throw error; }
    }))).filter((entry) => entry !== null);
    const threads = Number(/^Threads:\s*([0-9]+)$/mu.exec(status)?.[1]); const rss = Number(/^VmHWM:\s*([0-9]+)\s+kB$/mu.exec(status)?.[1]);
    const fields = stat.slice(stat.lastIndexOf(')') + 2).trim().split(/\s+/u); const userTicks = Number(fields[11]); const systemTicks = Number(fields[12]);
    if (![threads, rss, userTicks, systemTicks].every(Number.isSafeInteger) || taskEntries.some(([, ticks]) => !Number.isSafeInteger(ticks))) fail('NATIVE_PROVER_METRICS_UNAVAILABLE', 'native prover /proc metrics are malformed');
    return { threads, peakRssKiB: rss, userTicks, systemTicks, taskTicks: new Map(taskEntries) };
  } catch (error) { fail('NATIVE_PROVER_METRICS_UNAVAILABLE', 'native prover /proc metrics are unavailable', error); }
}
async function runNative({ binary, args, nproc }) {
  const start = performance.now(); const child = spawn(binary, args, { shell: false, stdio: ['ignore', 'pipe', 'pipe'], env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin', TZ: 'UTC', OMP_DYNAMIC: 'FALSE', OMP_NUM_THREADS: String(nproc) } });
  let stdout = 0; let stderr = 0; let last; let maximumThreads = 0; let peakRssKiB = 0; const priorTaskTicks = new Map(); const activeTaskIds = new Set();
  const sample = async () => { if (child.pid === undefined) return; const current = await procMetrics(child.pid); last = current; maximumThreads = Math.max(maximumThreads, current.threads, current.taskTicks.size); peakRssKiB = Math.max(peakRssKiB, current.peakRssKiB); for (const [id, ticks] of current.taskTicks) { if (ticks > (priorTaskTicks.get(id) ?? ticks)) activeTaskIds.add(id); priorTaskTicks.set(id, ticks); } };
  child.stdout.on('data', (x) => { stdout += x.length; }); child.stderr.on('data', (x) => { stderr += x.length; });
  // Register terminal listeners before the first asynchronous /proc read. A
  // fast child may otherwise exit between spawn and listener registration,
  // permanently losing its one `close` event and hanging the caller.
  const terminalPromise = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal })); });
  let timer;
  let terminal;
  try {
    await sample();
    timer = setInterval(() => { sample().catch(() => {}); }, 25);
    terminal = await terminalPromise;
  } catch (error) {
    await terminalPromise.catch(() => {});
    throw error;
  } finally {
    if (timer !== undefined) clearInterval(timer);
  }
  if (stdout > MAX_NATIVE_OUTPUT || stderr > MAX_NATIVE_OUTPUT) fail('NATIVE_PROVER_OUTPUT_EXCESSIVE', 'native prover emitted excessive output');
  if (terminal.code !== 0 || terminal.signal !== null) fail('NATIVE_PROVER_EXIT', `native prover failed (${terminal.signal ?? `exit ${terminal.code}`})`);
  if (last === undefined) fail('NATIVE_PROVER_METRICS_UNAVAILABLE', 'native prover emitted no measurable process metrics');
  return Object.freeze({ elapsedMs: performance.now() - start, threads: maximumThreads, activeCpuThreads: activeTaskIds.size, peakRssKiB, userTicks: last.userTicks, systemTicks: last.systemTicks, ompThreads: nproc });
}

export async function executeV2NativeGroth16ProofRequest(value, { snarkjsApi = snarkjs, nproc = undefined } = {}) {
  const production = nproc === undefined;
  const configuredNproc = production ? availableParallelism() : nproc;
  if (!Number.isSafeInteger(configuredNproc) || configuredNproc < 1 || configuredNproc > 1024) fail('NATIVE_PROVER_ENVIRONMENT_INVALID', 'nproc must be a bounded positive integer');
  const r = request(value); const artifacts = Object.freeze(Object.fromEntries(await Promise.all(ARTIFACTS.map(async (name) => [name, await receipt(r.artifacts.artifacts[name], `artifact ${name}`)])))); const binary = await receipt(r.nativeProver, 'native prover', true);
  const input = await pin(r.input, 'circuit input'); const inputBytes = await readFile(input.path); if (sha256Bytes(inputBytes) !== input.sha256) fail('NATIVE_PROVER_INPUT_HASH_MISMATCH', 'circuit input changed while reading'); const circuitInput = parseStrictJson(inputBytes, 'circuit input'); const vkBytes = await readFile(artifacts.verificationKey.path); if (sha256Bytes(vkBytes) !== artifacts.verificationKey.sha256 || !same(artifacts.verificationKey.identity, await regular(artifacts.verificationKey.path, 'artifact verificationKey'))) fail('NATIVE_PROVER_ARTIFACT_CHANGED', 'verification key changed while reading'); const vk = parseStrictJson(vkBytes, 'verification key');
  const started = performance.now(); const witnessStarted = performance.now(); await snarkjsApi.wtns.calculate(circuitInput, artifacts.wasm.path, r.witnessPath); await chmod(r.witnessPath, 0o600); const witnessCalculation = performance.now() - witnessStarted;
  const native = await runNative({ binary: binary.path, args: [artifacts.provingKey.path, r.witnessPath, r.nativeProofPath, r.nativePublicPath], nproc: configuredNproc });
  if (production && native.activeCpuThreads < configuredNproc) fail('NATIVE_PROVER_ALL_CORE_EVIDENCE_UNAVAILABLE', 'native prover did not prove CPU-tick activity on every available core');
  // parseStrictJson deliberately produces null-prototype records. Normalize the
  // accepted native proof before placing it in the JCS-serialized result, whose
  // serializer intentionally accepts only ordinary JSON objects.
  let proof;
  try { proof = normalizeV2RapidsnarkGroth16Proof(parseStrictJson(await readFile(r.nativeProofPath), 'native proof'), vk); }
  catch (error) { fail('NATIVE_PROVER_PROOF_SHAPE_INVALID', `native proof has an invalid producer shape: ${error.message}`, error); }
  const publicInputs = inputs(parseStrictJson(await readFile(r.nativePublicPath), 'native public signals'), 'native public signals'); if (publicInputs.some((x, i) => x !== r.expectedPublicInputs[i])) fail('NATIVE_PROVER_PUBLIC_INPUT_MISMATCH', 'native public inputs differ from the exact expected inputs'); const verifyStarted = performance.now(); if (!await snarkjsApi.groth16.verify(vk, publicInputs, proof)) fail('NATIVE_PROVER_PROOF_INVALID', 'native proof does not verify under the pinned verification key'); const proofVerification = performance.now() - verifyStarted;
  await Promise.all([...ARTIFACTS.map((name) => unchanged(artifacts[name], `artifact ${name}`)), unchanged(binary, 'native prover'), unchanged(input, 'circuit input', true)]);
  const result = { schema: V2_NATIVE_GROTH16_PROOF_RESULT_SCHEMA, claims: { proofVerified: true, witnessCalculated: true, witnessR1csChecked: false }, sourceHashes: Object.fromEntries(ARTIFACTS.map((name) => [name, artifacts[name].sha256])), nativeProver: { backend: 'rapidsnark', sha256: binary.sha256, ompThreads: native.ompThreads, threads: native.threads, activeCpuThreads: native.activeCpuThreads, peakRssKiB: native.peakRssKiB, userTicks: native.userTicks, systemTicks: native.systemTicks }, inputSha256: input.sha256, proof, publicInputs, timingsMs: { witnessCalculation, proofGeneration: native.elapsedMs, proofVerification, total: performance.now() - started } }; await writeExclusive(r.outputPath, result); return Object.freeze(result);
}
async function main() { const filename = absolute(process.argv[2], 'native proof request filename'); const r = request(parseStrictJson(await readFile(filename), 'native proof request')); try { await executeV2NativeGroth16ProofRequest(r); } catch (e) { await writeExclusive(r.failurePath, { schema: 'shieldkit-v2-direct-native-groth16-proof-failure-v1', code: typeof e?.code === 'string' ? e.code : 'NATIVE_PROVER_CHILD_FAILED', message: e instanceof Error ? e.message : String(e) }).catch(() => {}); throw e; } }
if (typeof process.argv[1] === 'string' && import.meta.url === pathToFileURL(process.argv[1]).href) main().then(() => process.exit(0), (e) => { process.stderr.write(`${e?.code ?? 'NATIVE_PROVER_CHILD_FAILED'}: ${e.message}\n`); process.exit(1); });
