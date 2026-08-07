import { spawn as nodeSpawn } from 'node:child_process';
import { readFile as nodeReadFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const PROVER_MEMORY_MAX_BYTES = 4_294_967_296;
export const PROVER_MEMORY_SWAP_MAX_BYTES = 0;
export const CGROUP_EVIDENCE_PREFIX = 'SHIELDKIT_CGROUP_EVIDENCE_V1 ';
export const PROVER_WORKER_ENVIRONMENT = Object.freeze({
  LANG: 'C',
  LC_ALL: 'C',
  PATH: '/usr/bin:/bin',
  TZ: 'UTC',
});

const CHILD_ENTRYPOINT = fileURLToPath(
  new URL('./linux-cgroup-v2-child.mjs', import.meta.url),
);
const SIGNAL_NUMBER = Object.freeze({
  SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGILL: 4, SIGTRAP: 5, SIGABRT: 6,
  SIGBUS: 7, SIGFPE: 8, SIGKILL: 9, SIGUSR1: 10, SIGSEGV: 11, SIGUSR2: 12,
  SIGPIPE: 13, SIGALRM: 14, SIGTERM: 15,
});

export class LinuxCgroupV2WorkerError extends Error {
  constructor(code, message, evidence = undefined, cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'LinuxCgroupV2WorkerError';
    this.code = code;
    this.evidence = evidence;
  }
}

const fail = (code, message, evidence, cause) => {
  throw new LinuxCgroupV2WorkerError(code, message, evidence, cause);
};

function exactKeys(value, expected, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', `${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', `${label} has missing or unknown properties`);
  }
  return value;
}

function executable(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0')) {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', `${label} must be an absolute executable path`);
  }
  return value;
}

function argumentArray(value, label) {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || item.includes('\0'))) {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', `${label} must be an argv string array`);
  }
  return Object.freeze([...value]);
}

function integer(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', `${label} must be a nonnegative safe integer`);
  }
  return value;
}

function cgroupRelativePath(text) {
  if (typeof text !== 'string') {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'cgroup membership must be text');
  }
  const record = text.split('\n').find((line) => line.startsWith('0::'));
  if (record === undefined) {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'cgroup v2 membership is unavailable');
  }
  const relative = record.slice(3);
  if (!relative.startsWith('/') || relative.includes('\0') || relative.split('/').includes('..')) {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'cgroup v2 membership is malformed');
  }
  return relative;
}

function parseLimit(value, label) {
  const trimmed = value.trim();
  if (!/^(0|[1-9][0-9]*)$/.test(trimmed)) {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', `${label} must be a finite decimal cgroup limit`);
  }
  return trimmed;
}

function parseMemoryEvents(value) {
  const result = Object.create(null);
  for (const line of value.trim().split('\n')) {
    if (line.length === 0) continue;
    const match = /^([a-z_]+) ([0-9]+)$/.exec(line);
    if (!match) fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'memory.events is malformed');
    result[match[1]] = Number(match[2]);
  }
  if (!Number.isSafeInteger(result.oom) || !Number.isSafeInteger(result.oom_kill)) {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'memory.events lacks oom counters');
  }
  return Object.freeze({ oom: result.oom, oomKill: result.oom_kill });
}

/** Read this process' cgroup-v2 memory limits; no fallback is permitted. */
export async function readLinuxCgroupV2Evidence({
  readFile = nodeReadFile,
  cgroupRoot = '/sys/fs/cgroup',
  procCgroupPath = '/proc/self/cgroup',
} = {}) {
  if (typeof readFile !== 'function') {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'readFile seam must be a function');
  }
  if (!path.isAbsolute(cgroupRoot) || !path.isAbsolute(procCgroupPath)) {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'cgroup probe paths must be absolute');
  }
  let membership;
  try {
    membership = await readFile(procCgroupPath, 'utf8');
  } catch (error) {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'cannot read cgroup v2 membership', undefined, error);
  }
  const relative = cgroupRelativePath(membership);
  // Strip the cgroup-relative leading slash explicitly. This keeps the
  // resolved control files beneath the configured cgroup root.
  const directory = path.join(cgroupRoot, relative.slice(1));
  let memoryMax;
  let memorySwapMax;
  let memoryPeak;
  let memoryEvents;
  try {
    [memoryMax, memorySwapMax, memoryPeak, memoryEvents] = await Promise.all([
      readFile(path.join(directory, 'memory.max'), 'utf8'),
      readFile(path.join(directory, 'memory.swap.max'), 'utf8'),
      readFile(path.join(directory, 'memory.peak'), 'utf8'),
      readFile(path.join(directory, 'memory.events'), 'utf8'),
    ]);
  } catch (error) {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'cannot read cgroup-v2 memory controls', undefined, error);
  }
  return Object.freeze({
    cgroup: relative,
    memoryMax: parseLimit(memoryMax, 'memory.max'),
    memorySwapMax: parseLimit(memorySwapMax, 'memory.swap.max'),
    memoryPeak: parseLimit(memoryPeak, 'memory.peak'),
    memoryEvents: parseMemoryEvents(memoryEvents),
  });
}

export function assertRequiredCgroupLimits(evidence) {
  exactKeys(
    evidence,
    ['cgroup', 'memoryEvents', 'memoryMax', 'memoryPeak', 'memorySwapMax'],
    'cgroup evidence',
  );
  if (
    typeof evidence.cgroup !== 'string'
    || evidence.memoryMax !== String(PROVER_MEMORY_MAX_BYTES)
    || evidence.memorySwapMax !== String(PROVER_MEMORY_SWAP_MAX_BYTES)
    || !/^(0|[1-9][0-9]*)$/.test(evidence.memoryPeak)
  ) {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'cgroup memory limits do not match the required proof-worker policy', evidence);
  }
  exactKeys(evidence.memoryEvents, ['oom', 'oomKill'], 'cgroup evidence.memoryEvents');
  integer(evidence.memoryEvents.oom, 'cgroup evidence.memoryEvents.oom');
  integer(evidence.memoryEvents.oomKill, 'cgroup evidence.memoryEvents.oomKill');
  return Object.freeze({ ...evidence, memoryEvents: Object.freeze({ ...evidence.memoryEvents }) });
}

export function systemdRunProofWorkerArgv({ command, arguments: inputArguments }, {
  systemdRun = '/usr/bin/systemd-run',
  node = process.execPath,
  childEntrypoint = CHILD_ENTRYPOINT,
} = {}) {
  executable(systemdRun, 'systemd-run');
  executable(node, 'node');
  executable(childEntrypoint, 'childEntrypoint');
  const workerCommand = executable(command, 'command');
  const workerArguments = argumentArray(inputArguments, 'arguments');
  return Object.freeze([
    '--user', '--scope', '--quiet', '--collect',
    '-p', `MemoryMax=${PROVER_MEMORY_MAX_BYTES}`,
    '-p', `MemorySwapMax=${PROVER_MEMORY_SWAP_MAX_BYTES}`,
    node, childEntrypoint, '--', workerCommand, ...workerArguments,
  ]);
}

function spawnAndCollect(command, args) {
  return new Promise((resolve, reject) => {
    const child = nodeSpawn(command, args, {
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: process.env,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', (exitCode, signal) => resolve(Object.freeze({
      exitCode,
      signal,
      stdout,
      stderr,
    })));
  });
}

function controlReports(stdout) {
  if (typeof stdout !== 'string') {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'systemd-run stdout is unavailable');
  }
  const reports = [];
  for (const line of stdout.split('\n')) {
    if (line.length === 0) continue;
    if (!line.startsWith(CGROUP_EVIDENCE_PREFIX)) {
      fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'proof worker emitted unexpected stdout before containment could be verified');
    }
    let parsed;
    try { parsed = JSON.parse(line.slice(CGROUP_EVIDENCE_PREFIX.length)); }
    catch (error) { fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'proof worker emitted malformed containment evidence', undefined, error); }
    reports.push(parsed);
  }
  if (reports.length !== 2) {
    fail(
      'PROVER_MEMORY_GUARD_UNAVAILABLE',
      'proof worker must emit exactly one limits and one termination report',
    );
  }
  return reports;
}

function limitsReport(reports) {
  const result = reports[0];
  exactKeys(result, ['evidence', 'phase'], 'proof worker limits evidence');
  if (result.phase !== 'limits') {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'proof worker did not report cgroup readback evidence');
  }
  return assertRequiredCgroupLimits(result.evidence);
}

function terminationReport(reports) {
  const result = reports[1];
  exactKeys(
    result,
    ['exitCode', 'memoryEvents', 'memoryPeak', 'phase', 'signal'],
    'proof worker termination evidence',
  );
  if (result.phase !== 'termination') {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'proof worker termination evidence is out of order');
  }
  if (result.exitCode !== null) integer(result.exitCode, 'proof worker termination exitCode');
  if (result.signal !== null && (typeof result.signal !== 'string' || !Object.hasOwn(SIGNAL_NUMBER, result.signal))) {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'proof worker termination signal is invalid');
  }
  exactKeys(result.memoryEvents, ['oom', 'oomKill'], 'proof worker termination memoryEvents');
  integer(result.memoryEvents.oom, 'proof worker termination memoryEvents.oom');
  integer(result.memoryEvents.oomKill, 'proof worker termination memoryEvents.oomKill');
  if (!/^(0|[1-9][0-9]*)$/.test(result.memoryPeak)) {
    fail(
      'PROVER_MEMORY_GUARD_UNAVAILABLE',
      'proof worker termination memory.peak is invalid',
    );
  }
  return Object.freeze({
    exitCode: result.exitCode,
    signal: result.signal,
    memoryPeak: result.memoryPeak,
    memoryEvents: Object.freeze({ ...result.memoryEvents }),
  });
}

function failureFromTermination(termination, evidence) {
  if (termination.memoryEvents.oomKill > evidence.memoryEvents.oomKill) {
    fail('PROVER_WORKER_OOM', 'proof worker was killed by the cgroup memory limit', Object.freeze({ evidence, termination }));
  }
  if (termination.signal !== null) {
    fail('PROVER_WORKER_SIGNAL', `proof worker terminated by ${termination.signal}`, Object.freeze({ evidence, termination }));
  }
  if (termination.exitCode !== 0) {
    fail('PROVER_WORKER_EXIT', `proof worker exited with status ${termination.exitCode}`, Object.freeze({ evidence, termination }));
  }
}

/**
 * Launch exactly one command in a user-systemd cgroup-v2 scope. The worker
 * reports its own cgroup readback before executing the requested command.
 */
export async function runLinuxCgroupV2ProofWorker(input, {
  platform = process.platform,
  spawn = spawnAndCollect,
  systemdRun,
  node,
  childEntrypoint,
} = {}) {
  exactKeys(input, ['arguments', 'command'], 'proof worker input');
  if (platform !== 'linux') {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'Linux cgroup-v2 proof-worker containment is unavailable on this platform');
  }
  if (typeof spawn !== 'function') {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'spawn seam must be a function');
  }
  const systemdExecutable = systemdRun ?? '/usr/bin/systemd-run';
  const args = systemdRunProofWorkerArgv(input, {
    systemdRun: systemdExecutable,
    ...(node === undefined ? {} : { node }),
    ...(childEntrypoint === undefined ? {} : { childEntrypoint }),
  });
  let result;
  try {
    result = await spawn(systemdExecutable, args);
  } catch (error) {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'unable to launch user systemd proof-worker scope', undefined, error);
  }
  exactKeys(result, ['exitCode', 'signal', 'stderr', 'stdout'], 'systemd-run result');
  if (result.exitCode !== null) integer(result.exitCode, 'systemd-run exitCode');
  if (result.signal !== null && (typeof result.signal !== 'string' || !Object.hasOwn(SIGNAL_NUMBER, result.signal))) {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'systemd-run signal is invalid');
  }
  if (typeof result.stderr !== 'string') fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'systemd-run stderr is unavailable');
  const reports = controlReports(result.stdout);
  const evidence = limitsReport(reports);
  const termination = terminationReport(reports);
  if (termination === undefined) {
    if (result.signal !== null) {
      fail('PROVER_WORKER_SIGNAL', `proof-worker scope terminated by ${result.signal}`, Object.freeze({ evidence, systemdRun: result }));
    }
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'proof worker did not report termination evidence', Object.freeze({ evidence, systemdRun: result }));
  }
  failureFromTermination(termination, evidence);
  if (result.signal !== null || result.exitCode !== 0) {
    fail('PROVER_MEMORY_GUARD_UNAVAILABLE', 'systemd-run scope disagrees with successful proof-worker termination', Object.freeze({ evidence, termination, systemdRun: result }));
  }
  return Object.freeze({
    backend: 'linux-systemd-cgroup-v2',
    command: input.command,
    arguments: Object.freeze([...input.arguments]),
    containment: evidence,
    termination,
  });
}
