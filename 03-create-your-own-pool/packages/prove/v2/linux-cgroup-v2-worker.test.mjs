import assert from 'node:assert/strict';
import test from 'node:test';

import {
  CGROUP_EVIDENCE_PREFIX,
  LinuxCgroupV2WorkerError,
  PROVER_MEMORY_MAX_BYTES,
  PROVER_MEMORY_SWAP_MAX_BYTES,
  PROVER_WORKER_ENVIRONMENT,
  readLinuxCgroupV2Evidence,
  runLinuxCgroupV2ProofWorker,
  systemdRunProofWorkerArgv,
} from './linux-cgroup-v2-worker.mjs';

const limits = ({ oom = 0, oomKill = 0, memoryPeak = '65536' } = {}) => ({
  cgroup: '/user.slice/user-1000.slice/app.slice/proof.scope',
  memoryMax: String(PROVER_MEMORY_MAX_BYTES),
  memorySwapMax: String(PROVER_MEMORY_SWAP_MAX_BYTES),
  memoryPeak,
  memoryEvents: { oom, oomKill },
});
const report = (value) => `${CGROUP_EVIDENCE_PREFIX}${JSON.stringify(value)}\n`;
const workerInput = Object.freeze({ command: '/usr/bin/node', arguments: Object.freeze(['worker.mjs', '--literal=$HOME', ';touch /tmp/not-executed']) });
const success = () => Object.freeze({
  exitCode: 0,
  signal: null,
  stderr: '',
  stdout: report({ phase: 'limits', evidence: limits() })
    + report({
      phase: 'termination',
      exitCode: 0,
      signal: null,
      memoryPeak: '131072',
      memoryEvents: { oom: 0, oomKill: 0 },
    }),
});

test('constructs a fixed argv systemd scope without shell interpolation', () => {
  const argv = systemdRunProofWorkerArgv(workerInput, {
    systemdRun: '/usr/bin/systemd-run',
    node: '/usr/bin/node',
    childEntrypoint: '/opt/shieldkit/linux-cgroup-v2-child.mjs',
  });
  assert.deepEqual(argv, [
    '--user', '--scope', '--quiet', '--collect',
    '-p', 'MemoryMax=4294967296',
    '-p', 'MemorySwapMax=0',
    '/usr/bin/node', '/opt/shieldkit/linux-cgroup-v2-child.mjs', '--',
    '/usr/bin/node', 'worker.mjs', '--literal=$HOME', ';touch /tmp/not-executed',
  ]);
  assert.throws(
    () => systemdRunProofWorkerArgv({ command: 'node', arguments: [] }),
    /absolute executable path/,
  );
});

test('reads the current cgroup limits through an injectable probe seam', async () => {
  const files = new Map([
    ['/proc/self/cgroup', '0::/user.slice/user-1000.slice/app.slice/proof.scope\n'],
    ['/sys/fs/cgroup/user.slice/user-1000.slice/app.slice/proof.scope/memory.max', '4294967296\n'],
    ['/sys/fs/cgroup/user.slice/user-1000.slice/app.slice/proof.scope/memory.swap.max', '0\n'],
    ['/sys/fs/cgroup/user.slice/user-1000.slice/app.slice/proof.scope/memory.peak', '65536\n'],
    ['/sys/fs/cgroup/user.slice/user-1000.slice/app.slice/proof.scope/memory.events', 'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n'],
  ]);
  const evidence = await readLinuxCgroupV2Evidence({
    readFile: async (filename) => {
      if (!files.has(filename)) throw new Error(`unexpected read: ${filename}`);
      return files.get(filename);
    },
  });
  assert.deepEqual(evidence, limits());
});

test('returns verified containment evidence only after exact cgroup readback', async () => {
  const calls = [];
  const result = await runLinuxCgroupV2ProofWorker(workerInput, {
    platform: 'linux',
    systemdRun: '/opt/shieldkit/systemd-run',
    childEntrypoint: '/opt/shieldkit/linux-cgroup-v2-child.mjs',
    spawn: async (command, args) => {
      calls.push({ command, args });
      return success();
    },
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, '/opt/shieldkit/systemd-run');
  assert.equal(calls[0].args.includes('--literal=$HOME'), true);
  assert.equal(calls[0].args.includes(';touch /tmp/not-executed'), true);
  assert.equal(result.backend, 'linux-systemd-cgroup-v2');
  assert.deepEqual(result.containment, limits());
  assert.deepEqual(result.termination, {
    exitCode: 0,
    signal: null,
    memoryPeak: '131072',
    memoryEvents: { oom: 0, oomKill: 0 },
  });
  assert.deepEqual(PROVER_WORKER_ENVIRONMENT, {
    LANG: 'C',
    LC_ALL: 'C',
    PATH: '/usr/bin:/bin',
    TZ: 'UTC',
  });
});

test('fails closed for unavailable containment and mismatched readback', async () => {
  await assert.rejects(
    () => runLinuxCgroupV2ProofWorker(workerInput, {
      platform: 'linux',
      spawn: async () => { throw new Error('Failed to connect to bus'); },
    }),
    (error) => error instanceof LinuxCgroupV2WorkerError && error.code === 'PROVER_MEMORY_GUARD_UNAVAILABLE',
  );
  await assert.rejects(
    () => runLinuxCgroupV2ProofWorker(workerInput, {
      platform: 'linux',
      spawn: async () => ({
        ...success(),
        stdout: report({ phase: 'limits', evidence: { ...limits(), memoryMax: '4294967297' } })
          + report({
            phase: 'termination',
            exitCode: 0,
            signal: null,
            memoryPeak: '131072',
            memoryEvents: { oom: 0, oomKill: 0 },
          }),
      }),
    }),
    (error) => error instanceof LinuxCgroupV2WorkerError && error.code === 'PROVER_MEMORY_GUARD_UNAVAILABLE',
  );
});

test('fails closed on spoofed, duplicate, and out-of-order control reports', async () => {
  const termination = report({
    phase: 'termination',
    exitCode: 0,
    signal: null,
    memoryPeak: '131072',
    memoryEvents: { oom: 0, oomKill: 0 },
  });
  const cases = [
    report({ phase: 'limits', evidence: limits() })
      + report({ phase: 'limits', evidence: limits() })
      + termination,
    termination + report({ phase: 'limits', evidence: limits() }),
    report({ phase: 'limits', evidence: limits(), spoofed: true }) + termination,
  ];
  for (const stdout of cases) {
    await assert.rejects(
      () => runLinuxCgroupV2ProofWorker(workerInput, {
        platform: 'linux',
        spawn: async () => ({ exitCode: 0, signal: null, stderr: '', stdout }),
      }),
      (error) => error instanceof LinuxCgroupV2WorkerError
        && error.code === 'PROVER_MEMORY_GUARD_UNAVAILABLE',
    );
  }
});

test('distinguishes cgroup OOM, ordinary exit, and signal termination', async () => {
  const cases = [
    [{ exitCode: null, signal: 'SIGKILL', memoryEvents: { oom: 1, oomKill: 1 } }, 'PROVER_WORKER_OOM'],
    [{ exitCode: 23, signal: null, memoryEvents: { oom: 0, oomKill: 0 } }, 'PROVER_WORKER_EXIT'],
    [{ exitCode: null, signal: 'SIGTERM', memoryEvents: { oom: 0, oomKill: 0 } }, 'PROVER_WORKER_SIGNAL'],
  ];
  for (const [termination, code] of cases) {
    await assert.rejects(
      () => runLinuxCgroupV2ProofWorker(workerInput, {
        platform: 'linux',
        spawn: async () => ({
          exitCode: termination.signal === null ? termination.exitCode : 137,
          signal: termination.signal,
          stderr: '',
        stdout: report({ phase: 'limits', evidence: limits() }) + report({
          phase: 'termination',
          memoryPeak: '131072',
          ...termination,
        }),
        }),
      }),
      (error) => error instanceof LinuxCgroupV2WorkerError && error.code === code,
    );
  }
});
