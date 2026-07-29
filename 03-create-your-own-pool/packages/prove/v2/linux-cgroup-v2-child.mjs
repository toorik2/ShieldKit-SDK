import { spawn } from 'node:child_process';
import {
  CGROUP_EVIDENCE_PREFIX,
  PROVER_WORKER_ENVIRONMENT,
  assertRequiredCgroupLimits,
  readLinuxCgroupV2Evidence,
} from './linux-cgroup-v2-worker.mjs';

const signalExit = Object.freeze({
  SIGHUP: 129, SIGINT: 130, SIGQUIT: 131, SIGILL: 132, SIGTRAP: 133,
  SIGABRT: 134, SIGBUS: 135, SIGFPE: 136, SIGKILL: 137, SIGUSR1: 138,
  SIGSEGV: 139, SIGUSR2: 140, SIGPIPE: 141, SIGALRM: 142, SIGTERM: 143,
});

function writeEvidence(value) {
  process.stdout.write(`${CGROUP_EVIDENCE_PREFIX}${JSON.stringify(value)}\n`);
}

function argumentsFromProcess() {
  const values = process.argv.slice(2);
  if (values.length < 2 || values[0] !== '--' || !values[1].startsWith('/')) {
    throw new Error('usage: linux-cgroup-v2-child.mjs -- /absolute/command [args...]');
  }
  if (values.some((value) => value.includes('\0'))) throw new Error('command arguments must not contain NUL');
  return { command: values[1], arguments: values.slice(2) };
}

async function main() {
  let evidence;
  try {
    evidence = assertRequiredCgroupLimits(await readLinuxCgroupV2Evidence());
  } catch (error) {
    writeEvidence({
      phase: 'limits',
      evidence: {
        cgroup: 'unavailable',
        memoryMax: 'unavailable',
        memorySwapMax: 'unavailable',
        memoryPeak: '0',
        memoryEvents: { oom: 0, oomKill: 0 },
      },
    });
    process.stderr.write(`${error.message}\n`);
    process.exit(70);
  }
  writeEvidence({ phase: 'limits', evidence });
  const input = argumentsFromProcess();
  const child = spawn(input.command, input.arguments, {
    shell: false,
    stdio: ['ignore', 'ignore', 'pipe'],
    env: PROVER_WORKER_ENVIRONMENT,
  });
  child.stderr.pipe(process.stderr, { end: false });
  let finished = false;
  child.once('error', async (error) => {
    if (finished) return;
    finished = true;
    const finalEvidence = await readLinuxCgroupV2Evidence().catch(() => evidence);
    writeEvidence({
      phase: 'termination',
      exitCode: 127,
      signal: null,
      memoryPeak: finalEvidence.memoryPeak,
      memoryEvents: finalEvidence.memoryEvents,
    });
    process.stderr.write(`${error.message}\n`);
    process.exit(127);
  });
  child.once('close', async (exitCode, signal) => {
    if (finished) return;
    finished = true;
    const finalEvidence = await readLinuxCgroupV2Evidence().catch(() => evidence);
    writeEvidence({
      phase: 'termination',
      exitCode,
      signal,
      memoryPeak: finalEvidence.memoryPeak,
      memoryEvents: finalEvidence.memoryEvents,
    });
    if (signal !== null) process.kill(process.pid, signal);
    process.exit(exitCode ?? signalExit[signal] ?? 1);
  });
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exit(70);
});
