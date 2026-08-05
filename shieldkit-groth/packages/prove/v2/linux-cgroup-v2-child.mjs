import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';
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

function argumentsFromProcess(argv = process.argv) {
  const values = argv.slice(2);
  if (values.length < 2 || values[0] !== '--' || !values[1].startsWith('/')) {
    throw new Error('usage: linux-cgroup-v2-child.mjs -- /absolute/command [args...]');
  }
  if (values.some((value) => value.includes('\0'))) throw new Error('command arguments must not contain NUL');
  return { command: values[1], arguments: values.slice(2) };
}

export async function runLinuxCgroupV2ProofChild({
  argv = process.argv,
  spawnChild = spawn,
  readEvidence = readLinuxCgroupV2Evidence,
  writeRecord = writeEvidence,
  writeError = message => process.stderr.write(`${message}\n`),
  pipeStderr = child => child.stderr.pipe(process.stderr, { end: false }),
} = {}) {
  let evidence;
  try {
    evidence = assertRequiredCgroupLimits(await readEvidence());
  } catch (error) {
    writeRecord({
      phase: 'limits',
      evidence: {
        cgroup: 'unavailable',
        memoryMax: 'unavailable',
        memorySwapMax: 'unavailable',
        memoryPeak: '0',
        memoryEvents: { oom: 0, oomKill: 0 },
      },
    });
    writeError(error.message);
    return { exitCode: 70, signal: null };
  }
  writeRecord({ phase: 'limits', evidence });
  let input;
  try {
    input = argumentsFromProcess(argv);
  } catch (error) {
    writeError(error.message);
    return { exitCode: 70, signal: null };
  }
  let child;
  try {
    child = spawnChild(input.command, input.arguments, {
      shell: false,
      stdio: ['ignore', 'ignore', 'pipe'],
      env: PROVER_WORKER_ENVIRONMENT,
    });
  } catch (error) {
    writeError(error.message);
    return { exitCode: 127, signal: null };
  }
  pipeStderr(child);
  return new Promise((resolve) => {
    let finished = false;
    const finalize = async (exitCode, signal, error = undefined) => {
      if (finished) return;
      finished = true;
      let finalEvidence;
      try {
        // A pre-run sample cannot stand in for post-run enforcement evidence.
        finalEvidence = assertRequiredCgroupLimits(await readEvidence());
      } catch (readError) {
        writeError(readError.message);
        resolve({ exitCode: 70, signal: null });
        return;
      }
      writeRecord({
        phase: 'termination',
        exitCode,
        signal,
        memoryPeak: finalEvidence.memoryPeak,
        memoryEvents: finalEvidence.memoryEvents,
      });
      if (error !== undefined) writeError(error.message);
      resolve({ exitCode: exitCode ?? signalExit[signal] ?? 1, signal });
    };
    child.once('error', error => { void finalize(127, null, error); });
    child.once('close', (exitCode, signal) => { void finalize(exitCode, signal); });
  });
}

async function main() {
  const terminal = await runLinuxCgroupV2ProofChild();
  if (terminal.signal !== null) process.kill(process.pid, terminal.signal);
  process.exit(terminal.exitCode);
}

if (typeof process.argv[1] === 'string' && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exit(70);
  });
}
