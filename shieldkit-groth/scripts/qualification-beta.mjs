#!/usr/bin/env node
/**
 * ShieldKit-Groth Beta local qualification entrypoint.
 *
 * Requires PF10 beta local/package evidence. Does NOT run D-01/D-02, Q-08/Q-09,
 * legacy seven-carrier, mining, or confirmation gates.
 */
import { spawnSync } from 'node:child_process';
import { availableParallelism } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const cores = Math.max(1, Math.min(availableParallelism(), Math.max(1, availableParallelism() - 2)));

const steps = [
  { name: 'check:no-seven-carrier-release', cmd: ['npm', 'run', 'check:no-seven-carrier-release'] },
  { name: 'check:source', cmd: ['npm', 'run', 'check:source'] },
  { name: 'check:type:v2', cmd: ['npm', 'run', 'check:type:v2'] },
  { name: 'audit:prod-high', cmd: ['npm', 'audit', '--omit=dev', '--audit-level=high'] },
  { name: 'test:beta-product:security', cmd: ['npm', 'run', 'test:beta-product:security'] },
  { name: 'test:rust:v2', cmd: ['npm', 'run', 'test:rust:v2'] },
  { name: 'test:portable', cmd: ['npm', 'test'] },
  { name: 'npm-pack-dry-run', cmd: ['npm', 'pack', '--dry-run', '--json'] },
];

const results = [];
for (const step of steps) {
  const started = Date.now();
  const env = {
    ...process.env,
    UV_THREADPOOL_SIZE: String(cores),
    CARGO_BUILD_JOBS: String(cores),
  };
  const run = spawnSync(step.cmd[0], step.cmd.slice(1), {
    cwd: repositoryRoot,
    encoding: 'utf8',
    env,
    maxBuffer: 64 * 1024 * 1024,
  });
  const ok = run.status === 0;
  results.push({
    name: step.name,
    ok,
    status: run.status,
    ms: Date.now() - started,
    stderrTail: (run.stderr || '').slice(-2000),
    stdoutTail: (run.stdout || '').slice(-2000),
  });
  if (!ok) {
    process.stdout.write(`${JSON.stringify({
      ok: false,
      product: 'ShieldKit-Groth',
      release: 'ShieldKit-Groth Beta',
      cores,
      failedStep: step.name,
      results,
    }, null, 2)}\n`);
    process.exit(1);
  }
}

process.stdout.write(`${JSON.stringify({
  ok: true,
  product: 'ShieldKit-Groth',
  release: 'ShieldKit-Groth Beta',
  cores,
  results: results.map(({ name, ok, status, ms }) => ({ name, ok, status, ms })),
  notes: [
    'Local/package beta gate only. Live Chipnet 5x5 zero-conf evidence is a separate final-candidate step.',
    'D-01/D-02 and Q-08/Q-09 remain post-beta production gates.',
  ],
}, null, 2)}\n`);
