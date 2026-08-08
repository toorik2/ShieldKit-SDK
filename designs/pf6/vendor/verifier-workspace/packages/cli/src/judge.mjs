import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';

import { repoRoot, resolveRepoPath } from './repo.mjs';

export const judgeBundle = (bundleInput, options = {}) => {
  const bundlePath = resolve(bundleInput);
  const tier = options.tier ?? 'fast';
  const outPath = options.out ? resolve(options.out) : resolve(dirname(bundlePath), `evidence-${tier}.json`);
  const tsx = resolveRepoPath('harness/node_modules/.bin/tsx');
  const judge = resolveRepoPath('packages/judge/src/judge-bundle.ts');
  const proc = spawnSync(tsx, [judge, bundlePath, '--tier', tier, '--out', outPath], {
    cwd: resolveRepoPath('harness'),
    env: { ...process.env, VC_REPO_ROOT: repoRoot },
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 64 * 1024 * 1024,
  });
  if (proc.stdout) process.stdout.write(proc.stdout);
  if (proc.stderr) process.stderr.write(proc.stderr);
  if (proc.error) throw proc.error;
  if (proc.status !== 0) throw new Error(`judge returned red at tier ${tier}; evidence: ${outPath}`);
  return outPath;
};
