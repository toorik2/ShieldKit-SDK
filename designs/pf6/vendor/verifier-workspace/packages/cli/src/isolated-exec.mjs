import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';

import { makeRunId, repoRelative, repoRoot, resolveRepoPath } from './repo.mjs';

export const runIsolated = ({ command, args = [], runId }) => {
  if (!command) throw new Error('isolated exec requires a command after --');
  if (!existsSync('/usr/bin/bwrap')) throw new Error('isolated exec requires /usr/bin/bwrap');
  const id = runId ?? makeRunId('exec', 'isolated');
  const runRoot = resolveRepoPath(`.vc/runs/${id}`);
  mkdirSync(resolveRepoPath('.vc/runs'), { recursive: true });
  try { mkdirSync(runRoot); }
  catch (error) {
    if (error?.code === 'EEXIST') throw new Error(`isolated run already exists: ${repoRelative(runRoot)}`);
    throw error;
  }
  mkdirSync(resolve(runRoot, 'tmp'), { recursive: true, mode: 0o1777 });
  mkdirSync(resolve(runRoot, 'generated'), { recursive: true });
  mkdirSync(resolve(runRoot, 'c7'), { recursive: true });
  const environment = {
    TMPDIR: '/tmp',
    VC_RUN_ID: id,
    VC_RUN_ROOT: runRoot,
    VC_TMPDIR: resolve(runRoot, 'tmp'),
    C7_TMP: resolve(runRoot, 'c7'),
    C7_GEN: resolve(runRoot, 'generated'),
  };
  const bwrapArgs = [
    '--die-with-parent',
    '--dev-bind', '/', '/',
    '--bind', resolve(runRoot, 'tmp'), '/tmp',
    '--chdir', repoRoot,
    ...Object.entries(environment).flatMap(([name, value]) => ['--setenv', name, value]),
    '--', command, ...args,
  ];
  const result = spawnSync('/usr/bin/bwrap', bwrapArgs, { cwd: repoRoot, env: process.env, stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`isolated command failed with exit ${result.status ?? 'unknown'}${result.signal ? ` (${result.signal})` : ''}`);
  return { runId: id, runRoot: repoRelative(runRoot), command: [command, ...args], privateTmp: true };
};
