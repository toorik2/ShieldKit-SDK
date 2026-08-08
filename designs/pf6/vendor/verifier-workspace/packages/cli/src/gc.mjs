import { existsSync, lstatSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';

import { repoRelative, repoRoot } from './repo.mjs';

const DAY_MS = 24 * 60 * 60 * 1000;

const readConfig = () => JSON.parse(readFileSync(resolve(repoRoot, 'control-plane.json'), 'utf8')).retention;
const directories = (root) => existsSync(root)
  ? readdirSync(root, { withFileTypes: true }).filter((entry) => entry.isDirectory()).map((entry) => resolve(root, entry.name))
  : [];

const bytesUnder = (path) => {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink()) return 0;
  if (!stat.isDirectory()) return stat.size;
  return readdirSync(path).reduce((total, name) => total + bytesUnder(resolve(path, name)), 0);
};

const eligibleByAge = ({ paths, policy, now, filter = () => true }) => {
  const rows = paths.map((path) => ({ path, stat: lstatSync(path) }))
    .filter(({ path }) => !existsSync(resolve(path, '.keep')))
    .filter(({ path }) => filter(path))
    .sort((left, right) => right.stat.mtimeMs - left.stat.mtimeMs);
  return rows.slice(policy.keepNewest).filter(({ stat }) => now - stat.mtimeMs >= policy.maxAgeDays * DAY_MS);
};

const finalizedArena = (path) => {
  const manifestPath = resolve(path, 'arena.json');
  if (!existsSync(manifestPath)) return false;
  try { return JSON.parse(readFileSync(manifestPath, 'utf8')).status === 'finalized'; }
  catch { return false; }
};

export const gcPlan = ({ now = Date.now() } = {}) => {
  const policy = readConfig();
  const groups = [
    {
      kind: 'run',
      rows: eligibleByAge({ paths: directories(resolve(repoRoot, '.vc/runs')), policy: policy.runs, now }),
    },
    {
      kind: 'check',
      rows: eligibleByAge({ paths: directories(resolve(repoRoot, '.vc/checks/frontiers')), policy: policy.checks, now }),
    },
    {
      kind: 'finalized-arena',
      rows: eligibleByAge({
        paths: directories(resolve(repoRoot, '.vc/arenas')),
        policy: policy.finalizedArenas,
        now,
        filter: finalizedArena,
      }),
    },
  ];
  const eligible = groups.flatMap(({ kind, rows }) => rows.map(({ path, stat }) => ({
    kind,
    path: repoRelative(path),
    modifiedAt: stat.mtime.toISOString(),
    bytes: bytesUnder(path),
  })));
  return {
    schema: 'verifier.cash/gc-plan/v1',
    generatedAt: new Date(now).toISOString(),
    eligible,
    bytes: eligible.reduce((sum, row) => sum + row.bytes, 0),
  };
};

export const gcControlPlane = ({ yes = false } = {}) => {
  const plan = gcPlan();
  if (yes) for (const row of plan.eligible) rmSync(resolve(repoRoot, row.path), { recursive: true, force: true });
  return { ...plan, applied: yes, removed: yes ? plan.eligible.length : 0 };
};
