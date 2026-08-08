import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { posix, resolve } from 'node:path';

import { assertValid } from '../../contracts/src/index.mjs';
import { repoRoot } from './repo.mjs';

const gitLines = (args, cwd) => execFileSync('git', args, {
  cwd,
  encoding: 'utf8',
  stdio: ['ignore', 'pipe', 'pipe'],
}).split('\n').map((line) => line.trim()).filter(Boolean);

const normalizePath = (value) => posix.normalize(String(value).replaceAll('\\', '/')).replace(/^\.\//, '');
const bootstrapPaths = (() => {
  const config = JSON.parse(readFileSync(resolve(repoRoot, 'control-plane.json'), 'utf8')).worktreeBootstrap;
  return new Set([
    ...config.links.map((entry) => normalizePath(entry.path)),
    ...config.externalLinks.map((entry) => normalizePath(entry.target)),
  ]);
})();
const isBootstrapPath = (path) => bootstrapPaths.has(normalizePath(path));

export const normalizeScope = (value) => {
  const normalized = normalizePath(value).replace('/<assigned-run-id>/', '/');
  if (normalized === '..' || normalized.startsWith('../') || normalized.startsWith('/')) {
    throw new Error(`write scope must stay inside the repository: ${value}`);
  }
  return normalized;
};

export const pathMatchesScope = (path, scope) => {
  const normalizedPath = normalizePath(path);
  const normalizedScope = normalizeScope(scope);
  if (normalizedScope.endsWith('/**')) {
    const prefix = normalizedScope.slice(0, -3).replace(/\/$/, '');
    return normalizedPath === prefix || normalizedPath.startsWith(`${prefix}/`);
  }
  return normalizedPath === normalizedScope || normalizedPath.startsWith(`${normalizedScope}/`);
};

export const pathsOutsideScope = (paths, scopes) => paths
  .map(normalizePath)
  .filter((path) => !scopes.some((scope) => pathMatchesScope(path, scope)))
  .sort();

export const readLaneWriteScope = (laneId) => {
  const path = resolve(repoRoot, 'lanes', laneId, 'lane.json');
  const lane = assertValid('lane', JSON.parse(readFileSync(path, 'utf8')));
  if (lane.id !== laneId) throw new Error(`lane id mismatch: ${laneId}`);
  return lane.writeScope.map(normalizeScope);
};

export const changedPaths = ({ cwd, base }) => {
  const tracked = gitLines(['diff', '--name-only', '--diff-filter=ACMRTUXB', base, '--'], cwd);
  const untracked = gitLines(['ls-files', '--others', '--exclude-standard'], cwd).filter((path) => !isBootstrapPath(path));
  return [...new Set([...tracked, ...untracked])].sort();
};

export const workingTreePaths = ({ cwd }) => {
  const tracked = gitLines(['diff', '--name-only', '--diff-filter=ACMRTUXB', 'HEAD', '--'], cwd);
  const untracked = gitLines(['ls-files', '--others', '--exclude-standard'], cwd).filter((path) => !isBootstrapPath(path));
  return [...new Set([...tracked, ...untracked])].sort();
};

export const checkOwnership = ({ cwd, base, scopes }) => {
  const changed = changedPaths({ cwd, base });
  const violations = pathsOutsideScope(changed, scopes);
  return { ok: violations.length === 0, changed, scopes, violations };
};

export const assertOwnership = (input) => {
  const result = checkOwnership(input);
  if (!result.ok) throw new Error(`write-scope violation:\n- ${result.violations.join('\n- ')}`);
  return result;
};

export const checkCurrentAssignment = () => {
  const assignmentPath = resolve(repoRoot, '.vc/assignment.json');
  if (!existsSync(assignmentPath)) throw new Error('this checkout has no arena assignment');
  const assignment = JSON.parse(readFileSync(assignmentPath, 'utf8'));
  const result = checkOwnership({ cwd: repoRoot, base: assignment.base, scopes: assignment.writeScope });
  if (!result.ok) throw new Error(`write-scope violation for ${assignment.worker}:\n- ${result.violations.join('\n- ')}`);
  return { assignment, ...result };
};
