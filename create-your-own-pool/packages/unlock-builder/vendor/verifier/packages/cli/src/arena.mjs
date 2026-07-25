import { createHash } from 'node:crypto';
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { assertOwnership, checkOwnership, normalizeScope, readLaneWriteScope, workingTreePaths } from './ownership.mjs';
import { git, repoRelative, repoRoot, resolveRepoPath, writeJson } from './repo.mjs';
import { bootstrapWorktree, verifyWorktreeBootstrap } from './worktree-bootstrap.mjs';

const validName = (value, label) => {
  if (!/^[a-z0-9][a-z0-9._-]*$/.test(value)) throw new Error(`${label} must match /^[a-z0-9][a-z0-9._-]*$/`);
  return value;
};

const primaryCheckoutRequired = () => {
  const marker = resolve(repoRoot, '.git');
  if (!existsSync(marker) || !lstatSync(marker).isDirectory()) {
    throw new Error('arena lifecycle commands must run from the primary checkout, not from a linked worktree');
  }
};

const branchExists = (branch) => {
  try { git(['show-ref', '--verify', '--quiet', `refs/heads/${branch}`]); return true; }
  catch { return false; }
};

const readArena = (runId) => {
  const root = resolveRepoPath(`.vc/arenas/${validName(runId, 'run id')}`);
  const manifestPath = resolve(root, 'arena.json');
  if (!existsSync(manifestPath)) throw new Error(`arena not found: ${runId}`);
  return { root, manifestPath, manifest: JSON.parse(readFileSync(manifestPath, 'utf8')) };
};

const resolveAssignments = ({ workers, targetLane, scopes }) => {
  if (!Array.isArray(workers) || workers.length === 0) throw new Error('arena create requires at least one worker');
  workers.forEach((worker) => validName(worker, 'worker'));
  if (new Set(workers).size !== workers.length) throw new Error('arena workers must be unique');
  if (targetLane && scopes?.length) throw new Error('choose --target-lane or --scope, not both');
  if (targetLane) {
    validName(targetLane, 'target lane');
    const writeScope = readLaneWriteScope(targetLane);
    return workers.map((worker) => ({ worker, targetLane, writeScope }));
  }
  if (scopes?.length) {
    const writeScope = [...new Set(scopes.map(normalizeScope))];
    return workers.map((worker) => ({ worker, targetLane: null, writeScope }));
  }
  return workers.map((worker) => ({ worker, targetLane: worker, writeScope: readLaneWriteScope(worker) }));
};

const sha256File = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');

const installScopeHook = ({ worktree, runId, base }) => {
  const assignment = {
    schema: 'verifier.cash/arena-assignment/v1',
    runId,
    worker: worktree.worker,
    targetLane: worktree.targetLane,
    base,
    writeScope: worktree.writeScope,
  };
  writeJson(resolve(worktree.path, '.vc/assignment.json'), assignment);
  const hooksDir = resolve(worktree.path, '.vc/hooks');
  const hookPath = resolve(hooksDir, 'pre-commit');
  mkdirSync(hooksDir, { recursive: true });
  writeFileSync(hookPath, '#!/bin/sh\nexec node packages/cli/src/vc.mjs scope-check\n');
  chmodSync(hookPath, 0o755);
  git(['config', 'extensions.worktreeConfig', 'true']);
  git(['config', '--worktree', 'core.hooksPath', hooksDir], { cwd: worktree.path });
};

export const createArena = ({ runId, workers, lanes, targetLane, scopes = [], base = 'HEAD', dryRun = false }) => {
  primaryCheckoutRequired();
  validName(runId, 'run id');
  const assignments = resolveAssignments({ workers: workers ?? lanes, targetLane, scopes });
  const root = resolveRepoPath(`.vc/arenas/${runId}`);
  if (existsSync(root)) throw new Error(`arena already exists: ${repoRelative(root)}`);
  const baseCommit = git(['rev-parse', base]);
  const worktrees = assignments.map((assignment) => ({
    ...assignment,
    branch: `arena/${runId}/${assignment.worker}`,
    path: resolve(root, 'worktrees', assignment.worker),
  }));
  const manifest = {
    schema: 'verifier.cash/arena/v2',
    runId,
    base: baseCommit,
    createdAt: new Date().toISOString(),
    status: dryRun ? 'planned' : 'active',
    worktrees: worktrees.map((worktree) => ({ ...worktree, path: repoRelative(worktree.path) })),
  };
  if (dryRun) return manifest;
  mkdirSync(resolve(root, 'worktrees'), { recursive: true });
  const created = [];
  try {
    for (const worktree of worktrees) {
      git(['worktree', 'add', '-b', worktree.branch, worktree.path, baseCommit]);
      created.push(worktree);
      bootstrapWorktree(worktree.path);
      installScopeHook({ worktree, runId, base: baseCommit });
    }
    writeJson(resolve(root, 'arena.json'), manifest);
    return manifest;
  } catch (error) {
    for (const worktree of created.reverse()) {
      try { git(['worktree', 'remove', '--force', worktree.path]); } catch {}
      try { git(['branch', '-D', worktree.branch]); } catch {}
    }
    throw error;
  }
};

export const arenaStatus = (runId) => {
  const { manifest } = readArena(runId);
  return {
    ...manifest,
    worktrees: manifest.worktrees.map((worktree) => {
      const path = resolveRepoPath(worktree.path);
      const refExists = branchExists(worktree.branch);
      if (!existsSync(path)) {
        return {
          ...worktree,
          exists: false,
          branchExists: refExists,
          clean: null,
          head: refExists ? git(['rev-parse', worktree.branch]) : worktree.head ?? null,
        };
      }
      const dirtyPaths = workingTreePaths({ cwd: path });
      const head = git(['rev-parse', 'HEAD'], { cwd: path });
      const ownership = checkOwnership({ cwd: path, base: manifest.base, scopes: worktree.writeScope });
      const bootstrap = verifyWorktreeBootstrap(path);
      return {
        ...worktree,
        exists: true,
        branchExists: refExists,
        clean: dirtyPaths.length === 0,
        dirtyPaths,
        head,
        ownership,
        bootstrap,
      };
    }),
  };
};

export const checkArena = ({ runId, worker }) => {
  const status = arenaStatus(runId);
  const selected = worker ? status.worktrees.filter((entry) => entry.worker === worker) : status.worktrees;
  if (worker && selected.length === 0) throw new Error(`arena worker not found: ${worker}`);
  const failures = selected.filter((entry) => !entry.exists || !entry.bootstrap?.ok || !entry.ownership?.ok);
  if (failures.length > 0) {
    throw new Error(`arena check failed:\n${failures.map((entry) => `- ${entry.worker}: exists=${entry.exists} bootstrap=${entry.bootstrap?.ok ?? false} ownership=${entry.ownership?.ok ?? false}${entry.ownership?.violations?.length ? ` violations=${entry.ownership.violations.join(',')}` : ''}`).join('\n')}`);
  }
  return { runId, ok: true, workers: selected.map((entry) => ({
    worker: entry.worker,
    head: entry.head,
    clean: entry.clean,
    changed: entry.ownership.changed,
  })) };
};

export const closeArena = ({ runId, yes = false }) => {
  primaryCheckoutRequired();
  if (!yes) throw new Error('arena close requires --yes');
  const { root, manifestPath, manifest } = readArena(runId);
  if (manifest.status !== 'active') throw new Error(`arena close requires active status, found: ${manifest.status}`);
  const status = arenaStatus(runId);
  const missing = status.worktrees.filter((worktree) => !worktree.exists);
  if (missing.length > 0) throw new Error(`refusing to close arena with missing worktrees: ${missing.map((entry) => entry.worker).join(', ')}`);
  const dirty = status.worktrees.filter((worktree) => !worktree.clean);
  if (dirty.length > 0) throw new Error(`refusing to close dirty arena worktrees: ${dirty.map((worktree) => worktree.worker).join(', ')}`);
  for (const worktree of status.worktrees) {
    assertOwnership({ cwd: resolveRepoPath(worktree.path), base: manifest.base, scopes: worktree.writeScope });
    if (!worktree.bootstrap.ok) throw new Error(`refusing to close unbootstrapped worktree: ${worktree.worker}`);
  }
  const archiveDir = resolve(root, 'archive');
  mkdirSync(archiveDir, { recursive: true });
  const bundlePath = resolve(archiveDir, 'candidate-refs.bundle');
  const refs = manifest.worktrees.map((worktree) => `refs/heads/${worktree.branch}`);
  const hasDivergentCommits = status.worktrees.some((worktree) => {
    try { return Number(git(['rev-list', '--count', `${manifest.base}..${worktree.branch}`])) > 0; }
    catch { return false; }
  });
  let archive;
  if (hasDivergentCommits) {
    git(['bundle', 'create', bundlePath, ...refs, `^${manifest.base}`]);
    git(['bundle', 'verify', bundlePath]);
    archive = {
      kind: 'incremental-git-bundle',
      path: repoRelative(bundlePath),
      prerequisite: manifest.base,
      sha256: sha256File(bundlePath),
      bytes: statSync(bundlePath).size,
    };
  } else {
    archive = {
      kind: 'no-divergent-commits',
      prerequisite: manifest.base,
      bytes: 0,
    };
  }
  const closedWorktrees = status.worktrees.map((entry) => ({
    worker: entry.worker,
    targetLane: entry.targetLane,
    writeScope: entry.writeScope,
    branch: entry.branch,
    path: entry.path,
    head: entry.head,
  }));
  for (const worktree of manifest.worktrees) git(['worktree', 'remove', '--force', resolveRepoPath(worktree.path)]);
  git(['worktree', 'prune']);
  const closed = {
    ...manifest,
    status: 'closed',
    closedAt: new Date().toISOString(),
    worktrees: closedWorktrees,
    archive,
    branchRetention: 'retained-pending-integration',
  };
  writeJson(manifestPath, closed);
  return closed;
};

export const finalizeArena = ({ runId, integratedInto, allowLocal = false, yes = false }) => {
  primaryCheckoutRequired();
  if (!yes) throw new Error('arena finalize requires --yes');
  if (!integratedInto) throw new Error('arena finalize requires --integrated-into REF');
  const { manifestPath, manifest } = readArena(runId);
  if (manifest.status !== 'closed') throw new Error(`arena finalize requires closed status, found: ${manifest.status}`);
  const integrationCommit = git(['rev-parse', integratedInto]);
  const notIntegrated = [];
  for (const worktree of manifest.worktrees) {
    const head = branchExists(worktree.branch) ? git(['rev-parse', worktree.branch]) : worktree.head;
    try { git(['merge-base', '--is-ancestor', head, integrationCommit]); }
    catch { notIntegrated.push(`${worktree.worker}:${head}`); }
  }
  if (notIntegrated.length > 0) {
    throw new Error(`refusing to finalize branches not reachable from ${integratedInto}:\n- ${notIntegrated.join('\n- ')}`);
  }
  const remoteRefs = git([
    'for-each-ref',
    '--contains', integrationCommit,
    '--format=%(refname)',
    'refs/remotes',
  ]).split('\n').filter(Boolean);
  if (remoteRefs.length === 0 && !allowLocal) {
    throw new Error(`refusing to finalize integration commit not present in any remote-tracking ref: ${integrationCommit}; push/fetch it first or explicitly use --allow-local`);
  }
  for (const worktree of manifest.worktrees) {
    if (branchExists(worktree.branch)) git(['branch', '-D', worktree.branch]);
  }
  git(['worktree', 'prune']);
  const finalized = {
    ...manifest,
    status: 'finalized',
    finalizedAt: new Date().toISOString(),
    integratedInto,
    integrationCommit,
    durability: remoteRefs.length > 0
      ? { kind: 'remote-tracking-ref', refs: remoteRefs }
      : { kind: 'local-override' },
    branchRetention: 'pruned-after-integration-proof',
  };
  writeJson(manifestPath, finalized);
  return finalized;
};
