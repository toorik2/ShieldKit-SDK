import assert from 'node:assert/strict';
import { existsSync, rmSync, writeFileSync } from 'node:fs';
import test from 'node:test';

import { validateBundle } from '../../contracts/src/index.mjs';
import { arenaStatus, closeArena, createArena, finalizeArena } from '../src/arena.mjs';
import { buildCandidateBundle } from '../src/bundle.mjs';
import { gcPlan } from '../src/gc.mjs';
import { pathMatchesScope, pathsOutsideScope } from '../src/ownership.mjs';
import { git, makeRunId, resolveRepoPath } from '../src/repo.mjs';

test('artifact candidates become hash-pinned bundles without copying artifacts', async () => {
  const out = `.vc/tests/frontier-bundle-${process.pid}-${Date.now()}`;
  const outPath = resolveRepoPath(out);
  rmSync(outPath, { recursive: true, force: true });
  try {
    const built = await buildCandidateBundle('lanes/bn254-onetx/candidates/bn254-onetx-directstate-10-public-ds1.json', { runId: 'test-frontier-bundle', out });
    assert.deepEqual(validateBundle(built.bundle), []);
    assert.equal(built.bundle.buildResult.score, 83294);
    assert.equal(built.bundle.files.vectors.bytes, 2505875);
    assert.equal(existsSync(built.bundlePath), true);
  } finally {
    rmSync(outPath, { recursive: true, force: true });
  }
});

test('arena dry-run plans isolated lane worktrees and branches', () => {
  const plan = createArena({
    runId: 'test-sub75-plan',
    workers: ['close', 'packing'],
    targetLane: 'bn254-onetx',
    base: 'HEAD',
    dryRun: true,
  });
  assert.equal(plan.status, 'planned');
  assert.equal(plan.worktrees.length, 2);
  assert.deepEqual(plan.worktrees.map((row) => row.branch), [
    'arena/test-sub75-plan/close',
    'arena/test-sub75-plan/packing',
  ]);
  assert.equal(plan.worktrees.every((row) => row.writeScope.includes('lanes/bn254-onetx/**')), true);
});

test('write scopes reject shared and cross-lane changes', () => {
  assert.equal(pathMatchesScope('lanes/bn254-onetx/src/build.mjs', 'lanes/bn254-onetx/**'), true);
  assert.equal(pathMatchesScope('lanes/bn254-native/lane.json', 'lanes/bn254-onetx/**'), false);
  assert.deepEqual(pathsOutsideScope([
    'lanes/bn254-onetx/src/build.mjs',
    'packages/judge/src/judge-bundle.ts',
  ], ['lanes/bn254-onetx/**']), ['packages/judge/src/judge-bundle.ts']);
});

test('run ids are collision resistant within the same millisecond', () => {
  const first = makeRunId('candidate', '0123456789abcdef');
  const second = makeRunId('candidate', '0123456789abcdef');
  assert.notEqual(first, second);
  assert.match(first, /^[a-z0-9][a-z0-9._-]*$/);
});

test('real arena lifecycle bootstraps dependencies and retains refs until integration', { timeout: 30_000 }, () => {
  const runId = `lifecycle-${process.pid}-${Date.now()}`;
  const root = resolveRepoPath(`.vc/arenas/${runId}`);
  try {
    const created = createArena({ runId, workers: ['worker'], targetLane: 'bn254-onetx', base: 'HEAD' });
    assert.equal(created.status, 'active');
    const active = arenaStatus(runId);
    assert.equal(active.worktrees[0].bootstrap.ok, true);
    assert.equal(active.worktrees[0].ownership.ok, true);
    assert.equal(existsSync(resolveRepoPath(`${active.worktrees[0].path}/harness/node_modules/.bin/tsx`)), true);

    const closed = closeArena({ runId, yes: true });
    assert.equal(closed.status, 'closed');
    assert.equal(closed.branchRetention, 'retained-pending-integration');
    assert.equal(arenaStatus(runId).worktrees[0].branchExists, true);

    const finalized = finalizeArena({ runId, integratedInto: 'HEAD', allowLocal: true, yes: true });
    assert.equal(finalized.status, 'finalized');
    assert.equal(arenaStatus(runId).worktrees[0].branchExists, false);
  } finally {
    try {
      const status = arenaStatus(runId);
      for (const worktree of status.worktrees) {
        if (worktree.exists) git(['worktree', 'remove', '--force', resolveRepoPath(worktree.path)]);
        if (worktree.branchExists) git(['branch', '-D', worktree.branch]);
      }
      git(['worktree', 'prune']);
    } catch {}
    rmSync(root, { recursive: true, force: true });
  }
});

test('arena archives contain only commits beyond the base', { timeout: 30_000 }, () => {
  const runId = `incremental-${process.pid}-${Date.now()}`;
  const root = resolveRepoPath(`.vc/arenas/${runId}`);
  try {
    const created = createArena({ runId, workers: ['worker'], targetLane: 'bn254-onetx', base: 'HEAD' });
    const worktreeRoot = resolveRepoPath(created.worktrees[0].path);
    const probe = `${worktreeRoot}/lanes/bn254-onetx/arena-incremental-probe.txt`;
    writeFileSync(probe, 'arena incremental archive probe\n');
    git(['add', 'lanes/bn254-onetx/arena-incremental-probe.txt'], { cwd: worktreeRoot });
    git(['-c', 'user.name=verifier.cash test', '-c', 'user.email=test@verifier.cash', 'commit', '--no-verify', '-m', 'test: arena incremental archive'], { cwd: worktreeRoot });

    const closed = closeArena({ runId, yes: true });
    assert.equal(closed.archive.kind, 'incremental-git-bundle');
    assert.equal(closed.archive.prerequisite, closed.base);
    assert.equal(closed.archive.bytes < 1_000_000, true);
  } finally {
    try {
      const status = arenaStatus(runId);
      for (const worktree of status.worktrees) {
        if (worktree.exists) git(['worktree', 'remove', '--force', resolveRepoPath(worktree.path)]);
        if (worktree.branchExists) git(['branch', '-D', worktree.branch]);
      }
      git(['worktree', 'prune']);
    } catch {}
    rmSync(root, { recursive: true, force: true });
  }
});

test('arena close rejects committed changes outside the assignment', { timeout: 30_000 }, () => {
  const runId = `scope-reject-${process.pid}-${Date.now()}`;
  const root = resolveRepoPath(`.vc/arenas/${runId}`);
  try {
    const created = createArena({ runId, workers: ['worker'], targetLane: 'bn254-onetx', base: 'HEAD' });
    const worktreeRoot = resolveRepoPath(created.worktrees[0].path);
    writeFileSync(`${worktreeRoot}/arena-out-of-scope-probe.txt`, 'must be rejected\n');
    git(['add', 'arena-out-of-scope-probe.txt'], { cwd: worktreeRoot });
    git(['-c', 'user.name=verifier.cash test', '-c', 'user.email=test@verifier.cash', 'commit', '--no-verify', '-m', 'test: out of scope'], { cwd: worktreeRoot });
    assert.throws(() => closeArena({ runId, yes: true }), /write-scope violation/);
  } finally {
    try {
      const status = arenaStatus(runId);
      for (const worktree of status.worktrees) {
        if (worktree.exists) git(['worktree', 'remove', '--force', resolveRepoPath(worktree.path)]);
        if (worktree.branchExists) git(['branch', '-D', worktree.branch]);
      }
      git(['worktree', 'prune']);
    } catch {}
    rmSync(root, { recursive: true, force: true });
  }
});

test('gc is dry-run by default and never selects unfinalized arenas', () => {
  const plan = gcPlan();
  assert.equal(plan.schema, 'verifier.cash/gc-plan/v1');
  assert.equal(plan.eligible.some((row) => row.kind === 'finalized-arena' && row.path.includes('architecture-lifecycle-test')), false);
});
