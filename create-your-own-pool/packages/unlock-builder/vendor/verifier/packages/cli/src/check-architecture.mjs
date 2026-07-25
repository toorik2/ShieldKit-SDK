#!/usr/bin/env node
import { existsSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { assertValid, readJson } from '../../contracts/src/index.mjs';
import { git, repoRoot, resolveRepoPath } from './repo.mjs';

const failures = [];
const check = (condition, message) => { if (!condition) failures.push(message); };
for (const path of ['AGENTS.md', 'control-plane.json', 'repo.layout.json', '.codex/config.toml', '.codex/agents/lane-worker.toml', '.codex/agents/redteam.toml', '.codex/agents/promotion-judge.toml']) {
  check(existsSync(resolveRepoPath(path)), `missing ${path}`);
}

try {
  const layout = readJson(resolveRepoPath('repo.layout.json'));
  check(layout.schema === 'verifier.cash/repository-layout/v1', 'invalid repository layout schema');
  const rootFiles = new Set(layout.trackedRootFiles ?? []);
  const roots = new Set(Object.keys(layout.trackedRoots ?? {}));
  const ignoredRoots = new Set(Object.keys(layout.ignoredRoots ?? {}));
  const allowedCheckoutEntries = new Set(['.git', ...rootFiles, ...roots, ...ignoredRoots]);
  for (const entry of readdirSync(repoRoot, { withFileTypes: true })) {
    check(allowedCheckoutEntries.has(entry.name), `undeclared checkout root entry: ${entry.name}`);
  }
  for (const path of git(['ls-files']).split('\n').filter(Boolean)) {
    const parts = path.split('/');
    if (parts.length === 1) check(rootFiles.has(path), `undeclared tracked root file: ${path}`);
    else check(roots.has(parts[0]), `undeclared tracked root directory: ${parts[0]}`);
  }
  for (const path of rootFiles) check(existsSync(resolveRepoPath(path)), `declared tracked root file is missing: ${path}`);
  for (const path of roots) check(existsSync(resolveRepoPath(path)), `declared tracked root directory is missing: ${path}`);
  for (const [path, descriptor] of Object.entries(layout.trackedRoots ?? {})) {
    check(typeof descriptor.class === 'string' && descriptor.class.length > 0, `${path}: layout class is missing`);
    check(['durable', 'migration', 'quarantined'].includes(descriptor.lifecycle), `${path}: invalid lifecycle`);
    check(typeof descriptor.owner === 'string' && descriptor.owner.length > 0, `${path}: owner is missing`);
    if (['migration', 'quarantined'].includes(descriptor.lifecycle)) {
      const trackedCount = git(['ls-files', path]).split('\n').filter(Boolean).length;
      check(Number.isInteger(descriptor.fileBudget) && descriptor.fileBudget >= 0, `${path}: migration file budget is missing`);
      check(trackedCount <= descriptor.fileBudget, `${path}: tracked file budget exceeded (${trackedCount} > ${descriptor.fileBudget})`);
      check(typeof descriptor.migrationTarget === 'string' && descriptor.migrationTarget.length > 0, `${path}: migration target is missing`);
    }
  }
} catch (error) {
  failures.push(`repository layout: ${error?.stack ?? error}`);
}

try {
  const controlPlane = readJson(resolveRepoPath('control-plane.json'));
  check(controlPlane.schema === 'verifier.cash/control-plane/v1', 'invalid control-plane schema');
  check(Array.isArray(controlPlane.worktreeBootstrap?.links), 'control-plane bootstrap links are missing');
  check(Array.isArray(controlPlane.worktreeBootstrap?.externalLinks), 'control-plane external links are missing');
  for (const tier of ['runs', 'checks', 'finalizedArenas']) {
    const policy = controlPlane.retention?.[tier];
    check(Number.isInteger(policy?.maxAgeDays) && policy.maxAgeDays >= 1, `${tier}: maxAgeDays must be positive`);
    check(Number.isInteger(policy?.keepNewest) && policy.keepNewest >= 0, `${tier}: keepNewest must be non-negative`);
  }
} catch (error) {
  failures.push(`control-plane config: ${error?.stack ?? error}`);
}

const lanesRoot = resolve(repoRoot, 'lanes');
const lanes = readdirSync(lanesRoot, { withFileTypes: true }).filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
check(lanes.length > 0, 'no lanes defined');
for (const laneName of lanes) {
  try {
    const lanePath = resolve(lanesRoot, laneName, 'lane.json');
    const lane = assertValid('lane', readJson(lanePath));
    check(lane.id === laneName, `${lanePath}: lane id must match directory`);
    check(existsSync(resolveRepoPath(lane.frontierCandidate)), `${lanePath}: frontier candidate does not exist`);
    check(existsSync(resolve(lanesRoot, laneName, 'AGENTS.md')), `${lanePath}: nested AGENTS.md is missing`);
    check(lane.writeScope.some((scope) => scope === `lanes/${laneName}/**`), `${lanePath}: write scope must own its lane subtree`);
    const candidatesRoot = resolve(lanesRoot, laneName, 'candidates');
    const candidates = readdirSync(candidatesRoot).filter((name) => name.endsWith('.json')).sort();
    check(candidates.length > 0, `${lanePath}: no candidates`);
    for (const candidateName of candidates) {
      const candidatePath = resolve(candidatesRoot, candidateName);
      const candidate = assertValid('candidate', readJson(candidatePath));
      check(candidate.lane === lane.id, `${candidatePath}: candidate lane mismatch`);
      // Filename stem must equal candidate.id so manifests are discoverable without open-coding nicknames.
      check(candidateName === `${candidate.id}.json`, `${candidatePath}: filename must be ${candidate.id}.json (see docs/NAMING.md)`);
      check(typeof candidate.id === 'string' && candidate.id.startsWith(`${lane.id}-`), `${candidatePath}: candidate.id must start with lane id prefix ${lane.id}-`);
      if (candidate.build.adapter === 'lane-module') {
        const modulePath = resolveRepoPath(candidate.build.module);
        check(existsSync(modulePath), `${candidatePath}: lane build module does not exist`);
        if (existsSync(modulePath)) {
          const adapter = await import(pathToFileURL(modulePath).href);
          check(typeof adapter.buildCandidate === 'function', `${candidatePath}: lane build module must export buildCandidate`);
          check(typeof adapter.validateBuild === 'function', `${candidatePath}: lane build module must export validateBuild`);
          if (typeof adapter.validateBuild === 'function') adapter.validateBuild(candidate.build);
        }
      }
    }
  } catch (error) {
    failures.push(String(error?.stack ?? error));
  }
}

for (const schema of ['lane', 'candidate', 'bundle', 'evidence']) {
  const path = resolveRepoPath(`packages/contracts/schema/${schema}.schema.json`);
  try { JSON.parse(String(await import('node:fs').then(({ readFileSync }) => readFileSync(path)))); }
  catch (error) { failures.push(`${path}: ${error}`); }
}

if (failures.length > 0) {
  console.error(`architecture check failed:\n- ${failures.join('\n- ')}`);
  process.exit(1);
}
console.log(`architecture contracts: ${lanes.length} lane(s), governance and manifests valid`);
