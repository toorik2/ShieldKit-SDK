import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { makeFileRef, writeCandidateBundle } from '../../build/src/index.mjs';
import { assertValid, hashCanonical, readJson } from '../../contracts/src/index.mjs';
import { currentCommit, makeRunId, repoRoot, resolveRepoPath } from './repo.mjs';

const bundleArtifact = ({ candidate, candidatePath, runId, outDir }) => {
  const root = resolveRepoPath(candidate.build.artifactRoot);
  const files = Object.fromEntries(Object.entries(candidate.build.files).map(([role, path]) => [role, makeFileRef(repoRoot, resolve(root, path))]));
  const sourceCommit = candidate.provenance.sourceCommit;
  const result = files.result ? readJson(resolveRepoPath(files.result.path)) : undefined;
  return writeCandidateBundle({ repoRoot, candidate, candidatePath, files, runId, sourceCommit, outDir, buildResult: result });
};

const buildLaneModule = async ({ candidate, candidatePath, runId, outDir }) => {
  const modulePath = resolveRepoPath(candidate.build.module);
  const adapter = await import(pathToFileURL(modulePath).href);
  if (typeof adapter.buildCandidate !== 'function') {
    throw new Error(`lane build module must export buildCandidate: ${candidate.build.module}`);
  }
  if (typeof adapter.validateBuild === 'function') adapter.validateBuild(candidate.build);
  const result = await adapter.buildCandidate({
    candidate,
    candidatePath,
    runId,
    outDir,
    repoRoot,
    sourceCommit: currentCommit(),
  });
  if (!result?.bundle || !result?.bundlePath) throw new Error(`lane build module returned an invalid result: ${candidate.build.module}`);
  assertValid('bundle', result.bundle);
  return result;
};

export const buildCandidateBundle = async (candidateInput, options = {}) => {
  const candidatePath = resolveRepoPath(candidateInput);
  const candidate = assertValid('candidate', readJson(candidatePath));
  const digest = hashCanonical(candidate);
  const runId = options.runId ?? makeRunId(candidate.id, digest);
  const outDir = options.out
    ? resolveRepoPath(options.out)
    : resolveRepoPath(`.vc/runs/${runId}`);
  mkdirSync(dirname(outDir), { recursive: true });
  try {
    mkdirSync(outDir);
  } catch (error) {
    if (error?.code === 'EEXIST') throw new Error(`run output already exists; choose a unique --run-id or --out: ${outDir}`);
    throw error;
  }
  if (candidate.build.adapter === 'artifact-bundle') return bundleArtifact({ candidate, candidatePath, runId, outDir });
  if (candidate.build.adapter === 'lane-module') return buildLaneModule({ candidate, candidatePath, runId, outDir });
  throw new Error(`unsupported build adapter: ${candidate.build.adapter}`);
};
