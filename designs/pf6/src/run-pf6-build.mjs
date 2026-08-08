// ShieldKit-54KB WP-1: materialize the pf6-a3-r1 reference build.
// Runs buildCandidate from the vendored lane against the workspace copy.
import { readFileSync, mkdirSync, copyFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const folder = '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/designs/pf6';
const ws = path.join(folder, 'vendor/verifier-workspace');
const runId = process.env.RUN_ID ?? 'pf6-a3-r1-wp1';
const outDir = path.join(ws, '.vc/runs', runId);

const { buildCandidate } = await import(
  pathToFileURL(path.join(ws, 'lanes/bn254-onetx/src/build-adapter.mjs')).href
);

const candidateSrc = path.join(folder, 'vendor/pf6-lane/candidates/bn254-onetx-pf6-a3-r1.json');
const candidatePath = path.join(outDir, 'candidate.json');
mkdirSync(path.dirname(candidatePath), { recursive: true });
copyFileSync(candidateSrc, candidatePath);
const candidate = JSON.parse(readFileSync(candidatePath, 'utf8'));

console.log(`[runner] runId=${runId} outDir=${outDir}`);
console.log(`[runner] candidate=${candidate.id} lane=${candidate.lane}`);
const t0 = Date.now();
const result = buildCandidate({
  candidate,
  candidatePath,
  runId,
  outDir,
  repoRoot: ws,
  sourceCommit: process.env.SOURCE_COMMIT ?? 'current-worktree',
});
console.log(`[runner] buildCandidate returned in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
console.log(`[runner] bundle=${result.bundlePath}`);
console.log(JSON.stringify(result.bundle.buildResult ?? {}, null, 1).slice(0, 1500));
