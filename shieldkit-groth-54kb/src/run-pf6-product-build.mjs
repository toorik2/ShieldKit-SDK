// ShieldKit-54KB WP-3: pf6 PRODUCT build (structural 9-input, SDA2, product VK).
// buildCandidate intentionally throws after the main build for structuralRoleCount=3;
// we catch it and report the produced artifacts (result.json etc.).
import { readFileSync, mkdirSync, copyFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const folder = '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/shieldkit-groth-54kb';
const ws = path.join(folder, 'vendor/verifier-workspace');
const runId = process.env.RUN_ID ?? 'pf6-a3-product-r1';
const outDir = path.join(ws, '.vc/runs', runId);
const candidateName = process.env.CANDIDATE ?? 'bn254-onetx-pf6-a3-shieldkit-r1.json';

const { buildCandidate } = await import(
  pathToFileURL(path.join(ws, 'lanes/bn254-onetx/src/build-adapter.mjs')).href
);

const candidateSrc = path.join(folder, 'vendor/pf6-lane/candidates', candidateName);
const candidatePath = path.join(outDir, 'candidate.json');
mkdirSync(path.dirname(candidatePath), { recursive: true });
copyFileSync(candidateSrc, candidatePath);
const candidate = JSON.parse(readFileSync(candidatePath, 'utf8'));

console.log(`[runner] runId=${runId} candidate=${candidate.id}`);
const t0 = Date.now();
try {
  const result = buildCandidate({
    candidate, candidatePath, runId, outDir,
    repoRoot: ws, sourceCommit: process.env.SOURCE_COMMIT ?? 'current-worktree',
  });
  console.log(`[runner] buildCandidate returned in ${((Date.now() - t0) / 1000).toFixed(1)}s (unexpected for structural)`);
  console.log(JSON.stringify(result.bundle.buildResult ?? {}, null, 1).slice(0, 800));
} catch (e) {
  console.log(`[runner] buildCandidate threw (expected for structural build): ${String(e.message).slice(0, 300)}`);
}
const resultPath = path.join(outDir, 'build/result.json');
if (!existsSync(resultPath)) {
  console.error('[runner] FATAL: no result.json produced');
  process.exit(1);
}
const res = JSON.parse(readFileSync(resultPath, 'utf8'));
console.log(`[runner] elapsed ${((Date.now() - t0) / 1000).toFixed(1)}s`);
console.log(JSON.stringify(res, null, 1).slice(0, 3000));
