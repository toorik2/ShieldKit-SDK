import { existsSync, mkdirSync, statSync, writeFileSync } from 'node:fs';
import { relative, resolve, sep } from 'node:path';

import { assertValid, hashCanonical, hashFile, schemas } from '../../contracts/src/index.mjs';

export const repoRelative = (repoRoot, path) => {
  const rel = relative(repoRoot, resolve(path));
  if (rel === '..' || rel.startsWith(`..${sep}`) || rel.startsWith(sep)) {
    throw new Error(`bundle path escapes repository: ${path}`);
  }
  return rel.split(sep).join('/');
};

export const makeFileRef = (repoRoot, path) => {
  if (!existsSync(path) || !statSync(path).isFile()) throw new Error(`bundle file does not exist: ${path}`);
  return {
    path: repoRelative(repoRoot, path),
    sha256: hashFile(path),
    bytes: statSync(path).size,
  };
};

export const writeCandidateBundle = ({
  repoRoot,
  candidate,
  candidatePath,
  files,
  runId,
  sourceCommit,
  outDir,
  buildResult,
}) => {
  const bundle = {
    schema: schemas.bundle,
    runId,
    candidateId: candidate.id,
    lane: candidate.lane,
    candidateManifest: repoRelative(repoRoot, candidatePath),
    candidateManifestSha256: hashCanonical(candidate),
    sourceCommit,
    capability: candidate.capability,
    toolchain: candidate.toolchain,
    provenance: candidate.provenance,
    judge: candidate.judge,
    files,
    ...(buildResult ? { buildResult } : {}),
  };
  assertValid('bundle', bundle);
  const bundlePath = resolve(outDir, 'bundle.json');
  mkdirSync(outDir, { recursive: true });
  writeFileSync(bundlePath, `${JSON.stringify(bundle, null, 2)}\n`);
  return { bundle, bundlePath, outDir };
};
