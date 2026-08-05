import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

export const repoRoot = fileURLToPath(new URL('../', import.meta.url));

export const repoPath = (relativePath = '') => {
  const resolved = resolve(repoRoot, relativePath);
  return relativePath.endsWith('/') ? `${resolved}/` : resolved;
};
