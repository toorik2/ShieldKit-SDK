import os from 'node:os';
import path from 'node:path';

export class UnsafePathError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UnsafePathError';
    this.code = 'UNSAFE_PATH';
  }
}

/**
 * Refuse recursive replacement of filesystem roots, the home directory, the repository,
 * the current working directory, or any ancestor containing one of those paths.
 */
export function assertSafeReplaceDirectory(candidate, { repositoryRoot } = {}) {
  const target = path.resolve(String(candidate || ''));
  const protectedPaths = new Set([
    path.parse(target).root,
    path.resolve(os.homedir()),
    path.resolve(process.cwd()),
  ]);
  if (repositoryRoot) protectedPaths.add(path.resolve(repositoryRoot));
  for (const protectedPath of protectedPaths) {
    if (target === protectedPath || protectedPath.startsWith(`${target}${path.sep}`)) {
      throw new UnsafePathError(`refusing recursive replacement of protected path: ${target}`);
    }
  }
  if (target.split(path.sep).filter(Boolean).length < 2) {
    throw new UnsafePathError(`refusing unusually broad replacement path: ${target}`);
  }
  return target;
}
