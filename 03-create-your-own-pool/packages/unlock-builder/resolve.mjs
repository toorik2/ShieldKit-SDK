import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = HERE;
/** 03-create-your-own-pool/ */
const CREATE_ROOT = path.resolve(HERE, '../..');
/** ShieldKit-SDK repo root (parent of 03-create-your-own-pool) */
const REPO_ROOT = path.resolve(CREATE_ROOT, '..');

function hasBuildEntry(root) {
  return existsSync(path.join(root, 'lanes/bn254-onetx/src/c7/build.ts'));
}

/**
 * Resolve C7 unlock toolchain root.
 * Order:
 *  1. explicit opts / SHIELDKIT_UNLOCK_ROOT / SHIELDKIT_PF7_WORKTREE
 *  2. packages/unlock-builder/vendor/verifier (shipped pin)
 *  3. packages/unlock-builder/vendor (flat layout)
 *  4. .worktrees/verifier-pf7-sub62 (dev escape hatch only)
 */
export function resolveUnlockRoot(opts = {}) {
  const candidates = [
    opts.unlockRoot,
    process.env.SHIELDKIT_UNLOCK_ROOT,
    process.env.SHIELDKIT_PF7_WORKTREE,
    path.join(PKG_ROOT, 'vendor/verifier'),
    path.join(PKG_ROOT, 'vendor'),
    path.join(REPO_ROOT, '.worktrees/verifier-pf7-sub62'),
  ].filter(Boolean).map((p) => path.resolve(p));

  for (const root of candidates) {
    if (hasBuildEntry(root)) return root;
  }
  throw new Error(
    'unlock-builder: no C7 toolchain root found. '
    + 'Expected packages/unlock-builder/vendor/verifier (shipped) '
    + 'or SHIELDKIT_UNLOCK_ROOT.',
  );
}

/**
 * Resolve LeanBCH root (fold optimizer only needed at runtime).
 */
export function resolveLeanRoot(opts = {}) {
  const candidates = [
    opts.leanRoot,
    process.env.SHIELDKIT_LEANBCH,
    path.join(PKG_ROOT, 'vendor/lean'),
    path.join(PKG_ROOT, 'vendor/lean-optimizer-host'),
    path.join(REPO_ROOT, '.worktrees/leanbch-pf7'),
  ].filter(Boolean).map((p) => path.resolve(p));

  for (const root of candidates) {
    if (existsSync(path.join(root, 'optimizer/passes/fold.mjs'))
      || existsSync(path.join(root, 'optimizer'))) {
      return root;
    }
  }
  throw new Error(
    'unlock-builder: no LeanBCH root found. Expected packages/unlock-builder/vendor/lean.',
  );
}

export function resolveTsxBin(unlockRoot) {
  const candidates = [
    // package-local first (blank-machine; no absolute symlinks to sibling repos)
    path.join(PKG_ROOT, 'node_modules/.bin/tsx'),
    path.join(unlockRoot, 'harness/node_modules/.bin/tsx'),
    path.join(unlockRoot, 'node_modules/.bin/tsx'),
  ];
  for (const bin of candidates) {
    if (existsSync(bin)) return bin;
  }
  // PATH fallback
  return 'tsx';
}

export { PKG_ROOT, REPO_ROOT, CREATE_ROOT };
