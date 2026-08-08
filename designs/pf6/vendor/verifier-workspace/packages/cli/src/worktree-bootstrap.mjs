import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname, relative, resolve } from 'node:path';

import { repoRoot } from './repo.mjs';

const readConfig = () => JSON.parse(readFileSync(resolve(repoRoot, 'control-plane.json'), 'utf8'));

const ensureDirectoryLink = ({ source, target, required, label }) => {
  if (!existsSync(source)) {
    if (required) throw new Error(`required arena dependency is missing: ${label}; run ./setup.sh in the primary checkout`);
    return { label, status: 'missing-optional' };
  }
  if (existsSync(target) || (() => { try { lstatSync(target); return true; } catch { return false; } })()) {
    const stat = lstatSync(target);
    if (!stat.isSymbolicLink() || resolve(dirname(target), readlinkSync(target)) !== resolve(source)) {
      throw new Error(`arena bootstrap target already exists and is not the expected link: ${target}`);
    }
    return { label, status: 'present', target };
  }
  mkdirSync(dirname(target), { recursive: true });
  symlinkSync(resolve(source), target, 'dir');
  return { label, status: 'linked', target };
};

export const bootstrapWorktree = (worktreeRoot) => {
  const config = readConfig().worktreeBootstrap;
  const links = [];
  for (const entry of config.links) {
    links.push(ensureDirectoryLink({
      source: resolve(repoRoot, entry.path),
      target: resolve(worktreeRoot, entry.path),
      required: entry.required === true,
      label: entry.path,
    }));
  }
  for (const entry of config.externalLinks) {
    links.push(ensureDirectoryLink({
      source: resolve(repoRoot, entry.source),
      target: resolve(worktreeRoot, entry.target),
      required: entry.required === true,
      label: entry.target,
    }));
  }
  const report = {
    schema: 'verifier.cash/worktree-bootstrap/v1',
    sourceCheckout: repoRoot,
    worktree: worktreeRoot,
    createdAt: new Date().toISOString(),
    links: links.map((entry) => ({
      label: entry.label,
      status: entry.status,
      ...(entry.target ? { target: relative(worktreeRoot, entry.target).split('\\').join('/') } : {}),
    })),
  };
  const reportPath = resolve(worktreeRoot, '.vc/bootstrap.json');
  mkdirSync(dirname(reportPath), { recursive: true });
  writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  return report;
};

export const verifyWorktreeBootstrap = (worktreeRoot) => {
  const config = readConfig().worktreeBootstrap;
  const requiredTargets = [
    ...config.links.filter((entry) => entry.required).map((entry) => entry.path),
    ...config.externalLinks.filter((entry) => entry.required).map((entry) => entry.target),
  ];
  const missing = requiredTargets.filter((path) => !existsSync(resolve(worktreeRoot, path)));
  return { ok: missing.length === 0, missing };
};
