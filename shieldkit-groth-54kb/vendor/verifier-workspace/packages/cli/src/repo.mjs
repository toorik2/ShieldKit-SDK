import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');

export const resolveRepoPath = (path) => {
  const resolved = resolve(repoRoot, path);
  const rel = relative(repoRoot, resolved);
  if (rel.startsWith(`..${sep}`) || rel === '..' || rel.startsWith(sep)) {
    throw new Error(`path escapes repository: ${path}`);
  }
  return resolved;
};

export const repoRelative = (path) => relative(repoRoot, resolve(path)).split(sep).join('/');

export const git = (args, options = {}) => execFileSync('git', args, {
  cwd: options.cwd ?? repoRoot,
  encoding: 'utf8',
  stdio: options.stdio ?? ['ignore', 'pipe', 'pipe'],
}).trim();

export const currentCommit = () => git(['rev-parse', 'HEAD']);

export const makeRunId = (candidateId, digest) => {
  const stamp = new Date().toISOString().replace(/[-:.]/g, '').toLowerCase();
  return `${stamp}-${candidateId}-${digest.slice(0, 10)}-${randomUUID().slice(0, 8)}`;
};

export const writeJson = (path, value) => {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
};

export const parseOptions = (args) => {
  const positionals = [];
  const options = {};
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (!arg.startsWith('--')) {
      positionals.push(arg);
      continue;
    }
    const name = arg.slice(2);
    if (['allow-local', 'dry-run', 'yes'].includes(name)) {
      options[name] = true;
      continue;
    }
    const value = args[++index];
    if (value === undefined) throw new Error(`missing value for --${name}`);
    options[name] = value;
  }
  return { positionals, options };
};
