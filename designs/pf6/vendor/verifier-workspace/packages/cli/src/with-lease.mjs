#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { resolve } from 'node:path';

import { repoRoot } from './repo.mjs';

const [name, separator, command, ...args] = process.argv.slice(2);
if (!name || separator !== '--' || !command || !/^[a-z0-9][a-z0-9._-]*$/.test(name)) {
  console.error('usage: with-lease NAME -- COMMAND [ARGS...]');
  process.exit(2);
}

const locksRoot = resolve(repoRoot, '.vc/locks');
const lockPath = resolve(locksRoot, `${name}.lock`);
mkdirSync(locksRoot, { recursive: true });

const staleLocalLock = () => {
  if (!existsSync(resolve(lockPath, 'owner.json'))) return false;
  try {
    const owner = JSON.parse(readFileSync(resolve(lockPath, 'owner.json'), 'utf8'));
    if (owner.host !== hostname()) return false;
    process.kill(owner.pid, 0);
    return false;
  } catch (error) {
    return error?.code === 'ESRCH' || error instanceof SyntaxError;
  }
};

if (existsSync(lockPath) && staleLocalLock()) rmSync(lockPath, { recursive: true, force: true });
try {
  mkdirSync(lockPath);
} catch (error) {
  const owner = existsSync(resolve(lockPath, 'owner.json')) ? readFileSync(resolve(lockPath, 'owner.json'), 'utf8').trim() : 'unknown owner';
  console.error(`lease already held: ${name}\n${owner}`);
  process.exit(1);
}

writeFileSync(resolve(lockPath, 'owner.json'), `${JSON.stringify({
  schema: 'verifier.cash/lease/v1',
  name,
  pid: process.pid,
  host: hostname(),
  startedAt: new Date().toISOString(),
  command: [command, ...args],
}, null, 2)}\n`);

try {
  const result = spawnSync(command, args, { cwd: repoRoot, env: process.env, stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.signal) {
    console.error(`leased command terminated by ${result.signal}`);
    process.exitCode = 1;
  } else {
    process.exitCode = result.status ?? 1;
  }
} finally {
  rmSync(lockPath, { recursive: true, force: true });
}
