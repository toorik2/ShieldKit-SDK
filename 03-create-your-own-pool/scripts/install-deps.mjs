#!/usr/bin/env node
/**
 * Install package-local deps so cold clones can run shieldkit / playground.
 * Root `npm install` runs this via postinstall.
 */
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const PKGS = path.join(ROOT, '03-create-your-own-pool/packages');

const STEPS = [
  // action first: pool-act / complete-action import libauth from packages/action/node_modules
  {
    dir: path.join(PKGS, 'action'),
    cmd: ['npm', 'install', '--no-fund', '--no-audit',
      '@bitauth/libauth@^3.1.0-next.8', 'circomlibjs@^0.1.7'],
  },
  { dir: path.join(PKGS, 'profile'), cmd: ['npm', 'install', '--no-fund', '--no-audit'] },
  {
    dir: path.join(PKGS, 'kit'),
    cmd: ['npm', 'install', '--no-fund', '--no-audit',
      '@bitauth/libauth@^3.1.0-next.8', 'poseidon-lite@^0.3.0'],
  },
  {
    dir: path.join(PKGS, 'recover'),
    cmd: ['npm', 'install', '--no-fund', '--no-audit',
      '@bitauth/libauth@^3.1.0-next.8', '@noble/hashes@^1.4.0', 'poseidon-lite@^0.3.0', 'circomlibjs@^0.1.7'],
  },
  {
    dir: path.join(PKGS, 'prove'),
    cmd: ['npm', 'install', '--no-fund', '--no-audit',
      '@bitauth/libauth@^3.1.0-next.8', '@noble/curves@^1.4.0', '@noble/hashes@^1.4.0', 'ffjavascript@^0.3.0'],
  },
  // tsx for densFuel unlock compile (full toolchain via setup-unlock-toolchain.mjs)
  { dir: path.join(PKGS, 'unlock-builder'), cmd: ['npm', 'install', '--no-fund', '--no-audit'] },
];

/** Hard gate: blank-machine acts fail with ERR_MODULE_NOT_FOUND if these are missing. */
const REQUIRED_MODULES = [
  path.join(PKGS, 'action/node_modules/@bitauth/libauth/build/index.js'),
  path.join(PKGS, 'kit/node_modules/@bitauth/libauth/build/index.js'),
  path.join(PKGS, 'profile/node_modules/snarkjs/package.json'),
];

function run(dir, cmd) {
  if (!existsSync(dir)) {
    console.error(`skip missing ${dir}`);
    return;
  }
  console.log(`→ ${path.relative(ROOT, dir)}: ${cmd.join(' ')}`);
  const r = spawnSync(cmd[0], cmd.slice(1), {
    cwd: dir, stdio: 'inherit', env: process.env,
  });
  if (r.status !== 0) {
    console.error(`FAIL in ${dir}`);
    process.exit(r.status ?? 1);
  }
}

for (const s of STEPS) run(s.dir, s.cmd);

for (const mod of REQUIRED_MODULES) {
  if (!existsSync(mod)) {
    console.error(`install-deps: missing required module after install: ${path.relative(ROOT, mod)}`);
    console.error('Re-run: npm run install:deps');
    process.exit(1);
  }
}
console.log('install-deps: required modules present (action/kit libauth, profile snarkjs)');

// densFuel pin: cashc dist + harness/build node_modules (gitignored)
const unlockSetup = path.join(ROOT, '03-create-your-own-pool/scripts/setup-unlock-toolchain.mjs');
if (existsSync(unlockSetup) && process.env.SHIELDKIT_SKIP_UNLOCK_SETUP !== '1') {
  console.log('→ unlock toolchain setup');
  const r = spawnSync(process.execPath, [unlockSetup], {
    cwd: ROOT, stdio: 'inherit', env: process.env,
  });
  if (r.status !== 0) {
    console.error('FAIL unlock toolchain setup (blank-machine settlement needs this)');
    process.exit(r.status ?? 1);
  }
} else if (process.env.SHIELDKIT_SKIP_UNLOCK_SETUP === '1') {
  console.log('skip unlock toolchain (SHIELDKIT_SKIP_UNLOCK_SETUP=1)');
}

console.log('install-deps: ok');
