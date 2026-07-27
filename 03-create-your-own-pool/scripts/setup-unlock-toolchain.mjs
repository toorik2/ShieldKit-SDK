#!/usr/bin/env node
/**
 * Blank-machine unlock toolchain (densFuel / C7 pin).
 *
 * Regenerates gitignored bulk under packages/unlock-builder/vendor/verifier:
 *   - cashc-resched dist + node_modules
 *   - verifier root / harness / build node_modules
 *   - packages/unlock-builder tsx
 *
 * Explicit after the root `npm ci`; postinstall never performs nested resolution.
 */
import { spawnSync } from 'node:child_process';
import {
  existsSync, mkdirSync, symlinkSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const UB = path.join(ROOT, '03-create-your-own-pool/packages/unlock-builder');
const VERIFIER = path.join(UB, 'vendor/verifier');
const CASHC = path.join(VERIFIER, 'vendor/cashc-resched');
const CASHC_PKG = path.join(CASHC, 'packages/cashc');
const LEAN = path.join(UB, 'vendor/lean');

function log(msg) {
  console.error(`[unlock-setup] ${msg}`);
}

function run(cwd, cmd, opts = {}) {
  log(`${path.relative(ROOT, cwd)}: ${cmd.join(' ')}`);
  const r = spawnSync(cmd[0], cmd.slice(1), {
    cwd,
    stdio: opts.quiet ? 'pipe' : 'inherit',
    env: opts.env || process.env,
    encoding: 'utf8',
  });
  if (r.status !== 0) {
    const err = new Error(
      `command failed (${r.status ?? r.error?.code ?? 'null'}): ${cmd.join(' ')}`
      + (r.error ? ` — ${r.error.message}` : ''),
    );
    err.cause = r.error;
    throw err;
  }
  return r;
}

function ensureDir(p) {
  mkdirSync(p, { recursive: true });
}

function linkCashc() {
  const linkPath = path.join(VERIFIER, 'build/node_modules/cashc');
  ensureDir(path.dirname(linkPath));
  const target = CASHC_PKG;
  if (existsSync(linkPath)) {
    log('cashc link/path already present');
    return;
  }
  symlinkSync(target, linkPath);
  log(`wired build/node_modules/cashc -> ${path.relative(ROOT, target)}`);
}

function main() {
  if (process.env.SHIELDKIT_SKIP_UNLOCK_SETUP === '1') {
    log('skip (SHIELDKIT_SKIP_UNLOCK_SETUP=1)');
    return;
  }
  if (!existsSync(path.join(VERIFIER, 'lanes/bn254-onetx/src/c7/build.ts'))) {
    log(`FAIL: verifier pin missing at ${VERIFIER}`);
    process.exit(1);
  }
  if (!existsSync(path.join(LEAN, 'optimizer')) && !existsSync(path.join(LEAN, 'optimizer/passes/fold.mjs'))) {
    log(`WARN: lean pin incomplete at ${LEAN} (unlock may still resolve)`);
  }

  const tsxBin = path.join(ROOT, 'node_modules/.bin/tsx');
  const yarnBin = path.join(ROOT, 'node_modules/.bin/yarn');
  const pnpmBin = path.join(ROOT, 'node_modules/.bin/pnpm');
  for (const [name, executable] of [
    ['tsx', tsxBin],
    ['yarn', yarnBin],
    ['pnpm', pnpmBin],
  ]) {
    if (!existsSync(executable)) {
      throw new Error(`${name} missing from the immutable root workspace; run npm ci`);
    }
  }

  // 1) cashc fork dist. Yarn itself is root-lockfile-pinned; its nested dependency
  // graph remains frozen by the tracked vendor yarn.lock.
  const cashcDist = path.join(CASHC_PKG, 'dist');
  if (existsSync(path.join(cashcDist, 'cashc-cli.js')) || existsSync(path.join(cashcDist, 'index.js'))) {
    log('cashc dist present');
  } else {
    log('building cashc-resched (first blank-machine install; can take several minutes)');
    const yarnEnvironment = {
      ...process.env,
      SKIP_YARN_COREPACK_CHECK: '1',
    };
    run(CASHC, [
      yarnBin,
      'install',
      '--frozen-lockfile',
      '--ignore-engines',
      '--ignore-scripts',
    ], { env: yarnEnvironment });
    run(CASHC, [yarnBin, 'build'], { env: yarnEnvironment });
  }

  // 2) verifier root dependency graph is immutable.
  if (!existsSync(path.join(VERIFIER, 'node_modules'))) {
    if (!existsSync(path.join(VERIFIER, 'package-lock.json'))) {
      throw new Error('verifier root package-lock.json is required');
    }
    run(VERIFIER, ['npm', 'ci', '--no-audit', '--no-fund']);
  } else {
    log('verifier node_modules present');
  }

  // 3) build/ + harness use their tracked pnpm locks and the root-lockfile-pinned pnpm.
  for (const sub of ['build', 'harness']) {
    const dir = path.join(VERIFIER, sub);
    if (!existsSync(path.join(dir, 'package.json'))) {
      log(`skip missing ${sub}/`);
      continue;
    }
    if (existsSync(path.join(dir, 'node_modules')) && existsSync(path.join(dir, 'node_modules/.bin'))) {
      log(`${sub}/ node_modules present`);
      continue;
    }
    if (!existsSync(path.join(dir, 'pnpm-lock.yaml'))) {
      throw new Error(`${sub}/pnpm-lock.yaml is required`);
    }
    run(dir, [pnpmBin, 'install', '--frozen-lockfile']);
  }

  linkCashc();

  // 4) preflight exact root-workspace executables.
  log(`ok tsx=${tsxBin}`);
  log(`ok leanRoot candidate=${LEAN}`);
  log('unlock toolchain ready');
}

try {
  main();
} catch (e) {
  console.error(`[unlock-setup] ${e.message || e}`);
  process.exit(1);
}
