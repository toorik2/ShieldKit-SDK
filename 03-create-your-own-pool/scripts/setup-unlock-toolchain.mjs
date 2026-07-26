#!/usr/bin/env node
/**
 * Blank-machine unlock toolchain (densFuel / C7 pin).
 *
 * Regenerates gitignored bulk under packages/unlock-builder/vendor/verifier:
 *   - cashc-resched dist + node_modules
 *   - verifier root / harness / build node_modules
 *   - packages/unlock-builder tsx
 *
 * Invoked from install-deps (postinstall). Skip with SHIELDKIT_SKIP_UNLOCK_SETUP=1.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, symlinkSync } from 'node:fs';
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
    env: process.env,
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

  // 1) package-local tsx
  run(UB, ['npm', 'install', '--no-fund', '--no-audit']);

  // 2) cashc fork dist
  // Parent vendor/verifier sets packageManager=npm@…; yarn classic needs COREPACK_ENABLE_STRICT=0.
  const cashcEnv = {
    ...process.env,
    COREPACK_ENABLE_STRICT: '0',
  };
  const cashcDist = path.join(CASHC_PKG, 'dist');
  if (existsSync(path.join(cashcDist, 'cashc-cli.js')) || existsSync(path.join(cashcDist, 'index.js'))) {
    log('cashc dist present');
  } else {
    log('building cashc-resched (first blank-machine install; can take several minutes)');
    run(CASHC, ['npx', '-y', 'yarn@1.22.22', 'install', '--frozen-lockfile'], { env: cashcEnv });
    run(CASHC, ['npx', '-y', 'yarn@1.22.22', 'build'], { env: cashcEnv });
  }

  // 3) verifier root deps
  if (!existsSync(path.join(VERIFIER, 'node_modules'))) {
    if (existsSync(path.join(VERIFIER, 'package-lock.json'))) {
      run(VERIFIER, ['npm', 'ci', '--no-audit', '--no-fund']);
    } else {
      run(VERIFIER, ['npm', 'install', '--no-audit', '--no-fund']);
    }
  } else {
    log('verifier node_modules present');
  }

  // 4) build/ + harness (pnpm)
  try {
    spawnSync('corepack', ['enable'], { stdio: 'ignore' });
  } catch {
    // optional
  }
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
    const lock = existsSync(path.join(dir, 'pnpm-lock.yaml'));
    if (lock) {
      run(dir, ['corepack', 'pnpm', 'install', '--frozen-lockfile']);
    } else {
      run(dir, ['npm', 'install', '--no-audit', '--no-fund']);
    }
  }

  linkCashc();

  // 5) preflight tsx
  const tsxBin = path.join(UB, 'node_modules/.bin/tsx');
  if (!existsSync(tsxBin)) {
    log(`FAIL: tsx missing after install: ${tsxBin}`);
    process.exit(1);
  }
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
