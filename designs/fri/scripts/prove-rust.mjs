#!/usr/bin/env node
/**
 * Product prove entry via native shieldkit-fri-worker (Rust).
 * Python pool_prove remains oracle-only: npm run prove:oracle-*.
 *
 * Usage:
 *   node scripts/prove-rust.mjs selftest
 *   node scripts/prove-rust.mjs params
 *   node scripts/prove-rust.mjs prove --kind transfer --depth 20
 */
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BIN =
  process.env.SHIELDKIT_FRI_WORKER ||
  path.join(ROOT, '.private/cargo-target/release/shieldkit-fri-worker');

function needBin() {
  if (!existsSync(BIN)) {
    console.error(
      `missing ${BIN}\nBuild: CARGO_TARGET_DIR=.private/cargo-target cargo build -p shieldkit-fri-worker --release`,
    );
    process.exit(2);
  }
}

function worker(req) {
  needBin();
  const r = spawnSync(BIN, [], {
    input: JSON.stringify(req) + '\n',
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    cwd: ROOT,
  });
  if (r.error) {
    console.error(r.error);
    process.exit(1);
  }
  if (r.status !== 0) {
    if (r.stderr) process.stderr.write(r.stderr);
    if (r.stdout) process.stdout.write(r.stdout);
    process.exit(r.status ?? 1);
  }
  return r.stdout.trim();
}

const argv = process.argv.slice(2);
const cmd = argv[0] || 'selftest';

if (cmd === 'selftest') {
  const out = worker({
    cmd: 'prove',
    kind: 'transfer',
    depth: 4,
    seed: 1,
    eligibility: 'development-only',
  });
  console.log(out);
  const j = JSON.parse(out);
  if (!j.verifyOk || j.usesPython) process.exit(1);
  process.exit(0);
}

if (cmd === 'params' || cmd === 'manifest') {
  console.log(worker({ cmd: 'manifest' }));
  process.exit(0);
}

if (cmd === 'prove') {
  const args = Object.fromEntries(
    argv.slice(1).flatMap((a, i, arr) => {
      if (a.startsWith('--') && arr[i + 1] && !arr[i + 1].startsWith('--')) {
        return [[a.slice(2), arr[i + 1]]];
      }
      return [];
    }),
  );
  const kind = args.kind || 'transfer';
  const depth = Number(args.depth || 20);  // AMENDED 2026-08-06 (product config depth 20)
  const seed = Number(args.seed || 1);
  const eligibility = args.eligibility || 'final';
  const req = {
    cmd: 'prove',
    kind,
    depth,
    seed,
    blowup: 2048,
    queries: 7,      // AMENDED 2026-08-06: product config nq=7 (was 8)
    grindBits: 30,   // AMENDED 2026-08-06: product config grind=30 (was 24; 7*10+30 = 100 bit)
    foldStep: 3,
    maskDeg: 64,
    deep: true,
  };
  if (eligibility === 'development-only') {
    req.eligibility = 'development-only';
  }
  const out = worker(req);
  console.log(out);
  const j = JSON.parse(out);
  if (!j.verifyOk || j.usesPython) process.exit(1);
  process.exit(0);
}

console.error(`unknown command: ${cmd}`);
process.exit(2);
