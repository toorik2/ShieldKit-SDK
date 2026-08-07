#!/usr/bin/env node
/**
 * Item-1 gate — RANDOM-MASK PROVER MODE (production-randomness upgrade).
 * - Random mode (default): two proofs of the same statement differ in bytes; maskSource=csprng.
 * - Deterministic mode (explicit seed + randomMask:false): byte-reproducible.
 * - Product-config random prove verifies.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { ROOT, writeJson } from './lib/evidence.mjs';

const outDir = path.join(ROOT, 'evidence/random-mask');
mkdirSync(outDir, { recursive: true });
const WORKER = path.join(ROOT, '.private/cargo-target/release/shieldkit-fri-worker');

function worker(req) {
  const r = spawnSync(WORKER, [], { input: JSON.stringify(req) + '\n', encoding: 'utf8', cwd: ROOT, timeout: 600_000 });
  if (r.status !== 0) return { error: (r.stderr || r.stdout || '').slice(0, 500) };
  const lines = (r.stdout || '').split('\n').filter((l) => l.trim().startsWith('{'));
  return lines.length ? JSON.parse(lines[lines.length - 1]) : { error: 'no JSON' };
}

const small = { cmd: 'prove', kind: 'transfer', depth: 4, blowup: 4, queries: 2, grindBits: 2, foldStep: 1, maskDeg: 8, deep: true };
const r1 = worker(small);
const r2 = worker(small);
const d1 = worker({ ...small, seed: 7, randomMask: false });
const d2 = worker({ ...small, seed: 7, randomMask: false });

const checks = [
  { id: 'random-verify-ok', ok: r1.verifyOk === true && r2.verifyOk === true },
  { id: 'random-mask-source-csprng', ok: r1.maskSource === 'csprng(thread_rng, 128-bit)' && r1.maskSeed === null },
  { id: 'random-proofs-differ', ok: r1.proofBlobSha256 !== r2.proofBlobSha256 },
  { id: 'random-same-statement', ok: r1.statement?.root === r2.statement?.root && r1.statement?.nf === r2.statement?.nf },
  { id: 'deterministic-reproducible', ok: d1.verifyOk === true && d1.proofBlobSha256 === d2.proofBlobSha256 },
  { id: 'deterministic-mask-source', ok: d1.maskSource === 'splitmix64(seed)' && d1.maskSeed === 7 },
];

// product-config random prove (timing + verify)
const t0 = Date.now();
const prod = worker({ cmd: 'prove', kind: 'transfer', depth: 20, blowup: 2048, queries: 7, grindBits: 30, foldStep: 3, maskDeg: 24, deep: true });
const prodWall = (Date.now() - t0) / 1000;
checks.push({ id: 'product-random-verify', ok: prod.verifyOk === true && prod.maskSource === 'csprng(thread_rng, 128-bit)' });
checks.push({ id: 'product-random-timing', ok: prodWall <= 120, wallSeconds: Math.round(prodWall * 10) / 10 });

const ok = checks.every((c) => c.ok);
const report = {
  gate: 'ITEM1-RANDOM-MASK',
  name: 'random-mask-prover-mode',
  ok,
  checks,
  samples: {
    random: { sha1: r1.proofBlobSha256?.slice(0, 16), sha2: r2.proofBlobSha256?.slice(0, 16),
              statementRoot: r1.statement?.root, maskSource: r1.maskSource, maskSeed: r1.maskSeed, witnessSeed: r1.witnessSeed },
    deterministic: { sha1: d1.proofBlobSha256?.slice(0, 16), sha2: d2.proofBlobSha256?.slice(0, 16), maskSource: d1.maskSource, maskSeed: d1.maskSeed },
    productConfig: { wallSeconds: Math.round(prodWall * 10) / 10, maskSource: prod.maskSource, verifyOk: prod.verifyOk },
  },
  notes: 'Production default is now random (CSPRNG mask, 128-bit effective entropy via two interleaved SplitMix64 streams seeded from rand::thread_rng). Explicit seed + randomMask:false preserves the deterministic test/oracle path.',
  timestamp: new Date().toISOString(),
};
writeJson(path.join(outDir, 'ITEM1_RANDOM_MASK.json'), report);
console.log(JSON.stringify(report, null, 2));
process.exit(ok ? 0 : 1);
