#!/usr/bin/env node
// Assemble the strict fixed-deployment benchmark fixture from committed build outputs.
// The fixture keeps the exact lockings and witnesses; only the harness context differs
// from the portable profile (strict source UTXO values are 10,000 satoshis).
import { readFileSync, writeFileSync } from 'node:fs';

const args = process.argv.slice(2);
const values = (name) => {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === name && args[i + 1] !== undefined) out.push(args[++i]);
  }
  return out;
};
const one = (name) => values(name)[0];
const baseDir = one('--base');
const extraDirs = values('--extra');
const worstDir = one('--worst');
const output = one('--out');
const profile = one('--profile') ?? 'strict';
const sourceCommit = one('--source-commit') ?? '22ecb02093cacfe07e73d075c08010cd3a579ed3';
if (!baseDir || extraDirs.length !== 3 || !worstDir || !output) {
  throw new Error('usage: --base DIR --extra DIR --extra DIR --extra DIR --worst DIR --out FILE');
}
if (!['strict', 'public'].includes(profile)) throw new Error(`unsupported profile: ${profile}`);

const labels = ['exec0', 'exec1', 'exec2', 'exec3', 'exec4', 'exec5', 'exec6', 'genesis', 'finalize', 'fused'];
const checkpoints = ['executor-start', 'miller-interior', 'miller-interior', 'miller-interior', 'miller-interior', 'miller-interior', 'miller-interior', 'vkx-subgroup', 'finalize', 'pairing-close'];

const readRun = (dir) => {
  const rows = JSON.parse(readFileSync(`${dir}/inputs_dump.json`, 'utf8'));
  if (!Array.isArray(rows) || rows.length !== labels.length) throw new Error(`expected 10 inputs in ${dir}`);
  return rows.map((row, index) => ({
    label: labels[index],
    locking: row.lock,
    unlocking: row.unlock,
    checkpoint: checkpoints[index],
  }));
};

const base = readRun(baseDir);
const lockings = base.map((step) => step.locking);
const assertSameLockings = (run, dir) => {
  run.forEach((step, index) => {
    if (step.locking !== lockings[index]) throw new Error(`locking drift at ${dir} input ${index}`);
  });
};
const extras = extraDirs.map((dir) => {
  const run = readRun(dir);
  assertSameLockings(run, dir);
  return run;
});
const worst = readRun(worstDir);
assertSameLockings(worst, worstDir);

// Flip one bit in the largest pushed witness item for each input. This mirrors the
// benchmark's proof-tamper class while preserving push structure and byte lengths.
const tamperLargestPush = (hex) => {
  const bytes = Buffer.from(hex, 'hex');
  const ranges = [];
  let i = 0;
  while (i < bytes.length) {
    const op = bytes[i++];
    let length = -1;
    if (op >= 1 && op <= 0x4b) length = op;
    else if (op === 0x4c) length = bytes[i++];
    else if (op === 0x4d) {
      length = bytes[i] | (bytes[i + 1] << 8);
      i += 2;
    } else if (op === 0x4e) {
      length = bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24);
      i += 4;
    }
    if (length > 0) ranges.push([i, i + length]);
    if (length >= 0) i += length;
  }
  ranges.sort((a, b) => (b[1] - b[0]) - (a[1] - a[0]));
  const target = ranges[0];
  if (!target) throw new Error('no pushed witness item to tamper');
  bytes[target[0] + Math.floor((target[1] - target[0]) / 2)] ^= 1;
  return bytes.toString('hex');
};

const invalid = base.map((_, target) => base.map((step, index) => ({
  ...step,
  unlocking: index === target ? tamperLargestPush(step.unlocking) : step.unlocking,
})));

const fixture = {
  schema: profile === 'public' ? 'verifier.cash/bch-direct-state-public-v1' : 'verifier.cash/bch-direct-state-strict-v1',
  sourceProfile: profile === 'public'
    ? 'DIRECT_FINALIZE_STATE=1; DP=1; STRIPED=1; STRIPE_BOUNDARY=1; STRICT_DEPLOYMENT=1; PUBLIC_BENCH_CONTEXT=1; KWIN=9'
    : 'DIRECT_FINALIZE_STATE=1; DP=1; STRIPED=1; STRIPE_BOUNDARY=1; STRICT_DEPLOYMENT=1; KWIN=9',
  sourceCommit,
  sourceValueSatoshis: profile === 'public' ? 1000 : 10000,
  steps: base,
  extraValidProofs: extras,
  worstCaseProof: worst,
  invalid,
};
writeFileSync(output, `${JSON.stringify(fixture, null, 2)}\n`);
console.log(JSON.stringify({ output, steps: base.length, extras: extras.length, invalid: invalid.length, worst: worst.length }));
