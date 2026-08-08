#!/usr/bin/env node
/**
 * S1 Ladder — N sequential deposit-shaped native proves (local, no Chipnet).
 * Usage: node run-s1.mjs --N 10 [--out scorecard.json]
 */
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  DESIGN_PF10_BASELINE,
  buildScorecard,
  percentile,
  resolveGitCommit,
} from '../scorecard.mjs';
import {
  designedMaxUnlockBytes,
  productRootFromBench,
  proveDepositOnce,
  resolveFirstUsableDataHome,
  writeJson,
} from './product-prove.mjs';

function parseArgs(argv) {
  let N = 10;
  let outPath = null;
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--N') {
      N = Number(argv[i + 1]);
      i += 1;
    } else if (argv[i] === '--out') {
      outPath = path.resolve(argv[i + 1] ?? '');
      i += 1;
    } else if (argv[i] === '--help' || argv[i] === '-h') {
      return { help: true };
    } else {
      throw new Error(`unknown argument: ${argv[i]}`);
    }
  }
  if (!Number.isSafeInteger(N) || N < 1) throw new Error('--N must be a positive integer');
  return { N, outPath };
}

export async function runS1({ N = 10 } = {}) {
  const commit = resolveGitCommit(productRootFromBench());
  const maxUnlock = designedMaxUnlockBytes();
  try {
    const session = await resolveFirstUsableDataHome();
    const proveSamples = [];
    const wallSamples = [];
    for (let i = 0; i < N; i += 1) {
      // First-try only: any prove failure aborts the ladder immediately.
      const proof = await proveDepositOnce(session);
      proveSamples.push(proof.proofGenerationMs);
      wallSamples.push(proof.wallMs);
    }
    return buildScorecard({
      design: DESIGN_PF10_BASELINE,
      commit,
      story: 'S1',
      N,
      ok: true,
      first_try: true,
      prove_ms_p50: percentile(proveSamples, 0.5),
      prove_ms_p95: percentile(proveSamples, 0.95),
      total_ms_p95: percentile(wallSamples, 0.95),
      tx_bytes: null,
      max_unlock_bytes: maxUnlock,
      notes: `N=${N} sequential deposit-shaped native proves; instance=${session.instanceId}`,
    });
  } catch (error) {
    return buildScorecard({
      design: DESIGN_PF10_BASELINE,
      commit,
      story: 'S1',
      N,
      ok: false,
      first_try: true,
      prove_ms_p50: null,
      prove_ms_p95: null,
      total_ms_p95: null,
      tx_bytes: null,
      max_unlock_bytes: maxUnlock,
      notes: `blocker: ${error.code || 'ERROR'}: ${error.message}`,
    });
  }
}

async function main(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    process.stdout.write('usage: node run-s1.mjs --N 10 [--out scorecard.json]\n');
    return;
  }
  const card = await runS1({ N: args.N });
  process.stdout.write(`${JSON.stringify(card, null, 2)}\n`);
  if (args.outPath) await writeJson(args.outPath, card);
  if (card.ok !== true) process.exitCode = 1;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
    process.exitCode = 1;
  });
}
