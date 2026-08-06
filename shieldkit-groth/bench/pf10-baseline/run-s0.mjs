#!/usr/bin/env node
/**
 * S0 Micro — one deposit-shaped native prove via shipped product prove path.
 * No Chipnet. Optional --out <file> writes scorecard JSON.
 */
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  DESIGN_PF10_BASELINE,
  buildScorecard,
  resolveGitCommit,
} from '../scorecard.mjs';
import {
  designedMaxUnlockBytes,
  proveDepositOnce,
  resolveFirstUsableDataHome,
  writeJson,
  productRootFromBench,
} from './product-prove.mjs';

function parseArgs(argv) {
  const out = { outPath: null };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--out') {
      out.outPath = path.resolve(argv[i + 1] ?? '');
      i += 1;
    } else if (argv[i] === '--help' || argv[i] === '-h') {
      out.help = true;
    } else {
      throw new Error(`unknown argument: ${argv[i]}`);
    }
  }
  return out;
}

export async function runS0() {
  const commit = resolveGitCommit(productRootFromBench());
  const maxUnlock = designedMaxUnlockBytes();
  try {
    const session = await resolveFirstUsableDataHome();
    const proof = await proveDepositOnce(session);
    return buildScorecard({
      design: DESIGN_PF10_BASELINE,
      commit,
      story: 'S0',
      N: 1,
      ok: true,
      first_try: true,
      prove_ms_p50: proof.proofGenerationMs,
      prove_ms_p95: proof.proofGenerationMs,
      total_ms_p95: proof.wallMs,
      tx_bytes: null,
      max_unlock_bytes: maxUnlock,
      notes: `deposit-shaped native prove instance=${session.instanceId}; unlock=max(DIRECT_V2_PF10_VERIFIER_UNLOCK_BYTES)`,
    });
  } catch (error) {
    return buildScorecard({
      design: DESIGN_PF10_BASELINE,
      commit,
      story: 'S0',
      N: 1,
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
    process.stdout.write('usage: node run-s0.mjs [--out scorecard.json]\n');
    return;
  }
  const card = await runS0();
  const text = `${JSON.stringify(card, null, 2)}\n`;
  process.stdout.write(text);
  if (args.outPath) await writeJson(args.outPath, card);
  if (card.ok !== true) process.exitCode = 1;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
    process.exitCode = 1;
  });
}
