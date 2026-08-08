#!/usr/bin/env node
/**
 * S2 Smoke — Chipnet 5 deposit + 1 transfer + 5 withdraw via product CLI when
 * environment is ready; otherwise one fail-closed scorecard (no multi-retry).
 *
 * Env:
 *   SHIELDKIT_BENCH_DATA_HOME — product data-home
 *   SHIELDKIT_BENCH_PAYOUT — external bchtest P2PKH (not fee wallet)
 */
import { spawnSync } from 'node:child_process';
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
  writeJson,
} from './product-prove.mjs';

const CLI = path.resolve(import.meta.dirname, '../../scripts/shieldkit.mjs');

function parseArgs(argv) {
  let outPath = null;
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--out') {
      outPath = path.resolve(argv[i + 1] ?? '');
      i += 1;
    } else if (argv[i] === '--help' || argv[i] === '-h') {
      return { help: true };
    } else {
      throw new Error(`unknown argument: ${argv[i]}`);
    }
  }
  return { outPath };
}

function runCli(args) {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: { ...process.env },
    maxBuffer: 20 * 1024 * 1024,
  });
  return result;
}

function parseOkJson(stdout) {
  try {
    const body = JSON.parse(stdout);
    return body;
  } catch {
    return null;
  }
}

export async function runS2() {
  const commit = resolveGitCommit(productRootFromBench());
  const maxUnlock = designedMaxUnlockBytes();
  const dataHome = process.env.SHIELDKIT_BENCH_DATA_HOME;
  const payout = process.env.SHIELDKIT_BENCH_PAYOUT;

  if (typeof dataHome !== 'string' || dataHome.length === 0) {
    return buildScorecard({
      design: DESIGN_PF10_BASELINE,
      commit,
      story: 'S2',
      N: 11,
      ok: false,
      first_try: true,
      max_unlock_bytes: maxUnlock,
      notes: 'blocker: SHIELDKIT_BENCH_DATA_HOME unset (Chipnet product data-home required for S2)',
    });
  }
  if (typeof payout !== 'string' || !payout.startsWith('bchtest:')) {
    return buildScorecard({
      design: DESIGN_PF10_BASELINE,
      commit,
      story: 'S2',
      N: 11,
      ok: false,
      first_try: true,
      max_unlock_bytes: maxUnlock,
      notes: 'blocker: SHIELDKIT_BENCH_PAYOUT unset or not bchtest P2PKH (must be external, not fee wallet)',
    });
  }

  const totals = [];
  const txids = [];
  try {
    for (let i = 1; i <= 5; i += 1) {
      const r = runCli(['pool', 'deposit', '--data-home', dataHome, '--json']);
      const body = parseOkJson(r.stdout);
      if (r.status !== 0 || body?.ok !== true) {
        const code = body?.error?.code || `exit_${r.status}`;
        const msg = body?.error?.message || r.stderr?.slice(0, 200) || 'deposit failed';
        return buildScorecard({
          design: DESIGN_PF10_BASELINE,
          commit,
          story: 'S2',
          N: 11,
          ok: false,
          first_try: true,
          max_unlock_bytes: maxUnlock,
          notes: `blocker: deposit ${i} ${code}: ${msg}`,
        });
      }
      totals.push(body.result?.timingsMs?.commandTotal ?? body.result?.timingsMs?.commandTotalMs);
      txids.push(body.result?.transactionId);
    }

    // transfer needs a note id from wallet — fail closed if not provided
    const noteId = process.env.SHIELDKIT_BENCH_NOTE_ID;
    if (typeof noteId !== 'string' || !/^[0-9a-f]{64}$/u.test(noteId)) {
      return buildScorecard({
        design: DESIGN_PF10_BASELINE,
        commit,
        story: 'S2',
        N: 11,
        ok: false,
        first_try: true,
        max_unlock_bytes: maxUnlock,
        notes: `blocker: deposits ok (${txids.filter(Boolean).length}/5) but SHIELDKIT_BENCH_NOTE_ID required for transfer; txids=${txids.filter(Boolean).join(',')}`,
      });
    }

    {
      const r = runCli(['pool', 'transfer', '--data-home', dataHome, '--note', noteId, '--json']);
      const body = parseOkJson(r.stdout);
      if (r.status !== 0 || body?.ok !== true) {
        return buildScorecard({
          design: DESIGN_PF10_BASELINE,
          commit,
          story: 'S2',
          N: 11,
          ok: false,
          first_try: true,
          max_unlock_bytes: maxUnlock,
          notes: `blocker: transfer ${body?.error?.code || r.status}: ${body?.error?.message || 'failed'}`,
        });
      }
      totals.push(body.result?.timingsMs?.commandTotal ?? body.result?.timingsMs?.commandTotalMs);
      txids.push(body.result?.transactionId);
    }

    for (let i = 1; i <= 5; i += 1) {
      const r = runCli(['pool', 'withdraw', '--data-home', dataHome, '--to', payout, '--json']);
      const body = parseOkJson(r.stdout);
      if (r.status !== 0 || body?.ok !== true) {
        return buildScorecard({
          design: DESIGN_PF10_BASELINE,
          commit,
          story: 'S2',
          N: 11,
          ok: false,
          first_try: true,
          max_unlock_bytes: maxUnlock,
          notes: `blocker: withdraw ${i} ${body?.error?.code || r.status}: ${body?.error?.message || 'failed'}`,
        });
      }
      totals.push(body.result?.timingsMs?.commandTotal ?? body.result?.timingsMs?.commandTotalMs);
      txids.push(body.result?.transactionId);
    }

    const samples = totals.filter((v) => typeof v === 'number' && Number.isFinite(v));
    return buildScorecard({
      design: DESIGN_PF10_BASELINE,
      commit,
      story: 'S2',
      N: 11,
      ok: true,
      first_try: true,
      prove_ms_p50: null,
      prove_ms_p95: null,
      total_ms_p95: samples.length ? percentile(samples, 0.95) : null,
      max_unlock_bytes: maxUnlock,
      notes: `5d+1t+5w first-try; txids=${txids.join(',')}`,
    });
  } catch (error) {
    return buildScorecard({
      design: DESIGN_PF10_BASELINE,
      commit,
      story: 'S2',
      N: 11,
      ok: false,
      first_try: true,
      max_unlock_bytes: maxUnlock,
      notes: `blocker: ${error.code || 'ERROR'}: ${error.message}`,
    });
  }
}

async function main(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    process.stdout.write(
      'usage: node run-s2.mjs [--out scorecard.json]\n'
      + 'env: SHIELDKIT_BENCH_DATA_HOME SHIELDKIT_BENCH_PAYOUT [SHIELDKIT_BENCH_NOTE_ID]\n',
    );
    return;
  }
  const card = await runS2();
  process.stdout.write(`${JSON.stringify(card, null, 2)}\n`);
  if (args.outPath) await writeJson(args.outPath, card);
  // S2 fail-closed is allowed for goal green; exit 0 so harness can capture scorecard
  process.exitCode = 0;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
    process.exitCode = 1;
  });
}
