#!/usr/bin/env node
/**
 * Primary action-benchmark entry (BENCHMARK_PLAN.md).
 *
 * Emits shieldkit-action-benchmark-run/v2 from real design action paths.
 * This is NOT the component S0/S1/S2 scorecard and NOT cli isolated-proof --bench.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { runPf10Action } from './adapters/pf10.mjs';
import { runPf6Action } from './adapters/pf6.mjs';
import { runFriAction } from './adapters/fri.mjs';
import { RUN_SCHEMA } from './schema.mjs';
import { normalizeAction } from './adapters/common.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_RESULTS = path.resolve(HERE, '../results');

const DESIGNS = new Set(['pf10', 'pf6', 'fri']);
const ACTIONS = new Set(['deposit', 'transfer', 'withdrawal', 'withdraw']);

export function parseArgs(argv) {
  const out = {
    design: null,
    action: 'deposit',
    dataHome: process.env.SHIELDKIT_BENCH_DATA_HOME
      || process.env.SHIELDKIT_DATA_HOME
      || null,
    to: process.env.SHIELDKIT_BENCH_PAYOUT || null,
    note: process.env.SHIELDKIT_BENCH_NOTE_ID || null,
    jsonOut: null,
    campaignId: process.env.SHIELDKIT_BENCH_CAMPAIGN_ID || null,
    cacheMode: 'warm-resident',
    live: process.env.SHIELDKIT_ACTION_BENCH_LIVE === '1',
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--help' || a === '-h') out.help = true;
    else if (a === '--design') out.design = argv[++i];
    else if (a === '--action' || a === '--kind') out.action = argv[++i];
    else if (a === '--data-home') out.dataHome = path.resolve(argv[++i] ?? '');
    else if (a === '--to') out.to = argv[++i];
    else if (a === '--note') out.note = argv[++i];
    else if (a === '--json-out') out.jsonOut = path.resolve(argv[++i] ?? '');
    else if (a === '--campaign-id') out.campaignId = argv[++i];
    else if (a === '--cache-mode') out.cacheMode = argv[++i];
    else if (a === '--live') out.live = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  if (!out.help) {
    if (!DESIGNS.has(out.design)) {
      throw new Error('--design must be pf10|pf6|fri');
    }
    if (!ACTIONS.has(out.action)) {
      throw new Error('--action must be deposit|transfer|withdrawal');
    }
    out.action = normalizeAction(out.action);
  }
  return out;
}

export function printHelp(stream = process.stdout) {
  stream.write(
    'ShieldKit action benchmark (primary end-to-end)\n'
    + `schema: ${RUN_SCHEMA}\n`
    + 'plan:   BENCHMARK_PLAN.md\n'
    + '\n'
    + 'This entry measures real pool actions to exact BCHN mempool observation.\n'
    + 'It is NOT the component S0/S1/S2 scorecard and NOT cli isolated-proof --bench.\n'
    + '\n'
    + 'usage:\n'
    + '  node bench/pipeline/run-action.mjs --design pf10|pf6|fri --action deposit|transfer|withdrawal [options]\n'
    + '  npm run bench:action -- --design pf10 --action deposit --data-home /abs/path\n'
    + '\n'
    + 'options:\n'
    + '  --data-home ABS   product data home (required for pf10 live)\n'
    + '  --to ADDRESS      withdrawal payout\n'
    + '  --note 64hex      transfer note id\n'
    + '  --json-out FILE   write run record (default bench/results/<design>-<action>.json)\n'
    + '  --campaign-id ID  group runs\n'
    + '  --cache-mode warm-resident|cold-installed|readiness\n'
    + '  --live            allow FRI multi-GB prove (or SHIELDKIT_FRI_BENCH_LIVE=1)\n'
    + '  --help\n'
    + '\n'
    + 'acceptance: sendrawtransaction + exact mempool membership (TMA is never acceptance)\n'
    + 'first-try only; failures retained as plan outcome classes\n'
    + 'results under bench/results/ are gitignored; use bench/pipeline/promote.mjs to promote\n',
  );
}

export function runOne(args) {
  const common = {
    action: args.action,
    dataHome: args.dataHome,
    to: args.to,
    note: args.note,
    campaignId: args.campaignId,
    cacheMode: args.cacheMode,
    live: args.live,
  };
  if (args.design === 'pf10') return runPf10Action(common);
  if (args.design === 'pf6') return runPf6Action(common);
  if (args.design === 'fri') return runFriAction(common);
  throw new Error(`unknown design: ${args.design}`);
}

export async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (args.help) {
    printHelp();
    return { ok: true, mode: 'help' };
  }
  const record = runOne(args);
  const out = args.jsonOut || path.join(
    DEFAULT_RESULTS,
    `${record.design}-${record.action}-${record.runId}.json`,
  );
  mkdirSync(path.dirname(out), { recursive: true });
  writeFileSync(out, `${JSON.stringify(record, null, 2)}\n`, 'utf8');
  process.stdout.write(`${JSON.stringify({
    ok: record.outcome.class === 'accepted' || record.outcome.class === 'accepted_commit_failed',
    schema: record.schema,
    design: record.design,
    action: record.action,
    outcome: record.outcome.class,
    txid: record.acceptance?.txid ?? null,
    jsonOut: out,
    recordSha256: record.provenance.recordSha256,
  }, null, 2)}\n`);
  return { ok: true, record, jsonOut: out };
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
    process.exitCode = 2;
  });
}
