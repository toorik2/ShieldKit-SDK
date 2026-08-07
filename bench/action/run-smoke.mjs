#!/usr/bin/env node
/**
 * Phase 5 smoke: one live (or honest fail-closed) run per design × action.
 * Nine cells: pf10|pf6|fri × deposit|transfer|withdrawal.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';

import { runPf10Action } from './adapters/pf10.mjs';
import { runPf6Action } from './adapters/pf6.mjs';
import { runFriAction } from './adapters/fri.mjs';
import { validateRunRecord, RUN_SCHEMA } from './schema.mjs';
import { OUTCOME_CLASSES } from './outcomes.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DESIGNS = ['pf10', 'pf6', 'fri'];
const ACTIONS = ['deposit', 'transfer', 'withdrawal'];

export function parseSmokeArgs(argv) {
  const out = {
    outDir: null,
    dataHome: process.env.SHIELDKIT_BENCH_DATA_HOME || process.env.SHIELDKIT_DATA_HOME || null,
    pf6DataHome: process.env.SHIELDKIT_PF6_DATA_HOME || null,
    to: process.env.SHIELDKIT_BENCH_PAYOUT || null,
    note: process.env.SHIELDKIT_BENCH_NOTE_ID || null,
    live: process.env.SHIELDKIT_ACTION_BENCH_LIVE === '1'
      || process.env.SHIELDKIT_FRI_BENCH_LIVE === '1',
    campaignId: process.env.SHIELDKIT_BENCH_CAMPAIGN_ID || `smoke-${randomUUID()}`,
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--help' || a === '-h') out.help = true;
    else if (a === '--out-dir') out.outDir = path.resolve(argv[++i] ?? '');
    else if (a === '--data-home') out.dataHome = path.resolve(argv[++i] ?? '');
    else if (a === '--pf6-data-home') out.pf6DataHome = path.resolve(argv[++i] ?? '');
    else if (a === '--to') out.to = argv[++i];
    else if (a === '--note') out.note = argv[++i];
    else if (a === '--live') out.live = true;
    else if (a === '--campaign-id') out.campaignId = argv[++i];
    else throw new Error(`unknown argument: ${a}`);
  }
  return out;
}

export function printHelp(stream = process.stdout) {
  stream.write(
    'Phase 5 action-benchmark smoke — 9 design×action cells\n'
    + `schema: ${RUN_SCHEMA}\n`
    + 'Each cell: one first-try real path OR plan-legal fail-closed outcome.\n'
    + 'No fixtures, synthetic circuits, or prebuilt unlocks.\n'
    + '\n'
    + 'usage:\n'
    + '  node bench/action/run-smoke.mjs --out-dir DIR [--data-home ABS] [--live]\n'
    + '  npm run bench:action:smoke -- --out-dir /path\n',
  );
}

function runCell(design, action, args) {
  const common = {
    action,
    campaignId: args.campaignId,
    cacheMode: 'warm-resident',
    to: args.to,
    note: args.note,
    live: args.live,
  };
  if (design === 'pf10') {
    return runPf10Action({ ...common, dataHome: args.dataHome });
  }
  if (design === 'pf6') {
    return runPf6Action({
      ...common,
      dataHome: args.pf6DataHome || args.dataHome,
    });
  }
  return runFriAction(common);
}

/**
 * Assert record is complete v2 and plan-legal.
 */
export function assertSmokeRecord(record) {
  const v = validateRunRecord(record);
  if (v.schema !== RUN_SCHEMA) throw new Error('schema mismatch');
  if (!OUTCOME_CLASSES.includes(v.outcome.class)) throw new Error('illegal outcome');
  if (v.acceptance.tmaIsAcceptance !== false) throw new Error('TMA must not be acceptance');
  if (v.outcome.class === 'accepted') {
    if (!/^[0-9a-f]{64}$/.test(v.acceptance.txid)) {
      throw new Error('accepted row needs full 64-char txid');
    }
    if (v.firstTry !== true) throw new Error('accepted requires firstTry');
  }
  // No multi-retry greenwash: attempts on proof spans should be 1 for accepted
  // (visible higher attempts only if production truly retried — still firstTry policy)
  return v;
}

export function runSmoke(args) {
  if (args.help) {
    printHelp();
    return { ok: true, mode: 'help', records: [] };
  }
  const outDir = args.outDir || path.join(HERE, '../results/smoke');
  mkdirSync(outDir, { recursive: true });

  const records = [];
  const index = [];
  for (const design of DESIGNS) {
    for (const action of ACTIONS) {
      const record = runCell(design, action, args);
      const validated = assertSmokeRecord(record);
      const file = path.join(outDir, `${design}-${action}.json`);
      writeFileSync(file, `${JSON.stringify(validated, null, 2)}\n`, 'utf8');
      records.push(validated);
      index.push({
        design,
        action,
        outcome: validated.outcome.class,
        txid: validated.acceptance.txid,
        file,
        recordSha256: validated.provenance.recordSha256,
      });
      process.stderr.write(
        `smoke ${design}×${action} → ${validated.outcome.class}`
        + `${validated.acceptance.txid ? ` txid=${validated.acceptance.txid}` : ''}\n`,
      );
    }
  }

  const indexPath = path.join(outDir, 'smoke-index.json');
  writeFileSync(indexPath, `${JSON.stringify({
    schema: 'shieldkit-action-benchmark-smoke-index/v1',
    campaignId: args.campaignId,
    cells: index,
  }, null, 2)}\n`, 'utf8');

  process.stdout.write(`${JSON.stringify({
    ok: true,
    campaignId: args.campaignId,
    cells: index.length,
    indexPath,
    outcomes: Object.fromEntries(index.map((c) => [`${c.design}-${c.action}`, c.outcome])),
  }, null, 2)}\n`);

  return { ok: true, records, index, outDir };
}

export async function main(argv = process.argv.slice(2)) {
  return runSmoke(parseSmokeArgs(argv));
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
    process.exitCode = 2;
  });
}
