#!/usr/bin/env node
/**
 * Print full act pipeline timings (tip → mempool → commit).
 *
 * Modes:
 *   --from-store   Read last accepted ops from data-home store (no network)
 *   --live         Run one product CLI act (deposit|transfer|withdraw)
 *
 * Env / flags:
 *   --data-home <abs>   or SHIELDKIT_BENCH_DATA_HOME / SHIELDKIT_DATA_HOME
 *   --kind deposit|transfer|withdraw   (live default: deposit)
 *   --to <bchtest>                     (withdraw)
 *   --note <64hex>                     (transfer/withdraw optional)
 *   --limit N                          (from-store, default 3)
 *   --json-out <file>                  machine-readable report(s)
 */
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

import {
  DESIGN_PF10_BASELINE,
  resolveGitCommit,
} from '../scorecard.mjs';
import {
  buildPipelineReport,
  formatPipelineTable,
  pipelineSourceFromCliResult,
} from '../pipeline.mjs';
import { productRootFromBench } from './product-prove.mjs';

const CLI = path.resolve(import.meta.dirname, '../../scripts/shieldkit.mjs');

function parseArgs(argv) {
  const out = {
    mode: null,
    dataHome: process.env.SHIELDKIT_BENCH_DATA_HOME
      || process.env.SHIELDKIT_DATA_HOME
      || null,
    kind: 'deposit',
    to: process.env.SHIELDKIT_BENCH_PAYOUT || null,
    note: process.env.SHIELDKIT_BENCH_NOTE_ID || null,
    limit: 3,
    jsonOut: null,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--from-store') out.mode = 'store';
    else if (a === '--live') out.mode = 'live';
    else if (a === '--data-home') { out.dataHome = path.resolve(argv[++i] ?? ''); }
    else if (a === '--kind') { out.kind = argv[++i]; }
    else if (a === '--to') { out.to = argv[++i]; }
    else if (a === '--note') { out.note = argv[++i]; }
    else if (a === '--limit') { out.limit = Number(argv[++i]); }
    else if (a === '--json-out') { out.jsonOut = path.resolve(argv[++i] ?? ''); }
    else if (a === '--help' || a === '-h') out.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  if (!out.help && !out.mode) {
    throw new Error('specify --from-store or --live');
  }
  if (!out.help && (typeof out.dataHome !== 'string' || !path.isAbsolute(out.dataHome))) {
    throw new Error('--data-home / SHIELDKIT_BENCH_DATA_HOME must be an absolute path');
  }
  if (!out.help && out.mode === 'live' && !['deposit', 'transfer', 'withdraw'].includes(out.kind)) {
    throw new Error('--kind must be deposit|transfer|withdraw');
  }
  if (!out.help && (!Number.isSafeInteger(out.limit) || out.limit < 1)) {
    throw new Error('--limit must be a positive integer');
  }
  return out;
}

function productDataDirectory(dataHome) {
  // Accept either …/shieldkit-packed-… or …/v2-beta-product
  if (dataHome.endsWith(`${path.sep}v2-beta-product`)) return dataHome;
  return path.join(dataHome, 'shieldkit', 'v2-beta-product');
}

function loadFromStore(dataDirectory, limit) {
  const session = JSON.parse(
    readFileSync(path.join(dataDirectory, 'session.json'), 'utf8'),
  );
  const storePath = session.storeDatabasePath
    || path.join(dataDirectory, 'store', 'pool.sqlite');
  const db = new DatabaseSync(storePath, { readOnly: true });
  const rows = db.prepare(
    `SELECT operation_id, kind, transaction_artifact, accepted_txid
     FROM operations
     WHERE state = 'accepted_zero_conf' AND transaction_artifact IS NOT NULL
     ORDER BY rowid DESC
     LIMIT ?`,
  ).all(limit);
  db.close();
  return rows.map((row) => {
    const artifact = JSON.parse(
      typeof row.transaction_artifact === 'string'
        ? row.transaction_artifact
        : Buffer.from(row.transaction_artifact).toString('utf8'),
    );
    const txid = row.accepted_txid
      ? Buffer.from(row.accepted_txid).toString('hex')
      : artifact.transactionId ?? null;
    return {
      operationId: row.operation_id,
      kind: row.kind === 'withdrawal' ? 'withdraw' : row.kind,
      transactionId: txid,
      actionTimingsMs: artifact.timingsMs ?? {},
      notes: 'from store transaction_artifact (admission/commit usually absent pre-send snapshot)',
    };
  });
}

function runLive(args) {
  const cliArgs = ['pool', args.kind, '--data-home', args.dataHome, '--json'];
  if (args.kind === 'withdraw') {
    if (!args.to) throw new Error('withdraw requires --to / SHIELDKIT_BENCH_PAYOUT');
    cliArgs.push('--to', args.to);
  }
  if ((args.kind === 'transfer' || args.kind === 'withdraw') && args.note) {
    cliArgs.push('--note', args.note);
  }
  if (args.kind === 'transfer' && !args.note) {
    throw new Error('transfer requires --note / SHIELDKIT_BENCH_NOTE_ID');
  }
  const result = spawnSync(process.execPath, [CLI, ...cliArgs], {
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
    env: { ...process.env },
  });
  let envelope;
  try {
    envelope = JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(
      `CLI did not return JSON (exit ${result.status}): ${result.stderr?.slice(0, 400) || error.message}`,
    );
  }
  if (envelope.ok !== true) {
    const code = envelope.error?.code || `exit_${result.status}`;
    const msg = envelope.error?.message || 'command failed';
    throw new Error(`${code}: ${msg}`);
  }
  const src = pipelineSourceFromCliResult(envelope);
  return [{
    operationId: src.operationId,
    kind: src.kind || args.kind,
    transactionId: src.transactionId,
    actionTimingsMs: src.actionTimingsMs,
    cliTimingsMs: src.cliTimingsMs,
    notes: 'live product CLI (full admission+commit when present)',
  }];
}

async function main(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    process.stdout.write(
      'usage:\n'
      + '  node run-pipeline.mjs --from-store --data-home ABS [--limit 3] [--json-out file]\n'
      + '  node run-pipeline.mjs --live --data-home ABS [--kind deposit|transfer|withdraw]\n'
      + '       [--to bchtest:…] [--note 64hex] [--json-out file]\n',
    );
    return;
  }

  const commit = resolveGitCommit(productRootFromBench());
  const dataDir = productDataDirectory(args.dataHome);
  let samples;
  if (args.mode === 'store') {
    samples = loadFromStore(dataDir, args.limit);
    if (samples.length === 0) {
      throw new Error(`no accepted operations with timings under ${dataDir}`);
    }
  } else {
    samples = runLive(args);
  }

  const reports = samples.map((sample) => buildPipelineReport({
    design: DESIGN_PF10_BASELINE,
    commit,
    kind: sample.kind,
    transactionId: sample.transactionId,
    operationId: sample.operationId,
    source: {
      actionTimingsMs: sample.actionTimingsMs,
      cliTimingsMs: sample.cliTimingsMs ?? {},
    },
    notes: sample.notes ?? '',
  }));

  for (let i = 0; i < reports.length; i += 1) {
    if (i > 0) process.stdout.write(`\n${'='.repeat(72)}\n\n`);
    process.stdout.write(`${formatPipelineTable(reports[i])}\n`);
  }

  if (args.jsonOut) {
    await mkdir(path.dirname(args.jsonOut), { recursive: true });
    const payload = reports.length === 1 ? reports[0] : reports;
    await writeFile(args.jsonOut, `${JSON.stringify(payload, null, 2)}\n`);
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
