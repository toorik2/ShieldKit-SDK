#!/usr/bin/env node
/**
 * Campaign summary + human report from immutable run records.
 * No global scalar winner.
 */
import { readdirSync, readFileSync, mkdirSync, writeFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  RUN_SCHEMA,
  buildCampaignSummary,
  formatCampaignReport,
  validateRunRecord,
} from './schema.mjs';

export function loadRunsFromDir(dir) {
  const files = readdirSync(dir).filter((f) => f.endsWith('.json') && f !== 'smoke-index.json');
  const runs = [];
  for (const f of files) {
    const p = path.join(dir, f);
    if (!statSync(p).isFile()) continue;
    let raw;
    try {
      raw = JSON.parse(readFileSync(p, 'utf8'));
    } catch {
      continue; // skip non-JSON noise (e.g. npm script banners redirected to .json)
    }
    if (!raw || raw.schema !== RUN_SCHEMA) continue;
    runs.push(validateRunRecord(raw));
  }
  return runs;
}

export function generateReport({ runsDir, outDir, campaignId = null }) {
  const runs = loadRunsFromDir(runsDir);
  if (runs.length === 0) {
    throw new Error(`no ${RUN_SCHEMA} records in ${runsDir}`);
  }
  const id = campaignId || runs[0].campaignId;
  const summary = buildCampaignSummary({ campaignId: id, runs });
  const text = formatCampaignReport(summary);
  mkdirSync(outDir, { recursive: true });
  const jsonPath = path.join(outDir, 'campaign-summary.json');
  const textPath = path.join(outDir, 'campaign-report.txt');
  writeFileSync(jsonPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');
  writeFileSync(textPath, `${text}\n`, 'utf8');
  return { summary, text, jsonPath, textPath };
}

function parseArgs(argv) {
  const out = { runsDir: null, outDir: null, campaignId: null, help: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--help' || a === '-h') out.help = true;
    else if (a === '--runs-dir') out.runsDir = path.resolve(argv[++i] ?? '');
    else if (a === '--out-dir') out.outDir = path.resolve(argv[++i] ?? '');
    else if (a === '--campaign-id') out.campaignId = argv[++i];
    else throw new Error(`unknown argument: ${a}`);
  }
  return out;
}

export async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (args.help || !args.runsDir || !args.outDir) {
    process.stdout.write(
      'usage: node bench/action/report.mjs --runs-dir DIR --out-dir DIR [--campaign-id ID]\n',
    );
    return { ok: args.help === true };
  }
  const result = generateReport(args);
  process.stdout.write(result.text);
  process.stdout.write(`\njson=${result.jsonPath}\n`);
  return { ok: true, ...result };
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
    process.exitCode = 2;
  });
}
