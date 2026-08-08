#!/usr/bin/env node
/**
 * Phase 6 deliberate promote: copy selected immutable run records into evidence/.
 * Raw bench/results remain gitignored; promotion is explicit.
 */
import {
  copyFileSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  existsSync,
} from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

import { RUN_SCHEMA, validateRunRecord } from './schema.mjs';
import { SDK_ROOT } from './adapters/common.mjs';

const DEFAULT_EVIDENCE = path.join(SDK_ROOT, 'evidence/action-benchmark');

export function promoteRecords({ sources, destDir = DEFAULT_EVIDENCE, label = null }) {
  if (!Array.isArray(sources) || sources.length === 0) {
    throw new Error('sources must be a non-empty array of run record paths');
  }
  mkdirSync(destDir, { recursive: true });
  const promoted = [];
  for (const src of sources) {
    const abs = path.resolve(src);
    if (!existsSync(abs)) throw new Error(`missing source: ${abs}`);
    const raw = readFileSync(abs);
    const record = validateRunRecord(JSON.parse(raw.toString('utf8')));
    if (record.schema !== RUN_SCHEMA) throw new Error('not a v2 run record');
    const name = `${record.design}-${record.action}-${record.provenance.recordSha256.slice(0, 16)}.json`;
    const dest = path.join(destDir, name);
    copyFileSync(abs, dest);
    promoted.push({
      source: abs,
      dest,
      recordSha256: record.provenance.recordSha256,
      design: record.design,
      action: record.action,
      outcome: record.outcome.class,
    });
  }
  const manifest = {
    schema: 'shieldkit-action-benchmark-promote/v1',
    label,
    promotedAt: new Date().toISOString(),
    destDir,
    items: promoted,
    contentSha256: createHash('sha256')
      .update(JSON.stringify(promoted))
      .digest('hex'),
  };
  const manifestPath = path.join(destDir, `promote-${Date.now()}.json`);
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  return { manifest, manifestPath, promoted };
}

function parseArgs(argv) {
  const out = { sources: [], destDir: DEFAULT_EVIDENCE, label: null, help: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--help' || a === '-h') out.help = true;
    else if (a === '--dest') out.destDir = path.resolve(argv[++i] ?? '');
    else if (a === '--label') out.label = argv[++i];
    else if (a === '--') continue;
    else if (a.startsWith('-')) throw new Error(`unknown argument: ${a}`);
    else out.sources.push(path.resolve(a));
  }
  return out;
}

export async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (args.help || args.sources.length === 0) {
    process.stdout.write(
      'usage: node bench/pipeline/promote.mjs [--dest DIR] [--label TEXT] RUN.json...\n'
      + 'Copies validated v2 run records into evidence/action-benchmark/ (explicit promote).\n',
    );
    return { ok: args.help === true };
  }
  const result = promoteRecords(args);
  process.stdout.write(`${JSON.stringify({ ok: true, manifestPath: result.manifestPath, count: result.promoted.length }, null, 2)}\n`);
  return { ok: true, ...result };
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
    process.exitCode = 2;
  });
}
