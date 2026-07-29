#!/usr/bin/env node
/**
 * Chipnet story 5: wipe → recover → respend recovered note.
 * Delegates to product-1tx e2e with V2_STOP_AFTER=deposit-respend.
 */
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync, mkdirSync, copyFileSync } from 'node:fs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const SCRIPT = path.join(
  ROOT,
  '03-create-your-own-pool/packages/v2-direct/scripts/chipnet-product-1tx-e2e.mjs',
);
const OUT = path.join(ROOT, '.cache/v2-direct-recover-respend');

mkdirSync(OUT, { recursive: true });
const env = {
  ...process.env,
  V2_STOP_AFTER: 'deposit-respend',
  PUBLIC_BENCH_CONTEXT: '1',
  C7_SOURCE_VALUE_SATS: process.env.C7_SOURCE_VALUE_SATS || '10000',
  TMPDIR: process.env.TMPDIR || '/tmp/skd32',
};
const r = spawnSync(process.execPath, [SCRIPT], {
  cwd: ROOT,
  env,
  encoding: 'utf8',
  maxBuffer: 64 * 1024 * 1024,
});
console.log(r.stdout || '');
if (r.stderr) console.error(r.stderr);
const productOut = path.join(ROOT, '.cache/v2-direct-product-1tx');
if (existsSync(path.join(productOut, 'recover-respend-evidence.json'))) {
  copyFileSync(
    path.join(productOut, 'recover-respend-evidence.json'),
    path.join(OUT, 'evidence.json'),
  );
  copyFileSync(
    path.join(productOut, 'recover-respend-txids.txt'),
    path.join(OUT, 'txids.txt'),
  );
  console.log(JSON.stringify({ ok: true, evidence: path.join(OUT, 'evidence.json') }));
  process.exit(0);
}
console.error(JSON.stringify({ ok: false, status: r.status, signal: r.signal }));
process.exit(r.status || 1);
