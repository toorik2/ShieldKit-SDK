import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseArgs } from './run-action.mjs';
import { RUN_SCHEMA } from './schema.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ENTRY = path.join(HERE, 'run-action.mjs');

test('parseArgs requires design and normalizes withdraw', () => {
  const args = parseArgs(['--design', 'pf10', '--action', 'withdraw', '--data-home', '/tmp/x']);
  assert.equal(args.design, 'pf10');
  assert.equal(args.action, 'withdrawal');
  assert.throws(() => parseArgs(['--design', 'nope', '--action', 'deposit']), /design/);
});

test('CLI help names schema and disclaims component/isolated-proof benches', () => {
  const r = spawnSync(process.execPath, [ENTRY, '--help'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, new RegExp(RUN_SCHEMA.replace('/', '\\/')));
  assert.match(r.stdout, /NOT the component S0\/S1\/S2/);
  assert.match(r.stdout, /NOT cli isolated-proof/);
  assert.match(r.stdout, /mempool membership/);
});
