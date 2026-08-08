#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tests = spawnSync(
  'node',
  [
    '--test',
    'packages/core/codecs/wire.test.mjs',
    'packages/settlement/settlement.test.mjs',
  ],
  { cwd: root, stdio: 'inherit' },
);
process.exit(tests.status ?? 1);
