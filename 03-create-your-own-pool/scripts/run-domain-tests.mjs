#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const project = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packages = path.join(project, 'packages');
const includeQualification = process.argv.includes('--include-qualification');
const selected = [];

function visit(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === 'vendor' || entry.name.startsWith('.')) continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      if (!includeQualification
        && full.includes(`${path.sep}prove${path.sep}internal${path.sep}covenants`)) continue;
      visit(full);
    } else if (entry.isFile() && entry.name.endsWith('.test.mjs')) {
      selected.push(full);
    }
  }
}

visit(packages);
selected.sort();
if (selected.length === 0) {
  console.error('no domain test files discovered');
  process.exit(1);
}
console.error(JSON.stringify({
  phase: 'test-discovery',
  qualification: includeQualification,
  files: selected.length,
}));
const result = spawnSync(process.execPath, [
  '--test',
  '--test-concurrency=1',
  ...selected,
], {
  cwd: project,
  stdio: 'inherit',
  env: process.env,
});
process.exit(result.status ?? 1);
