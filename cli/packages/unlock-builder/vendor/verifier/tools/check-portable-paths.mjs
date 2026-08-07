#!/usr/bin/env node
import { readFileSync, readdirSync } from 'node:fs';
import { extname, join } from 'node:path';

const roots = ['build', 'fri_stark', 'fri_stark55', 'harness/src', 'intel/validation', 'lanes', 'packages', 'tools'];
const extensions = new Set(['.mjs', '.js', '.ts', '.sh']);
const forbidden = [
  '/home/toorik/Projects/verifier.cash',
  'C:/Users/mathi',
  'groth16_cashscript/',
  'cashscript/packages/',
  '../zk-verifier-bench/',
];

const filesUnder = (directory) => readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
  const path = join(directory, entry.name);
  if (entry.isDirectory()) {
    if (entry.name === 'node_modules' || entry.name === 'generated') return [];
    return filesUnder(path);
  }
  return extensions.has(extname(entry.name)) ? [path] : [];
});

const violations = [];
for (const file of roots.flatMap(filesUnder)) {
  if (file.endsWith('check-portable-paths.mjs')) continue;
  const lines = readFileSync(file, 'utf8').split('\n');
  for (const [index, line] of lines.entries()) {
    for (const pattern of forbidden) {
      if (line.includes(pattern)) violations.push(`${file}:${index + 1}: ${pattern}`);
    }
  }
}

if (violations.length > 0) {
  console.error(violations.join('\n'));
  console.error(`found ${violations.length} non-portable active-source path references`);
  process.exitCode = 1;
} else {
  console.log('active source paths are repository-portable');
}
