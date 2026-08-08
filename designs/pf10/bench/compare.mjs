#!/usr/bin/env node
/**
 * Compare two shieldkit-component-bench-scorecard-v1 JSON files.
 * Usage: node compare.mjs <left.json> <right.json>
 */
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  formatCompareTableFromCards,
  validateScorecard,
} from './scorecard.mjs';

async function loadCard(filename) {
  const resolved = path.resolve(filename);
  const raw = await readFile(resolved, 'utf8');
  return validateScorecard(JSON.parse(raw));
}

async function main(argv) {
  if (argv.length !== 2) {
    process.stderr.write('usage: node compare.mjs <left.json> <right.json>\n');
    process.exitCode = 2;
    return;
  }
  const [leftPath, rightPath] = argv;
  const left = await loadCard(leftPath);
  const right = await loadCard(rightPath);
  process.stdout.write(`${formatCompareTableFromCards(left, right)}\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
