#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { canonicalJson, parseStrictJson } from '../core/verifier-profile.mjs';
import { runProfileReplacementDrill } from './profile-replacement-drill.mjs';

const usage = 'usage: node cli.mjs --input replacement-drill.json\n';
const args = process.argv.slice(2);

if (args.length !== 2 || args[0] !== '--input') {
  process.stderr.write(usage); process.exitCode = 64;
} else {
  try {
    const inputPath = path.resolve(args[1]);
    const parsed = parseStrictJson(await readFile(inputPath));
    for (const side of ['left', 'right']) {
      if (parsed?.[side] && typeof parsed[side] === 'object' && typeof parsed[side].bundleDirectory === 'string') {
        parsed[side].bundleDirectory = path.resolve(path.dirname(inputPath), parsed[side].bundleDirectory);
      }
    }
    process.stdout.write(`${canonicalJson(await runProfileReplacementDrill(parsed))}\n`);
  } catch (error) {
    process.stderr.write(`profile-replacement-drill: ${error.message}\n`); process.exitCode = 1;
  }
}
