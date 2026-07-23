#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { canonicalJson, parseStrictJson } from '../core/verifier-profile.mjs';
import { initializeDevelopmentGroth16 } from './local-setup.mjs';

const usage = 'usage: node cli.mjs --input <metadata.json> [--entropy-fd <already-open-private-fd>]\n';
const args = process.argv.slice(2);
if (!(args.length === 2 || args.length === 4) || args[0] !== '--input' || (args.length === 4 && args[2] !== '--entropy-fd')) {
  process.stderr.write(usage); process.exitCode = 64;
} else {
  try {
    const inputPath = path.resolve(args[1]); const base = path.dirname(inputPath);
    const input = parseStrictJson(await readFile(inputPath));
    for (const key of ['destination', 'r1csPath', 'ptauPath']) if (typeof input[key] === 'string') input[key] = path.resolve(base, input[key]);
    input.entropySource = args.length === 4 ? { kind: 'fd', fd: Number(args[3]) } : { kind: 'stdin' };
    const result = await initializeDevelopmentGroth16(input);
    process.stdout.write(`${canonicalJson({ directory: result.directory, metadataPath: path.join(result.directory, 'setup-metadata.json'), mode: 'development-only' })}\n`);
  } catch (error) {
    process.stderr.write(`local-setup: ${error.message}\n`); process.exitCode = 1;
  }
}
