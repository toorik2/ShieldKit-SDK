#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { canonicalJson, packageProverArtifacts, parsePackageManifest } from './prover-artifact-budget.mjs';

const usage = 'usage: node cli.mjs --input manifest.json\n';
const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== '--input') {
  process.stderr.write(usage); process.exitCode = 64;
} else {
  try {
    const manifest = path.resolve(args[1]);
    const result = await packageProverArtifacts(parsePackageManifest(await readFile(manifest), manifest));
    process.stdout.write(`${canonicalJson(result)}\n`);
  } catch (error) {
    const message = String(error?.message ?? 'artifact packaging failed').replace(/[\r\n]/g, ' ').slice(0, 1024);
    process.stderr.write(`prover-artifact-budget: ${message}\n`); process.exitCode = 1;
  }
}
