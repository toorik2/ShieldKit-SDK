#!/usr/bin/env node
import { link, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { canonicalJson, parseStrictJson } from './load.mjs';
import { runProfileReplacementDrill } from './profile-replacement-drill.mjs';

const usage = 'usage: node cli.mjs --input replacement-drill.json [--output result.json]\n';
const args = process.argv.slice(2);

if (
  !(
    (args.length === 2 && args[0] === '--input')
    || (args.length === 4 && args[0] === '--input' && args[2] === '--output')
  )
) {
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
    const output = `${canonicalJson(await runProfileReplacementDrill(parsed))}\n`;
    if (args.length === 4) {
      const outputPath = path.resolve(args[3]); const parent = path.dirname(outputPath);
      const stage = path.join(parent, `.${path.basename(outputPath)}.staging-${process.pid}`);
      await mkdir(parent, { recursive: true });
      try {
        await writeFile(stage, output, { flag: 'wx', mode: 0o600 });
        // Same-directory hard-link publication is atomic and fails closed if
        // the caller-selected evidence path already exists.
        await link(stage, outputPath);
      } finally {
        await rm(stage, { force: true });
      }
    }
    process.stdout.write(output);
  } catch (error) {
    process.stderr.write(`profile-replacement-drill: ${error.message}\n`); process.exitCode = 1;
  }
}
