#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { canonicalJson, parseStrictJson } from './load.mjs';
import { buildVerifierProfileBundle } from './build.mjs';

function usage() {
  return 'usage: node cli.mjs --input <metadata.json>\nThe CLI only packages caller-supplied artifact paths; it never generates setup, proof, or fixture artifacts.\n';
}

function resolveMetadataPaths(input, metadataPath) {
  const base = path.dirname(metadataPath);
  const resolveSource = (source) => {
    if (source && typeof source === 'object' && typeof source.sourcePath === 'string') source.sourcePath = path.resolve(base, source.sourcePath);
  };
  if (typeof input.destination === 'string') input.destination = path.resolve(base, input.destination);
  if (input.artifacts instanceof Array) for (const artifact of input.artifacts) resolveSource(artifact?.source);
  resolveSource(input.toolchain?.compiler?.source); resolveSource(input.toolchain?.generator?.source);
  return input;
}

const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== '--input') {
  process.stderr.write(usage()); process.exitCode = 64;
} else {
  try {
    const metadataPath = path.resolve(args[1]);
    const input = resolveMetadataPaths(parseStrictJson(await readFile(metadataPath)), metadataPath);
    const result = await buildVerifierProfileBundle(input);
    process.stdout.write(`${canonicalJson({ directory: result.directory, profileId: result.profileId, instanceId: result.instanceId })}\n`);
  } catch (error) {
    process.stderr.write(`profile-builder: ${error.message}\n`); process.exitCode = 1;
  }
}
