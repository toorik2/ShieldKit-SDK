#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { canonicalJson, parseStrictJson } from './load.mjs';
import { bridgeLocalSetupToProfile } from './bridge.mjs';

const usage = 'usage: node cli.mjs --input metadata.json\nThe bridge only packages a hash-pinned development setup; it never creates setup or an instance.\n';
function resolveSource(source, base) {
  if (source && typeof source === 'object' && typeof source.sourcePath === 'string') source.sourcePath = path.resolve(base, source.sourcePath);
}
function resolveInput(input, metadataPath) {
  const base = path.dirname(metadataPath);
  if (typeof input.destination === 'string') input.destination = path.resolve(base, input.destination);
  resolveSource(input.setupMetadata, base);
  for (const artifact of input.artifacts ?? []) resolveSource(artifact?.source, base);
  resolveSource(input.toolchain?.compiler?.source, base); resolveSource(input.toolchain?.generator?.source, base);
  return input;
}

const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== '--input') {
  process.stderr.write(usage); process.exitCode = 64;
} else {
  try {
    const metadataPath = path.resolve(args[1]);
    const result = await bridgeLocalSetupToProfile(resolveInput(parseStrictJson(await readFile(metadataPath)), metadataPath));
    process.stdout.write(`${canonicalJson({ directory: result.directory, profileId: result.profileId, instanceId: result.instanceId, mode: 'development-only' })}\n`);
  } catch (error) {
    process.stderr.write(`setup-profile-bridge: ${error.message}\n`); process.exitCode = 1;
  }
}
