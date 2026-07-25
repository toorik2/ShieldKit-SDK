#!/usr/bin/env node
import { compareDevelopmentVerifierProfileBundles } from './load.mjs';

const usage = 'usage: node compare-development-profiles.mjs --left bundle-a --right bundle-b\n';
const args = process.argv.slice(2);
if (args.length !== 4 || args[0] !== '--left' || args[2] !== '--right') {
  process.stderr.write(usage); process.exitCode = 64;
} else {
  try {
    const comparison = await compareDevelopmentVerifierProfileBundles({
      leftDirectory: args[1], rightDirectory: args[3],
    });
    process.stdout.write(`${comparison}\n`);
  } catch (error) {
    process.stderr.write(`verifier-profile-replacement: ${error.message}\n`); process.exitCode = 1;
  }
}
