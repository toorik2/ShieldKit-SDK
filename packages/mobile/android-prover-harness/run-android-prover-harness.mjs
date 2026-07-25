#!/usr/bin/env node
// Deliberately small physical-device entry point. It never creates a manifest
// or supplies artifacts: those remain explicit, SHA-256-pinned caller inputs.
import { runAndroidProverHarness } from './android-prover-harness.mjs';

const [manifestFile] = process.argv.slice(2);
if (!manifestFile || process.argv.length !== 3) {
  console.error('usage: node run-android-prover-harness.mjs /absolute/manifest.json');
  process.exitCode = 64;
} else {
  runAndroidProverHarness(manifestFile)
    .then((result) => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`))
    .catch((error) => {
      console.error(error.stack ?? error.message);
      process.exitCode = 1;
    });
}
