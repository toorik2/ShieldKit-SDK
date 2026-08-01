#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import { consumeV2NativeGroth16ProverInstallation, loadV2NativeGroth16ProverInstallation } from '../packages/prove/v2/native-groth16-prover-installation.mjs';

const fail = (message) => { throw new Error(`V2_NATIVE_PROVER_INSTALLATION_QUALIFICATION_FAILED: ${message}`); };

export async function qualifyV2NativeProverInstallation({ installationDirectory }) {
  const resolution = await loadV2NativeGroth16ProverInstallation({ installationDirectory });
  const binary = await consumeV2NativeGroth16ProverInstallation(resolution);
  return Object.freeze({ schema: 'shieldkit-v2-native-groth16-prover-installation-qualification-v1', status: 'verified-local-installation-not-release-qualification', resolution, binary });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [flag, installationDirectory] = process.argv.slice(2);
  if (flag !== '--installation' || process.argv.length !== 4) fail('usage: qualify-v2-native-prover-installation.mjs --installation <absolute-private-installation-directory>');
  qualifyV2NativeProverInstallation({ installationDirectory }).then((value) => process.stdout.write(`${JSON.stringify(value)}\n`), (error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
}
