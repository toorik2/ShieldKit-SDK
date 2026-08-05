#!/usr/bin/env node
import { fileURLToPath } from 'node:url';

import { packV2BetaProductOfflineBundle } from '../packages/profile/v2/beta-product-offline-bundle-packer.mjs';

const fail = (message) => { throw new Error(`V2_BETA_OFFLINE_PACK_FAILED: ${message}`); };
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [runtimeDirectory, ceremonyDirectory, nativeProverInstallationDirectory, outputDirectory, releaseId] = process.argv.slice(2);
  if (process.argv.length !== 7) fail('usage: pack-v2-beta-offline-bundle.mjs <runtime-dir> <ceremony-dir> <native-dir> <new-output-dir> <release-id>');
  packV2BetaProductOfflineBundle({ runtimeDirectory, ceremonyDirectory, nativeProverInstallationDirectory, outputDirectory, releaseId }).then(
    (value) => process.stdout.write(`${JSON.stringify(value)}\n`),
    (error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; },
  );
}
