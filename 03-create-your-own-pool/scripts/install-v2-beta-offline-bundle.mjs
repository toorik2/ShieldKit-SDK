#!/usr/bin/env node
import { fileURLToPath } from 'node:url';

import { installV2BetaProductOfflineBundle } from '../packages/profile/v2/beta-product-offline-bootstrap.mjs';

const fail = (message) => { throw new Error(`V2_BETA_OFFLINE_BOOTSTRAP_FAILED: ${message}`); };

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [bundleDirectory, productDataDirectory] = process.argv.slice(2);
  if (process.argv.length !== 4) fail('usage: install-v2-beta-offline-bundle.mjs <private-offline-bundle-dir> <private-product-data-dir>');
  installV2BetaProductOfflineBundle({ bundleDirectory, productDataDirectory }).then(
    (value) => process.stdout.write(`${JSON.stringify(value)}\n`),
    (error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; },
  );
}
