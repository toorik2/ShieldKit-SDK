#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import { installV2BetaProductArtifacts } from '../packages/profile/v2/beta-product-artifact-installation.mjs';

const fail = (message) => { throw new Error(`V2_BETA_PRODUCT_ARTIFACT_INSTALL_FAILED: ${message}`); };

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [productDataDirectory, sourceRuntimeDirectory, ceremonyDirectory, nativeProverInstallationDirectory] = process.argv.slice(2);
  if (process.argv.length !== 6) fail('usage: install-v2-beta-product-artifacts.mjs <private-product-data-dir> <verified-runtime-dir> <historical-ceremony-dir> <native-installation-dir>');
  installV2BetaProductArtifacts({ productDataDirectory, sourceRuntimeDirectory, ceremonyDirectory, nativeProverInstallationDirectory }).then(
    (value) => process.stdout.write(`${JSON.stringify(value)}\n`),
    (error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; },
  );
}
