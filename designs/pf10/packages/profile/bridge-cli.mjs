#!/usr/bin/env node
import { refuseLegacyProfileCreation } from './legacy.mjs';

try {
  // Refuse before parsing a path or reading configuration. This executable was
  // a direct creation surface for the V1 legacy relation.
  refuseLegacyProfileCreation('the historical setup-profile bridge CLI');
} catch (error) {
  process.stderr.write(
    `${error.code ?? error.name}: ${error.message}\n`,
  );
  process.exitCode = 1;
}
