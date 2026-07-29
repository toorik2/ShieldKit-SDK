#!/usr/bin/env node
/**
 * Protocol-design-v2 public CLI entry.
 * Implementation lives in packages/v2-direct; this path is the publish surface.
 */
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const impl = path.resolve(here, '../../03-create-your-own-pool/packages/v2-direct/cli/shieldkit-v2.mjs');
const { main } = await import(pathToFileURL(impl).href);

main(process.argv.slice(2)).then((code) => {
  process.exit(code ?? 0);
}).catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
