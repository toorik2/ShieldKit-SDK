// Compatibility entrypoint for historical reproduction commands.
// New work belongs in lanes/bn254-onetx/src/c7/build.ts.
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

process.env.C7_GEN ||= join(dirname(fileURLToPath(import.meta.url)), 'generated');
await import('../../../lanes/bn254-onetx/src/c7/build.ts');
