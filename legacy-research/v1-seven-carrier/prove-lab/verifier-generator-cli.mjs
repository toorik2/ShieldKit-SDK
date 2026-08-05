import { lstat, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseStrictJson } from '../../profile/load.mjs';
import { generatePf7VerifierSet } from './verifier-generator.mjs';

export async function loadCliConfig(filename) {
  if (typeof filename !== 'string' || !path.isAbsolute(filename)) throw new Error('configuration path must be absolute');
  const requested = path.resolve(filename);
  const stat = await lstat(requested).catch(() => { throw new Error('configuration path does not exist'); });
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('configuration path must be a regular non-symlink file');
  const resolved = await realpath(requested).catch(() => { throw new Error('configuration path cannot be resolved'); });
  if (resolved !== requested) throw new Error('configuration path must not resolve through a symlink');
  return parseStrictJson(await readFile(requested), 'PF7 generator configuration');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const input = process.argv[2];
  if (input === undefined || process.argv.length !== 3) {
    console.error('usage: node cli.mjs ABSOLUTE_CONFIG.json');
    process.exitCode = 2;
  } else {
    try {
      const result = await generatePf7VerifierSet(await loadCliConfig(input));
      console.log(JSON.stringify({ destination: result.destination, sha256: result.sha256 }));
    } catch (error) {
      console.error(error.message);
      process.exitCode = 1;
    }
  }
}
