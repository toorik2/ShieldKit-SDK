import { readFile } from 'node:fs/promises';
import { generatePf7VerifierSet } from './pf7-verifier-generator.mjs';

const input = process.argv[2];
if (input === undefined || process.argv.length !== 3) {
  console.error('usage: node cli.mjs ABSOLUTE_CONFIG.json');
  process.exitCode = 2;
} else {
  try {
    if (!input.startsWith('/')) throw new Error('configuration path must be absolute');
    const result = await generatePf7VerifierSet(JSON.parse(await readFile(input, 'utf8')));
    console.log(JSON.stringify({ destination: result.destination, sha256: result.sha256 }));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
