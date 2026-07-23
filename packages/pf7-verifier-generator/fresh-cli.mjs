import { fileURLToPath } from 'node:url';
import { loadCliConfig } from './cli.mjs';
import { generatePf7FreshDevelopmentCorpus } from './pf7-verifier-generator.mjs';

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const input = process.argv[2];
  if (input === undefined || process.argv.length !== 3) {
    console.error('usage: node fresh-cli.mjs ABSOLUTE_CONFIG.json');
    process.exitCode = 2;
  } else {
    try {
      const result = await generatePf7FreshDevelopmentCorpus(await loadCliConfig(input));
      console.log(JSON.stringify({ destination: result.destination, corpusSha256: result.sha256, verifierSetSha256: result.verifierSetSha256, sourceSetSha256: result.sourceSetSha256 }));
    } catch (error) {
      console.error(error.message);
      process.exitCode = 1;
    }
  }
}
