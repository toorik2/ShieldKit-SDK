import { readFile, writeFile } from 'node:fs/promises';

const [source, target] = process.argv.slice(2);
if (!source || !target) throw new Error('usage: make-invalid-boundary.mjs VALID.json INVALID.json');
const input = JSON.parse(await readFile(source, 'utf8'));
input.boundaryAmount = '1';
await writeFile(target, `${JSON.stringify(input)}\n`);
