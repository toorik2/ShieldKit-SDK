// Produce targeted negative inputs from a generated core-authoritative vector.
// Each edit is intentionally relation-invalid; this is not a vector generator.
import { readFile, writeFile } from 'node:fs/promises';

const [source, target, kind] = process.argv.slice(2);
if (!source || !target || !kind) {
  throw new Error('usage: make-invalid-core-vector.mjs SOURCE.json TARGET.json digest|membership|nullifier|reserve|inactive-record');
}
const input = JSON.parse(await readFile(source, 'utf8'));
switch (kind) {
  case 'digest':
    input.publicDigestHi = input.publicDigestHi === '0' ? '1' : '0';
    break;
  case 'membership':
    input.noteSiblings[0] = input.noteSiblings[0] === '0' ? '1' : '0';
    break;
  case 'nullifier':
    input.nullifierSiblings[0] = input.nullifierSiblings[0] === '0' ? '1' : '0';
    break;
  case 'reserve':
    input.postReserveSats = input.postReserveSats === '0' ? '1' : '0';
    break;
  case 'inactive-record':
    input.recordBits[0] = input.recordBits[0] === '0' ? '1' : '0';
    break;
  default:
    throw new Error(`unknown negative case: ${kind}`);
}
await writeFile(target, `${JSON.stringify(input)}\n`);
