/*
 * Produces the public LeanBCH fixture from a complete deposit artifact. The
 * output deliberately retains only the serialized transaction and the source
 * transaction outputs required to evaluate its scripts; it never copies proof,
 * witness, wallet, or broadcast material.
 */
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { encodeTransactionOutput } from '@bitauth/libauth';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const args = process.argv.slice(2);
const valueAfter = (flag) => {
  const index = args.indexOf(flag);
  if (index < 0 || index + 1 >= args.length) throw new Error(`missing ${flag}`);
  return args[index + 1];
};
const sourcePath = resolve(valueAfter('--source'));
const outputPath = resolve(valueAfter('--output'));
const sourceBytes = await readFile(sourcePath);
const source = JSON.parse(sourceBytes);
const toBytes = (value) => Uint8Array.from(Buffer.from(value, 'hex'));
const sourceOutputForWire = (output) => ({
  valueSatoshis: BigInt(output.valueSatoshis),
  lockingBytecode: toBytes(output.lockingBytecode),
  ...(output.token === null ? {} : {
    token: {
      category: toBytes(output.token.category),
      amount: BigInt(output.token.amount),
      ...(output.token.nft === undefined ? {} : {
        nft: {
          capability: output.token.nft.capability,
          commitment: toBytes(output.token.nft.commitment),
        },
      }),
    },
  }),
});

if (source.schema !== 'shield.cash/chipnet-complete-deposit/v1') {
  throw new Error(`unexpected source schema: ${source.schema}`);
}
if (!Array.isArray(source.sourceOutputs) || source.sourceOutputs.length !== 10) {
  throw new Error('source must contain exactly 10 source outputs');
}
if (!Array.isArray(source.inputs) || source.inputs.length !== 10) {
  throw new Error('source must contain exactly 10 inputs');
}
if (!/^[0-9a-f]{64}$/.test(source.transactionId)) {
  throw new Error('source transactionId must be a lowercase 32-byte hex value');
}
if (!/^[0-9a-f]+$/.test(source.transactionHex) || source.transactionHex.length % 2 !== 0) {
  throw new Error('source transactionHex must be even-length lowercase hex');
}
const sourceOutputsWire = Buffer.concat([
  Buffer.of(source.sourceOutputs.length),
  ...source.sourceOutputs.map((output) => Buffer.from(encodeTransactionOutput(sourceOutputForWire(output)))),
]);

const fixture = {
  schema: 'shield.cash/g2-real-deposit-leanbch-fixture/v1',
  qualification: [
    'Public structural LeanBCH fixture for real complete deposit transaction.',
    'It evaluates only input 7 binding and input 8 state helper.',
    'It does not LeanBCH-verify PF7 roles 0 through 6, the fee signature, standardness, BCHN relay, or Chipnet inclusion.',
  ].join(' '),
  provenance: {
    sourceArtifactFilename: 'deposit-complete.json',
    sourceArtifactSha256: sha256(sourceBytes),
    sourceSchema: source.schema,
    transactionId: source.transactionId,
  },
  profile: source.profile,
  transaction: {
    hex: source.transactionHex,
    sha256: sha256(Buffer.from(source.transactionHex, 'hex')),
    bytes: source.transactionHex.length / 2,
  },
  sourceOutputs: source.sourceOutputs,
  sourceOutputsWire: {
    sha256: sha256(sourceOutputsWire),
    bytes: sourceOutputsWire.length,
  },
  inputRoles: source.inputs.filter(({ inputIndex }) => inputIndex === 7 || inputIndex === 8),
  crosscheckInputIndexes: [7, 8],
};

await writeFile(outputPath, `${JSON.stringify(fixture, null, 2)}\n`);
console.log(JSON.stringify({
  outputPath,
  sourceArtifactSha256: fixture.provenance.sourceArtifactSha256,
  transactionId: fixture.provenance.transactionId,
  transactionSha256: fixture.transaction.sha256,
  transactionBytes: fixture.transaction.bytes,
  sourceOutputs: fixture.sourceOutputs.length,
  inputIndexes: fixture.crosscheckInputIndexes,
}, null, 2));
