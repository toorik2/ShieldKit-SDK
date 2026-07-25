import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import {
  createVirtualMachineBch2026,
  decodeTransaction,
  encodeTransaction,
  encodeTransactionOutput,
} from '@bitauth/libauth';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const hex = (value, label) => {
  if (typeof value !== 'string' || !/^[0-9a-f]*$/.test(value) || value.length % 2 !== 0) {
    throw new Error(`${label} must be even-length lowercase hexadecimal`);
  }
  return Uint8Array.from(Buffer.from(value, 'hex'));
};
const accepts = (result) => result.error === undefined
  && result.stack.length === 1 && result.stack[0].some((byte) => byte !== 0);

export const fixturePath = new URL('./fixtures/deposit-complete-real-v1.json', import.meta.url);
export const actionFixturePaths = Object.freeze(['deposit', 'transfer', 'withdrawal'].map((action) => new URL(`./fixtures/${action}-complete-real-v1.json`, import.meta.url)));

function sourceOutputFromFixture(output, index) {
  if (typeof output?.valueSatoshis !== 'string' || !/^[0-9]+$/.test(output.valueSatoshis)) {
    throw new Error(`sourceOutputs[${index}].valueSatoshis must be a decimal string`);
  }
  const token = output.token === null ? undefined : {
    category: hex(output.token?.category, `sourceOutputs[${index}].token.category`),
    amount: BigInt(output.token?.amount),
    nft: output.token?.nft === undefined ? undefined : {
      capability: output.token.nft.capability,
      commitment: hex(output.token.nft.commitment, `sourceOutputs[${index}].token.nft.commitment`),
    },
  };
  return {
    valueSatoshis: BigInt(output.valueSatoshis),
    lockingBytecode: hex(output.lockingBytecode, `sourceOutputs[${index}].lockingBytecode`),
    ...(token === undefined ? {} : { token }),
  };
}

export async function loadRealDepositFixture(path = fixturePath) {
  const fixtureBytes = await readFile(path);
  const fixture = JSON.parse(fixtureBytes);
  if (fixture.schema !== 'shield.cash/g2-real-action-leanbch-fixture/v1' && fixture.schema !== 'shield.cash/g2-real-deposit-leanbch-fixture/v1') {
    throw new Error(`unexpected fixture schema: ${fixture.schema}`);
  }
  if (!Array.isArray(fixture.sourceOutputs) || fixture.sourceOutputs.length !== 10) {
    throw new Error('fixture must contain exactly 10 source outputs');
  }
  if (JSON.stringify(fixture.crosscheckInputIndexes) !== '[7,8]') {
    throw new Error('fixture must pin exactly inputs 7 and 8');
  }
  const transactionBytes = hex(fixture.transaction?.hex, 'transaction.hex');
  if (transactionBytes.length !== fixture.transaction.bytes || sha256(transactionBytes) !== fixture.transaction.sha256) {
    throw new Error('transaction byte length or SHA-256 mismatch');
  }
  const transaction = decodeTransaction(transactionBytes);
  if (typeof transaction === 'string') throw new Error(`transaction decode failed: ${transaction}`);
  if (Buffer.from(encodeTransaction(transaction)).toString('hex') !== fixture.transaction.hex) {
    throw new Error('transaction did not canonical round-trip through Libauth');
  }
  const sourceOutputs = fixture.sourceOutputs.map(sourceOutputFromFixture);
  const sourceOutputsWire = Buffer.concat([
    Buffer.of(sourceOutputs.length),
    ...sourceOutputs.map((output) => Buffer.from(encodeTransactionOutput(output))),
  ]);
  if (sourceOutputsWire.length !== fixture.sourceOutputsWire?.bytes
    || sha256(sourceOutputsWire) !== fixture.sourceOutputsWire?.sha256) {
    throw new Error('source output byte length or SHA-256 mismatch');
  }
  return { fixture, fixtureBytes, transaction, transactionBytes, sourceOutputs, sourceOutputsWire };
}

function assertedInputIndexes(loaded, inputIndexes) {
  if (!Array.isArray(inputIndexes) || inputIndexes.length === 0) throw new Error('inputIndexes must be a non-empty array');
  const unique = [...new Set(inputIndexes)];
  if (unique.length !== inputIndexes.length || unique.some((index) => !Number.isInteger(index) || index < 0 || index >= loaded.transaction.inputs.length)) {
    throw new Error('inputIndexes must be unique transaction input indexes');
  }
  return unique;
}

export async function evaluateRoles(path = fixturePath, inputIndexes = undefined) {
  const loaded = await loadRealDepositFixture(path);
  const vm = createVirtualMachineBch2026(true);
  const indexes = assertedInputIndexes(loaded, inputIndexes ?? loaded.fixture.crosscheckInputIndexes);
  const results = indexes.map((inputIndex) => {
    const result = vm.evaluate({ inputIndex, sourceOutputs: loaded.sourceOutputs, transaction: loaded.transaction });
    return {
      inputIndex,
      accepted: accepts(result),
      error: result.error ?? null,
      operationCost: result.metrics?.operationCost ?? null,
    };
  });
  if (results.some(({ accepted }) => !accepted)) throw new Error('Libauth rejected a requested cross-check input');
  return {
    ...loaded,
    sourceOutputsSha256: sha256(loaded.sourceOutputsWire),
    fixtureSha256: sha256(loaded.fixtureBytes),
    libauth: results,
  };
}

export async function evaluateStructuralRoles(path = fixturePath) {
  return evaluateRoles(path);
}

export async function evaluateAllRoles(path = fixturePath) {
  const loaded = await loadRealDepositFixture(path);
  return evaluateRoles(path, loaded.transaction.inputs.map((_, inputIndex) => inputIndex));
}

export async function writeLeanBchInput(prefix, path = fixturePath, inputIndexes = undefined) {
  const result = await evaluateRoles(path, inputIndexes);
  const resolvedPrefix = resolve(prefix);
  await writeFile(`${resolvedPrefix}_tx.hex`, `${Buffer.from(result.transactionBytes).toString('hex')}\n`);
  await writeFile(`${resolvedPrefix}_srcouts.hex`, `${result.sourceOutputsWire.toString('hex')}\n`);
  return result;
}
