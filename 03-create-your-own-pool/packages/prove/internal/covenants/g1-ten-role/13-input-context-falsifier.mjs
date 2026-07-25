import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import {
  createVirtualMachineBch2026,
  encodeDataPush,
  encodeLockingBytecodeP2sh32,
  hash256,
  hexToBin,
} from '@bitauth/libauth';

const verifierRoot = process.argv[2] ?? process.env.VERIFIER_CASH_ROOT;
if (!verifierRoot) throw new Error('usage: VERIFIER_CASH_ROOT=/absolute/verifier.cash node 13-input-context-falsifier.mjs');
const dumpPath = resolve(verifierRoot, '.vc/runs/g1-real-deposit/tmp/inputs_dump.json');
const rows = JSON.parse(await readFile(dumpPath, 'utf8'));
assert.equal(rows.length, 10, 'expected the measured ten-role verifier input dump');

// Consume exactly one empty structural witness and leave exactly one true
// result. This isolates the verifier locks' fixed transaction topology: the
// three appended P2SH32 probes themselves must accept.
const redeem = Uint8Array.of(
  0x82, // OP_SIZE
  0x00, // OP_0
  0x9d, // OP_NUMEQUALVERIFY
  0x91, // OP_NOT (the consumed empty witness becomes true)
); // no OP_TRUE
const lock = encodeLockingBytecodeP2sh32(hash256(redeem));
const unlock = new Uint8Array([...encodeDataPush(new Uint8Array()), ...encodeDataPush(redeem)]);
const items = [
  ...rows.map((row) => ({
    name: row.name,
    lockingBytecode: hexToBin(row.lock),
    unlockingBytecode: hexToBin(row.unlock),
    ...(row.token ? { token: { category: hexToBin(row.token.category), amount: 0n, nft: { capability: row.token.capability, commitment: hexToBin(row.token.commitment) } } } : {}),
  })),
  ...['binding-probe', 'state-probe', 'fee-probe'].map((name) => ({ name, lockingBytecode: lock, unlockingBytecode: unlock })),
];
const sourceOutputs = items.map((item) => ({ lockingBytecode: item.lockingBytecode, valueSatoshis: 1_000n, ...(item.token ? { token: item.token } : {}) }));
const transaction = {
  version: 2,
  locktime: 0,
  inputs: items.map((item, index) => ({ outpointTransactionHash: new Uint8Array(32).fill(index), outpointIndex: index, sequenceNumber: 0, unlockingBytecode: item.unlockingBytecode })),
  outputs: [{ lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1_000n }],
};
const vm = createVirtualMachineBch2026(true);
const report = items.map((item, inputIndex) => {
  const result = vm.evaluate({ inputIndex, sourceOutputs, transaction });
  return { inputIndex, name: item.name, accepts: result.error === undefined, error: result.error ?? '', unlockingBytes: item.unlockingBytecode.length, operationCost: result.metrics.operationCost };
});
const rejected = report.filter((row) => !row.accepts).map((row) => row.name);
assert.deepEqual(rejected.slice(0, 9), ['exec0', 'exec1', 'exec2', 'exec3', 'exec4', 'exec5', 'exec6', 'finalize', 'fused']);
assert.deepEqual(report.slice(10).map((row) => [row.name, row.accepts]), [
  ['binding-probe', true],
  ['state-probe', true],
  ['fee-probe', true],
]);
console.log(JSON.stringify({ baselineVerifierInputs: rows.length, appendedStructuralInputs: 3, evaluatedInputCount: items.length, report }, null, 2));
