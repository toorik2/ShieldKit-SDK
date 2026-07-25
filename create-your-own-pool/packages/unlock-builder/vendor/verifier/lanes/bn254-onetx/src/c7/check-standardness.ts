// Evaluate a closed C7 transaction under BCH-2026's standard relay VM.
// Usage: tsx check-standardness.ts BUILD_DIR [OUTPUT_JSON]
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createVirtualMachineBch2026, hexToBin } from '@bitauth/libauth';
import { evaluatePair } from '../../../../harness/src/harness/vm.ts';

const buildDirectory = process.argv[2];
if (buildDirectory === undefined) throw new Error('usage: check-standardness.ts BUILD_DIR [OUTPUT_JSON]');
const output = process.argv[3];
const raw = JSON.parse(readFileSync(resolve(buildDirectory, 'inputs_dump.json'), 'utf8')) as Array<{ name: string; lock: string; unlock: string }>;
const buildResult = JSON.parse(readFileSync(resolve(buildDirectory, 'result.json'), 'utf8')) as {
  verifierInputCount?: number;
  structuralRolesUnevaluated?: boolean;
};
const inputs = raw.map((item) => ({
  lockingBytecode: hexToBin(item.lock),
  unlockingBytecode: hexToBin(item.unlock),
  valueSatoshis: 1000n,
  sequenceNumber: 0,
}));
const vm = createVirtualMachineBch2026(true);
const evaluatedInputCountRaw = buildResult.structuralRolesUnevaluated === true
  ? buildResult.verifierInputCount
  : inputs.length;
if (!Number.isInteger(evaluatedInputCountRaw)
    || evaluatedInputCountRaw! < 1 || evaluatedInputCountRaw! > inputs.length) {
  throw new Error(`invalid verifierInputCount in result.json: ${evaluatedInputCountRaw}`);
}
const evaluatedInputCount = evaluatedInputCountRaw as number;
const rows = inputs.slice(0, evaluatedInputCount).map((input, index) => {
  const result = evaluatePair(vm, input.lockingBytecode, input.unlockingBytecode, undefined, {
    index, inputs, outputValueSatoshis: 1000n,
  });
  return {
    index,
    name: raw[index]!.name,
    accepts: result.accepted,
    error: result.error ?? '',
    operationCost: result.operationCost,
    unlockingBytes: input.unlockingBytecode.length,
  };
});
const report = {
  standardVm: 'createVirtualMachineBch2026(true)',
  contextInputCount: inputs.length,
  evaluatedInputCount,
  scope: buildResult.structuralRolesUnevaluated === true
    ? 'verifier roles only; structural packet/state/fee roles explicitly unevaluated'
    : 'all transaction inputs',
  allAccept: rows.every((row) => row.accepts),
  maxUnlockingBytes: Math.max(...rows.map((row) => row.unlockingBytes)),
  maxOperationCost: Math.max(...rows.map((row) => row.operationCost)),
  rows,
};
if (output !== undefined) writeFileSync(resolve(output), `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify(report, null, 2));
if (!report.allAccept) process.exitCode = 1;
