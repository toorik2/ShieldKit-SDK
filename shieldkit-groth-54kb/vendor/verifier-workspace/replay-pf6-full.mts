
import { readFileSync } from 'node:fs';
import { assertAllInputsReal } from './harness/src/harness/realTx.ts';

const mat = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const gateInputs = [...mat.roles, ...mat.structuralRoles].map((role) => ({
  lockingBytecode: Uint8Array.from(Buffer.from(role.lock, 'hex')),
  unlockingBytecode: Uint8Array.from(Buffer.from(role.unlock, 'hex')),
  valueSatoshis: 1000n,
  sequenceNumber: 0n,
}));
const report = assertAllInputsReal(gateInputs, { label: 'pf6-material full-context replay', outputValueSatoshis: 1000n });
console.log('ok:', report.ok);
for (const row of report.perInput ?? []) {
  console.log(' ', row.index, row.accepts ? 'ACCEPT' : 'REJECT', row.reason ?? '', 'len=' + row.unlockingLen);
}
process.exit(report.ok ? 0 : 1);
