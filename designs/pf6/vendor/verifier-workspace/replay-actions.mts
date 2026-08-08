import { readFileSync } from 'node:fs';
import { createRealVm, evaluatePair } from './harness/src/harness/vm.ts';

const mat = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const vm = createRealVm();
let allOk = true;
for (const [action, a] of Object.entries(mat.actions)) {
  const all = [...a.verifierRoles, ...a.structural].map((role) => ({
    lockingBytecode: Uint8Array.from(Buffer.from(role.lock, 'hex')),
    unlockingBytecode: Uint8Array.from(Buffer.from(role.unlock, 'hex')),
    valueSatoshis: 1000n,
    sequenceNumber: 0n,
  }));
  let gateOk = true;
  const rows = [];
  for (let i = 0; i < all.length; i++) {
    const out = evaluatePair(vm, all[i].lockingBytecode, all[i].unlockingBytecode, undefined,
      { index: i, inputs: all, outputValueSatoshis: 1000n });
    const accepts = out.accepted === true;
    rows.push({ index: i, name: i < 6 ? a.verifierRoles[i].name : a.structural[i - 6].name, accepts, bytes: all[i].unlockingBytecode.length });
    if (i < 6 && !accepts) gateOk = false;
  }
  allOk = allOk && gateOk;
  const verifierBytes = a.verifierRoles.reduce((s, r) => s + r.unlockBytes, 0);
  const sigma = all.reduce((s, r) => s + r.unlockingBytecode.length, 0);
  console.log(`${action.padEnd(10)} gateOk=${gateOk} verifierUnlocks=${verifierBytes} sigmaUnlock=${sigma} ` +
    rows.map(r => `${r.name}:${r.accepts ? 'Y' : 'N'}`).join(' '));
}
console.log(allOk ? 'ALL 3 ACTIONS: 6/6 VERIFIER ROLES VM-ACCEPT (full 9-input context)' : 'FAILURE');
process.exit(allOk ? 0 : 1);
