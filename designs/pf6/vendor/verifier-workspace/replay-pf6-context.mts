
import { readFileSync } from 'node:fs';
import { createRealVm, evaluatePair } from './harness/src/harness/vm.ts';

const mat = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const all = [...mat.roles, ...mat.structuralRoles].map((role) => ({
  lockingBytecode: Uint8Array.from(Buffer.from(role.lock, 'hex')),
  unlockingBytecode: Uint8Array.from(Buffer.from(role.unlock, 'hex')),
  valueSatoshis: 1000n,
  sequenceNumber: 0n,
}));
const vm = createRealVm();
let gateOk = true;
for (let i = 0; i < all.length; i++) {
  const out = evaluatePair(vm, all[i].lockingBytecode, all[i].unlockingBytecode, undefined,
    { index: i, inputs: all, outputValueSatoshis: 1000n });
  const accepts = out.accepted === true;
  const label = i < mat.roles.length ? `VERIFIER ${mat.roles[i].name}` : `structural ${mat.structuralRoles[i - mat.roles.length].name}`;
  console.log(`input[${i}] ${label.padEnd(18)} unlock=${String(all[i].unlockingBytecode.length).padStart(5)} accepts=${accepts} ${out.error ?? ''}`);
  if (i < mat.roles.length && !accepts) gateOk = false;
}
console.log(gateOk ? 'GATE OK — 6/6 verifier roles VM-accept in the complete 9-input context (independent replay)' : 'GATE FAIL');
process.exit(gateOk ? 0 : 1);
