
import { readFileSync } from 'node:fs';
import { createRealVm, evaluatePair } from './harness/src/harness/vm.ts';

const mat = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const vm = createRealVm();
let allOk = true;
for (const role of mat.roles) {
  const lock = Uint8Array.from(Buffer.from(role.lock, 'hex'));
  const unlock = Uint8Array.from(Buffer.from(role.unlock, 'hex'));
  const r = evaluatePair(vm, lock, unlock);
  const ok = r.accepts === true;
  allOk = allOk && ok;
  console.log(role.name.padEnd(9), 'unlock', String(role.unlockBytes).padStart(5), 'accepts:', ok, r.error ?? '');
}
console.log(allOk ? 'ALL 6 VERIFIER INPUTS VM-ACCEPT (independent libauth replay)' : 'FAILURE');
process.exit(allOk ? 0 : 1);
