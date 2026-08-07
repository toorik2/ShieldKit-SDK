import { readFileSync } from 'node:fs';
import { createRealVm, evaluatePair } from './harness/src/harness/vm.ts';
import * as la from '@bitauth/libauth';
const d = JSON.parse(readFileSync(process.argv[2], 'utf8'));
// evaluate each of the 6 verifier inputs as the lane build's gate does: lock + unlock, minimal context
const vm = createRealVm();
const all = d.slice(0, 6).map((r, i) => ({ lockingBytecode: la.hexToBin(r.lock), unlockingBytecode: la.hexToBin(r.unlock), valueSatoshis: 1200n, sequenceNumber: 0n }));
for (let i = 0; i < 6; i++) {
  const out = evaluatePair(vm, all[i].lockingBytecode, all[i].unlockingBytecode, undefined, { index: i, inputs: all, outputValueSatoshis: 1000n });
  console.log(`input[${i}] accepts=${out.accepted === true} ${out.error ?? ''}`);
}
