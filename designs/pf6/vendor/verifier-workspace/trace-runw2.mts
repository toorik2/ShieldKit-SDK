
import { readFileSync } from 'node:fs';
import { createRealVm, evaluatePair } from './harness/src/harness/vm.ts';
import * as la from '@bitauth/libauth';
const { decodeTransaction, hexToBin } = la;
const txHex = readFileSync(process.argv[2], 'utf8').trim();
const soHex = readFileSync(process.argv[3], 'utf8').trim();
const tx = decodeTransaction(hexToBin(txHex));
const vm = createRealVm();
const ok = [];
// the eval needs the sources: decode the srcouts via the count-prefixed output list
const { decodeOutputList } = la;
const sos = decodeOutputList(hexToBin(soHex));
const inputs = tx.inputs.map((inp, i) => ({ lockingBytecode: sos[i].lockingBytecode, unlockingBytecode: inp.unlockingBytecode, valueSatoshis: sos[i].valueSatoshis, sequenceNumber: 0n, token: sos[i].token, outpointTransactionHash: inp.outpointTransactionHash, outpointIndex: inp.outpointIndex }));
const outputs = tx.outputs.map((o) => ({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, token: o.token ?? undefined }));
for (let i = 0; i < 6; i++) {
  const out = evaluatePair(vm, inputs[i].lockingBytecode, inputs[i].unlockingBytecode, undefined, { index: i, inputs, outputs, outputValueSatoshis: 1000n });
  console.log('role', i, ':', out.accepted, '|', (out.error || '').slice(0, 90));
}
console.log('internal tx outputs:', outputs.length, '| inputs:', inputs.length);
