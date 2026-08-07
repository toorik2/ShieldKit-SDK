import { readFileSync } from 'node:fs';
import { createRealVm, evaluatePair } from './harness/src/harness/vm.ts';
import * as la from '@bitauth/libauth';
const { decodeTransaction, hexToBin } = la;
const d = JSON.parse(readFileSync('/tmp/pf6-cont-deposit-tx.json', 'utf8'));
const tx = decodeTransaction(hexToBin(d.hex));
const wd = JSON.parse(readFileSync('/tmp/pf6-vps-withdrawal.json', 'utf8'));
const wTx = decodeTransaction(hexToBin(wd.hex));
const feeUtxo = JSON.parse(readFileSync('/tmp/pf6-fee-utxo.json', 'utf8'));
const feeTx = decodeTransaction(hexToBin(readFileSync('/tmp/pf6-fee-source.hex', 'utf8').trim()));
const sources = [];
for (let i = 0; i < 8; i++) { const o = wTx.outputs[i]; sources.push({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, sequenceNumber: 0n, token: o.token ?? undefined }); }
sources.push({ lockingBytecode: feeTx.outputs[feeUtxo.vout].lockingBytecode, valueSatoshis: feeTx.outputs[feeUtxo.vout].valueSatoshis, sequenceNumber: 0n, token: feeTx.outputs[feeUtxo.vout].token ?? undefined });
const inputs = tx.inputs.map((inp, i) => ({ lockingBytecode: sources[i].lockingBytecode, unlockingBytecode: inp.unlockingBytecode, valueSatoshis: sources[i].valueSatoshis, sequenceNumber: 0n, token: sources[i].token, outpointTransactionHash: inp.outpointTransactionHash, outpointIndex: inp.outpointIndex }));
const outputs = tx.outputs.map((o) => ({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, token: o.token ?? undefined }));
const vm = createRealVm();
for (let i = 0; i < 6; i++) {
  const o = evaluatePair(vm, inputs[i].lockingBytecode, inputs[i].unlockingBytecode, undefined, { index: i, inputs, outputs, outputValueSatoshis: 1000n });
  console.log('role', i, ':', o.accepted, '|', (o.error || '').slice(0, 80));
}
// the state covenant (input 7)
const o7 = evaluatePair(vm, inputs[7].lockingBytecode, inputs[7].unlockingBytecode, undefined, { index: 7, inputs, outputs, outputValueSatoshis: outputs[7].valueSatoshis });
console.log('state covenant:', o7.accepted, '|', (o7.error || '').slice(0, 80));
