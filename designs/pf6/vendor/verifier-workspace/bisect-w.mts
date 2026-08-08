
import { readFileSync } from 'node:fs';
import { createRealVm, evaluatePair } from './harness/src/harness/vm.ts';
import * as la from '@bitauth/libauth';
const { decodeTransaction, hexToBin } = la;
const d = JSON.parse(readFileSync('/tmp/pf6-cli3-withdrawal-tx.json', 'utf8'));
const tx = decodeTransaction(hexToBin(d.hex));
const tr = JSON.parse(readFileSync('/tmp/pf6-cli3-transfer-tx.json', 'utf8'));
const trTx = decodeTransaction(hexToBin(tr.hex));
const sources = [];
for (let i = 0; i < 8; i++) { const o = trTx.outputs[i]; sources.push({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, sequenceNumber: 0n, token: o.token ?? undefined }); }
sources.push({ lockingBytecode: trTx.outputs[8].lockingBytecode, valueSatoshis: trTx.outputs[8].valueSatoshis, sequenceNumber: 0n, token: trTx.outputs[8].token ?? undefined });
const base = tx.inputs.map((inp, i) => ({ lockingBytecode: sources[i].lockingBytecode, unlockingBytecode: inp.unlockingBytecode, valueSatoshis: sources[i].valueSatoshis, sequenceNumber: 0n, token: sources[i].token, outpointTransactionHash: inp.outpointTransactionHash, outpointIndex: inp.outpointIndex }));
const outputs10 = tx.outputs.map((o) => ({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, token: o.token ?? undefined }));
const outputs9 = outputs10.slice(0, 9);
const vm = createRealVm();
const evalG = (inputs, outputs, label) => {
  const out = evaluatePair(vm, inputs[4].lockingBytecode, inputs[4].unlockingBytecode, undefined, { index: 4, inputs, outputs, outputValueSatoshis: 1000n });
  console.log(label, ':', out.accepted, '|', (out.error || '').slice(0, 90));
};
evalG(base, outputs10, 'withdrawal genesis (10 outputs)');
evalG(base, outputs9, 'withdrawal genesis (9 outputs)');
// also the terminal
const evalT = (inputs, outputs, label) => {
  const out = evaluatePair(vm, inputs[5].lockingBytecode, inputs[5].unlockingBytecode, undefined, { index: 5, inputs, outputs, outputValueSatoshis: 1000n });
  console.log(label, ':', out.accepted, '|', (out.error || '').slice(0, 90));
};
evalT(base, outputs10, 'withdrawal terminal (10 outputs)');
evalT(base, outputs9, 'withdrawal terminal (9 outputs)');
