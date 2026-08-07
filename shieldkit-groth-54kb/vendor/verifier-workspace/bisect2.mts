
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
const inputs = tx.inputs.map((inp, i) => ({ lockingBytecode: sources[i].lockingBytecode, unlockingBytecode: inp.unlockingBytecode, valueSatoshis: sources[i].valueSatoshis, sequenceNumber: 0n, token: sources[i].token, outpointTransactionHash: inp.outpointTransactionHash, outpointIndex: inp.outpointIndex }));
const outputs = tx.outputs.map((o) => ({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, token: o.token ?? undefined }));
const vm = createRealVm();
const evalR = (ins, outs, label, idx) => {
  const out = evaluatePair(vm, ins[idx].lockingBytecode, ins[idx].unlockingBytecode, undefined, { index: idx, inputs: ins, outputs: outs, outputValueSatoshis: 1000n });
  console.log(label, ':', out.accepted, '|', (out.error || '').slice(0, 80));
};
// A: no token on the state input
const noTok = inputs.map((i, k) => k === 7 ? { ...i, token: undefined } : i);
evalR(noTok, outputs, 'genesis no-state-token', 4);
evalR(noTok, outputs, 'terminal no-state-token', 5);
// B: the state input value = 2500 (the pre-withdrawal state?? — actually the withdrawal's state in = 10,002,500 ✓ — try the deposit-like 2500)
const in2500 = inputs.map((i, k) => k === 7 ? { ...i, valueSatoshis: 2500n } : i);
evalR(in2500, outputs, 'genesis state-in-2500', 4);
// C: the outputs' state out value = 10,002,500
const out10002500 = outputs.map((o, k) => k === 7 ? { ...o, valueSatoshis: 10002500n } : o);
evalR(inputs, out10002500, 'genesis state-out-10002500', 4);
