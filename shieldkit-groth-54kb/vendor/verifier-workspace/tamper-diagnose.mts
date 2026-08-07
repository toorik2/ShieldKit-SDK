import { readFileSync } from 'node:fs';
import { createRealVm, evaluatePair } from './harness/src/harness/vm.ts';
import * as la from '@bitauth/libauth';
const name = 'deposit';
const t = JSON.parse(readFileSync('/tmp/pf6-deposit-tx.json', 'utf8'));
const tx = la.decodeTransaction(la.hexToBin(t.hex));
const gen = JSON.parse(readFileSync('/tmp/pf6-genesis.json', 'utf8'));
const genTx = la.decodeTransaction(la.hexToBin(gen.hex));
const feeUtxo = JSON.parse(readFileSync('/tmp/pf6-fee-utxo.json', 'utf8'));
const feeTx = la.decodeTransaction(la.hexToBin(readFileSync('/tmp/pf6-fee-source.hex', 'utf8').trim()));
const sources = [];
for (let i = 0; i < 8; i++) {
  const o = genTx.outputs[i];
  sources.push({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, sequenceNumber: 0n, token: o.token ?? undefined });
}
sources.push({ lockingBytecode: feeTx.outputs[feeUtxo.vout].lockingBytecode, valueSatoshis: feeTx.outputs[feeUtxo.vout].valueSatoshis, sequenceNumber: 0n, token: feeTx.outputs[feeUtxo.vout].token ?? undefined });
const inputs = tx.inputs.map((inp, i) => ({ lockingBytecode: sources[i].lockingBytecode, unlockingBytecode: inp.unlockingBytecode, valueSatoshis: sources[i].valueSatoshis, sequenceNumber: 0n, token: sources[i].token, outpointTransactionHash: inp.outpointTransactionHash, outpointIndex: inp.outpointIndex }));
const outputs = tx.outputs.map((o) => ({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, token: o.token ?? undefined }));
const vm = createRealVm();
const gate = (inps) => { for (let i = 0; i < 6; i++) { const o = evaluatePair(vm, inps[i].lockingBytecode, inps[i].unlockingBytecode, undefined, { index: i, inputs: inps, outputs, outputValueSatoshis: 1000n }); if (o.accepted !== true) return false; } return true; };
const u0 = inputs[0].unlockingBytecode;
const accepted = [];
for (let k = 0; k < u0.length; k++) {
  const tt = inputs.map((i, idx) => idx === 0 ? { ...i, unlockingBytecode: Uint8Array.from(i.unlockingBytecode).map((b, j) => j === k ? b ^ 0xff : b) } : i);
  if (gate(tt)) accepted.push(k);
}
console.log('exec0 accepted flip positions:', accepted.length, '/', u0.length);
// the runs of accepted positions
let runs = [];
let start = null, prev = -2;
for (const k of accepted) { if (k === prev + 1) { prev = k; } else { if (start !== null) runs.push([start, prev]); start = k; prev = k; } }
if (start !== null) runs.push([start, prev]);
console.log('runs:', JSON.stringify(runs.slice(0, 20)));
// where are the runs relative to the unlock structure (the redeem starts at the last push... the exec unlock = [args][redeem])
console.log('unlock len:', u0.length);
// the redeem start = find the last big push — the unlock's structure
