import { readFileSync } from 'node:fs';
import { createRealVm, evaluatePair } from './harness/src/harness/vm.ts';
import * as la from '@bitauth/libauth';
const { decodeTransaction, hexToBin } = la;
const name = 'deposit';
const t = JSON.parse(readFileSync('/tmp/pf6-deposit-tx.json', 'utf8'));
const tx = decodeTransaction(hexToBin(t.hex));
const gen = JSON.parse(readFileSync('/tmp/pf6-genesis.json', 'utf8'));
const genTx = decodeTransaction(hexToBin(gen.hex));
const feeUtxo = JSON.parse(readFileSync('/tmp/pf6-fee-utxo.json', 'utf8'));
const feeTx = decodeTransaction(hexToBin(readFileSync('/tmp/pf6-fee-source.hex', 'utf8').trim()));
const sources = [];
for (let i = 0; i < 8; i++) {
  const o = genTx.outputs[i];
  sources.push({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, sequenceNumber: 0n, token: o.token ?? undefined });
}
sources.push({ lockingBytecode: feeTx.outputs[feeUtxo.vout].lockingBytecode, valueSatoshis: feeTx.outputs[feeUtxo.vout].valueSatoshis, sequenceNumber: 0n, token: feeTx.outputs[feeUtxo.vout].token ?? undefined });
const inputs = tx.inputs.map((inp, i) => ({ lockingBytecode: sources[i].lockingBytecode, unlockingBytecode: inp.unlockingBytecode, valueSatoshis: sources[i].valueSatoshis, sequenceNumber: 0n, token: sources[i].token, outpointTransactionHash: inp.outpointTransactionHash, outpointIndex: inp.outpointIndex }));
const outputs = tx.outputs.map((o) => ({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, token: o.token ?? undefined }));
const vm = createRealVm();
// full validation: ALL 9 input locks
const gateFull = (inps) => {
  for (let i = 0; i < 9; i++) {
    const o = evaluatePair(vm, inps[i].lockingBytecode, inps[i].unlockingBytecode, undefined, { index: i, inputs: inps, outputs, outputValueSatoshis: i === 7 ? outputs[7].valueSatoshis : (i === 8 ? inps[8].valueSatoshis : 1000n) });
    if (o.accepted !== true) return false;
  }
  return true;
};
console.log('honest full:', gateFull(inputs) ? 'ACCEPT' : 'REJECT');
const rng = (seed) => { let s = seed; return () => { s = (s * 1103515245 + 12345) & 0x7fffffff; return s; }; };
const r = rng(7);
for (let idx = 6; idx <= 8; idx++) {
  const u = inputs[idx].unlockingBytecode;
  if (u.length === 0) continue;
  let accepts = 0, total = 0;
  for (let s = 0; s < 60; s++) {
    const k = r() % u.length;
    const tt = inputs.map((i, j) => j === idx ? { ...i, unlockingBytecode: Uint8Array.from(i.unlockingBytecode).map((b, q) => q === k ? b ^ 0xff : b) } : i);
    if (gateFull(tt)) accepts++;
    total++;
  }
  console.log(`input ${idx} (len ${u.length}): ${accepts}/${total} accepted under FULL 9-lock validation`);
}
// roles 1-5 sampled flips under full validation
for (let idx = 1; idx <= 5; idx++) {
  const u = inputs[idx].unlockingBytecode;
  let accepts = 0, total = 0;
  for (let s = 0; s < 60; s++) {
    const k = r() % u.length;
    const tt = inputs.map((i, j) => j === idx ? { ...i, unlockingBytecode: Uint8Array.from(i.unlockingBytecode).map((b, q) => q === k ? b ^ 0xff : b) } : i);
    if (gateFull(tt)) accepts++;
    total++;
  }
  console.log(`input ${idx} (len ${u.length}): ${accepts}/${total} accepted`);
}
