import { readFileSync } from 'node:fs';
import { createRealVm, evaluatePair } from './harness/src/harness/vm.ts';
import * as la from '@bitauth/libauth';
const { decodeTransaction, hexToBin } = la;
const load = (name) => {
  const t = JSON.parse(readFileSync(`/tmp/pf6-${name}-tx.json`, 'utf8'));
  const tx = decodeTransaction(hexToBin(t.hex));
  const parent = name === 'deposit'
    ? JSON.parse(readFileSync('/tmp/pf6-genesis.json', 'utf8'))
    : JSON.parse(readFileSync(`/tmp/pf6-${name === 'transfer' ? 'deposit' : 'transfer'}-tx.json`, 'utf8'));
  const parentTx = decodeTransaction(hexToBin(parent.hex));
  const feeUtxo = JSON.parse(readFileSync('/tmp/pf6-fee-utxo.json', 'utf8'));
  const feeTx = decodeTransaction(hexToBin(readFileSync('/tmp/pf6-fee-source.hex', 'utf8').trim()));
  const sources = [];
  for (let i = 0; i < 8; i++) {
    const o = parentTx.outputs[i];
    sources.push({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, sequenceNumber: 0n, token: o.token ?? undefined });
  }
  sources.push({ lockingBytecode: feeTx.outputs[feeUtxo.vout].lockingBytecode, valueSatoshis: feeTx.outputs[feeUtxo.vout].valueSatoshis, sequenceNumber: 0n, token: feeTx.outputs[feeUtxo.vout].token ?? undefined });
  const inputs = tx.inputs.map((inp, i) => ({ lockingBytecode: sources[i].lockingBytecode, unlockingBytecode: inp.unlockingBytecode, valueSatoshis: sources[i].valueSatoshis, sequenceNumber: 0n, token: sources[i].token, outpointTransactionHash: inp.outpointTransactionHash, outpointIndex: inp.outpointIndex }));
  const outputs = tx.outputs.map((o) => ({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, token: o.token ?? undefined }));
  return { inputs, outputs };
};
const vm = createRealVm();
const gate = (inputs, outputs) => { for (let i = 0; i < 6; i++) { const o = evaluatePair(vm, inputs[i].lockingBytecode, inputs[i].unlockingBytecode, undefined, { index: i, inputs, outputs, outputValueSatoshis: 1000n }); if (o.accepted !== true) return false; } return true; };
const rng = (seed) => { let s = seed; return () => { s = (s * 1103515245 + 12345) & 0x7fffffff; return s; }; };
for (const name of ['deposit', 'transfer', 'withdrawal']) {
  const { inputs, outputs } = load(name);
  const r = rng(100 + name.length);
  let perRole = {};
  for (let idx = 0; idx < 6; idx++) {
    const u = inputs[idx].unlockingBytecode;
    let accepts = 0, total = 0;
    for (let s = 0; s < 50; s++) {
      const k = r() % u.length;
      const tt = inputs.map((i, j) => j === idx ? { ...i, unlockingBytecode: Uint8Array.from(i.unlockingBytecode).map((b, q) => q === k ? b ^ 0xff : b) } : i);
      if (gate(tt, outputs)) accepts++;
      total++;
    }
    perRole[idx] = `${accepts}/${total}`;
  }
  // packet flips (input 6)
  const u6 = inputs[6].unlockingBytecode;
  let a6 = 0;
  for (let s = 0; s < 50; s++) {
    const k = r() % u6.length;
    const tt = inputs.map((i, j) => j === 6 ? { ...i, unlockingBytecode: Uint8Array.from(i.unlockingBytecode).map((b, q) => q === k ? b ^ 0xff : b) } : i);
    if (gate(tt, outputs)) a6++;
  }
  console.log(`${name}: roles ${JSON.stringify(perRole)} packet ${a6}/50`);
}
