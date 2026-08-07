import { readFileSync, writeFileSync } from 'node:fs';
import { createRealVm, evaluatePair } from './harness/src/harness/vm.ts';
import * as la from '@bitauth/libauth';

const load = (name) => {
  const t = JSON.parse(readFileSync(`/tmp/pf6-${name}-tx.json`, 'utf8'));
  const tx = la.decodeTransaction(la.hexToBin(t.hex));
  const parentName = name === 'deposit' ? 'genesis' : (name === 'transfer' ? 'deposit' : 'transfer');
  const parent = name === 'deposit'
    ? JSON.parse(readFileSync('/tmp/pf6-genesis.json', 'utf8'))
    : JSON.parse(readFileSync(`/tmp/pf6-${parentName}-tx.json`, 'utf8'));
  const parentTx = la.decodeTransaction(la.hexToBin(parent.hex));
  const feeUtxo = JSON.parse(readFileSync('/tmp/pf6-fee-utxo.json', 'utf8'));
  const feeTx = la.decodeTransaction(la.hexToBin(readFileSync('/tmp/pf6-fee-source.hex', 'utf8').trim()));
  const sources = [];
  for (let i = 0; i < 8; i++) {
    const o = parentTx.outputs[i];
    sources.push({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, sequenceNumber: 0n, token: o.token ?? undefined });
  }
  sources.push({ lockingBytecode: feeTx.outputs[feeUtxo.vout].lockingBytecode, valueSatoshis: feeTx.outputs[feeUtxo.vout].valueSatoshis, sequenceNumber: 0n, token: feeTx.outputs[feeUtxo.vout].token ?? undefined });
  const inputs = tx.inputs.map((inp, i) => ({ lockingBytecode: sources[i].lockingBytecode, unlockingBytecode: inp.unlockingBytecode, valueSatoshis: sources[i].valueSatoshis, sequenceNumber: 0n, token: sources[i].token, outpointTransactionHash: inp.outpointTransactionHash, outpointIndex: inp.outpointIndex }));
  const outputs = tx.outputs.map((o) => ({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, token: o.token ?? undefined }));
  return { name, inputs, outputs };
};

const vm = createRealVm();
const gate = (inputs, outputs) => {
  for (let i = 0; i < 6; i++) {
    const out = evaluatePair(vm, inputs[i].lockingBytecode, inputs[i].unlockingBytecode, undefined, { index: i, inputs, outputs, outputValueSatoshis: 1000n });
    if (out.accepted !== true) return false;
  }
  return true;
};

const rng = (seed) => { let s = seed; return () => { s = (s * 1103515245 + 12345) & 0x7fffffff; return s; }; };
const results = {};

for (const name of ['deposit', 'transfer', 'withdrawal']) {
  const { inputs, outputs } = load(name);
  const r = rng(42 + name.length);
  let accepts = 0, total = 0;
  // every-byte on exec0 (role 0) + 40 random flips per other role
  const u0 = inputs[0].unlockingBytecode;
  for (let k = 0; k < u0.length; k += 4) { // step 4 for the every-byte sweep (bounded)
    const t = inputs.map((i, idx) => idx === 0 ? { ...i, unlockingBytecode: Uint8Array.from(i.unlockingBytecode).map((b, j) => j === k ? b ^ 0xff : b) } : i);
    if (gate(t, outputs)) accepts++; total++;
  }
  for (let role = 1; role < 6; role++) {
    const u = inputs[role].unlockingBytecode;
    for (let s = 0; s < 40; s++) {
      const k = r() % u.length;
      const t = inputs.map((i, idx) => idx === role ? { ...i, unlockingBytecode: Uint8Array.from(i.unlockingBytecode).map((b, j) => j === k ? b ^ 0xff : b) } : i);
      if (gate(t, outputs)) accepts++; total++;
    }
  }
  // packet + state + fee flips
  for (let idx = 6; idx <= 8; idx++) {
    const u = inputs[idx].unlockingBytecode;
    if (u.length === 0) continue;
    for (let s = 0; s < 20; s++) {
      const k = r() % u.length;
      const t = inputs.map((i, j) => j === idx ? { ...i, unlockingBytecode: Uint8Array.from(i.unlockingBytecode).map((b, q) => q === k ? b ^ 0xff : b) } : i);
      if (gate(t, outputs)) accepts++; total++;
    }
  }
  results[name] = { total, accepts, allRejected: accepts === 0 };
  console.log(`${name}: ${accepts}/${total} tampered txs accepted (expect 0)`);
}
writeFileSync('/tmp/pf6-tamper-systematic.json', JSON.stringify(results, null, 1));
