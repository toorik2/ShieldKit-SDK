import { readFileSync } from 'node:fs';
import { createRealVm, evaluatePair } from './harness/src/harness/vm.ts';
import * as la from '@bitauth/libauth';

// the three live txs + their parent outputs
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
  return { name, txid: t.txid, inputs, outputs };
};

const vm = createRealVm();
const gate = (inputs, outputs) => {
  let ok = true;
  for (let i = 0; i < 6; i++) {
    const out = evaluatePair(vm, inputs[i].lockingBytecode, inputs[i].unlockingBytecode, undefined, { index: i, inputs, outputs, outputValueSatoshis: 1000n });
    if (out.accepted !== true) ok = false;
  }
  return ok;
};

for (const name of ['deposit', 'transfer', 'withdrawal']) {
  const { inputs, outputs, txid } = load(name);
  const honest = gate(inputs, outputs);
  const results = [`${name} honest: ${honest ? 'ACCEPT' : 'REJECT'}`];
  // limb flip in each verifier role
  for (let r = 0; r < 6; r++) {
    const t = inputs.map((i, idx) => idx === r ? { ...i, unlockingBytecode: Uint8Array.from(i.unlockingBytecode).map((b, k) => k === 20 ? b ^ 0x01 : b) } : i);
    results.push(`  limb-flip role${r}: ${!gate(t, outputs) ? 'REJECTED' : 'ACCEPTED(!)'}`);
  }
  // packet mutation
  const tp = inputs.map((i, idx) => idx === 6 ? { ...i, unlockingBytecode: Uint8Array.from(i.unlockingBytecode).map((b, k) => k === 30 ? b ^ 0x01 : b) } : i);
  results.push(`  packet-mutation: ${!gate(tp, outputs) ? 'REJECTED' : 'ACCEPTED(!)'}`);
  // role substitution
  const ts = inputs.map((i, idx) => idx === 4 ? { ...i, unlockingBytecode: inputs[5].unlockingBytecode } : i);
  results.push(`  role-substitution: ${!gate(ts, outputs) ? 'REJECTED' : 'ACCEPTED(!)'}`);
  // truncation
  const tt = inputs.map((i, idx) => idx === 0 ? { ...i, unlockingBytecode: i.unlockingBytecode.slice(0, -1) } : i);
  results.push(`  truncation: ${!gate(tt, outputs) ? 'REJECTED' : 'ACCEPTED(!)'}`);
  console.log(results.join('\n'));
}
