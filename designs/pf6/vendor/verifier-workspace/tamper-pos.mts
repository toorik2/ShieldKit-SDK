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
const gate = (inps) => { for (let i = 0; i < 6; i++) { const o = evaluatePair(vm, inps[i].lockingBytecode, inps[i].unlockingBytecode, undefined, { index: i, inputs: inps, outputs, outputValueSatoshis: 1000n }); if (o.accepted !== true) return false; } return true; };
for (const idx of [4, 5]) {
  const u = inputs[idx].unlockingBytecode;
  const accepted = [];
  for (let k = 0; k < u.length; k++) {
    const tt = inputs.map((i, j) => j === idx ? { ...i, unlockingBytecode: Uint8Array.from(i.unlockingBytecode).map((b, q) => q === k ? b ^ 0xff : b) } : i);
    if (gate(tt)) accepted.push(k);
  }
  let runs = [];
  let start = null, prev = -2;
  for (const k of accepted) { if (k === prev + 1) { prev = k; } else { if (start !== null) runs.push([start, prev]); start = k; prev = k; } }
  if (start !== null) runs.push([start, prev]);
  console.log(`role ${idx} (len ${u.length}): ${accepted.length} accepted positions; runs ${JSON.stringify(runs)}`);
}
// role 4: 8893 B, role 5: 9350 B — the runs tell where the filler is
