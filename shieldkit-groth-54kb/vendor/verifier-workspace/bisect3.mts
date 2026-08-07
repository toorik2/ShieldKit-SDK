
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
const evalG = (ins, outs, label) => {
  const out = evaluatePair(vm, ins[4].lockingBytecode, ins[4].unlockingBytecode, undefined, { index: 4, inputs: ins, outputs: outs, outputValueSatoshis: 1000n });
  console.log(label, ':', out.accepted, '|', (out.error || '').slice(0, 80));
};
// A: the fee input's outpoint txid = a DIFFERENT dummy txid (deposit-style)
const A = inputs.map((i, k) => k === 8 ? { ...i, outpointTransactionHash: Uint8Array.from({ length: 32 }, (_, j) => j) } : i);
evalG(A, outputs, 'genesis fee-different-txid');
// B: the fee input's vout = 11 (deposit-style)
const B = inputs.map((i, k) => k === 8 ? { ...i, outpointIndex: 11 } : i);
evalG(B, outputs, 'genesis fee-vout-11');
// C: the packet's [8] byte = 2 (transfer-style) — with the matching digest? — the digest is sha256(packet) — changing [8] changes the digest — skip; instead the whole packet = the transfer's packet + the transfer's input4 + the transfer's ctx?? — too invasive
// D: the state input's value = the deposit-like (2,500) — done before
// E: the outputs[9] (change) removed — the 9-output — done before
// F: the inputs 0-7's outpoint txids = a dummy (all the same dummy) — the guard's txid-equality
const F = inputs.map((i, k) => k < 8 ? { ...i, outpointTransactionHash: Uint8Array.from({ length: 32 }, (_, j) => j) } : i);
evalG(F, outputs, 'genesis all-parents-dummy');
