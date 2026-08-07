
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
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
// mutate the packet's [8] to 2 + recompute the digest (sha256 of the bare packet) in input4@451
const u6 = Uint8Array.from(tx.inputs[6].unlockingBytecode);
u6[3 + 8] = 2; // the bare packet's [8] (after the 3-byte push)
const bare = u6.subarray(3);
const digest = createHash('sha256').update(Buffer.from(bare)).digest();
const u4 = Uint8Array.from(tx.inputs[4].unlockingBytecode);
u4.set(digest, 451);
const ins = inputs.map((i, k) => k === 6 ? { ...i, unlockingBytecode: u6 } : (k === 4 ? { ...i, unlockingBytecode: u4 } : i));
evalG(ins, outputs, 'genesis packet[8]=2 + new digest');
