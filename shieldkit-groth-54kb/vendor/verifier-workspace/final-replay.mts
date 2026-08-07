
import { readFileSync } from 'node:fs';
import { createRealVm, evaluatePair } from './harness/src/harness/vm.ts';
import * as la from '@bitauth/libauth';
const { decodeTransaction, hexToBin } = la;
const raw = readFileSync('/tmp/cli-deposit.hex', 'utf8').trim();
const tx = decodeTransaction(hexToBin(raw));
const gen = JSON.parse(readFileSync('/tmp/pf6-cli-home3/pf6-pool.json', 'utf8'));
const genTx = decodeTransaction(hexToBin(gen.genesisHex));
const fee = JSON.parse(readFileSync('/tmp/pf6-vmb-depfee.json', 'utf8'));
const feeTx = decodeTransaction(hexToBin(fee.hex));
const sources = [];
for (let i = 0; i < 8; i++) { const o = genTx.outputs[i]; sources.push({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, sequenceNumber: 0n, token: o.token ?? undefined }); }
sources.push({ lockingBytecode: feeTx.outputs[fee.vout].lockingBytecode, valueSatoshis: feeTx.outputs[fee.vout].valueSatoshis, sequenceNumber: 0n, token: feeTx.outputs[fee.vout].token ?? undefined });
const inputs = tx.inputs.map((inp, i) => ({ lockingBytecode: sources[i].lockingBytecode, unlockingBytecode: inp.unlockingBytecode, valueSatoshis: sources[i].valueSatoshis, sequenceNumber: 0n, token: sources[i].token, outpointTransactionHash: inp.outpointTransactionHash, outpointIndex: inp.outpointIndex }));
const outputs = tx.outputs.map((o) => ({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, token: o.token ?? undefined }));
const vm = createRealVm();
const gate = (ins) => { for (let i = 0; i < 6; i++) { const o = evaluatePair(vm, ins[i].lockingBytecode, ins[i].unlockingBytecode, undefined, { index: i, inputs: ins, outputs, outputValueSatoshis: 1000n }); if (o.accepted !== true) return false; } return true; };
console.log('honest deposit gate:', gate(inputs) ? 'ACCEPT' : 'REJECT');
// tamper: flip a byte in the exec0 unlock (the authenticated region — NOT the densDrop windows)
const tampered = inputs.map((i, k) => k === 0 ? { ...i, unlockingBytecode: Uint8Array.from(i.unlockingBytecode).map((b, j) => j === 500 ? b ^ 0xff : b) } : i);
console.log('tampered gate:', gate(tampered) ? 'ACCEPT(!)' : 'REJECTED');
