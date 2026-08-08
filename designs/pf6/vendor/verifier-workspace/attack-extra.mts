import { readFileSync, createHash } from 'node:fs';
import { createRealVm, evaluatePair } from './harness/src/harness/vm.ts';
import * as la from '@bitauth/libauth';
const { decodeTransaction, hexToBin } = la;
const load = (name) => {
  const t = JSON.parse(readFileSync(`/tmp/pf6-${name}-tx.json`, 'utf8'));
  const tx = decodeTransaction(hexToBin(t.hex));
  const parentName = name === 'deposit' ? 'genesis' : (name === 'transfer' ? 'deposit' : 'transfer');
  const parent = name === 'deposit'
    ? JSON.parse(readFileSync('/tmp/pf6-genesis.json', 'utf8'))
    : JSON.parse(readFileSync(`/tmp/pf6-${parentName}-tx.json`, 'utf8'));
  const parentTx = decodeTransaction(hexToBin(parent.hex));
  const feeUtxo = JSON.parse(readFileSync('/tmp/pf6-fee-utxo.json', 'utf8'));
  const feeTx = decodeTransaction(hexToBin(readFileSync('/tmp/pf6-fee-source.hex', 'utf8').trim()));
  const sources = [];
  for (let i = 0; i < 8; i++) { const o = parentTx.outputs[i]; sources.push({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, sequenceNumber: 0n, token: o.token ?? undefined }); }
  sources.push({ lockingBytecode: feeTx.outputs[feeUtxo.vout].lockingBytecode, valueSatoshis: feeTx.outputs[feeUtxo.vout].valueSatoshis, sequenceNumber: 0n, token: feeTx.outputs[feeUtxo.vout].token ?? undefined });
  const inputs = tx.inputs.map((inp, i) => ({ lockingBytecode: sources[i].lockingBytecode, unlockingBytecode: inp.unlockingBytecode, valueSatoshis: sources[i].valueSatoshis, sequenceNumber: 0n, token: sources[i].token, outpointTransactionHash: inp.outpointTransactionHash, outpointIndex: inp.outpointIndex }));
  const outputs = tx.outputs.map((o) => ({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, token: o.token ?? undefined }));
  return { inputs, outputs };
};
const vm = createRealVm();
const gate = (inputs, outputs) => { for (let i = 0; i < 6; i++) { const o = evaluatePair(vm, inputs[i].lockingBytecode, inputs[i].unlockingBytecode, undefined, { index: i, inputs, outputs, outputValueSatoshis: 1000n }); if (o.accepted !== true) return false; } return true; };
const results = [];
const { inputs, outputs } = load('deposit');
results.push(['honest deposit', gate(inputs, outputs) ? 'ACCEPT' : 'REJECT']);
// A6: state output dust (2,499)
const outDust = outputs.map((o, i) => i === 7 ? { ...o, valueSatoshis: 2499n } : o);
results.push(['state-value dust 2499', gate(inputs, outDust) ? 'ACCEPT(!)' : 'REJECTED']);
// A6: carrier output dust (999)
const outCarrier = outputs.map((o, i) => i === 6 ? { ...o, valueSatoshis: 999n } : o);
results.push(['carrier-value dust 999', gate(inputs, outCarrier) ? 'ACCEPT(!)' : 'REJECTED']);
// A3: carrier substitution — swap input 6's lock for the verifier lock
const inCarrier = inputs.map((i, idx) => idx === 6 ? { ...i, lockingBytecode: inputs[5].lockingBytecode } : i);
results.push(['carrier lock substituted', gate(inCarrier, outputs) ? 'ACCEPT(!)' : 'REJECTED']);
// A3: packet from a different action (use the transfer packet in the deposit)
const tr = load('transfer');
const inCross = inputs.map((i, idx) => idx === 6 ? { ...i, unlockingBytecode: tr.inputs[6].unlockingBytecode } : i);
results.push(['cross-action packet substitution', gate(inCross, outputs) ? 'ACCEPT(!)' : 'REJECTED']);
// A2: state lock swapped for a verifier lock
const inState = inputs.map((i, idx) => idx === 7 ? { ...i, lockingBytecode: inputs[0].lockingBytecode } : i);
results.push(['state lock swapped', gate(inState, outputs) ? 'ACCEPT(!)' : 'REJECTED']);
// A8: wrong instanceId — mutate the packet's instance region (bytes 0-32 are the header; instance in the packet at 3+? — flip a byte in the packet's profile/instance area)
const pkt = Uint8Array.from(inputs[6].unlockingBytecode);
const inInst = inputs.map((i, idx) => idx === 6 ? { ...i, unlockingBytecode: pkt.map((b, k) => k === 3 ? b ^ 0x01 : b) } : i);
results.push(['packet instance-byte flip', gate(inInst, outputs) ? 'ACCEPT(!)' : 'REJECTED']);
for (const [n, r] of results) console.log(n + ':', r);
