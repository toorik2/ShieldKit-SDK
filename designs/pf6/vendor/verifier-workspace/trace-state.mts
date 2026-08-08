import { readFileSync } from 'node:fs';
import * as la from '@bitauth/libauth';

const dep = JSON.parse(readFileSync('/tmp/pf6-deposit-tx.json', 'utf8'));
const gen = JSON.parse(readFileSync('/tmp/pf6-genesis.json', 'utf8'));
const tx = la.decodeTransaction(la.hexToBin(dep.hex));
const genesis = la.decodeTransaction(la.hexToBin(gen.hex));
const feeUtxo = JSON.parse(readFileSync('/tmp/pf6-fee-utxo.json', 'utf8'));
const feeTx = la.decodeTransaction(la.hexToBin(readFileSync('/tmp/pf6-fee-source.hex', 'utf8').trim()));
const vouts = [1, 2, 3, 4, 5, 6, 7, 0];
const sources = [];
for (let i = 0; i < 8; i++) {
  const o = genesis.outputs[vouts[i]];
  sources.push({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, sequenceNumber: 0n, token: o.token ?? undefined });
}
sources.push({ lockingBytecode: feeTx.outputs[feeUtxo.vout].lockingBytecode, valueSatoshis: feeTx.outputs[feeUtxo.vout].valueSatoshis, sequenceNumber: 0n, token: feeTx.outputs[feeUtxo.vout].token ?? undefined });

const inputs = tx.inputs.map((inp, i) => ({ lockingBytecode: sources[i].lockingBytecode, unlockingBytecode: inp.unlockingBytecode, valueSatoshis: sources[i].valueSatoshis, sequenceNumber: 0n, token: sources[i].token }));
// run the state input (index 7) with trace
const vm = la.createVirtualMachineBch2026(false);
const state = {
  inputIndex: 7,
  sourceOutputs: inputs.map((i) => ({ lockingBytecode: i.lockingBytecode, valueSatoshis: i.valueSatoshis, token: i.token })),
  transaction: {
    version: 2,
    inputs: inputs.map((i, n) => ({ outpointTransactionHash: new Uint8Array(32), outpointIndex: n, sequenceNumber: 0, unlockingBytecode: i.unlockingBytecode })),
    outputs: [{ lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: 1000n }],
    locktime: 0,
  },
  spentOutputs: [],
};
const out = vm.evaluate(state);
console.log('success:', out.success, '| error:', out.error ?? '');
if (out.trace) {
  const steps = out.trace.steps ?? out.trace;
  console.log('trace steps:', Array.isArray(steps) ? steps.length : typeof steps);
}
