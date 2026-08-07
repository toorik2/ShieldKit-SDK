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
const vm = la.createVirtualMachineBch2026(false);
try {
  const out = vm.evaluate(state, { trace: true });
  console.log('success:', out.success, '| error:', out.error ?? '');
  const trace = out.trace;
  if (trace) {
    const steps = trace.steps ?? trace;
    console.log('steps:', steps.length);
    // find the last few steps before failure
    const last = steps.slice(-8);
    for (const s of last) console.log(JSON.stringify(s).slice(0, 160));
  }
} catch (e) {
  console.log('evaluate threw:', e.message);
  // try the harness approach: run the covenant+helper manually via evaluatePair's internals
  const vm2 = (await import('./harness/src/harness/vm.ts')).createRealVm();
  const out2 = (await import('./harness/src/harness/vm.ts')).evaluatePair(vm2, inputs[7].lockingBytecode, inputs[7].unlockingBytecode, undefined, { index: 7, inputs, outputValueSatoshis: 1000n });
  console.log('evaluatePair:', out2.accepted, out2.error);
}
