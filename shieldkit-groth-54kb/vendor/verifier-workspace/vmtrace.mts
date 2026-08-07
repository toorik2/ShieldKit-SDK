
import { readFileSync } from 'node:fs';
import { createVirtualMachineBch2026, createTestAuthenticationProgramBch } from '@bitauth/libauth';
import { createRealVm } from './harness/src/harness/vm.ts';
const la = await import('file:///home/toorik/Projects/ZK-Proofs/shieldkit-sdk/shieldkit-groth-54kb/vendor/verifier-workspace/build/node_modules/@bitauth/libauth/build/index.js');
const d = JSON.parse(readFileSync('/tmp/pf6-cli3-withdrawal-tx.json', 'utf8'));
const tx = la.decodeTransaction(la.hexToBin(d.hex));
const tr = JSON.parse(readFileSync('/tmp/pf6-cli3-transfer-tx.json', 'utf8'));
const trTx = la.decodeTransaction(la.hexToBin(tr.hex));
const sources = [];
for (let i = 0; i < 8; i++) { const o = trTx.outputs[i]; sources.push({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, sequenceNumber: 0n, token: o.token ?? undefined }); }
sources.push({ lockingBytecode: trTx.outputs[8].lockingBytecode, valueSatoshis: trTx.outputs[8].valueSatoshis, sequenceNumber: 0n, token: trTx.outputs[8].token ?? undefined });
const inputs = tx.inputs.map((inp, i) => ({ lockingBytecode: sources[i].lockingBytecode, unlockingBytecode: inp.unlockingBytecode, valueSatoshis: sources[i].valueSatoshis, sequenceNumber: 0n, token: sources[i].token, outpointTransactionHash: inp.outpointTransactionHash, outpointIndex: inp.outpointIndex }));
const outputs = tx.outputs.map((o) => ({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, token: o.token ?? undefined }));
// the real VM from the harness + the trace via the program
const vm = createRealVm();
// build the program the same way evaluatePair does
const program = {
  inputIndex: 4,
  sourceOutputs: inputs.map((i) => ({ lockingBytecode: i.lockingBytecode, valueSatoshis: i.valueSatoshis ?? 1000n, ...(i.token ? { token: { amount: i.token.amount ?? 0n, category: i.token.category, nft: { capability: i.token.capability, commitment: i.token.commitment } } } : {}) })),
  transaction: { version: 2, inputs: inputs.map((i, n) => ({ outpointTransactionHash: i.outpointTransactionHash ?? new Uint8Array(32), outpointIndex: i.outpointIndex ?? n, sequenceNumber: i.sequenceNumber ?? 0xffffffff, unlockingBytecode: i.unlockingBytecode })), outputs: outputs.map((o) => ({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis ?? 1000n, ...(o.token ? { token: { amount: o.token.amount ?? 0n, category: o.token.category, nft: { capability: o.token.capability, commitment: o.token.commitment } } } : {}) })), locktime: 0 },
};
const result = await vm.evaluate({ script: inputs[4].lockingBytecode, program: inputs[4].unlockingBytecode, inputIndex: 4, sourceOutputs: program.sourceOutputs, transaction: program.transaction, trace: true });
console.log('accepted:', result.accepted, '| error:', (result.error || '').slice(0, 120));
if (result.trace) {
  const steps = result.trace;
  console.log('steps:', steps.length);
  // the last 6 steps
  for (const st of steps.slice(-6)) {
    console.log(JSON.stringify(st).slice(0, 220));
  }
}
