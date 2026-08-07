
import { readFileSync } from 'node:fs';
const la = await import('file:///home/toorik/Projects/ZK-Proofs/shieldkit-sdk/shieldkit-groth-54kb/vendor/verifier-workspace/build/node_modules/@bitauth/libauth/build/index.js');
import { createRealVm } from './harness/src/harness/vm.ts';
const t = JSON.parse(readFileSync('/tmp/pf6-cli3-transfer-tx.json', 'utf8'));
const tx = la.decodeTransaction(la.hexToBin(t.hex));
const dep = readFileSync('/tmp/spender.hex', 'utf8').trim();
const depTx = la.decodeTransaction(la.hexToBin(dep));
const sources = [];
for (let i = 0; i < 8; i++) { const o = depTx.outputs[i]; sources.push({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, sequenceNumber: 0n, token: o.token ?? undefined }); }
sources.push({ lockingBytecode: depTx.outputs[8].lockingBytecode, valueSatoshis: depTx.outputs[8].valueSatoshis, sequenceNumber: 0n, token: depTx.outputs[8].token ?? undefined });
const inputs = tx.inputs.map((inp, i) => ({ lockingBytecode: sources[i].lockingBytecode, unlockingBytecode: inp.unlockingBytecode, valueSatoshis: sources[i].valueSatoshis, sequenceNumber: 0n, token: sources[i].token, outpointTransactionHash: inp.outpointTransactionHash, outpointIndex: inp.outpointIndex }));
const outputs = tx.outputs.map((o) => ({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, token: o.token ?? undefined }));
const vm = createRealVm();
const program = {
  inputIndex: 4,
  sourceOutputs: inputs.map((i) => ({ lockingBytecode: i.lockingBytecode, valueSatoshis: i.valueSatoshis ?? 1000n, ...(i.token ? { token: { amount: i.token.amount ?? 0n, category: i.token.category, nft: { capability: i.token.capability, commitment: i.token.commitment } } } : {}) })),
  transaction: { version: 2, inputs: inputs.map((i, n) => ({ outpointTransactionHash: i.outpointTransactionHash ?? new Uint8Array(32), outpointIndex: i.outpointIndex ?? n, sequenceNumber: i.sequenceNumber ?? 0xffffffff, unlockingBytecode: i.unlockingBytecode })), outputs: outputs.map((o) => ({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis ?? 1000n, ...(o.token ? { token: { amount: o.token.amount ?? 0n, category: o.token.category, nft: { capability: o.token.capability, commitment: o.token.commitment } } } : {}) })), locktime: 0 },
};
const result = await vm.evaluate({ script: inputs[4].lockingBytecode, program: inputs[4].unlockingBytecode, inputIndex: 4, sourceOutputs: program.sourceOutputs, transaction: program.transaction, trace: true });
console.log('transfer genesis accepted:', result.accepted, '| error:', (result.error || '').slice(0, 60));
const stack = result.stack || [];
console.log('stack depth:', stack.length);
if (stack.length > 74) {
  console.log('pick73 target:', la.binToHex(stack[stack.length - 1 - 73]), '| len', stack[stack.length - 1 - 73].length);
} else {
  console.log('stack too shallow — the transfer PASSES (the verify succeeded, the stack has been consumed differently)');
}
