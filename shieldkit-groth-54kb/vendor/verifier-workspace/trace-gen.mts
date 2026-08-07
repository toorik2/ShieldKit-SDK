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
const inputs = tx.inputs.map((inp, i) => ({ lockingBytecode: sources[i].lockingBytecode, unlockingBytecode: inp.unlockingBytecode, valueSatoshis: sources[i].valueSatoshis, sequenceNumber: 0n, token: sources[i].token, outpointTransactionHash: inp.outpointTransactionHash, outpointIndex: inp.outpointIndex }));
const outputs = tx.outputs.map((o) => ({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, token: o.token ?? undefined }));
const program = {
  inputIndex: 4,
  sourceOutputs: inputs.map((i) => ({ lockingBytecode: i.lockingBytecode, valueSatoshis: i.valueSatoshis, token: i.token })),
  transaction: { version: 2, inputs: inputs.map((i, n) => ({ outpointTransactionHash: i.outpointTransactionHash, outpointIndex: i.outpointIndex, sequenceNumber: 0, unlockingBytecode: i.unlockingBytecode })), outputs, locktime: 0 },
  spentOutputs: [],
};
const vm = la.createVirtualMachineBch2026(false);
const trace = vm.debug(program);
const errIdx = trace.findIndex(s => s.error !== undefined);
console.log('error at trace', errIdx, '| total', trace.length);
const hex = (x) => x === undefined ? '?' : (x.length !== undefined ? Buffer.from(x).toString('hex').slice(0, 20) : String(x).slice(0, 20));
for (let i = Math.max(0, errIdx - 5); i <= errIdx; i++) {
  const s = trace[i];
  const inst = (s.instructions ?? [])[s.ip];
  console.log(i, 'ip=' + s.ip, 'op=0x' + (inst?.opcode ?? '??').toString(16), 'depth=' + (s.stack?.length ?? '?'), (s.stack ?? []).map(hex).join(' | '), s.error ? '<<ERR' : '');
}
