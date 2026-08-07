
import { readFileSync } from 'node:fs';
import { createRealVm, evaluatePair } from './harness/src/harness/vm.ts';
import * as la from '@bitauth/libauth';
const { decodeTransaction, hexToBin } = la;
const txHex = readFileSync(process.argv[2], 'utf8').trim();
const soHex = readFileSync(process.argv[3], 'utf8').trim();
const tx = decodeTransaction(hexToBin(txHex));
// parse the count-prefixed output list: count varint + outputs (value8 + scriptLen varint + script + token?)
const soBytes = hexToBin(soHex);
let pos = 0;
const readVarint = () => { const b = soBytes[pos++]; if (b < 0xfd) return b; if (b === 0xfd) { const v = soBytes[pos] | (soBytes[pos+1] << 8); pos += 2; return v; } if (b === 0xfe) { let v = 0; for (let k = 0; k < 4; k++) v |= soBytes[pos+k] << (8*k); pos += 4; return v; } let v = 0n; for (let k = 0; k < 8; k++) v |= BigInt(soBytes[pos+k]) << BigInt(8*k); pos += 8; return v; };
const count = readVarint();
const sos = [];
for (let i = 0; i < count; i++) {
  const value = readVarint();
  const sl = readVarint();
  const script = soBytes.slice(pos, pos + sl); pos += sl;
  // the token presence: a token follows if the output has one — the wire format: [value][scriptLen][script][token?]
  // the token = category(32) + amount(8) + nft(commitmentLen varint + commitment + capability 1)? — parse best-effort:
  let token = undefined;
  if (pos + 41 <= soBytes.length) { token = { category: soBytes.slice(pos, pos + 32), amount: BigInt(soBytes[pos+32] | (soBytes[pos+33] << 8) | (soBytes[pos+34] << 16) | (soBytes[pos+35] << 24) | (soBytes[pos+36] << 32) | (soBytes[pos+37] << 40) | (soBytes[pos+38] << 48) | (soBytes[pos+39] << 56)), nft: { capability: 'mutable', commitment: soBytes.slice(pos + 41, pos + 41 + soBytes[pos+40]) } }; }
  sos.push({ lockingBytecode: script, valueSatoshis: value, token });
}
const vm = createRealVm();
const inputs = tx.inputs.map((inp, i) => ({ lockingBytecode: sos[i].lockingBytecode, unlockingBytecode: inp.unlockingBytecode, valueSatoshis: sos[i].valueSatoshis, sequenceNumber: 0n, token: sos[i].token, outpointTransactionHash: inp.outpointTransactionHash, outpointIndex: inp.outpointIndex }));
const outputs = tx.outputs.map((o) => ({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, token: o.token ?? undefined }));
console.log('internal tx outputs:', outputs.length, '| inputs:', inputs.length);
for (let i = 0; i < 6; i++) {
  const out = evaluatePair(vm, inputs[i].lockingBytecode, inputs[i].unlockingBytecode, undefined, { index: i, inputs, outputs, outputValueSatoshis: 1000n });
  console.log('role', i, ':', out.accepted, '|', (out.error || '').slice(0, 90));
}
