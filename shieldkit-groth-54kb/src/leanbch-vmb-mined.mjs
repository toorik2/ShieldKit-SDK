// vmb vectors from the MINED pool-11 chain with per-tx correct parents + fee sources.
import { readFileSync, writeFileSync } from 'node:fs';
const la = await import('file:///home/toorik/Projects/ZK-Proofs/shieldkit-sdk/shieldkit-groth-54kb/vendor/verifier-workspace/build/node_modules/@bitauth/libauth/build/index.js');
const { hexToBin, binToHex, decodeTransaction, encodeTransactionOutput, bigIntToCompactUint } = la;
const load = (name) => {
  const t = JSON.parse(readFileSync(`/tmp/pf6-mined-${name}.json`, 'utf8'));
  const tx = decodeTransaction(hexToBin(t.hex));
  const parent = JSON.parse(readFileSync(`/tmp/pf6-mined-${name === 'deposit' ? 'genesis' : (name === 'transfer' ? 'deposit' : 'transfer')}.json`, 'utf8'));
  const parentTx = decodeTransaction(hexToBin(parent.hex));
  const fee = JSON.parse(readFileSync(`/tmp/pf6-mined-fee-${name}.json`, 'utf8'));
  const feeTx = decodeTransaction(hexToBin(fee.hex));
  const sos = [];
  for (let i = 0; i < 8; i++) {
    const o = parentTx.outputs[i];
    sos.push({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, token: o.token ?? undefined });
  }
  const fo = feeTx.outputs[fee.vout];
  sos.push({ lockingBytecode: fo.lockingBytecode, valueSatoshis: fo.valueSatoshis, token: fo.token ?? undefined });
  const soHex = binToHex(Buffer.concat([bigIntToCompactUint(BigInt(sos.length)), ...sos.map(o => encodeTransactionOutput(o))]));
  return { name, txid: t.txid, txHex: t.hex, soHex };
};
const lines = [];
for (const name of ['deposit', 'transfer', 'withdrawal']) {
  const { name: n, txHex, soHex } = load(name);
  for (let idx = 0; idx < 9; idx++) lines.push(`1 ${n}-${idx} ${txHex} ${soHex} ${idx}`);
}
writeFileSync('/tmp/pf6-vmb-mined.txt', lines.join('\n') + '\n');
console.log('mined vmb lines:', lines.length);
