// Build vmb-format vectors (expected id txHex sourceOutputsHex idx) for the three live pf6 txs.
import { readFileSync, writeFileSync } from 'node:fs';
const la = await import('file:///home/toorik/Projects/ZK-Proofs/shieldkit-sdk/designs/pf6/vendor/verifier-workspace/build/node_modules/@bitauth/libauth/build/index.js');
const { hexToBin, binToHex, encodeTransaction, decodeTransaction, encodeTransactionOutput, bigIntToCompactUint } = la;
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
  const sos = [];
  for (let i = 0; i < 8; i++) {
    const o = parentTx.outputs[i];
    sos.push({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, token: o.token ?? undefined });
  }
  sos.push({ lockingBytecode: feeTx.outputs[feeUtxo.vout].lockingBytecode, valueSatoshis: feeTx.outputs[feeUtxo.vout].valueSatoshis, token: feeTx.outputs[feeUtxo.vout].token ?? undefined });
  const soHex = binToHex(Buffer.concat([bigIntToCompactUint(BigInt(sos.length)), ...sos.map(o => encodeTransactionOutput(o))]));
  return { name, txid: t.txid, txHex: t.hex, soHex };
};
const lines = [];
for (const name of ['deposit', 'transfer', 'withdrawal']) {
  const { txid, txHex, soHex } = load(name);
  for (let idx = 0; idx < 9; idx++) {
    lines.push(`1 ${name}-${idx} ${txHex} ${soHex} ${idx}`);
  }
}
writeFileSync('/tmp/pf6-vmb-live.txt', lines.join('\n') + '\n');
console.log('vmb lines:', lines.length, '| sample soHex head:', lines[0].split(' ')[3].slice(0, 40));
