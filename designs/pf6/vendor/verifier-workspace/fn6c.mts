
import { readFileSync } from 'node:fs';
const la = await import('file:///home/toorik/Projects/ZK-Proofs/shieldkit-sdk/shieldkit-groth-54kb/vendor/verifier-workspace/build/node_modules/@bitauth/libauth/build/index.js');
import { createRealVm } from './harness/src/harness/vm.ts';
const d = JSON.parse(readFileSync('/tmp/pf6-cli3-withdrawal-tx.json', 'utf8'));
const tx = la.decodeTransaction(la.hexToBin(d.hex));
const tr = JSON.parse(readFileSync('/tmp/pf6-cli3-transfer-tx.json', 'utf8'));
const trTx = la.decodeTransaction(la.hexToBin(tr.hex));
const sources = [];
for (let i = 0; i < 8; i++) { const o = trTx.outputs[i]; sources.push({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, sequenceNumber: 0n, token: o.token ?? undefined }); }
sources.push({ lockingBytecode: trTx.outputs[8].lockingBytecode, valueSatoshis: trTx.outputs[8].valueSatoshis, sequenceNumber: 0n, token: trTx.outputs[8].token ?? undefined });
const inputs = tx.inputs.map((inp, i) => ({ lockingBytecode: sources[i].lockingBytecode, unlockingBytecode: inp.unlockingBytecode, valueSatoshis: sources[i].valueSatoshis, sequenceNumber: 0n, token: sources[i].token, outpointTransactionHash: inp.outpointTransactionHash, outpointIndex: inp.outpointIndex }));
const outputs = tx.outputs.map((o) => ({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis, token: o.token ?? undefined }));
const vm = createRealVm();
const program = {
  inputIndex: 4,
  sourceOutputs: inputs.map((i) => ({ lockingBytecode: i.lockingBytecode, valueSatoshis: i.valueSatoshis ?? 1000n, ...(i.token ? { token: { amount: i.token.amount ?? 0n, category: i.token.category, nft: { capability: i.token.capability, commitment: i.token.commitment } } } : {}) })),
  transaction: { version: 2, inputs: inputs.map((i, n) => ({ outpointTransactionHash: i.outpointTransactionHash ?? new Uint8Array(32), outpointIndex: i.outpointIndex ?? n, sequenceNumber: i.sequenceNumber ?? 0xffffffff, unlockingBytecode: i.unlockingBytecode })), outputs: outputs.map((o) => ({ lockingBytecode: o.lockingBytecode, valueSatoshis: o.valueSatoshis ?? 1000n, ...(o.token ? { token: { amount: o.token.amount ?? 0n, category: o.token.category, nft: { capability: o.token.capability, commitment: o.token.commitment } } } : {}) })), locktime: 0 },
};
const result = await vm.evaluate({ script: inputs[4].lockingBytecode, program: inputs[4].unlockingBytecode, inputIndex: 4, sourceOutputs: program.sourceOutputs, transaction: program.transaction, trace: true });
const ft = result.functionTable || {};
const f6 = ft['06'];
console.log('f6 len:', f6 ? f6.length : 'MISSING', '| hex:', f6 ? la.binToHex(Uint8Array.from(f6)) : '');
// disassemble f6
const names = { 0x00:'ZERO',0x51:'1',0x52:'2',0x53:'3',0x54:'4',0x55:'5',0x56:'6',0x57:'7',0x58:'8',0x59:'9',0x5a:'10',0x5b:'11',0x5c:'12',0x5d:'13',0x5e:'14',0x5f:'15',0x60:'16',0x69:'VERIFY',0x74:'DEPTH',0x75:'DROP',0x76:'DUP',0x77:'NIP',0x78:'OVER',0x79:'PICK',0x7a:'ROLL',0x7b:'ROT',0x7c:'SWAP',0x7d:'TUCK',0x7e:'CAT',0x7f:'SPLIT',0x80:'NUM2BIN',0x81:'BIN2NUM',0x82:'SIZE',0x87:'EQUAL',0x88:'EQUALVERIFY',0x89:'DEFINE',0x8a:'INVOKE',0x8b:'ONEADD',0x8c:'ONESUB',0x93:'ADD',0x94:'SUB',0x95:'MUL',0x9c:'NUMEQUAL',0x9d:'NUMEQUALVERIFY',0x9e:'NUMNOTEQUAL',0x9f:'LESSTHAN',0xa0:'GREATERTHAN',0xa1:'LESSTHANOREQUAL',0xa2:'GREATERTHANOREQUAL',0xa3:'MIN',0xa4:'MAX',0xa5:'WITHIN',0xa8:'SHA256',0xa9:'HASH160',0xaa:'HASH256',0xc0:'INPUTINDEX',0xc1:'ACTIVEBYTECODE',0xc2:'TXVERSION',0xc3:'TXINPUTCOUNT',0xc4:'TXOUTPUTCOUNT',0xc5:'TXLOCKTIME',0xc6:'UTXOVALUE',0xc7:'UTXOBYTECODE',0xc8:'OUTPOINTTXHASH',0xc9:'OUTPOINTINDEX',0xca:'INPUTBYTECODE',0xcb:'INPUTSEQUENCE',0xcc:'OUTPUTVALUE',0xcd:'OUTPUTBYTECODE',0xce:'UTXOTOKENCATEGORY',0xcf:'UTXOTOKENCOMMITMENT',0xd0:'UTXOTOKENAMOUNT',0xd1:'OUTPUTTOKENCATEGORY',0xd2:'OUTPUTTOKENCOMMITMENT',0xd3:'OUTPUTTOKENAMOUNT' };
if (f6) {
  const b = Uint8Array.from(f6);
  let i = 0; const ops = [];
  while (i < b.length && ops.length < 60) {
    const c = b[i];
    if (c >= 0x01 && c <= 0x4b) { ops.push('PUSH' + c); i += 1 + c; continue; }
    if (c === 0x4c) { const n = b[i+1]; ops.push('PUSHDATA1(' + n + ')'); i += 2 + n; continue; }
    ops.push(names[c] || ('0x' + c.toString(16))); i += 1;
  }
  console.log('f6 ops:', ops.join(' '));
}
