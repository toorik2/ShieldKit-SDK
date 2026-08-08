// ShieldKit-54KB — pf6 WITHDRAWAL assembly (9 inputs, 10 outputs).
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
const FOLDER = '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/designs/pf6';
const G = '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/designs/pf10';
const CUSTODY = '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4';
const libauthUrl = 'file://' + FOLDER + '/vendor/verifier-workspace/build/node_modules/@bitauth/libauth/build/index.js';
const la = await import(libauthUrl);
const { hexToBin, binToHex, encodeTransaction, generateSigningSerializationBch, hash256, secp256k1, encodeDataPush } = la;
const st = await import('file://' + G + '/packages/action/v2/state.mjs');
const covenants = await import('file://' + path.join(FOLDER, 'src/product-port/structural-covenants.mjs'));
const topo = await import('file://' + path.join(FOLDER, 'src/topology-pf6.mjs'));
const wallet = JSON.parse(readFileSync(path.join(CUSTODY, 'wallet-private.json'), 'utf8'));
const priv = Uint8Array.from(Buffer.from(wallet.privateKeyHex, 'hex'));
const pubHex = wallet.publicKeyHex;
const hotLock = wallet.lockingBytecodeHex;
const gen = JSON.parse(readFileSync('/tmp/pf6-genesis.json', 'utf8'));
const tr = JSON.parse(readFileSync('/tmp/pf6-transfer-tx.json', 'utf8'));
const feeUtxo = JSON.parse(readFileSync('/tmp/pf6-fee-utxo.json', 'utf8'));
const meta = JSON.parse(readFileSync('/tmp/pf6-withdrawal-meta.json', 'utf8'));
const trTx = la.decodeTransaction(la.hexToBin(tr.hex));
const run = process.env.PF6_RUN ? '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/designs/pf6/vendor/verifier-workspace/.vc/runs/' + process.env.PF6_RUN : '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/designs/pf6/vendor/verifier-workspace/.vc/runs/pf6-a3-withdrawal-v1';
const inputsDump = JSON.parse(readFileSync(path.join(run, 'build/inputs_dump.json'), 'utf8'));
const instanceId = gen.instanceId;
const carrierValue = 1000n;
const stateInValue = trTx.outputs[7].valueSatoshis;
const stateOutValue = BigInt(meta.stateOutValue);
const verifierLocks = [0,1,2,3,4,5].map(i => trTx.outputs[i].lockingBytecode);
const bindingLock = trTx.outputs[6].lockingBytecode;
const stateLock = trTx.outputs[7].lockingBytecode;
const helper = covenants.buildDirectV2StateHelper({
  bindingLock, verifierLocks,
  verifierBaseValues: verifierLocks.map(() => carrierValue),
  bindingBaseValueSats: carrierValue, stateBaseValueSats: 2500n,
  denominationSats: '10000000', stateCategory: instanceId, minimumChangeSats: 546n,
  topologyId: topo.DIRECT_V2_PF6_TOPOLOGY_ID, verifierRoles: topo.DIRECT_V2_PF6_VERIFIER_ROLES,
});
const stateUnlock = covenants.buildDirectV2StateTrampolineUnlock(helper);
const postCommitment = st.encodeStateNftCommitment(meta.postState, { denominationSats: '10000000' });
const category = Uint8Array.from(Buffer.from(instanceId, 'hex')).reverse();
const stateToken = { amount: 0n, category, nft: { capability: 'mutable', commitment: postCommitment } };
// outputs: verifier@0-5 + carrier@6 + state@7 + withdrawal@8 + change@9
const outBase = [
  ...verifierLocks.map(l => ({ lockingBytecode: l, valueSatoshis: carrierValue })),
  { lockingBytecode: bindingLock, valueSatoshis: carrierValue },
  { lockingBytecode: stateLock, valueSatoshis: stateOutValue, token: stateToken },
  { lockingBytecode: hexToBin(hotLock), valueSatoshis: 10000000n },
];
const verifierUnlocks = inputsDump.slice(0, 6).map(i => Uint8Array.from(Buffer.from(i.unlock, 'hex')));
const packetUnlock = Uint8Array.from(Buffer.from(inputsDump[6].unlock, 'hex'));
const txInputs = [
  ...verifierUnlocks.map((u, i) => ({ outpointTransactionHash: hexToBin(tr.txid), outpointIndex: i, sequenceNumber: 0xfffffffe, unlockingBytecode: u })),
  { outpointTransactionHash: hexToBin(tr.txid), outpointIndex: 6, sequenceNumber: 0xfffffffe, unlockingBytecode: packetUnlock },
  { outpointTransactionHash: hexToBin(tr.txid), outpointIndex: 7, sequenceNumber: 0xfffffffe, unlockingBytecode: stateUnlock },
];
txInputs.push({ outpointTransactionHash: hexToBin(feeUtxo.txid), outpointIndex: feeUtxo.vout, sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array() });
const genesisToken = trTx.outputs[7].token;
let wHex = null, change = 0n;
for (let i = 0; i < 6; i++) {
  const tx = { version: 2, inputs: txInputs, outputs: [...outBase, { lockingBytecode: hexToBin(hotLock), valueSatoshis: change }], locktime: 0 };
  const ser = generateSigningSerializationBch(
    { inputIndex: 8, sourceOutputs: txInputs.map((inp, idx) => ({
        lockingBytecode: idx === 8 ? hexToBin(hotLock) : (idx === 7 ? stateLock : (idx === 6 ? bindingLock : verifierLocks[idx])),
        valueSatoshis: idx === 8 ? BigInt(feeUtxo.sats) : (idx === 7 ? stateInValue : carrierValue),
        ...(idx === 7 ? { token: genesisToken } : {}),
      })), transaction: tx },
    { coveredBytecode: hexToBin(hotLock), signingSerializationType: Uint8Array.of(97) },
  );
  const digest = hash256(ser);
  const schnorr = secp256k1.signMessageHashSchnorr(priv, digest);
  txInputs[8].unlockingBytecode = Buffer.concat([encodeDataPush(Uint8Array.from([...schnorr, 97])), encodeDataPush(Uint8Array.from(Buffer.from(pubHex, 'hex')))]);
  const raw = binToHex(encodeTransaction(tx));
  const requiredFee = BigInt(raw.length / 2 + 1);
  const totalIn = 6n * carrierValue + carrierValue + stateInValue + BigInt(feeUtxo.sats);
  const totalOut = stateOutValue + 6n * carrierValue + carrierValue + 10000000n + change;
  const actualFee = totalIn - totalOut;
  if (actualFee === requiredFee) { wHex = raw; break; }
  change = totalIn - (stateOutValue + 7n * carrierValue + 10000000n) - requiredFee;
}
if (!wHex) throw new Error('withdrawal fee loop did not converge');
const wTxid = binToHex(hash256(hexToBin(wHex)).reverse());
console.log('WITHDRAWAL TX:', wTxid, '| bytes:', wHex.length / 2);
writeFileSync(path.join(FOLDER, 'evidence/03-implementation/withdrawal-tx.hex'), wHex);
writeFileSync('/tmp/pf6-withdrawal-tx.json', JSON.stringify({ txid: wTxid, hex: wHex }));
