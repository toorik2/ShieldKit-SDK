// ShieldKit-54KB — pf6 TRANSFER assembly (9-input tx).
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
const walletPub = JSON.parse(readFileSync(path.join(CUSTODY, 'wallet-public.json'), 'utf8'));
const priv = Uint8Array.from(Buffer.from(wallet.privateKeyHex, 'hex'));
const pubHex = wallet.publicKeyHex;
const hotLock = wallet.lockingBytecodeHex;

const gen = JSON.parse(readFileSync('/tmp/pf6-genesis.json', 'utf8'));
const dep = JSON.parse(readFileSync('/tmp/pf6-deposit-tx.json', 'utf8'));
const feeUtxo = JSON.parse(readFileSync('/tmp/pf6-fee-utxo.json', 'utf8'));
const meta = JSON.parse(readFileSync('/tmp/pf6-transfer-meta.json', 'utf8'));
const depTx = la.decodeTransaction(la.hexToBin(dep.hex));
const run = process.env.PF6_RUN ? '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/designs/pf6/vendor/verifier-workspace/.vc/runs/' + process.env.PF6_RUN : '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/designs/pf6/vendor/verifier-workspace/.vc/runs/pf6-a3-transfer-live';
const inputsDump = JSON.parse(readFileSync(path.join(run, 'build/inputs_dump.json'), 'utf8'));

const instanceId = gen.instanceId;
const carrierValue = 1000n;
const stateInValue = 10002500n;
const stateOutValue = BigInt(meta.stateOutValue);

// the state unlock = the covenant's helper push (same helper as the pool)
const verifierLocks = [0,1,2,3,4,5].map(i => depTx.outputs[i].lockingBytecode);
const bindingLock = depTx.outputs[6].lockingBytecode;
const stateLock = depTx.outputs[7].lockingBytecode;
const helper = covenants.buildDirectV2StateHelper({
  bindingLock, verifierLocks,
  verifierBaseValues: verifierLocks.map(() => carrierValue),
  bindingBaseValueSats: carrierValue, stateBaseValueSats: 2500n,
  denominationSats: '10000000', stateCategory: instanceId, minimumChangeSats: 546n,
  topologyId: topo.DIRECT_V2_PF6_TOPOLOGY_ID, verifierRoles: topo.DIRECT_V2_PF6_VERIFIER_ROLES,
});
const stateUnlock = covenants.buildDirectV2StateTrampolineUnlock(helper);
console.log('state unlock:', stateUnlock.length, 'B');

// the post-transfer commitment (the state output's token)
const postCommitment = st.encodeStateNftCommitment(meta.postState, { denominationSats: '10000000' });
const category = Uint8Array.from(Buffer.from(instanceId, 'hex')).reverse();
const stateToken = { amount: 0n, category, nft: { capability: 'mutable', commitment: postCommitment } };

// outputs
const outBase = [
  ...verifierLocks.map(l => ({ lockingBytecode: l, valueSatoshis: carrierValue })),
  { lockingBytecode: bindingLock, valueSatoshis: carrierValue },
  { lockingBytecode: stateLock, valueSatoshis: stateOutValue, token: stateToken },
];

// inputs: verifier (0-5) + packet (6) + state (7) + fee (8) — sources = the deposit's outputs
const verifierUnlocks = inputsDump.slice(0, 6).map(i => Uint8Array.from(Buffer.from(i.unlock, 'hex')));
const packetUnlock = Uint8Array.from(Buffer.from(inputsDump[6].unlock, 'hex'));
const txInputs = [
  ...verifierUnlocks.map((u, i) => ({ outpointTransactionHash: hexToBin(dep.txid), outpointIndex: i, sequenceNumber: 0xfffffffe, unlockingBytecode: u })),
  { outpointTransactionHash: hexToBin(dep.txid), outpointIndex: 6, sequenceNumber: 0xfffffffe, unlockingBytecode: packetUnlock },
  { outpointTransactionHash: hexToBin(dep.txid), outpointIndex: 7, sequenceNumber: 0xfffffffe, unlockingBytecode: stateUnlock },
];
txInputs.push({ outpointTransactionHash: hexToBin(feeUtxo.txid), outpointIndex: feeUtxo.vout, sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array() });

// fee loop + sign (0x61 with the source tokens)
const genesisToken = depTx.outputs[7].token; // the state input's source token (post-deposit commitment, output 7)
let transferHex = null, change = 0n;
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
  const totalOut = stateOutValue + 6n * carrierValue + carrierValue + change;
  const actualFee = totalIn - totalOut;
  if (actualFee === requiredFee) { transferHex = raw; break; }
  change = totalIn - (stateOutValue + 7n * carrierValue) - requiredFee;
}
if (!transferHex) throw new Error('transfer fee loop did not converge');
const transferTxid = binToHex(hash256(hexToBin(transferHex)).reverse());
console.log('TRANSFER TX:', transferTxid, '| bytes:', transferHex.length / 2);
writeFileSync(path.join(FOLDER, 'evidence/03-implementation/transfer-tx.hex'), transferHex);
writeFileSync('/tmp/pf6-transfer-tx.json', JSON.stringify({ txid: transferTxid, hex: transferHex }));
