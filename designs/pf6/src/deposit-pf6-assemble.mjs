// Phase E: assemble the 9-input deposit tx + sign fee + validate.
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
const feeUtxo = JSON.parse(readFileSync('/tmp/pf6-fee-utxo.json', 'utf8'));
const constants = JSON.parse(readFileSync(path.join(FOLDER, 'src/fresh-pool-constants.json'), 'utf8'));
const postState = JSON.parse(readFileSync('/tmp/pf6-poststate.json', 'utf8'));
const mat = JSON.parse(readFileSync(path.join(FOLDER, 'src/verifier-material/pf6-action-material.json'), 'utf8'));
const depositMat = mat.actions.deposit;
const run = process.env.PF6_RUN ? path.join(FOLDER, 'vendor/verifier-workspace/.vc/runs', process.env.PF6_RUN) : path.join(FOLDER, 'vendor/verifier-workspace/.vc/runs/pf6-a3-deposit-live');
const inputsDump = JSON.parse(readFileSync(path.join(run, 'build/inputs_dump.json'), 'utf8'));

const instanceId = gen.instanceId;
const profileId = gen.profileId;
const stateBase = 2500n;
const carrierValue = 1000n; // the build's SOURCE_VALUE_SATS
const stateOutValue = stateBase + 10_000_000n;
const DENOMINATION = '10000000';

// state unlock: push(helper) — the trampoline
const verifierLocks = depositMat.verifierRoles.map(r => Uint8Array.from(Buffer.from(r.lock, 'hex')));
const bindingLock = Uint8Array.of(0x75, 0x51); // OP_DROP OP_TRUE (design 01 v3)
const helper = covenants.buildDirectV2StateHelper({
  bindingLock, verifierLocks,
  verifierBaseValues: verifierLocks.map(() => carrierValue),
  bindingBaseValueSats: carrierValue, stateBaseValueSats: stateBase,
  denominationSats: DENOMINATION, stateCategory: instanceId, minimumChangeSats: 546n,
  topologyId: topo.DIRECT_V2_PF6_TOPOLOGY_ID, verifierRoles: topo.DIRECT_V2_PF6_VERIFIER_ROLES,
});
const stateLock = covenants.buildDirectV2StateTrampolineLock({ helper, bindingLock, topologyId: topo.DIRECT_V2_PF6_TOPOLOGY_ID, verifierRoles: topo.DIRECT_V2_PF6_VERIFIER_ROLES });
const stateUnlock = covenants.buildDirectV2StateTrampolineUnlock(helper);
console.log('state unlock:', stateUnlock.length, 'B');

// post-state commitment (the state output's NFT)
const postCommitment = st.encodeStateNftCommitment(postState, { denominationSats: DENOMINATION });
const genesisTx = la.decodeTransaction(la.hexToBin(gen.hex));
const genesisStateToken = genesisTx.outputs[7].token; // the state input's source token (initial commitment)
const category = Uint8Array.from(Buffer.from(instanceId, 'hex')).reverse(); // WIRE order (VM returns display order)
const stateToken = { amount: 0n, category, nft: { capability: 'mutable', commitment: postCommitment } };

// outputs: state + 6 verifier + carrier + change (fee loop)
const outBase = [
  ...verifierLocks.map(l => ({ lockingBytecode: l, valueSatoshis: carrierValue })),
  { lockingBytecode: bindingLock, valueSatoshis: carrierValue },
  { lockingBytecode: stateLock, valueSatoshis: stateOutValue, token: stateToken },
];

// inputs: verifier (0-5) + packet (6) + state (7) + fee (8)
const verifierUnlocks = inputsDump.slice(0, 6).map(i => Uint8Array.from(Buffer.from(i.unlock, 'hex')));
const packetUnlock = Uint8Array.from(Buffer.from(inputsDump[6].unlock, 'hex'));
const txInputs = [
  ...verifierUnlocks.map(u => ({ outpointTransactionHash: hexToBin(gen.txid), outpointIndex: 0, sequenceNumber: 0xfffffffe, unlockingBytecode: u })),
  { outpointTransactionHash: hexToBin(gen.txid), outpointIndex: 6, sequenceNumber: 0xfffffffe, unlockingBytecode: packetUnlock },
  { outpointTransactionHash: hexToBin(gen.txid), outpointIndex: 0, sequenceNumber: 0xfffffffe, unlockingBytecode: stateUnlock },
];
// pf6 layout: input[i].vout == i (verifier@0-5, carrier@6, state@7)
verifierUnlocks.forEach((_, i) => { txInputs[i].outpointIndex = i; });
txInputs[6].outpointIndex = 6; // packet carrier
txInputs[7].outpointIndex = 7; // state
txInputs.push({ outpointTransactionHash: hexToBin(feeUtxo.txid), outpointIndex: feeUtxo.vout, sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array() });

// fee loop: assemble + sign input 8
let depositHex = null, change = 0n;
for (let i = 0; i < 6; i++) {
  const tx = { version: 2, inputs: txInputs, outputs: [...outBase, { lockingBytecode: hexToBin(hotLock), valueSatoshis: change }], locktime: 0 };
  const ser = generateSigningSerializationBch(
    { inputIndex: 8, sourceOutputs: txInputs.map((inp, idx) => ({
        lockingBytecode: idx === 8 ? hexToBin(hotLock) : (idx === 7 ? stateLock : (idx === 6 ? bindingLock : verifierLocks[idx])),
        valueSatoshis: idx === 8 ? BigInt(feeUtxo.sats) : (idx === 7 ? stateBase : carrierValue),
        ...(idx === 7 ? { token: genesisStateToken } : {}), // SIGHASH_UTXOS commits to the SOURCE tokens (the genesis's state output)
      })), transaction: tx },
    { coveredBytecode: hexToBin(hotLock), signingSerializationType: Uint8Array.of(97) },
  );
  const digest = hash256(ser);
  const schnorr = secp256k1.signMessageHashSchnorr(priv, digest);
  txInputs[8].unlockingBytecode = Buffer.concat([encodeDataPush(Uint8Array.from([...schnorr, 97])), encodeDataPush(Uint8Array.from(Buffer.from(pubHex, 'hex')))]);
  const raw = binToHex(encodeTransaction(tx));
  const requiredFee = BigInt(raw.length / 2 + 1);
  const totalIn = 6n * carrierValue + carrierValue + stateBase + BigInt(feeUtxo.sats);
  const totalOut = stateOutValue + 6n * carrierValue + carrierValue + change;
  const actualFee = totalIn - totalOut;
  if (actualFee === requiredFee) { depositHex = raw; break; }
  change = totalIn - (stateOutValue + 7n * carrierValue) - requiredFee;
}
if (!depositHex) throw new Error('deposit fee loop did not converge');
const depositTxid = binToHex(hash256(hexToBin(depositHex)).reverse());
console.log('DEPOSIT TX:', depositTxid, '| bytes:', depositHex.length / 2);
writeFileSync(path.join(FOLDER, 'evidence/03-implementation/deposit-tx.hex'), depositHex);
writeFileSync('/tmp/pf6-deposit-tx.json', JSON.stringify({ txid: depositTxid, hex: depositHex }));
