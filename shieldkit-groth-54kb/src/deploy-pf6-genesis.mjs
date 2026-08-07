// Phase B: genesis (pool-create) tx with the pf6 state covenant + verifier locks.
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';

const FOLDER = '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/shieldkit-groth-54kb';
const G = '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/shieldkit-groth';
const WALLET = '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4/wallet-private.json';
const libauthUrl = 'file:///home/toorik/Projects/ZK-Proofs/shieldkit-sdk/shieldkit-groth-54kb/vendor/verifier-workspace/build/node_modules/@bitauth/libauth/build/index.js';
const la = await import(libauthUrl);
const { hexToBin, binToHex, encodeTransaction, decodeTransaction, generateSigningSerializationBch, hash256, secp256k1, encodeDataPush, hash160 } = la;

const wallet = JSON.parse(readFileSync(WALLET, 'utf8'));
const priv = Uint8Array.from(Buffer.from(wallet.privateKeyHex, 'hex'));
const pubHex = wallet.publicKeyHex;
const hotLock = wallet.lockingBytecodeHex;

// pf6 material + covenants
const mat = JSON.parse(readFileSync(path.join(FOLDER, 'src/verifier-material/pf6-action-material.json'), 'utf8'));
const deposit = mat.actions.deposit;
const verifierLocks = deposit.verifierRoles.map(r => Uint8Array.from(Buffer.from(r.lock, 'hex')));
const covenants = await import('file://' + path.join(FOLDER, 'src/product-port/structural-covenants.mjs'));
const topo = await import('file://' + path.join(FOLDER, 'src/topology-pf6.mjs'));
const st = await import('file://' + G + '/packages/action/v2/state.mjs');

const src = JSON.parse(readFileSync('/tmp/pf6-source-txid.json', 'utf8'));
const instanceId = Buffer.from(src.txid, 'hex').reverse().toString('hex'); // product rule: instance = reversed source txid
const sourceFund = 2_000_000n;
const stateBase = 2_500n;
const carrierValue = 1_000n; // the build's SOURCE_VALUE_SATS (PUBLIC_BENCH_CONTEXT)

// initial SKS2 state (fresh pool — EMPTY-TREE HASHED ROOTS, not zeros!)
const pc = await import('file://' + G + '/packages/profile/v2/profile-core.mjs');
const core = JSON.parse(readFileSync(path.join(FOLDER, 'src/pf6-profile-core.json'), 'utf8'));
const profileId = pc.deriveProfileId(core);
const poolModel = await import('file://' + G + '/packages/action/v2/transition.mjs');
const model = poolModel.createDirectV2PoolModel({ profileId, maximumLiveNotes: '32', denominationSats: '10000000' });
const initialState = st.encodeStateNftCommitment(model.state, { denominationSats: '10000000' });

// state covenant (88 B) — helper + trampoline with the pf6 topology
const bindingLock = Uint8Array.of(0x75, 0x51); // OP_DROP OP_TRUE (design 01 v3)
const provisionalHelper = covenants.buildDirectV2StateHelper({
  bindingLock, verifierLocks,
  verifierBaseValues: verifierLocks.map(() => carrierValue),
  bindingBaseValueSats: carrierValue, stateBaseValueSats: 1000n,
  denominationSats: '10000000', stateCategory: instanceId, minimumChangeSats: 546n,
  topologyId: topo.DIRECT_V2_PF6_TOPOLOGY_ID, verifierRoles: topo.DIRECT_V2_PF6_VERIFIER_ROLES,
});
const provisionalLock = covenants.buildDirectV2StateTrampolineLock({ helper: provisionalHelper, bindingLock, topologyId: topo.DIRECT_V2_PF6_TOPOLOGY_ID, verifierRoles: topo.DIRECT_V2_PF6_VERIFIER_ROLES });
const helper = covenants.buildDirectV2StateHelper({
  bindingLock, verifierLocks,
  verifierBaseValues: verifierLocks.map(() => carrierValue),
  bindingBaseValueSats: carrierValue, stateBaseValueSats: stateBase,
  denominationSats: '10000000', stateCategory: instanceId, minimumChangeSats: 546n,
  topologyId: topo.DIRECT_V2_PF6_TOPOLOGY_ID, verifierRoles: topo.DIRECT_V2_PF6_VERIFIER_ROLES,
});
const stateLock = covenants.buildDirectV2StateTrampolineLock({ helper, bindingLock, topologyId: topo.DIRECT_V2_PF6_TOPOLOGY_ID, verifierRoles: topo.DIRECT_V2_PF6_VERIFIER_ROLES });
console.log('state covenant:', stateLock.length, 'B | instanceId:', instanceId.slice(0, 16));

// genesis tx
const category = Uint8Array.from(Buffer.from(instanceId, 'hex')).reverse(); // WIRE order (VM returns display order)
const stateToken = { amount: 0n, category, nft: { capability: 'mutable', commitment: initialState } };
const genesisTx = {
  version: 2,
  inputs: [{ outpointTransactionHash: hexToBin(src.txid), outpointIndex: 0, sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array() }],
  // pf6 covenant layout: verifier@0-5, carrier@6, state@7 (input[i].vout == i)
  outputs: [
    ...verifierLocks.map(l => ({ lockingBytecode: l, valueSatoshis: carrierValue })),
    { lockingBytecode: bindingLock, valueSatoshis: carrierValue },
    { lockingBytecode: stateLock, valueSatoshis: stateBase, token: stateToken },
  ],
  locktime: 0,
};
// sign + fee loop
let genesisHex = null, change = 0n;
for (let i = 0; i < 5; i++) {
  genesisTx.outputs.push({ lockingBytecode: hexToBin(hotLock), valueSatoshis: change });
  const ser = generateSigningSerializationBch(
    { inputIndex: 0, sourceOutputs: [{ lockingBytecode: hexToBin(hotLock), valueSatoshis: sourceFund }], transaction: genesisTx },
    { coveredBytecode: hexToBin(hotLock), signingSerializationType: Uint8Array.of(97) },
  );
  const digest = hash256(ser);
  const schnorr = secp256k1.signMessageHashSchnorr(priv, digest);
  genesisTx.inputs[0].unlockingBytecode = Buffer.concat([
    encodeDataPush(Uint8Array.from([...schnorr, 97])), encodeDataPush(Uint8Array.from(Buffer.from(pubHex, 'hex'))),
  ]);
  const raw = binToHex(encodeTransaction(genesisTx));
  const requiredFee = BigInt(raw.length / 2 + 1);
  const totalOut = stateBase + carrierValue * 7n + change;
  const actualFee = sourceFund - totalOut;
  if (actualFee === requiredFee) { genesisHex = raw; break; }
  change = sourceFund - (stateBase + carrierValue * 7n) - requiredFee;
  genesisTx.outputs.pop();
}
if (!genesisHex) throw new Error('genesis fee loop did not converge');
const genesisTxid = binToHex(hash256(hexToBin(genesisHex)).reverse());
console.log('GENESIS TX:', genesisTxid, '| bytes:', genesisHex.length / 2);
writeFileSync(path.join(FOLDER, 'evidence/03-implementation/deploy-genesis.hex'), genesisHex);
writeFileSync('/tmp/pf6-genesis.json', JSON.stringify({ txid: genesisTxid, hex: genesisHex, instanceId, profileId, stateBase: String(stateBase) }));
