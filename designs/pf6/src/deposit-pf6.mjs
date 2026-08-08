// ShieldKit-54KB — pf6 DEPOSIT (live chipnet, zero-conf).
// Linear flow: pool model -> output note -> context -> transition -> circuit input -> prove -> pf6 build -> assemble.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import path from 'node:path';

const FOLDER = '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/designs/pf6';
const G = '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/designs/pf10';
const CUSTODY = '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4';
const libauthUrl = 'file://' + FOLDER + '/vendor/verifier-workspace/build/node_modules/@bitauth/libauth/build/index.js';
const la = await import(libauthUrl);
const { hexToBin, binToHex, encodeTransaction, encodeTransactionOutputs, generateSigningSerializationBch, hash256, secp256k1, encodeDataPush } = la;

// product modules (read-only)
const notes = await import('file://' + G + '/packages/action/v2/notes.mjs');
const transitionMod = await import('file://' + G + '/packages/action/v2/transition.mjs');
const circuitWitness = await import('file://' + G + '/packages/action/v2/circuit-witness.mjs');
const contextMod = await import('file://' + G + '/packages/action/v2/context.mjs');
const st = await import('file://' + G + '/packages/action/v2/state.mjs');
const poolMod = await import('file://' + G + '/packages/action/v2/transition.mjs');
const covenants = await import('file://' + path.join(FOLDER, 'src/product-port/structural-covenants.mjs'));
const topo = await import('file://' + path.join(FOLDER, 'src/topology-pf6.mjs'));
const prove = await import('file://' + path.join(FOLDER, 'src/prove-pf6.mjs'));

// inputs
const gen = JSON.parse(readFileSync('/tmp/pf6-genesis.json', 'utf8'));
const feeUtxo = JSON.parse(readFileSync('/tmp/pf6-fee-utxo.json', 'utf8'));
const mat = JSON.parse(readFileSync(path.join(FOLDER, 'src/verifier-material/pf6-action-material.json'), 'utf8'));
const depositMat = mat.actions.deposit;
const constants = JSON.parse(readFileSync(path.join(FOLDER, 'src/fresh-pool-constants.json'), 'utf8'));

const instanceId = gen.instanceId;
const profileId = gen.profileId;
const stateBase = 2500n;
const carrierValue = 1000n;
const DENOMINATION = '10000000';
const wallet = JSON.parse(readFileSync(path.join(CUSTODY, 'wallet-private.json'), 'utf8'));
const priv = Uint8Array.from(Buffer.from(wallet.privateKeyHex, 'hex'));
const pubHex = wallet.publicKeyHex;
const hotLock = wallet.lockingBytecodeHex;

// ---- 1) pool account (note keys) — custody only ----
const accountPath = path.join(CUSTODY, 'pf6-pool-account.json');
const BABYJUB_ORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;
function sampleScalar() {
  for (let i = 0; i < 1024; i++) {
    const hex = randomBytes(32).toString('hex');
    const v = BigInt('0x' + hex);
    if (v > 0n && v < BABYJUB_ORDER) return hex;
  }
  throw new Error('scalar sampling failed');
}
let account;
if (existsSync(accountPath)) {
  account = JSON.parse(readFileSync(accountPath, 'utf8'));
} else {
  account = { spendSecret: sampleScalar(), incomingViewSecret: sampleScalar() };
  writeFileSync(accountPath, JSON.stringify(account, null, 1), { mode: 0o600 });
  console.log('pool account keys generated (custody)');
}
const address = notes.deriveDirectV2Address({ networkId: 2, profileId, instanceId, ...account });
console.log('address derived (authority', address.authority.slice(0, 12) + '...)');

// ---- 2) pool model + output note ----
const model = poolMod.createDirectV2PoolModel({ profileId, maximumLiveNotes: '32', denominationSats: DENOMINATION });
const rng = { bytes(length) { if (length !== 32) throw new Error('rng length'); return Uint8Array.from(randomBytes(32)); } };
const output = notes.constructDirectV2Output({ address, postActionSequence: '1', rng });
console.log('output note leaf:', output.public.outputNoteLeaf.slice(0, 16));

// ---- 3) context (skeleton) ----
const verifierLocks = depositMat.verifierRoles.map(r => Uint8Array.from(Buffer.from(r.lock, 'hex')));
const bindingLock = Uint8Array.of(0x75, 0x51); // OP_DROP OP_TRUE (design 01 v3)
const initialState = st.encodeStateNftCommitment({
  profileId, noteRoot: '0'.repeat(64), nullifierRoot: '0'.repeat(64),
  noteCount: '0', nullifierCount: '0', maximumLiveNotes: '32', reserveSats: '0', actionSequence: '0',
}, { denominationSats: DENOMINATION });
const helper = covenants.buildDirectV2StateHelper({
  bindingLock, verifierLocks,
  verifierBaseValues: verifierLocks.map(() => carrierValue),
  bindingBaseValueSats: carrierValue, stateBaseValueSats: stateBase,
  denominationSats: DENOMINATION, stateCategory: instanceId, minimumChangeSats: 546n,
  topologyId: topo.DIRECT_V2_PF6_TOPOLOGY_ID, verifierRoles: topo.DIRECT_V2_PF6_VERIFIER_ROLES,
});
const stateLock = covenants.buildDirectV2StateTrampolineLock({ helper, bindingLock, topologyId: topo.DIRECT_V2_PF6_TOPOLOGY_ID, verifierRoles: topo.DIRECT_V2_PF6_VERIFIER_ROLES });

// post-state commitment (transition with placeholder hash first)
const t0 = transitionMod.applyDirectV2Transition({
  kind: 'deposit', networkId: 2, profileId, instanceId, denominationSats: DENOMINATION,
  preState: model.state, noteTree: model.noteTree, nullifierTree: model.nullifierTree,
  transactionContextHash: '0'.repeat(64),
  output: { outputNoteLeaf: output.public.outputNoteLeaf, encryptedRecord: output.public.encryptedRecord },
});
const postState = t0.state; // {profileId, noteRoot, nullifierRoot, noteCount, ...}
console.log('postState noteRoot:', postState.noteRoot.slice(0, 16), '| noteCount:', postState.noteCount, '| seq:', postState.actionSequence);
writeFileSync('/tmp/pf6-poststate.json', JSON.stringify(postState));

// state output token prefix (via libauth output encoding)
const postCommitment = st.encodeStateNftCommitment(postState, { denominationSats: DENOMINATION });
const category = Uint8Array.from(Buffer.from(instanceId, 'hex')).reverse(); // WIRE order (VM returns display order)
const stateOutputWithToken = {
  lockingBytecode: stateLock, valueSatoshis: stateBase + 10_000_000n,
  token: { amount: 0n, category, nft: { capability: 'mutable', commitment: postCommitment } },
};
// encode a 1-output tx and slice the token prefix
const probe = { version: 2, inputs: [], outputs: [stateOutputWithToken], locktime: 0 };
const probeRaw = binToHex(encodeTransactionOutputs(probe.outputs));
// output format: value(8) + [token prefix] + locklen(1) + lock
const valueHex = probeRaw.slice(0, 16);
const lockLen = parseInt(probeRaw.slice(16 + 2 * (probeRaw.length / 2 - stateLock.length - 1 - 8), 16 + 2), 16);
// simpler: tokenPrefix = raw between value(8) and the lock's PUSHDATA length byte
const lockHex = binToHex(stateLock);
const tokenPrefixHex = probeRaw.slice(16, probeRaw.length - lockHex.length - 2);
console.log('state output token prefix:', tokenPrefixHex.slice(0, 24) + '...', '(' + tokenPrefixHex.length / 2 + ' B)');
writeFileSync('/tmp/pf6-state-tokenprefix.bin', Buffer.from(tokenPrefixHex, 'hex'));

// deposit outputs (9): state + 6 verifier + carrier + change
const depositOutputs = [
  stateOutputWithToken,
  ...verifierLocks.map(l => ({ lockingBytecode: l, valueSatoshis: carrierValue })),
  { lockingBytecode: bindingLock, valueSatoshis: carrierValue },
];

// context value
const role = (kind, ordinal) => ({ kind, ordinal: String(ordinal) });
const hash32 = (bytes) => createHash('sha256').update(bytes).digest();
const inRole = (kind, ordinal, outpoint, value, lock, tokenPrefix = new Uint8Array()) => ({
  role: role(kind, ordinal), outpointTransactionHash: outpoint.txid, outpointIndex: String(outpoint.vout),
  sequence: '4294967294', valueSats: String(value), lockingBytecode: lock, tokenPrefix,
});
const context = {
  networkId: 2, kind: 'deposit', profileId, instanceId,
  transactionVersion: '2', locktime: '0',
  preActionSequence: '0', postActionSequence: '1',
  inputs: [
    ...depositMat.verifierRoles.map((r, i) => inRole('verifier', i, { txid: gen.txid, vout: i }, 1000n, Uint8Array.from(Buffer.from(r.lock, 'hex')))),
    inRole('binding', 0, { txid: gen.txid, vout: 6 }, 1000n, bindingLock),
    inRole('state', 0, { txid: gen.txid, vout: 7 }, 2500n, stateLock, Uint8Array.from(Buffer.from(tokenPrefixHex, 'hex'))),
    inRole('funding', 0, { txid: feeUtxo.txid, vout: feeUtxo.vout }, BigInt(feeUtxo.sats), hexToBin(hotLock)),
  ],
  // The context hash is a Fiat-Shamir commitment (not tx-introspected): use the
  // PRODUCT's output layout (state@0, verifier@1-6, binding@7, change@8) so the
  // validator accepts; the actual tx outputs use the pf6 layout.
  outputs: [
    { role: role('state', 0), valueSats: String(stateBase + 10_000_000n), lockingBytecode: stateLock, tokenPrefix: Uint8Array.from(Buffer.from(tokenPrefixHex, 'hex')) },
    ...depositMat.verifierRoles.map((r, i) => ({ role: role('verifier', i), valueSats: '1000', lockingBytecode: Uint8Array.from(Buffer.from(r.lock, 'hex')), tokenPrefix: new Uint8Array() })),
    { role: role('binding', 0), valueSats: '1000', lockingBytecode: bindingLock, tokenPrefix: new Uint8Array() },
    { role: role('change', 0), valueSats: '0', lockingBytecode: hexToBin(hotLock), tokenPrefix: new Uint8Array() },
  ],
};
const contextHash = contextMod.hashDirectV2TransactionContext(context, { carrierCount: 6 }).toString('hex');
console.log('context hash:', contextHash.slice(0, 16));

// ---- 4) final transition with the real context hash ----
const transition = transitionMod.applyDirectV2Transition({
  kind: 'deposit', networkId: 2, profileId, instanceId, denominationSats: DENOMINATION,
  preState: model.state, noteTree: model.noteTree, nullifierTree: model.nullifierTree,
  transactionContextHash: contextHash,
  output: { outputNoteLeaf: output.public.outputNoteLeaf, encryptedRecord: output.public.encryptedRecord },
});
const packet = Buffer.from(transition.packet);
console.log('packet:', packet.length, 'B | magic:', packet.toString('utf8', 0, 4));
writeFileSync('/tmp/pf6-deposit-packet.bin', packet);
// packet's context hash == our hash?
console.log('packet contextHash match:', packet.subarray(520, 552).toString('hex') === contextHash);

// ---- 5) circuit input ----
const circuitInput = circuitWitness.buildDirectV2CircuitInput({
  transition, output, denominationSats: DENOMINATION,
});
writeFileSync('/tmp/pf6-deposit-input.json', JSON.stringify(circuitInput, null, 1));
console.log('circuit input written');
