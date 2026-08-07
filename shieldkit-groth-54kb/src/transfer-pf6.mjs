// ShieldKit-54KB — pf6 TRANSFER (live chipnet). Spend = the live deposit's note (recovered from its packet).
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import path from 'node:path';

const FOLDER = '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/shieldkit-groth-54kb';
const G = '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/shieldkit-groth';
const CUSTODY = '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4';
const libauthUrl = 'file://' + FOLDER + '/vendor/verifier-workspace/build/node_modules/@bitauth/libauth/build/index.js';
const la = await import(libauthUrl);
const { hexToBin, binToHex, decodeTransaction } = la;

const notes = await import('file://' + G + '/packages/action/v2/notes.mjs');
const transitionMod = await import('file://' + G + '/packages/action/v2/transition.mjs');
const circuitWitness = await import('file://' + G + '/packages/action/v2/circuit-witness.mjs');
const contextMod = await import('file://' + G + '/packages/action/v2/context.mjs');
const st = await import('file://' + G + '/packages/action/v2/state.mjs');
const noteTreeMod = await import('file://' + G + '/packages/action/v2/note-tree.mjs');
const inkt = await import('file://' + G + '/packages/action/v2/indexed-nullifier-tree.mjs');
const pz = await import('file://' + G + '/packages/action/v2/poseidon.mjs');

const gen = JSON.parse(readFileSync('/tmp/pf6-genesis.json', 'utf8'));
const dep = JSON.parse(readFileSync('/tmp/pf6-deposit-tx.json', 'utf8'));
const feeUtxo = JSON.parse(readFileSync('/tmp/pf6-fee-utxo.json', 'utf8'));
const account = JSON.parse(readFileSync(path.join(CUSTODY, 'pf6-pool-account.json'), 'utf8'));
const hotLockHex = JSON.parse(readFileSync(path.join(CUSTODY, 'wallet-public.json'), 'utf8')).lockingBytecodeHex;
const _addr = notes.deriveDirectV2Address({ networkId: 2, profileId: JSON.parse(readFileSync('/tmp/pf6-genesis.json', 'utf8')).profileId, instanceId: JSON.parse(readFileSync('/tmp/pf6-genesis.json', 'utf8')).instanceId, ...account });
account.address = _addr;
const profileId = gen.profileId;
const instanceId = gen.instanceId;
const DENOMINATION = '10000000';
const stateBase = 2500n;
const carrierValue = 1000n;

// the live deposit's packet (from the deposit tx's input 6)
const depTx = decodeTransaction(hexToBin(dep.hex));
const packet = depTx.inputs[6].unlockingBytecode.subarray(3, 3 + 552);
writeFileSync('/tmp/pf6-deposit-packet.bin', packet);
const outputNoteLeaf = Buffer.from(packet.subarray(328, 360)).toString('hex');
const encryptedRecord = packet.subarray(360, 488);

// recover the deposited note -> nullifier
const address = notes.deriveDirectV2Address({ networkId: 2, profileId, instanceId, ...account });
const recovered = notes.recoverDirectV2Output({ account, outputNoteLeaf, encryptedRecord });
console.log('recovered note nullifier:', recovered.nullifier.slice(0, 16));
console.log('note commitment:', recovered.noteCommitment.slice(0, 16), '| rho:', recovered.rho.slice(0, 16));

// the deposit's post-state (from the deposit tx's state output commitment)
const depositPostState = st.decodeStateNftCommitment(depTx.outputs[7].token.nft.commitment, { denominationSats: DENOMINATION });
console.log('post-deposit state: notes', depositPostState.noteCount, 'reserve', depositPostState.reserveSats, 'seq', depositPostState.actionSequence);

// the post-deposit trees: note tree with the note appended at 0; nullifier tree unchanged (empty)
const noteTree = noteTreeMod.append(
  noteTreeMod.create({ depth: 32, emptyLeafHash: pz.hashEmptyNoteLeaf(), hashNode: pz.hashNoteTreeNode }),
  BigInt('0x' + outputNoteLeaf),
).tree;
const nullifierTree = inkt.create({ depth: 32, hashLeaf: pz.hashIndexedNullifierLeaf, hashNode: pz.hashIndexedNullifierNode });

// the transfer's output note
const rng = { bytes(length) { if (length !== 32) throw new Error('rng'); return Uint8Array.from(randomBytes(32)); } };
const transferOutput = notes.constructDirectV2Output({ address, postActionSequence: '2', rng });

// the transfer's spend witness
const spend = {
  inputNoteLeaf: outputNoteLeaf,
  noteIndex: '0',
  publicNullifier: recovered.nullifier,
};

// context (inputs = the deposit tx's outputs 0-7 + a fee UTXO; outputs = state + verifier + carrier + change)
const depositOutputs = depTx.outputs;
const verifierLocks = [0,1,2,3,4,5].map(i => depositOutputs[i + 1].lockingBytecode);
const stateLock = depositOutputs[7].lockingBytecode;
const bindingLock = depositOutputs[6].lockingBytecode;
const stateToken = depositOutputs[0].token;
const stateInValue = depositOutputs[7].valueSatoshis; // 10,002,500 (post-deposit state at output 7)

// the transfer's post-state: noteCount 2, seq 2, reserve unchanged
const transferPostState = {
  profileId, noteRoot: null, nullifierRoot: null, // computed by the transition
  noteCount: (BigInt(depositPostState.noteCount) + 1n).toString(),
  nullifierCount: (BigInt(depositPostState.nullifierCount) + 1n).toString(),
  maximumLiveNotes: depositPostState.maximumLiveNotes,
  reserveSats: depositPostState.reserveSats,
  actionSequence: (BigInt(depositPostState.actionSequence) + 1n).toString(),
};

// provisional transition (placeholder hash) to get the post-state + trees
const t0 = transitionMod.applyDirectV2Transition({
  kind: 'transfer', networkId: 2, profileId, instanceId, denominationSats: DENOMINATION,
  preState: depositPostState, noteTree, nullifierTree,
  transactionContextHash: '0'.repeat(64),
  output: { outputNoteLeaf: transferOutput.public.outputNoteLeaf, encryptedRecord: transferOutput.public.encryptedRecord },
  spend,
});
const postState = t0.state;
console.log('transfer post-state: notes', postState.noteCount, 'seq', postState.actionSequence);
const postCommitment = st.encodeStateNftCommitment(postState, { denominationSats: DENOMINATION });

// the state output token prefix (via libauth)
const category = Uint8Array.from(Buffer.from(instanceId, 'hex')).reverse();
const stateOutToken = { amount: 0n, category, nft: { capability: 'mutable', commitment: postCommitment } };
const stateOutValue = stateInValue; // transfer: reserve unchanged

// context
const role = (kind, ordinal) => ({ kind, ordinal: String(ordinal) });
const hash32 = (b) => createHash('sha256').update(b).digest();
const tokenPrefixHex = (() => {
  // encode the state output with libauth and extract the prefix
  const probe = { version: 2, inputs: [], outputs: [{ lockingBytecode: stateLock, valueSatoshis: stateOutValue, token: stateOutToken }], locktime: 0 };
  const raw = binToHex(la.encodeTransaction(probe));
  const dec = decodeTransaction(hexToBin(raw));
  return dec.outputs[0].token ? null : null;
})();
// simpler: the prefix = the raw token bytes — derive from the deposit's state output raw prefix (same category, different commitment)
// use libauth encode + parse: the output raw = value(8) + prefix + locklen + lock
const probeTx = { version: 2, inputs: [], outputs: [{ lockingBytecode: stateLock, valueSatoshis: stateOutValue, token: stateOutToken }], locktime: 0 };
const probeRaw = binToHex(la.encodeTransaction(probeTx));
const probeDec = decodeTransaction(hexToBin(probeRaw));
// extract the prefix bytes between the value and the lock length: re-encode the output and slice
const outRaw = probeRaw.slice(probeRaw.length - (probeDec.outputs[0].lockingBytecode.length + 1 + 8 + 164 + 4) - 4);
const lockHex = binToHex(stateLock);
const idx = probeRaw.lastIndexOf(lockHex);
const prefixHex = probeRaw.slice(idx - 2 - 164, idx - 2); // 164 B prefix (category 32 + cap 1 + push 130 + amount 0 + locklen 1?)
const tokenPrefix = Uint8Array.from(Buffer.from(prefixHex, 'hex'));
console.log('state token prefix:', prefixHex.length / 2, 'B');

// context value
const inRole = (kind, ordinal, outpoint, value, lock, tokenPrefixBytes = new Uint8Array()) => ({
  role: role(kind, ordinal), outpointTransactionHash: outpoint.txid, outpointIndex: String(outpoint.vout),
  sequence: '4294967294', valueSats: String(value), lockingBytecode: lock, tokenPrefix: tokenPrefixBytes,
});
const context = {
  networkId: 2, kind: 'transfer', profileId, instanceId,
  transactionVersion: '2', locktime: '0',
  preActionSequence: String(depositPostState.actionSequence), postActionSequence: String(postState.actionSequence),
  inputs: [
    ...[0,1,2,3,4,5].map(i => inRole('verifier', i, { txid: dep.txid, vout: i + 1 }, 1000n, verifierLocks[i])),
    inRole('binding', 0, { txid: dep.txid, vout: 7 }, 1000n, bindingLock),
    inRole('state', 0, { txid: dep.txid, vout: 0 }, stateInValue, stateLock, tokenPrefix),
  ],
  outputs: [
    { role: role('state', 0), valueSats: String(stateOutValue), lockingBytecode: stateLock, tokenPrefix },
    ...[0,1,2,3,4,5].map(i => ({ role: role('verifier', i), valueSats: '1000', lockingBytecode: verifierLocks[i], tokenPrefix: new Uint8Array() })),
    { role: role('binding', 0), valueSats: '1000', lockingBytecode: bindingLock, tokenPrefix: new Uint8Array() },
    { role: role('change', 0), valueSats: '0', lockingBytecode: hexToBin(hotLockHex), tokenPrefix: new Uint8Array() },
  ],
};
// the funding input's lock: the hot P2PKH
context.inputs[8] = inRole('funding', 0, { txid: feeUtxo.txid, vout: feeUtxo.vout }, BigInt(feeUtxo.sats), hexToBin(hotLockHex));
const contextHash = contextMod.hashDirectV2TransactionContext(context, { carrierCount: 6 }).toString('hex');
console.log('context hash:', contextHash.slice(0, 16));

// final transition with the real hash
const transition = transitionMod.applyDirectV2Transition({
  kind: 'transfer', networkId: 2, profileId, instanceId, denominationSats: DENOMINATION,
  preState: depositPostState, noteTree, nullifierTree,
  transactionContextHash: contextHash,
  output: { outputNoteLeaf: transferOutput.public.outputNoteLeaf, encryptedRecord: transferOutput.public.encryptedRecord },
  spend,
});
const packetOut = Buffer.from(transition.packet);
writeFileSync('/tmp/pf6-transfer-packet.bin', packetOut);
console.log('transfer packet:', packetOut.length, 'B | ctx match:', packetOut.subarray(520, 552).toString('hex') === contextHash);

// circuit input: the spend = the recovered note's fields (the circuit witness shape)
const circuitSpend = {
  encryptedRecord: recovered.encryptedRecord,
  incomingViewPublicKey: address.incomingViewPublicKey,
  r: recovered.r,
  rho: recovered.rho,
  spendSecret: account.spendSecret,
};
const circuitInput = circuitWitness.buildDirectV2CircuitInput({
  transition, spend: circuitSpend, output: transferOutput, denominationSats: DENOMINATION,
});
writeFileSync('/tmp/pf6-transfer-input.json', JSON.stringify(circuitInput, null, 1));
writeFileSync('/tmp/pf6-transfer-meta.json', JSON.stringify({ contextHash, postState, transferOutput: { public: transferOutput.public }, spend, stateOutValue: String(stateOutValue), tokenPrefixHex: prefixHex }, null, 1));
console.log('transfer input written');
