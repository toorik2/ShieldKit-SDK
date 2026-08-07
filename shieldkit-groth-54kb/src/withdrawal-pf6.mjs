// ShieldKit-54KB — pf6 WITHDRAWAL (live chipnet). Spend = the transfer's output note.
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
const tr = JSON.parse(readFileSync('/tmp/pf6-transfer-tx.json', 'utf8'));
const feeUtxo = JSON.parse(readFileSync('/tmp/pf6-fee-utxo.json', 'utf8'));
const account = JSON.parse(readFileSync(path.join(CUSTODY, 'pf6-pool-account.json'), 'utf8'));
const hotLockHex = JSON.parse(readFileSync(path.join(CUSTODY, 'wallet-public.json'), 'utf8')).lockingBytecodeHex;
const profileId = gen.profileId;
const instanceId = gen.instanceId;
const DENOMINATION = '10000000';
const stateBase = 2500n;
const carrierValue = 1000n;

// the transfer's packet + note
const trTx = decodeTransaction(hexToBin(tr.hex));
const transferPacket = trTx.inputs[6].unlockingBytecode.subarray(3, 3 + 552);
const outputNoteLeaf = Buffer.from(transferPacket.subarray(328, 360)).toString('hex');
const encryptedRecord = transferPacket.subarray(360, 488);
const address = notes.deriveDirectV2Address({ networkId: 2, profileId, instanceId, ...account });
account.address = address;
const recovered = notes.recoverDirectV2Output({ account, outputNoteLeaf, encryptedRecord });
console.log('withdrawal note nullifier:', recovered.nullifier.slice(0, 16));

// the post-transfer state (the transfer tx's state output at 7)
const transferPostState = st.decodeStateNftCommitment(trTx.outputs[7].token.nft.commitment, { denominationSats: DENOMINATION });
console.log('post-transfer state: notes', transferPostState.noteCount, 'seq', transferPostState.actionSequence);

// trees: 2 notes (append the transfer's note to the post-deposit tree)
const depPacket = readFileSync('/tmp/pf6-deposit-packet.bin');
const depLeaf = Buffer.from(depPacket.subarray(328, 360)).toString('hex');
const noteTree0 = noteTreeMod.append(
  noteTreeMod.create({ depth: 32, emptyLeafHash: pz.hashEmptyNoteLeaf(), hashNode: pz.hashNoteTreeNode }),
  BigInt('0x' + depLeaf),
);
const noteTree = noteTreeMod.append(noteTree0.tree, BigInt('0x' + outputNoteLeaf)).tree;
// the preState's nullifier tree: the deposit's nullifier was inserted by the transfer
const depRecovered = notes.recoverDirectV2Output({ account, outputNoteLeaf: depLeaf, encryptedRecord: readFileSync('/tmp/pf6-deposit-packet.bin').subarray(360, 488) });
const nullifierTree0 = inkt.create({ depth: 32, hashLeaf: pz.hashIndexedNullifierLeaf, hashNode: pz.hashIndexedNullifierNode });
const nullifierTree = inkt.insert(nullifierTree0, Uint8Array.from(Buffer.from(depRecovered.nullifier, 'hex'))).tree;

// the withdrawal: no output note; the withdrawal locking bytecode hash = the hot P2PKH hash
const withdrawalLockingBytecodeHash = createHash('sha256').update(Buffer.from(hotLockHex, 'hex')).digest('hex');
const spend = { inputNoteLeaf: outputNoteLeaf, noteIndex: '1', publicNullifier: recovered.nullifier };

// provisional transition
const t0 = transitionMod.applyDirectV2Transition({
  kind: 'withdrawal', networkId: 2, profileId, instanceId, denominationSats: DENOMINATION,
  preState: transferPostState, noteTree, nullifierTree,
  transactionContextHash: '0'.repeat(64), spend, withdrawalLockingBytecodeHash,
});
const postState = t0.state;
console.log('withdrawal post-state: notes', postState.noteCount, 'reserve', postState.reserveSats, 'seq', postState.actionSequence);
const postCommitment = st.encodeStateNftCommitment(postState, { denominationSats: DENOMINATION });
const stateInValue = trTx.outputs[7].valueSatoshis; // 10,002,500
const stateOutValue = stateInValue - 10000000n; // 2,500 (reserve removed)

// state output token + prefix
const category = Uint8Array.from(Buffer.from(instanceId, 'hex')).reverse();
const stateOutToken = { amount: 0n, category, nft: { capability: 'mutable', commitment: postCommitment } };
const stateLock = trTx.outputs[7].lockingBytecode;
const verifierLocks = [0,1,2,3,4,5].map(i => trTx.outputs[i].lockingBytecode);
const bindingLock = trTx.outputs[6].lockingBytecode;
const probeTx = { version: 2, inputs: [], outputs: [{ lockingBytecode: stateLock, valueSatoshis: stateOutValue, token: stateOutToken }], locktime: 0 };
const probeRaw = binToHex(la.encodeTransaction(probeTx));
const lockHex = binToHex(stateLock);
const idx = probeRaw.lastIndexOf(lockHex);
const prefixHex = probeRaw.slice(idx - 2 - 164, idx - 2);
const tokenPrefix = Uint8Array.from(Buffer.from(prefixHex, 'hex'));

// context (10 outputs: verifier@0-5 + carrier@6 + state@7 + withdrawal@8 + change@9)
const role = (kind, ordinal) => ({ kind, ordinal: String(ordinal) });
const inRole = (kind, ordinal, outpoint, value, lock, tokenPrefixBytes = new Uint8Array()) => ({
  role: role(kind, ordinal), outpointTransactionHash: outpoint.txid, outpointIndex: String(outpoint.vout),
  sequence: '4294967294', valueSats: String(value), lockingBytecode: lock, tokenPrefix: tokenPrefixBytes,
});
const context = {
  networkId: 2, kind: 'withdrawal', profileId, instanceId,
  transactionVersion: '2', locktime: '0',
  preActionSequence: String(transferPostState.actionSequence), postActionSequence: String(postState.actionSequence),
  inputs: [
    ...[0,1,2,3,4,5].map(i => inRole('verifier', i, { txid: tr.txid, vout: i }, 1000n, verifierLocks[i])),
    inRole('binding', 0, { txid: tr.txid, vout: 6 }, 1000n, bindingLock),
    inRole('state', 0, { txid: tr.txid, vout: 7 }, stateInValue, stateLock, tokenPrefix),
    inRole('funding', 0, { txid: feeUtxo.txid, vout: feeUtxo.vout }, BigInt(feeUtxo.sats), hexToBin(hotLockHex)),
  ],
  outputs: [
    { role: role('state', 0), valueSats: String(stateOutValue), lockingBytecode: stateLock, tokenPrefix },
    ...[0,1,2,3,4,5].map(i => ({ role: role('verifier', i), valueSats: '1000', lockingBytecode: verifierLocks[i], tokenPrefix: new Uint8Array() })),
    { role: role('binding', 0), valueSats: '1000', lockingBytecode: bindingLock, tokenPrefix: new Uint8Array() },
    { role: role('withdrawal', 0), valueSats: '10000000', lockingBytecode: hexToBin(hotLockHex), tokenPrefix: new Uint8Array() },
    { role: role('change', 0), valueSats: '0', lockingBytecode: hexToBin(hotLockHex), tokenPrefix: new Uint8Array() },
  ],
};
const contextHash = contextMod.hashDirectV2TransactionContext(context, { carrierCount: 6 }).toString('hex');
console.log('withdrawal context hash:', contextHash.slice(0, 16));

const transition = transitionMod.applyDirectV2Transition({
  kind: 'withdrawal', networkId: 2, profileId, instanceId, denominationSats: DENOMINATION,
  preState: transferPostState, noteTree, nullifierTree,
  transactionContextHash: contextHash, spend, withdrawalLockingBytecodeHash,
});
const packetOut = Buffer.from(transition.packet);
writeFileSync('/tmp/pf6-withdrawal-packet.bin', packetOut);
console.log('withdrawal packet:', packetOut.length, 'B | ctx match:', packetOut.subarray(520, 552).toString('hex') === contextHash);

const circuitInput = circuitWitness.buildDirectV2CircuitInput({
  transition, spend: {
    encryptedRecord: recovered.encryptedRecord,
    incomingViewPublicKey: address.incomingViewPublicKey,
    r: recovered.r,
    rho: recovered.rho,
    spendSecret: account.spendSecret,
  }, denominationSats: DENOMINATION,
});
writeFileSync('/tmp/pf6-withdrawal-input.json', JSON.stringify(circuitInput, null, 1));
writeFileSync('/tmp/pf6-withdrawal-meta.json', JSON.stringify({ contextHash, postState, spend, stateOutValue: String(stateOutValue), tokenPrefixHex: prefixHex, withdrawalLockingBytecodeHash }, null, 1));
console.log('withdrawal input written');
