// Continuation deposit on the exhausted VPS pool (post-withdrawal): preState = the withdrawal's post-state.
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
const FOLDER = '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/shieldkit-groth-54kb';
const G = '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/shieldkit-groth-94kb';
const notes = await import('file://' + G + '/packages/action/v2/notes.mjs');
const transitionMod = await import('file://' + G + '/packages/action/v2/transition.mjs');
const st = await import('file://' + G + '/packages/action/v2/state.mjs');
const noteTreeMod = await import('file://' + G + '/packages/action/v2/note-tree.mjs');
const inkt = await import('file://' + G + '/packages/action/v2/indexed-nullifier-tree.mjs');
const pz = await import('file://' + G + '/packages/action/v2/poseidon.mjs');
const la = await import('file://' + FOLDER + '/vendor/verifier-workspace/build/node_modules/@bitauth/libauth/build/index.js');
const { hexToBin, binToHex, decodeTransaction } = la;
const core = JSON.parse(readFileSync(path.join(FOLDER, 'src/pf6-profile-core.json'), 'utf8'));
const account = JSON.parse(readFileSync('/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4/pf6-pool-account.json', 'utf8'));
const pc = await import('file://' + G + '/packages/profile/v2/profile-core.mjs');
const profileId = pc.deriveProfileId(core);
const DENOMINATION = '10000000';
const networkId = 2;
const wd = JSON.parse(readFileSync('/tmp/pf6-vps-withdrawal.json', 'utf8'));
const wTx = decodeTransaction(hexToBin(wd.hex));
const instanceId = JSON.parse(readFileSync('/tmp/pf6-instance-vps.json', 'utf8')).instanceId;
account.address = notes.deriveDirectV2Address({ networkId, profileId, instanceId, ...account });
// the withdrawal's post-state (state output at 7)
const postState = st.decodeStateNftCommitment(wTx.outputs[7].token.nft.commitment, { denominationSats: DENOMINATION });
console.log('post-withdrawal state: notes', postState.noteCount, 'reserve', String(postState.reserveSats), 'seq', postState.actionSequence);
// the trees: 2 notes (deposit + transfer leaves from the packets), 2 nullifiers (recovered from the packets)
const depPkt = readFileSync('/tmp/pf6-vps-deposit-packet.bin');
const trPkt = readFileSync('/tmp/pf6-vps-transfer-packet.bin');
const depLeaf = Buffer.from(depPkt.subarray(328, 360)).toString('hex');
const trLeaf = Buffer.from(trPkt.subarray(328, 360)).toString('hex');
const n0 = noteTreeMod.create({ depth: 32, emptyLeafHash: pz.hashEmptyNoteLeaf(), hashNode: pz.hashNoteTreeNode });
const n1 = noteTreeMod.append(n0, BigInt('0x' + depLeaf)).tree;
const noteTree = noteTreeMod.append(n1, BigInt('0x' + trLeaf)).tree;
const recDep = notes.recoverDirectV2Output({ account, outputNoteLeaf: depLeaf, encryptedRecord: depPkt.subarray(360, 488) });
const recTr = notes.recoverDirectV2Output({ account, outputNoteLeaf: trLeaf, encryptedRecord: trPkt.subarray(360, 488) });
const k0 = inkt.create({ depth: 32, hashLeaf: pz.hashIndexedNullifierLeaf, hashNode: pz.hashIndexedNullifierNode });
const k1 = inkt.insert(k0, Uint8Array.from(Buffer.from(recDep.nullifier, 'hex'))).tree;
const nullifierTree = inkt.insert(k1, Uint8Array.from(Buffer.from(recTr.nullifier, 'hex'))).tree;
// the continuation deposit's output note
const rng = { bytes(len) { if (len !== 32) throw new Error('len'); return Uint8Array.from(randomBytes(32)); } };
const out = notes.constructDirectV2Output({ address: account.address, postActionSequence: String(Number(postState.actionSequence) + 1), rng });
console.log('cont deposit leaf:', out.public.outputNoteLeaf.slice(0, 16));
// provisional transition (placeholder context) to get the post-state commitment
const t0 = transitionMod.applyDirectV2Transition({
  kind: 'deposit', networkId, profileId, instanceId, denominationSats: DENOMINATION,
  preState: postState, noteTree, nullifierTree, transactionContextHash: '0'.repeat(64),
  output: { outputNoteLeaf: out.public.outputNoteLeaf, encryptedRecord: out.public.encryptedRecord },
});
const postState2 = t0.state;
console.log('cont post-state: notes', postState2.noteCount, 'reserve', String(postState2.reserveSats), 'seq', postState2.actionSequence);
const postCommitment = st.encodeStateNftCommitment(postState2, { denominationSats: DENOMINATION });
const category = Uint8Array.from(Buffer.from(instanceId, 'hex')).reverse();
// the state output token + prefix (probe)
const probeTx = { version: 2, inputs: [], outputs: [{ lockingBytecode: wTx.outputs[7].lockingBytecode, valueSatoshis: 10002500n, token: { amount: 0n, category, nft: { capability: 'mutable', commitment: postCommitment } } }], locktime: 0 };
const probeRaw = binToHex(la.encodeTransaction(probeTx));
const lockHex = binToHex(wTx.outputs[7].lockingBytecode);
const idx = probeRaw.lastIndexOf(lockHex);
const prefixHex = probeRaw.slice(idx - 2 - 164, idx - 2);
// the context (9 inputs: the withdrawal's outputs 0-7 + fee; 9 outputs: verifier@0-5 + carrier@6 + state@7 + note@8)
const role = (kind, ordinal) => ({ kind, ordinal: String(ordinal) });
const inRole = (kind, ordinal, outpoint, value, lock, tokenPrefixBytes = new Uint8Array()) => ({
  role: role(kind, ordinal), outpointTransactionHash: outpoint.txid, outpointIndex: String(outpoint.vout),
  sequence: '4294967294', valueSats: String(value), lockingBytecode: lock, tokenPrefix: tokenPrefixBytes,
});
const feeUtxo = JSON.parse(readFileSync('/tmp/pf6-fee-utxo.json', 'utf8'));
const context = {
  networkId: 2, kind: 'deposit', profileId, instanceId, transactionVersion: '2', locktime: '0',
  preActionSequence: String(postState.actionSequence), postActionSequence: String(postState2.actionSequence),
  inputs: [
    ...[0, 1, 2, 3, 4, 5].map(i => inRole('verifier', i, { txid: wd.txid, vout: i }, 1000n, wTx.outputs[i].lockingBytecode)),
    inRole('binding', 0, { txid: wd.txid, vout: 6 }, 1000n, wTx.outputs[6].lockingBytecode),
    inRole('state', 0, { txid: wd.txid, vout: 7 }, wTx.outputs[7].valueSatoshis, wTx.outputs[7].lockingBytecode, Uint8Array.from(Buffer.from(prefixHex, 'hex'))),
    inRole('funding', 0, { txid: feeUtxo.txid, vout: feeUtxo.vout }, BigInt(feeUtxo.sats), hexToBin(JSON.parse(readFileSync('/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4/wallet-public.json', 'utf8')).lockingBytecodeHex), new Uint8Array()),
  ],
  outputs: [
    { role: role('state', 0), valueSats: '10002500', lockingBytecode: wTx.outputs[7].lockingBytecode, tokenPrefix: Uint8Array.from(Buffer.from(prefixHex, 'hex')) },
    ...[0, 1, 2, 3, 4, 5].map(i => ({ role: role('verifier', i), valueSats: '1000', lockingBytecode: wTx.outputs[i].lockingBytecode, tokenPrefix: new Uint8Array() })),
    { role: role('binding', 0), valueSats: '1000', lockingBytecode: wTx.outputs[6].lockingBytecode, tokenPrefix: new Uint8Array() },
    { role: role('change', 0), valueSats: '10000000', lockingBytecode: hexToBin(JSON.parse(readFileSync('/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4/wallet-public.json', 'utf8')).lockingBytecodeHex), tokenPrefix: new Uint8Array() },
  ],
};
// NOTE: the funding input lock must be the hot wallet lock; the context needs it — patch below.
const contextMod = await import('file://' + G + '/packages/action/v2/context.mjs');
const circuitWitness = await import('file://' + G + '/packages/action/v2/circuit-witness.mjs');
const contextHash = contextMod.hashDirectV2TransactionContext(context, { carrierCount: 6 }).toString('hex');
console.log('cont context hash:', contextHash.slice(0, 16));
const t1 = transitionMod.applyDirectV2Transition({
  kind: 'deposit', networkId, profileId, instanceId, denominationSats: DENOMINATION,
  preState: postState, noteTree, nullifierTree, transactionContextHash: contextHash,
  output: { outputNoteLeaf: out.public.outputNoteLeaf, encryptedRecord: out.public.encryptedRecord },
});
const packetOut = Buffer.from(t1.packet);
writeFileSync('/tmp/pf6-cont-packet.bin', packetOut);
console.log('cont packet:', packetOut.length, 'B | ctx match:', packetOut.subarray(520, 552).toString('hex') === contextHash);
const circuitInput = circuitWitness.buildDirectV2CircuitInput({
  transition: t1, output: out, denominationSats: DENOMINATION,
});
writeFileSync('/tmp/pf6-cont-input.json', JSON.stringify(circuitInput, null, 1));
writeFileSync('/tmp/pf6-cont-meta.json', JSON.stringify({ contextHash, postState, postState2, stateInValue: String(wTx.outputs[7].valueSatoshis), stateOutValue: '10002500', tokenPrefixHex: prefixHex, withdrawalTxid: wd.txid, instanceId, postCommitment }, null, 1));
writeFileSync('/tmp/pf6-cont-prefix.json', JSON.stringify({ prefixHex, instanceId, postState, postState2, postCommitment, depLeaf, trLeaf }));
console.log('cont deposit input written');
