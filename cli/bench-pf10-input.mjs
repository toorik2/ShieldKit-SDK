// cli/bench-pf10-input.mjs — builds the pf10 deposit circuit input via the product's own v2-direct modules.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import path from 'node:path';

export async function buildPf10DepositInput({ G, tpl, root }) {
  const la = await import('file://' + path.resolve(root, '../shieldkit-groth-54kb') + '/vendor/verifier-workspace/build/node_modules/@bitauth/libauth/build/index.js');
  const notes = await import('file://' + G + '/packages/action/v2/notes.mjs');
  const tm = await import('file://' + G + '/packages/action/v2/transition.mjs');
  const st = await import('file://' + G + '/packages/action/v2/state.mjs');
  const cx = await import('file://' + G + '/packages/action/v2/context.mjs');
  const cw = await import('file://' + G + '/packages/action/v2/circuit-witness.mjs');
  const pc = await import('file://' + G + '/packages/profile/v2/profile-core.mjs');
  const portable = await import('file://' + G + '/packages/recover/portable-core.mjs');
  const core = JSON.parse(readFileSync(path.join(tpl, 'profile/profile-core.json'), 'utf8'));
  const profileId = pc.deriveProfileId(core);
  const instanceId = 'aa'.repeat(32);
  const verifierLocks = [0,1,2,3,4,5,6,7,8,9].map(i => Uint8Array.from(readFileSync(path.join(tpl, `structural/verifier-lock-${i}.bin`))));
  const bindingLock = Uint8Array.from(readFileSync(path.join(tpl, 'structural/binding-lock.bin')));
  const stateLock = Uint8Array.from(readFileSync(path.join(tpl, 'structural/state-lock.bin')));
  const sampleScalar = () => { for (let i = 0; i < 1024; i++) { const h = randomBytes(32).toString('hex'); if (BigInt('0x' + h) > 0n && BigInt('0x' + h) < portable.BABYJUB_SUBGROUP_ORDER) return h; } throw new Error('sample'); };
  const account = { spendSecret: sampleScalar(), incomingViewSecret: sampleScalar() };
  const address = notes.deriveDirectV2Address({ networkId: 2, profileId, instanceId, ...account });
  const model = tm.createDirectV2PoolModel({ profileId, maximumLiveNotes: '32', denominationSats: '10000000' });
  const rng = { bytes(len) { if (len !== 32) throw new Error('len'); return Uint8Array.from(randomBytes(32)); } };
  const output = notes.constructDirectV2Output({ address, postActionSequence: '1', rng });
  const t0 = tm.applyDirectV2Transition({
    kind: 'deposit', networkId: 2, profileId, instanceId, denominationSats: '10000000',
    preState: model.state, noteTree: model.noteTree, nullifierTree: model.nullifierTree,
    transactionContextHash: '0'.repeat(64),
    output: { outputNoteLeaf: output.public.outputNoteLeaf, encryptedRecord: output.public.encryptedRecord },
  });
  const postState = t0.state;
  const postCommitment = st.encodeStateNftCommitment(postState, { denominationSats: '10000000' });
  const category = Uint8Array.from(Buffer.from(instanceId, 'hex')).reverse();
  const probe = { version: 2, inputs: [], outputs: [{ lockingBytecode: stateLock, valueSatoshis: 10002500n, token: { amount: 0n, category, nft: { capability: 'mutable', commitment: postCommitment } } }], locktime: 0 };
  const probeRaw = la.binToHex(la.encodeTransaction(probe));
  const lockHex = la.binToHex(stateLock);
  const idx = probeRaw.lastIndexOf(lockHex);
  const tokenPrefix = Uint8Array.from(Buffer.from(probeRaw.slice(idx - 2 - 164, idx - 2), 'hex'));
  const role = (k, o) => ({ kind: k, ordinal: String(o) });
  const inRole = (k, o, txid, vout, value, lock, tp = new Uint8Array()) => ({ role: role(k, o), outpointTransactionHash: txid, outpointIndex: String(vout), sequence: '4294967294', valueSats: String(value), lockingBytecode: lock, tokenPrefix: tp });
  const context = {
    networkId: 2, kind: 'deposit', profileId, instanceId, transactionVersion: '2', locktime: '0',
    preActionSequence: '0', postActionSequence: '1',
    inputs: [
      ...[0,1,2,3,4,5,6,7,8,9].map(i => inRole('verifier', i, 'bb'.repeat(32), i, 1000n, verifierLocks[i])),
      inRole('binding', 0, 'bb'.repeat(32), 10, 1000n, bindingLock),
      inRole('state', 0, 'bb'.repeat(32), 11, 2500n, stateLock, tokenPrefix),
      inRole('funding', 0, 'cc'.repeat(32), 0, 21000000n, new Uint8Array(25)),
    ],
    outputs: [
      { role: role('state', 0), valueSats: '10002500', lockingBytecode: stateLock, tokenPrefix },
      ...[0,1,2,3,4,5,6,7,8,9].map(i => ({ role: role('verifier', i), valueSats: '1000', lockingBytecode: verifierLocks[i], tokenPrefix: new Uint8Array() })),
      { role: role('binding', 0), valueSats: '1000', lockingBytecode: bindingLock, tokenPrefix: new Uint8Array() },
      { role: role('change', 0), valueSats: '0', lockingBytecode: new Uint8Array(), tokenPrefix: new Uint8Array() },
    ],
  };
  const contextHash = cx.hashDirectV2TransactionContext(context, { carrierCount: 10 }).toString('hex');
  const t1 = tm.applyDirectV2Transition({
    kind: 'deposit', networkId: 2, profileId, instanceId, denominationSats: '10000000',
    preState: model.state, noteTree: model.noteTree, nullifierTree: model.nullifierTree,
    transactionContextHash: contextHash,
    output: { outputNoteLeaf: output.public.outputNoteLeaf, encryptedRecord: output.public.encryptedRecord },
  });
  const circuitInput = cw.buildDirectV2CircuitInput({ transition: t1, output, denominationSats: '10000000' });
  const outPath = path.join(root, 'evidence/03-implementation/bench-prove/pf10-deposit-input.json');
  mkdirSync(path.dirname(outPath), { recursive: true });
  writeFileSync(outPath, JSON.stringify(circuitInput, null, 1));
  return outPath;
}
