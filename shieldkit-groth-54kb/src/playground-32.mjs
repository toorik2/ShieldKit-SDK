// Q-09: 32-live-note playground campaign — full state-machine lifecycle (32 deposits -> 32 erases).
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
const FOLDER = '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/shieldkit-groth-54kb';
const G = '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/shieldkit-groth';
const notes = await import('file://' + G + '/packages/action/v2/notes.mjs');
const transitionMod = await import('file://' + G + '/packages/action/v2/transition.mjs');
const st = await import('file://' + G + '/packages/action/v2/state.mjs');
const noteTreeMod = await import('file://' + G + '/packages/action/v2/note-tree.mjs');
const inkt = await import('file://' + G + '/packages/action/v2/indexed-nullifier-tree.mjs');
const pz = await import('file://' + G + '/packages/action/v2/poseidon.mjs');
const core = JSON.parse(readFileSync(path.join(FOLDER, 'src/pf6-profile-core.json'), 'utf8'));
const account = JSON.parse(readFileSync('/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4/pf6-pool-account.json', 'utf8'));
const pc = await import('file://' + G + '/packages/profile/v2/profile-core.mjs');
const profileId = pc.deriveProfileId(core);
const DENOMINATION = '10000000';
const networkId = 2;
const instanceId = '5'.repeat(64);
const address = notes.deriveDirectV2Address({ networkId, profileId, instanceId, ...account });
account.address = address;
let model = transitionMod.createDirectV2PoolModel({ profileId, maximumLiveNotes: '32', denominationSats: DENOMINATION });
let noteTree = noteTreeMod.create({ depth: 32, emptyLeafHash: pz.hashEmptyNoteLeaf(), hashNode: pz.hashNoteTreeNode });
let nullifierTree = inkt.create({ depth: 32, hashLeaf: pz.hashIndexedNullifierLeaf, hashNode: pz.hashIndexedNullifierNode });
const ctxHash = '1'.repeat(64);
let live = 0;
const rng = () => ({ bytes(len) { if (len !== 32) throw new Error('len'); return Uint8Array.from(randomBytes(32)); } });
const leaves = [], encs = [];
const log = [];
// 32 deposits -> 32 live notes
for (let i = 0; i < 32; i++) {
  const out = notes.constructDirectV2Output({ address, postActionSequence: String(i + 1), rng: rng() });
  const t = transitionMod.applyDirectV2Transition({
    kind: 'deposit', networkId, profileId, instanceId, denominationSats: DENOMINATION,
    preState: model.state, noteTree, nullifierTree, transactionContextHash: ctxHash,
    output: { outputNoteLeaf: out.public.outputNoteLeaf, encryptedRecord: out.public.encryptedRecord },
  });
  model = { ...model, state: t.state };
  noteTree = noteTreeMod.append(noteTree, BigInt('0x' + out.public.outputNoteLeaf)).tree;
  leaves.push(out.public.outputNoteLeaf); encs.push(out.public.encryptedRecord);
  live++;
  if ((i + 1) % 8 === 0) log.push(`after deposit ${i + 1}: live ${live}, reserve ${String(model.state.reserveSats)}, seq ${String(model.state.actionSequence)}`);
}
// 32 erases (spend each recovered deposited note)
for (let i = 0; i < 32; i++) {
  const rec = notes.recoverDirectV2Output({ account, outputNoteLeaf: leaves[i], encryptedRecord: encs[i] });
  const spend = { inputNoteLeaf: leaves[i], noteIndex: String(i), publicNullifier: rec.nullifier };
  const t = transitionMod.applyDirectV2Transition({
    kind: 'withdrawal', networkId, profileId, instanceId, denominationSats: DENOMINATION,
    preState: model.state, noteTree, nullifierTree, transactionContextHash: ctxHash,
    spend, withdrawalLockingBytecodeHash: '0'.repeat(64),
  });
  model = { ...model, state: t.state };
  nullifierTree = inkt.insert(nullifierTree, Uint8Array.from(Buffer.from(rec.nullifier, 'hex'))).tree;
  live--;
  if ((i + 1) % 8 === 0) log.push(`after erase ${i + 1}: live ${live}, reserve ${String(model.state.reserveSats)}, seq ${String(model.state.actionSequence)}`);
}
const summary = {
  schema: 'shieldkit-54kb/playground-32-campaign/v1',
  generated: new Date().toISOString(),
  status: live === 0 && model.state.reserveSats === 0n && model.state.noteCount === 0n && model.state.actionSequence === 64n ? 'CAMPAIGN COMPLETE' : 'CAMPAIGN FAILED',
  campaign: '32 sequential deposits (32 live notes) + 32 erases (recovered-note spends)',
  final: { liveNotes: live, reserve: String(model.state.reserveSats), noteCount: String(model.state.noteCount), seq: String(model.state.actionSequence) },
  log,
};
writeFileSync('/tmp/pf6-playground-32.json', JSON.stringify(summary, null, 1));
console.log(JSON.stringify(summary, null, 1));
