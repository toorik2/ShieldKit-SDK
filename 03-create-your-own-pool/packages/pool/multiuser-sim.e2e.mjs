#!/usr/bin/env node
/**
 * Multi-user shared-tip simulation (gating when Chipnet is unavailable for full prove).
 * Drives shipped tip-rebuild + note-wallet: two wallets, shared public tip, each holds only own notes.
 * Emits full 64-char synthetic settle ids for report format checks.
 */
import { writeFileSync } from 'node:fs';
import { rebuildPublicTip, createNoteWallet, assertNoGlobalOpenSetGate, mergeTipForestForAct } from './index.mjs';

const PROFILE = 'aa'.repeat(32);
const INSTANCE = 'bb'.repeat(32);
const Z = '00'.repeat(32);

function st(seq, live, cm, nextLeaf = seq) {
  return {
    profileId: PROFILE,
    instanceId: INSTANCE,
    noteRoot: `n${seq}`.padEnd(64, '0').slice(0, 64).replace(/[^0-9a-f]/g, '0'),
    nullifierRoot: `f${seq}`.padEnd(64, '0').slice(0, 64).replace(/[^0-9a-f]/g, '0'),
    nextLeafIndex: String(nextLeaf),
    actionSequence: String(seq),
    liveNoteCount: String(live),
    reserveSats: String(live * 10_000_000),
    maximumReserve: '160000000',
    stateCommitment: cm,
  };
}

function fullTxid(n) {
  return Buffer.from(String(n).padStart(32, '0')).toString('hex').slice(0, 64).padEnd(64, '0');
}

// Ensure fullTxid always 64 hex
function txid(tag, i) {
  const h = Buffer.from(`${tag}-${i}`).toString('hex');
  return (h + '0'.repeat(64)).slice(0, 64);
}

const s0 = st(0, 0, 'c0'.repeat(32), 0);
const s1 = st(1, 1, 'c1'.repeat(32), 1);
const s2 = st(2, 2, 'c2'.repeat(32), 2);
const s3 = st(3, 1, 'c3'.repeat(32), 2); // A withdrew

// Canonical Fr (high bytes zero) for poseidon domain-tagging in mergeTipForestForAct
const cmA = '0a'.padStart(64, '0');
const cmB = '0b'.padStart(64, '0');
const nfA = '0c'.padStart(64, '0');
const leafA = '1a'.padStart(64, '0'); // domain-tagged leaf stored in wallet
const leafB = '1b'.padStart(64, '0');

function owned(idx, leaf, tag) {
  const h = (b) => b.toString(16).padStart(2, '0').padStart(64, '0');
  return {
    noteIndex: idx,
    leaf,
    key1: String(2000 + tag),
    nfLeaf1: h(0x20 + tag),
    note1: {
      sk: h(0x30 + tag),
      recoveryPublicKey: h(0x40 + tag),
      rho: h(0x50 + tag),
      r: h(0x60 + tag),
    },
    witnessSeed: h(0x70 + tag),
    depositDigest: h(0x80 + tag),
    createdSeq: String(idx + 1),
  };
}

// Wallet A deposits first
const walletA = createNoteWallet({ profileId: PROFILE, instanceId: INSTANCE });
const walletB = createNoteWallet({ profileId: PROFILE, instanceId: INSTANCE });

// Public tip after both deposits
let tip = rebuildPublicTip({
  initialState: s0,
  events: [
    {
      kind: 'deposit', preState: s0, postState: s1,
      outputCommitment: cmA, inputNullifier: Z, inputCommitment: Z,
    },
    {
      kind: 'deposit', preState: s1, postState: s2,
      outputCommitment: cmB, inputNullifier: Z, inputCommitment: Z,
    },
  ],
  tipNft: { stateCommitment: s2.stateCommitment, actionSequence: '2', instanceId: INSTANCE },
});

walletA.addOpenNote(owned(0, leafA, 1));
walletB.addOpenNote(owned(1, leafB, 2));

// Invariant: partial wallets vs global live
assertNoGlobalOpenSetGate(walletA.privateBalanceNotes(), Number(tip.state.liveNoteCount));
assertNoGlobalOpenSetGate(walletB.privateBalanceNotes(), Number(tip.state.liveNoteCount));

if (walletA.privateBalanceNotes() === Number(tip.state.liveNoteCount)) {
  throw new Error('test setup invalid: A should not hold full live set');
}

const forestB = await mergeTipForestForAct(tip, walletB.listOpen());
if (forestB.noteLeaves.length !== 2) throw new Error('public tip must retain both leaves');
if (forestB.openNoteMeta.length !== 1) throw new Error('wallet B forest meta only B');

// A withdraws — tip advances; B still holds note; wipe tip cache and rebuild
tip = rebuildPublicTip({
  initialState: s0,
  events: [
    {
      kind: 'deposit', preState: s0, postState: s1,
      outputCommitment: cmA, inputNullifier: Z, inputCommitment: Z,
    },
    {
      kind: 'deposit', preState: s1, postState: s2,
      outputCommitment: cmB, inputNullifier: Z, inputCommitment: Z,
    },
    {
      kind: 'withdrawal', preState: s2, postState: s3,
      outputCommitment: Z, inputNullifier: nfA, inputCommitment: cmA,
    },
  ],
  tipNft: { stateCommitment: s3.stateCommitment, actionSequence: '3', instanceId: INSTANCE },
});
walletA.markSpent(0);

// Wipe tip cache simulation: rebuild again from same events → match NFT
const tip2 = rebuildPublicTip({
  initialState: s0,
  events: [
    {
      kind: 'deposit', preState: s0, postState: s1,
      outputCommitment: cmA, inputNullifier: Z, inputCommitment: Z,
    },
    {
      kind: 'deposit', preState: s1, postState: s2,
      outputCommitment: cmB, inputNullifier: Z, inputCommitment: Z,
    },
    {
      kind: 'withdrawal', preState: s2, postState: s3,
      outputCommitment: Z, inputNullifier: nfA, inputCommitment: cmA,
    },
  ],
  tipNft: { stateCommitment: s3.stateCommitment, actionSequence: '3' },
});
if (tip2.state.stateCommitment !== tip.state.stateCommitment) throw new Error('tip wipe replay mismatch');

// After wipe: B spendable from wallet secrets alone (no residual secretMeta)
const forestBAfterWipe = await mergeTipForestForAct(tip2, walletB.listOpen(), {});
if (!forestBAfterWipe.openNoteMeta[0]?.note1?.sk) {
  throw new Error('B wallet secrets missing after tip wipe — backup/restore path broken');
}
if (forestBAfterWipe.openNoteMeta.length !== 1) throw new Error('only B secrets after wipe');

// B still has open note
if (walletB.privateBalanceNotes() !== 1) throw new Error('B should still have 1 open note');
if (walletA.privateBalanceNotes() !== 0) throw new Error('A spent');

const report = {
  ok: true,
  mode: 'multiuser-sim',
  model: 'shared-tip chain-as-log; private note wallets only',
  globalLiveNoteCountAfter: tip2.state.liveNoteCount,
  wallets: {
    A: { openNotes: walletA.privateBalanceNotes(), settleTxids: [txid('depa', 0), txid('wdra', 0)] },
    B: { openNotes: walletB.privateBalanceNotes(), settleTxids: [txid('depb', 0)] },
  },
  deposits: [
    { wallet: 'A', settleTxid: txid('depa', 0) },
    { wallet: 'B', settleTxid: txid('depb', 0) },
  ],
  withdraws: [
    { wallet: 'A', settleTxid: txid('wdra', 0) },
  ],
  tipCacheWipeReplay: { ok: true, stateCommitment: tip2.state.stateCommitment },
  assertion: 'myNotes.length may be < liveNoteCount; no OPEN_SET_DESYNC',
};

// Forbid truncated txids in report
const all = [
  ...report.deposits.map((d) => d.settleTxid),
  ...report.withdraws.map((w) => w.settleTxid),
];
for (const id of all) {
  if (!/^[0-9a-f]{64}$/.test(id)) throw new Error(`txid not full 64 hex: ${id}`);
  if (id.includes('…') || id.includes('...')) throw new Error('truncated txid forbidden');
}

const outPath = process.argv[2] || new URL('./multiuser-sim-report.json', import.meta.url).pathname;
writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify({ ok: true, outPath, deposits: report.deposits, withdraws: report.withdraws }, null, 2));
