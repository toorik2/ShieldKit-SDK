import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createNoteWallet,
  importEncryptedNoteWallet,
  ownedNoteFromOpenMeta,
  NoteWalletError,
  assertNoGlobalOpenSetGate,
} from './index.mjs';

const PROFILE = '11'.repeat(32);
const INSTANCE = '22'.repeat(32);

function fullNote(idx, tag) {
  const t = (n) => String(n).padStart(2, '0').padStart(64, '0').replace(/^0+(?=.{2})/, (m) => m); // simplified
  // Use small canonical Fr hex values
  const hex = (byte) => byte.toString(16).padStart(2, '0').padStart(64, '0');
  return {
    noteIndex: idx,
    leaf: hex(0x10 + tag),
    key1: String(1000 + tag),
    nfLeaf1: hex(0x20 + tag),
    note1: {
      sk: hex(0x30 + tag),
      recoveryPublicKey: hex(0x40 + tag),
      rho: hex(0x50 + tag),
      r: hex(0x60 + tag),
    },
    witnessSeed: hex(0x70 + tag),
    depositDigest: hex(0x80 + tag),
    createdSeq: String(idx + 1),
  };
}

test('wallet holds only my notes with full spend secrets; balance is open count', () => {
  const w = createNoteWallet({ profileId: PROFILE, instanceId: INSTANCE });
  assert.equal(w.privateBalanceNotes(), 0);
  w.addOpenNote(fullNote(0, 1));
  w.addOpenNote(fullNote(3, 2));
  assert.equal(w.privateBalanceNotes(), 2);
  assert.equal(w.listOpen().length, 2);
  assert.ok(w.listOpen()[0].note1.sk);
  assert.ok(w.listOpen()[0].key1);
  assert.ok(w.listOpen()[0].nfLeaf1);
  const gate = assertNoGlobalOpenSetGate(w.privateBalanceNotes(), 9);
  assert.equal(gate.ok, true);
  assert.equal(gate.gate, 'disabled-by-construction');
});

test('encrypt/decrypt backup restores full spend secrets', () => {
  const w = createNoteWallet({ profileId: PROFILE, instanceId: INSTANCE, network: 'chipnet' });
  const n = fullNote(1, 3);
  w.addOpenNote(n);
  const backup = w.exportEncrypted('test-pass-ok');
  assert.equal(backup.schema, 'shieldkit/note-wallet-backup/v1');
  const w2 = importEncryptedNoteWallet(backup, 'test-pass-ok');
  assert.equal(w2.privateBalanceNotes(), 1);
  const open = w2.listOpen()[0];
  assert.equal(open.noteIndex, 1);
  assert.equal(open.witnessSeed, n.witnessSeed);
  assert.equal(open.note1.sk, n.note1.sk);
  assert.equal(open.note1.rho, n.note1.rho);
  assert.equal(open.key1, n.key1);
  assert.equal(open.nfLeaf1, n.nfLeaf1);
  assert.equal(open.leaf, n.leaf);
});

test('wrong passphrase fails decrypt', () => {
  const w = createNoteWallet({ profileId: PROFILE, instanceId: INSTANCE });
  w.addOpenNote(fullNote(0, 4));
  const backup = w.exportEncrypted('correct-pass');
  assert.throws(
    () => importEncryptedNoteWallet(backup, 'wrong-pass!'),
    (e) => e instanceof NoteWalletError && e.code === 'DECRYPT',
  );
});

test('markSpent and lastOpen among my notes only', () => {
  const w = createNoteWallet({ profileId: PROFILE, instanceId: INSTANCE });
  w.addOpenNote(fullNote(0, 5));
  w.addOpenNote(fullNote(5, 6));
  assert.equal(w.lastOpen().noteIndex, 5);
  w.markSpent(5);
  assert.equal(w.privateBalanceNotes(), 1);
  assert.equal(w.lastOpen().noteIndex, 0);
});

test('addOpenNote rejects incomplete secrets', () => {
  const w = createNoteWallet({ profileId: PROFILE, instanceId: INSTANCE });
  assert.throws(
    () => w.addOpenNote({
      noteIndex: 0,
      leaf: '0a'.padStart(64, '0'),
      witnessSeed: '0b'.padStart(64, '0'),
      depositDigest: '0c'.padStart(64, '0'),
    }),
    (e) => e instanceof NoteWalletError,
  );
});

test('ownedNoteFromOpenMeta maps deposit residual into wallet fields', () => {
  const meta = {
    noteIndex: 2,
    leaf: '0a'.padStart(64, '0'),
    key1: '42',
    nfLeaf1: '0b'.padStart(64, '0'),
    note1: {
      sk: '01'.padStart(64, '0'),
      recoveryPublicKey: '02'.padStart(64, '0'),
      rho: '03'.padStart(64, '0'),
      r: '04'.padStart(64, '0'),
    },
    witnessSeed: '0e'.padStart(64, '0'),
  };
  const owned = ownedNoteFromOpenMeta(meta, {
    witnessSeed: '0e'.padStart(64, '0'),
    depositDigest: '0f'.padStart(64, '0'),
    createdSeq: '3',
  });
  const w = createNoteWallet({ profileId: PROFILE, instanceId: INSTANCE });
  w.addOpenNote(owned);
  assert.equal(w.getOpen(2).key1, '42');
  assert.equal(w.toOpenNoteMeta(2).note1.sk, meta.note1.sk);
});

test('legacy enforceEquality gate is not product default', () => {
  assert.throws(
    () => assertNoGlobalOpenSetGate(1, 9, { enforceEquality: true }),
    (e) => e.code === 'OPEN_SET_DESYNC',
  );
  assert.equal(assertNoGlobalOpenSetGate(1, 9).ok, true);
});
