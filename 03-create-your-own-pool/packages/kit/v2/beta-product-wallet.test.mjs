import assert from 'node:assert/strict';
import {
  chmodSync,
  linkSync,
  lstatSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import {
  V2BetaProductWalletCrash,
  V2BetaProductWalletError,
  openV2BetaProductWallet,
} from './beta-product-wallet.mjs';

// TEST-ONLY fixed scalar: it is never written by the product implementation.
const TEST_FUNDING_KEY = '01'.padStart(64, '0');
const PROFILE_ID = 'a'.repeat(64);
const INSTANCE_ID = 'b'.repeat(64);

function temporaryWallet() {
  const directory = mkdtempSync(join(tmpdir(), 'shieldkit-beta-wallet-'));
  chmodSync(directory, 0o700);
  return { directory, databasePath: join(directory, 'wallet.sqlite') };
}

function openFixture(databasePath, options = {}) {
  return openV2BetaProductWallet({
    databasePath,
    profileId: PROFILE_ID,
    instanceId: INSTANCE_ID,
    fundingPrivateKeyHex: TEST_FUNDING_KEY,
    ...options,
  });
}

test('creates a secret-free public account and a durable 0700/0600 wallet', () => {
  const fixture = temporaryWallet();
  try {
    const wallet = openFixture(fixture.databasePath);
    const summary = wallet.publicSummary();
    assert.equal(summary.fundingWalletCount, 1);
    assert.equal(summary.changeWalletCount, 0);
    assert.equal(summary.noteAddress.profileId, PROFILE_ID);
    assert.equal(summary.noteAddress.instanceId, INSTANCE_ID);
    assert.equal(JSON.stringify(summary).includes(TEST_FUNDING_KEY), false);
    assert.equal(JSON.stringify(summary).includes('note_spend_secret'), false);
    assert.equal(lstatSync(fixture.directory).mode & 0o777, 0o700);
    assert.equal(lstatSync(fixture.databasePath).mode & 0o777, 0o600);
    const [funding] = wallet.fundingWallets();
    const signature = wallet.signFunding({ walletId: funding.walletId, digestHex: 'c'.repeat(64) });
    assert.equal(signature.length, 64);
    wallet.close();
  } finally { rmSync(fixture.directory, { recursive: true, force: true }); }
});

test('stages distinct change wallets before signing and attaches only to one accepted outpoint', () => {
  const fixture = temporaryWallet();
  try {
    const wallet = openFixture(fixture.databasePath);
    const one = wallet.stageChangeWallet({ operationId: 'operation.one' });
    const two = wallet.stageChangeWallet({ operationId: 'operation.two' });
    assert.equal(one.state, 'prepared');
    assert.notEqual(one.cashAddress, two.cashAddress);
    assert.equal(wallet.stageChangeWallet({ operationId: 'operation.one' }).walletId, one.walletId);
    assert.throws(
      () => wallet.attachChangeWallet({ operationId: 'operation.one', txid: 'd'.repeat(64), vout: 0, valueSats: '123', acceptedCommit: false }),
      error => error instanceof V2BetaProductWalletError && error.code === 'UNACCEPTED_COMMIT',
    );
    wallet.markChangeWalletSent({ operationId: 'operation.one' });
    const attached = wallet.attachChangeWallet({ operationId: 'operation.one', txid: 'd'.repeat(64), vout: 0, valueSats: '123', acceptedCommit: true });
    assert.deepEqual(attached, wallet.attachChangeWallet({ operationId: 'operation.one', txid: 'd'.repeat(64), vout: 0, valueSats: '123', acceptedCommit: true }));
    assert.throws(
      () => wallet.attachChangeWallet({ operationId: 'operation.one', txid: 'e'.repeat(64), vout: 0, valueSats: '123', acceptedCommit: true }),
      error => error instanceof V2BetaProductWalletError && error.code === 'CHANGE_WALLET_REUSE',
    );
    assert.equal(wallet.publicSummary().attachedChangeCount, 1);
    wallet.close();
  } finally { rmSync(fixture.directory, { recursive: true, force: true }); }
});

test('reopen recovery retains abandoned prepared change keys forever as watched orphans', () => {
  const fixture = temporaryWallet();
  try {
    const initial = openFixture(fixture.databasePath);
    const staged = initial.stageChangeWallet({ operationId: 'abandoned.prepare' });
    initial.close();
    const reopened = openFixture(fixture.databasePath);
    assert.equal(reopened.recoverPreparedChanges(), 1);
    const [orphan] = reopened.changeWalletsForWatch();
    assert.equal(orphan.walletId, staged.walletId);
    assert.equal(orphan.state, 'orphan-recoverable');
    assert.throws(
      () => reopened.attachChangeWallet({ operationId: 'abandoned.prepare', txid: 'f'.repeat(64), vout: 0, valueSats: '1', acceptedCommit: true }),
      error => error instanceof V2BetaProductWalletError && error.code === 'CHANGE_WALLET_NOT_RECONCILABLE',
    );
    reopened.close();
  } finally { rmSync(fixture.directory, { recursive: true, force: true }); }
});

test('change send uncertainty survives reopen and exact accepted attachment reconciles sent or indeterminate keys', () => {
  const fixture = temporaryWallet();
  try {
    const initial = openFixture(fixture.databasePath);
    initial.stageChangeWallet({ operationId: 'change.safe' });
    initial.stageChangeWallet({ operationId: 'change.sent' });
    initial.markChangeWalletSent({ operationId: 'change.sent' });
    initial.stageChangeWallet({ operationId: 'change.indeterminate' });
    initial.markChangeWalletIndeterminate({ operationId: 'change.indeterminate' });
    initial.close();
    const reopened = openFixture(fixture.databasePath);
    assert.equal(reopened.recoverPreparedChanges(), 1);
    assert.deepEqual(
      reopened.changeWalletsForWatch().map(change => `${change.operationId}:${change.state}`).sort(),
      ['change.indeterminate:indeterminate', 'change.safe:orphan-recoverable', 'change.sent:sent'],
    );
    assert.equal(reopened.attachChangeWallet({ operationId: 'change.sent', txid: 'a'.repeat(64), vout: 0, valueSats: '1', acceptedCommit: true }).state, 'attached');
    assert.equal(reopened.attachChangeWallet({ operationId: 'change.indeterminate', txid: 'b'.repeat(64), vout: 1, valueSats: '2', acceptedCommit: true }).state, 'attached');
    reopened.close();
  } finally { rmSync(fixture.directory, { recursive: true, force: true }); }
});

test('change send crash rolls back to definitely pre-send and recovery will orphan it', () => {
  const fixture = temporaryWallet();
  try {
    const wallet = openFixture(fixture.databasePath, { crashAt: 'wallet.change.sent.after_update' });
    wallet.stageChangeWallet({ operationId: 'change.send.crash' });
    assert.throws(
      () => wallet.markChangeWalletSent({ operationId: 'change.send.crash' }),
      error => error instanceof V2BetaProductWalletCrash && error.stage === 'wallet.change.sent.after_update',
    );
    wallet.close();
    const reopened = openFixture(fixture.databasePath);
    assert.equal(reopened.recoverPreparedChanges(), 1);
    assert.equal(reopened.changeWalletsForWatch()[0].state, 'orphan-recoverable');
    reopened.close();
  } finally { rmSync(fixture.directory, { recursive: true, force: true }); }
});

test('only an accepted attached change appears as spendable funding and signs the next action', () => {
  const fixture = temporaryWallet();
  try {
    const wallet = openFixture(fixture.databasePath);
    const prepared = wallet.stageChangeWallet({ operationId: 'chain.prepared' });
    const sent = wallet.stageChangeWallet({ operationId: 'chain.sent' });
    wallet.markChangeWalletSent({ operationId: 'chain.sent' });
    const indeterminate = wallet.stageChangeWallet({ operationId: 'chain.indeterminate' });
    wallet.markChangeWalletIndeterminate({ operationId: 'chain.indeterminate' });
    const orphan = wallet.stageChangeWallet({ operationId: 'chain.orphan' });
    wallet.markChangeOrphanRecoverable({ operationId: 'chain.orphan', reason: 'abandoned before send' });
    const accepted = wallet.stageChangeWallet({ operationId: 'chain.accepted' });
    wallet.markChangeWalletSent({ operationId: 'chain.accepted' });
    wallet.attachChangeWallet({ operationId: 'chain.accepted', txid: 'c'.repeat(64), vout: 2, valueSats: '456', acceptedCommit: true });
    for (const change of [prepared, sent, indeterminate, orphan]) {
      assert.throws(
        () => wallet.signFunding({ walletId: change.walletId, digestHex: 'd'.repeat(64) }),
        error => error instanceof V2BetaProductWalletError && error.code === 'CHANGE_WALLET_NOT_SPENDABLE',
      );
    }
    const spendable = wallet.spendableFundingWallets();
    const attached = spendable.find(entry => entry.walletId === accepted.walletId);
    assert.deepEqual(attached.attachedOutpoint, { txid: 'c'.repeat(64), vout: 2 });
    assert.equal(attached.attachedValueSats, '456');
    assert.equal(wallet.signFunding({ walletId: attached.walletId, digestHex: 'd'.repeat(64) }).length, 64);
    assert.equal(spendable.filter(entry => entry.source === 'attached-change').length, 1);
    assert.equal(JSON.stringify(spendable).includes('privateKey'), false);
    wallet.close();
  } finally { rmSync(fixture.directory, { recursive: true, force: true }); }
});

test('combined action send and uncertainty transitions never half-update change and withdrawal note resources', () => {
  const fixture = temporaryWallet();
  try {
    const sendCrash = openFixture(fixture.databasePath, { crashAt: 'wallet.action.send.after_change_update' });
    const deposit = sendCrash.stageDepositNote({ operationId: 'deposit.action', postActionSequence: '1' });
    sendCrash.attachAcceptedDeposit({ operationId: 'deposit.action', noteIndex: 0, txid: 'e'.repeat(64), acceptedCommit: true });
    sendCrash.stageChangeWallet({ operationId: 'withdraw.action' });
    sendCrash.reserveOwnedNoteForWithdrawal({ operationId: 'withdraw.action', noteId: deposit.note.noteId });
    assert.throws(
      () => sendCrash.markActionSendAttempt({ operationId: 'withdraw.action', kind: 'withdrawal' }),
      error => error instanceof V2BetaProductWalletCrash && error.stage === 'wallet.action.send.after_change_update',
    );
    assert.equal(sendCrash.changeWalletsForWatch().find(change => change.operationId === 'withdraw.action').state, 'prepared');
    assert.equal(sendCrash.ownedNotesForWatch()[0].reservationPhase, 'prepared');
    sendCrash.close();
    const sent = openFixture(fixture.databasePath);
    const sentResult = sent.markActionSendAttempt({ operationId: 'withdraw.action', kind: 'withdrawal' });
    assert.equal(sentResult.change.state, 'sent');
    assert.equal(sentResult.note.reservationPhase, 'sent');
    sent.stageChangeWallet({ operationId: 'deposit.only-change' });
    assert.equal(sent.markActionSendAttempt({ operationId: 'deposit.only-change', kind: 'deposit' }).note, null);
    sent.close();
    const indeterminateCrash = openFixture(fixture.databasePath, { crashAt: 'wallet.action.indeterminate.after_change_update' });
    assert.throws(
      () => indeterminateCrash.markActionIndeterminate({ operationId: 'withdraw.action', kind: 'withdrawal' }),
      error => error instanceof V2BetaProductWalletCrash && error.stage === 'wallet.action.indeterminate.after_change_update',
    );
    assert.equal(indeterminateCrash.changeWalletsForWatch().find(change => change.operationId === 'withdraw.action').state, 'sent');
    assert.equal(indeterminateCrash.ownedNotesForWatch()[0].reservationPhase, 'sent');
    indeterminateCrash.close();
    const indeterminate = openFixture(fixture.databasePath);
    const result = indeterminate.markActionIndeterminate({ operationId: 'withdraw.action', kind: 'withdrawal' });
    assert.equal(result.change.state, 'indeterminate');
    assert.equal(result.note.reservationPhase, 'indeterminate');
    indeterminate.close();
  } finally { rmSync(fixture.directory, { recursive: true, force: true }); }
});

test('operation-scoped pre-send abort atomically orphans change and rejects/releases only its note resource', () => {
  const fixture = temporaryWallet();
  try {
    const wallet = openFixture(fixture.databasePath);
    wallet.stageChangeWallet({ operationId: 'abort.deposit' });
    const deposit = wallet.stageDepositNote({ operationId: 'abort.deposit', postActionSequence: '1' });
    const aborted = wallet.abortSafePreSendAction({ operationId: 'abort.deposit', kind: 'deposit', reason: 'proof construction failed' });
    assert.equal(aborted.change.state, 'orphan-recoverable');
    assert.equal(aborted.note.state, 'deposit-rejected');
    assert.deepEqual(aborted, wallet.abortSafePreSendAction({ operationId: 'abort.deposit', kind: 'deposit', reason: 'proof construction failed' }));
    assert.throws(
      () => wallet.abortSafePreSendAction({ operationId: 'abort.deposit', kind: 'deposit', reason: 'different reason' }),
      error => error instanceof V2BetaProductWalletError && error.code === 'ACTION_ABORT_REPLAY_MISMATCH',
    );
    assert.throws(
      () => wallet.stageDepositNote({ operationId: 'abort.deposit', postActionSequence: '1' }),
      error => error instanceof V2BetaProductWalletError && error.code === 'NOTE_OPERATION_REJECTED',
    );

    const accepted = wallet.stageDepositNote({ operationId: 'abort.source', postActionSequence: '2' });
    wallet.attachAcceptedDeposit({ operationId: 'abort.source', noteIndex: 0, txid: '1'.repeat(64), acceptedCommit: true });
    wallet.stageChangeWallet({ operationId: 'abort.withdrawal' });
    wallet.reserveOwnedNoteForWithdrawal({ operationId: 'abort.withdrawal', noteId: accepted.note.noteId });
    const released = wallet.abortSafePreSendAction({ operationId: 'abort.withdrawal', kind: 'withdrawal', reason: 'proof construction failed' });
    assert.equal(released.change.state, 'orphan-recoverable');
    assert.equal(released.note.state, 'unspent');
    assert.equal(released.note.reservationOperationId, null);
    assert.equal(wallet.reserveOwnedNoteForWithdrawal({ operationId: 'abort.withdrawal.next', noteId: accepted.note.noteId }).note.state, 'reserved');

    wallet.stageChangeWallet({ operationId: 'abort.sent' });
    wallet.stageDepositNote({ operationId: 'abort.sent', postActionSequence: '3' });
    wallet.markActionSendAttempt({ operationId: 'abort.sent', kind: 'deposit' });
    assert.throws(
      () => wallet.abortSafePreSendAction({ operationId: 'abort.sent', kind: 'deposit', reason: 'too late' }),
      error => error instanceof V2BetaProductWalletError && error.code === 'ACTION_ABORT_NOT_PRE_SEND',
    );
    wallet.markActionIndeterminate({ operationId: 'abort.sent', kind: 'deposit' });
    assert.throws(
      () => wallet.abortSafePreSendAction({ operationId: 'abort.sent', kind: 'deposit', reason: 'still too late' }),
      error => error instanceof V2BetaProductWalletError && error.code === 'ACTION_ABORT_NOT_PRE_SEND',
    );
    wallet.stageChangeWallet({ operationId: 'abort.attached' });
    wallet.stageDepositNote({ operationId: 'abort.attached', postActionSequence: '4' });
    wallet.markActionSendAttempt({ operationId: 'abort.attached', kind: 'deposit' });
    wallet.attachChangeWallet({ operationId: 'abort.attached', txid: '2'.repeat(64), vout: 0, valueSats: '1', acceptedCommit: true });
    assert.throws(
      () => wallet.abortSafePreSendAction({ operationId: 'abort.attached', kind: 'deposit', reason: 'attached' }),
      error => error instanceof V2BetaProductWalletError && error.code === 'ACTION_ABORT_NOT_PRE_SEND',
    );
    wallet.close();
    const reopened = openFixture(fixture.databasePath);
    assert.equal(reopened.publicSummary().rejectedDepositNoteCount, 1);
    reopened.close();
    assert.equal(deposit.note.noteId.length, 64);
  } finally { rmSync(fixture.directory, { recursive: true, force: true }); }
});

test('pre-send abort crash rolls back both change and deposit-note state', () => {
  const fixture = temporaryWallet();
  try {
    const wallet = openFixture(fixture.databasePath, { crashAt: 'wallet.action.abort.after_change_update' });
    wallet.stageChangeWallet({ operationId: 'abort.crash' });
    wallet.stageDepositNote({ operationId: 'abort.crash', postActionSequence: '1' });
    assert.throws(
      () => wallet.abortSafePreSendAction({ operationId: 'abort.crash', kind: 'deposit', reason: 'test crash' }),
      error => error instanceof V2BetaProductWalletCrash && error.stage === 'wallet.action.abort.after_change_update',
    );
    assert.equal(wallet.changeWalletsForWatch()[0].state, 'prepared');
    assert.equal(wallet.ownedNotesForWatch()[0].state, 'deposit-staged');
    wallet.close();
  } finally { rmSync(fixture.directory, { recursive: true, force: true }); }
});

test('crash seams roll back atomically and never make a staged key reusable', () => {
  const fixture = temporaryWallet();
  try {
    const crashing = openFixture(fixture.databasePath, { crashAt: 'wallet.stage.after_insert' });
    assert.throws(
      () => crashing.stageChangeWallet({ operationId: 'crash.before.commit' }),
      error => error instanceof V2BetaProductWalletCrash && error.stage === 'wallet.stage.after_insert',
    );
    crashing.close();
    const recovered = openFixture(fixture.databasePath);
    assert.equal(recovered.changeWalletsForWatch().length, 0);
    recovered.close();
  } finally { rmSync(fixture.directory, { recursive: true, force: true }); }
});

test('attachment crash retains sent uncertainty while pre-send orphan crash remains recoverable', () => {
  const fixture = temporaryWallet();
  try {
    const seed = openFixture(fixture.databasePath);
    seed.stageChangeWallet({ operationId: 'crash.after.prepare' });
    seed.close();
    const attachmentCrash = openFixture(fixture.databasePath, { crashAt: 'wallet.attach.after_update' });
    attachmentCrash.markChangeWalletSent({ operationId: 'crash.after.prepare' });
    assert.throws(
      () => attachmentCrash.attachChangeWallet({ operationId: 'crash.after.prepare', txid: '1'.repeat(64), vout: 1, valueSats: '2', acceptedCommit: true }),
      error => error instanceof V2BetaProductWalletCrash && error.stage === 'wallet.attach.after_update',
    );
    attachmentCrash.close();
    const orphanCrash = openFixture(fixture.databasePath, { crashAt: 'wallet.orphan.after_update' });
    orphanCrash.stageChangeWallet({ operationId: 'crash.pre-send' });
    assert.throws(
      () => orphanCrash.markChangeOrphanRecoverable({ operationId: 'crash.pre-send', reason: 'test interruption' }),
      error => error instanceof V2BetaProductWalletCrash && error.stage === 'wallet.orphan.after_update',
    );
    orphanCrash.close();
    const recovered = openFixture(fixture.databasePath);
    assert.equal(recovered.recoverPreparedChanges({ reason: 'post-crash recovery' }), 1);
    assert.deepEqual(
      recovered.changeWalletsForWatch().map(change => `${change.operationId}:${change.state}`).sort(),
      ['crash.after.prepare:sent', 'crash.pre-send:orphan-recoverable'],
    );
    recovered.close();
  } finally { rmSync(fixture.directory, { recursive: true, force: true }); }
});

test('two live wallet capabilities serialize distinct operations without address reuse', () => {
  const fixture = temporaryWallet();
  try {
    const first = openFixture(fixture.databasePath);
    const second = openFixture(fixture.databasePath);
    const a = first.stageChangeWallet({ operationId: 'concurrent.a' });
    const b = second.stageChangeWallet({ operationId: 'concurrent.b' });
    assert.notEqual(a.walletId, b.walletId);
    assert.equal(first.changeWalletsForWatch().length, 2);
    first.close(); second.close();
  } finally { rmSync(fixture.directory, { recursive: true, force: true }); }
});

test('stages a private deposit note before proving, then attaches its exact accepted index and transaction', () => {
  const fixture = temporaryWallet();
  try {
    const wallet = openFixture(fixture.databasePath);
    const staged = wallet.stageDepositNote({ operationId: 'deposit.private', postActionSequence: '1' });
    assert.equal(staged.note.state, 'deposit-staged');
    assert.equal(staged.publicOutput.outputNoteLeaf, staged.circuitOutput.public.outputNoteLeaf);
    assert.equal(staged.circuitOutput.witness.rho.length, 64);
    assert.equal(staged.privateStoreMaterial.noteId, staged.note.noteId);
    assert.equal(staged.privateStoreMaterial.recordId.length, 64);
    const summary = JSON.stringify(wallet.publicSummary());
    assert.equal(summary.includes(staged.circuitOutput.witness.rho), false);
    assert.equal(summary.includes(staged.circuitOutput.witness.r), false);
    assert.equal(summary.includes(staged.privateStoreMaterial.nullifier), false);
    assert.equal(summary.includes(staged.privateStoreMaterial.recordId), false);
    assert.throws(
      () => wallet.attachAcceptedDeposit({ operationId: 'deposit.private', noteIndex: 0, txid: '3'.repeat(64), acceptedCommit: false }),
      error => error instanceof V2BetaProductWalletError && error.code === 'UNACCEPTED_COMMIT',
    );
    const accepted = wallet.attachAcceptedDeposit({ operationId: 'deposit.private', noteIndex: 0, txid: '3'.repeat(64), acceptedCommit: true });
    assert.equal(accepted.state, 'unspent');
    assert.equal(accepted.noteIndex, '0');
    assert.deepEqual(accepted, wallet.attachAcceptedDeposit({ operationId: 'deposit.private', noteIndex: 0, txid: '3'.repeat(64), acceptedCommit: true }));
    assert.throws(
      () => wallet.attachAcceptedDeposit({ operationId: 'deposit.private', noteIndex: 1, txid: '3'.repeat(64), acceptedCommit: true }),
      error => error instanceof V2BetaProductWalletError && error.code === 'OWNED_NOTE_REUSE',
    );
    const watched = JSON.stringify(wallet.ownedNotesForWatch());
    assert.equal(watched.includes(staged.privateStoreMaterial.nullifier), false);
    assert.equal(watched.includes(staged.privateStoreMaterial.recordId), false);
    const reserved = wallet.reserveOwnedNoteForWithdrawal({ operationId: 'withdraw.private', noteId: staged.privateStoreMaterial.noteId });
    assert.equal(reserved.note.noteId, staged.privateStoreMaterial.noteId);
    assert.equal(reserved.publicSpend.publicNullifier, staged.privateStoreMaterial.nullifier);
    wallet.close();
  } finally { rmSync(fixture.directory, { recursive: true, force: true }); }
});

test('reserves exactly one accepted note, retains circuit spend privately, and spends only after accepted commit', () => {
  const fixture = temporaryWallet();
  try {
    const wallet = openFixture(fixture.databasePath);
    const staged = wallet.stageDepositNote({ operationId: 'deposit.spend', postActionSequence: '1' });
    wallet.attachAcceptedDeposit({ operationId: 'deposit.spend', noteIndex: 0, txid: '4'.repeat(64), acceptedCommit: true });
    const reserved = wallet.reserveOwnedNoteForWithdrawal({ operationId: 'withdraw.spend', noteId: staged.note.noteId });
    assert.equal(reserved.note.state, 'reserved');
    assert.equal(reserved.publicSpend.noteIndex, '0');
    assert.equal(reserved.circuitSpend.spendSecret.length, 64);
    assert.equal(JSON.stringify(wallet.publicSummary()).includes(reserved.circuitSpend.spendSecret), false);
    assert.throws(
      () => wallet.commitAcceptedWithdrawalSpend({ operationId: 'withdraw.spend', txid: '5'.repeat(64), acceptedCommit: true }),
      error => error instanceof V2BetaProductWalletError && error.code === 'WITHDRAWAL_RESERVATION_STATE',
    );
    wallet.markWithdrawalReservationSent({ operationId: 'withdraw.spend' });
    assert.equal(
      wallet.markWithdrawalReservationIndeterminate({ operationId: 'withdraw.spend' }).reservationPhase,
      'indeterminate',
    );
    const spent = wallet.commitAcceptedWithdrawalSpend({ operationId: 'withdraw.spend', txid: '5'.repeat(64), acceptedCommit: true });
    assert.equal(spent.state, 'spent');
    assert.throws(
      () => wallet.reserveOwnedNoteForWithdrawal({ operationId: 'withdraw.again', noteId: staged.note.noteId }),
      error => error instanceof V2BetaProductWalletError && error.code === 'OWNED_NOTE_UNAVAILABLE',
    );
    wallet.close();
  } finally { rmSync(fixture.directory, { recursive: true, force: true }); }
});

test('reopen recovery releases only safe pre-send reservations and retains sent or indeterminate reservations', () => {
  const fixture = temporaryWallet();
  try {
    const first = openFixture(fixture.databasePath);
    for (const [suffix, index] of [['safe', 0], ['sent', 1], ['indeterminate', 2]]) {
      first.stageDepositNote({ operationId: `deposit.${suffix}`, postActionSequence: String(index + 1) });
      first.attachAcceptedDeposit({ operationId: `deposit.${suffix}`, noteIndex: index, txid: String(index + 6).repeat(64), acceptedCommit: true });
    }
    first.reserveOwnedNoteForWithdrawal({ operationId: 'withdraw.safe' });
    first.reserveOwnedNoteForWithdrawal({ operationId: 'withdraw.sent' });
    first.markWithdrawalReservationSent({ operationId: 'withdraw.sent' });
    first.reserveOwnedNoteForWithdrawal({ operationId: 'withdraw.indeterminate' });
    first.markWithdrawalReservationIndeterminate({ operationId: 'withdraw.indeterminate' });
    first.close();
    const reopened = openFixture(fixture.databasePath);
    assert.equal(reopened.recoverSafePreSendWithdrawals(), 1);
    const states = reopened.ownedNotesForWatch().map(note => `${note.reservationOperationId}:${note.state}:${note.reservationPhase}`).sort();
    assert.deepEqual(states, [
      'null:unspent:null',
      'withdraw.indeterminate:reserved:indeterminate',
      'withdraw.sent:reserved:sent',
    ]);
    reopened.close();
  } finally { rmSync(fixture.directory, { recursive: true, force: true }); }
});

test('note crash seams, concurrent reservation, and tamper detection preserve one-note ownership', () => {
  const fixture = temporaryWallet();
  try {
    const stageCrash = openFixture(fixture.databasePath, { crashAt: 'wallet.note.stage.after_insert' });
    assert.throws(
      () => stageCrash.stageDepositNote({ operationId: 'deposit.crash', postActionSequence: '1' }),
      error => error instanceof V2BetaProductWalletCrash && error.stage === 'wallet.note.stage.after_insert',
    );
    stageCrash.close();
    const first = openFixture(fixture.databasePath);
    assert.equal(first.ownedNotesForWatch().length, 0);
    const staged = first.stageDepositNote({ operationId: 'deposit.concurrent', postActionSequence: '1' });
    first.attachAcceptedDeposit({ operationId: 'deposit.concurrent', noteIndex: 0, txid: 'a'.repeat(64), acceptedCommit: true });
    const second = openFixture(fixture.databasePath);
    const reserved = first.reserveOwnedNoteForWithdrawal({ operationId: 'withdraw.concurrent', noteId: staged.note.noteId });
    assert.equal(reserved.note.reservationOperationId, 'withdraw.concurrent');
    assert.throws(
      () => second.reserveOwnedNoteForWithdrawal({ operationId: 'withdraw.raced', noteId: staged.note.noteId }),
      error => error instanceof V2BetaProductWalletError && error.code === 'OWNED_NOTE_UNAVAILABLE',
    );
    first.close(); second.close();
    const database = new DatabaseSync(fixture.databasePath);
    database.exec(`UPDATE owned_notes SET nullifier='${'0'.repeat(64)}'`);
    database.close();
    assert.throws(
      () => openFixture(fixture.databasePath),
      error => error instanceof V2BetaProductWalletError && error.code === 'WALLET_TAMPERED',
    );
  } finally { rmSync(fixture.directory, { recursive: true, force: true }); }
});

test('rejects unsafe modes, symlink database paths, and a tampered metadata fingerprint', () => {
  const unsafe = temporaryWallet();
  const fixture = temporaryWallet();
  const linked = temporaryWallet();
  const hardLinked = temporaryWallet();
  try {
    chmodSync(unsafe.directory, 0o755);
    assert.throws(
      () => openFixture(unsafe.databasePath),
      error => error instanceof V2BetaProductWalletError && error.code === 'UNSAFE_WALLET_PATH',
    );
    const wallet = openFixture(fixture.databasePath);
    wallet.close();
    symlinkSync(fixture.databasePath, linked.databasePath);
    assert.throws(
      () => openFixture(linked.databasePath),
      error => error instanceof V2BetaProductWalletError && error.code === 'UNSAFE_WALLET_PATH',
    );
    const database = new DatabaseSync(fixture.databasePath);
    database.exec(`UPDATE wallet_metadata SET fingerprint='${'0'.repeat(64)}'`);
    database.close();
    assert.throws(
      () => openFixture(fixture.databasePath),
      error => error instanceof V2BetaProductWalletError && error.code === 'WALLET_TAMPERED',
    );
    linkSync(fixture.databasePath, hardLinked.databasePath);
    assert.throws(
      () => openFixture(hardLinked.databasePath),
      error => error instanceof V2BetaProductWalletError && error.code === 'UNSAFE_WALLET_PATH',
    );
  } finally {
    rmSync(unsafe.directory, { recursive: true, force: true });
    rmSync(fixture.directory, { recursive: true, force: true });
    rmSync(linked.directory, { recursive: true, force: true });
    rmSync(hardLinked.directory, { recursive: true, force: true });
  }
});
