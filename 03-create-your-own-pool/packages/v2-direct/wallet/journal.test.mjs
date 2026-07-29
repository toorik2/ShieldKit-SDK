import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, mkdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import { createJournal } from './journal.mjs';
import { createNoteWallet } from './notes.mjs';

const profileId = createHash('sha256').update('wallet-test-p').digest('hex');
const instanceId = createHash('sha256').update('wallet-test-i').digest('hex');
const testRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../../.cache/v2-direct-tests');
mkdirSync(testRoot, { recursive: true });
const tmpHome = (prefix) => mkdtempSync(path.join(testRoot, `${prefix}-${randomBytes(4).toString('hex')}-`));

describe('journal + wallet', () => {
  it('writes secrets mode 0600 and enforces FUNDING_UTXO_REQUIRED before prove', () => {
    const root = tmpHome('v2-wallet');
    const wallet = createNoteWallet(path.join(root, 'w'), { profileId, instanceId });
    const mode = statSync(wallet.secretsPath).mode & 0o777;
    assert.equal(mode, 0o600);

    const journal = createJournal(path.join(root, 'j'));
    const op = journal.createOperation({ kind: 'deposit' });
    assert.equal(op.state, 'draft');
    assert.throws(() => wallet.selectFundingUtxo(10_000_000n, op.id), /FUNDING_UTXO_REQUIRED/);

    wallet.setUtxos([{
      outpoint: 'aa'.repeat(32) + ':0',
      txid: 'aa'.repeat(32),
      vout: 0,
      value: '20000000',
    }]);
    const utxo = wallet.selectFundingUtxo(10_000_000n, op.id);
    assert.equal(utxo.value, '20000000');
    journal.transition(op.id, 'funding_selected');
    journal.transition(op.id, 'tip_synced');
    journal.transition(op.id, 'proving');
    journal.transition(op.id, 'proved');
    journal.transition(op.id, 'signed');
    journal.transition(op.id, 'broadcast');
    journal.transition(op.id, 'mempool');
    journal.transition(op.id, 'confirmed');
    const settled = journal.transition(op.id, 'settled');
    assert.equal(settled.confirmedStateCommitted, true);
    assert.throws(
      () => journal.transition(op.id, 'broadcast'),
      /illegal/,
    );
  });

  it('rejects premature confirmedStateCommitted', () => {
    const root = tmpHome('v2-journal');
    const journal = createJournal(root);
    const op = journal.createOperation({ kind: 'deposit' });
    assert.throws(
      () => journal.transition(op.id, 'funding_selected', { confirmedStateCommitted: true }),
      /cannot mark confirmed/,
    );
  });
});
