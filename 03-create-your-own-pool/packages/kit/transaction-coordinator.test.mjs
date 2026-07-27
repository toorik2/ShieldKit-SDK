import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  broadcastStagedOperation,
  commitStagedOperation,
  loadPendingOperation,
  stageOperation,
  transactionIdFromHex,
} from './transaction-coordinator.mjs';

const transaction = (role, hex) => ({ role, hex, txid: transactionIdFromHex(hex) });

test('offline staging writes a 0600 journal and does not mutate live state', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-operation-'));
  t.after(async () => import('node:fs/promises').then(({ rm }) => rm(root, { recursive: true, force: true })));
  const statePath = path.join(root, 'state.json');
  await writeFile(statePath, '{"stateTxid":"old"}\n', { mode: 0o644 });
  const staged = stageOperation({
    poolDirectory: root,
    kind: 'deposit',
    network: 'chipnet',
    setupMode: 'development-only',
    transactions: [transaction('prep', '01000000000000000000')],
    nextState: { stateTxid: 'new', openNotes: [{ secret: 'private' }] },
    ledgerRecord: { kind: 'deposit' },
  });
  assert.equal(JSON.parse(await readFile(statePath, 'utf8')).stateTxid, 'old');
  assert.equal((await stat(staged.journalPath)).mode & 0o777, 0o600);
  assert.equal(loadPendingOperation(root).journal.status, 'prepared');
});

test('mainnet gate runs before the RPC send capability', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-mainnet-gate-'));
  t.after(async () => import('node:fs/promises').then(({ rm }) => rm(root, { recursive: true, force: true })));
  const { journalPath } = stageOperation({
    poolDirectory: root,
    kind: 'deposit',
    network: 'mainnet',
    setupMode: 'development-only',
    transactions: [transaction('prep', '01000000000000000000')],
    nextState: {},
    ledgerRecord: {},
  });
  let sends = 0;
  await assert.rejects(
    broadcastStagedOperation({
      journalPath,
      rpc: {
        async sendrawtransaction() { sends += 1; },
        async testmempoolaccept() { return [{ allowed: true }]; },
      },
    }),
    /mainnet broadcast refused/,
  );
  assert.equal(sends, 0);
});

test('broadcast and commit are ordered, durable, and idempotent', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-commit-'));
  t.after(async () => import('node:fs/promises').then(({ rm }) => rm(root, { recursive: true, force: true })));
  const txs = [
    transaction('prep', '01000000000000000000'),
    transaction('settlement', '02000000000000000000'),
  ];
  const { journalPath } = stageOperation({
    poolDirectory: root,
    kind: 'withdrawal',
    network: 'chipnet',
    setupMode: 'development-only',
    transactions: txs,
    nextState: { stateTxid: txs[1].txid, openNotes: [] },
    ledgerRecord: { kind: 'withdrawal' },
  });
  const sent = [];
  await broadcastStagedOperation({
    journalPath,
    rpc: {
      async testmempoolaccept(hex) {
        assert.equal(sent.length, hex === txs[0].hex ? 0 : 1);
        return [{ allowed: true }];
      },
      async sendrawtransaction(hex) {
        sent.push(hex);
        return transactionIdFromHex(hex);
      },
    },
  });
  const statePath = path.join(root, 'state.json');
  const ledgerPath = path.join(root, 'ledger.jsonl');
  commitStagedOperation({ journalPath, statePath, ledgerPath });
  commitStagedOperation({ journalPath, statePath, ledgerPath });
  assert.deepEqual(sent, txs.map((tx) => tx.hex));
  assert.equal(JSON.parse(await readFile(statePath, 'utf8')).stateTxid, txs[1].txid);
  assert.equal((await stat(statePath)).mode & 0o777, 0o600);
  assert.equal((await stat(ledgerPath)).mode & 0o777, 0o600);
  assert.equal((await readFile(ledgerPath, 'utf8')).trim().split('\n').length, 1);
});

test('atomic commit repairs a pre-existing permissive state mode', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-mode-'));
  t.after(async () => import('node:fs/promises').then(({ rm }) => rm(root, { recursive: true, force: true })));
  const tx = transaction('prep', '01000000000000000000');
  const { journalPath } = stageOperation({
    poolDirectory: root,
    kind: 'maintenance',
    network: 'chipnet',
    setupMode: 'development-only',
    transactions: [tx],
    nextState: { ok: true },
    ledgerRecord: { kind: 'maintenance' },
  });
  const journal = JSON.parse(await readFile(journalPath, 'utf8'));
  journal.status = 'broadcast';
  await writeFile(journalPath, JSON.stringify(journal));
  await chmod(journalPath, 0o600);
  const statePath = path.join(root, 'state.json');
  await writeFile(statePath, '{}\n', { mode: 0o644 });
  commitStagedOperation({ journalPath, statePath, ledgerPath: path.join(root, 'ledger.jsonl') });
  assert.equal((await stat(statePath)).mode & 0o777, 0o600);
});
